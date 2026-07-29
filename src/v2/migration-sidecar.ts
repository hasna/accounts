import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { z } from "zod";
import { assertSafeWritePath } from "../lib/safe-path.js";
import { AccountsError } from "../types.js";
import {
  accountIdSchema,
  bindingIdSchema,
  machineIdSchema,
  registryScopeSchema,
  runtimeIdSchema,
  timestampSchema,
  type AccountId,
  type BindingId,
  type RegistryScope,
  type RuntimeId,
} from "./domain.js";
import { machineBindingSchema } from "./machine-binding.js";

const OPAQUE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const SAFE_TEXT_PATTERN = /^[^\0\r\n]+$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SIDECAR_MODE = 0o600;
const NOFOLLOW_FLAG =
  typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;
const EXCLUSIVE_NOFOLLOW_WRITE_FLAGS =
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  fsConstants.O_WRONLY |
  NOFOLLOW_FLAG;
const NOFOLLOW_READ_FLAGS = fsConstants.O_RDONLY | NOFOLLOW_FLAG;

const migrationOpaqueIdSchema = z
  .string()
  .min(16)
  .max(128)
  .regex(OPAQUE_ID_PATTERN, "migration identifier must be opaque");

export const migrationDigestSchema = z
  .string()
  .regex(
    DIGEST_PATTERN,
    "digest must be sha256 followed by 64 lowercase hex characters",
  );

export type MigrationDigest = z.infer<typeof migrationDigestSchema>;

export const migrationRedactionDomainSchema = z.enum([
  "machine",
  "source.key",
  "source.authority-id",
  "source.tool",
  "source.name",
  "runtime.label",
  "root.path",
  "root.real-path",
  "root.device",
  "root.inode",
  "root.unsafe-reason",
  "alias",
  "alias.session",
  "diagnostic.plan",
  "diagnostic.source-key",
  "diagnostic.source-tool",
  "diagnostic.alias.account",
  "diagnostic.alias.session",
  "diagnostic.runtime-id",
]);

export type MigrationRedactionDomain = z.infer<
  typeof migrationRedactionDomainSchema
>;

export interface MigrationDiagnosticReference {
  domain: MigrationRedactionDomain;
  digest: MigrationDigest;
}

interface MigrationDiagnosticOptions {
  code?: string;
  count?: number;
  references?: readonly MigrationDiagnosticReference[];
}

const sourceAuthoritySchema = z.enum(["local-v1", "api-v1"]);
const legacyToolSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, "legacy tool must be a runtime slug");
const runtimeLabelSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(SAFE_TEXT_PATTERN)
  .refine(
    (value) => value === canonicalRuntimeLabel(value),
    "runtime label must use canonical Unicode and whitespace",
  );
export const migrationAliasKindSchema = z.enum([
  "legacy_account",
  "session_ref",
]);
const legacyKeySchema = z
  .string()
  .min(1)
  .max(512)
  .regex(SAFE_TEXT_PATTERN, "legacy key contains invalid control characters");
const aliasSchema = z
  .string()
  .min(1)
  .max(512)
  .regex(SAFE_TEXT_PATTERN, "alias contains invalid control characters");
const canonicalAliasSchema = aliasSchema.refine(
  (alias) => alias === canonicalAlias(alias),
  "alias must use canonical Unicode NFC form",
);

function aliasArraySchema(label: string, requireCanonicalOrder: boolean) {
  const valueSchema = requireCanonicalOrder
    ? canonicalAliasSchema
    : aliasSchema;
  return z.array(valueSchema).superRefine((aliases, context) => {
    const seen = new Set<string>();
    for (const [index, alias] of aliases.entries()) {
      const canonical = canonicalAlias(alias);
      if (seen.has(canonical)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index],
          message: `duplicate ${label}`,
        });
      }
      seen.add(canonical);
      if (
        requireCanonicalOrder &&
        index > 0 &&
        compareCanonicalText(aliases[index - 1]!, alias) >= 0
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index],
          message: `${label}s must use canonical order`,
        });
      }
    }
  });
}

const historicalAliasInputSchema = aliasArraySchema("historical alias", false);
const historicalSessionAliasInputSchema = aliasArraySchema(
  "historical session alias",
  false,
);
const canonicalHistoricalAliasSchema = aliasArraySchema(
  "historical alias",
  true,
);
const canonicalHistoricalSessionAliasSchema = aliasArraySchema(
  "historical session alias",
  true,
);

const verifiedRootObservationSchema = z
  .object({
    state: z.literal("verified"),
    path: z.string().min(1).refine(isAbsolute, "root path must be absolute"),
    realPath: z
      .string()
      .min(1)
      .refine(isAbsolute, "root realPath must be absolute"),
    device: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[0-9]+$/, "device must be numeric"),
    inode: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[0-9]+$/, "inode must be numeric"),
    entryCount: z.number().int().nonnegative().safe(),
    byteCount: z.number().int().nonnegative().safe(),
    digest: migrationDigestSchema,
  })
  .strict()
  .superRefine((root, context) => {
    if (resolve(root.path) !== resolve(root.realPath)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["realPath"],
        message: "verified root path must already be its canonical realPath",
      });
    }
  });

const unsafeRootCodeSchema = z.enum([
  "missing",
  "foreign",
  "nested",
  "traversal",
  "symlink",
  "unreadable",
  "divergent",
]);

const unsafeRootObservationSchema = z
  .object({
    state: z.literal("unsafe"),
    code: unsafeRootCodeSchema,
    pathDigest: migrationDigestSchema,
    reason: z.string().min(1).max(512).regex(SAFE_TEXT_PATTERN),
  })
  .strict();

export const migrationRootObservationSchema = z.union([
  verifiedRootObservationSchema,
  unsafeRootObservationSchema,
]);

const pointerObservationSchema = z
  .object({
    current: z.boolean(),
    applied: z.boolean(),
    toolLock: z.boolean(),
  })
  .strict();

export const legacyProfileObservationSchema = z
  .object({
    source: z
      .object({
        authority: sourceAuthoritySchema,
        authorityId: migrationOpaqueIdSchema,
        tool: legacyToolSchema,
        name: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[a-z0-9][a-z0-9-]*$/, "legacy name must be a profile slug"),
      })
      .strict(),
    runtimeLabel: runtimeLabelSchema,
    inputDigest: migrationDigestSchema,
    root: migrationRootObservationSchema,
    authentication: z.enum(["authenticated", "needs_login", "unknown"]),
    pointers: pointerObservationSchema,
    sessionReferenceDigests: z.array(migrationDigestSchema),
    catalogSkipDigests: z.array(migrationDigestSchema),
    historicalAliases: historicalAliasInputSchema,
    historicalSessionAliases: historicalSessionAliasInputSchema,
  })
  .strict();

export type LegacyProfileObservation = z.infer<
  typeof legacyProfileObservationSchema
>;

const requiredBackupArtifacts = [
  "v1_registry",
  "migration_sidecar",
  "referenced_roots",
  "auth_snapshots",
  "hooks",
  "supervisor_metadata",
] as const;

export const backupRestorePlanSchema = z
  .object({
    archiveId: migrationOpaqueIdSchema,
    encryption: z.enum(["age", "kms", "other-aead"]),
    manifestEncrypted: z.literal(true),
    fileMode: z.literal(SIDECAR_MODE),
    requiredArtifacts: z.tuple([
      z.literal(requiredBackupArtifacts[0]),
      z.literal(requiredBackupArtifacts[1]),
      z.literal(requiredBackupArtifacts[2]),
      z.literal(requiredBackupArtifacts[3]),
      z.literal(requiredBackupArtifacts[4]),
      z.literal(requiredBackupArtifacts[5]),
    ]),
    databasePitrRequired: z.literal(true),
    restoreDrillRequired: z.literal(true),
    requiredBytes: z.number().int().nonnegative().safe(),
  })
  .strict();

export type BackupRestorePlan = Readonly<
  z.infer<typeof backupRestorePlanSchema>
>;

export const migrationSourceDigestsSchema = z
  .object({
    v1Registry: migrationDigestSchema,
    sessionCatalog: migrationDigestSchema,
    hooks: migrationDigestSchema,
    supervisor: migrationDigestSchema,
  })
  .strict();

const migrationPlanInputSchema = z
  .object({
    scope: registryScopeSchema,
    machineId: machineIdSchema,
    createdAt: timestampSchema,
    cutoverEpoch: timestampSchema,
    sourceDigests: migrationSourceDigestsSchema,
    backup: backupRestorePlanSchema,
    observations: z.array(legacyProfileObservationSchema),
  })
  .strict()
  .superRefine((input, context) => {
    if (input.cutoverEpoch < input.createdAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["cutoverEpoch"],
        message: "cutoverEpoch must not precede plan creation",
      });
    }
    const observedBytes = input.observations.reduce(
      (total, observation) =>
        total +
        (observation.root.state === "verified"
          ? observation.root.byteCount
          : 0),
      0,
    );
    if (input.backup.requiredBytes < observedBytes) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["backup", "requiredBytes"],
        message: "backup requiredBytes must cover every verified root byte",
      });
    }
  });

export type MigrationPlanInput = Readonly<
  z.infer<typeof migrationPlanInputSchema>
>;

const quarantineReasonSchema = z.enum([
  "same_name_cross_runtime",
  "duplicate_legacy_identity",
  "duplicate_verified_root",
  "root_missing",
  "root_foreign",
  "root_nested",
  "root_traversal",
  "root_symlink",
  "root_unreadable",
  "root_divergent",
  "catalog_skip",
]);

export type MigrationQuarantineReason = z.infer<typeof quarantineReasonSchema>;

const migrationTargetSchema = z
  .object({
    accountId: accountIdSchema,
    runtimeId: runtimeIdSchema,
    bindingId: bindingIdSchema,
  })
  .strict();

const readyDispositionSchema = z.object({ state: z.literal("ready") }).strict();
const quarantinedDispositionSchema = z
  .object({
    state: z.literal("quarantined"),
    reasons: z.array(quarantineReasonSchema).min(1),
  })
  .strict();

const migrationRecordSchema = z
  .object({
    sourceKey: legacyKeySchema,
    source: legacyProfileObservationSchema.shape.source,
    runtimeLabel: legacyProfileObservationSchema.shape.runtimeLabel,
    inputDigest: migrationDigestSchema,
    target: migrationTargetSchema,
    root: migrationRootObservationSchema,
    authentication: legacyProfileObservationSchema.shape.authentication,
    pointers: pointerObservationSchema,
    sessionReferenceDigests: z.array(migrationDigestSchema),
    catalogSkipDigests: z.array(migrationDigestSchema),
    historicalAliases: canonicalHistoricalAliasSchema,
    historicalSessionAliases: canonicalHistoricalSessionAliasSchema,
    binding: machineBindingSchema.optional(),
    disposition: z.discriminatedUnion("state", [
      readyDispositionSchema,
      quarantinedDispositionSchema,
    ]),
  })
  .strict()
  .superRefine((record, context) => {
    if (record.sourceKey !== sourceKeyFromSource(record.source)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sourceKey"],
        message:
          "migration sourceKey must match its structured source identity",
      });
    }
    if (record.disposition.state === "ready" && !record.binding) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding"],
        message: "ready migration record requires a machine binding",
      });
    }
    if (record.disposition.state === "quarantined" && record.binding) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding"],
        message:
          "quarantined migration record may not install a machine binding",
      });
    }
    if (
      record.binding &&
      (record.binding.id !== record.target.bindingId ||
        record.binding.accountId !== record.target.accountId ||
        record.binding.runtimeId !== record.target.runtimeId)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding"],
        message: "migration binding identity must match its frozen target",
      });
    }
    if (
      record.binding &&
      record.root.state === "verified" &&
      record.binding.rootPath !== record.root.realPath
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding", "rootPath"],
        message:
          "migration binding root must match its verified canonical root",
      });
    }
    if (
      record.binding &&
      record.binding.authentication !== record.authentication
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding", "authentication"],
        message:
          "migration binding authentication must match the frozen observation",
      });
    }
    if (record.binding && record.binding.generation !== 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding", "generation"],
        message: "migration binding must begin at generation zero",
      });
    }
    if (record.binding && record.binding.credentialRef !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding", "credentialRef"],
        message: "migration sidecar may not carry credential references",
      });
    }
  });

export type MigrationRecord = Readonly<z.infer<typeof migrationRecordSchema>>;

type RuntimeDefinitionCarrier = Readonly<{
  source: Readonly<{ tool: string }>;
  runtimeLabel: string;
}>;

type RuntimeDefinitionRecord = RuntimeDefinitionCarrier &
  Readonly<{
    target: Readonly<{ runtimeId: RuntimeId }>;
  }>;

type CanonicalRuntimeDefinition = readonly [
  legacyTool: string,
  runtimeLabel: string,
];

interface RuntimeDefinitionConflict {
  index: number;
  runtimeId: RuntimeId;
}

function canonicalRuntimeDefinition(
  value: RuntimeDefinitionCarrier,
): CanonicalRuntimeDefinition {
  return [value.source.tool, value.runtimeLabel] as const;
}

function sameRuntimeDefinition(
  left: CanonicalRuntimeDefinition,
  right: CanonicalRuntimeDefinition,
): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

function runtimeDefinitionIdentity(
  value: RuntimeDefinitionCarrier,
): MigrationDigest {
  return hashCanonical(canonicalRuntimeDefinition(value));
}

function findRuntimeDefinitionConflicts(
  records: readonly RuntimeDefinitionRecord[],
): readonly RuntimeDefinitionConflict[] {
  const definitionByRuntimeId = new Map<
    RuntimeId,
    CanonicalRuntimeDefinition
  >();
  const runtimeIdByDefinition = new Map<MigrationDigest, RuntimeId>();
  const conflicts: RuntimeDefinitionConflict[] = [];

  for (const [index, record] of records.entries()) {
    const definition = canonicalRuntimeDefinition(record);
    const existingDefinition = definitionByRuntimeId.get(
      record.target.runtimeId,
    );
    if (
      existingDefinition &&
      !sameRuntimeDefinition(existingDefinition, definition)
    ) {
      conflicts.push({ index, runtimeId: record.target.runtimeId });
    } else {
      definitionByRuntimeId.set(record.target.runtimeId, definition);
    }

    const identity = runtimeDefinitionIdentity(record);
    const existingRuntimeId = runtimeIdByDefinition.get(identity);
    if (
      existingRuntimeId !== undefined &&
      existingRuntimeId !== record.target.runtimeId
    ) {
      conflicts.push({ index, runtimeId: record.target.runtimeId });
    } else {
      runtimeIdByDefinition.set(identity, record.target.runtimeId);
    }
  }

  return conflicts;
}

function assertRuntimeDefinitionConsistency(
  records: readonly RuntimeDefinitionRecord[],
): void {
  const conflicts = findRuntimeDefinitionConflicts(records);
  if (conflicts.length === 0) return;
  throw new MigrationConflictError(
    "runtime id maps to conflicting migration definitions",
    {
      code: "migration_runtime_definition_conflict",
      count: conflicts.length + 1,
      references: conflicts.map((conflict) =>
        diagnosticReference("diagnostic.runtime-id", conflict.runtimeId),
      ),
    },
  );
}

export const migrationPlanSchema = z
  .object({
    schemaVersion: z.literal(1),
    id: migrationOpaqueIdSchema,
    idempotencyKey: migrationDigestSchema,
    inputDigest: migrationDigestSchema,
    scope: registryScopeSchema,
    machineId: machineIdSchema,
    createdAt: timestampSchema,
    cutoverEpoch: timestampSchema,
    sourceDigests: migrationSourceDigestsSchema,
    backup: backupRestorePlanSchema,
    records: z.array(migrationRecordSchema),
    planDigest: migrationDigestSchema,
  })
  .strict()
  .superRefine((plan, context) => {
    const sourceKeys = new Set<string>();
    const accountIds = new Set<string>();
    const bindingIds = new Set<string>();
    const legacyAccountAliases = new Set<string>();
    const sessionAliases = new Set<string>();
    const identifierKinds = new Map<string, MigrationIdKind>();
    const claimIdentifier = (
      value: string,
      kind: MigrationIdKind,
      path: (string | number)[],
    ) => {
      const existingKind = identifierKinds.get(value);
      if (existingKind && existingKind !== kind) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path,
          message:
            "migration identifiers must be globally unique across entity kinds",
        });
      } else {
        identifierKinds.set(value, kind);
      }
    };
    claimIdentifier(plan.id, "plan", ["id"]);
    for (const [index, record] of plan.records.entries()) {
      if (
        index > 0 &&
        plan.records[index - 1]!.sourceKey.localeCompare(record.sourceKey) >= 0
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["records", index, "sourceKey"],
          message: "migration plan records must use canonical source-key order",
        });
      }
      for (const [value, values, label] of [
        [record.sourceKey, sourceKeys, "source key"],
        [record.target.accountId, accountIds, "account id"],
        [record.target.bindingId, bindingIds, "binding id"],
      ] as const) {
        if (values.has(value)) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["records", index],
            message: `migration plan contains duplicate ${label}`,
          });
        }
        values.add(value);
      }
      claimIdentifier(record.target.accountId, "account", [
        "records",
        index,
        "target",
        "accountId",
      ]);
      claimIdentifier(record.target.runtimeId, "runtime", [
        "records",
        index,
        "target",
        "runtimeId",
      ]);
      claimIdentifier(record.target.bindingId, "binding", [
        "records",
        index,
        "target",
        "bindingId",
      ]);
      for (const [aliases, claims, label, path] of [
        [
          record.historicalAliases,
          legacyAccountAliases,
          "legacy account alias",
          "historicalAliases",
        ],
        [
          record.historicalSessionAliases,
          sessionAliases,
          "session alias",
          "historicalSessionAliases",
        ],
      ] as const) {
        for (const [aliasIndex, alias] of aliases.entries()) {
          if (claims.has(alias)) {
            context.addIssue({
              code: z.ZodIssueCode.custom,
              path: ["records", index, path, aliasIndex],
              message: `migration plan contains duplicate ${label}`,
            });
          }
          claims.add(alias);
        }
      }
      if (
        record.binding &&
        (record.binding.tenantId !== plan.scope.tenantId ||
          record.binding.scopeId !== plan.scope.scopeId ||
          record.binding.machineId !== plan.machineId)
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["records", index, "binding"],
          message:
            "migration binding must remain inside the frozen plan scope and machine",
        });
      }
    }
    for (const conflict of findRuntimeDefinitionConflicts(plan.records)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["records", conflict.index, "target", "runtimeId"],
        message:
          "migration runtime identity must map one-to-one to its canonical definition",
      });
    }
    const reconstructedInputResult = migrationPlanInputSchema.safeParse(
      migrationPlanInputFromPlan(plan),
    );
    if (!reconstructedInputResult.success) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["records"],
        message: "migration plan does not reconstruct a valid frozen census",
      });
    } else {
      const reconstructedInput = normalizeMigrationPlanInput(
        reconstructedInputResult.data,
      );
      if (plan.inputDigest !== hashCanonical(reconstructedInput)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["inputDigest"],
          message:
            "migration plan input digest does not match its frozen census",
        });
      }
      for (const [index, record] of plan.records.entries()) {
        const expectedReasons = deriveMigrationQuarantineReasons(
          reconstructedInput.observations[index]!,
          reconstructedInput.observations,
        );
        const dispositionMatches =
          expectedReasons.length === 0
            ? record.disposition.state === "ready"
            : record.disposition.state === "quarantined" &&
              hashCanonical(record.disposition.reasons) ===
                hashCanonical(expectedReasons);
        if (!dispositionMatches) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["records", index, "disposition"],
            message:
              "migration record disposition must match the frozen conflict census",
          });
        }
      }
    }
    const expectedIdempotencyKey = hashCanonical({
      planId: plan.id,
      inputDigest: plan.inputDigest,
      scope: plan.scope,
      cutoverEpoch: plan.cutoverEpoch,
    });
    if (plan.idempotencyKey !== expectedIdempotencyKey) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["idempotencyKey"],
        message:
          "migration plan idempotency key does not match its frozen identity",
      });
    }
    const { planDigest: _planDigest, ...planCore } = plan;
    if (plan.planDigest !== hashCanonical(planCore)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["planDigest"],
        message:
          "migration plan digest does not match its complete frozen plan",
      });
    }
  });

export type MigrationPlan = Readonly<z.infer<typeof migrationPlanSchema>>;

export const migrationIdKindSchema = z.enum([
  "plan",
  "runtime",
  "account",
  "binding",
]);
export type MigrationIdKind = z.infer<typeof migrationIdKindSchema>;
export type MigrationIdFactory = (
  kind: MigrationIdKind,
  seed: string,
) => string;

export interface BuildMigrationPlanOptions {
  idFactory?: MigrationIdFactory;
  existingPlan?: MigrationPlan;
}

const buildMigrationPlanOptionsSchema = z
  .object({
    idFactory: z
      .custom<MigrationIdFactory>((value) => typeof value === "function")
      .optional(),
    existingPlan: migrationPlanSchema.optional(),
  })
  .strict();

function frozenPlanOutputIdentity(plan: MigrationPlan) {
  return {
    id: plan.id,
    idempotencyKey: plan.idempotencyKey,
    records: plan.records.map((record) => ({
      sourceKey: record.sourceKey,
      target: record.target,
      binding: record.binding,
      disposition: record.disposition,
    })),
  };
}

function assertFrozenPlanOutputIdentity(
  existing: MigrationPlan,
  expected: MigrationPlan,
): void {
  if (
    hashCanonical(frozenPlanOutputIdentity(existing)) ===
    hashCanonical(frozenPlanOutputIdentity(expected))
  ) {
    return;
  }

  const expectedRecords = new Map(
    expected.records.map((record) => [record.sourceKey, record]),
  );
  const references: MigrationDiagnosticReference[] = [
    diagnosticReference("diagnostic.plan", existing.id),
  ];
  for (const record of existing.records) {
    const expectedRecord = expectedRecords.get(record.sourceKey);
    if (
      !expectedRecord ||
      hashCanonical({
        sourceKey: record.sourceKey,
        target: record.target,
        binding: record.binding,
        disposition: record.disposition,
      }) !==
        hashCanonical({
          sourceKey: expectedRecord.sourceKey,
          target: expectedRecord.target,
          binding: expectedRecord.binding,
          disposition: expectedRecord.disposition,
        })
    ) {
      references.push(
        diagnosticReference("diagnostic.source-key", record.sourceKey),
      );
    }
  }

  throw new MigrationDriftError(
    "migration frozen output identity changed for plan",
    {
      code: "migration_frozen_output_identity_changed",
      references,
    },
  );
}

export class MigrationConflictError extends AccountsError {
  readonly code: string;
  readonly count?: number;
  readonly references: readonly MigrationDiagnosticReference[];

  constructor(message: string, options: MigrationDiagnosticOptions = {}) {
    super(message);
    this.name = "MigrationConflictError";
    this.code = options.code ?? stableDiagnosticCode(message);
    this.count = options.count;
    this.references = deepFreeze([...(options.references ?? [])]);
  }

  toJSON(): Readonly<{
    name: string;
    message: string;
    code: string;
    count?: number;
    references: readonly MigrationDiagnosticReference[];
  }> {
    return deepFreeze({
      name: this.name,
      message: this.message,
      code: this.code,
      ...(this.count === undefined ? {} : { count: this.count }),
      references: this.references,
    });
  }
}

export class MigrationDriftError extends AccountsError {
  readonly code: string;
  readonly count?: number;
  readonly references: readonly MigrationDiagnosticReference[];

  constructor(message: string, options: MigrationDiagnosticOptions = {}) {
    super(message);
    this.name = "MigrationDriftError";
    this.code = options.code ?? stableDiagnosticCode(message);
    this.count = options.count;
    this.references = deepFreeze([...(options.references ?? [])]);
  }

  toJSON(): Readonly<{
    name: string;
    message: string;
    code: string;
    count?: number;
    references: readonly MigrationDiagnosticReference[];
  }> {
    return deepFreeze({
      name: this.name,
      message: this.message,
      code: this.code,
      ...(this.count === undefined ? {} : { count: this.count }),
      references: this.references,
    });
  }
}

function publicMigrationBoundary<T>(code: string, operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (
      error instanceof MigrationConflictError ||
      error instanceof MigrationDriftError
    ) {
      throw error;
    }
    throw new MigrationConflictError("migration public input was rejected", {
      code,
    });
  }
}

async function publicMigrationBoundaryAsync<T>(
  code: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof MigrationConflictError ||
      error instanceof MigrationDriftError
    ) {
      throw error;
    }
    throw new MigrationConflictError(
      "migration public operation was rejected",
      {
        code,
      },
    );
  }
}

function parsePublicMigrationSchema<TSchema extends z.ZodTypeAny>(
  schema: TSchema,
  value: unknown,
  code: string,
): z.output<TSchema> {
  try {
    const result = schema.safeParse(value);
    if (result.success) return result.data;
  } catch {
    // Getter, proxy, or coercion failures are caller-origin diagnostics too.
  }
  throw new MigrationConflictError("migration public input was rejected", {
    code,
  });
}

function normalizeMigrationPlanInput(
  input: MigrationPlanInput,
): MigrationPlanInput {
  return {
    ...input,
    sourceDigests: sortRecord(
      input.sourceDigests,
    ) as MigrationPlanInput["sourceDigests"],
    observations: input.observations
      .map((observation) => ({
        ...observation,
        root:
          observation.root.state === "verified"
            ? {
                ...observation.root,
                realPath: resolve(observation.root.realPath),
                device: canonicalDecimal(observation.root.device),
                inode: canonicalDecimal(observation.root.inode),
              }
            : observation.root,
        sessionReferenceDigests: [
          ...observation.sessionReferenceDigests,
        ].sort(),
        catalogSkipDigests: [...observation.catalogSkipDigests].sort(),
        historicalAliases: observation.historicalAliases
          .map(canonicalAlias)
          .sort(compareCanonicalText),
        historicalSessionAliases: observation.historicalSessionAliases
          .map(canonicalAlias)
          .sort(compareCanonicalText),
      }))
      .sort((left, right) => sourceKey(left).localeCompare(sourceKey(right))),
  };
}

function buildMigrationPlanInternal(
  inputValue: MigrationPlanInput,
  options: BuildMigrationPlanOptions = {},
): MigrationPlan {
  const input = normalizeMigrationPlanInput(
    migrationPlanInputSchema.parse(inputValue),
  );
  const inputDigest = hashCanonical(input);
  if (options.existingPlan) {
    const existing = migrationPlanSchema.parse(options.existingPlan);
    assertRuntimeDefinitionConsistency(existing.records);
    if (existing.inputDigest !== inputDigest) {
      throw new MigrationDriftError(
        "migration input digest changed for frozen plan",
        {
          code: "migration_frozen_input_digest_changed",
          references: [diagnosticReference("diagnostic.plan", existing.id)],
        },
      );
    }
    const existingInput = normalizeMigrationPlanInput(
      migrationPlanInputFromPlan(existing),
    );
    if (
      JSON.stringify(canonicalize(existingInput)) !==
      JSON.stringify(canonicalize(input))
    ) {
      throw new MigrationDriftError(
        "migration canonical frozen input changed for plan",
        {
          code: "migration_frozen_input_changed",
          references: [diagnosticReference("diagnostic.plan", existing.id)],
        },
      );
    }
    const { existingPlan: _existingPlan, ...freshOptions } = options;
    const expected = buildMigrationPlanInternal(input, freshOptions);
    assertFrozenPlanOutputIdentity(existing, expected);
    return deepFreeze(structuredClone(existing));
  }

  const idFactory = options.idFactory ?? defaultIdFactory;
  const planId = invokeMigrationIdFactory(idFactory, "plan", inputDigest);
  const scopedSeed = `${input.scope.tenantId}:${input.scope.scopeId}`;
  const sourceKeys = new Set<string>();
  const runtimeByTool = new Map<
    string,
    Readonly<{
      definition: CanonicalRuntimeDefinition;
      runtimeId: RuntimeId;
    }>
  >();
  const observations = [...input.observations].sort((left, right) =>
    sourceKey(left).localeCompare(sourceKey(right)),
  );

  for (const observation of observations) {
    const key = sourceKey(observation);
    if (sourceKeys.has(key)) {
      throw new MigrationConflictError("duplicate legacy source key", {
        code: "migration_duplicate_legacy_source_key",
        count: 2,
        references: [diagnosticReference("diagnostic.source-key", key)],
      });
    }
    sourceKeys.add(key);
    const definition = canonicalRuntimeDefinition(observation);
    const existingRuntime = runtimeByTool.get(observation.source.tool);
    if (
      existingRuntime &&
      !sameRuntimeDefinition(existingRuntime.definition, definition)
    ) {
      throw new MigrationConflictError(
        "legacy tool has conflicting runtime labels",
        {
          code: "migration_runtime_definition_conflict",
          count: 2,
          references: [
            diagnosticReference(
              "diagnostic.source-tool",
              observation.source.tool,
            ),
          ],
        },
      );
    }
    if (!existingRuntime) {
      runtimeByTool.set(
        observation.source.tool,
        deepFreeze({
          definition,
          runtimeId: runtimeIdSchema.parse(
            invokeMigrationIdFactory(
              idFactory,
              "runtime",
              `${scopedSeed}:${runtimeDefinitionIdentity(observation)}`,
            ),
          ),
        }),
      );
    }
  }

  const records = observations.map((observation): MigrationRecord => {
    const key = sourceKey(observation);
    const reasons = deriveMigrationQuarantineReasons(observation, observations);

    const target = migrationTargetSchema.parse({
      accountId: invokeMigrationIdFactory(
        idFactory,
        "account",
        `${scopedSeed}:${key}`,
      ),
      runtimeId: runtimeByTool.get(observation.source.tool)?.runtimeId,
      bindingId: invokeMigrationIdFactory(
        idFactory,
        "binding",
        `${scopedSeed}:${key}`,
      ),
    });

    const disposition =
      reasons.length === 0
        ? ({ state: "ready" } as const)
        : ({
            state: "quarantined",
            reasons,
          } as const);

    const binding =
      disposition.state === "ready" && observation.root.state === "verified"
        ? machineBindingSchema.parse({
            id: target.bindingId,
            tenantId: input.scope.tenantId,
            scopeId: input.scope.scopeId,
            accountId: target.accountId,
            runtimeId: target.runtimeId,
            machineId: input.machineId,
            rootPath: observation.root.realPath,
            authentication: observation.authentication,
            generation: 0,
          })
        : undefined;

    return migrationRecordSchema.parse({
      sourceKey: key,
      source: observation.source,
      runtimeLabel: observation.runtimeLabel,
      inputDigest: observation.inputDigest,
      target,
      root: observation.root,
      authentication: observation.authentication,
      pointers: observation.pointers,
      sessionReferenceDigests: [...observation.sessionReferenceDigests].sort(),
      catalogSkipDigests: [...observation.catalogSkipDigests].sort(),
      historicalAliases: [...observation.historicalAliases].sort(
        compareCanonicalText,
      ),
      historicalSessionAliases: [...observation.historicalSessionAliases].sort(
        compareCanonicalText,
      ),
      ...(binding ? { binding } : {}),
      disposition,
    });
  });

  const planCore = {
    schemaVersion: 1,
    id: planId,
    idempotencyKey: hashCanonical({
      planId,
      inputDigest,
      scope: input.scope,
      cutoverEpoch: input.cutoverEpoch,
    }),
    inputDigest,
    scope: input.scope,
    machineId: input.machineId,
    createdAt: input.createdAt,
    cutoverEpoch: input.cutoverEpoch,
    sourceDigests: sortRecord(input.sourceDigests),
    backup: input.backup,
    records,
  } as const;
  const plan = migrationPlanSchema.parse({
    ...planCore,
    planDigest: hashCanonical(planCore),
  });
  return deepFreeze(plan);
}

export function buildMigrationPlan(
  inputValue: MigrationPlanInput,
  options: BuildMigrationPlanOptions = {},
): MigrationPlan {
  const input = parsePublicMigrationSchema(
    migrationPlanInputSchema,
    inputValue,
    "migration_invalid_plan_input",
  );
  const parsedOptions = parsePublicMigrationSchema(
    buildMigrationPlanOptionsSchema,
    options,
    "migration_invalid_plan_input",
  );
  return publicMigrationBoundary("migration_invalid_plan_input", () =>
    buildMigrationPlanInternal(input, parsedOptions),
  );
}

function rootQuarantineReason(
  code: z.infer<typeof unsafeRootCodeSchema>,
): MigrationQuarantineReason {
  const value = `root_${code}`;
  return quarantineReasonSchema.parse(value);
}

function sourceKey(observation: LegacyProfileObservation): string {
  return sourceKeyFromSource(observation.source);
}

function sourceKeyFromSource(
  source: LegacyProfileObservation["source"],
): string {
  return [source.authority, source.authorityId, source.tool, source.name].join(
    ":",
  );
}

function deriveMigrationQuarantineReasons(
  observation: LegacyProfileObservation,
  observations: readonly LegacyProfileObservation[],
): MigrationQuarantineReason[] {
  const reasons = new Set<MigrationQuarantineReason>();
  const nameGroup = observations.filter(
    (candidate) => candidate.source.name === observation.source.name,
  );
  if (nameGroup.length > 1) {
    const runtimeKeys = new Set(
      nameGroup.map((candidate) => candidate.source.tool),
    );
    reasons.add(
      runtimeKeys.size > 1
        ? "same_name_cross_runtime"
        : "duplicate_legacy_identity",
    );
  }
  if (observation.root.state === "verified") {
    const canonicalPath = resolve(observation.root.realPath);
    const physicalIdentity = verifiedRootDeviceInodeKey(observation.root);
    if (
      observations.filter(
        (candidate) =>
          candidate.root.state === "verified" &&
          (resolve(candidate.root.realPath) === canonicalPath ||
            verifiedRootDeviceInodeKey(candidate.root) === physicalIdentity),
      ).length > 1
    ) {
      reasons.add("duplicate_verified_root");
    }
  } else {
    reasons.add(rootQuarantineReason(observation.root.code));
  }
  if (observation.catalogSkipDigests.length > 0) reasons.add("catalog_skip");
  return [...reasons].sort();
}

function verifiedRootDeviceInodeKey(
  root: z.infer<typeof verifiedRootObservationSchema>,
): string {
  return `${canonicalDecimal(root.device)}\0${canonicalDecimal(root.inode)}`;
}

function canonicalDecimal(value: string): string {
  return BigInt(value).toString(10);
}

function compareCanonicalText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalAlias(value: string): string {
  return value.normalize("NFC");
}

function canonicalRuntimeLabel(value: string): string {
  return value.normalize("NFC").trim().replace(/\s+/gu, " ");
}

function defaultIdFactory(kind: MigrationIdKind, seed: string): string {
  return `${kind}_${createHash("sha256")
    .update(`accounts-v2-migration:${kind}:${seed}`)
    .digest("hex")
    .slice(0, 32)}`;
}

function invokeMigrationIdFactory(
  idFactory: MigrationIdFactory,
  kind: MigrationIdKind,
  seed: string,
): string {
  try {
    return migrationOpaqueIdSchema.parse(idFactory(kind, seed));
  } catch {
    throw new MigrationConflictError(
      "migration identifier allocation was rejected",
      { code: "migration_id_allocation_failed" },
    );
  }
}

function migrationPlanInputFromPlan(plan: MigrationPlan): MigrationPlanInput {
  return {
    scope: plan.scope,
    machineId: plan.machineId,
    createdAt: plan.createdAt,
    cutoverEpoch: plan.cutoverEpoch,
    sourceDigests: plan.sourceDigests,
    backup: plan.backup,
    observations: plan.records.map((record) => ({
      source: record.source,
      runtimeLabel: record.runtimeLabel,
      inputDigest: record.inputDigest,
      root: record.root,
      authentication: record.authentication,
      pointers: record.pointers,
      sessionReferenceDigests: [...record.sessionReferenceDigests],
      catalogSkipDigests: [...record.catalogSkipDigests],
      historicalAliases: [...record.historicalAliases],
      historicalSessionAliases: [...record.historicalSessionAliases],
    })),
  };
}

export interface RedactedMigrationRecord {
  sourceKeyDigest: MigrationDigest;
  source: {
    authority: z.infer<typeof sourceAuthoritySchema>;
    authorityIdDigest: MigrationDigest;
    toolDigest: MigrationDigest;
    nameDigest: MigrationDigest;
  };
  runtimeLabelDigest: MigrationDigest;
  inputDigest: MigrationDigest;
  target: MigrationRecord["target"];
  root:
    | {
        state: "verified";
        pathDigest: MigrationDigest;
        realPathDigest: MigrationDigest;
        deviceDigest: MigrationDigest;
        inodeDigest: MigrationDigest;
        entryCount: number;
        byteCount: number;
        digest: MigrationDigest;
      }
    | {
        state: "unsafe";
        code: z.infer<typeof unsafeRootCodeSchema>;
        pathDigest: MigrationDigest;
        reasonDigest: MigrationDigest;
      };
  authentication: MigrationRecord["authentication"];
  pointers: MigrationRecord["pointers"];
  sessionReferenceDigests: readonly MigrationDigest[];
  catalogSkipDigests: readonly MigrationDigest[];
  historicalAliasDigests: readonly MigrationDigest[];
  historicalSessionAliasDigests: readonly MigrationDigest[];
  disposition: MigrationRecord["disposition"];
}

export interface RedactedMigrationPlan {
  schemaVersion: 1;
  redactionVersion: 1;
  id: string;
  idempotencyKey: MigrationDigest;
  inputDigest: MigrationDigest;
  planDigest: MigrationDigest;
  scope: RegistryScope;
  machineIdDigest: MigrationDigest;
  createdAt: string;
  cutoverEpoch: string;
  sourceDigests: Readonly<Record<string, MigrationDigest>>;
  backup: BackupRestorePlan;
  records: readonly RedactedMigrationRecord[];
}

function redactMigrationPlanInternal(
  planInput: MigrationPlan,
): RedactedMigrationPlan {
  const plan = migrationPlanSchema.parse(planInput);
  assertRuntimeDefinitionConsistency(plan.records);
  return deepFreeze({
    schemaVersion: 1 as const,
    redactionVersion: 1 as const,
    id: plan.id,
    idempotencyKey: plan.idempotencyKey,
    inputDigest: plan.inputDigest,
    planDigest: plan.planDigest,
    scope: plan.scope,
    machineIdDigest: migrationRedactionDigest("machine", plan.machineId),
    createdAt: plan.createdAt,
    cutoverEpoch: plan.cutoverEpoch,
    sourceDigests: plan.sourceDigests,
    backup: plan.backup,
    records: plan.records.map((record) => {
      const [legacyTool, runtimeLabel] = canonicalRuntimeDefinition(record);
      return {
        sourceKeyDigest: migrationRedactionDigest(
          "source.key",
          record.sourceKey,
        ),
        source: {
          authority: record.source.authority,
          authorityIdDigest: migrationRedactionDigest(
            "source.authority-id",
            record.source.authorityId,
          ),
          toolDigest: migrationRedactionDigest("source.tool", legacyTool),
          nameDigest: migrationRedactionDigest(
            "source.name",
            record.source.name,
          ),
        },
        runtimeLabelDigest: migrationRedactionDigest(
          "runtime.label",
          runtimeLabel,
        ),
        inputDigest: record.inputDigest,
        target: record.target,
        root:
          record.root.state === "verified"
            ? {
                state: "verified" as const,
                pathDigest: migrationRedactionDigest(
                  "root.path",
                  record.root.path,
                ),
                realPathDigest: migrationRedactionDigest(
                  "root.real-path",
                  record.root.realPath,
                ),
                deviceDigest: migrationRedactionDigest(
                  "root.device",
                  record.root.device,
                ),
                inodeDigest: migrationRedactionDigest(
                  "root.inode",
                  record.root.inode,
                ),
                entryCount: record.root.entryCount,
                byteCount: record.root.byteCount,
                digest: record.root.digest,
              }
            : {
                state: record.root.state,
                code: record.root.code,
                pathDigest: migrationRedactionDigest(
                  "root.path",
                  record.root.pathDigest,
                ),
                reasonDigest: migrationRedactionDigest(
                  "root.unsafe-reason",
                  record.root.reason,
                ),
              },
        authentication: record.authentication,
        pointers: record.pointers,
        sessionReferenceDigests: record.sessionReferenceDigests,
        catalogSkipDigests: record.catalogSkipDigests,
        historicalAliasDigests: record.historicalAliases.map((alias) =>
          migrationRedactionDigest("alias", alias),
        ),
        historicalSessionAliasDigests: record.historicalSessionAliases.map(
          (alias) => migrationRedactionDigest("alias.session", alias),
        ),
        disposition: record.disposition,
      };
    }),
  });
}

export function redactMigrationPlan(
  planInput: MigrationPlan,
): RedactedMigrationPlan {
  const plan = parsePublicMigrationSchema(
    migrationPlanSchema,
    planInput,
    "migration_invalid_redaction_plan",
  );
  return publicMigrationBoundary("migration_invalid_redaction_plan", () =>
    redactMigrationPlanInternal(plan),
  );
}

const backupRestoreEvidenceSchema = z
  .object({
    archiveId: migrationOpaqueIdSchema,
    encrypted: z.boolean(),
    manifestEncrypted: z.boolean(),
    fileMode: z.number().int().nonnegative(),
    verifiedArtifacts: z.array(z.enum(requiredBackupArtifacts)),
    databasePitrVerified: z.boolean(),
    restoreDrillVerified: z.boolean(),
    restoredAt: timestampSchema,
    cutoverEpoch: timestampSchema,
  })
  .strict();

const migrationGateEvidenceSchema = z
  .object({
    planId: migrationOpaqueIdSchema,
    idempotencyKey: migrationDigestSchema,
    cutoverEpoch: timestampSchema,
    activeWriters: z.array(z.string().min(1).max(256).regex(SAFE_TEXT_PATTERN)),
    observedDigests: z.record(migrationDigestSchema),
    availableBytes: z.number().int().nonnegative().safe(),
    unknownLedgerEntries: z.array(
      z.string().min(1).max(256).regex(SAFE_TEXT_PATTERN),
    ),
    checksumMismatches: z.array(
      z.string().min(1).max(256).regex(SAFE_TEXT_PATTERN),
    ),
    unresolvedCatalogSkipDigests: z.array(migrationDigestSchema),
    backupRestore: backupRestoreEvidenceSchema,
  })
  .strict();

export type MigrationGateEvidence = Readonly<
  z.infer<typeof migrationGateEvidenceSchema>
>;
export const migrationGateIntentSchema = z.enum(["partial", "final"]);
export type MigrationGateIntent = z.infer<typeof migrationGateIntentSchema>;
export const migrationStateSchema = z.enum([
  "planned",
  "partial_ready",
  "partial_applied",
  "final_ready",
  "final_applied",
]);
export type MigrationState = z.infer<typeof migrationStateSchema>;

export interface MigrationGateResult {
  intent: MigrationGateIntent;
  ready: boolean;
  nextState: "partial_ready" | "final_ready" | null;
  reasons: readonly string[];
}

const migrationGateReceiptCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    sequence: z.number().int().positive().safe(),
    intent: migrationGateIntentSchema,
    targetState: z.enum(["partial_ready", "final_ready"]),
    sourceIntegrityDigest: migrationDigestSchema,
    planId: migrationOpaqueIdSchema,
    idempotencyKey: migrationDigestSchema,
    evidence: migrationGateEvidenceSchema,
  })
  .strict();

const migrationGateReceiptSchema = migrationGateReceiptCoreSchema
  .extend({
    digest: migrationDigestSchema,
  })
  .strict();

export type MigrationGateReceipt = Readonly<
  z.infer<typeof migrationGateReceiptSchema>
>;

const ensureResultSchema = z.enum(["created", "adopted"]);
type EnsureResult = z.infer<typeof ensureResultSchema>;

const migrationBackfillCountsSchema = z
  .object({
    runtimes: z
      .object({
        created: z.number().int().nonnegative().safe(),
        adopted: z.number().int().nonnegative().safe(),
      })
      .strict(),
    accounts: z
      .object({
        created: z.number().int().nonnegative().safe(),
        adopted: z.number().int().nonnegative().safe(),
      })
      .strict(),
    crosswalks: z
      .object({
        created: z.number().int().nonnegative().safe(),
        adopted: z.number().int().nonnegative().safe(),
      })
      .strict(),
    epoch: ensureResultSchema,
  })
  .strict();

type MigrationBackfillCounts = z.infer<typeof migrationBackfillCountsSchema>;

const migrationBackfillReceiptCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    sequence: z.number().int().positive().safe(),
    planId: migrationOpaqueIdSchema,
    idempotencyKey: migrationDigestSchema,
    scope: registryScopeSchema,
    readyState: z.enum(["partial_ready", "final_ready"]),
    sourceIntegrityDigest: migrationDigestSchema,
    readyRecordsDigest: migrationDigestSchema,
    result: migrationBackfillCountsSchema,
  })
  .strict();

const migrationBackfillReceiptSchema = migrationBackfillReceiptCoreSchema
  .extend({
    digest: migrationDigestSchema,
  })
  .strict();

export type MigrationBackfillReceipt = Readonly<
  z.infer<typeof migrationBackfillReceiptSchema>
>;

function evaluateMigrationGatesInternal(
  planInput: MigrationPlan,
  evidenceInput: MigrationGateEvidence,
  intent: MigrationGateIntent,
): MigrationGateResult {
  const plan = migrationPlanSchema.parse(planInput);
  const evidence = migrationGateEvidenceSchema.parse(evidenceInput);
  const parsedIntent = migrationGateIntentSchema.parse(intent);
  const reasons = new Set<string>();

  if (
    evidence.planId !== plan.id ||
    evidence.idempotencyKey !== plan.idempotencyKey
  ) {
    reasons.add("plan_identity_mismatch");
  }
  if (
    evidence.cutoverEpoch !== plan.cutoverEpoch ||
    evidence.backupRestore.cutoverEpoch !== plan.cutoverEpoch
  ) {
    reasons.add("cutover_epoch_mismatch");
  }
  if (evidence.activeWriters.length > 0) reasons.add("active_writers");
  if (
    hashCanonical(sortRecord(evidence.observedDigests)) !==
    hashCanonical(plan.sourceDigests)
  ) {
    reasons.add("input_digest_drift");
  }
  if (evidence.availableBytes < plan.backup.requiredBytes) {
    reasons.add("insufficient_free_space");
  }
  if (evidence.unknownLedgerEntries.length > 0)
    reasons.add("unknown_ledger_entry");
  if (evidence.checksumMismatches.length > 0) reasons.add("checksum_mismatch");
  if (evidence.unresolvedCatalogSkipDigests.length > 0)
    reasons.add("catalog_skip");

  const backup = evidence.backupRestore;
  if (
    backup.archiveId !== plan.backup.archiveId ||
    !backup.encrypted ||
    !backup.manifestEncrypted ||
    backup.fileMode !== SIDECAR_MODE ||
    !backup.databasePitrVerified ||
    !backup.restoreDrillVerified ||
    !hasAllRequiredArtifacts(backup.verifiedArtifacts)
  ) {
    reasons.add("restore_unverified");
  }
  if (backup.restoredAt > plan.cutoverEpoch) {
    reasons.add("restore_after_cutover_epoch");
  }
  if (backup.restoredAt < plan.createdAt) {
    reasons.add("restore_before_plan_creation");
  }

  const quarantined = plan.records.some(
    (record) => record.disposition.state === "quarantined",
  );
  const readyRecords = plan.records.some(
    (record) => record.disposition.state === "ready",
  );
  if (parsedIntent === "final" && quarantined) {
    reasons.add("unresolved_quarantine");
  }
  if (parsedIntent === "partial" && !readyRecords) {
    reasons.add("no_ready_records");
  }

  return deepFreeze({
    intent: parsedIntent,
    ready: reasons.size === 0,
    nextState:
      reasons.size === 0
        ? parsedIntent === "partial"
          ? "partial_ready"
          : "final_ready"
        : null,
    reasons: [...reasons],
  });
}

export function evaluateMigrationGates(
  planInput: MigrationPlan,
  evidenceInput: MigrationGateEvidence,
  intent: MigrationGateIntent,
): MigrationGateResult {
  const parsedIntent = parsePublicMigrationSchema(
    migrationGateIntentSchema,
    intent,
    "migration_invalid_gate_intent",
  );
  const plan = parsePublicMigrationSchema(
    migrationPlanSchema,
    planInput,
    "migration_invalid_gate_input",
  );
  const evidence = parsePublicMigrationSchema(
    migrationGateEvidenceSchema,
    evidenceInput,
    "migration_invalid_gate_input",
  );
  return publicMigrationBoundary("migration_invalid_gate_input", () =>
    evaluateMigrationGatesInternal(plan, evidence, parsedIntent),
  );
}

function hasAllRequiredArtifacts(values: readonly string[]): boolean {
  const actual = new Set(values);
  return (
    actual.size === requiredBackupArtifacts.length &&
    requiredBackupArtifacts.every((artifact) => actual.has(artifact))
  );
}

const migrationAliasInputSchema = z
  .object({
    kind: migrationAliasKindSchema,
    alias: canonicalAliasSchema,
    sourceKey: legacyKeySchema,
    targetId: migrationOpaqueIdSchema,
  })
  .strict();

export type MigrationAliasInput = Readonly<
  z.infer<typeof migrationAliasInputSchema>
>;

const migrationAliasEntrySchema = migrationAliasInputSchema
  .extend({
    sequence: z.number().int().positive().safe(),
    previousDigest: migrationDigestSchema.nullable(),
    digest: migrationDigestSchema,
  })
  .strict();

export type MigrationAliasEntry = Readonly<
  z.infer<typeof migrationAliasEntrySchema>
>;

const migrationTransitionEntryCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    sequence: z.number().int().positive().safe(),
    previousDigest: migrationDigestSchema.nullable(),
    sourceState: migrationStateSchema,
    targetState: migrationStateSchema,
    sourceIntegrityDigest: migrationDigestSchema,
    sourceAliasJournalLength: z.number().int().nonnegative().safe(),
    sourceGateReceiptCount: z.number().int().nonnegative().safe(),
    sourceBackfillReceiptCount: z.number().int().nonnegative().safe(),
  })
  .strict();

const migrationTransitionEntrySchema = migrationTransitionEntryCoreSchema
  .extend({
    digest: migrationDigestSchema,
  })
  .strict();

export type MigrationTransitionEntry = Readonly<
  z.infer<typeof migrationTransitionEntrySchema>
>;

const migrationSidecarCoreSchema = z
  .object({
    schemaVersion: z.literal(1),
    plan: migrationPlanSchema,
    state: migrationStateSchema,
    aliasJournal: z.array(migrationAliasEntrySchema),
    gateReceipts: z.array(migrationGateReceiptSchema),
    backfillReceipts: z.array(migrationBackfillReceiptSchema),
    transitionJournal: z.array(migrationTransitionEntrySchema),
  })
  .strict();

export const migrationSidecarSchema = migrationSidecarCoreSchema
  .extend({
    integrityDigest: migrationDigestSchema,
  })
  .strict();

export type MigrationSidecar = Readonly<z.infer<typeof migrationSidecarSchema>>;

function createMigrationSidecarInternal(
  planInput: MigrationPlan,
): MigrationSidecar {
  const plan = migrationPlanSchema.parse(planInput);
  return withSidecarIntegrity({
    schemaVersion: 1,
    plan,
    state: "planned",
    aliasJournal: canonicalGenesisAliasJournal(plan),
    gateReceipts: [],
    backfillReceipts: [],
    transitionJournal: [],
  });
}

export function createMigrationSidecar(
  planInput: MigrationPlan,
): MigrationSidecar {
  const plan = parsePublicMigrationSchema(
    migrationPlanSchema,
    planInput,
    "migration_invalid_sidecar_plan",
  );
  return publicMigrationBoundary("migration_invalid_sidecar_plan", () =>
    createMigrationSidecarInternal(plan),
  );
}

function appendMigrationAliasInternal(
  sidecarInput: MigrationSidecar,
  aliasInput: MigrationAliasInput,
): MigrationSidecar {
  const sidecar = parseSidecar(sidecarInput);
  const aliasJournal = appendAliasToJournal(
    sidecar.plan,
    sidecar.aliasJournal,
    aliasInput,
  );
  if (aliasJournal === sidecar.aliasJournal) return sidecar;
  return withSidecarIntegrity({
    schemaVersion: 1,
    plan: sidecar.plan,
    state: sidecar.state,
    aliasJournal,
    gateReceipts: sidecar.gateReceipts,
    backfillReceipts: sidecar.backfillReceipts,
    transitionJournal: sidecar.transitionJournal,
  });
}

export function appendMigrationAlias(
  sidecarInput: MigrationSidecar,
  aliasInput: MigrationAliasInput,
): MigrationSidecar {
  const sidecar = parsePublicMigrationSchema(
    migrationSidecarSchema,
    sidecarInput,
    "migration_invalid_alias_input",
  );
  const alias = parsePublicMigrationSchema(
    migrationAliasInputSchema,
    aliasInput,
    "migration_invalid_alias_input",
  );
  return publicMigrationBoundary("migration_invalid_alias_input", () =>
    appendMigrationAliasInternal(sidecar, alias),
  );
}

function canonicalGenesisAliasJournal(
  plan: MigrationPlan,
): MigrationSidecar["aliasJournal"] {
  let entries: MigrationSidecar["aliasJournal"] = [];
  const expectedAliasCount = plan.records.reduce(
    (count, record) =>
      count +
      record.historicalAliases.length +
      record.historicalSessionAliases.length,
    0,
  );
  for (const record of plan.records) {
    for (const alias of record.historicalAliases) {
      entries = appendAliasToJournal(plan, entries, {
        kind: "legacy_account",
        alias,
        sourceKey: record.sourceKey,
        targetId: record.target.accountId,
      });
    }
    for (const alias of record.historicalSessionAliases) {
      entries = appendAliasToJournal(plan, entries, {
        kind: "session_ref",
        alias,
        sourceKey: record.sourceKey,
        targetId: record.target.bindingId,
      });
    }
  }
  if (entries.length !== expectedAliasCount) {
    throw new MigrationDriftError(
      "migration plan aliases do not exactly correspond to canonical genesis",
    );
  }
  return entries;
}

function appendAliasToJournal(
  plan: MigrationPlan,
  entries: MigrationSidecar["aliasJournal"],
  aliasInput: MigrationAliasInput,
): MigrationSidecar["aliasJournal"] {
  const alias = migrationAliasInputSchema.parse(aliasInput);
  const record = plan.records.find(
    (candidate) => candidate.sourceKey === alias.sourceKey,
  );
  if (!record) {
    throw new MigrationConflictError(
      "migration alias source is not in the frozen plan",
      {
        code: "migration_alias_source_not_in_plan",
        references: [
          diagnosticReference("diagnostic.source-key", alias.sourceKey),
          diagnosticAliasReference(alias.kind, alias.alias),
        ],
      },
    );
  }
  const expectedTarget =
    alias.kind === "legacy_account"
      ? record.target.accountId
      : record.target.bindingId;
  if (alias.targetId !== expectedTarget) {
    throw new MigrationConflictError(
      "migration alias does not target its frozen immutable identity",
      {
        code: "migration_alias_target_mismatch",
        references: [
          diagnosticReference("diagnostic.source-key", alias.sourceKey),
          diagnosticAliasReference(alias.kind, alias.alias),
        ],
      },
    );
  }
  const existing = entries.find(
    (entry) => entry.kind === alias.kind && entry.alias === alias.alias,
  );
  if (existing) {
    if (
      existing.sourceKey === alias.sourceKey &&
      existing.targetId === alias.targetId
    ) {
      return entries;
    }
    throw new MigrationConflictError(
      "migration alias already targets a different immutable identity",
      {
        code: "migration_alias_identity_conflict",
        count: 2,
        references: [diagnosticAliasReference(alias.kind, alias.alias)],
      },
    );
  }
  const previousDigest = entries.at(-1)?.digest ?? null;
  const entry = migrationAliasEntrySchema.parse({
    ...alias,
    sequence: entries.length + 1,
    previousDigest,
    digest: hashCanonical({
      ...alias,
      sequence: entries.length + 1,
      previousDigest,
    }),
  });
  return [...entries, entry];
}

const stateRank: Record<MigrationState, number> = {
  planned: 0,
  partial_ready: 1,
  partial_applied: 2,
  final_ready: 3,
  final_applied: 4,
};

const allowedTransitions: Readonly<
  Record<MigrationState, readonly MigrationState[]>
> = {
  planned: ["partial_ready", "final_ready"],
  partial_ready: ["partial_applied"],
  partial_applied: ["final_ready"],
  final_ready: ["final_applied"],
  final_applied: [],
};

export interface TransitionMigrationSidecarOptions {
  gateEvidence?: MigrationGateEvidence;
  backfillReceipt?: MigrationBackfillReceipt;
}

const transitionMigrationSidecarOptionsSchema = z
  .object({
    gateEvidence: migrationGateEvidenceSchema.optional(),
    backfillReceipt: migrationBackfillReceiptSchema.optional(),
  })
  .strict();

function transitionMigrationSidecarInternal(
  sidecarInput: MigrationSidecar,
  target: MigrationState,
  options: TransitionMigrationSidecarOptions = {},
): MigrationSidecar {
  const sidecar = parseSidecar(sidecarInput);
  const parsedTarget = migrationStateSchema.parse(target);
  const parsedOptions = transitionMigrationSidecarOptionsSchema.parse(options);
  if (parsedTarget === sidecar.state) return sidecar;
  if (stateRank[parsedTarget] < stateRank[sidecar.state]) {
    throw new MigrationConflictError("cannot move migration state backwards");
  }
  if (!allowedTransitions[sidecar.state].includes(parsedTarget)) {
    throw new MigrationConflictError(
      `invalid migration state transition ${sidecar.state} -> ${parsedTarget}`,
    );
  }
  let gateReceipts = sidecar.gateReceipts;
  let backfillReceipts = sidecar.backfillReceipts;
  if (parsedTarget === "partial_ready" || parsedTarget === "final_ready") {
    if (!parsedOptions.gateEvidence) {
      throw new MigrationConflictError(
        `entering ${parsedTarget} requires current migration gate evidence`,
      );
    }
    const gate = evaluateMigrationGates(
      sidecar.plan,
      parsedOptions.gateEvidence,
      parsedTarget === "partial_ready" ? "partial" : "final",
    );
    if (!gate.ready || gate.nextState !== parsedTarget) {
      throw new MigrationConflictError(
        `migration gates block ${parsedTarget}: ${gate.reasons.join(", ")}`,
      );
    }
    const evidence = migrationGateEvidenceSchema.parse(
      parsedOptions.gateEvidence,
    );
    const receiptCore = migrationGateReceiptCoreSchema.parse({
      schemaVersion: 1,
      sequence: sidecar.gateReceipts.length + 1,
      intent: parsedTarget === "partial_ready" ? "partial" : "final",
      targetState: parsedTarget,
      sourceIntegrityDigest: sidecar.integrityDigest,
      planId: sidecar.plan.id,
      idempotencyKey: sidecar.plan.idempotencyKey,
      evidence,
    });
    gateReceipts = [
      ...sidecar.gateReceipts,
      migrationGateReceiptSchema.parse({
        ...receiptCore,
        digest: hashCanonical(receiptCore),
      }),
    ];
  }
  if (parsedTarget === "partial_applied" || parsedTarget === "final_applied") {
    if (!parsedOptions.backfillReceipt) {
      throw new MigrationConflictError(
        `entering ${parsedTarget} requires a committed scope-bound backfill receipt`,
      );
    }
    const receipt = migrationBackfillReceiptSchema.parse(
      parsedOptions.backfillReceipt,
    );
    validateBackfillReceipt(sidecar.plan, receipt);
    const expectedReadyState =
      parsedTarget === "partial_applied" ? "partial_ready" : "final_ready";
    if (
      receipt.readyState !== expectedReadyState ||
      receipt.sourceIntegrityDigest !== sidecar.integrityDigest ||
      receipt.sequence !== sidecar.backfillReceipts.length + 1
    ) {
      throw new MigrationConflictError(
        `backfill receipt does not bind the exact ${expectedReadyState} predecessor`,
      );
    }
    backfillReceipts = [...sidecar.backfillReceipts, receipt];
  }
  if (
    (parsedTarget === "final_ready" || parsedTarget === "final_applied") &&
    sidecar.plan.records.some(
      (record) => record.disposition.state === "quarantined",
    )
  ) {
    throw new MigrationConflictError(
      "cannot enter final migration state with unresolved quarantine",
    );
  }
  const transitionCore = migrationTransitionEntryCoreSchema.parse({
    schemaVersion: 1,
    sequence: sidecar.transitionJournal.length + 1,
    previousDigest: sidecar.transitionJournal.at(-1)?.digest ?? null,
    sourceState: sidecar.state,
    targetState: parsedTarget,
    sourceIntegrityDigest: sidecar.integrityDigest,
    sourceAliasJournalLength: sidecar.aliasJournal.length,
    sourceGateReceiptCount: sidecar.gateReceipts.length,
    sourceBackfillReceiptCount: sidecar.backfillReceipts.length,
  });
  const transition = migrationTransitionEntrySchema.parse({
    ...transitionCore,
    digest: hashCanonical(transitionCore),
  });
  return withSidecarIntegrity({
    schemaVersion: 1,
    plan: sidecar.plan,
    state: parsedTarget,
    aliasJournal: sidecar.aliasJournal,
    gateReceipts,
    backfillReceipts,
    transitionJournal: [...sidecar.transitionJournal, transition],
  });
}

export function transitionMigrationSidecar(
  sidecarInput: MigrationSidecar,
  target: MigrationState,
  options: TransitionMigrationSidecarOptions = {},
): MigrationSidecar {
  const parsedTarget = parsePublicMigrationSchema(
    migrationStateSchema,
    target,
    "migration_invalid_transition_target",
  );
  const sidecar = parsePublicMigrationSchema(
    migrationSidecarSchema,
    sidecarInput,
    "migration_invalid_transition_input",
  );
  const parsedOptions = parsePublicMigrationSchema(
    transitionMigrationSidecarOptionsSchema,
    options,
    "migration_invalid_transition_input",
  );
  return publicMigrationBoundary("migration_invalid_transition_input", () =>
    transitionMigrationSidecarInternal(sidecar, parsedTarget, parsedOptions),
  );
}

function withSidecarIntegrity(
  coreInput: z.input<typeof migrationSidecarCoreSchema>,
): MigrationSidecar {
  const core = migrationSidecarCoreSchema.parse(coreInput);
  return deepFreeze(
    migrationSidecarSchema.parse({
      ...core,
      integrityDigest: hashCanonical(core),
    }),
  );
}

function parseSidecar(value: unknown): MigrationSidecar {
  const sidecar = migrationSidecarSchema.parse(value);
  const { integrityDigest: _integrityDigest, ...coreValue } = sidecar;
  const core = migrationSidecarCoreSchema.parse(coreValue);
  if (hashCanonical(core) !== sidecar.integrityDigest) {
    throw new MigrationDriftError(
      "migration sidecar integrity digest mismatch",
    );
  }
  validateAliasJournal(sidecar.plan, sidecar.aliasJournal);
  const canonicalAliasCount = validateCanonicalGenesisAliasPrefix(
    sidecar.plan,
    sidecar.aliasJournal,
  );
  validateTransitionReceipts(sidecar, canonicalAliasCount);
  return deepFreeze(sidecar);
}

function validateCanonicalGenesisAliasPrefix(
  plan: MigrationPlan,
  entries: readonly MigrationAliasEntry[],
): number {
  const canonical = canonicalGenesisAliasJournal(plan);
  if (entries.length < canonical.length) {
    throw new MigrationDriftError(
      "migration alias journal omits its canonical genesis alias prefix",
    );
  }
  for (const [index, entry] of canonical.entries()) {
    if (hashCanonical(entries[index]) !== hashCanonical(entry)) {
      throw new MigrationDriftError(
        "migration alias journal changed its canonical genesis alias prefix",
      );
    }
  }
  return canonical.length;
}

function validateTransitionReceipts(
  sidecar: MigrationSidecar,
  canonicalAliasCount: number,
): void {
  for (const [index, receipt] of sidecar.gateReceipts.entries()) {
    validateGateReceipt(sidecar.plan, receipt);
    if (receipt.sequence !== index + 1) {
      throw new MigrationDriftError(
        "migration gate receipt sequence is invalid",
      );
    }
  }
  for (const [index, receipt] of sidecar.backfillReceipts.entries()) {
    validateBackfillReceipt(sidecar.plan, receipt);
    if (receipt.sequence !== index + 1) {
      throw new MigrationDriftError(
        "migration backfill receipt sequence is invalid",
      );
    }
  }

  const gates = sidecar.gateReceipts;
  const backfills = sidecar.backfillReceipts;
  const partialGate = gates[0]?.targetState === "partial_ready";
  const finalGate = gates.at(-1)?.targetState === "final_ready";
  const partialBackfill = backfills[0]?.readyState === "partial_ready";
  const finalBackfill = backfills.at(-1)?.readyState === "final_ready";
  const valid =
    (sidecar.state === "planned" &&
      gates.length === 0 &&
      backfills.length === 0) ||
    (sidecar.state === "partial_ready" &&
      gates.length === 1 &&
      partialGate &&
      backfills.length === 0) ||
    (sidecar.state === "partial_applied" &&
      gates.length === 1 &&
      partialGate &&
      backfills.length === 1 &&
      partialBackfill) ||
    (sidecar.state === "final_ready" &&
      finalGate &&
      ((gates.length === 1 && backfills.length === 0) ||
        (gates.length === 2 &&
          partialGate &&
          backfills.length === 1 &&
          partialBackfill))) ||
    (sidecar.state === "final_applied" &&
      finalGate &&
      finalBackfill &&
      gates.length === backfills.length &&
      (gates.length === 1 ||
        (gates.length === 2 && partialGate && partialBackfill)));
  if (!valid) {
    const requiredReceipt =
      sidecar.state === "partial_ready" || sidecar.state === "final_ready"
        ? "durable gate receipt"
        : sidecar.state === "planned"
          ? "empty receipt"
          : "durable backfill receipt";
    throw new MigrationDriftError(
      `migration state "${sidecar.state}" lacks its required ${requiredReceipt} history`,
    );
  }
  validatePredecessorTransitionChain(sidecar, canonicalAliasCount);
}

function validatePredecessorTransitionChain(
  sidecar: MigrationSidecar,
  canonicalAliasCount: number,
): void {
  let expectedState: MigrationState = "planned";
  let expectedGateReceiptCount = 0;
  let expectedBackfillReceiptCount = 0;
  let minimumAliasJournalLength = canonicalAliasCount;
  let previousDigest: MigrationDigest | null = null;

  for (const [index, entry] of sidecar.transitionJournal.entries()) {
    const { digest, ...coreValue } = entry;
    const core = migrationTransitionEntryCoreSchema.parse(coreValue);
    const sourceCore = migrationSidecarCoreSchema.parse({
      schemaVersion: 1,
      plan: sidecar.plan,
      state: entry.sourceState,
      aliasJournal: sidecar.aliasJournal.slice(
        0,
        entry.sourceAliasJournalLength,
      ),
      gateReceipts: sidecar.gateReceipts.slice(0, entry.sourceGateReceiptCount),
      backfillReceipts: sidecar.backfillReceipts.slice(
        0,
        entry.sourceBackfillReceiptCount,
      ),
      transitionJournal: sidecar.transitionJournal.slice(0, index),
    });
    const structurallyValid =
      entry.sequence === index + 1 &&
      entry.previousDigest === previousDigest &&
      entry.digest === hashCanonical(core) &&
      entry.sourceState === expectedState &&
      allowedTransitions[entry.sourceState].includes(entry.targetState) &&
      entry.sourceAliasJournalLength >= minimumAliasJournalLength &&
      entry.sourceAliasJournalLength <= sidecar.aliasJournal.length &&
      entry.sourceGateReceiptCount === expectedGateReceiptCount &&
      entry.sourceBackfillReceiptCount === expectedBackfillReceiptCount &&
      entry.sourceIntegrityDigest === hashCanonical(sourceCore);
    if (!structurallyValid) {
      throw new MigrationDriftError(
        "migration receipt predecessor transition chain is invalid",
      );
    }

    if (
      entry.targetState === "partial_ready" ||
      entry.targetState === "final_ready"
    ) {
      const receipt = sidecar.gateReceipts[expectedGateReceiptCount];
      if (
        !receipt ||
        receipt.sourceIntegrityDigest !== entry.sourceIntegrityDigest ||
        receipt.targetState !== entry.targetState
      ) {
        throw new MigrationDriftError(
          "migration receipt predecessor transition chain is invalid",
        );
      }
      expectedGateReceiptCount += 1;
    } else {
      const receipt = sidecar.backfillReceipts[expectedBackfillReceiptCount];
      const expectedReadyState =
        entry.targetState === "partial_applied"
          ? "partial_ready"
          : "final_ready";
      if (
        !receipt ||
        receipt.sourceIntegrityDigest !== entry.sourceIntegrityDigest ||
        receipt.readyState !== expectedReadyState
      ) {
        throw new MigrationDriftError(
          "migration receipt predecessor transition chain is invalid",
        );
      }
      expectedBackfillReceiptCount += 1;
    }

    expectedState = entry.targetState;
    minimumAliasJournalLength = entry.sourceAliasJournalLength;
    previousDigest = entry.digest;
  }

  if (
    expectedState !== sidecar.state ||
    expectedGateReceiptCount !== sidecar.gateReceipts.length ||
    expectedBackfillReceiptCount !== sidecar.backfillReceipts.length
  ) {
    throw new MigrationDriftError(
      "migration receipt predecessor transition chain is invalid",
    );
  }
}

function validateGateReceipt(
  plan: MigrationPlan,
  receiptInput: MigrationGateReceipt,
): void {
  const receipt = migrationGateReceiptSchema.parse(receiptInput);
  const { digest, ...coreValue } = receipt;
  const core = migrationGateReceiptCoreSchema.parse(coreValue);
  if (hashCanonical(core) !== digest) {
    throw new MigrationDriftError("migration gate receipt digest is invalid");
  }
  if (
    receipt.planId !== plan.id ||
    receipt.idempotencyKey !== plan.idempotencyKey
  ) {
    throw new MigrationDriftError(
      "migration gate receipt plan identity is invalid",
    );
  }
  const gate = evaluateMigrationGates(plan, receipt.evidence, receipt.intent);
  if (!gate.ready || gate.nextState !== receipt.targetState) {
    throw new MigrationDriftError(
      "migration gate receipt does not contain accepted evidence for its target state",
    );
  }
}

function validateAliasJournal(
  plan: MigrationPlan,
  entries: readonly MigrationAliasEntry[],
): void {
  let previousDigest: MigrationDigest | null = null;
  const aliases = new Set<string>();
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    const aliasKey = `${entry.kind}\0${entry.alias}`;
    if (aliases.has(aliasKey)) {
      throw new MigrationDriftError(
        "migration alias journal contains a duplicate alias",
      );
    }
    aliases.add(aliasKey);
    if (
      entry.sequence !== index + 1 ||
      entry.previousDigest !== previousDigest
    ) {
      throw new MigrationDriftError(
        "migration alias journal sequence or chain is invalid",
      );
    }
    const record = plan.records.find(
      (candidate) => candidate.sourceKey === entry.sourceKey,
    );
    const expectedTarget =
      entry.kind === "legacy_account"
        ? record?.target.accountId
        : record?.target.bindingId;
    if (!record || entry.targetId !== expectedTarget) {
      throw new MigrationDriftError(
        "migration alias journal does not target its frozen source identity",
      );
    }
    const expected = hashCanonical({
      kind: entry.kind,
      alias: entry.alias,
      sourceKey: entry.sourceKey,
      targetId: entry.targetId,
      sequence: entry.sequence,
      previousDigest: entry.previousDigest,
    });
    if (entry.digest !== expected) {
      throw new MigrationDriftError(
        "migration alias journal digest is invalid",
      );
    }
    previousDigest = entry.digest;
  }
}

export interface ScopedBackfillRuntime {
  id: RuntimeId;
  tenantId: RegistryScope["tenantId"];
  scopeId: RegistryScope["scopeId"];
  key: string;
  label: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScopedBackfillAccount {
  id: AccountId;
  tenantId: RegistryScope["tenantId"];
  scopeId: RegistryScope["scopeId"];
  name: string;
  runtimeId: RuntimeId;
  createdAt: string;
  updatedAt: string;
}

export interface ScopedBackfillCrosswalk {
  sourceKey: string;
  sourceAuthority: z.infer<typeof sourceAuthoritySchema>;
  sourceAuthorityId: string;
  legacyTool: string;
  legacyName: string;
  accountId: AccountId;
  runtimeId: RuntimeId;
  bindingId: BindingId;
}

export interface MigrationBackfillTransaction {
  ensureRuntime(runtime: ScopedBackfillRuntime): Promise<EnsureResult>;
  ensureAccount(account: ScopedBackfillAccount): Promise<EnsureResult>;
  ensureCrosswalk(crosswalk: ScopedBackfillCrosswalk): Promise<EnsureResult>;
  recordEpoch(input: {
    planId: string;
    idempotencyKey: string;
    cutoverEpoch: string;
  }): Promise<EnsureResult>;
}

export interface MigrationBackfillPort {
  transaction<T>(
    scope: RegistryScope,
    operation: (transaction: MigrationBackfillTransaction) => Promise<T>,
  ): Promise<T>;
}

export const migrationBackfillPortSchema = z
  .object({
    transaction: z.custom<MigrationBackfillPort["transaction"]>(
      (value) => typeof value === "function",
    ),
  })
  .strict();

export interface MigrationBackfillResult {
  runtimes: { created: number; adopted: number };
  accounts: { created: number; adopted: number };
  crosswalks: { created: number; adopted: number };
  epoch: EnsureResult;
  receipt: MigrationBackfillReceipt;
}

async function applyScopedBackfillInternal(
  sidecarInput: MigrationSidecar,
  port: MigrationBackfillPort,
): Promise<MigrationBackfillResult> {
  const sidecar = parseSidecar(sidecarInput);
  if (sidecar.state !== "partial_ready" && sidecar.state !== "final_ready") {
    throw new MigrationConflictError(
      "scoped backfill requires a gate-approved partial_ready or final_ready sidecar",
    );
  }
  assertRuntimeDefinitionConsistency(sidecar.plan.records);
  const records = sidecar.plan.records.filter(
    (record): record is MigrationRecord & { disposition: { state: "ready" } } =>
      record.disposition.state === "ready",
  );
  const runtimes = new Map<RuntimeId, ScopedBackfillRuntime>();
  for (const record of records) {
    const [legacyTool, runtimeLabel] = canonicalRuntimeDefinition(record);
    const runtime: ScopedBackfillRuntime = {
      id: record.target.runtimeId,
      tenantId: sidecar.plan.scope.tenantId,
      scopeId: sidecar.plan.scope.scopeId,
      key: legacyTool,
      label: runtimeLabel,
      createdAt: sidecar.plan.createdAt,
      updatedAt: sidecar.plan.createdAt,
    };
    const existing = runtimes.get(runtime.id);
    if (existing && hashCanonical(existing) !== hashCanonical(runtime)) {
      throw new MigrationConflictError(
        "runtime id maps to conflicting migration definitions",
        {
          code: "migration_runtime_definition_conflict",
          count: 2,
          references: [
            diagnosticReference("diagnostic.runtime-id", runtime.id),
          ],
        },
      );
    }
    runtimes.set(runtime.id, runtime);
  }

  let result: MigrationBackfillCounts;
  try {
    let callbackInvocationCount = 0;
    let callbackCompleted = false;
    let capturedResult: MigrationBackfillCounts | undefined;
    const transactionResult = await port.transaction(
      sidecar.plan.scope,
      async (transaction) => {
        callbackInvocationCount += 1;
        if (callbackInvocationCount !== 1) {
          throw new MigrationConflictError(
            "migration backfill transaction callback must run exactly once",
          );
        }
        const counts: MigrationBackfillCounts = {
          runtimes: { created: 0, adopted: 0 },
          accounts: { created: 0, adopted: 0 },
          crosswalks: { created: 0, adopted: 0 },
          epoch: "created",
        };

        for (const runtime of [...runtimes.values()].sort((a, b) =>
          a.id.localeCompare(b.id),
        )) {
          tally(
            counts.runtimes,
            await transaction.ensureRuntime(deepFreeze(runtime)),
          );
        }
        for (const record of [...records].sort((a, b) =>
          a.sourceKey.localeCompare(b.sourceKey),
        )) {
          const account: ScopedBackfillAccount = {
            id: record.target.accountId,
            tenantId: sidecar.plan.scope.tenantId,
            scopeId: sidecar.plan.scope.scopeId,
            name: record.source.name,
            runtimeId: record.target.runtimeId,
            createdAt: sidecar.plan.createdAt,
            updatedAt: sidecar.plan.createdAt,
          };
          tally(
            counts.accounts,
            await transaction.ensureAccount(deepFreeze(account)),
          );
        }
        for (const record of [...records].sort((a, b) =>
          a.sourceKey.localeCompare(b.sourceKey),
        )) {
          const [legacyTool] = canonicalRuntimeDefinition(record);
          const crosswalk: ScopedBackfillCrosswalk = {
            sourceKey: record.sourceKey,
            sourceAuthority: record.source.authority,
            sourceAuthorityId: record.source.authorityId,
            legacyTool,
            legacyName: record.source.name,
            accountId: record.target.accountId,
            runtimeId: record.target.runtimeId,
            bindingId: record.target.bindingId,
          };
          tally(
            counts.crosswalks,
            await transaction.ensureCrosswalk(deepFreeze(crosswalk)),
          );
        }
        counts.epoch = ensureResultSchema.parse(
          await transaction.recordEpoch({
            planId: sidecar.plan.id,
            idempotencyKey: sidecar.plan.idempotencyKey,
            cutoverEpoch: sidecar.plan.cutoverEpoch,
          }),
        );
        capturedResult = deepFreeze(
          migrationBackfillCountsSchema.parse(counts),
        );
        callbackCompleted = true;
        return capturedResult;
      },
    );
    if (
      callbackInvocationCount !== 1 ||
      !callbackCompleted ||
      capturedResult === undefined ||
      transactionResult !== capturedResult
    ) {
      throw new MigrationConflictError(
        "migration backfill transaction callback contract was violated",
      );
    }
    result = capturedResult;
  } catch {
    throw new MigrationConflictError(
      "migration backfill port operation was rejected",
      { code: "migration_backfill_failed" },
    );
  }

  const receiptCore = migrationBackfillReceiptCoreSchema.parse({
    schemaVersion: 1,
    sequence: sidecar.backfillReceipts.length + 1,
    planId: sidecar.plan.id,
    idempotencyKey: sidecar.plan.idempotencyKey,
    scope: sidecar.plan.scope,
    readyState: sidecar.state,
    sourceIntegrityDigest: sidecar.integrityDigest,
    readyRecordsDigest: readyRecordsDigest(sidecar.plan),
    result,
  });
  const receipt = migrationBackfillReceiptSchema.parse({
    ...receiptCore,
    digest: hashCanonical(receiptCore),
  });
  return deepFreeze({
    ...result,
    receipt,
  });
}

export async function applyScopedBackfill(
  sidecarInput: MigrationSidecar,
  port: MigrationBackfillPort,
): Promise<MigrationBackfillResult> {
  const sidecar = parsePublicMigrationSchema(
    migrationSidecarSchema,
    sidecarInput,
    "migration_backfill_failed",
  );
  parsePublicMigrationSchema(
    migrationBackfillPortSchema,
    port,
    "migration_backfill_failed",
  );
  return publicMigrationBoundaryAsync("migration_backfill_failed", () =>
    applyScopedBackfillInternal(sidecar, port),
  );
}

function tally(
  counter: { created: number; adopted: number },
  value: EnsureResult,
): void {
  counter[ensureResultSchema.parse(value)] += 1;
}

function readyRecordsDigest(plan: MigrationPlan): MigrationDigest {
  assertRuntimeDefinitionConsistency(plan.records);
  return hashCanonical(
    plan.records.filter((record) => record.disposition.state === "ready"),
  );
}

function validateBackfillReceipt(
  plan: MigrationPlan,
  receiptInput: MigrationBackfillReceipt,
): void {
  assertRuntimeDefinitionConsistency(plan.records);
  const receipt = migrationBackfillReceiptSchema.parse(receiptInput);
  const { digest, ...coreValue } = receipt;
  const core = migrationBackfillReceiptCoreSchema.parse(coreValue);
  if (hashCanonical(core) !== digest) {
    throw new MigrationDriftError(
      "migration backfill receipt digest is invalid",
    );
  }
  if (
    receipt.planId !== plan.id ||
    receipt.idempotencyKey !== plan.idempotencyKey ||
    hashCanonical(receipt.scope) !== hashCanonical(plan.scope) ||
    receipt.readyRecordsDigest !== readyRecordsDigest(plan)
  ) {
    throw new MigrationDriftError(
      "migration backfill receipt is not bound to the frozen plan and scope",
    );
  }
  const readyRecords = plan.records.filter(
    (record) => record.disposition.state === "ready",
  );
  const runtimeCount = new Set(
    readyRecords.map((record) => record.target.runtimeId),
  ).size;
  if (
    receipt.result.runtimes.created + receipt.result.runtimes.adopted !==
      runtimeCount ||
    receipt.result.accounts.created + receipt.result.accounts.adopted !==
      readyRecords.length ||
    receipt.result.crosswalks.created + receipt.result.crosswalks.adopted !==
      readyRecords.length
  ) {
    throw new MigrationDriftError(
      "migration backfill receipt counts do not cover the frozen ready records",
    );
  }
}

export const migrationCompatibilityFixtureSchema = z
  .object({
    schemaVersion: z.literal(1),
    cases: z.array(
      z
        .object({
          client: z.enum(["old", "transition", "new"]),
          server: z.enum(["old", "transition", "new"]),
          result: z.enum([
            "v1_unchanged",
            "v1_projection",
            "preflight_only",
            "sidecar_backfill",
            "upgrade_required",
            "requires_final_cutover",
            "v2",
          ]),
          writes: z.enum(["none", "v1_only", "journaled_v2", "v2_only"]),
        })
        .strict(),
    ),
  })
  .strict()
  .superRefine((fixture, context) => {
    const versions = ["old", "transition", "new"] as const;
    const seen = new Set<string>();
    for (const [index, entry] of fixture.cases.entries()) {
      const key = `${entry.client}->${entry.server}`;
      if (seen.has(key)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["cases", index],
          message: `compatibility matrix contains duplicate case ${key}`,
        });
      }
      seen.add(key);
    }
    for (const client of versions) {
      for (const server of versions) {
        const key = `${client}->${server}`;
        if (!seen.has(key)) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["cases"],
            message: `compatibility matrix is missing case ${key}`,
          });
        }
      }
    }
    if (fixture.cases.length !== versions.length ** 2) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["cases"],
        message:
          "compatibility matrix must contain exactly one complete 3x3 grid",
      });
    }
  });

const migrationWalSchema = z
  .object({
    schemaVersion: z.literal(1),
    planId: migrationOpaqueIdSchema,
    idempotencyKey: migrationDigestSchema,
    previousDigest: migrationDigestSchema.nullable(),
    nextDigest: migrationDigestSchema,
    nextSidecar: migrationSidecarSchema,
  })
  .strict();

type MigrationWal = z.infer<typeof migrationWalSchema>;

export const migrationDurabilityEventSchema = z.enum([
  "wal_file_fsync",
  "wal_rename",
  "wal_directory_fsync",
  "sidecar_file_fsync",
  "sidecar_rename",
  "sidecar_directory_fsync",
  "wal_remove",
  "cleanup_directory_fsync",
]);
export type MigrationDurabilityEvent = z.infer<
  typeof migrationDurabilityEventSchema
>;

export const migrationSidecarFailurePointSchema = z.enum([
  "after_wal_file_fsync",
  "after_wal_rename",
  "after_wal_directory_fsync",
  "after_sidecar_file_fsync",
  "after_sidecar_rename",
  "after_sidecar_directory_fsync",
  "before_wal_remove",
  "after_wal_remove",
]);
export type MigrationSidecarFailurePoint = z.infer<
  typeof migrationSidecarFailurePointSchema
>;

export interface MigrationSidecarStoreOptions {
  sidecarPath: string;
  legacyStorePath: string;
  injectFailure?: (point: MigrationSidecarFailurePoint) => void;
  onDurabilityEvent?: (event: MigrationDurabilityEvent) => void;
}

export interface MigrationSidecarInstallOptions {
  expectedPreviousDigest?: MigrationDigest | null;
}

const migrationSidecarStoreOptionsSchema = z
  .object({
    sidecarPath: z.string().min(1),
    legacyStorePath: z.string().min(1),
    injectFailure: z
      .custom<NonNullable<MigrationSidecarStoreOptions["injectFailure"]>>(
        (value) => typeof value === "function",
      )
      .optional(),
    onDurabilityEvent: z
      .custom<NonNullable<MigrationSidecarStoreOptions["onDurabilityEvent"]>>(
        (value) => typeof value === "function",
      )
      .optional(),
  })
  .strict();

const migrationSidecarInstallOptionsSchema = z
  .object({
    expectedPreviousDigest: migrationDigestSchema.nullable().optional(),
  })
  .strict();

interface WriterLockReclaimToken {
  readonly path: string;
  readonly descriptor: number;
}

interface MigrationSidecarStorePaths {
  readonly directory: string;
  readonly sidecar: string;
  readonly sidecarStaging: string;
  readonly wal: string;
  readonly walStaging: string;
  readonly lock: string;
  readonly guarded: readonly string[];
  readonly mutableEntries: readonly string[];
}

function deriveMigrationSidecarStorePaths(
  sidecarPathInput: string,
): MigrationSidecarStorePaths {
  const sidecar = resolve(sidecarPathInput);
  const directory = dirname(sidecar);
  const sidecarStaging = `${sidecar}.tmp`;
  const wal = `${sidecar}.wal`;
  const walStaging = `${wal}.tmp`;
  const lock = `${sidecar}.lock`;
  const mutableEntries = Object.freeze([
    sidecar,
    sidecarStaging,
    wal,
    walStaging,
    lock,
  ]);
  return Object.freeze({
    directory,
    sidecar,
    sidecarStaging,
    wal,
    walStaging,
    lock,
    mutableEntries,
    guarded: Object.freeze([directory, ...mutableEntries]),
  });
}

export class MigrationSidecarStore {
  readonly #paths: MigrationSidecarStorePaths;
  readonly #legacyStorePath: string;
  readonly #injectFailure?: (point: MigrationSidecarFailurePoint) => void;
  readonly #onDurabilityEvent?: (event: MigrationDurabilityEvent) => void;

  constructor(options: MigrationSidecarStoreOptions) {
    const parsedOptions = parsePublicMigrationSchema(
      migrationSidecarStoreOptionsSchema,
      options,
      "migration_invalid_store_options",
    );
    this.#paths = deriveMigrationSidecarStorePaths(parsedOptions.sidecarPath);
    this.#legacyStorePath = resolve(parsedOptions.legacyStorePath);
    this.#injectFailure = parsedOptions.injectFailure;
    this.#onDurabilityEvent = parsedOptions.onDurabilityEvent;
    this.#storeBoundary("migration_store_initialization_failed", () =>
      this.#assertGuardedPathsDistinctFromLegacy(),
    );
  }

  toJSON(): Readonly<{
    schemaVersion: 1;
    kind: "migration_sidecar_store";
  }> {
    return deepFreeze({
      schemaVersion: 1 as const,
      kind: "migration_sidecar_store" as const,
    });
  }

  load(): MigrationSidecar | null {
    return this.#storeBoundary("migration_store_read_failed", () => {
      this.#assertGuardedPathsDistinctFromLegacy();
      if (!existsSync(this.#paths.sidecar)) return null;
      assertPrivateRegularFile(this.#paths.sidecar, "migration sidecar");
      const contents = readPrivateRegularFileNoFollow(
        this.#paths.sidecar,
        "migration sidecar",
      ).contents;
      try {
        return parseSidecar(JSON.parse(contents));
      } catch (error) {
        if (error instanceof MigrationDriftError) throw error;
        throw new MigrationDriftError("could not parse migration sidecar", {
          code: "migration_sidecar_parse_failed",
        });
      }
    });
  }

  install(
    sidecarInput: MigrationSidecar,
    options: MigrationSidecarInstallOptions = {},
  ): MigrationSidecar {
    const parsedSidecarInput = parsePublicMigrationSchema(
      migrationSidecarSchema,
      sidecarInput,
      "migration_store_install_failed",
    );
    const parsedOptions = parsePublicMigrationSchema(
      migrationSidecarInstallOptionsSchema,
      options,
      "migration_store_install_failed",
    );
    return this.#storeBoundary("migration_store_install_failed", () => {
      const sidecar = parseSidecar(parsedSidecarInput);
      const expectedPreviousDigest = parsedOptions.expectedPreviousDigest;
      return this.#withLock(() => {
        this.#assertGuardedPathsDistinctFromLegacy();
        if (existsSync(this.#paths.wal) || existsSync(this.#paths.walStaging)) {
          throw new MigrationConflictError(
            "pending migration WAL must be repaired before another install",
          );
        }
        const current = this.load();
        if (current?.integrityDigest === sidecar.integrityDigest)
          return current;
        if (
          !current &&
          expectedPreviousDigest !== undefined &&
          expectedPreviousDigest !== null
        ) {
          throw new MigrationConflictError(
            "migration sidecar compare-and-swap expected an existing predecessor",
          );
        }
        if (!current && sidecar.state !== "planned") {
          throw new MigrationConflictError(
            "the first durable migration sidecar state must be planned",
          );
        }
        if (!current) assertCanonicalPlannedGenesis(sidecar);
        if (current && expectedPreviousDigest === undefined) {
          throw new MigrationConflictError(
            "updating a migration sidecar requires its expected previous integrity digest",
          );
        }
        if (current && expectedPreviousDigest !== current.integrityDigest) {
          throw new MigrationConflictError(
            "migration sidecar changed since it was read; refusing a stale writer",
          );
        }
        if (
          current &&
          hashCanonical(current.plan) !== hashCanonical(sidecar.plan)
        ) {
          throw new MigrationConflictError(
            "existing migration sidecar belongs to a different frozen plan",
          );
        }
        if (current) assertSidecarSuccessor(current, sidecar);
        const wal = migrationWalSchema.parse({
          schemaVersion: 1,
          planId: sidecar.plan.id,
          idempotencyKey: sidecar.plan.idempotencyKey,
          previousDigest: current?.integrityDigest ?? null,
          nextDigest: sidecar.integrityDigest,
          nextSidecar: sidecar,
        });
        this.#prepareDirectory();
        this.#writeWal(wal);
        this.#writeSidecar(sidecar);
        this.#finishWal();
        return sidecar;
      });
    });
  }

  repair(): MigrationSidecar | null {
    return this.#storeBoundary("migration_store_repair_failed", () =>
      this.#withLock(() => {
        this.#prepareDirectory();
        if (
          !existsSync(this.#paths.wal) &&
          existsSync(this.#paths.walStaging)
        ) {
          assertPrivateRegularFile(
            this.#paths.walStaging,
            "migration WAL staging file",
          );
          this.#readWal(this.#paths.walStaging);
          this.#assertGuardedPathsDistinctFromLegacy();
          renameSync(this.#paths.walStaging, this.#paths.wal);
          this.#emitDurabilityEvent("wal_rename");
          fsyncDirectory(this.#paths.directory);
          this.#emitDurabilityEvent("wal_directory_fsync");
        }
        if (!existsSync(this.#paths.wal)) return this.load();

        const wal = this.#readWal(this.#paths.wal);
        if (wal.previousDigest === null) {
          assertCanonicalPlannedGenesis(wal.nextSidecar);
        }
        let current: MigrationSidecar | null;
        try {
          current = this.load();
        } catch {
          throw new MigrationDriftError(
            "migration sidecar drift is ambiguous; preserving WAL",
            { code: "migration_sidecar_drift_ambiguous" },
          );
        }
        if (current?.integrityDigest === wal.nextDigest) {
          this.#finishWal({ allowFailureInjection: false });
          return current;
        }
        if (
          (current === null && wal.previousDigest === null) ||
          current?.integrityDigest === wal.previousDigest
        ) {
          if (current) {
            if (
              hashCanonical(current.plan) !==
              hashCanonical(wal.nextSidecar.plan)
            ) {
              throw new MigrationConflictError(
                "migration WAL successor belongs to a different frozen plan",
              );
            }
            assertSidecarSuccessor(current, wal.nextSidecar);
          }
          this.#writeSidecar(wal.nextSidecar, {
            allowFailureInjection: false,
          });
          this.#finishWal({ allowFailureInjection: false });
          return wal.nextSidecar;
        }
        throw new MigrationDriftError(
          "migration sidecar changed outside the frozen WAL transition; preserving WAL and data",
        );
      }),
    );
  }

  #prepareDirectory(): void {
    this.#assertGuardedPathsDistinctFromLegacy();
    assertSafeWritePath(this.#paths.sidecar, {
      mustStayUnder: this.#paths.directory,
    });
    assertSafeWritePath(this.#paths.sidecarStaging, {
      mustStayUnder: this.#paths.directory,
    });
    assertSafeWritePath(this.#paths.wal, {
      mustStayUnder: this.#paths.directory,
    });
    assertSafeWritePath(this.#paths.walStaging, {
      mustStayUnder: this.#paths.directory,
    });
    assertSafeWritePath(this.#paths.lock, {
      mustStayUnder: this.#paths.directory,
    });
    this.#assertGuardedPathsDistinctFromLegacy();
  }

  #assertGuardedPathsDistinctFromLegacy(): void {
    for (const candidate of this.#paths.guarded) {
      if (!pathsReferToSameFile(candidate, this.#legacyStorePath)) continue;
      throw new MigrationConflictError(
        "migration sidecar storage must not alias the configured v1 registry path",
        {
          code: "migration_store_path_rejected",
          references: [diagnosticReference("root.path", candidate)],
        },
      );
    }
  }

  #writeWal(wal: MigrationWal): void {
    this.#writeDurableFile(
      this.#paths.wal,
      JSON.stringify(wal, null, 2) + "\n",
      "wal",
      this.#paths.walStaging,
      true,
    );
  }

  #writeSidecar(
    sidecar: MigrationSidecar,
    options: { allowFailureInjection?: boolean } = {},
  ): void {
    this.#writeDurableFile(
      this.#paths.sidecar,
      JSON.stringify(sidecar, null, 2) + "\n",
      "sidecar",
      this.#paths.sidecarStaging,
      options.allowFailureInjection ?? true,
    );
  }

  #writeDurableFile(
    target: string,
    contents: string,
    kind: "wal" | "sidecar",
    temp: string,
    allowFailureInjection: boolean,
  ): void {
    this.#assertGuardedPathsDistinctFromLegacy();
    rmSync(temp, { force: true });
    this.#assertGuardedPathsDistinctFromLegacy();
    let descriptor: number | undefined;
    let completed = false;
    try {
      descriptor = openSync(temp, EXCLUSIVE_NOFOLLOW_WRITE_FLAGS, SIDECAR_MODE);
      writeFileSync(descriptor, contents, { encoding: "utf8" });
      fsyncSync(descriptor);
      this.#emitDurabilityEvent(`${kind}_file_fsync`);
      if (allowFailureInjection) {
        this.#injectFailurePoint(`after_${kind}_file_fsync`);
      }
      closeSync(descriptor);
      descriptor = undefined;
      this.#assertGuardedPathsDistinctFromLegacy();
      renameSync(temp, target);
      this.#emitDurabilityEvent(`${kind}_rename`);
      if (allowFailureInjection) {
        this.#injectFailurePoint(`after_${kind}_rename`);
      }
      fsyncDirectory(this.#paths.directory);
      this.#emitDurabilityEvent(`${kind}_directory_fsync`);
      if (allowFailureInjection) {
        this.#injectFailurePoint(`after_${kind}_directory_fsync`);
      }
      completed = true;
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      if (completed) {
        this.#assertGuardedPathsDistinctFromLegacy();
        rmSync(temp, { force: true });
      }
    }
  }

  #finishWal(options: { allowFailureInjection?: boolean } = {}): void {
    const allowFailureInjection = options.allowFailureInjection ?? true;
    if (allowFailureInjection) this.#injectFailurePoint("before_wal_remove");
    this.#assertGuardedPathsDistinctFromLegacy();
    if (existsSync(this.#paths.wal)) unlinkSync(this.#paths.wal);
    this.#assertGuardedPathsDistinctFromLegacy();
    rmSync(this.#paths.walStaging, { force: true });
    this.#emitDurabilityEvent("wal_remove");
    if (allowFailureInjection) this.#injectFailurePoint("after_wal_remove");
    fsyncDirectory(this.#paths.directory);
    this.#emitDurabilityEvent("cleanup_directory_fsync");
  }

  #emitDurabilityEvent(event: MigrationDurabilityEvent): void {
    try {
      this.#onDurabilityEvent?.(event);
    } catch {
      throw new MigrationConflictError(
        "migration durability callback was rejected",
        { code: "migration_store_callback_failed" },
      );
    }
  }

  #injectFailurePoint(point: MigrationSidecarFailurePoint): void {
    try {
      this.#injectFailure?.(point);
    } catch {
      throw new MigrationConflictError(
        "migration failure-injection callback was rejected",
        { code: "migration_store_callback_failed" },
      );
    }
  }

  #readWal(path: string): MigrationWal {
    this.#assertGuardedPathsDistinctFromLegacy();
    assertPrivateRegularFile(path, "migration WAL");
    const contents = readPrivateRegularFileNoFollow(
      path,
      "migration WAL",
    ).contents;
    try {
      const wal = migrationWalSchema.parse(JSON.parse(contents));
      const sidecar = parseSidecar(wal.nextSidecar);
      if (
        sidecar.plan.id !== wal.planId ||
        sidecar.plan.idempotencyKey !== wal.idempotencyKey ||
        sidecar.integrityDigest !== wal.nextDigest
      ) {
        throw new MigrationDriftError(
          "migration WAL identity or digest does not match its payload",
        );
      }
      return wal;
    } catch (error) {
      if (error instanceof MigrationDriftError) throw error;
      throw new MigrationDriftError("could not parse migration WAL", {
        code: "migration_wal_parse_failed",
      });
    }
  }

  #withLock<T>(operation: () => T): T {
    this.#prepareDirectory();
    const descriptor = this.#acquireLock();
    try {
      return operation();
    } finally {
      this.#releaseLock(descriptor);
    }
  }

  #acquireLock(): number {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      let descriptor: number | undefined;
      try {
        this.#assertGuardedPathsDistinctFromLegacy();
        descriptor = openSync(
          this.#paths.lock,
          EXCLUSIVE_NOFOLLOW_WRITE_FLAGS,
          SIDECAR_MODE,
        );
        writeFileSync(descriptor, `${process.pid}\n`, { encoding: "utf8" });
        fsyncSync(descriptor);
        return descriptor;
      } catch (error) {
        if (descriptor !== undefined) {
          this.#releaseLock(descriptor);
        }
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (attempt === 0 && this.#removeDeadWriterLock()) continue;
        throw new MigrationConflictError(
          "another v2 migration writer holds the sidecar lock",
        );
      }
    }
    throw new MigrationConflictError(
      "could not acquire the v2 migration writer lock",
    );
  }

  #releaseLock(descriptor: number): void {
    const openedStat = fstatSync(descriptor);
    closeSync(descriptor);
    this.#assertGuardedPathsDistinctFromLegacy();
    const currentStat = lstatIfExists(this.#paths.lock);
    if (
      !currentStat ||
      currentStat.dev !== openedStat.dev ||
      currentStat.ino !== openedStat.ino
    ) {
      throw new MigrationConflictError(
        "migration writer lock identity changed before release",
      );
    }
    unlinkSync(this.#paths.lock);
    fsyncDirectory(this.#paths.directory);
  }

  #removeDeadWriterLock(): boolean {
    this.#assertGuardedPathsDistinctFromLegacy();
    assertPrivateRegularFile(this.#paths.lock, "migration writer lock");
    const observed = readPrivateRegularFileNoFollow(
      this.#paths.lock,
      "migration writer lock",
    );
    if (!writerLockPidIsDead(observed.contents)) return false;

    // Reclaiming a dead writer lock is an observe -> verify -> unlink sequence
    // that is not atomic on its own. Two processes that observe the same dead
    // lock can both pass the device/inode identity check; the first unlinks and
    // immediately re-creates its own live lock through the O_EXCL retry, and the
    // second then unlinks that live lock and acquires the mutex as well, putting
    // two writers past a mutex whose whole purpose is to prevent that. Gate the
    // sequence behind an exclusive reclaim token named after the observed lock
    // identity, so exactly one process may reclaim a given dead lock, and re-read
    // the lock inside the token rather than trusting the earlier observation.
    //
    // The token is bound to the dead lock's device/inode, so a token abandoned by
    // a process that died inside the reclaim window cannot block reclaim of any
    // later lock (a new lock file gets a new inode). It can only block reclaim of
    // that one abandoned identity, which fails closed with
    // `migration_writer_lock_reclaim_contended` and is cleared by removing the
    // reported reclaim token. Failing closed is the intended trade against
    // admitting a second concurrent writer.
    const token = this.#openWriterLockReclaimToken(observed.stat);
    try {
      this.#assertGuardedPathsDistinctFromLegacy();
      const current = readPrivateRegularFileNoFollow(
        this.#paths.lock,
        "migration writer lock",
      );
      if (
        current.stat.dev !== observed.stat.dev ||
        current.stat.ino !== observed.stat.ino ||
        current.contents !== observed.contents ||
        !writerLockPidIsDead(current.contents)
      ) {
        return false;
      }
      unlinkSync(this.#paths.lock);
      fsyncDirectory(this.#paths.directory);
      return true;
    } finally {
      this.#closeWriterLockReclaimToken(token);
    }
  }

  #writerLockReclaimTokenPath(stat: Stats): string {
    if (
      !Number.isSafeInteger(stat.dev) ||
      !Number.isSafeInteger(stat.ino) ||
      stat.dev < 0 ||
      stat.ino < 0
    ) {
      throw new MigrationConflictError(
        "migration writer lock identity is not addressable",
        {
          code: "migration_writer_lock_identity_unaddressable",
          references: [diagnosticReference("root.path", this.#paths.lock)],
        },
      );
    }
    return `${this.#paths.lock}.reclaim-${stat.dev}-${stat.ino}`;
  }

  #openWriterLockReclaimToken(stat: Stats): WriterLockReclaimToken {
    const path = this.#writerLockReclaimTokenPath(stat);
    this.#assertGuardedPathsDistinctFromLegacy();
    if (pathsReferToSameFile(path, this.#legacyStorePath)) {
      throw new MigrationConflictError(
        "migration sidecar storage must not alias the configured v1 registry path",
        {
          code: "migration_store_path_rejected",
          references: [diagnosticReference("root.path", path)],
        },
      );
    }
    assertSafeWritePath(path, { mustStayUnder: this.#paths.directory });
    let descriptor: number;
    try {
      descriptor = openSync(path, EXCLUSIVE_NOFOLLOW_WRITE_FLAGS, SIDECAR_MODE);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      throw new MigrationConflictError(
        "another v2 migration writer is reclaiming the sidecar lock",
        {
          code: "migration_writer_lock_reclaim_contended",
          references: [diagnosticReference("root.path", path)],
        },
      );
    }
    try {
      writeFileSync(descriptor, `${process.pid}\n`, { encoding: "utf8" });
      fsyncSync(descriptor);
    } catch (error) {
      this.#closeWriterLockReclaimToken({ path, descriptor });
      throw error;
    }
    return { path, descriptor };
  }

  #closeWriterLockReclaimToken(token: WriterLockReclaimToken): void {
    try {
      closeSync(token.descriptor);
    } finally {
      rmSync(token.path, { force: true });
      fsyncDirectory(this.#paths.directory);
    }
  }

  #storeBoundary<T>(code: string, operation: () => T): T {
    try {
      return operation();
    } catch (error) {
      if (
        error instanceof MigrationConflictError ||
        error instanceof MigrationDriftError
      ) {
        throw error;
      }
      const pathRejected = error instanceof AccountsError;
      throw new MigrationConflictError(
        pathRejected
          ? "migration store path was rejected"
          : "migration store operation failed",
        {
          code: pathRejected ? "migration_store_path_rejected" : code,
          references: [diagnosticReference("root.path", this.#paths.sidecar)],
        },
      );
    }
  }
}

function assertSidecarSuccessor(
  current: MigrationSidecar,
  next: MigrationSidecar,
): void {
  if (
    current.state !== next.state &&
    !allowedTransitions[current.state].includes(next.state)
  ) {
    throw new MigrationConflictError(
      `invalid durable migration state transition ${current.state} -> ${next.state}`,
    );
  }
  if (next.aliasJournal.length < current.aliasJournal.length) {
    throw new MigrationConflictError(
      "migration alias journal may not be truncated",
    );
  }
  for (let index = 0; index < current.aliasJournal.length; index += 1) {
    if (
      hashCanonical(current.aliasJournal[index]) !==
      hashCanonical(next.aliasJournal[index])
    ) {
      throw new MigrationConflictError(
        "migration alias journal history is immutable",
      );
    }
  }
  assertReceiptPrefix(
    current.gateReceipts,
    next.gateReceipts,
    "migration gate receipt history is immutable",
  );
  assertReceiptPrefix(
    current.backfillReceipts,
    next.backfillReceipts,
    "migration backfill receipt history is immutable",
  );
  assertReceiptPrefix(
    current.transitionJournal,
    next.transitionJournal,
    "migration transition journal history is immutable",
  );
  if (current.state === next.state) {
    if (
      next.gateReceipts.length !== current.gateReceipts.length ||
      next.backfillReceipts.length !== current.backfillReceipts.length ||
      next.transitionJournal.length !== current.transitionJournal.length
    ) {
      throw new MigrationConflictError(
        "receipt journals may advance only with their matching state transition",
      );
    }
    return;
  }
  const transition = next.transitionJournal.at(-1);
  if (
    next.transitionJournal.length !== current.transitionJournal.length + 1 ||
    transition?.sourceState !== current.state ||
    transition.targetState !== next.state ||
    transition.sourceIntegrityDigest !== current.integrityDigest ||
    transition.sourceAliasJournalLength !== current.aliasJournal.length ||
    transition.sourceGateReceiptCount !== current.gateReceipts.length ||
    transition.sourceBackfillReceiptCount !== current.backfillReceipts.length
  ) {
    throw new MigrationConflictError(
      `durable transition journal must bind ${current.state} -> ${next.state}`,
    );
  }
  if (next.state === "partial_ready" || next.state === "final_ready") {
    const receipt = next.gateReceipts.at(-1);
    if (
      next.gateReceipts.length !== current.gateReceipts.length + 1 ||
      next.backfillReceipts.length !== current.backfillReceipts.length ||
      receipt?.sourceIntegrityDigest !== current.integrityDigest ||
      receipt?.targetState !== next.state
    ) {
      throw new MigrationConflictError(
        `durable gate receipt must bind ${current.state} -> ${next.state}`,
      );
    }
    return;
  }
  const receipt = next.backfillReceipts.at(-1);
  const expectedReadyState =
    next.state === "partial_applied" ? "partial_ready" : "final_ready";
  if (
    next.backfillReceipts.length !== current.backfillReceipts.length + 1 ||
    next.gateReceipts.length !== current.gateReceipts.length ||
    receipt?.sourceIntegrityDigest !== current.integrityDigest ||
    receipt?.readyState !== expectedReadyState
  ) {
    throw new MigrationConflictError(
      `durable backfill receipt must bind ${current.state} -> ${next.state}`,
    );
  }
}

function assertCanonicalPlannedGenesis(sidecar: MigrationSidecar): void {
  const canonical = createMigrationSidecar(sidecar.plan);
  if (
    sidecar.state !== "planned" ||
    hashCanonical(sidecar) !== hashCanonical(canonical)
  ) {
    throw new MigrationConflictError(
      "the first durable migration sidecar must be the canonical planned genesis",
    );
  }
}

function assertReceiptPrefix(
  current: readonly unknown[],
  next: readonly unknown[],
  message: string,
): void {
  if (next.length < current.length) {
    throw new MigrationConflictError(message);
  }
  for (let index = 0; index < current.length; index += 1) {
    if (hashCanonical(current[index]) !== hashCanonical(next[index])) {
      throw new MigrationConflictError(message);
    }
  }
}

function pathsReferToSameFile(left: string, right: string): boolean {
  const normalizedLeft = resolve(left);
  const normalizedRight = resolve(right);
  if (normalizedLeft === normalizedRight) return true;

  const leftStat = lstatIfExists(normalizedLeft);
  const rightStat = lstatIfExists(normalizedRight);
  if (
    leftStat &&
    rightStat &&
    leftStat.dev === rightStat.dev &&
    leftStat.ino === rightStat.ino
  ) {
    return true;
  }

  const physicalLeft = resolvePhysicalPath(normalizedLeft);
  const physicalRight = resolvePhysicalPath(normalizedRight);
  return (
    physicalLeft !== undefined &&
    physicalRight !== undefined &&
    physicalLeft === physicalRight
  );
}

function lstatIfExists(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function resolvePhysicalPath(path: string): string | undefined {
  let cursor = resolve(path);
  const missingSegments: string[] = [];
  for (;;) {
    const stat = lstatIfExists(cursor);
    if (stat) {
      try {
        return resolve(realpathSync(cursor), ...missingSegments);
      } catch {
        return undefined;
      }
    }
    const parent = dirname(cursor);
    if (parent === cursor) return undefined;
    missingSegments.unshift(basename(cursor));
    cursor = parent;
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function writerLockPidIsDead(contents: string): boolean {
  const rawPid = contents.trim();
  if (!/^[1-9][0-9]*$/.test(rawPid)) return false;
  const pid = Number(rawPid);
  if (!Number.isSafeInteger(pid)) return false;
  return !processIsAlive(pid);
}

function assertPrivateRegularFile(path: string, label: string): void {
  const stat = lstatSync(path);
  assertPrivateRegularStat(stat, label);
}

function assertPrivateRegularStat(stat: Stats, label: string): void {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new AccountsError(`${label} must be a regular non-symlink file`);
  }
  if ((stat.mode & 0o777) !== SIDECAR_MODE) {
    throw new AccountsError(`${label} must be mode 0600`);
  }
}

function readPrivateRegularFileNoFollow(
  path: string,
  label: string,
): Readonly<{
  contents: string;
  stat: Stats;
}> {
  const descriptor = openSync(path, NOFOLLOW_READ_FLAGS);
  try {
    const stat = fstatSync(descriptor);
    assertPrivateRegularStat(stat, label);
    return {
      contents: readFileSync(descriptor, "utf8"),
      stat,
    };
  } finally {
    closeSync(descriptor);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, "r");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

export function migrationRedactionDigest(
  domainInput: MigrationRedactionDomain,
  value: string,
): MigrationDigest {
  const domainResult = migrationRedactionDomainSchema.safeParse(domainInput);
  if (!domainResult.success) {
    throw new MigrationConflictError(
      "migration redaction domain is not schema-owned",
      { code: "migration_invalid_redaction_domain" },
    );
  }
  const domain = domainResult.data;
  const valueResult = z.string().safeParse(value);
  if (!valueResult.success) {
    throw new MigrationConflictError("migration redaction value was rejected", {
      code: "migration_invalid_redaction_value",
    });
  }
  const parsedValue = valueResult.data;
  const frame = (part: string): Buffer => {
    const payload = Buffer.from(part, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(payload.length);
    return Buffer.concat([length, payload]);
  };
  return `sha256:${createHash("sha256")
    .update(frame("hasna.accounts.v2.migration.redaction"))
    .update(frame("1"))
    .update(frame(domain))
    .update(frame(parsedValue))
    .digest("hex")}`;
}

function diagnosticReference(
  domain: MigrationRedactionDomain,
  value: string,
): MigrationDiagnosticReference {
  return deepFreeze({
    domain,
    digest: migrationRedactionDigest(domain, value),
  });
}

function diagnosticAliasReference(
  kind: z.infer<typeof migrationAliasKindSchema>,
  value: string,
): MigrationDiagnosticReference {
  return diagnosticReference(
    kind === "legacy_account"
      ? "diagnostic.alias.account"
      : "diagnostic.alias.session",
    value,
  );
}

function stableDiagnosticCode(message: string): string {
  const normalized = message
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized.startsWith("migration_")
    ? normalized
    : `migration_${normalized}`;
}

function hashText(value: string): MigrationDigest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function hashCanonical(value: unknown): MigrationDigest {
  return hashText(JSON.stringify(canonicalize(value)));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function sortRecord<T>(record: Readonly<Record<string, T>>): Record<string, T> {
  const sorted: Record<string, T> = {};
  for (const key of Object.keys(record).sort()) sorted[key] = record[key] as T;
  return sorted;
}

function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== "object" || Object.isFrozen(value))
    return value;
  for (const child of Object.values(value as Record<string, unknown>))
    deepFreeze(child);
  return Object.freeze(value);
}
