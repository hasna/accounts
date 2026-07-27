import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { z } from "zod";
import { assertSafeWritePath } from "../lib/safe-path.js";
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

const migrationOpaqueIdSchema = z
  .string()
  .min(16)
  .max(128)
  .regex(OPAQUE_ID_PATTERN, "migration identifier must be opaque");

export const migrationDigestSchema = z
  .string()
  .regex(DIGEST_PATTERN, "digest must be sha256 followed by 64 lowercase hex characters");

export type MigrationDigest = z.infer<typeof migrationDigestSchema>;

const migrationRedactionDomainSchema = z.enum([
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
  "diagnostic.alias",
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
  const valueSchema = requireCanonicalOrder ? canonicalAliasSchema : aliasSchema;
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
const canonicalHistoricalAliasSchema = aliasArraySchema("historical alias", true);
const canonicalHistoricalSessionAliasSchema = aliasArraySchema(
  "historical session alias",
  true,
);

const verifiedRootObservationSchema = z
  .object({
    state: z.literal("verified"),
    path: z.string().min(1).refine(isAbsolute, "root path must be absolute"),
    realPath: z.string().min(1).refine(isAbsolute, "root realPath must be absolute"),
    device: z.string().min(1).max(128).regex(/^[0-9]+$/, "device must be numeric"),
    inode: z.string().min(1).max(128).regex(/^[0-9]+$/, "inode must be numeric"),
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
        tool: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[a-z0-9][a-z0-9-]*$/, "legacy tool must be a runtime slug"),
        name: z
          .string()
          .min(1)
          .max(64)
          .regex(/^[a-z0-9][a-z0-9-]*$/, "legacy name must be a profile slug"),
      })
      .strict(),
    runtimeLabel: z.string().min(1).max(128).regex(SAFE_TEXT_PATTERN),
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

export type LegacyProfileObservation = z.infer<typeof legacyProfileObservationSchema>;

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

export type BackupRestorePlan = Readonly<z.infer<typeof backupRestorePlanSchema>>;

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
        total + (observation.root.state === "verified" ? observation.root.byteCount : 0),
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

export type MigrationPlanInput = Readonly<z.infer<typeof migrationPlanInputSchema>>;

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
        message: "migration sourceKey must match its structured source identity",
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
        message: "quarantined migration record may not install a machine binding",
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
        message: "migration binding root must match its verified canonical root",
      });
    }
    if (
      record.binding &&
      record.binding.authentication !== record.authentication
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["binding", "authentication"],
        message: "migration binding authentication must match the frozen observation",
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
    const runtimeTools = new Map<string, string>();
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
      claimIdentifier(
        record.target.accountId,
        "account",
        ["records", index, "target", "accountId"],
      );
      claimIdentifier(
        record.target.runtimeId,
        "runtime",
        ["records", index, "target", "runtimeId"],
      );
      claimIdentifier(
        record.target.bindingId,
        "binding",
        ["records", index, "target", "bindingId"],
      );
      const runtimeTool = runtimeTools.get(record.target.runtimeId);
      if (runtimeTool && runtimeTool !== record.source.tool) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["records", index, "target", "runtimeId"],
          message: "one runtime id may not represent multiple legacy tools",
        });
      }
      runtimeTools.set(record.target.runtimeId, record.source.tool);
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
          message: "migration binding must remain inside the frozen plan scope and machine",
        });
      }
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
          message: "migration plan input digest does not match its frozen census",
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
        message: "migration plan idempotency key does not match its frozen identity",
      });
    }
    const { planDigest: _planDigest, ...planCore } = plan;
    if (plan.planDigest !== hashCanonical(planCore)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["planDigest"],
        message: "migration plan digest does not match its complete frozen plan",
      });
    }
  });

export type MigrationPlan = Readonly<z.infer<typeof migrationPlanSchema>>;

export type MigrationIdKind = "plan" | "runtime" | "account" | "binding";
export type MigrationIdFactory = (kind: MigrationIdKind, seed: string) => string;

export interface BuildMigrationPlanOptions {
  idFactory?: MigrationIdFactory;
  existingPlan?: MigrationPlan;
}

export class MigrationConflictError extends Error {
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
}

export class MigrationDriftError extends Error {
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
}

function normalizeMigrationPlanInput(input: MigrationPlanInput): MigrationPlanInput {
  return {
    ...input,
    sourceDigests: sortRecord(input.sourceDigests) as MigrationPlanInput["sourceDigests"],
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
        sessionReferenceDigests: [...observation.sessionReferenceDigests].sort(),
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

export function buildMigrationPlan(
  inputValue: MigrationPlanInput,
  options: BuildMigrationPlanOptions = {},
): MigrationPlan {
  const input = normalizeMigrationPlanInput(migrationPlanInputSchema.parse(inputValue));
  const inputDigest = hashCanonical(input);
  if (options.existingPlan) {
    const existing = migrationPlanSchema.parse(options.existingPlan);
    if (existing.inputDigest !== inputDigest) {
      throw new MigrationDriftError(
        "migration input digest changed for frozen plan",
        {
          code: "migration_frozen_input_digest_changed",
          references: [
            diagnosticReference("diagnostic.plan", existing.id),
          ],
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
          references: [
            diagnosticReference("diagnostic.plan", existing.id),
          ],
        },
      );
    }
    return deepFreeze(structuredClone(existing));
  }

  const idFactory = options.idFactory ?? defaultIdFactory;
  const planId = migrationOpaqueIdSchema.parse(idFactory("plan", inputDigest));
  const scopedSeed = `${input.scope.tenantId}:${input.scope.scopeId}`;
  const sourceKeys = new Set<string>();
  const runtimeIdByTool = new Map<string, RuntimeId>();
  const runtimeLabelByTool = new Map<string, string>();
  const observations = [...input.observations].sort((left, right) =>
    sourceKey(left).localeCompare(sourceKey(right)),
  );

  for (const observation of observations) {
    const key = sourceKey(observation);
    if (sourceKeys.has(key)) {
      throw new MigrationConflictError("duplicate legacy source key", {
        code: "migration_duplicate_legacy_source_key",
        count: 2,
        references: [
          diagnosticReference("diagnostic.source-key", key),
        ],
      });
    }
    sourceKeys.add(key);
    const existingRuntimeLabel = runtimeLabelByTool.get(observation.source.tool);
    if (existingRuntimeLabel && existingRuntimeLabel !== observation.runtimeLabel) {
      throw new MigrationConflictError(
        "legacy tool has conflicting runtime labels",
        {
          code: "migration_conflicting_runtime_labels",
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
    runtimeLabelByTool.set(observation.source.tool, observation.runtimeLabel);
    if (!runtimeIdByTool.has(observation.source.tool)) {
      runtimeIdByTool.set(
        observation.source.tool,
        runtimeIdSchema.parse(
          idFactory("runtime", `${scopedSeed}:${observation.source.tool}`),
        ),
      );
    }
  }

  const records = observations.map((observation): MigrationRecord => {
    const key = sourceKey(observation);
    const reasons = deriveMigrationQuarantineReasons(
      observation,
      observations,
    );

    const target = migrationTargetSchema.parse({
      accountId: idFactory("account", `${scopedSeed}:${key}`),
      runtimeId: runtimeIdByTool.get(observation.source.tool),
      bindingId: idFactory("binding", `${scopedSeed}:${key}`),
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
  return [
    source.authority,
    source.authorityId,
    source.tool,
    source.name,
  ].join(":");
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

function defaultIdFactory(kind: MigrationIdKind, seed: string): string {
  return `${kind}_${createHash("sha256")
    .update(`accounts-v2-migration:${kind}:${seed}`)
    .digest("hex")
    .slice(0, 32)}`;
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

export function redactMigrationPlan(planInput: MigrationPlan): RedactedMigrationPlan {
  const plan = migrationPlanSchema.parse(planInput);
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
    records: plan.records.map((record) => ({
      sourceKeyDigest: migrationRedactionDigest("source.key", record.sourceKey),
      source: {
        authority: record.source.authority,
        authorityIdDigest: migrationRedactionDigest(
          "source.authority-id",
          record.source.authorityId,
        ),
        toolDigest: migrationRedactionDigest("source.tool", record.source.tool),
        nameDigest: migrationRedactionDigest("source.name", record.source.name),
      },
      runtimeLabelDigest: migrationRedactionDigest(
        "runtime.label",
        record.runtimeLabel,
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
              pathDigest: record.root.pathDigest,
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
    })),
  });
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
    unknownLedgerEntries: z.array(z.string().min(1).max(256).regex(SAFE_TEXT_PATTERN)),
    checksumMismatches: z.array(z.string().min(1).max(256).regex(SAFE_TEXT_PATTERN)),
    unresolvedCatalogSkipDigests: z.array(migrationDigestSchema),
    backupRestore: backupRestoreEvidenceSchema,
  })
  .strict();

export type MigrationGateEvidence = Readonly<z.infer<typeof migrationGateEvidenceSchema>>;
export type MigrationGateIntent = "partial" | "final";
const migrationStateSchema = z.enum([
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
    intent: z.enum(["partial", "final"]),
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

export type MigrationGateReceipt = Readonly<z.infer<typeof migrationGateReceiptSchema>>;

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

export function evaluateMigrationGates(
  planInput: MigrationPlan,
  evidenceInput: MigrationGateEvidence,
  intent: MigrationGateIntent,
): MigrationGateResult {
  const plan = migrationPlanSchema.parse(planInput);
  const evidence = migrationGateEvidenceSchema.parse(evidenceInput);
  const reasons = new Set<string>();

  if (evidence.planId !== plan.id || evidence.idempotencyKey !== plan.idempotencyKey) {
    reasons.add("plan_identity_mismatch");
  }
  if (
    evidence.cutoverEpoch !== plan.cutoverEpoch ||
    evidence.backupRestore.cutoverEpoch !== plan.cutoverEpoch
  ) {
    reasons.add("cutover_epoch_mismatch");
  }
  if (evidence.activeWriters.length > 0) reasons.add("active_writers");
  if (hashCanonical(sortRecord(evidence.observedDigests)) !== hashCanonical(plan.sourceDigests)) {
    reasons.add("input_digest_drift");
  }
  if (evidence.availableBytes < plan.backup.requiredBytes) {
    reasons.add("insufficient_free_space");
  }
  if (evidence.unknownLedgerEntries.length > 0) reasons.add("unknown_ledger_entry");
  if (evidence.checksumMismatches.length > 0) reasons.add("checksum_mismatch");
  if (evidence.unresolvedCatalogSkipDigests.length > 0) reasons.add("catalog_skip");

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
  const readyRecords = plan.records.some((record) => record.disposition.state === "ready");
  if (intent === "final" && quarantined) reasons.add("unresolved_quarantine");
  if (intent === "partial" && !readyRecords) reasons.add("no_ready_records");

  return deepFreeze({
    intent,
    ready: reasons.size === 0,
    nextState:
      reasons.size === 0 ? (intent === "partial" ? "partial_ready" : "final_ready") : null,
    reasons: [...reasons],
  });
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
    kind: z.enum(["legacy_account", "session_ref"]),
    alias: canonicalAliasSchema,
    sourceKey: legacyKeySchema,
    targetId: migrationOpaqueIdSchema,
  })
  .strict();

export type MigrationAliasInput = Readonly<z.infer<typeof migrationAliasInputSchema>>;

const migrationAliasEntrySchema = migrationAliasInputSchema
  .extend({
    sequence: z.number().int().positive().safe(),
    previousDigest: migrationDigestSchema.nullable(),
    digest: migrationDigestSchema,
  })
  .strict();

export type MigrationAliasEntry = Readonly<z.infer<typeof migrationAliasEntrySchema>>;

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

export function createMigrationSidecar(planInput: MigrationPlan): MigrationSidecar {
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

export function appendMigrationAlias(
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
          diagnosticReference("diagnostic.alias", alias.alias),
        ],
      },
    );
  }
  const expectedTarget =
    alias.kind === "legacy_account" ? record.target.accountId : record.target.bindingId;
  if (alias.targetId !== expectedTarget) {
    throw new MigrationConflictError(
      "migration alias does not target its frozen immutable identity",
      {
        code: "migration_alias_target_mismatch",
        references: [
          diagnosticReference("diagnostic.source-key", alias.sourceKey),
          diagnosticReference("diagnostic.alias", alias.alias),
        ],
      },
    );
  }
  const existing = entries.find(
    (entry) => entry.kind === alias.kind && entry.alias === alias.alias,
  );
  if (existing) {
    if (existing.sourceKey === alias.sourceKey && existing.targetId === alias.targetId) {
      return entries;
    }
    throw new MigrationConflictError(
      "migration alias already targets a different immutable identity",
      {
        code: "migration_alias_identity_conflict",
        count: 2,
        references: [
          diagnosticReference("diagnostic.alias", alias.alias),
        ],
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

const allowedTransitions: Readonly<Record<MigrationState, readonly MigrationState[]>> = {
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

export function transitionMigrationSidecar(
  sidecarInput: MigrationSidecar,
  target: MigrationState,
  options: TransitionMigrationSidecarOptions = {},
): MigrationSidecar {
  const sidecar = parseSidecar(sidecarInput);
  if (target === sidecar.state) return sidecar;
  if (stateRank[target] < stateRank[sidecar.state]) {
    throw new MigrationConflictError("cannot move migration state backwards");
  }
  if (!allowedTransitions[sidecar.state].includes(target)) {
    throw new MigrationConflictError(
      `invalid migration state transition ${sidecar.state} -> ${target}`,
    );
  }
  let gateReceipts = sidecar.gateReceipts;
  let backfillReceipts = sidecar.backfillReceipts;
  if (target === "partial_ready" || target === "final_ready") {
    if (!options.gateEvidence) {
      throw new MigrationConflictError(
        `entering ${target} requires current migration gate evidence`,
      );
    }
    const gate = evaluateMigrationGates(
      sidecar.plan,
      options.gateEvidence,
      target === "partial_ready" ? "partial" : "final",
    );
    if (!gate.ready || gate.nextState !== target) {
      throw new MigrationConflictError(
        `migration gates block ${target}: ${gate.reasons.join(", ")}`,
      );
    }
    const evidence = migrationGateEvidenceSchema.parse(options.gateEvidence);
    const receiptCore = migrationGateReceiptCoreSchema.parse({
      schemaVersion: 1,
      sequence: sidecar.gateReceipts.length + 1,
      intent: target === "partial_ready" ? "partial" : "final",
      targetState: target,
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
  if (target === "partial_applied" || target === "final_applied") {
    if (!options.backfillReceipt) {
      throw new MigrationConflictError(
        `entering ${target} requires a committed scope-bound backfill receipt`,
      );
    }
    const receipt = migrationBackfillReceiptSchema.parse(options.backfillReceipt);
    validateBackfillReceipt(sidecar.plan, receipt);
    const expectedReadyState =
      target === "partial_applied" ? "partial_ready" : "final_ready";
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
    (target === "final_ready" || target === "final_applied") &&
    sidecar.plan.records.some((record) => record.disposition.state === "quarantined")
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
    targetState: target,
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
    state: target,
    aliasJournal: sidecar.aliasJournal,
    gateReceipts,
    backfillReceipts,
    transitionJournal: [...sidecar.transitionJournal, transition],
  });
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
    throw new MigrationDriftError("migration sidecar integrity digest mismatch");
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
      throw new MigrationDriftError("migration gate receipt sequence is invalid");
    }
  }
  for (const [index, receipt] of sidecar.backfillReceipts.entries()) {
    validateBackfillReceipt(sidecar.plan, receipt);
    if (receipt.sequence !== index + 1) {
      throw new MigrationDriftError("migration backfill receipt sequence is invalid");
    }
  }

  const gates = sidecar.gateReceipts;
  const backfills = sidecar.backfillReceipts;
  const partialGate = gates[0]?.targetState === "partial_ready";
  const finalGate = gates.at(-1)?.targetState === "final_ready";
  const partialBackfill = backfills[0]?.readyState === "partial_ready";
  const finalBackfill = backfills.at(-1)?.readyState === "final_ready";
  const valid =
    (sidecar.state === "planned" && gates.length === 0 && backfills.length === 0) ||
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
      gateReceipts: sidecar.gateReceipts.slice(
        0,
        entry.sourceGateReceiptCount,
      ),
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

    if (entry.targetState === "partial_ready" || entry.targetState === "final_ready") {
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
    throw new MigrationDriftError("migration gate receipt plan identity is invalid");
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
      throw new MigrationDriftError("migration alias journal contains a duplicate alias");
    }
    aliases.add(aliasKey);
    if (entry.sequence !== index + 1 || entry.previousDigest !== previousDigest) {
      throw new MigrationDriftError("migration alias journal sequence or chain is invalid");
    }
    const record = plan.records.find((candidate) => candidate.sourceKey === entry.sourceKey);
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
      throw new MigrationDriftError("migration alias journal digest is invalid");
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

export interface MigrationBackfillResult {
  runtimes: { created: number; adopted: number };
  accounts: { created: number; adopted: number };
  crosswalks: { created: number; adopted: number };
  epoch: EnsureResult;
  receipt: MigrationBackfillReceipt;
}

export async function applyScopedBackfill(
  sidecarInput: MigrationSidecar,
  port: MigrationBackfillPort,
): Promise<MigrationBackfillResult> {
  const sidecar = parseSidecar(sidecarInput);
  if (sidecar.state !== "partial_ready" && sidecar.state !== "final_ready") {
    throw new MigrationConflictError(
      "scoped backfill requires a gate-approved partial_ready or final_ready sidecar",
    );
  }
  const records = sidecar.plan.records.filter(
    (record): record is MigrationRecord & { disposition: { state: "ready" } } =>
      record.disposition.state === "ready",
  );
  const runtimes = new Map<RuntimeId, ScopedBackfillRuntime>();
  for (const record of records) {
    const runtime: ScopedBackfillRuntime = {
      id: record.target.runtimeId,
      tenantId: sidecar.plan.scope.tenantId,
      scopeId: sidecar.plan.scope.scopeId,
      key: record.source.tool,
      label: record.runtimeLabel,
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

  const result = await port.transaction(sidecar.plan.scope, async (transaction) => {
    const counts: MigrationBackfillCounts = {
      runtimes: { created: 0, adopted: 0 },
      accounts: { created: 0, adopted: 0 },
      crosswalks: { created: 0, adopted: 0 },
      epoch: "created",
    };

    for (const runtime of [...runtimes.values()].sort((a, b) => a.id.localeCompare(b.id))) {
      tally(counts.runtimes, await transaction.ensureRuntime(deepFreeze(runtime)));
    }
    for (const record of [...records].sort((a, b) => a.sourceKey.localeCompare(b.sourceKey))) {
      const account: ScopedBackfillAccount = {
        id: record.target.accountId,
        tenantId: sidecar.plan.scope.tenantId,
        scopeId: sidecar.plan.scope.scopeId,
        name: record.source.name,
        runtimeId: record.target.runtimeId,
        createdAt: sidecar.plan.createdAt,
        updatedAt: sidecar.plan.createdAt,
      };
      tally(counts.accounts, await transaction.ensureAccount(deepFreeze(account)));
    }
    for (const record of [...records].sort((a, b) => a.sourceKey.localeCompare(b.sourceKey))) {
      const crosswalk: ScopedBackfillCrosswalk = {
        sourceKey: record.sourceKey,
        sourceAuthority: record.source.authority,
        sourceAuthorityId: record.source.authorityId,
        legacyTool: record.source.tool,
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
    return deepFreeze(migrationBackfillCountsSchema.parse(counts));
  });

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

function tally(counter: { created: number; adopted: number }, value: EnsureResult): void {
  counter[ensureResultSchema.parse(value)] += 1;
}

function readyRecordsDigest(plan: MigrationPlan): MigrationDigest {
  return hashCanonical(
    plan.records.filter((record) => record.disposition.state === "ready"),
  );
}

function validateBackfillReceipt(
  plan: MigrationPlan,
  receiptInput: MigrationBackfillReceipt,
): void {
  const receipt = migrationBackfillReceiptSchema.parse(receiptInput);
  const { digest, ...coreValue } = receipt;
  const core = migrationBackfillReceiptCoreSchema.parse(coreValue);
  if (hashCanonical(core) !== digest) {
    throw new MigrationDriftError("migration backfill receipt digest is invalid");
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
        message: "compatibility matrix must contain exactly one complete 3x3 grid",
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

export type MigrationDurabilityEvent =
  | "wal_file_fsync"
  | "wal_rename"
  | "wal_directory_fsync"
  | "sidecar_file_fsync"
  | "sidecar_rename"
  | "sidecar_directory_fsync"
  | "wal_remove"
  | "cleanup_directory_fsync";

export type MigrationSidecarFailurePoint =
  | "after_wal_file_fsync"
  | "after_wal_rename"
  | "after_wal_directory_fsync"
  | "after_sidecar_file_fsync"
  | "after_sidecar_rename"
  | "after_sidecar_directory_fsync"
  | "before_wal_remove"
  | "after_wal_remove";

export interface MigrationSidecarStoreOptions {
  sidecarPath: string;
  legacyStorePath: string;
  injectFailure?: (point: MigrationSidecarFailurePoint) => void;
  onDurabilityEvent?: (event: MigrationDurabilityEvent) => void;
}

export interface MigrationSidecarInstallOptions {
  expectedPreviousDigest?: MigrationDigest | null;
}

export class MigrationSidecarStore {
  readonly sidecarPath: string;
  readonly legacyStorePath: string;
  private readonly directory: string;
  private readonly walPath: string;
  private readonly walTempPath: string;
  private readonly lockPath: string;
  private readonly injectFailure?: (point: MigrationSidecarFailurePoint) => void;
  private readonly onDurabilityEvent?: (event: MigrationDurabilityEvent) => void;

  constructor(options: MigrationSidecarStoreOptions) {
    this.sidecarPath = resolve(options.sidecarPath);
    this.legacyStorePath = resolve(options.legacyStorePath);
    this.assertDistinctLegacyStore();
    this.directory = dirname(this.sidecarPath);
    this.walPath = `${this.sidecarPath}.wal`;
    this.walTempPath = `${this.walPath}.tmp`;
    this.lockPath = `${this.sidecarPath}.lock`;
    this.injectFailure = options.injectFailure;
    this.onDurabilityEvent = options.onDurabilityEvent;
  }

  load(): MigrationSidecar | null {
    if (!existsSync(this.sidecarPath)) return null;
    assertPrivateRegularFile(this.sidecarPath, "migration sidecar");
    try {
      return parseSidecar(JSON.parse(readFileSync(this.sidecarPath, "utf8")));
    } catch (error) {
      if (error instanceof MigrationDriftError) throw error;
      throw new MigrationDriftError(
        "could not parse migration sidecar",
        { code: "migration_sidecar_parse_failed" },
      );
    }
  }

  install(
    sidecarInput: MigrationSidecar,
    options: MigrationSidecarInstallOptions = {},
  ): MigrationSidecar {
    const sidecar = parseSidecar(sidecarInput);
    const expectedPreviousDigest =
      options.expectedPreviousDigest === undefined
        ? undefined
        : options.expectedPreviousDigest === null
          ? null
          : migrationDigestSchema.parse(options.expectedPreviousDigest);
    return this.withLock(() => {
      this.assertDistinctLegacyStore();
      if (existsSync(this.walPath) || existsSync(this.walTempPath)) {
        throw new MigrationConflictError(
          "pending migration WAL must be repaired before another install",
        );
      }
      const current = this.load();
      if (current?.integrityDigest === sidecar.integrityDigest) return current;
      if (!current && expectedPreviousDigest !== undefined && expectedPreviousDigest !== null) {
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
      if (current && hashCanonical(current.plan) !== hashCanonical(sidecar.plan)) {
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
      this.prepareDirectory();
      this.writeWal(wal);
      this.writeSidecar(sidecar);
      this.finishWal();
      return sidecar;
    });
  }

  repair(): MigrationSidecar | null {
    return this.withLock(() => {
      this.prepareDirectory();
      if (!existsSync(this.walPath) && existsSync(this.walTempPath)) {
        assertPrivateRegularFile(this.walTempPath, "migration WAL staging file");
        this.readWal(this.walTempPath);
        renameSync(this.walTempPath, this.walPath);
        chmodSync(this.walPath, SIDECAR_MODE);
        this.onDurabilityEvent?.("wal_rename");
        fsyncDirectory(this.directory);
        this.onDurabilityEvent?.("wal_directory_fsync");
      }
      if (!existsSync(this.walPath)) return this.load();

      const wal = this.readWal(this.walPath);
      if (wal.previousDigest === null) {
        assertCanonicalPlannedGenesis(wal.nextSidecar);
      }
      let current: MigrationSidecar | null;
      try {
        current = this.load();
      } catch (error) {
        throw new MigrationDriftError(
          "migration sidecar drift is ambiguous; preserving WAL",
          { code: "migration_sidecar_drift_ambiguous" },
        );
      }
      if (current?.integrityDigest === wal.nextDigest) {
        this.finishWal({ allowFailureInjection: false });
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
        this.writeSidecar(wal.nextSidecar, { allowFailureInjection: false });
        this.finishWal({ allowFailureInjection: false });
        return wal.nextSidecar;
      }
      throw new MigrationDriftError(
        "migration sidecar changed outside the frozen WAL transition; preserving WAL and data",
      );
    });
  }

  private prepareDirectory(): void {
    this.assertDistinctLegacyStore();
    assertSafeWritePath(this.sidecarPath, { mustStayUnder: this.directory });
    assertSafeWritePath(this.walPath, { mustStayUnder: this.directory });
    assertSafeWritePath(this.walTempPath, { mustStayUnder: this.directory });
    assertSafeWritePath(this.lockPath, { mustStayUnder: this.directory });
  }

  private assertDistinctLegacyStore(): void {
    if (
      this.sidecarPath === this.legacyStorePath ||
      pathsReferToSameFile(this.sidecarPath, this.legacyStorePath)
    ) {
      throw new MigrationConflictError(
        "migration sidecar path must not be accounts.json or the configured v1 registry path",
      );
    }
  }

  private writeWal(wal: MigrationWal): void {
    this.writeDurableFile(
      this.walPath,
      JSON.stringify(wal, null, 2) + "\n",
      "wal",
      this.walTempPath,
      true,
    );
  }

  private writeSidecar(
    sidecar: MigrationSidecar,
    options: { allowFailureInjection?: boolean } = {},
  ): void {
    this.writeDurableFile(
      this.sidecarPath,
      JSON.stringify(sidecar, null, 2) + "\n",
      "sidecar",
      `${this.sidecarPath}.tmp`,
      options.allowFailureInjection ?? true,
    );
  }

  private writeDurableFile(
    target: string,
    contents: string,
    kind: "wal" | "sidecar",
    temp: string,
    allowFailureInjection: boolean,
  ): void {
    rmSync(temp, { force: true });
    let descriptor: number | undefined;
    let completed = false;
    try {
      descriptor = openSync(temp, "wx", SIDECAR_MODE);
      writeFileSync(descriptor, contents, { encoding: "utf8" });
      fsyncSync(descriptor);
      this.onDurabilityEvent?.(`${kind}_file_fsync`);
      if (allowFailureInjection) this.injectFailure?.(`after_${kind}_file_fsync`);
      closeSync(descriptor);
      descriptor = undefined;
      renameSync(temp, target);
      chmodSync(target, SIDECAR_MODE);
      this.onDurabilityEvent?.(`${kind}_rename`);
      if (allowFailureInjection) this.injectFailure?.(`after_${kind}_rename`);
      fsyncDirectory(this.directory);
      this.onDurabilityEvent?.(`${kind}_directory_fsync`);
      if (allowFailureInjection) this.injectFailure?.(`after_${kind}_directory_fsync`);
      completed = true;
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      if (completed) rmSync(temp, { force: true });
    }
  }

  private finishWal(options: { allowFailureInjection?: boolean } = {}): void {
    const allowFailureInjection = options.allowFailureInjection ?? true;
    if (allowFailureInjection) this.injectFailure?.("before_wal_remove");
    if (existsSync(this.walPath)) unlinkSync(this.walPath);
    rmSync(this.walTempPath, { force: true });
    this.onDurabilityEvent?.("wal_remove");
    if (allowFailureInjection) this.injectFailure?.("after_wal_remove");
    fsyncDirectory(this.directory);
    this.onDurabilityEvent?.("cleanup_directory_fsync");
  }

  private readWal(path: string): MigrationWal {
    assertPrivateRegularFile(path, "migration WAL");
    try {
      const wal = migrationWalSchema.parse(JSON.parse(readFileSync(path, "utf8")));
      const sidecar = parseSidecar(wal.nextSidecar);
      if (
        sidecar.plan.id !== wal.planId ||
        sidecar.plan.idempotencyKey !== wal.idempotencyKey ||
        sidecar.integrityDigest !== wal.nextDigest
      ) {
        throw new MigrationDriftError("migration WAL identity or digest does not match its payload");
      }
      return wal;
    } catch (error) {
      if (error instanceof MigrationDriftError) throw error;
      throw new MigrationDriftError(
        "could not parse migration WAL",
        { code: "migration_wal_parse_failed" },
      );
    }
  }

  private withLock<T>(operation: () => T): T {
    this.prepareDirectory();
    const descriptor = this.acquireLock();
    try {
      return operation();
    } finally {
      closeSync(descriptor);
      unlinkSync(this.lockPath);
      fsyncDirectory(this.directory);
    }
  }

  private acquireLock(): number {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      let descriptor: number | undefined;
      try {
        descriptor = openSync(this.lockPath, "wx", SIDECAR_MODE);
        writeFileSync(descriptor, `${process.pid}\n`, { encoding: "utf8" });
        fsyncSync(descriptor);
        return descriptor;
      } catch (error) {
        if (descriptor !== undefined) {
          closeSync(descriptor);
          rmSync(this.lockPath, { force: true });
          fsyncDirectory(this.directory);
        }
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (attempt === 0 && this.removeDeadWriterLock()) continue;
        throw new MigrationConflictError(
          "another v2 migration writer holds the sidecar lock",
        );
      }
    }
    throw new MigrationConflictError("could not acquire the v2 migration writer lock");
  }

  private removeDeadWriterLock(): boolean {
    assertPrivateRegularFile(this.lockPath, "migration writer lock");
    const observedStat = lstatSync(this.lockPath);
    const rawPid = readFileSync(this.lockPath, "utf8").trim();
    if (!/^[1-9][0-9]*$/.test(rawPid)) return false;
    const pid = Number(rawPid);
    if (!Number.isSafeInteger(pid) || processIsAlive(pid)) return false;
    const currentStat = lstatSync(this.lockPath);
    if (observedStat.dev !== currentStat.dev || observedStat.ino !== currentStat.ino) {
      return false;
    }
    unlinkSync(this.lockPath);
    fsyncDirectory(this.directory);
    return true;
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
    throw new MigrationConflictError("migration alias journal may not be truncated");
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
  if (!existsSync(left) || !existsSync(right)) return false;
  const leftStat = lstatSync(left);
  const rightStat = lstatSync(right);
  if (leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino) return true;
  return realpathSync(left) === realpathSync(right);
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function assertPrivateRegularFile(path: string, label: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new MigrationDriftError(`${label} must be a regular non-symlink file`);
  }
  if ((stat.mode & 0o777) !== SIDECAR_MODE) {
    throw new MigrationDriftError(`${label} must be mode 0600`);
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
    .update(frame(value))
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
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return Object.freeze(value);
}
