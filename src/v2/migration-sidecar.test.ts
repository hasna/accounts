import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { inspect } from "node:util";
import { AccountsError } from "../types.js";
import {
  MigrationConflictError,
  MigrationDriftError,
  MigrationSidecarStore,
  appendMigrationAlias,
  applyScopedBackfill,
  backupRestorePlanSchema,
  buildMigrationPlan,
  createMigrationSidecar,
  evaluateMigrationGates,
  migrationCompatibilityFixtureSchema,
  migrationPlanSchema,
  migrationRedactionDigest,
  migrationSidecarSchema,
  redactMigrationPlan,
  transitionMigrationSidecar,
  type MigrationAliasInput,
  type MigrationBackfillPort,
  type MigrationBackfillTransaction,
  type MigrationGateEvidence,
  type MigrationPlan,
  type MigrationPlanInput,
  type MigrationSidecar,
  type MigrationSidecarFailurePoint,
  type ScopedBackfillAccount,
  type ScopedBackfillCrosswalk,
  type ScopedBackfillRuntime,
} from "./migration-sidecar.js";

const TENANT = "tenant_0000000000000001";
const SCOPE = "scope_00000000000000001";
const MACHINE = "machine_000000000000001";
const CREATED_AT = "2026-07-27T12:00:00.000Z";
const CUTOVER_EPOCH = "2026-07-27T13:00:00.000Z";

const tempRoots: string[] = [];

afterEach(() => {
  for (const root of tempRoots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "accounts-v2-migration-"));
  tempRoots.push(root);
  return root;
}

function digest(seed: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(seed).digest("hex")}`;
}

function stableId(kind: string, seed: string): string {
  return `${kind}_${createHash("sha256").update(seed).digest("hex").slice(0, 24)}`;
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

function canonicalDigest(value: unknown): `sha256:${string}` {
  return digest(JSON.stringify(canonicalize(value)));
}

function redactionDigest(domain: string, value: string): `sha256:${string}` {
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

function captureError(operation: () => unknown): Error & {
  code?: string;
  count?: number;
  references?: readonly unknown[];
} {
  try {
    operation();
  } catch (error) {
    return error as Error & {
      code?: string;
      count?: number;
      references?: readonly unknown[];
    };
  }
  throw new Error("expected operation to throw");
}

function backupPlan() {
  return {
    archiveId: "backup_000000000000001",
    encryption: "age" as const,
    manifestEncrypted: true as const,
    fileMode: 0o600 as const,
    requiredArtifacts: [
      "v1_registry",
      "migration_sidecar",
      "referenced_roots",
      "auth_snapshots",
      "hooks",
      "supervisor_metadata",
    ] as const,
    databasePitrRequired: true,
    restoreDrillRequired: true,
    requiredBytes: 4096,
  };
}

function safeObservation(
  name: string,
  tool = "claude",
  overrides: Record<string, unknown> = {},
) {
  const root = `/profiles/${tool}/${name}`;
  return {
    source: {
      authority: "local-v1" as const,
      authorityId: MACHINE,
      tool,
      name,
    },
    runtimeLabel: tool === "claude" ? "Claude Code" : "Codex CLI",
    inputDigest: digest(`${tool}-${name}`),
    root: {
      state: "verified" as const,
      path: root,
      realPath: root,
      device: "1",
      inode: Number.parseInt(
        createHash("sha256")
          .update(`${tool}:${name}`)
          .digest("hex")
          .slice(0, 12),
        16,
      ).toString(),
      entryCount: 12,
      byteCount: 2048,
      digest: digest(`root-${tool}-${name}`),
    },
    authentication: "authenticated" as const,
    pointers: { current: name === "alice", applied: false, toolLock: false },
    sessionReferenceDigests: [digest(`session-${tool}-${name}`)],
    catalogSkipDigests: [],
    historicalAliases: [`legacy:${tool}:${name}`],
    historicalSessionAliases: [`session:${tool}:${name}`],
    ...overrides,
  };
}

function planInput(
  observations = [safeObservation("alice"), safeObservation("bob", "codex")],
): MigrationPlanInput {
  return {
    scope: { tenantId: TENANT, scopeId: SCOPE },
    machineId: MACHINE,
    createdAt: CREATED_AT,
    cutoverEpoch: CUTOVER_EPOCH,
    sourceDigests: {
      v1Registry: digest("registry"),
      sessionCatalog: digest("catalog"),
      hooks: digest("hooks"),
      supervisor: digest("supervisor"),
    },
    backup: backupPlan(),
    observations,
  };
}

function buildPlan(
  observations = [safeObservation("alice"), safeObservation("bob", "codex")],
  existingPlan?: MigrationPlan,
): MigrationPlan {
  return buildMigrationPlan(planInput(observations), {
    idFactory: stableId,
    ...(existingPlan ? { existingPlan } : {}),
  });
}

function rehashPlanWithRecords(
  plan: MigrationPlan,
  records: MigrationPlan["records"],
): MigrationPlan {
  const frozenInput = {
    scope: plan.scope,
    machineId: plan.machineId,
    createdAt: plan.createdAt,
    cutoverEpoch: plan.cutoverEpoch,
    sourceDigests: plan.sourceDigests,
    backup: plan.backup,
    observations: records.map((record) => ({
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
  const inputDigest = canonicalDigest(frozenInput);
  const idempotencyKey = canonicalDigest({
    planId: plan.id,
    inputDigest,
    scope: plan.scope,
    cutoverEpoch: plan.cutoverEpoch,
  });
  const planCore = {
    ...plan,
    inputDigest,
    idempotencyKey,
    records,
  };
  const { planDigest: _planDigest, ...coreWithoutDigest } = planCore;
  return {
    ...coreWithoutDigest,
    planDigest: canonicalDigest(coreWithoutDigest),
  } as MigrationPlan;
}

function passingEvidence(plan: MigrationPlan): MigrationGateEvidence {
  return {
    planId: plan.id,
    idempotencyKey: plan.idempotencyKey,
    cutoverEpoch: plan.cutoverEpoch,
    activeWriters: [],
    observedDigests: { ...plan.sourceDigests },
    availableBytes: plan.backup.requiredBytes + 1,
    unknownLedgerEntries: [],
    checksumMismatches: [],
    unresolvedCatalogSkipDigests: [],
    backupRestore: {
      archiveId: plan.backup.archiveId,
      encrypted: true,
      manifestEncrypted: true,
      fileMode: 0o600,
      verifiedArtifacts: [...plan.backup.requiredArtifacts],
      databasePitrVerified: true,
      restoreDrillVerified: true,
      restoredAt: "2026-07-27T12:30:00.000Z",
      cutoverEpoch: plan.cutoverEpoch,
    },
  };
}

describe("v2 migration plan", () => {
  test("uses deterministic default identities and idempotency keys for identical input", () => {
    const first = buildMigrationPlan(planInput());
    const second = buildMigrationPlan(planInput());
    const otherScope = buildMigrationPlan({
      ...planInput(),
      scope: {
        tenantId: "tenant_0000000000000002",
        scopeId: "scope_00000000000000002",
      },
    });

    expect(second).toEqual(first);
    expect(first.id).toMatch(/^plan_[a-f0-9]{32}$/);
    expect(first.idempotencyKey).toBe(second.idempotencyKey);
    expect(otherScope.records[0]!.target.accountId).not.toBe(
      first.records[0]!.target.accountId,
    );
    expect(otherScope.records[0]!.target.runtimeId).not.toBe(
      first.records[0]!.target.runtimeId,
    );
  });

  test("allocates stable immutable targets without rewriting or grouping legacy records", () => {
    const plan = buildPlan();

    expect(plan.records).toHaveLength(2);
    expect(plan.records.map((record) => record.disposition.state)).toEqual([
      "ready",
      "ready",
    ]);
    expect(
      new Set(plan.records.map((record) => record.target.accountId)).size,
    ).toBe(2);
    expect(
      new Set(plan.records.map((record) => record.target.bindingId)).size,
    ).toBe(2);
    expect(
      new Set(plan.records.map((record) => record.target.runtimeId)).size,
    ).toBe(2);
    expect(plan.records[0]?.binding?.rootPath).toBe("/profiles/claude/alice");
    expect(plan.records[1]?.binding?.rootPath).toBe("/profiles/codex/bob");
    expect(plan.records.every((record) => !("credentialRef" in record))).toBe(
      true,
    );
    expect(migrationPlanSchema.parse(plan)).toEqual(plan);

    const rerun = buildPlan(
      [safeObservation("bob", "codex"), safeObservation("alice")],
      plan,
    );
    expect(rerun).toEqual(plan);
  });

  test("freezes one canonical unique alias representation across input, plan, and genesis", () => {
    const observation = safeObservation("alice", "claude", {
      historicalAliases: [
        "legacy:claude:alice-z",
        "legacy:claude:alice-a",
        "legacy:claude:cafe\u0301",
      ],
      historicalSessionAliases: [
        "session:claude:alice-z",
        "session:claude:alice-a",
      ],
    });
    const plan = buildPlan([observation]);
    const canonicallyEquivalentPlan = buildPlan([
      {
        ...observation,
        historicalAliases: [
          "legacy:claude:café",
          "legacy:claude:alice-a",
          "legacy:claude:alice-z",
        ],
      },
    ]);

    expect(canonicallyEquivalentPlan).toEqual(plan);
    expect(plan.records[0]?.historicalAliases).toEqual([
      "legacy:claude:alice-a",
      "legacy:claude:alice-z",
      "legacy:claude:café",
    ]);
    expect(plan.records[0]?.historicalSessionAliases).toEqual([
      "session:claude:alice-a",
      "session:claude:alice-z",
    ]);
    expect(
      createMigrationSidecar(plan).aliasJournal.map((entry) => entry.alias),
    ).toEqual([
      "legacy:claude:alice-a",
      "legacy:claude:alice-z",
      "legacy:claude:café",
      "session:claude:alice-a",
      "session:claude:alice-z",
    ]);

    const forgedRecord = {
      ...plan.records[0]!,
      historicalAliases: [...plan.records[0]!.historicalAliases].reverse(),
    };
    const { planDigest: _planDigest, ...planCore } = plan;
    const forgedCore = {
      ...planCore,
      records: [forgedRecord],
    };
    const forgedPlan = {
      ...forgedCore,
      planDigest: canonicalDigest(forgedCore),
    } as MigrationPlan;
    const duplicateRecord = {
      ...plan.records[0]!,
      historicalAliases: [
        plan.records[0]!.historicalAliases[0]!,
        plan.records[0]!.historicalAliases[0]!,
      ],
    };
    const duplicateCore = {
      ...planCore,
      records: [duplicateRecord],
    };
    const duplicatePlan = {
      ...duplicateCore,
      planDigest: canonicalDigest(duplicateCore),
    };

    expect(migrationPlanSchema.safeParse(forgedPlan).success).toBe(false);
    expect(migrationPlanSchema.safeParse(duplicatePlan).success).toBe(false);
    expect(
      captureError(() =>
        buildMigrationPlan(planInput([observation]), {
          idFactory: stableId,
          existingPlan: forgedPlan,
        }),
      ).code,
    ).toBe("migration_invalid_plan_input");
  });

  test("rejects duplicate aliases before digest allocation and across plan records", () => {
    expect(
      captureError(() =>
        buildPlan([
          safeObservation("alice", "claude", {
            historicalAliases: ["legacy:claude:alice", "legacy:claude:alice"],
          }),
        ]),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildPlan([
          safeObservation("alice", "claude", {
            historicalAliases: [
              "legacy:claude:cafe\u0301",
              "legacy:claude:café",
            ],
          }),
        ]),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildPlan([
          safeObservation("alice", "claude", {
            historicalAliases: ["legacy:shared-account-alias"],
          }),
          safeObservation("bob", "codex", {
            historicalAliases: ["legacy:shared-account-alias"],
          }),
        ]),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildPlan([
          safeObservation("alice", "claude", {
            historicalSessionAliases: ["session:shared-alias"],
          }),
          safeObservation("bob", "codex", {
            historicalSessionAliases: ["session:shared-alias"],
          }),
        ]),
      ).code,
    ).toBe("migration_invalid_plan_input");
  });

  test("rejects changed input when reusing a frozen plan idempotency boundary", () => {
    const plan = buildPlan();
    expect(() =>
      buildPlan(
        [
          safeObservation("alice", "claude", {
            inputDigest: digest("changed"),
          }),
          safeObservation("bob", "codex"),
        ],
        plan,
      ),
    ).toThrow("input digest changed");
  });

  test("allocates ids once but quarantines cross-runtime names and unsafe roots", () => {
    const plan = buildPlan([
      safeObservation("same", "claude"),
      safeObservation("same", "codex"),
      safeObservation("missing", "claude", {
        root: {
          state: "unsafe",
          code: "missing",
          pathDigest: digest("missing-path"),
          reason: "root was not present during the frozen census",
        },
      }),
    ]);

    expect(plan.records).toHaveLength(3);
    expect(
      plan.records.every((record) => record.target.accountId.length >= 16),
    ).toBe(true);
    expect(
      plan.records
        .filter((record) => record.source.name === "same")
        .map((record) => record.disposition),
    ).toEqual([
      { state: "quarantined", reasons: ["same_name_cross_runtime"] },
      { state: "quarantined", reasons: ["same_name_cross_runtime"] },
    ]);
    expect(
      plan.records.find((record) => record.source.name === "missing")
        ?.disposition,
    ).toEqual({
      state: "quarantined",
      reasons: ["root_missing"],
    });
    expect(plan.records.every((record) => record.binding === undefined)).toBe(
      true,
    );
  });

  test("quarantines distinct legacy names that resolve to the same verified root identity", () => {
    const sharedRoot = safeObservation("alice").root;
    const plan = buildPlan([
      safeObservation("alice"),
      safeObservation("bob", "claude", {
        root: sharedRoot,
        inputDigest: digest("same-root-bob"),
      }),
    ]);

    expect(plan.records.map((record) => record.disposition)).toEqual([
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
    ]);
    expect(plan.records.every((record) => record.binding === undefined)).toBe(
      true,
    );
  });

  test("canonicalizes verified root aliases before duplicate physical-root quarantine", () => {
    const sharedIdentity = {
      device: "7",
      inode: "42",
      entryCount: 12,
      byteCount: 2048,
      digest: digest("canonical-shared-root"),
    };
    const plan = buildPlan([
      safeObservation("alice", "claude", {
        root: {
          state: "verified",
          path: "/profiles/shared",
          realPath: "/profiles/shared",
          ...sharedIdentity,
        },
      }),
      safeObservation("bob", "claude", {
        inputDigest: digest("canonical-shared-root-bob"),
        root: {
          state: "verified",
          path: "/profiles/dir/../shared",
          realPath: "/profiles/dir/../shared",
          ...sharedIdentity,
        },
      }),
    ]);

    expect(plan.records.map((record) => record.root)).toEqual([
      expect.objectContaining({ realPath: "/profiles/shared" }),
      expect.objectContaining({ realPath: "/profiles/shared" }),
    ]);
    expect(plan.records.map((record) => record.disposition)).toEqual([
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
    ]);
  });

  test.each([
    {
      label: "hard-link aliases with different canonical paths",
      left: {
        path: "/profiles/hardlink-a",
        realPath: "/profiles/hardlink-a",
        device: "7",
        inode: "42",
        digest: digest("hard-link-shared-root"),
      },
      right: {
        path: "/profiles/hardlink-b",
        realPath: "/profiles/hardlink-b",
        device: "7",
        inode: "42",
        digest: digest("hard-link-shared-root"),
      },
    },
    {
      label: "one canonical path with contradictory inode metadata",
      left: {
        path: "/profiles/shared",
        realPath: "/profiles/shared",
        device: "7",
        inode: "42",
        digest: digest("shared-root"),
      },
      right: {
        path: "/profiles/shared",
        realPath: "/profiles/shared",
        device: "7",
        inode: "43",
        digest: digest("shared-root"),
      },
    },
    {
      label: "one canonical path with contradictory content digests",
      left: {
        path: "/profiles/shared",
        realPath: "/profiles/shared",
        device: "7",
        inode: "42",
        digest: digest("shared-root-left"),
      },
      right: {
        path: "/profiles/shared",
        realPath: "/profiles/shared",
        device: "7",
        inode: "42",
        digest: digest("shared-root-right"),
      },
    },
    {
      label: "one device-inode identity with contradictory content digests",
      left: {
        path: "/profiles/hardlink-a",
        realPath: "/profiles/hardlink-a",
        device: "7",
        inode: "42",
        digest: digest("hard-link-left"),
      },
      right: {
        path: "/profiles/hardlink-b",
        realPath: "/profiles/hardlink-b",
        device: "7",
        inode: "42",
        digest: digest("hard-link-right"),
      },
    },
  ])("quarantines $label", ({ left, right }) => {
    const metadata = {
      state: "verified" as const,
      entryCount: 12,
      byteCount: 2048,
    };
    const plan = buildPlan([
      safeObservation("alice", "claude", {
        root: { ...metadata, ...left },
      }),
      safeObservation("bob", "claude", {
        inputDigest: digest(`physical-conflict-${left.path}-${right.inode}`),
        root: { ...metadata, ...right },
      }),
    ]);

    expect(plan.records.map((record) => record.disposition)).toEqual([
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
    ]);
    expect(plan.records.every((record) => record.binding === undefined)).toBe(
      true,
    );
  });

  test("canonicalizes numeric device and inode aliases before physical-root quarantine", () => {
    const metadata = {
      state: "verified" as const,
      entryCount: 12,
      byteCount: 2048,
      digest: digest("numeric-identity-shared-root"),
    };
    const plan = buildPlan([
      safeObservation("alice", "claude", {
        root: {
          ...metadata,
          path: "/profiles/numeric-a",
          realPath: "/profiles/numeric-a",
          device: "1",
          inode: "2",
        },
      }),
      safeObservation("bob", "claude", {
        inputDigest: digest("numeric-identity-bob"),
        root: {
          ...metadata,
          path: "/profiles/numeric-b",
          realPath: "/profiles/numeric-b",
          device: "01",
          inode: "002",
        },
      }),
    ]);

    expect(
      plan.records.map((record) =>
        record.root.state === "verified"
          ? [record.root.device, record.root.inode]
          : null,
      ),
    ).toEqual([
      ["1", "2"],
      ["1", "2"],
    ]);
    expect(plan.records.map((record) => record.disposition)).toEqual([
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
      { state: "quarantined", reasons: ["duplicate_verified_root"] },
    ]);
  });

  test("does not conflate equal content digests without a path or device-inode identity match", () => {
    const sharedDigest = digest("same-content-distinct-roots");
    const plan = buildPlan([
      safeObservation("alice", "claude", {
        root: {
          ...safeObservation("alice").root,
          digest: sharedDigest,
        },
      }),
      safeObservation("bob", "claude", {
        inputDigest: digest("same-content-bob"),
        root: {
          ...safeObservation("bob").root,
          digest: sharedDigest,
        },
      }),
    ]);

    expect(plan.records.map((record) => record.disposition)).toEqual([
      { state: "ready" },
      { state: "ready" },
    ]);
  });

  test("fails duplicate source observations rather than silently overwriting", () => {
    expect(() =>
      buildPlan([safeObservation("alice"), safeObservation("alice")]),
    ).toThrow("duplicate legacy source key");
  });

  test("fails conflicting runtime definitions and incomplete census contracts", () => {
    expect(() =>
      buildPlan([
        safeObservation("alice"),
        safeObservation("bob", "claude", {
          runtimeLabel: "Different Claude Runtime",
        }),
      ]),
    ).toThrow("conflicting runtime labels");

    expect(
      captureError(() =>
        buildMigrationPlan(planInput(), {
          idFactory: (kind, seed) =>
            kind === "account" ? "account_duplicate0000" : stableId(kind, seed),
        }),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildMigrationPlan(planInput([safeObservation("alice")]), {
          idFactory: () => "shared_identifier_000000000001",
        }),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildMigrationPlan(
          {
            ...planInput([safeObservation("alice")]),
            backup: { ...backupPlan(), requiredBytes: 2047 },
          },
          { idFactory: stableId },
        ),
      ).code,
    ).toBe("migration_invalid_plan_input");

    expect(
      captureError(() =>
        buildMigrationPlan(
          {
            ...planInput(),
            cutoverEpoch: "2026-07-27T11:59:59.999Z",
          },
          { idFactory: stableId },
        ),
      ).code,
    ).toBe("migration_invalid_plan_input");

    const plan = buildPlan();
    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        sourceDigests: {
          ...plan.sourceDigests,
          untrackedSource: digest("unknown"),
        },
      }).success,
    ).toBe(false);

    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          {
            ...plan.records[0],
            binding: {
              ...plan.records[0]!.binding!,
              credentialRef: "vault://must-not-enter-sidecar",
            },
          },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);

    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          {
            ...plan.records[0],
            disposition: {
              state: "quarantined",
              reasons: ["catalog_skip"],
            },
            binding: undefined,
          },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);

    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          {
            ...plan.records[0],
            sourceKey: "local-v1:machine_000000000000001:claude:forged",
          },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);

    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          {
            ...plan.records[0],
            binding: {
              ...plan.records[0]!.binding!,
              accountId: plan.records[1]!.target.accountId,
            },
          },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);

    const forgedAccountId = "account_forged0000000000001";
    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          {
            ...plan.records[0],
            target: {
              ...plan.records[0]!.target,
              accountId: forgedAccountId,
            },
            binding: {
              ...plan.records[0]!.binding!,
              accountId: forgedAccountId,
            },
          },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);

    expect(
      captureError(() =>
        buildMigrationPlan(planInput(), {
          existingPlan: {
            ...plan,
            records: [
              {
                ...plan.records[0],
                runtimeLabel: "Forged but schema-valid label",
              },
              plan.records[1],
            ],
          },
        }),
      ).code,
    ).toBe("migration_invalid_plan_input");
  });

  test.each([
    {
      label: "ready/ready",
      observations: [
        safeObservation("alice"),
        safeObservation("bob", "claude", {
          inputDigest: digest("runtime-ready-ready-bob"),
        }),
      ],
      expectedDispositions: ["ready", "ready"],
    },
    {
      label: "ready/quarantined",
      observations: [
        safeObservation("alice"),
        safeObservation("missing", "claude", {
          inputDigest: digest("runtime-ready-quarantined-missing"),
          root: {
            state: "unsafe" as const,
            code: "missing" as const,
            pathDigest: digest("runtime-ready-quarantined-path"),
            reason: "missing",
          },
        }),
      ],
      expectedDispositions: ["ready", "quarantined"],
    },
    {
      label: "quarantined/quarantined",
      observations: [
        safeObservation("missing", "claude", {
          inputDigest: digest("runtime-quarantined-missing"),
          root: {
            state: "unsafe" as const,
            code: "missing" as const,
            pathDigest: digest("runtime-quarantined-missing-path"),
            reason: "missing",
          },
        }),
        safeObservation("unreadable", "claude", {
          inputDigest: digest("runtime-quarantined-unreadable"),
          root: {
            state: "unsafe" as const,
            code: "unreadable" as const,
            pathDigest: digest("runtime-quarantined-unreadable-path"),
            reason: "unreadable",
          },
        }),
      ],
      expectedDispositions: ["quarantined", "quarantined"],
    },
  ])(
    "rejects a fully rehashed $label plan whose shared runtime id has conflicting definitions",
    ({ observations, expectedDispositions }) => {
      const plan = buildPlan(observations);
      expect(plan.records.map((record) => record.disposition.state)).toEqual(
        expectedDispositions,
      );
      expect(
        new Set(plan.records.map((record) => record.target.runtimeId)),
      ).toEqual(new Set([plan.records[0]!.target.runtimeId]));
      expect(migrationPlanSchema.safeParse(plan).success).toBe(true);

      const marker = `Bearer runtime definition ${expectedDispositions.join("-")}`;
      const forgedRecords = plan.records.map((record, index) =>
        index === 1
          ? {
              ...record,
              runtimeLabel: marker,
            }
          : record,
      ) as MigrationPlan["records"];
      const forgedPlan = rehashPlanWithRecords(plan, forgedRecords);

      expect(forgedPlan.inputDigest).not.toBe(plan.inputDigest);
      expect(forgedPlan.idempotencyKey).not.toBe(plan.idempotencyKey);
      expect(forgedPlan.planDigest).not.toBe(plan.planDigest);
      expect(migrationPlanSchema.safeParse(forgedPlan).success).toBe(false);

      const sidecarError = captureError(() =>
        createMigrationSidecar(forgedPlan),
      );
      expect(sidecarError.code).toBe("migration_invalid_sidecar_plan");
      expect(JSON.stringify(sidecarError)).not.toContain(marker);
      expect(String(sidecarError)).not.toContain(marker);
    },
  );

  test("requires a trusted original census to detect a fully rehashed self-consistent runtime remap", () => {
    const observations = [
      safeObservation("alice"),
      safeObservation("bob", "claude", {
        inputDigest: digest("runtime-self-consistent-remap-bob"),
      }),
    ];
    const plan = buildPlan(observations);
    const remappedLabel = "Claude Code Remapped";
    expect(
      new Set(plan.records.map((record) => record.target.runtimeId)).size,
    ).toBe(1);
    expect(
      plan.records.every((record) => record.runtimeLabel === "Claude Code"),
    ).toBe(true);
    const remappedPlan = rehashPlanWithRecords(
      plan,
      plan.records.map((record) => ({
        ...record,
        runtimeLabel: remappedLabel,
      })) as MigrationPlan["records"],
    );

    expect(
      remappedPlan.records.every(
        (record) => record.runtimeLabel === remappedLabel,
      ),
    ).toBe(true);
    expect(remappedPlan.inputDigest).not.toBe(plan.inputDigest);
    expect(remappedPlan.idempotencyKey).not.toBe(plan.idempotencyKey);
    expect(remappedPlan.planDigest).not.toBe(plan.planDigest);
    expect(migrationPlanSchema.parse(remappedPlan)).toEqual(remappedPlan);
    expect(createMigrationSidecar(remappedPlan).plan).toEqual(remappedPlan);

    const trustedCensusError = captureError(() =>
      buildMigrationPlan(planInput(observations), {
        idFactory: stableId,
        existingPlan: remappedPlan,
      }),
    );
    expect(trustedCensusError.code).toBe(
      "migration_frozen_input_digest_changed",
    );
    expect(JSON.stringify(trustedCensusError)).not.toContain(remappedLabel);
  });

  test("requires frozen target identities when reusing a trusted existing plan", () => {
    const observations = [safeObservation("alice")];
    const plan = buildPlan(observations);
    const forgedAccountId = "account_forged0000000000001";
    const forgedRecords = plan.records.map((record, index) =>
      index === 0
        ? {
            ...record,
            target: {
              ...record.target,
              accountId: forgedAccountId,
            },
            ...(record.binding
              ? {
                  binding: {
                    ...record.binding,
                    accountId: forgedAccountId,
                  },
                }
              : {}),
          }
        : record,
    ) as MigrationPlan["records"];
    const forgedPlan = rehashPlanWithRecords(plan, forgedRecords);

    expect(forgedPlan.inputDigest).toBe(plan.inputDigest);
    expect(forgedPlan.planDigest).not.toBe(plan.planDigest);
    expect(migrationPlanSchema.safeParse(forgedPlan).success).toBe(true);

    const trustedCensusError = captureError(() =>
      buildMigrationPlan(planInput(observations), {
        idFactory: stableId,
        existingPlan: forgedPlan,
      }),
    );
    expect(trustedCensusError).toBeInstanceOf(MigrationDriftError);
    expect(trustedCensusError.code).toBe(
      "migration_frozen_output_identity_changed",
    );
    expect(JSON.stringify(trustedCensusError)).not.toContain(forgedAccountId);
  });

  test.each([
    ["case", "claude code"],
    ["noncanonical whitespace", "Claude  Code"],
    ["noncanonical Unicode", "Claude Cafe\u0301"],
  ])(
    "keeps builder and schema aligned for %s runtime-label variants",
    (_variant, conflictingLabel) => {
      const baseLabel =
        conflictingLabel === "Claude Cafe\u0301"
          ? "Claude Café"
          : "Claude Code";
      const observations = [
        safeObservation("alice", "claude", { runtimeLabel: baseLabel }),
        safeObservation("bob", "claude", {
          runtimeLabel: baseLabel,
          inputDigest: digest(`runtime-variant-${conflictingLabel}`),
        }),
      ];
      const plan = buildPlan(observations);
      const marker = conflictingLabel;
      const forgedPlan = rehashPlanWithRecords(
        plan,
        plan.records.map((record, index) =>
          index === 1 ? { ...record, runtimeLabel: marker } : record,
        ) as MigrationPlan["records"],
      );

      expect(migrationPlanSchema.safeParse(forgedPlan).success).toBe(false);
      const existingPlanError = captureError(() =>
        buildMigrationPlan(planInput(observations), {
          idFactory: stableId,
          existingPlan: forgedPlan,
        }),
      );
      expect(existingPlanError.code).toBe("migration_invalid_plan_input");
      expect(JSON.stringify(existingPlanError)).not.toContain(marker);
    },
  );

  test("preserves multiple records that share one identical canonical runtime definition", () => {
    const plan = buildPlan([
      safeObservation("alice"),
      safeObservation("bob", "claude", {
        inputDigest: digest("identical-runtime-definition-bob"),
      }),
    ]);

    expect(
      new Set(plan.records.map((record) => record.target.runtimeId)).size,
    ).toBe(1);
    expect(migrationPlanSchema.parse(plan)).toEqual(plan);
    const conflictingRuntimeId = "runtime_distinct000000000001";
    const conflictingIdPlan = rehashPlanWithRecords(
      plan,
      plan.records.map((record, index) =>
        index === 1
          ? {
              ...record,
              target: {
                ...record.target,
                runtimeId: conflictingRuntimeId,
              },
              binding: record.binding
                ? {
                    ...record.binding,
                    runtimeId: conflictingRuntimeId,
                  }
                : undefined,
            }
          : record,
      ) as MigrationPlan["records"],
    );
    expect(migrationPlanSchema.safeParse(conflictingIdPlan).success).toBe(
      false,
    );

    const marker = "Bearer conflicting runtime definition";
    const builderError = captureError(() =>
      buildPlan([
        safeObservation("alice"),
        safeObservation("bob", "claude", {
          runtimeLabel: marker,
          inputDigest: digest("conflicting-runtime-definition-bob"),
        }),
      ]),
    );
    expect(builderError.code).toBe("migration_runtime_definition_conflict");
    expect(JSON.stringify(builderError)).not.toContain(marker);
    expect(String(builderError)).not.toContain(marker);
  });

  test("redacts paths and aliases while retaining counts, digests, and conflict evidence", () => {
    const plan = buildPlan([
      safeObservation("alice", "credential-token-runtime", {
        runtimeLabel: "Bearer synthetic credential marker",
      }),
      safeObservation("missing", "codex", {
        root: {
          state: "unsafe",
          code: "missing",
          pathDigest: digest("missing-path"),
          reason: "private root /secret/missing was absent",
        },
      }),
    ]);
    const redacted = redactMigrationPlan(plan);
    const encoded = JSON.stringify(redacted);
    const sensitivePlanRecord = plan.records.find(
      (record) => record.source.tool === "credential-token-runtime",
    )!;
    const sensitiveRecord = redacted.records.find(
      (record) =>
        record.target.accountId === sensitivePlanRecord.target.accountId,
    );
    const unsafeRecord = redacted.records.find(
      (record) => record.root.state === "unsafe",
    );

    expect(encoded).not.toContain("/profiles/");
    expect(encoded).not.toContain("/secret/");
    expect(encoded).not.toContain("alice");
    expect(encoded).not.toContain("legacy:claude:alice");
    expect(encoded).not.toContain("credential");
    expect(encoded).not.toContain("Bearer synthetic credential marker");
    expect(encoded).not.toContain("Codex CLI");
    expect(
      redacted.records.every(
        (record) => !("runtimeLabel" in record) && !("tool" in record.source),
      ),
    ).toBe(true);
    expect(sensitiveRecord?.source).not.toHaveProperty("tool");
    expect(sensitiveRecord).not.toHaveProperty("runtimeLabel");
    expect(sensitiveRecord?.source.toolDigest).toBe(
      redactionDigest("source.tool", "credential-token-runtime"),
    );
    expect(sensitiveRecord?.runtimeLabelDigest).toBe(
      redactionDigest("runtime.label", "Bearer synthetic credential marker"),
    );
    expect(sensitiveRecord?.root?.byteCount).toBe(2048);
    expect(sensitiveRecord?.root?.digest).toBe(
      digest("root-credential-token-runtime-alice"),
    );
    expect(redacted.redactionVersion).toBe(1);
    expect(sensitiveRecord?.root).not.toHaveProperty("device");
    expect(sensitiveRecord?.root).not.toHaveProperty("inode");
    expect(sensitiveRecord?.root).toMatchObject({
      deviceDigest: redactionDigest("root.device", "1"),
      inodeDigest: redactionDigest(
        "root.inode",
        sensitivePlanRecord.root.state === "verified"
          ? sensitivePlanRecord.root.inode
          : "",
      ),
    });
    if (sensitiveRecord?.root?.state === "verified") {
      expect(sensitiveRecord.root.pathDigest).not.toBe(
        sensitiveRecord.root.realPathDigest,
      );
    }
    expect(sensitiveRecord?.historicalAliasDigests).toHaveLength(1);
    expect(sensitiveRecord?.historicalSessionAliasDigests).toHaveLength(1);
    expect(unsafeRecord?.root).toMatchObject({
      state: "unsafe",
      code: "missing",
      pathDigest: redactionDigest("root.path", digest("missing-path")),
      reasonDigest: redactionDigest(
        "root.unsafe-reason",
        "private root /secret/missing was absent",
      ),
    });
    expect(unsafeRecord?.root.pathDigest).not.toBe(digest("missing-path"));
  });

  test("domain-separates and length-frames every caller-origin redacted value", () => {
    const shared = "shared-redaction-marker";
    const device = "98765432101234567890";
    const inode = device;
    const plan = buildPlan([
      safeObservation(shared, shared, {
        runtimeLabel: shared,
        root: {
          ...safeObservation(shared, shared).root,
          device,
          inode,
        },
        historicalAliases: [shared, ".sessionframing-marker"],
        historicalSessionAliases: [shared, "framing-marker"],
      }),
    ]);
    const redacted = redactMigrationPlan(plan);
    const encoded = JSON.stringify(redacted);
    const record = redacted.records[0]!;

    const sameValueDigests = [
      record.source.toolDigest,
      record.source.nameDigest,
      record.runtimeLabelDigest,
      record.historicalAliasDigests[0],
      record.historicalSessionAliasDigests[0],
    ];
    expect(new Set(sameValueDigests).size).toBe(sameValueDigests.length);
    expect(record.historicalAliasDigests[0]).not.toBe(
      record.historicalSessionAliasDigests[0],
    );
    expect(record.historicalAliasDigests[0]).toBe(
      redactionDigest("alias", ".sessionframing-marker"),
    );
    expect(record.historicalSessionAliasDigests[0]).toBe(
      redactionDigest("alias.session", "framing-marker"),
    );
    expect(migrationRedactionDigest("alias", ".sessionframing-marker")).toBe(
      redactionDigest("alias", ".sessionframing-marker"),
    );
    expect(encoded).not.toContain(shared);
    expect(encoded).not.toContain(device);
    expect(encoded).not.toContain(inode);
    expect(record.root).not.toHaveProperty("device");
    expect(record.root).not.toHaveProperty("inode");
    expect(record.root).toMatchObject({
      deviceDigest: redactionDigest("root.device", device),
      inodeDigest: redactionDigest("root.inode", inode),
    });
    if (record.root.state === "verified") {
      expect(record.root.deviceDigest).not.toBe(record.root.inodeDigest);
    }
  });

  test("returns stable diagnostic codes and opaque references without caller text", () => {
    const marker = "bearer-secret-diagnostic-marker";
    const duplicate = safeObservation(marker, marker);
    const duplicateError = captureError(() =>
      buildPlan([duplicate, duplicate]),
    );
    const runtimeError = captureError(() =>
      buildPlan([
        safeObservation("alice", marker, { runtimeLabel: `${marker}-one` }),
        safeObservation("bob", marker, { runtimeLabel: `${marker}-two` }),
      ]),
    );
    const markerPlan = buildMigrationPlan(planInput(), {
      idFactory: (kind, seed) =>
        kind === "plan" ? `plan-${marker}` : stableId(kind, seed),
    });
    const frozenPlanError = captureError(() =>
      buildMigrationPlan(
        planInput([
          safeObservation("alice", "claude", {
            inputDigest: digest("changed"),
          }),
          safeObservation("bob", "codex"),
        ]),
        { existingPlan: markerPlan },
      ),
    );
    const initial = createMigrationSidecar(buildPlan());
    const unknownSourceError = captureError(() =>
      appendMigrationAlias(initial, {
        kind: "legacy_account",
        alias: marker,
        sourceKey: marker,
        targetId: initial.plan.records[0]!.target.accountId,
      }),
    );
    const wrongTargetError = captureError(() =>
      appendMigrationAlias(initial, {
        kind: "legacy_account",
        alias: marker,
        sourceKey: initial.plan.records[0]!.sourceKey,
        targetId: initial.plan.records[1]!.target.accountId,
      }),
    );
    const aliasOwner = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: marker,
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    const aliasConflictError = captureError(() =>
      appendMigrationAlias(aliasOwner, {
        kind: "legacy_account",
        alias: marker,
        sourceKey: initial.plan.records[1]!.sourceKey,
        targetId: initial.plan.records[1]!.target.accountId,
      }),
    );

    for (const error of [
      duplicateError,
      runtimeError,
      frozenPlanError,
      unknownSourceError,
      wrongTargetError,
      aliasConflictError,
    ]) {
      const exported = JSON.stringify({
        name: error.name,
        message: error.message,
        code: error.code,
        count: error.count,
        references: error.references,
      });
      expect(exported).not.toContain(marker);
      expect(error.code).toMatch(/^migration_[a-z0-9_]+$/);
      expect(error.references?.length).toBeGreaterThan(0);
      expect(exported).toMatch(/sha256:[a-f0-9]{64}/);
    }

    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    writeFileSync(
      sidecarPath,
      `${JSON.stringify({ ...initial, state: marker })}\n`,
      { mode: 0o600 },
    );
    const loadError = captureError(() =>
      new MigrationSidecarStore({
        sidecarPath,
        legacyStorePath: legacy,
      }).load(),
    );
    expect(loadError.message).not.toContain(marker);
    expect(loadError.code).toBe("migration_sidecar_parse_failed");

    const domainError = captureError(() =>
      migrationRedactionDigest(marker as never, marker),
    );
    expect(domainError.message).not.toContain(marker);
    expect(domainError.code).toBe("migration_invalid_redaction_domain");
  });

  test("runtime-validates public discriminants before branching or echoing caller text", () => {
    const marker = "bearer-invalid-discriminant-marker";
    const plan = buildPlan();
    const initial = createMigrationSidecar(plan);
    const invalidIntent = captureError(() =>
      evaluateMigrationGates(plan, passingEvidence(plan), marker as never),
    );
    const invalidTarget = captureError(() =>
      transitionMigrationSidecar(initial, marker as never),
    );
    const invalidAliasKind = captureError(() =>
      appendMigrationAlias(initial, {
        kind: marker as never,
        alias: "safe-alias",
        sourceKey: initial.plan.records[0]!.sourceKey,
        targetId: initial.plan.records[0]!.target.accountId,
      }),
    );
    const invalidRedactionValue = captureError(() =>
      migrationRedactionDigest("alias", { [marker]: marker } as never),
    );
    const throwingInput = {
      ...planInput(),
    } as Record<string, unknown>;
    Object.defineProperty(throwingInput, "scope", {
      enumerable: true,
      get() {
        throw new MigrationConflictError(marker);
      },
    });
    const throwingGetter = captureError(() =>
      buildMigrationPlan(throwingInput as never),
    );
    const throwingIdFactory = captureError(() =>
      buildMigrationPlan(planInput(), {
        idFactory() {
          throw new MigrationConflictError(marker);
        },
      }),
    );

    for (const [error, code] of [
      [invalidIntent, "migration_invalid_gate_intent"],
      [invalidTarget, "migration_invalid_transition_target"],
      [invalidAliasKind, "migration_invalid_alias_input"],
      [invalidRedactionValue, "migration_invalid_redaction_value"],
      [throwingGetter, "migration_invalid_plan_input"],
      [throwingIdFactory, "migration_id_allocation_failed"],
    ] as const) {
      expect(error).toBeInstanceOf(MigrationConflictError);
      expect(error.code).toBe(code);
      expect(error.message).not.toContain(marker);
      expect(String(error)).not.toContain(marker);
      expect(JSON.stringify(error)).not.toContain(marker);
      expect(inspect(error)).not.toContain(marker);
    }
  });

  test("domain-separates account and session diagnostic aliases", () => {
    const marker = "shared-diagnostic-alias-marker";
    const initial = createMigrationSidecar(buildPlan());
    const accountError = captureError(() =>
      appendMigrationAlias(initial, {
        kind: "legacy_account",
        alias: marker,
        sourceKey: "unknown:account:source",
        targetId: initial.plan.records[0]!.target.accountId,
      }),
    );
    const sessionError = captureError(() =>
      appendMigrationAlias(initial, {
        kind: "session_ref",
        alias: marker,
        sourceKey: "unknown:session:source",
        targetId: initial.plan.records[0]!.target.bindingId,
      }),
    );
    const accountAlias = accountError.references?.find(
      (reference) =>
        (reference as { domain?: string }).domain ===
        "diagnostic.alias.account",
    ) as { domain: string; digest: string } | undefined;
    const sessionAlias = sessionError.references?.find(
      (reference) =>
        (reference as { domain?: string }).domain ===
        "diagnostic.alias.session",
    ) as { domain: string; digest: string } | undefined;

    expect(accountAlias).toBeDefined();
    expect(sessionAlias).toBeDefined();
    expect(accountAlias?.digest).not.toBe(sessionAlias?.digest);
    expect(accountAlias?.digest).toBe(
      redactionDigest("diagnostic.alias.account", marker),
    );
    expect(sessionAlias?.digest).toBe(
      redactionDigest("diagnostic.alias.session", marker),
    );
    expect(
      captureError(() =>
        appendMigrationAlias(initial, {
          kind: "legacy_account",
          alias: marker,
          sourceKey: "another:unknown:account",
          targetId: initial.plan.records[0]!.target.accountId,
        }),
      ).references?.find(
        (reference) =>
          (reference as { domain?: string }).domain ===
          "diagnostic.alias.account",
      ),
    ).toMatchObject({ digest: accountAlias?.digest });
  });

  test("sanitizes strict-schema failures at every public migration boundary", async () => {
    const marker = "bearer-unknown-schema-key-marker";
    const plan = buildPlan();
    const initial = createMigrationSidecar(plan);
    const errors = [
      captureError(() =>
        buildMigrationPlan({ ...planInput(), [marker]: marker } as never),
      ),
      captureError(() =>
        buildMigrationPlan(planInput(), { [marker]: marker } as never),
      ),
      captureError(() =>
        redactMigrationPlan({ ...plan, [marker]: marker } as never),
      ),
      captureError(() =>
        evaluateMigrationGates(
          plan,
          { ...passingEvidence(plan), [marker]: marker } as never,
          "partial",
        ),
      ),
      captureError(() =>
        createMigrationSidecar({ ...plan, [marker]: marker } as never),
      ),
      captureError(() =>
        appendMigrationAlias(initial, {
          kind: "legacy_account",
          alias: "safe-alias",
          sourceKey: initial.plan.records[0]!.sourceKey,
          targetId: initial.plan.records[0]!.target.accountId,
          [marker]: marker,
        } as never),
      ),
      captureError(() =>
        transitionMigrationSidecar(
          { ...initial, [marker]: marker } as never,
          "partial_ready",
          { gateEvidence: passingEvidence(plan) },
        ),
      ),
      captureError(() =>
        transitionMigrationSidecar(initial, "partial_ready", {
          gateEvidence: passingEvidence(plan),
          [marker]: marker,
        } as never),
      ),
    ];
    const backfillError = await applyScopedBackfill(
      transitionMigrationSidecar(initial, "partial_ready", {
        gateEvidence: passingEvidence(plan),
      }),
      {
        async transaction() {
          throw new MigrationConflictError(marker);
        },
      },
    ).then(
      () => {
        throw new Error("expected backfill to reject");
      },
      (error) => error as Error & { code?: string },
    );
    const unknownPortError = await applyScopedBackfill(
      transitionMigrationSidecar(initial, "partial_ready", {
        gateEvidence: passingEvidence(plan),
      }),
      {
        [marker]: marker,
        async transaction() {
          throw new Error(
            "strict port parsing should reject before invocation",
          );
        },
      } as never,
    ).then(
      () => {
        throw new Error("expected strict backfill port parsing to reject");
      },
      (error) => error as Error & { code?: string },
    );
    errors.push(backfillError, unknownPortError);

    for (const error of errors) {
      const exported = [
        error.message,
        String(error),
        JSON.stringify(error),
        inspect(error),
      ].join("\n");
      expect(error).toBeInstanceOf(MigrationConflictError);
      expect(error.code).toMatch(/^migration_[a-z0-9_]+$/);
      expect(exported).not.toContain(marker);
      expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
    }
  });

  test("strict schemas reject credential and transcript tunnels", () => {
    const plan = buildPlan();
    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        credentialRef: "vault://secret",
      }).success,
    ).toBe(false);
    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        records: [
          { ...plan.records[0], transcript: "secret transcript" },
          plan.records[1],
        ],
      }).success,
    ).toBe(false);
  });
});

describe("backup, gates, aliases, and cutover states", () => {
  test("requires encrypted 0600 complete backup and restore contracts", () => {
    expect(backupRestorePlanSchema.parse(backupPlan())).toEqual(backupPlan());
    expect(
      backupRestorePlanSchema.safeParse({
        ...backupPlan(),
        manifestEncrypted: false,
      }).success,
    ).toBe(false);
    expect(
      backupRestorePlanSchema.safeParse({ ...backupPlan(), fileMode: 0o644 })
        .success,
    ).toBe(false);
    expect(
      backupRestorePlanSchema.safeParse({
        ...backupPlan(),
        requiredArtifacts: backupPlan().requiredArtifacts.filter(
          (artifact) => artifact !== "auth_snapshots",
        ),
      }).success,
    ).toBe(false);
  });

  test("allows partial scoped readiness with quarantine but blocks final cutover", () => {
    const plan = buildPlan([
      safeObservation("alice"),
      safeObservation("missing", "claude", {
        root: {
          state: "unsafe",
          code: "missing",
          pathDigest: digest("missing-path"),
          reason: "missing",
        },
      }),
    ]);
    const evidence = passingEvidence(plan);

    expect(evaluateMigrationGates(plan, evidence, "partial")).toEqual({
      intent: "partial",
      ready: true,
      nextState: "partial_ready",
      reasons: [],
    });
    expect(evaluateMigrationGates(plan, evidence, "final")).toMatchObject({
      intent: "final",
      ready: false,
      nextState: null,
      reasons: ["unresolved_quarantine"],
    });
  });

  test("fails closed on writers, drift, space, ledger, catalog, restore, or epoch mismatch", () => {
    const plan = buildPlan();
    const base = passingEvidence(plan);
    const variants: Array<[string, MigrationGateEvidence]> = [
      ["active_writers", { ...base, activeWriters: ["accounts-supervisor"] }],
      [
        "input_digest_drift",
        {
          ...base,
          observedDigests: {
            ...base.observedDigests,
            v1Registry: digest("drift"),
          },
        },
      ],
      [
        "insufficient_free_space",
        { ...base, availableBytes: plan.backup.requiredBytes - 1 },
      ],
      [
        "unknown_ledger_entry",
        { ...base, unknownLedgerEntries: ["future_migration"] },
      ],
      ["checksum_mismatch", { ...base, checksumMismatches: ["accounts_0005"] }],
      [
        "catalog_skip",
        { ...base, unresolvedCatalogSkipDigests: [digest("skip")] },
      ],
      [
        "restore_unverified",
        {
          ...base,
          backupRestore: { ...base.backupRestore, restoreDrillVerified: false },
        },
      ],
      [
        "restore_after_cutover_epoch",
        {
          ...base,
          backupRestore: {
            ...base.backupRestore,
            restoredAt: "2026-07-27T13:00:01.000Z",
          },
        },
      ],
      [
        "cutover_epoch_mismatch",
        {
          ...base,
          backupRestore: {
            ...base.backupRestore,
            cutoverEpoch: "2026-07-27T13:00:01.000Z",
          },
        },
      ],
    ];

    for (const [reason, evidence] of variants) {
      expect(evaluateMigrationGates(plan, evidence, "partial")).toMatchObject({
        ready: false,
        reasons: expect.arrayContaining([reason]),
      });
    }

    expect(
      evaluateMigrationGates(
        plan,
        {
          ...base,
          backupRestore: {
            ...base.backupRestore,
            restoredAt: "2026-07-27T11:59:59.999Z",
          },
        },
        "partial",
      ),
    ).toMatchObject({
      ready: false,
      reasons: expect.arrayContaining(["restore_before_plan_creation"]),
    });
  });

  test("journals aliases with a digest chain and exact idempotent replay", () => {
    const initial = createMigrationSidecar(buildPlan());
    expect(initial.aliasJournal.map((entry) => entry.kind)).toEqual([
      "legacy_account",
      "session_ref",
      "legacy_account",
      "session_ref",
    ]);
    const alias: MigrationAliasInput = {
      kind: "legacy_account",
      alias: "legacy:claude:alice-renamed",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    };
    const once = appendMigrationAlias(initial, alias);
    const replay = appendMigrationAlias(once, alias);

    expect(once.aliasJournal).toHaveLength(initial.aliasJournal.length + 1);
    expect(replay).toEqual(once);
    expect(once.aliasJournal.at(-1)?.previousDigest).toBe(
      initial.aliasJournal.at(-1)?.digest ?? null,
    );
    expect(once.aliasJournal.at(-1)?.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(() =>
      appendMigrationAlias(once, {
        ...alias,
        targetId: initial.plan.records[1]!.target.accountId,
      }),
    ).toThrow(MigrationConflictError);
    expect(() =>
      appendMigrationAlias(once, {
        kind: "session_ref",
        alias: "session:claude:wrong-target",
        sourceKey: initial.plan.records[0]!.sourceKey,
        targetId: initial.plan.records[0]!.target.accountId,
      }),
    ).toThrow("does not target its frozen immutable identity");
    expect(
      captureError(() =>
        appendMigrationAlias(once, {
          ...alias,
          alias: "legacy:claude:cafe\u0301",
        }),
      ).code,
    ).toBe("migration_invalid_alias_input");
  });

  test("enforces durable gate and scope-bound backfill receipts across cutover states", async () => {
    const plan = buildPlan();
    const initial = createMigrationSidecar(plan);
    expect(() => transitionMigrationSidecar(initial, "partial_ready")).toThrow(
      "requires current migration gate evidence",
    );
    const partialReady = transitionMigrationSidecar(initial, "partial_ready", {
      gateEvidence: passingEvidence(plan),
    });
    expect(partialReady.gateReceipts).toHaveLength(1);
    expect(partialReady.gateReceipts[0]).toMatchObject({
      intent: "partial",
      targetState: "partial_ready",
      sourceIntegrityDigest: initial.integrityDigest,
    });
    expect(() =>
      transitionMigrationSidecar(partialReady, "partial_applied"),
    ).toThrow("requires a committed scope-bound backfill receipt");
    const partialBackfill = await applyScopedBackfill(
      partialReady,
      new RecordingBackfillPort(),
    );
    const { digest: _receiptDigest, ...partialReceiptCore } =
      partialBackfill.receipt;
    const wrongScopeCore = {
      ...partialReceiptCore,
      scope: {
        tenantId: "tenant_0000000000000002",
        scopeId: "scope_00000000000000002",
      },
    };
    expect(() =>
      transitionMigrationSidecar(partialReady, "partial_applied", {
        backfillReceipt: {
          ...wrongScopeCore,
          digest: canonicalDigest(wrongScopeCore),
        },
      }),
    ).toThrow("not bound to the frozen plan and scope");
    const aliasAdvanced = appendMigrationAlias(partialReady, {
      kind: "legacy_account",
      alias: "legacy:claude:alice-after-backfill",
      sourceKey: partialReady.plan.records[0]!.sourceKey,
      targetId: partialReady.plan.records[0]!.target.accountId,
    });
    expect(() =>
      transitionMigrationSidecar(aliasAdvanced, "partial_applied", {
        backfillReceipt: partialBackfill.receipt,
      }),
    ).toThrow("does not bind the exact partial_ready predecessor");
    const partialApplied = transitionMigrationSidecar(
      partialReady,
      "partial_applied",
      {
        backfillReceipt: partialBackfill.receipt,
      },
    );
    const finalReady = transitionMigrationSidecar(
      partialApplied,
      "final_ready",
      {
        gateEvidence: passingEvidence(plan),
      },
    );
    const finalBackfill = await applyScopedBackfill(
      finalReady,
      new RecordingBackfillPort(),
    );
    const finalApplied = transitionMigrationSidecar(
      finalReady,
      "final_applied",
      {
        backfillReceipt: finalBackfill.receipt,
      },
    );

    expect(finalApplied.state).toBe("final_applied");
    expect(finalApplied.gateReceipts).toHaveLength(2);
    expect(finalApplied.backfillReceipts).toHaveLength(2);
    expect(() =>
      transitionMigrationSidecar(finalApplied, "partial_applied"),
    ).toThrow("cannot move migration state backwards");

    const quarantined = createMigrationSidecar(
      buildPlan([
        safeObservation("missing", "claude", {
          root: {
            state: "unsafe",
            code: "missing",
            pathDigest: digest("missing"),
            reason: "missing",
          },
        }),
      ]),
    );
    expect(() =>
      transitionMigrationSidecar(quarantined, "final_ready", {
        gateEvidence: passingEvidence(quarantined.plan),
      }),
    ).toThrow("unresolved_quarantine");
  });

  test("rejects a receipt copied from an unrelated predecessor even after checksums are recomputed", () => {
    const initial = createMigrationSidecar(buildPlan());
    const firstPredecessor = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:first-predecessor",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    const secondPredecessor = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:second-predecessor",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    const firstReady = transitionMigrationSidecar(
      firstPredecessor,
      "partial_ready",
      {
        gateEvidence: passingEvidence(initial.plan),
      },
    );
    const secondReady = transitionMigrationSidecar(
      secondPredecessor,
      "partial_ready",
      {
        gateEvidence: passingEvidence(initial.plan),
      },
    );
    const {
      integrityDigest: _integrityDigest,
      gateReceipts: _gateReceipts,
      ...firstCore
    } = firstReady;
    const forgedCore = {
      ...firstCore,
      gateReceipts: secondReady.gateReceipts,
    };
    const forged = {
      ...forgedCore,
      integrityDigest: canonicalDigest(forgedCore),
    } as MigrationSidecar;

    expect(() => transitionMigrationSidecar(forged, "partial_ready")).toThrow(
      "predecessor transition chain",
    );
  });
});

class RecordingBackfillTransaction implements MigrationBackfillTransaction {
  readonly events: string[] = [];
  failAt?: string;
  invalidResultAt?: string;

  async ensureRuntime(
    runtime: ScopedBackfillRuntime,
  ): Promise<"created" | "adopted"> {
    this.events.push(`runtime:${runtime.id}`);
    this.maybeFail("runtime");
    return this.result("runtime");
  }

  async ensureAccount(
    account: ScopedBackfillAccount,
  ): Promise<"created" | "adopted"> {
    this.events.push(`account:${account.id}`);
    this.maybeFail("account");
    return this.result("account");
  }

  async ensureCrosswalk(
    crosswalk: ScopedBackfillCrosswalk,
  ): Promise<"created" | "adopted"> {
    this.events.push(`crosswalk:${crosswalk.sourceKey}`);
    this.maybeFail("crosswalk");
    return this.result("crosswalk");
  }

  async recordEpoch(input: {
    planId: string;
    idempotencyKey: string;
    cutoverEpoch: string;
  }): Promise<"created" | "adopted"> {
    this.events.push(`epoch:${input.planId}`);
    this.maybeFail("epoch");
    return this.result("epoch");
  }

  private maybeFail(point: string): void {
    if (this.failAt === point) throw new Error(`forced ${point} failure`);
  }

  private result(point: string): "created" | "adopted" {
    return this.invalidResultAt === point
      ? ("invalid" as "created")
      : "created";
  }
}

class RecordingBackfillPort implements MigrationBackfillPort {
  readonly #transactionImpl = new RecordingBackfillTransaction();
  #committed = false;
  #rolledBack = false;
  #observedScope?: { tenantId: string; scopeId: string };

  get transactionImpl(): RecordingBackfillTransaction {
    return this.#transactionImpl;
  }

  get committed(): boolean {
    return this.#committed;
  }

  get rolledBack(): boolean {
    return this.#rolledBack;
  }

  get observedScope(): { tenantId: string; scopeId: string } | undefined {
    return this.#observedScope;
  }

  async transaction<T>(
    scope: { tenantId: string; scopeId: string },
    operation: (transaction: MigrationBackfillTransaction) => Promise<T>,
  ): Promise<T> {
    this.#observedScope = scope;
    try {
      const result = await operation(this.#transactionImpl);
      this.#committed = true;
      return result;
    } catch (error) {
      this.#rolledBack = true;
      throw error;
    }
  }
}

describe("scoped transactional backfill hooks", () => {
  test("writes only ready records in one scope-bound transaction and records the shared epoch", async () => {
    const plan = buildPlan([
      safeObservation("alice"),
      safeObservation("missing", "claude", {
        root: {
          state: "unsafe",
          code: "missing",
          pathDigest: digest("missing"),
          reason: "missing",
        },
      }),
    ]);
    const port = new RecordingBackfillPort();
    const result = await applyScopedBackfill(
      transitionMigrationSidecar(
        createMigrationSidecar(plan),
        "partial_ready",
        {
          gateEvidence: passingEvidence(plan),
        },
      ),
      port,
    );

    expect(port.observedScope).toEqual(plan.scope);
    expect(port.committed).toBe(true);
    expect(port.rolledBack).toBe(false);
    expect(result).toEqual({
      runtimes: { created: 1, adopted: 0 },
      accounts: { created: 1, adopted: 0 },
      crosswalks: { created: 1, adopted: 0 },
      epoch: "created",
      receipt: expect.objectContaining({
        planId: plan.id,
        idempotencyKey: plan.idempotencyKey,
        scope: plan.scope,
        readyState: "partial_ready",
      }),
    });
    expect(
      port.transactionImpl.events.filter((event) =>
        event.startsWith("account:"),
      ),
    ).toHaveLength(1);
    expect(port.transactionImpl.events.at(-1)).toBe(`epoch:${plan.id}`);
  });

  test("surfaces failure and relies on the port transaction to roll back atomically", async () => {
    const port = new RecordingBackfillPort();
    port.transactionImpl.failAt = "crosswalk";
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );

    const error = await applyScopedBackfill(sidecar, port).then(
      () => {
        throw new Error("expected backfill to reject");
      },
      (caught) => caught as Error & { code?: string },
    );
    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(error.message).not.toContain("forced crosswalk failure");
    expect(port.committed).toBe(false);
    expect(port.rolledBack).toBe(true);
    expect(sidecar.state).toBe("partial_ready");
  });

  test("validates port outcomes inside the transaction before a receipt can be issued", async () => {
    const port = new RecordingBackfillPort();
    port.transactionImpl.invalidResultAt = "account";
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );

    await expect(applyScopedBackfill(sidecar, port)).rejects.toThrow();
    expect(port.committed).toBe(false);
    expect(port.rolledBack).toBe(true);
  });

  test("sanitizes poisoned successful backfill return values", async () => {
    const marker = "bearer-backfill-return-marker";
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    const poisonedResult = {} as Record<string, unknown>;
    Object.defineProperty(poisonedResult, "runtimes", {
      enumerable: true,
      get() {
        throw new MigrationConflictError(marker);
      },
    });

    const error = await applyScopedBackfill(sidecar, {
      async transaction() {
        return poisonedResult as never;
      },
    }).then(
      () => {
        throw new Error("expected poisoned backfill result to reject");
      },
      (caught) =>
        caught as Error & {
          code?: string;
          cause?: unknown;
        },
    );
    const exported = [
      error.message,
      String(error),
      JSON.stringify(error),
      inspect(error),
    ].join("\n");

    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(exported).not.toContain(marker);
    expect(error.cause).toBeUndefined();
  });

  test("validates the epoch result before the transaction callback can commit", async () => {
    const port = new RecordingBackfillPort();
    port.transactionImpl.invalidResultAt = "epoch";
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );

    await expect(applyScopedBackfill(sidecar, port)).rejects.toThrow();
    expect(port.committed).toBe(false);
    expect(port.rolledBack).toBe(true);
  });

  test("rejects a valid substituted result when the transaction skips the callback", async () => {
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    const error = await applyScopedBackfill(sidecar, {
      async transaction() {
        return {
          runtimes: { created: 1, adopted: 0 },
          accounts: { created: 2, adopted: 0 },
          crosswalks: { created: 2, adopted: 0 },
          epoch: "created" as const,
        };
      },
    }).then(
      () => {
        throw new Error("expected skipped transaction callback to reject");
      },
      (caught) => caught as Error & { code?: string },
    );

    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(sidecar.state).toBe("partial_ready");
    expect(sidecar.backfillReceipts).toEqual([]);
  });

  test("rejects a valid substituted result after the callback performs its writes", async () => {
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    const transaction = new RecordingBackfillTransaction();
    const error = await applyScopedBackfill(sidecar, {
      async transaction(_scope, operation) {
        const captured = await operation(transaction);
        return {
          ...captured,
          runtimes: {
            created: captured.runtimes.created - 1,
            adopted: captured.runtimes.adopted + 1,
          },
        };
      },
    }).then(
      () => {
        throw new Error("expected substituted transaction result to reject");
      },
      (caught) => caught as Error & { code?: string },
    );

    expect(transaction.events.length).toBeGreaterThan(0);
    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(sidecar.state).toBe("partial_ready");
    expect(sidecar.backfillReceipts).toEqual([]);
  });

  test("rejects a caught second callback invocation before it can call the port again", async () => {
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    const transaction = new RecordingBackfillTransaction();
    let eventsAfterFirstInvocation = 0;
    let eventsAfterSecondInvocation = 0;
    const error = await applyScopedBackfill(sidecar, {
      async transaction(_scope, operation) {
        const captured = await operation(transaction);
        eventsAfterFirstInvocation = transaction.events.length;
        try {
          await operation(transaction);
        } catch {
          // A hostile port may swallow the second-invocation failure.
        }
        eventsAfterSecondInvocation = transaction.events.length;
        return captured;
      },
    }).then(
      () => {
        throw new Error("expected repeated transaction callback to reject");
      },
      (caught) => caught as Error & { code?: string },
    );

    expect(eventsAfterFirstInvocation).toBeGreaterThan(0);
    expect(eventsAfterSecondInvocation).toBe(eventsAfterFirstInvocation);
    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(sidecar.state).toBe("partial_ready");
    expect(sidecar.backfillReceipts).toEqual([]);
  });

  test("rejects an unawaited callback before it can mint a receipt", async () => {
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    let releaseRuntime!: () => void;
    const runtimeGate = new Promise<void>((resolve) => {
      releaseRuntime = resolve;
    });
    let callbackPromise: Promise<unknown> | undefined;
    const transaction: MigrationBackfillTransaction = {
      async ensureRuntime() {
        await runtimeGate;
        return "created";
      },
      async ensureAccount() {
        return "created";
      },
      async ensureCrosswalk() {
        return "created";
      },
      async recordEpoch() {
        return "created";
      },
    };

    const outcome = await applyScopedBackfill(sidecar, {
      async transaction(_scope, operation) {
        callbackPromise = operation(transaction);
        return {
          runtimes: { created: 1, adopted: 0 },
          accounts: { created: 2, adopted: 0 },
          crosswalks: { created: 2, adopted: 0 },
          epoch: "created" as const,
        };
      },
    }).then(
      () => new Error("expected unawaited transaction callback to reject"),
      (caught) => caught as Error & { code?: string },
    );
    releaseRuntime();
    await callbackPromise;

    expect(outcome).toBeInstanceOf(MigrationConflictError);
    expect((outcome as Error & { code?: string }).code).toBe(
      "migration_backfill_failed",
    );
    expect(sidecar.state).toBe("partial_ready");
    expect(sidecar.backfillReceipts).toEqual([]);
  });

  test("rejects mutation of the captured callback result after it returns", async () => {
    const plan = buildPlan();
    const sidecar = transitionMigrationSidecar(
      createMigrationSidecar(plan),
      "partial_ready",
      { gateEvidence: passingEvidence(plan) },
    );
    const transaction = new RecordingBackfillTransaction();
    const error = await applyScopedBackfill(sidecar, {
      async transaction(_scope, operation) {
        const captured = await operation(transaction);
        captured.runtimes.created = 999;
        return captured;
      },
    }).then(
      () => {
        throw new Error("expected captured result mutation to reject");
      },
      (caught) => caught as Error & { code?: string },
    );

    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_backfill_failed");
    expect(sidecar.state).toBe("partial_ready");
    expect(sidecar.backfillReceipts).toEqual([]);
  });

  test.each(["runtime", "account", "crosswalk", "epoch"] as const)(
    "rejects invalid %s callback output before transaction commit",
    async (point) => {
      const port = new RecordingBackfillPort();
      port.transactionImpl.invalidResultAt = point;
      const plan = buildPlan();
      const sidecar = transitionMigrationSidecar(
        createMigrationSidecar(plan),
        "partial_ready",
        { gateEvidence: passingEvidence(plan) },
      );

      await expect(applyScopedBackfill(sidecar, port)).rejects.toThrow();
      expect(port.committed).toBe(false);
      expect(port.rolledBack).toBe(true);
      expect(sidecar.state).toBe("partial_ready");
      expect(sidecar.backfillReceipts).toEqual([]);
    },
  );
});

describe("durable sidecar WAL and repair", () => {
  test("keeps every configured path and callback out of stringify and inspection", () => {
    const marker = "bearer-private-store-path-marker";
    const root = tempRoot();
    const sidecarPath = join(root, marker, "migration-v2.json");
    const legacyStorePath = join(root, marker, "accounts.json");
    const injectFailure = () => {
      throw new Error(marker);
    };
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath,
      injectFailure,
      onDurabilityEvent: injectFailure,
    });

    expect(Object.keys(store)).toEqual([]);
    expect(JSON.stringify(store)).toBe(
      '{"schemaVersion":1,"kind":"migration_sidecar_store"}',
    );
    expect(inspect(store)).not.toContain(marker);
    expect(inspect(store)).not.toContain(sidecarPath);
    expect(inspect(store)).not.toContain(legacyStorePath);
    expect(inspect(store)).not.toContain("injectFailure");
    expect(inspect(store)).not.toContain("onDurabilityEvent");
  });

  test("sanitizes strict store constructor and install options", () => {
    const marker = "bearer-store-option-marker";
    const root = tempRoot();
    const sidecarPath = join(root, "migration-v2.json");
    const legacyStorePath = join(root, "accounts.json");
    const constructorError = captureError(
      () =>
        new MigrationSidecarStore({
          sidecarPath,
          legacyStorePath,
          [marker]: marker,
        } as never),
    );
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath,
    });
    const installError = captureError(() =>
      store.install(createMigrationSidecar(buildPlan()), {
        [marker]: marker,
      } as never),
    );
    const throwingOptions = {} as Record<string, unknown>;
    Object.defineProperty(throwingOptions, "sidecarPath", {
      enumerable: true,
      get() {
        throw new MigrationConflictError(marker);
      },
    });
    throwingOptions.legacyStorePath = legacyStorePath;
    const throwingConstructorError = captureError(
      () => new MigrationSidecarStore(throwingOptions as never),
    );

    expect(constructorError.code).toBe("migration_invalid_store_options");
    expect(installError.code).toBe("migration_store_install_failed");
    expect(throwingConstructorError.code).toBe(
      "migration_invalid_store_options",
    );
    for (const error of [
      constructorError,
      installError,
      throwingConstructorError,
    ]) {
      const exported = [
        error.message,
        String(error),
        JSON.stringify(error),
        inspect(error),
      ].join("\n");
      expect(error).toBeInstanceOf(AccountsError);
      expect(exported).not.toContain(marker);
      expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
    }
  });

  test("maps safe-path and filesystem failures to stable path references", () => {
    const marker = "bearer-symlink-path-marker";
    const root = tempRoot();
    const target = join(root, "target");
    const linked = join(root, marker);
    const legacy = join(root, "accounts.json");
    mkdirSync(target);
    symlinkSync(target, linked);
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath: join(linked, "nested", "migration-v2.json"),
      legacyStorePath: legacy,
    });
    const error = captureError(() =>
      store.install(createMigrationSidecar(buildPlan())),
    );
    const exported = [
      error.message,
      String(error),
      JSON.stringify(error),
      inspect(error),
    ].join("\n");

    expect(error).toBeInstanceOf(MigrationConflictError);
    expect(error.code).toBe("migration_store_path_rejected");
    expect(error.references).toHaveLength(1);
    expect(error.references?.[0]).toMatchObject({
      domain: "root.path",
      digest: redactionDigest(
        "root.path",
        join(linked, "nested", "migration-v2.json"),
      ),
    });
    expect(exported).not.toContain(marker);
    expect(exported).not.toContain(linked);
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
    expect(existsSync(join(target, "nested"))).toBe(false);
  });

  test("sanitizes caller-thrown migration errors from store callbacks", () => {
    const marker = "bearer-store-callback-marker";
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
      onDurabilityEvent() {
        throw new MigrationConflictError(marker);
      },
    });
    const error = captureError(() =>
      store.install(createMigrationSidecar(buildPlan())),
    );
    const exported = [
      error.message,
      String(error),
      JSON.stringify(error),
      inspect(error),
    ].join("\n");

    expect(error.code).toBe("migration_store_callback_failed");
    expect(exported).not.toContain(marker);
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
  });

  test("refuses to share a path with the untouched v1 registry", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const error = captureError(
      () =>
        new MigrationSidecarStore({
          sidecarPath: legacy,
          legacyStorePath: legacy,
        }),
    );
    expect(error.code).toBe("migration_store_path_rejected");
    expect(error.references).toEqual([
      {
        domain: "root.path",
        digest: redactionDigest("root.path", legacy),
      },
    ]);
    expect(JSON.stringify(error)).not.toContain(legacy);
  });

  test("refuses hard-link aliases of the untouched v1 registry", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    linkSync(legacy, sidecarPath);

    const error = captureError(
      () => new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy }),
    );
    expect(error.code).toBe("migration_store_path_rejected");
    expect(error.references).toEqual([
      {
        domain: "root.path",
        digest: redactionDigest("root.path", sidecarPath),
      },
    ]);
    expect(JSON.stringify(error)).not.toContain(sidecarPath);
    expect(JSON.stringify(error)).not.toContain(legacy);
  });

  test.each([
    ["sidecar", (sidecarPath: string) => sidecarPath],
    ["sidecar staging", (sidecarPath: string) => `${sidecarPath}.tmp`],
    ["WAL", (sidecarPath: string) => `${sidecarPath}.wal`],
    ["WAL staging", (sidecarPath: string) => `${sidecarPath}.wal.tmp`],
    ["writer lock", (sidecarPath: string) => `${sidecarPath}.lock`],
  ] as const)(
    "refuses every exact and physical v1 alias at the %s path without changing v1",
    (_label, companionPath) => {
      for (const aliasMode of [
        "exact",
        "parent-normalized",
        "symlink",
        "hard-link",
      ] as const) {
        const root = tempRoot();
        const sidecarPath = join(root, "migration-v2.json");
        const candidate = companionPath(sidecarPath);
        const actualLegacyPath =
          aliasMode === "exact" || aliasMode === "parent-normalized"
            ? candidate
            : join(root, `accounts-${aliasMode}.json`);
        const configuredLegacyPath =
          aliasMode === "parent-normalized"
            ? join(
                dirname(candidate),
                "normalization-segment",
                "..",
                basename(candidate),
              )
            : actualLegacyPath;
        const sentinel = `{"version":1,"aliasMode":"${aliasMode}"}\n`;
        writeFileSync(actualLegacyPath, sentinel, { mode: 0o600 });
        if (aliasMode === "symlink") {
          symlinkSync(actualLegacyPath, candidate);
        } else if (aliasMode === "hard-link") {
          linkSync(actualLegacyPath, candidate);
        }

        const allCompanions = [
          sidecarPath,
          `${sidecarPath}.tmp`,
          `${sidecarPath}.wal`,
          `${sidecarPath}.wal.tmp`,
          `${sidecarPath}.lock`,
        ];
        const companionSnapshots = new Map(
          allCompanions.map((path) => {
            if (!existsSync(path)) return [path, null] as const;
            const stat = lstatSync(path);
            return [
              path,
              {
                device: stat.dev,
                inode: stat.ino,
                mode: stat.mode,
                symbolicLink: stat.isSymbolicLink(),
              },
            ] as const;
          }),
        );
        const before = statSync(actualLegacyPath);
        const error = captureError(() => {
          const store = new MigrationSidecarStore({
            sidecarPath,
            legacyStorePath: configuredLegacyPath,
          });
          store.install(createMigrationSidecar(buildPlan()));
        });
        const after = statSync(actualLegacyPath);

        expect(error.code).toBe("migration_store_path_rejected");
        expect(readFileSync(actualLegacyPath, "utf8")).toBe(sentinel);
        expect(after.mode & 0o777).toBe(0o600);
        expect(after.dev).toBe(before.dev);
        expect(after.ino).toBe(before.ino);
        for (const path of allCompanions) {
          const snapshot = companionSnapshots.get(path);
          if (snapshot === null) {
            expect(existsSync(path)).toBe(false);
            continue;
          }
          const current = lstatSync(path);
          expect({
            device: current.dev,
            inode: current.ino,
            mode: current.mode,
            symbolicLink: current.isSymbolicLink(),
          }).toEqual(snapshot);
        }
      }
    },
  );

  test("refuses to use the v1 registry file as the sidecar directory", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(legacy, "migration-v2.json");
    const sentinel = '{"version":1,"directoryCollision":true}\n';
    writeFileSync(legacy, sentinel, { mode: 0o600 });
    const before = statSync(legacy);

    const error = captureError(
      () =>
        new MigrationSidecarStore({
          sidecarPath,
          legacyStorePath: legacy,
        }),
    );
    const after = statSync(legacy);

    expect(error.code).toBe("migration_store_path_rejected");
    expect(readFileSync(legacy, "utf8")).toBe(sentinel);
    expect(after.mode & 0o777).toBe(0o600);
    expect(after.dev).toBe(before.dev);
    expect(after.ino).toBe(before.ino);
    expect(existsSync(sidecarPath)).toBe(false);
  });

  test.each([
    ["sidecar", (sidecarPath: string) => sidecarPath],
    ["sidecar staging", (sidecarPath: string) => `${sidecarPath}.tmp`],
    ["WAL", (sidecarPath: string) => `${sidecarPath}.wal`],
    ["WAL staging", (sidecarPath: string) => `${sidecarPath}.wal.tmp`],
    ["writer lock", (sidecarPath: string) => `${sidecarPath}.lock`],
  ] as const)(
    "revalidates a post-construction v1 alias at the %s path before mutation",
    (_label, companionPath) => {
      for (const aliasMode of ["symlink", "hard-link"] as const) {
        const root = tempRoot();
        const legacy = join(root, `accounts-${aliasMode}.json`);
        const sidecarPath = join(root, "migration-v2.json");
        const candidate = companionPath(sidecarPath);
        const sentinel = `{"version":1,"lateAlias":"${aliasMode}"}\n`;
        writeFileSync(legacy, sentinel, { mode: 0o600 });
        const store = new MigrationSidecarStore({
          sidecarPath,
          legacyStorePath: legacy,
        });
        if (aliasMode === "symlink") {
          symlinkSync(legacy, candidate);
        } else {
          linkSync(legacy, candidate);
        }
        const before = statSync(legacy);
        const candidateBefore = lstatSync(candidate);

        const error = captureError(() =>
          store.install(createMigrationSidecar(buildPlan())),
        );
        const after = statSync(legacy);
        const candidateAfter = lstatSync(candidate);

        expect(error.code).toBe("migration_store_path_rejected");
        expect(readFileSync(legacy, "utf8")).toBe(sentinel);
        expect(after.mode & 0o777).toBe(0o600);
        expect(after.dev).toBe(before.dev);
        expect(after.ino).toBe(before.ino);
        expect(candidateAfter.dev).toBe(candidateBefore.dev);
        expect(candidateAfter.ino).toBe(candidateBefore.ino);
        expect(candidateAfter.isSymbolicLink()).toBe(
          candidateBefore.isSymbolicLink(),
        );
      }
    },
  );

  test("refuses symlink ancestors before creating sidecar directories", () => {
    const root = tempRoot();
    const target = join(root, "target");
    const linked = join(root, "linked");
    const legacy = join(root, "accounts.json");
    mkdirSync(target);
    symlinkSync(target, linked);
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const sidecarPath = join(linked, "nested", "migration-v2.json");
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });

    const error = captureError(() =>
      store.install(createMigrationSidecar(buildPlan())),
    );
    expect(error.code).toBe("migration_store_path_rejected");
    expect(error.message).not.toContain(linked);
    expect(existsSync(join(target, "nested"))).toBe(false);
  });

  test("installs through WAL, file fsync, and parent-directory fsync without changing v1", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const before = readFileSync(legacy, "utf8");
    const events: string[] = [];
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
      onDurabilityEvent: (event) => events.push(event),
    });
    const sidecar = createMigrationSidecar(buildPlan());

    store.install(sidecar);

    expect(store.load()).toEqual(sidecar);
    expect(readFileSync(legacy, "utf8")).toBe(before);
    expect(statSync(sidecarPath).mode & 0o777).toBe(0o600);
    expect(existsSync(`${sidecarPath}.wal`)).toBe(false);
    expect(events).toEqual([
      "wal_file_fsync",
      "wal_rename",
      "wal_directory_fsync",
      "sidecar_file_fsync",
      "sidecar_rename",
      "sidecar_directory_fsync",
      "wal_remove",
      "cleanup_directory_fsync",
    ]);
  });

  test("repairs every durable crash boundary using the same frozen plan and idempotency key", () => {
    const points: MigrationSidecarFailurePoint[] = [
      "after_wal_file_fsync",
      "after_wal_rename",
      "after_wal_directory_fsync",
      "after_sidecar_file_fsync",
      "after_sidecar_rename",
      "after_sidecar_directory_fsync",
      "before_wal_remove",
      "after_wal_remove",
    ];

    for (const point of points) {
      const root = tempRoot();
      const legacy = join(root, "accounts.json");
      const sidecarPath = join(root, "migration-v2.json");
      writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
      const sidecar = createMigrationSidecar(buildPlan());
      const failing = new MigrationSidecarStore({
        sidecarPath,
        legacyStorePath: legacy,
        injectFailure: (candidate) => {
          if (candidate === point) throw new Error(`forced crash ${point}`);
        },
      });

      const error = captureError(() => failing.install(sidecar));
      expect(error.code).toBe("migration_store_callback_failed");
      expect(error.message).not.toContain(`forced crash ${point}`);

      const repaired = new MigrationSidecarStore({
        sidecarPath,
        legacyStorePath: legacy,
      });
      expect(repaired.repair()).toEqual(sidecar);
      expect(repaired.load()).toEqual(sidecar);
      expect(existsSync(`${sidecarPath}.wal`)).toBe(false);
      expect(readFileSync(legacy, "utf8")).toBe('{"version":1}\n');
    }
  });

  test("keeps uncertain WAL evidence when out-of-band sidecar drift is detected", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const sidecar = createMigrationSidecar(buildPlan());
    const failing = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
      injectFailure: (point) => {
        if (point === "after_wal_directory_fsync") throw new Error("crash");
      },
    });
    expect(captureError(() => failing.install(sidecar)).code).toBe(
      "migration_store_callback_failed",
    );
    writeFileSync(sidecarPath, JSON.stringify({ unexpected: "drift" }), {
      mode: 0o600,
    });

    const repaired = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    expect(() => repaired.repair()).toThrow(MigrationDriftError);
    expect(existsSync(`${sidecarPath}.wal`)).toBe(true);
  });

  test("requires compare-and-swap for updates and rejects stale writers", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const initial = createMigrationSidecar(buildPlan());
    store.install(initial);

    const updated = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:alice-renamed",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    store.install(updated, { expectedPreviousDigest: initial.integrityDigest });

    expect(() =>
      store.install(
        transitionMigrationSidecar(initial, "partial_ready", {
          gateEvidence: passingEvidence(initial.plan),
        }),
        {
          expectedPreviousDigest: initial.integrityDigest,
        },
      ),
    ).toThrow("refusing a stale writer");
    expect(store.load()).toEqual(updated);
  });

  test("refuses to overwrite a valid pending WAL before repair preserves its first intent", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const first = createMigrationSidecar(buildPlan());
    const crashing = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
      injectFailure: (point) => {
        if (point === "after_wal_directory_fsync") throw new Error("crash");
      },
    });
    expect(captureError(() => crashing.install(first)).code).toBe(
      "migration_store_callback_failed",
    );
    const walBefore = readFileSync(`${sidecarPath}.wal`, "utf8");

    const second = createMigrationSidecar(
      buildPlan([safeObservation("charlie")]),
    );
    const competing = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    expect(() => competing.install(second)).toThrow("pending migration WAL");
    expect(readFileSync(`${sidecarPath}.wal`, "utf8")).toBe(walBefore);
    expect(competing.repair()).toEqual(first);
  });

  test("rejects a WAL successor that truncates immutable alias history", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    const walPath = `${sidecarPath}.wal`;
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const initial = createMigrationSidecar(buildPlan());
    store.install(initial);
    const current = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:durable-before-crash",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    store.install(current, { expectedPreviousDigest: initial.integrityDigest });
    const truncatedSuccessor = transitionMigrationSidecar(
      initial,
      "partial_ready",
      {
        gateEvidence: passingEvidence(initial.plan),
      },
    );
    writeFileSync(
      walPath,
      `${JSON.stringify(
        {
          schemaVersion: 1,
          planId: initial.plan.id,
          idempotencyKey: initial.plan.idempotencyKey,
          previousDigest: current.integrityDigest,
          nextDigest: truncatedSuccessor.integrityDigest,
          nextSidecar: truncatedSuccessor,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    expect(() => store.repair()).toThrow("alias journal may not be truncated");
    expect(store.load()).toEqual(current);
    expect(existsSync(walPath)).toBe(true);
  });

  test("rejects a noncanonical planned genesis from a WAL", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    const walPath = `${sidecarPath}.wal`;
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const initial = createMigrationSidecar(buildPlan());
    const noncanonicalGenesis = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:before-genesis",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    writeFileSync(
      walPath,
      `${JSON.stringify(
        {
          schemaVersion: 1,
          planId: initial.plan.id,
          idempotencyKey: initial.plan.idempotencyKey,
          previousDigest: null,
          nextDigest: noncanonicalGenesis.integrityDigest,
          nextSidecar: noncanonicalGenesis,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    expect(() => store.repair()).toThrow("canonical planned genesis");
    expect(store.load()).toBeNull();
    expect(existsSync(walPath)).toBe(true);
  });

  test("rejects loaded states that omit canonical genesis aliases after rehashing the predecessor chain", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const initial = createMigrationSidecar(buildPlan());
    const legitimate = transitionMigrationSidecar(initial, "final_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });

    const { integrityDigest: _initialIntegrityDigest, ...initialCore } =
      initial;
    const aliaslessGenesisCore = {
      ...initialCore,
      aliasJournal: [],
    };
    const aliaslessGenesis = {
      ...aliaslessGenesisCore,
      integrityDigest: canonicalDigest(aliaslessGenesisCore),
    } as MigrationSidecar;

    const { digest: _gateDigest, ...gateCore } = legitimate.gateReceipts[0]!;
    const forgedGateCore = {
      ...gateCore,
      sourceIntegrityDigest: aliaslessGenesis.integrityDigest,
    };
    const forgedGate = {
      ...forgedGateCore,
      digest: canonicalDigest(forgedGateCore),
    };
    const { digest: _transitionDigest, ...transitionCore } =
      legitimate.transitionJournal[0]!;
    const forgedTransitionCore = {
      ...transitionCore,
      sourceIntegrityDigest: aliaslessGenesis.integrityDigest,
      sourceAliasJournalLength: 0,
    };
    const forgedTransition = {
      ...forgedTransitionCore,
      digest: canonicalDigest(forgedTransitionCore),
    };
    const { integrityDigest: _legitimateIntegrityDigest, ...legitimateCore } =
      legitimate;
    const forgedCore = {
      ...legitimateCore,
      aliasJournal: [],
      gateReceipts: [forgedGate],
      transitionJournal: [forgedTransition],
    };
    const forged = {
      ...forgedCore,
      integrityDigest: canonicalDigest(forgedCore),
    } as MigrationSidecar;
    writeFileSync(sidecarPath, `${JSON.stringify(forged, null, 2)}\n`, {
      mode: 0o600,
    });

    expect(() => store.load()).toThrow("canonical genesis alias");
  });

  test("rejects a valid-integrity readiness successor with no durable gate receipt", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const initial = createMigrationSidecar(buildPlan());
    store.install(initial);

    const legitimate = transitionMigrationSidecar(initial, "final_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });
    const {
      integrityDigest: _integrityDigest,
      gateReceipts: _gateReceipts,
      ...withoutReceipt
    } = legitimate;
    const forgedCore = { ...withoutReceipt, gateReceipts: [] };
    const forged = {
      ...forgedCore,
      integrityDigest: canonicalDigest(forgedCore),
    } as MigrationSidecar;

    expect(() =>
      store.install(forged, {
        expectedPreviousDigest: initial.integrityDigest,
      }),
    ).toThrow("durable gate receipt");
    expect(store.load()).toEqual(initial);
  });

  test("preserves active writer locks and removes only dead-writer locks", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    const lockPath = `${sidecarPath}.lock`;
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    writeFileSync(lockPath, `${process.pid}\n`, { mode: 0o600 });
    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });

    expect(() => store.repair()).toThrow("another v2 migration writer");
    expect(readFileSync(lockPath, "utf8")).toBe(`${process.pid}\n`);

    writeFileSync(lockPath, "999999999\n", { mode: 0o600 });
    expect(store.repair()).toBeNull();
    expect(existsSync(lockPath)).toBe(false);
  });

  test("rejects group/world-readable existing sidecars before use", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    writeFileSync(sidecarPath, "{}\n", { mode: 0o644 });
    chmodSync(sidecarPath, 0o644);

    const store = new MigrationSidecarStore({
      sidecarPath,
      legacyStorePath: legacy,
    });
    const error = captureError(() => store.load());
    expect(error.message).toBe("migration store path was rejected");
    expect(error.code).toBe("migration_store_path_rejected");
    expect(error.references).toEqual([
      {
        domain: "root.path",
        digest: redactionDigest("root.path", sidecarPath),
      },
    ]);
    expect(JSON.stringify(error)).not.toContain(sidecarPath);
  });
});

describe("old and new client-server compatibility fixtures", () => {
  test("freeze the compatibility matrix without activating new routes", () => {
    const fixturePath = join(
      import.meta.dir,
      "..",
      "..",
      "test",
      "fixtures",
      "v2-migration-compatibility.json",
    );
    const fixture = migrationCompatibilityFixtureSchema.parse(
      JSON.parse(readFileSync(fixturePath, "utf8")),
    );

    expect(fixture.cases).toEqual([
      {
        client: "old",
        server: "old",
        result: "v1_unchanged",
        writes: "v1_only",
      },
      {
        client: "old",
        server: "transition",
        result: "v1_projection",
        writes: "v1_only",
      },
      {
        client: "old",
        server: "new",
        result: "upgrade_required",
        writes: "none",
      },
      {
        client: "transition",
        server: "old",
        result: "preflight_only",
        writes: "none",
      },
      {
        client: "transition",
        server: "transition",
        result: "sidecar_backfill",
        writes: "journaled_v2",
      },
      {
        client: "transition",
        server: "new",
        result: "v2",
        writes: "v2_only",
      },
      {
        client: "new",
        server: "old",
        result: "upgrade_required",
        writes: "none",
      },
      {
        client: "new",
        server: "transition",
        result: "requires_final_cutover",
        writes: "none",
      },
      {
        client: "new",
        server: "new",
        result: "v2",
        writes: "v2_only",
      },
    ]);

    expect(
      migrationCompatibilityFixtureSchema.safeParse({
        ...fixture,
        cases: fixture.cases.slice(0, 8),
      }).success,
    ).toBe(false);
    expect(
      migrationCompatibilityFixtureSchema.safeParse({
        ...fixture,
        cases: [...fixture.cases.slice(0, 8), fixture.cases[0]],
      }).success,
    ).toBe(false);
  });
});
