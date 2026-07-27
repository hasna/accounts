import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  for (const root of tempRoots.splice(0)) rmSync(root, { recursive: true, force: true });
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
        createHash("sha256").update(`${tool}:${name}`).digest("hex").slice(0, 12),
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
    expect(plan.records.map((record) => record.disposition.state)).toEqual(["ready", "ready"]);
    expect(new Set(plan.records.map((record) => record.target.accountId)).size).toBe(2);
    expect(new Set(plan.records.map((record) => record.target.bindingId)).size).toBe(2);
    expect(new Set(plan.records.map((record) => record.target.runtimeId)).size).toBe(2);
    expect(plan.records[0]?.binding?.rootPath).toBe("/profiles/claude/alice");
    expect(plan.records[1]?.binding?.rootPath).toBe("/profiles/codex/bob");
    expect(plan.records.every((record) => !("credentialRef" in record))).toBe(true);
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
    expect(createMigrationSidecar(plan).aliasJournal.map((entry) => entry.alias)).toEqual([
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
    expect(() =>
      buildMigrationPlan(planInput([observation]), {
        idFactory: stableId,
        existingPlan: forgedPlan,
      }),
    ).toThrow("canonical");
  });

  test("rejects duplicate aliases before digest allocation and across plan records", () => {
    expect(() =>
      buildPlan([
        safeObservation("alice", "claude", {
          historicalAliases: [
            "legacy:claude:alice",
            "legacy:claude:alice",
          ],
        }),
      ]),
    ).toThrow("duplicate historical alias");

    expect(() =>
      buildPlan([
        safeObservation("alice", "claude", {
          historicalAliases: [
            "legacy:claude:cafe\u0301",
            "legacy:claude:café",
          ],
        }),
      ]),
    ).toThrow("duplicate historical alias");

    expect(() =>
      buildPlan([
        safeObservation("alice", "claude", {
          historicalAliases: ["legacy:shared-account-alias"],
        }),
        safeObservation("bob", "codex", {
          historicalAliases: ["legacy:shared-account-alias"],
        }),
      ]),
    ).toThrow("duplicate legacy account alias");

    expect(() =>
      buildPlan([
        safeObservation("alice", "claude", {
          historicalSessionAliases: ["session:shared-alias"],
        }),
        safeObservation("bob", "codex", {
          historicalSessionAliases: ["session:shared-alias"],
        }),
      ]),
    ).toThrow("duplicate session alias");
  });

  test("rejects changed input when reusing a frozen plan idempotency boundary", () => {
    const plan = buildPlan();
    expect(() =>
      buildPlan(
        [
          safeObservation("alice", "claude", { inputDigest: digest("changed") }),
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
    expect(plan.records.every((record) => record.target.accountId.length >= 16)).toBe(true);
    expect(
      plan.records
        .filter((record) => record.source.name === "same")
        .map((record) => record.disposition),
    ).toEqual([
      { state: "quarantined", reasons: ["same_name_cross_runtime"] },
      { state: "quarantined", reasons: ["same_name_cross_runtime"] },
    ]);
    expect(plan.records.find((record) => record.source.name === "missing")?.disposition).toEqual({
      state: "quarantined",
      reasons: ["root_missing"],
    });
    expect(plan.records.every((record) => record.binding === undefined)).toBe(true);
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
    expect(plan.records.every((record) => record.binding === undefined)).toBe(true);
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
    expect(plan.records.every((record) => record.binding === undefined)).toBe(true);
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
    expect(() => buildPlan([safeObservation("alice"), safeObservation("alice")])).toThrow(
      "duplicate legacy source key",
    );
  });

  test("fails conflicting runtime definitions and incomplete census contracts", () => {
    expect(() =>
      buildPlan([
        safeObservation("alice"),
        safeObservation("bob", "claude", { runtimeLabel: "Different Claude Runtime" }),
      ]),
    ).toThrow("conflicting runtime labels");

    expect(() =>
      buildMigrationPlan(planInput(), {
        idFactory: (kind, seed) =>
          kind === "account" ? "account_duplicate0000" : stableId(kind, seed),
      }),
    ).toThrow("duplicate account id");

    expect(() =>
      buildMigrationPlan(planInput([safeObservation("alice")]), {
        idFactory: () => "shared_identifier_000000000001",
      }),
    ).toThrow("globally unique across entity kinds");

    expect(() =>
      buildMigrationPlan(
        {
          ...planInput([safeObservation("alice")]),
          backup: { ...backupPlan(), requiredBytes: 2047 },
        },
        { idFactory: stableId },
      ),
    ).toThrow("cover every verified root byte");

    expect(() =>
      buildMigrationPlan(
        {
          ...planInput(),
          cutoverEpoch: "2026-07-27T11:59:59.999Z",
        },
        { idFactory: stableId },
      ),
    ).toThrow("must not precede plan creation");

    const plan = buildPlan();
    expect(
      migrationPlanSchema.safeParse({
        ...plan,
        sourceDigests: { ...plan.sourceDigests, untrackedSource: digest("unknown") },
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

    expect(() =>
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
    ).toThrow("input digest");
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
    const sensitiveRecord = redacted.records.find(
      (record) =>
        record.source.toolDigest === digest("credential-token-runtime"),
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
        (record) =>
          !("runtimeLabel" in record) &&
          !("tool" in record.source),
      ),
    ).toBe(true);
    expect(sensitiveRecord?.source).not.toHaveProperty("tool");
    expect(sensitiveRecord).not.toHaveProperty("runtimeLabel");
    expect(sensitiveRecord?.source.toolDigest).toBe(
      digest("credential-token-runtime"),
    );
    expect(sensitiveRecord?.runtimeLabelDigest).toBe(
      digest("Bearer synthetic credential marker"),
    );
    expect(sensitiveRecord?.root?.byteCount).toBe(2048);
    expect(sensitiveRecord?.root?.digest).toBe(
      digest("root-credential-token-runtime-alice"),
    );
    expect(sensitiveRecord?.historicalAliasDigests).toHaveLength(1);
    expect(sensitiveRecord?.historicalSessionAliasDigests).toHaveLength(1);
    expect(unsafeRecord?.root).toMatchObject({
      state: "unsafe",
      code: "missing",
      pathDigest: digest("missing-path"),
      reasonDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
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
        records: [{ ...plan.records[0], transcript: "secret transcript" }, plan.records[1]],
      }).success,
    ).toBe(false);
  });
});

describe("backup, gates, aliases, and cutover states", () => {
  test("requires encrypted 0600 complete backup and restore contracts", () => {
    expect(backupRestorePlanSchema.parse(backupPlan())).toEqual(backupPlan());
    expect(
      backupRestorePlanSchema.safeParse({ ...backupPlan(), manifestEncrypted: false }).success,
    ).toBe(false);
    expect(
      backupRestorePlanSchema.safeParse({ ...backupPlan(), fileMode: 0o644 }).success,
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
        { ...base, observedDigests: { ...base.observedDigests, v1Registry: digest("drift") } },
      ],
      ["insufficient_free_space", { ...base, availableBytes: plan.backup.requiredBytes - 1 }],
      ["unknown_ledger_entry", { ...base, unknownLedgerEntries: ["future_migration"] }],
      ["checksum_mismatch", { ...base, checksumMismatches: ["accounts_0005"] }],
      ["catalog_skip", { ...base, unresolvedCatalogSkipDigests: [digest("skip")] }],
      [
        "restore_unverified",
        { ...base, backupRestore: { ...base.backupRestore, restoreDrillVerified: false } },
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
    expect(() =>
      appendMigrationAlias(once, {
        ...alias,
        alias: "legacy:claude:cafe\u0301",
      }),
    ).toThrow("canonical Unicode NFC");
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
    expect(() => transitionMigrationSidecar(partialReady, "partial_applied")).toThrow(
      "requires a committed scope-bound backfill receipt",
    );
    const partialBackfill = await applyScopedBackfill(partialReady, new RecordingBackfillPort());
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
    const partialApplied = transitionMigrationSidecar(partialReady, "partial_applied", {
      backfillReceipt: partialBackfill.receipt,
    });
    const finalReady = transitionMigrationSidecar(partialApplied, "final_ready", {
      gateEvidence: passingEvidence(plan),
    });
    const finalBackfill = await applyScopedBackfill(finalReady, new RecordingBackfillPort());
    const finalApplied = transitionMigrationSidecar(finalReady, "final_applied", {
      backfillReceipt: finalBackfill.receipt,
    });

    expect(finalApplied.state).toBe("final_applied");
    expect(finalApplied.gateReceipts).toHaveLength(2);
    expect(finalApplied.backfillReceipts).toHaveLength(2);
    expect(() => transitionMigrationSidecar(finalApplied, "partial_applied")).toThrow(
      "cannot move migration state backwards",
    );

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
    const firstReady = transitionMigrationSidecar(firstPredecessor, "partial_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });
    const secondReady = transitionMigrationSidecar(secondPredecessor, "partial_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });
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

    expect(() =>
      transitionMigrationSidecar(forged, "partial_ready"),
    ).toThrow("predecessor transition chain");
  });
});

class RecordingBackfillTransaction implements MigrationBackfillTransaction {
  readonly events: string[] = [];
  failAt?: string;
  invalidResultAt?: string;

  async ensureRuntime(runtime: ScopedBackfillRuntime): Promise<"created" | "adopted"> {
    this.events.push(`runtime:${runtime.id}`);
    this.maybeFail("runtime");
    return this.result("runtime");
  }

  async ensureAccount(account: ScopedBackfillAccount): Promise<"created" | "adopted"> {
    this.events.push(`account:${account.id}`);
    this.maybeFail("account");
    return this.result("account");
  }

  async ensureCrosswalk(crosswalk: ScopedBackfillCrosswalk): Promise<"created" | "adopted"> {
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
  readonly transactionImpl = new RecordingBackfillTransaction();
  committed = false;
  rolledBack = false;
  observedScope?: { tenantId: string; scopeId: string };

  async transaction<T>(
    scope: { tenantId: string; scopeId: string },
    operation: (transaction: MigrationBackfillTransaction) => Promise<T>,
  ): Promise<T> {
    this.observedScope = scope;
    try {
      const result = await operation(this.transactionImpl);
      this.committed = true;
      return result;
    } catch (error) {
      this.rolledBack = true;
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
      transitionMigrationSidecar(createMigrationSidecar(plan), "partial_ready", {
        gateEvidence: passingEvidence(plan),
      }),
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
    expect(port.transactionImpl.events.filter((event) => event.startsWith("account:"))).toHaveLength(
      1,
    );
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

    await expect(applyScopedBackfill(sidecar, port)).rejects.toThrow(
      "forced crosswalk failure",
    );
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
});

describe("durable sidecar WAL and repair", () => {
  test("refuses to share a path with the untouched v1 registry", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    expect(
      () => new MigrationSidecarStore({ sidecarPath: legacy, legacyStorePath: legacy }),
    ).toThrow("must not be accounts.json");
  });

  test("refuses hard-link aliases of the untouched v1 registry", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    linkSync(legacy, sidecarPath);

    expect(
      () => new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy }),
    ).toThrow("must not be accounts.json");
  });

  test("refuses symlink ancestors before creating sidecar directories", () => {
    const root = tempRoot();
    const target = join(root, "target");
    const linked = join(root, "linked");
    const legacy = join(root, "accounts.json");
    mkdirSync(target);
    symlinkSync(target, linked);
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const sidecarPath = join(linked, "nested", "migration-v2.json");
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });

    expect(() => store.install(createMigrationSidecar(buildPlan()))).toThrow(
      "symlink base directory",
    );
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

      expect(() => failing.install(sidecar)).toThrow(`forced crash ${point}`);

      const repaired = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
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
    expect(() => failing.install(sidecar)).toThrow("crash");
    writeFileSync(sidecarPath, JSON.stringify({ unexpected: "drift" }), { mode: 0o600 });

    const repaired = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
    expect(() => repaired.repair()).toThrow(MigrationDriftError);
    expect(existsSync(`${sidecarPath}.wal`)).toBe(true);
  });

  test("requires compare-and-swap for updates and rejects stale writers", () => {
    const root = tempRoot();
    const legacy = join(root, "accounts.json");
    const sidecarPath = join(root, "migration-v2.json");
    writeFileSync(legacy, '{"version":1}\n', { mode: 0o600 });
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
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
      store.install(transitionMigrationSidecar(initial, "partial_ready", {
        gateEvidence: passingEvidence(initial.plan),
      }), {
        expectedPreviousDigest: initial.integrityDigest,
      }),
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
    expect(() => crashing.install(first)).toThrow("crash");
    const walBefore = readFileSync(`${sidecarPath}.wal`, "utf8");

    const second = createMigrationSidecar(
      buildPlan([safeObservation("charlie")]),
    );
    const competing = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
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
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
    const initial = createMigrationSidecar(buildPlan());
    store.install(initial);
    const current = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:durable-before-crash",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    store.install(current, { expectedPreviousDigest: initial.integrityDigest });
    const truncatedSuccessor = transitionMigrationSidecar(initial, "partial_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });
    writeFileSync(
      walPath,
      `${JSON.stringify({
        schemaVersion: 1,
        planId: initial.plan.id,
        idempotencyKey: initial.plan.idempotencyKey,
        previousDigest: current.integrityDigest,
        nextDigest: truncatedSuccessor.integrityDigest,
        nextSidecar: truncatedSuccessor,
      }, null, 2)}\n`,
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
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
    const initial = createMigrationSidecar(buildPlan());
    const noncanonicalGenesis = appendMigrationAlias(initial, {
      kind: "legacy_account",
      alias: "legacy:claude:before-genesis",
      sourceKey: initial.plan.records[0]!.sourceKey,
      targetId: initial.plan.records[0]!.target.accountId,
    });
    writeFileSync(
      walPath,
      `${JSON.stringify({
        schemaVersion: 1,
        planId: initial.plan.id,
        idempotencyKey: initial.plan.idempotencyKey,
        previousDigest: null,
        nextDigest: noncanonicalGenesis.integrityDigest,
        nextSidecar: noncanonicalGenesis,
      }, null, 2)}\n`,
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
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
    const initial = createMigrationSidecar(buildPlan());
    const legitimate = transitionMigrationSidecar(initial, "final_ready", {
      gateEvidence: passingEvidence(initial.plan),
    });

    const {
      integrityDigest: _initialIntegrityDigest,
      ...initialCore
    } = initial;
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
    const {
      integrityDigest: _legitimateIntegrityDigest,
      ...legitimateCore
    } = legitimate;
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
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
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
    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });

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

    const store = new MigrationSidecarStore({ sidecarPath, legacyStorePath: legacy });
    expect(() => store.load()).toThrow("must be mode 0600");
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
