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
  });

  test("redacts paths and aliases while retaining counts, digests, and conflict evidence", () => {
    const plan = buildPlan([
      safeObservation("alice"),
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

    expect(encoded).not.toContain("/profiles/");
    expect(encoded).not.toContain("/secret/");
    expect(encoded).not.toContain("alice");
    expect(encoded).not.toContain("legacy:claude:alice");
    expect(encoded).not.toContain("credential");
    expect(redacted.records[0]?.root?.byteCount).toBe(2048);
    expect(redacted.records[0]?.root?.digest).toBe(digest("root-claude-alice"));
    expect(redacted.records[0]?.historicalAliasDigests).toHaveLength(1);
    expect(redacted.records[0]?.historicalSessionAliasDigests).toHaveLength(1);
    expect(redacted.records[1]?.root).toMatchObject({
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
  });

  test("enforces explicit monotonic partial and final cutover states", () => {
    const plan = buildPlan();
    const initial = createMigrationSidecar(plan);
    expect(() => transitionMigrationSidecar(initial, "partial_ready")).toThrow(
      "requires current migration gate evidence",
    );
    const partialReady = transitionMigrationSidecar(initial, "partial_ready", {
      gateEvidence: passingEvidence(plan),
    });
    const partialApplied = transitionMigrationSidecar(partialReady, "partial_applied");
    const finalReady = transitionMigrationSidecar(partialApplied, "final_ready", {
      gateEvidence: passingEvidence(plan),
    });
    const finalApplied = transitionMigrationSidecar(finalReady, "final_applied");

    expect(finalApplied.state).toBe("final_applied");
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
});

class RecordingBackfillTransaction implements MigrationBackfillTransaction {
  readonly events: string[] = [];
  failAt?: string;

  async ensureRuntime(runtime: ScopedBackfillRuntime): Promise<"created" | "adopted"> {
    this.events.push(`runtime:${runtime.id}`);
    this.maybeFail("runtime");
    return "created";
  }

  async ensureAccount(account: ScopedBackfillAccount): Promise<"created" | "adopted"> {
    this.events.push(`account:${account.id}`);
    this.maybeFail("account");
    return "created";
  }

  async ensureCrosswalk(crosswalk: ScopedBackfillCrosswalk): Promise<"created" | "adopted"> {
    this.events.push(`crosswalk:${crosswalk.sourceKey}`);
    this.maybeFail("crosswalk");
    return "created";
  }

  async recordEpoch(input: {
    planId: string;
    idempotencyKey: string;
    cutoverEpoch: string;
  }): Promise<"created" | "adopted"> {
    this.events.push(`epoch:${input.planId}`);
    this.maybeFail("epoch");
    return "created";
  }

  private maybeFail(point: string): void {
    if (this.failAt === point) throw new Error(`forced ${point} failure`);
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
  });
});
