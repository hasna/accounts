import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";

import {
  AccountsError,
  MAX_COUNTER,
  createSQLiteAccounts,
  newCredentialBindingId,
  newCredentialOperationId,
  parseCounter,
  canonicalJson,
  parseClosedJsonBytes,
  type Account,
} from "../../src/index";
import { AccountsCatalog } from "../../src/domain/catalog";
import { transitionEntity } from "../../src/domain/state";
import { InMemoryAccountsRepository } from "../../src/storage/memory";
import type { AccountsRepository } from "../../src/storage/repository";
import { SQLiteAccountsRepository } from "../../src/storage/sqlite";
import { FileRecoveryLedger } from "../../src/storage/file-recovery-ledger";
import {
  SQLITE_MIGRATION_V1,
  SQLITE_MIGRATION_V1_CHECKSUM,
} from "../../src/storage/sqlite-migrations";
import type { InMemoryRecoveryLedger } from "../../src/storage/recovery";
import {
  C0,
  C1,
  CATALOG_INCARNATION,
  NOW,
  clock,
  makeFixtureGraph,
  makeCredentialHandleFor,
  makeCredentialResolution,
  mutationContext,
  seedActiveCatalog,
  TEST_CREDENTIAL_VERIFIER,
  makeTestRecoveryLedger,
  TEST_CREDENTIAL_USE_AUTHORIZER,
  TEST_AUTHORITY_POLICY,
} from "../fixtures";

const TEMP_ROOT = join(import.meta.dir, "..", "..", ".tmp", "storage-tests");
mkdirSync(TEMP_ROOT, { recursive: true, mode: 0o700 });
chmodSync(join(import.meta.dir, "..", "..", ".tmp"), 0o700);
chmodSync(TEMP_ROOT, 0o700);

const cleanup: string[] = [];
afterAll(() => {
  for (const path of cleanup) rmSync(path, { recursive: true, force: true });
});

type AdapterFactory = () => {
  repository: AccountsRepository;
  catalog: AccountsCatalog;
  ledger: InMemoryRecoveryLedger;
  directory?: string;
};

const adapters: ReadonlyArray<readonly ["memory" | "sqlite", AdapterFactory]> = [
  [
    "memory",
    () => {
      const ledger = makeTestRecoveryLedger();
      const repository = new InMemoryAccountsRepository(
        TEST_CREDENTIAL_VERIFIER,
        ledger,
        TEST_CREDENTIAL_USE_AUTHORIZER,
      );
      return { repository, catalog: new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY), ledger };
    },
  ],
  [
    "sqlite",
    () => {
      const directory = mkdtempSync(join(TEMP_ROOT, "sqlite-"));
      cleanup.push(directory);
      const ledger = makeTestRecoveryLedger();
      const repository = new SQLiteAccountsRepository(join(directory, "accounts.db"), {
        credentialVerifier: TEST_CREDENTIAL_VERIFIER,
        recoveryLedger: ledger,
        catalogIncarnation: CATALOG_INCARNATION,
        credentialUseAuthorizer: TEST_CREDENTIAL_USE_AUTHORIZER,
      });
      return {
        repository,
        catalog: new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY),
        directory,
        ledger,
      };
    },
  ],
];

for (const [adapterName, factory] of adapters) {
  describe(`${adapterName} repository conformance`, () => {
    test("runs the same complete catalog and eligibility flow", async () => {
      const { catalog } = factory();
      const graph = makeFixtureGraph();
      await seedActiveCatalog(catalog, graph, `${adapterName}:flow`);
      const result = await catalog.eligibility({
        accessMethodId: graph.method.id,
        operation: "responses.create",
        model: "model.example",
        dataClassification: "internal",
        destinationPolicyClass: "default",
      });
      expect(result.eligible).toBe(true);
      const doctor = await catalog.doctor();
      expect(doctor.integrity).toBe("ok");
      expect(doctor.adapter).toBe(adapterName);
      await catalog.close();
    });

    test("atomically promotes signed authority evidence and replays only the exact request", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 8);
      await catalog.add(
        "account",
        graph.account,
        mutationContext(`${adapterName}:authority:add`),
      );
      const context = mutationContext(`${adapterName}:authority:activate`);
      const first = await catalog.activateProviderAccount(
        graph.activeAccount,
        graph.ownershipEvidence,
        graph.ownershipFence,
        C0,
        context,
      );
      const replay = await catalog.activateProviderAccount(
        graph.activeAccount,
        graph.ownershipEvidence,
        graph.ownershipFence,
        C0,
        context,
      );
      expect(first.replayed).toBe(false);
      expect(replay.replayed).toBe(true);
      expect(replay.eventId).toBe(first.eventId);

      const capacityContext = mutationContext(`${adapterName}:capacity-evidence:add`);
      const capacity = await catalog.addCapacityPoolFromEvidence(
        graph.pool,
        graph.capacityEvidence,
        graph.capacityFence,
        capacityContext,
      );
      const capacityReplay = await catalog.addCapacityPoolFromEvidence(
        graph.pool,
        graph.capacityEvidence,
        graph.capacityFence,
        capacityContext,
      );
      expect(capacity.replayed).toBe(false);
      expect(capacityReplay.replayed).toBe(true);
      expect(capacityReplay.eventId).toBe(capacity.eventId);
      expect(capacity.record).toMatchObject({
        capacityEvidenceRef: `evidence:provider_capacity:8`,
        capacityEvidenceIssuerRef: "authority:provider_capacity_verifier",
        capacityEvidenceVersion: "accounts.authority-evidence.v1",
        capacityEvidenceGeneration: C1,
        capacityPolicyVersion: "capacity-policy-v1",
      });
      expect(capacity.record.capacityEvidenceDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
      await expect(
        repository.insert(
          "capacity_pool",
          makeFixtureGraph("api_key", 82).pool,
          mutationContext(`${adapterName}:capacity-evidence:unverified`),
        ),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });

      const unverified = makeFixtureGraph("api_key", 9);
      await repository.insert(
        "account",
        unverified.account,
        mutationContext(`${adapterName}:authority:unverified:add`),
      );
      await expect(
        repository.replace(
          "account",
          unverified.activeAccount,
          C0,
          mutationContext(`${adapterName}:authority:unverified:activate`),
        ),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });

      const forged = makeFixtureGraph("api_key", 10);
      await catalog.add(
        "account",
        forged.account,
        mutationContext(`${adapterName}:authority:forged:add`),
      );
      const parsed = parseClosedJsonBytes(forged.ownershipEvidence) as Record<string, unknown>;
      const signature = parsed.signature as string;
      parsed.signature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
      await expect(
        catalog.activateProviderAccount(
          forged.activeAccount,
          Buffer.from(canonicalJson(parsed), "utf8"),
          forged.ownershipFence,
          C0,
          mutationContext(`${adapterName}:authority:forged:activate`),
        ),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });

      const forgedCapacity = makeFixtureGraph("api_key", 83);
      await catalog.add(
        "account",
        forgedCapacity.account,
        mutationContext(`${adapterName}:capacity-evidence:forged-account:add`),
      );
      await catalog.activateProviderAccount(
        forgedCapacity.activeAccount,
        forgedCapacity.ownershipEvidence,
        forgedCapacity.ownershipFence,
        C0,
        mutationContext(`${adapterName}:capacity-evidence:forged-account:activate`),
      );
      await expect(
        catalog.addCapacityPoolFromEvidence(
          {
            ...forgedCapacity.pool,
            capacityEvidenceDigest: `sha256:${"0".repeat(64)}`,
          },
          forgedCapacity.capacityEvidence,
          forgedCapacity.capacityFence,
          mutationContext(`${adapterName}:capacity-evidence:projection-mismatch`),
        ),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });
      const capacityEnvelope = parseClosedJsonBytes(
        forgedCapacity.capacityEvidence,
      ) as Record<string, unknown>;
      const capacitySignature = capacityEnvelope.signature as string;
      capacityEnvelope.signature = `${capacitySignature[0] === "A" ? "B" : "A"}${capacitySignature.slice(1)}`;
      await expect(
        catalog.addCapacityPoolFromEvidence(
          forgedCapacity.pool,
          Buffer.from(canonicalJson(capacityEnvelope), "utf8"),
          forgedCapacity.capacityFence,
          mutationContext(`${adapterName}:capacity-evidence:forged`),
        ),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
      await catalog.close();
    });

    test("replays the original idempotent response after later mutation", async () => {
      const { repository } = factory();
      const graph = makeFixtureGraph("native_session", 11);
      const account = graph.account;
      const context = mutationContext(`${adapterName}:idempotent-insert`);
      const inserted = await repository.insert("account", account, context);
      const revoked = transitionEntity("account", account, "revoked", NOW.toISOString());
      await repository.replace(
        "account",
        revoked,
        account.revision,
        mutationContext(`${adapterName}:later-update`),
      );
      const replay = await repository.insert("account", account, context);
      expect(replay.replayed).toBe(true);
      expect(replay.eventId).toBe(inserted.eventId);
      expect(replay.record.revision).toBe(C0);
      expect(replay.record.status).toBe("pending");
      await repository.close();
    });

    test("rejects idempotency reuse when audited reason changes", async () => {
      const { repository } = factory();
      const account = makeFixtureGraph("native_session", 12).account;
      await repository.insert(
        "account",
        account,
        mutationContext(`${adapterName}:reason-conflict`, "FIRST_REASON"),
      );
      await expect(
        repository.insert(
          "account",
          account,
          mutationContext(`${adapterName}:reason-conflict`, "SECOND_REASON"),
        ),
      ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
      await repository.close();
    });

    test("preserves exact signed-64-bit counters beyond Number precision", async () => {
      const { repository } = factory();
      const source = makeFixtureGraph("native_session", 13).account;
      const record: Account = {
        ...source,
        status: "revoked",
        revision: parseCounter(MAX_COUNTER.toString(10)),
      };
      await repository.insert("account", record, mutationContext(`${adapterName}:int64`));
      const loaded = await repository.get("account", record.id);
      expect(String(loaded?.revision)).toBe("9223372036854775807");
      expect(typeof loaded?.revision).toBe("string");
      await repository.close();
    });

    test("orders UUID identifiers deterministically and rejects missing parents", async () => {
      const { catalog } = factory();
      const later = makeFixtureGraph("native_session", 21);
      const earlier = makeFixtureGraph("native_session", 20);
      await catalog.add("account", later.account, mutationContext(`${adapterName}:later`));
      await catalog.add("account", earlier.account, mutationContext(`${adapterName}:earlier`));
      const records = await catalog.list("account");
      expect(records.map((record) => record.id)).toEqual(
        [later.account.id, earlier.account.id].sort((left, right) => (left < right ? -1 : 1)),
      );
      await expect(
        catalog.add(
          "entitlement",
          makeFixtureGraph("native_session", 22).entitlement,
          mutationContext(`${adapterName}:missing-parent`),
        ),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
      await catalog.close();
    });

    test("serializes racing provider-subject ownership", async () => {
      const { catalog } = factory();
      const first = makeFixtureGraph("native_session", 31);
      const second = makeFixtureGraph(
        "native_session",
        32,
        first.activeAccount.providerSubjectRef!,
      );
      await catalog.add("account", first.account, mutationContext(`${adapterName}:race:first:add`));
      await catalog.add("account", second.account, mutationContext(`${adapterName}:race:second:add`));
      const outcomes = await Promise.allSettled([
        catalog.activateProviderAccount(
          first.activeAccount,
          first.ownershipEvidence,
          first.ownershipFence,
          C0,
          mutationContext(`${adapterName}:race:first:active`),
        ),
        catalog.activateProviderAccount(
          second.activeAccount,
          second.ownershipEvidence,
          second.ownershipFence,
          C0,
          mutationContext(`${adapterName}:race:second:active`),
        ),
      ]);
      expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
      await catalog.close();
    });

    test("keeps credential-family purpose lineage immutable across generations", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 41);
      await seedActiveCatalog(catalog, graph, `${adapterName}:family`);
      const conflicting = {
        ...graph.binding,
        id: makeFixtureGraph("workload_identity", 42).binding.id,
        purpose: "workload_identity" as const,
        resolver: "workload_identity" as const,
        credentialGeneration: parseCounter("1"),
        revision: C0,
        status: "pending" as const,
      };
      await expect(
        repository.insertCredentialBinding(
          conflicting,
          makeCredentialHandleFor({
            account: graph.account,
            pool: graph.pool,
            method: graph.method,
            binding: conflicting,
          }, 42),
          mutationContext(`${adapterName}:family:conflict`),
        ),
      ).rejects.toMatchObject({ code: "CAPACITY_DOMAIN_CONFLICT" });
      await catalog.close();
    });

    test("preserves provider-subject ownership after terminal revocation", async () => {
      const { repository, catalog } = factory();
      const first = makeFixtureGraph("native_session", 51);
      const firstPending = first.account;
      await catalog.add(
        "account",
        firstPending,
        mutationContext(`${adapterName}:subject:first:add`),
      );
      const firstActive = (
        await catalog.activateProviderAccount(
          first.activeAccount,
          first.ownershipEvidence,
          first.ownershipFence,
          firstPending.revision,
          mutationContext(`${adapterName}:subject:first:active`),
        )
      ).record;
      const firstRevoked = transitionEntity(
        "account",
        firstActive,
        "revoked",
        new Date(NOW.getTime() + 1).toISOString(),
      );
      await repository.replace(
        "account",
        firstRevoked,
        firstActive.revision,
        mutationContext(`${adapterName}:subject:first:revoked`),
      );
      const second = makeFixtureGraph(
        "native_session",
        52,
        firstActive.providerSubjectRef!,
      );
      const secondPending = second.account;
      await catalog.add(
        "account",
        secondPending,
        mutationContext(`${adapterName}:subject:second:add`),
      );
      await expect(
        catalog.activateProviderAccount(
          second.activeAccount,
          second.ownershipEvidence,
          second.ownershipFence,
          secondPending.revision,
          mutationContext(`${adapterName}:subject:second:active`),
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      await repository.close();
    });

    test("replays an earlier transition after subsequent state changes", async () => {
      const { catalog } = factory();
      const graph = makeFixtureGraph("api_key", 61);
      await seedActiveCatalog(catalog, graph, `${adapterName}:replay-parents`);
      const draft = {
        ...makeFixtureGraph("api_key", 62).method,
        entitlementId: graph.entitlement.id,
        capacityPoolId: graph.pool.id,
      };
      await catalog.add(
        "access_method",
        draft,
        mutationContext(`${adapterName}:replay:add`),
      );
      const firstContext = mutationContext(`${adapterName}:replay:disable`);
      const first = await catalog.transition(
        "access_method",
        draft.id,
        "disabled",
        C0,
        firstContext,
      );
      await catalog.transition(
        "access_method",
        draft.id,
        "draft",
        first.record.revision,
        mutationContext(`${adapterName}:replay:draft`),
      );
      const replay = await catalog.transition(
        "access_method",
        draft.id,
        "disabled",
        C0,
        firstContext,
      );
      expect(replay.replayed).toBe(true);
      expect(replay.record.revision).toBe(first.record.revision);
      await catalog.close();
    });

    test("requires a signed full-tuple actor-bound grant before resolving a handle", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 71);
      await seedActiveCatalog(catalog, graph, `${adapterName}:resolve`);
      const doctor = await catalog.doctor();
      if (doctor.recoveryFrontier === "unavailable") {
        throw new Error("test recovery frontier was unavailable");
      }
      const { grant, transport } = makeCredentialResolution(graph, doctor.recoveryFrontier);
      const resolved = await catalog.resolveCredentialHandle(graph.binding.id, grant, transport);
      expect(resolved.opaqueHandle).toBe(graph.handle.opaqueHandle);

      await expect(
        repository.insertCredentialBinding(
          {
            ...graph.binding,
            id: newCredentialBindingId(NOW.getTime() + 71_090),
            credentialGeneration: C1,
          },
          { ...graph.handle, credentialGeneration: C1 },
          mutationContext(`${adapterName}:resolve:forged-issuer`),
        ),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });

      await expect(
        catalog.resolveCredentialHandle(graph.binding.id, grant, {
          ...transport,
          authenticatedActorPrincipal: "principal:service:hasna:substituted-actor",
        }),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });
      await expect(
        catalog.resolveCredentialHandle(
          graph.binding.id,
          {
            ...grant,
            actor_principal: "principal:service:hasna:substituted-actor",
          },
          {
            ...transport,
            authenticatedActorPrincipal: "principal:service:hasna:substituted-actor",
          },
        ),
      ).rejects.toMatchObject({ code: "POLICY_DENIED" });

      const serializedAudit = JSON.stringify({
        events: await repository.events(),
        outbox: await repository.outbox(),
        bindings: await repository.list("credential_binding"),
      });
      expect(serializedAudit).not.toContain(graph.handle.opaqueHandle);
      await catalog.close();
    });

    test("atomically retires native N and creates a distinct no-handle N+1 barrier", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("native_session", 72);
      await seedActiveCatalog(catalog, graph, `${adapterName}:native-revoke`);
      const pool = await catalog.get("capacity_pool", graph.pool.id);
      const method = await catalog.get("access_method", graph.method.id);
      const capsule = await catalog.get("auth_capsule", graph.capsule!.id);
      const binding = await catalog.get("credential_binding", graph.binding.id);
      const request = {
        capsuleId: capsule.id,
        bindingId: binding.id,
        barrierBindingId: newCredentialBindingId(NOW.getTime() + 72_090),
        operationId: newCredentialOperationId(NOW.getTime() + 72_091),
        expectedPoolRevision: pool.revision,
        expectedMethodRevision: method.revision,
        expectedCapsuleRevision: capsule.revision,
        expectedBindingRevision: binding.revision,
        occurredAt: new Date(NOW.getTime() + 10).toISOString(),
        context: mutationContext(`${adapterName}:native-revoke:commit`, "NATIVE_REVOKE"),
      } as const;
      const result = await catalog.revokeNativeGeneration(request);
      expect(result.pool.status).toBe("draining");
      expect(result.pool.denyState).toBe("denied");
      expect(result.capsule.status).toBe("revoked");
      expect(result.capsule.authGeneration).toBe(C1);
      expect(result.retiredBinding.status).toBe("revoked");
      expect(result.retiredBinding.credentialGeneration).toBe(C0);
      expect(result.barrierBinding.status).toBe("revoked");
      expect(result.barrierBinding.credentialGeneration).toBe(C1);
      if (
        result.retiredBinding.status !== "revoked" ||
        result.retiredBinding.terminalKind !== "retired_handle_generation" ||
        result.barrierBinding.status !== "revoked" ||
        result.barrierBinding.terminalKind !== "revocation_barrier"
      ) {
        throw new Error("unexpected native terminal shapes");
      }
      expect(result.retiredBinding.credentialHandleAuditDigest).toMatch(/^hmac-sha256:/);
      expect(result.barrierBinding.lastUsableCredentialGeneration).toBe(C0);
      expect(result.barrierBinding).not.toHaveProperty("credentialHandleAuditDigest");
      expect(result.barrierBinding).not.toHaveProperty("bindingEvidenceRef");
      expect(result.operation.state).toBe("verifying");
      expect(result.operation.completionReceiptDigest).toBeUndefined();

      const replay = await catalog.revokeNativeGeneration(request);
      expect(replay.replayed).toBe(true);
      expect(await repository.credentialOperations()).toHaveLength(1);
      expect((await repository.outbox()).some(
        (entry) => entry.topic === "accounts.capsule.cleanup.requested",
      )).toBe(true);
      expect(JSON.stringify(await repository.outbox())).not.toContain(graph.handle.opaqueHandle);
      await catalog.close();
    });

    test("latches recovery hold when the external frontier leads the catalog", async () => {
      const { ledger, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 73);
      await seedActiveCatalog(catalog, graph, `${adapterName}:frontier`);
      const doctor = await catalog.doctor();
      if (doctor.recoveryFrontier === "unavailable") {
        throw new Error("test recovery frontier was unavailable");
      }
      ledger.append(doctor.recoveryFrontier, {
        kind: "catalog_mutation",
        aggregateKind: "access_method",
        aggregateId: graph.method.id,
        mutationDigest: `sha256:${"f".repeat(64)}`,
        occurredAt: new Date(NOW.getTime() + 20).toISOString(),
      });
      const eligibility = await catalog.eligibility({
        accessMethodId: graph.method.id,
        operation: "responses.create",
        model: "model.example",
        dataClassification: "internal",
        destinationPolicyClass: "default",
      });
      expect(eligibility.eligible).toBe(false);
      expect(eligibility.reasonCodes).toContain("RECOVERY_HOLD");
      await expect(
        catalog.add(
          "account",
          makeFixtureGraph("api_key", 74).account,
          mutationContext(`${adapterName}:frontier:blocked-write`),
        ),
      ).rejects.toMatchObject({ code: "RECOVERY_HOLD" });
      await expect(catalog.doctor()).resolves.toMatchObject({
        readiness: "recovery_hold",
        recoveryHold: true,
        positiveEligibility: false,
      });
      await catalog.close();
    });

    test("claims and acknowledges outbox rows with fenced compare-and-set delivery", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 75);
      await seedActiveCatalog(catalog, graph, `${adapterName}:outbox`);
      const now = new Date(NOW.getTime() + 100).toISOString();
      const claimExpiresAt = new Date(NOW.getTime() + 10_000).toISOString();
      const first = await repository.claimOutbox({
        workerRef: "principal:service:hasna:outbox-worker-a",
        limit: 2,
        now,
        claimExpiresAt,
      });
      expect(first).toHaveLength(2);
      expect(first.every((record) => record.status === "in_flight" && record.attemptCount === C1)).toBe(true);
      const second = await repository.claimOutbox({
        workerRef: "principal:service:hasna:outbox-worker-b",
        limit: 100,
        now,
        claimExpiresAt,
      });
      expect(second.some((candidate) => first.some((claimed) => claimed.id === candidate.id))).toBe(false);
      await expect(
        repository.acknowledgeOutbox({
          outboxId: first[0]!.id,
          workerRef: "principal:service:hasna:outbox-worker-b",
          expectedAttemptCount: C1,
          outcome: "delivered",
          now: new Date(NOW.getTime() + 200).toISOString(),
        }),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      const delivered = await repository.acknowledgeOutbox({
        outboxId: first[0]!.id,
        workerRef: "principal:service:hasna:outbox-worker-a",
        expectedAttemptCount: C1,
        outcome: "delivered",
        now: new Date(NOW.getTime() + 200).toISOString(),
      });
      expect(delivered.status).toBe("delivered");
      expect(delivered.claimOwnerRef).toBeUndefined();
      const eligibility = await catalog.eligibility({
        accessMethodId: graph.method.id,
        operation: "responses.create",
        model: "model.example",
        dataClassification: "internal",
        destinationPolicyClass: "default",
      });
      expect(eligibility.eligible).toBe(true);
      await catalog.close();
    });
  });
}

describe("SQLite migration and filesystem hardening", () => {
  test("explicit persistent recovery configuration preserves positive local evaluation across reopen", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "persistent-recovery-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const ledgerPath = join(directory, "accounts.recovery.log");
    const catalogIncarnation = CATALOG_INCARNATION;
    const signingKey = new Uint8Array(32).fill(0x5a);
    const repository = new SQLiteAccountsRepository(filename, {
      credentialVerifier: TEST_CREDENTIAL_VERIFIER,
      recoveryLedger: new FileRecoveryLedger({
        path: ledgerPath,
        catalogIncarnation,
        signingKey,
      }),
      catalogIncarnation,
      credentialUseAuthorizer: TEST_CREDENTIAL_USE_AUTHORIZER,
    });
    const internalCatalog = new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY);
    const graph = makeFixtureGraph("api_key", 81);
    await seedActiveCatalog(internalCatalog, graph, "persistent-local");
    await internalCatalog.close();

    const publicCapacity = createSQLiteAccounts({
      path: filename,
      clock,
      recovery: { ledgerPath, catalogIncarnation, signingKey },
    });
    const result = await publicCapacity.eligibility({
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    });
    expect(result.eligible).toBe(true);
    await expect(publicCapacity.doctor()).resolves.toMatchObject({
      readiness: "ready",
      recoveryHold: false,
      positiveEligibility: true,
    });
    await publicCapacity.close();
  });

  test("public local evaluation stays denied without a recovery frontier", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "public-deny-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const repository = new SQLiteAccountsRepository(filename, {
      credentialVerifier: TEST_CREDENTIAL_VERIFIER,
      recoveryLedger: makeTestRecoveryLedger(),
      catalogIncarnation: CATALOG_INCARNATION,
      credentialUseAuthorizer: TEST_CREDENTIAL_USE_AUTHORIZER,
    });
    const internalCatalog = new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY);
    const graph = makeFixtureGraph();
    await seedActiveCatalog(internalCatalog, graph, "public-deny");
    await internalCatalog.close();

    const publicCapacity = createSQLiteAccounts({ path: filename, clock });
    const result = await publicCapacity.eligibility({
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    });
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toEqual(["RECOVERY_HOLD"]);
    await publicCapacity.close();
  });

  test("creates owner-only database files and WAL mode", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "permissions-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const repository = new SQLiteAccountsRepository(filename);
    const doctor = await repository.doctor();
    expect(doctor).toMatchObject({ adapter: "sqlite", journalMode: "wal" });
    await repository.close();
    expect(statSync(directory).mode & 0o777).toBe(0o700);
    expect(statSync(filename).mode & 0o777).toBe(0o600);
  });

  test("applies V1 to V2 forward migration and creates the complete table floor", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "forward-v2-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const legacy = new Database(filename, { safeIntegers: true });
    legacy.exec(
      "CREATE TABLE accounts_schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)",
    );
    legacy.exec(SQLITE_MIGRATION_V1);
    legacy
      .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (1, ?, ?)")
      .run(SQLITE_MIGRATION_V1_CHECKSUM, NOW.toISOString());
    legacy.close();
    chmodSync(filename, 0o600);

    const repository = new SQLiteAccountsRepository(filename, {
      recoveryLedger: makeTestRecoveryLedger(),
      catalogIncarnation: CATALOG_INCARNATION,
    });
    await expect(repository.doctor()).resolves.toMatchObject({ schemaVersion: "2" });
    const inspector = new Database(filename, { readonly: true, safeIntegers: true });
    const tables = (inspector
      .query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all() as Array<{ name: string }>).map((row) => row.name);
    inspector.close();
    for (const table of [
      "accounts_installation",
      "provider_subject_claims",
      "provider_accounts",
      "entitlements",
      "capacity_pools",
      "account_lanes",
      "auth_capsules",
      "credential_bindings",
      "credential_operations",
      "import_candidates",
      "evidence_records",
      "recovery_ledger_receipts",
      "slot_eligibility_audit",
      "account_events",
      "outbox",
      "idempotency_records",
      "accounts_schema_migrations",
    ]) {
      expect(tables).toContain(table);
    }
    expect(tables).not.toContain("access_methods");
    await repository.close();
  });

  test("refuses symbolic-link path components", () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "symlink-"));
    const target = mkdtempSync(join(TEMP_ROOT, "target-"));
    cleanup.push(directory, target);
    const link = join(directory, "linked");
    symlinkSync(target, link, "dir");
    expect(() => new SQLiteAccountsRepository(join(link, "accounts.db"))).toThrow(
      expect.objectContaining({ code: "DATABASE_PATH_UNSAFE" }),
    );
  });

  test("refuses unknown newer and checksum-mismatched schemas", () => {
    for (const [name, version, checksum] of [
      ["newer", 3n, "sha256:future"],
      ["mismatch", 1n, "sha256:mismatch"],
    ] as const) {
      const directory = mkdtempSync(join(TEMP_ROOT, `${name}-`));
      cleanup.push(directory);
      const filename = join(directory, "accounts.db");
      const database = new Database(filename, { safeIntegers: true });
      database.exec(
        "CREATE TABLE accounts_schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)",
      );
      database
        .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)")
        .run(version, checksum, NOW.toISOString());
      database.close();
      chmodSync(filename, 0o600);
      expect(() => new SQLiteAccountsRepository(filename)).toThrow(AccountsError);
    }
  });
});
