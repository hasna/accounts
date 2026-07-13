import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { AccountsError } from "../../src/errors";
import { parseCounter } from "../../src/domain/counter";
import {
  canonicalJson,
  parseClosedJsonBytes,
} from "../../src/serialization/json";
import * as publicApi from "../../src/index";
import {
  ONLINE_GENERATION_CONTEXT_FIELDS_V1,
  createAccountsSlotEligibilityAdapter,
  createDeterministicAccountsSlotEligibilitySource,
  signOnlineGenerationCheckReceiptV1,
  signSlotEligibilityV1,
  type AccountsEvidenceSignerHistoryV2,
  type AccountsOnlineGenerationContextV1,
  type AccountsOnlineGenerationSourceRequestV1,
  type AccountsSlotEligibilityRequestV1,
  type SlotEligibilityPositiveV1,
  type V10Sha256Digest,
} from "../../src/v10";
import {
  SQLiteAccountsSlotEligibilitySource,
  type AccountsRecoveryFrontierPort,
  type AccountsRecoveryFrontierV1,
} from "../../src/v10/sqlite-slot-source";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
} from "../../src/v10/capability-use-ledger";
import {
  INFINITY_INTEGRATION_COMMIT,
  type InfinityAccountsOperationPort,
  type VerifiedConsumeBoundOperation,
} from "../../src/v10/infinity-operation-port";

interface Fixture {
  readonly wire: Record<string, unknown>;
}

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as {
  readonly wire_fixtures: Readonly<Record<string, Fixture>>;
};
const runtimePin = await Bun.file(
  new URL("../../contracts/accounts-v10/pin.json", import.meta.url),
).json() as {
  readonly source_commit: string;
  readonly infinity_integration_commit: string;
  readonly sandboxes_integration_commit: string;
  readonly integration_authorized: boolean;
  readonly publish_authorized: boolean;
};
const NOW = new Date("2026-07-11T10:00:15.000Z");
const LANE_ID = "0198a0a0-0000-7000-8000-000000000002";
const E2E_CHANNEL_BINDING_DIGEST = `sha256:${"7".repeat(64)}`;
const SLOT_REQUEST: AccountsSlotEligibilityRequestV1 = {
  schema_version: "accounts.eligibility-request.v1",
  account_lane_id: LANE_ID,
  data_classification: "internal",
  destination_policy_class: "provider_api",
  model: "provider-model-1",
  operation: "generate",
};
const FRONTIER: AccountsRecoveryFrontierV1 = {
  catalog_incarnation: "catalog-incarnation-1",
  sequence: parseCounter("42"),
  hash: `sha256:${"1".repeat(64)}`,
};
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

class MutableRecoveryFrontier implements AccountsRecoveryFrontierPort {
  state: "current" | "stale" | "forked" | "unavailable" = "current";

  async readFreshFrontier(): Promise<AccountsRecoveryFrontierV1> {
    if (this.state === "unavailable") {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Recovery frontier unavailable");
    }
    if (this.state === "stale") return { ...FRONTIER, sequence: parseCounter("41") };
    if (this.state === "forked") return { ...FRONTIER, hash: `sha256:${"2".repeat(64)}` };
    return FRONTIER;
  }
}

class RacingDenyRecoveryFrontier extends MutableRecoveryFrontier {
  private armed = false;
  private readsAfterArm = 0;
  denyWriteWasBlocked = false;

  constructor(private readonly path: string) {
    super();
  }

  arm(): void {
    this.armed = true;
    this.readsAfterArm = 0;
  }

  override async readFreshFrontier(): Promise<AccountsRecoveryFrontierV1> {
    if (this.armed) {
      this.readsAfterArm += 1;
      if (this.readsAfterArm === 2) {
        const writer = new Database(this.path);
        try {
          writer.exec("PRAGMA busy_timeout=1");
          try {
            writer.query(
              "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
            ).run(LANE_ID);
          } catch {
            this.denyWriteWasBlocked = true;
          }
        } finally {
          writer.close();
        }
      }
    }
    return super.readFreshFrontier();
  }
}

function fixtureBytes(name: string): Uint8Array {
  return new TextEncoder().encode(canonicalJson(fixtureDocument.wire_fixtures[name]!.wire));
}

function sha256(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function onlineContext(
  fixtureName = "online_generation_check_positive",
): AccountsOnlineGenerationContextV1 {
  const wire = fixtureDocument.wire_fixtures[fixtureName]!.wire;
  return Object.fromEntries(ONLINE_GENERATION_CONTEXT_FIELDS_V1.map((field) => [
    field,
    field === "authenticated_actor_principal"
      ? wire.actor_principal
      : field === "sender_constraint_confirmation"
        ? E2E_CHANNEL_BINDING_DIGEST
      : structuredClone(wire[field]),
  ])) as unknown as AccountsOnlineGenerationContextV1;
}

function createSignedEvidence() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer = {
    issuer: "accounts:self-hosted",
    issuerIncarnation: "accounts-sqlite-e2e-incarnation",
    audience: "infinity:self-hosted",
    keyId: "accounts-sqlite-e2e-current",
    privateKey,
  } as const;
  const signerHistory: AccountsEvidenceSignerHistoryV2 = {
    schema_version: "accounts.evidence-signer-history/v2",
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    current_key_id: signer.keyId,
    keys: [{
      key_id: signer.keyId,
      public_key_spki_base64url: publicKey
        .export({ format: "der", type: "spki" })
        .toString("base64url"),
      activated_at: "2026-07-11T09:00:00.000Z",
      expires_at: "2026-07-12T00:00:00.000Z",
      retired_at: null,
      revoked_at: null,
    }],
  };
  const requestDigest = sha256(new TextEncoder().encode(canonicalJson(SLOT_REQUEST)));
  const slotDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    eligibility_request_digest: requestDigest,
  };
  delete slotDraft.signature;
  const slotAllow = signSlotEligibilityV1(slotDraft, signer);
  const slotDenyDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_resolved_negative!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    eligibility_request_digest: requestDigest,
  };
  delete slotDenyDraft.signature;
  const slotDeny = signSlotEligibilityV1(slotDenyDraft, signer);
  const onlineDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    sender_constraint_confirmation: E2E_CHANNEL_BINDING_DIGEST,
    slot_eligibility_digest: sha256(slotAllow),
  };
  delete onlineDraft.signature;
  const onlineAllow = signOnlineGenerationCheckReceiptV1(onlineDraft, signer);
  const onlineDenyDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_resolved_negative!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    sender_constraint_confirmation: E2E_CHANNEL_BINDING_DIGEST,
    slot_eligibility_digest: sha256(slotAllow),
  };
  delete onlineDenyDraft.signature;
  const onlineDeny = signOnlineGenerationCheckReceiptV1(onlineDenyDraft, signer);
  return Object.freeze({ signer, signerHistory, slotAllow, slotDeny, onlineAllow, onlineDeny });
}

const signedEvidence = createSignedEvidence();

function onlineSourceRequest(): AccountsOnlineGenerationSourceRequestV1 {
  return {
    context: onlineContext(),
    slot_eligibility_digest: sha256(signedEvidence.slotAllow) as V10Sha256Digest,
  };
}

function onlineCheckRequest(
  expectedSlotEligibility: SlotEligibilityPositiveV1,
  context = onlineContext(),
) {
  return { context, expectedSlotEligibility } as const;
}

function stringField(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string") throw new Error(`fixture ${field} must be a string`);
  return value;
}

const E2E_ANCHOR_BYTES = new TextEncoder().encode(canonicalJson({ anchor: "e2e-prepared-open" }));
const E2E_ANCHOR_DIGEST = sha256(E2E_ANCHOR_BYTES);

function consumeRequest(
  onlineBytes: Uint8Array,
  variant: "first" | "second",
): Uint8Array {
  const online = parseClosedJsonBytes(onlineBytes) as Record<string, unknown>;
  const channelBindingDigest = stringField(online, "sender_constraint_confirmation");
  const requestId = variant === "first"
    ? "0198a0a0-0000-7000-8000-000000000921"
    : "0198a0a0-0000-7000-8000-000000000922";
  const request = {
    schema_version: "accounts.capability-use-consume-request.v1",
    schema_digest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
    consume_request_id: requestId,
    capability_id: stringField(online, "capability_id"),
    capability_digest: stringField(online, "capability_digest"),
    nonce: stringField(online, "nonce"),
    subject: stringField(online, "subject"),
    actor_principal: stringField(online, "actor_principal"),
    effect_namespace_id: stringField(online, "effect_namespace_id"),
    account_lane_id: stringField(online, "account_lane_id"),
    capacity_pool_id: stringField(online, "capacity_pool_id"),
    capacity_domain_ref: stringField(online, "capacity_domain_ref"),
    serialization_key_digest: stringField(online, "serialization_key_digest"),
    credential_family_id: stringField(online, "credential_family_id"),
    resource_lease_id: stringField(online, "resource_lease_id"),
    resource_id: stringField(online, "resource_id"),
    resource_lifecycle_generation: stringField(online, "resource_lifecycle_generation"),
    operation_id: stringField(online, "operation_id"),
    operation_digest: stringField(online, "operation_digest"),
    operation_execution_epoch: stringField(online, "operation_execution_epoch"),
    sender_key_thumbprint: stringField(online, "sender_key_thumbprint"),
    channel_binding_digest: channelBindingDigest,
    canonical_request_digest: stringField(online, "canonical_request_digest"),
    provider_destination_policy_digest: stringField(online, "provider_destination_policy_digest"),
    online_receipt_id: stringField(online, "receipt_id"),
    online_receipt_digest: sha256(onlineBytes),
    model_call_anchor_digest: E2E_ANCHOR_DIGEST,
    expected_use_count: "0",
    max_uses: "1",
    not_after: stringField(online, "expires_at"),
    idempotency_key_digest: `sha256:${(variant === "first" ? "a" : "b").repeat(64)}`,
  };
  return new TextEncoder().encode(canonicalJson(request));
}

function infinityOperationPort() {
  const calls = { read: 0, preparedCurrent: 0, bind: 0, assert: 0 };
  let unavailable = false;
  const port: InfinityAccountsOperationPort = {
    readPreparedOpenOperation: async (binding) => {
      calls.read += 1;
      if (unavailable) throw new Error("Infinity unavailable");
      const holdBytes = new TextEncoder().encode(canonicalJson({ hold: "e2e-open" }));
      return {
        schemaVersion: "infinity.model-call-prepared-anchor/v1",
        schemaDigest: "sha256:39f247a54d025353bdb2cf98907ccfe9ad49d8c03ba4244bf66c72da667e924e",
        recordKind: "PREPARED",
        holdState: "OPEN",
        binding,
        preparedAnchorJcsBase64url: Buffer.from(E2E_ANCHOR_BYTES).toString("base64url"),
        preparedAnchorDigest: E2E_ANCHOR_DIGEST,
        openHoldReceiptJcsBase64url: Buffer.from(holdBytes).toString("base64url"),
        openHoldReceiptDigest: sha256(holdBytes),
        holdAuthorityEpoch: "1",
        holdId: "e2e-hold-1",
        holdGeneration: "1",
        resourceLeaseFrontierSequence: "1",
        resourceLeaseFrontierHash: `sha256:${"2".repeat(64)}`,
        preparedModelEffectFrontierSequence: "2",
        preparedModelEffectFrontierHash: `sha256:${"3".repeat(64)}`,
        deliveryFrontierSequence: "3",
        deliveryFrontierHash: `sha256:${"4".repeat(64)}`,
        holdModelFrontierDigest: `sha256:${"5".repeat(64)}`,
      };
    },
    assertPreparedOpenCurrent: async ({ prepared }) => {
      calls.preparedCurrent += 1;
      if (unavailable) throw new Error("Infinity unavailable");
      return prepared;
    },
    bindCapabilityUse: async (input) => {
      calls.bind += 1;
      if (unavailable) throw new Error("Infinity unavailable");
      const bindingBytes = new TextEncoder().encode(canonicalJson({
        consume_receipt_digest: input.consumeReceiptDigest,
        use_id: input.useId,
      }));
      return {
        schemaVersion: "infinity.model-call-consume-binding/v1",
        schemaDigest: "sha256:5ed69a61c6162ac1aa42e50e8d718b92fc8bbfab9b1da0d78ecbe91c24f621d2",
        recordKind: "CONSUME_BOUND",
        holdState: "OPEN",
        prepared: input.prepared,
        consumeReceiptDigest: input.consumeReceiptDigest,
        useId: input.useId,
        consumeBindingJcsBase64url: Buffer.from(bindingBytes).toString("base64url"),
        consumeBindingDigest: sha256(bindingBytes),
        boundModelEffectFrontierSequence: "3",
        boundModelEffectFrontierHash: `sha256:${"6".repeat(64)}`,
      } satisfies VerifiedConsumeBoundOperation;
    },
    assertConsumeBoundCurrent: async ({ consumeBound }) => {
      calls.assert += 1;
      if (unavailable) throw new Error("Infinity unavailable");
      return consumeBound;
    },
  };
  return { port, calls, setUnavailable: () => { unavailable = true; } };
}

function installSignedEvidence(path: string): void {
  const database = new Database(path);
  try {
    const insert = database.query(`
      INSERT INTO accounts_v10_signed_evidence(
        account_lane_id, phase, decision, wire_jcs,
        catalog_incarnation, recovery_frontier_sequence, recovery_frontier_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    for (const [phase, decision, name] of [
      ["SLOT", "ALLOW", signedEvidence.slotAllow],
      ["SLOT", "DENY", signedEvidence.slotDeny],
      ["ONLINE", "ALLOW", signedEvidence.onlineAllow],
      ["ONLINE", "DENY", signedEvidence.onlineDeny],
    ] as const) {
      insert.run(
        LANE_ID,
        phase,
        decision,
        name,
        FRONTIER.catalog_incarnation,
        FRONTIER.sequence,
        FRONTIER.hash,
      );
    }
    database.query(
      "INSERT INTO accounts_v10_runtime_state(account_lane_id, current_deny) VALUES (?, 0)",
    ).run(LANE_ID);
  } finally {
    database.close();
  }
}

describe("ACC-041 SQLite Slot/online adapter", () => {
  test("pins the reviewed planning, Infinity, and Sandboxes integration refs without lifting gates", () => {
    expect(runtimePin).toMatchObject({
      source_commit: "80054c36b10111765a18b89743214679c58ad7c6",
      infinity_integration_commit: "6c2ba3d490cd58c7192d6e274514a9d849575ab8",
      sandboxes_integration_commit: "d8a4d37c35e8d98ea468a8d95dcf98b0a890fa48",
      implementation_status: "EXACT_BYTE_REVIEW_READY",
      integration_authorized: false,
      publish_authorized: false,
      deploy_authorized: false,
    });
    expect(INFINITY_INTEGRATION_COMMIT).toBe(
      "6c2ba3d490cd58c7192d6e274514a9d849575ab8",
    );
    expect(publicApi).toHaveProperty("createSQLiteAccountsSlotEligibilityPort");
    expect(publicApi).not.toHaveProperty("SQLiteAccountsSlotEligibilitySource");
    expect(publicApi).toMatchObject({
      CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
      CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
      INFINITY_INTEGRATION_COMMIT,
    });
    expect(publicApi).not.toHaveProperty("NonRewindableCapabilityUseLedger");
    expect(publicApi).not.toHaveProperty("verifyCapabilityUseEvidence");
    expect(publicApi).not.toHaveProperty("createCoordinatedOwnerOnlySignedAppendLog");
  });

  test("uses the same exact codecs for deterministic and production SQLite sources", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-slot-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const frontier = new MutableRecoveryFrontier();
    const trust = {
      signerHistory: signedEvidence.signerHistory,
      clock: () => new Date(NOW),
      expectedEffectNamespaceId: "effect-namespace-1",
    };
    const production = publicApi.createSQLiteAccountsSlotEligibilityPort({
      path,
      recoveryFrontier: frontier,
      trust,
    });
    installSignedEvidence(path);
    const deterministic = createAccountsSlotEligibilityAdapter(
      createDeterministicAccountsSlotEligibilitySource({
        slot: signedEvidence.slotAllow,
        online: signedEvidence.onlineAllow,
      }),
      trust,
    );

    const productionSlot = await production.getSlotEligibility(SLOT_REQUEST);
    const deterministicSlot = await deterministic.getSlotEligibility(SLOT_REQUEST);
    expect(productionSlot).toEqual(deterministicSlot);
    if (!productionSlot.eligible || !deterministicSlot.eligible) {
      throw new Error("signed E2E SlotEligibility must be positive");
    }
    expect(await production.checkOnlineGeneration(onlineCheckRequest(productionSlot))).toEqual(
      await deterministic.checkOnlineGeneration(onlineCheckRequest(deterministicSlot)),
    );
    for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
      if (existsSync(candidate)) expect(lstatSync(candidate).mode & 0o777).toBe(0o600);
    }
    production.close();
  });

  test("current deny changes signed generation/revision consequences and no allow survives", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-deny-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const source = new SQLiteAccountsSlotEligibilitySource({
      path,
      recoveryFrontier: new MutableRecoveryFrontier(),
    });
    installSignedEvidence(path);
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: signedEvidence.signerHistory,
      clock: () => new Date(NOW),
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    const positiveSlot = await port.getSlotEligibility(SLOT_REQUEST);
    if (!positiveSlot.eligible) throw new Error("signed E2E SlotEligibility must be positive");
    const allowed = await port.checkOnlineGeneration(onlineCheckRequest(positiveSlot));
    expect(allowed.allowed).toBe(true);

    const database = new Database(path);
    database.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
    ).run(LANE_ID);
    database.close();
    const deniedSlot = await port.getSlotEligibility(SLOT_REQUEST);
    const denied = await port.checkOnlineGeneration(onlineCheckRequest(
      positiveSlot,
      onlineContext("online_generation_check_resolved_negative"),
    ));
    expect(deniedSlot.eligible).toBe(false);
    expect(denied.allowed).toBe(false);
    expect(denied.current_deny).toBe(true);
    expect(BigInt(denied.deny_generation)).toBeGreaterThan(BigInt(allowed.deny_generation));
    expect(denied.accounts_revision_set_digest).not.toBe(allowed.accounts_revision_set_digest);
    source.close();
  });

  test("linearizes a racing deny and advances a monotonic state revision", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-deny-race-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const frontier = new RacingDenyRecoveryFrontier(path);
    const source = new SQLiteAccountsSlotEligibilitySource({ path, recoveryFrontier: frontier });
    installSignedEvidence(path);
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: signedEvidence.signerHistory,
      clock: () => new Date(NOW),
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    const positiveSlot = await port.getSlotEligibility(SLOT_REQUEST);
    if (!positiveSlot.eligible) throw new Error("signed E2E SlotEligibility must be positive");

    frontier.arm();
    const linearizedAllow = await port.checkOnlineGeneration(
      onlineCheckRequest(positiveSlot),
    );
    expect(linearizedAllow.allowed).toBe(true);
    expect(frontier.denyWriteWasBlocked).toBe(true);

    const writer = new Database(path, { safeIntegers: true });
    const initialRevision = writer.query<{
      readonly runtime_state_revision: bigint;
    }, [string]>(`
      SELECT runtime_state_revision
      FROM accounts_v10_runtime_revision
      WHERE account_lane_id=?
    `).get(LANE_ID);
    if (initialRevision === null) throw new Error("runtime state revision must exist");
    writer.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
    ).run(LANE_ID);
    writer.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=0 WHERE account_lane_id=?",
    ).run(LANE_ID);
    writer.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
    ).run(LANE_ID);
    const state = writer.query<{
      readonly current_deny: bigint;
      readonly runtime_state_revision: bigint;
    }, [string]>(`
      SELECT state.current_deny, revision.runtime_state_revision
      FROM accounts_v10_runtime_state AS state
      JOIN accounts_v10_runtime_revision AS revision USING(account_lane_id)
      WHERE state.account_lane_id=?
    `).get(LANE_ID);
    expect(state).toEqual({
      current_deny: 1n,
      runtime_state_revision: initialRevision.runtime_state_revision + 3n,
    });
    writer.query(`
      UPDATE accounts_v10_signed_evidence
      SET wire_jcs=wire_jcs
      WHERE account_lane_id=? AND phase='ONLINE' AND decision='DENY'
    `).run(LANE_ID);
    const evidenceRevision = writer.query<{
      readonly runtime_state_revision: bigint;
    }, [string]>(`
      SELECT runtime_state_revision
      FROM accounts_v10_runtime_revision
      WHERE account_lane_id=?
    `).get(LANE_ID);
    writer.close();
    expect(evidenceRevision?.runtime_state_revision).toBe(
      initialRevision.runtime_state_revision + 4n,
    );

    const denied = await port.checkOnlineGeneration(onlineCheckRequest(
      positiveSlot,
      onlineContext("online_generation_check_resolved_negative"),
    ));
    expect(denied.allowed).toBe(false);
    source.close();
  });

  test("composes signed v11 consumption through live Infinity evidence and replays after reopen", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-e2e-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const port = publicApi.createSQLiteAccountsSlotEligibilityPort({
      path,
      recoveryFrontier: new MutableRecoveryFrontier(),
      trust: {
        signerHistory: signedEvidence.signerHistory,
        clock: () => new Date(NOW),
        expectedEffectNamespaceId: "effect-namespace-1",
      },
    });
    installSignedEvidence(path);
    const slot = await port.getSlotEligibility(SLOT_REQUEST);
    if (!slot.eligible) throw new Error("signed E2E SlotEligibility must be positive");
    const online = await port.checkOnlineGeneration(onlineCheckRequest(slot));
    expect(online.allowed).toBe(true);
    expect(sha256(new TextEncoder().encode(canonicalJson(online)))).toBe(
      sha256(signedEvidence.onlineAllow),
    );

    const ledgerOptions = {
      ledgerPath: join(root, "capability-use.log"),
      mirrorPath: join(root, "capability-use.sqlite"),
      catalogIncarnation: "catalog-incarnation-1",
      signingKey: new Uint8Array(32).fill(0x61),
    } as const;
    const infinity = infinityOperationPort();
    const createConsumer = (clock = () => new Date(NOW)) =>
      publicApi.createAccountsCapabilityUseConsumer({
      infinity: infinity.port,
      receiptSigner: signedEvidence.signer,
      receiptSignerHistory: signedEvidence.signerHistory,
      onlineTrust: {
        signerHistory: signedEvidence.signerHistory,
        expectedEffectNamespaceId: "effect-namespace-1",
      },
      expectedSerializationKeyDigest:
        slot.serialization_key_digest as unknown as `sha256:${string}`,
      clock,
      ledger: ledgerOptions,
    });
    const consumeInput = (consumeRequestBytes: Uint8Array) => ({
      consumeRequestBytes,
      authenticatedChannelBindingDigest: stringField(
        online as unknown as Record<string, unknown>,
        "sender_constraint_confirmation",
      ) as `sha256:${string}`,
      expectedSlotEligibility: slot,
      onlineReceiptBytes: signedEvidence.onlineAllow,
    });
    const firstRequest = consumeRequest(signedEvidence.onlineAllow, "first");
    const consumer = createConsumer();
    const first = await consumer.consume(consumeInput(firstRequest));
    expect(first.replayed).toBe(false);
    expect(first.bindingCurrent).toBe(true);
    expect(first.consumeBound?.recordKind).toBe("CONSUME_BOUND");
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 1 });

    const secondRequest = consumeRequest(signedEvidence.onlineAllow, "second");
    await expect(consumer.consume(consumeInput(secondRequest))).rejects.toEqual(
      expect.objectContaining({ code: "CONFLICT" }),
    );
    consumer.close();

    infinity.setUnavailable();
    const reopened = createConsumer(() => new Date("2026-07-11T10:05:00.000Z"));
    const replay = await reopened.consume(consumeInput(firstRequest));
    expect(replay.replayed).toBe(true);
    expect(replay.bindingCurrent).toBe(false);
    expect(replay.consumeBound).toBeUndefined();
    expect(replay.receiptBytes).toEqual(first.receiptBytes);
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 1 });

    const writer = new Database(path);
    writer.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
    ).run(LANE_ID);
    writer.close();
    const denied = await port.checkOnlineGeneration(onlineCheckRequest(
      slot,
      onlineContext("online_generation_check_resolved_negative"),
    ));
    expect(denied.allowed).toBe(false);
    expect((await reopened.consume(consumeInput(firstRequest))).useId).toBe(first.useId);
    reopened.close();
    port.close();
  });

  test("SQLite source rejects obsolete, extra, and accessor-backed request shapes", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-closed-request-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const source = new SQLiteAccountsSlotEligibilitySource({
      path,
      recoveryFrontier: new MutableRecoveryFrontier(),
    });
    installSignedEvidence(path);

    await expect(source.getSlotEligibility({ account_lane_id: LANE_ID } as never))
      .rejects.toBeInstanceOf(AccountsError);
    await expect(source.checkOnlineGeneration({
      ...onlineSourceRequest(),
      context: { ...onlineContext(), unexpected: true },
    } as never)).rejects.toBeInstanceOf(AccountsError);

    let accessorInvoked = false;
    const accessorContext = { ...onlineContext() } as Record<string, unknown>;
    Object.defineProperty(accessorContext, "account_lane_id", {
      enumerable: true,
      get() {
        accessorInvoked = true;
        return LANE_ID;
      },
    });
    await expect(source.checkOnlineGeneration({
      context: accessorContext,
      slot_eligibility_digest: sha256(signedEvidence.slotAllow),
    } as never)).rejects.toBeInstanceOf(AccountsError);
    expect(accessorInvoked).toBe(false);
    source.close();
  });

  test("stale, forked, or unavailable external frontier fails before returning signed evidence", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-frontier-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const frontier = new MutableRecoveryFrontier();
    const source = new SQLiteAccountsSlotEligibilitySource({ path, recoveryFrontier: frontier });
    installSignedEvidence(path);

    for (const state of ["stale", "forked", "unavailable"] as const) {
      frontier.state = state;
      await expect(source.getSlotEligibility(SLOT_REQUEST))
        .rejects.toBeInstanceOf(AccountsError);
      await expect(source.checkOnlineGeneration(onlineSourceRequest()))
        .rejects.toBeInstanceOf(AccountsError);
    }
    source.close();
  });
});
