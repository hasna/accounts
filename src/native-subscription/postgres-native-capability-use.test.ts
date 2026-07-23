import { generateKeyPairSync } from "node:crypto";
import { describe, expect, test } from "bun:test";

import { PostgresNativeCapabilityUseStore } from "./postgres-native-capability-use.js";
import type { OnlineGenerationReceiptUseCasRequest } from "./online-generation-receipt.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

const OWNER = "principal:service:hasna:infinity";
const SUBJECT = "principal:service:hasna:worker";
const NOW = new Date("2030-07-18T12:00:00.000Z");
const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;
const D5 = `sha256:${"5".repeat(64)}`;
const IDS = {
  consumeRequest: "018f0f00-0001-7000-8000-000000000001",
  consumeRequest2: "018f0f00-0002-7000-8000-000000000002",
  capability: "018f0f00-0003-7000-8000-000000000003",
  capability2: "018f0f00-0003-7000-8000-000000000004",
  accountLane: "018f0f00-0004-7000-8000-000000000004",
  capacityPool: "018f0f00-0005-7000-8000-000000000005",
  resourceLease: "018f0f00-0006-7000-8000-000000000006",
  operation: "018f0f00-0007-7000-8000-000000000007",
  onlineReceipt: "018f0f00-0008-7000-8000-000000000008",
  consumeReceipt: "018f0f00-0009-7000-8000-000000000009",
} as const;

interface UseRow {
  owner_ref: string;
  consume_request_id: string;
  request_digest: string;
  capability_id: string;
  idempotency_key_digest: string;
  receipt_jcs_base64url: string;
  committed_at: string;
}

interface FakeState {
  rows: UseRow[];
  modes: string[];
  locks: string[];
}

function fakeClient(state: FakeState): PostgresSqlClient {
  const transaction = (async (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<unknown[]> => {
    const query = strings.join("?").replace(/\s+/g, " ").trim();
    if (query.includes("set_config('accounts.principal'")) return [];
    if (query.includes("accounts.current_principal() AS principal")) {
      return [{
        principal: OWNER,
        realm: "hasna",
        role_name: "accounts_runtime",
        login_role_name: "accounts_runtime",
      }];
    }
    if (query.includes("pg_advisory_xact_lock")) {
      state.locks.push(String(values[0]));
      return [];
    }
    if (
      query.includes("FROM accounts.capability_use_consumptions") &&
      query.includes("consume_request_id =")
    ) {
      return state.rows.filter(
        (row) => row.owner_ref === values[0] && row.consume_request_id === values[1],
      );
    }
    if (
      query.includes("FROM accounts.capability_use_consumptions") &&
      query.includes("idempotency_key_digest =")
    ) {
      return state.rows.filter(
        (row) => row.owner_ref === values[0] && row.idempotency_key_digest === values[1],
      );
    }
    if (
      query.includes("FROM accounts.capability_use_consumptions") &&
      query.includes("capability_id =")
    ) {
      return state.rows
        .filter((row) => row.owner_ref === values[0] && row.capability_id === values[1])
        .map((row) => ({ consume_request_id: row.consume_request_id }));
    }
    if (query.startsWith("INSERT INTO accounts.capability_use_consumptions")) {
      state.rows.push({
        owner_ref: String(values[0]),
        consume_request_id: String(values[1]),
        request_digest: String(values[2]),
        capability_id: String(values[3]),
        idempotency_key_digest: String(values[4]),
        receipt_jcs_base64url: String(values[5]),
        committed_at: String(values[6]),
      });
      return [];
    }
    throw new Error(`unexpected fake query: ${query}`);
  }) as unknown as PostgresTransaction;
  transaction.unsafe = (() => ({
    simple: async () => [],
  })) as unknown as PostgresTransaction["unsafe"];
  return {
    begin: async (
      mode: string,
      callback: (value: PostgresTransaction) => Promise<unknown>,
    ) => {
      state.modes.push(mode);
      return callback(transaction);
    },
  } as PostgresSqlClient;
}

function request(
  overrides: Partial<OnlineGenerationReceiptUseCasRequest> = {},
): OnlineGenerationReceiptUseCasRequest {
  return {
    schema_version: "accounts.capability-use-consume-request.v1",
    schema_digest: "sha256:c248ce62b2acb9bb75f9bc88dfc272b05a9cd627f7e6ac19829bad9ea36de249",
    consume_request_id: IDS.consumeRequest,
    capability_id: IDS.capability,
    capability_digest: D0,
    nonce: "nonce-a",
    subject: SUBJECT,
    actor_principal: OWNER,
    effect_namespace_id: "effect-a",
    account_lane_id: IDS.accountLane,
    capacity_pool_id: IDS.capacityPool,
    capacity_domain_ref: "capacity-a",
    serialization_key_digest: D1,
    credential_family_id: "credential-family-a",
    resource_lease_id: IDS.resourceLease,
    resource_id: "resource-a",
    resource_lifecycle_generation: "1",
    operation_id: IDS.operation,
    operation_digest: D2,
    operation_execution_epoch: "1",
    sender_key_thumbprint: D3,
    channel_binding_digest: D4,
    canonical_request_digest: D5,
    provider_destination_policy_digest: D0,
    online_receipt_id: IDS.onlineReceipt,
    online_receipt_digest: D1,
    model_call_anchor_digest: D2,
    expected_use_count: "0",
    max_uses: "1",
    not_after: "2030-07-18T12:05:00.000Z",
    idempotency_key_digest: D3,
    ...overrides,
  };
}

describe("Postgres native capability-use store", () => {
  test("commits ordinal one once and replays the exact stored bytes after restart", async () => {
    const state: FakeState = { rows: [], modes: [], locks: [] };
    const keys = generateKeyPairSync("ed25519");
    let currentChecks = 0;
    const options = {
      client: fakeClient(state),
      principalRef: OWNER,
      runtimeRole: { mode: "direct", roleName: "accounts_runtime" } as const,
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-capability-use-key-a",
      audience: "infinity-self-hosted",
      privateKey: keys.privateKey,
      clock: () => NOW,
      idFactory: () => IDS.consumeReceipt,
      validateCurrent: () => {
        currentChecks += 1;
        return {
          catalogIncarnation: "catalog-a",
          recoveryFrontierSequence: "1" as const,
          recoveryFrontierHash: D4,
        };
      },
    };
    const first = new PostgresNativeCapabilityUseStore(options);
    const consumed = await first.compareAndConsume(request());
    expect(consumed.status).toBe("consumed");
    expect(state.rows).toHaveLength(1);

    const restarted = new PostgresNativeCapabilityUseStore({
      ...options,
      client: fakeClient(state),
    });
    const replayed = await restarted.compareAndConsume(request());
    expect(replayed.status).toBe("replayed");
    if (consumed.status === "consumed" && replayed.status === "replayed") {
      expect(replayed.signedReceipt).toEqual(consumed.signedReceipt);
    }
    expect(currentChecks).toBe(1);
    expect(state.rows).toHaveLength(1);
    expect(state.modes.every((mode) => mode === "isolation level serializable read write")).toBe(true);
    expect(state.locks).toContain(
      `accounts.capability-use.owner:${OWNER}:capability:${IDS.capability}`,
    );
    expect(state.locks).toContain(
      `accounts.capability-use.owner:${OWNER}:idempotency:${D3}`,
    );
    expect(state.locks).toContain(
      `accounts.capability-use.owner:${OWNER}:request:${IDS.consumeRequest}`,
    );
  });

  test("rejects changed idempotent bytes and exhausts a capability under a new request", async () => {
    const state: FakeState = { rows: [], modes: [], locks: [] };
    const keys = generateKeyPairSync("ed25519");
    const store = new PostgresNativeCapabilityUseStore({
      client: fakeClient(state),
      principalRef: OWNER,
      runtimeRole: { mode: "direct", roleName: "accounts_runtime" },
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-capability-use-key-a",
      audience: "infinity-self-hosted",
      privateKey: keys.privateKey,
      clock: () => NOW,
      idFactory: () => IDS.consumeReceipt,
      validateCurrent: () => ({
        catalogIncarnation: "catalog-a",
        recoveryFrontierSequence: "1",
        recoveryFrontierHash: D4,
      }),
    });
    expect((await store.compareAndConsume(request())).status).toBe("consumed");
    expect((await store.compareAndConsume(request({ nonce: "nonce-b" }))).status)
      .toBe("idempotency_conflict");
    expect((await store.compareAndConsume(request({
      consume_request_id: IDS.consumeRequest2,
      capability_id: IDS.capability2,
    }))).status).toBe("idempotency_conflict");
    expect((await store.compareAndConsume(request({
      consume_request_id: IDS.consumeRequest2,
      idempotency_key_digest: D5,
    }))).status).toBe("exhausted");
    expect(state.rows).toHaveLength(1);
  });

  test("rejects credential-shaped arbitrary DTO values before signing or persistence", async () => {
    const state: FakeState = { rows: [], modes: [], locks: [] };
    const keys = generateKeyPairSync("ed25519");
    const store = new PostgresNativeCapabilityUseStore({
      client: fakeClient(state),
      principalRef: OWNER,
      runtimeRole: { mode: "direct", roleName: "accounts_runtime" },
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-capability-use-key-a",
      audience: "infinity-self-hosted",
      privateKey: keys.privateKey,
      clock: () => NOW,
      idFactory: () => IDS.consumeReceipt,
      validateCurrent: () => ({
        catalogIncarnation: "catalog-a",
        recoveryFrontierSequence: "1",
        recoveryFrontierHash: D4,
      }),
    });
    await expect(store.compareAndConsume(request({
      resource_id: "sk-" + "A".repeat(24),
    }))).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    expect(state.rows).toEqual([]);
  });
});
