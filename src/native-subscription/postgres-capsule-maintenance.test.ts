import { describe, expect, test } from "bun:test";

import type {
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import {
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
  maintenanceTargetDigest,
} from "./capsule-maintenance.js";
import { canonicalJson, canonicalSha256 } from "./json.js";
import { PostgresCapsuleMaintenanceLedger } from "./postgres-capsule-maintenance.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

const OWNER = "principal:service:hasna:accounts-maintenance";
const GRANT_ID = "018f0f00-0001-7000-8000-000000000001";
const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;
const MAINTENANCE_OPERATION_ID = "018f0f00-0002-7000-8000-000000000002";
const PROVIDER_ACCOUNT_ID = "018f0f00-0003-7000-8000-000000000003";
const ACCOUNT_LANE_ID = "018f0f00-0004-7000-8000-000000000004";
const CAPACITY_POOL_ID = "018f0f00-0005-7000-8000-000000000005";
const AUTH_CAPSULE_ID = "018f0f00-0006-7000-8000-000000000006";
const CANONICAL_NODE_ID = "018f0f00-0007-7000-8000-000000000007";
const CONSUME_RECEIPT_ID = "018f0f00-0008-7000-8000-000000000008";
const SIGNATURE = Buffer.alloc(64, 7).toString("base64url");

interface FakeGrant {
  grant_id: string;
  owner_ref: string;
  idempotency_key_digest: string;
  request_digest: string;
  reservation_key_digest: string;
  grant_digest: string;
  grant_jcs_base64url: string;
  expires_at: string;
  state: "live" | "consumed" | "expired";
}

interface FakeUse {
  grant_id: string;
  owner_ref: string;
  idempotency_key_digest: string;
  request_digest: string;
  maintenance_use_id: string;
  consume_receipt_digest: string;
  consume_receipt_jcs_base64url: string;
}

interface FakeState {
  readonly grants: FakeGrant[];
  readonly uses: FakeUse[];
  readonly modes: string[];
}

function fakeClient(state: FakeState): PostgresSqlClient {
  const transaction = (async (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<unknown[]> => {
    const query = strings.join("?").replace(/\s+/g, " ").trim();
    if (query.includes("set_config('accounts.principal'")) return [];
    if (query.includes("pg_advisory_xact_lock")) return [];
    if (query.includes("accounts.current_principal() AS principal")) {
      return [{
        principal: OWNER,
        realm: "hasna",
        role_name: "accounts_runtime",
        login_role_name: "accounts_runtime",
      }];
    }
    if (query.startsWith("UPDATE accounts.capsule_maintenance_grants") && query.includes("expires_at <=")) {
      return [];
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("idempotency_key_digest =")) {
      return state.grants.filter(
        (row) => row.owner_ref === values[0] && row.idempotency_key_digest === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("reservation_key_digest =")) {
      return state.grants
        .filter(
          (row) =>
            row.owner_ref === values[0] &&
            row.reservation_key_digest === values[1] &&
            row.state === "live",
        )
        .map((row) => ({ grant_id: row.grant_id }));
    }
    if (query.startsWith("INSERT INTO accounts.capsule_maintenance_grants")) {
      state.grants.push({
        grant_id: String(values[0]), owner_ref: String(values[1]),
        idempotency_key_digest: String(values[2]), request_digest: String(values[3]),
        reservation_key_digest: String(values[4]), grant_digest: String(values[5]),
        grant_jcs_base64url: String(values[6]), expires_at: String(values[7]), state: "live",
      });
      return [];
    }
    if (query.includes("FROM accounts.capsule_maintenance_uses") && query.includes("idempotency_key_digest =")) {
      return state.uses.filter(
        (row) => row.owner_ref === values[0] && row.idempotency_key_digest === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("grant_id =")) {
      return state.grants.filter(
        (row) => row.owner_ref === values[0] && row.grant_id === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_uses") && query.includes("grant_id =")) {
      return state.uses
        .filter((row) => row.owner_ref === values[0] && row.grant_id === values[1])
        .map((row) => ({ grant_id: row.grant_id }));
    }
    if (query.startsWith("INSERT INTO accounts.capsule_maintenance_uses")) {
      state.uses.push({
        grant_id: String(values[0]), owner_ref: String(values[1]),
        idempotency_key_digest: String(values[2]), request_digest: String(values[3]),
        maintenance_use_id: String(values[4]), consume_receipt_digest: String(values[5]),
        consume_receipt_jcs_base64url: String(values[6]),
      });
      return [];
    }
    if (query.startsWith("UPDATE accounts.capsule_maintenance_grants") && query.includes("state = 'consumed'")) {
      const grant = state.grants.find(
        (row) => row.owner_ref === values[1] && row.grant_id === values[2],
      );
      if (grant !== undefined) grant.state = "consumed";
      return [];
    }
    throw new Error(`unexpected fake query: ${query}`);
  }) as unknown as PostgresTransaction;
  transaction.unsafe = (() => ({
    simple: async () => [],
  })) as unknown as PostgresTransaction["unsafe"];
  return {
    begin: async (mode: string, callback: (value: PostgresTransaction) => Promise<unknown>) => {
      state.modes.push(mode);
      return callback(transaction);
    },
  } as PostgresSqlClient;
}

function grant(overrides: Partial<CapsuleMaintenanceGrantReservation> = {}): CapsuleMaintenanceGrantReservation {
  const evidence = {
    schema_version: CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
    schema_digest: CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
    grant_id: GRANT_ID,
    issuer: "accounts-maintenance",
    issuer_incarnation: "accounts-maintenance-1",
    key_id: "accounts-maintenance-key-1",
    audience: "infinity",
    effect_namespace_id: "accounts-native-subscription",
    maintenance_authority_epoch: "1",
    maintenance_operation_id: MAINTENANCE_OPERATION_ID,
    operation_digest: D0,
    operation_execution_epoch: "1",
    operation_execution_expires_at: "2030-07-18T12:05:00.000Z",
    execution_fence_digest: D1,
    action: "PROBE_NATIVE",
    effect_class: "read_only",
    target_kind: "native_capsule",
    subject: OWNER,
    actor_principal: OWNER,
    maintenance_executor_principal: OWNER,
    sender_key_thumbprint: D2,
    channel_binding_digest: D3,
    owner_ref: OWNER,
    provider_account_id: PROVIDER_ACCOUNT_ID,
    provider_subject_ref: "provider-subject",
    account_lane_id: ACCOUNT_LANE_ID,
    capacity_pool_id: CAPACITY_POOL_ID,
    capacity_domain_ref: "capacity-domain",
    serialization_key_digest: D4,
    access_transport: "native_session",
    credential_family_id: "credential-family",
    capacity_generation: "1",
    deny_generation: "0",
    expected_record_revision: "1",
    expected_credential_generation: "1",
    maintenance_decision_digest: D0,
    canonical_request_digest: D1,
    approval_mode: "NOT_REQUIRED",
    policy_digest: D2,
    catalog_incarnation: "catalog-1",
    recovery_frontier_sequence: "1",
    recovery_frontier_hash: D3,
    issued_at: "2030-07-18T12:00:00.000Z",
    not_before: "2030-07-18T12:00:00.000Z",
    expires_at: "2030-07-18T12:01:00.000Z",
    nonce: "nonce-1",
    max_uses: "1",
    signature: SIGNATURE,
    auth_capsule_id: AUTH_CAPSULE_ID,
    canonical_node_id: CANONICAL_NODE_ID,
    node_key_thumbprint: D4,
    node_generation: "1",
    placement_generation: "1",
    expected_auth_generation: "1",
    expected_auth_state_revision: "1",
  };
  const grantBytes = Uint8Array.from(Buffer.from(canonicalJson(evidence), "utf8"));
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D0,
    requestDigest: D1,
    reservationKeyDigest: canonicalSha256({
      effect_namespace_id: evidence.effect_namespace_id,
      execution_fence_digest: evidence.execution_fence_digest,
      expected_credential_generation: evidence.expected_credential_generation,
      expected_record_revision: evidence.expected_record_revision,
      schema_version: "accounts.capsule-maintenance-reservation-key.v1",
      serialization_key_digest: evidence.serialization_key_digest,
      target_digest: maintenanceTargetDigest(evidence),
    }),
    grantDigest: canonicalSha256(evidence),
    grantBytes,
    expiresAt: "2030-07-18T12:01:00.000Z",
    ...overrides,
  };
}

function use(overrides: Partial<CapsuleMaintenanceUseCommit> = {}): CapsuleMaintenanceUseCommit {
  const grantDigest = grant().grantDigest;
  const evidence = {
    schema_version: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
    schema_digest: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    consume_receipt_id: CONSUME_RECEIPT_ID,
    grant_id: GRANT_ID,
    grant_digest: grantDigest,
    issuer: "accounts-maintenance",
    issuer_incarnation: "accounts-maintenance-1",
    key_id: "accounts-maintenance-key-1",
    audience: "infinity",
    effect_namespace_id: "accounts-native-subscription",
    maintenance_authority_epoch: "1",
    maintenance_operation_id: MAINTENANCE_OPERATION_ID,
    operation_digest: D0,
    operation_step_id: "probe_native",
    operation_execution_epoch: "1",
    operation_execution_expires_at: "2030-07-18T12:05:00.000Z",
    action: "PROBE_NATIVE",
    target_digest: D1,
    subject: OWNER,
    actor_principal: OWNER,
    maintenance_executor_principal: OWNER,
    sender_key_thumbprint: D2,
    channel_binding_digest: D3,
    execution_fence_digest: D4,
    max_uses: "1",
    prior_use_count: "0",
    next_use_count: "1",
    use_ordinal: "1",
    maintenance_use_id: D4,
    committed_at: "2030-07-18T12:00:00.000Z",
    expires_at: "2030-07-18T12:01:00.000Z",
    catalog_incarnation: "catalog-1",
    recovery_frontier_sequence: "1",
    recovery_frontier_hash: D0,
    signature: SIGNATURE,
  };
  const consumeReceiptBytes = Uint8Array.from(
    Buffer.from(canonicalJson(evidence), "utf8"),
  );
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D3,
    requestDigest: D4,
    maintenanceUseId: D4,
    consumeReceiptDigest: canonicalSha256(evidence),
    consumeReceiptBytes,
    committedAt: "2030-07-18T12:00:00.000Z",
    ...overrides,
  };
}

describe("Postgres capsule maintenance ledger", () => {
  test("preserves exact replay across adapter restart and rejects distinct live reservations", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const first = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    const restarted = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    expect(await first.reserve(grant())).toEqual({
      status: "reserved",
      grantBytes: grant().grantBytes,
    });
    expect(await restarted.reserve(grant())).toEqual({
      status: "replayed",
      grantBytes: grant().grantBytes,
    });
    expect((await restarted.reserve(grant({ requestDigest: D4 }))).status)
      .toBe("idempotency_conflict");
    expect((await restarted.reserve(grant({ idempotencyKeyDigest: D4 }))).status)
      .toBe("reservation_conflict");
    expect(state.modes.every((mode) => mode === "isolation level serializable read write")).toBe(true);
  });

  test("commits ordinal-one evidence once and returns exact bytes on replay", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const first = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    const restarted = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    await first.reserve(grant());
    expect(await first.consume(use())).toEqual({
      status: "consumed",
      consumeReceiptBytes: use().consumeReceiptBytes,
    });
    expect(await restarted.consume(use())).toEqual({
      status: "replayed",
      consumeReceiptBytes: use().consumeReceiptBytes,
    });
    expect((await restarted.consume(use({ requestDigest: D0 }))).status)
      .toBe("idempotency_conflict");
    expect((await restarted.consume(use({ idempotencyKeyDigest: D1 }))).status)
      .toBe("exhausted");
    expect(state.uses).toHaveLength(1);
  });

  test("rejects credential-shaped arbitrary values before durable persistence", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    expect(() => ledger.reserve(grant({
      grantBytes: Uint8Array.from(Buffer.from(JSON.stringify({
        grant: "one",
        note: "sk-" + "A".repeat(24),
      }))),
    }))).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(() => ledger.consume(use({
      consumeReceiptBytes: Uint8Array.from(Buffer.from(JSON.stringify({
        receipt: "one",
        metadata: { password: "not-a-real-password" },
      }))),
    }))).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(state.grants).toEqual([]);
    expect(state.uses).toEqual([]);
  });

  test("rejects malformed public DTOs and arbitrary evidence before opening a transaction", async () => {
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const malformedReservations = [
      { ...grant(), unexpected: "accepted-by-structural-typing" },
      grant({ grantId: "not-a-uuid" }),
      grant({ expiresAt: "infinity" }),
      grant({ grantBytes: Uint8Array.from(Buffer.from('{"grant":"arbitrary"}')) }),
    ] as unknown as CapsuleMaintenanceGrantReservation[];
    for (const reservation of malformedReservations) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      expect(() => ledger.reserve(reservation)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
      expect(state.modes).toEqual([]);
      expect(state.grants).toEqual([]);
    }

    const malformedCommits = [
      { ...use(), unexpected: "accepted-by-structural-typing" },
      use({ committedAt: "2030-07-18T12:00:00Z" }),
      use({ consumeReceiptBytes: Uint8Array.from(Buffer.from('{"receipt":"arbitrary"}')) }),
    ] as unknown as CapsuleMaintenanceUseCommit[];
    for (const commit of malformedCommits) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      expect(() => ledger.consume(commit)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
      expect(state.modes).toEqual([]);
      expect(state.uses).toEqual([]);
    }
  });
});
