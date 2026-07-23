import { describe, expect, test } from "bun:test";

import type {
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import { PostgresCapsuleMaintenanceLedger } from "./postgres-capsule-maintenance.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

const OWNER = "principal:service:hasna:accounts-maintenance";
const GRANT_ID = "018f0f00-0001-7000-8000-000000000001";
const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;

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
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D0,
    requestDigest: D1,
    reservationKeyDigest: D2,
    grantDigest: D3,
    grantBytes: Uint8Array.from(Buffer.from('{"grant":"one"}', "utf8")),
    expiresAt: "2030-07-18T12:01:00.000Z",
    ...overrides,
  };
}

function use(overrides: Partial<CapsuleMaintenanceUseCommit> = {}): CapsuleMaintenanceUseCommit {
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D3,
    requestDigest: D4,
    maintenanceUseId: D4,
    consumeReceiptDigest: D2,
    consumeReceiptBytes: Uint8Array.from(Buffer.from('{"receipt":"one"}', "utf8")),
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
});
