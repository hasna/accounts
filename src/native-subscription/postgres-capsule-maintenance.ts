import { AccountsError } from "./errors.js";
import type {
  CapsuleMaintenanceConsumeResult,
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceLedger,
  CapsuleMaintenanceReserveResult,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import { assertNoSensitiveFields, parseClosedJsonBytes } from "./json.js";
import {
  installPostgresRuntimeContext,
  type PostgresRuntimeRoleBoundary,
} from "./postgres-runtime.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

interface GrantRow {
  readonly grant_id: string;
  readonly owner_ref: string;
  readonly idempotency_key_digest: string;
  readonly request_digest: string;
  readonly reservation_key_digest: string;
  readonly grant_digest: string;
  readonly grant_jcs_base64url: string;
  readonly expires_at: string;
  readonly expired: boolean;
  readonly state: "live" | "consumed" | "expired";
}

interface UseRow {
  readonly grant_id: string;
  readonly owner_ref: string;
  readonly idempotency_key_digest: string;
  readonly request_digest: string;
  readonly maintenance_use_id: string;
  readonly consume_receipt_digest: string;
  readonly consume_receipt_jcs_base64url: string;
}

const PRINCIPAL = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * Durable self-hosted maintenance ledger. Reservation and consume are each a
 * single SERIALIZABLE transaction under the same forced-RLS runtime role as
 * the Accounts repository. Exact replay bytes are read back from Postgres;
 * they are never regenerated or re-signed.
 */
export class PostgresCapsuleMaintenanceLedger implements CapsuleMaintenanceLedger {
  constructor(
    private readonly client: PostgresSqlClient,
    private readonly principalRef: string,
    private readonly runtimeRole: PostgresRuntimeRoleBoundary,
  ) {
    if (!PRINCIPAL.test(principalRef)) {
      throw new AccountsError("VALIDATION_FAILED", "Postgres maintenance principal is invalid", {
        details: { field: "principalRef" },
      });
    }
  }

  reserve(input: CapsuleMaintenanceGrantReservation): Promise<CapsuleMaintenanceReserveResult> {
    this.assertOwnedInput(input.ownerRef);
    assertNoSensitiveFields(input);
    assertNoSensitiveFields(parseClosedJsonBytes(input.grantBytes));
    return this.serializable(async (transaction) => {
      await lockSorted(transaction, [
        maintenanceLockKey(input.ownerRef, "grant", input.grantId),
        maintenanceLockKey(input.ownerRef, "idempotency", input.idempotencyKeyDigest),
        maintenanceLockKey(input.ownerRef, "reservation", input.reservationKeyDigest),
      ]);
      await transaction`
        UPDATE accounts.capsule_maintenance_grants
        SET state = 'expired', terminal_at = transaction_timestamp()
        WHERE owner_ref = ${input.ownerRef}
          AND state = 'live'
          AND expires_at <= transaction_timestamp()
      `;
      const [idempotent] = await transaction<GrantRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          reservation_key_digest, grant_digest, grant_jcs_base64url,
          to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
          expires_at <= transaction_timestamp() AS expired,
          state
        FROM accounts.capsule_maintenance_grants
        WHERE owner_ref = ${input.ownerRef}
          AND idempotency_key_digest = ${input.idempotencyKeyDigest}
        FOR UPDATE
      `;
      if (idempotent !== undefined) {
        return idempotent.request_digest === input.requestDigest && idempotent.owner_ref === input.ownerRef
          ? {
              status: "replayed",
              grantBytes: decodeCanonicalBase64(idempotent.grant_jcs_base64url),
            }
          : { status: "idempotency_conflict" };
      }
      const [reserved] = await transaction<Array<{ readonly grant_id: string }>>`
        SELECT grant_id::text
        FROM accounts.capsule_maintenance_grants
        WHERE owner_ref = ${input.ownerRef}
          AND reservation_key_digest = ${input.reservationKeyDigest}
          AND state = 'live'
        FOR UPDATE
      `;
      if (reserved !== undefined) return { status: "reservation_conflict" };
      const bytes = Buffer.from(input.grantBytes).toString("base64url");
      await transaction`
        INSERT INTO accounts.capsule_maintenance_grants (
          grant_id, owner_ref, idempotency_key_digest, request_digest,
          reservation_key_digest, grant_digest, grant_jcs_base64url,
          expires_at, state, created_at
        ) VALUES (
          ${input.grantId}::uuid, ${input.ownerRef}, ${input.idempotencyKeyDigest},
          ${input.requestDigest}, ${input.reservationKeyDigest}, ${input.grantDigest},
          ${bytes}, ${input.expiresAt}::timestamptz, 'live', transaction_timestamp()
        )
      `;
      return { status: "reserved", grantBytes: Uint8Array.from(input.grantBytes) };
    }, "reserve", () => this.recoverReserveConflict(input));
  }

  consume(input: CapsuleMaintenanceUseCommit): Promise<CapsuleMaintenanceConsumeResult> {
    this.assertOwnedInput(input.ownerRef);
    assertNoSensitiveFields(input);
    assertNoSensitiveFields(parseClosedJsonBytes(input.consumeReceiptBytes));
    return this.serializable(async (transaction) => {
      await lockSorted(transaction, [
        maintenanceLockKey(input.ownerRef, "grant", input.grantId),
        maintenanceLockKey(input.ownerRef, "idempotency", input.idempotencyKeyDigest),
        maintenanceLockKey(input.ownerRef, "use", input.maintenanceUseId),
      ]);
      const [idempotent] = await transaction<UseRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          maintenance_use_id, consume_receipt_digest, consume_receipt_jcs_base64url
        FROM accounts.capsule_maintenance_uses
        WHERE owner_ref = ${input.ownerRef}
          AND idempotency_key_digest = ${input.idempotencyKeyDigest}
      `;
      if (idempotent !== undefined) {
        return idempotent.request_digest === input.requestDigest &&
          idempotent.grant_id === input.grantId &&
          idempotent.owner_ref === input.ownerRef
          ? {
              status: "replayed",
              consumeReceiptBytes: decodeCanonicalBase64(idempotent.consume_receipt_jcs_base64url),
            }
          : { status: "idempotency_conflict" };
      }
      const [grant] = await transaction<GrantRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          reservation_key_digest, grant_digest, grant_jcs_base64url,
          to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
          expires_at <= transaction_timestamp() AS expired,
          state
        FROM accounts.capsule_maintenance_grants
        WHERE owner_ref = ${input.ownerRef}
          AND grant_id = ${input.grantId}::uuid
        FOR UPDATE
      `;
      if (grant === undefined || grant.owner_ref !== input.ownerRef) return { status: "not_found" };
      if (grant.state !== "live" || grant.expired) {
        if (grant.state === "live") {
          await transaction`
            UPDATE accounts.capsule_maintenance_grants
            SET state = 'expired', terminal_at = transaction_timestamp()
            WHERE owner_ref = ${input.ownerRef}
              AND grant_id = ${input.grantId}::uuid
              AND state = 'live'
          `;
        }
        return { status: "exhausted" };
      }
      const [alreadyConsumed] = await transaction<Array<{ readonly grant_id: string }>>`
        SELECT grant_id::text
        FROM accounts.capsule_maintenance_uses
        WHERE owner_ref = ${input.ownerRef}
          AND grant_id = ${input.grantId}::uuid
      `;
      if (alreadyConsumed !== undefined) return { status: "exhausted" };
      const receiptBytes = Buffer.from(input.consumeReceiptBytes).toString("base64url");
      await transaction`
        INSERT INTO accounts.capsule_maintenance_uses (
          grant_id, owner_ref, idempotency_key_digest, request_digest,
          maintenance_use_id, consume_receipt_digest, consume_receipt_jcs_base64url,
          committed_at
        ) VALUES (
          ${input.grantId}::uuid, ${input.ownerRef}, ${input.idempotencyKeyDigest},
          ${input.requestDigest}, ${input.maintenanceUseId}, ${input.consumeReceiptDigest},
          ${receiptBytes}, ${input.committedAt}::timestamptz
        )
      `;
      await transaction`
        UPDATE accounts.capsule_maintenance_grants
        SET state = 'consumed', terminal_at = ${input.committedAt}::timestamptz
        WHERE owner_ref = ${input.ownerRef}
          AND grant_id = ${input.grantId}::uuid
          AND state = 'live'
      `;
      return {
        status: "consumed",
        consumeReceiptBytes: Uint8Array.from(input.consumeReceiptBytes),
      };
    }, "consume", () => this.recoverConsumeConflict(input));
  }

  private async serializable<T>(
    work: (transaction: PostgresTransaction) => Promise<T>,
    operation: "reserve" | "consume",
    recoverUniqueConflict: () => Promise<T>,
  ): Promise<T> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.client.begin(
          "isolation level serializable read write",
          async (transaction) => {
            await installPostgresRuntimeContext(transaction, {
              principalRef: this.principalRef,
              role: this.runtimeRole,
            });
            return work(transaction);
          },
        );
      } catch (error) {
        if (error instanceof AccountsError) throw error;
        const code = postgresCode(error);
        if ((code === "40001" || code === "40P01") && attempt < 2) continue;
        if (code === "23505") return recoverUniqueConflict();
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres maintenance transaction failed", {
          retryable: code === "40001" || code === "40P01",
          details: { adapter: "postgres", operation },
        });
      }
    }
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres maintenance transaction retried", {
      retryable: true,
      details: { adapter: "postgres", operation },
    });
  }

  private async recoverReserveConflict(
    input: CapsuleMaintenanceGrantReservation,
  ): Promise<CapsuleMaintenanceReserveResult> {
    return this.readWithContext(async (transaction) => {
      const [idempotent] = await transaction<GrantRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          reservation_key_digest, grant_digest, grant_jcs_base64url,
          to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
          expires_at <= transaction_timestamp() AS expired,
          state
        FROM accounts.capsule_maintenance_grants
        WHERE owner_ref = ${input.ownerRef}
          AND idempotency_key_digest = ${input.idempotencyKeyDigest}
      `;
      if (idempotent !== undefined) {
        return idempotent.request_digest === input.requestDigest
          ? {
              status: "replayed",
              grantBytes: decodeCanonicalBase64(idempotent.grant_jcs_base64url),
            }
          : { status: "idempotency_conflict" };
      }
      return { status: "reservation_conflict" };
    });
  }

  private async recoverConsumeConflict(
    input: CapsuleMaintenanceUseCommit,
  ): Promise<CapsuleMaintenanceConsumeResult> {
    return this.readWithContext(async (transaction) => {
      const [idempotent] = await transaction<UseRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          maintenance_use_id, consume_receipt_digest, consume_receipt_jcs_base64url
        FROM accounts.capsule_maintenance_uses
        WHERE owner_ref = ${input.ownerRef}
          AND idempotency_key_digest = ${input.idempotencyKeyDigest}
      `;
      if (idempotent !== undefined) {
        return idempotent.request_digest === input.requestDigest &&
          idempotent.grant_id === input.grantId
          ? {
              status: "replayed",
              consumeReceiptBytes: decodeCanonicalBase64(
                idempotent.consume_receipt_jcs_base64url,
              ),
            }
          : { status: "idempotency_conflict" };
      }
      return { status: "exhausted" };
    });
  }

  private readWithContext<T>(
    work: (transaction: PostgresTransaction) => Promise<T>,
  ): Promise<T> {
    return this.client.begin("read only", async (transaction) => {
      await installPostgresRuntimeContext(transaction, {
        principalRef: this.principalRef,
        role: this.runtimeRole,
      });
      return work(transaction);
    });
  }

  private assertOwnedInput(ownerRef: string): void {
    if (ownerRef !== this.principalRef) {
      throw new AccountsError("FORBIDDEN", "Postgres maintenance owner does not match context");
    }
  }
}

function postgresCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object") return undefined;
  for (const field of ["sqlState", "errno", "code"] as const) {
    const value = Reflect.get(error, field);
    if (typeof value === "string" && /^[0-9A-Z]{5}$/.test(value)) return value;
  }
  return undefined;
}

function decodeCanonicalBase64(value: string): Uint8Array {
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (bytes.byteLength === 0 || Buffer.from(bytes).toString("base64url") !== value) {
    throw new AccountsError("RECOVERY_HOLD", "Stored maintenance evidence is invalid");
  }
  return bytes;
}

function maintenanceLockKey(
  ownerRef: string,
  namespace: "grant" | "idempotency" | "reservation" | "use",
  value: string,
): string {
  return `accounts.maintenance.owner:${ownerRef}:${namespace}:${value}`;
}

async function lockSorted(
  transaction: PostgresTransaction,
  keys: readonly string[],
): Promise<void> {
  for (const key of [...new Set(keys)].sort()) {
    await transaction`
      SELECT pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(${key}, 0)
      )
    `;
  }
}
