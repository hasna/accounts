import type { SQL, TransactionSQL } from "bun";

import { AccountsError } from "./errors";
import type {
  CapsuleMaintenanceConsumeResult,
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceLedger,
  CapsuleMaintenanceReserveResult,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance";

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
    private readonly client: SQL,
    private readonly principalRef: string,
  ) {
    if (!PRINCIPAL.test(principalRef)) {
      throw new AccountsError("VALIDATION_FAILED", "Postgres maintenance principal is invalid", {
        details: { field: "principalRef" },
      });
    }
  }

  reserve(input: CapsuleMaintenanceGrantReservation): Promise<CapsuleMaintenanceReserveResult> {
    return this.serializable(async (transaction) => {
      await transaction`
        UPDATE accounts.capsule_maintenance_grants
        SET state = 'expired', terminal_at = transaction_timestamp()
        WHERE state = 'live' AND expires_at <= transaction_timestamp()
      `;
      const [idempotent] = await transaction<GrantRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          reservation_key_digest, grant_digest, grant_jcs_base64url,
          to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
          expires_at <= transaction_timestamp() AS expired,
          state
        FROM accounts.capsule_maintenance_grants
        WHERE idempotency_key_digest = ${input.idempotencyKeyDigest}
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
        WHERE reservation_key_digest = ${input.reservationKeyDigest}
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
    }, "reserve");
  }

  consume(input: CapsuleMaintenanceUseCommit): Promise<CapsuleMaintenanceConsumeResult> {
    return this.serializable(async (transaction) => {
      const [idempotent] = await transaction<UseRow[]>`
        SELECT
          grant_id::text, owner_ref, idempotency_key_digest, request_digest,
          maintenance_use_id, consume_receipt_digest, consume_receipt_jcs_base64url
        FROM accounts.capsule_maintenance_uses
        WHERE idempotency_key_digest = ${input.idempotencyKeyDigest}
        FOR UPDATE
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
        WHERE grant_id = ${input.grantId}::uuid
        FOR UPDATE
      `;
      if (grant === undefined || grant.owner_ref !== input.ownerRef) return { status: "not_found" };
      if (grant.state !== "live" || grant.expired) {
        if (grant.state === "live") {
          await transaction`
            UPDATE accounts.capsule_maintenance_grants
            SET state = 'expired', terminal_at = transaction_timestamp()
            WHERE grant_id = ${input.grantId}::uuid AND state = 'live'
          `;
        }
        return { status: "exhausted" };
      }
      const [alreadyConsumed] = await transaction<Array<{ readonly grant_id: string }>>`
        SELECT grant_id::text
        FROM accounts.capsule_maintenance_uses
        WHERE grant_id = ${input.grantId}::uuid
        FOR UPDATE
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
        WHERE grant_id = ${input.grantId}::uuid AND state = 'live'
      `;
      return {
        status: "consumed",
        consumeReceiptBytes: Uint8Array.from(input.consumeReceiptBytes),
      };
    }, "consume");
  }

  private async serializable<T>(
    work: (transaction: TransactionSQL) => Promise<T>,
    operation: "reserve" | "consume",
  ): Promise<T> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.client.begin(
          "isolation level serializable read write",
          async (transaction) => {
            await transaction.unsafe(
              "SET LOCAL ROLE accounts_runtime; SET LOCAL search_path = pg_catalog, accounts; SET LOCAL row_security = on",
            ).simple();
            await transaction`
              SELECT
                set_config('accounts.principal', ${this.principalRef}, true),
                set_config('accounts.identity_realm', 'hasna', true)
            `;
            const [context] = await transaction<Array<{
              readonly principal: string | null;
              readonly realm: string | null;
              readonly role_name: string;
            }>>`
              SELECT
                accounts.current_principal() AS principal,
                accounts.current_identity_realm() AS realm,
                current_user AS role_name
            `;
            if (
              context?.principal !== this.principalRef ||
              context.realm !== "hasna" ||
              context.role_name !== "accounts_runtime"
            ) throw new AccountsError("FORBIDDEN", "Postgres maintenance context was not installed");
            return work(transaction);
          },
        );
      } catch (error) {
        if (error instanceof AccountsError) throw error;
        const code = postgresCode(error);
        if ((code === "40001" || code === "40P01") && attempt < 2) continue;
        if (code === "23505") {
          return (operation === "reserve"
            ? { status: "reservation_conflict" }
            : { status: "exhausted" }) as T;
        }
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
}

function postgresCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object") return undefined;
  const code = Reflect.get(error, "code");
  return typeof code === "string" ? code : undefined;
}

function decodeCanonicalBase64(value: string): Uint8Array {
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (bytes.byteLength === 0 || Buffer.from(bytes).toString("base64url") !== value) {
    throw new AccountsError("RECOVERY_HOLD", "Stored maintenance evidence is invalid");
  }
  return bytes;
}
