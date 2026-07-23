import type { KeyLike } from "node:crypto";

import { AccountsError } from "./errors.js";
import { canonicalSha256 } from "./json.js";
import {
  issueNativeCapabilityUseReceipt,
  parseNativeCapabilityUseRequest,
  validateNativeCapabilityUseCurrentState,
  type NativeCapabilityUseCurrentState,
} from "./native-subscription.js";
import type {
  OnlineGenerationReceiptUseCasRequest,
  OnlineGenerationReceiptUseCasResult,
  OnlineGenerationReceiptUseStore,
} from "./online-generation-receipt.js";
import {
  installPostgresRuntimeContext,
  type PostgresRuntimeRoleBoundary,
} from "./postgres-runtime.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

interface CapabilityUseRow {
  readonly consume_request_id: string;
  readonly request_digest: string;
  readonly capability_id: string;
  readonly idempotency_key_digest: string;
  readonly receipt_jcs_base64url: string;
}

export interface PostgresNativeCapabilityUseStoreOptions {
  readonly client: PostgresSqlClient;
  readonly principalRef: string;
  readonly runtimeRole: PostgresRuntimeRoleBoundary;
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly privateKey: KeyLike;
  readonly clock?: () => Date;
  readonly idFactory?: (nowMs: number) => string;
  readonly validateCurrent: (
    request: OnlineGenerationReceiptUseCasRequest,
    transaction: PostgresTransaction,
  ) => NativeCapabilityUseCurrentState | Promise<NativeCapabilityUseCurrentState>;
}

const PRINCIPAL =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/**
 * Durable Accounts-owned ordinal-one CAS. Each request and capability is
 * serialized by transaction-scoped advisory locks, then protected by unique
 * database constraints. Exact replay returns the originally stored receipt
 * bytes; receipts are never regenerated after commit.
 */
export class PostgresNativeCapabilityUseStore
  implements OnlineGenerationReceiptUseStore {
  private readonly clock: () => Date;

  constructor(private readonly options: PostgresNativeCapabilityUseStoreOptions) {
    if (!PRINCIPAL.test(options.principalRef)) {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Postgres capability-use principal is invalid",
        { details: { field: "principalRef" } },
      );
    }
    this.clock = options.clock ?? (() => new Date());
  }

  async compareAndConsume(
    source: OnlineGenerationReceiptUseCasRequest,
  ): Promise<OnlineGenerationReceiptUseCasResult> {
    const request = parseNativeCapabilityUseRequest(source);
    const requestDigest = canonicalSha256(request);
    return this.serializable(async (transaction) => {
      const lockKeys = [
        capabilityLockKey(this.options.principalRef, "capability", request.capability_id),
        capabilityLockKey(
          this.options.principalRef,
          "idempotency",
          request.idempotency_key_digest,
        ),
        capabilityLockKey(this.options.principalRef, "request", request.consume_request_id),
      ].sort();
      for (const lockKey of lockKeys) {
        await transaction`
          SELECT pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(${lockKey}, 0)
          )
        `;
      }

      const [prior] = await transaction<CapabilityUseRow[]>`
        SELECT
          consume_request_id::text, request_digest, capability_id::text,
          idempotency_key_digest, receipt_jcs_base64url
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND consume_request_id = ${request.consume_request_id}::uuid
      `;
      if (prior !== undefined) {
        return prior.request_digest === requestDigest
          ? {
              status: "replayed",
              signedReceipt: decodeCanonicalBase64(prior.receipt_jcs_base64url),
            }
          : { status: "idempotency_conflict" };
      }

      const [idempotent] = await transaction<CapabilityUseRow[]>`
        SELECT
          consume_request_id::text, request_digest, capability_id::text,
          idempotency_key_digest, receipt_jcs_base64url
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND idempotency_key_digest = ${request.idempotency_key_digest}
      `;
      if (idempotent !== undefined) return { status: "idempotency_conflict" };

      const [consumed] = await transaction<Array<{ readonly consume_request_id: string }>>`
        SELECT consume_request_id::text
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND capability_id = ${request.capability_id}::uuid
      `;
      if (consumed !== undefined) return { status: "exhausted" };

      const now = this.clock();
      if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capability-use clock failed");
      }
      if (Date.parse(request.not_after) <= now.getTime()) return { status: "conflict" };

      const current = validateNativeCapabilityUseCurrentState(
        await this.options.validateCurrent(request, transaction),
      );
      const signedReceipt = issueNativeCapabilityUseReceipt(
        request,
        current,
        this.options,
        now,
        this.options.idFactory,
      );
      const encodedReceipt = Buffer.from(signedReceipt).toString("base64url");
      await transaction`
        INSERT INTO accounts.capability_use_consumptions (
          owner_ref, consume_request_id, request_digest, capability_id,
          idempotency_key_digest, receipt_jcs_base64url, committed_at
        ) VALUES (
          ${this.options.principalRef}, ${request.consume_request_id}::uuid,
          ${requestDigest}, ${request.capability_id}::uuid,
          ${request.idempotency_key_digest}, ${encodedReceipt},
          ${now.toISOString()}::timestamptz
        )
      `;
      return { status: "consumed", signedReceipt: Uint8Array.from(signedReceipt) };
    }, () => this.recoverUniqueConflict(request, requestDigest));
  }

  private async serializable<T>(
    work: (transaction: PostgresTransaction) => Promise<T>,
    recoverUniqueConflict: () => Promise<T>,
  ): Promise<T> {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await this.options.client.begin(
          "isolation level serializable read write",
          async (transaction) => {
            await installPostgresRuntimeContext(transaction, {
              principalRef: this.options.principalRef,
              role: this.options.runtimeRole,
            });
            return work(transaction);
          },
        );
      } catch (error) {
        if (error instanceof AccountsError) throw error;
        const code = postgresCode(error);
        if ((code === "40001" || code === "40P01") && attempt < 2) continue;
        if (code === "23505") return recoverUniqueConflict();
        throw new AccountsError(
          "DEPENDENCY_UNAVAILABLE",
          "Postgres capability-use transaction failed",
          {
            retryable: code === "40001" || code === "40P01",
            details: { adapter: "postgres", operation: "capability_use" },
          },
        );
      }
    }
    throw new AccountsError(
      "DEPENDENCY_UNAVAILABLE",
      "Postgres capability-use transaction retried",
      {
        retryable: true,
        details: { adapter: "postgres", operation: "capability_use" },
      },
    );
  }

  private recoverUniqueConflict(
    request: OnlineGenerationReceiptUseCasRequest,
    requestDigest: string,
  ): Promise<OnlineGenerationReceiptUseCasResult> {
    return this.options.client.begin("read only", async (transaction) => {
      await installPostgresRuntimeContext(transaction, {
        principalRef: this.options.principalRef,
        role: this.options.runtimeRole,
      });
      const [prior] = await transaction<CapabilityUseRow[]>`
        SELECT
          consume_request_id::text, request_digest, capability_id::text,
          idempotency_key_digest, receipt_jcs_base64url
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND consume_request_id = ${request.consume_request_id}::uuid
      `;
      if (prior !== undefined) {
        return prior.request_digest === requestDigest
          ? {
              status: "replayed",
              signedReceipt: decodeCanonicalBase64(prior.receipt_jcs_base64url),
            }
          : { status: "idempotency_conflict" };
      }
      const [idempotent] = await transaction<CapabilityUseRow[]>`
        SELECT
          consume_request_id::text, request_digest, capability_id::text,
          idempotency_key_digest, receipt_jcs_base64url
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND idempotency_key_digest = ${request.idempotency_key_digest}
      `;
      if (idempotent !== undefined) return { status: "idempotency_conflict" };
      const [consumed] = await transaction<Array<{ readonly consume_request_id: string }>>`
        SELECT consume_request_id::text
        FROM accounts.capability_use_consumptions
        WHERE owner_ref = ${this.options.principalRef}
          AND capability_id = ${request.capability_id}::uuid
      `;
      return consumed === undefined ? { status: "conflict" } : { status: "exhausted" };
    });
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
    throw new AccountsError(
      "RECOVERY_HOLD",
      "Stored capability-use evidence is invalid",
    );
  }
  return bytes;
}

function capabilityLockKey(
  ownerRef: string,
  namespace: "capability" | "idempotency" | "request",
  value: string,
): string {
  return `accounts.capability-use.owner:${ownerRef}:${namespace}:${value}`;
}
