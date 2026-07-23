import { AccountsError } from "./errors.js";
import type {
  CapsuleMaintenanceConsumeResult,
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceLedger,
  CapsuleMaintenanceReserveResult,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import {
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
  maintenanceTargetDigest,
} from "./capsule-maintenance.js";
import { parseCounter } from "./counter.js";
import { isUuidV7 } from "./ids.js";
import {
  assertNoSensitiveFields,
  canonicalJson,
  canonicalSha256,
  parseClosedJsonBytes,
} from "./json.js";
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
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RESERVATION_FIELDS = Object.freeze([
  "grantId",
  "ownerRef",
  "idempotencyKeyDigest",
  "requestDigest",
  "reservationKeyDigest",
  "grantDigest",
  "grantBytes",
  "expiresAt",
] as const);
const USE_COMMIT_FIELDS = Object.freeze([
  "grantId",
  "ownerRef",
  "idempotencyKeyDigest",
  "requestDigest",
  "maintenanceUseId",
  "consumeReceiptDigest",
  "consumeReceiptBytes",
  "committedAt",
] as const);
const ACTION_TARGET_KIND = Object.freeze({
  BOOTSTRAP_NATIVE: "native_capsule",
  CLEANUP_CREDENTIAL: "account_record",
  PROBE_NATIVE: "native_capsule",
  REAUTHENTICATE_NATIVE: "native_capsule",
  REFRESH_NATIVE: "native_capsule",
  REVOKE_BROKERED: "account_record",
  REVOKE_PROVIDER_SESSION: "native_capsule",
  ROTATE_BROKERED: "account_record",
} as const);
const ACTION_STEP = Object.freeze({
  BOOTSTRAP_NATIVE: "bootstrap_native",
  CLEANUP_CREDENTIAL: "cleanup_credential",
  PROBE_NATIVE: "probe_native",
  REAUTHENTICATE_NATIVE: "reauthenticate_native",
  REFRESH_NATIVE: "refresh_native",
  REVOKE_BROKERED: "revoke_brokered",
  REVOKE_PROVIDER_SESSION: "revoke_provider_session",
  ROTATE_BROKERED: "rotate_brokered",
} as const);

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
    validateGrantReservation(input);
    this.assertOwnedInput(input.ownerRef);
    assertNoSensitiveFields(input);
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
    const receipt = validateUseCommit(input);
    this.assertOwnedInput(input.ownerRef);
    assertNoSensitiveFields(input);
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
      if (receipt.grant_digest !== grant.grant_digest) {
        throw new AccountsError("VALIDATION_FAILED", "Maintenance receipt grant digest mismatch");
      }
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

type JsonRecord = Record<string, unknown>;

function validateGrantReservation(
  input: CapsuleMaintenanceGrantReservation,
): JsonRecord {
  assertExactDto(input, RESERVATION_FIELDS);
  assertUuid(input.grantId, "grantId");
  assertPrincipal(input.ownerRef, "ownerRef");
  for (const field of [
    "idempotencyKeyDigest",
    "requestDigest",
    "reservationKeyDigest",
    "grantDigest",
  ] as const) {
    assertDigest(input[field], field);
  }
  const expiresAt = assertTimestamp(input.expiresAt, "expiresAt");
  const grant = parseCanonicalEvidence(input.grantBytes, "grantBytes");
  const action = String(grant.action);
  const effectClass = String(grant.effect_class);
  const targetKind = String(grant.target_kind);
  const approvalMode = String(grant.approval_mode);
  const allowedEffects = Reflect.get(
    CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.action_effect_classes,
    action,
  );
  if (
    !Array.isArray(allowedEffects) ||
    !allowedEffects.includes(effectClass) ||
    (targetKind !== "native_capsule" && targetKind !== "account_record") ||
    (approvalMode !== "NOT_REQUIRED" && approvalMode !== "REQUIRED") ||
    Reflect.get(ACTION_TARGET_KIND, action) !== targetKind ||
    (targetKind === "native_capsule" && grant.access_transport !== "native_session") ||
    (targetKind === "account_record" && grant.access_transport === "native_session")
  ) {
    throw validationFailed("grantBytes");
  }
  const expectedFields = [
    ...CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.common_fields,
    ...(targetKind === "native_capsule"
      ? CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.native_capsule
      : CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.account_record),
    ...(approvalMode === "REQUIRED" ? ["approval_ref", "approval_digest"] : []),
    ...(effectClass === "read_only"
      ? []
      : CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.mutation_only_fields),
    ...(effectClass === "containment_mutation"
      ? CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.containment_only_fields
      : []),
  ];
  assertExactRecord(grant, expectedFields, "grantBytes");
  assertStringRecord(grant, "grantBytes");
  if (
    grant.schema_version !== CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION ||
    grant.schema_digest !== CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST ||
    grant.max_uses !== "1"
  ) {
    throw validationFailed("grantBytes");
  }
  validateEnvelopeScalars(grant, [
    "grant_id",
    "maintenance_operation_id",
    "provider_account_id",
    "account_lane_id",
    "capacity_pool_id",
    ...(targetKind === "native_capsule"
      ? ["auth_capsule_id", "canonical_node_id"]
      : ["credential_binding_id"]),
  ]);
  for (const field of [
    "owner_ref",
    "subject",
    "actor_principal",
    "maintenance_executor_principal",
  ]) {
    assertPrincipal(grant[field], field);
  }
  for (const field of [
    "issuer",
    "issuer_incarnation",
    "key_id",
    "audience",
    "effect_namespace_id",
    "provider_subject_ref",
    "capacity_domain_ref",
    "credential_family_id",
    "catalog_incarnation",
    "nonce",
    ...(approvalMode === "REQUIRED" ? ["approval_ref"] : []),
  ]) {
    assertReference(grant[field], field);
  }
  for (const field of [
    "maintenance_authority_epoch",
    "operation_execution_epoch",
  ]) {
    assertPositiveCounter(grant[field], field);
  }
  if (
    grant.grant_id !== input.grantId ||
    grant.owner_ref !== input.ownerRef ||
    grant.expires_at !== expiresAt ||
    canonicalSha256(grant) !== input.grantDigest ||
    canonicalSha256({
      effect_namespace_id: grant.effect_namespace_id,
      execution_fence_digest: grant.execution_fence_digest,
      expected_credential_generation: grant.expected_credential_generation,
      expected_record_revision: grant.expected_record_revision,
      schema_version: "accounts.capsule-maintenance-reservation-key.v1",
      serialization_key_digest: grant.serialization_key_digest,
      target_digest: maintenanceTargetDigest(grant),
    }) !== input.reservationKeyDigest
  ) {
    throw validationFailed("grantBytes");
  }
  return grant;
}

function validateUseCommit(input: CapsuleMaintenanceUseCommit): JsonRecord {
  assertExactDto(input, USE_COMMIT_FIELDS);
  assertUuid(input.grantId, "grantId");
  assertPrincipal(input.ownerRef, "ownerRef");
  for (const field of [
    "idempotencyKeyDigest",
    "requestDigest",
    "maintenanceUseId",
    "consumeReceiptDigest",
  ] as const) {
    assertDigest(input[field], field);
  }
  const committedAt = assertTimestamp(input.committedAt, "committedAt");
  const receipt = parseCanonicalEvidence(
    input.consumeReceiptBytes,
    "consumeReceiptBytes",
  );
  const action = String(receipt.action);
  const mutation = (
    CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR.mutation_actions as readonly string[]
  ).includes(action);
  if (
    !(CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.actions as readonly string[])
      .includes(action)
  ) {
    throw validationFailed("consumeReceiptBytes");
  }
  const expectedFields = [
    ...CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR.common_fields,
    ...(mutation
      ? CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR.mutation_only_fields
      : []),
  ];
  assertExactRecord(receipt, expectedFields, "consumeReceiptBytes");
  assertStringRecord(receipt, "consumeReceiptBytes");
  if (
    receipt.schema_version !== CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION ||
    receipt.schema_digest !== CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST ||
    receipt.max_uses !== "1" ||
    receipt.prior_use_count !== "0" ||
    receipt.next_use_count !== "1" ||
    receipt.use_ordinal !== "1" ||
    Reflect.get(ACTION_STEP, action) !== receipt.operation_step_id
  ) {
    throw validationFailed("consumeReceiptBytes");
  }
  validateEnvelopeScalars(receipt, [
    "consume_receipt_id",
    "grant_id",
    "maintenance_operation_id",
  ]);
  for (const field of [
    "subject",
    "actor_principal",
    "maintenance_executor_principal",
  ]) {
    assertPrincipal(receipt[field], field);
  }
  for (const field of [
    "issuer",
    "issuer_incarnation",
    "key_id",
    "audience",
    "effect_namespace_id",
    "catalog_incarnation",
  ]) {
    assertReference(receipt[field], field);
  }
  for (const field of [
    "maintenance_authority_epoch",
    "operation_execution_epoch",
  ]) {
    assertPositiveCounter(receipt[field], field);
  }
  if (
    receipt.grant_id !== input.grantId ||
    receipt.maintenance_use_id !== input.maintenanceUseId ||
    receipt.committed_at !== committedAt ||
    canonicalSha256(receipt) !== input.consumeReceiptDigest
  ) {
    throw validationFailed("consumeReceiptBytes");
  }
  return receipt;
}

function parseCanonicalEvidence(bytes: Uint8Array, field: string): JsonRecord {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    throw validationFailed(field);
  }
  const parsed = parseClosedJsonBytes(bytes);
  assertNoSensitiveFields(parsed);
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !Buffer.from(bytes).equals(Buffer.from(canonicalJson(parsed), "utf8"))
  ) {
    throw validationFailed(field);
  }
  return parsed as JsonRecord;
}

function validateEnvelopeScalars(
  value: JsonRecord,
  identifierFields: readonly string[],
): void {
  for (const field of identifierFields) assertUuid(value[field], field);
  for (const [field, candidate] of Object.entries(value)) {
    if (
      field.endsWith("_digest") ||
      field.endsWith("_hash") ||
      field.endsWith("_thumbprint")
    ) {
      assertDigest(candidate, field);
    } else if (
      field.endsWith("_epoch") ||
      field.endsWith("_generation") ||
      field.endsWith("_revision") ||
      field.endsWith("_sequence")
    ) {
      try {
        parseCounter(candidate, field);
      } catch {
        throw validationFailed(field);
      }
    } else if (
      field.endsWith("_at") ||
      field.endsWith("_expires_at") ||
      field === "not_before"
    ) {
      assertTimestamp(candidate, field);
    }
  }
  const signature = value.signature;
  if (typeof signature !== "string" || !BASE64URL.test(signature)) {
    throw validationFailed("signature");
  }
  const decoded = Buffer.from(signature, "base64url");
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== signature) {
    throw validationFailed("signature");
  }
}

function assertExactDto(
  value: unknown,
  expectedFields: readonly string[],
): asserts value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null) ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw validationFailed("input");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const fields = Object.keys(descriptors);
  if (
    fields.length !== expectedFields.length ||
    fields.some((field) => !expectedFields.includes(field)) ||
    expectedFields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw validationFailed("input");
  }
  for (const field of fields) {
    const descriptor = descriptors[field]!;
    if (
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw validationFailed(field);
    }
  }
}

function assertExactRecord(
  value: JsonRecord,
  expectedFields: readonly string[],
  field: string,
): void {
  const fields = Object.keys(value);
  if (
    fields.length !== expectedFields.length ||
    fields.some((candidate) => !expectedFields.includes(candidate)) ||
    expectedFields.some((candidate) => !Object.hasOwn(value, candidate))
  ) {
    throw validationFailed(field);
  }
}

function assertStringRecord(value: JsonRecord, field: string): void {
  if (Object.values(value).some((candidate) => typeof candidate !== "string")) {
    throw validationFailed(field);
  }
}

function assertUuid(value: unknown, field: string): string {
  if (typeof value !== "string" || !isUuidV7(value)) {
    throw validationFailed(field);
  }
  return value;
}

function assertDigest(value: unknown, field: string): string {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw validationFailed(field);
  }
  return value;
}

function assertPrincipal(value: unknown, field: string): string {
  if (typeof value !== "string" || !PRINCIPAL.test(value)) {
    throw validationFailed(field);
  }
  return value;
}

function assertReference(value: unknown, field: string): string {
  if (typeof value !== "string" || !REFERENCE.test(value)) {
    throw validationFailed(field);
  }
  return value;
}

function assertPositiveCounter(value: unknown, field: string): void {
  try {
    if (parseCounter(value, field) === "0") throw validationFailed(field);
  } catch {
    throw validationFailed(field);
  }
}

function assertTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string") throw validationFailed(field);
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw validationFailed(field);
  }
  return value;
}

function validationFailed(field: string): AccountsError {
  return new AccountsError(
    "VALIDATION_FAILED",
    "Postgres maintenance ledger input is invalid",
    { details: { field } },
  );
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
