import {
  createHash,
  createPublicKey,
  sign as signSignature,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";

import { incrementCounter, parseCounter, type Counter } from "../domain/counter";
import { AccountsError } from "../errors";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import {
  OwnerOnlySignedAppendLog,
  type SignedLogFrontier,
  type SignedLogRecord,
  type SignedLogSnapshot,
} from "./file-recovery-ledger";

const CLAIM_LOG_KIND = "accounts-effect-claims" as const;
const PREPARED_LOG_KIND = "accounts-effect-prepared" as const;
const EFFECT_LOG_KIND = "accounts-effect-dispatch" as const;
const CLAIM_SCHEMA = "accounts.credential-effect-claim.v1" as const;
const PREPARED_SCHEMA = "accounts.credential-effect-prepared.v1" as const;
const DISPATCHED_SCHEMA = "accounts.credential-effect-dispatched.v1" as const;
const OUTCOME_SCHEMA = "infinity.effect-journal-outcome/v1" as const;
const OUTCOME_SCHEMA_DIGEST =
  "sha256:7ab380a0475ebf79d2ed925e20bcbb9303d78a56c358d09adbdce796e740bf20" as const;
const LOOKUP_SCHEMA = "accounts.provider-effect-lookup.v1" as const;
const SEMANTIC_KEY_SCHEMA = "accounts.credential-effect-semantic-key.v1" as const;
const PROVIDER_TOKEN_SCHEMA = "accounts.provider-idempotency.v1" as const;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const UUID_V7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$/;
const STEP_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const MAXIMUM_EVIDENCE_AGE_MS = 60_000;
const MAXIMUM_CLOCK_SKEW_MS = 5_000;

export type EffectOutcomeKind =
  | "succeeded"
  | "failed_effect"
  | "failed_no_effect"
  | "reconciliation_blocked";

export interface EffectClaimRecord {
  readonly schema_version: typeof CLAIM_SCHEMA;
  readonly record_kind: "CLAIMED";
  readonly semantic_operation_key_digest: string;
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly credential_family_id: string;
  readonly serialization_key_digest: string;
  readonly request_digest: string;
  readonly source_fences_digest: string;
  readonly claimed_at: string;
}

export interface EffectPreparedRecord {
  readonly schema_version: typeof PREPARED_SCHEMA;
  readonly record_kind: "PREPARED";
  readonly semantic_operation_key_digest: string;
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_execution_epoch: Counter;
  readonly credential_family_id: string;
  readonly serialization_key_digest: string;
  readonly operation_digest: string;
  readonly request_digest: string;
  readonly target_digest: string;
  readonly source_fences_digest: string;
  readonly maintenance_fence_digest: string;
  readonly maintenance_grant_digest: string;
  readonly effect_endpoint_ref: string;
  readonly provider_key: string;
  readonly prepared_at: string;
  readonly prior_failed_no_effect_receipt_digest?: string;
}

interface EffectDispatchedCommon {
  readonly schema_version: typeof DISPATCHED_SCHEMA;
  readonly record_kind: "DISPATCHED";
  readonly outcome_schema_version: typeof OUTCOME_SCHEMA;
  readonly outcome_schema_digest: typeof OUTCOME_SCHEMA_DIGEST;
  readonly semantic_operation_key_digest: string;
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_digest: string;
  readonly request_digest: string;
  readonly target_digest: string;
  readonly source_fences_digest: string;
  readonly maintenance_fence_digest: string;
  readonly maintenance_grant_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly provider_key: string;
  readonly effect_endpoint_ref: string;
  readonly provider_idempotency_token_sha256: string;
  readonly prepared_receipt_digest: string;
  readonly audience: string;
  readonly dispatched_at: string;
  readonly signer_ref: string;
  readonly signer_incarnation: string;
  readonly key_id: string;
}

export interface EffectDispatchedRecord extends EffectDispatchedCommon {
  readonly signature: string;
}

export type UnsignedEffectDispatchedRecord = EffectDispatchedCommon;

interface EffectOutcomeCommon {
  readonly schema_version: typeof OUTCOME_SCHEMA;
  readonly schema_digest: typeof OUTCOME_SCHEMA_DIGEST;
  readonly record_kind: "OUTCOME";
  readonly semantic_operation_key_digest: string;
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_digest: string;
  readonly request_digest: string;
  readonly target_digest: string;
  readonly source_fences_digest: string;
  readonly maintenance_grant_digest: string;
  readonly maintenance_fence_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly dispatched_receipt_digest: string;
  readonly provider_idempotency_token_sha256: string;
  readonly effect_endpoint_ref: string;
  readonly effect_endpoint_incarnation: string;
  readonly effect_endpoint_key_id: string;
  readonly audience: string;
  readonly observed_at: string;
}

export interface EffectSucceededOutcome extends EffectOutcomeCommon {
  readonly outcome_kind: "succeeded";
  readonly provider_result_receipt_digest: string;
  readonly endpoint_signature: string;
}

export interface EffectFailedEffectOutcome extends EffectOutcomeCommon {
  readonly outcome_kind: "failed_effect";
  readonly provider_failure_receipt_digest: string;
  readonly endpoint_signature: string;
}

export interface EffectFailedNoEffectOutcome extends EffectOutcomeCommon {
  readonly outcome_kind: "failed_no_effect";
  readonly provider_lookup_evidence_digest: string;
  readonly endpoint_signature: string;
}

export interface EffectReconciliationBlockedOutcome extends EffectOutcomeCommon {
  readonly outcome_kind: "reconciliation_blocked";
  readonly reconciliation_evidence_digest: string;
  readonly endpoint_signature: string;
}

export type EffectOutcomeRecord =
  | EffectSucceededOutcome
  | EffectFailedEffectOutcome
  | EffectFailedNoEffectOutcome
  | EffectReconciliationBlockedOutcome;

export type UnsignedEffectOutcomeRecord =
  | Omit<EffectSucceededOutcome, "endpoint_signature">
  | Omit<EffectFailedEffectOutcome, "endpoint_signature">
  | Omit<EffectFailedNoEffectOutcome, "endpoint_signature">
  | Omit<EffectReconciliationBlockedOutcome, "endpoint_signature">;

export type EffectDispatchRecord = EffectDispatchedRecord | EffectOutcomeRecord;

interface ProviderLookupEvidenceCommon {
  readonly schema_version: typeof LOOKUP_SCHEMA;
  readonly provider_key: string;
  readonly provider_lookup_issuer_ref: string;
  readonly provider_lookup_issuer_incarnation: string;
  readonly provider_lookup_key_id: string;
  readonly audience: string;
  readonly effect_endpoint_ref: string;
  readonly provider_idempotency_token_sha256: string;
  readonly semantic_operation_key_digest: string;
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_digest: string;
  readonly request_digest: string;
  readonly target_digest: string;
  readonly source_fences_digest: string;
  readonly maintenance_fence_digest: string;
  readonly maintenance_grant_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly lookup_result: "rejected_not_accepted_no_state_change";
  readonly provider_observation_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export interface ProviderLookupEvidence extends ProviderLookupEvidenceCommon {
  readonly provider_signature: string;
}

export type UnsignedProviderLookupEvidence = ProviderLookupEvidenceCommon;

export interface EffectPrepareInput {
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_execution_epoch: Counter;
  readonly credential_family_id: string;
  readonly serialization_key_digest: string;
  readonly operation_digest: string;
  readonly request_digest: string;
  readonly target_digest: string;
  readonly source_fences_digest: string;
  readonly maintenance_fence_digest: string;
  readonly maintenance_grant_digest: string;
  readonly effect_endpoint_ref: string;
  readonly provider_key: string;
  readonly prior_failed_no_effect_receipt_digest?: string;
}

export interface EffectDispatchInput {
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_execution_epoch: Counter;
  readonly prepared_receipt_digest: string;
}

interface OutcomeSigningCommonInput {
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_execution_epoch: Counter;
  readonly dispatched_receipt_digest: string;
  readonly observed_at: string;
}

export type EffectOutcomeSigningInput =
  | (OutcomeSigningCommonInput & {
      readonly outcome_kind: "succeeded";
      readonly provider_result_receipt_digest: string;
    })
  | (OutcomeSigningCommonInput & {
      readonly outcome_kind: "failed_effect";
      readonly provider_failure_receipt_digest: string;
    })
  | (OutcomeSigningCommonInput & {
      readonly outcome_kind: "failed_no_effect";
      readonly provider_lookup_evidence_digest: string;
    })
  | (OutcomeSigningCommonInput & {
      readonly outcome_kind: "reconciliation_blocked";
      readonly reconciliation_evidence_digest: string;
    });

export interface EffectJournalAppend<T> {
  readonly record: T;
  readonly receipt_digest: string;
  readonly frontier: SignedLogFrontier;
  readonly replayed: boolean;
}

export interface EffectDispatchAppend
  extends EffectJournalAppend<EffectDispatchedRecord> {
  /** The raw token is returned only to the caller that may invoke the endpoint. */
  readonly provider_idempotency_token: string;
  /** True only for the process that durably appended the first DISPATCHED record. */
  readonly newly_appended: boolean;
}

export type EffectDispatchState =
  | {
      readonly phase: "PREPARED";
      readonly operation_execution_epoch: Counter;
      readonly prepared: EffectJournalAppend<EffectPreparedRecord>;
    }
  | {
      readonly phase: "DISPATCHED";
      readonly operation_execution_epoch: Counter;
      readonly prepared: EffectJournalAppend<EffectPreparedRecord>;
      readonly dispatched: EffectJournalAppend<EffectDispatchedRecord>;
    }
  | {
      readonly phase: "OUTCOME";
      readonly operation_execution_epoch: Counter;
      readonly outcome_kind: EffectOutcomeKind;
      readonly prepared: EffectJournalAppend<EffectPreparedRecord>;
      readonly dispatched: EffectJournalAppend<EffectDispatchedRecord>;
      readonly outcome: EffectJournalAppend<EffectOutcomeRecord>;
    };

export interface EffectDispatchSigner {
  readonly signerRef: string;
  readonly signerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly privateKey: KeyObject;
}

export interface EffectEndpointTrust {
  readonly incarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly publicKey: KeyObject;
}

export interface ProviderLookupTrust {
  readonly incarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly publicKey: KeyObject;
}

export interface EffectDispatchJournalOptions {
  readonly path: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
  readonly dispatchSigner: EffectDispatchSigner;
  readonly effectEndpointTrust: ReadonlyMap<string, EffectEndpointTrust>;
  readonly providerLookupTrust: ReadonlyMap<string, ProviderLookupTrust>;
  readonly clock?: () => Date;
}

function invalid(stored: boolean): never {
  throw new AccountsError(
    stored ? "RECOVERY_HOLD" : "VALIDATION_FAILED",
    "Effect journal record is invalid",
  );
}

function recoveryHold(message: string): never {
  throw new AccountsError("RECOVERY_HOLD", message);
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  stored: boolean,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(stored);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid(stored);
  if (Object.getOwnPropertySymbols(value).length !== 0) invalid(stored);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  const allowed = new Set([...required, ...optional]);
  if (
    keys.some((key) => !allowed.has(key)) ||
    required.some((key) => !Object.hasOwn(descriptors, key))
  ) {
    invalid(stored);
  }
  const record = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      invalid(stored);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function ownDataField(value: unknown, key: string, stored: boolean): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid(stored);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid(stored);
  if (Object.getOwnPropertySymbols(value).length !== 0) invalid(stored);
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !("value" in descriptor) ||
    descriptor.get !== undefined ||
    descriptor.set !== undefined
  ) {
    invalid(stored);
  }
  return descriptor.value;
}

function stringField(value: unknown, stored: boolean): string {
  if (typeof value !== "string") invalid(stored);
  return value;
}

function referenceField(value: unknown, pattern: RegExp, stored: boolean): string {
  const reference = stringField(value, stored);
  if (!pattern.test(reference)) invalid(stored);
  return reference;
}

function digestField(value: unknown, stored: boolean): string {
  const digest = stringField(value, stored);
  if (!SHA256_PATTERN.test(digest)) invalid(stored);
  return digest;
}

function epochField(value: unknown, stored: boolean): Counter {
  try {
    const parsed = parseCounter(value, "operation_execution_epoch");
    if (parsed === "0") invalid(stored);
    return parsed;
  } catch {
    return invalid(stored);
  }
}

function timestampField(value: unknown, stored: boolean): string {
  const timestamp = stringField(value, stored);
  try {
    if (new Date(timestamp).toISOString() !== timestamp) invalid(stored);
  } catch {
    invalid(stored);
  }
  return timestamp;
}

function signatureField(value: unknown, stored: boolean): string {
  const signature = stringField(value, stored);
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) invalid(stored);
  const bytes = Buffer.from(signature, "base64url");
  if (bytes.byteLength !== 64 || bytes.toString("base64url") !== signature) invalid(stored);
  return signature;
}

function assertEd25519Key(key: unknown, kind: "private" | "public"): KeyObject {
  if (
    !(key instanceof Object) ||
    !("type" in key) ||
    (key as KeyObject).type !== kind ||
    (key as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new AccountsError("VALIDATION_FAILED", `Effect ${kind} key is invalid`);
  }
  return key as KeyObject;
}

function sha256Ascii(value: string): string {
  return `sha256:${createHash("sha256").update(value, "ascii").digest("hex")}`;
}

function claimSemanticDigest(
  catalogIncarnation: string,
  value: Pick<
    EffectClaimRecord,
    | "credential_family_id"
    | "serialization_key_digest"
    | "operation_step_id"
    | "request_digest"
    | "source_fences_digest"
  >,
): string {
  return canonicalSha256({
    schema_version: SEMANTIC_KEY_SCHEMA,
    catalog_incarnation: catalogIncarnation,
    credential_family_id: value.credential_family_id,
    serialization_key_digest: value.serialization_key_digest,
    operation_step_id: value.operation_step_id,
    request_digest: value.request_digest,
    source_fences_digest: value.source_fences_digest,
  });
}

function validateClaim(value: unknown, stored: boolean): EffectClaimRecord {
  const record = exactRecord(
    value,
    [
      "schema_version",
      "record_kind",
      "semantic_operation_key_digest",
      "operation_id",
      "operation_step_id",
      "credential_family_id",
      "serialization_key_digest",
      "request_digest",
      "source_fences_digest",
      "claimed_at",
    ],
    [],
    stored,
  );
  if (record.schema_version !== CLAIM_SCHEMA || record.record_kind !== "CLAIMED") {
    invalid(stored);
  }
  return Object.freeze({
    schema_version: CLAIM_SCHEMA,
    record_kind: "CLAIMED",
    semantic_operation_key_digest: digestField(
      record.semantic_operation_key_digest,
      stored,
    ),
    operation_id: referenceField(record.operation_id, UUID_V7_PATTERN, stored),
    operation_step_id: referenceField(record.operation_step_id, STEP_PATTERN, stored),
    credential_family_id: referenceField(
      record.credential_family_id,
      SAFE_REF_PATTERN,
      stored,
    ),
    serialization_key_digest: digestField(record.serialization_key_digest, stored),
    request_digest: digestField(record.request_digest, stored),
    source_fences_digest: digestField(record.source_fences_digest, stored),
    claimed_at: timestampField(record.claimed_at, stored),
  });
}

function validatePrepared(value: unknown, stored: boolean): EffectPreparedRecord {
  const record = exactRecord(
    value,
    [
      "schema_version",
      "record_kind",
      "semantic_operation_key_digest",
      "operation_id",
      "operation_step_id",
      "operation_execution_epoch",
      "credential_family_id",
      "serialization_key_digest",
      "operation_digest",
      "request_digest",
      "target_digest",
      "source_fences_digest",
      "maintenance_fence_digest",
      "maintenance_grant_digest",
      "effect_endpoint_ref",
      "provider_key",
      "prepared_at",
    ],
    ["prior_failed_no_effect_receipt_digest"],
    stored,
  );
  if (record.schema_version !== PREPARED_SCHEMA || record.record_kind !== "PREPARED") {
    invalid(stored);
  }
  const prior = Object.hasOwn(record, "prior_failed_no_effect_receipt_digest")
    ? digestField(record.prior_failed_no_effect_receipt_digest, stored)
    : undefined;
  return Object.freeze({
    schema_version: PREPARED_SCHEMA,
    record_kind: "PREPARED",
    semantic_operation_key_digest: digestField(
      record.semantic_operation_key_digest,
      stored,
    ),
    operation_id: referenceField(record.operation_id, UUID_V7_PATTERN, stored),
    operation_step_id: referenceField(record.operation_step_id, STEP_PATTERN, stored),
    operation_execution_epoch: epochField(record.operation_execution_epoch, stored),
    credential_family_id: referenceField(
      record.credential_family_id,
      SAFE_REF_PATTERN,
      stored,
    ),
    serialization_key_digest: digestField(record.serialization_key_digest, stored),
    operation_digest: digestField(record.operation_digest, stored),
    request_digest: digestField(record.request_digest, stored),
    target_digest: digestField(record.target_digest, stored),
    source_fences_digest: digestField(record.source_fences_digest, stored),
    maintenance_fence_digest: digestField(record.maintenance_fence_digest, stored),
    maintenance_grant_digest: digestField(record.maintenance_grant_digest, stored),
    effect_endpoint_ref: referenceField(
      record.effect_endpoint_ref,
      SAFE_REF_PATTERN,
      stored,
    ),
    provider_key: referenceField(record.provider_key, SAFE_REF_PATTERN, stored),
    prepared_at: timestampField(record.prepared_at, stored),
    ...(prior === undefined ? {} : { prior_failed_no_effect_receipt_digest: prior }),
  });
}

const DISPATCHED_COMMON_KEYS = [
  "schema_version",
  "record_kind",
  "outcome_schema_version",
  "outcome_schema_digest",
  "semantic_operation_key_digest",
  "operation_id",
  "operation_step_id",
  "operation_digest",
  "request_digest",
  "target_digest",
  "source_fences_digest",
  "maintenance_fence_digest",
  "maintenance_grant_digest",
  "operation_execution_epoch",
  "provider_key",
  "effect_endpoint_ref",
  "provider_idempotency_token_sha256",
  "prepared_receipt_digest",
  "audience",
  "dispatched_at",
  "signer_ref",
  "signer_incarnation",
  "key_id",
] as const;

function validateDispatchedStructure(
  value: unknown,
  stored: boolean,
  requireSignature: boolean,
): EffectDispatchedRecord | UnsignedEffectDispatchedRecord {
  const record = exactRecord(
    value,
    [...DISPATCHED_COMMON_KEYS, ...(requireSignature ? ["signature"] : [])],
    [],
    stored,
  );
  if (
    record.schema_version !== DISPATCHED_SCHEMA ||
    record.record_kind !== "DISPATCHED" ||
    record.outcome_schema_version !== OUTCOME_SCHEMA ||
    record.outcome_schema_digest !== OUTCOME_SCHEMA_DIGEST
  ) {
    invalid(stored);
  }
  const common: UnsignedEffectDispatchedRecord = Object.freeze({
    schema_version: DISPATCHED_SCHEMA,
    record_kind: "DISPATCHED",
    outcome_schema_version: OUTCOME_SCHEMA,
    outcome_schema_digest: OUTCOME_SCHEMA_DIGEST,
    semantic_operation_key_digest: digestField(
      record.semantic_operation_key_digest,
      stored,
    ),
    operation_id: referenceField(record.operation_id, UUID_V7_PATTERN, stored),
    operation_step_id: referenceField(record.operation_step_id, STEP_PATTERN, stored),
    operation_digest: digestField(record.operation_digest, stored),
    request_digest: digestField(record.request_digest, stored),
    target_digest: digestField(record.target_digest, stored),
    source_fences_digest: digestField(record.source_fences_digest, stored),
    maintenance_fence_digest: digestField(record.maintenance_fence_digest, stored),
    maintenance_grant_digest: digestField(record.maintenance_grant_digest, stored),
    operation_execution_epoch: epochField(record.operation_execution_epoch, stored),
    provider_key: referenceField(record.provider_key, SAFE_REF_PATTERN, stored),
    effect_endpoint_ref: referenceField(
      record.effect_endpoint_ref,
      SAFE_REF_PATTERN,
      stored,
    ),
    provider_idempotency_token_sha256: digestField(
      record.provider_idempotency_token_sha256,
      stored,
    ),
    prepared_receipt_digest: digestField(record.prepared_receipt_digest, stored),
    audience: referenceField(record.audience, SAFE_REF_PATTERN, stored),
    dispatched_at: timestampField(record.dispatched_at, stored),
    signer_ref: referenceField(record.signer_ref, SAFE_REF_PATTERN, stored),
    signer_incarnation: referenceField(
      record.signer_incarnation,
      SAFE_REF_PATTERN,
      stored,
    ),
    key_id: referenceField(record.key_id, SAFE_REF_PATTERN, stored),
  });
  if (!requireSignature) return common;
  return Object.freeze({
    ...common,
    signature: signatureField(record.signature, stored),
  });
}

/** Exact RFC 8785 JCS bytes signed by the Accounts effect sink. */
export function effectDispatchedSigningBytes(
  dispatched: UnsignedEffectDispatchedRecord,
): Uint8Array {
  return Buffer.from(
    canonicalJson(validateDispatchedStructure(dispatched, false, false)),
    "utf8",
  );
}

const OUTCOME_COMMON_KEYS = [
  "schema_version",
  "schema_digest",
  "record_kind",
  "outcome_kind",
  "semantic_operation_key_digest",
  "operation_id",
  "operation_step_id",
  "operation_digest",
  "request_digest",
  "target_digest",
  "source_fences_digest",
  "maintenance_grant_digest",
  "maintenance_fence_digest",
  "operation_execution_epoch",
  "dispatched_receipt_digest",
  "provider_idempotency_token_sha256",
  "effect_endpoint_ref",
  "effect_endpoint_incarnation",
  "effect_endpoint_key_id",
  "audience",
  "observed_at",
] as const;

function outcomeEvidenceKey(kind: unknown, stored: boolean): string {
  switch (kind) {
    case "succeeded":
      return "provider_result_receipt_digest";
    case "failed_effect":
      return "provider_failure_receipt_digest";
    case "failed_no_effect":
      return "provider_lookup_evidence_digest";
    case "reconciliation_blocked":
      return "reconciliation_evidence_digest";
    default:
      return invalid(stored);
  }
}

function validateOutcomeStructure(
  value: unknown,
  stored: boolean,
  requireSignature: boolean,
): EffectOutcomeRecord | UnsignedEffectOutcomeRecord {
  const kind = ownDataField(value, "outcome_kind", stored);
  const evidenceKey = outcomeEvidenceKey(kind, stored);
  const record = exactRecord(
    value,
    [
      ...OUTCOME_COMMON_KEYS,
      evidenceKey,
      ...(requireSignature ? ["endpoint_signature"] : []),
    ],
    [],
    stored,
  );
  if (
    record.schema_version !== OUTCOME_SCHEMA ||
    record.schema_digest !== OUTCOME_SCHEMA_DIGEST ||
    record.record_kind !== "OUTCOME"
  ) {
    invalid(stored);
  }
  const common = {
    schema_version: OUTCOME_SCHEMA,
    schema_digest: OUTCOME_SCHEMA_DIGEST,
    record_kind: "OUTCOME" as const,
    semantic_operation_key_digest: digestField(
      record.semantic_operation_key_digest,
      stored,
    ),
    operation_id: referenceField(record.operation_id, UUID_V7_PATTERN, stored),
    operation_step_id: referenceField(record.operation_step_id, STEP_PATTERN, stored),
    operation_digest: digestField(record.operation_digest, stored),
    request_digest: digestField(record.request_digest, stored),
    target_digest: digestField(record.target_digest, stored),
    source_fences_digest: digestField(record.source_fences_digest, stored),
    maintenance_grant_digest: digestField(record.maintenance_grant_digest, stored),
    maintenance_fence_digest: digestField(record.maintenance_fence_digest, stored),
    operation_execution_epoch: epochField(record.operation_execution_epoch, stored),
    dispatched_receipt_digest: digestField(record.dispatched_receipt_digest, stored),
    provider_idempotency_token_sha256: digestField(
      record.provider_idempotency_token_sha256,
      stored,
    ),
    effect_endpoint_ref: referenceField(
      record.effect_endpoint_ref,
      SAFE_REF_PATTERN,
      stored,
    ),
    effect_endpoint_incarnation: referenceField(
      record.effect_endpoint_incarnation,
      SAFE_REF_PATTERN,
      stored,
    ),
    effect_endpoint_key_id: referenceField(
      record.effect_endpoint_key_id,
      SAFE_REF_PATTERN,
      stored,
    ),
    audience: referenceField(record.audience, SAFE_REF_PATTERN, stored),
    observed_at: timestampField(record.observed_at, stored),
  };
  const endpointSignature = requireSignature
    ? signatureField(record.endpoint_signature, stored)
    : undefined;
  switch (kind) {
    case "succeeded":
      return Object.freeze({
        ...common,
        outcome_kind: kind,
        provider_result_receipt_digest: digestField(
          record.provider_result_receipt_digest,
          stored,
        ),
        ...(endpointSignature === undefined
          ? {}
          : { endpoint_signature: endpointSignature }),
      }) as EffectSucceededOutcome | Omit<EffectSucceededOutcome, "endpoint_signature">;
    case "failed_effect":
      return Object.freeze({
        ...common,
        outcome_kind: kind,
        provider_failure_receipt_digest: digestField(
          record.provider_failure_receipt_digest,
          stored,
        ),
        ...(endpointSignature === undefined
          ? {}
          : { endpoint_signature: endpointSignature }),
      }) as EffectFailedEffectOutcome | Omit<EffectFailedEffectOutcome, "endpoint_signature">;
    case "failed_no_effect":
      return Object.freeze({
        ...common,
        outcome_kind: kind,
        provider_lookup_evidence_digest: digestField(
          record.provider_lookup_evidence_digest,
          stored,
        ),
        ...(endpointSignature === undefined
          ? {}
          : { endpoint_signature: endpointSignature }),
      }) as EffectFailedNoEffectOutcome | Omit<EffectFailedNoEffectOutcome, "endpoint_signature">;
    case "reconciliation_blocked":
      return Object.freeze({
        ...common,
        outcome_kind: kind,
        reconciliation_evidence_digest: digestField(
          record.reconciliation_evidence_digest,
          stored,
        ),
        ...(endpointSignature === undefined
          ? {}
          : { endpoint_signature: endpointSignature }),
      }) as
        | EffectReconciliationBlockedOutcome
        | Omit<EffectReconciliationBlockedOutcome, "endpoint_signature">;
  }
  return invalid(stored);
}

/** Exact RFC 8785 JCS bytes an owning effect endpoint signs. */
export function effectOutcomeSigningBytes(
  outcome: UnsignedEffectOutcomeRecord,
): Uint8Array {
  return Buffer.from(
    canonicalJson(validateOutcomeStructure(outcome, false, false)),
    "utf8",
  );
}

function unsignedOutcome(outcome: EffectOutcomeRecord): UnsignedEffectOutcomeRecord {
  const { endpoint_signature: _signature, ...unsigned } = outcome;
  return unsigned as UnsignedEffectOutcomeRecord;
}

const LOOKUP_COMMON_KEYS = [
  "schema_version",
  "provider_key",
  "provider_lookup_issuer_ref",
  "provider_lookup_issuer_incarnation",
  "provider_lookup_key_id",
  "audience",
  "effect_endpoint_ref",
  "provider_idempotency_token_sha256",
  "semantic_operation_key_digest",
  "operation_id",
  "operation_step_id",
  "operation_digest",
  "request_digest",
  "target_digest",
  "source_fences_digest",
  "maintenance_fence_digest",
  "maintenance_grant_digest",
  "operation_execution_epoch",
  "lookup_result",
  "provider_observation_id",
  "issued_at",
  "expires_at",
] as const;

function validateLookupEvidenceStructure(
  value: unknown,
  stored: boolean,
  requireSignature: boolean,
): ProviderLookupEvidence | UnsignedProviderLookupEvidence {
  const record = exactRecord(
    value,
    [...LOOKUP_COMMON_KEYS, ...(requireSignature ? ["provider_signature"] : [])],
    [],
    stored,
  );
  if (
    record.schema_version !== LOOKUP_SCHEMA ||
    record.lookup_result !== "rejected_not_accepted_no_state_change"
  ) {
    invalid(stored);
  }
  const common: UnsignedProviderLookupEvidence = Object.freeze({
    schema_version: LOOKUP_SCHEMA,
    provider_key: referenceField(record.provider_key, SAFE_REF_PATTERN, stored),
    provider_lookup_issuer_ref: referenceField(
      record.provider_lookup_issuer_ref,
      SAFE_REF_PATTERN,
      stored,
    ),
    provider_lookup_issuer_incarnation: referenceField(
      record.provider_lookup_issuer_incarnation,
      SAFE_REF_PATTERN,
      stored,
    ),
    provider_lookup_key_id: referenceField(
      record.provider_lookup_key_id,
      SAFE_REF_PATTERN,
      stored,
    ),
    audience: referenceField(record.audience, SAFE_REF_PATTERN, stored),
    effect_endpoint_ref: referenceField(
      record.effect_endpoint_ref,
      SAFE_REF_PATTERN,
      stored,
    ),
    provider_idempotency_token_sha256: digestField(
      record.provider_idempotency_token_sha256,
      stored,
    ),
    semantic_operation_key_digest: digestField(
      record.semantic_operation_key_digest,
      stored,
    ),
    operation_id: referenceField(record.operation_id, UUID_V7_PATTERN, stored),
    operation_step_id: referenceField(record.operation_step_id, STEP_PATTERN, stored),
    operation_digest: digestField(record.operation_digest, stored),
    request_digest: digestField(record.request_digest, stored),
    target_digest: digestField(record.target_digest, stored),
    source_fences_digest: digestField(record.source_fences_digest, stored),
    maintenance_fence_digest: digestField(record.maintenance_fence_digest, stored),
    maintenance_grant_digest: digestField(record.maintenance_grant_digest, stored),
    operation_execution_epoch: epochField(record.operation_execution_epoch, stored),
    lookup_result: "rejected_not_accepted_no_state_change",
    provider_observation_id: referenceField(
      record.provider_observation_id,
      SAFE_REF_PATTERN,
      stored,
    ),
    issued_at: timestampField(record.issued_at, stored),
    expires_at: timestampField(record.expires_at, stored),
  });
  if (!requireSignature) return common;
  return Object.freeze({
    ...common,
    provider_signature: signatureField(record.provider_signature, stored),
  });
}

/** Exact RFC 8785 JCS bytes a provider lookup issuer signs. */
export function providerLookupEvidenceSigningBytes(
  evidence: UnsignedProviderLookupEvidence,
): Uint8Array {
  return Buffer.from(
    canonicalJson(validateLookupEvidenceStructure(evidence, false, false)),
    "utf8",
  );
}

function unsignedLookupEvidence(
  evidence: ProviderLookupEvidence,
): UnsignedProviderLookupEvidence {
  const { provider_signature: _signature, ...unsigned } = evidence;
  return unsigned;
}

function journalAppend<T>(
  record: SignedLogRecord<T>,
  replayed: boolean,
): EffectJournalAppend<T> {
  return Object.freeze({
    record: structuredClone(record.payload),
    receipt_digest: record.receiptDigest,
    frontier: Object.freeze({
      catalogIncarnation: record.catalogIncarnation,
      sequence: record.sequence,
      hash: record.hash,
      signatureDigest: record.signatureDigest,
    }),
    replayed,
  });
}

function operationKey(value: {
  readonly operation_id: string;
  readonly operation_step_id: string;
}): string {
  return `${value.operation_id}\u0000${value.operation_step_id}`;
}

function epochKey(value: {
  readonly operation_id: string;
  readonly operation_step_id: string;
  readonly operation_execution_epoch: Counter;
}): string {
  return `${operationKey(value)}\u0000${value.operation_execution_epoch}`;
}

function preparedReplayDigest(record: EffectPreparedRecord): string {
  return canonicalSha256({
    semantic_operation_key_digest: record.semantic_operation_key_digest,
    operation_id: record.operation_id,
    operation_step_id: record.operation_step_id,
    operation_execution_epoch: record.operation_execution_epoch,
    credential_family_id: record.credential_family_id,
    serialization_key_digest: record.serialization_key_digest,
    operation_digest: record.operation_digest,
    request_digest: record.request_digest,
    target_digest: record.target_digest,
    source_fences_digest: record.source_fences_digest,
    maintenance_fence_digest: record.maintenance_fence_digest,
    maintenance_grant_digest: record.maintenance_grant_digest,
    effect_endpoint_ref: record.effect_endpoint_ref,
    provider_key: record.provider_key,
    ...(record.prior_failed_no_effect_receipt_digest === undefined
      ? {}
      : {
          prior_failed_no_effect_receipt_digest:
            record.prior_failed_no_effect_receipt_digest,
        }),
  });
}

function retryIdentityDigest(record: EffectPreparedRecord): string {
  return canonicalSha256({
    semantic_operation_key_digest: record.semantic_operation_key_digest,
    operation_id: record.operation_id,
    operation_step_id: record.operation_step_id,
    credential_family_id: record.credential_family_id,
    serialization_key_digest: record.serialization_key_digest,
    operation_digest: record.operation_digest,
    request_digest: record.request_digest,
    target_digest: record.target_digest,
    source_fences_digest: record.source_fences_digest,
    maintenance_fence_digest: record.maintenance_fence_digest,
    effect_endpoint_ref: record.effect_endpoint_ref,
    provider_key: record.provider_key,
  });
}

interface EpochRecords {
  readonly prepared: SignedLogRecord<EffectPreparedRecord>;
  dispatched?: SignedLogRecord<EffectDispatchRecord>;
  outcome?: SignedLogRecord<EffectDispatchRecord>;
}

interface EffectSnapshots {
  readonly claims: SignedLogSnapshot<EffectClaimRecord>;
  readonly prepared: SignedLogSnapshot<EffectPreparedRecord>;
  readonly effects: SignedLogSnapshot<EffectDispatchRecord>;
}

interface ValidatedDispatchSigner {
  readonly signerRef: string;
  readonly signerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

function validateDispatchSigner(value: EffectDispatchSigner): ValidatedDispatchSigner {
  const record = exactRecord(
    value,
    ["signerRef", "signerIncarnation", "keyId", "audience", "privateKey"],
    [],
    false,
  );
  const privateKey = assertEd25519Key(record.privateKey, "private");
  return Object.freeze({
    signerRef: referenceField(record.signerRef, SAFE_REF_PATTERN, false),
    signerIncarnation: referenceField(
      record.signerIncarnation,
      SAFE_REF_PATTERN,
      false,
    ),
    keyId: referenceField(record.keyId, SAFE_REF_PATTERN, false),
    audience: referenceField(record.audience, SAFE_REF_PATTERN, false),
    privateKey,
    publicKey: createPublicKey(
      privateKey.export({ format: "pem", type: "pkcs8" }),
    ),
  });
}

function validateTrustMap<T extends EffectEndpointTrust | ProviderLookupTrust>(
  value: ReadonlyMap<string, T>,
  expectedAudience: string,
  label: string,
): ReadonlyMap<string, T> {
  if (!(value instanceof Map) || value.size === 0) {
    throw new AccountsError("VALIDATION_FAILED", `${label} trust is required`);
  }
  const result = new Map<string, T>();
  for (const [reference, trust] of value) {
    if (!SAFE_REF_PATTERN.test(reference)) {
      throw new AccountsError("VALIDATION_FAILED", `${label} reference is invalid`);
    }
    const record = exactRecord(
      trust,
      ["incarnation", "keyId", "audience", "publicKey"],
      [],
      false,
    );
    const validated = Object.freeze({
      incarnation: referenceField(record.incarnation, SAFE_REF_PATTERN, false),
      keyId: referenceField(record.keyId, SAFE_REF_PATTERN, false),
      audience: referenceField(record.audience, SAFE_REF_PATTERN, false),
      publicKey: assertEd25519Key(record.publicKey, "public"),
    }) as T;
    if (validated.audience !== expectedAudience) {
      throw new AccountsError("VALIDATION_FAILED", `${label} audience is inconsistent`);
    }
    result.set(reference, validated);
  }
  return result;
}

export class EffectDispatchJournal {
  private readonly claimLog: OwnerOnlySignedAppendLog<EffectClaimRecord>;
  private readonly preparedLog: OwnerOnlySignedAppendLog<EffectPreparedRecord>;
  private readonly effectLog: OwnerOnlySignedAppendLog<EffectDispatchRecord>;
  private readonly catalogIncarnation: string;
  private readonly dispatchSigner: ValidatedDispatchSigner;
  private readonly endpointTrust: ReadonlyMap<string, EffectEndpointTrust>;
  private readonly lookupTrust: ReadonlyMap<string, ProviderLookupTrust>;
  private readonly clock: () => Date;

  constructor(options: EffectDispatchJournalOptions) {
    this.catalogIncarnation = referenceField(
      options.catalogIncarnation,
      SAFE_REF_PATTERN,
      false,
    );
    this.dispatchSigner = validateDispatchSigner(options.dispatchSigner);
    this.endpointTrust = validateTrustMap(
      options.effectEndpointTrust,
      this.dispatchSigner.audience,
      "Effect endpoint",
    );
    this.lookupTrust = validateTrustMap(
      options.providerLookupTrust,
      this.dispatchSigner.audience,
      "Provider lookup",
    );
    this.clock = options.clock ?? (() => new Date());
    this.claimLog = new OwnerOnlySignedAppendLog({
      path: `${options.path}.claims`,
      catalogIncarnation: this.catalogIncarnation,
      signingKey: options.signingKey,
      logKind: CLAIM_LOG_KIND,
      validatePayload: (value) => validateClaim(value, true),
    });
    this.preparedLog = new OwnerOnlySignedAppendLog({
      path: `${options.path}.prepared`,
      catalogIncarnation: this.catalogIncarnation,
      signingKey: options.signingKey,
      logKind: PREPARED_LOG_KIND,
      validatePayload: (value) => validatePrepared(value, true),
    });
    this.effectLog = new OwnerOnlySignedAppendLog({
      path: options.path,
      catalogIncarnation: this.catalogIncarnation,
      signingKey: options.signingKey,
      logKind: EFFECT_LOG_KIND,
      validatePayload: (value) => this.validateStoredEffect(value),
    });
    this.verifiedSnapshots();
  }

  readState(
    operationId: string,
    operationStepId: string,
  ): EffectDispatchState | undefined {
    if (!UUID_V7_PATTERN.test(operationId) || !STEP_PATTERN.test(operationStepId)) {
      throw new AccountsError("VALIDATION_FAILED", "Effect dispatch identity is invalid");
    }
    const epochs = this.operationEpochs(
      this.verifiedSnapshots(),
      operationId,
      operationStepId,
    );
    const latest = epochs.at(-1);
    if (latest === undefined) return undefined;
    const prepared = journalAppend(latest.prepared, false);
    const preparedRecord = latest.prepared.payload;
    if (latest.dispatched === undefined) {
      return Object.freeze({
        phase: "PREPARED",
        operation_execution_epoch: preparedRecord.operation_execution_epoch,
        prepared,
      });
    }
    const dispatched = journalAppend(
      latest.dispatched as SignedLogRecord<EffectDispatchedRecord>,
      false,
    );
    if (latest.outcome === undefined) {
      return Object.freeze({
        phase: "DISPATCHED",
        operation_execution_epoch: preparedRecord.operation_execution_epoch,
        prepared,
        dispatched,
      });
    }
    const outcome = journalAppend(
      latest.outcome as SignedLogRecord<EffectOutcomeRecord>,
      false,
    );
    return Object.freeze({
      phase: "OUTCOME",
      operation_execution_epoch: preparedRecord.operation_execution_epoch,
      outcome_kind: outcome.record.outcome_kind,
      prepared,
      dispatched,
      outcome,
    });
  }

  prepare(input: EffectPrepareInput): EffectJournalAppend<EffectPreparedRecord> {
    const inputRecord = exactRecord(
      input,
      [
        "operation_id",
        "operation_step_id",
        "operation_execution_epoch",
        "credential_family_id",
        "serialization_key_digest",
        "operation_digest",
        "request_digest",
        "target_digest",
        "source_fences_digest",
        "maintenance_fence_digest",
        "maintenance_grant_digest",
        "effect_endpoint_ref",
        "provider_key",
      ],
      ["prior_failed_no_effect_receipt_digest"],
      false,
    );
    const now = this.now();
    const claimWithoutDigest = {
      schema_version: CLAIM_SCHEMA,
      record_kind: "CLAIMED" as const,
      operation_id: referenceField(inputRecord.operation_id, UUID_V7_PATTERN, false),
      operation_step_id: referenceField(
        inputRecord.operation_step_id,
        STEP_PATTERN,
        false,
      ),
      credential_family_id: referenceField(
        inputRecord.credential_family_id,
        SAFE_REF_PATTERN,
        false,
      ),
      serialization_key_digest: digestField(
        inputRecord.serialization_key_digest,
        false,
      ),
      request_digest: digestField(inputRecord.request_digest, false),
      source_fences_digest: digestField(inputRecord.source_fences_digest, false),
      claimed_at: now,
    };
    const claim = validateClaim(
      {
        ...claimWithoutDigest,
        semantic_operation_key_digest: claimSemanticDigest(
          this.catalogIncarnation,
          claimWithoutDigest,
        ),
      },
      false,
    );
    if (!this.endpointTrust.has(referenceField(
      inputRecord.effect_endpoint_ref,
      SAFE_REF_PATTERN,
      false,
    ))) {
      throw new AccountsError("VALIDATION_FAILED", "Effect endpoint is not configured");
    }

    let snapshots = this.verifiedSnapshots();
    const existingClaim = snapshots.claims.records.find(
      (record) =>
        record.payload.semantic_operation_key_digest ===
        claim.semantic_operation_key_digest,
    );
    if (
      existingClaim !== undefined &&
      (existingClaim.payload.operation_id !== claim.operation_id ||
        existingClaim.payload.operation_step_id !== claim.operation_step_id)
    ) {
      recoveryHold("Semantic effect identity is already claimed by another operation");
    }
    if (existingClaim === undefined) {
      this.claimLog.append(snapshots.claims.frontier, claim);
      snapshots = this.verifiedSnapshots();
    }

    const candidate = validatePrepared(
      {
        schema_version: PREPARED_SCHEMA,
        record_kind: "PREPARED",
        semantic_operation_key_digest: claim.semantic_operation_key_digest,
        ...inputRecord,
        prepared_at: now,
      },
      false,
    );
    const epochs = this.operationEpochs(
      snapshots,
      candidate.operation_id,
      candidate.operation_step_id,
    );
    const sameEpoch = epochs.find(
      (epoch) =>
        epoch.prepared.payload.operation_execution_epoch ===
        candidate.operation_execution_epoch,
    );
    if (sameEpoch !== undefined) {
      if (
        preparedReplayDigest(sameEpoch.prepared.payload) !==
        preparedReplayDigest(candidate)
      ) {
        recoveryHold("Prepared effect identity conflicts");
      }
      return journalAppend(sameEpoch.prepared, true);
    }

    const latest = epochs.at(-1);
    if (latest === undefined) {
      if (candidate.prior_failed_no_effect_receipt_digest !== undefined) {
        recoveryHold("Initial effect epoch cannot cite a retry");
      }
    } else {
      const previousPrepared = latest.prepared.payload;
      const previousOutcome = latest.outcome?.payload as EffectOutcomeRecord | undefined;
      let expectedEpoch: Counter;
      try {
        expectedEpoch = incrementCounter(previousPrepared.operation_execution_epoch);
      } catch {
        recoveryHold("Effect retry epoch cannot advance");
      }
      if (
        previousOutcome?.outcome_kind !== "failed_no_effect" ||
        candidate.operation_execution_epoch !== expectedEpoch ||
        candidate.prior_failed_no_effect_receipt_digest !== latest.outcome?.receiptDigest ||
        retryIdentityDigest(candidate) !== retryIdentityDigest(previousPrepared) ||
        candidate.maintenance_grant_digest ===
          previousPrepared.maintenance_grant_digest
      ) {
        recoveryHold("Effect redispatch is not authorized");
      }
    }

    const appended = this.preparedLog.append(snapshots.prepared.frontier, candidate);
    return journalAppend(appended, false);
  }

  dispatch(input: EffectDispatchInput): EffectDispatchAppend {
    const record = exactRecord(
      input,
      [
        "operation_id",
        "operation_step_id",
        "operation_execution_epoch",
        "prepared_receipt_digest",
      ],
      [],
      false,
    );
    const operationId = referenceField(record.operation_id, UUID_V7_PATTERN, false);
    const operationStepId = referenceField(
      record.operation_step_id,
      STEP_PATTERN,
      false,
    );
    const epoch = epochField(record.operation_execution_epoch, false);
    const preparedReceipt = digestField(record.prepared_receipt_digest, false);
    const snapshots = this.verifiedSnapshots();
    const epochRecords = this.operationEpochs(
      snapshots,
      operationId,
      operationStepId,
    ).find(
      (candidate) =>
        candidate.prepared.payload.operation_execution_epoch === epoch,
    );
    if (
      epochRecords === undefined ||
      epochRecords.prepared.receiptDigest !== preparedReceipt
    ) {
      recoveryHold("Prepared effect receipt does not match");
    }
    const prepared = epochRecords.prepared.payload;
    const providerToken = this.providerIdempotencyToken(prepared);
    if (epochRecords.dispatched !== undefined) {
      return Object.freeze({
        ...journalAppend(
          epochRecords.dispatched as SignedLogRecord<EffectDispatchedRecord>,
          true,
        ),
        provider_idempotency_token: providerToken,
        newly_appended: false,
      });
    }
    const unsigned = validateDispatchedStructure(
      {
        schema_version: DISPATCHED_SCHEMA,
        record_kind: "DISPATCHED",
        outcome_schema_version: OUTCOME_SCHEMA,
        outcome_schema_digest: OUTCOME_SCHEMA_DIGEST,
        semantic_operation_key_digest: prepared.semantic_operation_key_digest,
        operation_id: prepared.operation_id,
        operation_step_id: prepared.operation_step_id,
        operation_digest: prepared.operation_digest,
        request_digest: prepared.request_digest,
        target_digest: prepared.target_digest,
        source_fences_digest: prepared.source_fences_digest,
        maintenance_fence_digest: prepared.maintenance_fence_digest,
        maintenance_grant_digest: prepared.maintenance_grant_digest,
        operation_execution_epoch: prepared.operation_execution_epoch,
        provider_key: prepared.provider_key,
        effect_endpoint_ref: prepared.effect_endpoint_ref,
        provider_idempotency_token_sha256: sha256Ascii(providerToken),
        prepared_receipt_digest: preparedReceipt,
        audience: this.dispatchSigner.audience,
        dispatched_at: this.now(),
        signer_ref: this.dispatchSigner.signerRef,
        signer_incarnation: this.dispatchSigner.signerIncarnation,
        key_id: this.dispatchSigner.keyId,
      },
      false,
      false,
    ) as UnsignedEffectDispatchedRecord;
    const candidate = validateDispatchedStructure(
      {
        ...unsigned,
        signature: signSignature(
          null,
          effectDispatchedSigningBytes(unsigned),
          this.dispatchSigner.privateKey,
        ).toString("base64url"),
      },
      false,
      true,
    ) as EffectDispatchedRecord;
    this.verifyDispatchSignature(candidate, false);
    const appended = this.effectLog.append(snapshots.effects.frontier, candidate);
    return Object.freeze({
      ...journalAppend(
        appended as SignedLogRecord<EffectDispatchedRecord>,
        false,
      ),
      provider_idempotency_token: providerToken,
      newly_appended: true,
    });
  }

  outcomeForSigning(input: EffectOutcomeSigningInput): UnsignedEffectOutcomeRecord {
    const kind = ownDataField(input, "outcome_kind", false);
    const evidenceKey = outcomeEvidenceKey(kind, false);
    const record = exactRecord(
      input,
      [
        "operation_id",
        "operation_step_id",
        "operation_execution_epoch",
        "dispatched_receipt_digest",
        "observed_at",
        "outcome_kind",
        evidenceKey,
      ],
      [],
      false,
    );
    const operationId = referenceField(record.operation_id, UUID_V7_PATTERN, false);
    const operationStepId = referenceField(
      record.operation_step_id,
      STEP_PATTERN,
      false,
    );
    const epoch = epochField(record.operation_execution_epoch, false);
    const dispatchedReceipt = digestField(record.dispatched_receipt_digest, false);
    const snapshots = this.verifiedSnapshots();
    const epochRecords = this.operationEpochs(
      snapshots,
      operationId,
      operationStepId,
    ).find(
      (candidate) =>
        candidate.prepared.payload.operation_execution_epoch === epoch,
    );
    if (
      epochRecords?.dispatched === undefined ||
      epochRecords.outcome !== undefined ||
      epochRecords.dispatched.receiptDigest !== dispatchedReceipt
    ) {
      recoveryHold("Effect outcome has no current dispatch");
    }
    const prepared = epochRecords.prepared.payload;
    const dispatched = epochRecords.dispatched.payload as EffectDispatchedRecord;
    const trust = this.endpointTrust.get(prepared.effect_endpoint_ref);
    if (trust === undefined) recoveryHold("Effect endpoint trust is unavailable");
    const candidate = {
      schema_version: OUTCOME_SCHEMA,
      schema_digest: OUTCOME_SCHEMA_DIGEST,
      record_kind: "OUTCOME",
      outcome_kind: kind,
      semantic_operation_key_digest: prepared.semantic_operation_key_digest,
      operation_id: prepared.operation_id,
      operation_step_id: prepared.operation_step_id,
      operation_digest: prepared.operation_digest,
      request_digest: prepared.request_digest,
      target_digest: prepared.target_digest,
      source_fences_digest: prepared.source_fences_digest,
      maintenance_grant_digest: prepared.maintenance_grant_digest,
      maintenance_fence_digest: prepared.maintenance_fence_digest,
      operation_execution_epoch: prepared.operation_execution_epoch,
      dispatched_receipt_digest: dispatchedReceipt,
      provider_idempotency_token_sha256:
        dispatched.provider_idempotency_token_sha256,
      effect_endpoint_ref: prepared.effect_endpoint_ref,
      effect_endpoint_incarnation: trust.incarnation,
      effect_endpoint_key_id: trust.keyId,
      audience: trust.audience,
      observed_at: timestampField(record.observed_at, false),
      [evidenceKey]: digestField(record[evidenceKey], false),
    };
    return validateOutcomeStructure(
      candidate,
      false,
      false,
    ) as UnsignedEffectOutcomeRecord;
  }

  recordOutcome(
    outcome: EffectOutcomeRecord,
    providerLookupEvidence?: ProviderLookupEvidence,
  ): EffectJournalAppend<EffectOutcomeRecord> {
    const validated = validateOutcomeStructure(
      outcome,
      false,
      true,
    ) as EffectOutcomeRecord;
    this.verifyEndpointOutcome(validated, false);
    if (validated.outcome_kind === "failed_no_effect") {
      if (providerLookupEvidence === undefined) {
        throw new AccountsError(
          "VALIDATION_FAILED",
          "failed_no_effect requires provider lookup evidence",
        );
      }
    } else if (providerLookupEvidence !== undefined) {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Provider lookup evidence is only valid for failed_no_effect",
      );
    }

    const snapshots = this.verifiedSnapshots();
    const epochs = this.operationEpochs(
      snapshots,
      validated.operation_id,
      validated.operation_step_id,
    );
    const epochRecords = epochs.find(
      (candidate) =>
        candidate.prepared.payload.operation_execution_epoch ===
        validated.operation_execution_epoch,
    );
    const latestDispatched = [...epochs]
      .reverse()
      .find((candidate) => candidate.dispatched !== undefined);
    if (
      epochRecords?.dispatched === undefined ||
      latestDispatched !== epochRecords ||
      epochRecords.dispatched.receiptDigest !==
        validated.dispatched_receipt_digest ||
      !this.outcomeMatchesEpoch(validated, epochRecords)
    ) {
      recoveryHold("Effect outcome does not match current dispatch");
    }
    if (providerLookupEvidence !== undefined) {
      this.verifyProviderLookupEvidence(
        providerLookupEvidence,
        validated as EffectFailedNoEffectOutcome,
        epochRecords,
      );
    }
    if (epochRecords.outcome !== undefined) {
      const existing = epochRecords.outcome.payload as EffectOutcomeRecord;
      if (canonicalJson(existing) !== canonicalJson(validated)) {
        recoveryHold("Effect outcome is already terminal");
      }
      return journalAppend(
        epochRecords.outcome as SignedLogRecord<EffectOutcomeRecord>,
        true,
      );
    }
    this.assertFreshOutcome(validated, epochRecords.dispatched.payload as EffectDispatchedRecord);
    const appended = this.effectLog.append(snapshots.effects.frontier, validated);
    return journalAppend(
      appended as SignedLogRecord<EffectOutcomeRecord>,
      false,
    );
  }

  private now(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new AccountsError("RECOVERY_HOLD", "Trusted effect journal clock is invalid");
    }
    return value.toISOString();
  }

  private validateStoredEffect(value: unknown): EffectDispatchRecord {
    const kind = ownDataField(value, "record_kind", true);
    if (kind === "DISPATCHED") {
      const dispatched = validateDispatchedStructure(
        value,
        true,
        true,
      ) as EffectDispatchedRecord;
      this.verifyDispatchSignature(dispatched, true);
      return dispatched;
    }
    if (kind === "OUTCOME") {
      const outcome = validateOutcomeStructure(
        value,
        true,
        true,
      ) as EffectOutcomeRecord;
      this.verifyEndpointOutcome(outcome, true);
      return outcome;
    }
    return invalid(true);
  }

  private verifyDispatchSignature(
    dispatched: EffectDispatchedRecord,
    stored: boolean,
  ): void {
    if (
      dispatched.signer_ref !== this.dispatchSigner.signerRef ||
      dispatched.signer_incarnation !== this.dispatchSigner.signerIncarnation ||
      dispatched.key_id !== this.dispatchSigner.keyId ||
      dispatched.audience !== this.dispatchSigner.audience
    ) {
      invalid(stored);
    }
    const { signature, ...unsigned } = dispatched;
    let valid = false;
    try {
      valid = verifySignature(
        null,
        effectDispatchedSigningBytes(unsigned),
        this.dispatchSigner.publicKey,
        Buffer.from(signature, "base64url"),
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      if (stored) invalid(true);
      throw new AccountsError("FORBIDDEN", "Effect dispatch signature is invalid");
    }
  }

  private verifyEndpointOutcome(outcome: EffectOutcomeRecord, stored: boolean): void {
    const trust = this.endpointTrust.get(outcome.effect_endpoint_ref);
    if (
      trust === undefined ||
      outcome.effect_endpoint_incarnation !== trust.incarnation ||
      outcome.effect_endpoint_key_id !== trust.keyId ||
      outcome.audience !== trust.audience
    ) {
      invalid(stored);
    }
    let valid = false;
    try {
      valid = verifySignature(
        null,
        effectOutcomeSigningBytes(unsignedOutcome(outcome)),
        trust.publicKey,
        Buffer.from(outcome.endpoint_signature, "base64url"),
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      if (stored) invalid(true);
      throw new AccountsError("FORBIDDEN", "Effect endpoint signature is invalid");
    }
  }

  private verifyProviderLookupEvidence(
    evidence: ProviderLookupEvidence,
    outcome: EffectFailedNoEffectOutcome,
    epoch: EpochRecords,
  ): void {
    const validated = validateLookupEvidenceStructure(
      evidence,
      false,
      true,
    ) as ProviderLookupEvidence;
    const trust = this.lookupTrust.get(validated.provider_lookup_issuer_ref);
    if (
      trust === undefined ||
      validated.provider_lookup_issuer_incarnation !== trust.incarnation ||
      validated.provider_lookup_key_id !== trust.keyId ||
      validated.audience !== trust.audience
    ) {
      throw new AccountsError("FORBIDDEN", "Provider lookup issuer is not trusted");
    }
    let signatureValid = false;
    try {
      signatureValid = verifySignature(
        null,
        providerLookupEvidenceSigningBytes(unsignedLookupEvidence(validated)),
        trust.publicKey,
        Buffer.from(validated.provider_signature, "base64url"),
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      throw new AccountsError("FORBIDDEN", "Provider lookup signature is invalid");
    }
    const prepared = epoch.prepared.payload;
    const dispatched = epoch.dispatched!.payload as EffectDispatchedRecord;
    if (
      canonicalSha256(validated) !== outcome.provider_lookup_evidence_digest ||
      validated.provider_key !== prepared.provider_key ||
      validated.effect_endpoint_ref !== prepared.effect_endpoint_ref ||
      validated.provider_idempotency_token_sha256 !==
        dispatched.provider_idempotency_token_sha256 ||
      validated.semantic_operation_key_digest !==
        prepared.semantic_operation_key_digest ||
      validated.operation_id !== prepared.operation_id ||
      validated.operation_step_id !== prepared.operation_step_id ||
      validated.operation_digest !== prepared.operation_digest ||
      validated.request_digest !== prepared.request_digest ||
      validated.target_digest !== prepared.target_digest ||
      validated.source_fences_digest !== prepared.source_fences_digest ||
      validated.maintenance_fence_digest !==
        prepared.maintenance_fence_digest ||
      validated.maintenance_grant_digest !==
        prepared.maintenance_grant_digest ||
      validated.operation_execution_epoch !==
        prepared.operation_execution_epoch
    ) {
      recoveryHold("Provider lookup evidence does not bind the dispatched effect");
    }
    const issued = Date.parse(validated.issued_at);
    const expires = Date.parse(validated.expires_at);
    const dispatchedAt = Date.parse(dispatched.dispatched_at);
    const observedAt = Date.parse(outcome.observed_at);
    const now = Date.parse(this.now());
    if (
      issued < dispatchedAt ||
      expires < issued ||
      expires - issued > MAXIMUM_EVIDENCE_AGE_MS ||
      issued - now > MAXIMUM_CLOCK_SKEW_MS ||
      now - issued > MAXIMUM_EVIDENCE_AGE_MS ||
      now - expires > MAXIMUM_CLOCK_SKEW_MS ||
      observedAt < issued ||
      observedAt > expires
    ) {
      recoveryHold("Provider lookup evidence is stale or temporally invalid");
    }
  }

  private assertFreshOutcome(
    outcome: EffectOutcomeRecord,
    dispatched: EffectDispatchedRecord,
  ): void {
    const observed = Date.parse(outcome.observed_at);
    const dispatchedAt = Date.parse(dispatched.dispatched_at);
    const now = Date.parse(this.now());
    if (
      observed < dispatchedAt ||
      observed - now > MAXIMUM_CLOCK_SKEW_MS ||
      now - observed > MAXIMUM_EVIDENCE_AGE_MS
    ) {
      recoveryHold("Effect outcome is stale or temporally invalid");
    }
  }

  private verifiedSnapshots(): EffectSnapshots {
    const snapshots = {
      claims: this.claimLog.readSnapshot(),
      prepared: this.preparedLog.readSnapshot(),
      effects: this.effectLog.readSnapshot(),
    };
    this.validateHistory(snapshots);
    return snapshots;
  }

  private validateHistory(snapshots: EffectSnapshots): void {
    const claims = new Map<string, EffectClaimRecord>();
    for (const record of snapshots.claims.records) {
      const claim = record.payload;
      if (
        claim.semantic_operation_key_digest !==
        claimSemanticDigest(this.catalogIncarnation, claim)
      ) {
        invalid(true);
      }
      const existing = claims.get(claim.semantic_operation_key_digest);
      if (
        existing !== undefined &&
        (existing.operation_id !== claim.operation_id ||
          existing.operation_step_id !== claim.operation_step_id ||
          canonicalJson(existing) !== canonicalJson(claim))
      ) {
        invalid(true);
      }
      claims.set(claim.semantic_operation_key_digest, claim);
    }

    const preparedByEpoch = new Map<string, SignedLogRecord<EffectPreparedRecord>>();
    const preparedGroups = new Map<string, SignedLogRecord<EffectPreparedRecord>[]>();
    for (const record of snapshots.prepared.records) {
      const prepared = record.payload;
      const claim = claims.get(prepared.semantic_operation_key_digest);
      if (
        claim === undefined ||
        claim.operation_id !== prepared.operation_id ||
        claim.operation_step_id !== prepared.operation_step_id ||
        claim.credential_family_id !== prepared.credential_family_id ||
        claim.serialization_key_digest !== prepared.serialization_key_digest ||
        claim.request_digest !== prepared.request_digest ||
        claim.source_fences_digest !== prepared.source_fences_digest
      ) {
        invalid(true);
      }
      const key = epochKey(prepared);
      if (preparedByEpoch.has(key)) invalid(true);
      preparedByEpoch.set(key, record);
      const groupKey = operationKey(prepared);
      const group = preparedGroups.get(groupKey) ?? [];
      group.push(record);
      preparedGroups.set(groupKey, group);
    }

    const effectsByEpoch = new Map<string, EpochRecords>();
    for (const [key, prepared] of preparedByEpoch) {
      effectsByEpoch.set(key, { prepared });
    }
    for (const record of snapshots.effects.records) {
      const key = epochKey(record.payload);
      const epoch = effectsByEpoch.get(key);
      if (epoch === undefined) invalid(true);
      if (record.payload.record_kind === "DISPATCHED") {
        if (epoch.dispatched !== undefined || epoch.outcome !== undefined) invalid(true);
        if (!this.dispatchedMatchesPrepared(record.payload, epoch.prepared)) invalid(true);
        epoch.dispatched = record;
      } else {
        if (epoch.dispatched === undefined || epoch.outcome !== undefined) invalid(true);
        if (!this.outcomeMatchesEpoch(record.payload, epoch)) invalid(true);
        epoch.outcome = record;
      }
    }

    for (const group of preparedGroups.values()) {
      let previous: EpochRecords | undefined;
      for (const preparedRecord of group) {
        const prepared = preparedRecord.payload;
        const current = effectsByEpoch.get(epochKey(prepared));
        if (current === undefined) invalid(true);
        if (previous === undefined) {
          if (prepared.prior_failed_no_effect_receipt_digest !== undefined) invalid(true);
        } else {
          const priorPrepared = previous.prepared.payload;
          const priorOutcome = previous.outcome?.payload as EffectOutcomeRecord | undefined;
          let nextEpoch: Counter;
          try {
            nextEpoch = incrementCounter(priorPrepared.operation_execution_epoch);
          } catch {
            invalid(true);
          }
          if (
            priorOutcome?.outcome_kind !== "failed_no_effect" ||
            prepared.operation_execution_epoch !== nextEpoch ||
            prepared.prior_failed_no_effect_receipt_digest !==
              previous.outcome?.receiptDigest ||
            retryIdentityDigest(prepared) !== retryIdentityDigest(priorPrepared) ||
            prepared.maintenance_grant_digest ===
              priorPrepared.maintenance_grant_digest
          ) {
            invalid(true);
          }
        }
        previous = current;
      }
    }
  }

  private operationEpochs(
    snapshots: EffectSnapshots,
    operationId: string,
    operationStepId: string,
  ): EpochRecords[] {
    const result = snapshots.prepared.records
      .filter(
        (record) =>
          record.payload.operation_id === operationId &&
          record.payload.operation_step_id === operationStepId,
      )
      .map((prepared) => ({ prepared }) as EpochRecords);
    for (const effect of snapshots.effects.records) {
      if (
        effect.payload.operation_id !== operationId ||
        effect.payload.operation_step_id !== operationStepId
      ) {
        continue;
      }
      const epoch = result.find(
        (candidate) =>
          candidate.prepared.payload.operation_execution_epoch ===
          effect.payload.operation_execution_epoch,
      );
      if (epoch === undefined) invalid(true);
      if (effect.payload.record_kind === "DISPATCHED") epoch.dispatched = effect;
      else epoch.outcome = effect;
    }
    return result;
  }

  private dispatchedMatchesPrepared(
    dispatched: EffectDispatchedRecord,
    preparedRecord: SignedLogRecord<EffectPreparedRecord>,
  ): boolean {
    const prepared = preparedRecord.payload;
    return (
      dispatched.semantic_operation_key_digest ===
        prepared.semantic_operation_key_digest &&
      dispatched.operation_id === prepared.operation_id &&
      dispatched.operation_step_id === prepared.operation_step_id &&
      dispatched.operation_digest === prepared.operation_digest &&
      dispatched.request_digest === prepared.request_digest &&
      dispatched.target_digest === prepared.target_digest &&
      dispatched.source_fences_digest === prepared.source_fences_digest &&
      dispatched.maintenance_fence_digest ===
        prepared.maintenance_fence_digest &&
      dispatched.maintenance_grant_digest ===
        prepared.maintenance_grant_digest &&
      dispatched.operation_execution_epoch ===
        prepared.operation_execution_epoch &&
      dispatched.provider_key === prepared.provider_key &&
      dispatched.effect_endpoint_ref === prepared.effect_endpoint_ref &&
      dispatched.prepared_receipt_digest === preparedRecord.receiptDigest &&
      dispatched.provider_idempotency_token_sha256 ===
        sha256Ascii(this.providerIdempotencyToken(prepared))
    );
  }

  private outcomeMatchesEpoch(
    outcome: EffectOutcomeRecord,
    epoch: EpochRecords,
  ): boolean {
    if (epoch.dispatched === undefined) return false;
    const prepared = epoch.prepared.payload;
    const dispatched = epoch.dispatched.payload as EffectDispatchedRecord;
    return (
      outcome.semantic_operation_key_digest ===
        prepared.semantic_operation_key_digest &&
      outcome.operation_id === prepared.operation_id &&
      outcome.operation_step_id === prepared.operation_step_id &&
      outcome.operation_digest === prepared.operation_digest &&
      outcome.request_digest === prepared.request_digest &&
      outcome.target_digest === prepared.target_digest &&
      outcome.source_fences_digest === prepared.source_fences_digest &&
      outcome.maintenance_fence_digest === prepared.maintenance_fence_digest &&
      outcome.maintenance_grant_digest === prepared.maintenance_grant_digest &&
      outcome.operation_execution_epoch ===
        prepared.operation_execution_epoch &&
      outcome.dispatched_receipt_digest === epoch.dispatched.receiptDigest &&
      outcome.provider_idempotency_token_sha256 ===
        dispatched.provider_idempotency_token_sha256 &&
      outcome.effect_endpoint_ref === prepared.effect_endpoint_ref
    );
  }

  private providerIdempotencyToken(prepared: EffectPreparedRecord): string {
    const digest = canonicalSha256({
      schema_version: PROVIDER_TOKEN_SCHEMA,
      catalog_incarnation: this.catalogIncarnation,
      effect_endpoint_ref: prepared.effect_endpoint_ref,
      operation_id: prepared.operation_id,
      operation_step_id: prepared.operation_step_id,
      provider_key: prepared.provider_key,
      request_digest: prepared.request_digest,
      semantic_operation_key_digest: prepared.semantic_operation_key_digest,
      target_digest: prepared.target_digest,
    });
    return `accounts-effect-v1.${digest.slice("sha256:".length)}`;
  }
}
