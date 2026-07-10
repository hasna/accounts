import {
  sign as ed25519Sign,
  verify as ed25519Verify,
  type KeyObject,
} from "node:crypto";

import { AccountsError } from "../errors";
import { parseCounter, type Counter } from "./counter";
import { isUuidV7 } from "./ids";
import {
  canonicalJson,
  canonicalSha256,
  parseClosedJson,
  parseClosedJsonBytes,
} from "../serialization/json";

export const AUTHORITY_EVIDENCE_SCHEMA_VERSION =
  "accounts.authority-evidence.v1" as const;

export const AUTHORITY_EVIDENCE_TYPES = [
  "provider_ownership",
  "provider_capacity",
  "entitlement_execution_policy",
  "entitlement_terms",
  "entitlement_data_policy",
  "lane_isolation_policy",
  "lane_execution_policy",
  "lane_health",
] as const;

export type AuthorityEvidenceType = (typeof AUTHORITY_EVIDENCE_TYPES)[number];

export const AUTHORITY_ISSUER_CLASSES = [
  "provider_ownership_verifier",
  "provider_capacity_verifier",
  "execution_policy_authority",
  "terms_authority",
  "adapter_health_reporter",
] as const;

export type AuthorityIssuerClass = (typeof AUTHORITY_ISSUER_CLASSES)[number];
export type AuthorityAggregateKind =
  | "provider_account"
  | "capacity_pool"
  | "entitlement"
  | "account_lane";

export interface ProviderOwnershipPayload {
  readonly provider_key: string;
  readonly provider_subject_ref: string;
  readonly owner_ref: string;
  readonly identity_realm: string;
  readonly ownership_generation: Counter;
}

export interface ProviderCapacityPayload {
  readonly provider_account_id: string;
  readonly provider_key: string;
  readonly owner_ref: string;
  readonly capacity_domain_ref: string;
  readonly serialization_key: string;
  readonly max_concurrency: Counter;
  readonly decision: "allowed" | "denied";
  readonly policy_version: string;
}

export interface EntitlementExecutionPolicyPayload {
  readonly provider_account_id: string;
  readonly owner_ref: string;
  readonly provider_key: string;
  readonly use_case: string;
  readonly adapter_version: string;
  readonly decision: "allowed" | "denied";
  readonly capability_set: {
    readonly operations: readonly string[];
    readonly models: readonly string[];
  };
  readonly policy_version: string;
}

export interface EntitlementTermsPayload {
  readonly provider_account_id: string;
  readonly owner_ref: string;
  readonly provider_key: string;
  readonly use_case: string;
  readonly decision: "allowed" | "denied";
  readonly terms_version: string;
  readonly terms_digest: string;
}

export interface EntitlementDataPolicyPayload {
  readonly provider_account_id: string;
  readonly owner_ref: string;
  readonly provider_key: string;
  readonly use_case: string;
  readonly decision: "allowed" | "denied";
  readonly allowed_classifications: readonly string[];
  readonly retention_class: "none" | "transient" | "bounded";
  readonly max_retention_days?: Counter;
  readonly policy_version: string;
}

export interface LaneIsolationPolicyPayload {
  readonly provider_account_id: string;
  readonly entitlement_id: string;
  readonly capacity_pool_id: string;
  readonly owner_ref: string;
  readonly adapter_key: string;
  readonly adapter_version: string;
  readonly access_transport: "native_session" | "api_key" | "workload_identity";
  readonly decision: "allowed" | "denied";
  readonly required_isolation_policy_ref?: string;
  readonly required_isolation_policy_digest?: string;
  readonly policy_version: string;
}

export interface LaneExecutionPolicyPayload {
  readonly provider_account_id: string;
  readonly entitlement_id: string;
  readonly capacity_pool_id: string;
  readonly owner_ref: string;
  readonly adapter_key: string;
  readonly adapter_version: string;
  readonly access_transport: "native_session" | "api_key" | "workload_identity";
  readonly decision: "allowed" | "denied";
  readonly allowed_operations: readonly string[];
  readonly allowed_models: readonly string[];
  readonly allowed_destination_policy_classes: readonly string[];
  readonly policy_version: string;
}

export interface LaneHealthPayload {
  readonly provider_account_id: string;
  readonly entitlement_id: string;
  readonly capacity_pool_id: string;
  readonly owner_ref: string;
  readonly adapter_key: string;
  readonly adapter_version: string;
  readonly state: "healthy" | "degraded" | "unavailable" | "unknown";
  readonly observed_at: string;
}

export type AuthorityEvidencePayload<
  Type extends AuthorityEvidenceType = AuthorityEvidenceType,
> = Type extends "provider_ownership"
  ? ProviderOwnershipPayload
  : Type extends "provider_capacity"
    ? ProviderCapacityPayload
  : Type extends "entitlement_execution_policy"
    ? EntitlementExecutionPolicyPayload
    : Type extends "entitlement_terms"
      ? EntitlementTermsPayload
      : Type extends "entitlement_data_policy"
        ? EntitlementDataPolicyPayload
        : Type extends "lane_isolation_policy"
          ? LaneIsolationPolicyPayload
          : Type extends "lane_execution_policy"
            ? LaneExecutionPolicyPayload
            : Type extends "lane_health"
              ? LaneHealthPayload
              : never;

type IssuerClassFor<Type extends AuthorityEvidenceType> =
  Type extends "provider_ownership"
    ? "provider_ownership_verifier"
    : Type extends "provider_capacity"
      ? "provider_capacity_verifier"
    : Type extends "entitlement_terms"
      ? "terms_authority"
      : Type extends "lane_health"
        ? "adapter_health_reporter"
        : "execution_policy_authority";

type AggregateKindFor<Type extends AuthorityEvidenceType> =
  Type extends "provider_ownership"
    ? "provider_account"
    : Type extends "provider_capacity"
      ? "capacity_pool"
    : Type extends `entitlement_${string}`
      ? "entitlement"
      : "account_lane";

export interface AuthorityEvidenceDraft<
  Type extends AuthorityEvidenceType = AuthorityEvidenceType,
> {
  readonly schema_version: typeof AUTHORITY_EVIDENCE_SCHEMA_VERSION;
  readonly evidence_type: Type;
  readonly evidence_ref: string;
  readonly subject_ref: string;
  readonly aggregate_kind: AggregateKindFor<Type>;
  readonly aggregate_id: string;
  readonly aggregate_revision: Counter;
  readonly identity_realm: string;
  readonly issuer_ref: string;
  readonly issuer_class: IssuerClassFor<Type>;
  readonly issuer_incarnation: string;
  readonly audience: string;
  readonly key_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly nonce: string;
  readonly evidence_generation: Counter;
  readonly payload: AuthorityEvidencePayload<Type>;
}

export interface AuthorityEvidenceEnvelope<
  Type extends AuthorityEvidenceType = AuthorityEvidenceType,
> extends AuthorityEvidenceDraft<Type> {
  readonly payload_digest: string;
  readonly signature: string;
}

export interface AuthorityEvidenceTrustRoot {
  readonly issuerRef: string;
  readonly issuerClass: AuthorityIssuerClass;
  readonly issuerIncarnation: string;
  readonly audience: string;
  readonly identityRealm: string;
  readonly keyId: string;
  readonly publicKey: KeyObject;
  readonly revoked: boolean;
}

export interface ProviderOwnershipBinding {
  readonly providerKey: string;
  readonly providerSubjectRef: string;
  readonly ownerRef: string;
}

export interface ProviderCapacityBinding {
  readonly providerAccountId: string;
  readonly providerKey: string;
  readonly ownerRef: string;
  readonly capacityDomainRef: string;
  readonly serializationKey: string;
  readonly maxConcurrency: Counter;
}

export interface EntitlementPolicyBinding {
  readonly providerAccountId: string;
  readonly ownerRef: string;
  readonly providerKey: string;
  readonly useCase: string;
}

export interface EntitlementExecutionPolicyBinding extends EntitlementPolicyBinding {
  readonly adapterVersion: string;
}

export interface LanePolicyBinding {
  readonly providerAccountId: string;
  readonly entitlementId: string;
  readonly capacityPoolId: string;
  readonly ownerRef: string;
  readonly adapterKey: string;
  readonly adapterVersion: string;
  readonly accessTransport: "native_session" | "api_key" | "workload_identity";
}

export interface LaneHealthBinding {
  readonly providerAccountId: string;
  readonly entitlementId: string;
  readonly capacityPoolId: string;
  readonly ownerRef: string;
  readonly adapterKey: string;
  readonly adapterVersion: string;
}

export type AuthorityEvidenceBinding<
  Type extends AuthorityEvidenceType = AuthorityEvidenceType,
> = Type extends "provider_ownership"
  ? ProviderOwnershipBinding
  : Type extends "provider_capacity"
    ? ProviderCapacityBinding
  : Type extends "entitlement_execution_policy"
    ? EntitlementExecutionPolicyBinding
    : Type extends "entitlement_terms" | "entitlement_data_policy"
      ? EntitlementPolicyBinding
      : Type extends "lane_isolation_policy" | "lane_execution_policy"
        ? LanePolicyBinding
        : Type extends "lane_health"
          ? LaneHealthBinding
          : never;

export interface AuthorityEvidenceExpectation<
  Type extends AuthorityEvidenceType = AuthorityEvidenceType,
> {
  readonly evidenceType: Type;
  readonly subjectRef: string;
  readonly aggregateKind: AggregateKindFor<Type>;
  readonly aggregateId: string;
  readonly aggregateRevision: Counter;
  readonly identityRealm: string;
  readonly evidenceGeneration: Counter;
  readonly nonce: string;
  readonly now: Date;
  readonly maximumAgeMs: number;
  readonly maximumLifetimeMs: number;
  readonly allowedClockSkewMs?: number;
  readonly binding: AuthorityEvidenceBinding<Type>;
}

type JsonObject = Record<string, unknown>;

const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const KEY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const OWNER_PATTERN =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REALM_PATTERN = /^[a-z][a-z0-9._:-]{0,127}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const COMMON_KEYS = [
  "schema_version",
  "evidence_type",
  "evidence_ref",
  "subject_ref",
  "aggregate_kind",
  "aggregate_id",
  "aggregate_revision",
  "identity_realm",
  "issuer_ref",
  "issuer_class",
  "issuer_incarnation",
  "audience",
  "key_id",
  "issued_at",
  "expires_at",
  "nonce",
  "evidence_generation",
  "payload",
] as const;

const EXPECTED_ISSUER_CLASS: Readonly<Record<AuthorityEvidenceType, AuthorityIssuerClass>> = {
  provider_ownership: "provider_ownership_verifier",
  provider_capacity: "provider_capacity_verifier",
  entitlement_execution_policy: "execution_policy_authority",
  entitlement_terms: "terms_authority",
  entitlement_data_policy: "execution_policy_authority",
  lane_isolation_policy: "execution_policy_authority",
  lane_execution_policy: "execution_policy_authority",
  lane_health: "adapter_health_reporter",
};

const EXPECTED_AGGREGATE_KIND: Readonly<
  Record<AuthorityEvidenceType, AuthorityAggregateKind>
> = {
  provider_ownership: "provider_account",
  provider_capacity: "capacity_pool",
  entitlement_execution_policy: "entitlement",
  entitlement_terms: "entitlement",
  entitlement_data_policy: "entitlement",
  lane_isolation_policy: "account_lane",
  lane_execution_policy: "account_lane",
  lane_health: "account_lane",
};

function malformed(): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Authority evidence is malformed");
}

function forbidden(): AccountsError {
  return new AccountsError("FORBIDDEN", "Authority evidence is not trusted");
}

function stale(): AccountsError {
  return new AccountsError("STALE_ATTESTATION", "Authority evidence is stale");
}

function object(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw malformed();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw malformed();
  return value as JsonObject;
}

function exactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw malformed();
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw malformed();
  }
}

function string(
  value: unknown,
  options: { readonly min?: number; readonly max?: number; readonly pattern?: RegExp } = {},
): string {
  if (typeof value !== "string") throw malformed();
  const min = options.min ?? 1;
  const max = options.max ?? 255;
  if (value.length < min || value.length > max || value.trim() !== value) throw malformed();
  if (options.pattern !== undefined && !options.pattern.test(value)) throw malformed();
  return value;
}

function reference(value: unknown): string {
  return string(value, { pattern: REFERENCE_PATTERN });
}

function opaqueSubject(value: unknown): string {
  const result = string(value);
  if (/\p{Cc}/u.test(result)) throw malformed();
  return result;
}

function owner(value: unknown): string {
  return string(value, { max: 160, pattern: OWNER_PATTERN });
}

function realm(value: unknown): string {
  return string(value, { max: 128, pattern: REALM_PATTERN });
}

function key(value: unknown): string {
  return string(value, { max: 64, pattern: KEY_PATTERN });
}

function digest(value: unknown): string {
  return string(value, { max: 71, pattern: DIGEST_PATTERN });
}

function uuidV7(value: unknown): string {
  if (typeof value !== "string" || !isUuidV7(value)) throw malformed();
  return value;
}

function timestamp(value: unknown): string {
  const result = string(value, { max: 24, pattern: TIMESTAMP_PATTERN });
  const milliseconds = Date.parse(result);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== result) {
    throw malformed();
  }
  return result;
}

function counter(value: unknown, nonzero = false): Counter {
  let result: Counter;
  try {
    result = parseCounter(value);
  } catch {
    throw malformed();
  }
  if (nonzero && result === "0") throw malformed();
  return result;
}

function enumValue<const Values extends readonly string[]>(
  value: unknown,
  allowed: Values,
): Values[number] {
  if (typeof value !== "string" || !allowed.includes(value)) throw malformed();
  return value as Values[number];
}

function stringList(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 128) throw malformed();
  const result = value.map((item) => reference(item));
  if (new Set(result).size !== result.length) throw malformed();
  return result;
}

function base64url(value: unknown, minimumBytes: number, maximumBytes: number): string {
  const encoded = string(value, {
    max: Math.ceil((maximumBytes * 4) / 3),
    pattern: BASE64URL_PATTERN,
  });
  if (encoded.includes("=")) throw malformed();
  const decoded = Buffer.from(encoded, "base64url");
  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes ||
    decoded.toString("base64url") !== encoded
  ) {
    throw malformed();
  }
  return encoded;
}

function validateProviderOwnershipPayload(value: unknown): ProviderOwnershipPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_key",
    "provider_subject_ref",
    "owner_ref",
    "identity_realm",
    "ownership_generation",
  ]);
  key(payload.provider_key);
  opaqueSubject(payload.provider_subject_ref);
  owner(payload.owner_ref);
  realm(payload.identity_realm);
  counter(payload.ownership_generation, true);
  return payload as unknown as ProviderOwnershipPayload;
}

function validateProviderCapacityPayload(value: unknown): ProviderCapacityPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_account_id",
    "provider_key",
    "owner_ref",
    "capacity_domain_ref",
    "serialization_key",
    "max_concurrency",
    "decision",
    "policy_version",
  ]);
  uuidV7(payload.provider_account_id);
  key(payload.provider_key);
  owner(payload.owner_ref);
  reference(payload.capacity_domain_ref);
  reference(payload.serialization_key);
  counter(payload.max_concurrency, true);
  enumValue(payload.decision, ["allowed", "denied"] as const);
  reference(payload.policy_version);
  return payload as unknown as ProviderCapacityPayload;
}

function validateEntitlementExecutionPolicyPayload(
  value: unknown,
): EntitlementExecutionPolicyPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_account_id",
    "owner_ref",
    "provider_key",
    "use_case",
    "adapter_version",
    "decision",
    "capability_set",
    "policy_version",
  ]);
  uuidV7(payload.provider_account_id);
  owner(payload.owner_ref);
  key(payload.provider_key);
  reference(payload.use_case);
  reference(payload.adapter_version);
  const decision = enumValue(payload.decision, ["allowed", "denied"] as const);
  const capabilitySet = object(payload.capability_set);
  exactKeys(capabilitySet, ["operations", "models"]);
  const operations = stringList(capabilitySet.operations);
  const models = stringList(capabilitySet.models);
  reference(payload.policy_version);
  if (decision === "denied" && (operations.length !== 0 || models.length !== 0)) throw malformed();
  return payload as unknown as EntitlementExecutionPolicyPayload;
}

function validateEntitlementTermsPayload(value: unknown): EntitlementTermsPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_account_id",
    "owner_ref",
    "provider_key",
    "use_case",
    "decision",
    "terms_version",
    "terms_digest",
  ]);
  uuidV7(payload.provider_account_id);
  owner(payload.owner_ref);
  key(payload.provider_key);
  reference(payload.use_case);
  enumValue(payload.decision, ["allowed", "denied"] as const);
  reference(payload.terms_version);
  digest(payload.terms_digest);
  return payload as unknown as EntitlementTermsPayload;
}

function validateEntitlementDataPolicyPayload(value: unknown): EntitlementDataPolicyPayload {
  const payload = object(value);
  exactKeys(
    payload,
    [
      "provider_account_id",
      "owner_ref",
      "provider_key",
      "use_case",
      "decision",
      "allowed_classifications",
      "retention_class",
      "policy_version",
    ],
    ["max_retention_days"],
  );
  uuidV7(payload.provider_account_id);
  owner(payload.owner_ref);
  key(payload.provider_key);
  reference(payload.use_case);
  const decision = enumValue(payload.decision, ["allowed", "denied"] as const);
  const classifications = stringList(payload.allowed_classifications);
  const retention = enumValue(payload.retention_class, ["none", "transient", "bounded"] as const);
  reference(payload.policy_version);
  if (retention === "bounded") {
    counter(payload.max_retention_days, true);
  } else if (payload.max_retention_days !== undefined) {
    throw malformed();
  }
  if (
    decision === "denied" &&
    (classifications.length !== 0 || retention !== "none" || payload.max_retention_days !== undefined)
  ) {
    throw malformed();
  }
  return payload as unknown as EntitlementDataPolicyPayload;
}

function validateLaneIdentity(payload: JsonObject): void {
  uuidV7(payload.provider_account_id);
  uuidV7(payload.entitlement_id);
  uuidV7(payload.capacity_pool_id);
  owner(payload.owner_ref);
  key(payload.adapter_key);
  reference(payload.adapter_version);
}

function validateLaneIsolationPolicyPayload(value: unknown): LaneIsolationPolicyPayload {
  const payload = object(value);
  exactKeys(
    payload,
    [
      "provider_account_id",
      "entitlement_id",
      "capacity_pool_id",
      "owner_ref",
      "adapter_key",
      "adapter_version",
      "access_transport",
      "decision",
      "policy_version",
    ],
    ["required_isolation_policy_ref", "required_isolation_policy_digest"],
  );
  validateLaneIdentity(payload);
  enumValue(payload.access_transport, ["native_session", "api_key", "workload_identity"] as const);
  const decision = enumValue(payload.decision, ["allowed", "denied"] as const);
  reference(payload.policy_version);
  if (decision === "allowed") {
    reference(payload.required_isolation_policy_ref);
    digest(payload.required_isolation_policy_digest);
  } else if (
    payload.required_isolation_policy_ref !== undefined ||
    payload.required_isolation_policy_digest !== undefined
  ) {
    throw malformed();
  }
  return payload as unknown as LaneIsolationPolicyPayload;
}

function validateLaneExecutionPolicyPayload(value: unknown): LaneExecutionPolicyPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_account_id",
    "entitlement_id",
    "capacity_pool_id",
    "owner_ref",
    "adapter_key",
    "adapter_version",
    "access_transport",
    "decision",
    "allowed_operations",
    "allowed_models",
    "allowed_destination_policy_classes",
    "policy_version",
  ]);
  validateLaneIdentity(payload);
  enumValue(payload.access_transport, ["native_session", "api_key", "workload_identity"] as const);
  const decision = enumValue(payload.decision, ["allowed", "denied"] as const);
  const operations = stringList(payload.allowed_operations);
  const models = stringList(payload.allowed_models);
  const destinations = stringList(payload.allowed_destination_policy_classes);
  reference(payload.policy_version);
  if (
    decision === "denied" &&
    (operations.length !== 0 || models.length !== 0 || destinations.length !== 0)
  ) {
    throw malformed();
  }
  return payload as unknown as LaneExecutionPolicyPayload;
}

function validateLaneHealthPayload(value: unknown): LaneHealthPayload {
  const payload = object(value);
  exactKeys(payload, [
    "provider_account_id",
    "entitlement_id",
    "capacity_pool_id",
    "owner_ref",
    "adapter_key",
    "adapter_version",
    "state",
    "observed_at",
  ]);
  validateLaneIdentity(payload);
  enumValue(payload.state, ["healthy", "degraded", "unavailable", "unknown"] as const);
  timestamp(payload.observed_at);
  return payload as unknown as LaneHealthPayload;
}

function validatePayload<Type extends AuthorityEvidenceType>(
  type: Type,
  value: unknown,
): AuthorityEvidencePayload<Type> {
  switch (type) {
    case "provider_ownership":
      return validateProviderOwnershipPayload(value) as AuthorityEvidencePayload<Type>;
    case "provider_capacity":
      return validateProviderCapacityPayload(value) as AuthorityEvidencePayload<Type>;
    case "entitlement_execution_policy":
      return validateEntitlementExecutionPolicyPayload(value) as AuthorityEvidencePayload<Type>;
    case "entitlement_terms":
      return validateEntitlementTermsPayload(value) as AuthorityEvidencePayload<Type>;
    case "entitlement_data_policy":
      return validateEntitlementDataPolicyPayload(value) as AuthorityEvidencePayload<Type>;
    case "lane_isolation_policy":
      return validateLaneIsolationPolicyPayload(value) as AuthorityEvidencePayload<Type>;
    case "lane_execution_policy":
      return validateLaneExecutionPolicyPayload(value) as AuthorityEvidencePayload<Type>;
    case "lane_health":
      return validateLaneHealthPayload(value) as AuthorityEvidencePayload<Type>;
  }
}

function validateEnvelope(value: unknown): AuthorityEvidenceEnvelope {
  const envelope = object(value);
  exactKeys(envelope, [...COMMON_KEYS, "payload_digest", "signature"]);
  if (envelope.schema_version !== AUTHORITY_EVIDENCE_SCHEMA_VERSION) throw malformed();
  const type = enumValue(envelope.evidence_type, AUTHORITY_EVIDENCE_TYPES);
  reference(envelope.evidence_ref);
  reference(envelope.subject_ref);
  const aggregateKind = enumValue(envelope.aggregate_kind, [
    "provider_account",
    "capacity_pool",
    "entitlement",
    "account_lane",
  ] as const);
  if (aggregateKind !== EXPECTED_AGGREGATE_KIND[type]) throw malformed();
  uuidV7(envelope.aggregate_id);
  counter(envelope.aggregate_revision);
  realm(envelope.identity_realm);
  reference(envelope.issuer_ref);
  const issuerClass = enumValue(envelope.issuer_class, AUTHORITY_ISSUER_CLASSES);
  if (issuerClass !== EXPECTED_ISSUER_CLASS[type]) throw malformed();
  uuidV7(envelope.issuer_incarnation);
  reference(envelope.audience);
  reference(envelope.key_id);
  const issuedAt = timestamp(envelope.issued_at);
  const expiresAt = timestamp(envelope.expires_at);
  if (Date.parse(issuedAt) >= Date.parse(expiresAt)) throw malformed();
  base64url(envelope.nonce, 16, 64);
  const evidenceGeneration = counter(envelope.evidence_generation, true);
  const payload = validatePayload(type, envelope.payload);
  const payloadDigest = digest(envelope.payload_digest);
  if (payloadDigest !== canonicalSha256(payload)) throw malformed();
  base64url(envelope.signature, 64, 64);
  if (
    type === "provider_ownership" &&
    (payload as ProviderOwnershipPayload).ownership_generation !== evidenceGeneration
  ) {
    throw malformed();
  }
  if (
    type === "provider_ownership" &&
    (payload as ProviderOwnershipPayload).identity_realm !== envelope.identity_realm
  ) {
    throw malformed();
  }
  if (type === "lane_health") {
    const observedAt = Date.parse((payload as LaneHealthPayload).observed_at);
    if (observedAt > Date.parse(issuedAt)) throw malformed();
  }
  return envelope as unknown as AuthorityEvidenceEnvelope;
}

function validateDraft(value: unknown): AuthorityEvidenceDraft {
  const draft = object(value);
  exactKeys(draft, COMMON_KEYS);
  const withTemporarySignature = {
    ...draft,
    payload_digest: canonicalSha256(draft.payload),
    signature: Buffer.alloc(64).toString("base64url"),
  };
  const envelope = validateEnvelope(withTemporarySignature);
  const { payload_digest: _payloadDigest, signature: _signature, ...validated } = envelope;
  return validated;
}

function assertTrust(
  envelope: AuthorityEvidenceEnvelope,
  trust: AuthorityEvidenceTrustRoot,
): void {
  if (
    trust.revoked !== false ||
    envelope.issuer_ref !== trust.issuerRef ||
    envelope.issuer_class !== trust.issuerClass ||
    envelope.issuer_incarnation !== trust.issuerIncarnation ||
    envelope.audience !== trust.audience ||
    envelope.identity_realm !== trust.identityRealm ||
    envelope.key_id !== trust.keyId ||
    trust.issuerClass !== EXPECTED_ISSUER_CLASS[envelope.evidence_type]
  ) {
    throw forbidden();
  }
  const publicKey = trust.publicKey as KeyObject | null | undefined;
  if (
    publicKey === undefined ||
    publicKey === null ||
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw forbidden();
  }
}

function unsignedEnvelope(envelope: AuthorityEvidenceEnvelope): JsonObject {
  const { signature: _signature, ...unsigned } = envelope;
  return unsigned;
}

function assertSignature(
  envelope: AuthorityEvidenceEnvelope,
  publicKey: KeyObject,
): void {
  const message = Buffer.from(canonicalJson(unsignedEnvelope(envelope)), "utf8");
  const signature = Buffer.from(envelope.signature, "base64url");
  let valid = false;
  try {
    valid = ed25519Verify(null, message, publicKey, signature);
  } catch {
    throw forbidden();
  }
  if (!valid) throw forbidden();
}

function safeDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw malformed();
  return value;
}

function assertFreshness(
  envelope: AuthorityEvidenceEnvelope,
  expectation: AuthorityEvidenceExpectation,
): void {
  if (!(expectation.now instanceof Date)) throw malformed();
  const now = expectation.now.getTime();
  if (!Number.isFinite(now)) throw malformed();
  const maximumAge = safeDuration(expectation.maximumAgeMs);
  const maximumLifetime = safeDuration(expectation.maximumLifetimeMs);
  const allowedClockSkew = expectation.allowedClockSkewMs ?? 0;
  if (!Number.isSafeInteger(allowedClockSkew) || allowedClockSkew < 0 || allowedClockSkew > 300_000) {
    throw malformed();
  }
  const issuedAt = Date.parse(envelope.issued_at);
  const expiresAt = Date.parse(envelope.expires_at);
  if (
    issuedAt > now + allowedClockSkew ||
    expiresAt <= now ||
    now - issuedAt > maximumAge + allowedClockSkew ||
    expiresAt - issuedAt > maximumLifetime
  ) {
    throw stale();
  }
  if (envelope.evidence_type === "lane_health") {
    const observedAt = Date.parse((envelope.payload as LaneHealthPayload).observed_at);
    if (observedAt > now + allowedClockSkew || now - observedAt > maximumAge + allowedClockSkew) {
      throw stale();
    }
  }
}

function assertEqual(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw forbidden();
}

function assertBinding<Type extends AuthorityEvidenceType>(
  envelope: AuthorityEvidenceEnvelope<Type>,
  expectation: AuthorityEvidenceExpectation<Type>,
): void {
  assertEqual(envelope.evidence_type, expectation.evidenceType);
  assertEqual(envelope.subject_ref, expectation.subjectRef);
  assertEqual(envelope.aggregate_kind, expectation.aggregateKind);
  assertEqual(envelope.aggregate_id, expectation.aggregateId);
  assertEqual(envelope.aggregate_revision, expectation.aggregateRevision);
  assertEqual(envelope.identity_realm, expectation.identityRealm);
  assertEqual(envelope.evidence_generation, expectation.evidenceGeneration);
  assertEqual(envelope.nonce, expectation.nonce);

  switch (envelope.evidence_type) {
    case "provider_ownership": {
      const payload = envelope.payload as ProviderOwnershipPayload;
      const binding = expectation.binding as ProviderOwnershipBinding;
      assertEqual(payload.provider_key, binding.providerKey);
      assertEqual(payload.provider_subject_ref, binding.providerSubjectRef);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.identity_realm, expectation.identityRealm);
      return;
    }
    case "provider_capacity": {
      const payload = envelope.payload as ProviderCapacityPayload;
      const binding = expectation.binding as ProviderCapacityBinding;
      assertEqual(payload.provider_account_id, binding.providerAccountId);
      assertEqual(payload.provider_key, binding.providerKey);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.capacity_domain_ref, binding.capacityDomainRef);
      assertEqual(payload.serialization_key, binding.serializationKey);
      assertEqual(payload.max_concurrency, binding.maxConcurrency);
      return;
    }
    case "entitlement_execution_policy": {
      const payload = envelope.payload as EntitlementExecutionPolicyPayload;
      const binding = expectation.binding as EntitlementExecutionPolicyBinding;
      assertEqual(payload.provider_account_id, binding.providerAccountId);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.provider_key, binding.providerKey);
      assertEqual(payload.use_case, binding.useCase);
      assertEqual(payload.adapter_version, binding.adapterVersion);
      return;
    }
    case "entitlement_terms":
    case "entitlement_data_policy": {
      const payload = envelope.payload as EntitlementTermsPayload | EntitlementDataPolicyPayload;
      const binding = expectation.binding as EntitlementPolicyBinding;
      assertEqual(payload.provider_account_id, binding.providerAccountId);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.provider_key, binding.providerKey);
      assertEqual(payload.use_case, binding.useCase);
      return;
    }
    case "lane_isolation_policy":
    case "lane_execution_policy": {
      const payload = envelope.payload as LaneIsolationPolicyPayload | LaneExecutionPolicyPayload;
      const binding = expectation.binding as LanePolicyBinding;
      assertEqual(payload.provider_account_id, binding.providerAccountId);
      assertEqual(payload.entitlement_id, binding.entitlementId);
      assertEqual(payload.capacity_pool_id, binding.capacityPoolId);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.adapter_key, binding.adapterKey);
      assertEqual(payload.adapter_version, binding.adapterVersion);
      assertEqual(payload.access_transport, binding.accessTransport);
      return;
    }
    case "lane_health": {
      const payload = envelope.payload as LaneHealthPayload;
      const binding = expectation.binding as LaneHealthBinding;
      assertEqual(payload.provider_account_id, binding.providerAccountId);
      assertEqual(payload.entitlement_id, binding.entitlementId);
      assertEqual(payload.capacity_pool_id, binding.capacityPoolId);
      assertEqual(payload.owner_ref, binding.ownerRef);
      assertEqual(payload.adapter_key, binding.adapterKey);
      assertEqual(payload.adapter_version, binding.adapterVersion);
    }
  }
}

function deepFreeze<Type>(value: Type, seen = new Set<object>()): Type {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

/**
 * Verifies an immutable, canonical signed authority envelope against a trust root
 * selected by deployment configuration and the exact aggregate being promoted.
 */
export function verifyAuthorityEvidence<Type extends AuthorityEvidenceType>(
  source: Uint8Array,
  trust: AuthorityEvidenceTrustRoot,
  expectation: AuthorityEvidenceExpectation<Type>,
): AuthorityEvidenceEnvelope<Type> {
  const parsed = parseClosedJsonBytes(source);
  const canonical = Buffer.from(canonicalJson(parsed), "utf8");
  const supplied = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  if (!supplied.equals(canonical)) throw malformed();

  const envelope = validateEnvelope(parsed);
  assertTrust(envelope, trust);
  assertSignature(envelope, trust.publicKey);
  assertFreshness(envelope, expectation as AuthorityEvidenceExpectation);
  assertBinding(
    envelope as AuthorityEvidenceEnvelope<Type>,
    expectation,
  );
  return deepFreeze(envelope as AuthorityEvidenceEnvelope<Type>);
}

/**
 * Test-fixture helper only. Keep this internal module out of the package export map.
 * Production signers must live behind their separately authorized issuer service.
 */
export function signAuthorityEvidenceForTest<Type extends AuthorityEvidenceType>(
  input: AuthorityEvidenceDraft<Type>,
  privateKey: KeyObject,
): Uint8Array {
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw malformed();
  }
  const canonicalDraft = canonicalJson(input);
  const draft = validateDraft(parseClosedJson(canonicalDraft)) as AuthorityEvidenceDraft<Type>;
  const unsigned: Omit<AuthorityEvidenceEnvelope<Type>, "signature"> = {
    ...draft,
    payload_digest: canonicalSha256(draft.payload),
  };
  const signature = ed25519Sign(
    null,
    Buffer.from(canonicalJson(unsigned), "utf8"),
    privateKey,
  ).toString("base64url");
  return Buffer.from(canonicalJson({ ...unsigned, signature }), "utf8");
}
