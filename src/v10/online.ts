import { AccountsError } from "../errors";
import {
  ONLINE_BASE_FIELDS_V1,
  ONLINE_BROKERED_FIELDS_V1,
  ONLINE_GENERATION_CHECK_MAX_LIFETIME_MS,
  ONLINE_GENERATION_CHECK_REASON_CODES_V1,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_DIGEST_V1,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1,
  ONLINE_NATIVE_FIELDS_V1,
  PROVIDER_DESTINATION_POLICY_FIELDS_V1,
} from "./constants";
import {
  assertAllDigestFields,
  assertAllStringFields,
  assertSignatureShape,
  canonicalBytes,
  canonicalDigest,
  cloneWire,
  counter,
  invariant,
  nonemptyString,
  normalizeTrust,
  parseCanonicalWireBytes,
  positiveCounter,
  record,
  requiredKeys,
  sha256Digest,
  signEvidenceBytes,
  timestampMs,
  uuidV7,
  verifyEvidenceSignature,
  type NormalizedTrust,
} from "./primitives";
import { isResolvedSlotEligibilityV1 } from "./slot";
import type {
  AccountsEvidenceSigner,
  AccountsEvidenceTrustV1,
  AllowedOnlineGenerationCheckReceiptV1,
  OnlineGenerationCheckReasonCodeV1,
  OnlineGenerationCheckReceiptV1,
  SlotEligibilityPositiveV1,
  SlotEligibilityResolvedNegativeV1,
} from "./types";

type OnlineDecisionState =
  | "POSITIVE"
  | "DENIED"
  | "UNRESOLVED"
  | "EXHAUSTED"
  | "EXPIRED_FENCE";
type OnlineTarget = "brokered" | "native";

const DENIED_ONLY = ["DENIED"] as const;
const ANY_TARGET = ["brokered", "native"] as const;
const ONLINE_REASON_STATES: Readonly<
  Record<OnlineGenerationCheckReasonCodeV1, readonly OnlineDecisionState[]>
> = Object.freeze({
  ACCESS_METHOD_NOT_READY: DENIED_ONLY,
  ACCOUNT_NOT_ACTIVE: DENIED_ONLY,
  ATTESTATION_STALE: DENIED_ONLY,
  CAPACITY_EVIDENCE_STALE: DENIED_ONLY,
  CAPACITY_POOL_NOT_ACTIVE: DENIED_ONLY,
  CAPSULE_NOT_READY: DENIED_ONLY,
  CAPSULE_OWNER_MISMATCH: DENIED_ONLY,
  CAPSULE_PLACEMENT_INVALID: DENIED_ONLY,
  CAPSULE_REQUIRED: DENIED_ONLY,
  CREDENTIAL_BINDING_EXPIRED: DENIED_ONLY,
  CREDENTIAL_BINDING_NOT_ACTIVE: DENIED_ONLY,
  CREDENTIAL_BINDING_REQUIRED: DENIED_ONLY,
  CREDENTIAL_BINDING_RETIRING: DENIED_ONLY,
  CURRENT_DENY: DENIED_ONLY,
  DATA_CLASSIFICATION_NOT_ALLOWED: DENIED_ONLY,
  DEPENDENCY_UNAVAILABLE: ["DENIED", "UNRESOLVED"],
  DESTINATION_POLICY_NOT_ALLOWED: DENIED_ONLY,
  ENTITLEMENT_NOT_ACTIVE: DENIED_ONLY,
  GENERATION_MISMATCH: DENIED_ONLY,
  HEALTH_NOT_HEALTHY: DENIED_ONLY,
  HEALTH_STALE: DENIED_ONLY,
  INVALID_ACCESS_TARGET: DENIED_ONLY,
  MODEL_NOT_ALLOWED: DENIED_ONLY,
  OPERATION_NOT_ALLOWED: ["DENIED", "EXPIRED_FENCE"],
  POLICY_DIGEST_MISMATCH: DENIED_ONLY,
  POLICY_EVIDENCE_STALE: DENIED_ONLY,
  RECOVERY_HOLD: ["DENIED", "UNRESOLVED"],
  TERMS_NOT_ALLOWED: DENIED_ONLY,
  TERMS_STALE: DENIED_ONLY,
  USE_LIMIT_REACHED: ["EXHAUSTED"],
});
const ONLINE_REASON_TARGETS: Readonly<
  Record<OnlineGenerationCheckReasonCodeV1, readonly OnlineTarget[]>
> = Object.freeze({
  ACCESS_METHOD_NOT_READY: ANY_TARGET,
  ACCOUNT_NOT_ACTIVE: ANY_TARGET,
  ATTESTATION_STALE: ANY_TARGET,
  CAPACITY_EVIDENCE_STALE: ANY_TARGET,
  CAPACITY_POOL_NOT_ACTIVE: ANY_TARGET,
  CAPSULE_NOT_READY: ["native"],
  CAPSULE_OWNER_MISMATCH: ["native"],
  CAPSULE_PLACEMENT_INVALID: ["native"],
  CAPSULE_REQUIRED: ["native"],
  CREDENTIAL_BINDING_EXPIRED: ["brokered"],
  CREDENTIAL_BINDING_NOT_ACTIVE: ["brokered"],
  CREDENTIAL_BINDING_REQUIRED: ["brokered"],
  CREDENTIAL_BINDING_RETIRING: ["brokered"],
  CURRENT_DENY: ANY_TARGET,
  DATA_CLASSIFICATION_NOT_ALLOWED: ANY_TARGET,
  DEPENDENCY_UNAVAILABLE: ANY_TARGET,
  DESTINATION_POLICY_NOT_ALLOWED: ANY_TARGET,
  ENTITLEMENT_NOT_ACTIVE: ANY_TARGET,
  GENERATION_MISMATCH: ANY_TARGET,
  HEALTH_NOT_HEALTHY: ANY_TARGET,
  HEALTH_STALE: ANY_TARGET,
  INVALID_ACCESS_TARGET: ANY_TARGET,
  MODEL_NOT_ALLOWED: ANY_TARGET,
  OPERATION_NOT_ALLOWED: ANY_TARGET,
  POLICY_DIGEST_MISMATCH: ANY_TARGET,
  POLICY_EVIDENCE_STALE: ANY_TARGET,
  RECOVERY_HOLD: ANY_TARGET,
  TERMS_NOT_ALLOWED: ANY_TARGET,
  TERMS_STALE: ANY_TARGET,
  USE_LIMIT_REACHED: ANY_TARGET,
});

const ONLINE_REASON_SET = new Set<string>(ONLINE_GENERATION_CHECK_REASON_CODES_V1);
const DUMMY_SIGNATURE = Buffer.alloc(64).toString("base64url");
const STRING_EXCLUSIONS = new Set([
  "allowed",
  "reason_codes",
  "provider_destination_policy",
  "current_deny",
]);

function assertPolicyCoverage(): void {
  const registry = [...ONLINE_GENERATION_CHECK_REASON_CODES_V1].sort();
  invariant(
    JSON.stringify(registry) === JSON.stringify(Object.keys(ONLINE_REASON_STATES).sort()),
    "online reason-state policy is incomplete",
  );
  invariant(
    JSON.stringify(registry) === JSON.stringify(Object.keys(ONLINE_REASON_TARGETS).sort()),
    "online reason-target policy is incomplete",
  );
}
assertPolicyCoverage();

function onlineReasons(
  value: unknown,
  state: OnlineDecisionState,
  target: OnlineTarget,
): readonly OnlineGenerationCheckReasonCodeV1[] {
  invariant(Array.isArray(value), "online-check reason_codes must be an array");
  invariant(
    value.every((reason) => typeof reason === "string" && ONLINE_REASON_SET.has(reason)),
    "online-check reason_codes are not closed-registry strings",
  );
  invariant(new Set(value).size === value.length, "online-check reason_codes must be unique");
  invariant(
    JSON.stringify([...value].sort()) === JSON.stringify(value),
    "online-check reason_codes must be sorted",
  );
  if (state === "POSITIVE") {
    invariant(value.length === 0, "positive online-check must have no reasons");
  } else {
    invariant(value.length > 0, "negative online-check requires stable reasons");
    for (const reason of value as OnlineGenerationCheckReasonCodeV1[]) {
      invariant(
        ONLINE_REASON_STATES[reason].includes(state),
        `online-check reason ${reason} is not permitted for ${state}`,
      );
      invariant(
        ONLINE_REASON_TARGETS[reason].includes(target),
        `online-check reason ${reason} is not permitted for ${target}`,
      );
    }
  }
  return value as OnlineGenerationCheckReasonCodeV1[];
}

function decisionState(wire: Record<string, unknown>): OnlineDecisionState {
  invariant(typeof wire.allowed === "boolean", "online-check allowed must be boolean");
  if (wire.allowed) return "POSITIVE";
  if (wire.deny_state === "denied") return "DENIED";
  if (wire.use_count === "1") return "EXHAUSTED";
  if (
    Array.isArray(wire.reason_codes) &&
    wire.reason_codes.length === 1 &&
    wire.reason_codes[0] === "OPERATION_NOT_ALLOWED"
  ) {
    return "EXPIRED_FENCE";
  }
  return "UNRESOLVED";
}

function validateTimes(
  wire: Record<string, unknown>,
  state: OnlineDecisionState,
  trust: NormalizedTrust | undefined,
): void {
  const issuedAt = timestampMs(wire.issued_at, "online-check.issued_at");
  const notBefore = timestampMs(wire.not_before, "online-check.not_before");
  const expiresAt = timestampMs(wire.expires_at, "online-check.expires_at");
  const leaseExpiresAt = timestampMs(wire.lease_expires_at, "online-check.lease_expires_at");
  const operationExpiresAt = timestampMs(
    wire.operation_execution_expires_at,
    "online-check.operation_execution_expires_at",
  );
  invariant(issuedAt < expiresAt && notBefore < expiresAt, "online-check time interval is inverted");
  const maximumLifetime = trust?.onlineMaximumLifetimeMs ?? ONLINE_GENERATION_CHECK_MAX_LIFETIME_MS;
  invariant(expiresAt - issuedAt <= maximumLifetime, "online-check lifetime is too long");
  if (trust === undefined) return;
  invariant(
    issuedAt <= trust.nowMs + trust.allowedClockSkewMs &&
      notBefore <= trust.nowMs + trust.allowedClockSkewMs &&
      trust.nowMs < expiresAt,
    "online-check receipt is not valid at trusted now",
  );
  invariant(
    trust.nowMs - issuedAt <= trust.onlineMaximumAgeMs + trust.allowedClockSkewMs,
    "online-check maximum age is exceeded",
  );
  if (state === "POSITIVE") {
    invariant(
      trust.nowMs < leaseExpiresAt && trust.nowMs < operationExpiresAt,
      "positive online-check binds an expired fence",
    );
    invariant(
      expiresAt <= leaseExpiresAt && expiresAt <= operationExpiresAt,
      "online-check outlives a bound fence",
    );
  } else if (state === "EXPIRED_FENCE") {
    invariant(
      leaseExpiresAt <= trust.nowMs || operationExpiresAt <= trust.nowMs,
      "expired-fence online-check does not bind an expired fence",
    );
  }
}

function validateDecision(
  wire: Record<string, unknown>,
  state: OnlineDecisionState,
  reasons: readonly OnlineGenerationCheckReasonCodeV1[],
): void {
  invariant(wire.max_uses === "1", "online-check max_uses must be 1");
  invariant(wire.use_count === "0" || wire.use_count === "1", "online-check use_count is invalid");
  if (state === "POSITIVE") {
    invariant(
      wire.allowed === true &&
        wire.deny_state === "allowed" &&
        !Object.hasOwn(wire, "current_deny") &&
        wire.use_count === "0" &&
        reasons.length === 0,
      "positive online-check is contradictory",
    );
  } else if (state === "DENIED") {
    invariant(
      wire.allowed === false &&
        wire.deny_state === "denied" &&
        wire.current_deny === true &&
        wire.use_count === "0" &&
        reasons.includes("CURRENT_DENY"),
      "denied online-check is contradictory",
    );
  } else if (state === "EXHAUSTED") {
    invariant(
      wire.allowed === false &&
        wire.deny_state === "allowed" &&
        !Object.hasOwn(wire, "current_deny") &&
        wire.use_count === "1" &&
        reasons.length === 1 &&
        reasons[0] === "USE_LIMIT_REACHED",
      "exhausted online-check is contradictory",
    );
  } else if (state === "EXPIRED_FENCE") {
    invariant(
      wire.allowed === false &&
        wire.deny_state === "allowed" &&
        !Object.hasOwn(wire, "current_deny") &&
        wire.use_count === "0" &&
        reasons.length === 1 &&
        reasons[0] === "OPERATION_NOT_ALLOWED",
      "expired-fence online-check is contradictory",
    );
  } else {
    invariant(
      wire.allowed === false &&
        wire.deny_state === "allowed" &&
        !Object.hasOwn(wire, "current_deny") &&
        wire.use_count === "0" &&
        reasons.length > 0,
      "unresolved online-check is contradictory",
    );
  }
}

function validateTarget(wire: Record<string, unknown>, target: OnlineTarget): void {
  if (target === "native") {
    invariant(
      wire.access_transport === "native_session" &&
        wire.allowed_channel_class === "capsule_remote_tool",
      "native online-check transport/channel mismatch",
    );
    uuidV7(wire.auth_capsule_id, "online-check.auth_capsule_id");
    uuidV7(wire.canonical_node_id, "online-check.canonical_node_id");
    sha256Digest(wire.node_key_thumbprint, "online-check.node_key_thumbprint");
    for (const field of [
      "node_generation",
      "placement_generation",
      "auth_generation",
      "auth_state_revision",
    ]) {
      positiveCounter(wire[field], `online-check.${field}`);
    }
  } else {
    invariant(
      (wire.access_transport === "api_key" || wire.access_transport === "workload_identity") &&
        wire.allowed_channel_class === "brokered_provider_proxy",
      "brokered online-check transport/channel mismatch",
    );
    uuidV7(wire.credential_binding_id, "online-check.credential_binding_id");
    nonemptyString(wire.broker_ref, "online-check.broker_ref");
  }
}

function validateExpectedSlot(
  wire: Record<string, unknown>,
  state: OnlineDecisionState,
  target: OnlineTarget,
  slot: SlotEligibilityPositiveV1 | SlotEligibilityResolvedNegativeV1,
): void {
  for (const field of [
    "effect_namespace_id",
    "access_transport",
    "allowed_channel_class",
    "provider_account_id",
    "account_lane_id",
    "capacity_pool_id",
    "capacity_domain_ref",
    "serialization_key",
    "serialization_key_digest",
    "credential_family_id",
    "capacity_generation",
    "credential_generation",
    "catalog_incarnation",
  ]) {
    invariant(wire[field] === slot[field], `online-check ${field} differs from SlotEligibility`);
  }
  const accessTarget = slot.access_target;
  if (target === "native") {
    invariant(accessTarget.kind === "native", "online-check target kind differs from SlotEligibility");
    for (const field of [
      "auth_capsule_id",
      "canonical_node_id",
      "node_key_thumbprint",
      "node_generation",
      "placement_generation",
      "auth_generation",
      "auth_state_revision",
    ]) {
      invariant(wire[field] === accessTarget[field], `online-check ${field} differs from SlotEligibility`);
    }
  } else {
    invariant(accessTarget.kind === "brokered", "online-check target kind differs from SlotEligibility");
    invariant(
      wire.credential_binding_id === accessTarget.credential_binding_id &&
        wire.broker_ref === accessTarget.broker_ref,
      "online-check brokered target differs from SlotEligibility",
    );
  }
  if (state === "DENIED") {
    invariant(
      BigInt(counter(wire.deny_generation, "online-check.deny_generation")) >
        BigInt(slot.deny_generation),
      "online-check current deny must advance deny_generation",
    );
    invariant(
      wire.accounts_revision_set_digest !== slot.accounts_revision_set_digest,
      "online-check current deny must change accounts_revision_set_digest",
    );
  } else {
    invariant(wire.deny_generation === slot.deny_generation, "online-check deny_generation differs from SlotEligibility");
    invariant(
      wire.accounts_revision_set_digest === slot.accounts_revision_set_digest,
      "online-check accounts_revision_set_digest differs from SlotEligibility",
    );
  }
  invariant(
    wire.recovery_frontier_sequence === slot.recovery_frontier_sequence &&
      wire.recovery_frontier_hash === slot.recovery_frontier_hash,
    "online-check recovery frontier is stale or forked",
  );
  invariant(
    wire.slot_eligibility_digest === canonicalDigest(slot),
    "online-check SlotEligibility digest binding mismatch",
  );
}

function validateOnlineRecord(
  wire: Record<string, unknown>,
  trust: NormalizedTrust | undefined,
  verifySignature: boolean,
): OnlineGenerationCheckReceiptV1 {
  invariant(
    wire.schema_version === ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1,
    "online-check schema/version mismatch",
  );
  invariant(
    wire.schema_digest === ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_DIGEST_V1,
    "online-check descriptor digest mismatch",
  );
  const target: OnlineTarget = wire.access_transport === "native_session" ? "native" : "brokered";
  const state = decisionState(wire);
  const fields = [
    ...(target === "native" ? ONLINE_NATIVE_FIELDS_V1 : ONLINE_BROKERED_FIELDS_V1),
    ...(state === "DENIED" ? ["current_deny"] : []),
  ];
  requiredKeys(wire, fields, "online-check wire");
  assertAllStringFields(wire, fields, STRING_EXCLUSIONS, "online-check");
  assertSignatureShape(wire.signature);
  uuidV7(wire.receipt_id, "online-check.receipt_id");
  uuidV7(wire.provider_account_id, "online-check.provider_account_id");
  uuidV7(wire.account_lane_id, "online-check.account_lane_id");
  uuidV7(wire.capacity_pool_id, "online-check.capacity_pool_id");
  uuidV7(wire.credential_family_id, "online-check.credential_family_id");
  validateTarget(wire, target);

  const reasons = onlineReasons(wire.reason_codes, state, target);
  validateDecision(wire, state, reasons);
  invariant(
    wire.approval_mode === "NOT_REQUIRED" || wire.approval_mode === "REQUIRED",
    "online-check approval_mode is invalid",
  );
  validateTimes(wire, state, trust);
  for (const field of [
    "authority_epoch",
    "route_epoch",
    "lease_epoch",
    "resource_lifecycle_generation",
    "operation_execution_epoch",
  ]) {
    positiveCounter(wire[field], `online-check.${field}`);
  }
  counter(wire.capacity_generation, "online-check.capacity_generation");
  counter(wire.deny_generation, "online-check.deny_generation");
  counter(wire.credential_generation, "online-check.credential_generation");
  counter(wire.recovery_frontier_sequence, "online-check.recovery_frontier_sequence");

  if (trust?.expectedEffectNamespaceId !== undefined) {
    invariant(
      wire.effect_namespace_id === trust.expectedEffectNamespaceId,
      "online-check effect_namespace_id does not match configured trust",
    );
  }
  const destination = record(
    wire.provider_destination_policy,
    "online-check.provider_destination_policy",
  );
  requiredKeys(
    destination,
    PROVIDER_DESTINATION_POLICY_FIELDS_V1,
    "online-check.provider_destination_policy",
  );
  assertAllStringFields(
    destination,
    PROVIDER_DESTINATION_POLICY_FIELDS_V1,
    new Set(),
    "online-check.provider_destination_policy",
  );
  sha256Digest(
    destination.request_body_digest,
    "online-check.provider_destination_policy.request_body_digest",
  );
  sha256Digest(
    destination.egress_policy_digest,
    "online-check.provider_destination_policy.egress_policy_digest",
  );
  invariant(
    wire.provider_destination_policy_digest === canonicalDigest(destination),
    "online-check provider_destination_policy_digest consequence mismatch",
  );
  assertAllDigestFields(wire, "online-check");

  if (trust?.expectedSlotEligibility !== undefined) {
    invariant(
      isResolvedSlotEligibilityV1(trust.expectedSlotEligibility),
      "expected SlotEligibility must be resolved",
    );
    validateExpectedSlot(wire, state, target, trust.expectedSlotEligibility);
  }
  if (verifySignature) {
    invariant(trust !== undefined, "signature verification requires trust");
    verifyEvidenceSignature(wire, trust, trust.onlineMaximumLifetimeMs);
  }
  return wire as unknown as OnlineGenerationCheckReceiptV1;
}

export function parseOnlineGenerationCheckReceiptV1(
  source: Uint8Array,
  options: AccountsEvidenceTrustV1,
): OnlineGenerationCheckReceiptV1 {
  const trust = normalizeTrust(options);
  return validateOnlineRecord(parseCanonicalWireBytes(source, "online-check"), trust, true);
}

export function encodeOnlineGenerationCheckReceiptV1(
  value: OnlineGenerationCheckReceiptV1,
): Uint8Array {
  const wire = cloneWire(value, "online-check");
  validateOnlineRecord(wire, undefined, false);
  return canonicalBytes(wire);
}

export function onlineGenerationCheckReceiptSigningBytesV1(
  value: OnlineGenerationCheckReceiptV1,
): Uint8Array {
  const wire = cloneWire(value, "online-check");
  validateOnlineRecord(wire, undefined, false);
  const unsigned = { ...wire };
  delete unsigned.signature;
  return canonicalBytes(unsigned);
}

export function signOnlineGenerationCheckReceiptV1(
  draft: Readonly<Record<string, unknown>>,
  signer: AccountsEvidenceSigner,
): Uint8Array {
  const unsigned = cloneWire(draft, "online-check signing draft");
  invariant(!Object.hasOwn(unsigned, "signature"), "online-check signing draft already has signature");
  invariant(
    unsigned.issuer === signer.issuer &&
      unsigned.issuer_incarnation === signer.issuerIncarnation &&
      unsigned.audience === signer.audience &&
      unsigned.key_id === signer.keyId,
    "online-check signing identity does not match signer",
  );
  const candidate = { ...unsigned, signature: DUMMY_SIGNATURE };
  validateOnlineRecord(candidate, undefined, false);
  const signature = signEvidenceBytes(unsigned, signer.privateKey);
  return canonicalBytes({ ...unsigned, signature: Buffer.from(signature).toString("base64url") });
}

export function requireAllowedOnlineGenerationCheckReceiptV1(
  value: OnlineGenerationCheckReceiptV1,
): AllowedOnlineGenerationCheckReceiptV1 {
  if (!value.allowed) {
    throw new AccountsError("CURRENT_DENY", "Online generation is not allowed");
  }
  return value;
}
