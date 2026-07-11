import {
  SLOT_BROKERED_FIELDS_V1,
  SLOT_COMMON_FIELDS_V1,
  SLOT_ELIGIBILITY_MAX_LIFETIME_MS,
  SLOT_ELIGIBILITY_REASON_CODES_V1,
  SLOT_ELIGIBILITY_SCHEMA_DIGEST_V1,
  SLOT_ELIGIBILITY_SCHEMA_VERSION_V1,
  SLOT_NATIVE_FIELDS_V1,
  SLOT_RESOLVED_FIELDS_V1,
  SLOT_UNRESOLVED_FIELDS_V1,
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
import type {
  AccountsEvidenceSigner,
  AccountsEvidenceTrustV1,
  SlotEligibilityReasonCodeV1,
  SlotEligibilityPositiveV1,
  SlotEligibilityResolvedNegativeV1,
  SlotEligibilityResolvedV1,
  SlotEligibilityV1,
} from "./types";

type SlotNegativeState =
  | "BROKERED_RESOLVED_NEGATIVE"
  | "NATIVE_RESOLVED_NEGATIVE"
  | "UNRESOLVED_NEGATIVE";

const BOTH_RESOLVED = [
  "BROKERED_RESOLVED_NEGATIVE",
  "NATIVE_RESOLVED_NEGATIVE",
] as const;
const SLOT_REASON_POLICY: Readonly<
  Record<SlotEligibilityReasonCodeV1, readonly SlotNegativeState[]>
> = Object.freeze({
  ACCESS_METHOD_NOT_READY: ["UNRESOLVED_NEGATIVE"],
  ACCOUNT_NOT_ACTIVE: BOTH_RESOLVED,
  ATTESTATION_STALE: BOTH_RESOLVED,
  CAPACITY_EVIDENCE_STALE: BOTH_RESOLVED,
  CAPACITY_POOL_NOT_ACTIVE: BOTH_RESOLVED,
  CAPSULE_NOT_READY: ["NATIVE_RESOLVED_NEGATIVE"],
  CAPSULE_OWNER_MISMATCH: ["NATIVE_RESOLVED_NEGATIVE"],
  CAPSULE_PLACEMENT_INVALID: ["NATIVE_RESOLVED_NEGATIVE"],
  CAPSULE_REQUIRED: ["UNRESOLVED_NEGATIVE"],
  CREDENTIAL_BINDING_EXPIRED: ["BROKERED_RESOLVED_NEGATIVE"],
  CREDENTIAL_BINDING_NOT_ACTIVE: ["BROKERED_RESOLVED_NEGATIVE"],
  CREDENTIAL_BINDING_REQUIRED: ["UNRESOLVED_NEGATIVE"],
  CREDENTIAL_BINDING_RETIRING: ["BROKERED_RESOLVED_NEGATIVE"],
  CURRENT_DENY: BOTH_RESOLVED,
  DATA_CLASSIFICATION_NOT_ALLOWED: BOTH_RESOLVED,
  DEPENDENCY_UNAVAILABLE: ["UNRESOLVED_NEGATIVE"],
  DESTINATION_POLICY_NOT_ALLOWED: BOTH_RESOLVED,
  ENTITLEMENT_NOT_ACTIVE: BOTH_RESOLVED,
  GENERATION_MISMATCH: BOTH_RESOLVED,
  HEALTH_NOT_HEALTHY: BOTH_RESOLVED,
  HEALTH_STALE: BOTH_RESOLVED,
  INVALID_ACCESS_TARGET: ["UNRESOLVED_NEGATIVE"],
  MODEL_NOT_ALLOWED: BOTH_RESOLVED,
  OPERATION_NOT_ALLOWED: BOTH_RESOLVED,
  POLICY_DIGEST_MISMATCH: BOTH_RESOLVED,
  POLICY_EVIDENCE_STALE: BOTH_RESOLVED,
  RECOVERY_HOLD: ["UNRESOLVED_NEGATIVE"],
  TERMS_NOT_ALLOWED: BOTH_RESOLVED,
  TERMS_STALE: BOTH_RESOLVED,
});

const SLOT_REASON_SET = new Set<string>(SLOT_ELIGIBILITY_REASON_CODES_V1);
const DUMMY_SIGNATURE = Buffer.alloc(64).toString("base64url");
const STRING_EXCLUSIONS = new Set(["eligible", "reason_codes"]);
const RESOLVED_STRING_EXCLUSIONS = new Set([
  ...STRING_EXCLUSIONS,
  "access_target",
  "record_revision_set",
]);

function assertPolicyCoverage(): void {
  const registry = [...SLOT_ELIGIBILITY_REASON_CODES_V1].sort();
  const audited = Object.keys(SLOT_REASON_POLICY).sort();
  invariant(JSON.stringify(registry) === JSON.stringify(audited), "Slot reason policy is incomplete");
}
assertPolicyCoverage();

function reasonCodes(
  value: unknown,
  state: "POSITIVE" | SlotNegativeState,
): readonly SlotEligibilityReasonCodeV1[] {
  invariant(Array.isArray(value), "SlotEligibility reason_codes must be an array");
  invariant(
    value.every((reason) => typeof reason === "string" && SLOT_REASON_SET.has(reason)),
    "SlotEligibility reason_codes are not closed-registry strings",
  );
  invariant(new Set(value).size === value.length, "SlotEligibility reason_codes must be unique");
  invariant(
    JSON.stringify([...value].sort()) === JSON.stringify(value),
    "SlotEligibility reason_codes must be sorted",
  );
  if (state === "POSITIVE") {
    invariant(value.length === 0, "positive SlotEligibility must have no reasons");
  } else {
    invariant(value.length > 0, "negative SlotEligibility requires stable reasons");
    for (const reason of value as SlotEligibilityReasonCodeV1[]) {
      invariant(
        SLOT_REASON_POLICY[reason].includes(state),
        `SlotEligibility reason ${reason} is not permitted for ${state}`,
      );
    }
  }
  return value as SlotEligibilityReasonCodeV1[];
}

function slotTimes(
  wire: Record<string, unknown>,
  trust: NormalizedTrust | undefined,
): { readonly issuedAt: number; readonly expiresAt: number } {
  const issuedAt = timestampMs(wire.issued_at, "SlotEligibility.issued_at");
  const expiresAt = timestampMs(wire.expires_at, "SlotEligibility.expires_at");
  invariant(expiresAt > issuedAt, "SlotEligibility expiry must be after issuance");
  const maximumLifetime = trust?.slotMaximumLifetimeMs ?? SLOT_ELIGIBILITY_MAX_LIFETIME_MS;
  invariant(expiresAt - issuedAt <= maximumLifetime, "SlotEligibility lifetime is too long");
  if (trust !== undefined) {
    invariant(
      issuedAt <= trust.nowMs + trust.allowedClockSkewMs && trust.nowMs < expiresAt,
      "SlotEligibility is not valid at trusted now",
    );
    invariant(
      trust.nowMs - issuedAt <= trust.slotMaximumAgeMs + trust.allowedClockSkewMs,
      "SlotEligibility maximum age is exceeded",
    );
  }
  return { issuedAt, expiresAt };
}

function validateCommon(
  wire: Record<string, unknown>,
  state: "POSITIVE" | SlotNegativeState,
  trust: NormalizedTrust | undefined,
): { readonly expiresAt: number; readonly reasons: readonly SlotEligibilityReasonCodeV1[] } {
  invariant(
    wire.schema_version === SLOT_ELIGIBILITY_SCHEMA_VERSION_V1,
    "SlotEligibility schema/version mismatch",
  );
  invariant(
    wire.schema_digest === SLOT_ELIGIBILITY_SCHEMA_DIGEST_V1,
    "SlotEligibility descriptor digest mismatch",
  );
  assertAllStringFields(wire, SLOT_COMMON_FIELDS_V1, STRING_EXCLUSIONS, "SlotEligibility");
  uuidV7(wire.evidence_id, "SlotEligibility.evidence_id");
  uuidV7(wire.account_lane_id, "SlotEligibility.account_lane_id");
  sha256Digest(wire.schema_digest, "SlotEligibility.schema_digest");
  sha256Digest(wire.eligibility_request_digest, "SlotEligibility.eligibility_request_digest");
  assertSignatureShape(wire.signature);
  const times = slotTimes(wire, trust);
  const reasons = reasonCodes(wire.reason_codes, state);
  return { expiresAt: times.expiresAt, reasons };
}

function validateEvidenceIntervals(
  wire: Record<string, unknown>,
  slotExpiresAt: number,
  trust: NormalizedTrust | undefined,
  native: boolean,
): void {
  const intervals: [string, string][] = [
    ["accounts_attested_at", "accounts_attestation_expires_at"],
    ["capacity_evidence_issued_at", "capacity_evidence_expires_at"],
    ["ownership_evidence_issued_at", "ownership_evidence_expires_at"],
    ["terms_evidence_issued_at", "terms_evidence_expires_at"],
    ["execution_policy_evidence_issued_at", "execution_policy_evidence_expires_at"],
    ["data_policy_evidence_issued_at", "data_policy_evidence_expires_at"],
    ["isolation_policy_evidence_issued_at", "isolation_policy_evidence_expires_at"],
    ["health_evidence_issued_at", "health_evidence_expires_at"],
  ];
  if (native) {
    intervals.push(["capsule_attestation_issued_at", "capsule_attestation_expires_at"]);
  }
  for (const [issuedField, expiresField] of intervals) {
    const issuedAt = timestampMs(wire[issuedField], `SlotEligibility.${issuedField}`);
    const expiresAt = timestampMs(wire[expiresField], `SlotEligibility.${expiresField}`);
    invariant(issuedAt < expiresAt, `SlotEligibility ${issuedField}/${expiresField} is inverted`);
    invariant(slotExpiresAt <= expiresAt, `SlotEligibility outlives ${expiresField}`);
    if (trust !== undefined) {
      invariant(
        issuedAt <= trust.nowMs + trust.allowedClockSkewMs && trust.nowMs < expiresAt,
        `SlotEligibility bound evidence ${issuedField}/${expiresField} is not live`,
      );
    }
  }
}

function validateResolved(
  wire: Record<string, unknown>,
  state: "POSITIVE" | Exclude<SlotNegativeState, "UNRESOLVED_NEGATIVE">,
  native: boolean,
  trust: NormalizedTrust | undefined,
  slotExpiresAt: number,
  reasons: readonly SlotEligibilityReasonCodeV1[],
): void {
  assertAllStringFields(
    wire,
    native ? SLOT_NATIVE_FIELDS_V1 : SLOT_BROKERED_FIELDS_V1,
    RESOLVED_STRING_EXCLUSIONS,
    "SlotEligibility",
  );
  if (trust?.expectedEffectNamespaceId !== undefined) {
    invariant(
      wire.effect_namespace_id === trust.expectedEffectNamespaceId,
      "SlotEligibility effect_namespace_id does not match configured trust",
    );
  }
  uuidV7(wire.provider_account_id, "SlotEligibility.provider_account_id");
  uuidV7(wire.entitlement_id, "SlotEligibility.entitlement_id");
  uuidV7(wire.capacity_pool_id, "SlotEligibility.capacity_pool_id");
  uuidV7(wire.credential_family_id, "SlotEligibility.credential_family_id");
  validateEvidenceIntervals(wire, slotExpiresAt, trust, native);

  const accessTarget = record(wire.access_target, "SlotEligibility.access_target");
  let revisionFields: readonly string[];
  if (native) {
    invariant(
      wire.access_transport === "native_session" &&
        wire.allowed_channel_class === "capsule_remote_tool",
      "native SlotEligibility transport/channel mismatch",
    );
    requiredKeys(accessTarget, [
      "kind",
      "auth_capsule_id",
      "canonical_node_id",
      "node_key_thumbprint",
      "node_generation",
      "placement_generation",
      "auth_generation",
      "auth_state_revision",
    ], "SlotEligibility native access_target");
    invariant(accessTarget.kind === "native", "native SlotEligibility target kind mismatch");
    uuidV7(accessTarget.auth_capsule_id, "SlotEligibility.access_target.auth_capsule_id");
    uuidV7(accessTarget.canonical_node_id, "SlotEligibility.access_target.canonical_node_id");
    sha256Digest(accessTarget.node_key_thumbprint, "SlotEligibility.access_target.node_key_thumbprint");
    for (const field of [
      "node_generation",
      "placement_generation",
      "auth_generation",
      "auth_state_revision",
    ]) {
      positiveCounter(accessTarget[field], `SlotEligibility.access_target.${field}`);
    }
    revisionFields = [
      "provider_account",
      "entitlement",
      "capacity_pool",
      "account_lane",
      "auth_capsule",
    ];
  } else {
    invariant(
      (wire.access_transport === "api_key" || wire.access_transport === "workload_identity") &&
        wire.allowed_channel_class === "brokered_provider_proxy",
      "brokered SlotEligibility transport/channel mismatch",
    );
    requiredKeys(accessTarget, [
      "kind",
      "credential_binding_id",
      "broker_ref",
      "resolver",
    ], "SlotEligibility brokered access_target");
    invariant(accessTarget.kind === "brokered", "brokered SlotEligibility target kind mismatch");
    uuidV7(
      accessTarget.credential_binding_id,
      "SlotEligibility.access_target.credential_binding_id",
    );
    nonemptyString(accessTarget.broker_ref, "SlotEligibility.access_target.broker_ref");
    const expectedResolver = wire.access_transport === "api_key"
      ? "brokered_secret"
      : "workload_identity";
    invariant(
      accessTarget.resolver === expectedResolver,
      "brokered SlotEligibility resolver does not match access_transport",
    );
    revisionFields = [
      "provider_account",
      "entitlement",
      "capacity_pool",
      "account_lane",
      "credential_binding",
    ];
  }

  const revisionSet = record(wire.record_revision_set, "SlotEligibility.record_revision_set");
  requiredKeys(revisionSet, revisionFields, "SlotEligibility.record_revision_set");
  for (const field of revisionFields) {
    counter(revisionSet[field], `SlotEligibility.record_revision_set.${field}`);
  }
  invariant(
    wire.accounts_revision_set_digest === canonicalDigest({
      record_revision_set: revisionSet,
      schema_version: "accounts.record-revision-set.v1",
    }),
    "SlotEligibility accounts_revision_set_digest consequence mismatch",
  );
  invariant(
    wire.serialization_key_digest === canonicalDigest({
      capacity_domain_ref: wire.capacity_domain_ref,
      capacity_pool_id: wire.capacity_pool_id,
      effect_namespace_id: wire.effect_namespace_id,
      owner_ref: wire.owner_ref,
      provider_account_id: wire.provider_account_id,
      schema_version: "accounts.serialization-domain.v1",
      serialization_key: wire.serialization_key,
    }),
    "SlotEligibility serialization_key_digest consequence mismatch",
  );
  invariant(
    wire.capacity_evidence_version === "accounts.authority-evidence.v1",
    "SlotEligibility capacity_evidence_version mismatch",
  );
  invariant(
    wire.capacity_evidence_digest === canonicalDigest({
      capacity_domain_ref: wire.capacity_domain_ref,
      decision: "allowed",
      max_concurrency: wire.max_concurrency,
      owner_ref: wire.owner_ref,
      policy_version: wire.capacity_policy_version,
      provider_account_id: wire.provider_account_id,
      provider_key: wire.provider_key,
      serialization_key: wire.serialization_key,
    }),
    "SlotEligibility capacity_evidence_digest consequence mismatch",
  );

  positiveCounter(wire.max_concurrency, "SlotEligibility.max_concurrency");
  counter(wire.recovery_frontier_sequence, "SlotEligibility.recovery_frontier_sequence");
  counter(wire.capacity_generation, "SlotEligibility.capacity_generation");
  const denyGeneration = counter(wire.deny_generation, "SlotEligibility.deny_generation");
  counter(wire.credential_generation, "SlotEligibility.credential_generation");
  positiveCounter(
    wire.capacity_evidence_generation,
    "SlotEligibility.capacity_evidence_generation",
  );
  positiveCounter(wire.ownership_generation, "SlotEligibility.ownership_generation");

  if (state === "POSITIVE") {
    invariant(wire.eligible === true && wire.deny_state === "allowed", "positive SlotEligibility is contradictory");
  } else {
    invariant(wire.eligible === false, "negative SlotEligibility is contradictory");
    invariant(wire.deny_state === "allowed" || wire.deny_state === "denied", "SlotEligibility deny_state is invalid");
    invariant(
      (wire.deny_state === "denied") === reasons.includes("CURRENT_DENY"),
      "SlotEligibility CURRENT_DENY reason and deny_state disagree",
    );
    if (reasons.includes("CURRENT_DENY") && trust?.previousSlotEligibility !== undefined) {
      const previous = trust.previousSlotEligibility;
      invariant(
        isResolvedSlotEligibilityV1(previous),
        "previous SlotEligibility must be resolved",
      );
      invariant(
        BigInt(denyGeneration) > BigInt(previous.deny_generation),
        "current deny must advance deny_generation",
      );
      invariant(
        wire.accounts_revision_set_digest !== previous.accounts_revision_set_digest,
        "current deny must change accounts_revision_set_digest",
      );
    }
  }
  assertAllDigestFields(wire, "SlotEligibility");
}

function validateSlotRecord(
  wire: Record<string, unknown>,
  trust: NormalizedTrust | undefined,
  verifySignature: boolean,
): SlotEligibilityV1 {
  const unresolved = Object.hasOwn(wire, "rejection_stage");
  const accessTarget = unresolved ? undefined : record(wire.access_target, "SlotEligibility.access_target");
  const native = accessTarget?.kind === "native";
  const brokered = accessTarget?.kind === "brokered";
  invariant(unresolved || native || brokered, "SlotEligibility target variant is unresolved or mixed");

  let state: "POSITIVE" | SlotNegativeState;
  if (wire.eligible === true) {
    invariant(!unresolved, "positive SlotEligibility cannot be unresolved");
    state = "POSITIVE";
  } else {
    invariant(wire.eligible === false, "SlotEligibility eligible must be boolean");
    state = unresolved
      ? "UNRESOLVED_NEGATIVE"
      : native
        ? "NATIVE_RESOLVED_NEGATIVE"
        : "BROKERED_RESOLVED_NEGATIVE";
  }
  const fields = unresolved
    ? SLOT_UNRESOLVED_FIELDS_V1
    : native
      ? SLOT_NATIVE_FIELDS_V1
      : SLOT_BROKERED_FIELDS_V1;
  requiredKeys(wire, fields, "SlotEligibility wire");
  const common = validateCommon(wire, state, trust);
  if (unresolved) {
    invariant(wire.rejection_stage === "unresolved", "unresolved SlotEligibility rejection_stage mismatch");
  } else {
    validateResolved(
      wire,
      state as "POSITIVE" | Exclude<SlotNegativeState, "UNRESOLVED_NEGATIVE">,
      native,
      trust,
      common.expiresAt,
      common.reasons,
    );
  }
  if (verifySignature) {
    invariant(trust !== undefined, "signature verification requires trust");
    verifyEvidenceSignature(wire, trust, trust.slotMaximumLifetimeMs);
  }
  return wire as unknown as SlotEligibilityV1;
}

export function parseSlotEligibilityV1(
  source: Uint8Array,
  options: AccountsEvidenceTrustV1,
): SlotEligibilityV1 {
  const trust = normalizeTrust(options);
  return validateSlotRecord(parseCanonicalWireBytes(source, "SlotEligibility"), trust, true);
}

export function encodeSlotEligibilityV1(value: SlotEligibilityV1): Uint8Array {
  const wire = cloneWire(value, "SlotEligibility");
  validateSlotRecord(wire, undefined, false);
  return canonicalBytes(wire);
}

export function slotEligibilitySigningBytesV1(value: SlotEligibilityV1): Uint8Array {
  const wire = cloneWire(value, "SlotEligibility");
  validateSlotRecord(wire, undefined, false);
  const unsigned = { ...wire };
  delete unsigned.signature;
  return canonicalBytes(unsigned);
}

export function signSlotEligibilityV1(
  draft: Readonly<Record<string, unknown>>,
  signer: AccountsEvidenceSigner,
): Uint8Array {
  const unsigned = cloneWire(draft, "SlotEligibility signing draft");
  invariant(!Object.hasOwn(unsigned, "signature"), "SlotEligibility signing draft already has signature");
  invariant(
    unsigned.issuer === signer.issuer &&
      unsigned.issuer_incarnation === signer.issuerIncarnation &&
      unsigned.audience === signer.audience &&
      unsigned.key_id === signer.keyId,
    "SlotEligibility signing identity does not match signer",
  );
  const candidate = { ...unsigned, signature: DUMMY_SIGNATURE };
  validateSlotRecord(candidate, undefined, false);
  const signature = signEvidenceBytes(unsigned, signer.privateKey);
  return canonicalBytes({ ...unsigned, signature: Buffer.from(signature).toString("base64url") });
}

export function isResolvedSlotEligibilityV1(
  value: SlotEligibilityV1,
): value is SlotEligibilityPositiveV1 | SlotEligibilityResolvedNegativeV1 {
  return Object.hasOwn(value, "access_target");
}
