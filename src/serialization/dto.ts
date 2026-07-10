import { AccountsError } from "../errors";
import { parseCounter } from "../domain/counter";
import {
  parseAccessMethodId,
  parseAccountId,
  parseAuthCapsuleId,
  parseCanonicalNodeId,
  parseCapacityPoolId,
  parseCredentialBindingId,
  parseEligibilityEvidenceId,
  parseEntitlementId,
} from "../domain/ids";
import {
  ACCOUNTS_CAPACITY_SCHEMA_VERSION,
  ELIGIBILITY_REASON_CODES,
  type Account,
  type AccessMethod,
  type AuthCapsule,
  type CapacityPool,
  type CredentialBinding,
  type EntityKind,
  type EntityMap,
  type Entitlement,
  type EligibilityRequest,
  type SlotEligibilityMetadata,
} from "../domain/models";
import {
  assertNoSensitiveFields,
  canonicalJson,
  parseClosedJson,
} from "./json";

const ENTITY_KINDS = [
  "account",
  "entitlement",
  "capacity_pool",
  "access_method",
  "auth_capsule",
  "credential_binding",
] as const satisfies readonly EntityKind[];

const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const KEY_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const KEYED_DIGEST_PATTERN = /^hmac-sha256:[0-9a-f]{64}$/;
const OWNER_PATTERN = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

type JsonObject = Record<string, unknown>;

function object(value: unknown, field: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(field);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid(field);
  return value as JsonObject;
}

function exactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
  field = "data",
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw invalid(`${field}.${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw invalid(`${field}.${key}`);
  }
}

function invalid(field: string): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "DTO validation failed", {
    details: { field: field.replace(/[^A-Za-z0-9_.]/g, "_").slice(0, 64) },
  });
}

function string(
  value: unknown,
  field: string,
  options: { min?: number; max?: number; pattern?: RegExp } = {},
): string {
  if (typeof value !== "string") throw invalid(field);
  const min = options.min ?? 1;
  const max = options.max ?? 255;
  if (value.length < min || value.length > max || value.trim() !== value) throw invalid(field);
  if (options.pattern !== undefined && !options.pattern.test(value)) throw invalid(field);
  return value;
}

function enumValue<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  field: string,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) throw invalid(field);
  return value as T[number];
}

function timestamp(value: unknown, field: string): string {
  const parsed = string(value, field, { pattern: TIMESTAMP_PATTERN });
  const time = Date.parse(parsed);
  if (Number.isNaN(time) || new Date(time).toISOString() !== parsed) throw invalid(field);
  return parsed;
}

function ordered(before: unknown, after: unknown, field: string): void {
  if (Date.parse(before as string) >= Date.parse(after as string)) throw invalid(field);
}

function digest(value: unknown, field: string): string {
  return string(value, field, { pattern: DIGEST_PATTERN, max: 71 });
}

function keyedDigest(value: unknown, field: string): string {
  return string(value, field, { pattern: KEYED_DIGEST_PATTERN, max: 76 });
}

function reference(value: unknown, field: string): string {
  return string(value, field, { pattern: REF_PATTERN });
}

function owner(value: unknown, field: string): string {
  return string(value, field, { pattern: OWNER_PATTERN, max: 160 });
}

function stringList(value: unknown, field: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 128) throw invalid(field);
  const result = value.map((item, index) =>
    string(item, `${field}.${index}`, { pattern: REF_PATTERN }),
  );
  if (new Set(result).size !== result.length) throw invalid(field);
  return result;
}

function validateBase(value: JsonObject, kind: EntityKind): void {
  switch (kind) {
    case "account":
      parseAccountId(value.id);
      break;
    case "entitlement":
      parseEntitlementId(value.id);
      break;
    case "capacity_pool":
      parseCapacityPoolId(value.id);
      break;
    case "access_method":
      parseAccessMethodId(value.id);
      break;
    case "auth_capsule":
      parseAuthCapsuleId(value.id);
      break;
    case "credential_binding":
      parseCredentialBindingId(value.id);
      break;
  }
  parseCounter(value.revision, "revision");
  timestamp(value.createdAt, "createdAt");
  timestamp(value.updatedAt, "updatedAt");
  if (Date.parse(value.updatedAt as string) < Date.parse(value.createdAt as string)) {
    throw invalid("updatedAt");
  }
}

function metadata(value: unknown, field: string): Readonly<Record<string, string | boolean>> {
  const record = object(value, field);
  const entries = Object.entries(record);
  if (entries.length > 32) throw invalid(field);
  for (const [key, item] of entries) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(key)) throw invalid(`${field}.${key}`);
    if (/(?:auth|bearer|binary|command|cookie|credential|env|key|password|path|role|secret|token|url)/i.test(key)) {
      throw invalid(`${field}.${key}`);
    }
    if (typeof item === "string") {
      string(item, `${field}.${key}`, { min: 0, max: 128 });
    } else if (typeof item !== "boolean") {
      throw invalid(`${field}.${key}`);
    }
  }
  return record as Readonly<Record<string, string | boolean>>;
}

function validateAccount(input: unknown): Account {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  exactKeys(
    value,
    ["id", "providerKey", "ownerRef", "displayLabel", "status", "revision", "createdAt", "updatedAt"],
    [
      "providerSubjectRef",
      "providerSubjectCandidateRef",
      "providerDisplayHint",
      "ownershipEvidenceRef",
      "ownershipEvidenceIssuerRef",
      "ownershipEvidenceVersion",
      "ownershipEvidenceDigest",
      "ownershipEvidenceIssuedAt",
      "ownershipEvidenceExpiresAt",
      "ownershipGeneration",
    ],
  );
  validateBase(value, "account");
  string(value.providerKey, "providerKey", { pattern: KEY_PATTERN });
  owner(value.ownerRef, "ownerRef");
  string(value.displayLabel, "displayLabel", { max: 128 });
  const status = enumValue(value.status, ["pending", "active", "suspended", "revoked"], "status");
  if (value.providerSubjectRef !== undefined) reference(value.providerSubjectRef, "providerSubjectRef");
  if (value.providerSubjectCandidateRef !== undefined) {
    reference(value.providerSubjectCandidateRef, "providerSubjectCandidateRef");
  }
  const ownershipFields = [
    "ownershipEvidenceRef",
    "ownershipEvidenceIssuerRef",
    "ownershipEvidenceVersion",
    "ownershipEvidenceDigest",
    "ownershipEvidenceIssuedAt",
    "ownershipEvidenceExpiresAt",
    "ownershipGeneration",
  ] as const;
  const ownershipCount = ownershipFields.filter((field) => value[field] !== undefined).length;
  if (status === "pending") {
    if (value.providerSubjectRef !== undefined || ownershipCount !== 0) throw invalid("ownershipEvidenceRef");
  } else if (status === "active" || status === "suspended") {
    if (value.providerSubjectRef === undefined || ownershipCount !== ownershipFields.length) {
      throw invalid("ownershipEvidenceRef");
    }
  } else if (ownershipCount !== 0 && ownershipCount !== ownershipFields.length) {
    throw invalid("ownershipEvidenceRef");
  }
  if (ownershipCount === ownershipFields.length) {
    reference(value.ownershipEvidenceRef, "ownershipEvidenceRef");
    reference(value.ownershipEvidenceIssuerRef, "ownershipEvidenceIssuerRef");
    reference(value.ownershipEvidenceVersion, "ownershipEvidenceVersion");
    digest(value.ownershipEvidenceDigest, "ownershipEvidenceDigest");
    timestamp(value.ownershipEvidenceIssuedAt, "ownershipEvidenceIssuedAt");
    timestamp(value.ownershipEvidenceExpiresAt, "ownershipEvidenceExpiresAt");
    ordered(value.ownershipEvidenceIssuedAt, value.ownershipEvidenceExpiresAt, "ownershipEvidenceExpiresAt");
    const generation = parseCounter(value.ownershipGeneration, "ownershipGeneration");
    if (generation === "0") throw invalid("ownershipGeneration");
    if (value.providerSubjectRef === undefined || value.providerSubjectCandidateRef !== undefined) {
      throw invalid("providerSubjectRef");
    }
  }
  if (value.providerDisplayHint !== undefined) {
    string(value.providerDisplayHint, "providerDisplayHint", { max: 128 });
  }
  return value as unknown as Account;
}

function validateTermsDecision(input: unknown): void {
  const value = object(input, "termsDecision");
  const decision = enumValue(value.decision, ["allowed", "denied", "unknown"], "termsDecision.decision");
  if (decision === "unknown") {
    exactKeys(value, ["decision", "useCase", "reasonCode"], [], "termsDecision");
    reference(value.useCase, "termsDecision.useCase");
    string(value.reasonCode, "termsDecision.reasonCode", {
      pattern: /^[A-Z][A-Z0-9_]{0,63}$/,
      max: 64,
    });
    return;
  }
  exactKeys(value, [
    "decision",
    "useCase",
    "evidenceRef",
    "verifiedBy",
    "verifiedAt",
    "expiresAt",
    "termsVersion",
    "termsDigest",
  ], [], "termsDecision");
  reference(value.useCase, "termsDecision.useCase");
  reference(value.evidenceRef, "termsDecision.evidenceRef");
  reference(value.verifiedBy, "termsDecision.verifiedBy");
  timestamp(value.verifiedAt, "termsDecision.verifiedAt");
  timestamp(value.expiresAt, "termsDecision.expiresAt");
  ordered(value.verifiedAt, value.expiresAt, "termsDecision.expiresAt");
  reference(value.termsVersion, "termsDecision.termsVersion");
  digest(value.termsDigest, "termsDecision.termsDigest");
}

function validateDataPolicy(input: unknown): void {
  const value = object(input, "dataPolicy");
  exactKeys(
    value,
    ["allowedClassifications", "retentionClass"],
    ["maxRetentionDays"],
    "dataPolicy",
  );
  stringList(value.allowedClassifications, "dataPolicy.allowedClassifications");
  const retention = enumValue(
    value.retentionClass,
    ["none", "transient", "bounded"],
    "dataPolicy.retentionClass",
  );
  if (retention === "bounded") {
    parseCounter(value.maxRetentionDays, "dataPolicy.maxRetentionDays");
  } else if (value.maxRetentionDays !== undefined) {
    throw invalid("dataPolicy.maxRetentionDays");
  }
}

function validateEntitlement(input: unknown): Entitlement {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  const positiveFields = [
    "capabilitySet",
    "capabilityEvidenceRef",
    "capabilityDigest",
    "capabilityExpiresAt",
    "executionPolicyDecisionRef",
    "executionPolicyDecisionDigest",
    "executionPolicyDecisionExpiresAt",
    "dataPolicy",
    "dataPolicyEvidenceRef",
    "dataPolicyDigest",
    "dataPolicyExpiresAt",
    "lastVerifiedAt",
  ] as const;
  exactKeys(value, [
    "id",
    "accountId",
    "fundingKind",
    "status",
    "revision",
    "createdAt",
    "updatedAt",
  ], ["termsDecision", ...positiveFields]);
  validateBase(value, "entitlement");
  parseAccountId(value.accountId);
  enumValue(
    value.fundingKind,
    ["subscription", "metered", "credit", "contract", "externally_managed"],
    "fundingKind",
  );
  const status = enumValue(value.status, ["pending", "active", "paused", "expired", "revoked"], "status");
  const positiveCount = positiveFields.filter((field) => value[field] !== undefined).length;
  if (value.termsDecision !== undefined) validateTermsDecision(value.termsDecision);
  const termsDecision = value.termsDecision as { decision?: unknown } | undefined;
  if (status === "pending") {
    if (positiveCount !== 0 || termsDecision?.decision === "allowed") throw invalid("capabilitySet");
  } else if (status === "active") {
    if (positiveCount !== positiveFields.length || termsDecision?.decision !== "allowed") {
      throw invalid("capabilitySet");
    }
  } else if (positiveCount !== 0 && positiveCount !== positiveFields.length) {
    throw invalid("capabilitySet");
  }
  if (positiveCount === positiveFields.length) {
    const capabilitySet = object(value.capabilitySet, "capabilitySet");
    exactKeys(capabilitySet, ["operations", "models"], [], "capabilitySet");
    stringList(capabilitySet.operations, "capabilitySet.operations");
    stringList(capabilitySet.models, "capabilitySet.models");
    reference(value.capabilityEvidenceRef, "capabilityEvidenceRef");
    digest(value.capabilityDigest, "capabilityDigest");
    timestamp(value.capabilityExpiresAt, "capabilityExpiresAt");
    reference(value.executionPolicyDecisionRef, "executionPolicyDecisionRef");
    digest(value.executionPolicyDecisionDigest, "executionPolicyDecisionDigest");
    timestamp(value.executionPolicyDecisionExpiresAt, "executionPolicyDecisionExpiresAt");
    if (termsDecision === undefined) throw invalid("termsDecision");
    validateDataPolicy(value.dataPolicy);
    reference(value.dataPolicyEvidenceRef, "dataPolicyEvidenceRef");
    digest(value.dataPolicyDigest, "dataPolicyDigest");
    timestamp(value.dataPolicyExpiresAt, "dataPolicyExpiresAt");
    timestamp(value.lastVerifiedAt, "lastVerifiedAt");
    ordered(value.lastVerifiedAt, value.dataPolicyExpiresAt, "dataPolicyExpiresAt");
    ordered(value.lastVerifiedAt, value.capabilityExpiresAt, "capabilityExpiresAt");
    ordered(value.lastVerifiedAt, value.executionPolicyDecisionExpiresAt, "executionPolicyDecisionExpiresAt");
  }
  return value as unknown as Entitlement;
}

function validateCapacityPool(input: unknown): CapacityPool {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  exactKeys(value, [
    "id",
    "accountId",
    "capacityDomainRef",
    "capacityEvidenceRef",
    "capacityEvidenceIssuerRef",
    "capacityEvidenceVersion",
    "capacityEvidenceDigest",
    "capacityEvidenceIssuedAt",
    "capacityEvidenceExpiresAt",
    "capacityEvidenceGeneration",
    "capacityPolicyVersion",
    "serializationKey",
    "maxConcurrency",
    "status",
    "capacityGeneration",
    "denyGeneration",
    "denyState",
    "revision",
    "createdAt",
    "updatedAt",
  ]);
  validateBase(value, "capacity_pool");
  parseAccountId(value.accountId);
  reference(value.capacityDomainRef, "capacityDomainRef");
  reference(value.capacityEvidenceRef, "capacityEvidenceRef");
  reference(value.capacityEvidenceIssuerRef, "capacityEvidenceIssuerRef");
  reference(value.capacityEvidenceVersion, "capacityEvidenceVersion");
  digest(value.capacityEvidenceDigest, "capacityEvidenceDigest");
  timestamp(value.capacityEvidenceIssuedAt, "capacityEvidenceIssuedAt");
  timestamp(value.capacityEvidenceExpiresAt, "capacityEvidenceExpiresAt");
  ordered(
    value.capacityEvidenceIssuedAt,
    value.capacityEvidenceExpiresAt,
    "capacityEvidenceExpiresAt",
  );
  const capacityEvidenceGeneration = parseCounter(
    value.capacityEvidenceGeneration,
    "capacityEvidenceGeneration",
  );
  if (capacityEvidenceGeneration === "0") throw invalid("capacityEvidenceGeneration");
  reference(value.capacityPolicyVersion, "capacityPolicyVersion");
  reference(value.serializationKey, "serializationKey");
  const max = parseCounter(value.maxConcurrency, "maxConcurrency");
  if (max === "0") throw invalid("maxConcurrency");
  const status = enumValue(
    value.status,
    ["pending", "active", "draining", "denied", "retired"],
    "status",
  );
  parseCounter(value.capacityGeneration, "capacityGeneration");
  parseCounter(value.denyGeneration, "denyGeneration");
  const denyState = enumValue(value.denyState, ["allowed", "denied"], "denyState");
  if (status === "active" && denyState !== "allowed") throw invalid("denyState");
  if (status === "pending" && denyState !== "denied") throw invalid("denyState");
  if (["draining", "denied", "retired"].includes(status) && denyState !== "denied") {
    throw invalid("denyState");
  }
  return value as unknown as CapacityPool;
}

function validateHealth(input: unknown): void {
  const value = object(input, "health");
  exactKeys(value, ["state", "evidenceRef", "observedAt", "expiresAt"], [], "health");
  enumValue(value.state, ["healthy", "degraded", "unavailable", "unknown"], "health.state");
  reference(value.evidenceRef, "health.evidenceRef");
  timestamp(value.observedAt, "health.observedAt");
  timestamp(value.expiresAt, "health.expiresAt");
  ordered(value.observedAt, value.expiresAt, "health.expiresAt");
}

function validateAccessMethod(input: unknown): AccessMethod {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  const positiveFields = [
    "requiredIsolationPolicyRef",
    "requiredIsolationPolicyDigest",
    "isolationEvidenceExpiresAt",
    "allowedDestinationPolicyClasses",
    "parentPolicyDecisionRef",
    "parentPolicyDecisionDigest",
    "executionPolicyEvidenceRef",
    "executionPolicyDigest",
    "executionPolicyExpiresAt",
    "health",
  ] as const;
  exactKeys(
    value,
    [
      "id",
      "entitlementId",
      "capacityPoolId",
      "adapterKey",
      "adapterVersion",
      "accessTransport",
      "status",
      "revision",
      "createdAt",
      "updatedAt",
    ],
    positiveFields,
  );
  validateBase(value, "access_method");
  parseEntitlementId(value.entitlementId);
  parseCapacityPoolId(value.capacityPoolId);
  string(value.adapterKey, "adapterKey", { pattern: KEY_PATTERN });
  reference(value.adapterVersion, "adapterVersion");
  enumValue(value.accessTransport, ["native_session", "api_key", "workload_identity"], "accessTransport");
  const status = enumValue(value.status, ["draft", "ready", "draining", "disabled", "retired"], "status");
  const positiveCount = positiveFields.filter((field) => value[field] !== undefined).length;
  if (status === "draft" && positiveCount !== 0) throw invalid("requiredIsolationPolicyRef");
  if ((status === "ready" || status === "draining") && positiveCount !== positiveFields.length) {
    throw invalid("requiredIsolationPolicyRef");
  }
  if (
    (status === "disabled" || status === "retired") &&
    positiveCount !== 0 &&
    positiveCount !== positiveFields.length
  ) {
    throw invalid("requiredIsolationPolicyRef");
  }
  if (positiveCount === positiveFields.length) {
    reference(value.requiredIsolationPolicyRef, "requiredIsolationPolicyRef");
    digest(value.requiredIsolationPolicyDigest, "requiredIsolationPolicyDigest");
    timestamp(value.isolationEvidenceExpiresAt, "isolationEvidenceExpiresAt");
    ordered(value.updatedAt, value.isolationEvidenceExpiresAt, "isolationEvidenceExpiresAt");
    stringList(value.allowedDestinationPolicyClasses, "allowedDestinationPolicyClasses");
    reference(value.parentPolicyDecisionRef, "parentPolicyDecisionRef");
    digest(value.parentPolicyDecisionDigest, "parentPolicyDecisionDigest");
    reference(value.executionPolicyEvidenceRef, "executionPolicyEvidenceRef");
    digest(value.executionPolicyDigest, "executionPolicyDigest");
    timestamp(value.executionPolicyExpiresAt, "executionPolicyExpiresAt");
    ordered(value.updatedAt, value.executionPolicyExpiresAt, "executionPolicyExpiresAt");
    validateHealth(value.health);
  }
  return value as unknown as AccessMethod;
}

function validateAttestation(input: unknown): void {
  const value = object(input, "attestation");
  exactKeys(
    value,
    ["evidenceRef", "issuerRef", "measurementDigest", "attestedAt", "expiresAt"],
    [],
    "attestation",
  );
  reference(value.evidenceRef, "attestation.evidenceRef");
  reference(value.issuerRef, "attestation.issuerRef");
  digest(value.measurementDigest, "attestation.measurementDigest");
  timestamp(value.attestedAt, "attestation.attestedAt");
  timestamp(value.expiresAt, "attestation.expiresAt");
  ordered(value.attestedAt, value.expiresAt, "attestation.expiresAt");
}

function validateAuthCapsule(input: unknown): AuthCapsule {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  exactKeys(
    value,
    [
      "id",
      "accessMethodId",
      "capacityPoolId",
      "kind",
      "ownerRef",
      "placementKind",
      "placementRef",
      "hardwareKeyThumbprint",
      "nodeGeneration",
      "placementGeneration",
      "status",
      "refreshOwnerRef",
      "refreshMode",
      "authGeneration",
      "authStateRevision",
      "isolationPolicyRef",
      "isolationPolicyDigest",
      "revision",
      "createdAt",
      "updatedAt",
    ],
    ["attestation", "lastHealthAt"],
  );
  validateBase(value, "auth_capsule");
  parseAccessMethodId(value.accessMethodId);
  parseCapacityPoolId(value.capacityPoolId);
  enumValue(value.kind, ["native_session"], "kind");
  owner(value.ownerRef, "ownerRef");
  enumValue(value.placementKind, ["enrolled_node"], "placementKind");
  parseCanonicalNodeId(value.placementRef);
  digest(value.hardwareKeyThumbprint, "hardwareKeyThumbprint");
  parseCounter(value.nodeGeneration, "nodeGeneration");
  parseCounter(value.placementGeneration, "placementGeneration");
  const status = enumValue(
    value.status,
    ["unprovisioned", "bootstrapping", "ready", "degraded", "revoked"],
    "status",
  );
  const refreshOwnerRef = owner(value.refreshOwnerRef, "refreshOwnerRef");
  const refreshMode = enumValue(value.refreshMode, ["provider_native", "interactive_owner"], "refreshMode");
  if (refreshMode === "interactive_owner" && refreshOwnerRef !== value.ownerRef) {
    throw invalid("refreshOwnerRef");
  }
  if (refreshMode === "provider_native" && !refreshOwnerRef.startsWith("principal:service:hasna:")) {
    throw invalid("refreshOwnerRef");
  }
  if (
    refreshMode === "provider_native" &&
    refreshOwnerRef !== `principal:service:hasna:capsule-host:${String(value.id)}`
  ) {
    throw invalid("refreshOwnerRef");
  }
  parseCounter(value.authGeneration, "authGeneration");
  parseCounter(value.authStateRevision, "authStateRevision");
  reference(value.isolationPolicyRef, "isolationPolicyRef");
  digest(value.isolationPolicyDigest, "isolationPolicyDigest");
  if (value.attestation !== undefined) validateAttestation(value.attestation);
  if (value.lastHealthAt !== undefined) timestamp(value.lastHealthAt, "lastHealthAt");
  if (status === "ready" && (value.attestation === undefined || value.lastHealthAt === undefined)) {
    throw invalid("attestation");
  }
  return value as unknown as AuthCapsule;
}

function validateCredentialBinding(input: unknown): CredentialBinding {
  const value = object(input, "data");
  assertNoSensitiveFields(value);
  const status = enumValue(value.status, ["pending", "active", "retiring", "revoked"], "status");
  const terminalKind =
    status === "revoked"
      ? enumValue(
          value.terminalKind,
          ["retired_handle_generation", "revocation_barrier"],
          "terminalKind",
        )
      : undefined;
  const commonRequired = [
    "id",
    "accessMethodId",
    "capacityPoolId",
    "credentialFamilyId",
    "purpose",
    "resolver",
    "credentialGeneration",
    "status",
    "policyDigest",
    "revision",
    "createdAt",
    "updatedAt",
  ] as const;
  const evidenceRequired = [
    "bindingEvidenceRef",
    "bindingEvidenceIssuerRef",
    "bindingEvidenceDigest",
    "bindingEvidenceExpiresAt",
  ] as const;
  const terminalRequired = [
    "terminalKind",
    "revocationBarrierReceiptDigest",
    "revokedAt",
  ] as const;
  exactKeys(
    value,
    terminalKind === "revocation_barrier"
      ? [...commonRequired, ...terminalRequired, "lastUsableCredentialGeneration"]
      : terminalKind === "retired_handle_generation"
        ? [...commonRequired, ...evidenceRequired, ...terminalRequired, "credentialHandleAuditDigest"]
        : [...commonRequired, ...evidenceRequired],
    [
      "authCapsuleId",
      "authStateRevision",
      "refreshMode",
      "rotatedAt",
      ...(terminalKind === "revocation_barrier" ? [] : ["expiresAt"]),
    ],
  );
  validateBase(value, "credential_binding");
  parseAccessMethodId(value.accessMethodId);
  parseCapacityPoolId(value.capacityPoolId);
  reference(value.credentialFamilyId, "credentialFamilyId");
  const purpose = enumValue(value.purpose, ["provider_session", "api_key", "workload_identity"], "purpose");
  const resolver = enumValue(
    value.resolver,
    ["brokered_secret", "workload_identity", "capsule_local_native"],
    "resolver",
  );
  parseCounter(value.credentialGeneration, "credentialGeneration");
  digest(value.policyDigest, "policyDigest");
  if (terminalKind !== "revocation_barrier") {
    reference(value.bindingEvidenceRef, "bindingEvidenceRef");
    reference(value.bindingEvidenceIssuerRef, "bindingEvidenceIssuerRef");
    digest(value.bindingEvidenceDigest, "bindingEvidenceDigest");
    timestamp(value.bindingEvidenceExpiresAt, "bindingEvidenceExpiresAt");
    ordered(value.createdAt, value.bindingEvidenceExpiresAt, "bindingEvidenceExpiresAt");
  }
  if (value.rotatedAt !== undefined) timestamp(value.rotatedAt, "rotatedAt");
  if (value.expiresAt !== undefined) timestamp(value.expiresAt, "expiresAt");
  if (value.expiresAt !== undefined) ordered(value.createdAt, value.expiresAt, "expiresAt");

  if (status === "revoked") {
    digest(value.revocationBarrierReceiptDigest, "revocationBarrierReceiptDigest");
    timestamp(value.revokedAt, "revokedAt");
    if (Date.parse(value.revokedAt as string) !== Date.parse(value.updatedAt as string)) {
      throw invalid("revokedAt");
    }
    if (terminalKind === "retired_handle_generation") {
      keyedDigest(value.credentialHandleAuditDigest, "credentialHandleAuditDigest");
    } else {
      parseCounter(value.lastUsableCredentialGeneration, "lastUsableCredentialGeneration");
      if (value.expiresAt !== undefined) throw invalid("expiresAt");
    }
  }

  if (resolver === "capsule_local_native") {
    if (purpose !== "provider_session" || value.authCapsuleId === undefined) throw invalid("resolver");
    parseAuthCapsuleId(value.authCapsuleId);
    parseCounter(value.authStateRevision, "authStateRevision");
    if (value.refreshMode !== undefined) throw invalid("refreshMode");
  } else {
    if (value.authCapsuleId !== undefined || value.authStateRevision !== undefined) {
      throw invalid("authCapsuleId");
    }
    enumValue(value.refreshMode, ["broker_serialized"], "refreshMode");
    if (resolver === "brokered_secret" && purpose !== "api_key") throw invalid("purpose");
    if (resolver === "workload_identity" && purpose !== "workload_identity") throw invalid("purpose");
  }
  return value as unknown as CredentialBinding;
}

export function validateEntity<K extends EntityKind>(kind: K, input: unknown): EntityMap[K] {
  switch (kind) {
    case "account":
      return validateAccount(input) as EntityMap[K];
    case "entitlement":
      return validateEntitlement(input) as EntityMap[K];
    case "capacity_pool":
      return validateCapacityPool(input) as EntityMap[K];
    case "access_method":
      return validateAccessMethod(input) as EntityMap[K];
    case "auth_capsule":
      return validateAuthCapsule(input) as EntityMap[K];
    case "credential_binding":
      return validateCredentialBinding(input) as EntityMap[K];
  }
}

export function validateEligibilityRequest(input: unknown): EligibilityRequest {
  const value = object(input, "eligibilityRequest");
  assertNoSensitiveFields(value);
  exactKeys(
    value,
    ["accessMethodId", "operation", "model", "dataClassification", "destinationPolicyClass"],
    [],
    "eligibilityRequest",
  );
  parseAccessMethodId(value.accessMethodId);
  reference(value.operation, "operation");
  reference(value.model, "model");
  reference(value.dataClassification, "dataClassification");
  reference(value.destinationPolicyClass, "destinationPolicyClass");
  return value as unknown as EligibilityRequest;
}

export interface RecordEnvelope<K extends EntityKind = EntityKind> {
  readonly schemaVersion: typeof ACCOUNTS_CAPACITY_SCHEMA_VERSION;
  readonly kind: K;
  readonly data: EntityMap[K];
}

export function encodeRecordEnvelope<K extends EntityKind>(kind: K, data: EntityMap[K]): RecordEnvelope<K> {
  return {
    schemaVersion: ACCOUNTS_CAPACITY_SCHEMA_VERSION,
    kind,
    data: validateEntity(kind, data),
  };
}

export function decodeRecordEnvelope(input: unknown): RecordEnvelope {
  const value = object(input, "envelope");
  assertNoSensitiveFields(value);
  exactKeys(value, ["schemaVersion", "kind", "data"], [], "envelope");
  if (value.schemaVersion !== ACCOUNTS_CAPACITY_SCHEMA_VERSION) {
    throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Unsupported DTO schema version", {
      details: {
        schemaVersion:
          typeof value.schemaVersion === "string" && /^[a-z][a-z0-9.-]{0,63}$/.test(value.schemaVersion)
            ? value.schemaVersion
            : "invalid",
      },
    });
  }
  const kind = enumValue(value.kind, ENTITY_KINDS, "kind");
  return encodeRecordEnvelope(kind, validateEntity(kind, value.data));
}

export function serializeRecordEnvelope<K extends EntityKind>(kind: K, data: EntityMap[K]): string {
  return canonicalJson(encodeRecordEnvelope(kind, data));
}

export function deserializeRecordEnvelope(source: string): RecordEnvelope {
  return decodeRecordEnvelope(parseClosedJson(source));
}

function validateEligibilityAccessTarget(input: unknown): void {
  const value = object(input, "accessTarget");
  const kind = enumValue(value.kind, ["native", "brokered", "unresolved"], "accessTarget.kind");
  if (kind === "unresolved") {
    exactKeys(value, ["kind"], [], "accessTarget");
    return;
  }
  if (kind === "brokered") {
    exactKeys(value, ["kind", "credentialBindingId", "resolver"], [], "accessTarget");
    parseCredentialBindingId(value.credentialBindingId);
    enumValue(value.resolver, ["brokered_secret", "workload_identity"], "accessTarget.resolver");
    return;
  }
  exactKeys(
    value,
    [
      "kind",
      "authCapsuleId",
      "canonicalNodeId",
      "nodeKeyThumbprint",
      "nodeGeneration",
      "placementGeneration",
      "authGeneration",
      "authStateRevision",
    ],
    [],
    "accessTarget",
  );
  parseAuthCapsuleId(value.authCapsuleId);
  parseCanonicalNodeId(value.canonicalNodeId);
  digest(value.nodeKeyThumbprint, "accessTarget.nodeKeyThumbprint");
  parseCounter(value.nodeGeneration, "accessTarget.nodeGeneration");
  parseCounter(value.placementGeneration, "accessTarget.placementGeneration");
  parseCounter(value.authGeneration, "accessTarget.authGeneration");
  parseCounter(value.authStateRevision, "accessTarget.authStateRevision");
}

export function validateSlotEligibility(input: unknown): SlotEligibilityMetadata {
  const value = object(input, "eligibility");
  assertNoSensitiveFields(value);
  exactKeys(
    value,
    [
      "schemaVersion",
      "evidenceId",
      "evidenceClass",
      "authority",
      "reservation",
      "accessMethodId",
      "accessTarget",
      "recordRevisionSet",
      "eligibilityRequestDigest",
      "eligible",
      "reasonCodes",
      "issuedAt",
      "expiresAt",
    ],
    [
      "accountId",
      "entitlementId",
      "capacityPoolId",
      "ownerRef",
      "accessTransport",
      "serializationKey",
      "maxConcurrency",
      "capacityGeneration",
      "denyGeneration",
      "denyState",
      "credentialFamilyId",
      "credentialGeneration",
      "catalogIncarnation",
      "recoveryFrontierSequence",
      "recoveryFrontierHash",
    ],
    "eligibility",
  );
  if (value.schemaVersion !== "accounts.slot-eligibility.v1") throw invalid("schemaVersion");
  parseEligibilityEvidenceId(value.evidenceId);
  enumValue(value.evidenceClass, ["local_diagnostic"], "evidenceClass");
  enumValue(value.authority, ["none"], "authority");
  enumValue(value.reservation, ["none"], "reservation");
  parseAccessMethodId(value.accessMethodId);
  validateEligibilityAccessTarget(value.accessTarget);
  if (value.accountId !== undefined) parseAccountId(value.accountId);
  if (value.entitlementId !== undefined) parseEntitlementId(value.entitlementId);
  if (value.capacityPoolId !== undefined) parseCapacityPoolId(value.capacityPoolId);
  if (value.ownerRef !== undefined) owner(value.ownerRef, "ownerRef");
  if (value.accessTransport !== undefined) {
    enumValue(value.accessTransport, ["native_session", "api_key", "workload_identity"], "accessTransport");
  }
  if (value.serializationKey !== undefined) reference(value.serializationKey, "serializationKey");
  for (const field of [
    "maxConcurrency",
    "capacityGeneration",
    "denyGeneration",
    "credentialGeneration",
  ] as const) {
    if (value[field] !== undefined) parseCounter(value[field], field);
  }
  if (value.denyState !== undefined) enumValue(value.denyState, ["allowed", "denied"], "denyState");
  if (value.credentialFamilyId !== undefined) reference(value.credentialFamilyId, "credentialFamilyId");
  if (value.catalogIncarnation !== undefined) reference(value.catalogIncarnation, "catalogIncarnation");
  if (value.recoveryFrontierSequence !== undefined) {
    parseCounter(value.recoveryFrontierSequence, "recoveryFrontierSequence");
  }
  if (value.recoveryFrontierHash !== undefined) {
    digest(value.recoveryFrontierHash, "recoveryFrontierHash");
  }
  const revisions = object(value.recordRevisionSet, "recordRevisionSet");
  exactKeys(revisions, [], ENTITY_KINDS, "recordRevisionSet");
  for (const [kind, revision] of Object.entries(revisions)) parseCounter(revision, `recordRevisionSet.${kind}`);
  digest(value.eligibilityRequestDigest, "eligibilityRequestDigest");
  if (typeof value.eligible !== "boolean") throw invalid("eligible");
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.length > ELIGIBILITY_REASON_CODES.length) {
    throw invalid("reasonCodes");
  }
  const reasons = value.reasonCodes.map((reason, index) =>
    enumValue(reason, ELIGIBILITY_REASON_CODES, `reasonCodes.${index}`),
  );
  if (new Set(reasons).size !== reasons.length) throw invalid("reasonCodes");
  if (reasons.some((reason, index) => index > 0 && reasons[index - 1]! > reason)) {
    throw invalid("reasonCodes");
  }
  if (value.eligible === true && reasons.length !== 0) throw invalid("reasonCodes");
  if (value.eligible === false && reasons.length === 0) throw invalid("reasonCodes");
  if (value.eligible === true) {
    const requiredPositive = [
      "accountId",
      "entitlementId",
      "capacityPoolId",
      "ownerRef",
      "accessTransport",
      "serializationKey",
      "maxConcurrency",
      "capacityGeneration",
      "denyGeneration",
      "denyState",
      "credentialFamilyId",
      "credentialGeneration",
      "catalogIncarnation",
      "recoveryFrontierSequence",
      "recoveryFrontierHash",
    ] as const;
    for (const field of requiredPositive) {
      if (value[field] === undefined) throw invalid(field);
    }
    if (value.denyState !== "allowed") throw invalid("denyState");
    if (value.maxConcurrency === "0") throw invalid("maxConcurrency");
    const target = value.accessTarget as {
      kind?: unknown;
      resolver?: unknown;
      authGeneration?: unknown;
    };
    if (target.kind === "unresolved") throw invalid("accessTarget");
    if (value.accessTransport === "native_session") {
      if (target.kind !== "native" || value.maxConcurrency !== "1") throw invalid("accessTarget");
      if (target.authGeneration !== value.credentialGeneration) throw invalid("credentialGeneration");
    } else if (value.accessTransport === "api_key") {
      if (target.kind !== "brokered" || target.resolver !== "brokered_secret") throw invalid("accessTarget");
    } else if (value.accessTransport === "workload_identity") {
      if (target.kind !== "brokered" || target.resolver !== "workload_identity") throw invalid("accessTarget");
    }
    const requiredRevisionKinds =
      target.kind === "native" ? ENTITY_KINDS : ENTITY_KINDS.filter((kind) => kind !== "auth_capsule");
    for (const kind of requiredRevisionKinds) {
      if (revisions[kind] === undefined) throw invalid(`recordRevisionSet.${kind}`);
    }
    if (target.kind === "brokered" && revisions.auth_capsule !== undefined) {
      throw invalid("recordRevisionSet.auth_capsule");
    }
  }
  timestamp(value.issuedAt, "issuedAt");
  timestamp(value.expiresAt, "expiresAt");
  ordered(value.issuedAt, value.expiresAt, "expiresAt");
  return value as unknown as SlotEligibilityMetadata;
}
