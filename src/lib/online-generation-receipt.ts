import {
  createHash,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";

import { AccountsError } from "../types.js";

export const ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION =
  "accounts.online-generation-check-receipt.v1" as const;
export const ONLINE_GENERATION_CHECK_RECEIPT_VALIDATION_EVIDENCE_SCHEMA_VERSION =
  "accounts.online-generation-check-receipt-validation-evidence.v1" as const;

/**
 * Provenance for the displaced Accounts V1 receipt shape only. This is not a
 * contract pin for this package and grants no admission, lease, fence, or
 * effect authority.
 */
export const ONLINE_GENERATION_RECEIPT_LEGACY_CONTRACT_SHA256 =
  "0d2b45c286f56452312b251b7622e009c486e2fe71fe8f2a5a59c01472eb8b2a" as const;

export const ONLINE_GENERATION_RECEIPT_MAXIMUM_AGE_MS = 60_000 as const;
export const ONLINE_GENERATION_RECEIPT_MAXIMUM_LIFETIME_MS = 120_000 as const;
export const ONLINE_GENERATION_RECEIPT_MAXIMUM_CLOCK_SKEW_MS = 5_000 as const;

export const ONLINE_GENERATION_RECEIPT_REASON_CODES = [
  "ACCESS_METHOD_NOT_READY",
  "ACCOUNT_NOT_ACTIVE",
  "ATTESTATION_STALE",
  "CAPACITY_EVIDENCE_STALE",
  "CAPACITY_POOL_NOT_ACTIVE",
  "CAPSULE_NOT_READY",
  "CAPSULE_OWNER_MISMATCH",
  "CAPSULE_PLACEMENT_INVALID",
  "CAPSULE_REQUIRED",
  "CREDENTIAL_BINDING_EXPIRED",
  "CREDENTIAL_BINDING_NOT_ACTIVE",
  "CREDENTIAL_BINDING_REQUIRED",
  "CREDENTIAL_BINDING_RETIRING",
  "CURRENT_DENY",
  "DATA_CLASSIFICATION_NOT_ALLOWED",
  "DEPENDENCY_UNAVAILABLE",
  "DESTINATION_POLICY_NOT_ALLOWED",
  "ENTITLEMENT_NOT_ACTIVE",
  "GENERATION_MISMATCH",
  "HEALTH_NOT_HEALTHY",
  "HEALTH_STALE",
  "INVALID_ACCESS_TARGET",
  "MODEL_NOT_ALLOWED",
  "OPERATION_NOT_ALLOWED",
  "POLICY_DIGEST_MISMATCH",
  "POLICY_EVIDENCE_STALE",
  "RECOVERY_HOLD",
  "TERMS_NOT_ALLOWED",
  "TERMS_STALE",
  "USE_LIMIT_REACHED",
] as const;

export type OnlineGenerationReceiptReasonCode =
  (typeof ONLINE_GENERATION_RECEIPT_REASON_CODES)[number];
export type OnlineGenerationAccessTransport =
  | "native_session"
  | "api_key"
  | "workload_identity";
export type OnlineGenerationAllowedChannelClass =
  | "capsule_remote_tool"
  | "brokered_provider_proxy";

export interface OnlineGenerationProviderDestinationPolicy {
  readonly scheme: "https";
  readonly normalized_host: string;
  readonly port: string;
  readonly operation_path: string;
  readonly model: string;
  readonly request_body_digest: string;
  readonly tls_server_name: string;
  readonly resolved_address_class: string;
  readonly egress_policy_digest: string;
}

interface OnlineGenerationReceiptCommon {
  readonly schema_version: typeof ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION;
  readonly schema_digest: string;
  readonly receipt_id: string;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly not_before: string;
  readonly expires_at: string;
  readonly capability_id: string;
  readonly capability_digest: string;
  readonly authority_epoch: string;
  readonly route_lineage_id: string;
  readonly route_id: string;
  readonly route_epoch: string;
  readonly run_id: string;
  readonly attempt_id: string;
  readonly attempt_lease_id: string;
  readonly lease_epoch: string;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_lifecycle_generation: string;
  readonly lease_expires_at: string;
  readonly operation_id: string;
  readonly operation_digest: string;
  readonly operation_execution_epoch: string;
  readonly operation_execution_expires_at: string;
  readonly subject: string;
  readonly actor_principal: string;
  readonly lease_holder_principal: string;
  readonly operation_executor_principal: string;
  readonly sender_key_thumbprint: string;
  readonly provider_account_id: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly capacity_domain_ref: string;
  readonly credential_family_id: string;
  readonly allowed: boolean;
  readonly deny_state: "allowed" | "denied";
  readonly reason_codes: readonly OnlineGenerationReceiptReasonCode[];
  readonly current_deny?: true;
  readonly capacity_generation: string;
  readonly deny_generation: string;
  readonly credential_generation: string;
  readonly accounts_revision_set_digest: string;
  readonly slot_eligibility_digest: string;
  readonly approval_ref: string;
  readonly policy_digest: string;
  readonly canonical_request_digest: string;
  readonly provider_destination_policy: OnlineGenerationProviderDestinationPolicy;
  readonly provider_destination_policy_digest: string;
  readonly sender_constraint_confirmation: string;
  readonly max_uses: "1";
  readonly use_count: "0" | "1";
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string;
  readonly recovery_frontier_hash: string;
  readonly signature: string;
}

export interface NativeOnlineGenerationCheckReceipt
  extends OnlineGenerationReceiptCommon {
  readonly access_transport: "native_session";
  readonly allowed_channel_class: "capsule_remote_tool";
  readonly auth_capsule_id: string;
  readonly canonical_node_id: string;
  readonly node_key_thumbprint: string;
  readonly node_generation: string;
  readonly placement_generation: string;
  readonly auth_generation: string;
  readonly auth_state_revision: string;
}

export interface BrokeredOnlineGenerationCheckReceipt
  extends OnlineGenerationReceiptCommon {
  readonly access_transport: "api_key" | "workload_identity";
  readonly allowed_channel_class: "brokered_provider_proxy";
  readonly credential_binding_id: string;
  readonly broker_ref: string;
}

export type OnlineGenerationCheckReceipt =
  | NativeOnlineGenerationCheckReceipt
  | BrokeredOnlineGenerationCheckReceipt;

export interface OnlineGenerationCheckReceiptTrustRoot {
  readonly schemaDigest: string;
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly publicKey: KeyObject;
  readonly revoked: boolean;
}

export type OnlineGenerationDecisionExpectation =
  | {
      readonly allowed: true;
      readonly denyState: "allowed";
      readonly reasonCodes: readonly [];
      readonly currentDeny?: never;
    }
  | {
      readonly allowed: false;
      readonly denyState: "allowed";
      readonly reasonCodes: readonly OnlineGenerationReceiptReasonCode[];
      readonly currentDeny?: never;
    }
  | {
      readonly allowed: false;
      readonly denyState: "denied";
      readonly reasonCodes: readonly OnlineGenerationReceiptReasonCode[];
      readonly currentDeny: true;
    };

export type OnlineGenerationTargetExpectation =
  | {
      readonly kind: "native";
      readonly authCapsuleId: string;
      readonly canonicalNodeId: string;
      readonly nodeKeyThumbprint: string;
      readonly nodeGeneration: string;
      readonly placementGeneration: string;
      readonly authGeneration: string;
      readonly authStateRevision: string;
    }
  | {
      readonly kind: "brokered";
      readonly credentialBindingId: string;
      readonly brokerRef: string;
    };

export interface OnlineGenerationLegacyExecutionExpectation {
  readonly capability: {
    readonly capabilityId: string;
    readonly capabilityDigest: string;
  };
  readonly route: {
    readonly authorityEpoch: string;
    readonly routeLineageId: string;
    readonly routeId: string;
    readonly routeEpoch: string;
  };
  readonly attempt: {
    readonly runId: string;
    readonly attemptId: string;
    readonly attemptLeaseId: string;
    readonly leaseEpoch: string;
  };
  readonly resourceLease: {
    readonly resourceLeaseId: string;
    readonly resourceId: string;
    readonly resourceLifecycleGeneration: string;
    readonly leaseExpiresAt: string;
  };
  readonly operation: {
    readonly operationId: string;
    readonly operationDigest: string;
    readonly operationExecutionEpoch: string;
    readonly operationExecutionExpiresAt: string;
  };
  readonly leaseHolderPrincipal: string;
  readonly operationExecutorPrincipal: string;
}

/**
 * All run, attempt, lease, route-fence, and operation-fence compatibility data
 * is deliberately confined to compatibility.legacyExecution. Accounts only
 * compares it; Accounts does not acquire, renew, consume, or enforce it.
 */
export interface OnlineGenerationCheckReceiptExpectation {
  readonly trustedClock: () => Date;
  readonly maximumAgeMs: number;
  readonly maximumLifetimeMs: number;
  readonly allowedClockSkewMs?: number;
  readonly authenticatedActorPrincipal: string;
  readonly receipt: {
    readonly receiptId: string;
    readonly nonce: string;
    readonly issuedAt: string;
    readonly notBefore: string;
    readonly expiresAt: string;
  };
  readonly compatibility: {
    readonly legacyExecution: OnlineGenerationLegacyExecutionExpectation;
  };
  readonly principals: {
    readonly subject: string;
    readonly actorPrincipal: string;
    readonly senderKeyThumbprint: string;
  };
  readonly account: {
    readonly providerAccountId: string;
    readonly accountLaneId: string;
    readonly capacityPoolId: string;
    readonly capacityDomainRef: string;
    readonly accessTransport: OnlineGenerationAccessTransport;
    readonly credentialFamilyId: string;
    readonly allowedChannelClass: OnlineGenerationAllowedChannelClass;
  };
  readonly decision: OnlineGenerationDecisionExpectation;
  readonly generations: {
    readonly capacityGeneration: string;
    readonly denyGeneration: string;
    readonly credentialGeneration: string;
    readonly accountsRevisionSetDigest: string;
  };
  readonly authorization: {
    readonly slotEligibilityDigest: string;
    readonly approvalRef: string;
    readonly policyDigest: string;
    readonly canonicalRequestDigest: string;
    readonly senderConstraintConfirmation: string;
    readonly maxUses: "1";
    readonly useCount: "0" | "1";
  };
  readonly destination: {
    readonly policy: OnlineGenerationProviderDestinationPolicy;
    readonly policyDigest: string;
  };
  readonly recovery: {
    readonly catalogIncarnation: string;
    readonly recoveryFrontierSequence: string;
    readonly recoveryFrontierHash: string;
  };
  readonly target: OnlineGenerationTargetExpectation;
}

export interface OnlineGenerationLegacyExecutionEvidence {
  readonly capability_id: string;
  readonly capability_digest: string;
  readonly authority_epoch: string;
  readonly route_lineage_id: string;
  readonly route_id: string;
  readonly route_epoch: string;
  readonly run_id: string;
  readonly attempt_id: string;
  readonly attempt_lease_id: string;
  readonly lease_epoch: string;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_lifecycle_generation: string;
  readonly lease_expires_at: string;
  readonly operation_id: string;
  readonly operation_digest: string;
  readonly operation_execution_epoch: string;
  readonly operation_execution_expires_at: string;
  readonly lease_holder_principal: string;
  readonly operation_executor_principal: string;
}

export type OnlineGenerationTargetEvidence =
  | {
      readonly kind: "native";
      readonly auth_capsule_id: string;
      readonly canonical_node_id: string;
      readonly node_key_thumbprint: string;
      readonly node_generation: string;
      readonly placement_generation: string;
      readonly auth_generation: string;
      readonly auth_state_revision: string;
    }
  | {
      readonly kind: "brokered";
      readonly credential_binding_id: string;
      readonly broker_ref: string;
    };

export interface OnlineGenerationCheckReceiptValidationEvidence {
  readonly schema_version: typeof ONLINE_GENERATION_CHECK_RECEIPT_VALIDATION_EVIDENCE_SCHEMA_VERSION;
  readonly receipt_schema_version: typeof ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION;
  readonly receipt_schema_digest: string;
  readonly receipt_id: string;
  readonly receipt_digest: string;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly verified_at: string;
  readonly receipt_decision: {
    readonly allowed: boolean;
    readonly deny_state: "allowed" | "denied";
    readonly reason_codes: readonly OnlineGenerationReceiptReasonCode[];
    readonly current_deny?: true;
  };
  readonly validated_bindings: {
    readonly actor_principal: string;
    readonly subject: string;
    readonly sender_key_thumbprint: string;
    readonly provider_account_id: string;
    readonly account_lane_id: string;
    readonly capacity_pool_id: string;
    readonly capacity_domain_ref: string;
    readonly access_transport: OnlineGenerationAccessTransport;
    readonly credential_family_id: string;
    readonly capacity_generation: string;
    readonly deny_generation: string;
    readonly credential_generation: string;
    readonly accounts_revision_set_digest: string;
    readonly allowed_channel_class: OnlineGenerationAllowedChannelClass;
    readonly slot_eligibility_digest: string;
    readonly approval_ref: string;
    readonly policy_digest: string;
    readonly canonical_request_digest: string;
    readonly provider_destination_policy_digest: string;
    readonly sender_constraint_confirmation: string;
    readonly catalog_incarnation: string;
    readonly recovery_frontier_sequence: string;
    readonly recovery_frontier_hash: string;
    readonly target: OnlineGenerationTargetEvidence;
  };
  readonly compatibility: {
    readonly source_contract_sha256: typeof ONLINE_GENERATION_RECEIPT_LEGACY_CONTRACT_SHA256;
    readonly legacy_execution: OnlineGenerationLegacyExecutionEvidence;
  };
  readonly authority: "none";
  readonly admission: "not_evaluated";
  readonly reservation: "none";
}

export type OnlineGenerationReceiptVerificationErrorCode =
  | "MALFORMED_RECEIPT"
  | "UNTRUSTED_RECEIPT"
  | "STALE_RECEIPT"
  | "BINDING_MISMATCH"
  | "INVALID_VERIFIER_CONFIGURATION";

export class OnlineGenerationReceiptVerificationError extends AccountsError {
  readonly code: OnlineGenerationReceiptVerificationErrorCode;

  constructor(code: OnlineGenerationReceiptVerificationErrorCode) {
    const descriptions: Record<OnlineGenerationReceiptVerificationErrorCode, string> = {
      MALFORMED_RECEIPT: "Online generation receipt verification failed: malformed receipt",
      UNTRUSTED_RECEIPT: "Online generation receipt verification failed: untrusted receipt",
      STALE_RECEIPT: "Online generation receipt verification failed: stale receipt",
      BINDING_MISMATCH: "Online generation receipt verification failed: binding mismatch",
      INVALID_VERIFIER_CONFIGURATION:
        "Online generation receipt verification failed: invalid verifier configuration",
    };
    super(descriptions[code]);
    this.name = "OnlineGenerationReceiptVerificationError";
    this.code = code;
  }
}

type JsonObject = Record<string, unknown>;

const MAX_RECEIPT_BYTES = 262_144;
const MAX_JSON_DEPTH = 16;
const MAX_CONTAINER_ITEMS = 512;
const MAX_COUNTER = 9_223_372_036_854_775_807n;
const FORBIDDEN_JSON_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const UUID_V7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const PRINCIPAL_PATTERN =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TIMESTAMP_PATTERN =
  /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const HOST_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;
const REASON_CODE_SET = new Set<string>(ONLINE_GENERATION_RECEIPT_REASON_CODES);

const COMMON_RECEIPT_KEYS = [
  "schema_version",
  "schema_digest",
  "receipt_id",
  "issuer",
  "issuer_incarnation",
  "key_id",
  "audience",
  "nonce",
  "issued_at",
  "not_before",
  "expires_at",
  "capability_id",
  "capability_digest",
  "authority_epoch",
  "route_lineage_id",
  "route_id",
  "route_epoch",
  "run_id",
  "attempt_id",
  "attempt_lease_id",
  "lease_epoch",
  "resource_lease_id",
  "resource_id",
  "resource_lifecycle_generation",
  "lease_expires_at",
  "operation_id",
  "operation_digest",
  "operation_execution_epoch",
  "operation_execution_expires_at",
  "subject",
  "actor_principal",
  "lease_holder_principal",
  "operation_executor_principal",
  "sender_key_thumbprint",
  "provider_account_id",
  "account_lane_id",
  "capacity_pool_id",
  "capacity_domain_ref",
  "access_transport",
  "credential_family_id",
  "allowed",
  "deny_state",
  "reason_codes",
  "capacity_generation",
  "deny_generation",
  "credential_generation",
  "accounts_revision_set_digest",
  "allowed_channel_class",
  "slot_eligibility_digest",
  "approval_ref",
  "policy_digest",
  "canonical_request_digest",
  "provider_destination_policy",
  "provider_destination_policy_digest",
  "sender_constraint_confirmation",
  "max_uses",
  "use_count",
  "catalog_incarnation",
  "recovery_frontier_sequence",
  "recovery_frontier_hash",
] as const;

const NATIVE_TARGET_KEYS = [
  "auth_capsule_id",
  "canonical_node_id",
  "node_key_thumbprint",
  "node_generation",
  "placement_generation",
  "auth_generation",
  "auth_state_revision",
] as const;

const BROKERED_TARGET_KEYS = ["credential_binding_id", "broker_ref"] as const;

const DESTINATION_POLICY_KEYS = [
  "scheme",
  "normalized_host",
  "port",
  "operation_path",
  "model",
  "request_body_digest",
  "tls_server_name",
  "resolved_address_class",
  "egress_policy_digest",
] as const;

function verificationError(
  code: OnlineGenerationReceiptVerificationErrorCode,
): OnlineGenerationReceiptVerificationError {
  return new OnlineGenerationReceiptVerificationError(code);
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (following < 0xdc00 || following > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** A purpose-built JSON reader that retains duplicate-key information. */
class ReceiptJsonReader {
  private cursor = 0;

  constructor(private readonly input: string) {}

  read(): unknown {
    this.skipWhitespace();
    const value = this.readValue(0);
    this.skipWhitespace();
    if (this.cursor !== this.input.length) throw verificationError("MALFORMED_RECEIPT");
    return value;
  }

  private readValue(depth: number): unknown {
    if (depth > MAX_JSON_DEPTH) throw verificationError("MALFORMED_RECEIPT");
    const next = this.input[this.cursor];
    if (next === "{") return this.readObject(depth + 1);
    if (next === "[") return this.readArray(depth + 1);
    if (next === '"') return this.readString();
    if (next === "t") return this.readLiteral("true", true);
    if (next === "f") return this.readLiteral("false", false);
    if (next === "n") return this.readLiteral("null", null);
    if (next === "-" || (next !== undefined && next >= "0" && next <= "9")) {
      return this.readNumber();
    }
    throw verificationError("MALFORMED_RECEIPT");
  }

  private readObject(depth: number): JsonObject {
    this.cursor += 1;
    this.skipWhitespace();
    const result = Object.create(null) as JsonObject;
    const keys = new Set<string>();
    if (this.input[this.cursor] === "}") {
      this.cursor += 1;
      return result;
    }

    while (true) {
      if (this.input[this.cursor] !== '"') throw verificationError("MALFORMED_RECEIPT");
      const key = this.readString();
      if (FORBIDDEN_JSON_KEYS.has(key) || keys.has(key)) {
        throw verificationError("MALFORMED_RECEIPT");
      }
      keys.add(key);
      if (keys.size > MAX_CONTAINER_ITEMS) throw verificationError("MALFORMED_RECEIPT");
      this.skipWhitespace();
      if (this.input[this.cursor] !== ":") throw verificationError("MALFORMED_RECEIPT");
      this.cursor += 1;
      this.skipWhitespace();
      result[key] = this.readValue(depth);
      this.skipWhitespace();
      const separator = this.input[this.cursor];
      if (separator === "}") {
        this.cursor += 1;
        return result;
      }
      if (separator !== ",") throw verificationError("MALFORMED_RECEIPT");
      this.cursor += 1;
      this.skipWhitespace();
    }
  }

  private readArray(depth: number): unknown[] {
    this.cursor += 1;
    this.skipWhitespace();
    const result: unknown[] = [];
    if (this.input[this.cursor] === "]") {
      this.cursor += 1;
      return result;
    }

    while (true) {
      result.push(this.readValue(depth));
      if (result.length > MAX_CONTAINER_ITEMS) throw verificationError("MALFORMED_RECEIPT");
      this.skipWhitespace();
      const separator = this.input[this.cursor];
      if (separator === "]") {
        this.cursor += 1;
        return result;
      }
      if (separator !== ",") throw verificationError("MALFORMED_RECEIPT");
      this.cursor += 1;
      this.skipWhitespace();
    }
  }

  private readString(): string {
    const start = this.cursor;
    this.cursor += 1;
    let escaped = false;
    while (this.cursor < this.input.length) {
      const character = this.input[this.cursor]!;
      if (!escaped && character === '"') {
        this.cursor += 1;
        try {
          const value = JSON.parse(this.input.slice(start, this.cursor)) as unknown;
          if (typeof value !== "string" || hasLoneSurrogate(value)) {
            throw verificationError("MALFORMED_RECEIPT");
          }
          return value;
        } catch (error) {
          if (error instanceof OnlineGenerationReceiptVerificationError) throw error;
          throw verificationError("MALFORMED_RECEIPT");
        }
      }
      if (!escaped && character.charCodeAt(0) < 0x20) {
        throw verificationError("MALFORMED_RECEIPT");
      }
      if (!escaped && character === "\\") escaped = true;
      else escaped = false;
      this.cursor += 1;
    }
    throw verificationError("MALFORMED_RECEIPT");
  }

  private readNumber(): number {
    const remainder = this.input.slice(this.cursor);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remainder);
    if (match === null) throw verificationError("MALFORMED_RECEIPT");
    this.cursor += match[0].length;
    const value = Number(match[0]);
    if (
      !Number.isFinite(value) ||
      Object.is(value, -0) ||
      (Number.isInteger(value) && !Number.isSafeInteger(value))
    ) {
      throw verificationError("MALFORMED_RECEIPT");
    }
    return value;
  }

  private readLiteral<Value>(token: string, value: Value): Value {
    if (!this.input.startsWith(token, this.cursor)) {
      throw verificationError("MALFORMED_RECEIPT");
    }
    this.cursor += token.length;
    return value;
  }

  private skipWhitespace(): void {
    while (
      this.input[this.cursor] === " " ||
      this.input[this.cursor] === "\t" ||
      this.input[this.cursor] === "\r" ||
      this.input[this.cursor] === "\n"
    ) {
      this.cursor += 1;
    }
  }
}

function parseReceiptBytes(source: Uint8Array): unknown {
  if (!(source instanceof Uint8Array) || source.byteLength === 0 || source.byteLength > MAX_RECEIPT_BYTES) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(source);
  } catch {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return new ReceiptJsonReader(decoded).read();
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    const primitive = JSON.stringify(value);
    if (primitive === undefined) throw verificationError("MALFORMED_RECEIPT");
    return primitive;
  }
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw verificationError("MALFORMED_RECEIPT");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value === undefined || typeof value !== "object") {
    throw verificationError("MALFORMED_RECEIPT");
  }
  const record = value as JsonObject;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function canonicalDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

function jsonObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return value as JsonObject;
}

function exactKeys(
  value: JsonObject,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const permitted = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!permitted.has(key)) throw verificationError("MALFORMED_RECEIPT");
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw verificationError("MALFORMED_RECEIPT");
  }
}

function checkedString(
  value: unknown,
  options: { readonly min?: number; readonly max?: number; readonly pattern?: RegExp } = {},
): string {
  if (typeof value !== "string") throw verificationError("MALFORMED_RECEIPT");
  const minimum = options.min ?? 1;
  const maximum = options.max ?? 255;
  if (value.length < minimum || value.length > maximum || value.trim() !== value) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  if (options.pattern !== undefined && !options.pattern.test(value)) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return value;
}

function reference(value: unknown): string {
  return checkedString(value, { pattern: REFERENCE_PATTERN });
}

function principal(value: unknown): string {
  return checkedString(value, { max: 160, pattern: PRINCIPAL_PATTERN });
}

function digest(value: unknown): string {
  return checkedString(value, { max: 71, pattern: DIGEST_PATTERN });
}

function uuidV7(value: unknown): string {
  return checkedString(value, { min: 36, max: 36, pattern: UUID_V7_PATTERN });
}

function counter(value: unknown, positive = false): string {
  const parsed = checkedString(value, { max: 19, pattern: /^(?:0|[1-9][0-9]{0,18})$/ });
  if (BigInt(parsed) > MAX_COUNTER || (positive && parsed === "0")) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return parsed;
}

function timestamp(value: unknown): number {
  const candidate = checkedString(value, { max: 24, pattern: TIMESTAMP_PATTERN });
  const match = TIMESTAMP_PATTERN.exec(candidate);
  if (match === null) throw verificationError("MALFORMED_RECEIPT");
  const normalized = `${match[1]}.${(match[2] ?? "").padEnd(3, "0")}Z`;
  const milliseconds = Date.parse(normalized);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== normalized) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return milliseconds;
}

function enumValue<const Values extends readonly string[]>(
  value: unknown,
  values: Values,
): Values[number] {
  if (typeof value !== "string" || !values.includes(value)) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return value as Values[number];
}

function base64url(value: unknown, expectedBytes: number): string {
  const encoded = checkedString(value, {
    max: Math.ceil((expectedBytes * 4) / 3),
    pattern: BASE64URL_PATTERN,
  });
  const decoded = Buffer.from(encoded, "base64url");
  if (decoded.byteLength !== expectedBytes || decoded.toString("base64url") !== encoded) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  return encoded;
}

function hostname(value: unknown): string {
  return checkedString(value, { max: 253, pattern: HOST_PATTERN });
}

function port(value: unknown): string {
  const result = checkedString(value, { max: 5, pattern: /^[1-9][0-9]{0,4}$/ });
  if (Number(result) > 65_535) throw verificationError("MALFORMED_RECEIPT");
  return result;
}

function operationPath(value: unknown): string {
  const result = checkedString(value, { max: 2_048 });
  if (
    !result.startsWith("/") ||
    result.startsWith("//") ||
    result.includes("\\") ||
    result.includes("?") ||
    result.includes("#") ||
    result.includes("%") ||
    /[\p{Cc}\p{Z}]/u.test(result)
  ) {
    throw verificationError("MALFORMED_RECEIPT");
  }
  if (result !== "/") {
    if (result.endsWith("/") || result.includes("//")) {
      throw verificationError("MALFORMED_RECEIPT");
    }
    const segments = result.slice(1).split("/");
    if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
      throw verificationError("MALFORMED_RECEIPT");
    }
  }
  return result;
}
