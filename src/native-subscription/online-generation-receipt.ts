import {
  verify as ed25519Verify,
  type KeyObject,
} from "node:crypto";

import { AccountsError } from "./errors.js";
import {
  canonicalJson,
  canonicalSha256,
  parseClosedJsonBytes,
} from "./json.js";
import {
  parseCounter,
  type Counter,
} from "./counter.js";
import { isUuidV7 } from "./ids.js";

export const ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION =
  "accounts.online-generation-check-receipt.v1" as const;
export const ONLINE_GENERATION_RECEIPT_MAXIMUM_AGE_MS = 60_000 as const;
export const ONLINE_GENERATION_RECEIPT_MAXIMUM_LIFETIME_MS = 120_000 as const;
export const ONLINE_GENERATION_RECEIPT_MAXIMUM_CLOCK_SKEW_MS = 5_000 as const;
export const ONLINE_GENERATION_RECEIPT_MAX_USES = 1n as const;
export const CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION =
  "accounts.capability-use-consume-request.v1" as const;
export const CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST =
  "sha256:c248ce62b2acb9bb75f9bc88dfc272b05a9cd627f7e6ac19829bad9ea36de249" as const;
export const CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION =
  "accounts.capability-use-consume-receipt.v1" as const;
export const CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST =
  "sha256:4e969fab6b3ae55c479357ebffed40b5de1ce207ca955b478462b36c9a345bfc" as const;

/** Frozen successor-candidate claims that do not hash to the expanded descriptors. */
export const CAPABILITY_USE_CONSUME_REQUEST_SUPERSEDED_CLAIMED_DIGEST =
  "sha256:a7cdc1dfbebeaea3bad6a5014cfb5189be40fb010f57161b46437458492cd1bc" as const;
export const CAPABILITY_USE_CONSUME_RECEIPT_SUPERSEDED_CLAIMED_DIGEST =
  "sha256:a0999ffabc197f46f6fdeb8a6b78521364b0f2153d52a0e6e63ee360bb408bce" as const;
export const CAPABILITY_USE_DESCRIPTOR_REFREEZE_REQUIRED = true as const;
export const CAPABILITY_USE_UNREFROZEN_SUCCESSOR_CONTRACT_DIGEST =
  "sha256:eda1c92990d3562a81128a5bd455fdfc32be6b7170820f9519aae611af0a8bdc" as const;

export const CAPABILITY_USE_CONSUME_REQUEST_DESCRIPTOR = Object.freeze({
  fields: Object.freeze([
    "schema_version", "schema_digest", "consume_request_id", "capability_id",
    "capability_digest", "nonce", "subject", "actor_principal", "effect_namespace_id",
    "account_lane_id", "capacity_pool_id", "capacity_domain_ref", "serialization_key_digest",
    "credential_family_id", "resource_lease_id", "resource_id",
    "resource_lifecycle_generation", "operation_id", "operation_digest",
    "operation_execution_epoch", "sender_key_thumbprint", "channel_binding_digest",
    "canonical_request_digest", "provider_destination_policy_digest", "online_receipt_id",
    "online_receipt_digest", "model_call_anchor_digest", "expected_use_count", "max_uses",
    "not_after", "idempotency_key_digest",
  ]),
  schema_version: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
});
export const CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR = Object.freeze({
  fields: Object.freeze([
    "schema_version", "schema_digest", "consume_request_id", "consume_receipt_id", "issuer",
    "issuer_incarnation", "key_id", "audience", "capability_id", "capability_digest", "nonce",
    "subject", "actor_principal", "effect_namespace_id", "account_lane_id", "capacity_pool_id",
    "serialization_key_digest", "resource_lease_id", "operation_id", "operation_execution_epoch",
    "sender_key_thumbprint", "channel_binding_digest", "canonical_request_digest",
    "online_receipt_digest", "model_call_anchor_digest", "max_uses", "prior_use_count",
    "next_use_count", "use_ordinal", "use_id", "committed_at", "expires_at",
    "catalog_incarnation", "recovery_frontier_sequence", "recovery_frontier_hash", "signature",
  ]),
  schema_version: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
});

if (
  canonicalSha256(CAPABILITY_USE_CONSUME_REQUEST_DESCRIPTOR) !==
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST ||
  canonicalSha256(CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR) !==
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST
) {
  throw new AccountsError("SCHEMA_CHECKSUM_MISMATCH", "Capability-use descriptor mismatch");
}

export type OnlineGenerationAccessTransport =
  | "native_session"
  | "api_key"
  | "workload_identity";
export type OnlineGenerationAllowedChannelClass =
  | "capsule_remote_tool"
  | "brokered_provider_proxy";

export interface ProviderDestinationPolicy {
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

interface OnlineGenerationReceiptBaseDraft {
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
  readonly authority_epoch: Counter;
  readonly route_lineage_id: string;
  readonly route_id: string;
  readonly route_epoch: Counter;
  readonly run_id: string;
  readonly attempt_id: string;
  readonly attempt_lease_id: string;
  readonly lease_epoch: Counter;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_lifecycle_generation: Counter;
  readonly lease_expires_at: string;
  readonly operation_id: string;
  readonly operation_digest: string;
  readonly operation_execution_epoch: Counter;
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
  readonly access_transport: OnlineGenerationAccessTransport;
  readonly credential_family_id: string;
  readonly capacity_generation: Counter;
  readonly deny_generation: Counter;
  readonly credential_generation: Counter;
  readonly accounts_revision_set_digest: string;
  readonly allowed_channel_class: OnlineGenerationAllowedChannelClass;
  readonly slot_eligibility_digest: string;
  readonly approval_ref: string;
  readonly policy_digest: string;
  readonly canonical_request_digest: string;
  readonly provider_destination_policy: ProviderDestinationPolicy;
  readonly provider_destination_policy_digest: string;
  readonly sender_constraint_confirmation: string;
  readonly max_uses: Counter;
  readonly use_count: Counter;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: Counter;
  readonly recovery_frontier_hash: string;
}

export type OnlineGenerationReceiptDecision =
  | {
      readonly allowed: true;
      readonly deny_state: "allowed";
      readonly reason_codes: readonly [];
      readonly current_deny?: never;
    }
  | {
      readonly allowed: false;
      readonly deny_state: "allowed";
      readonly reason_codes: readonly string[];
      readonly current_deny?: never;
    }
  | {
      readonly allowed: false;
      readonly deny_state: "denied";
      readonly reason_codes: readonly string[];
      readonly current_deny: true;
    };

export interface NativeOnlineGenerationReceiptTarget {
  readonly access_transport: "native_session";
  readonly allowed_channel_class: "capsule_remote_tool";
  readonly auth_capsule_id: string;
  readonly canonical_node_id: string;
  readonly node_key_thumbprint: string;
  readonly node_generation: Counter;
  readonly placement_generation: Counter;
  readonly auth_generation: Counter;
  readonly auth_state_revision: Counter;
}

export interface BrokeredOnlineGenerationReceiptTarget {
  readonly access_transport: "api_key" | "workload_identity";
  readonly allowed_channel_class: "brokered_provider_proxy";
  readonly credential_binding_id: string;
  readonly broker_ref: string;
}

export type OnlineGenerationCheckReceiptDraft =
  OnlineGenerationReceiptBaseDraft &
  OnlineGenerationReceiptDecision &
  (NativeOnlineGenerationReceiptTarget | BrokeredOnlineGenerationReceiptTarget);

type OnlineGenerationCheckReceipt = OnlineGenerationCheckReceiptDraft & {
  readonly signature: string;
};

declare const verifiedReceiptBrand: unique symbol;
declare const allowedReceiptBrand: unique symbol;
declare const projectedReceiptBrand: unique symbol;
declare const consumedReceiptUseBrand: unique symbol;
declare const verifiedConsumeReceiptBrand: unique symbol;

export type VerifiedOnlineGenerationCheckReceipt = OnlineGenerationCheckReceipt & {
  readonly [verifiedReceiptBrand]: true;
};

export type VerifiedAllowedOnlineGenerationCheckReceipt =
  VerifiedOnlineGenerationCheckReceipt & {
    readonly allowed: true;
    readonly [allowedReceiptBrand]: true;
  };

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
      readonly reasonCodes: readonly string[];
      readonly currentDeny?: never;
    }
  | {
      readonly allowed: false;
      readonly denyState: "denied";
      readonly reasonCodes: readonly string[];
      readonly currentDeny: true;
    };

export type OnlineGenerationTargetExpectation =
  | {
      readonly kind: "native";
      readonly authCapsuleId: string;
      readonly canonicalNodeId: string;
      readonly nodeKeyThumbprint: string;
      readonly nodeGeneration: Counter;
      readonly placementGeneration: Counter;
      readonly authGeneration: Counter;
      readonly authStateRevision: Counter;
    }
  | {
      readonly kind: "brokered";
      readonly credentialBindingId: string;
      readonly brokerRef: string;
    };

/**
 * The caller supplies the coherent live Infinity/Accounts tuple it is about to
 * use. Verification compares every security-significant receipt member to this
 * tuple; there is no partial/four-epoch verification mode.
 */
export interface OnlineGenerationCheckReceiptExpectation {
  readonly now: Date;
  readonly maximumAgeMs: number;
  readonly maximumLifetimeMs: number;
  readonly allowedClockSkewMs?: number;
  /** Independently derived from the authenticated transport, never the receipt. */
  readonly authenticatedActorPrincipal: string;
  readonly receipt: {
    readonly receiptId: string;
    readonly nonce: string;
    readonly issuedAt: string;
    readonly notBefore: string;
    readonly expiresAt: string;
  };
  readonly capability: {
    readonly capabilityId: string;
    readonly capabilityDigest: string;
  };
  readonly route: {
    readonly authorityEpoch: Counter;
    readonly routeLineageId: string;
    readonly routeId: string;
    readonly routeEpoch: Counter;
  };
  readonly attempt: {
    readonly runId: string;
    readonly attemptId: string;
    readonly attemptLeaseId: string;
    readonly leaseEpoch: Counter;
  };
  readonly resourceLease: {
    readonly resourceLeaseId: string;
    readonly resourceId: string;
    readonly resourceLifecycleGeneration: Counter;
    readonly leaseExpiresAt: string;
  };
  readonly operation: {
    readonly operationId: string;
    readonly operationDigest: string;
    readonly operationExecutionEpoch: Counter;
    readonly operationExecutionExpiresAt: string;
  };
  readonly principals: {
    readonly subject: string;
    readonly actorPrincipal: string;
    readonly leaseHolderPrincipal: string;
    readonly operationExecutorPrincipal: string;
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
    readonly capacityGeneration: Counter;
    readonly denyGeneration: Counter;
    readonly credentialGeneration: Counter;
    readonly accountsRevisionSetDigest: string;
  };
  readonly authorization: {
    readonly slotEligibilityDigest: string;
    readonly approvalRef: string;
    readonly policyDigest: string;
    readonly canonicalRequestDigest: string;
    readonly senderConstraintConfirmation: string;
    readonly maxUses: Counter;
    readonly useCount: Counter;
  };
  readonly destination: {
    readonly policy: ProviderDestinationPolicy;
    readonly policyDigest: string;
  };
  readonly recovery: {
    readonly catalogIncarnation: string;
    readonly recoveryFrontierSequence: Counter;
    readonly recoveryFrontierHash: string;
  };
  readonly target: OnlineGenerationTargetExpectation;
}

export interface ProviderDestinationPolicySdk {
  readonly scheme: "https";
  readonly normalizedHost: string;
  readonly port: string;
  readonly operationPath: string;
  readonly model: string;
  readonly requestBodyDigest: string;
  readonly tlsServerName: string;
  readonly resolvedAddressClass: string;
  readonly egressPolicyDigest: string;
}

export type OnlineGenerationReceiptTargetSdk =
  | {
      readonly kind: "native";
      readonly authCapsuleId: string;
      readonly canonicalNodeId: string;
      readonly nodeKeyThumbprint: string;
      readonly nodeGeneration: Counter;
      readonly placementGeneration: Counter;
      readonly authGeneration: Counter;
      readonly authStateRevision: Counter;
    }
  | {
      readonly kind: "brokered";
      readonly credentialBindingId: string;
      readonly brokerRef: string;
    };

interface OnlineGenerationCheckReceiptSdk {
  readonly schemaVersion: typeof ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION;
  readonly schemaDigest: string;
  readonly receiptId: string;
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly notBefore: string;
  readonly expiresAt: string;
  readonly signature: string;
  readonly capabilityId: string;
  readonly capabilityDigest: string;
  readonly authorityEpoch: Counter;
  readonly routeLineageId: string;
  readonly routeId: string;
  readonly routeEpoch: Counter;
  readonly runId: string;
  readonly attemptId: string;
  readonly attemptLeaseId: string;
  readonly leaseEpoch: Counter;
  readonly resourceLeaseId: string;
  readonly resourceId: string;
  readonly resourceLifecycleGeneration: Counter;
  readonly leaseExpiresAt: string;
  readonly operationId: string;
  readonly operationDigest: string;
  readonly operationExecutionEpoch: Counter;
  readonly operationExecutionExpiresAt: string;
  readonly subject: string;
  readonly actorPrincipal: string;
  readonly leaseHolderPrincipal: string;
  readonly operationExecutorPrincipal: string;
  readonly senderKeyThumbprint: string;
  readonly providerAccountId: string;
  readonly accountLaneId: string;
  readonly capacityPoolId: string;
  readonly capacityDomainRef: string;
  readonly accessTransport: OnlineGenerationAccessTransport;
  readonly credentialFamilyId: string;
  readonly allowed: boolean;
  readonly denyState: "allowed" | "denied";
  readonly reasonCodes: readonly string[];
  readonly currentDeny?: true;
  readonly capacityGeneration: Counter;
  readonly denyGeneration: Counter;
  readonly credentialGeneration: Counter;
  readonly accountsRevisionSetDigest: string;
  readonly allowedChannelClass: OnlineGenerationAllowedChannelClass;
  readonly slotEligibilityDigest: string;
  readonly approvalRef: string;
  readonly policyDigest: string;
  readonly canonicalRequestDigest: string;
  readonly providerDestinationPolicy: ProviderDestinationPolicySdk;
  readonly providerDestinationPolicyDigest: string;
  readonly senderConstraintConfirmation: string;
  readonly maxUses: Counter;
  readonly useCount: Counter;
  readonly catalogIncarnation: string;
  readonly recoveryFrontierSequence: Counter;
  readonly recoveryFrontierHash: string;
  readonly target: OnlineGenerationReceiptTargetSdk;
}

export type ProjectedOnlineGenerationCheckReceipt = OnlineGenerationCheckReceiptSdk & {
  readonly [projectedReceiptBrand]: true;
};

export interface OnlineGenerationReceiptUseCasRequest {
  readonly schema_version: typeof CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION;
  readonly schema_digest: typeof CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST;
  readonly consume_request_id: string;
  readonly capability_id: string;
  readonly capability_digest: string;
  readonly nonce: string;
  readonly subject: string;
  readonly actor_principal: string;
  readonly effect_namespace_id: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly capacity_domain_ref: string;
  readonly serialization_key_digest: string;
  readonly credential_family_id: string;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_lifecycle_generation: Counter;
  readonly operation_id: string;
  readonly operation_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly sender_key_thumbprint: string;
  readonly channel_binding_digest: string;
  readonly canonical_request_digest: string;
  readonly provider_destination_policy_digest: string;
  readonly online_receipt_id: string;
  readonly online_receipt_digest: string;
  readonly model_call_anchor_digest: string;
  readonly expected_use_count: Counter;
  readonly max_uses: Counter;
  /** Earliest online-receipt, resource-lease, or operation-execution expiry. */
  readonly not_after: string;
  readonly idempotency_key_digest: string;
}

export type OnlineGenerationReceiptUseCasResult =
  | {
      readonly status: "consumed" | "replayed";
      /** Canonical UTF-8 bytes of the exact signed consume receipt. */
      readonly signedReceipt: Uint8Array;
    }
  | {
      readonly status: "idempotency_conflict" | "conflict" | "exhausted";
    };

/**
 * Accounts-owned durable adapter. compareAndConsume MUST verify the coherent
 * current Accounts tuple and atomically insert the one-use tombstone before it
 * returns a signed receipt. The tombstone and idempotency record MUST survive
 * database restore. An exact request replay returns the original receipt bytes;
 * changed bytes under the same consume_request_id return idempotency_conflict.
 * A restorable in-memory/request-local set is insufficient.
 */
export interface OnlineGenerationReceiptUseStore {
  compareAndConsume(
    request: OnlineGenerationReceiptUseCasRequest,
  ): OnlineGenerationReceiptUseCasResult | Promise<OnlineGenerationReceiptUseCasResult>;
}

/**
 * Effect-bound refresh hooks. The clock must be trusted process/deployment
 * time, and refreshExpectation must directly re-read the coherent current
 * Accounts deny/generation tuple; it must not return cached success.
 */
export interface OnlineGenerationReceiptUseGuard {
  readonly clock: () => Date;
  /** Independently derived from the authenticated sender channel. */
  readonly authenticatedChannelBindingDigest: string;
  /** Independently derived from the non-rewindable effect ledger. */
  readonly effectNamespaceId: string;
  /** Independently derived from the current account serialization domain. */
  readonly serializationKeyDigest: string;
  /**
   * Supplied only by integration configuration after a successor contract is
   * refrozen with the actual expanded descriptor hashes. The known defective
   * candidate digest is rejected.
   */
  readonly approvedDescriptorRefreeze?: {
    readonly successorContractDigest: string;
    readonly requestSchemaDigest: typeof CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST;
    readonly receiptSchemaDigest: typeof CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST;
  };
  readonly consumeRequestId: string;
  /** Digest of the already durable PREPARED model-call anchor. */
  readonly modelCallAnchorDigest: string;
  readonly idempotencyKeyDigest: string;
  readonly refreshExpectation: (
    receipt: VerifiedAllowedOnlineGenerationCheckReceipt,
    checkedAt: Date,
  ) =>
    | OnlineGenerationCheckReceiptExpectation
    | Promise<OnlineGenerationCheckReceiptExpectation>;
}

interface CapabilityUseConsumeReceipt {
  readonly schema_version: typeof CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION;
  readonly schema_digest: typeof CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST;
  readonly consume_request_id: string;
  readonly consume_receipt_id: string;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly capability_id: string;
  readonly capability_digest: string;
  readonly nonce: string;
  readonly subject: string;
  readonly actor_principal: string;
  readonly effect_namespace_id: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly serialization_key_digest: string;
  readonly resource_lease_id: string;
  readonly operation_id: string;
  readonly operation_execution_epoch: Counter;
  readonly sender_key_thumbprint: string;
  readonly channel_binding_digest: string;
  readonly canonical_request_digest: string;
  readonly online_receipt_digest: string;
  readonly model_call_anchor_digest: string;
  readonly max_uses: Counter;
  readonly prior_use_count: Counter;
  readonly next_use_count: Counter;
  readonly use_ordinal: Counter;
  readonly use_id: string;
  readonly committed_at: string;
  readonly expires_at: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: Counter;
  readonly recovery_frontier_hash: string;
  readonly signature: string;
}

export type VerifiedCapabilityUseConsumeReceipt = CapabilityUseConsumeReceipt & {
  readonly [verifiedConsumeReceiptBrand]: true;
};

export interface ConsumedOnlineGenerationReceiptUse {
  readonly receipt: VerifiedAllowedOnlineGenerationCheckReceipt;
  readonly use: {
    readonly request: OnlineGenerationReceiptUseCasRequest;
    readonly consumeReceipt: VerifiedCapabilityUseConsumeReceipt;
    readonly consumeReceiptDigest: string;
    readonly useId: string;
    readonly priorUseCount: Counter;
    readonly nextUseCount: Counter;
    readonly useOrdinal: Counter;
    readonly committedAt: string;
    readonly expiresAt: string;
    readonly replayed: boolean;
  };
  readonly [consumedReceiptUseBrand]: true;
}

type JsonObject = Record<string, unknown>;

const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const PRINCIPAL_PATTERN =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TIMESTAMP_PATTERN =
  /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REASON_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const HOST_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;

const COMMON_REQUIRED_KEYS = [
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

const CONSUME_RECEIPT_KEYS = [
  "schema_version",
  "schema_digest",
  "consume_request_id",
  "consume_receipt_id",
  "issuer",
  "issuer_incarnation",
  "key_id",
  "audience",
  "capability_id",
  "capability_digest",
  "nonce",
  "subject",
  "actor_principal",
  "effect_namespace_id",
  "account_lane_id",
  "capacity_pool_id",
  "serialization_key_digest",
  "resource_lease_id",
  "operation_id",
  "operation_execution_epoch",
  "sender_key_thumbprint",
  "channel_binding_digest",
  "canonical_request_digest",
  "online_receipt_digest",
  "model_call_anchor_digest",
  "max_uses",
  "prior_use_count",
  "next_use_count",
  "use_ordinal",
  "use_id",
  "committed_at",
  "expires_at",
  "catalog_incarnation",
  "recovery_frontier_sequence",
  "recovery_frontier_hash",
  "signature",
] as const;

function malformed(): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Online generation receipt is malformed");
}

function forbidden(): AccountsError {
  return new AccountsError("FORBIDDEN", "Online generation receipt is not trusted");
}

function stale(): AccountsError {
  return new AccountsError("STALE_ATTESTATION", "Online generation receipt is stale");
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
  options: {
    readonly min?: number;
    readonly max?: number;
    readonly pattern?: RegExp;
  } = {},
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

function principal(value: unknown): string {
  return string(value, { max: 160, pattern: PRINCIPAL_PATTERN });
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
  const match = TIMESTAMP_PATTERN.exec(result);
  if (match === null) throw malformed();
  const normalized = `${match[1]}.${(match[2] ?? "").padEnd(3, "0")}Z`;
  const milliseconds = Date.parse(normalized);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== normalized) {
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
  values: Values,
): Values[number] {
  if (typeof value !== "string" || !values.includes(value)) throw malformed();
  return value as Values[number];
}

function base64url(value: unknown, exactBytes: number): string {
  const encoded = string(value, {
    max: Math.ceil((exactBytes * 4) / 3),
    pattern: BASE64URL_PATTERN,
  });
  if (encoded.includes("=")) throw malformed();
  const decoded = Buffer.from(encoded, "base64url");
  if (decoded.byteLength !== exactBytes || decoded.toString("base64url") !== encoded) {
    throw malformed();
  }
  return encoded;
}

function reasonCodes(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 128) throw malformed();
  const result = value.map((item) => string(item, { max: 64, pattern: REASON_CODE_PATTERN }));
  if (
    new Set(result).size !== result.length ||
    result.some((code, index) => index > 0 && result[index - 1]! >= code)
  ) {
    throw malformed();
  }
  return result;
}

function hostname(value: unknown): string {
  return string(value, { max: 253, pattern: HOST_PATTERN });
}

function port(value: unknown): string {
  const result = string(value, { max: 5, pattern: /^[1-9][0-9]{0,4}$/ });
  if (Number(result) > 65_535) throw malformed();
  return result;
}

function operationPath(value: unknown): string {
  const result = string(value, { max: 2_048 });
  if (
    !result.startsWith("/") ||
    result.startsWith("//") ||
    result.includes("\\") ||
    result.includes("?") ||
    result.includes("#") ||
    result.includes("%") ||
    /[\p{Cc}\p{Z}]/u.test(result)
  ) {
    throw malformed();
  }
  if (result !== "/") {
    if (result.endsWith("/") || result.includes("//")) throw malformed();
    const segments = result.slice(1).split("/");
    if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
      throw malformed();
    }
  }
  return result;
}

function validateDestinationPolicy(value: unknown): ProviderDestinationPolicy {
  const policy = object(value);
  exactKeys(policy, DESTINATION_POLICY_KEYS);
  if (policy.scheme !== "https") throw malformed();
  hostname(policy.normalized_host);
  port(policy.port);
  operationPath(policy.operation_path);
  reference(policy.model);
  digest(policy.request_body_digest);
  hostname(policy.tls_server_name);
  reference(policy.resolved_address_class);
  digest(policy.egress_policy_digest);
  return policy as unknown as ProviderDestinationPolicy;
}

function validateDecision(envelope: JsonObject): readonly string[] {
  if (typeof envelope.allowed !== "boolean") throw malformed();
  const denyState = enumValue(envelope.deny_state, ["allowed", "denied"] as const);
  const reasons = reasonCodes(envelope.reason_codes);
  const hasCurrentDeny = Object.hasOwn(envelope, "current_deny");

  if (envelope.allowed) {
    if (denyState !== "allowed" || reasons.length !== 0 || hasCurrentDeny) throw malformed();
    return reasons;
  }
  if (reasons.length === 0) throw malformed();
  if (denyState === "denied") {
    if (envelope.current_deny !== true) throw malformed();
    return reasons;
  }
  if (hasCurrentDeny) throw malformed();
  return reasons;
}

function validateCommon(envelope: JsonObject): void {
  if (envelope.schema_version !== ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION) {
    throw malformed();
  }
  digest(envelope.schema_digest);
  uuidV7(envelope.receipt_id);
  reference(envelope.issuer);
  reference(envelope.issuer_incarnation);
  reference(envelope.key_id);
  reference(envelope.audience);
  reference(envelope.nonce);
  const issuedAt = timestamp(envelope.issued_at);
  const notBefore = timestamp(envelope.not_before);
  const expiresAt = timestamp(envelope.expires_at);
  if (Date.parse(issuedAt) >= Date.parse(expiresAt) || Date.parse(notBefore) >= Date.parse(expiresAt)) {
    throw malformed();
  }
  uuidV7(envelope.capability_id);
  digest(envelope.capability_digest);
  counter(envelope.authority_epoch, true);
  uuidV7(envelope.route_lineage_id);
  uuidV7(envelope.route_id);
  counter(envelope.route_epoch, true);
  uuidV7(envelope.run_id);
  uuidV7(envelope.attempt_id);
  uuidV7(envelope.attempt_lease_id);
  counter(envelope.lease_epoch, true);
  uuidV7(envelope.resource_lease_id);
  reference(envelope.resource_id);
  counter(envelope.resource_lifecycle_generation, true);
  timestamp(envelope.lease_expires_at);
  uuidV7(envelope.operation_id);
  digest(envelope.operation_digest);
  counter(envelope.operation_execution_epoch, true);
  timestamp(envelope.operation_execution_expires_at);
  principal(envelope.subject);
  principal(envelope.actor_principal);
  principal(envelope.lease_holder_principal);
  principal(envelope.operation_executor_principal);
  digest(envelope.sender_key_thumbprint);
  uuidV7(envelope.provider_account_id);
  uuidV7(envelope.account_lane_id);
  uuidV7(envelope.capacity_pool_id);
  reference(envelope.capacity_domain_ref);
  uuidV7(envelope.credential_family_id);
  const reasons = validateDecision(envelope);
  counter(envelope.capacity_generation);
  counter(envelope.deny_generation);
  counter(envelope.credential_generation);
  digest(envelope.accounts_revision_set_digest);
  digest(envelope.slot_eligibility_digest);
  reference(envelope.approval_ref);
  digest(envelope.policy_digest);
  digest(envelope.canonical_request_digest);
  const policy = validateDestinationPolicy(envelope.provider_destination_policy);
  const policyDigest = digest(envelope.provider_destination_policy_digest);
  if (policyDigest !== canonicalSha256(policy)) throw malformed();
  digest(envelope.sender_constraint_confirmation);
  const maxUses = counter(envelope.max_uses, true);
  if (maxUses !== "1") throw malformed();
  const useCount = counter(envelope.use_count);
  if (
    (useCount !== "0" && useCount !== "1") ||
    (envelope.allowed === true && useCount !== "0") ||
    (useCount === "1" && !reasons.includes("USE_LIMIT_REACHED")) ||
    (useCount === "0" && reasons.includes("USE_LIMIT_REACHED"))
  ) {
    throw malformed();
  }
  if (
    envelope.allowed === true &&
    (Date.parse(expiresAt) > Date.parse(timestamp(envelope.lease_expires_at)) ||
      Date.parse(expiresAt) > Date.parse(timestamp(envelope.operation_execution_expires_at)))
  ) {
    throw malformed();
  }
  reference(envelope.catalog_incarnation);
  counter(envelope.recovery_frontier_sequence);
  digest(envelope.recovery_frontier_hash);
}

function validateEnvelope(value: unknown): OnlineGenerationCheckReceipt {
  const envelope = object(value);
  const transport = enumValue(envelope.access_transport, [
    "native_session",
    "api_key",
    "workload_identity",
  ] as const);
  if (transport === "native_session") {
    exactKeys(
      envelope,
      [...COMMON_REQUIRED_KEYS, ...NATIVE_TARGET_KEYS, "signature"],
      ["current_deny"],
    );
  } else {
    exactKeys(
      envelope,
      [...COMMON_REQUIRED_KEYS, ...BROKERED_TARGET_KEYS, "signature"],
      ["current_deny"],
    );
  }
  validateCommon(envelope);
  if (transport === "native_session") {
    if (envelope.allowed_channel_class !== "capsule_remote_tool") throw malformed();
    uuidV7(envelope.auth_capsule_id);
    uuidV7(envelope.canonical_node_id);
    digest(envelope.node_key_thumbprint);
    counter(envelope.node_generation, true);
    counter(envelope.placement_generation, true);
    counter(envelope.auth_generation);
    counter(envelope.auth_state_revision);
  } else {
    if (envelope.allowed_channel_class !== "brokered_provider_proxy") throw malformed();
    uuidV7(envelope.credential_binding_id);
    reference(envelope.broker_ref);
  }
  base64url(envelope.signature, 64);
  return envelope as unknown as OnlineGenerationCheckReceipt;
}

function assertTrust(
  envelope: OnlineGenerationCheckReceipt,
  trust: OnlineGenerationCheckReceiptTrustRoot,
): void {
  if (
    trust.revoked !== false ||
    envelope.schema_digest !== trust.schemaDigest ||
    envelope.issuer !== trust.issuer ||
    envelope.issuer_incarnation !== trust.issuerIncarnation ||
    envelope.key_id !== trust.keyId ||
    envelope.audience !== trust.audience
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

function unsignedEnvelope(envelope: OnlineGenerationCheckReceipt): JsonObject {
  const { signature: _signature, ...unsigned } = envelope;
  return unsigned;
}

function assertSignature(envelope: OnlineGenerationCheckReceipt, publicKey: KeyObject): void {
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

function safePositiveDuration(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw malformed();
  return value;
}

function assertFreshness(
  envelope: OnlineGenerationCheckReceipt,
  expectation: OnlineGenerationCheckReceiptExpectation,
): void {
  if (!(expectation.now instanceof Date)) throw malformed();
  const now = expectation.now.getTime();
  if (!Number.isFinite(now)) throw malformed();
  const maximumAge = safePositiveDuration(expectation.maximumAgeMs);
  const maximumLifetime = safePositiveDuration(expectation.maximumLifetimeMs);
  if (
    maximumAge > ONLINE_GENERATION_RECEIPT_MAXIMUM_AGE_MS ||
    maximumLifetime > ONLINE_GENERATION_RECEIPT_MAXIMUM_LIFETIME_MS
  ) {
    throw malformed();
  }
  const allowedClockSkew = expectation.allowedClockSkewMs ?? 0;
  if (
    !Number.isSafeInteger(allowedClockSkew) ||
    allowedClockSkew < 0 ||
    allowedClockSkew > ONLINE_GENERATION_RECEIPT_MAXIMUM_CLOCK_SKEW_MS
  ) {
    throw malformed();
  }
  const issuedAt = Date.parse(envelope.issued_at);
  const notBefore = Date.parse(envelope.not_before);
  const expiresAt = Date.parse(envelope.expires_at);
  if (
    issuedAt > now + allowedClockSkew ||
    notBefore > now + allowedClockSkew ||
    expiresAt <= now ||
    now - issuedAt > maximumAge + allowedClockSkew ||
    expiresAt - issuedAt > maximumLifetime
  ) {
    throw stale();
  }
  if (
    envelope.allowed &&
    (Date.parse(envelope.lease_expires_at) <= now ||
      Date.parse(envelope.operation_execution_expires_at) <= now)
  ) {
    throw stale();
  }
}

function assertEqual(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw forbidden();
}

function assertCanonicalEqual(actual: unknown, expected: unknown): void {
  let actualCanonical: string;
  let expectedCanonical: string;
  try {
    actualCanonical = canonicalJson(actual);
    expectedCanonical = canonicalJson(expected);
  } catch {
    throw malformed();
  }
  if (actualCanonical !== expectedCanonical) throw forbidden();
}

function assertBinding(
  envelope: OnlineGenerationCheckReceipt,
  expectation: OnlineGenerationCheckReceiptExpectation,
): void {
  const receipt = object(expectation.receipt);
  assertEqual(envelope.receipt_id, receipt.receiptId);
  assertEqual(envelope.nonce, receipt.nonce);
  assertEqual(envelope.issued_at, receipt.issuedAt);
  assertEqual(envelope.not_before, receipt.notBefore);
  assertEqual(envelope.expires_at, receipt.expiresAt);

  const capability = object(expectation.capability);
  assertEqual(envelope.capability_id, capability.capabilityId);
  assertEqual(envelope.capability_digest, capability.capabilityDigest);

  const route = object(expectation.route);
  assertEqual(envelope.authority_epoch, route.authorityEpoch);
  assertEqual(envelope.route_lineage_id, route.routeLineageId);
  assertEqual(envelope.route_id, route.routeId);
  assertEqual(envelope.route_epoch, route.routeEpoch);

  const attempt = object(expectation.attempt);
  assertEqual(envelope.run_id, attempt.runId);
  assertEqual(envelope.attempt_id, attempt.attemptId);
  assertEqual(envelope.attempt_lease_id, attempt.attemptLeaseId);
  assertEqual(envelope.lease_epoch, attempt.leaseEpoch);

  const resourceLease = object(expectation.resourceLease);
  assertEqual(envelope.resource_lease_id, resourceLease.resourceLeaseId);
  assertEqual(envelope.resource_id, resourceLease.resourceId);
  assertEqual(envelope.resource_lifecycle_generation, resourceLease.resourceLifecycleGeneration);
  assertEqual(envelope.lease_expires_at, resourceLease.leaseExpiresAt);

  const operation = object(expectation.operation);
  assertEqual(envelope.operation_id, operation.operationId);
  assertEqual(envelope.operation_digest, operation.operationDigest);
  assertEqual(envelope.operation_execution_epoch, operation.operationExecutionEpoch);
  assertEqual(envelope.operation_execution_expires_at, operation.operationExecutionExpiresAt);

  const principals = object(expectation.principals);
  assertEqual(envelope.subject, principals.subject);
  assertEqual(envelope.actor_principal, expectation.authenticatedActorPrincipal);
  assertEqual(envelope.actor_principal, principals.actorPrincipal);
  assertEqual(envelope.lease_holder_principal, principals.leaseHolderPrincipal);
  assertEqual(envelope.operation_executor_principal, principals.operationExecutorPrincipal);
  assertEqual(envelope.sender_key_thumbprint, principals.senderKeyThumbprint);

  const account = object(expectation.account);
  assertEqual(envelope.provider_account_id, account.providerAccountId);
  assertEqual(envelope.account_lane_id, account.accountLaneId);
  assertEqual(envelope.capacity_pool_id, account.capacityPoolId);
  assertEqual(envelope.capacity_domain_ref, account.capacityDomainRef);
  assertEqual(envelope.access_transport, account.accessTransport);
  assertEqual(envelope.credential_family_id, account.credentialFamilyId);
  assertEqual(envelope.allowed_channel_class, account.allowedChannelClass);

  const decision = object(expectation.decision);
  assertEqual(envelope.allowed, decision.allowed);
  assertEqual(envelope.deny_state, decision.denyState);
  assertCanonicalEqual(envelope.reason_codes, decision.reasonCodes);
  if (envelope.deny_state === "denied") {
    assertEqual(envelope.current_deny, decision.currentDeny);
  } else if (Object.hasOwn(decision, "currentDeny")) {
    throw malformed();
  }

  const generations = object(expectation.generations);
  assertEqual(envelope.capacity_generation, generations.capacityGeneration);
  assertEqual(envelope.deny_generation, generations.denyGeneration);
  assertEqual(envelope.credential_generation, generations.credentialGeneration);
  assertEqual(envelope.accounts_revision_set_digest, generations.accountsRevisionSetDigest);

  const authorization = object(expectation.authorization);
  assertEqual(envelope.slot_eligibility_digest, authorization.slotEligibilityDigest);
  assertEqual(envelope.approval_ref, authorization.approvalRef);
  assertEqual(envelope.policy_digest, authorization.policyDigest);
  assertEqual(envelope.canonical_request_digest, authorization.canonicalRequestDigest);
  assertEqual(
    envelope.sender_constraint_confirmation,
    authorization.senderConstraintConfirmation,
  );
  assertEqual(envelope.max_uses, authorization.maxUses);
  assertEqual(envelope.use_count, authorization.useCount);

  const destination = object(expectation.destination);
  assertCanonicalEqual(envelope.provider_destination_policy, destination.policy);
  assertEqual(envelope.provider_destination_policy_digest, destination.policyDigest);

  const recovery = object(expectation.recovery);
  assertEqual(envelope.catalog_incarnation, recovery.catalogIncarnation);
  assertEqual(envelope.recovery_frontier_sequence, recovery.recoveryFrontierSequence);
  assertEqual(envelope.recovery_frontier_hash, recovery.recoveryFrontierHash);

  const target = object(expectation.target);
  if (envelope.access_transport === "native_session") {
    assertEqual(target.kind, "native");
    assertEqual(envelope.auth_capsule_id, target.authCapsuleId);
    assertEqual(envelope.canonical_node_id, target.canonicalNodeId);
    assertEqual(envelope.node_key_thumbprint, target.nodeKeyThumbprint);
    assertEqual(envelope.node_generation, target.nodeGeneration);
    assertEqual(envelope.placement_generation, target.placementGeneration);
    assertEqual(envelope.auth_generation, target.authGeneration);
    assertEqual(envelope.auth_state_revision, target.authStateRevision);
  } else {
    assertEqual(target.kind, "brokered");
    assertEqual(envelope.credential_binding_id, target.credentialBindingId);
    assertEqual(envelope.broker_ref, target.brokerRef);
  }
}

function deepFreeze<Type>(value: Type, seen = new Set<object>()): Type {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

/**
 * Parses canonical UTF-8/JCS bytes, validates the closed variant, verifies its
 * Ed25519 signature and configured Accounts trust root, checks freshness using
 * only the caller's trusted clock, and binds the complete live tuple.
 */
export function verifyOnlineGenerationCheckReceipt(
  source: Uint8Array,
  trust: OnlineGenerationCheckReceiptTrustRoot,
  expectation: OnlineGenerationCheckReceiptExpectation,
): VerifiedOnlineGenerationCheckReceipt {
  const parsed = parseClosedJsonBytes(source);
  const canonical = Buffer.from(canonicalJson(parsed), "utf8");
  const supplied = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  if (!supplied.equals(canonical)) throw malformed();

  const envelope = validateEnvelope(parsed);
  assertTrust(envelope, trust);
  assertSignature(envelope, trust.publicKey);
  assertFreshness(envelope, expectation);
  assertBinding(envelope, expectation);
  return deepFreeze(envelope) as VerifiedOnlineGenerationCheckReceipt;
}

/**
 * Pure cryptographic/decision verification. It never returns negative evidence
 * as allowed evidence, but it deliberately does not consume the nonce. Before
 * any effect, call consumeOnlineGenerationCheckReceiptUse with the Accounts
 * durable CAS store and compose that result with the execution-ledger protocol.
 */
export function verifyAllowedOnlineGenerationCheckReceipt(
  source: Uint8Array,
  trust: OnlineGenerationCheckReceiptTrustRoot,
  expectation: OnlineGenerationCheckReceiptExpectation,
): VerifiedAllowedOnlineGenerationCheckReceipt {
  const receipt = verifyOnlineGenerationCheckReceipt(source, trust, expectation);
  if (!receipt.allowed) {
    if (receipt.deny_state === "denied" && receipt.current_deny === true) {
      throw new AccountsError("CURRENT_DENY", "Current denial state blocks the operation", {
        details: { reasonCodes: receipt.reason_codes },
      });
    }
    throw new AccountsError("POLICY_DENIED", "Policy denied the operation", {
      details: { reasonCodes: receipt.reason_codes },
    });
  }
  return receipt as VerifiedAllowedOnlineGenerationCheckReceipt;
}

function useStoreUnavailable(): AccountsError {
  return new AccountsError(
    "DEPENDENCY_UNAVAILABLE",
    "The receipt use store is unavailable",
    { retryable: true },
  );
}

function validateUseStoreResult(
  value: unknown,
): OnlineGenerationReceiptUseCasResult {
  let result: JsonObject;
  try {
    result = object(value);
    const status = enumValue(result.status, [
      "consumed",
      "replayed",
      "idempotency_conflict",
      "conflict",
      "exhausted",
    ] as const);
    if (status === "consumed" || status === "replayed") {
      exactKeys(result, ["status", "signedReceipt"]);
      const signedReceipt = result.signedReceipt;
      if (
        !(signedReceipt instanceof Uint8Array) ||
        signedReceipt.byteLength === 0 ||
        signedReceipt.byteLength > 65_536
      ) {
        throw malformed();
      }
      return Object.freeze({
        status,
        signedReceipt: Uint8Array.from(signedReceipt),
      });
    } else {
      exactKeys(result, ["status"]);
      return Object.freeze({ status });
    }
  } catch {
    throw useStoreUnavailable();
  }
}

function trustedClockNow(guard: OnlineGenerationReceiptUseGuard): Date {
  if (
    guard === null ||
    typeof guard !== "object" ||
    typeof guard.clock !== "function" ||
    typeof guard.refreshExpectation !== "function"
  ) {
    throw malformed();
  }
  let observed: Date;
  try {
    observed = guard.clock();
  } catch {
    throw useStoreUnavailable();
  }
  if (!(observed instanceof Date) || !Number.isFinite(observed.getTime())) throw malformed();
  return new Date(observed);
}

function earliestExpiry(receipt: VerifiedAllowedOnlineGenerationCheckReceipt): string {
  return [
    receipt.expires_at,
    receipt.lease_expires_at,
    receipt.operation_execution_expires_at,
  ].reduce((earliest, candidate) =>
    Date.parse(candidate) < Date.parse(earliest) ? candidate : earliest,
  );
}

function buildUseRequest(
  receipt: VerifiedAllowedOnlineGenerationCheckReceipt,
  guard: OnlineGenerationReceiptUseGuard,
): OnlineGenerationReceiptUseCasRequest {
  uuidV7(guard.consumeRequestId);
  const channelBindingDigest = digest(guard.authenticatedChannelBindingDigest);
  const effectNamespaceId = reference(guard.effectNamespaceId);
  const serializationKeyDigest = digest(guard.serializationKeyDigest);
  const refreeze = guard.approvedDescriptorRefreeze;
  if (
    refreeze === undefined ||
    digest(refreeze.successorContractDigest) === CAPABILITY_USE_UNREFROZEN_SUCCESSOR_CONTRACT_DIGEST ||
    refreeze.requestSchemaDigest !== CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST ||
    refreeze.receiptSchemaDigest !== CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST
  ) {
    throw new AccountsError(
      "SCHEMA_CHECKSUM_MISMATCH",
      "Capability-use successor descriptor refreeze is required",
    );
  }
  digest(guard.modelCallAnchorDigest);
  digest(guard.idempotencyKeyDigest);
  if (channelBindingDigest !== receipt.sender_constraint_confirmation) throw forbidden();
  return deepFreeze({
    schema_version: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
    schema_digest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
    consume_request_id: guard.consumeRequestId,
    capability_id: receipt.capability_id,
    capability_digest: receipt.capability_digest,
    nonce: receipt.nonce,
    subject: receipt.subject,
    actor_principal: receipt.actor_principal,
    effect_namespace_id: effectNamespaceId,
    account_lane_id: receipt.account_lane_id,
    capacity_pool_id: receipt.capacity_pool_id,
    capacity_domain_ref: receipt.capacity_domain_ref,
    serialization_key_digest: serializationKeyDigest,
    credential_family_id: receipt.credential_family_id,
    resource_lease_id: receipt.resource_lease_id,
    resource_id: receipt.resource_id,
    resource_lifecycle_generation: receipt.resource_lifecycle_generation,
    operation_id: receipt.operation_id,
    operation_digest: receipt.operation_digest,
    operation_execution_epoch: receipt.operation_execution_epoch,
    sender_key_thumbprint: receipt.sender_key_thumbprint,
    channel_binding_digest: channelBindingDigest,
    canonical_request_digest: receipt.canonical_request_digest,
    provider_destination_policy_digest: receipt.provider_destination_policy_digest,
    online_receipt_id: receipt.receipt_id,
    online_receipt_digest: canonicalSha256(receipt),
    model_call_anchor_digest: guard.modelCallAnchorDigest,
    expected_use_count: receipt.use_count,
    max_uses: receipt.max_uses,
    not_after: earliestExpiry(receipt),
    idempotency_key_digest: guard.idempotencyKeyDigest,
  } satisfies OnlineGenerationReceiptUseCasRequest);
}

function consumeUseId(request: OnlineGenerationReceiptUseCasRequest): string {
  return canonicalSha256({
    capability_id: request.capability_id,
    channel_binding_digest: request.channel_binding_digest,
    model_call_anchor_digest: request.model_call_anchor_digest,
    nonce: request.nonce,
    operation_id: request.operation_id,
    resource_lease_id: request.resource_lease_id,
    schema_version: "accounts.capability-use.v1",
    sender_key_thumbprint: request.sender_key_thumbprint,
    use_ordinal: "1",
  });
}

function assertConsumeReceiptSignature(
  envelope: CapabilityUseConsumeReceipt,
  publicKey: KeyObject,
): void {
  const { signature: _signature, ...unsigned } = envelope;
  const message = Buffer.from(canonicalJson(unsigned), "utf8");
  const signature = Buffer.from(envelope.signature, "base64url");
  let valid = false;
  try {
    valid = ed25519Verify(null, message, publicKey, signature);
  } catch {
    throw forbidden();
  }
  if (!valid) throw forbidden();
}

function validateConsumeReceipt(
  source: Uint8Array,
  trust: OnlineGenerationCheckReceiptTrustRoot,
  request: OnlineGenerationReceiptUseCasRequest,
  onlineReceipt: VerifiedAllowedOnlineGenerationCheckReceipt,
  now: Date,
  allowedClockSkew: number,
): VerifiedCapabilityUseConsumeReceipt {
  const parsed = parseClosedJsonBytes(source);
  const canonical = Buffer.from(canonicalJson(parsed), "utf8");
  const supplied = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  if (!supplied.equals(canonical)) throw malformed();

  const value = object(parsed);
  exactKeys(value, CONSUME_RECEIPT_KEYS);
  if (
    value.schema_version !== CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION ||
    value.schema_digest !== CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST
  ) {
    throw malformed();
  }
  uuidV7(value.consume_request_id);
  uuidV7(value.consume_receipt_id);
  reference(value.issuer);
  reference(value.issuer_incarnation);
  reference(value.key_id);
  reference(value.audience);
  uuidV7(value.capability_id);
  digest(value.capability_digest);
  reference(value.nonce);
  principal(value.subject);
  principal(value.actor_principal);
  reference(value.effect_namespace_id);
  uuidV7(value.account_lane_id);
  uuidV7(value.capacity_pool_id);
  digest(value.serialization_key_digest);
  uuidV7(value.resource_lease_id);
  uuidV7(value.operation_id);
  counter(value.operation_execution_epoch, true);
  digest(value.sender_key_thumbprint);
  digest(value.channel_binding_digest);
  digest(value.canonical_request_digest);
  digest(value.online_receipt_digest);
  digest(value.model_call_anchor_digest);
  if (
    counter(value.max_uses, true) !== "1" ||
    counter(value.prior_use_count) !== "0" ||
    counter(value.next_use_count, true) !== "1" ||
    counter(value.use_ordinal, true) !== "1"
  ) {
    throw malformed();
  }
  digest(value.use_id);
  const committedAt = timestamp(value.committed_at);
  const expiresAt = timestamp(value.expires_at);
  reference(value.catalog_incarnation);
  counter(value.recovery_frontier_sequence);
  digest(value.recovery_frontier_hash);
  base64url(value.signature, 64);

  const publicKey = trust.publicKey as KeyObject | null | undefined;
  if (
    trust.revoked !== false ||
    value.issuer !== trust.issuer ||
    value.issuer_incarnation !== trust.issuerIncarnation ||
    value.key_id !== trust.keyId ||
    value.audience !== trust.audience ||
    publicKey === undefined ||
    publicKey === null ||
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw forbidden();
  }

  assertEqual(value.consume_request_id, request.consume_request_id);
  assertEqual(value.capability_id, request.capability_id);
  assertEqual(value.capability_digest, request.capability_digest);
  assertEqual(value.nonce, request.nonce);
  assertEqual(value.subject, request.subject);
  assertEqual(value.actor_principal, request.actor_principal);
  assertEqual(value.effect_namespace_id, request.effect_namespace_id);
  assertEqual(value.account_lane_id, request.account_lane_id);
  assertEqual(value.capacity_pool_id, request.capacity_pool_id);
  assertEqual(value.serialization_key_digest, request.serialization_key_digest);
  assertEqual(value.resource_lease_id, request.resource_lease_id);
  assertEqual(value.operation_id, request.operation_id);
  assertEqual(value.operation_execution_epoch, request.operation_execution_epoch);
  assertEqual(value.sender_key_thumbprint, request.sender_key_thumbprint);
  assertEqual(value.channel_binding_digest, request.channel_binding_digest);
  assertEqual(value.canonical_request_digest, request.canonical_request_digest);
  assertEqual(value.online_receipt_digest, request.online_receipt_digest);
  assertEqual(value.model_call_anchor_digest, request.model_call_anchor_digest);
  assertEqual(value.max_uses, request.max_uses);
  assertEqual(value.use_id, consumeUseId(request));
  assertEqual(value.catalog_incarnation, onlineReceipt.catalog_incarnation);
  assertEqual(
    value.recovery_frontier_sequence,
    onlineReceipt.recovery_frontier_sequence,
  );
  assertEqual(value.recovery_frontier_hash, onlineReceipt.recovery_frontier_hash);

  const nowMs = now.getTime();
  if (
    Date.parse(committedAt) < Date.parse(onlineReceipt.issued_at) ||
    Date.parse(committedAt) >= Date.parse(expiresAt) ||
    Date.parse(expiresAt) > Date.parse(request.not_after) ||
    Date.parse(expiresAt) <= nowMs ||
    Date.parse(committedAt) > nowMs + allowedClockSkew
  ) {
    throw stale();
  }
  const receipt = value as unknown as CapabilityUseConsumeReceipt;
  assertConsumeReceiptSignature(receipt, publicKey);
  return deepFreeze(receipt) as VerifiedCapabilityUseConsumeReceipt;
}

/**
 * Atomically consumes the sole V1 use through the Accounts-owned durable CAS.
 * Exact idempotent replay returns the original signed receipt; changed replay,
 * exhaustion, adapter errors, and malformed or forged receipts fail closed
 * before an external DISPATCHED anchor or provider effect can begin.
 */
export async function consumeOnlineGenerationCheckReceiptUse(
  source: Uint8Array,
  trust: OnlineGenerationCheckReceiptTrustRoot,
  expectation: OnlineGenerationCheckReceiptExpectation,
  store: OnlineGenerationReceiptUseStore,
  guard: OnlineGenerationReceiptUseGuard,
): Promise<ConsumedOnlineGenerationReceiptUse> {
  const sourceSnapshot = Uint8Array.from(source);
  const trustSnapshot = Object.freeze({
    schemaDigest: trust.schemaDigest,
    issuer: trust.issuer,
    issuerIncarnation: trust.issuerIncarnation,
    keyId: trust.keyId,
    audience: trust.audience,
    publicKey: trust.publicKey,
    revoked: trust.revoked,
  } satisfies OnlineGenerationCheckReceiptTrustRoot);
  const initialNow = trustedClockNow(guard);
  const receipt = verifyAllowedOnlineGenerationCheckReceipt(sourceSnapshot, trustSnapshot, {
    ...expectation,
    now: initialNow,
  });
  const allowedClockSkew = expectation.allowedClockSkewMs ?? 0;
  if (
    store === null ||
    typeof store !== "object" ||
    typeof store.compareAndConsume !== "function"
  ) {
    throw useStoreUnavailable();
  }
  const request = buildUseRequest(receipt, guard);
  let rawResult: unknown;
  try {
    rawResult = await store.compareAndConsume(request);
  } catch {
    throw useStoreUnavailable();
  }
  const result = validateUseStoreResult(rawResult);
  if (result.status !== "consumed" && result.status !== "replayed") {
    throw new AccountsError(
      result.status === "idempotency_conflict" ? "IDEMPOTENCY_CONFLICT" : "CONFLICT",
      "The receipt use could not be consumed",
    );
  }

  const refreshRequestedAt = trustedClockNow(guard);
  if (refreshRequestedAt.getTime() < initialNow.getTime()) throw stale();
  const consumeReceipt = validateConsumeReceipt(
    result.signedReceipt,
    trustSnapshot,
    request,
    receipt,
    refreshRequestedAt,
    allowedClockSkew,
  );
  let refreshed: OnlineGenerationCheckReceiptExpectation;
  try {
    refreshed = await guard.refreshExpectation(receipt, new Date(refreshRequestedAt));
  } catch {
    throw useStoreUnavailable();
  }
  const finalNow = trustedClockNow(guard);
  if (finalNow.getTime() < refreshRequestedAt.getTime()) throw stale();
  if (Date.parse(consumeReceipt.expires_at) <= finalNow.getTime()) throw stale();
  const currentReceipt = verifyAllowedOnlineGenerationCheckReceipt(sourceSnapshot, trustSnapshot, {
    ...refreshed,
    now: finalNow,
  });
  return deepFreeze({
    receipt: currentReceipt,
    use: {
      request,
      consumeReceipt,
      consumeReceiptDigest: canonicalSha256(consumeReceipt),
      useId: consumeReceipt.use_id,
      priorUseCount: consumeReceipt.prior_use_count,
      nextUseCount: consumeReceipt.next_use_count,
      useOrdinal: consumeReceipt.use_ordinal,
      committedAt: consumeReceipt.committed_at,
      expiresAt: consumeReceipt.expires_at,
      replayed: result.status === "replayed",
    },
  }) as ConsumedOnlineGenerationReceiptUse;
}

/** Explicit snake_case wire to camelCase SDK projection, after verification. */
export function projectOnlineGenerationCheckReceipt(
  receipt: VerifiedOnlineGenerationCheckReceipt,
): ProjectedOnlineGenerationCheckReceipt {
  const target: OnlineGenerationReceiptTargetSdk = receipt.access_transport === "native_session"
    ? {
        kind: "native",
        authCapsuleId: receipt.auth_capsule_id,
        canonicalNodeId: receipt.canonical_node_id,
        nodeKeyThumbprint: receipt.node_key_thumbprint,
        nodeGeneration: receipt.node_generation,
        placementGeneration: receipt.placement_generation,
        authGeneration: receipt.auth_generation,
        authStateRevision: receipt.auth_state_revision,
      }
    : {
        kind: "brokered",
        credentialBindingId: receipt.credential_binding_id,
        brokerRef: receipt.broker_ref,
      };
  const projected: OnlineGenerationCheckReceiptSdk = {
    schemaVersion: receipt.schema_version,
    schemaDigest: receipt.schema_digest,
    receiptId: receipt.receipt_id,
    issuer: receipt.issuer,
    issuerIncarnation: receipt.issuer_incarnation,
    keyId: receipt.key_id,
    audience: receipt.audience,
    nonce: receipt.nonce,
    issuedAt: receipt.issued_at,
    notBefore: receipt.not_before,
    expiresAt: receipt.expires_at,
    signature: receipt.signature,
    capabilityId: receipt.capability_id,
    capabilityDigest: receipt.capability_digest,
    authorityEpoch: receipt.authority_epoch,
    routeLineageId: receipt.route_lineage_id,
    routeId: receipt.route_id,
    routeEpoch: receipt.route_epoch,
    runId: receipt.run_id,
    attemptId: receipt.attempt_id,
    attemptLeaseId: receipt.attempt_lease_id,
    leaseEpoch: receipt.lease_epoch,
    resourceLeaseId: receipt.resource_lease_id,
    resourceId: receipt.resource_id,
    resourceLifecycleGeneration: receipt.resource_lifecycle_generation,
    leaseExpiresAt: receipt.lease_expires_at,
    operationId: receipt.operation_id,
    operationDigest: receipt.operation_digest,
    operationExecutionEpoch: receipt.operation_execution_epoch,
    operationExecutionExpiresAt: receipt.operation_execution_expires_at,
    subject: receipt.subject,
    actorPrincipal: receipt.actor_principal,
    leaseHolderPrincipal: receipt.lease_holder_principal,
    operationExecutorPrincipal: receipt.operation_executor_principal,
    senderKeyThumbprint: receipt.sender_key_thumbprint,
    providerAccountId: receipt.provider_account_id,
    accountLaneId: receipt.account_lane_id,
    capacityPoolId: receipt.capacity_pool_id,
    capacityDomainRef: receipt.capacity_domain_ref,
    accessTransport: receipt.access_transport,
    credentialFamilyId: receipt.credential_family_id,
    allowed: receipt.allowed,
    denyState: receipt.deny_state,
    reasonCodes: receipt.reason_codes,
    ...(receipt.deny_state === "denied" ? { currentDeny: true as const } : {}),
    capacityGeneration: receipt.capacity_generation,
    denyGeneration: receipt.deny_generation,
    credentialGeneration: receipt.credential_generation,
    accountsRevisionSetDigest: receipt.accounts_revision_set_digest,
    allowedChannelClass: receipt.allowed_channel_class,
    slotEligibilityDigest: receipt.slot_eligibility_digest,
    approvalRef: receipt.approval_ref,
    policyDigest: receipt.policy_digest,
    canonicalRequestDigest: receipt.canonical_request_digest,
    providerDestinationPolicy: {
      scheme: receipt.provider_destination_policy.scheme,
      normalizedHost: receipt.provider_destination_policy.normalized_host,
      port: receipt.provider_destination_policy.port,
      operationPath: receipt.provider_destination_policy.operation_path,
      model: receipt.provider_destination_policy.model,
      requestBodyDigest: receipt.provider_destination_policy.request_body_digest,
      tlsServerName: receipt.provider_destination_policy.tls_server_name,
      resolvedAddressClass: receipt.provider_destination_policy.resolved_address_class,
      egressPolicyDigest: receipt.provider_destination_policy.egress_policy_digest,
    },
    providerDestinationPolicyDigest: receipt.provider_destination_policy_digest,
    senderConstraintConfirmation: receipt.sender_constraint_confirmation,
    maxUses: receipt.max_uses,
    useCount: receipt.use_count,
    catalogIncarnation: receipt.catalog_incarnation,
    recoveryFrontierSequence: receipt.recovery_frontier_sequence,
    recoveryFrontierHash: receipt.recovery_frontier_hash,
    target,
  };
  return deepFreeze(projected) as ProjectedOnlineGenerationCheckReceipt;
}
