import { type KeyObject } from "node:crypto";

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
