import type { Counter } from "./counter";
import type {
  AccessMethodId,
  AccountId,
  AuthCapsuleId,
  CanonicalNodeId,
  CapacityPoolId,
  CredentialBindingId,
  EligibilityEvidenceId,
  EntitlementId,
} from "./ids";

export const ACCOUNTS_CAPACITY_SCHEMA_VERSION = "accounts.capacity.v1" as const;

export interface RecordBase<Id extends string> {
  readonly id: Id;
  readonly revision: Counter;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type AccountStatus = "pending" | "active" | "suspended" | "revoked";

export interface Account extends RecordBase<AccountId> {
  readonly providerKey: string;
  readonly ownerRef: string;
  readonly displayLabel: string;
  readonly providerSubjectRef?: string;
  readonly providerDisplayHint?: string;
  readonly status: AccountStatus;
}

export type ProviderAccount = Account;

export type FundingKind =
  | "subscription"
  | "metered"
  | "credit"
  | "contract"
  | "externally_managed";

export type EntitlementStatus = "pending" | "active" | "paused" | "expired" | "revoked";

export interface TermsDecision {
  readonly decision: "allowed" | "denied" | "unknown";
  readonly useCase: string;
  readonly evidenceRef: string;
  readonly verifiedBy: string;
  readonly verifiedAt: string;
  readonly expiresAt: string;
  readonly termsVersion: string;
  readonly termsDigest: string;
}

export interface DataPolicy {
  readonly allowedClassifications: readonly string[];
  readonly retentionClass: "none" | "transient" | "bounded";
  readonly maxRetentionDays?: Counter;
}

export interface CapabilitySet {
  readonly operations: readonly string[];
  readonly models: readonly string[];
}

export interface Entitlement extends RecordBase<EntitlementId> {
  readonly accountId: AccountId;
  readonly fundingKind: FundingKind;
  readonly status: EntitlementStatus;
  readonly capabilitySet: CapabilitySet;
  readonly capabilityEvidenceRef: string;
  readonly capabilityDigest: string;
  readonly capabilityExpiresAt: string;
  readonly executionPolicyDecisionRef: string;
  readonly executionPolicyDecisionDigest: string;
  readonly executionPolicyDecisionExpiresAt: string;
  readonly termsDecision: TermsDecision;
  readonly dataPolicy: DataPolicy;
  readonly dataPolicyEvidenceRef: string;
  readonly dataPolicyDigest: string;
  readonly dataPolicyExpiresAt: string;
  readonly lastVerifiedAt: string;
}

export type CapacityPoolStatus = "pending" | "active" | "draining" | "denied" | "retired";
export type DenyState = "allowed" | "denied";

export interface CapacityPool extends RecordBase<CapacityPoolId> {
  readonly accountId: AccountId;
  readonly capacityDomainRef: string;
  readonly evidenceRef: string;
  readonly evidenceExpiresAt: string;
  readonly serializationKey: string;
  readonly maxConcurrency: Counter;
  readonly status: CapacityPoolStatus;
  readonly capacityGeneration: Counter;
  readonly denyGeneration: Counter;
  readonly denyState: DenyState;
}

export type AccessTransport = "native_session" | "api_key" | "workload_identity";
export type AccessMethodStatus = "draft" | "ready" | "draining" | "disabled" | "retired";
export type HealthState = "healthy" | "degraded" | "unavailable" | "unknown";

export interface HealthObservation {
  readonly state: HealthState;
  readonly evidenceRef: string;
  readonly observedAt: string;
  readonly expiresAt: string;
}

export interface AccessMethod extends RecordBase<AccessMethodId> {
  readonly entitlementId: EntitlementId;
  readonly capacityPoolId: CapacityPoolId;
  readonly adapterKey: string;
  readonly adapterVersion: string;
  readonly accessTransport: AccessTransport;
  readonly status: AccessMethodStatus;
  readonly requiredIsolationPolicyRef: string;
  readonly requiredIsolationPolicyDigest: string;
  readonly isolationEvidenceExpiresAt: string;
  readonly allowedDestinationPolicyClasses: readonly string[];
  readonly parentPolicyDecisionRef: string;
  readonly parentPolicyDecisionDigest: string;
  readonly executionPolicyEvidenceRef: string;
  readonly executionPolicyDigest: string;
  readonly executionPolicyExpiresAt: string;
  readonly health?: HealthObservation;
}

export type AccountLane = AccessMethod;

export type AuthCapsuleStatus =
  | "unprovisioned"
  | "bootstrapping"
  | "ready"
  | "degraded"
  | "revoked";

export interface CapsuleAttestation {
  readonly evidenceRef: string;
  readonly issuerRef: string;
  readonly measurementDigest: string;
  readonly attestedAt: string;
  readonly expiresAt: string;
}

export interface AuthCapsule extends RecordBase<AuthCapsuleId> {
  readonly accessMethodId: AccessMethodId;
  readonly capacityPoolId: CapacityPoolId;
  readonly kind: "native_session";
  readonly ownerRef: string;
  readonly placementKind: "enrolled_node";
  readonly placementRef: CanonicalNodeId;
  readonly hardwareKeyThumbprint: string;
  readonly nodeGeneration: Counter;
  readonly placementGeneration: Counter;
  readonly status: AuthCapsuleStatus;
  readonly refreshOwnerRef: string;
  readonly refreshMode: "provider_native" | "interactive_owner";
  readonly authGeneration: Counter;
  readonly authStateRevision: Counter;
  readonly isolationPolicyRef: string;
  readonly isolationPolicyDigest: string;
  readonly attestation?: CapsuleAttestation;
  readonly lastHealthAt?: string;
}

export type CredentialBindingStatus = "pending" | "active" | "retiring" | "revoked";
export type CredentialResolver =
  | "brokered_secret"
  | "workload_identity"
  | "capsule_local_native";
export type CredentialPurpose = "provider_session" | "api_key" | "workload_identity";

export interface CredentialBinding extends RecordBase<CredentialBindingId> {
  readonly accessMethodId: AccessMethodId;
  readonly capacityPoolId: CapacityPoolId;
  readonly authCapsuleId?: AuthCapsuleId;
  readonly credentialFamilyId: string;
  readonly purpose: CredentialPurpose;
  readonly resolver: CredentialResolver;
  readonly credentialGeneration: Counter;
  readonly authStateRevision?: Counter;
  readonly refreshMode?: "broker_serialized";
  readonly status: CredentialBindingStatus;
  readonly policyDigest: string;
  readonly rotatedAt?: string;
  readonly expiresAt?: string;
}

export type EntityKind =
  | "account"
  | "entitlement"
  | "capacity_pool"
  | "access_method"
  | "auth_capsule"
  | "credential_binding";

export interface EntityMap {
  readonly account: Account;
  readonly entitlement: Entitlement;
  readonly capacity_pool: CapacityPool;
  readonly access_method: AccessMethod;
  readonly auth_capsule: AuthCapsule;
  readonly credential_binding: CredentialBinding;
}

export type AnyEntity = EntityMap[EntityKind];

export const ELIGIBILITY_REASON_CODES = [
  "CURRENT_DENY",
  "ACCOUNT_NOT_ACTIVE",
  "ENTITLEMENT_NOT_ACTIVE",
  "TERMS_NOT_ALLOWED",
  "TERMS_STALE",
  "OPERATION_NOT_ALLOWED",
  "MODEL_NOT_ALLOWED",
  "DATA_CLASSIFICATION_NOT_ALLOWED",
  "DESTINATION_POLICY_NOT_ALLOWED",
  "CAPACITY_POOL_NOT_ACTIVE",
  "CAPACITY_EVIDENCE_STALE",
  "ACCESS_METHOD_NOT_READY",
  "HEALTH_NOT_HEALTHY",
  "HEALTH_STALE",
  "POLICY_EVIDENCE_STALE",
  "POLICY_DIGEST_MISMATCH",
  "CAPSULE_REQUIRED",
  "CAPSULE_NOT_READY",
  "CAPSULE_OWNER_MISMATCH",
  "CAPSULE_PLACEMENT_INVALID",
  "ATTESTATION_STALE",
  "CREDENTIAL_BINDING_REQUIRED",
  "CREDENTIAL_BINDING_NOT_ACTIVE",
  "CREDENTIAL_BINDING_RETIRING",
  "CREDENTIAL_BINDING_EXPIRED",
  "INVALID_ACCESS_TARGET",
  "GENERATION_MISMATCH",
  "DEPENDENCY_UNAVAILABLE",
] as const;

export type EligibilityReasonCode = (typeof ELIGIBILITY_REASON_CODES)[number];

export interface EligibilityRequest {
  readonly accessMethodId: AccessMethodId;
  readonly operation: string;
  readonly model: string;
  readonly dataClassification: string;
  readonly destinationPolicyClass: string;
}

export type EligibilityAccessTarget =
  | {
      readonly kind: "native";
      readonly authCapsuleId: AuthCapsuleId;
      readonly canonicalNodeId: string;
      readonly nodeKeyThumbprint: string;
      readonly nodeGeneration: Counter;
      readonly placementGeneration: Counter;
      readonly authGeneration: Counter;
      readonly authStateRevision: Counter;
    }
  | {
      readonly kind: "brokered";
      readonly credentialBindingId: CredentialBindingId;
      readonly resolver: "brokered_secret" | "workload_identity";
    }
  | { readonly kind: "unresolved" };

interface SlotEligibilityBase {
  readonly schemaVersion: "accounts.slot-eligibility.v1";
  readonly evidenceId: EligibilityEvidenceId;
  readonly evidenceClass: "local_diagnostic";
  readonly authority: "none";
  readonly reservation: "none";
  readonly accessMethodId: AccessMethodId;
  readonly accessTarget: EligibilityAccessTarget;
  readonly eligibilityRequestDigest: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface EligibleSlotEligibility extends SlotEligibilityBase {
  readonly eligible: true;
  readonly reasonCodes: readonly [];
  readonly accountId: AccountId;
  readonly entitlementId: EntitlementId;
  readonly capacityPoolId: CapacityPoolId;
  readonly ownerRef: string;
  readonly accessTransport: AccessTransport;
  readonly accessTarget: Exclude<EligibilityAccessTarget, { readonly kind: "unresolved" }>;
  readonly serializationKey: string;
  readonly maxConcurrency: Counter;
  readonly capacityGeneration: Counter;
  readonly denyGeneration: Counter;
  readonly denyState: "allowed";
  readonly credentialFamilyId: string;
  readonly credentialGeneration: Counter;
  readonly recordRevisionSet: Readonly<
    Record<Exclude<EntityKind, "auth_capsule">, Counter> &
      Partial<Record<"auth_capsule", Counter>>
  >;
}

export interface IneligibleSlotEligibility extends SlotEligibilityBase {
  readonly eligible: false;
  readonly reasonCodes: readonly EligibilityReasonCode[];
  readonly accountId?: AccountId;
  readonly entitlementId?: EntitlementId;
  readonly capacityPoolId?: CapacityPoolId;
  readonly ownerRef?: string;
  readonly accessTransport?: AccessTransport;
  readonly serializationKey?: string;
  readonly maxConcurrency?: Counter;
  readonly capacityGeneration?: Counter;
  readonly denyGeneration?: Counter;
  readonly denyState?: DenyState;
  readonly credentialFamilyId?: string;
  readonly credentialGeneration?: Counter;
  readonly recordRevisionSet: Readonly<Partial<Record<EntityKind, Counter>>>;
}

export type SlotEligibilityMetadata = EligibleSlotEligibility | IneligibleSlotEligibility;

export type SlotEligibility = SlotEligibilityMetadata;
