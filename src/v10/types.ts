import type { KeyLike } from "node:crypto";

import type {
  ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1,
  ACCOUNTS_EVIDENCE_SIGNER_HISTORY_SCHEMA_VERSION_V2,
  ONLINE_GENERATION_CHECK_REASON_CODES_V1,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1,
  SLOT_ELIGIBILITY_REASON_CODES_V1,
  SLOT_ELIGIBILITY_SCHEMA_VERSION_V1,
} from "./constants";

declare const v10Brand: unique symbol;
export type V10Brand<Value, Name extends string> = Value & {
  readonly [v10Brand]: Name;
};

export type V10Counter = V10Brand<string, "V10Counter">;
export type V10PositiveCounter = V10Brand<string, "V10PositiveCounter">;
export type V10Sha256Digest = V10Brand<string, "V10Sha256Digest">;
export type V10Timestamp = V10Brand<string, "V10Timestamp">;
export type V10UuidV7 = V10Brand<string, "V10UuidV7">;

export type SlotEligibilityReasonCodeV1 =
  (typeof SLOT_ELIGIBILITY_REASON_CODES_V1)[number];
export type OnlineGenerationCheckReasonCodeV1 =
  (typeof ONLINE_GENERATION_CHECK_REASON_CODES_V1)[number];

export type V10JsonPrimitive = null | boolean | number | string;
export type V10JsonValue =
  | V10JsonPrimitive
  | readonly V10JsonValue[]
  | { readonly [key: string]: V10JsonValue };
export type V10WireObject = Readonly<Record<string, V10JsonValue>>;

export interface AccountsEvidenceSignerKeyV2 {
  readonly key_id: string;
  readonly public_key_spki_base64url: string;
  readonly activated_at: string;
  readonly expires_at: string;
  readonly retired_at: string | null;
  readonly revoked_at: string | null;
}

export interface AccountsEvidenceSignerHistoryV2 {
  readonly schema_version: typeof ACCOUNTS_EVIDENCE_SIGNER_HISTORY_SCHEMA_VERSION_V2;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly audience: string;
  readonly current_key_id: string;
  readonly keys: readonly AccountsEvidenceSignerKeyV2[];
}

export interface AccountsEvidenceSigner {
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly audience: string;
  readonly keyId: string;
  readonly privateKey: KeyLike;
}

export interface SlotEligibilityCommonV1 extends V10WireObject {
  readonly schema_version: typeof SLOT_ELIGIBILITY_SCHEMA_VERSION_V1;
  readonly schema_digest: V10Sha256Digest;
  readonly evidence_id: V10UuidV7;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly catalog_incarnation: string;
  readonly audience: string;
  readonly key_id: string;
  readonly nonce: string;
  readonly account_lane_id: V10UuidV7;
  readonly eligibility_request_digest: V10Sha256Digest;
  readonly reason_codes: readonly SlotEligibilityReasonCodeV1[];
  readonly issued_at: V10Timestamp;
  readonly expires_at: V10Timestamp;
  readonly signature: string;
}

export interface SlotEligibilityResolvedV1 extends SlotEligibilityCommonV1 {
  readonly access_transport: "api_key" | "workload_identity" | "native_session";
  readonly access_target: V10WireObject;
  readonly effect_namespace_id: string;
  readonly provider_account_id: V10UuidV7;
  readonly entitlement_id: V10UuidV7;
  readonly capacity_pool_id: V10UuidV7;
  readonly credential_family_id: V10UuidV7;
  readonly serialization_key: string;
  readonly serialization_key_digest: V10Sha256Digest;
  readonly max_concurrency: V10PositiveCounter;
  readonly capacity_generation: V10Counter;
  readonly deny_generation: V10Counter;
  readonly credential_generation: V10Counter;
  readonly record_revision_set: Readonly<Record<string, V10Counter>>;
  readonly accounts_revision_set_digest: V10Sha256Digest;
  readonly recovery_frontier_sequence: V10Counter;
  readonly recovery_frontier_hash: V10Sha256Digest;
}

export interface SlotEligibilityPositiveV1 extends SlotEligibilityResolvedV1 {
  readonly eligible: true;
  readonly reason_codes: readonly [];
  readonly deny_state: "allowed";
}

export interface SlotEligibilityResolvedNegativeV1 extends SlotEligibilityResolvedV1 {
  readonly eligible: false;
  readonly reason_codes: readonly [SlotEligibilityReasonCodeV1, ...SlotEligibilityReasonCodeV1[]];
  readonly deny_state: "allowed" | "denied";
}

export interface SlotEligibilityUnresolvedNegativeV1 extends SlotEligibilityCommonV1 {
  readonly eligible: false;
  readonly reason_codes: readonly [SlotEligibilityReasonCodeV1, ...SlotEligibilityReasonCodeV1[]];
  readonly rejection_stage: "unresolved";
}

export type SlotEligibilityV1 =
  | SlotEligibilityPositiveV1
  | SlotEligibilityResolvedNegativeV1
  | SlotEligibilityUnresolvedNegativeV1;

export interface OnlineGenerationCheckCommonV1 extends V10WireObject {
  readonly schema_version: typeof ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1;
  readonly schema_digest: V10Sha256Digest;
  readonly receipt_id: V10UuidV7;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly nonce: string;
  readonly issued_at: V10Timestamp;
  readonly not_before: V10Timestamp;
  readonly expires_at: V10Timestamp;
  readonly signature: string;
  readonly sender_constraint_confirmation: string;
  readonly reason_codes: readonly OnlineGenerationCheckReasonCodeV1[];
  readonly capacity_generation: V10Counter;
  readonly deny_generation: V10Counter;
  readonly credential_generation: V10Counter;
  readonly recovery_frontier_sequence: V10Counter;
  readonly recovery_frontier_hash: V10Sha256Digest;
}

export interface AllowedOnlineGenerationCheckReceiptV1
  extends OnlineGenerationCheckCommonV1 {
  readonly allowed: true;
  readonly deny_state: "allowed";
  readonly reason_codes: readonly [];
  readonly max_uses: "1";
  readonly use_count: "0";
}

export interface DeniedOnlineGenerationCheckReceiptV1
  extends OnlineGenerationCheckCommonV1 {
  readonly allowed: false;
  readonly deny_state: "allowed" | "denied";
  readonly reason_codes: readonly [
    OnlineGenerationCheckReasonCodeV1,
    ...OnlineGenerationCheckReasonCodeV1[],
  ];
  readonly max_uses: "1";
  readonly use_count: "0" | "1";
  readonly current_deny?: true;
}

export type OnlineGenerationCheckReceiptV1 =
  | AllowedOnlineGenerationCheckReceiptV1
  | DeniedOnlineGenerationCheckReceiptV1;

export interface AccountsEvidenceTrustV1 {
  readonly signerHistory: AccountsEvidenceSignerHistoryV2;
  readonly now?: Date;
  readonly clock?: () => Date;
  readonly allowedClockSkewMs?: number;
  readonly slotMaximumLifetimeMs?: number;
  readonly slotMaximumAgeMs?: number;
  readonly onlineMaximumLifetimeMs?: number;
  readonly onlineMaximumAgeMs?: number;
  readonly expectedEffectNamespaceId?: string;
  readonly expectedSlotEligibility?: SlotEligibilityPositiveV1;
  readonly previousSlotEligibility?: SlotEligibilityPositiveV1;
}

export interface AccountsSlotEligibilitySource {
  readonly getSlotEligibility: (
    request: AccountsSlotEligibilityRequestV1,
  ) => Promise<Uint8Array> | Uint8Array;
  readonly checkOnlineGeneration: (
    request: AccountsOnlineGenerationSourceRequestV1,
  ) => Promise<Uint8Array> | Uint8Array;
}

export interface DeterministicAccountsSlotEligibilitySource
  extends AccountsSlotEligibilitySource {
  readonly advance: (fixture: {
    readonly slot: Uint8Array;
    readonly online: Uint8Array;
  }) => void;
  readonly setUnavailable: (unavailable: boolean) => void;
}

export interface AccountsSlotEligibilityAdapterTrustV1 extends AccountsEvidenceTrustV1 {
  readonly expectedEffectNamespaceId: string;
}

export interface AccountsSlotEligibilityPort {
  readonly getSlotEligibility: (
    request: AccountsSlotEligibilityRequestV1,
  ) => Promise<SlotEligibilityV1>;
  readonly checkOnlineGeneration: (
    request: AccountsOnlineGenerationCheckRequest,
  ) => Promise<OnlineGenerationCheckReceiptV1>;
}

export interface AccountsOnlineGenerationCheckRequest {
  readonly expectedSlotEligibility: SlotEligibilityPositiveV1;
  readonly context: AccountsOnlineGenerationContextV1;
}

export interface AccountsOnlineGenerationSourceRequestV1 {
  readonly context: AccountsOnlineGenerationContextV1;
  readonly slot_eligibility_digest: V10Sha256Digest;
}

export interface AccountsSlotEligibilityRequestV1 {
  readonly schema_version: typeof ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1;
  readonly account_lane_id: string;
  readonly data_classification: string;
  readonly destination_policy_class: string;
  readonly model: string;
  readonly operation: string;
}

export interface AccountsOnlineGenerationContextV1 {
  readonly authenticated_actor_principal: string;
  readonly account_lane_id: string;
  readonly capability_id: string;
  readonly capability_digest: string;
  readonly nonce: string;
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
  readonly approval_mode: string;
  readonly approval_binding_digest: string;
  readonly policy_digest: string;
  readonly canonical_request_digest: string;
  readonly provider_destination_policy: V10WireObject;
  readonly provider_destination_policy_digest: string;
  readonly sender_constraint_confirmation: string;
  readonly max_uses: "1";
}
