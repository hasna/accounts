import {
  createPublicKey,
  type KeyLike,
  KeyObject,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";

import { AccountsError } from "./errors.js";
import { parseCounter, type Counter } from "./counter.js";
import { generateUuidV7, isUuidV7 } from "./ids.js";
import { canonicalJson, canonicalSha256, parseClosedJsonBytes } from "./json.js";

export const CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION =
  "accounts.capsule-maintenance/v1" as const;
export const CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST =
  "sha256:d9d4849ab62a4d3a59c923bc3957a42f754f99b694cd5393b86dd5b8bbd84fd8" as const;
export const CAPSULE_MAINTENANCE_ISSUANCE_REQUEST_SCHEMA_VERSION =
  "accounts.capsule-maintenance-issuance-request/v1" as const;
export const CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION =
  "accounts.capsule-maintenance-consume-request/v1" as const;
export const CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION =
  "accounts.capsule-maintenance-consume-receipt.v1" as const;
export const CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST =
  "sha256:17b0fe15182d3e33affa550c3f0f21b11e8cc9bc330fa0ea18f2f530b944616f" as const;
export const INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION =
  "infinity.account-maintenance-hold-receipt/v1" as const;
export const INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST =
  "sha256:cf939104366bc82aaf820d6bae85703e3d326ac8454ab9d717d1febd2436e9ed" as const;

export const CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR = Object.freeze({
  action_effect_classes: Object.freeze({
    BOOTSTRAP_NATIVE: Object.freeze(["mutation"]),
    CLEANUP_CREDENTIAL: Object.freeze(["containment_mutation", "mutation"]),
    PROBE_NATIVE: Object.freeze(["read_only"]),
    REAUTHENTICATE_NATIVE: Object.freeze(["mutation"]),
    REFRESH_NATIVE: Object.freeze(["mutation"]),
    REVOKE_BROKERED: Object.freeze(["containment_mutation", "mutation"]),
    REVOKE_PROVIDER_SESSION: Object.freeze(["containment_mutation", "mutation"]),
    ROTATE_BROKERED: Object.freeze(["mutation"]),
  }),
  actions: Object.freeze([
    "BOOTSTRAP_NATIVE",
    "CLEANUP_CREDENTIAL",
    "PROBE_NATIVE",
    "REAUTHENTICATE_NATIVE",
    "REFRESH_NATIVE",
    "REVOKE_BROKERED",
    "REVOKE_PROVIDER_SESSION",
    "ROTATE_BROKERED",
  ]),
  approval_modes: Object.freeze(["NOT_REQUIRED", "REQUIRED"]),
  approval_variant_fields: Object.freeze({
    NOT_REQUIRED: Object.freeze([]),
    REQUIRED: Object.freeze(["approval_ref", "approval_digest"]),
  }),
  common_fields: Object.freeze([
    "schema_version", "schema_digest", "grant_id", "issuer", "issuer_incarnation",
    "key_id", "audience", "effect_namespace_id", "maintenance_authority_epoch",
    "maintenance_operation_id", "operation_digest", "operation_execution_epoch",
    "operation_execution_expires_at", "execution_fence_digest", "action", "effect_class",
    "target_kind", "subject", "actor_principal", "maintenance_executor_principal",
    "sender_key_thumbprint", "channel_binding_digest", "owner_ref", "provider_account_id",
    "provider_subject_ref", "account_lane_id", "capacity_pool_id", "capacity_domain_ref",
    "serialization_key_digest", "access_transport", "credential_family_id",
    "capacity_generation", "deny_generation", "expected_record_revision",
    "expected_credential_generation", "maintenance_decision_digest",
    "canonical_request_digest", "approval_mode", "policy_digest", "catalog_incarnation",
    "recovery_frontier_sequence", "recovery_frontier_hash", "issued_at", "not_before",
    "expires_at", "nonce", "max_uses", "signature",
  ]),
  containment_only_fields: Object.freeze(["containment_authorization_digest"]),
  mutation_only_fields: Object.freeze([
    "source_lineage_digest", "maintenance_hold_receipt_digest", "drain_receipt_digest",
  ]),
  schema_version: CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
  target_variants: Object.freeze({
    account_record: Object.freeze(["credential_binding_id", "expected_binding_revision"]),
    native_capsule: Object.freeze([
      "auth_capsule_id", "canonical_node_id", "node_key_thumbprint", "node_generation",
      "placement_generation", "expected_auth_generation", "expected_auth_state_revision",
    ]),
  }),
});

export const CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR = Object.freeze({
  common_fields: Object.freeze([
    "schema_version", "schema_digest", "consume_receipt_id", "grant_id", "grant_digest",
    "issuer", "issuer_incarnation", "key_id", "audience", "effect_namespace_id",
    "maintenance_authority_epoch", "maintenance_operation_id", "operation_digest",
    "operation_step_id", "operation_execution_epoch", "operation_execution_expires_at",
    "action", "target_digest", "subject", "actor_principal",
    "maintenance_executor_principal", "sender_key_thumbprint", "channel_binding_digest",
    "execution_fence_digest", "max_uses", "prior_use_count", "next_use_count",
    "use_ordinal", "maintenance_use_id", "committed_at", "expires_at",
    "catalog_incarnation", "recovery_frontier_sequence", "recovery_frontier_hash", "signature",
  ]),
  mutation_actions: Object.freeze([
    "BOOTSTRAP_NATIVE", "CLEANUP_CREDENTIAL", "REAUTHENTICATE_NATIVE", "REFRESH_NATIVE",
    "REVOKE_BROKERED", "REVOKE_PROVIDER_SESSION", "ROTATE_BROKERED",
  ]),
  mutation_only_fields: Object.freeze(["source_lineage_digest"]),
  schema_version: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
});

export const INFINITY_MAINTENANCE_HELD_RECEIPT_DESCRIPTOR = Object.freeze({
  fields: Object.freeze([
    "schema_version", "schema_digest", "receipt_id", "issuer", "issuer_incarnation", "key_id",
    "audience", "effect_namespace_id", "authority_epoch", "hold_id", "hold_generation",
    "hold_state", "hold_begin_receipt_digest", "barrier_head_receipt_digest",
    "maintenance_operation_id", "operation_digest", "source_lineage_digest",
    "operation_execution_epoch", "operation_execution_expires_at", "execution_fence_digest",
    "action", "effect_class", "drain_receipt_digest", "account_resource_id",
    "resource_lifecycle_generation", "target_digest", "owner_ref", "provider_account_id",
    "provider_subject_ref", "account_lane_id", "capacity_pool_id", "capacity_domain_ref",
    "serialization_key_digest", "access_transport", "credential_family_id", "capacity_generation",
    "deny_generation", "credential_generation", "resource_lease_frontier_sequence",
    "resource_lease_frontier_hash", "model_effect_frontier_sequence", "model_effect_frontier_hash",
    "delivery_frontier_sequence", "delivery_frontier_hash", "active_resource_lease_count",
    "unresolved_effect_count", "queued_delivery_count", "inflight_delivery_count",
    "ambiguity_obligation_count", "obligation_set_digest", "issued_at", "observed_at",
    "expires_at", "signature",
  ]),
  literals: Object.freeze({
    active_resource_lease_count: "0",
    ambiguity_obligation_count: "0",
    hold_state: "HELD",
    inflight_delivery_count: "0",
    queued_delivery_count: "0",
    unresolved_effect_count: "0",
  }),
  schema_version: INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION,
});

assertDescriptor(
  CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  "capsule maintenance grant",
);
assertDescriptor(
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  "capsule maintenance consume receipt",
);
assertDescriptor(
  INFINITY_MAINTENANCE_HELD_RECEIPT_DESCRIPTOR,
  INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST,
  "Infinity maintenance HELD receipt",
);

export type CapsuleMaintenanceAction =
  | "BOOTSTRAP_NATIVE"
  | "CLEANUP_CREDENTIAL"
  | "PROBE_NATIVE"
  | "REAUTHENTICATE_NATIVE"
  | "REFRESH_NATIVE"
  | "REVOKE_BROKERED"
  | "REVOKE_PROVIDER_SESSION"
  | "ROTATE_BROKERED";
export type CapsuleMaintenanceEffectClass = "read_only" | "mutation" | "containment_mutation";
export type CapsuleMaintenanceTargetKind = "account_record" | "native_capsule";
export type CapsuleMaintenanceApprovalMode = "NOT_REQUIRED" | "REQUIRED";

export interface CapsuleMaintenanceTransportBinding {
  readonly authenticatedOwnerRef: string;
  readonly authenticatedActorPrincipal: string;
  readonly authenticatedMaintenanceExecutorPrincipal: string;
  readonly authenticatedSenderKeyThumbprint: string;
  readonly authenticatedChannelBindingDigest: string;
}

export interface CapsuleMaintenanceGrant extends Readonly<Record<string, unknown>> {
  readonly schema_version: typeof CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION;
  readonly schema_digest: typeof CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST;
  readonly grant_id: string;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly effect_namespace_id: string;
  readonly maintenance_authority_epoch: Counter;
  readonly maintenance_operation_id: string;
  readonly operation_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly operation_execution_expires_at: string;
  readonly execution_fence_digest: string;
  readonly action: CapsuleMaintenanceAction;
  readonly effect_class: CapsuleMaintenanceEffectClass;
  readonly target_kind: CapsuleMaintenanceTargetKind;
  readonly subject: string;
  readonly actor_principal: string;
  readonly maintenance_executor_principal: string;
  readonly sender_key_thumbprint: string;
  readonly channel_binding_digest: string;
  readonly owner_ref: string;
  readonly provider_account_id: string;
  readonly provider_subject_ref: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly capacity_domain_ref: string;
  readonly serialization_key_digest: string;
  readonly access_transport: "native_session" | "api_key" | "workload_identity";
  readonly credential_family_id: string;
  readonly capacity_generation: Counter;
  readonly deny_generation: Counter;
  readonly expected_record_revision: Counter;
  readonly expected_credential_generation: Counter;
  readonly maintenance_decision_digest: string;
  readonly canonical_request_digest: string;
  readonly approval_mode: CapsuleMaintenanceApprovalMode;
  readonly policy_digest: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: Counter;
  readonly recovery_frontier_hash: string;
  readonly issued_at: string;
  readonly not_before: string;
  readonly expires_at: string;
  readonly nonce: string;
  readonly max_uses: "1";
  readonly signature: string;
}

export interface VerifiedInfinityMaintenanceHeldReceipt extends Readonly<Record<string, unknown>> {
  readonly schema_version: typeof INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION;
  readonly schema_digest: typeof INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST;
  readonly receipt_id: string;
  readonly effect_namespace_id: string;
  readonly authority_epoch: Counter;
  readonly hold_id: string;
  readonly hold_generation: Counter;
  readonly maintenance_operation_id: string;
  readonly operation_digest: string;
  readonly source_lineage_digest: string;
  readonly operation_execution_epoch: Counter;
  readonly operation_execution_expires_at: string;
  readonly execution_fence_digest: string;
  readonly action: CapsuleMaintenanceAction;
  readonly effect_class: "mutation" | "containment_mutation";
  readonly drain_receipt_digest: string;
  readonly target_digest: string;
  readonly serialization_key_digest: string;
  readonly expires_at: string;
}

export interface CapsuleMaintenanceConsumeReceipt extends Readonly<Record<string, unknown>> {
  readonly schema_version: typeof CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION;
  readonly schema_digest: typeof CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST;
  readonly consume_receipt_id: string;
  readonly grant_id: string;
  readonly grant_digest: string;
  readonly maintenance_use_id: string;
  readonly use_ordinal: "1";
  readonly signature: string;
}

export interface CapsuleMaintenanceTrust {
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly publicKey: KeyObject | string | Buffer;
}

export interface InfinityMaintenanceHeldTrust extends CapsuleMaintenanceTrust {
  readonly authorityEpoch: Counter;
}

export interface CapsuleMaintenanceCurrentState {
  /** Must compare every grant field and current non-rewindable authority/frontier before issuance. */
  verifyIssuance(
    grant: CapsuleMaintenanceGrant,
    held: VerifiedInfinityMaintenanceHeldReceipt | undefined,
  ): void | Promise<void>;
  /** Must repeat the complete comparison immediately before the ledger consume transaction. */
  verifyConsume(
    grant: CapsuleMaintenanceGrant,
    held: VerifiedInfinityMaintenanceHeldReceipt | undefined,
  ): void | Promise<void>;
  /** Must prove this exact signed HELD digest is the current Infinity serialization-domain head. */
  verifyCurrentHeldHead(
    heldReceiptDigest: string,
    held: VerifiedInfinityMaintenanceHeldReceipt,
  ): void | Promise<void>;
}

export interface CapsuleMaintenanceGrantReservation {
  readonly grantId: string;
  readonly ownerRef: string;
  readonly idempotencyKeyDigest: string;
  readonly requestDigest: string;
  readonly reservationKeyDigest: string;
  readonly grantDigest: string;
  readonly grantBytes: Uint8Array;
  readonly expiresAt: string;
}

export interface CapsuleMaintenanceUseCommit {
  readonly grantId: string;
  readonly ownerRef: string;
  readonly idempotencyKeyDigest: string;
  readonly requestDigest: string;
  readonly maintenanceUseId: string;
  readonly consumeReceiptDigest: string;
  readonly consumeReceiptBytes: Uint8Array;
  readonly committedAt: string;
}

export type CapsuleMaintenanceReserveResult =
  | { readonly status: "reserved" | "replayed"; readonly grantBytes: Uint8Array }
  | { readonly status: "idempotency_conflict" | "reservation_conflict" };
export type CapsuleMaintenanceConsumeResult =
  | { readonly status: "consumed" | "replayed"; readonly consumeReceiptBytes: Uint8Array }
  | { readonly status: "idempotency_conflict" | "exhausted" | "not_found" };

/** Production implementations must make each method one serializable durable transaction. */
export interface CapsuleMaintenanceLedger {
  reserve(input: CapsuleMaintenanceGrantReservation): Promise<CapsuleMaintenanceReserveResult>;
  consume(input: CapsuleMaintenanceUseCommit): Promise<CapsuleMaintenanceConsumeResult>;
}

export interface CapsuleMaintenanceAuthorityOptions extends CapsuleMaintenanceTrust {
  readonly privateKey: KeyLike;
  readonly infinityHeldTrust: InfinityMaintenanceHeldTrust;
  readonly currentState: CapsuleMaintenanceCurrentState;
  readonly ledger: CapsuleMaintenanceLedger;
  readonly maintenanceAuthorityEpoch: Counter;
  readonly clock?: () => Date;
  readonly idFactory?: (nowMs: number) => string;
  readonly grantLifetimeMs?: number;
}

type JsonObject = Record<string, unknown>;

const PRINCIPAL = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

const ACTION_STEPS: Readonly<Record<CapsuleMaintenanceAction, string>> = Object.freeze({
  BOOTSTRAP_NATIVE: "bootstrap_native",
  CLEANUP_CREDENTIAL: "cleanup_credential",
  PROBE_NATIVE: "probe_native",
  REAUTHENTICATE_NATIVE: "reauthenticate_native",
  REFRESH_NATIVE: "refresh_native",
  REVOKE_BROKERED: "revoke_brokered",
  REVOKE_PROVIDER_SESSION: "revoke_provider_session",
  ROTATE_BROKERED: "rotate_brokered",
});

const NATIVE_ACTIONS = new Set<CapsuleMaintenanceAction>([
  "BOOTSTRAP_NATIVE", "PROBE_NATIVE", "REAUTHENTICATE_NATIVE", "REFRESH_NATIVE",
  "REVOKE_PROVIDER_SESSION",
]);
const ACCOUNT_ACTIONS = new Set<CapsuleMaintenanceAction>([
  "CLEANUP_CREDENTIAL", "REVOKE_BROKERED", "ROTATE_BROKERED",
]);
const CONTAINMENT_ACTIONS = new Set<CapsuleMaintenanceAction>([
  "CLEANUP_CREDENTIAL", "REVOKE_BROKERED", "REVOKE_PROVIDER_SESSION",
]);

const ISSUANCE_KEYS = Object.freeze([
  "schema_version", "account_lane_id", "idempotency_key_digest", "hold_receipt_jcs_base64url", "draft",
]);
const CONSUME_KEYS = Object.freeze([
  "schema_version", "account_lane_id", "idempotency_key_digest", "grant_jcs_base64url",
  "hold_receipt_jcs_base64url",
]);

const DRAFT_COMMON_KEYS = Object.freeze([
  "effect_namespace_id", "maintenance_authority_epoch", "maintenance_operation_id",
  "operation_execution_epoch", "operation_execution_expires_at", "execution_fence_digest",
  "action", "effect_class", "target_kind", "subject", "owner_ref", "provider_account_id",
  "provider_subject_ref", "account_lane_id", "capacity_pool_id", "capacity_domain_ref",
  "serialization_key_digest", "access_transport", "credential_family_id", "capacity_generation",
  "deny_generation", "expected_record_revision", "expected_credential_generation",
  "maintenance_decision_digest", "approval_mode", "policy_digest", "catalog_incarnation",
  "recovery_frontier_sequence", "recovery_frontier_hash", "nonce",
]);

export class CapsuleMaintenanceAuthority {
  private readonly publicKey: KeyObject;
  private readonly clock: () => Date;
  private readonly idFactory: (nowMs: number) => string;
  private readonly grantLifetimeMs: number;

  constructor(private readonly options: CapsuleMaintenanceAuthorityOptions) {
    for (const value of [options.issuer, options.issuerIncarnation, options.keyId, options.audience]) {
      reference(value);
    }
    this.publicKey = publicKey(options.publicKey);
    this.clock = options.clock ?? (() => new Date());
    this.idFactory = options.idFactory ?? generateUuidV7;
    this.grantLifetimeMs = options.grantLifetimeMs ?? 30_000;
    positiveCounter(options.maintenanceAuthorityEpoch);
    if (!Number.isInteger(this.grantLifetimeMs) || this.grantLifetimeMs < 1 || this.grantLifetimeMs > 60_000) {
      throw invalid("grantLifetimeMs");
    }
    const challenge = Buffer.from("accounts.capsule-maintenance-key-check/v1", "utf8");
    if (!verifyBytes(null, challenge, this.publicKey, signBytes(null, challenge, options.privateKey))) {
      throw invalid("privateKey");
    }
  }

  async issueMaintenanceGrant(
    source: unknown,
    transport: CapsuleMaintenanceTransportBinding,
  ): Promise<CapsuleMaintenanceGrant> {
    const request = parseIssuanceRequest(source);
    const binding = validateTransport(transport);
    const draft = parseGrantDraft(request.draft);
    if (
      draft.account_lane_id !== request.accountLaneId ||
      draft.owner_ref !== binding.authenticatedOwnerRef ||
      draft.maintenance_authority_epoch !== this.options.maintenanceAuthorityEpoch
    ) {
      throw forbidden("Maintenance issuance transport or authority epoch mismatch");
    }
    const targetDigest = maintenanceTargetDigest(draft);
    const requestDigest = maintenanceCanonicalRequestDigest(draft, targetDigest);
    const sourceLineageDigest = draft.action === "PROBE_NATIVE"
      ? undefined
      : maintenanceSourceLineageDigest(draft, targetDigest, requestDigest);
    const operationDigest = maintenanceOperationDigest(
      draft,
      targetDigest,
      requestDigest,
      sourceLineageDigest,
    );
    const held = draft.action === "PROBE_NATIVE"
      ? requireNoHeldReceipt(request.holdReceiptBytes)
      : verifyHeldForDraft(
          request.holdReceiptBytes,
          this.options.infinityHeldTrust,
          draft,
          targetDigest,
          sourceLineageDigest!,
          operationDigest,
          this.now(),
        );
    if (held !== undefined) {
      await this.options.currentState.verifyCurrentHeldHead(canonicalSha256Bytes(request.holdReceiptBytes!), held);
    }
    const now = this.now();
    const expiresAt = new Date(Math.min(
      now.getTime() + this.grantLifetimeMs,
      Date.parse(String(draft.operation_execution_expires_at)),
      held === undefined ? Number.POSITIVE_INFINITY : Date.parse(held.expires_at),
    ));
    if (expiresAt.getTime() <= now.getTime()) throw stale("Maintenance evidence expired");
    const unsigned: JsonObject = {
      schema_version: CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
      schema_digest: CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
      grant_id: this.newId(now.getTime()),
      issuer: this.options.issuer,
      issuer_incarnation: this.options.issuerIncarnation,
      key_id: this.options.keyId,
      audience: this.options.audience,
      ...draft,
      operation_digest: operationDigest,
      canonical_request_digest: requestDigest,
      actor_principal: binding.authenticatedActorPrincipal,
      maintenance_executor_principal: binding.authenticatedMaintenanceExecutorPrincipal,
      sender_key_thumbprint: binding.authenticatedSenderKeyThumbprint,
      channel_binding_digest: binding.authenticatedChannelBindingDigest,
      ...(held === undefined ? {} : {
        source_lineage_digest: sourceLineageDigest,
        maintenance_hold_receipt_digest: canonicalSha256Bytes(request.holdReceiptBytes!),
        drain_receipt_digest: held.drain_receipt_digest,
      }),
      issued_at: now.toISOString(),
      not_before: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      max_uses: "1",
    };
    const grant = Object.freeze({
      ...unsigned,
      signature: signCanonical(unsigned, this.options.privateKey),
    }) as CapsuleMaintenanceGrant;
    verifyGrantObject(grant, this.options, now);
    await this.options.currentState.verifyIssuance(grant, held);
    const grantBytes = canonicalBytes(grant);
    const reservation = await this.options.ledger.reserve({
      grantId: grant.grant_id,
      ownerRef: grant.owner_ref,
      idempotencyKeyDigest: request.idempotencyKeyDigest,
      requestDigest: canonicalSha256({
        draft,
        hold_receipt_digest: held === undefined ? null : canonicalSha256Bytes(request.holdReceiptBytes!),
        transport: binding,
      }),
      reservationKeyDigest: maintenanceReservationKeyDigest(grant),
      grantDigest: canonicalSha256Bytes(grantBytes),
      grantBytes,
      expiresAt: grant.expires_at,
    });
    if (reservation.status === "idempotency_conflict") throw idempotencyConflict();
    if (reservation.status === "reservation_conflict") {
      throw new AccountsError("CONFLICT", "A live maintenance reservation already exists");
    }
    if (reservation.status !== "reserved" && reservation.status !== "replayed") {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Maintenance ledger returned an invalid result");
    }
    return verifyCapsuleMaintenanceGrant(reservation.grantBytes, this.options, this.now());
  }

  async consumeMaintenanceGrant(
    source: unknown,
    transport: CapsuleMaintenanceTransportBinding,
  ): Promise<CapsuleMaintenanceConsumeReceipt> {
    const request = parseConsumeRequest(source);
    const binding = validateTransport(transport);
    const grant = verifyCapsuleMaintenanceGrant(request.grantBytes, this.options, this.now());
    if (grant.account_lane_id !== request.accountLaneId) throw forbidden("Maintenance lane mismatch");
    assertGrantTransport(grant, binding);
    const targetDigest = maintenanceTargetDigest(grant);
    const held = grant.action === "PROBE_NATIVE"
      ? requireNoHeldReceipt(request.holdReceiptBytes)
      : verifyHeldForGrant(
          request.holdReceiptBytes,
          this.options.infinityHeldTrust,
          grant,
          targetDigest,
          this.now(),
        );
    if (held !== undefined) {
      await this.options.currentState.verifyCurrentHeldHead(canonicalSha256Bytes(request.holdReceiptBytes!), held);
    }
    await this.options.currentState.verifyConsume(grant, held);
    const now = this.now();
    const operationStepId = ACTION_STEPS[grant.action];
    const grantDigest = canonicalSha256Bytes(request.grantBytes);
    const maintenanceUseId = maintenanceUseIdDigest({
      grant_id: grant.grant_id,
      grant_digest: grantDigest,
      maintenance_operation_id: grant.maintenance_operation_id,
      operation_step_id: operationStepId,
      operation_execution_epoch: grant.operation_execution_epoch,
      sender_key_thumbprint: grant.sender_key_thumbprint,
      channel_binding_digest: grant.channel_binding_digest,
      use_ordinal: "1",
    });
    const expiresAt = new Date(Math.min(
      now.getTime() + 60_000,
      Date.parse(grant.expires_at),
      Date.parse(grant.operation_execution_expires_at),
    ));
    if (expiresAt.getTime() <= now.getTime()) throw stale("Maintenance grant expired");
    const unsigned: JsonObject = {
      schema_version: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
      schema_digest: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
      consume_receipt_id: this.newId(now.getTime()),
      grant_id: grant.grant_id,
      grant_digest: grantDigest,
      issuer: this.options.issuer,
      issuer_incarnation: this.options.issuerIncarnation,
      key_id: this.options.keyId,
      audience: this.options.audience,
      effect_namespace_id: grant.effect_namespace_id,
      maintenance_authority_epoch: grant.maintenance_authority_epoch,
      maintenance_operation_id: grant.maintenance_operation_id,
      operation_digest: grant.operation_digest,
      operation_step_id: operationStepId,
      operation_execution_epoch: grant.operation_execution_epoch,
      operation_execution_expires_at: grant.operation_execution_expires_at,
      action: grant.action,
      target_digest: targetDigest,
      subject: grant.subject,
      actor_principal: grant.actor_principal,
      maintenance_executor_principal: grant.maintenance_executor_principal,
      sender_key_thumbprint: grant.sender_key_thumbprint,
      channel_binding_digest: grant.channel_binding_digest,
      execution_fence_digest: grant.execution_fence_digest,
      max_uses: "1",
      prior_use_count: "0",
      next_use_count: "1",
      use_ordinal: "1",
      maintenance_use_id: maintenanceUseId,
      committed_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      catalog_incarnation: grant.catalog_incarnation,
      recovery_frontier_sequence: grant.recovery_frontier_sequence,
      recovery_frontier_hash: grant.recovery_frontier_hash,
      ...(grant.action === "PROBE_NATIVE" ? {} : {
        source_lineage_digest: grant.source_lineage_digest,
      }),
    };
    const receipt = Object.freeze({
      ...unsigned,
      signature: signCanonical(unsigned, this.options.privateKey),
    }) as CapsuleMaintenanceConsumeReceipt;
    const receiptBytes = canonicalBytes(receipt);
    const consumeRequestDigest = canonicalSha256({
      grant_digest: grantDigest,
      hold_receipt_digest: held === undefined ? null : canonicalSha256Bytes(request.holdReceiptBytes!),
      schema_version: CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION,
      transport: binding,
    });
    const committed = await this.options.ledger.consume({
      grantId: grant.grant_id,
      ownerRef: grant.owner_ref,
      idempotencyKeyDigest: request.idempotencyKeyDigest,
      requestDigest: consumeRequestDigest,
      maintenanceUseId,
      consumeReceiptDigest: canonicalSha256Bytes(receiptBytes),
      consumeReceiptBytes: receiptBytes,
      committedAt: now.toISOString(),
    });
    if (committed.status === "idempotency_conflict") throw idempotencyConflict();
    if (committed.status === "exhausted") throw new AccountsError("CONFLICT", "Maintenance grant is exhausted");
    if (committed.status === "not_found") throw new AccountsError("NOT_FOUND", "Maintenance grant was not found");
    if (committed.status !== "consumed" && committed.status !== "replayed") {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Maintenance ledger returned an invalid result");
    }
    return parseConsumeReceipt(committed.consumeReceiptBytes, this.options, grant, this.now());
  }

  private now(): Date {
    let value: Date;
    try {
      value = this.clock();
    } catch {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Trusted clock unavailable");
    }
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw invalid("clock");
    return new Date(value);
  }

  private newId(nowMs: number): string {
    const value = this.idFactory(nowMs);
    if (!isUuidV7(value)) throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Identifier source failed");
    return value;
  }
}

export class InMemoryCapsuleMaintenanceLedgerState {
  readonly grantsByIdempotency = new Map<string, CapsuleMaintenanceGrantReservation>();
  readonly grantsById = new Map<string, CapsuleMaintenanceGrantReservation>();
  readonly liveReservations = new Map<string, string>();
  readonly usesByIdempotency = new Map<string, CapsuleMaintenanceUseCommit>();
  readonly usesByGrant = new Map<string, CapsuleMaintenanceUseCommit>();
  tail: Promise<void> = Promise.resolve();
}

/** Test/conformance ledger only. Production code must use a durable adapter. */
export class InMemoryCapsuleMaintenanceLedger implements CapsuleMaintenanceLedger {
  constructor(readonly state = new InMemoryCapsuleMaintenanceLedgerState()) {}

  reserve(input: CapsuleMaintenanceGrantReservation): Promise<CapsuleMaintenanceReserveResult> {
    return this.serial(async () => {
      const prior = this.state.grantsByIdempotency.get(input.idempotencyKeyDigest);
      if (prior !== undefined) {
        return prior.requestDigest === input.requestDigest
          ? { status: "replayed", grantBytes: Uint8Array.from(prior.grantBytes) }
          : { status: "idempotency_conflict" };
      }
      const liveGrantId = this.state.liveReservations.get(input.reservationKeyDigest);
      if (liveGrantId !== undefined) {
        const live = this.state.grantsById.get(liveGrantId);
        if (live !== undefined && Date.parse(live.expiresAt) > Date.now()) {
          return { status: "reservation_conflict" };
        }
        this.state.liveReservations.delete(input.reservationKeyDigest);
      }
      const stored = cloneReservation(input);
      this.state.grantsByIdempotency.set(input.idempotencyKeyDigest, stored);
      this.state.grantsById.set(input.grantId, stored);
      this.state.liveReservations.set(input.reservationKeyDigest, input.grantId);
      return { status: "reserved", grantBytes: Uint8Array.from(input.grantBytes) };
    });
  }

  consume(input: CapsuleMaintenanceUseCommit): Promise<CapsuleMaintenanceConsumeResult> {
    return this.serial(async () => {
      const idempotent = this.state.usesByIdempotency.get(input.idempotencyKeyDigest);
      if (idempotent !== undefined) {
        return idempotent.requestDigest === input.requestDigest && idempotent.grantId === input.grantId
          ? { status: "replayed", consumeReceiptBytes: Uint8Array.from(idempotent.consumeReceiptBytes) }
          : { status: "idempotency_conflict" };
      }
      if (!this.state.grantsById.has(input.grantId)) return { status: "not_found" };
      const prior = this.state.usesByGrant.get(input.grantId);
      if (prior !== undefined) return { status: "exhausted" };
      const stored = cloneUse(input);
      this.state.usesByIdempotency.set(input.idempotencyKeyDigest, stored);
      this.state.usesByGrant.set(input.grantId, stored);
      return { status: "consumed", consumeReceiptBytes: Uint8Array.from(input.consumeReceiptBytes) };
    });
  }

  private async serial<T>(operation: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.state.tail;
    this.state.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

export function verifyCapsuleMaintenanceGrant(
  source: Uint8Array,
  trust: CapsuleMaintenanceTrust,
  now: Date,
): CapsuleMaintenanceGrant {
  const value = parseCanonicalObject(source, "grant");
  const grant = value as CapsuleMaintenanceGrant;
  verifyGrantObject(grant, trust, now);
  return Object.freeze({ ...grant });
}

export function verifyInfinityMaintenanceHeldReceipt(
  source: Uint8Array,
  trust: InfinityMaintenanceHeldTrust,
  now: Date,
): VerifiedInfinityMaintenanceHeldReceipt {
  const value = parseCanonicalObject(source, "heldReceipt");
  exactKeys(value, INFINITY_MAINTENANCE_HELD_RECEIPT_DESCRIPTOR.fields);
  if (
    value.schema_version !== INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION ||
    value.schema_digest !== INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST ||
    value.hold_state !== "HELD"
  ) throw invalid("heldReceipt");
  for (const field of [
    "active_resource_lease_count", "ambiguity_obligation_count", "inflight_delivery_count",
    "queued_delivery_count", "unresolved_effect_count",
  ]) if (value[field] !== "0") throw forbidden("Infinity hold is not quiescent");
  validateSignedEnvelope(value, trust);
  for (const field of [
    "receipt_id", "hold_id", "maintenance_operation_id", "account_resource_id",
    "provider_account_id", "account_lane_id", "capacity_pool_id",
  ]) uuid(value[field]);
  for (const field of [
    "schema_digest", "hold_begin_receipt_digest", "barrier_head_receipt_digest",
    "operation_digest", "source_lineage_digest", "execution_fence_digest",
    "drain_receipt_digest", "target_digest", "serialization_key_digest",
    "resource_lease_frontier_hash", "model_effect_frontier_hash", "delivery_frontier_hash",
    "obligation_set_digest",
  ]) digest(value[field]);
  for (const field of [
    "authority_epoch", "hold_generation", "resource_lifecycle_generation",
    "operation_execution_epoch", "capacity_generation", "deny_generation",
    "credential_generation", "resource_lease_frontier_sequence",
    "model_effect_frontier_sequence", "delivery_frontier_sequence",
  ]) parseCounter(value[field]);
  positiveCounter(value.authority_epoch);
  positiveCounter(value.hold_generation);
  positiveCounter(value.operation_execution_epoch);
  for (const field of ["issued_at", "observed_at", "expires_at", "operation_execution_expires_at"]) {
    timestamp(value[field]);
  }
  if (
    value.authority_epoch !== trust.authorityEpoch ||
    Date.parse(String(value.issued_at)) > now.getTime() + 5_000 ||
    Date.parse(String(value.observed_at)) > now.getTime() + 5_000 ||
    Date.parse(String(value.expires_at)) <= now.getTime() ||
    Date.parse(String(value.operation_execution_expires_at)) <= now.getTime()
  ) throw stale("Infinity hold is stale");
  return Object.freeze({ ...value }) as VerifiedInfinityMaintenanceHeldReceipt;
}

export function maintenanceTargetDigest(source: Readonly<Record<string, unknown>>): string {
  return canonicalSha256(source.target_kind === "native_capsule"
    ? {
        auth_capsule_id: source.auth_capsule_id,
        canonical_node_id: source.canonical_node_id,
        expected_auth_generation: source.expected_auth_generation,
        expected_auth_state_revision: source.expected_auth_state_revision,
        node_generation: source.node_generation,
        node_key_thumbprint: source.node_key_thumbprint,
        placement_generation: source.placement_generation,
        schema_version: "accounts.credential-effect-target.v1",
        target_kind: "native_capsule",
      }
    : {
        credential_binding_id: source.credential_binding_id,
        expected_binding_revision: source.expected_binding_revision,
        schema_version: "accounts.credential-effect-target.v1",
        target_kind: "account_record",
      });
}

function parseIssuanceRequest(source: unknown): {
  readonly idempotencyKeyDigest: string;
  readonly accountLaneId: string;
  readonly holdReceiptBytes: Uint8Array | undefined;
  readonly draft: unknown;
} {
  const value = plainObject(source);
  exactKeys(value, ISSUANCE_KEYS);
  if (value.schema_version !== CAPSULE_MAINTENANCE_ISSUANCE_REQUEST_SCHEMA_VERSION) {
    throw invalid("schema_version");
  }
  digest(value.idempotency_key_digest);
  uuid(value.account_lane_id);
  return {
    idempotencyKeyDigest: value.idempotency_key_digest as string,
    accountLaneId: value.account_lane_id as string,
    holdReceiptBytes: nullableCanonicalBase64(value.hold_receipt_jcs_base64url),
    draft: value.draft,
  };
}

function parseConsumeRequest(source: unknown): {
  readonly idempotencyKeyDigest: string;
  readonly accountLaneId: string;
  readonly grantBytes: Uint8Array;
  readonly holdReceiptBytes: Uint8Array | undefined;
} {
  const value = plainObject(source);
  exactKeys(value, CONSUME_KEYS);
  if (value.schema_version !== CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION) {
    throw invalid("schema_version");
  }
  digest(value.idempotency_key_digest);
  uuid(value.account_lane_id);
  const grantBytes = canonicalBase64(value.grant_jcs_base64url);
  return {
    idempotencyKeyDigest: value.idempotency_key_digest as string,
    accountLaneId: value.account_lane_id as string,
    grantBytes,
    holdReceiptBytes: nullableCanonicalBase64(value.hold_receipt_jcs_base64url),
  };
}

function parseGrantDraft(source: unknown): JsonObject {
  const value = plainObject(source);
  const action = maintenanceAction(value.action);
  const effectClass = maintenanceEffectClass(value.effect_class);
  const targetKind = maintenanceTargetKind(value.target_kind);
  const approvalMode = maintenanceApprovalMode(value.approval_mode);
  assertActionShape(action, effectClass, targetKind);
  const expected = [
    ...DRAFT_COMMON_KEYS,
    ...(targetKind === "native_capsule"
      ? CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.native_capsule
      : CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.account_record),
    ...(approvalMode === "REQUIRED" ? ["approval_ref", "approval_digest"] : []),
    ...(effectClass === "containment_mutation" ? ["containment_authorization_digest"] : []),
  ];
  exactKeys(value, expected);
  for (const field of ["maintenance_operation_id", "provider_account_id", "account_lane_id", "capacity_pool_id"]) {
    uuid(value[field]);
  }
  if (targetKind === "native_capsule") {
    for (const field of ["auth_capsule_id", "canonical_node_id"]) uuid(value[field]);
    digest(value.node_key_thumbprint);
    for (const field of [
      "node_generation", "placement_generation", "expected_auth_generation",
      "expected_auth_state_revision",
    ]) parseCounter(value[field]);
  } else {
    uuid(value.credential_binding_id);
    parseCounter(value.expected_binding_revision);
  }
  for (const field of ["subject", "owner_ref"]) principal(value[field]);
  for (const field of [
    "effect_namespace_id", "provider_subject_ref", "capacity_domain_ref", "credential_family_id",
    "catalog_incarnation", "nonce",
  ]) reference(value[field]);
  if (!new Set(["native_session", "api_key", "workload_identity"]).has(String(value.access_transport))) {
    throw invalid("access_transport");
  }
  if (
    (targetKind === "native_capsule" && value.access_transport !== "native_session") ||
    (targetKind === "account_record" && value.access_transport === "native_session")
  ) throw invalid("access_transport");
  for (const field of [
    "execution_fence_digest", "serialization_key_digest", "maintenance_decision_digest",
    "policy_digest", "recovery_frontier_hash", "approval_digest",
    "containment_authorization_digest",
  ]) if (value[field] !== undefined) digest(value[field]);
  if (approvalMode === "REQUIRED") reference(value.approval_ref);
  for (const field of [
    "maintenance_authority_epoch", "operation_execution_epoch", "capacity_generation",
    "deny_generation", "expected_record_revision", "expected_credential_generation",
    "recovery_frontier_sequence",
  ]) parseCounter(value[field]);
  positiveCounter(value.maintenance_authority_epoch);
  positiveCounter(value.operation_execution_epoch);
  timestamp(value.operation_execution_expires_at);
  return Object.freeze({ ...value });
}

function verifyGrantObject(grant: CapsuleMaintenanceGrant, trust: CapsuleMaintenanceTrust, now: Date): void {
  const value = plainObject(grant);
  const action = maintenanceAction(value.action);
  const effectClass = maintenanceEffectClass(value.effect_class);
  const targetKind = maintenanceTargetKind(value.target_kind);
  const approvalMode = maintenanceApprovalMode(value.approval_mode);
  assertActionShape(action, effectClass, targetKind);
  const expected = [
    ...CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.common_fields,
    ...(targetKind === "native_capsule"
      ? CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.native_capsule
      : CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.account_record),
    ...(approvalMode === "REQUIRED" ? ["approval_ref", "approval_digest"] : []),
    ...(effectClass === "read_only" ? [] : CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.mutation_only_fields),
    ...(effectClass === "containment_mutation"
      ? CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.containment_only_fields
      : []),
  ];
  exactKeys(value, expected);
  if (
    value.schema_version !== CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION ||
    value.schema_digest !== CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST ||
    value.max_uses !== "1"
  ) throw invalid("grant");
  validateSignedEnvelope(value, trust);
  const draft: JsonObject = Object.create(null) as JsonObject;
  for (const key of expected) {
    if (DRAFT_COMMON_KEYS.includes(key as (typeof DRAFT_COMMON_KEYS)[number]) ||
        CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.native_capsule.includes(key as never) ||
        CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.target_variants.account_record.includes(key as never) ||
        ["approval_ref", "approval_digest", "containment_authorization_digest"].includes(key)) {
      draft[key] = value[key];
    }
  }
  parseGrantDraft({ ...draft });
  uuid(value.grant_id);
  for (const field of ["operation_digest", "canonical_request_digest"]) digest(value[field]);
  const targetDigest = maintenanceTargetDigest(value);
  const expectedRequest = maintenanceCanonicalRequestDigest(value, targetDigest);
  if (value.canonical_request_digest !== expectedRequest) throw forbidden("Maintenance request digest mismatch");
  if (action !== "PROBE_NATIVE") {
    const lineage = maintenanceSourceLineageDigest(value, targetDigest, expectedRequest);
    if (value.source_lineage_digest !== lineage) throw forbidden("Maintenance lineage mismatch");
    for (const field of ["maintenance_hold_receipt_digest", "drain_receipt_digest"]) digest(value[field]);
  }
  const expectedOperation = maintenanceOperationDigest(
    value,
    targetDigest,
    expectedRequest,
    action === "PROBE_NATIVE" ? undefined : String(value.source_lineage_digest),
  );
  if (value.operation_digest !== expectedOperation) throw forbidden("Maintenance operation digest mismatch");
  const issuedAt = timestamp(value.issued_at);
  const notBefore = timestamp(value.not_before);
  const expiresAt = timestamp(value.expires_at);
  const operationExpiresAt = timestamp(value.operation_execution_expires_at);
  if (
    Date.parse(issuedAt) > now.getTime() + 5_000 ||
    Date.parse(notBefore) > now.getTime() + 5_000 ||
    Date.parse(expiresAt) <= now.getTime() ||
    Date.parse(operationExpiresAt) <= now.getTime() ||
    Date.parse(expiresAt) - Date.parse(issuedAt) > 60_000 ||
    Date.parse(operationExpiresAt) < Date.parse(expiresAt) ||
    Date.parse(operationExpiresAt) > Date.parse(issuedAt) + 300_000
  ) throw stale("Maintenance grant is stale");
}

function verifyHeldForDraft(
  source: Uint8Array | undefined,
  trust: InfinityMaintenanceHeldTrust,
  draft: JsonObject,
  targetDigest: string,
  sourceLineageDigest: string,
  operationDigest: string,
  now: Date,
): VerifiedInfinityMaintenanceHeldReceipt {
  if (source === undefined) throw forbidden("Signed Infinity HELD receipt is required");
  const held = verifyInfinityMaintenanceHeldReceipt(source, trust, now);
  assertHeldBindings(held, draft, targetDigest, sourceLineageDigest, operationDigest);
  return held;
}

function verifyHeldForGrant(
  source: Uint8Array | undefined,
  trust: InfinityMaintenanceHeldTrust,
  grant: CapsuleMaintenanceGrant,
  targetDigest: string,
  now: Date,
): VerifiedInfinityMaintenanceHeldReceipt {
  if (source === undefined) throw forbidden("Signed Infinity HELD receipt is required");
  const held = verifyInfinityMaintenanceHeldReceipt(source, trust, now);
  if (canonicalSha256Bytes(source) !== grant.maintenance_hold_receipt_digest) {
    throw forbidden("Maintenance HELD receipt digest mismatch");
  }
  assertHeldBindings(
    held,
    grant,
    targetDigest,
    String(grant.source_lineage_digest),
    grant.operation_digest,
  );
  return held;
}

function assertHeldBindings(
  held: VerifiedInfinityMaintenanceHeldReceipt,
  expected: Readonly<Record<string, unknown>>,
  targetDigest: string,
  sourceLineageDigest: string,
  operationDigest: string,
): void {
  const equalFields = [
    "effect_namespace_id", "maintenance_operation_id", "operation_execution_epoch",
    "operation_execution_expires_at", "execution_fence_digest", "action", "effect_class",
    "owner_ref", "provider_account_id", "provider_subject_ref", "account_lane_id",
    "capacity_pool_id", "capacity_domain_ref", "serialization_key_digest", "access_transport",
    "credential_family_id", "capacity_generation", "deny_generation",
  ];
  for (const field of equalFields) {
    if (held[field] !== expected[field]) throw forbidden("Maintenance HELD binding mismatch");
  }
  if (
    held.target_digest !== targetDigest ||
    held.source_lineage_digest !== sourceLineageDigest ||
    held.operation_digest !== operationDigest ||
    held.credential_generation !== expected.expected_credential_generation
  ) throw forbidden("Maintenance HELD lineage mismatch");
}

function parseConsumeReceipt(
  source: Uint8Array,
  trust: CapsuleMaintenanceTrust,
  grant: CapsuleMaintenanceGrant,
  now: Date,
): CapsuleMaintenanceConsumeReceipt {
  const value = parseCanonicalObject(source, "consumeReceipt");
  const expected = [
    ...CAPSULE_MAINTENANCE_CONSUME_RECEIPT_DESCRIPTOR.common_fields,
    ...(grant.action === "PROBE_NATIVE" ? [] : ["source_lineage_digest"]),
  ];
  exactKeys(value, expected);
  if (
    value.schema_version !== CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION ||
    value.schema_digest !== CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST ||
    value.grant_id !== grant.grant_id ||
    value.operation_step_id !== ACTION_STEPS[grant.action] ||
    value.max_uses !== "1" || value.prior_use_count !== "0" ||
    value.next_use_count !== "1" || value.use_ordinal !== "1"
  ) throw invalid("consumeReceipt");
  validateSignedEnvelope(value, trust);
  for (const field of [
    "grant_digest", "operation_digest", "target_digest", "sender_key_thumbprint",
    "channel_binding_digest", "execution_fence_digest", "maintenance_use_id",
    "recovery_frontier_hash",
  ]) digest(value[field]);
  const committedAt = timestamp(value.committed_at);
  const expiresAt = timestamp(value.expires_at);
  if (
    Date.parse(committedAt) > now.getTime() + 5_000 ||
    Date.parse(expiresAt) <= now.getTime() ||
    Date.parse(expiresAt) - Date.parse(committedAt) > 60_000
  ) throw stale("Maintenance consume receipt is stale");
  return Object.freeze({ ...value }) as CapsuleMaintenanceConsumeReceipt;
}

export function maintenanceCanonicalRequestDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
): string {
  return canonicalSha256(source.action === "PROBE_NATIVE"
    ? {
        action: "PROBE_NATIVE",
        auth_capsule_id: source.auth_capsule_id,
        canonical_node_id: source.canonical_node_id,
        expected_auth_generation: source.expected_auth_generation,
        expected_auth_state_revision: source.expected_auth_state_revision,
        node_generation: source.node_generation,
        node_key_thumbprint: source.node_key_thumbprint,
        placement_generation: source.placement_generation,
        schema_version: "accounts.capsule-probe-request.v1",
        target_digest: targetDigest,
      }
    : {
    access_transport: source.access_transport,
    account_lane_id: source.account_lane_id,
    action: source.action,
    capacity_domain_ref: source.capacity_domain_ref,
    capacity_pool_id: source.capacity_pool_id,
    credential_family_id: source.credential_family_id,
    effect_class: source.effect_class,
    operation_role: source.effect_class === "containment_mutation" ? "CONTAINMENT" : "ORDINARY",
    owner_ref: source.owner_ref,
    provider_account_id: source.provider_account_id,
    provider_subject_ref: source.provider_subject_ref,
    schema_version: "accounts.credential-effect-request.v1",
    serialization_key_digest: source.serialization_key_digest,
    source_credential_generation: source.expected_credential_generation,
    source_record_revision: source.expected_record_revision,
    target_digest: targetDigest,
  });
}

export function maintenanceSourceLineageDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
  requestDigest: string,
): string {
  return canonicalSha256({
    action: source.action,
    credential_family_id: source.credential_family_id,
    effect_namespace_id: source.effect_namespace_id,
    operation_role: source.effect_class === "containment_mutation" ? "CONTAINMENT" : "ORDINARY",
    request_digest: requestDigest,
    schema_version: "accounts.credential-effect-source-lineage.v1",
    serialization_key_digest: source.serialization_key_digest,
    target_digest: targetDigest,
  });
}

export function maintenanceOperationDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
  requestDigest: string,
  sourceLineageDigest: string | undefined,
): string {
  return canonicalSha256(source.action === "PROBE_NATIVE"
    ? {
        action: "PROBE_NATIVE",
        canonical_request_digest: requestDigest,
        maintenance_operation_id: source.maintenance_operation_id,
        operation_execution_epoch: source.operation_execution_epoch,
        operation_step_id: "probe_native",
        schema_version: "accounts.capsule-probe-operation.v1",
        target_digest: targetDigest,
      }
    : {
        action: source.action,
        canonical_request_digest: requestDigest,
        effect_namespace_id: source.effect_namespace_id,
        maintenance_operation_id: source.maintenance_operation_id,
        operation_step_id: ACTION_STEPS[source.action as CapsuleMaintenanceAction],
        schema_version: "accounts.credential-effect-operation.v1",
        source_lineage_digest: sourceLineageDigest,
        target_digest: targetDigest,
      });
}

export function maintenanceReservationKeyDigest(
  grant: Readonly<Record<string, unknown>>,
): string {
  return canonicalSha256({
    effect_namespace_id: grant.effect_namespace_id,
    execution_fence_digest: grant.execution_fence_digest,
    expected_credential_generation: grant.expected_credential_generation,
    expected_record_revision: grant.expected_record_revision,
    schema_version: "accounts.capsule-maintenance-reservation-key.v1",
    serialization_key_digest: grant.serialization_key_digest,
    target_digest: maintenanceTargetDigest(grant),
  });
}

export function maintenanceUseIdDigest(
  source: Readonly<Record<string, unknown>>,
): string {
  return canonicalSha256({
    schema_version: "accounts.capsule-maintenance-use.v1",
    grant_id: source.grant_id,
    grant_digest: source.grant_digest,
    maintenance_operation_id: source.maintenance_operation_id,
    operation_step_id: source.operation_step_id,
    operation_execution_epoch: source.operation_execution_epoch,
    sender_key_thumbprint: source.sender_key_thumbprint,
    channel_binding_digest: source.channel_binding_digest,
    use_ordinal: source.use_ordinal,
  });
}

function assertActionShape(
  action: CapsuleMaintenanceAction,
  effectClass: CapsuleMaintenanceEffectClass,
  targetKind: CapsuleMaintenanceTargetKind,
): void {
  if (
    (NATIVE_ACTIONS.has(action) && targetKind !== "native_capsule") ||
    (ACCOUNT_ACTIONS.has(action) && targetKind !== "account_record") ||
    (action === "PROBE_NATIVE" && effectClass !== "read_only") ||
    (action !== "PROBE_NATIVE" && effectClass === "read_only") ||
    (effectClass === "containment_mutation" && !CONTAINMENT_ACTIONS.has(action))
  ) throw invalid("action");
}

function assertGrantTransport(
  grant: CapsuleMaintenanceGrant,
  binding: CapsuleMaintenanceTransportBinding,
): void {
  if (
    grant.owner_ref !== binding.authenticatedOwnerRef ||
    grant.actor_principal !== binding.authenticatedActorPrincipal ||
    grant.maintenance_executor_principal !== binding.authenticatedMaintenanceExecutorPrincipal ||
    grant.sender_key_thumbprint !== binding.authenticatedSenderKeyThumbprint ||
    grant.channel_binding_digest !== binding.authenticatedChannelBindingDigest
  ) throw forbidden("Maintenance transport binding mismatch");
}

function validateTransport(source: CapsuleMaintenanceTransportBinding): CapsuleMaintenanceTransportBinding {
  const value = plainObject(source);
  exactKeys(value, [
    "authenticatedOwnerRef", "authenticatedActorPrincipal",
    "authenticatedMaintenanceExecutorPrincipal", "authenticatedSenderKeyThumbprint",
    "authenticatedChannelBindingDigest",
  ]);
  for (const field of [
    "authenticatedOwnerRef", "authenticatedActorPrincipal", "authenticatedMaintenanceExecutorPrincipal",
  ]) principal(value[field]);
  digest(value.authenticatedSenderKeyThumbprint);
  digest(value.authenticatedChannelBindingDigest);
  return Object.freeze({ ...source });
}

function validateSignedEnvelope(value: JsonObject, trust: CapsuleMaintenanceTrust): void {
  for (const field of ["issuer", "issuer_incarnation", "key_id", "audience"]) reference(value[field]);
  signature(value.signature);
  if (
    value.issuer !== trust.issuer || value.issuer_incarnation !== trust.issuerIncarnation ||
    value.key_id !== trust.keyId || value.audience !== trust.audience
  ) throw forbidden("Signed evidence trust root mismatch");
  const { signature: _signature, ...unsigned } = value;
  let valid = false;
  try {
    valid = verifyBytes(
      null,
      Buffer.from(canonicalJson(unsigned), "utf8"),
      publicKey(trust.publicKey),
      Buffer.from(value.signature as string, "base64url"),
    );
  } catch {
    throw forbidden("Signed evidence verification failed");
  }
  if (!valid) throw forbidden("Signed evidence verification failed");
}

function parseCanonicalObject(source: Uint8Array, field: string): JsonObject {
  const parsed = parseClosedJsonBytes(source);
  const supplied = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  if (!supplied.equals(Buffer.from(canonicalJson(parsed), "utf8"))) throw invalid(field);
  return plainObject(parsed);
}

function canonicalBase64(value: unknown): Uint8Array {
  if (typeof value !== "string" || !BASE64URL.test(value)) throw invalid("base64url");
  const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
  if (bytes.byteLength === 0 || Buffer.from(bytes).toString("base64url") !== value) throw invalid("base64url");
  parseCanonicalObject(bytes, "base64url");
  return bytes;
}

function nullableCanonicalBase64(value: unknown): Uint8Array | undefined {
  return value === null ? undefined : canonicalBase64(value);
}

function requireNoHeldReceipt(value: Uint8Array | undefined): undefined {
  if (value !== undefined) throw invalid("holdReceipt");
  return undefined;
}

function cloneReservation(input: CapsuleMaintenanceGrantReservation): CapsuleMaintenanceGrantReservation {
  return Object.freeze({ ...input, grantBytes: Uint8Array.from(input.grantBytes) });
}

function cloneUse(input: CapsuleMaintenanceUseCommit): CapsuleMaintenanceUseCommit {
  return Object.freeze({ ...input, consumeReceiptBytes: Uint8Array.from(input.consumeReceiptBytes) });
}

function plainObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw invalid("body");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid("body");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw invalid("body");
  return value as JsonObject;
}

function exactKeys(value: JsonObject, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) throw invalid("body");
  for (const key of expected) if (!Object.hasOwn(value, key)) throw invalid("body");
}

function maintenanceAction(value: unknown): CapsuleMaintenanceAction {
  if (!(CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR.actions as readonly unknown[]).includes(value)) throw invalid("action");
  return value as CapsuleMaintenanceAction;
}

function maintenanceEffectClass(value: unknown): CapsuleMaintenanceEffectClass {
  if (!new Set(["read_only", "mutation", "containment_mutation"]).has(String(value))) throw invalid("effect_class");
  return value as CapsuleMaintenanceEffectClass;
}

function maintenanceTargetKind(value: unknown): CapsuleMaintenanceTargetKind {
  if (value !== "account_record" && value !== "native_capsule") throw invalid("target_kind");
  return value;
}

function maintenanceApprovalMode(value: unknown): CapsuleMaintenanceApprovalMode {
  if (value !== "NOT_REQUIRED" && value !== "REQUIRED") throw invalid("approval_mode");
  return value;
}

function reference(value: unknown): string {
  if (typeof value !== "string" || !REFERENCE.test(value)) throw invalid("reference");
  return value;
}

function principal(value: unknown): string {
  if (typeof value !== "string" || !PRINCIPAL.test(value)) throw invalid("principal");
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value)) throw invalid("digest");
  return value;
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !isUuidV7(value)) throw invalid("id");
  return value;
}

function positiveCounter(value: unknown): Counter {
  const parsed = parseCounter(value);
  if (parsed === "0") throw invalid("counter");
  return parsed;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string") throw invalid("timestamp");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw invalid("timestamp");
  return value;
}

function signature(value: unknown): string {
  if (typeof value !== "string" || !BASE64URL.test(value)) {
    throw invalid("signature");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) {
    throw invalid("signature");
  }
  return value;
}

function publicKey(value: KeyObject | string | Buffer): KeyObject {
  let key: KeyObject;
  try {
    key = value instanceof KeyObject ? value : createPublicKey(value);
  } catch {
    throw invalid("publicKey");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw invalid("publicKey");
  return key;
}

function signCanonical(value: unknown, key: KeyLike): string {
  return signBytes(null, Buffer.from(canonicalJson(value), "utf8"), key).toString("base64url");
}

function canonicalBytes(value: unknown): Uint8Array {
  return Uint8Array.from(Buffer.from(canonicalJson(value), "utf8"));
}

function canonicalSha256Bytes(value: Uint8Array): string {
  return canonicalSha256(parseClosedJsonBytes(value));
}

function assertDescriptor(value: unknown, expected: string, label: string): void {
  if (canonicalSha256(value) !== expected) {
    throw new AccountsError("SCHEMA_CHECKSUM_MISMATCH", `${label} descriptor mismatch`);
  }
}

function idempotencyConflict(): AccountsError {
  return new AccountsError("IDEMPOTENCY_CONFLICT", "Maintenance idempotency conflict");
}

function forbidden(message: string): AccountsError {
  return new AccountsError("FORBIDDEN", message);
}

function stale(message: string): AccountsError {
  return new AccountsError("STALE_ATTESTATION", message);
}

function invalid(field: string): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Capsule maintenance input is invalid", {
    details: { field },
  });
}
