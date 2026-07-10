import type { Counter } from "../domain/counter";
import type {
  AccountEventId,
  AuthCapsuleId,
  CredentialBindingId,
  CredentialOperationId,
  EntityId,
  OutboxId,
} from "../domain/ids";
import type {
  Account,
  AccessMethod,
  AuthCapsule,
  CapacityPool,
  CredentialBinding,
  CredentialOperation,
  EntityKind,
  EntityMap,
  Entitlement,
} from "../domain/models";

export interface MutationContext {
  readonly actorRef: string;
  readonly idempotencyKey: string;
  readonly reasonCode: string;
}

export interface AccountEvent {
  readonly id: AccountEventId;
  readonly aggregateKind: EntityKind;
  readonly aggregateId: EntityId;
  readonly aggregateRevision: Counter;
  readonly actorRef: string;
  readonly reasonCode: string;
  readonly occurredAt: string;
}

export interface MutationResult<T> {
  readonly record: T;
  readonly eventId: AccountEventId;
  readonly replayed: boolean;
}

export type AuthorityPromotionKind =
  | "account"
  | "entitlement"
  | "capacity_pool"
  | "access_method";

/**
 * Canonical, already cryptographically verified authority evidence persisted with
 * its aggregate promotion. Repositories still validate this closed storage shape
 * and atomically fence every nonce; they never accept an unsigned projection.
 */
export interface VerifiedAuthorityEvidenceRecord {
  readonly evidenceType:
    | "provider_ownership"
    | "provider_capacity"
    | "entitlement_execution_policy"
    | "entitlement_terms"
    | "entitlement_data_policy"
    | "lane_isolation_policy"
    | "lane_execution_policy"
    | "lane_health";
  readonly evidenceRef: string;
  readonly subjectRef: string;
  readonly aggregateKind:
    | "provider_account"
    | "capacity_pool"
    | "entitlement"
    | "account_lane";
  readonly aggregateId: string;
  readonly aggregateRevision: Counter;
  readonly identityRealm: string;
  readonly issuerRef: string;
  readonly issuerClass:
    | "provider_ownership_verifier"
    | "provider_capacity_verifier"
    | "execution_policy_authority"
    | "terms_authority"
    | "adapter_health_reporter";
  readonly issuerIncarnation: string;
  readonly audience: string;
  readonly keyId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly evidenceGeneration: Counter;
  readonly payloadDigest: string;
  readonly envelopeDigest: string;
  readonly envelopeJson: string;
}

export interface EmbeddedRepositoryDoctor {
  readonly adapter: "memory" | "sqlite";
  readonly schemaVersion: string;
  readonly migrationChecksum: string;
  readonly foreignKeys: boolean | "not_applicable";
  readonly journalMode: "memory" | "wal";
  readonly integrity: "ok";
  readonly readiness: "ready" | "recovery_hold" | "metadata_only";
  readonly recoveryFrontier: RecoveryFrontier | "unavailable";
  readonly recoveryHold: boolean;
  readonly positiveEligibility: boolean;
}

export interface PostgresRepositoryDoctor {
  readonly adapter: "postgres";
  readonly schemaVersion: string;
  readonly migrationChecksum: string;
  readonly foreignKeys: true;
  readonly integrity: "ok";
  readonly tls: "verify-full" | "loopback-test-only";
  readonly rls: "forced";
  readonly runtimeRole: "accounts_runtime";
  readonly readiness: "ready" | "recovery_hold";
  readonly recoveryFrontier: RecoveryFrontier | "unavailable";
  readonly recoveryHold: boolean;
  readonly positiveEligibility: boolean;
}

export type RepositoryDoctor = EmbeddedRepositoryDoctor | PostgresRepositoryDoctor;

export interface RecoveryFrontier {
  readonly catalogIncarnation: string;
  readonly sequence: Counter;
  readonly hash: string;
  readonly signatureDigest: string;
}

export interface RecoveryLedgerEntry {
  readonly kind: "catalog_mutation" | "native_revocation_barrier";
  readonly aggregateKind: EntityKind | "credential_operation";
  readonly aggregateId: string;
  readonly mutationDigest: string;
  readonly occurredAt: string;
}

export interface RecoveryLedgerReceipt extends RecoveryFrontier {
  readonly previousHash: string;
  readonly entryDigest: string;
  readonly receiptDigest: string;
}

export interface RecoveryLedger {
  readFreshFrontier(): RecoveryFrontier;
  append(
    expected: RecoveryFrontier,
    entry: RecoveryLedgerEntry,
  ): RecoveryLedgerReceipt;
  verifyFrontier(frontier: RecoveryFrontier): boolean;
}

export interface RecoverySnapshot {
  readonly matched: boolean;
  readonly hold: boolean;
  readonly frontier?: RecoveryFrontier;
}

/** Internal issuer-to-storage envelope. It is deliberately absent from the public package exports. */
export interface CredentialHandleEnvelope {
  readonly opaqueHandle: string;
  readonly issuerRef: string;
  readonly audience: "accounts-local" | "accounts-self-hosted";
  readonly catalogIncarnation: string;
  readonly backendClass: "secrets_broker" | "workload_identity_broker" | "capsule_protected_state";
  readonly ownerRef: string;
  readonly providerAccountId: Account["id"];
  readonly providerKey: string;
  readonly capacityPoolId: CapacityPool["id"];
  readonly capacityDomainRef: string;
  readonly accessMethodId: AccessMethod["id"];
  readonly credentialFamilyId: string;
  readonly purpose: CredentialBinding["purpose"];
  readonly resolver: CredentialBinding["resolver"];
  readonly policyDigest: string;
  readonly credentialGeneration: Counter;
  readonly authCapsuleId?: AuthCapsule["id"];
  readonly canonicalNodeId?: AuthCapsule["placementRef"];
  readonly nodeGeneration?: Counter;
  readonly placementGeneration?: Counter;
  readonly issuedAt: string;
  readonly expiresAt?: string;
  readonly signature: string;
}

export type UnsignedCredentialHandleEnvelope = Omit<CredentialHandleEnvelope, "signature">;

export interface CredentialHandleExpectedClaims {
  readonly audience: CredentialHandleEnvelope["audience"];
  readonly catalogIncarnation: string;
  readonly backendClass: CredentialHandleEnvelope["backendClass"];
  readonly ownerRef: string;
  readonly providerAccountId: Account["id"];
  readonly providerKey: string;
  readonly capacityPoolId: CapacityPool["id"];
  readonly capacityDomainRef: string;
  readonly accessMethodId: AccessMethod["id"];
  readonly credentialFamilyId: string;
  readonly purpose: CredentialBinding["purpose"];
  readonly resolver: CredentialBinding["resolver"];
  readonly policyDigest: string;
  readonly credentialGeneration: Counter;
  readonly authCapsuleId?: AuthCapsule["id"];
  readonly canonicalNodeId?: AuthCapsule["placementRef"];
  readonly nodeGeneration?: Counter;
  readonly placementGeneration?: Counter;
}

export interface CredentialHandleVerification {
  readonly credentialHandleAuditDigest: string;
}

export interface CredentialHandleVerifier {
  verify(
    envelope: CredentialHandleEnvelope,
    expected: CredentialHandleExpectedClaims,
  ): CredentialHandleVerification;
}

export interface CredentialResolutionGrant {
  readonly schema_version: "accounts.handle-resolution.v1";
  readonly issuer_ref: string;
  readonly provider_account_id: Account["id"];
  readonly account_lane_id: AccessMethod["id"];
  readonly capacity_pool_id: CapacityPool["id"];
  readonly credential_binding_id: CredentialBindingId;
  readonly credential_family_id: string;
  readonly credential_generation: Counter;
  readonly purpose: CredentialBinding["purpose"];
  readonly resolver: CredentialBinding["resolver"];
  readonly run_id: string;
  readonly attempt_id: string;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_generation: Counter;
  readonly operation_id: string;
  readonly operation_digest: string;
  readonly execution_epoch: Counter;
  readonly subject_principal: string;
  readonly actor_principal: string;
  readonly holder_principal: string;
  readonly executor_principal: string;
  readonly audience: string;
  readonly sender_key_thumbprint: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: Counter;
  readonly recovery_frontier_hash: string;
  readonly request_digest: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly signature: string;
}

export type UnsignedCredentialResolutionGrant = Omit<CredentialResolutionGrant, "signature">;

export interface CredentialResolutionTransport {
  readonly authenticatedActorPrincipal: string;
  readonly authenticatedHolderPrincipal: string;
  readonly authenticatedExecutorPrincipal: string;
  readonly authenticatedSenderKeyThumbprint: string;
  readonly audience: string;
  readonly runId: string;
  readonly attemptId: string;
  readonly resourceLeaseId: string;
  readonly resourceId: string;
  readonly resourceGeneration: Counter;
  readonly operationId: string;
  readonly operationDigest: string;
  readonly executionEpoch: Counter;
  readonly requestDigest: string;
  readonly now: string;
}

export interface CredentialResolutionExpected {
  readonly providerAccountId: Account["id"];
  readonly ownerRef: string;
  readonly accessMethodId: AccessMethod["id"];
  readonly capacityPoolId: CapacityPool["id"];
  readonly bindingId: CredentialBindingId;
  readonly credentialFamilyId: string;
  readonly credentialGeneration: Counter;
  readonly purpose: CredentialBinding["purpose"];
  readonly resolver: CredentialBinding["resolver"];
  readonly catalogIncarnation: string;
  readonly recoveryFrontierSequence: Counter;
  readonly recoveryFrontierHash: string;
}

export interface CredentialUseAuthorizer {
  verify(
    grant: CredentialResolutionGrant,
    expected: CredentialResolutionExpected,
    transport: CredentialResolutionTransport,
  ): void;
}

export interface ResolvedCredentialHandle {
  readonly bindingId: CredentialBindingId;
  readonly opaqueHandle: string;
  readonly issuerRef: string;
  readonly audience: CredentialHandleEnvelope["audience"];
  readonly backendClass: CredentialHandleEnvelope["backendClass"];
  readonly expiresAt?: string;
}

export interface OutboxRecord {
  readonly id: OutboxId;
  readonly topic: "accounts.aggregate.changed" | "accounts.capsule.cleanup.requested";
  readonly aggregateKind: EntityKind | "credential_operation";
  readonly aggregateId: string;
  readonly eventId?: AccountEventId;
  readonly payloadDigest: string;
  readonly payloadJson: string;
  readonly status: "pending" | "in_flight" | "delivered" | "dead_letter";
  readonly attemptCount: Counter;
  readonly claimOwnerRef?: string;
  readonly claimExpiresAt?: string;
  readonly createdAt: string;
}

export interface OutboxClaimRequest {
  readonly workerRef: string;
  readonly limit: number;
  readonly now: string;
  readonly claimExpiresAt: string;
}

export interface OutboxAcknowledgeRequest {
  readonly outboxId: OutboxId;
  readonly workerRef: string;
  readonly expectedAttemptCount: Counter;
  readonly outcome: "delivered" | "retry" | "dead_letter";
  readonly now: string;
}

export interface NativeRevocationRequest {
  readonly capsuleId: AuthCapsuleId;
  readonly bindingId: CredentialBindingId;
  readonly barrierBindingId: CredentialBindingId;
  readonly operationId: CredentialOperationId;
  readonly expectedPoolRevision: Counter;
  readonly expectedMethodRevision: Counter;
  readonly expectedCapsuleRevision: Counter;
  readonly expectedBindingRevision: Counter;
  readonly occurredAt: string;
  readonly context: MutationContext;
}

export interface NativeRevocationResult {
  readonly pool: CapacityPool;
  readonly method: AccessMethod;
  readonly capsule: AuthCapsule;
  readonly retiredBinding: CredentialBinding;
  readonly barrierBinding: CredentialBinding;
  readonly operation: CredentialOperation;
  readonly replayed: boolean;
}

export interface EligibilitySnapshot {
  readonly method?: AccessMethod;
  readonly entitlement?: Entitlement;
  readonly account?: Account;
  readonly pool?: CapacityPool;
  readonly capsules: readonly AuthCapsule[];
  readonly bindings: readonly CredentialBinding[];
  readonly recovery: RecoverySnapshot;
}

export interface AccountsRepository {
  get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined>;
  list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]>;
  readEligibilitySnapshot(accessMethodId: AccessMethod["id"]): Promise<EligibilitySnapshot>;
  insert<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
  insertCredentialBinding(
    record: CredentialBinding,
    handle: CredentialHandleEnvelope,
    context: MutationContext,
  ): Promise<MutationResult<CredentialBinding>>;
  insertCapacityPoolWithAuthorityEvidence(
    record: CapacityPool,
    evidence: VerifiedAuthorityEvidenceRecord,
    context: MutationContext,
  ): Promise<MutationResult<CapacityPool>>;
  promoteWithAuthorityEvidence<K extends AuthorityPromotionKind>(
    kind: K,
    record: EntityMap[K],
    expectedRevision: Counter,
    evidence: readonly VerifiedAuthorityEvidenceRecord[],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
  resolveCredentialHandle(
    bindingId: CredentialBindingId,
    grant: CredentialResolutionGrant,
    transport: CredentialResolutionTransport,
  ): Promise<ResolvedCredentialHandle>;
  revokeNativeGeneration(request: NativeRevocationRequest): Promise<NativeRevocationResult>;
  credentialOperations(): Promise<readonly CredentialOperation[]>;
  outbox(): Promise<readonly OutboxRecord[]>;
  claimOutbox(request: OutboxClaimRequest): Promise<readonly OutboxRecord[]>;
  acknowledgeOutbox(request: OutboxAcknowledgeRequest): Promise<OutboxRecord>;
  replace<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
  findReplacementReplay<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]> | undefined>;
  events(): Promise<readonly AccountEvent[]>;
  doctor(): Promise<RepositoryDoctor>;
  close(): Promise<void>;
}
