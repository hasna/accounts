import { AccountsError } from "../errors";
import type {
  AccountsRepository,
  CredentialHandleEnvelope,
  CredentialResolutionGrant,
  CredentialResolutionTransport,
  MutationContext,
  MutationResult,
  NativeRevocationRequest,
  OutboxAcknowledgeRequest,
  OutboxClaimRequest,
  VerifiedAuthorityEvidenceRecord,
} from "../storage/repository";
import { incrementCounter, type Counter } from "./counter";
import type { EntityKind, EntityMap } from "./models";
import { assertInsertInvariants } from "./invariants";
import { assertBindingMayRetire, transitionEntity } from "./state";
import { checkCurrentEligibility, evaluateSlotEligibility } from "./eligibility";
import type { EligibilityRequest, SlotEligibilityMetadata } from "./models";
import { validateEligibilityRequest } from "../serialization/dto";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import {
  verifyAuthorityEvidence,
  type AuthorityEvidenceEnvelope,
  type AuthorityEvidenceBinding,
  type AuthorityEvidenceTrustRoot,
  type AuthorityEvidenceType,
  type EntitlementDataPolicyPayload,
  type EntitlementExecutionPolicyPayload,
  type EntitlementTermsPayload,
  type LaneExecutionPolicyPayload,
  type LaneHealthPayload,
  type LaneIsolationPolicyPayload,
  type ProviderOwnershipPayload,
  type ProviderCapacityPayload,
} from "./authority-evidence";

export interface AuthorityEvidencePolicy {
  readonly trustRoots: ReadonlyMap<AuthorityEvidenceType, AuthorityEvidenceTrustRoot>;
  readonly identityRealm: string;
  readonly maximumAgeMs: number;
  readonly maximumLifetimeMs: number;
  readonly allowedClockSkewMs?: number;
}

export interface EvidenceFence {
  readonly nonce: string;
  readonly evidenceGeneration: Counter;
}

export interface EntitlementEvidenceBundle {
  readonly executionPolicy: Uint8Array;
  readonly executionPolicyFence: EvidenceFence;
  readonly terms: Uint8Array;
  readonly termsFence: EvidenceFence;
  readonly dataPolicy: Uint8Array;
  readonly dataPolicyFence: EvidenceFence;
  readonly useCase: string;
  readonly adapterVersion: string;
}

export interface LaneEvidenceBundle {
  readonly isolationPolicy: Uint8Array;
  readonly isolationPolicyFence: EvidenceFence;
  readonly executionPolicy: Uint8Array;
  readonly executionPolicyFence: EvidenceFence;
  readonly health: Uint8Array;
  readonly healthFence: EvidenceFence;
}

export class AccountsCatalog {
  private mutationTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly repository: AccountsRepository,
    private readonly now: () => Date = () => new Date(),
    private readonly authorityPolicy?: AuthorityEvidencePolicy,
  ) {}

  async get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K]> {
    const record = await this.repository.get(kind, id);
    if (record === undefined) {
      throw new AccountsError("NOT_FOUND", "Record not found", {
        details: { aggregateKind: kind, aggregateId: id },
      });
    }
    return record;
  }

  list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    return this.repository.list(kind);
  }

  async add<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    return this.runMutation(async () => {
      if (kind === "credential_binding") {
        throw new AccountsError(
          "VALIDATION_FAILED",
          "Credential bindings require an atomic issuer handle ingestion",
        );
      }
      if (kind === "capacity_pool") {
        throw new AccountsError(
          "VALIDATION_FAILED",
          "Capacity pools require signed provider-capacity evidence ingestion",
        );
      }
      const existing = await this.repository.get(kind, record.id);
      if (existing !== undefined) return this.repository.insert(kind, record, context);
      await assertInsertInvariants(this.repository, kind, record);
      return this.repository.insert(kind, record, context);
    });
  }

  async addCapacityPoolFromEvidence(
    record: EntityMap["capacity_pool"],
    evidence: Uint8Array,
    fence: EvidenceFence,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["capacity_pool"]>> {
    return this.runMutation(async () => {
      if (
        record.status !== "pending" ||
        record.revision !== "0" ||
        record.capacityGeneration !== "0" ||
        record.denyGeneration !== "0" ||
        record.denyState !== "denied"
      ) {
        throw new AccountsError("INVALID_TRANSITION", "Capacity pool evidence insertion is invalid");
      }
      const account = await this.get("account", record.accountId);
      if (account.status !== "active") {
        throw new AccountsError("POLICY_DENIED", "Capacity pool account is not active");
      }
      const envelope = this.verifyEvidence(
        "provider_capacity",
        evidence,
        fence,
        record.id,
        record.id,
        record.revision,
        {
          providerAccountId: account.id,
          providerKey: account.providerKey,
          ownerRef: account.ownerRef,
          capacityDomainRef: record.capacityDomainRef,
          serializationKey: record.serializationKey,
          maxConcurrency: record.maxConcurrency,
        },
      );
      const payload = envelope.payload as ProviderCapacityPayload;
      if (
        payload.decision !== "allowed" ||
        record.capacityEvidenceRef !== envelope.evidence_ref ||
        record.capacityEvidenceIssuerRef !== envelope.issuer_ref ||
        record.capacityEvidenceVersion !== envelope.schema_version ||
        record.capacityEvidenceDigest !== envelope.payload_digest ||
        record.capacityEvidenceIssuedAt !== envelope.issued_at ||
        record.capacityEvidenceExpiresAt !== envelope.expires_at ||
        record.capacityEvidenceGeneration !== envelope.evidence_generation ||
        record.capacityPolicyVersion !== payload.policy_version
      ) {
        throw new AccountsError("POLICY_DENIED", "Capacity projection is not verifier-derived");
      }
      const existing = await this.repository.get("capacity_pool", record.id);
      if (existing === undefined) {
        await assertInsertInvariants(this.repository, "capacity_pool", record);
      } else if (canonicalJson(existing) !== canonicalJson(record)) {
        throw new AccountsError("CONFLICT", "Capacity pool identifier already exists");
      }
      return this.repository.insertCapacityPoolWithAuthorityEvidence(
        record,
        this.evidenceRecord(envelope, evidence),
        context,
      );
    });
  }

  async addCredentialBinding(
    record: EntityMap["credential_binding"],
    handle: CredentialHandleEnvelope,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["credential_binding"]>> {
    return this.runMutation(async () => {
      const existing = await this.repository.get("credential_binding", record.id);
      if (existing !== undefined) {
        return this.repository.insertCredentialBinding(record, handle, context);
      }
      await assertInsertInvariants(this.repository, "credential_binding", record);
      return this.repository.insertCredentialBinding(record, handle, context);
    });
  }

  async activateProviderAccount(
    candidate: EntityMap["account"],
    evidence: Uint8Array,
    fence: EvidenceFence,
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["account"]>> {
    return this.runMutation(async () => {
      const current = await this.get("account", candidate.id);
      const exactReplay =
        current.status === "active" && canonicalJson(current) === canonicalJson(candidate);
      if (
        (!exactReplay && current.status !== "pending") ||
        candidate.status !== "active" ||
        candidate.providerSubjectRef === undefined ||
        candidate.providerSubjectCandidateRef !== undefined ||
        (!exactReplay && current.providerSubjectCandidateRef !== undefined &&
          current.providerSubjectCandidateRef !== candidate.providerSubjectRef)
      ) {
        throw new AccountsError("INVALID_TRANSITION", "Provider ownership activation is invalid");
      }
      const envelope = this.verifyEvidence(
        "provider_ownership",
        evidence,
        fence,
        current.id,
        current.id,
        expectedRevision,
        {
          providerKey: candidate.providerKey,
          providerSubjectRef: candidate.providerSubjectRef,
          ownerRef: candidate.ownerRef,
        },
      );
      const payload = envelope.payload as ProviderOwnershipPayload;
      if (
        payload.ownership_generation !== candidate.ownershipGeneration ||
        candidate.ownershipEvidenceRef !== envelope.evidence_ref ||
        candidate.ownershipEvidenceIssuerRef !== envelope.issuer_ref ||
        candidate.ownershipEvidenceVersion !== envelope.schema_version ||
        candidate.ownershipEvidenceDigest !== envelope.payload_digest ||
        candidate.ownershipEvidenceIssuedAt !== envelope.issued_at ||
        candidate.ownershipEvidenceExpiresAt !== envelope.expires_at
      ) {
        throw new AccountsError("POLICY_DENIED", "Provider ownership projection is not issuer-derived");
      }
      return this.repository.promoteWithAuthorityEvidence(
        "account",
        candidate,
        expectedRevision,
        [this.evidenceRecord(envelope, evidence)],
        context,
      );
    });
  }

  async activateEntitlement(
    candidate: EntityMap["entitlement"],
    bundle: EntitlementEvidenceBundle,
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["entitlement"]>> {
    return this.runMutation(async () => {
      const current = await this.get("entitlement", candidate.id);
      const account = await this.get("account", current.accountId);
      const exactReplay =
        current.status === "active" && canonicalJson(current) === canonicalJson(candidate);
      if (
        (!exactReplay && current.status !== "pending") ||
        candidate.status !== "active" ||
        account.status !== "active"
      ) {
        throw new AccountsError("INVALID_TRANSITION", "Entitlement activation is invalid");
      }
      const binding = {
        providerAccountId: account.id,
        ownerRef: account.ownerRef,
        providerKey: account.providerKey,
        useCase: bundle.useCase,
      };
      const execution = this.verifyEvidence(
        "entitlement_execution_policy",
        bundle.executionPolicy,
        bundle.executionPolicyFence,
        current.id,
        current.id,
        expectedRevision,
        { ...binding, adapterVersion: bundle.adapterVersion },
      );
      const terms = this.verifyEvidence(
        "entitlement_terms",
        bundle.terms,
        bundle.termsFence,
        current.id,
        current.id,
        expectedRevision,
        binding,
      );
      const data = this.verifyEvidence(
        "entitlement_data_policy",
        bundle.dataPolicy,
        bundle.dataPolicyFence,
        current.id,
        current.id,
        expectedRevision,
        binding,
      );
      const executionPayload = execution.payload as EntitlementExecutionPolicyPayload;
      const termsPayload = terms.payload as EntitlementTermsPayload;
      const dataPayload = data.payload as EntitlementDataPolicyPayload;
      if (
        executionPayload.decision !== "allowed" ||
        termsPayload.decision !== "allowed" ||
        dataPayload.decision !== "allowed" ||
        canonicalJson(candidate.capabilitySet) !== canonicalJson(executionPayload.capability_set) ||
        candidate.capabilityEvidenceRef !== execution.evidence_ref ||
        candidate.capabilityDigest !== execution.payload_digest ||
        candidate.capabilityExpiresAt !== execution.expires_at ||
        candidate.executionPolicyDecisionRef !== execution.evidence_ref ||
        candidate.executionPolicyDecisionDigest !== execution.payload_digest ||
        candidate.executionPolicyDecisionExpiresAt !== execution.expires_at ||
        candidate.termsDecision?.decision !== "allowed" ||
        candidate.termsDecision.useCase !== termsPayload.use_case ||
        candidate.termsDecision.evidenceRef !== terms.evidence_ref ||
        candidate.termsDecision.verifiedBy !== terms.issuer_ref ||
        candidate.termsDecision.verifiedAt !== terms.issued_at ||
        candidate.termsDecision.expiresAt !== terms.expires_at ||
        candidate.termsDecision.termsVersion !== termsPayload.terms_version ||
        candidate.termsDecision.termsDigest !== termsPayload.terms_digest ||
        canonicalJson(candidate.dataPolicy) !==
          canonicalJson({
            allowedClassifications: dataPayload.allowed_classifications,
            retentionClass: dataPayload.retention_class,
            ...(dataPayload.max_retention_days === undefined
              ? {}
              : { maxRetentionDays: dataPayload.max_retention_days }),
          }) ||
        candidate.dataPolicyEvidenceRef !== data.evidence_ref ||
        candidate.dataPolicyDigest !== data.payload_digest ||
        candidate.dataPolicyExpiresAt !== data.expires_at ||
        candidate.lastVerifiedAt !== execution.issued_at
      ) {
        throw new AccountsError("POLICY_DENIED", "Entitlement projection is not authority-derived");
      }
      return this.repository.promoteWithAuthorityEvidence(
        "entitlement",
        candidate,
        expectedRevision,
        [
          this.evidenceRecord(execution, bundle.executionPolicy),
          this.evidenceRecord(terms, bundle.terms),
          this.evidenceRecord(data, bundle.dataPolicy),
        ],
        context,
      );
    });
  }

  async activateAccessMethod(
    candidate: EntityMap["access_method"],
    bundle: LaneEvidenceBundle,
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["access_method"]>> {
    return this.runMutation(async () => {
      const current = await this.get("access_method", candidate.id);
      const entitlement = await this.get("entitlement", current.entitlementId);
      const pool = await this.get("capacity_pool", current.capacityPoolId);
      const account = await this.get("account", pool.accountId);
      const exactReplay =
        current.status === "ready" && canonicalJson(current) === canonicalJson(candidate);
      if (
        (!exactReplay && current.status !== "draft") ||
        candidate.status !== "ready" ||
        entitlement.status !== "active" ||
        pool.status !== "active" ||
        account.status !== "active"
      ) {
        throw new AccountsError("INVALID_TRANSITION", "Account-lane activation is invalid");
      }
      const binding = {
        providerAccountId: account.id,
        entitlementId: entitlement.id,
        capacityPoolId: pool.id,
        ownerRef: account.ownerRef,
        adapterKey: candidate.adapterKey,
        adapterVersion: candidate.adapterVersion,
        accessTransport: candidate.accessTransport,
      };
      const isolation = this.verifyEvidence(
        "lane_isolation_policy",
        bundle.isolationPolicy,
        bundle.isolationPolicyFence,
        current.id,
        current.id,
        expectedRevision,
        binding,
      );
      const execution = this.verifyEvidence(
        "lane_execution_policy",
        bundle.executionPolicy,
        bundle.executionPolicyFence,
        current.id,
        current.id,
        expectedRevision,
        binding,
      );
      const health = this.verifyEvidence(
        "lane_health",
        bundle.health,
        bundle.healthFence,
        current.id,
        current.id,
        expectedRevision,
        {
          providerAccountId: account.id,
          entitlementId: entitlement.id,
          capacityPoolId: pool.id,
          ownerRef: account.ownerRef,
          adapterKey: candidate.adapterKey,
          adapterVersion: candidate.adapterVersion,
        },
      );
      const isolationPayload = isolation.payload as LaneIsolationPolicyPayload;
      const executionPayload = execution.payload as LaneExecutionPolicyPayload;
      const healthPayload = health.payload as LaneHealthPayload;
      const candidateHealth = candidate.health;
      if (
        isolationPayload.decision !== "allowed" ||
        executionPayload.decision !== "allowed" ||
        healthPayload.state !== "healthy" ||
        candidate.requiredIsolationPolicyRef !== isolationPayload.required_isolation_policy_ref ||
        candidate.requiredIsolationPolicyDigest !== isolationPayload.required_isolation_policy_digest ||
        candidate.isolationEvidenceExpiresAt !== isolation.expires_at ||
        canonicalJson(candidate.allowedDestinationPolicyClasses) !==
          canonicalJson(executionPayload.allowed_destination_policy_classes) ||
        candidate.parentPolicyDecisionRef !== entitlement.executionPolicyDecisionRef ||
        candidate.parentPolicyDecisionDigest !== entitlement.executionPolicyDecisionDigest ||
        candidate.executionPolicyEvidenceRef !== execution.evidence_ref ||
        candidate.executionPolicyDigest !== execution.payload_digest ||
        candidate.executionPolicyExpiresAt !== execution.expires_at ||
        candidateHealth?.state !== healthPayload.state ||
        candidateHealth.evidenceRef !== health.evidence_ref ||
        candidateHealth.observedAt !== healthPayload.observed_at ||
        candidateHealth.expiresAt !== health.expires_at
      ) {
        throw new AccountsError("POLICY_DENIED", "Account-lane projection is not authority-derived");
      }
      return this.repository.promoteWithAuthorityEvidence(
        "access_method",
        candidate,
        expectedRevision,
        [
          this.evidenceRecord(isolation, bundle.isolationPolicy),
          this.evidenceRecord(execution, bundle.executionPolicy),
          this.evidenceRecord(health, bundle.health),
        ],
        context,
      );
    });
  }

  resolveCredentialHandle(
    bindingId: EntityMap["credential_binding"]["id"],
    grant: CredentialResolutionGrant,
    transport: CredentialResolutionTransport,
  ) {
    return this.repository.resolveCredentialHandle(bindingId, grant, transport);
  }

  revokeNativeGeneration(request: NativeRevocationRequest) {
    return this.runMutation(() => this.repository.revokeNativeGeneration(request));
  }

  credentialOperations() {
    return this.repository.credentialOperations();
  }

  outbox() {
    return this.repository.outbox();
  }

  claimOutbox(request: OutboxClaimRequest) {
    return this.repository.claimOutbox(request);
  }

  acknowledgeOutbox(request: OutboxAcknowledgeRequest) {
    return this.repository.acknowledgeOutbox(request);
  }

  async transition<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    return this.runMutation(async () => {
      const replay = await this.repository.findReplacementReplay(
        kind,
        id,
        to,
        expectedRevision,
        context,
      );
      if (replay !== undefined) return replay;
      const current = await this.get(kind, id);
      if (current.revision !== expectedRevision) {
        if (current.revision === incrementCounter(expectedRevision) && current.status === to) {
          return this.repository.replace(kind, current, expectedRevision, context);
        }
        throw new AccountsError("STALE_REVISION", "Expected revision does not match current state", {
          details: {
            aggregateKind: kind,
            aggregateId: id,
            expectedRevision,
            actualRevision: current.revision,
          },
        });
      }
      await this.assertTransitionPreconditions(kind, current, to);
      const next = transitionEntity(kind, current, to, this.nextTimestamp(current.updatedAt));
      return this.repository.replace(kind, next, expectedRevision, context);
    });
  }

  eligibility(request: EligibilityRequest): Promise<SlotEligibilityMetadata> {
    return evaluateSlotEligibility(this.repository, validateEligibilityRequest(request), this.now);
  }

  checkCurrent(
    evidence: SlotEligibilityMetadata,
    request: EligibilityRequest,
  ): Promise<SlotEligibilityMetadata> {
    return checkCurrentEligibility(
      this.repository,
      evidence,
      validateEligibilityRequest(request),
      this.now,
    );
  }

  doctor() {
    return this.repository.doctor();
  }

  close(): Promise<void> {
    return this.repository.close();
  }

  private async assertTransitionPreconditions<K extends EntityKind>(
    kind: K,
    current: EntityMap[K],
    to: EntityMap[K]["status"],
  ): Promise<void> {
    const now = this.now().getTime();
    switch (kind) {
      case "account": {
        const account = current as EntityMap["account"];
        if (to === "active") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Account activation requires signed ownership evidence ingestion",
          );
        }
        if (to === "suspended" || to === "revoked") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Parent denial requires an atomic child-pool barrier and recovery-ledger receipt",
          );
        }
        if (to === "active" && account.providerSubjectRef === undefined) {
          throw new AccountsError("POLICY_DENIED", "Account ownership is not verified");
        }
        if (to === "active") {
          const accounts = await this.repository.list("account");
          if (
            accounts.some(
              (candidate) =>
                candidate.id !== account.id &&
                candidate.status !== "pending" &&
                candidate.providerKey === account.providerKey &&
                candidate.providerSubjectRef === account.providerSubjectRef,
            )
          ) {
            throw new AccountsError("CONFLICT", "Provider subject is permanently claimed");
          }
        }
        return;
      }
      case "entitlement": {
        const entitlement = current as EntityMap["entitlement"];
        if (to === "active") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Entitlement activation requires a signed authority evidence cohort",
          );
        }
        if (to === "paused" || to === "expired" || to === "revoked") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Parent denial requires an atomic child-pool barrier and recovery-ledger receipt",
          );
        }
        if (to !== "active") return;
        const account = await this.get("account", entitlement.accountId);
        const terms = entitlement.termsDecision;
        if (
          account.status !== "active" ||
          terms === undefined ||
          terms.decision !== "allowed" ||
          entitlement.capabilitySet === undefined ||
          entitlement.capabilityExpiresAt === undefined ||
          entitlement.executionPolicyDecisionRef === undefined ||
          entitlement.executionPolicyDecisionExpiresAt === undefined ||
          entitlement.dataPolicy === undefined ||
          entitlement.dataPolicyExpiresAt === undefined ||
          Date.parse(terms.expiresAt) <= now ||
          Date.parse(entitlement.capabilityExpiresAt) <= now ||
          Date.parse(entitlement.executionPolicyDecisionExpiresAt) <= now ||
          Date.parse(entitlement.dataPolicyExpiresAt) <= now
        ) {
          throw new AccountsError("TERMS_NOT_ALLOWED", "Entitlement evidence does not allow activation");
        }
        return;
      }
      case "capacity_pool": {
        const pool = current as EntityMap["capacity_pool"];
        if (to !== "active") return;
        if (pool.status === "denied" || pool.status === "draining" || pool.denyGeneration !== "0") {
          throw new AccountsError("NOT_IMPLEMENTED", "Capacity reactivation requires fresh signed evidence");
        }
        const account = await this.get("account", pool.accountId);
        if (account.status !== "active" || Date.parse(pool.capacityEvidenceExpiresAt) <= now) {
          throw new AccountsError("POLICY_DENIED", "Capacity evidence does not allow activation");
        }
        return;
      }
      case "access_method": {
        const method = current as EntityMap["access_method"];
        const pool = await this.get("capacity_pool", method.capacityPoolId);
        if (to === "draining") {
          if (pool.status !== "draining" || pool.denyState !== "denied") {
            throw new AccountsError("CURRENT_DENY", "Capacity denial must precede access-method drain");
          }
          return;
        }
        if (to !== "ready") return;
        throw new AccountsError(
          "NOT_IMPLEMENTED",
          "Account-lane readiness requires a signed authority evidence cohort",
        );
      }
      case "auth_capsule": {
        const capsule = current as EntityMap["auth_capsule"];
        if (to === "revoked") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Central native revocation requires an atomic N and N+1 terminal barrier",
          );
        }
        if (to === "bootstrapping" && (capsule.status === "ready" || capsule.status === "degraded")) {
          throw new AccountsError("NOT_IMPLEMENTED", "Native mutation awaits a trusted Infinity drain verifier");
        }
        if (to !== "ready") return;
        const method = await this.get("access_method", capsule.accessMethodId);
        const pool = await this.get("capacity_pool", capsule.capacityPoolId);
        if (
          method.status !== "ready" ||
          pool.status !== "active" ||
          pool.denyState !== "allowed" ||
          capsule.attestation === undefined ||
          Date.parse(capsule.attestation.expiresAt) <= now ||
          capsule.lastHealthAt === undefined ||
          Date.parse(capsule.lastHealthAt) + 5 * 60 * 1_000 <= now ||
          capsule.isolationPolicyDigest !== method.requiredIsolationPolicyDigest
        ) {
          throw new AccountsError("CAPSULE_NOT_READY", "Capsule evidence does not allow readiness");
        }
        return;
      }
      case "credential_binding": {
        const binding = current as EntityMap["credential_binding"];
        if (to === "revoked") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Credential revocation requires a closed terminal tombstone union",
          );
        }
        const method = await this.get("access_method", binding.accessMethodId);
        const pool = await this.get("capacity_pool", binding.capacityPoolId);
        if (to === "retiring") {
          assertBindingMayRetire(binding, method, pool);
          return;
        }
        if (to !== "active") return;
        if (binding.status === "revoked") {
          throw new AccountsError("INVALID_TRANSITION", "A terminal credential binding cannot activate");
        }
        if (method.status !== "ready" || pool.status !== "active" || pool.denyState !== "allowed") {
          throw new AccountsError("POLICY_DENIED", "Credential binding cannot activate against denied capacity");
        }
        if (binding.expiresAt !== undefined && Date.parse(binding.expiresAt) <= now) {
          throw new AccountsError("POLICY_DENIED", "Credential binding is expired");
        }
        if (binding.policyDigest !== method.executionPolicyDigest) {
          throw new AccountsError("POLICY_DENIED", "Credential policy does not match access method");
        }
        if (binding.resolver === "capsule_local_native") {
          const capsule = await this.get("auth_capsule", binding.authCapsuleId!);
          if (
            capsule.status !== "ready" ||
            capsule.authGeneration !== binding.credentialGeneration ||
            capsule.authStateRevision !== binding.authStateRevision
          ) {
            throw new AccountsError("CAPSULE_NOT_READY", "Native credential binding does not match capsule");
          }
        }
      }
    }
  }

  private nextTimestamp(previous: string): string {
    const current = this.now().getTime();
    return new Date(Math.max(current, Date.parse(previous) + 1)).toISOString();
  }

  private verifyEvidence<Type extends AuthorityEvidenceType>(
    type: Type,
    source: Uint8Array,
    fence: EvidenceFence,
    subjectRef: string,
    aggregateId: string,
    aggregateRevision: Counter,
    binding: AuthorityEvidenceBinding<Type>,
  ): AuthorityEvidenceEnvelope<Type> {
    const policy = this.authorityPolicy;
    const trust = policy?.trustRoots.get(type);
    if (policy === undefined || trust === undefined) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Authority evidence verifier is not configured");
    }
    const aggregateKind =
      type === "provider_ownership"
        ? "provider_account"
        : type === "provider_capacity"
          ? "capacity_pool"
        : type.startsWith("entitlement_")
          ? "entitlement"
          : "account_lane";
    return verifyAuthorityEvidence(
      source,
      trust,
      {
        evidenceType: type,
        subjectRef,
        aggregateKind,
        aggregateId,
        aggregateRevision,
        identityRealm: policy.identityRealm,
        evidenceGeneration: fence.evidenceGeneration,
        nonce: fence.nonce,
        now: this.now(),
        maximumAgeMs: policy.maximumAgeMs,
        maximumLifetimeMs: policy.maximumLifetimeMs,
        ...(policy.allowedClockSkewMs === undefined
          ? {}
          : { allowedClockSkewMs: policy.allowedClockSkewMs }),
        binding,
      } as never,
    ) as AuthorityEvidenceEnvelope<Type>;
  }

  private evidenceRecord(
    envelope: AuthorityEvidenceEnvelope,
    source: Uint8Array,
  ): VerifiedAuthorityEvidenceRecord {
    const envelopeJson = new TextDecoder("utf-8", { fatal: true }).decode(source);
    return Object.freeze({
      evidenceType: envelope.evidence_type,
      evidenceRef: envelope.evidence_ref,
      subjectRef: envelope.subject_ref,
      aggregateKind: envelope.aggregate_kind,
      aggregateId: envelope.aggregate_id,
      aggregateRevision: envelope.aggregate_revision,
      identityRealm: envelope.identity_realm,
      issuerRef: envelope.issuer_ref,
      issuerClass: envelope.issuer_class,
      issuerIncarnation: envelope.issuer_incarnation,
      audience: envelope.audience,
      keyId: envelope.key_id,
      issuedAt: envelope.issued_at,
      expiresAt: envelope.expires_at,
      nonce: envelope.nonce,
      evidenceGeneration: envelope.evidence_generation,
      payloadDigest: envelope.payload_digest,
      envelopeDigest: canonicalSha256(envelope),
      envelopeJson,
    });
  }

  private async runMutation<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.mutationTail;
    let release!: () => void;
    this.mutationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}
