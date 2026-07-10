import { AccountsError } from "../errors";
import type { AccountsRepository, MutationContext, MutationResult } from "../storage/repository";
import { incrementCounter, type Counter } from "./counter";
import type { EntityKind, EntityMap } from "./models";
import { assertInsertInvariants } from "./invariants";
import { assertBindingMayRetire, transitionEntity } from "./state";
import { checkCurrentEligibility, evaluateSlotEligibility } from "./eligibility";
import type { EligibilityRequest, SlotEligibilityMetadata } from "./models";
import { validateEligibilityRequest } from "../serialization/dto";

export class AccountsCatalog {
  private mutationTail: Promise<void> = Promise.resolve();

  constructor(
    private readonly repository: AccountsRepository,
    private readonly now: () => Date = () => new Date(),
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
      const existing = await this.repository.get(kind, record.id);
      if (existing !== undefined) return this.repository.insert(kind, record, context);
      await assertInsertInvariants(this.repository, kind, record);
      return this.repository.insert(kind, record, context);
    });
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
        if (to === "paused" || to === "expired" || to === "revoked") {
          throw new AccountsError(
            "NOT_IMPLEMENTED",
            "Parent denial requires an atomic child-pool barrier and recovery-ledger receipt",
          );
        }
        if (to !== "active") return;
        const account = await this.get("account", entitlement.accountId);
        if (
          account.status !== "active" ||
          entitlement.termsDecision.decision !== "allowed" ||
          Date.parse(entitlement.termsDecision.expiresAt) <= now ||
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
        if (account.status !== "active" || Date.parse(pool.evidenceExpiresAt) <= now) {
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
        if (method.status === "draining") {
          throw new AccountsError("NOT_IMPLEMENTED", "Drained access method requires fresh evidence to reopen");
        }
        const entitlement = await this.get("entitlement", method.entitlementId);
        if (
          entitlement.status !== "active" ||
          pool.status !== "active" ||
          pool.denyState !== "allowed" ||
          method.parentPolicyDecisionRef !== entitlement.executionPolicyDecisionRef ||
          method.parentPolicyDecisionDigest !== entitlement.executionPolicyDecisionDigest ||
          method.health?.state !== "healthy" ||
          Date.parse(method.health.expiresAt) <= now ||
          Date.parse(method.isolationEvidenceExpiresAt) <= now ||
          Date.parse(method.executionPolicyExpiresAt) <= now
        ) {
          throw new AccountsError("POLICY_DENIED", "Access-method evidence does not allow readiness");
        }
        return;
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
