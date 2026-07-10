import { AccountsError } from "../errors";
import type { AccountsRepository, MutationContext, MutationResult } from "../storage/repository";
import type { Counter } from "./counter";
import type { EntityKind, EntityMap } from "./models";
import { assertInsertInvariants } from "./invariants";
import { assertBindingMayRetire, transitionEntity } from "./state";
import { evaluateSlotEligibility } from "./eligibility";
import type { EligibilityRequest, SlotEligibilityMetadata } from "./models";

export class AccountsCatalog {
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
    await assertInsertInvariants(this.repository, kind, record);
    return this.repository.insert(kind, record, context);
  }

  async transition<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    const current = await this.get(kind, id);
    if (current.revision !== expectedRevision) {
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
  }

  eligibility(request: EligibilityRequest): Promise<SlotEligibilityMetadata> {
    return evaluateSlotEligibility(this.repository, request, this.now);
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
        if (to === "active" && account.providerSubjectRef === undefined) {
          throw new AccountsError("POLICY_DENIED", "Account ownership is not verified");
        }
        return;
      }
      case "entitlement": {
        const entitlement = current as EntityMap["entitlement"];
        if (to !== "active") return;
        const account = await this.get("account", entitlement.accountId);
        if (
          account.status !== "active" ||
          entitlement.termsDecision.decision !== "allowed" ||
          Date.parse(entitlement.termsDecision.expiresAt) <= now ||
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
          method.health?.state !== "healthy" ||
          Date.parse(method.health.expiresAt) <= now ||
          Date.parse(method.isolationEvidenceExpiresAt) <= now
        ) {
          throw new AccountsError("POLICY_DENIED", "Access-method evidence does not allow readiness");
        }
        return;
      }
      case "auth_capsule": {
        const capsule = current as EntityMap["auth_capsule"];
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
          Date.parse(capsule.attestation.expiresAt) <= now
        ) {
          throw new AccountsError("CAPSULE_NOT_READY", "Capsule evidence does not allow readiness");
        }
        return;
      }
      case "credential_binding": {
        const binding = current as EntityMap["credential_binding"];
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
}
