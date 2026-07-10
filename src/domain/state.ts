import { AccountsError } from "../errors";
import { incrementCounter } from "./counter";
import { canonicalJson } from "../serialization/json";
import type {
  AccessMethod,
  AnyEntity,
  AuthCapsule,
  CapacityPool,
  CredentialBinding,
  EntityKind,
  EntityMap,
} from "./models";

const TRANSITIONS = {
  account: {
    pending: ["active", "revoked"],
    active: ["suspended", "revoked"],
    suspended: ["active", "revoked"],
    revoked: [],
  },
  entitlement: {
    pending: ["active", "revoked"],
    active: ["paused", "expired", "revoked"],
    paused: ["active", "expired", "revoked"],
    expired: [],
    revoked: [],
  },
  capacity_pool: {
    pending: ["active", "denied", "retired"],
    active: ["draining", "denied", "retired"],
    draining: ["active", "denied", "retired"],
    denied: ["pending", "retired"],
    retired: [],
  },
  access_method: {
    draft: ["ready", "disabled", "retired"],
    ready: ["draining", "disabled", "retired"],
    draining: ["ready", "disabled", "retired"],
    disabled: ["draft", "retired"],
    retired: [],
  },
  auth_capsule: {
    unprovisioned: ["bootstrapping", "revoked"],
    bootstrapping: ["ready", "degraded", "unprovisioned", "revoked"],
    ready: ["degraded", "bootstrapping", "revoked"],
    degraded: ["ready", "bootstrapping", "revoked"],
    revoked: [],
  },
  credential_binding: {
    pending: ["active", "revoked"],
    active: ["retiring", "revoked"],
    retiring: ["revoked"],
    revoked: [],
  },
} as const;

type EntityStatus<K extends EntityKind> = EntityMap[K]["status"];

export function assertTransition<K extends EntityKind>(
  kind: K,
  from: EntityStatus<K>,
  to: EntityStatus<K>,
): void {
  const allowed = TRANSITIONS[kind][from as keyof (typeof TRANSITIONS)[K]] as readonly string[];
  if (!allowed.includes(to)) {
    throw new AccountsError("INVALID_TRANSITION", `Invalid ${kind} lifecycle transition`, {
      details: {
        aggregateKind: kind,
        fromStatus: from,
        toStatus: to,
      },
    });
  }
}

export function transitionEntity<K extends EntityKind>(
  kind: K,
  entity: EntityMap[K],
  to: EntityStatus<K>,
  now: string,
): EntityMap[K] {
  assertTransition(kind, entity.status, to);
  const base = {
    ...entity,
    status: to,
    revision: incrementCounter(entity.revision),
    updatedAt: now,
  };
  if (kind === "capacity_pool") {
    const pool = base as CapacityPool;
    const entersDeny = to === "draining" || to === "denied" || to === "retired";
    const leavesDeny = to === "active";
    return {
      ...pool,
      denyState: entersDeny ? "denied" : leavesDeny ? "allowed" : pool.denyState,
      denyGeneration: entersDeny ? incrementCounter(pool.denyGeneration) : pool.denyGeneration,
      capacityGeneration: incrementCounter(pool.capacityGeneration),
    } as EntityMap[K];
  }
  return base as EntityMap[K];
}

export function assertBindingMayRetire(
  binding: CredentialBinding,
  method: AccessMethod,
  pool: CapacityPool,
): void {
  if (binding.status !== "active") {
    throw new AccountsError("INVALID_TRANSITION", "Only an active credential binding can retire", {
      details: { fromStatus: binding.status, toStatus: "retiring" },
    });
  }
  if (binding.accessMethodId !== method.id || binding.capacityPoolId !== pool.id) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Credential binding lineage does not match the drain target");
  }
  if (method.status !== "draining" || pool.status !== "draining" || pool.denyState !== "denied") {
    throw new AccountsError("POLICY_DENIED", "Credential retirement requires deny and drain first", {
      details: { operation: "credential_retire", reasonCodes: ["CURRENT_DENY"] },
    });
  }
}

/** Validates a proposed metadata update only. It does not prove zero live leases or authorize I/O. */
export function validateRoutineNativeRefreshCandidate(
  method: AccessMethod,
  pool: CapacityPool,
  beforeCapsule: AuthCapsule,
  afterCapsule: AuthCapsule,
  beforeBinding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }>,
  afterBinding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }>,
): void {
  const beforeState = beforeBinding.authStateRevision;
  if (beforeState === undefined) {
    throw new AccountsError("STALE_AUTH_STATE_REVISION", "Native binding has no authentication state revision", {
      details: { operation: "native_refresh" },
    });
  }
  const valid =
    method.accessTransport === "native_session" &&
    method.status === "draining" &&
    pool.status === "draining" &&
    pool.denyState === "denied" &&
    beforeBinding.resolver === "capsule_local_native" &&
    afterBinding.resolver === "capsule_local_native" &&
    beforeBinding.id === afterBinding.id &&
    beforeCapsule.id === afterCapsule.id &&
    beforeCapsule.accessMethodId === method.id &&
    afterCapsule.accessMethodId === method.id &&
    beforeCapsule.capacityPoolId === pool.id &&
    afterCapsule.capacityPoolId === pool.id &&
    beforeBinding.accessMethodId === method.id &&
    afterBinding.accessMethodId === method.id &&
    beforeBinding.capacityPoolId === pool.id &&
    afterBinding.capacityPoolId === pool.id &&
    beforeBinding.authCapsuleId === beforeCapsule.id &&
    afterBinding.authCapsuleId === afterCapsule.id &&
    beforeBinding.credentialFamilyId === afterBinding.credentialFamilyId &&
    beforeBinding.status === "active" &&
    afterBinding.status === "active" &&
    beforeCapsule.authGeneration === beforeBinding.credentialGeneration &&
    beforeCapsule.authGeneration === afterCapsule.authGeneration &&
    beforeBinding.credentialGeneration === afterBinding.credentialGeneration &&
    afterCapsule.authGeneration === afterBinding.credentialGeneration &&
    afterCapsule.authStateRevision === incrementCounter(beforeCapsule.authStateRevision) &&
    afterBinding.authStateRevision === incrementCounter(beforeState) &&
    afterCapsule.authStateRevision === afterBinding.authStateRevision;
  const {
    authStateRevision: _beforeCapsuleState,
    revision: _beforeCapsuleRevision,
    updatedAt: _beforeCapsuleUpdated,
    ...beforeCapsuleStable
  } = beforeCapsule;
  const {
    authStateRevision: _afterCapsuleState,
    revision: _afterCapsuleRevision,
    updatedAt: _afterCapsuleUpdated,
    ...afterCapsuleStable
  } = afterCapsule;
  const {
    authStateRevision: _beforeBindingState,
    revision: _beforeBindingRevision,
    updatedAt: _beforeBindingUpdated,
    ...beforeBindingStable
  } = beforeBinding;
  const {
    authStateRevision: _afterBindingState,
    revision: _afterBindingRevision,
    updatedAt: _afterBindingUpdated,
    ...afterBindingStable
  } = afterBinding;
  const stable =
    canonicalJson(beforeCapsuleStable) === canonicalJson(afterCapsuleStable) &&
    canonicalJson(beforeBindingStable) === canonicalJson(afterBindingStable) &&
    afterCapsule.revision === incrementCounter(beforeCapsule.revision) &&
    afterBinding.revision === incrementCounter(beforeBinding.revision) &&
    Date.parse(afterCapsule.updatedAt) > Date.parse(beforeCapsule.updatedAt) &&
    Date.parse(afterBinding.updatedAt) > Date.parse(beforeBinding.updatedAt);
  if (!valid || !stable) {
    throw new AccountsError("STALE_AUTH_STATE_REVISION", "Native refresh update violates generation fencing", {
      details: { operation: "native_refresh" },
    });
  }
}

/** Validates a proposed metadata lineage only. Native execution remains unavailable in this slice. */
export function validateNativeReauthenticationCandidate(
  method: AccessMethod,
  pool: CapacityPool,
  beforeCapsule: AuthCapsule,
  afterCapsule: AuthCapsule,
  retiringBinding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }>,
  replacementBinding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }>,
): void {
  const nextGeneration = incrementCounter(beforeCapsule.authGeneration);
  const valid =
    method.accessTransport === "native_session" &&
    method.status === "draining" &&
    pool.status === "draining" &&
    pool.denyState === "denied" &&
    retiringBinding.resolver === "capsule_local_native" &&
    retiringBinding.status === "retiring" &&
    replacementBinding.resolver === "capsule_local_native" &&
    replacementBinding.status === "pending" &&
    retiringBinding.id !== replacementBinding.id &&
    beforeCapsule.id === afterCapsule.id &&
    beforeCapsule.accessMethodId === method.id &&
    afterCapsule.accessMethodId === method.id &&
    beforeCapsule.capacityPoolId === pool.id &&
    afterCapsule.capacityPoolId === pool.id &&
    retiringBinding.accessMethodId === method.id &&
    replacementBinding.accessMethodId === method.id &&
    retiringBinding.capacityPoolId === pool.id &&
    replacementBinding.capacityPoolId === pool.id &&
    retiringBinding.authCapsuleId === beforeCapsule.id &&
    replacementBinding.authCapsuleId === afterCapsule.id &&
    beforeCapsule.authGeneration === retiringBinding.credentialGeneration &&
    retiringBinding.credentialFamilyId === replacementBinding.credentialFamilyId &&
    retiringBinding.capacityPoolId === replacementBinding.capacityPoolId &&
    retiringBinding.authCapsuleId === replacementBinding.authCapsuleId &&
    afterCapsule.authGeneration === nextGeneration &&
    replacementBinding.credentialGeneration === nextGeneration &&
    afterCapsule.authStateRevision === "0" &&
    replacementBinding.authStateRevision === "0";
  const {
    authGeneration: _beforeAuthGeneration,
    authStateRevision: _beforeAuthState,
    status: _beforeStatus,
    attestation: _beforeAttestation,
    lastHealthAt: _beforeHealth,
    revision: _beforeRevision,
    updatedAt: _beforeUpdated,
    ...beforeCapsuleStable
  } = beforeCapsule;
  const {
    authGeneration: _afterAuthGeneration,
    authStateRevision: _afterAuthState,
    status: _afterStatus,
    attestation: _afterAttestation,
    lastHealthAt: _afterHealth,
    revision: _afterRevision,
    updatedAt: _afterUpdated,
    ...afterCapsuleStable
  } = afterCapsule;
  const {
    id: _retiringId,
    credentialGeneration: _retiringGeneration,
    authStateRevision: _retiringState,
    status: _retiringStatus,
    revision: _retiringRevision,
    createdAt: _retiringCreated,
    updatedAt: _retiringUpdated,
    rotatedAt: _retiringRotated,
    expiresAt: _retiringExpires,
    ...retiringStable
  } = retiringBinding;
  const {
    id: _replacementId,
    credentialGeneration: _replacementGeneration,
    authStateRevision: _replacementState,
    status: _replacementStatus,
    revision: _replacementRevision,
    createdAt: _replacementCreated,
    updatedAt: _replacementUpdated,
    rotatedAt: _replacementRotated,
    expiresAt: _replacementExpires,
    ...replacementStable
  } = replacementBinding;
  const stable =
    canonicalJson(beforeCapsuleStable) === canonicalJson(afterCapsuleStable) &&
    canonicalJson(retiringStable) === canonicalJson(replacementStable) &&
    afterCapsule.revision === incrementCounter(beforeCapsule.revision) &&
    Date.parse(afterCapsule.updatedAt) > Date.parse(beforeCapsule.updatedAt);
  if (!valid || !stable) {
    throw new AccountsError("STALE_CREDENTIAL_GENERATION", "Native reauthentication violates generation fencing", {
      details: { operation: "native_reauthentication" },
    });
  }
}

export function entityStatus(entity: AnyEntity): string {
  return entity.status;
}
