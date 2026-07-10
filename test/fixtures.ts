import {
  newAccessMethodId,
  newAccountId,
  newAuthCapsuleId,
  newCapacityPoolId,
  newCredentialBindingId,
  newEntitlementId,
  parseCounter,
  parseCanonicalNodeId,
  type Account,
  type AccessMethod,
  type AccessTransport,
  type AuthCapsule,
  type CapacityPool,
  type CredentialBinding,
  type Entitlement,
} from "../src/index";
import type { AccountsCatalog } from "../src/domain/catalog";
import type { MutationContext } from "../src/storage/repository";

export const NOW = new Date("2026-07-10T12:00:00.000Z");
export const CREATED_AT = "2026-07-10T11:59:00.000Z";
export const FUTURE = "2026-07-10T13:00:00.000Z";
export const ACTOR_REF = "principal:human:hasna:owner-a";
export const C0 = parseCounter("0");
export const C1 = parseCounter("1");
export const C2 = parseCounter("2");

export const clock = (): Date => new Date(NOW);

export function digest(character = "a"): string {
  return `sha256:${character.repeat(64)}`;
}

export function mutationContext(suffix: string, reasonCode = "TEST_MUTATION"): MutationContext {
  return {
    actorRef: ACTOR_REF,
    idempotencyKey: `idem:${suffix}`,
    reasonCode,
  };
}

export interface FixtureGraph {
  readonly account: Account;
  readonly entitlement: Entitlement;
  readonly pool: CapacityPool;
  readonly method: AccessMethod;
  readonly capsule?: AuthCapsule;
  readonly binding: CredentialBinding;
}

export function makeFixtureGraph(
  transport: AccessTransport = "native_session",
  offset = 0,
): FixtureGraph {
  const accountId = newAccountId(NOW.getTime() + offset * 100 + 1);
  const entitlementId = newEntitlementId(NOW.getTime() + offset * 100 + 2);
  const capacityPoolId = newCapacityPoolId(NOW.getTime() + offset * 100 + 3);
  const accessMethodId = newAccessMethodId(NOW.getTime() + offset * 100 + 4);
  const policyDecisionRef = `evidence:policy-decision-${offset}`;
  const executionPolicyDigest = digest("d");
  const account: Account = {
    id: accountId,
    providerKey: "provider-example",
    ownerRef: ACTOR_REF,
    displayLabel: `Example account ${offset}`,
    providerSubjectRef: `provider-subject-${offset}`,
    status: "pending",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const entitlement: Entitlement = {
    id: entitlementId,
    accountId,
    fundingKind: "subscription",
    status: "pending",
    capabilitySet: {
      operations: ["responses.create"],
      models: ["model.example"],
    },
    capabilityEvidenceRef: policyDecisionRef,
    capabilityDigest: digest("b"),
    capabilityExpiresAt: FUTURE,
    executionPolicyDecisionRef: policyDecisionRef,
    executionPolicyDecisionDigest: digest("c"),
    executionPolicyDecisionExpiresAt: FUTURE,
    termsDecision: {
      decision: "allowed",
      useCase: "software-development",
      evidenceRef: "evidence:terms-1",
      verifiedBy: "authority:terms-1",
      verifiedAt: CREATED_AT,
      expiresAt: FUTURE,
      termsVersion: "terms-v1",
      termsDigest: digest("1"),
    },
    dataPolicy: {
      allowedClassifications: ["internal"],
      retentionClass: "transient",
    },
    dataPolicyEvidenceRef: policyDecisionRef,
    dataPolicyDigest: digest("2"),
    dataPolicyExpiresAt: FUTURE,
    lastVerifiedAt: CREATED_AT,
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const pool: CapacityPool = {
    id: capacityPoolId,
    accountId,
    capacityDomainRef: `capacity-domain-${offset}`,
    evidenceRef: `evidence:capacity-${offset}`,
    evidenceExpiresAt: FUTURE,
    serializationKey: `serialization-${offset}`,
    maxConcurrency: transport === "native_session" ? C1 : C2,
    status: "pending",
    capacityGeneration: C0,
    denyGeneration: C0,
    denyState: "denied",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const method: AccessMethod = {
    id: accessMethodId,
    entitlementId,
    capacityPoolId,
    adapterKey: "adapter-example",
    adapterVersion: "adapter-v1",
    accessTransport: transport,
    status: "draft",
    requiredIsolationPolicyRef: "policy:isolation-1",
    requiredIsolationPolicyDigest: digest("3"),
    isolationEvidenceExpiresAt: FUTURE,
    allowedDestinationPolicyClasses: ["default"],
    parentPolicyDecisionRef: policyDecisionRef,
    parentPolicyDecisionDigest: digest("c"),
    executionPolicyEvidenceRef: `evidence:lane-policy-${offset}`,
    executionPolicyDigest,
    executionPolicyExpiresAt: FUTURE,
    health: {
      state: "healthy",
      evidenceRef: `evidence:health-${offset}`,
      observedAt: CREATED_AT,
      expiresAt: FUTURE,
    },
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const capsuleId = newAuthCapsuleId(NOW.getTime() + offset * 100 + 5);
  const capsule =
    transport === "native_session"
      ? ({
          id: capsuleId,
          accessMethodId,
          capacityPoolId,
          kind: "native_session",
          ownerRef: ACTOR_REF,
          placementKind: "enrolled_node",
          placementRef: parseCanonicalNodeId(
            `018f0f0${(offset % 10).toString()}-7b6d-7a10-8a00-${(offset + 1)
              .toString(16)
              .padStart(12, "0")}`,
          ),
          hardwareKeyThumbprint: digest("4"),
          nodeGeneration: C1,
          placementGeneration: C1,
          status: "unprovisioned",
          refreshOwnerRef: `principal:service:hasna:capsule-host:${capsuleId}`,
          refreshMode: "provider_native",
          authGeneration: C0,
          authStateRevision: C0,
          isolationPolicyRef: "policy:isolation-1",
          isolationPolicyDigest: digest("3"),
          attestation: {
            evidenceRef: `evidence:attestation-${offset}`,
            issuerRef: "authority:machines-1",
            measurementDigest: digest("5"),
            attestedAt: CREATED_AT,
            expiresAt: FUTURE,
          },
          lastHealthAt: CREATED_AT,
          revision: C0,
          createdAt: CREATED_AT,
          updatedAt: CREATED_AT,
        } satisfies AuthCapsule)
      : undefined;
  const binding: CredentialBinding = {
    id: newCredentialBindingId(NOW.getTime() + offset * 100 + 7),
    accessMethodId,
    capacityPoolId,
    ...(capsule === undefined ? {} : { authCapsuleId: capsule.id }),
    credentialFamilyId: `credential-family-${offset}`,
    purpose:
      transport === "native_session"
        ? "provider_session"
        : transport === "api_key"
          ? "api_key"
          : "workload_identity",
    resolver:
      transport === "native_session"
        ? "capsule_local_native"
        : transport === "api_key"
          ? "brokered_secret"
          : "workload_identity",
    credentialGeneration: C0,
    ...(capsule === undefined
      ? { refreshMode: "broker_serialized" as const }
      : { authStateRevision: C0 }),
    status: "pending",
    policyDigest: executionPolicyDigest,
    bindingEvidenceRef: `evidence:binding-${offset}`,
    bindingEvidenceIssuerRef: "authority:credential-issuer-1",
    bindingEvidenceDigest: digest("6"),
    bindingEvidenceExpiresAt: FUTURE,
    expiresAt: FUTURE,
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  return {
    account,
    entitlement,
    pool,
    method,
    ...(capsule === undefined ? {} : { capsule }),
    binding,
  };
}

export async function seedActiveCatalog(
  catalog: AccountsCatalog,
  graph: FixtureGraph,
  prefix = "seed",
): Promise<void> {
  await catalog.add("account", graph.account, mutationContext(`${prefix}:account:add`));
  await catalog.transition(
    "account",
    graph.account.id,
    "active",
    C0,
    mutationContext(`${prefix}:account:active`),
  );
  await catalog.add("entitlement", graph.entitlement, mutationContext(`${prefix}:entitlement:add`));
  await catalog.transition(
    "entitlement",
    graph.entitlement.id,
    "active",
    C0,
    mutationContext(`${prefix}:entitlement:active`),
  );
  await catalog.add("capacity_pool", graph.pool, mutationContext(`${prefix}:pool:add`));
  await catalog.transition(
    "capacity_pool",
    graph.pool.id,
    "active",
    C0,
    mutationContext(`${prefix}:pool:active`),
  );
  await catalog.add("access_method", graph.method, mutationContext(`${prefix}:method:add`));
  await catalog.transition(
    "access_method",
    graph.method.id,
    "ready",
    C0,
    mutationContext(`${prefix}:method:ready`),
  );
  if (graph.capsule !== undefined) {
    await catalog.add("auth_capsule", graph.capsule, mutationContext(`${prefix}:capsule:add`));
    await catalog.transition(
      "auth_capsule",
      graph.capsule.id,
      "bootstrapping",
      C0,
      mutationContext(`${prefix}:capsule:bootstrapping`),
    );
    await catalog.transition(
      "auth_capsule",
      graph.capsule.id,
      "ready",
      C1,
      mutationContext(`${prefix}:capsule:ready`),
    );
  }
  await catalog.add("credential_binding", graph.binding, mutationContext(`${prefix}:binding:add`));
  await catalog.transition(
    "credential_binding",
    graph.binding.id,
    "active",
    C0,
    mutationContext(`${prefix}:binding:active`),
  );
}
