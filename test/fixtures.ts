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
import type {
  AccountsCatalog,
  AuthorityEvidencePolicy,
  EntitlementEvidenceBundle,
  EvidenceFence,
  LaneEvidenceBundle,
} from "../src/domain/catalog";
import type { MutationContext } from "../src/storage/repository";
import type { CredentialHandleEnvelope } from "../src/storage/repository";
import {
  Ed25519CredentialHandleVerifier,
  signCredentialHandleEnvelope,
} from "../src/storage/credential-verifier";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { InMemoryRecoveryLedger } from "../src/storage/recovery";
import {
  Ed25519CredentialUseAuthorizer,
  signCredentialResolutionGrant,
} from "../src/storage/credential-use-authorizer";
import type {
  CredentialResolutionGrant,
  CredentialResolutionTransport,
  RecoveryFrontier,
} from "../src/storage/repository";
import {
  signAuthorityEvidenceForTest,
  type AuthorityEvidenceDraft,
  type AuthorityEvidenceEnvelope,
  type AuthorityEvidencePayload,
  type AuthorityEvidenceTrustRoot,
  type AuthorityEvidenceType,
} from "../src/domain/authority-evidence";
import { parseClosedJsonBytes } from "../src/serialization/json";

export const NOW = new Date("2026-07-10T12:00:00.000Z");
export const CREATED_AT = "2026-07-10T11:59:00.000Z";
export const FUTURE = "2026-07-10T13:00:00.000Z";
export const ACTOR_REF = "principal:human:hasna:owner-a";
export const CATALOG_INCARNATION = "catalog:test-incarnation";
const CREDENTIAL_ISSUER_KEYS = generateKeyPairSync("ed25519");
const CREDENTIAL_USE_KEYS = generateKeyPairSync("ed25519");
const AUTHORITY_KEYS = {
  provider_ownership_verifier: generateKeyPairSync("ed25519"),
  provider_capacity_verifier: generateKeyPairSync("ed25519"),
  execution_policy_authority: generateKeyPairSync("ed25519"),
  terms_authority: generateKeyPairSync("ed25519"),
  adapter_health_reporter: generateKeyPairSync("ed25519"),
} as const;
const AUTHORITY_AUDIENCE = "accounts:self-hosted:capacity";
const IDENTITY_REALM = "hasna";
const AUTHORITY_ISSUER_INCARNATION = "018f0f00-0010-7000-8000-000000000010";

const AUTHORITY_TYPE_CONFIG = {
  provider_ownership: {
    aggregateKind: "provider_account",
    issuerClass: "provider_ownership_verifier",
  },
  provider_capacity: {
    aggregateKind: "capacity_pool",
    issuerClass: "provider_capacity_verifier",
  },
  entitlement_execution_policy: {
    aggregateKind: "entitlement",
    issuerClass: "execution_policy_authority",
  },
  entitlement_terms: {
    aggregateKind: "entitlement",
    issuerClass: "terms_authority",
  },
  entitlement_data_policy: {
    aggregateKind: "entitlement",
    issuerClass: "execution_policy_authority",
  },
  lane_isolation_policy: {
    aggregateKind: "account_lane",
    issuerClass: "execution_policy_authority",
  },
  lane_execution_policy: {
    aggregateKind: "account_lane",
    issuerClass: "execution_policy_authority",
  },
  lane_health: {
    aggregateKind: "account_lane",
    issuerClass: "adapter_health_reporter",
  },
} as const;

function authorityTrustRoot(type: AuthorityEvidenceType): AuthorityEvidenceTrustRoot {
  const config = AUTHORITY_TYPE_CONFIG[type];
  return {
    issuerRef: `authority:${config.issuerClass}`,
    issuerClass: config.issuerClass,
    issuerIncarnation: AUTHORITY_ISSUER_INCARNATION,
    audience: AUTHORITY_AUDIENCE,
    identityRealm: IDENTITY_REALM,
    keyId: `key-${config.issuerClass}-1`,
    publicKey: AUTHORITY_KEYS[config.issuerClass].publicKey,
    revoked: false,
  };
}

export const TEST_AUTHORITY_POLICY: AuthorityEvidencePolicy = {
  trustRoots: new Map(
    (Object.keys(AUTHORITY_TYPE_CONFIG) as AuthorityEvidenceType[]).map((type) => [
      type,
      authorityTrustRoot(type),
    ]),
  ),
  identityRealm: IDENTITY_REALM,
  maximumAgeMs: 5 * 60_000,
  maximumLifetimeMs: 2 * 60 * 60_000,
};
export const TEST_CREDENTIAL_VERIFIER = new Ed25519CredentialHandleVerifier({
  issuerPublicKeys: new Map([["authority:credential-issuer-1", CREDENTIAL_ISSUER_KEYS.publicKey]]),
  auditKey: randomBytes(32),
});
export const makeTestRecoveryLedger = (): InMemoryRecoveryLedger =>
  new InMemoryRecoveryLedger(CATALOG_INCARNATION);
export const TEST_CREDENTIAL_USE_AUTHORIZER = new Ed25519CredentialUseAuthorizer(
  new Map([["authority:infinity-run-authority", CREDENTIAL_USE_KEYS.publicKey]]),
);
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

function evidenceNonce(offset: number, salt: number): string {
  const bytes = Buffer.alloc(24);
  bytes.writeUInt32BE(offset >>> 0, 0);
  bytes.writeUInt32BE(salt >>> 0, 4);
  bytes.fill((offset * 17 + salt * 29) & 0xff, 8);
  return bytes.toString("base64url");
}

function signedAuthorityEvidence<Type extends AuthorityEvidenceType>(
  type: Type,
  aggregateId: string,
  payload: AuthorityEvidencePayload<Type>,
  offset: number,
  salt: number,
): {
  readonly source: Uint8Array;
  readonly envelope: AuthorityEvidenceEnvelope<Type>;
  readonly fence: EvidenceFence;
} {
  const config = AUTHORITY_TYPE_CONFIG[type];
  const trust = authorityTrustRoot(type);
  const nonce = evidenceNonce(offset, salt);
  const evidenceGeneration = C1;
  const draft = {
    schema_version: "accounts.authority-evidence.v1",
    evidence_type: type,
    evidence_ref: `evidence:${type}:${offset}`,
    subject_ref: aggregateId,
    aggregate_kind: config.aggregateKind,
    aggregate_id: aggregateId,
    aggregate_revision: C0,
    identity_realm: IDENTITY_REALM,
    issuer_ref: trust.issuerRef,
    issuer_class: trust.issuerClass,
    issuer_incarnation: trust.issuerIncarnation,
    audience: trust.audience,
    key_id: trust.keyId,
    issued_at: CREATED_AT,
    expires_at: FUTURE,
    nonce,
    evidence_generation: evidenceGeneration,
    payload,
  } as AuthorityEvidenceDraft<Type>;
  const source = signAuthorityEvidenceForTest(
    draft,
    AUTHORITY_KEYS[config.issuerClass].privateKey,
  );
  return {
    source,
    envelope: parseClosedJsonBytes(source) as unknown as AuthorityEvidenceEnvelope<Type>,
    fence: { nonce, evidenceGeneration },
  };
}

export interface FixtureGraph {
  readonly account: Account;
  readonly activeAccount: Account;
  readonly ownershipEvidence: Uint8Array;
  readonly ownershipFence: EvidenceFence;
  readonly entitlement: Entitlement;
  readonly activeEntitlement: Entitlement;
  readonly entitlementEvidence: EntitlementEvidenceBundle;
  readonly pool: CapacityPool;
  readonly capacityEvidence: Uint8Array;
  readonly capacityFence: EvidenceFence;
  readonly method: AccessMethod;
  readonly readyMethod: AccessMethod;
  readonly laneEvidence: LaneEvidenceBundle;
  readonly capsule?: AuthCapsule;
  readonly binding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }>;
  readonly handle: CredentialHandleEnvelope;
}

export function makeCredentialHandleFor(
  graph: Pick<FixtureGraph, "account" | "pool" | "method" | "capsule"> & {
    readonly binding: Extract<
      CredentialBinding,
      { readonly status: "pending" | "active" | "retiring" }
    >;
  },
  offset = 0,
  audience: CredentialHandleEnvelope["audience"] = "accounts-local",
): CredentialHandleEnvelope {
  const { account, pool, method, capsule, binding } = graph;
  return signCredentialHandleEnvelope({
    opaqueHandle: `accounts-handle:v1:issuer-1:${String(offset).padStart(64, "a")}`,
    issuerRef: binding.bindingEvidenceIssuerRef,
    audience,
    catalogIncarnation: CATALOG_INCARNATION,
    backendClass:
      binding.resolver === "capsule_local_native"
        ? "capsule_protected_state"
        : binding.resolver === "brokered_secret"
          ? "secrets_broker"
          : "workload_identity_broker",
    ownerRef: account.ownerRef,
    providerAccountId: account.id,
    providerKey: account.providerKey,
    capacityPoolId: pool.id,
    capacityDomainRef: pool.capacityDomainRef,
    accessMethodId: method.id,
    credentialFamilyId: binding.credentialFamilyId,
    purpose: binding.purpose,
    resolver: binding.resolver,
    policyDigest: binding.policyDigest,
    credentialGeneration: binding.credentialGeneration,
    ...(capsule === undefined
      ? {}
      : {
          authCapsuleId: capsule.id,
          canonicalNodeId: capsule.placementRef,
          nodeGeneration: capsule.nodeGeneration,
          placementGeneration: capsule.placementGeneration,
        }),
    issuedAt: CREATED_AT,
    ...(binding.expiresAt === undefined ? {} : { expiresAt: binding.expiresAt }),
  }, CREDENTIAL_ISSUER_KEYS.privateKey);
}

export function makeCredentialResolution(
  graph: FixtureGraph,
  frontier: RecoveryFrontier,
): {
  readonly grant: CredentialResolutionGrant;
  readonly transport: CredentialResolutionTransport;
} {
  const transport: CredentialResolutionTransport = {
    authenticatedActorPrincipal: "principal:service:hasna:infinity-effect-sink",
    authenticatedHolderPrincipal: "principal:service:hasna:run-holder",
    authenticatedExecutorPrincipal: "principal:service:hasna:sandbox-executor",
    authenticatedSenderKeyThumbprint: digest("8"),
    audience: "accounts-local-resolver",
    runId: "run:test-1",
    attemptId: "attempt:test-1",
    resourceLeaseId: "resource-lease:test-1",
    resourceId: "resource:test-1",
    resourceGeneration: C1,
    operationId: "operation:responses-create",
    operationDigest: digest("9"),
    executionEpoch: C1,
    requestDigest: digest("0"),
    now: NOW.toISOString(),
  };
  const grant = signCredentialResolutionGrant(
    {
      schema_version: "accounts.handle-resolution.v1",
      issuer_ref: "authority:infinity-run-authority",
      provider_account_id: graph.account.id,
      account_lane_id: graph.method.id,
      capacity_pool_id: graph.pool.id,
      credential_binding_id: graph.binding.id,
      credential_family_id: graph.binding.credentialFamilyId,
      credential_generation: graph.binding.credentialGeneration,
      purpose: graph.binding.purpose,
      resolver: graph.binding.resolver,
      run_id: transport.runId,
      attempt_id: transport.attemptId,
      resource_lease_id: transport.resourceLeaseId,
      resource_id: transport.resourceId,
      resource_generation: transport.resourceGeneration,
      operation_id: transport.operationId,
      operation_digest: transport.operationDigest,
      execution_epoch: transport.executionEpoch,
      subject_principal: graph.account.ownerRef,
      actor_principal: transport.authenticatedActorPrincipal,
      holder_principal: transport.authenticatedHolderPrincipal,
      executor_principal: transport.authenticatedExecutorPrincipal,
      audience: transport.audience,
      sender_key_thumbprint: transport.authenticatedSenderKeyThumbprint,
      catalog_incarnation: frontier.catalogIncarnation,
      recovery_frontier_sequence: frontier.sequence,
      recovery_frontier_hash: frontier.hash,
      request_digest: transport.requestDigest,
      issued_at: new Date(NOW.getTime() - 1_000).toISOString(),
      expires_at: new Date(NOW.getTime() + 29_000).toISOString(),
    },
    CREDENTIAL_USE_KEYS.privateKey,
  );
  return { grant, transport };
}

export function makeFixtureGraph(
  transport: AccessTransport = "native_session",
  offset = 0,
  providerSubjectRef = `provider-subject-${offset}`,
): FixtureGraph {
  const accountId = newAccountId(NOW.getTime() + offset * 100 + 1);
  const entitlementId = newEntitlementId(NOW.getTime() + offset * 100 + 2);
  const capacityPoolId = newCapacityPoolId(NOW.getTime() + offset * 100 + 3);
  const accessMethodId = newAccessMethodId(NOW.getTime() + offset * 100 + 4);
  const account: Account = {
    id: accountId,
    providerKey: "provider-example",
    ownerRef: ACTOR_REF,
    displayLabel: `Example account ${offset}`,
    providerSubjectCandidateRef: providerSubjectRef,
    status: "pending",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const ownership = signedAuthorityEvidence(
    "provider_ownership",
    accountId,
    {
      provider_key: account.providerKey,
      provider_subject_ref: providerSubjectRef,
      owner_ref: account.ownerRef,
      identity_realm: IDENTITY_REALM,
      ownership_generation: C1,
    },
    offset,
    1,
  );
  const activeAccount: Account = {
    id: account.id,
    providerKey: account.providerKey,
    ownerRef: account.ownerRef,
    displayLabel: account.displayLabel,
    providerSubjectRef,
    ownershipEvidenceRef: ownership.envelope.evidence_ref,
    ownershipEvidenceIssuerRef: ownership.envelope.issuer_ref,
    ownershipEvidenceVersion: ownership.envelope.schema_version,
    ownershipEvidenceDigest: ownership.envelope.payload_digest,
    ownershipEvidenceIssuedAt: ownership.envelope.issued_at,
    ownershipEvidenceExpiresAt: ownership.envelope.expires_at,
    ownershipGeneration: C1,
    status: "active",
    revision: C1,
    createdAt: account.createdAt,
    updatedAt: NOW.toISOString(),
  };
  const entitlement: Entitlement = {
    id: entitlementId,
    accountId,
    fundingKind: "subscription",
    status: "pending",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const useCase = "software-development";
  const executionPolicy = signedAuthorityEvidence(
    "entitlement_execution_policy",
    entitlementId,
    {
      provider_account_id: accountId,
      owner_ref: account.ownerRef,
      provider_key: account.providerKey,
      use_case: useCase,
      adapter_version: "adapter-v1",
      decision: "allowed",
      capability_set: {
        operations: ["responses.create"],
        models: ["model.example"],
      },
      policy_version: "policy-v1",
    },
    offset,
    2,
  );
  const terms = signedAuthorityEvidence(
    "entitlement_terms",
    entitlementId,
    {
      provider_account_id: accountId,
      owner_ref: account.ownerRef,
      provider_key: account.providerKey,
      use_case: useCase,
      decision: "allowed",
      terms_version: "terms-v1",
      terms_digest: digest("1"),
    },
    offset,
    3,
  );
  const dataPolicy = signedAuthorityEvidence(
    "entitlement_data_policy",
    entitlementId,
    {
      provider_account_id: accountId,
      owner_ref: account.ownerRef,
      provider_key: account.providerKey,
      use_case: useCase,
      decision: "allowed",
      allowed_classifications: ["internal"],
      retention_class: "transient",
      policy_version: "policy-v1",
    },
    offset,
    4,
  );
  const activeEntitlement: Entitlement = {
    ...entitlement,
    status: "active",
    capabilitySet: executionPolicy.envelope.payload.capability_set,
    capabilityEvidenceRef: executionPolicy.envelope.evidence_ref,
    capabilityDigest: executionPolicy.envelope.payload_digest,
    capabilityExpiresAt: executionPolicy.envelope.expires_at,
    executionPolicyDecisionRef: executionPolicy.envelope.evidence_ref,
    executionPolicyDecisionDigest: executionPolicy.envelope.payload_digest,
    executionPolicyDecisionExpiresAt: executionPolicy.envelope.expires_at,
    termsDecision: {
      decision: "allowed",
      useCase,
      evidenceRef: terms.envelope.evidence_ref,
      verifiedBy: terms.envelope.issuer_ref,
      verifiedAt: terms.envelope.issued_at,
      expiresAt: terms.envelope.expires_at,
      termsVersion: terms.envelope.payload.terms_version,
      termsDigest: terms.envelope.payload.terms_digest,
    },
    dataPolicy: {
      allowedClassifications: dataPolicy.envelope.payload.allowed_classifications,
      retentionClass: dataPolicy.envelope.payload.retention_class,
    },
    dataPolicyEvidenceRef: dataPolicy.envelope.evidence_ref,
    dataPolicyDigest: dataPolicy.envelope.payload_digest,
    dataPolicyExpiresAt: dataPolicy.envelope.expires_at,
    lastVerifiedAt: executionPolicy.envelope.issued_at,
    revision: C1,
    updatedAt: NOW.toISOString(),
  };
  const poolProjection = {
    id: capacityPoolId,
    accountId,
    capacityDomainRef: `capacity-domain-${offset}`,
    serializationKey: `serialization-${offset}`,
    maxConcurrency: transport === "native_session" ? C1 : C2,
    status: "pending",
    capacityGeneration: C0,
    denyGeneration: C0,
    denyState: "denied",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  } as const;
  const capacityEvidence = signedAuthorityEvidence(
    "provider_capacity",
    capacityPoolId,
    {
      provider_account_id: accountId,
      provider_key: account.providerKey,
      owner_ref: account.ownerRef,
      capacity_domain_ref: poolProjection.capacityDomainRef,
      serialization_key: poolProjection.serializationKey,
      max_concurrency: poolProjection.maxConcurrency,
      decision: "allowed",
      policy_version: "capacity-policy-v1",
    },
    offset,
    8,
  );
  const pool: CapacityPool = {
    ...poolProjection,
    capacityEvidenceRef: capacityEvidence.envelope.evidence_ref,
    capacityEvidenceIssuerRef: capacityEvidence.envelope.issuer_ref,
    capacityEvidenceVersion: capacityEvidence.envelope.schema_version,
    capacityEvidenceDigest: capacityEvidence.envelope.payload_digest,
    capacityEvidenceIssuedAt: capacityEvidence.envelope.issued_at,
    capacityEvidenceExpiresAt: capacityEvidence.envelope.expires_at,
    capacityEvidenceGeneration: capacityEvidence.envelope.evidence_generation,
    capacityPolicyVersion: capacityEvidence.envelope.payload.policy_version,
  };
  const method: AccessMethod = {
    id: accessMethodId,
    entitlementId,
    capacityPoolId,
    adapterKey: "adapter-example",
    adapterVersion: "adapter-v1",
    accessTransport: transport,
    status: "draft",
    revision: C0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  };
  const laneIsolation = signedAuthorityEvidence(
    "lane_isolation_policy",
    accessMethodId,
    {
      provider_account_id: accountId,
      entitlement_id: entitlementId,
      capacity_pool_id: capacityPoolId,
      owner_ref: account.ownerRef,
      adapter_key: method.adapterKey,
      adapter_version: method.adapterVersion,
      access_transport: transport,
      decision: "allowed",
      required_isolation_policy_ref: "policy:isolation-1",
      required_isolation_policy_digest: digest("3"),
      policy_version: "policy-v1",
    },
    offset,
    5,
  );
  const laneExecution = signedAuthorityEvidence(
    "lane_execution_policy",
    accessMethodId,
    {
      provider_account_id: accountId,
      entitlement_id: entitlementId,
      capacity_pool_id: capacityPoolId,
      owner_ref: account.ownerRef,
      adapter_key: method.adapterKey,
      adapter_version: method.adapterVersion,
      access_transport: transport,
      decision: "allowed",
      allowed_operations: ["responses.create"],
      allowed_models: ["model.example"],
      allowed_destination_policy_classes: ["default"],
      policy_version: "policy-v1",
    },
    offset,
    6,
  );
  const laneHealth = signedAuthorityEvidence(
    "lane_health",
    accessMethodId,
    {
      provider_account_id: accountId,
      entitlement_id: entitlementId,
      capacity_pool_id: capacityPoolId,
      owner_ref: account.ownerRef,
      adapter_key: method.adapterKey,
      adapter_version: method.adapterVersion,
      state: "healthy",
      observed_at: CREATED_AT,
    },
    offset,
    7,
  );
  const readyMethod: AccessMethod = {
    ...method,
    status: "ready",
    requiredIsolationPolicyRef:
      laneIsolation.envelope.payload.required_isolation_policy_ref!,
    requiredIsolationPolicyDigest:
      laneIsolation.envelope.payload.required_isolation_policy_digest!,
    isolationEvidenceExpiresAt: laneIsolation.envelope.expires_at,
    allowedDestinationPolicyClasses:
      laneExecution.envelope.payload.allowed_destination_policy_classes,
    parentPolicyDecisionRef: activeEntitlement.executionPolicyDecisionRef!,
    parentPolicyDecisionDigest: activeEntitlement.executionPolicyDecisionDigest!,
    executionPolicyEvidenceRef: laneExecution.envelope.evidence_ref,
    executionPolicyDigest: laneExecution.envelope.payload_digest,
    executionPolicyExpiresAt: laneExecution.envelope.expires_at,
    health: {
      state: laneHealth.envelope.payload.state,
      evidenceRef: laneHealth.envelope.evidence_ref,
      observedAt: laneHealth.envelope.payload.observed_at,
      expiresAt: laneHealth.envelope.expires_at,
    },
    revision: C1,
    updatedAt: NOW.toISOString(),
  };
  const executionPolicyDigest = laneExecution.envelope.payload_digest;
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
  const binding: Extract<CredentialBinding, { readonly status: "pending" | "active" | "retiring" }> = {
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
  const handle = makeCredentialHandleFor(
    { account, pool, method, ...(capsule === undefined ? {} : { capsule }), binding },
    offset,
  );
  return {
    account,
    activeAccount,
    ownershipEvidence: ownership.source,
    ownershipFence: ownership.fence,
    entitlement,
    activeEntitlement,
    entitlementEvidence: {
      executionPolicy: executionPolicy.source,
      executionPolicyFence: executionPolicy.fence,
      terms: terms.source,
      termsFence: terms.fence,
      dataPolicy: dataPolicy.source,
      dataPolicyFence: dataPolicy.fence,
      useCase,
      adapterVersion: method.adapterVersion,
    },
    pool,
    capacityEvidence: capacityEvidence.source,
    capacityFence: capacityEvidence.fence,
    method,
    readyMethod,
    laneEvidence: {
      isolationPolicy: laneIsolation.source,
      isolationPolicyFence: laneIsolation.fence,
      executionPolicy: laneExecution.source,
      executionPolicyFence: laneExecution.fence,
      health: laneHealth.source,
      healthFence: laneHealth.fence,
    },
    ...(capsule === undefined ? {} : { capsule }),
    binding,
    handle,
  };
}

export async function seedActiveCatalog(
  catalog: AccountsCatalog,
  graph: FixtureGraph,
  prefix = "seed",
): Promise<void> {
  await catalog.add("account", graph.account, mutationContext(`${prefix}:account:add`));
  await catalog.activateProviderAccount(
    graph.activeAccount,
    graph.ownershipEvidence,
    graph.ownershipFence,
    C0,
    mutationContext(`${prefix}:account:active`),
  );
  await catalog.add("entitlement", graph.entitlement, mutationContext(`${prefix}:entitlement:add`));
  await catalog.activateEntitlement(
    graph.activeEntitlement,
    graph.entitlementEvidence,
    C0,
    mutationContext(`${prefix}:entitlement:active`),
  );
  await catalog.addCapacityPoolFromEvidence(
    graph.pool,
    graph.capacityEvidence,
    graph.capacityFence,
    mutationContext(`${prefix}:pool:add`),
  );
  await catalog.transition(
    "capacity_pool",
    graph.pool.id,
    "active",
    C0,
    mutationContext(`${prefix}:pool:active`),
  );
  await catalog.add("access_method", graph.method, mutationContext(`${prefix}:method:add`));
  await catalog.activateAccessMethod(
    graph.readyMethod,
    graph.laneEvidence,
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
  await catalog.addCredentialBinding(
    graph.binding,
    graph.handle,
    mutationContext(`${prefix}:binding:add`),
  );
  await catalog.transition(
    "credential_binding",
    graph.binding.id,
    "active",
    C0,
    mutationContext(`${prefix}:binding:active`),
  );
}
