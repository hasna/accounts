import { AccountsError } from "../errors";
import { compareCounters, incrementCounter, parseCounter, type Counter } from "../domain/counter";
import type { EntityKind, EntityMap } from "../domain/models";
import type { CredentialBinding } from "../domain/models";
import { assertTransition } from "../domain/state";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import {
  deserializeRecordEnvelope,
  serializeRecordEnvelope,
  validateEntity,
} from "../serialization/dto";
import type {
  AccountsRepository,
  CredentialHandleEnvelope,
  CredentialHandleExpectedClaims,
  MutationContext,
  OutboxAcknowledgeRequest,
  OutboxClaimRequest,
  AuthorityPromotionKind,
  VerifiedAuthorityEvidenceRecord,
} from "./repository";
import { parseClosedJson } from "../serialization/json";

const ACTOR_PATTERN = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const HANDLE_PATTERN = /^accounts-handle:v1:[a-z0-9][a-z0-9._-]{0,63}:[A-Za-z0-9_-]{43,512}$/;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function validateMutationContext(context: MutationContext): void {
  if (!ACTOR_PATTERN.test(context.actorRef)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid mutation actor", {
      details: { field: "actorRef" },
    });
  }
  if (!IDEMPOTENCY_PATTERN.test(context.idempotencyKey)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid idempotency key", {
      details: { field: "idempotencyKey" },
    });
  }
  if (!REASON_PATTERN.test(context.reasonCode)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid mutation reason code", {
      details: { field: "reasonCode" },
    });
  }
}

export function validateOutboxClaimRequest(request: OutboxClaimRequest): void {
  if (
    !/^principal:service:hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.workerRef) ||
    !Number.isSafeInteger(request.limit) ||
    request.limit < 1 ||
    request.limit > 100 ||
    !TIMESTAMP_PATTERN.test(request.now) ||
    !TIMESTAMP_PATTERN.test(request.claimExpiresAt) ||
    new Date(Date.parse(request.now)).toISOString() !== request.now ||
    new Date(Date.parse(request.claimExpiresAt)).toISOString() !== request.claimExpiresAt ||
    Date.parse(request.claimExpiresAt) <= Date.parse(request.now) ||
    Date.parse(request.claimExpiresAt) - Date.parse(request.now) > 5 * 60_000
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Outbox claim request is invalid");
  }
}

export function validateOutboxAcknowledgeRequest(request: OutboxAcknowledgeRequest): void {
  if (
    !/^principal:service:hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.workerRef) ||
    !TIMESTAMP_PATTERN.test(request.now) ||
    new Date(Date.parse(request.now)).toISOString() !== request.now
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Outbox acknowledgement is invalid");
  }
  parseCounter(request.expectedAttemptCount, "expectedAttemptCount");
}

export function validateCredentialHandleEnvelope(
  binding: CredentialBinding,
  handle: CredentialHandleEnvelope,
): void {
  if (binding.status === "revoked") {
    throw new AccountsError("INVALID_TRANSITION", "A revoked binding cannot receive a handle");
  }
  if (!HANDLE_PATTERN.test(handle.opaqueHandle)) {
    throw new AccountsError("VALIDATION_FAILED", "Credential handle envelope is invalid", {
      details: { field: "opaqueHandle" },
    });
  }
  if (
    !REF_PATTERN.test(handle.issuerRef) ||
    handle.issuerRef !== binding.bindingEvidenceIssuerRef ||
    !REF_PATTERN.test(handle.catalogIncarnation) ||
    !SIGNATURE_PATTERN.test(handle.signature) ||
    !TIMESTAMP_PATTERN.test(handle.issuedAt) ||
    new Date(Date.parse(handle.issuedAt)).toISOString() !== handle.issuedAt ||
    (handle.expiresAt !== undefined &&
      (!TIMESTAMP_PATTERN.test(handle.expiresAt) ||
        new Date(Date.parse(handle.expiresAt)).toISOString() !== handle.expiresAt ||
        Date.parse(handle.expiresAt) <= Date.parse(handle.issuedAt))) ||
    (binding.expiresAt !== undefined && handle.expiresAt !== binding.expiresAt)
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Credential handle binding is invalid", {
      details: { field: "credentialHandleEnvelope" },
    });
  }
  const expectedBackend =
    binding.resolver === "capsule_local_native"
      ? "capsule_protected_state"
      : binding.resolver === "brokered_secret"
        ? "secrets_broker"
        : "workload_identity_broker";
  if (handle.backendClass !== expectedBackend) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Credential handle backend does not match resolver");
  }
  const nativeClaims = [
    handle.authCapsuleId,
    handle.canonicalNodeId,
    handle.nodeGeneration,
    handle.placementGeneration,
  ];
  if (
    (binding.resolver === "capsule_local_native" && nativeClaims.some((value) => value === undefined)) ||
    (binding.resolver !== "capsule_local_native" && nativeClaims.some((value) => value !== undefined))
  ) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Credential handle native claims are invalid");
  }
}

export async function buildCredentialHandleExpectedClaims(
  repository: Pick<AccountsRepository, "get">,
  binding: CredentialBinding,
  authority: Pick<
    CredentialHandleExpectedClaims,
    "audience" | "catalogIncarnation" | "backendClass"
  >,
): Promise<CredentialHandleExpectedClaims> {
  const method = await repository.get("access_method", binding.accessMethodId);
  const pool = await repository.get("capacity_pool", binding.capacityPoolId);
  const account = pool === undefined ? undefined : await repository.get("account", pool.accountId);
  if (
    method === undefined ||
    pool === undefined ||
    account === undefined ||
    method.capacityPoolId !== pool.id
  ) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Credential handle lineage is incomplete");
  }
  const capsule =
    binding.resolver === "capsule_local_native"
      ? await repository.get("auth_capsule", binding.authCapsuleId!)
      : undefined;
  if (
    binding.resolver === "capsule_local_native" &&
    (capsule === undefined ||
      capsule.accessMethodId !== method.id ||
      capsule.capacityPoolId !== pool.id)
  ) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Native credential handle lineage is incomplete");
  }
  return {
    ...authority,
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
  };
}

export function cloneEntity<K extends EntityKind>(kind: K, record: EntityMap[K]): EntityMap[K] {
  const envelope = deserializeRecordEnvelope(serializeRecordEnvelope(kind, record));
  return envelope.data as EntityMap[K];
}

export function mutationHash<K extends EntityKind>(
  operation: "insert" | "replace",
  kind: K,
  record: EntityMap[K],
  context: MutationContext,
  expectedRevision?: Counter,
): string {
  return canonicalSha256({
    operation,
    kind,
    record: validateEntity(kind, record),
    reasonCode: context.reasonCode,
    ...(expectedRevision === undefined ? {} : { expectedRevision }),
  });
}

const AUTHORITY_TYPES_BY_KIND = {
  account: ["provider_ownership"],
  capacity_pool: ["provider_capacity"],
  entitlement: [
    "entitlement_execution_policy",
    "entitlement_terms",
    "entitlement_data_policy",
  ],
  access_method: ["lane_isolation_policy", "lane_execution_policy", "lane_health"],
} as const satisfies Readonly<Record<AuthorityPromotionKind, readonly string[]>>;

export function isAuthorityPromotion<K extends EntityKind>(
  kind: K,
  previous: EntityMap[K],
  next: EntityMap[K],
): boolean {
  return (
    (kind === "account" && previous.status === "pending" && next.status === "active") ||
    (kind === "entitlement" && previous.status === "pending" && next.status === "active") ||
    (kind === "access_method" && previous.status === "draft" && next.status === "ready")
  );
}

export function validateVerifiedAuthorityEvidence(
  kind: AuthorityPromotionKind,
  aggregateId: string,
  expectedRevision: Counter,
  evidence: readonly VerifiedAuthorityEvidenceRecord[],
): readonly VerifiedAuthorityEvidenceRecord[] {
  const expectedTypes = AUTHORITY_TYPES_BY_KIND[kind];
  if (!Array.isArray(evidence) || evidence.length !== expectedTypes.length) {
    throw new AccountsError("VALIDATION_FAILED", "Authority evidence cohort is incomplete");
  }
  const sorted = [...evidence].sort((left, right) =>
    left.evidenceType < right.evidenceType ? -1 : left.evidenceType > right.evidenceType ? 1 : 0,
  );
  if (
    sorted.some((record, index) => record.evidenceType !== [...expectedTypes].sort()[index]) ||
    new Set(sorted.map((record) => record.nonce)).size !== sorted.length ||
    new Set(sorted.map((record) => record.evidenceRef)).size !== sorted.length
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Authority evidence cohort is invalid");
  }
  const expectedAggregateKind =
    kind === "account"
      ? "provider_account"
      : kind === "capacity_pool"
        ? "capacity_pool"
        : kind === "entitlement"
          ? "entitlement"
          : "account_lane";
  for (const record of sorted) {
    if (
      record.aggregateKind !== expectedAggregateKind ||
      record.aggregateId !== aggregateId ||
      record.subjectRef !== aggregateId ||
      record.aggregateRevision !== expectedRevision ||
      parseCounter(record.evidenceGeneration, "evidenceGeneration") === "0" ||
      !/^[A-Za-z0-9_-]{22,86}$/.test(record.nonce) ||
      !/^sha256:[0-9a-f]{64}$/.test(record.payloadDigest) ||
      !/^sha256:[0-9a-f]{64}$/.test(record.envelopeDigest) ||
      !TIMESTAMP_PATTERN.test(record.issuedAt) ||
      !TIMESTAMP_PATTERN.test(record.expiresAt) ||
      Date.parse(record.issuedAt) >= Date.parse(record.expiresAt)
    ) {
      throw new AccountsError("VALIDATION_FAILED", "Authority evidence storage fence is invalid");
    }
    const parsed = parseClosedJson(record.envelopeJson);
    if (
      canonicalJson(parsed) !== record.envelopeJson ||
      canonicalSha256(parsed) !== record.envelopeDigest ||
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new AccountsError("VALIDATION_FAILED", "Authority evidence envelope is invalid");
    }
    const envelope = parsed as Record<string, unknown>;
    if (
      envelope.evidence_type !== record.evidenceType ||
      envelope.evidence_ref !== record.evidenceRef ||
      envelope.subject_ref !== record.subjectRef ||
      envelope.aggregate_kind !== record.aggregateKind ||
      envelope.aggregate_id !== record.aggregateId ||
      envelope.aggregate_revision !== record.aggregateRevision ||
      envelope.identity_realm !== record.identityRealm ||
      envelope.issuer_ref !== record.issuerRef ||
      envelope.issuer_class !== record.issuerClass ||
      envelope.issuer_incarnation !== record.issuerIncarnation ||
      envelope.audience !== record.audience ||
      envelope.key_id !== record.keyId ||
      envelope.issued_at !== record.issuedAt ||
      envelope.expires_at !== record.expiresAt ||
      envelope.nonce !== record.nonce ||
      envelope.evidence_generation !== record.evidenceGeneration ||
      envelope.payload_digest !== record.payloadDigest
    ) {
      throw new AccountsError("VALIDATION_FAILED", "Authority evidence metadata changed");
    }
  }
  return Object.freeze(sorted.map((record) => Object.freeze({ ...record })));
}

export function authorityPromotionHash<K extends AuthorityPromotionKind>(
  kind: K,
  record: EntityMap[K],
  expectedRevision: Counter,
  evidence: readonly VerifiedAuthorityEvidenceRecord[],
  context: MutationContext,
): string {
  return canonicalSha256({
    mutation: mutationHash("replace", kind, record, context, expectedRevision),
    evidence: evidence.map((item) => ({
      evidenceType: item.evidenceType,
      evidenceRef: item.evidenceRef,
      nonce: item.nonce,
      evidenceGeneration: item.evidenceGeneration,
      envelopeDigest: item.envelopeDigest,
    })),
  });
}

export function authorityEvidenceInsertHash(
  record: EntityMap["capacity_pool"],
  evidence: VerifiedAuthorityEvidenceRecord,
  context: MutationContext,
): string {
  return canonicalSha256({
    mutation: mutationHash("insert", "capacity_pool", record, context),
    evidence: {
      evidenceType: evidence.evidenceType,
      evidenceRef: evidence.evidenceRef,
      nonce: evidence.nonce,
      evidenceGeneration: evidence.evidenceGeneration,
      envelopeDigest: evidence.envelopeDigest,
    },
  });
}

export function credentialBindingInsertHash(
  record: CredentialBinding,
  handle: CredentialHandleEnvelope,
  context: MutationContext,
): string {
  return canonicalSha256({
    mutationHash: mutationHash("insert", "credential_binding", record, context),
    handleLocatorDigest: canonicalSha256(handle.opaqueHandle),
    issuerRef: handle.issuerRef,
    audience: handle.audience,
    catalogIncarnation: handle.catalogIncarnation,
    backendClass: handle.backendClass,
    signedClaimsDigest: canonicalSha256({
      ownerRef: handle.ownerRef,
      providerAccountId: handle.providerAccountId,
      providerKey: handle.providerKey,
      capacityPoolId: handle.capacityPoolId,
      capacityDomainRef: handle.capacityDomainRef,
      accessMethodId: handle.accessMethodId,
      credentialFamilyId: handle.credentialFamilyId,
      purpose: handle.purpose,
      resolver: handle.resolver,
      policyDigest: handle.policyDigest,
      credentialGeneration: handle.credentialGeneration,
      ...(handle.authCapsuleId === undefined ? {} : { authCapsuleId: handle.authCapsuleId }),
      ...(handle.canonicalNodeId === undefined ? {} : { canonicalNodeId: handle.canonicalNodeId }),
      ...(handle.nodeGeneration === undefined ? {} : { nodeGeneration: handle.nodeGeneration }),
      ...(handle.placementGeneration === undefined
        ? {}
        : { placementGeneration: handle.placementGeneration }),
    }),
    signature: handle.signature,
    issuedAt: handle.issuedAt,
    ...(handle.expiresAt === undefined ? {} : { expiresAt: handle.expiresAt }),
  });
}

export function idempotencyScope(
  operation: "insert" | "replace",
  kind: EntityKind,
  context: MutationContext,
): string {
  return `${context.actorRef}|${operation}|${kind}|${context.idempotencyKey}`;
}

export function assertReplacement<K extends EntityKind>(
  kind: K,
  previous: EntityMap[K],
  next: EntityMap[K],
  expectedRevision: Counter,
): void {
  if (previous.revision !== expectedRevision) {
    throw new AccountsError("STALE_REVISION", "Expected revision does not match current state", {
      details: {
        aggregateKind: kind,
        aggregateId: previous.id,
        expectedRevision,
        actualRevision: previous.revision,
      },
    });
  }
  if (next.id !== previous.id || next.createdAt !== previous.createdAt) {
    throw new AccountsError("VALIDATION_FAILED", "Immutable record identity changed");
  }
  if (Date.parse(next.updatedAt) <= Date.parse(previous.updatedAt)) {
    throw new AccountsError("VALIDATION_FAILED", "Replacement timestamp did not advance", {
      details: { field: "updatedAt" },
    });
  }
  if (next.revision !== incrementCounter(expectedRevision)) {
    throw new AccountsError("STALE_REVISION", "Replacement revision is not the exact successor", {
      details: {
        aggregateKind: kind,
        aggregateId: previous.id,
        expectedRevision: incrementCounter(expectedRevision),
        actualRevision: next.revision,
      },
    });
  }
  assertTransition(kind, previous.status, next.status);
  assertAuthorityProjectionChange(kind, previous, next);
  if (canonicalJson(stableFields(kind, previous)) !== canonicalJson(stableFields(kind, next))) {
    throw new AccountsError("VALIDATION_FAILED", "Immutable aggregate fields changed", {
      details: { aggregateKind: kind, aggregateId: previous.id },
    });
  }
  if (kind === "capacity_pool") {
    const before = previous as EntityMap["capacity_pool"];
    const after = next as EntityMap["capacity_pool"];
    if (
      compareCounters(after.capacityGeneration, before.capacityGeneration) < 0 ||
      compareCounters(after.denyGeneration, before.denyGeneration) < 0
    ) {
      throw new AccountsError("CURRENT_DENY", "Capacity generations cannot move backward");
    }
    if (
      before.denyState === "allowed" &&
      after.denyState === "denied" &&
      compareCounters(after.denyGeneration, before.denyGeneration) <= 0
    ) {
      throw new AccountsError("CURRENT_DENY", "A denial transition must advance deny generation");
    }
  }
}

function assertAuthorityProjectionChange<K extends EntityKind>(
  kind: K,
  previous: EntityMap[K],
  next: EntityMap[K],
): void {
  const allowedInitialPromotion =
    (kind === "account" && previous.status === "pending" && next.status === "active") ||
    (kind === "entitlement" && previous.status === "pending" && next.status === "active") ||
    (kind === "access_method" && previous.status === "draft" && next.status === "ready");
  if (allowedInitialPromotion) return;
  if (
    canonicalJson(authorityProjection(kind, previous)) !==
    canonicalJson(authorityProjection(kind, next))
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Authority-derived projection changed", {
      details: { aggregateKind: kind, aggregateId: previous.id },
    });
  }
}

function authorityProjection<K extends EntityKind>(kind: K, entity: EntityMap[K]): unknown {
  if (kind === "account") {
    const account = entity as EntityMap["account"];
    return {
      ...(account.providerSubjectRef === undefined
        ? {}
        : { providerSubjectRef: account.providerSubjectRef }),
      ...(account.providerSubjectCandidateRef === undefined
        ? {}
        : { providerSubjectCandidateRef: account.providerSubjectCandidateRef }),
      ...(account.ownershipEvidenceRef === undefined
        ? {}
        : { ownershipEvidenceRef: account.ownershipEvidenceRef }),
      ...(account.ownershipEvidenceIssuerRef === undefined
        ? {}
        : { ownershipEvidenceIssuerRef: account.ownershipEvidenceIssuerRef }),
      ...(account.ownershipEvidenceVersion === undefined
        ? {}
        : { ownershipEvidenceVersion: account.ownershipEvidenceVersion }),
      ...(account.ownershipEvidenceDigest === undefined
        ? {}
        : { ownershipEvidenceDigest: account.ownershipEvidenceDigest }),
      ...(account.ownershipEvidenceIssuedAt === undefined
        ? {}
        : { ownershipEvidenceIssuedAt: account.ownershipEvidenceIssuedAt }),
      ...(account.ownershipEvidenceExpiresAt === undefined
        ? {}
        : { ownershipEvidenceExpiresAt: account.ownershipEvidenceExpiresAt }),
      ...(account.ownershipGeneration === undefined
        ? {}
        : { ownershipGeneration: account.ownershipGeneration }),
    };
  }
  if (kind === "entitlement") {
    const entitlement = entity as EntityMap["entitlement"];
    return {
      ...(entitlement.capabilitySet === undefined ? {} : { capabilitySet: entitlement.capabilitySet }),
      ...(entitlement.capabilityEvidenceRef === undefined
        ? {}
        : { capabilityEvidenceRef: entitlement.capabilityEvidenceRef }),
      ...(entitlement.capabilityDigest === undefined
        ? {}
        : { capabilityDigest: entitlement.capabilityDigest }),
      ...(entitlement.capabilityExpiresAt === undefined
        ? {}
        : { capabilityExpiresAt: entitlement.capabilityExpiresAt }),
      ...(entitlement.executionPolicyDecisionRef === undefined
        ? {}
        : { executionPolicyDecisionRef: entitlement.executionPolicyDecisionRef }),
      ...(entitlement.executionPolicyDecisionDigest === undefined
        ? {}
        : { executionPolicyDecisionDigest: entitlement.executionPolicyDecisionDigest }),
      ...(entitlement.executionPolicyDecisionExpiresAt === undefined
        ? {}
        : { executionPolicyDecisionExpiresAt: entitlement.executionPolicyDecisionExpiresAt }),
      ...(entitlement.termsDecision === undefined
        ? {}
        : { termsDecision: entitlement.termsDecision }),
      ...(entitlement.dataPolicy === undefined ? {} : { dataPolicy: entitlement.dataPolicy }),
      ...(entitlement.dataPolicyEvidenceRef === undefined
        ? {}
        : { dataPolicyEvidenceRef: entitlement.dataPolicyEvidenceRef }),
      ...(entitlement.dataPolicyDigest === undefined
        ? {}
        : { dataPolicyDigest: entitlement.dataPolicyDigest }),
      ...(entitlement.dataPolicyExpiresAt === undefined
        ? {}
        : { dataPolicyExpiresAt: entitlement.dataPolicyExpiresAt }),
      ...(entitlement.lastVerifiedAt === undefined
        ? {}
        : { lastVerifiedAt: entitlement.lastVerifiedAt }),
    };
  }
  if (kind === "access_method") {
    const method = entity as EntityMap["access_method"];
    return {
      ...(method.requiredIsolationPolicyRef === undefined
        ? {}
        : { requiredIsolationPolicyRef: method.requiredIsolationPolicyRef }),
      ...(method.requiredIsolationPolicyDigest === undefined
        ? {}
        : { requiredIsolationPolicyDigest: method.requiredIsolationPolicyDigest }),
      ...(method.isolationEvidenceExpiresAt === undefined
        ? {}
        : { isolationEvidenceExpiresAt: method.isolationEvidenceExpiresAt }),
      ...(method.allowedDestinationPolicyClasses === undefined
        ? {}
        : { allowedDestinationPolicyClasses: method.allowedDestinationPolicyClasses }),
      ...(method.parentPolicyDecisionRef === undefined
        ? {}
        : { parentPolicyDecisionRef: method.parentPolicyDecisionRef }),
      ...(method.parentPolicyDecisionDigest === undefined
        ? {}
        : { parentPolicyDecisionDigest: method.parentPolicyDecisionDigest }),
      ...(method.executionPolicyEvidenceRef === undefined
        ? {}
        : { executionPolicyEvidenceRef: method.executionPolicyEvidenceRef }),
      ...(method.executionPolicyDigest === undefined
        ? {}
        : { executionPolicyDigest: method.executionPolicyDigest }),
      ...(method.executionPolicyExpiresAt === undefined
        ? {}
        : { executionPolicyExpiresAt: method.executionPolicyExpiresAt }),
      ...(method.health === undefined ? {} : { health: method.health }),
    };
  }
  return {};
}

function stableFields<K extends EntityKind>(kind: K, entity: EntityMap[K]): unknown {
  const common = entity as EntityMap[EntityKind];
  const { status: _status, revision: _revision, updatedAt: _updatedAt, ...base } = common;
  if (kind === "credential_binding") {
    const {
      terminalKind: _terminalKind,
      credentialHandleAuditDigest: _credentialHandleAuditDigest,
      lastUsableCredentialGeneration: _lastUsableCredentialGeneration,
      revocationBarrierReceiptDigest: _revocationBarrierReceiptDigest,
      revokedAt: _revokedAt,
      ...stable
    } = base as Omit<EntityMap["credential_binding"], "status" | "revision" | "updatedAt"> & {
      terminalKind?: unknown;
      credentialHandleAuditDigest?: unknown;
      lastUsableCredentialGeneration?: unknown;
      revocationBarrierReceiptDigest?: unknown;
      revokedAt?: unknown;
    };
    return stable;
  }
  if (kind === "account") {
    const {
      providerSubjectRef: _providerSubjectRef,
      providerSubjectCandidateRef: _providerSubjectCandidateRef,
      ownershipEvidenceRef: _ownershipEvidenceRef,
      ownershipEvidenceIssuerRef: _ownershipEvidenceIssuerRef,
      ownershipEvidenceVersion: _ownershipEvidenceVersion,
      ownershipEvidenceDigest: _ownershipEvidenceDigest,
      ownershipEvidenceIssuedAt: _ownershipEvidenceIssuedAt,
      ownershipEvidenceExpiresAt: _ownershipEvidenceExpiresAt,
      ownershipGeneration: _ownershipGeneration,
      ...stable
    } = base as Omit<EntityMap["account"], "status" | "revision" | "updatedAt">;
    return stable;
  }
  if (kind === "entitlement") {
    const {
      capabilitySet: _capabilitySet,
      capabilityEvidenceRef: _capabilityEvidenceRef,
      capabilityDigest: _capabilityDigest,
      capabilityExpiresAt: _capabilityExpiresAt,
      executionPolicyDecisionRef: _executionPolicyDecisionRef,
      executionPolicyDecisionDigest: _executionPolicyDecisionDigest,
      executionPolicyDecisionExpiresAt: _executionPolicyDecisionExpiresAt,
      termsDecision: _termsDecision,
      dataPolicy: _dataPolicy,
      dataPolicyEvidenceRef: _dataPolicyEvidenceRef,
      dataPolicyDigest: _dataPolicyDigest,
      dataPolicyExpiresAt: _dataPolicyExpiresAt,
      lastVerifiedAt: _lastVerifiedAt,
      ...stable
    } = base as Omit<EntityMap["entitlement"], "status" | "revision" | "updatedAt">;
    return stable;
  }
  if (kind === "access_method") {
    const {
      requiredIsolationPolicyRef: _requiredIsolationPolicyRef,
      requiredIsolationPolicyDigest: _requiredIsolationPolicyDigest,
      isolationEvidenceExpiresAt: _isolationEvidenceExpiresAt,
      allowedDestinationPolicyClasses: _allowedDestinationPolicyClasses,
      parentPolicyDecisionRef: _parentPolicyDecisionRef,
      parentPolicyDecisionDigest: _parentPolicyDecisionDigest,
      executionPolicyEvidenceRef: _executionPolicyEvidenceRef,
      executionPolicyDigest: _executionPolicyDigest,
      executionPolicyExpiresAt: _executionPolicyExpiresAt,
      health: _health,
      ...stable
    } = base as Omit<EntityMap["access_method"], "status" | "revision" | "updatedAt">;
    return stable;
  }
  if (kind !== "capacity_pool") return base;
  const {
    capacityGeneration: _capacityGeneration,
    denyGeneration: _denyGeneration,
    denyState: _denyState,
    ...stable
  } = base as Omit<EntityMap["capacity_pool"], "status" | "revision" | "updatedAt">;
  return stable;
}
