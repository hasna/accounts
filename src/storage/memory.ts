import { AccountsError } from "../errors";
import { newAccountEventId, newOutboxId } from "../domain/ids";
import type { CredentialBinding, CredentialOperation, EntityKind, EntityMap } from "../domain/models";
import type {
  AccountEvent,
  AccountsRepository,
  MutationContext,
  MutationResult,
  RepositoryDoctor,
  EligibilitySnapshot,
  CredentialHandleEnvelope,
  CredentialHandleVerifier,
  CredentialResolutionGrant,
  CredentialResolutionTransport,
  CredentialUseAuthorizer,
  NativeRevocationRequest,
  NativeRevocationResult,
  OutboxRecord,
  OutboxAcknowledgeRequest,
  OutboxClaimRequest,
  RecoveryFrontier,
  RecoveryLedger,
  RecoveryLedgerReceipt,
  RecoverySnapshot,
  ResolvedCredentialHandle,
  AuthorityPromotionKind,
  VerifiedAuthorityEvidenceRecord,
} from "./repository";
import {
  assertReplacement,
  cloneEntity,
  idempotencyScope,
  mutationHash,
  credentialBindingInsertHash,
  buildCredentialHandleExpectedClaims,
  validateCredentialHandleEnvelope,
  validateMutationContext,
  validateOutboxAcknowledgeRequest,
  validateOutboxClaimRequest,
  authorityPromotionHash,
  isAuthorityPromotion,
  validateVerifiedAuthorityEvidence,
  authorityEvidenceInsertHash,
} from "./shared";
import { incrementCounter, parseCounter, type Counter } from "../domain/counter";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import { deriveNativeRevocation } from "./native-revocation";
import { REJECTING_CREDENTIAL_HANDLE_VERIFIER } from "./credential-verifier";
import { UNAVAILABLE_RECOVERY_LEDGER } from "./recovery";
import { REJECTING_CREDENTIAL_USE_AUTHORIZER } from "./credential-use-authorizer";

interface IdempotencyEntry {
  readonly hash: string;
  readonly kind: EntityKind;
  readonly aggregateId: string;
  readonly eventId: AccountEvent["id"];
  readonly response: string;
}

interface NativeRevocationReplay {
  readonly hash: string;
  readonly result: NativeRevocationResult;
}

interface StoredCredentialHandle {
  readonly envelope: CredentialHandleEnvelope;
  readonly credentialHandleAuditDigest: string;
}

export class InMemoryAccountsRepository implements AccountsRepository {
  private readonly records: {
    [K in EntityKind]: Map<string, EntityMap[K]>;
  } = {
    account: new Map(),
    entitlement: new Map(),
    capacity_pool: new Map(),
    access_method: new Map(),
    auth_capsule: new Map(),
    credential_binding: new Map(),
  };

  private readonly eventLog: AccountEvent[] = [];
  private readonly idempotency = new Map<string, IdempotencyEntry>();
  private readonly handles = new Map<string, StoredCredentialHandle>();
  private readonly operationLog = new Map<string, CredentialOperation>();
  private readonly outboxLog: OutboxRecord[] = [];
  private readonly nativeRevocationReplays = new Map<string, NativeRevocationReplay>();
  private readonly authorityEvidenceByNonce = new Map<string, VerifiedAuthorityEvidenceRecord>();
  private databaseFrontier?: RecoveryFrontier;
  private recoveryHold = true;
  private closed = false;

  constructor(
    private readonly credentialVerifier: CredentialHandleVerifier =
      REJECTING_CREDENTIAL_HANDLE_VERIFIER,
    private readonly recoveryLedger: RecoveryLedger = UNAVAILABLE_RECOVERY_LEDGER,
    private readonly credentialUseAuthorizer: CredentialUseAuthorizer =
      REJECTING_CREDENTIAL_USE_AUTHORIZER,
  ) {
    try {
      const frontier = recoveryLedger.readFreshFrontier();
      if (recoveryLedger.verifyFrontier(frontier)) {
        this.databaseFrontier = { ...frontier };
        this.recoveryHold = false;
      }
    } catch {
      this.recoveryHold = true;
    }
  }

  async get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined> {
    this.assertOpen();
    const record = this.records[kind].get(id) as EntityMap[K] | undefined;
    return record === undefined ? undefined : cloneEntity(kind, record);
  }

  async list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    this.assertOpen();
    return [...this.records[kind].values()]
      .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
      .map((record) => cloneEntity(kind, record as EntityMap[K]));
  }

  async readEligibilitySnapshot(
    accessMethodId: EntityMap["access_method"]["id"],
  ): Promise<EligibilitySnapshot> {
    this.assertOpen();
    const method = this.records.access_method.get(accessMethodId);
    const entitlement =
      method === undefined ? undefined : this.records.entitlement.get(method.entitlementId);
    const account =
      entitlement === undefined ? undefined : this.records.account.get(entitlement.accountId);
    const pool = method === undefined ? undefined : this.records.capacity_pool.get(method.capacityPoolId);
    return {
      ...(method === undefined ? {} : { method: cloneEntity("access_method", method) }),
      ...(entitlement === undefined
        ? {}
        : { entitlement: cloneEntity("entitlement", entitlement) }),
      ...(account === undefined ? {} : { account: cloneEntity("account", account) }),
      ...(pool === undefined ? {} : { pool: cloneEntity("capacity_pool", pool) }),
      capsules: [...this.records.auth_capsule.values()]
        .filter((candidate) => candidate.accessMethodId === accessMethodId)
        .map((candidate) => cloneEntity("auth_capsule", candidate)),
      bindings: [...this.records.credential_binding.values()]
        .filter((candidate) => candidate.accessMethodId === accessMethodId)
        .map((candidate) => cloneEntity("credential_binding", candidate)),
      recovery: this.readRecoverySnapshot(),
    };
  }

  async insert<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    if (kind === "credential_binding") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Credential bindings require an atomic issuer handle ingestion",
      );
    }
    if (kind === "capacity_pool") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Capacity pools require atomic provider-capacity evidence ingestion",
      );
    }
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    const scope = idempotencyScope("insert", kind, context);
    const hash = mutationHash("insert", kind, record, context);
    const replay = this.replay(kind, scope, hash);
    if (replay !== undefined) return replay as MutationResult<EntityMap[K]>;
    if (this.records[kind].has(record.id)) {
      throw new AccountsError("CONFLICT", "Record already exists", {
        details: { aggregateKind: kind, aggregateId: record.id },
      });
    }
    this.assertUniqueness(kind, record);
    const recovery = this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
    const event = this.makeEvent(kind, record, context);
    this.records[kind].set(record.id, record);
    this.eventLog.push(event);
    this.appendAggregateOutbox(kind, record, event);
    this.idempotency.set(scope, {
      hash,
      kind,
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope(kind, record),
    });
    this.commitRecovery(recovery);
    return { record: cloneEntity(kind, record), eventId: event.id, replayed: false };
  }

  async insertCapacityPoolWithAuthorityEvidence(
    input: EntityMap["capacity_pool"],
    inputEvidence: VerifiedAuthorityEvidenceRecord,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["capacity_pool"]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity("capacity_pool", input);
    if (record.status !== "pending" || record.revision !== "0") {
      throw new AccountsError("INVALID_TRANSITION", "Capacity pool evidence must create pending revision zero");
    }
    const [evidence] = validateVerifiedAuthorityEvidence(
      "capacity_pool",
      record.id,
      record.revision,
      [inputEvidence],
    );
    if (evidence === undefined) {
      throw new AccountsError("VALIDATION_FAILED", "Capacity evidence is missing");
    }
    const scope = idempotencyScope("insert", "capacity_pool", context);
    const hash = authorityEvidenceInsertHash(record, evidence, context);
    const replay = this.replay("capacity_pool", scope, hash);
    if (replay !== undefined) return replay;
    if (this.records.capacity_pool.has(record.id)) {
      throw new AccountsError("CONFLICT", "Record already exists", {
        details: { aggregateKind: "capacity_pool", aggregateId: record.id },
      });
    }
    if (
      this.authorityEvidenceByNonce.has(evidence.nonce) ||
      [...this.authorityEvidenceByNonce.values()].some(
        (stored) =>
          stored.evidenceRef === evidence.evidenceRef ||
          stored.envelopeDigest === evidence.envelopeDigest,
      )
    ) {
      throw new AccountsError("CONFLICT", "Authority evidence was already consumed");
    }
    this.assertUniqueness("capacity_pool", record);
    const recovery = this.appendRecovery(
      "catalog_mutation",
      "capacity_pool",
      record.id,
      hash,
      record.updatedAt,
    );
    const event = this.makeEvent("capacity_pool", record, context);
    this.records.capacity_pool.set(record.id, record);
    this.authorityEvidenceByNonce.set(evidence.nonce, evidence);
    this.eventLog.push(event);
    this.appendAggregateOutbox("capacity_pool", record, event);
    this.idempotency.set(scope, {
      hash,
      kind: "capacity_pool",
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope("capacity_pool", record),
    });
    this.commitRecovery(recovery);
    return { record: cloneEntity("capacity_pool", record), eventId: event.id, replayed: false };
  }

  async insertCredentialBinding(
    input: CredentialBinding,
    inputHandle: CredentialHandleEnvelope,
    context: MutationContext,
  ): Promise<MutationResult<CredentialBinding>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity("credential_binding", input);
    const handle = Object.freeze({ ...inputHandle });
    validateCredentialHandleEnvelope(record, handle);
    if (this.databaseFrontier === undefined) {
      throw new AccountsError("RECOVERY_HOLD", "Credential ingestion requires a recovery frontier");
    }
    const expectedClaims = await buildCredentialHandleExpectedClaims(this, record, {
      audience: "accounts-local",
      catalogIncarnation: this.databaseFrontier.catalogIncarnation,
      backendClass:
        record.resolver === "capsule_local_native"
          ? "capsule_protected_state"
          : record.resolver === "brokered_secret"
            ? "secrets_broker"
            : "workload_identity_broker",
    });
    const verification = this.credentialVerifier.verify(handle, expectedClaims);
    const scope = idempotencyScope("insert", "credential_binding", context);
    const hash = credentialBindingInsertHash(record, handle, context);
    const replay = this.replay("credential_binding", scope, hash);
    if (replay !== undefined) return replay;
    if (this.records.credential_binding.has(record.id) || this.handles.has(record.id)) {
      throw new AccountsError("CONFLICT", "Credential binding already exists", {
        details: { aggregateKind: "credential_binding", aggregateId: record.id },
      });
    }
    this.assertUniqueness("credential_binding", record);
    const recovery = this.appendRecovery(
      "catalog_mutation",
      "credential_binding",
      record.id,
      hash,
      record.updatedAt,
    );
    const event = this.makeEvent("credential_binding", record, context);
    this.records.credential_binding.set(record.id, record);
    this.handles.set(record.id, { envelope: handle, ...verification });
    this.eventLog.push(event);
    this.appendAggregateOutbox("credential_binding", record, event);
    this.idempotency.set(scope, {
      hash,
      kind: "credential_binding",
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope("credential_binding", record),
    });
    this.commitRecovery(recovery);
    return { record: cloneEntity("credential_binding", record), eventId: event.id, replayed: false };
  }

  async resolveCredentialHandle(
    bindingId: CredentialBinding["id"],
    grant: CredentialResolutionGrant,
    transport: CredentialResolutionTransport,
  ): Promise<ResolvedCredentialHandle> {
    this.assertOpen();
    const binding = this.records.credential_binding.get(bindingId);
    const handle = this.handles.get(bindingId);
    const method = binding === undefined ? undefined : this.records.access_method.get(binding.accessMethodId);
    const pool = binding === undefined ? undefined : this.records.capacity_pool.get(binding.capacityPoolId);
    const account = pool === undefined ? undefined : this.records.account.get(pool.accountId);
    const recovery = this.readRecoverySnapshot();
    if (
      binding === undefined ||
      handle === undefined ||
      method === undefined ||
      pool === undefined ||
      account === undefined ||
      !recovery.matched ||
      recovery.hold ||
      recovery.frontier === undefined ||
      binding.status !== "active" ||
      pool.status !== "active" ||
      pool.denyState !== "allowed" ||
      method.status !== "ready" ||
      handle.envelope.catalogIncarnation !== recovery.frontier.catalogIncarnation ||
      (binding.expiresAt !== undefined && Date.parse(binding.expiresAt) <= Date.parse(transport.now)) ||
      (handle.envelope.expiresAt !== undefined &&
        Date.parse(handle.envelope.expiresAt) <= Date.parse(transport.now))
    ) {
      throw new AccountsError("POLICY_DENIED", "Credential handle scope is not authorized");
    }
    this.credentialUseAuthorizer.verify(
      grant,
      {
        providerAccountId: account.id,
        ownerRef: account.ownerRef,
        accessMethodId: method.id,
        capacityPoolId: pool.id,
        bindingId: binding.id,
        credentialFamilyId: binding.credentialFamilyId,
        credentialGeneration: binding.credentialGeneration,
        purpose: binding.purpose,
        resolver: binding.resolver,
        catalogIncarnation: recovery.frontier.catalogIncarnation,
        recoveryFrontierSequence: recovery.frontier.sequence,
        recoveryFrontierHash: recovery.frontier.hash,
      },
      transport,
    );
    return {
      bindingId,
      opaqueHandle: handle.envelope.opaqueHandle,
      issuerRef: handle.envelope.issuerRef,
      audience: handle.envelope.audience,
      backendClass: handle.envelope.backendClass,
      ...(handle.envelope.expiresAt === undefined
        ? {}
        : { expiresAt: handle.envelope.expiresAt }),
    };
  }

  async replace<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    if (kind === "credential_binding" && record.status === "revoked") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Credential revocation requires an atomic terminal-handle barrier",
      );
    }
    const scope = idempotencyScope("replace", kind, context);
    const hash = mutationHash("replace", kind, record, context, expectedRevision);
    const replay = this.replay(kind, scope, hash);
    if (replay !== undefined) return replay as MutationResult<EntityMap[K]>;
    const previous = this.records[kind].get(record.id) as EntityMap[K] | undefined;
    if (previous === undefined) {
      throw new AccountsError("NOT_FOUND", "Record not found", {
        details: { aggregateKind: kind, aggregateId: record.id },
      });
    }
    if (isAuthorityPromotion(kind, previous, record)) {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Authority promotion requires an atomic verified evidence cohort",
      );
    }
    assertReplacement(kind, previous, record, expectedRevision);
    this.assertUniqueness(kind, record);
    const recovery = this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
    const event = this.makeEvent(kind, record, context);
    this.records[kind].set(record.id, record);
    this.eventLog.push(event);
    this.appendAggregateOutbox(kind, record, event);
    this.idempotency.set(scope, {
      hash,
      kind,
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope(kind, record),
    });
    this.commitRecovery(recovery);
    return { record: cloneEntity(kind, record), eventId: event.id, replayed: false };
  }

  async promoteWithAuthorityEvidence<K extends AuthorityPromotionKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    inputEvidence: readonly VerifiedAuthorityEvidenceRecord[],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    const evidence = validateVerifiedAuthorityEvidence(
      kind,
      record.id,
      expectedRevision,
      inputEvidence,
    );
    const scope = idempotencyScope("replace", kind, context);
    const hash = authorityPromotionHash(kind, record, expectedRevision, evidence, context);
    const replay = this.replay(kind, scope, hash);
    if (replay !== undefined) return replay as MutationResult<EntityMap[K]>;
    const previous = this.records[kind].get(record.id) as EntityMap[K] | undefined;
    if (previous === undefined) {
      throw new AccountsError("NOT_FOUND", "Record not found", {
        details: { aggregateKind: kind, aggregateId: record.id },
      });
    }
    assertReplacement(kind, previous, record, expectedRevision);
    if (!isAuthorityPromotion(kind, previous, record)) {
      throw new AccountsError("INVALID_TRANSITION", "Authority promotion edge is invalid");
    }
    for (const item of evidence) {
      if (
        this.authorityEvidenceByNonce.has(item.nonce) ||
        [...this.authorityEvidenceByNonce.values()].some(
          (stored) =>
            stored.evidenceRef === item.evidenceRef ||
            stored.envelopeDigest === item.envelopeDigest,
        )
      ) {
        throw new AccountsError("CONFLICT", "Authority evidence was already consumed");
      }
    }
    this.assertUniqueness(kind, record);
    const recovery = this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
    const event = this.makeEvent(kind, record, context);
    this.records[kind].set(record.id, record);
    for (const item of evidence) this.authorityEvidenceByNonce.set(item.nonce, item);
    this.eventLog.push(event);
    this.appendAggregateOutbox(kind, record, event);
    this.idempotency.set(scope, {
      hash,
      kind,
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope(kind, record),
    });
    this.commitRecovery(recovery);
    return { record: cloneEntity(kind, record), eventId: event.id, replayed: false };
  }

  async revokeNativeGeneration(request: NativeRevocationRequest): Promise<NativeRevocationResult> {
    this.assertOpen();
    validateMutationContext(request.context);
    const scope = `${request.context.actorRef}|native_revoke|${request.context.idempotencyKey}`;
    const hash = canonicalSha256({
      capsuleId: request.capsuleId,
      bindingId: request.bindingId,
      barrierBindingId: request.barrierBindingId,
      operationId: request.operationId,
      expectedPoolRevision: request.expectedPoolRevision,
      expectedMethodRevision: request.expectedMethodRevision,
      expectedCapsuleRevision: request.expectedCapsuleRevision,
      expectedBindingRevision: request.expectedBindingRevision,
      occurredAt: request.occurredAt,
      reasonCode: request.context.reasonCode,
    });
    const replay = this.nativeRevocationReplays.get(scope);
    if (replay !== undefined) {
      if (replay.hash !== hash) {
        throw new AccountsError("IDEMPOTENCY_CONFLICT", "Native revocation request changed");
      }
      return cloneNativeRevocationResult({ ...replay.result, replayed: true });
    }
    if (
      this.records.credential_binding.has(request.barrierBindingId) ||
      this.operationLog.has(request.operationId)
    ) {
      throw new AccountsError("CONFLICT", "Native revocation identifiers already exist");
    }
    const capsule = this.records.auth_capsule.get(request.capsuleId);
    const binding = this.records.credential_binding.get(request.bindingId);
    const handle = this.handles.get(request.bindingId);
    const method = capsule === undefined ? undefined : this.records.access_method.get(capsule.accessMethodId);
    const pool = capsule === undefined ? undefined : this.records.capacity_pool.get(capsule.capacityPoolId);
    if (capsule === undefined || binding === undefined || handle === undefined || method === undefined || pool === undefined) {
      throw new AccountsError("NOT_FOUND", "Native revocation source was not found");
    }
    const source =
      {
        pool,
        method,
        capsule,
        binding,
        credentialHandleAuditDigest: handle.credentialHandleAuditDigest,
      };
    const preview = deriveNativeRevocation(
      source,
      request,
      `sha256:${"0".repeat(64)}`,
    );
    this.assertUniqueness("credential_binding", preview.barrierBinding);
    const recovery = this.appendRecovery(
      "native_revocation_barrier",
      "credential_operation",
      request.operationId,
      hash,
      request.occurredAt,
    );
    const derived = deriveNativeRevocation(source, request, recovery.receiptDigest);
    this.records.capacity_pool.set(pool.id, derived.pool);
    this.records.access_method.set(method.id, derived.method);
    this.records.auth_capsule.set(capsule.id, derived.capsule);
    this.records.credential_binding.set(binding.id, derived.retiredBinding);
    this.records.credential_binding.set(derived.barrierBinding.id, derived.barrierBinding);
    this.handles.delete(binding.id);
    this.operationLog.set(derived.operation.id, derived.operation);
    for (const [kind, record] of [
      ["capacity_pool", derived.pool],
      ["access_method", derived.method],
      ["auth_capsule", derived.capsule],
      ["credential_binding", derived.retiredBinding],
      ["credential_binding", derived.barrierBinding],
    ] as const) {
      const event = this.makeEvent(kind, record as EntityMap[typeof kind], request.context);
      this.eventLog.push(event);
      this.appendAggregateOutbox(kind, record as EntityMap[typeof kind], event);
    }
    this.appendCleanupOutbox(derived.operation);
    const result = cloneNativeRevocationResult({ ...derived, replayed: false });
    this.nativeRevocationReplays.set(scope, { hash, result });
    this.commitRecovery(recovery);
    return result;
  }

  async credentialOperations(): Promise<readonly CredentialOperation[]> {
    this.assertOpen();
    return [...this.operationLog.values()]
      .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
      .map((operation) => ({ ...operation }));
  }

  async outbox(): Promise<readonly OutboxRecord[]> {
    this.assertOpen();
    return this.outboxLog.map((record) => ({ ...record }));
  }

  async claimOutbox(request: OutboxClaimRequest): Promise<readonly OutboxRecord[]> {
    this.assertOpen();
    validateOutboxClaimRequest(request);
    const now = Date.parse(request.now);
    const candidates = this.outboxLog
      .filter(
        (record) =>
          record.status === "pending" ||
          (record.status === "in_flight" &&
            record.claimExpiresAt !== undefined &&
            Date.parse(record.claimExpiresAt) <= now),
      )
      .sort((left, right) =>
        left.createdAt === right.createdAt
          ? left.id < right.id
            ? -1
            : left.id > right.id
              ? 1
              : 0
          : left.createdAt < right.createdAt
            ? -1
            : 1,
      )
      .slice(0, request.limit);
    return candidates.map((candidate) => {
      const claimed: OutboxRecord = {
        ...candidate,
        status: "in_flight",
        attemptCount: incrementCounter(candidate.attemptCount),
        claimOwnerRef: request.workerRef,
        claimExpiresAt: request.claimExpiresAt,
      };
      const index = this.outboxLog.findIndex((record) => record.id === candidate.id);
      this.outboxLog[index] = claimed;
      return { ...claimed };
    });
  }

  async acknowledgeOutbox(request: OutboxAcknowledgeRequest): Promise<OutboxRecord> {
    this.assertOpen();
    validateOutboxAcknowledgeRequest(request);
    const index = this.outboxLog.findIndex((record) => record.id === request.outboxId);
    const current = this.outboxLog[index];
    if (
      current === undefined ||
      current.status !== "in_flight" ||
      current.claimOwnerRef !== request.workerRef ||
      current.attemptCount !== request.expectedAttemptCount ||
      current.claimExpiresAt === undefined ||
      Date.parse(current.claimExpiresAt) <= Date.parse(request.now)
    ) {
      throw new AccountsError("CONFLICT", "Outbox claim is stale");
    }
    const next: OutboxRecord =
      request.outcome === "retry"
        ? {
            ...current,
            status: "pending",
            attemptCount: current.attemptCount,
            createdAt: current.createdAt,
          }
        : {
            ...current,
            status: request.outcome,
            attemptCount: current.attemptCount,
            createdAt: current.createdAt,
          };
    const {
      claimOwnerRef: _claimOwnerRef,
      claimExpiresAt: _claimExpiresAt,
      ...withoutClaim
    } = next;
    this.outboxLog[index] = withoutClaim;
    return { ...withoutClaim };
  }

  async events(): Promise<readonly AccountEvent[]> {
    this.assertOpen();
    return this.eventLog.map((event) => ({ ...event }));
  }

  async findReplacementReplay<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]> | undefined> {
    this.assertOpen();
    validateMutationContext(context);
    const scope = idempotencyScope("replace", kind, context);
    const entry = this.idempotency.get(scope);
    if (entry === undefined) return undefined;
    const envelope = deserializeRecordEnvelope(entry.response);
    if (envelope.kind !== kind) throw new AccountsError("IDEMPOTENCY_CONFLICT", "Stored replay kind changed");
    const record = envelope.data as EntityMap[K];
    const expectedHash = mutationHash("replace", kind, record, context, expectedRevision);
    if (
      entry.hash !== expectedHash ||
      record.id !== id ||
      record.status !== to ||
      record.revision !== incrementCounter(expectedRevision)
    ) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotent transition input changed");
    }
    return { record, eventId: entry.eventId, replayed: true };
  }

  async doctor(): Promise<RepositoryDoctor> {
    this.assertOpen();
    const recovery = this.readRecoverySnapshot();
    return {
      adapter: "memory",
      schemaVersion: "1",
      migrationChecksum: "memory-reference-v1",
      foreignKeys: "not_applicable",
      journalMode: "memory",
      integrity: "ok",
      readiness: recovery.matched && !recovery.hold ? "ready" : "recovery_hold",
      recoveryFrontier: recovery.frontier ?? "unavailable",
      recoveryHold: recovery.hold,
      positiveEligibility: recovery.matched && !recovery.hold,
    };
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  private readRecoverySnapshot(): RecoverySnapshot {
    if (this.recoveryHold || this.databaseFrontier === undefined) {
      return { matched: false, hold: true };
    }
    try {
      const frontier = this.recoveryLedger.readFreshFrontier();
      const matched =
        this.recoveryLedger.verifyFrontier(frontier) &&
        frontier.catalogIncarnation === this.databaseFrontier.catalogIncarnation &&
        frontier.sequence === this.databaseFrontier.sequence &&
        frontier.hash === this.databaseFrontier.hash &&
        frontier.signatureDigest === this.databaseFrontier.signatureDigest;
      if (!matched) this.recoveryHold = true;
      return {
        matched,
        hold: this.recoveryHold,
        ...(matched ? { frontier: { ...frontier } } : {}),
      };
    } catch {
      this.recoveryHold = true;
      return { matched: false, hold: true };
    }
  }

  private appendRecovery(
    kind: "catalog_mutation" | "native_revocation_barrier",
    aggregateKind: EntityKind | "credential_operation",
    aggregateId: string,
    mutationDigest: string,
    occurredAt: string,
  ): RecoveryLedgerReceipt {
    const snapshot = this.readRecoverySnapshot();
    if (!snapshot.matched || snapshot.hold || snapshot.frontier === undefined) {
      throw new AccountsError("RECOVERY_HOLD", "Recovery frontier is not writable");
    }
    try {
      return this.recoveryLedger.append(snapshot.frontier, {
        kind,
        aggregateKind,
        aggregateId,
        mutationDigest,
        occurredAt,
      });
    } catch (error) {
      this.recoveryHold = true;
      throw error instanceof AccountsError
        ? error
        : new AccountsError("RECOVERY_HOLD", "Recovery append failed");
    }
  }

  private commitRecovery(receipt: RecoveryLedgerReceipt): void {
    this.databaseFrontier = {
      catalogIncarnation: receipt.catalogIncarnation,
      sequence: receipt.sequence,
      hash: receipt.hash,
      signatureDigest: receipt.signatureDigest,
    };
  }

  private replay<K extends EntityKind>(
    requestedKind: K,
    scope: string,
    hash: string,
  ): MutationResult<EntityMap[K]> | undefined {
    const entry = this.idempotency.get(scope);
    if (entry === undefined) return undefined;
    if (entry.hash !== hash) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused for different input");
    }
    if (entry.kind !== requestedKind) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency scope changed");
    }
    const envelope = deserializeRecordEnvelope(entry.response);
    if (envelope.kind !== requestedKind) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Idempotency result kind is invalid");
    }
    const record = envelope.data as EntityMap[K];
    return { record: cloneEntity(requestedKind, record), eventId: entry.eventId, replayed: true };
  }

  private makeEvent<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): AccountEvent {
    return {
      id: newAccountEventId(Date.parse(record.updatedAt)),
      aggregateKind: kind,
      aggregateId: record.id,
      aggregateRevision: record.revision,
      actorRef: context.actorRef,
      reasonCode: context.reasonCode,
      occurredAt: record.updatedAt,
    };
  }

  private appendAggregateOutbox<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    event: AccountEvent,
  ): void {
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      aggregateKind: kind,
      aggregateId: record.id,
      aggregateRevision: record.revision,
      eventId: event.id,
    });
    this.outboxLog.push({
      id: newOutboxId(Date.parse(record.updatedAt)),
      topic: "accounts.aggregate.changed",
      aggregateKind: kind,
      aggregateId: record.id,
      eventId: event.id,
      payloadDigest: canonicalSha256(payloadJson),
      payloadJson,
      status: "pending",
      attemptCount: parseCounter("0"),
      createdAt: record.updatedAt,
    });
  }

  private appendCleanupOutbox(operation: CredentialOperation): void {
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      operationId: operation.id,
      sourceBindingId: operation.sourceBindingId,
      barrierBindingId: operation.targetBindingId,
      barrierReceiptDigest: operation.barrierReceiptDigest,
    });
    this.outboxLog.push({
      id: newOutboxId(Date.parse(operation.updatedAt)),
      topic: "accounts.capsule.cleanup.requested",
      aggregateKind: "credential_operation",
      aggregateId: operation.id,
      payloadDigest: canonicalSha256(payloadJson),
      payloadJson,
      status: "pending",
      attemptCount: parseCounter("0"),
      createdAt: operation.updatedAt,
    });
  }

  private assertUniqueness<K extends EntityKind>(kind: K, record: EntityMap[K]): void {
    if (kind === "account") {
      const item = record as EntityMap["account"];
      if (
        item.status !== "pending" &&
        item.providerSubjectRef !== undefined &&
        [...this.records.account.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.status !== "pending" &&
            candidate.providerKey === item.providerKey &&
            candidate.providerSubjectRef === item.providerSubjectRef,
        )
      ) {
        throw new AccountsError("CONFLICT", "Provider subject is permanently claimed");
      }
    } else if (kind === "capacity_pool") {
      const item = record as EntityMap["capacity_pool"];
      const account = this.records.account.get(item.accountId);
      if (
        [...this.records.capacity_pool.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            (candidate.serializationKey === item.serializationKey ||
              (candidate.capacityDomainRef === item.capacityDomainRef &&
                this.records.account.get(candidate.accountId)?.providerKey === account?.providerKey)),
        )
      ) {
        throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Capacity domain is already claimed");
      }
    } else if (kind === "auth_capsule") {
      const item = record as EntityMap["auth_capsule"];
      if (
        item.status !== "revoked" &&
        [...this.records.auth_capsule.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.status !== "revoked" &&
            candidate.capacityPoolId === item.capacityPoolId,
        )
      ) {
        throw new AccountsError("CONFLICT", "A live capsule already exists for this capacity pool");
      }
    } else if (kind === "credential_binding") {
      const item = record as EntityMap["credential_binding"];
      if (
        [...this.records.credential_binding.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.credentialFamilyId === item.credentialFamilyId &&
            (candidate.credentialGeneration === item.credentialGeneration ||
              candidate.capacityPoolId !== item.capacityPoolId ||
              candidate.purpose !== item.purpose ||
              candidate.resolver !== item.resolver),
        )
      ) {
        throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Credential family lineage already exists");
      }
      if (
        item.resolver === "capsule_local_native" &&
        item.status === "active" &&
        [...this.records.credential_binding.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.resolver === "capsule_local_native" &&
            candidate.status === "active" &&
            candidate.capacityPoolId === item.capacityPoolId &&
            candidate.purpose === item.purpose,
        )
      ) {
        throw new AccountsError("CONFLICT", "An active native binding already exists");
      }
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Repository is closed", {
        details: { adapter: "memory" },
      });
    }
  }
}

function cloneNativeRevocationResult(result: NativeRevocationResult): NativeRevocationResult {
  return {
    pool: cloneEntity("capacity_pool", result.pool),
    method: cloneEntity("access_method", result.method),
    capsule: cloneEntity("auth_capsule", result.capsule),
    retiredBinding: cloneEntity("credential_binding", result.retiredBinding),
    barrierBinding: cloneEntity("credential_binding", result.barrierBinding),
    operation: { ...result.operation },
    replayed: result.replayed,
  };
}
