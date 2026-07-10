import { Database } from "bun:sqlite";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
} from "node:fs";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";

import { AccountsError } from "../errors";
import { incrementCounter, parseCounter, type Counter } from "../domain/counter";
import { generateUuidV7, newAccountEventId, newOutboxId } from "../domain/ids";
import type { CredentialBinding, CredentialOperation, EntityKind, EntityMap } from "../domain/models";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";
import { parseClosedJson } from "../serialization/json";
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
import {
  SQLITE_MIGRATION_CHECKSUM,
  SQLITE_MIGRATIONS,
  SQLITE_SCHEMA_VERSION,
} from "./sqlite-migrations";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import { deriveNativeRevocation } from "./native-revocation";
import { ACCOUNTS_V1_CONTRACT_SHA256 } from "../version";
import { REJECTING_CREDENTIAL_HANDLE_VERIFIER } from "./credential-verifier";
import { UNAVAILABLE_RECOVERY_LEDGER } from "./recovery";
import { REJECTING_CREDENTIAL_USE_AUTHORIZER } from "./credential-use-authorizer";

const TABLES: Readonly<Record<EntityKind, string>> = {
  account: "provider_accounts",
  entitlement: "entitlements",
  capacity_pool: "capacity_pools",
  access_method: "account_lanes",
  auth_capsule: "auth_capsules",
  credential_binding: "credential_bindings",
};

interface PayloadRow {
  readonly payload_json: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly aggregate_kind: EntityKind;
  readonly event_id: string;
  readonly response_json: string;
}

interface EventRow {
  readonly id: string;
  readonly aggregate_kind: EntityKind;
  readonly aggregate_id: string;
  readonly aggregate_revision: bigint;
  readonly actor_ref: string;
  readonly reason_code: string;
  readonly occurred_at: string;
}

interface HandleRow {
  readonly opaque_handle: string;
  readonly issuer_ref: string;
  readonly audience: CredentialHandleEnvelope["audience"];
  readonly catalog_incarnation: string;
  readonly backend_class: CredentialHandleEnvelope["backendClass"];
  readonly audit_digest: string;
  readonly issued_at: string;
  readonly expires_at: string | null;
}

interface OperationRow {
  readonly id: string;
  readonly kind: CredentialOperation["kind"];
  readonly source_binding_id: string | null;
  readonly target_binding_id: string | null;
  readonly credential_family_id: string;
  readonly capacity_pool_id: string;
  readonly serialization_key: string;
  readonly expected_source_generation: bigint;
  readonly expected_auth_state_revision: bigint | null;
  readonly proposed_target_generation: bigint;
  readonly proposed_auth_state_revision: bigint | null;
  readonly state: CredentialOperation["state"];
  readonly idempotency_request_hash: string;
  readonly barrier_receipt_digest: string | null;
  readonly completion_receipt_digest: string | null;
  readonly revision: bigint;
  readonly created_at: string;
  readonly updated_at: string;
}

interface OutboxRow {
  readonly id: string;
  readonly topic: OutboxRecord["topic"];
  readonly aggregate_kind: OutboxRecord["aggregateKind"];
  readonly aggregate_id: string;
  readonly event_id: string | null;
  readonly payload_digest: string;
  readonly payload_json: string;
  readonly status: OutboxRecord["status"];
  readonly attempt_count: bigint;
  readonly claim_owner_ref: string | null;
  readonly claim_expires_at: string | null;
  readonly created_at: string;
}

interface InstallationRecoveryRow {
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: bigint;
  readonly recovery_frontier_hash: string;
  readonly recovery_frontier_signature_digest: string;
  readonly database_frontier_sequence: bigint;
  readonly database_frontier_hash: string;
  readonly database_frontier_signature_digest: string;
  readonly recovery_hold: bigint;
}

export class SQLiteAccountsRepository implements AccountsRepository {
  private readonly database: Database;
  private readonly credentialVerifier: CredentialHandleVerifier;
  private readonly recoveryLedger: RecoveryLedger;
  private readonly credentialUseAuthorizer: CredentialUseAuthorizer;
  private readonly configuredCatalogIncarnation: string | undefined;
  private closed = false;

  constructor(
    readonly filename: string,
    options: {
      readonly credentialVerifier?: CredentialHandleVerifier;
      readonly recoveryLedger?: RecoveryLedger;
      readonly catalogIncarnation?: string;
      readonly credentialUseAuthorizer?: CredentialUseAuthorizer;
    } = {},
  ) {
    this.credentialVerifier =
      options.credentialVerifier ?? REJECTING_CREDENTIAL_HANDLE_VERIFIER;
    this.recoveryLedger = options.recoveryLedger ?? UNAVAILABLE_RECOVERY_LEDGER;
    this.credentialUseAuthorizer =
      options.credentialUseAuthorizer ?? REJECTING_CREDENTIAL_USE_AUTHORIZER;
    this.configuredCatalogIncarnation = options.catalogIncarnation;
    if (filename !== ":memory:") prepareDatabasePath(filename);
    const previousUmask = process.umask(0o077);
    try {
      this.database = new Database(filename, { create: true, strict: true, safeIntegers: true });
    } finally {
      process.umask(previousUmask);
    }
    this.database.exec("PRAGMA foreign_keys = ON");
    this.database.exec("PRAGMA busy_timeout = 5000");
    if (filename !== ":memory:") this.database.exec("PRAGMA journal_mode = WAL");
    this.migrate();
    this.secureFiles();
  }

  async get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined> {
    this.assertOpen();
    const row = this.database
      .query(`SELECT payload_json FROM ${TABLES[kind]} WHERE id = ?`)
      .get(id) as PayloadRow | null;
    return row === null ? undefined : decodePayload(kind, row.payload_json);
  }

  async list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    this.assertOpen();
    const rows = this.database
      .query(`SELECT payload_json FROM ${TABLES[kind]} ORDER BY id COLLATE BINARY ASC`)
      .all() as PayloadRow[];
    return rows.map((row) => decodePayload(kind, row.payload_json));
  }

  async readEligibilitySnapshot(
    accessMethodId: EntityMap["access_method"]["id"],
  ): Promise<EligibilitySnapshot> {
    this.assertOpen();
    const transaction = this.database.transaction(() => {
      const method = this.readOne("access_method", accessMethodId);
      const entitlement =
        method === undefined ? undefined : this.readOne("entitlement", method.entitlementId);
      const account =
        entitlement === undefined ? undefined : this.readOne("account", entitlement.accountId);
      const pool =
        method === undefined ? undefined : this.readOne("capacity_pool", method.capacityPoolId);
      const capsuleRows = this.database
        .query("SELECT payload_json FROM auth_capsules WHERE access_method_id = ? ORDER BY id COLLATE BINARY ASC")
        .all(accessMethodId) as PayloadRow[];
      const bindingRows = this.database
        .query("SELECT payload_json FROM credential_bindings WHERE access_method_id = ? ORDER BY id COLLATE BINARY ASC")
        .all(accessMethodId) as PayloadRow[];
      return {
        ...(method === undefined ? {} : { method }),
        ...(entitlement === undefined ? {} : { entitlement }),
        ...(account === undefined ? {} : { account }),
        ...(pool === undefined ? {} : { pool }),
        capsules: capsuleRows.map((row) => decodePayload("auth_capsule", row.payload_json)),
        bindings: bindingRows.map((row) => decodePayload("credential_binding", row.payload_json)),
        recovery: this.readRecoverySnapshot(),
      } satisfies EligibilitySnapshot;
    });
    return transaction.immediate();
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
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay<K>(kind, scope, hash);
        if (replay !== undefined) return replay;
        this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
        this.insertRecord(kind, record);
        return this.recordMutation(kind, record, context, scope, hash);
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, kind, record.id);
    }
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
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay("capacity_pool", scope, hash);
        if (replay !== undefined) return replay;
        this.appendRecovery("catalog_mutation", "capacity_pool", record.id, hash, record.updatedAt);
        this.database
          .query(
            "INSERT INTO evidence_records(id, evidence_type, aggregate_kind, aggregate_id, aggregate_revision, evidence_generation, nonce, issuer_ref, issuer_class, issuer_incarnation, audience, identity_realm, key_id, subject_ref, payload_digest, envelope_digest, envelope_json, issued_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .run(
            evidence.evidenceRef,
            evidence.evidenceType,
            evidence.aggregateKind,
            evidence.aggregateId,
            BigInt(evidence.aggregateRevision),
            BigInt(evidence.evidenceGeneration),
            evidence.nonce,
            evidence.issuerRef,
            evidence.issuerClass,
            evidence.issuerIncarnation,
            evidence.audience,
            evidence.identityRealm,
            evidence.keyId,
            evidence.subjectRef,
            evidence.payloadDigest,
            evidence.envelopeDigest,
            evidence.envelopeJson,
            evidence.issuedAt,
            evidence.expiresAt,
            record.updatedAt,
          );
        this.insertRecord("capacity_pool", record);
        return this.recordMutation("capacity_pool", record, context, scope, hash);
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, "capacity_pool", record.id);
    }
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
    const expectedClaims = await buildCredentialHandleExpectedClaims(this, record, {
      audience: "accounts-local",
      catalogIncarnation: this.installationCatalogIncarnation(),
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
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay("credential_binding", scope, hash);
        if (replay !== undefined) return replay;
        this.appendRecovery(
          "catalog_mutation",
          "credential_binding",
          record.id,
          hash,
          record.updatedAt,
        );
        this.insertRecord("credential_binding", record);
        this.database
          .query("INSERT INTO credential_binding_handles(binding_id, opaque_handle, issuer_ref, audience, catalog_incarnation, backend_class, audit_digest, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(
            record.id,
            handle.opaqueHandle,
            handle.issuerRef,
            handle.audience,
            handle.catalogIncarnation,
            handle.backendClass,
            verification.credentialHandleAuditDigest,
            handle.issuedAt,
            handle.expiresAt ?? null,
          );
        return this.recordMutation("credential_binding", record, context, scope, hash);
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, "credential_binding", record.id);
    }
  }

  async resolveCredentialHandle(
    bindingId: CredentialBinding["id"],
    grant: CredentialResolutionGrant,
    transport: CredentialResolutionTransport,
  ): Promise<ResolvedCredentialHandle> {
    this.assertOpen();
    const transaction = this.database.transaction(() => {
      const binding = this.readOne("credential_binding", bindingId);
      const handle = this.database
        .query("SELECT opaque_handle, issuer_ref, audience, catalog_incarnation, backend_class, audit_digest, issued_at, expires_at FROM credential_binding_handles WHERE binding_id = ?")
        .get(bindingId) as HandleRow | null;
      const method = binding === undefined ? undefined : this.readOne("access_method", binding.accessMethodId);
      const pool = binding === undefined ? undefined : this.readOne("capacity_pool", binding.capacityPoolId);
      const account = pool === undefined ? undefined : this.readOne("account", pool.accountId);
      const recovery = this.readRecoverySnapshot();
      if (
        binding === undefined ||
        handle === null ||
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
        handle.catalog_incarnation !== recovery.frontier.catalogIncarnation ||
        (binding.expiresAt !== undefined && Date.parse(binding.expiresAt) <= Date.parse(transport.now)) ||
        (handle.expires_at !== null && Date.parse(handle.expires_at) <= Date.parse(transport.now))
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
        opaqueHandle: handle.opaque_handle,
        issuerRef: handle.issuer_ref,
        audience: handle.audience,
        backendClass: handle.backend_class,
        ...(handle.expires_at === null ? {} : { expiresAt: handle.expires_at }),
      } satisfies ResolvedCredentialHandle;
    });
    return transaction.immediate();
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
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay<K>(kind, scope, hash);
        if (replay !== undefined) return replay;
        const currentRow = this.database
          .query(`SELECT payload_json FROM ${TABLES[kind]} WHERE id = ?`)
          .get(record.id) as PayloadRow | null;
        if (currentRow === null) {
          throw new AccountsError("NOT_FOUND", "Record not found", {
            details: { aggregateKind: kind, aggregateId: record.id },
          });
        }
        const previous = decodePayload(kind, currentRow.payload_json);
        if (isAuthorityPromotion(kind, previous, record)) {
          throw new AccountsError(
            "VALIDATION_FAILED",
            "Authority promotion requires an atomic verified evidence cohort",
          );
        }
        assertReplacement(kind, previous, record, expectedRevision);
        this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
        this.updateRecord(kind, record, expectedRevision);
        return this.recordMutation(kind, record, context, scope, hash);
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, kind, record.id);
    }
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
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay<K>(kind, scope, hash);
        if (replay !== undefined) return replay;
        const currentRow = this.database
          .query(`SELECT payload_json FROM ${TABLES[kind]} WHERE id = ?`)
          .get(record.id) as PayloadRow | null;
        if (currentRow === null) {
          throw new AccountsError("NOT_FOUND", "Record not found", {
            details: { aggregateKind: kind, aggregateId: record.id },
          });
        }
        const previous = decodePayload(kind, currentRow.payload_json);
        assertReplacement(kind, previous, record, expectedRevision);
        if (!isAuthorityPromotion(kind, previous, record)) {
          throw new AccountsError("INVALID_TRANSITION", "Authority promotion edge is invalid");
        }
        this.appendRecovery("catalog_mutation", kind, record.id, hash, record.updatedAt);
        for (const item of evidence) {
          this.database
            .query(
              "INSERT INTO evidence_records(id, evidence_type, aggregate_kind, aggregate_id, aggregate_revision, evidence_generation, nonce, issuer_ref, issuer_class, issuer_incarnation, audience, identity_realm, key_id, subject_ref, payload_digest, envelope_digest, envelope_json, issued_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .run(
              item.evidenceRef,
              item.evidenceType,
              item.aggregateKind,
              item.aggregateId,
              BigInt(item.aggregateRevision),
              BigInt(item.evidenceGeneration),
              item.nonce,
              item.issuerRef,
              item.issuerClass,
              item.issuerIncarnation,
              item.audience,
              item.identityRealm,
              item.keyId,
              item.subjectRef,
              item.payloadDigest,
              item.envelopeDigest,
              item.envelopeJson,
              item.issuedAt,
              item.expiresAt,
              record.updatedAt,
            );
        }
        this.updateRecord(kind, record, expectedRevision);
        return this.recordMutation(kind, record, context, scope, hash);
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, kind, record.id);
    }
  }

  async events(): Promise<readonly AccountEvent[]> {
    this.assertOpen();
    const rows = this.database
      .query(
        "SELECT id, aggregate_kind, aggregate_id, aggregate_revision, actor_ref, reason_code, occurred_at FROM account_events ORDER BY rowid ASC",
      )
      .all() as EventRow[];
    return rows.map((row) => ({
      id: row.id as AccountEvent["id"],
      aggregateKind: row.aggregate_kind,
      aggregateId: row.aggregate_id as AccountEvent["aggregateId"],
      aggregateRevision: row.aggregate_revision.toString(10) as Counter,
      actorRef: row.actor_ref,
      reasonCode: row.reason_code,
      occurredAt: row.occurred_at,
    }));
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
    try {
      const transaction = this.database.transaction(() => {
        const idempotency = this.database
          .query("SELECT request_hash, response_json FROM idempotency_records WHERE scope = ?")
          .get(scope) as { request_hash: string; response_json: string } | null;
        if (idempotency !== null) {
          if (idempotency.request_hash !== hash) {
            throw new AccountsError("IDEMPOTENCY_CONFLICT", "Native revocation request changed");
          }
          return this.readNativeRevocationResult(idempotency.response_json, true);
        }
        if (
          this.readOne("credential_binding", request.barrierBindingId) !== undefined ||
          this.database.query("SELECT 1 FROM credential_operations WHERE id = ?").get(request.operationId) !== null
        ) {
          throw new AccountsError("CONFLICT", "Native revocation identifiers already exist");
        }
        const capsule = this.readOne("auth_capsule", request.capsuleId);
        const binding = this.readOne("credential_binding", request.bindingId);
        const handle = this.database
          .query("SELECT opaque_handle, issuer_ref, audience, catalog_incarnation, backend_class, audit_digest, issued_at, expires_at FROM credential_binding_handles WHERE binding_id = ?")
          .get(request.bindingId) as HandleRow | null;
        const method = capsule === undefined ? undefined : this.readOne("access_method", capsule.accessMethodId);
        const pool = capsule === undefined ? undefined : this.readOne("capacity_pool", capsule.capacityPoolId);
        if (capsule === undefined || binding === undefined || handle === null || method === undefined || pool === undefined) {
          throw new AccountsError("NOT_FOUND", "Native revocation source was not found");
        }
        const source = {
          pool,
          method,
          capsule,
          binding,
          credentialHandleAuditDigest: handle.audit_digest,
        };
        const preview = deriveNativeRevocation(
          source,
          request,
          `sha256:${"0".repeat(64)}`,
        );
        if (
          this.database
            .query("SELECT 1 FROM credential_bindings WHERE credential_family_id = ? AND credential_generation = ?")
            .get(binding.credentialFamilyId, BigInt(preview.barrierBinding.credentialGeneration)) !== null ||
          this.database
            .query("SELECT 1 FROM credential_operations WHERE credential_family_id = ? AND serialization_key = ? AND state IN ('requested','quiescing','applying','verifying','failed_before_dispatch','failed')")
            .get(binding.credentialFamilyId, pool.serializationKey) !== null
        ) {
          throw new AccountsError("CONFLICT", "Native revocation generation or operation is already active");
        }
        const recovery = this.appendRecovery(
          "native_revocation_barrier",
          "credential_operation",
          request.operationId,
          hash,
          request.occurredAt,
        );
        const derived = deriveNativeRevocation(source, request, recovery.receiptDigest);
        this.database.query("DELETE FROM credential_binding_handles WHERE binding_id = ?").run(binding.id);
        this.updateRecord("capacity_pool", derived.pool, pool.revision);
        this.updateRecord("access_method", derived.method, method.revision);
        this.updateRecord("auth_capsule", derived.capsule, capsule.revision);
        this.updateRecord("credential_binding", derived.retiredBinding, binding.revision);
        this.insertRecord("credential_binding", derived.barrierBinding);
        this.insertOperation(derived.operation);

        let barrierEventId: AccountEvent["id"] | undefined;
        for (const [kind, record] of [
          ["capacity_pool", derived.pool],
          ["access_method", derived.method],
          ["auth_capsule", derived.capsule],
          ["credential_binding", derived.retiredBinding],
          ["credential_binding", derived.barrierBinding],
        ] as const) {
          const eventId = this.appendEventAndOutbox(
            kind,
            record as EntityMap[typeof kind],
            request.context,
          );
          if (record.id === derived.barrierBinding.id) barrierEventId = eventId;
        }
        this.appendCleanupOutbox(derived.operation);
        if (barrierEventId === undefined) {
          throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Native revocation audit event is missing");
        }
        const responseJson = canonicalJson({
          schemaVersion: "accounts.native-revocation-result.v1",
          poolId: derived.pool.id,
          methodId: derived.method.id,
          capsuleId: derived.capsule.id,
          retiredBindingId: derived.retiredBinding.id,
          barrierBindingId: derived.barrierBinding.id,
          operationId: derived.operation.id,
        });
        this.database
          .query("INSERT INTO idempotency_records(scope, request_hash, aggregate_kind, aggregate_id, event_id, response_json, created_at) VALUES (?, ?, 'credential_binding', ?, ?, ?, ?)")
          .run(scope, hash, derived.barrierBinding.id, barrierEventId, responseJson, request.occurredAt);
        return { ...derived, replayed: false } satisfies NativeRevocationResult;
      });
      const result = transaction.immediate();
      this.secureFiles();
      return result;
    } catch (error) {
      throw mapSqliteError(error, "credential_binding", request.bindingId);
    }
  }

  async credentialOperations(): Promise<readonly CredentialOperation[]> {
    this.assertOpen();
    const rows = this.database
      .query("SELECT id, kind, source_binding_id, target_binding_id, credential_family_id, capacity_pool_id, serialization_key, expected_source_generation, expected_auth_state_revision, proposed_target_generation, proposed_auth_state_revision, state, idempotency_request_hash, barrier_receipt_digest, completion_receipt_digest, revision, created_at, updated_at FROM credential_operations ORDER BY id COLLATE BINARY ASC")
      .all() as OperationRow[];
    return rows.map(decodeOperation);
  }

  async outbox(): Promise<readonly OutboxRecord[]> {
    this.assertOpen();
    const rows = this.database
      .query("SELECT id, topic, aggregate_kind, aggregate_id, event_id, payload_digest, payload_json, status, attempt_count, claim_owner_ref, claim_expires_at, created_at FROM outbox ORDER BY rowid ASC")
      .all() as OutboxRow[];
    return rows.map(decodeOutbox);
  }

  async claimOutbox(request: OutboxClaimRequest): Promise<readonly OutboxRecord[]> {
    this.assertOpen();
    validateOutboxClaimRequest(request);
    const transaction = this.database.transaction(() => {
      const candidates = this.database
        .query("SELECT id FROM outbox WHERE status = 'pending' OR (status = 'in_flight' AND claim_expires_at <= ?) ORDER BY created_at ASC, id COLLATE BINARY ASC LIMIT ?")
        .all(request.now, request.limit) as Array<{ id: string }>;
      const claimed: OutboxRecord[] = [];
      for (const candidate of candidates) {
        const changes = this.database
          .query("UPDATE outbox SET status = 'in_flight', attempt_count = attempt_count + 1, claim_owner_ref = ?, claim_expires_at = ? WHERE id = ? AND (status = 'pending' OR (status = 'in_flight' AND claim_expires_at <= ?))")
          .run(request.workerRef, request.claimExpiresAt, candidate.id, request.now).changes;
        if (changes !== 1) continue;
        const row = this.database
          .query("SELECT id, topic, aggregate_kind, aggregate_id, event_id, payload_digest, payload_json, status, attempt_count, claim_owner_ref, claim_expires_at, created_at FROM outbox WHERE id = ?")
          .get(candidate.id) as OutboxRow | null;
        if (row !== null) claimed.push(decodeOutbox(row));
      }
      return claimed;
    });
    return transaction.immediate();
  }

  async acknowledgeOutbox(request: OutboxAcknowledgeRequest): Promise<OutboxRecord> {
    this.assertOpen();
    validateOutboxAcknowledgeRequest(request);
    const status = request.outcome === "retry" ? "pending" : request.outcome;
    const transaction = this.database.transaction(() => {
      const changes = this.database
        .query("UPDATE outbox SET status = ?, claim_owner_ref = NULL, claim_expires_at = NULL WHERE id = ? AND status = 'in_flight' AND claim_owner_ref = ? AND attempt_count = ? AND claim_expires_at > ?")
        .run(
          status,
          request.outboxId,
          request.workerRef,
          BigInt(request.expectedAttemptCount),
          request.now,
        ).changes;
      if (changes !== 1) throw new AccountsError("CONFLICT", "Outbox claim is stale");
      const row = this.database
        .query("SELECT id, topic, aggregate_kind, aggregate_id, event_id, payload_digest, payload_json, status, attempt_count, claim_owner_ref, claim_expires_at, created_at FROM outbox WHERE id = ?")
        .get(request.outboxId) as OutboxRow | null;
      if (row === null) throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Outbox row disappeared");
      return decodeOutbox(row);
    });
    return transaction.immediate();
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
    const row = this.database
      .query("SELECT request_hash, aggregate_kind, event_id, response_json FROM idempotency_records WHERE scope = ?")
      .get(scope) as IdempotencyRow | null;
    if (row === null) return undefined;
    if (row.aggregate_kind !== kind) throw new AccountsError("IDEMPOTENCY_CONFLICT", "Stored replay kind changed");
    const record = decodePayload(kind, row.response_json);
    const expectedHash = mutationHash("replace", kind, record, context, expectedRevision);
    if (
      row.request_hash !== expectedHash ||
      record.id !== id ||
      record.status !== to ||
      record.revision !== incrementCounter(expectedRevision)
    ) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotent transition input changed");
    }
    return {
      record,
      eventId: row.event_id as AccountEvent["id"],
      replayed: true,
    };
  }

  async doctor(): Promise<RepositoryDoctor> {
    this.assertOpen();
    const foreignKeys = this.database.query("PRAGMA foreign_keys").values()[0]?.[0] === 1n;
    const journal = this.database.query("PRAGMA journal_mode").values()[0]?.[0];
    const integrity = this.database.query("PRAGMA integrity_check").values()[0]?.[0];
    const migration = this.database
      .query("SELECT checksum FROM accounts_schema_migrations WHERE version = ?")
      .get(BigInt(SQLITE_SCHEMA_VERSION)) as { checksum: string } | null;
    if (
      foreignKeys !== true ||
      integrity !== "ok" ||
      migration?.checksum !== SQLITE_MIGRATION_CHECKSUM ||
      (this.filename !== ":memory:" && journal !== "wal")
    ) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "SQLite integrity checks failed", {
        details: { adapter: "sqlite" },
      });
    }
    const recovery = this.readRecoverySnapshot();
    return {
      adapter: "sqlite",
      schemaVersion: SQLITE_SCHEMA_VERSION.toString(10),
      migrationChecksum: SQLITE_MIGRATION_CHECKSUM,
      foreignKeys: true,
      journalMode: journal === "wal" ? "wal" : "memory",
      integrity: "ok",
      readiness: recovery.matched && !recovery.hold ? "ready" : "recovery_hold",
      recoveryFrontier: recovery.frontier ?? "unavailable",
      recoveryHold: recovery.hold,
      positiveEligibility: recovery.matched && !recovery.hold,
    };
  }

  async close(): Promise<void> {
    if (!this.closed) {
      this.database.close();
      this.closed = true;
      this.secureFiles();
    }
  }

  private installationCatalogIncarnation(): string {
    const row = this.database
      .query("SELECT catalog_incarnation FROM accounts_installation WHERE singleton = 1")
      .get() as { catalog_incarnation: string } | null;
    if (row === null) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Accounts installation state is missing");
    }
    return row.catalog_incarnation;
  }

  private readRecoverySnapshot(): RecoverySnapshot {
    const row = this.database
      .query("SELECT catalog_incarnation, recovery_frontier_sequence, recovery_frontier_hash, recovery_frontier_signature_digest, database_frontier_sequence, database_frontier_hash, database_frontier_signature_digest, recovery_hold FROM accounts_installation WHERE singleton = 1")
      .get() as InstallationRecoveryRow | null;
    if (row === null || row.recovery_hold === 1n) {
      return { matched: false, hold: true };
    }
    try {
      const frontier = this.recoveryLedger.readFreshFrontier();
      const matched =
        this.recoveryLedger.verifyFrontier(frontier) &&
        frontier.catalogIncarnation === row.catalog_incarnation &&
        frontier.sequence === row.recovery_frontier_sequence.toString(10) &&
        frontier.sequence === row.database_frontier_sequence.toString(10) &&
        frontier.hash === row.recovery_frontier_hash &&
        frontier.hash === row.database_frontier_hash &&
        frontier.signatureDigest === row.recovery_frontier_signature_digest &&
        frontier.signatureDigest === row.database_frontier_signature_digest;
      if (!matched) {
        this.database
          .query("UPDATE accounts_installation SET recovery_hold = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE singleton = 1")
          .run();
        return { matched: false, hold: true };
      }
      return { matched: true, hold: false, frontier };
    } catch {
      this.database
        .query("UPDATE accounts_installation SET recovery_hold = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE singleton = 1")
        .run();
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
    let receipt: RecoveryLedgerReceipt;
    try {
      receipt = this.recoveryLedger.append(snapshot.frontier, {
        kind,
        aggregateKind,
        aggregateId,
        mutationDigest,
        occurredAt,
      });
    } catch (error) {
      this.database
        .query("UPDATE accounts_installation SET recovery_hold = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE singleton = 1")
        .run();
      throw error instanceof AccountsError
        ? error
        : new AccountsError("RECOVERY_HOLD", "Recovery append failed");
    }
    this.database
      .query("INSERT INTO recovery_ledger_receipts(sequence, frontier_hash, frontier_signature_digest, catalog_incarnation, receipt_digest, entry_kind, aggregate_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(
        BigInt(receipt.sequence),
        receipt.hash,
        receipt.signatureDigest,
        receipt.catalogIncarnation,
        receipt.receiptDigest,
        kind,
        aggregateId,
        occurredAt,
      );
    this.database
      .query("UPDATE accounts_installation SET recovery_frontier_sequence = ?, recovery_frontier_hash = ?, recovery_frontier_signature_digest = ?, database_frontier_sequence = ?, database_frontier_hash = ?, database_frontier_signature_digest = ?, recovery_hold = 0, updated_at = ? WHERE singleton = 1")
      .run(
        BigInt(receipt.sequence),
        receipt.hash,
        receipt.signatureDigest,
        BigInt(receipt.sequence),
        receipt.hash,
        receipt.signatureDigest,
        occurredAt,
      );
    return receipt;
  }

  private migrate(): void {
    const transaction = this.database.transaction(() => {
      this.database.exec(`
        CREATE TABLE IF NOT EXISTS accounts_schema_migrations (
          version INTEGER PRIMARY KEY,
          checksum TEXT NOT NULL,
          applied_at TEXT NOT NULL
        )
      `);
      const rows = this.database
        .query("SELECT version, checksum FROM accounts_schema_migrations ORDER BY version ASC")
        .all() as Array<{ version: bigint; checksum: string }>;
      if (rows.some((row) => row.version > BigInt(SQLITE_SCHEMA_VERSION))) {
        throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Database schema is newer than this build", {
          details: { schemaVersion: "newer" },
        });
      }
      for (const row of rows) {
        const migration = SQLITE_MIGRATIONS.find(
          (candidate) => BigInt(candidate.version) === row.version,
        );
        if (migration === undefined || row.checksum !== migration.checksum) {
          throw new AccountsError("SCHEMA_CHECKSUM_MISMATCH", "Database schema checksum mismatch", {
            details: { adapter: "sqlite" },
          });
        }
      }
      for (const migration of SQLITE_MIGRATIONS) {
        if (rows.some((row) => row.version === BigInt(migration.version))) continue;
        if (migration.version === 2) {
          const existingBindings = this.database
            .query("SELECT count(*) AS count FROM credential_bindings")
            .get() as { count: bigint };
          if (existingBindings.count !== 0n) {
            throw new AccountsError(
              "SCHEMA_VERSION_UNSUPPORTED",
              "Legacy credential bindings require explicit reissuance before migration",
            );
          }
        }
        this.database.exec(migration.sql);
        this.database
          .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
          .run(BigInt(migration.version), migration.checksum);
      }
      const installation = this.database
        .query("SELECT singleton FROM accounts_installation WHERE singleton = 1")
        .get() as { singleton: bigint } | null;
      if (installation === null) {
        const timestamp = new Date().toISOString();
        let ledgerFrontier: RecoveryFrontier | undefined;
        try {
          const candidate = this.recoveryLedger.readFreshFrontier();
          if (this.recoveryLedger.verifyFrontier(candidate)) ledgerFrontier = candidate;
        } catch {
          ledgerFrontier = undefined;
        }
        const catalogIncarnation =
          this.configuredCatalogIncarnation ??
          ledgerFrontier?.catalogIncarnation ??
          `catalog:${generateUuidV7()}`;
        const matched =
          ledgerFrontier !== undefined &&
          ledgerFrontier.catalogIncarnation === catalogIncarnation &&
          ledgerFrontier.sequence === "0";
        const genesisHash = canonicalSha256({
          kind: "accounts-recovery-genesis",
          catalogIncarnation,
        });
        const initialFrontier: RecoveryFrontier = matched && ledgerFrontier !== undefined
          ? ledgerFrontier
          : {
              catalogIncarnation,
              sequence: parseCounter("0"),
              hash: genesisHash,
              signatureDigest: canonicalSha256({ unavailable: true, catalogIncarnation }),
            };
        this.database
          .query("INSERT INTO accounts_installation(singleton, deployment_mode, identity_realm, organization_ref, schema_version, build_digest, configuration_attestation_digest, catalog_incarnation, recovery_frontier_sequence, recovery_frontier_hash, recovery_frontier_signature_digest, database_frontier_sequence, database_frontier_hash, database_frontier_signature_digest, recovery_hold, created_at, updated_at) VALUES (1, 'local', 'hasna', 'organization:hasna', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(
            SQLITE_SCHEMA_VERSION.toString(10),
            `sha256:${ACCOUNTS_V1_CONTRACT_SHA256}`,
            canonicalSha256({ deploymentMode: "local", identityRealm: "hasna" }),
            catalogIncarnation,
            BigInt(initialFrontier.sequence),
            initialFrontier.hash,
            initialFrontier.signatureDigest,
            BigInt(initialFrontier.sequence),
            initialFrontier.hash,
            initialFrontier.signatureDigest,
            matched ? 0n : 1n,
            timestamp,
            timestamp,
          );
      }
    });
    transaction.exclusive();
  }

  private readOne<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): EntityMap[K] | undefined {
    const row = this.database
      .query(`SELECT payload_json FROM ${TABLES[kind]} WHERE id = ?`)
      .get(id) as PayloadRow | null;
    return row === null ? undefined : decodePayload(kind, row.payload_json);
  }

  private insertRecord<K extends EntityKind>(kind: K, record: EntityMap[K]): void {
    const payload = serializeRecordEnvelope(kind, record);
    const common = [record.id, record.status, BigInt(record.revision), record.createdAt, record.updatedAt, payload];
    switch (kind) {
      case "account": {
        const item = record as EntityMap["account"];
        this.database
          .query("INSERT INTO provider_accounts(id, provider_key, owner_ref, provider_subject_ref, status, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.providerKey, item.ownerRef, item.providerSubjectRef ?? null, ...common.slice(1));
        return;
      }
      case "entitlement": {
        const item = record as EntityMap["entitlement"];
        this.database
          .query("INSERT INTO entitlements(id, account_id, status, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.accountId, ...common.slice(1));
        return;
      }
      case "capacity_pool": {
        const item = record as EntityMap["capacity_pool"];
        const lineage = this.database
          .query("SELECT provider_key, owner_ref FROM provider_accounts WHERE id = ?")
          .get(item.accountId) as { provider_key: string; owner_ref: string } | null;
        if (lineage === null) throw new AccountsError("NOT_FOUND", "Capacity account was not found");
        this.database
          .query("INSERT INTO capacity_pools(id, account_id, provider_key, capacity_domain_ref, serialization_key, status, deny_state, revision, capacity_generation, deny_generation, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.accountId, lineage.provider_key, item.capacityDomainRef, item.serializationKey, item.status, item.denyState, BigInt(item.revision), BigInt(item.capacityGeneration), BigInt(item.denyGeneration), item.createdAt, item.updatedAt, payload);
        this.database
          .query("INSERT OR IGNORE INTO capacity_domain_claims(provider_key, capacity_domain_ref, serialization_key, owner_ref, capacity_pool_id, claimed_at) VALUES (?, ?, ?, ?, ?, ?)")
          .run(lineage.provider_key, item.capacityDomainRef, item.serializationKey, lineage.owner_ref, item.id, item.createdAt);
        const claim = this.database
          .query("SELECT serialization_key, owner_ref, capacity_pool_id FROM capacity_domain_claims WHERE provider_key = ? AND capacity_domain_ref = ?")
          .get(lineage.provider_key, item.capacityDomainRef) as {
            serialization_key: string;
            owner_ref: string;
            capacity_pool_id: string;
          };
        if (
          claim.serialization_key !== item.serializationKey ||
          claim.owner_ref !== lineage.owner_ref ||
          claim.capacity_pool_id !== item.id
        ) {
          throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Capacity domain lineage is permanently claimed");
        }
        return;
      }
      case "access_method": {
        const item = record as EntityMap["access_method"];
        this.database
          .query("INSERT INTO account_lanes(id, entitlement_id, capacity_pool_id, access_transport, status, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.entitlementId, item.capacityPoolId, item.accessTransport, ...common.slice(1));
        return;
      }
      case "auth_capsule": {
        const item = record as EntityMap["auth_capsule"];
        this.database
          .query("INSERT INTO auth_capsules(id, access_method_id, capacity_pool_id, owner_ref, placement_ref, status, auth_generation, auth_state_revision, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.accessMethodId, item.capacityPoolId, item.ownerRef, item.placementRef, item.status, BigInt(item.authGeneration), BigInt(item.authStateRevision), BigInt(item.revision), item.createdAt, item.updatedAt, payload);
        return;
      }
      case "credential_binding": {
        const item = record as EntityMap["credential_binding"];
        const retired = item.status === "revoked" && item.terminalKind === "retired_handle_generation";
        const barrier = item.status === "revoked" && item.terminalKind === "revocation_barrier";
        this.database
          .query("INSERT INTO credential_bindings(id, access_method_id, capacity_pool_id, auth_capsule_id, credential_family_id, resolver, purpose, status, credential_generation, auth_state_revision, revision, created_at, updated_at, payload_json, terminal_kind, credential_handle_audit_digest, last_usable_credential_generation, revocation_barrier_receipt_digest, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(
            item.id,
            item.accessMethodId,
            item.capacityPoolId,
            item.authCapsuleId ?? null,
            item.credentialFamilyId,
            item.resolver,
            item.purpose,
            item.status,
            BigInt(item.credentialGeneration),
            item.authStateRevision === undefined ? null : BigInt(item.authStateRevision),
            BigInt(item.revision),
            item.createdAt,
            item.updatedAt,
            payload,
            item.status === "revoked" ? item.terminalKind : null,
            retired ? item.credentialHandleAuditDigest : null,
            barrier ? BigInt(item.lastUsableCredentialGeneration) : null,
            item.status === "revoked" ? item.revocationBarrierReceiptDigest : null,
            item.status === "revoked" ? item.revokedAt : null,
          );
        const ownerRow = this.database
          .query("SELECT pa.owner_ref FROM capacity_pools cp JOIN provider_accounts pa ON pa.id = cp.account_id WHERE cp.id = ?")
          .get(item.capacityPoolId) as { owner_ref: string } | null;
        if (ownerRow === null) throw new AccountsError("NOT_FOUND", "Credential capacity owner was not found");
        this.database
          .query("INSERT OR IGNORE INTO credential_family_claims(credential_family_id, capacity_pool_id, owner_ref, purpose, resolver, claimed_at) VALUES (?, ?, ?, ?, ?, ?)")
          .run(item.credentialFamilyId, item.capacityPoolId, ownerRow.owner_ref, item.purpose, item.resolver, item.createdAt);
        const familyClaim = this.database
          .query("SELECT capacity_pool_id, owner_ref, purpose, resolver FROM credential_family_claims WHERE credential_family_id = ?")
          .get(item.credentialFamilyId) as {
            capacity_pool_id: string;
            owner_ref: string;
            purpose: string;
            resolver: string;
          };
        if (
          familyClaim.capacity_pool_id !== item.capacityPoolId ||
          familyClaim.owner_ref !== ownerRow.owner_ref ||
          familyClaim.purpose !== item.purpose ||
          familyClaim.resolver !== item.resolver
        ) {
          throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Credential family lineage is permanently claimed");
        }
      }
    }
  }

  private updateRecord<K extends EntityKind>(kind: K, record: EntityMap[K], expected: Counter): void {
    const payload = serializeRecordEnvelope(kind, record);
    let changes: number;
    switch (kind) {
      case "account": {
        const item = record as EntityMap["account"];
        changes = this.database
          .query("UPDATE provider_accounts SET provider_key=?, owner_ref=?, provider_subject_ref=?, status=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.providerKey, item.ownerRef, item.providerSubjectRef ?? null, item.status, BigInt(item.revision), item.updatedAt, payload, item.id, BigInt(expected)).changes;
        if (changes === 1 && item.status !== "pending" && item.providerSubjectRef !== undefined) {
          this.database
            .query("INSERT OR IGNORE INTO provider_subject_claims(provider_key, provider_subject_ref, owner_ref, provider_account_id, claimed_at) VALUES (?, ?, ?, ?, ?)")
            .run(item.providerKey, item.providerSubjectRef, item.ownerRef, item.id, item.updatedAt);
          const claim = this.database
            .query("SELECT owner_ref, provider_account_id FROM provider_subject_claims WHERE provider_key = ? AND provider_subject_ref = ?")
            .get(item.providerKey, item.providerSubjectRef) as {
              owner_ref: string;
              provider_account_id: string;
            };
          if (claim.owner_ref !== item.ownerRef || claim.provider_account_id !== item.id) {
            throw new AccountsError("CONFLICT", "Provider subject is permanently claimed");
          }
        }
        break;
      }
      case "entitlement": {
        const item = record as EntityMap["entitlement"];
        changes = this.database
          .query("UPDATE entitlements SET account_id=?, status=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.accountId, item.status, BigInt(item.revision), item.updatedAt, payload, item.id, BigInt(expected)).changes;
        break;
      }
      case "capacity_pool": {
        const item = record as EntityMap["capacity_pool"];
        changes = this.database
          .query("UPDATE capacity_pools SET account_id=?, capacity_domain_ref=?, serialization_key=?, status=?, deny_state=?, revision=?, capacity_generation=?, deny_generation=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.accountId, item.capacityDomainRef, item.serializationKey, item.status, item.denyState, BigInt(item.revision), BigInt(item.capacityGeneration), BigInt(item.denyGeneration), item.updatedAt, payload, item.id, BigInt(expected)).changes;
        break;
      }
      case "access_method": {
        const item = record as EntityMap["access_method"];
        changes = this.database
          .query("UPDATE account_lanes SET entitlement_id=?, capacity_pool_id=?, access_transport=?, status=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.entitlementId, item.capacityPoolId, item.accessTransport, item.status, BigInt(item.revision), item.updatedAt, payload, item.id, BigInt(expected)).changes;
        break;
      }
      case "auth_capsule": {
        const item = record as EntityMap["auth_capsule"];
        changes = this.database
          .query("UPDATE auth_capsules SET access_method_id=?, capacity_pool_id=?, owner_ref=?, placement_ref=?, status=?, auth_generation=?, auth_state_revision=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.accessMethodId, item.capacityPoolId, item.ownerRef, item.placementRef, item.status, BigInt(item.authGeneration), BigInt(item.authStateRevision), BigInt(item.revision), item.updatedAt, payload, item.id, BigInt(expected)).changes;
        break;
      }
      case "credential_binding": {
        const item = record as EntityMap["credential_binding"];
        const retired = item.status === "revoked" && item.terminalKind === "retired_handle_generation";
        const barrier = item.status === "revoked" && item.terminalKind === "revocation_barrier";
        changes = this.database
          .query("UPDATE credential_bindings SET access_method_id=?, capacity_pool_id=?, auth_capsule_id=?, credential_family_id=?, resolver=?, purpose=?, status=?, credential_generation=?, auth_state_revision=?, revision=?, updated_at=?, payload_json=?, terminal_kind=?, credential_handle_audit_digest=?, last_usable_credential_generation=?, revocation_barrier_receipt_digest=?, revoked_at=? WHERE id=? AND revision=?")
          .run(
            item.accessMethodId,
            item.capacityPoolId,
            item.authCapsuleId ?? null,
            item.credentialFamilyId,
            item.resolver,
            item.purpose,
            item.status,
            BigInt(item.credentialGeneration),
            item.authStateRevision === undefined ? null : BigInt(item.authStateRevision),
            BigInt(item.revision),
            item.updatedAt,
            payload,
            item.status === "revoked" ? item.terminalKind : null,
            retired ? item.credentialHandleAuditDigest : null,
            barrier ? BigInt(item.lastUsableCredentialGeneration) : null,
            item.status === "revoked" ? item.revocationBarrierReceiptDigest : null,
            item.status === "revoked" ? item.revokedAt : null,
            item.id,
            BigInt(expected),
          ).changes;
        break;
      }
    }
    if (changes !== 1) {
      throw new AccountsError("STALE_REVISION", "Concurrent record update detected", {
        details: { aggregateKind: kind, aggregateId: record.id, expectedRevision: expected },
      });
    }
  }

  private recordMutation<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
    scope: string,
    hash: string,
  ): MutationResult<EntityMap[K]> {
    const eventId = this.appendEventAndOutbox(kind, record, context);
    this.database
      .query("INSERT INTO idempotency_records(scope, request_hash, aggregate_kind, aggregate_id, event_id, response_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(scope, hash, kind, record.id, eventId, serializeRecordEnvelope(kind, record), record.updatedAt);
    return { record: cloneEntity(kind, record), eventId, replayed: false };
  }

  private appendEventAndOutbox<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): AccountEvent["id"] {
    const eventId = newAccountEventId(Date.parse(record.updatedAt));
    this.database
      .query("INSERT INTO account_events(id, aggregate_kind, aggregate_id, aggregate_revision, actor_ref, reason_code, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(eventId, kind, record.id, BigInt(record.revision), context.actorRef, context.reasonCode, record.updatedAt);
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      aggregateKind: kind,
      aggregateId: record.id,
      aggregateRevision: record.revision,
      eventId,
    });
    this.database
      .query("INSERT INTO outbox(id, topic, aggregate_kind, aggregate_id, event_id, payload_digest, payload_json, status, attempt_count, claim_owner_ref, claim_expires_at, created_at) VALUES (?, 'accounts.aggregate.changed', ?, ?, ?, ?, ?, 'pending', 0, NULL, NULL, ?)")
      .run(
        newOutboxId(Date.parse(record.updatedAt)),
        kind,
        record.id,
        eventId,
        canonicalSha256(payloadJson),
        payloadJson,
        record.updatedAt,
      );
    return eventId;
  }

  private appendCleanupOutbox(operation: CredentialOperation): void {
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      operationId: operation.id,
      sourceBindingId: operation.sourceBindingId,
      barrierBindingId: operation.targetBindingId,
      barrierReceiptDigest: operation.barrierReceiptDigest,
    });
    this.database
      .query("INSERT INTO outbox(id, topic, aggregate_kind, aggregate_id, event_id, payload_digest, payload_json, status, attempt_count, claim_owner_ref, claim_expires_at, created_at) VALUES (?, 'accounts.capsule.cleanup.requested', 'credential_operation', ?, NULL, ?, ?, 'pending', 0, NULL, NULL, ?)")
      .run(
        newOutboxId(Date.parse(operation.updatedAt)),
        operation.id,
        canonicalSha256(payloadJson),
        payloadJson,
        operation.updatedAt,
      );
  }

  private insertOperation(operation: CredentialOperation): void {
    this.database
      .query("INSERT INTO credential_operations(id, kind, source_binding_id, target_binding_id, credential_family_id, capacity_pool_id, serialization_key, expected_source_generation, expected_auth_state_revision, proposed_target_generation, proposed_auth_state_revision, state, idempotency_request_hash, barrier_receipt_digest, completion_receipt_digest, revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(
        operation.id,
        operation.kind,
        operation.sourceBindingId ?? null,
        operation.targetBindingId ?? null,
        operation.credentialFamilyId,
        operation.capacityPoolId,
        operation.serializationKey,
        BigInt(operation.expectedSourceGeneration),
        operation.expectedAuthStateRevision === undefined
          ? null
          : BigInt(operation.expectedAuthStateRevision),
        BigInt(operation.proposedTargetGeneration),
        operation.proposedAuthStateRevision === undefined
          ? null
          : BigInt(operation.proposedAuthStateRevision),
        operation.state,
        operation.idempotencyRequestHash,
        operation.barrierReceiptDigest ?? null,
        operation.completionReceiptDigest ?? null,
        BigInt(operation.revision),
        operation.createdAt,
        operation.updatedAt,
      );
  }

  private readNativeRevocationResult(
    responseJson: string,
    replayed: boolean,
  ): NativeRevocationResult {
    const value = parseClosedJson(responseJson);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored native revocation result is invalid");
    }
    const record = value as Record<string, unknown>;
    const expectedKeys = [
      "schemaVersion",
      "poolId",
      "methodId",
      "capsuleId",
      "retiredBindingId",
      "barrierBindingId",
      "operationId",
    ];
    if (
      record.schemaVersion !== "accounts.native-revocation-result.v1" ||
      Object.keys(record).length !== expectedKeys.length ||
      expectedKeys.some((key) => !Object.hasOwn(record, key)) ||
      expectedKeys.slice(1).some((key) => typeof record[key] !== "string")
    ) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored native revocation result is invalid");
    }
    const pool = this.readOne("capacity_pool", record.poolId as EntityMap["capacity_pool"]["id"]);
    const method = this.readOne("access_method", record.methodId as EntityMap["access_method"]["id"]);
    const capsule = this.readOne("auth_capsule", record.capsuleId as EntityMap["auth_capsule"]["id"]);
    const retiredBinding = this.readOne(
      "credential_binding",
      record.retiredBindingId as EntityMap["credential_binding"]["id"],
    );
    const barrierBinding = this.readOne(
      "credential_binding",
      record.barrierBindingId as EntityMap["credential_binding"]["id"],
    );
    const operationRow = this.database
      .query("SELECT id, kind, source_binding_id, target_binding_id, credential_family_id, capacity_pool_id, serialization_key, expected_source_generation, expected_auth_state_revision, proposed_target_generation, proposed_auth_state_revision, state, idempotency_request_hash, barrier_receipt_digest, completion_receipt_digest, revision, created_at, updated_at FROM credential_operations WHERE id = ?")
      .get(record.operationId as string) as OperationRow | null;
    if (
      pool === undefined ||
      method === undefined ||
      capsule === undefined ||
      retiredBinding === undefined ||
      barrierBinding === undefined ||
      operationRow === null
    ) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored native revocation result is incomplete");
    }
    return {
      pool,
      method,
      capsule,
      retiredBinding,
      barrierBinding,
      operation: decodeOperation(operationRow),
      replayed,
    };
  }

  private replay<K extends EntityKind>(
    kind: K,
    scope: string,
    hash: string,
  ): MutationResult<EntityMap[K]> | undefined {
    const row = this.database
      .query("SELECT request_hash, aggregate_kind, event_id, response_json FROM idempotency_records WHERE scope = ?")
      .get(scope) as IdempotencyRow | null;
    if (row === null) return undefined;
    if (row.request_hash !== hash || row.aggregate_kind !== kind) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused for different input");
    }
    return {
      record: decodePayload(kind, row.response_json),
      eventId: row.event_id as AccountEvent["id"],
      replayed: true,
    };
  }

  private secureFiles(): void {
    if (this.filename === ":memory:") return;
    for (const path of [this.filename, `${this.filename}-wal`, `${this.filename}-shm`]) {
      if (existsSync(path)) chmodSync(path, 0o600);
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Repository is closed", {
        details: { adapter: "sqlite" },
      });
    }
  }
}

function decodePayload<K extends EntityKind>(kind: K, source: string): EntityMap[K] {
  const envelope = deserializeRecordEnvelope(source);
  if (envelope.kind !== kind) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored record kind is invalid", {
      details: { adapter: "sqlite" },
    });
  }
  return envelope.data as EntityMap[K];
}

function decodeOperation(row: OperationRow): CredentialOperation {
  return {
    id: row.id as CredentialOperation["id"],
    kind: row.kind,
    ...(row.source_binding_id === null
      ? {}
      : { sourceBindingId: row.source_binding_id as NonNullable<CredentialOperation["sourceBindingId"]> }),
    ...(row.target_binding_id === null
      ? {}
      : { targetBindingId: row.target_binding_id as NonNullable<CredentialOperation["targetBindingId"]> }),
    credentialFamilyId: row.credential_family_id,
    capacityPoolId: row.capacity_pool_id as CredentialOperation["capacityPoolId"],
    serializationKey: row.serialization_key,
    expectedSourceGeneration: parseCounter(row.expected_source_generation.toString(10)),
    ...(row.expected_auth_state_revision === null
      ? {}
      : {
          expectedAuthStateRevision: parseCounter(
            row.expected_auth_state_revision.toString(10),
          ),
        }),
    proposedTargetGeneration: parseCounter(row.proposed_target_generation.toString(10)),
    ...(row.proposed_auth_state_revision === null
      ? {}
      : {
          proposedAuthStateRevision: parseCounter(
            row.proposed_auth_state_revision.toString(10),
          ),
        }),
    state: row.state,
    idempotencyRequestHash: row.idempotency_request_hash,
    ...(row.barrier_receipt_digest === null
      ? {}
      : { barrierReceiptDigest: row.barrier_receipt_digest }),
    ...(row.completion_receipt_digest === null
      ? {}
      : { completionReceiptDigest: row.completion_receipt_digest }),
    revision: parseCounter(row.revision.toString(10)),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function decodeOutbox(row: OutboxRow): OutboxRecord {
  return {
    id: row.id as OutboxRecord["id"],
    topic: row.topic,
    aggregateKind: row.aggregate_kind,
    aggregateId: row.aggregate_id,
    ...(row.event_id === null ? {} : { eventId: row.event_id as AccountEvent["id"] }),
    payloadDigest: row.payload_digest,
    payloadJson: row.payload_json,
    status: row.status,
    attemptCount: parseCounter(row.attempt_count.toString(10)),
    ...(row.claim_owner_ref === null ? {} : { claimOwnerRef: row.claim_owner_ref }),
    ...(row.claim_expires_at === null ? {} : { claimExpiresAt: row.claim_expires_at }),
    createdAt: row.created_at,
  };
}

function prepareDatabasePath(input: string): void {
  if (!isAbsolute(input)) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite path must be absolute", {
      details: { adapter: "sqlite" },
    });
  }
  const filename = resolve(input);
  const parent = dirname(filename);
  const uid = process.getuid?.();
  if (uid === undefined) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Cannot verify SQLite path ownership");
  }
  const missing: string[] = [];
  let existing = parent;
  while (!existsSync(existing)) {
    missing.unshift(existing);
    const next = dirname(existing);
    if (next === existing) break;
    existing = next;
  }
  validateExistingPath(existing, uid);
  for (const directory of missing) {
    mkdirSync(directory, { mode: 0o700 });
    const status = lstatSync(directory);
    if (!status.isDirectory() || status.uid !== uid || (status.mode & 0o077) !== 0) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Created SQLite directory is unsafe");
    }
  }
  const parentStatus = lstatSync(parent);
  if (!parentStatus.isDirectory() || parentStatus.uid !== uid || (parentStatus.mode & 0o077) !== 0) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite parent directory is not owner-only", {
      details: { adapter: "sqlite" },
    });
  }
  if (existsSync(filename)) {
    const fileStatus = lstatSync(filename);
    if (
      fileStatus.isSymbolicLink() ||
      !fileStatus.isFile() ||
      fileStatus.uid !== uid ||
      (fileStatus.mode & 0o077) !== 0
    ) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite database is not owner-only", {
        details: { adapter: "sqlite" },
      });
    }
  } else {
    const descriptor = openSync(
      filename,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    closeSync(descriptor);
  }
}

function validateExistingPath(path: string, uid: number): void {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  const components = absolute.slice(root.length).split("/").filter(Boolean);
  let current = root;
  for (const component of components) {
    current = join(current, component);
    const status = lstatSync(current);
    if (status.isSymbolicLink() || !status.isDirectory()) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite path contains an unsafe component");
    }
    const writableByOthers = (status.mode & 0o022) !== 0;
    const rootStickyDirectory = status.uid === 0 && (status.mode & 0o1000) !== 0;
    if (status.uid !== uid && status.uid !== 0) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite path component has an unexpected owner");
    }
    if (status.uid !== uid && writableByOthers && !rootStickyDirectory) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite path component is writable by another user");
    }
  }
}

function mapSqliteError(error: unknown, kind: EntityKind, id: string): AccountsError {
  if (error instanceof AccountsError) return error;
  if (error instanceof Error && /UNIQUE constraint failed/.test(error.message)) {
    return new AccountsError("CONFLICT", "A uniqueness constraint rejected the record", {
      details: { aggregateKind: kind, aggregateId: id },
    });
  }
  if (error instanceof Error && /FOREIGN KEY constraint failed/.test(error.message)) {
    return new AccountsError("NOT_FOUND", "A required parent record was not found", {
      details: { aggregateKind: kind, aggregateId: id },
    });
  }
  return new AccountsError("DEPENDENCY_UNAVAILABLE", "SQLite operation failed", {
    details: { adapter: "sqlite" },
  });
}
