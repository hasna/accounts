import { SQL, type TransactionSQL } from "bun";

import { incrementCounter, parseCounter, type Counter } from "../domain/counter";
import { newAccountEventId, newOutboxId } from "../domain/ids";
import type {
  CredentialBinding,
  CredentialOperation,
  EntityKind,
  EntityMap,
} from "../domain/models";
import { AccountsError } from "../errors";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";
import { canonicalJson, canonicalSha256, parseClosedJson } from "../serialization/json";
import { ACCOUNTS_V1_CONTRACT_SHA256 } from "../version";
import { REJECTING_CREDENTIAL_USE_AUTHORIZER } from "./credential-use-authorizer";
import { REJECTING_CREDENTIAL_HANDLE_VERIFIER } from "./credential-verifier";
import { deriveNativeRevocation } from "./native-revocation";
import {
  normalizePostgresConnection,
  validatePostgresRuntimeContext,
  type PostgresConnectionInput,
} from "./postgres-config";
import {
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations";
import type {
  AccountEvent,
  AccountsRepository,
  AuthorityPromotionKind,
  CredentialHandleEnvelope,
  CredentialHandleExpectedClaims,
  CredentialHandleVerifier,
  CredentialResolutionGrant,
  CredentialResolutionTransport,
  CredentialUseAuthorizer,
  EligibilitySnapshot,
  MutationContext,
  MutationResult,
  NativeRevocationRequest,
  NativeRevocationResult,
  OutboxAcknowledgeRequest,
  OutboxClaimRequest,
  OutboxRecord,
  RecoveryFrontier,
  RecoveryLedger,
  RecoveryLedgerEntry,
  RecoveryLedgerReceipt,
  RecoverySnapshot,
  ResolvedCredentialHandle,
  VerifiedAuthorityEvidenceRecord,
  PostgresRepositoryDoctor as SharedPostgresRepositoryDoctor,
} from "./repository";
import {
  assertReplacement,
  authorityPromotionHash,
  cloneEntity,
  credentialBindingInsertHash,
  idempotencyScope,
  isAuthorityPromotion,
  mutationHash,
  validateCredentialHandleEnvelope,
  validateMutationContext,
  validateOutboxAcknowledgeRequest,
  validateOutboxClaimRequest,
  validateVerifiedAuthorityEvidence,
  authorityEvidenceInsertHash,
} from "./shared";

export const POSTGRES_ADAPTER_STATUS_V1 = Object.freeze({
  adapter: "postgres" as const,
  implemented: true as const,
  conformanceClaim: true as const,
  target: "self_hosted" as const,
});

export type PostgresRepositoryDoctor = SharedPostgresRepositoryDoctor;

export interface PostgresAccountsRepositoryContract extends AccountsRepository {}

export interface PostgresRepositoryAuthority {
  readonly principalRef: string;
  readonly identityRealm: "hasna";
  readonly organizationRef: string;
  readonly catalogIncarnation: string;
  readonly buildDigest: string;
  readonly configurationAttestationDigest: string;
  readonly recoveryLedger: RecoveryLedger;
  readonly credentialVerifier?: CredentialHandleVerifier;
  readonly credentialUseAuthorizer?: CredentialUseAuthorizer;
}

export interface ConnectPostgresAccountsOptions
  extends PostgresConnectionInput,
    PostgresRepositoryAuthority {
  readonly maxConnections?: number;
}

interface PayloadRow {
  readonly payload_json: string;
}

interface IdempotencyRow {
  readonly request_hash: string;
  readonly aggregate_kind: EntityKind;
  readonly event_id: string;
  readonly response_json: string;
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

interface EventRow {
  readonly id: string;
  readonly aggregate_kind: EntityKind;
  readonly aggregate_id: string;
  readonly aggregate_revision: string;
  readonly actor_ref: string;
  readonly reason_code: string;
  readonly occurred_at: string;
}

interface OperationRow {
  readonly id: string;
  readonly kind: CredentialOperation["kind"];
  readonly source_binding_id: string | null;
  readonly target_binding_id: string | null;
  readonly credential_family_id: string;
  readonly capacity_pool_id: string;
  readonly serialization_key: string;
  readonly expected_source_generation: string;
  readonly expected_auth_state_revision: string | null;
  readonly proposed_target_generation: string;
  readonly proposed_auth_state_revision: string | null;
  readonly state: CredentialOperation["state"];
  readonly idempotency_request_hash: string;
  readonly barrier_receipt_digest: string | null;
  readonly completion_receipt_digest: string | null;
  readonly revision: string;
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
  readonly attempt_count: string;
  readonly claim_owner_ref: string | null;
  readonly claim_expires_at: string | null;
  readonly created_at: string;
}

interface InstallationRow {
  readonly deployment_mode: "self_hosted";
  readonly identity_realm: "hasna";
  readonly organization_ref: string;
  readonly schema_version: string;
  readonly build_digest: string;
  readonly configuration_attestation_digest: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string;
  readonly recovery_frontier_hash: string;
  readonly recovery_frontier_signature_digest: string;
  readonly database_frontier_sequence: string;
  readonly database_frontier_hash: string;
  readonly database_frontier_signature_digest: string;
  readonly recovery_hold: boolean;
}

/**
 * Self-hosted Postgres repository core. Every runtime query executes under
 * `SET LOCAL ROLE accounts_runtime` and transaction-local identity settings;
 * no pooled connection carries an Accounts principal between transactions.
 */
export class PostgresAccountsRepository implements PostgresAccountsRepositoryContract {
  private readonly principalRef: string;
  private readonly identityRealm: "hasna";
  private readonly organizationRef: string;
  private readonly catalogIncarnation: string;
  private readonly buildDigest: string;
  private readonly configurationAttestationDigest: string;
  private readonly recoveryLedger: RecoveryLedger;
  private readonly credentialVerifier: CredentialHandleVerifier;
  private readonly credentialUseAuthorizer: CredentialUseAuthorizer;
  private closed = false;

  constructor(
    private readonly client: SQL,
    authority: PostgresRepositoryAuthority,
    private readonly connectionSecurity: "verify-full" | "loopback-test-only" = "verify-full",
    private readonly ownsClient = false,
  ) {
    const runtime = validatePostgresRuntimeContext(authority);
    this.principalRef = runtime.principalRef;
    this.identityRealm = runtime.identityRealm;
    this.organizationRef = validateRef(authority.organizationRef, "organizationRef");
    this.catalogIncarnation = validateRef(authority.catalogIncarnation, "catalogIncarnation");
    this.buildDigest = validateDigest(authority.buildDigest, "buildDigest");
    this.configurationAttestationDigest = validateDigest(
      authority.configurationAttestationDigest,
      "configurationAttestationDigest",
    );
    this.recoveryLedger = authority.recoveryLedger;
    this.credentialVerifier =
      authority.credentialVerifier ?? REJECTING_CREDENTIAL_HANDLE_VERIFIER;
    this.credentialUseAuthorizer =
      authority.credentialUseAuthorizer ?? REJECTING_CREDENTIAL_USE_AUTHORIZER;
  }

  static connect(options: ConnectPostgresAccountsOptions): PostgresAccountsRepository {
    const connection = normalizePostgresConnection(options);
    if (
      options.maxConnections !== undefined &&
      (!Number.isSafeInteger(options.maxConnections) ||
        options.maxConnections < 1 ||
        options.maxConnections > 32)
    ) {
      throw new AccountsError("VALIDATION_FAILED", "Invalid Postgres pool size", {
        details: { field: "maxConnections" },
      });
    }
    let client: SQL;
    try {
      client = new SQL(connection.url, {
        adapter: "postgres",
        tls: connection.tls,
        bigint: true,
        max: options.maxConnections ?? 10,
        connectionTimeout: 10,
        idleTimeout: 30,
        maxLifetime: 900,
        connection: {
          application_name: "hasna-accounts",
          statement_timeout: "15s",
          lock_timeout: "5s",
          idle_in_transaction_session_timeout: "15s",
        },
      });
    } catch {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres client initialization failed", {
        details: { adapter: "postgres" },
      });
    }
    return new PostgresAccountsRepository(
      client,
      options,
      connection.tls === false ? "loopback-test-only" : "verify-full",
      true,
    );
  }

  async initialize(): Promise<void> {
    const ready = await this.withPrincipal("read write", async (transaction) => {
      await this.ensureInstallation(transaction);
      const recovery = await this.readRecoverySnapshot(transaction);
      if (!recovery.matched || recovery.hold) {
        await transaction`
          UPDATE accounts.accounts_installation
          SET recovery_hold = true, updated_at = clock_timestamp()
          WHERE singleton = 1
        `;
        return false;
      }
      return true;
    });
    if (!ready) throw new AccountsError("RECOVERY_HOLD", "Postgres recovery is not ready");
  }

  async get<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
  ): Promise<EntityMap[K] | undefined> {
    return this.withPrincipal("read only", async (transaction) =>
      this.readOne(transaction, kind, id),
    );
  }

  async list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    return this.withPrincipal("read only", async (transaction) => {
      const rows = await selectPayloads(transaction, kind);
      return rows.map((row) => decodePayload(kind, row.payload_json));
    });
  }

  async readEligibilitySnapshot(
    accessMethodId: EntityMap["access_method"]["id"],
  ): Promise<EligibilitySnapshot> {
    return this.withPrincipal(
      "isolation level repeatable read read only",
      async (transaction) => {
        const method = await this.readOne(transaction, "access_method", accessMethodId);
        const entitlement =
          method === undefined
            ? undefined
            : await this.readOne(transaction, "entitlement", method.entitlementId);
        const account =
          entitlement === undefined
            ? undefined
            : await this.readOne(transaction, "account", entitlement.accountId);
        const pool =
          method === undefined
            ? undefined
            : await this.readOne(transaction, "capacity_pool", method.capacityPoolId);
        const capsuleRows = await transaction<PayloadRow[]>`
          SELECT payload_json
          FROM accounts.auth_capsules
          WHERE access_method_id = ${accessMethodId}
          ORDER BY id ASC
        `;
        const bindingRows = await transaction<PayloadRow[]>`
          SELECT payload_json
          FROM accounts.credential_bindings
          WHERE access_method_id = ${accessMethodId}
          ORDER BY id ASC
        `;
        return {
          ...(method === undefined ? {} : { method }),
          ...(entitlement === undefined ? {} : { entitlement }),
          ...(account === undefined ? {} : { account }),
          ...(pool === undefined ? {} : { pool }),
          capsules: capsuleRows.map((row) => decodePayload("auth_capsule", row.payload_json)),
          bindings: bindingRows.map((row) =>
            decodePayload("credential_binding", row.payload_json),
          ),
          recovery: await this.readRecoverySnapshot(transaction),
        } satisfies EligibilitySnapshot;
      },
    );
  }

  async insert<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    if (kind === "credential_binding") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Credential bindings require atomic handle ingestion",
      );
    }
    if (kind === "capacity_pool") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Capacity pools require atomic provider-capacity evidence ingestion",
      );
    }
    validateMutationContext(context);
    this.assertActor(context);
    const record = cloneEntity(kind, input);
    const scope = idempotencyScope("insert", kind, context);
    const hash = mutationHash("insert", kind, record, context);
    try {
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const replay = await this.replay(transaction, kind, scope, hash);
        if (replay !== undefined) return replay;
        await this.appendRecovery(
          transaction,
          {
            kind: "catalog_mutation",
            aggregateKind: kind,
            aggregateId: record.id,
            mutationDigest: hash,
            occurredAt: record.updatedAt,
          },
        );
        await this.insertRecord(transaction, kind, record);
        return this.recordMutation(transaction, kind, record, context, scope, hash);
      });
    } catch (error) {
      throw mapPostgresError(error, kind, record.id);
    }
  }

  async insertCapacityPoolWithAuthorityEvidence(
    input: EntityMap["capacity_pool"],
    inputEvidence: VerifiedAuthorityEvidenceRecord,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap["capacity_pool"]>> {
    validateMutationContext(context);
    this.assertActor(context);
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
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const replay = await this.replay(transaction, "capacity_pool", scope, hash);
        if (replay !== undefined) return replay;
        await this.appendRecovery(transaction, {
          kind: "catalog_mutation",
          aggregateKind: "capacity_pool",
          aggregateId: record.id,
          mutationDigest: hash,
          occurredAt: record.updatedAt,
        });
        await transaction`
          INSERT INTO accounts.evidence_records(
            id, owner_ref, evidence_type, subject_ref, aggregate_kind,
            aggregate_id, aggregate_revision, identity_realm, issuer_ref,
            issuer_class, issuer_incarnation, audience, key_id, issued_at,
            expires_at, nonce, evidence_generation, payload_digest,
            envelope_digest, envelope_json, created_at
          ) VALUES (
            ${evidence.evidenceRef}, ${this.principalRef}, ${evidence.evidenceType},
            ${evidence.subjectRef}, ${evidence.aggregateKind}, ${evidence.aggregateId},
            ${evidence.aggregateRevision}, ${evidence.identityRealm}, ${evidence.issuerRef},
            ${evidence.issuerClass}, ${evidence.issuerIncarnation}, ${evidence.audience},
            ${evidence.keyId}, ${evidence.issuedAt}, ${evidence.expiresAt},
            ${evidence.nonce}, ${evidence.evidenceGeneration}, ${evidence.payloadDigest},
            ${evidence.envelopeDigest}, ${evidence.envelopeJson}, ${record.updatedAt}
          )
        `;
        await this.insertRecord(transaction, "capacity_pool", record);
        return this.recordMutation(
          transaction,
          "capacity_pool",
          record,
          context,
          scope,
          hash,
        );
      });
    } catch (error) {
      throw mapPostgresError(error, "capacity_pool", record.id);
    }
  }

  async insertCredentialBinding(
    input: CredentialBinding,
    inputHandle: CredentialHandleEnvelope,
    context: MutationContext,
  ): Promise<MutationResult<CredentialBinding>> {
    validateMutationContext(context);
    this.assertActor(context);
    const record = cloneEntity("credential_binding", input);
    const handle = Object.freeze({ ...inputHandle });
    validateCredentialHandleEnvelope(record, handle);
    if (handle.audience !== "accounts-self-hosted") {
      throw new AccountsError("INVALID_ACCESS_TARGET", "Credential handle audience is invalid");
    }
    const scope = idempotencyScope("insert", "credential_binding", context);
    const hash = credentialBindingInsertHash(record, handle, context);
    try {
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const replay = await this.replay(transaction, "credential_binding", scope, hash);
        if (replay !== undefined) return replay;
        const expected = await this.buildHandleExpectedClaims(transaction, record);
        const verification = this.credentialVerifier.verify(handle, expected);
        await this.appendRecovery(
          transaction,
          {
            kind: "catalog_mutation",
            aggregateKind: "credential_binding",
            aggregateId: record.id,
            mutationDigest: hash,
            occurredAt: record.updatedAt,
          },
        );
        await this.insertRecord(transaction, "credential_binding", record);
        await transaction`
          INSERT INTO accounts.credential_binding_handles(
            binding_id, owner_ref, opaque_handle, issuer_ref, audience,
            catalog_incarnation, backend_class, audit_digest, issued_at, expires_at
          ) VALUES (
            ${record.id}, ${this.principalRef}, ${handle.opaqueHandle}, ${handle.issuerRef},
            ${handle.audience}, ${handle.catalogIncarnation}, ${handle.backendClass},
            ${verification.credentialHandleAuditDigest}, ${handle.issuedAt},
            ${handle.expiresAt ?? null}
          )
        `;
        return this.recordMutation(
          transaction,
          "credential_binding",
          record,
          context,
          scope,
          hash,
        );
      });
    } catch (error) {
      throw mapPostgresError(error, "credential_binding", record.id);
    }
  }

  async promoteWithAuthorityEvidence<K extends AuthorityPromotionKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    inputEvidence: readonly VerifiedAuthorityEvidenceRecord[],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    validateMutationContext(context);
    this.assertActor(context);
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
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const replay = await this.replay(transaction, kind, scope, hash);
        if (replay !== undefined) return replay;
        const previous = await this.readOneForUpdate(transaction, kind, record.id);
        if (previous === undefined) {
          throw new AccountsError("NOT_FOUND", "Promotion source was not found", {
            details: { aggregateKind: kind, aggregateId: record.id },
          });
        }
        assertReplacement(kind, previous, record, expectedRevision);
        if (!isAuthorityPromotion(kind, previous, record)) {
          throw new AccountsError("INVALID_TRANSITION", "Authority promotion is invalid");
        }
        await this.appendRecovery(
          transaction,
          {
            kind: "catalog_mutation",
            aggregateKind: kind,
            aggregateId: record.id,
            mutationDigest: hash,
            occurredAt: record.updatedAt,
          },
        );
        for (const item of evidence) {
          await transaction`
            INSERT INTO accounts.evidence_records(
              id,
              owner_ref,
              evidence_type,
              subject_ref,
              aggregate_kind,
              aggregate_id,
              aggregate_revision,
              identity_realm,
              issuer_ref,
              issuer_class,
              issuer_incarnation,
              audience,
              key_id,
              issued_at,
              expires_at,
              nonce,
              evidence_generation,
              payload_digest,
              envelope_digest,
              envelope_json,
              created_at
            ) VALUES (
              ${item.evidenceRef},
              ${this.principalRef},
              ${item.evidenceType},
              ${item.subjectRef},
              ${item.aggregateKind},
              ${item.aggregateId},
              ${item.aggregateRevision},
              ${item.identityRealm},
              ${item.issuerRef},
              ${item.issuerClass},
              ${item.issuerIncarnation},
              ${item.audience},
              ${item.keyId},
              ${item.issuedAt},
              ${item.expiresAt},
              ${item.nonce},
              ${item.evidenceGeneration},
              ${item.payloadDigest},
              ${item.envelopeDigest},
              ${item.envelopeJson},
              ${record.updatedAt}
            )
          `;
        }
        await this.updateRecord(transaction, kind, record, expectedRevision);
        return this.recordMutation(transaction, kind, record, context, scope, hash);
      });
    } catch (error) {
      throw mapPostgresError(error, kind, record.id);
    }
  }

  async resolveCredentialHandle(
    bindingId: CredentialBinding["id"],
    grant: CredentialResolutionGrant,
    transport: CredentialResolutionTransport,
  ): Promise<ResolvedCredentialHandle> {
    return this.withPrincipal(
      "isolation level repeatable read read only",
      async (transaction) => {
        const binding = await this.readOne(transaction, "credential_binding", bindingId);
        const [handle] = await transaction<HandleRow[]>`
          SELECT
            opaque_handle,
            issuer_ref,
            audience,
            catalog_incarnation,
            backend_class,
            audit_digest,
            to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS issued_at,
            CASE WHEN expires_at IS NULL THEN NULL
              ELSE to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS expires_at
          FROM accounts.credential_binding_handles
          WHERE binding_id = ${bindingId}
        `;
        const method =
          binding === undefined
            ? undefined
            : await this.readOne(transaction, "access_method", binding.accessMethodId);
        const pool =
          binding === undefined
            ? undefined
            : await this.readOne(transaction, "capacity_pool", binding.capacityPoolId);
        const account =
          pool === undefined
            ? undefined
            : await this.readOne(transaction, "account", pool.accountId);
        const recovery = await this.readRecoverySnapshot(transaction);
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
          handle.catalog_incarnation !== recovery.frontier.catalogIncarnation ||
          (binding.expiresAt !== undefined &&
            Date.parse(binding.expiresAt) <= Date.parse(transport.now)) ||
          (handle.expires_at !== null &&
            Date.parse(handle.expires_at) <= Date.parse(transport.now))
        ) {
          throw new AccountsError("POLICY_DENIED", "Credential handle is not authorized");
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
        };
      },
    );
  }

  async replace<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    validateMutationContext(context);
    this.assertActor(context);
    const record = cloneEntity(kind, input);
    if (kind === "credential_binding" && record.status === "revoked") {
      throw new AccountsError(
        "VALIDATION_FAILED",
        "Credential revocation requires an atomic terminal barrier",
      );
    }
    const scope = idempotencyScope("replace", kind, context);
    const hash = mutationHash("replace", kind, record, context, expectedRevision);
    try {
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const replay = await this.replay(transaction, kind, scope, hash);
        if (replay !== undefined) return replay;
        const previous = await this.readOneForUpdate(transaction, kind, record.id);
        if (previous === undefined) {
          throw new AccountsError("NOT_FOUND", "Record was not found", {
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
        await this.appendRecovery(
          transaction,
          {
            kind: "catalog_mutation",
            aggregateKind: kind,
            aggregateId: record.id,
            mutationDigest: hash,
            occurredAt: record.updatedAt,
          },
        );
        await this.updateRecord(transaction, kind, record, expectedRevision);
        return this.recordMutation(transaction, kind, record, context, scope, hash);
      });
    } catch (error) {
      throw mapPostgresError(error, kind, record.id);
    }
  }

  async findReplacementReplay<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]> | undefined> {
    validateMutationContext(context);
    this.assertActor(context);
    return this.withPrincipal("read only", async (transaction) => {
      const scope = idempotencyScope("replace", kind, context);
      const [row] = await transaction<IdempotencyRow[]>`
        SELECT request_hash, aggregate_kind, event_id::text, response_json
        FROM accounts.idempotency_records
        WHERE scope = ${scope}
      `;
      if (row === undefined) return undefined;
      if (row.aggregate_kind !== kind) {
        throw new AccountsError("IDEMPOTENCY_CONFLICT", "Stored replay kind changed");
      }
      const record = decodePayload(kind, row.response_json);
      const expectedHash = mutationHash("replace", kind, record, context, expectedRevision);
      if (
        row.request_hash !== expectedHash ||
        record.id !== id ||
        record.status !== to ||
        record.revision !== incrementCounter(expectedRevision)
      ) {
        throw new AccountsError("IDEMPOTENCY_CONFLICT", "Replacement replay changed");
      }
      return {
        record,
        eventId: row.event_id as AccountEvent["id"],
        replayed: true,
      };
    });
  }

  async events(): Promise<readonly AccountEvent[]> {
    return this.withPrincipal("read only", async (transaction) => {
      const rows = await transaction<EventRow[]>`
        SELECT
          id::text,
          aggregate_kind,
          aggregate_id::text,
          aggregate_revision::text,
          actor_ref,
          reason_code,
          to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at
        FROM accounts.account_events
        ORDER BY occurred_at ASC, id ASC
      `;
      return rows.map((row) => ({
        id: row.id as AccountEvent["id"],
        aggregateKind: row.aggregate_kind,
        aggregateId: row.aggregate_id as AccountEvent["aggregateId"],
        aggregateRevision: parseCounter(row.aggregate_revision),
        actorRef: row.actor_ref,
        reasonCode: row.reason_code,
        occurredAt: row.occurred_at,
      }));
    });
  }

  async credentialOperations(): Promise<readonly CredentialOperation[]> {
    return this.withPrincipal("read only", async (transaction) => {
      const rows = await selectOperations(transaction);
      return rows.map(decodeOperation);
    });
  }

  async outbox(): Promise<readonly OutboxRecord[]> {
    return this.withPrincipal("read only", async (transaction) => {
      const rows = await selectOutbox(transaction);
      return rows.map(decodeOutbox);
    });
  }

  async claimOutbox(request: OutboxClaimRequest): Promise<readonly OutboxRecord[]> {
    validateOutboxClaimRequest(request);
    return this.withPrincipal("read write", async (transaction) => {
      const rows = await transaction<OutboxRow[]>`
        WITH candidates AS (
          SELECT id
          FROM accounts.outbox
          WHERE status = 'pending'
             OR (status = 'in_flight' AND claim_expires_at <= ${request.now})
          ORDER BY created_at ASC, id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT ${request.limit}
        )
        UPDATE accounts.outbox AS target
        SET status = 'in_flight',
            attempt_count = target.attempt_count + 1,
            claim_owner_ref = ${request.workerRef},
            claim_expires_at = ${request.claimExpiresAt}
        FROM candidates
        WHERE target.id = candidates.id
        RETURNING
          target.id::text,
          target.topic,
          target.aggregate_kind,
          target.aggregate_id,
          target.event_id::text,
          target.payload_digest,
          target.payload_json,
          target.status,
          target.attempt_count::text,
          target.claim_owner_ref,
          CASE WHEN target.claim_expires_at IS NULL THEN NULL
            ELSE to_char(target.claim_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS claim_expires_at,
          to_char(target.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
      `;
      return rows.map(decodeOutbox);
    });
  }

  async acknowledgeOutbox(request: OutboxAcknowledgeRequest): Promise<OutboxRecord> {
    validateOutboxAcknowledgeRequest(request);
    const status = request.outcome === "retry" ? "pending" : request.outcome;
    return this.withPrincipal("read write", async (transaction) => {
      const rows = await transaction<OutboxRow[]>`
        UPDATE accounts.outbox
        SET status = ${status}, claim_owner_ref = NULL, claim_expires_at = NULL
        WHERE id = ${request.outboxId}
          AND status = 'in_flight'
          AND claim_owner_ref = ${request.workerRef}
          AND attempt_count = ${request.expectedAttemptCount}
          AND claim_expires_at > ${request.now}
        RETURNING
          id::text,
          topic,
          aggregate_kind,
          aggregate_id,
          event_id::text,
          payload_digest,
          payload_json,
          status,
          attempt_count::text,
          claim_owner_ref,
          CASE WHEN claim_expires_at IS NULL THEN NULL
            ELSE to_char(claim_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS claim_expires_at,
          to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
      `;
      const row = rows[0];
      if (row === undefined) throw new AccountsError("CONFLICT", "Outbox claim is stale");
      return decodeOutbox(row);
    });
  }

  async revokeNativeGeneration(
    request: NativeRevocationRequest,
  ): Promise<NativeRevocationResult> {
    validateMutationContext(request.context);
    this.assertActor(request.context);
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
      return await this.withPrincipal("isolation level serializable read write", async (transaction) => {
        const [idempotency] = await transaction<
          Array<{ request_hash: string; response_json: string }>
        >`
          SELECT request_hash, response_json
          FROM accounts.idempotency_records
          WHERE scope = ${scope}
        `;
        if (idempotency !== undefined) {
          if (idempotency.request_hash !== hash) {
            throw new AccountsError("IDEMPOTENCY_CONFLICT", "Native revocation changed");
          }
          return this.readNativeRevocationResult(transaction, idempotency.response_json, true);
        }

        const capsule = await this.readOneForUpdate(
          transaction,
          "auth_capsule",
          request.capsuleId,
        );
        const binding = await this.readOneForUpdate(
          transaction,
          "credential_binding",
          request.bindingId,
        );
        const [handle] = await transaction<HandleRow[]>`
          SELECT
            opaque_handle,
            issuer_ref,
            audience,
            catalog_incarnation,
            backend_class,
            audit_digest,
            to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS issued_at,
            CASE WHEN expires_at IS NULL THEN NULL
              ELSE to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS expires_at
          FROM accounts.credential_binding_handles
          WHERE binding_id = ${request.bindingId}
        `;
        const method =
          capsule === undefined
            ? undefined
            : await this.readOneForUpdate(
                transaction,
                "access_method",
                capsule.accessMethodId,
              );
        const pool =
          capsule === undefined
            ? undefined
            : await this.readOneForUpdate(
                transaction,
                "capacity_pool",
                capsule.capacityPoolId,
              );
        if (
          capsule === undefined ||
          binding === undefined ||
          handle === undefined ||
          method === undefined ||
          pool === undefined
        ) {
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
        const [collision] = await transaction<Array<{ collision: number }>>`
          SELECT 1 AS collision
          FROM accounts.credential_bindings
          WHERE id = ${request.barrierBindingId}
             OR (
               credential_family_id = ${binding.credentialFamilyId}
               AND credential_generation = ${preview.barrierBinding.credentialGeneration}
             )
          LIMIT 1
        `;
        const [operationCollision] = await transaction<Array<{ collision: number }>>`
          SELECT 1 AS collision
          FROM accounts.credential_operations
          WHERE id = ${request.operationId}
             OR (
               credential_family_id = ${binding.credentialFamilyId}
               AND serialization_key = ${pool.serializationKey}
               AND state IN ('requested','quiescing','applying','verifying','failed_before_dispatch','failed')
             )
          LIMIT 1
        `;
        if (collision !== undefined || operationCollision !== undefined) {
          throw new AccountsError("CONFLICT", "Native revocation identifiers conflict");
        }

        const recovery = await this.appendRecovery(
          transaction,
          {
            kind: "native_revocation_barrier",
            aggregateKind: "credential_operation",
            aggregateId: request.operationId,
            mutationDigest: hash,
            occurredAt: request.occurredAt,
          },
        );
        const derived = deriveNativeRevocation(source, request, recovery.receiptDigest);
        const [deleted] = await transaction<Array<{ deleted: boolean }>>`
          SELECT accounts.delete_credential_handle_for_revocation(
            ${binding.id}, ${this.principalRef}
          ) AS deleted
        `;
        if (deleted?.deleted !== true) {
          throw new AccountsError(
            "DEPENDENCY_UNAVAILABLE",
            "Credential handle removal was not acknowledged",
          );
        }
        await this.updateRecord(
          transaction,
          "capacity_pool",
          derived.pool,
          pool.revision,
        );
        await this.updateRecord(
          transaction,
          "access_method",
          derived.method,
          method.revision,
        );
        await this.updateRecord(
          transaction,
          "auth_capsule",
          derived.capsule,
          capsule.revision,
        );
        await this.updateRecord(
          transaction,
          "credential_binding",
          derived.retiredBinding,
          binding.revision,
        );
        await this.insertRecord(
          transaction,
          "credential_binding",
          derived.barrierBinding,
        );
        await this.insertOperation(transaction, derived.operation);

        let barrierEventId: AccountEvent["id"] | undefined;
        for (const [kind, record] of [
          ["capacity_pool", derived.pool],
          ["access_method", derived.method],
          ["auth_capsule", derived.capsule],
          ["credential_binding", derived.retiredBinding],
          ["credential_binding", derived.barrierBinding],
        ] as const) {
          const eventId = await this.appendEventAndOutbox(
            transaction,
            kind,
            record as EntityMap[typeof kind],
            request.context,
          );
          if (record.id === derived.barrierBinding.id) barrierEventId = eventId;
        }
        await this.appendCleanupOutbox(transaction, derived.operation);
        if (barrierEventId === undefined) {
          throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Revocation audit event is missing");
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
        await transaction`
          INSERT INTO accounts.idempotency_records(
            scope, owner_ref, request_hash, aggregate_kind, aggregate_id,
            event_id, response_json, created_at
          ) VALUES (
            ${scope}, ${this.principalRef}, ${hash}, 'credential_binding',
            ${derived.barrierBinding.id}, ${barrierEventId}, ${responseJson},
            ${request.occurredAt}
          )
        `;
        return { ...derived, replayed: false };
      });
    } catch (error) {
      throw mapPostgresError(error, "credential_binding", request.bindingId);
    }
  }

  async doctor(): Promise<PostgresRepositoryDoctor> {
    return this.withPrincipal("read only", async (transaction) => {
      const [role] = await transaction<
        Array<{ role_name: string; row_security: string; table_count: string }>
      >`
        SELECT
          current_user AS role_name,
          current_setting('row_security') AS row_security,
          (
            SELECT count(*)::text
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'accounts'
              AND relation.relkind = 'r'
              AND relation.relrowsecurity
              AND relation.relforcerowsecurity
          ) AS table_count
      `;
      if (
        role?.role_name !== "accounts_runtime" ||
        role.row_security !== "on" ||
        Number(role.table_count) < 19
      ) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres RLS checks failed", {
          details: { adapter: "postgres" },
        });
      }
      const [migration] = await transaction<Array<{ version: string; checksum: string }>>`
        SELECT version::text, checksum
        FROM accounts.schema_migrations
        ORDER BY version DESC
        LIMIT 1
      `;
      if (
        migration?.version !== String(POSTGRES_SCHEMA_VERSION) ||
        migration.checksum !== POSTGRES_MIGRATION_CHECKSUM
      ) {
        throw new AccountsError(
          "SCHEMA_CHECKSUM_MISMATCH",
          "Postgres migration attestation changed",
          { details: { adapter: "postgres", schemaVersion: String(POSTGRES_SCHEMA_VERSION) } },
        );
      }
      const recovery = await this.readRecoverySnapshot(transaction);
      return {
        adapter: "postgres",
        schemaVersion: String(POSTGRES_SCHEMA_VERSION),
        migrationChecksum: POSTGRES_MIGRATION_CHECKSUM,
        foreignKeys: true,
        integrity: "ok",
        tls: this.connectionSecurity,
        rls: "forced",
        runtimeRole: "accounts_runtime",
        readiness: recovery.matched && !recovery.hold ? "ready" : "recovery_hold",
        recoveryFrontier: recovery.frontier ?? "unavailable",
        recoveryHold: recovery.hold,
        positiveEligibility: recovery.matched && !recovery.hold,
      };
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.ownsClient) await this.client.close({ timeout: 5 });
  }

  private async withPrincipal<T>(
    mode: string,
    work: (transaction: TransactionSQL) => Promise<T>,
  ): Promise<T> {
    this.assertOpen();
    try {
      return await this.client.begin(mode, async (transaction) => {
        await transaction.unsafe(
          "SET LOCAL ROLE accounts_runtime; SET LOCAL search_path = pg_catalog, accounts; SET LOCAL row_security = on",
        ).simple();
        await transaction`
          SELECT
            set_config('accounts.principal', ${this.principalRef}, true),
            set_config('accounts.identity_realm', ${this.identityRealm}, true)
        `;
        const [context] = await transaction<
          Array<{ principal: string | null; realm: string | null; role_name: string }>
        >`
          SELECT
            accounts.current_principal() AS principal,
            accounts.current_identity_realm() AS realm,
            current_user AS role_name
        `;
        if (
          context?.principal !== this.principalRef ||
          context.realm !== this.identityRealm ||
          context.role_name !== "accounts_runtime"
        ) {
          throw new AccountsError("FORBIDDEN", "Postgres runtime context was not installed");
        }
        const result = await work(transaction);
        await transaction`
          SELECT
            set_config('accounts.principal', '', true),
            set_config('accounts.identity_realm', '', true)
        `;
        await transaction.unsafe("RESET ROLE").simple();
        return result;
      });
    } catch (error) {
      if (error instanceof AccountsError) throw error;
      throw mapPostgresError(error);
    }
  }

  private async ensureInstallation(transaction: TransactionSQL): Promise<InstallationRow> {
    const [existing] = await selectInstallation(transaction, true);
    if (existing !== undefined) {
      if (
        existing.deployment_mode !== "self_hosted" ||
        existing.identity_realm !== this.identityRealm ||
        existing.organization_ref !== this.organizationRef ||
        existing.schema_version !== String(POSTGRES_SCHEMA_VERSION) ||
        existing.build_digest !== this.buildDigest ||
        existing.configuration_attestation_digest !==
          this.configurationAttestationDigest ||
        existing.catalog_incarnation !== this.catalogIncarnation
      ) {
        throw new AccountsError("RECOVERY_HOLD", "Postgres installation authority changed");
      }
      return existing;
    }
    const fresh = this.readVerifiedLedgerFrontier();
    if (
      fresh.catalogIncarnation !== this.catalogIncarnation ||
      fresh.sequence !== parseCounter("0")
    ) {
      throw new AccountsError("RECOVERY_HOLD", "Recovery catalog incarnation changed");
    }
    const now = new Date().toISOString();
    await transaction`
      INSERT INTO accounts.accounts_installation(
        singleton,
        deployment_mode,
        identity_realm,
        organization_ref,
        schema_version,
        build_digest,
        configuration_attestation_digest,
        catalog_incarnation,
        recovery_frontier_sequence,
        recovery_frontier_hash,
        recovery_frontier_signature_digest,
        database_frontier_sequence,
        database_frontier_hash,
        database_frontier_signature_digest,
        recovery_hold,
        created_at,
        updated_at
      ) VALUES (
        1,
        'self_hosted',
        ${this.identityRealm},
        ${this.organizationRef},
        ${String(POSTGRES_SCHEMA_VERSION)},
        ${this.buildDigest},
        ${this.configurationAttestationDigest},
        ${fresh.catalogIncarnation},
        ${fresh.sequence},
        ${fresh.hash},
        ${fresh.signatureDigest},
        ${fresh.sequence},
        ${fresh.hash},
        ${fresh.signatureDigest},
        false,
        ${now},
        ${now}
      )
      ON CONFLICT (singleton) DO NOTHING
    `;
    const [row] = await selectInstallation(transaction, true);
    if (
      row === undefined ||
      row.catalog_incarnation !== this.catalogIncarnation ||
      row.organization_ref !== this.organizationRef ||
      row.build_digest !== this.buildDigest ||
      row.configuration_attestation_digest !== this.configurationAttestationDigest
    ) {
      throw new AccountsError("RECOVERY_HOLD", "Postgres installation authority changed");
    }
    return row;
  }

  private readVerifiedLedgerFrontier(): RecoveryFrontier {
    try {
      const frontier = this.recoveryLedger.readFreshFrontier();
      if (
        !this.recoveryLedger.verifyFrontier(frontier) ||
        !isDigest(frontier.hash) ||
        !isDigest(frontier.signatureDigest)
      ) {
        throw new Error("invalid recovery frontier");
      }
      parseCounter(frontier.sequence, "recoveryFrontierSequence");
      return Object.freeze({ ...frontier });
    } catch {
      throw new AccountsError("RECOVERY_HOLD", "Recovery ledger is unavailable", {
        retryable: true,
      });
    }
  }

  private async readRecoverySnapshot(
    transaction: TransactionSQL,
  ): Promise<RecoverySnapshot> {
    const [row] = await selectInstallation(transaction, false);
    if (row === undefined) return { matched: false, hold: true };
    let fresh: RecoveryFrontier;
    try {
      fresh = this.readVerifiedLedgerFrontier();
    } catch {
      return { matched: false, hold: true };
    }
    const database = installationDatabaseFrontier(row);
    const recorded = installationRecordedFrontier(row);
    const matched =
      row.catalog_incarnation === this.catalogIncarnation &&
      sameFrontier(database, recorded) &&
      sameFrontier(database, fresh);
    return {
      matched,
      hold: row.recovery_hold || !matched,
      ...(matched ? { frontier: database } : {}),
    };
  }

  private async appendRecovery(
    transaction: TransactionSQL,
    entry: RecoveryLedgerEntry,
  ): Promise<RecoveryLedgerReceipt> {
    const row = await this.ensureInstallation(transaction);
    const expected = installationDatabaseFrontier(row);
    const recorded = installationRecordedFrontier(row);
    const fresh = this.readVerifiedLedgerFrontier();
    if (
      row.recovery_hold ||
      !sameFrontier(expected, recorded) ||
      !sameFrontier(expected, fresh)
    ) {
      throw new AccountsError("RECOVERY_HOLD", "Recovery frontier does not match");
    }
    let receipt: RecoveryLedgerReceipt;
    try {
      receipt = this.recoveryLedger.append(expected, entry);
      if (
        !this.recoveryLedger.verifyFrontier(receipt) ||
        receipt.catalogIncarnation !== expected.catalogIncarnation ||
        receipt.sequence !== incrementCounter(expected.sequence) ||
        receipt.previousHash !== expected.hash ||
        !isDigest(receipt.hash) ||
        !isDigest(receipt.signatureDigest) ||
        !isDigest(receipt.entryDigest) ||
        !isDigest(receipt.receiptDigest)
      ) {
        throw new Error("invalid recovery receipt");
      }
    } catch {
      throw new AccountsError("RECOVERY_HOLD", "Recovery receipt was not issued", {
        retryable: true,
      });
    }
    await transaction`
      INSERT INTO accounts.recovery_ledger_receipts(
        sequence,
        identity_realm,
        frontier_hash,
        frontier_signature_digest,
        catalog_incarnation,
        receipt_digest,
        entry_kind,
        aggregate_id,
        created_at
      ) VALUES (
        ${receipt.sequence},
        ${this.identityRealm},
        ${receipt.hash},
        ${receipt.signatureDigest},
        ${receipt.catalogIncarnation},
        ${receipt.receiptDigest},
        ${entry.kind},
        ${entry.aggregateId},
        ${entry.occurredAt}
      )
    `;
    await transaction`
      UPDATE accounts.accounts_installation
      SET recovery_frontier_sequence = ${receipt.sequence},
          recovery_frontier_hash = ${receipt.hash},
          recovery_frontier_signature_digest = ${receipt.signatureDigest},
          database_frontier_sequence = ${receipt.sequence},
          database_frontier_hash = ${receipt.hash},
          database_frontier_signature_digest = ${receipt.signatureDigest},
          recovery_hold = false,
          updated_at = clock_timestamp()
      WHERE singleton = 1
    `;
    return receipt;
  }

  private async readOne<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    id: EntityMap[K]["id"],
  ): Promise<EntityMap[K] | undefined> {
    const row = await selectPayload(transaction, kind, id, false);
    return row === undefined ? undefined : decodePayload(kind, row.payload_json);
  }

  private async readOneForUpdate<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    id: EntityMap[K]["id"],
  ): Promise<EntityMap[K] | undefined> {
    const row = await selectPayload(transaction, kind, id, true);
    return row === undefined ? undefined : decodePayload(kind, row.payload_json);
  }

  private async insertRecord<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    record: EntityMap[K],
  ): Promise<void> {
    const payload = serializeRecordEnvelope(kind, record);
    switch (kind) {
      case "account": {
        const item = record as EntityMap["account"];
        if (item.ownerRef !== this.principalRef) {
          throw new AccountsError("FORBIDDEN", "Account owner does not match runtime principal");
        }
        await transaction`
          INSERT INTO accounts.provider_accounts(
            id, owner_ref, provider_key, provider_subject_ref, status,
            revision, created_at, updated_at, payload_json
          ) VALUES (
            ${item.id}, ${item.ownerRef}, ${item.providerKey},
            ${item.providerSubjectRef ?? null}, ${item.status}, ${item.revision},
            ${item.createdAt}, ${item.updatedAt}, ${payload}
          )
        `;
        if (item.status !== "pending" && item.providerSubjectRef !== undefined) {
          await transaction`
            INSERT INTO accounts.provider_subject_claims(
              provider_key, provider_subject_ref, owner_ref, provider_account_id, claimed_at
            ) VALUES (
              ${item.providerKey}, ${item.providerSubjectRef}, ${item.ownerRef},
              ${item.id}, ${item.createdAt}
            )
            ON CONFLICT (provider_key, provider_subject_ref) DO NOTHING
          `;
          await assertProviderSubjectClaim(transaction, item);
        }
        return;
      }
      case "entitlement": {
        const item = record as EntityMap["entitlement"];
        await this.requireParentOwner(transaction, "account", item.accountId);
        await transaction`
          INSERT INTO accounts.entitlements(
            id, owner_ref, account_id, status, revision, created_at, updated_at, payload_json
          ) VALUES (
            ${item.id}, ${this.principalRef}, ${item.accountId}, ${item.status},
            ${item.revision}, ${item.createdAt}, ${item.updatedAt}, ${payload}
          )
        `;
        return;
      }
      case "capacity_pool": {
        const item = record as EntityMap["capacity_pool"];
        const account = await this.requireParentOwner(transaction, "account", item.accountId);
        await transaction`
          INSERT INTO accounts.capacity_pools(
            id, owner_ref, account_id, provider_key, capacity_domain_ref,
            serialization_key, status, deny_state, revision, capacity_generation,
            deny_generation, created_at, updated_at, payload_json
          ) VALUES (
            ${item.id}, ${this.principalRef}, ${item.accountId}, ${account.providerKey},
            ${item.capacityDomainRef}, ${item.serializationKey}, ${item.status},
            ${item.denyState}, ${item.revision}, ${item.capacityGeneration},
            ${item.denyGeneration}, ${item.createdAt}, ${item.updatedAt}, ${payload}
          )
        `;
        await transaction`
          INSERT INTO accounts.capacity_domain_claims(
            provider_key, capacity_domain_ref, serialization_key, owner_ref,
            capacity_pool_id, claimed_at
          ) VALUES (
            ${account.providerKey}, ${item.capacityDomainRef}, ${item.serializationKey},
            ${this.principalRef}, ${item.id}, ${item.createdAt}
          )
          ON CONFLICT (provider_key, capacity_domain_ref) DO NOTHING
        `;
        await assertCapacityDomainClaim(
          transaction,
          account.providerKey,
          item.capacityDomainRef,
          item.serializationKey,
          this.principalRef,
          item.id,
        );
        return;
      }
      case "access_method": {
        const item = record as EntityMap["access_method"];
        await this.requireParentOwner(transaction, "entitlement", item.entitlementId);
        await this.requireParentOwner(transaction, "capacity_pool", item.capacityPoolId);
        await transaction`
          INSERT INTO accounts.account_lanes(
            id, owner_ref, entitlement_id, capacity_pool_id, access_transport,
            status, revision, created_at, updated_at, payload_json
          ) VALUES (
            ${item.id}, ${this.principalRef}, ${item.entitlementId},
            ${item.capacityPoolId}, ${item.accessTransport}, ${item.status},
            ${item.revision}, ${item.createdAt}, ${item.updatedAt}, ${payload}
          )
        `;
        return;
      }
      case "auth_capsule": {
        const item = record as EntityMap["auth_capsule"];
        if (item.ownerRef !== this.principalRef) {
          throw new AccountsError("FORBIDDEN", "Capsule owner does not match runtime principal");
        }
        await this.requireParentOwner(transaction, "access_method", item.accessMethodId);
        await this.requireParentOwner(transaction, "capacity_pool", item.capacityPoolId);
        await transaction`
          INSERT INTO accounts.auth_capsules(
            id, owner_ref, access_method_id, capacity_pool_id, placement_ref,
            status, auth_generation, auth_state_revision, revision, created_at,
            updated_at, payload_json
          ) VALUES (
            ${item.id}, ${item.ownerRef}, ${item.accessMethodId}, ${item.capacityPoolId},
            ${item.placementRef}, ${item.status}, ${item.authGeneration},
            ${item.authStateRevision}, ${item.revision}, ${item.createdAt},
            ${item.updatedAt}, ${payload}
          )
        `;
        return;
      }
      case "credential_binding": {
        const item = record as EntityMap["credential_binding"];
        await this.requireParentOwner(transaction, "access_method", item.accessMethodId);
        await this.requireParentOwner(transaction, "capacity_pool", item.capacityPoolId);
        if (item.authCapsuleId !== undefined) {
          await this.requireParentOwner(transaction, "auth_capsule", item.authCapsuleId);
        }
        const terminal = terminalColumns(item);
        await transaction`
          INSERT INTO accounts.credential_bindings(
            id, owner_ref, access_method_id, capacity_pool_id, auth_capsule_id,
            credential_family_id, resolver, purpose, status, credential_generation,
            auth_state_revision, revision, created_at, updated_at, payload_json,
            terminal_kind, credential_handle_audit_digest,
            last_usable_credential_generation, revocation_barrier_receipt_digest,
            revoked_at
          ) VALUES (
            ${item.id}, ${this.principalRef}, ${item.accessMethodId},
            ${item.capacityPoolId}, ${item.authCapsuleId ?? null},
            ${item.credentialFamilyId}, ${item.resolver}, ${item.purpose}, ${item.status},
            ${item.credentialGeneration}, ${item.authStateRevision ?? null},
            ${item.revision}, ${item.createdAt}, ${item.updatedAt}, ${payload},
            ${terminal.terminalKind}, ${terminal.credentialHandleAuditDigest},
            ${terminal.lastUsableCredentialGeneration},
            ${terminal.revocationBarrierReceiptDigest}, ${terminal.revokedAt}
          )
        `;
        await transaction`
          INSERT INTO accounts.credential_family_claims(
            credential_family_id, owner_ref, capacity_pool_id, purpose, resolver, claimed_at
          ) VALUES (
            ${item.credentialFamilyId}, ${this.principalRef}, ${item.capacityPoolId},
            ${item.purpose}, ${item.resolver}, ${item.createdAt}
          )
          ON CONFLICT (credential_family_id) DO NOTHING
        `;
        await assertCredentialFamilyClaim(transaction, item, this.principalRef);
      }
    }
  }

  private async updateRecord<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    record: EntityMap[K],
    expectedRevision: Counter,
  ): Promise<void> {
    const payload = serializeRecordEnvelope(kind, record);
    let changed = false;
    switch (kind) {
      case "account": {
        const item = record as EntityMap["account"];
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.provider_accounts
          SET provider_key = ${item.providerKey},
              provider_subject_ref = ${item.providerSubjectRef ?? null},
              status = ${item.status},
              revision = ${item.revision},
              updated_at = ${item.updatedAt},
              payload_json = ${payload}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        if (changed && item.status !== "pending" && item.providerSubjectRef !== undefined) {
          await transaction`
            INSERT INTO accounts.provider_subject_claims(
              provider_key, provider_subject_ref, owner_ref, provider_account_id, claimed_at
            ) VALUES (
              ${item.providerKey}, ${item.providerSubjectRef}, ${this.principalRef},
              ${item.id}, ${item.updatedAt}
            )
            ON CONFLICT (provider_key, provider_subject_ref) DO NOTHING
          `;
          await assertProviderSubjectClaim(transaction, item);
        }
        break;
      }
      case "entitlement": {
        const item = record as EntityMap["entitlement"];
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.entitlements
          SET status = ${item.status}, revision = ${item.revision},
              updated_at = ${item.updatedAt}, payload_json = ${payload}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        break;
      }
      case "capacity_pool": {
        const item = record as EntityMap["capacity_pool"];
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.capacity_pools
          SET status = ${item.status}, deny_state = ${item.denyState},
              revision = ${item.revision}, capacity_generation = ${item.capacityGeneration},
              deny_generation = ${item.denyGeneration}, updated_at = ${item.updatedAt},
              payload_json = ${payload}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        break;
      }
      case "access_method": {
        const item = record as EntityMap["access_method"];
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.account_lanes
          SET status = ${item.status}, revision = ${item.revision},
              updated_at = ${item.updatedAt}, payload_json = ${payload}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        break;
      }
      case "auth_capsule": {
        const item = record as EntityMap["auth_capsule"];
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.auth_capsules
          SET status = ${item.status}, auth_generation = ${item.authGeneration},
              auth_state_revision = ${item.authStateRevision}, revision = ${item.revision},
              updated_at = ${item.updatedAt}, payload_json = ${payload}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        break;
      }
      case "credential_binding": {
        const item = record as EntityMap["credential_binding"];
        const terminal = terminalColumns(item);
        const rows = await transaction<Array<{ id: string }>>`
          UPDATE accounts.credential_bindings
          SET status = ${item.status}, credential_generation = ${item.credentialGeneration},
              auth_state_revision = ${item.authStateRevision ?? null},
              revision = ${item.revision}, updated_at = ${item.updatedAt},
              payload_json = ${payload}, terminal_kind = ${terminal.terminalKind},
              credential_handle_audit_digest = ${terminal.credentialHandleAuditDigest},
              last_usable_credential_generation = ${terminal.lastUsableCredentialGeneration},
              revocation_barrier_receipt_digest = ${terminal.revocationBarrierReceiptDigest},
              revoked_at = ${terminal.revokedAt}
          WHERE id = ${item.id} AND revision = ${expectedRevision}
          RETURNING id::text
        `;
        changed = rows.length === 1;
        break;
      }
    }
    if (!changed) {
      throw new AccountsError("STALE_REVISION", "Concurrent Postgres update detected", {
        details: {
          aggregateKind: kind,
          aggregateId: record.id,
          expectedRevision,
        },
      });
    }
  }

  private async requireParentOwner<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    id: EntityMap[K]["id"],
  ): Promise<EntityMap[K]> {
    const record = await this.readOne(transaction, kind, id);
    if (record === undefined) {
      throw new AccountsError("NOT_FOUND", "Parent record was not found", {
        details: { aggregateKind: kind, aggregateId: id },
      });
    }
    if (
      (kind === "account" &&
        (record as EntityMap["account"]).ownerRef !== this.principalRef) ||
      (kind === "auth_capsule" &&
        (record as EntityMap["auth_capsule"]).ownerRef !== this.principalRef)
    ) {
      throw new AccountsError("FORBIDDEN", "Parent owner does not match runtime principal");
    }
    return record;
  }

  private async buildHandleExpectedClaims(
    transaction: TransactionSQL,
    binding: CredentialBinding,
  ): Promise<CredentialHandleExpectedClaims> {
    const method = await this.requireParentOwner(
      transaction,
      "access_method",
      binding.accessMethodId,
    );
    const pool = await this.requireParentOwner(
      transaction,
      "capacity_pool",
      binding.capacityPoolId,
    );
    const account = await this.requireParentOwner(transaction, "account", pool.accountId);
    if (method.capacityPoolId !== pool.id) {
      throw new AccountsError("INVALID_ACCESS_TARGET", "Credential lineage is inconsistent");
    }
    const capsule =
      binding.resolver === "capsule_local_native"
        ? await this.requireParentOwner(
            transaction,
            "auth_capsule",
            binding.authCapsuleId!,
          )
        : undefined;
    if (
      capsule !== undefined &&
      (capsule.accessMethodId !== method.id || capsule.capacityPoolId !== pool.id)
    ) {
      throw new AccountsError("INVALID_ACCESS_TARGET", "Native credential lineage is inconsistent");
    }
    return {
      audience: "accounts-self-hosted",
      catalogIncarnation: this.catalogIncarnation,
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
    };
  }

  private async recordMutation<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
    scope: string,
    hash: string,
  ): Promise<MutationResult<EntityMap[K]>> {
    const eventId = await this.appendEventAndOutbox(transaction, kind, record, context);
    await transaction`
      INSERT INTO accounts.idempotency_records(
        scope, owner_ref, request_hash, aggregate_kind, aggregate_id,
        event_id, response_json, created_at
      ) VALUES (
        ${scope}, ${this.principalRef}, ${hash}, ${kind}, ${record.id},
        ${eventId}, ${serializeRecordEnvelope(kind, record)}, ${record.updatedAt}
      )
    `;
    return { record: cloneEntity(kind, record), eventId, replayed: false };
  }

  private async appendEventAndOutbox<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): Promise<AccountEvent["id"]> {
    const eventId = newAccountEventId(Date.parse(record.updatedAt));
    await transaction`
      INSERT INTO accounts.account_events(
        id, owner_ref, aggregate_kind, aggregate_id, aggregate_revision,
        actor_ref, reason_code, occurred_at
      ) VALUES (
        ${eventId}, ${this.principalRef}, ${kind}, ${record.id}, ${record.revision},
        ${context.actorRef}, ${context.reasonCode}, ${record.updatedAt}
      )
    `;
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      aggregateKind: kind,
      aggregateId: record.id,
      aggregateRevision: record.revision,
      eventId,
    });
    await transaction`
      INSERT INTO accounts.outbox(
        id, owner_ref, topic, aggregate_kind, aggregate_id, event_id,
        payload_digest, payload_json, status, attempt_count,
        claim_owner_ref, claim_expires_at, created_at
      ) VALUES (
        ${newOutboxId(Date.parse(record.updatedAt))}, ${this.principalRef},
        'accounts.aggregate.changed', ${kind}, ${record.id}, ${eventId},
        ${canonicalSha256(payloadJson)}, ${payloadJson}, 'pending', 0,
        NULL, NULL, ${record.updatedAt}
      )
    `;
    return eventId;
  }

  private async appendCleanupOutbox(
    transaction: TransactionSQL,
    operation: CredentialOperation,
  ): Promise<void> {
    const payloadJson = canonicalJson({
      schemaVersion: "accounts.outbox.v1",
      operationId: operation.id,
      sourceBindingId: operation.sourceBindingId,
      barrierBindingId: operation.targetBindingId,
      barrierReceiptDigest: operation.barrierReceiptDigest,
    });
    await transaction`
      INSERT INTO accounts.outbox(
        id, owner_ref, topic, aggregate_kind, aggregate_id, event_id,
        payload_digest, payload_json, status, attempt_count,
        claim_owner_ref, claim_expires_at, created_at
      ) VALUES (
        ${newOutboxId(Date.parse(operation.updatedAt))}, ${this.principalRef},
        'accounts.capsule.cleanup.requested', 'credential_operation',
        ${operation.id}, NULL, ${canonicalSha256(payloadJson)}, ${payloadJson},
        'pending', 0, NULL, NULL, ${operation.updatedAt}
      )
    `;
  }

  private async insertOperation(
    transaction: TransactionSQL,
    operation: CredentialOperation,
  ): Promise<void> {
    await transaction`
      INSERT INTO accounts.credential_operations(
        id, owner_ref, kind, source_binding_id, target_binding_id,
        credential_family_id, capacity_pool_id, serialization_key,
        expected_source_generation, expected_auth_state_revision,
        proposed_target_generation, proposed_auth_state_revision, state,
        idempotency_request_hash, barrier_receipt_digest,
        completion_receipt_digest, revision, created_at, updated_at
      ) VALUES (
        ${operation.id}, ${this.principalRef}, ${operation.kind},
        ${operation.sourceBindingId ?? null}, ${operation.targetBindingId ?? null},
        ${operation.credentialFamilyId}, ${operation.capacityPoolId},
        ${operation.serializationKey}, ${operation.expectedSourceGeneration},
        ${operation.expectedAuthStateRevision ?? null},
        ${operation.proposedTargetGeneration},
        ${operation.proposedAuthStateRevision ?? null}, ${operation.state},
        ${operation.idempotencyRequestHash}, ${operation.barrierReceiptDigest ?? null},
        ${operation.completionReceiptDigest ?? null}, ${operation.revision},
        ${operation.createdAt}, ${operation.updatedAt}
      )
    `;
  }

  private async replay<K extends EntityKind>(
    transaction: TransactionSQL,
    kind: K,
    scope: string,
    hash: string,
  ): Promise<MutationResult<EntityMap[K]> | undefined> {
    const [row] = await transaction<IdempotencyRow[]>`
      SELECT request_hash, aggregate_kind, event_id::text, response_json
      FROM accounts.idempotency_records
      WHERE scope = ${scope}
    `;
    if (row === undefined) return undefined;
    if (row.request_hash !== hash || row.aggregate_kind !== kind) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency key input changed");
    }
    return {
      record: decodePayload(kind, row.response_json),
      eventId: row.event_id as AccountEvent["id"],
      replayed: true,
    };
  }

  private async readNativeRevocationResult(
    transaction: TransactionSQL,
    responseJson: string,
    replayed: boolean,
  ): Promise<NativeRevocationResult> {
    const value = parseClosedJson(responseJson);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored revocation result is invalid");
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
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored revocation result is invalid");
    }
    const pool = await this.readOne(
      transaction,
      "capacity_pool",
      record.poolId as EntityMap["capacity_pool"]["id"],
    );
    const method = await this.readOne(
      transaction,
      "access_method",
      record.methodId as EntityMap["access_method"]["id"],
    );
    const capsule = await this.readOne(
      transaction,
      "auth_capsule",
      record.capsuleId as EntityMap["auth_capsule"]["id"],
    );
    const retiredBinding = await this.readOne(
      transaction,
      "credential_binding",
      record.retiredBindingId as EntityMap["credential_binding"]["id"],
    );
    const barrierBinding = await this.readOne(
      transaction,
      "credential_binding",
      record.barrierBindingId as EntityMap["credential_binding"]["id"],
    );
    const operationRows = await selectOperations(transaction, record.operationId as string);
    const operationRow = operationRows[0];
    if (
      pool === undefined ||
      method === undefined ||
      capsule === undefined ||
      retiredBinding === undefined ||
      barrierBinding === undefined ||
      operationRow === undefined
    ) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored revocation result is incomplete");
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

  private assertActor(context: MutationContext): void {
    if (context.actorRef !== this.principalRef) {
      throw new AccountsError("FORBIDDEN", "Mutation actor does not match runtime principal");
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres repository is closed", {
        details: { adapter: "postgres" },
      });
    }
  }
}

function decodePayload<K extends EntityKind>(kind: K, source: string): EntityMap[K] {
  const envelope = deserializeRecordEnvelope(source);
  if (envelope.kind !== kind) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Stored Postgres record kind changed", {
      details: { adapter: "postgres" },
    });
  }
  return envelope.data as EntityMap[K];
}

async function selectPayload<K extends EntityKind>(
  transaction: TransactionSQL,
  kind: K,
  id: EntityMap[K]["id"],
  forUpdate: boolean,
): Promise<PayloadRow | undefined> {
  const suffix = forUpdate ? " FOR UPDATE" : "";
  const table = tableFor(kind);
  const rows = await transaction
    .unsafe<PayloadRow[]>(
      `SELECT payload_json FROM accounts.${table} WHERE id = $1${suffix}`,
      [id],
    );
  return rows[0];
}

async function selectPayloads<K extends EntityKind>(
  transaction: TransactionSQL,
  kind: K,
): Promise<PayloadRow[]> {
  return transaction
    .unsafe<PayloadRow[]>(
      `SELECT payload_json FROM accounts.${tableFor(kind)} ORDER BY id ASC`,
    );
}

function tableFor(kind: EntityKind): string {
  switch (kind) {
    case "account":
      return "provider_accounts";
    case "entitlement":
      return "entitlements";
    case "capacity_pool":
      return "capacity_pools";
    case "access_method":
      return "account_lanes";
    case "auth_capsule":
      return "auth_capsules";
    case "credential_binding":
      return "credential_bindings";
  }
}

async function selectInstallation(
  transaction: TransactionSQL,
  forUpdate: boolean,
): Promise<InstallationRow[]> {
  return transaction.unsafe<InstallationRow[]>(`
    SELECT
      deployment_mode,
      identity_realm,
      organization_ref,
      schema_version,
      build_digest,
      configuration_attestation_digest,
      catalog_incarnation,
      recovery_frontier_sequence::text,
      recovery_frontier_hash,
      recovery_frontier_signature_digest,
      database_frontier_sequence::text,
      database_frontier_hash,
      database_frontier_signature_digest,
      recovery_hold
    FROM accounts.accounts_installation
    WHERE singleton = 1
    ${forUpdate ? "FOR UPDATE" : ""}
  `);
}

function installationDatabaseFrontier(row: InstallationRow): RecoveryFrontier {
  return {
    catalogIncarnation: row.catalog_incarnation,
    sequence: parseCounter(row.database_frontier_sequence),
    hash: row.database_frontier_hash,
    signatureDigest: row.database_frontier_signature_digest,
  };
}

function installationRecordedFrontier(row: InstallationRow): RecoveryFrontier {
  return {
    catalogIncarnation: row.catalog_incarnation,
    sequence: parseCounter(row.recovery_frontier_sequence),
    hash: row.recovery_frontier_hash,
    signatureDigest: row.recovery_frontier_signature_digest,
  };
}

function sameFrontier(left: RecoveryFrontier, right: RecoveryFrontier): boolean {
  return (
    left.catalogIncarnation === right.catalogIncarnation &&
    left.sequence === right.sequence &&
    left.hash === right.hash &&
    left.signatureDigest === right.signatureDigest
  );
}

async function selectOperations(
  transaction: TransactionSQL,
  operationId?: string,
): Promise<OperationRow[]> {
  return transaction.unsafe<OperationRow[]>(
    `SELECT
      id::text,
      kind,
      source_binding_id::text,
      target_binding_id::text,
      credential_family_id,
      capacity_pool_id::text,
      serialization_key,
      expected_source_generation::text,
      expected_auth_state_revision::text,
      proposed_target_generation::text,
      proposed_auth_state_revision::text,
      state,
      idempotency_request_hash,
      barrier_receipt_digest,
      completion_receipt_digest,
      revision::text,
      to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
      to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
    FROM accounts.credential_operations
    ${operationId === undefined ? "" : "WHERE id = $1"}
    ORDER BY id ASC`,
    operationId === undefined ? [] : [operationId],
  );
}

function decodeOperation(row: OperationRow): CredentialOperation {
  return {
    id: row.id as CredentialOperation["id"],
    kind: row.kind,
    ...(row.source_binding_id === null
      ? {}
      : {
          sourceBindingId:
            row.source_binding_id as NonNullable<CredentialOperation["sourceBindingId"]>,
        }),
    ...(row.target_binding_id === null
      ? {}
      : {
          targetBindingId:
            row.target_binding_id as NonNullable<CredentialOperation["targetBindingId"]>,
        }),
    credentialFamilyId: row.credential_family_id,
    capacityPoolId: row.capacity_pool_id as CredentialOperation["capacityPoolId"],
    serializationKey: row.serialization_key,
    expectedSourceGeneration: parseCounter(row.expected_source_generation),
    ...(row.expected_auth_state_revision === null
      ? {}
      : { expectedAuthStateRevision: parseCounter(row.expected_auth_state_revision) }),
    proposedTargetGeneration: parseCounter(row.proposed_target_generation),
    ...(row.proposed_auth_state_revision === null
      ? {}
      : { proposedAuthStateRevision: parseCounter(row.proposed_auth_state_revision) }),
    state: row.state,
    idempotencyRequestHash: row.idempotency_request_hash,
    ...(row.barrier_receipt_digest === null
      ? {}
      : { barrierReceiptDigest: row.barrier_receipt_digest }),
    ...(row.completion_receipt_digest === null
      ? {}
      : { completionReceiptDigest: row.completion_receipt_digest }),
    revision: parseCounter(row.revision),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function selectOutbox(transaction: TransactionSQL): Promise<OutboxRow[]> {
  return transaction<OutboxRow[]>`
    SELECT
      id::text,
      topic,
      aggregate_kind,
      aggregate_id,
      event_id::text,
      payload_digest,
      payload_json,
      status,
      attempt_count::text,
      claim_owner_ref,
      CASE WHEN claim_expires_at IS NULL THEN NULL
        ELSE to_char(claim_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS claim_expires_at,
      to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
    FROM accounts.outbox
    ORDER BY created_at ASC, id ASC
  `;
}

function decodeOutbox(row: OutboxRow): OutboxRecord {
  return {
    id: row.id as OutboxRecord["id"],
    topic: row.topic,
    aggregateKind: row.aggregate_kind,
    aggregateId: row.aggregate_id,
    ...(row.event_id === null
      ? {}
      : { eventId: row.event_id as AccountEvent["id"] }),
    payloadDigest: row.payload_digest,
    payloadJson: row.payload_json,
    status: row.status,
    attemptCount: parseCounter(row.attempt_count),
    ...(row.claim_owner_ref === null ? {} : { claimOwnerRef: row.claim_owner_ref }),
    ...(row.claim_expires_at === null ? {} : { claimExpiresAt: row.claim_expires_at }),
    createdAt: row.created_at,
  };
}

function terminalColumns(binding: CredentialBinding): {
  readonly terminalKind: string | null;
  readonly credentialHandleAuditDigest: string | null;
  readonly lastUsableCredentialGeneration: Counter | null;
  readonly revocationBarrierReceiptDigest: string | null;
  readonly revokedAt: string | null;
} {
  if (binding.status !== "revoked") {
    return {
      terminalKind: null,
      credentialHandleAuditDigest: null,
      lastUsableCredentialGeneration: null,
      revocationBarrierReceiptDigest: null,
      revokedAt: null,
    };
  }
  if (binding.terminalKind === "retired_handle_generation") {
    return {
      terminalKind: binding.terminalKind,
      credentialHandleAuditDigest: binding.credentialHandleAuditDigest,
      lastUsableCredentialGeneration: null,
      revocationBarrierReceiptDigest: binding.revocationBarrierReceiptDigest,
      revokedAt: binding.revokedAt,
    };
  }
  return {
    terminalKind: binding.terminalKind,
    credentialHandleAuditDigest: null,
    lastUsableCredentialGeneration: binding.lastUsableCredentialGeneration,
    revocationBarrierReceiptDigest: binding.revocationBarrierReceiptDigest,
    revokedAt: binding.revokedAt,
  };
}

async function assertProviderSubjectClaim(
  transaction: TransactionSQL,
  account: EntityMap["account"],
): Promise<void> {
  const [claim] = await transaction<
    Array<{ owner_ref: string; provider_account_id: string }>
  >`
    SELECT owner_ref, provider_account_id::text
    FROM accounts.provider_subject_claims
    WHERE provider_key = ${account.providerKey}
      AND provider_subject_ref = ${account.providerSubjectRef!}
  `;
  if (
    claim?.owner_ref !== account.ownerRef ||
    claim.provider_account_id !== account.id
  ) {
    throw new AccountsError("CONFLICT", "Provider subject is permanently claimed");
  }
}

async function assertCapacityDomainClaim(
  transaction: TransactionSQL,
  providerKey: string,
  capacityDomainRef: string,
  serializationKey: string,
  ownerRef: string,
  poolId: string,
): Promise<void> {
  const [claim] = await transaction<
    Array<{ serialization_key: string; owner_ref: string; capacity_pool_id: string }>
  >`
    SELECT serialization_key, owner_ref, capacity_pool_id::text
    FROM accounts.capacity_domain_claims
    WHERE provider_key = ${providerKey}
      AND capacity_domain_ref = ${capacityDomainRef}
  `;
  if (
    claim?.serialization_key !== serializationKey ||
    claim.owner_ref !== ownerRef ||
    claim.capacity_pool_id !== poolId
  ) {
    throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Capacity domain is claimed");
  }
}

async function assertCredentialFamilyClaim(
  transaction: TransactionSQL,
  binding: CredentialBinding,
  ownerRef: string,
): Promise<void> {
  const [claim] = await transaction<
    Array<{
      owner_ref: string;
      capacity_pool_id: string;
      purpose: string;
      resolver: string;
    }>
  >`
    SELECT owner_ref, capacity_pool_id::text, purpose, resolver
    FROM accounts.credential_family_claims
    WHERE credential_family_id = ${binding.credentialFamilyId}
  `;
  if (
    claim?.owner_ref !== ownerRef ||
    claim.capacity_pool_id !== binding.capacityPoolId ||
    claim.purpose !== binding.purpose ||
    claim.resolver !== binding.resolver
  ) {
    throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Credential family is claimed");
  }
}

export function postgresSqlState(error: unknown): string | undefined {
  if (error === null || typeof error !== "object") return undefined;
  const errno = Reflect.get(error, "errno");
  if (typeof errno === "string" && /^[0-9A-Z]{5}$/.test(errno)) return errno;
  const code = Reflect.get(error, "code");
  return typeof code === "string" && /^[0-9A-Z]{5}$/.test(code) ? code : undefined;
}

function mapPostgresError(
  error: unknown,
  kind?: EntityKind,
  id?: string,
): AccountsError {
  if (error instanceof AccountsError) return error;
  const details =
    kind === undefined || id === undefined
      ? { adapter: "postgres" as const }
      : { adapter: "postgres" as const, aggregateKind: kind, aggregateId: id };
  switch (postgresSqlState(error)) {
    case "23505":
    case "23P01":
      return new AccountsError("CONFLICT", "Postgres uniqueness constraint rejected input", {
        details,
      });
    case "23503":
      return new AccountsError("NOT_FOUND", "Postgres parent record was not found", {
        details,
      });
    case "23514":
    case "22P02":
    case "22007":
      return new AccountsError("VALIDATION_FAILED", "Postgres constraint rejected input", {
        details,
      });
    case "42501":
      return new AccountsError("FORBIDDEN", "Postgres runtime role rejected the operation", {
        details,
      });
    case "40001":
    case "40P01":
    case "55P03":
      return new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres transaction must retry", {
        retryable: true,
        details,
      });
    default:
      return new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres operation failed", {
        retryable: true,
        details,
      });
  }
}

function validateRef(value: string, field: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid Postgres authority reference", {
      details: { field },
    });
  }
  return value;
}

function isDigest(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(value);
}

function validateDigest(value: string, field: string): string {
  if (!isDigest(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid Postgres authority digest", {
      details: { field },
    });
  }
  return value;
}

// Kept referenced so an adapter build cannot silently drift from the finalized
// package contract while remaining isolated from public index wiring.
export const POSTGRES_ACCOUNTS_CONTRACT_SHA256 = ACCOUNTS_V1_CONTRACT_SHA256;
