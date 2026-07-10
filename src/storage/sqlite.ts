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
import { incrementCounter, type Counter } from "../domain/counter";
import { newAccountEventId } from "../domain/ids";
import type { EntityKind, EntityMap } from "../domain/models";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";
import type {
  AccountEvent,
  AccountsRepository,
  MutationContext,
  MutationResult,
  RepositoryDoctor,
  EligibilitySnapshot,
} from "./repository";
import {
  assertReplacement,
  cloneEntity,
  idempotencyScope,
  mutationHash,
  validateMutationContext,
} from "./shared";
import {
  SQLITE_MIGRATION_CHECKSUM,
  SQLITE_MIGRATION_V1,
  SQLITE_SCHEMA_VERSION,
} from "./sqlite-migrations";

const TABLES: Readonly<Record<EntityKind, string>> = {
  account: "provider_accounts",
  entitlement: "entitlements",
  capacity_pool: "capacity_pools",
  access_method: "access_methods",
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

export class SQLiteAccountsRepository implements AccountsRepository {
  private readonly database: Database;
  private closed = false;

  constructor(readonly filename: string) {
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
      } satisfies EligibilitySnapshot;
    });
    return transaction.deferred();
  }

  async insert<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    const scope = idempotencyScope("insert", kind, context);
    const hash = mutationHash("insert", kind, record, context);
    try {
      const transaction = this.database.transaction(() => {
        const replay = this.replay<K>(kind, scope, hash);
        if (replay !== undefined) return replay;
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

  async replace<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
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
        assertReplacement(kind, previous, record, expectedRevision);
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
    return {
      adapter: "sqlite",
      schemaVersion: SQLITE_SCHEMA_VERSION.toString(10),
      migrationChecksum: SQLITE_MIGRATION_CHECKSUM,
      foreignKeys: true,
      journalMode: journal === "wal" ? "wal" : "memory",
      integrity: "ok",
      readiness: "metadata_only",
      recoveryFrontier: "unavailable",
      positiveEligibility: false,
    };
  }

  async close(): Promise<void> {
    if (!this.closed) {
      this.database.close();
      this.closed = true;
      this.secureFiles();
    }
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
      const current = rows.find((row) => row.version === 1n);
      if (current !== undefined && current.checksum !== SQLITE_MIGRATION_CHECKSUM) {
        throw new AccountsError("SCHEMA_CHECKSUM_MISMATCH", "Database schema checksum mismatch", {
          details: { adapter: "sqlite" },
        });
      }
      if (current === undefined) {
        this.database.exec(SQLITE_MIGRATION_V1);
        this.database
          .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
          .run(1n, SQLITE_MIGRATION_CHECKSUM);
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
          .query("INSERT INTO access_methods(id, entitlement_id, capacity_pool_id, access_transport, status, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
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
        this.database
          .query("INSERT INTO credential_bindings(id, access_method_id, capacity_pool_id, auth_capsule_id, credential_family_id, resolver, purpose, status, credential_generation, auth_state_revision, revision, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.accessMethodId, item.capacityPoolId, item.authCapsuleId ?? null, item.credentialFamilyId, item.resolver, item.purpose, item.status, BigInt(item.credentialGeneration), item.authStateRevision === undefined ? null : BigInt(item.authStateRevision), BigInt(item.revision), item.createdAt, item.updatedAt, payload);
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
          .query("UPDATE access_methods SET entitlement_id=?, capacity_pool_id=?, access_transport=?, status=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
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
        changes = this.database
          .query("UPDATE credential_bindings SET access_method_id=?, capacity_pool_id=?, auth_capsule_id=?, credential_family_id=?, resolver=?, purpose=?, status=?, credential_generation=?, auth_state_revision=?, revision=?, updated_at=?, payload_json=? WHERE id=? AND revision=?")
          .run(item.accessMethodId, item.capacityPoolId, item.authCapsuleId ?? null, item.credentialFamilyId, item.resolver, item.purpose, item.status, BigInt(item.credentialGeneration), item.authStateRevision === undefined ? null : BigInt(item.authStateRevision), BigInt(item.revision), item.updatedAt, payload, item.id, BigInt(expected)).changes;
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
    const eventId = newAccountEventId(Date.parse(record.updatedAt));
    this.database
      .query("INSERT INTO account_events(id, aggregate_kind, aggregate_id, aggregate_revision, actor_ref, reason_code, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(eventId, kind, record.id, BigInt(record.revision), context.actorRef, context.reasonCode, record.updatedAt);
    this.database
      .query("INSERT INTO idempotency_records(scope, request_hash, aggregate_kind, aggregate_id, event_id, response_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(scope, hash, kind, record.id, eventId, serializeRecordEnvelope(kind, record), record.updatedAt);
    return { record: cloneEntity(kind, record), eventId, replayed: false };
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
