import { Database } from "bun:sqlite";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";

import { AccountsError } from "../errors";
import type { Counter } from "../domain/counter";
import { newAccountEventId } from "../domain/ids";
import type { EntityKind, EntityMap } from "../domain/models";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";
import type {
  AccountEvent,
  AccountsRepository,
  MutationContext,
  MutationResult,
  RepositoryDoctor,
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
    this.database = new Database(filename, { create: true, strict: true, safeIntegers: true });
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
        "SELECT id, aggregate_kind, aggregate_id, aggregate_revision, actor_ref, reason_code, occurred_at FROM account_events ORDER BY id COLLATE BINARY ASC",
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

  async doctor(): Promise<RepositoryDoctor> {
    this.assertOpen();
    const foreignKeys = this.database.query("PRAGMA foreign_keys").values()[0]?.[0] === 1n;
    const journal = this.database.query("PRAGMA journal_mode").values()[0]?.[0];
    const integrity = this.database.query("PRAGMA integrity_check").values()[0]?.[0];
    if (foreignKeys !== true || integrity !== "ok") {
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
      const transaction = this.database.transaction(() => {
        this.database.exec(SQLITE_MIGRATION_V1);
        this.database
          .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)")
          .run(1n, SQLITE_MIGRATION_CHECKSUM, new Date().toISOString());
      });
      transaction.exclusive();
    }
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
        this.database
          .query("INSERT INTO capacity_pools(id, account_id, capacity_domain_ref, serialization_key, status, deny_state, revision, capacity_generation, deny_generation, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
          .run(item.id, item.accountId, item.capacityDomainRef, item.serializationKey, item.status, item.denyState, BigInt(item.revision), BigInt(item.capacityGeneration), BigInt(item.denyGeneration), item.createdAt, item.updatedAt, payload);
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
    chmodSync(dirname(this.filename), 0o700);
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
  if (!existsSync(parent)) mkdirSync(parent, { recursive: true, mode: 0o700 });
  const root = parse(filename).root;
  const relative = filename.slice(root.length).split("/").filter(Boolean);
  let current = root;
  for (const component of relative) {
    current = join(current, component);
    if (!existsSync(current)) continue;
    const status = lstatSync(current);
    if (status.isSymbolicLink()) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite path contains a symbolic link", {
        details: { adapter: "sqlite" },
      });
    }
  }
  const parentStatus = statSync(realpathSync(parent));
  if (parentStatus.uid !== process.getuid?.() || (parentStatus.mode & 0o077) !== 0) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite parent directory is not owner-only", {
      details: { adapter: "sqlite" },
    });
  }
  if (existsSync(filename)) {
    const fileStatus = statSync(filename);
    if (fileStatus.uid !== process.getuid?.() || (fileStatus.mode & 0o077) !== 0) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "SQLite database is not owner-only", {
        details: { adapter: "sqlite" },
      });
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
