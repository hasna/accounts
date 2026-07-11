import { Database } from "bun:sqlite";
import {
  closeSync,
  chmodSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

import { AccountsError } from "../errors";
import { parseCounter, type Counter } from "../domain/counter";
import { isUuidV7 } from "../domain/ids";
import {
  ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1,
  ONLINE_GENERATION_CONTEXT_FIELDS_V1,
} from "./constants";
import type {
  AccountsOnlineGenerationSourceRequestV1,
  AccountsSlotEligibilityAdapterTrustV1,
  AccountsSlotEligibilityPort,
  AccountsSlotEligibilityRequestV1,
  AccountsSlotEligibilitySource,
} from "./types";
import { createAccountsSlotEligibilityAdapter } from "./adapter";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const MAX_WIRE_BYTES = 98_304;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CLOEXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;

export interface AccountsRecoveryFrontierV1 {
  readonly catalog_incarnation: string;
  readonly sequence: Counter;
  readonly hash: string;
}

export interface AccountsRecoveryFrontierPort {
  readFreshFrontier(): AccountsRecoveryFrontierV1 | Promise<AccountsRecoveryFrontierV1>;
}

export interface SQLiteAccountsSlotEligibilitySourceOptions {
  readonly path: string;
  readonly recoveryFrontier: AccountsRecoveryFrontierPort;
}

export interface SQLiteAccountsSlotEligibilityPortOptions
  extends SQLiteAccountsSlotEligibilitySourceOptions {
  readonly trust: AccountsSlotEligibilityAdapterTrustV1;
}

export interface SQLiteAccountsSlotEligibilityPort extends AccountsSlotEligibilityPort {
  readonly close: () => void;
}

interface EvidenceRow {
  readonly wire_jcs: Uint8Array;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string | number | bigint;
  readonly recovery_frontier_hash: string;
}

interface StateRow {
  readonly current_deny: bigint;
  readonly runtime_state_revision: bigint;
}

/**
 * Production read-side composition for ACC-041. It stores only already signed,
 * exact wire evidence and never invents a missing issuer, signature, frontier,
 * generation, or authority field. Issuance/provisioning is a separate trusted
 * workflow; this source intentionally exposes no seed or mutation shortcut.
 */
export class SQLiteAccountsSlotEligibilitySource implements AccountsSlotEligibilitySource {
  private readonly database: Database;
  private readonly recoveryFrontier: AccountsRecoveryFrontierPort;
  private closed = false;

  constructor(options: SQLiteAccountsSlotEligibilitySourceOptions) {
    this.recoveryFrontier = options.recoveryFrontier;
    const path = prepareDatabasePath(options.path);
    const previousUmask = process.umask(0o077);
    try {
      this.database = new Database(path, { create: false, strict: true, safeIntegers: true });
    } finally {
      process.umask(previousUmask);
    }
    this.database.exec("PRAGMA journal_mode=WAL");
    this.database.exec("PRAGMA synchronous=FULL");
    this.database.exec("PRAGMA foreign_keys=ON");
    this.database.exec("PRAGMA busy_timeout=5000");
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS accounts_v10_signed_evidence (
        account_lane_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('SLOT','ONLINE')),
        decision TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY')),
        wire_jcs BLOB NOT NULL CHECK (length(wire_jcs) BETWEEN 1 AND ${MAX_WIRE_BYTES}),
        catalog_incarnation TEXT NOT NULL,
        recovery_frontier_sequence TEXT NOT NULL,
        recovery_frontier_hash TEXT NOT NULL,
        PRIMARY KEY(account_lane_id, phase, decision)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS accounts_v10_runtime_state (
        account_lane_id TEXT PRIMARY KEY,
        current_deny INTEGER NOT NULL CHECK (current_deny IN (0,1))
      ) STRICT;
      CREATE TABLE IF NOT EXISTS accounts_v10_runtime_revision (
        account_lane_id TEXT PRIMARY KEY,
        runtime_state_revision INTEGER NOT NULL
          CHECK (runtime_state_revision BETWEEN 1 AND 9223372036854775807)
      ) STRICT;
    `);
    this.database.exec(`
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_state_insert
      AFTER INSERT ON accounts_v10_runtime_state
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (NEW.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_state_deny
      AFTER UPDATE OF current_deny ON accounts_v10_runtime_state
      WHEN NEW.current_deny != OLD.current_deny
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (NEW.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_state_lane
      AFTER UPDATE OF account_lane_id ON accounts_v10_runtime_state
      WHEN NEW.account_lane_id != OLD.account_lane_id
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (OLD.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (NEW.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_state_delete
      AFTER DELETE ON accounts_v10_runtime_state
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (OLD.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_evidence_insert
      AFTER INSERT ON accounts_v10_signed_evidence
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (NEW.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_evidence_delete
      AFTER DELETE ON accounts_v10_signed_evidence
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (OLD.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_evidence_update_same_lane
      AFTER UPDATE ON accounts_v10_signed_evidence
      WHEN NEW.account_lane_id = OLD.account_lane_id
      BEGIN
        UPDATE accounts_v10_runtime_revision
           SET runtime_state_revision = runtime_state_revision + 1
         WHERE account_lane_id = NEW.account_lane_id;
      END;
      CREATE TRIGGER IF NOT EXISTS accounts_v10_runtime_revision_evidence_update_new_lane
      AFTER UPDATE ON accounts_v10_signed_evidence
      WHEN NEW.account_lane_id != OLD.account_lane_id
      BEGIN
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (OLD.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
        INSERT INTO accounts_v10_runtime_revision(account_lane_id, runtime_state_revision)
        VALUES (NEW.account_lane_id, 1)
        ON CONFLICT(account_lane_id) DO UPDATE
          SET runtime_state_revision = runtime_state_revision + 1;
      END;
    `);
    this.database.exec(`
      INSERT OR IGNORE INTO accounts_v10_runtime_revision(
        account_lane_id, runtime_state_revision
      ) SELECT account_lane_id, 1 FROM accounts_v10_runtime_state;
      INSERT OR IGNORE INTO accounts_v10_runtime_revision(
        account_lane_id, runtime_state_revision
      ) SELECT DISTINCT account_lane_id, 1 FROM accounts_v10_signed_evidence;
    `);
    secureSqliteFiles(path);
  }

  async getSlotEligibility(request: AccountsSlotEligibilityRequestV1): Promise<Uint8Array> {
    return this.read("SLOT", slotRequestAccountLaneId(request));
  }

  async checkOnlineGeneration(
    request: AccountsOnlineGenerationSourceRequestV1,
  ): Promise<Uint8Array> {
    return this.read("ONLINE", onlineRequestAccountLaneId(request));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.database.close();
  }

  private async read(phase: "SLOT" | "ONLINE", laneId: string): Promise<Uint8Array> {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Accounts evidence source is closed");
    }
    let transactionOpen = false;
    try {
      this.database.exec("BEGIN IMMEDIATE");
      transactionOpen = true;
    } catch {
      throw new AccountsError(
        "DEPENDENCY_UNAVAILABLE",
        "Accounts signed evidence decision lock is unavailable",
        { retryable: true },
      );
    }
    try {
      const before = await this.readExternalFrontier();
      const state = this.database
        .query<StateRow, [string]>(`
          SELECT state.current_deny, revision.runtime_state_revision
          FROM accounts_v10_runtime_state AS state
          JOIN accounts_v10_runtime_revision AS revision USING(account_lane_id)
          WHERE state.account_lane_id=?
        `)
        .get(laneId);
      if (state === null) {
        throw new AccountsError("NOT_FOUND", "Signed Accounts state is unavailable");
      }
      const selected = this.database
        .query<EvidenceRow, [string, string, string]>(`
          SELECT wire_jcs, catalog_incarnation, recovery_frontier_sequence,
                 recovery_frontier_hash
            FROM accounts_v10_signed_evidence
           WHERE account_lane_id=? AND phase=? AND decision=?
        `)
        .get(laneId, phase, state.current_deny === 1n ? "DENY" : "ALLOW");
      if (selected === null) {
        throw new AccountsError("NOT_FOUND", "Signed Accounts evidence is unavailable");
      }
      const after = await this.readExternalFrontier();
      const revalidatedState = this.database
        .query<StateRow, [string]>(`
          SELECT state.current_deny, revision.runtime_state_revision
          FROM accounts_v10_runtime_state AS state
          JOIN accounts_v10_runtime_revision AS revision USING(account_lane_id)
          WHERE state.account_lane_id=?
        `)
        .get(laneId);
      if (
        revalidatedState === null ||
        revalidatedState.current_deny !== state.current_deny ||
        revalidatedState.runtime_state_revision !== state.runtime_state_revision
      ) {
        throw new AccountsError("RECOVERY_HOLD", "Accounts deny state changed during decision");
      }
      const databaseFrontier = validateFrontier({
        catalog_incarnation: selected.catalog_incarnation,
        sequence: parseCounter(selected.recovery_frontier_sequence, "recovery_frontier_sequence"),
        hash: selected.recovery_frontier_hash,
      });
      if (!sameFrontier(before, after) || !sameFrontier(databaseFrontier, after)) {
        throw new AccountsError("RECOVERY_HOLD", "Accounts recovery frontier is not coherent");
      }
      const wire = selected.wire_jcs;
      if (!(wire instanceof Uint8Array) || wire.byteLength === 0 || wire.byteLength > MAX_WIRE_BYTES) {
        throw new AccountsError("RECOVERY_HOLD", "Stored Accounts evidence is malformed");
      }
      const result = Uint8Array.from(wire);
      this.database.exec("COMMIT");
      transactionOpen = false;
      return result;
    } catch (error) {
      if (transactionOpen) {
        try {
          this.database.exec("ROLLBACK");
        } catch {
          throw new AccountsError("RECOVERY_HOLD", "Accounts evidence rollback failed");
        }
      }
      if (error instanceof AccountsError) throw error;
      throw new AccountsError(
        "DEPENDENCY_UNAVAILABLE",
        "Accounts signed evidence database is unavailable",
        { retryable: true },
      );
    }
  }

  private async readExternalFrontier(): Promise<AccountsRecoveryFrontierV1> {
    if (
      this.recoveryFrontier === null ||
      typeof this.recoveryFrontier !== "object" ||
      typeof this.recoveryFrontier.readFreshFrontier !== "function"
    ) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Recovery frontier reader is unavailable");
    }
    try {
      return validateFrontier(await this.recoveryFrontier.readFreshFrontier());
    } catch (error) {
      if (error instanceof AccountsError) throw error;
      throw new AccountsError(
        "DEPENDENCY_UNAVAILABLE",
        "Recovery frontier reader is unavailable",
        { retryable: true },
      );
    }
  }
}

/** Package-safe composition: callers receive verified evidence, never raw signed bytes. */
export function createSQLiteAccountsSlotEligibilityPort(
  options: SQLiteAccountsSlotEligibilityPortOptions,
): SQLiteAccountsSlotEligibilityPort {
  const source = new SQLiteAccountsSlotEligibilitySource({
    path: options.path,
    recoveryFrontier: options.recoveryFrontier,
  });
  try {
    const adapter = createAccountsSlotEligibilityAdapter(source, options.trust);
    return Object.freeze({
      getSlotEligibility: adapter.getSlotEligibility,
      checkOnlineGeneration: adapter.checkOnlineGeneration,
      close: () => source.close(),
    });
  } catch (error) {
    source.close();
    throw error;
  }
}

function closedRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError("VALIDATION_FAILED", `${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AccountsError("VALIDATION_FAILED", `${label} must be a plain object`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new AccountsError("VALIDATION_FAILED", `${label} contains symbol fields`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new AccountsError("VALIDATION_FAILED", `${label} is not closed`);
  }
  const record = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new AccountsError("VALIDATION_FAILED", `${label} contains accessor fields`);
    }
    record[key] = descriptor.value;
  }
  return record;
}

function validatedAccountLaneId(value: unknown, label: string): string {
  if (typeof value !== "string" || !isUuidV7(value)) {
    throw new AccountsError("VALIDATION_FAILED", `${label} account lane is invalid`);
  }
  return value;
}

function slotRequestAccountLaneId(value: AccountsSlotEligibilityRequestV1): string {
  const request = closedRecord(value, [
    "schema_version",
    "account_lane_id",
    "data_classification",
    "destination_policy_class",
    "model",
    "operation",
  ], "SlotEligibility source request");
  if (request.schema_version !== ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1) {
    throw new AccountsError("VALIDATION_FAILED", "SlotEligibility request schema is invalid");
  }
  return validatedAccountLaneId(request.account_lane_id, "SlotEligibility request");
}

function onlineRequestAccountLaneId(value: AccountsOnlineGenerationSourceRequestV1): string {
  const request = closedRecord(
    value,
    ["context", "slot_eligibility_digest"],
    "Online generation source request",
  );
  if (typeof request.slot_eligibility_digest !== "string" || !DIGEST.test(request.slot_eligibility_digest)) {
    throw new AccountsError("VALIDATION_FAILED", "Online generation Slot digest is invalid");
  }
  const context = closedRecord(
    request.context,
    ONLINE_GENERATION_CONTEXT_FIELDS_V1,
    "Online generation context",
  );
  return validatedAccountLaneId(context.account_lane_id, "Online generation context");
}

function validateFrontier(value: AccountsRecoveryFrontierV1): AccountsRecoveryFrontierV1 {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.catalog_incarnation !== "string" ||
    value.catalog_incarnation.length === 0 ||
    value.catalog_incarnation.length > 255 ||
    !DIGEST.test(value.hash)
  ) {
    throw new AccountsError("RECOVERY_HOLD", "Recovery frontier is malformed");
  }
  return Object.freeze({
    catalog_incarnation: value.catalog_incarnation,
    sequence: parseCounter(value.sequence, "recovery_frontier_sequence"),
    hash: value.hash,
  });
}

function sameFrontier(left: AccountsRecoveryFrontierV1, right: AccountsRecoveryFrontierV1): boolean {
  return (
    left.catalog_incarnation === right.catalog_incarnation &&
    left.sequence === right.sequence &&
    left.hash === right.hash
  );
}

function prepareDatabasePath(input: string): string {
  if (!isAbsolute(input)) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database path must be absolute");
  }
  const path = resolve(input);
  const parent = dirname(path);
  let realParent: string;
  try {
    realParent = realpathSync.native(parent);
  } catch {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database directory is unsafe");
  }
  const parentMetadata = lstatSync(parent);
  const uid = process.getuid?.();
  if (
    uid === undefined ||
    realParent !== parent ||
    !parentMetadata.isDirectory() ||
    parentMetadata.isSymbolicLink() ||
    parentMetadata.uid !== uid ||
    (parentMetadata.mode & 0o077) !== 0
  ) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database directory is unsafe");
  }

  let descriptor: number;
  if (!existsSync(path)) {
    try {
      descriptor = openSync(
        path,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | NOFOLLOW | CLOEXEC,
        0o600,
      );
    } catch {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database file is unsafe");
    }
  } else {
    const link = lstatSync(path);
    if (link.isSymbolicLink()) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database file is unsafe");
    }
    try {
      descriptor = openSync(path, constants.O_RDWR | NOFOLLOW | CLOEXEC);
    } catch {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database file is unsafe");
    }
  }
  try {
    const metadata = fstatSync(descriptor);
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.uid !== uid ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database file is unsafe");
    }
  } finally {
    closeSync(descriptor);
  }
  return path;
}

function secureSqliteFiles(path: string): void {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    if (!existsSync(candidate)) continue;
    const metadata = lstatSync(candidate);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts SQLite sidecar is unsafe");
    }
    chmodSync(candidate, 0o600);
  }
}
