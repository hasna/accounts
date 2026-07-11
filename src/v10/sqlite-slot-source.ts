import { Database } from "bun:sqlite";
import {
  closeSync,
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
import type { AccountsSlotEligibilitySource } from "./index";

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

interface EvidenceRow {
  readonly wire_jcs: Uint8Array;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string | number | bigint;
  readonly recovery_frontier_hash: string;
}

interface StateRow {
  readonly current_deny: number;
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
    this.database = new Database(path, { create: false, strict: true });
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
    `);
  }

  async getSlotEligibility(request: unknown): Promise<Uint8Array> {
    return this.read("SLOT", accountLaneId(request));
  }

  async checkOnlineGeneration(request: unknown): Promise<Uint8Array> {
    return this.read("ONLINE", accountLaneId(request));
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
    const before = await this.readExternalFrontier();
    let selected: EvidenceRow | undefined;
    try {
      selected = this.database.transaction(() => {
        const state = this.database
          .query<StateRow, [string]>(
            "SELECT current_deny FROM accounts_v10_runtime_state WHERE account_lane_id=?",
          )
          .get(laneId);
        if (state === null) return undefined;
        return this.database
          .query<EvidenceRow, [string, string, string]>(`
            SELECT wire_jcs, catalog_incarnation, recovery_frontier_sequence,
                   recovery_frontier_hash
              FROM accounts_v10_signed_evidence
             WHERE account_lane_id=? AND phase=? AND decision=?
          `)
          .get(laneId, phase, state.current_deny === 1 ? "DENY" : "ALLOW") ?? undefined;
      })();
    } catch {
      throw new AccountsError(
        "DEPENDENCY_UNAVAILABLE",
        "Accounts signed evidence database is unavailable",
        { retryable: true },
      );
    }
    if (selected === undefined) {
      throw new AccountsError("NOT_FOUND", "Signed Accounts evidence is unavailable");
    }
    const after = await this.readExternalFrontier();
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
    return Uint8Array.from(wire);
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

function accountLaneId(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Account lane query must be an object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Object.keys(descriptors).length !== 1 ||
    !Object.hasOwn(descriptors, "account_lane_id") ||
    descriptors.account_lane_id?.get !== undefined ||
    descriptors.account_lane_id?.set !== undefined ||
    !("value" in descriptors.account_lane_id!) ||
    typeof descriptors.account_lane_id.value !== "string" ||
    !isUuidV7(descriptors.account_lane_id.value)
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Account lane query is not closed or canonical");
  }
  return descriptors.account_lane_id.value;
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
  if (
    realParent !== parent ||
    !parentMetadata.isDirectory() ||
    parentMetadata.isSymbolicLink() ||
    (typeof process.getuid === "function" && parentMetadata.uid !== process.getuid()) ||
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
      (typeof process.getuid === "function" && metadata.uid !== process.getuid()) ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Accounts database file is unsafe");
    }
  } finally {
    closeSync(descriptor);
  }
  return path;
}
