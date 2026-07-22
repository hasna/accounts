// Postgres-backed accounts repository for the cloud service.
//
// PURE REMOTE (Amendment A1): every method reads/writes the cloud Postgres
// directly through the vendored kit's typed client — no cache, no local mirror.
// Domain semantics mirror the local library (src/lib/profiles.ts): duplicate
// (tool,name) rejected, delete clears the current selection, set-current
// requires the account to exist and stamps last_used_at.

import { AccountsError, type ToolDef, toolDefSchema } from "../types.js";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { PoolQueryClient, TypedQueryClient } from "../generated/storage-kit/index.js";
import type {
  CreateAccountInput,
  CreateLoginAccountInput,
  LoginUpdateAccountInput,
  RemoveCreatedAccountInput,
  RestoreAccountInput,
  UpdateAccountInput,
} from "./schema.js";

export interface Account {
  tool: string;
  name: string;
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata: Record<string, string | number | boolean | null>;
  dir?: string;
  description?: string;
  createdAt: string;
  incarnationId: string;
  lastUsedAt?: string;
}

export interface CurrentSelection {
  tool: string;
  name: string;
  updatedAt: string;
  revision: string;
}

export interface LoginCurrentSelection extends CurrentSelection {
  operationId: string;
  previousName?: string;
  previousTargetLastUsedAt?: string;
}

export interface CreatedAccountCleanupResult {
  removed: boolean;
  /** Authoritative same-transaction observation after applying/replaying the operation. */
  currentExists: boolean;
  /** True when the caller's bounded replay window has elapsed; no account mutation ran. */
  expired: boolean;
}

export const LOGIN_CLEANUP_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;
export const LOGIN_CLEANUP_MAX_PER_TARGET = 64;
const LOGIN_CLEANUP_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const LOGIN_CLEANUP_OPERATION_CLASS = "remove-created";

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AccountsError("login cleanup request contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  throw new AccountsError("login cleanup request contains an unsupported value");
}

/** Bind one operation id to the complete canonical conditional cleanup request. */
export function loginCleanupRequestDigest(
  tool: string,
  name: string,
  input: RemoveCreatedAccountInput,
): string {
  const canonical = canonicalJson({
    cleanupOperationId: input.cleanupOperationId,
    cleanupRequestedAt: new Date(input.cleanupRequestedAt).toISOString(),
    expectedCardLast4: input.expectedCardLast4,
    expectedCreatedAt: new Date(input.expectedCreatedAt).toISOString(),
    expectedDescription: input.expectedDescription,
    expectedDir: input.expectedDir,
    expectedDisplayName: input.expectedDisplayName,
    expectedEmail: input.expectedEmail,
    expectedIdentity: input.expectedIdentity,
    expectedIncarnationId: input.expectedIncarnationId,
    expectedLastUsedAt: input.expectedLastUsedAt
      ? new Date(input.expectedLastUsedAt).toISOString()
      : null,
    expectedMetadata: input.expectedMetadata,
    name,
    operationClass: LOGIN_CLEANUP_OPERATION_CLASS,
    tool,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/** The storage surface the HTTP handler depends on (implemented by AccountsRepo). */
export interface AccountsStore {
  list(tool?: string): Promise<Account[]>;
  get(tool: string, name: string): Promise<Account | null>;
  create(input: CreateAccountInput): Promise<Account>;
  createForLogin(input: CreateLoginAccountInput): Promise<Account>;
  update(tool: string, name: string, input: UpdateAccountInput): Promise<Account>;
  updateForLogin(tool: string, name: string, input: LoginUpdateAccountInput): Promise<Account>;
  restoreProfile(tool: string, name: string, input: RestoreAccountInput): Promise<Account>;
  removeCreated(
    tool: string,
    name: string,
    input: RemoveCreatedAccountInput,
  ): Promise<CreatedAccountCleanupResult>;
  rename(tool: string, oldName: string, newName: string): Promise<Account>;
  remove(tool: string, name: string): Promise<boolean>;
  listCurrent(): Promise<CurrentSelection[]>;
  getCurrent(tool: string): Promise<CurrentSelection | null>;
  setCurrent(tool: string, name: string): Promise<CurrentSelection>;
  setCurrentForLogin(
    tool: string,
    name: string,
    operationId: string,
    expectedIncarnationId: string,
  ): Promise<LoginCurrentSelection>;
  restoreCurrent(
    tool: string,
    expectedName: string,
    expectedRevision?: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean>;
  restoreCurrentOperation(
    tool: string,
    expectedName: string,
    operationId: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean>;
  listCustomTools(): Promise<ToolDef[]>;
  addCustomTool(def: ToolDef): Promise<ToolDef>;
  removeCustomTool(id: string): Promise<boolean>;
}

interface AccountRow {
  tool: string;
  name: string;
  email: string | null;
  display_name: string | null;
  identity: string | null;
  card_last4: string | null;
  metadata: unknown;
  dir: string | null;
  description: string | null;
  created_at: string | Date;
  incarnation_id: string;
  last_used_at: string | Date | null;
}

function iso(value: string | Date | null | undefined): string | undefined {
  if (value === null || value === undefined) return undefined;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function parseMetadata(value: unknown): Record<string, string | number | boolean | null> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, string | number | boolean | null>;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
    } catch {
      // fall through
    }
  }
  return {};
}

function rowToAccount(row: AccountRow): Account {
  const account: Account = {
    tool: row.tool,
    name: row.name,
    metadata: parseMetadata(row.metadata),
    createdAt: iso(row.created_at) ?? new Date(0).toISOString(),
    incarnationId: row.incarnation_id,
  };
  if (row.email !== null) account.email = row.email;
  if (row.display_name !== null) account.displayName = row.display_name;
  if (row.identity !== null) account.identity = row.identity;
  if (row.card_last4 !== null) account.cardLast4 = row.card_last4;
  if (row.dir !== null) account.dir = row.dir;
  if (row.description !== null) account.description = row.description;
  const lastUsed = iso(row.last_used_at);
  if (lastUsed) account.lastUsedAt = lastUsed;
  return account;
}

export class AccountsRepo implements AccountsStore {
  constructor(private readonly client: PoolQueryClient) {}

  async list(tool?: string): Promise<Account[]> {
    const rows = tool
      ? await this.client.many<AccountRow>(
          "SELECT * FROM accounts WHERE tool = $1 ORDER BY tool, name",
          [tool],
        )
      : await this.client.many<AccountRow>("SELECT * FROM accounts ORDER BY tool, name");
    return rows.map(rowToAccount);
  }

  async get(tool: string, name: string): Promise<Account | null> {
    return this.getWith(this.client, tool, name);
  }

  private async getWith(
    client: TypedQueryClient,
    tool: string,
    name: string,
    opts: { forUpdate?: boolean } = {},
  ): Promise<Account | null> {
    const row = await client.get<AccountRow>(
      `SELECT * FROM accounts WHERE tool = $1 AND name = $2${opts.forUpdate ? " FOR UPDATE" : ""}`,
      [tool, name],
    );
    return row ? rowToAccount(row) : null;
  }

  private async lockToolRegistry(client: TypedQueryClient, tool: string): Promise<void> {
    await client.execute(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`accounts:tool:${tool}`],
    );
  }

  private async lockLoginOperation(client: TypedQueryClient, operationId: string): Promise<void> {
    await client.execute(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`accounts:login-operation:${operationId}`],
    );
  }

  private async lockCleanupJournalTarget(
    client: TypedQueryClient,
    tool: string,
    name: string,
  ): Promise<void> {
    await client.execute(
      "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
      [`accounts:cleanup-journal:${JSON.stringify([LOGIN_CLEANUP_OPERATION_CLASS, tool, name])}`],
    );
  }

  private async lockAccounts(
    client: TypedQueryClient,
    tool: string,
    names: string[],
  ): Promise<Set<string>> {
    const uniqueNames = [...new Set(names)].sort();
    if (uniqueNames.length === 0) return new Set();
    const rows = await client.many<{ name: string }>(
      `SELECT name
         FROM accounts
        WHERE tool = $1 AND name = ANY($2::text[])
        ORDER BY name
        FOR UPDATE`,
      [tool, uniqueNames],
    );
    return new Set(rows.map((row) => row.name));
  }

  async create(input: CreateAccountInput): Promise<Account> {
    return this.client.transaction(async (client) => {
      await this.lockToolRegistry(client, input.tool);
      const removed = await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        [input.tool],
      );
      if (removed) {
        throw new AccountsError(`custom tool "${input.tool}" was explicitly removed`);
      }
      const existing = await this.getWith(client, input.tool, input.name);
      if (existing) {
        throw new AccountsError(`a ${input.tool} profile named "${input.name}" already exists`);
      }
      const row = await client.one<AccountRow>(
        `INSERT INTO accounts (tool, name, email, display_name, identity, card_last4, metadata, dir, description)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
         RETURNING *`,
        [
          input.tool,
          input.name,
          input.email ?? null,
          input.displayName ?? null,
          input.identity ?? null,
          input.cardLast4 ?? null,
          JSON.stringify(input.metadata ?? {}),
          input.dir ?? null,
          input.description ?? null,
        ],
      );
      return rowToAccount(row);
    });
  }

  async createForLogin(input: CreateLoginAccountInput): Promise<Account> {
    return this.client.transaction(async (client) => {
      await this.lockToolRegistry(client, input.tool);
      const removed = await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        [input.tool],
      );
      if (removed) {
        throw new AccountsError(`custom tool "${input.tool}" was explicitly removed`);
      }
      const row = await client.get<AccountRow>(
        `INSERT INTO accounts
           (tool, name, email, display_name, identity, card_last4, metadata, dir, description, incarnation_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::uuid)
         ON CONFLICT (tool, name) DO NOTHING
         RETURNING *`,
        [
          input.tool,
          input.name,
          input.email ?? null,
          input.displayName ?? null,
          input.identity ?? null,
          input.cardLast4 ?? null,
          JSON.stringify(input.metadata ?? {}),
          input.dir ?? null,
          input.description ?? null,
          input.expectedIncarnationId,
        ],
      );
      if (row) return rowToAccount(row);
      const existing = await this.getWith(client, input.tool, input.name, { forUpdate: true });
      if (
        existing &&
        existing.incarnationId === input.expectedIncarnationId &&
        (existing.email ?? null) === (input.email ?? null) &&
        (existing.displayName ?? null) === (input.displayName ?? null) &&
        (existing.identity ?? null) === (input.identity ?? null) &&
        (existing.cardLast4 ?? null) === (input.cardLast4 ?? null) &&
        isDeepStrictEqual(existing.metadata, input.metadata ?? {}) &&
        (existing.dir ?? null) === (input.dir ?? null) &&
        (existing.description ?? null) === (input.description ?? null)
      ) {
        return existing;
      }
      throw new AccountsError(`a ${input.tool} profile named "${input.name}" already exists`);
    });
  }

  async update(tool: string, name: string, input: UpdateAccountInput): Promise<Account> {
    const current = await this.get(tool, name);
    if (!current) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);

    // Merge metadata (patch semantics like the core updateProfile).
    const mergedMetadata =
      input.metadata !== undefined ? { ...current.metadata, ...input.metadata } : undefined;

    const sets: string[] = [];
    const params: unknown[] = [];
    let i = 1;
    const put = (col: string, value: unknown, cast = "") => {
      sets.push(`${col} = $${i}${cast}`);
      params.push(value);
      i += 1;
    };
    if (input.email !== undefined) put("email", input.email);
    if (input.displayName !== undefined) put("display_name", input.displayName);
    if (input.identity !== undefined) put("identity", input.identity);
    if (input.cardLast4 !== undefined) put("card_last4", input.cardLast4);
    if (mergedMetadata !== undefined) put("metadata", JSON.stringify(mergedMetadata), "::jsonb");
    if (input.dir !== undefined) put("dir", input.dir);
    if (input.description !== undefined) put("description", input.description);
    if (input.lastUsedAt !== undefined) put("last_used_at", input.lastUsedAt);

    if (sets.length === 0) return current;

    params.push(tool, name);
    const row = await this.client.one<AccountRow>(
      `UPDATE accounts SET ${sets.join(", ")} WHERE tool = $${i} AND name = $${i + 1} RETURNING *`,
      params,
    );
    return rowToAccount(row);
  }

  async updateForLogin(tool: string, name: string, input: LoginUpdateAccountInput): Promise<Account> {
    const row = await this.client.get<AccountRow>(
      `UPDATE accounts
          SET email = $1
        WHERE tool = $2 AND name = $3 AND incarnation_id = $4::uuid
          AND email IS NOT DISTINCT FROM $5
        RETURNING *`,
      [input.email, tool, name, input.expectedIncarnationId, input.expectedEmail],
    );
    if (row) return rowToAccount(row);
    const current = await this.get(tool, name);
    if (!current) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
    if (current.incarnationId !== input.expectedIncarnationId) {
      throw new AccountsError("profile changed while login finalization was in progress");
    }
    // A same-incarnation concurrent email edit won the compare-and-set. Return
    // it unchanged so the client records no rollback ownership.
    return current;
  }

  async rename(tool: string, oldName: string, newName: string): Promise<Account> {
    return this.client.transaction(async (client) => {
      const existing = await this.getWith(client, tool, oldName, { forUpdate: true });
      if (!existing) throw new AccountsError(`no profile named "${oldName}" for tool "${tool}"`);
      if (oldName !== newName) {
        const dupe = await this.getWith(client, tool, newName);
        if (dupe) throw new AccountsError(`a ${tool} profile named "${newName}" already exists`);
      }
      const row = await client.one<AccountRow>(
        "UPDATE accounts SET name = $1 WHERE tool = $2 AND name = $3 RETURNING *",
        [newName, tool, oldName],
      );
      return rowToAccount(row);
    });
  }

  async restoreProfile(tool: string, name: string, input: RestoreAccountInput): Promise<Account> {
    const sets: string[] = [];
    const params: unknown[] = [];
    let index = 1;
    if (input.email) {
      sets.push(`email = CASE WHEN email IS NOT DISTINCT FROM $${index} THEN $${index + 1} ELSE email END`);
      params.push(input.email.expected, input.email.restore);
      index += 2;
    }
    if (input.lastUsedAt) {
      sets.push(
        `last_used_at = CASE WHEN last_used_at IS NOT DISTINCT FROM $${index}::timestamptz ` +
        `THEN $${index + 1}::timestamptz ELSE last_used_at END`,
      );
      params.push(input.lastUsedAt.expected, input.lastUsedAt.restore);
      index += 2;
    }
    params.push(tool, name, input.expectedIncarnationId);
    const row = await this.client.get<AccountRow>(
      `UPDATE accounts SET ${sets.join(", ")} ` +
      `WHERE tool = $${index} AND name = $${index + 1} AND incarnation_id = $${index + 2}::uuid RETURNING *`,
      params,
    );
    if (row) return rowToAccount(row);
    // A replacement incarnation is a successful no-op: rollback did not own
    // it and must not turn the original login failure into a second error.
    const current = await this.getWith(this.client, tool, name);
    if (!current) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
    return current;
  }

  async removeCreated(
    tool: string,
    name: string,
    input: RemoveCreatedAccountInput,
  ): Promise<CreatedAccountCleanupResult> {
    return this.client.transaction(async (client) => {
      await this.lockLoginOperation(client, input.cleanupOperationId);
      await this.lockCleanupJournalTarget(client, tool, name);
      await client.execute(
        `DELETE FROM account_login_cleanup_operations
          WHERE completed_at IS NOT NULL
            AND requested_at < now() - ($1::double precision * interval '1 millisecond')`,
        [LOGIN_CLEANUP_RETENTION_MS],
      );
      const capTerminalRows = () => client.execute(
        `DELETE FROM account_login_cleanup_operations
          WHERE operation_id IN (
            SELECT operation_id
              FROM account_login_cleanup_operations
             WHERE operation_class = $1 AND tool = $2 AND name = $3
               AND completed_at IS NOT NULL
             ORDER BY completed_at DESC, operation_id DESC
            OFFSET $4
          )`,
        [LOGIN_CLEANUP_OPERATION_CLASS, tool, name, LOGIN_CLEANUP_MAX_PER_TARGET],
      );
      await capTerminalRows();
      const requestedAt = new Date(input.cleanupRequestedAt).getTime();
      const age = Date.now() - requestedAt;
      if (age > LOGIN_CLEANUP_RETENTION_MS) {
        return { removed: false, currentExists: false, expired: true };
      }
      if (age < -LOGIN_CLEANUP_FUTURE_SKEW_MS) {
        throw new AccountsError("login cleanup request time is too far in the future");
      }
      const requestDigest = loginCleanupRequestDigest(tool, name, input);
      const completed = await client.get<{
        tool: string;
        name: string;
        target_incarnation_id: string;
        request_digest: string;
        removed: boolean | null;
        completed_at: string | null;
      }>(
        `SELECT tool, name, target_incarnation_id, request_digest, removed, completed_at
           FROM account_login_cleanup_operations
          WHERE operation_id = $1`,
        [input.cleanupOperationId],
      );
      if (completed) {
        if (
          completed.tool !== tool ||
          completed.name !== name ||
          completed.target_incarnation_id !== input.expectedIncarnationId ||
          completed.request_digest !== requestDigest
        ) {
          throw new AccountsError(
            "login cleanup operation id is already bound to another conditional request",
          );
        }
        if (!completed.completed_at || completed.removed === null) {
          throw new AccountsError("login cleanup operation is still incomplete; retry later");
        }
        const current = await this.getWith(client, tool, name, { forUpdate: true });
        return { removed: completed.removed, currentExists: Boolean(current), expired: false };
      }
      const retained = await client.get<{
        incomplete_count: string | number;
        terminal_count: string | number;
      }>(
        `SELECT count(*) FILTER (WHERE completed_at IS NULL) AS incomplete_count,
                count(*) FILTER (WHERE completed_at IS NOT NULL) AS terminal_count
           FROM account_login_cleanup_operations
          WHERE operation_class = $1 AND tool = $2 AND name = $3`,
        [LOGIN_CLEANUP_OPERATION_CLASS, tool, name],
      );
      if (Number(retained?.incomplete_count ?? 0) >= LOGIN_CLEANUP_MAX_PER_TARGET) {
        // Terminal results are safely evictable because the account delete is
        // still fully conditional and the client rechecks the current row.
        // Incomplete ownership must never be evicted or bypassed.
        throw new AccountsError(
          "login cleanup journal has too many incomplete operations for this profile; retry later",
        );
      }
      const finish = async (
        removed: boolean,
        currentExists: boolean,
      ): Promise<CreatedAccountCleanupResult> => {
        await client.execute(
          `INSERT INTO account_login_cleanup_operations
             (operation_id, operation_class, tool, name, target_incarnation_id,
              request_digest, removed, requested_at, completed_at)
           VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8::timestamptz, now())`,
          [
            input.cleanupOperationId,
            LOGIN_CLEANUP_OPERATION_CLASS,
            tool,
            name,
            input.expectedIncarnationId,
            requestDigest,
            removed,
            input.cleanupRequestedAt,
          ],
        );
        await capTerminalRows();
        return { removed, currentExists, expired: false };
      };
      const current = await this.getWith(client, tool, name, { forUpdate: true });
      if (!current) return finish(false, false);
      const unchanged =
        current.incarnationId === input.expectedIncarnationId &&
        current.createdAt === new Date(input.expectedCreatedAt).toISOString() &&
        (current.email ?? null) === input.expectedEmail &&
        (current.displayName ?? null) === input.expectedDisplayName &&
        (current.identity ?? null) === input.expectedIdentity &&
        (current.cardLast4 ?? null) === input.expectedCardLast4 &&
        isDeepStrictEqual(current.metadata, input.expectedMetadata) &&
        (current.dir ?? null) === input.expectedDir &&
        (current.description ?? null) === input.expectedDescription &&
        (current.lastUsedAt ?? null) === input.expectedLastUsedAt;
      if (!unchanged) return finish(false, true);

      const selected = await client.get<{ name: string }>(
        `SELECT name
           FROM current_selections
          WHERE tool = $1
          FOR UPDATE`,
        [tool],
      );
      if (selected?.name === name) return finish(false, true);

      const result = await client.query<AccountRow>(
        `DELETE FROM accounts
          WHERE tool = $1 AND name = $2 AND incarnation_id = $3::uuid
            AND created_at IS NOT DISTINCT FROM $4::timestamptz
            AND email IS NOT DISTINCT FROM $5
            AND display_name IS NOT DISTINCT FROM $6
            AND identity IS NOT DISTINCT FROM $7
            AND card_last4 IS NOT DISTINCT FROM $8
            AND metadata IS NOT DISTINCT FROM $9::jsonb
            AND dir IS NOT DISTINCT FROM $10
            AND description IS NOT DISTINCT FROM $11
            AND last_used_at IS NOT DISTINCT FROM $12::timestamptz
        RETURNING *`,
        [
          tool,
          name,
          input.expectedIncarnationId,
          input.expectedCreatedAt,
          input.expectedEmail,
          input.expectedDisplayName,
          input.expectedIdentity,
          input.expectedCardLast4,
          JSON.stringify(input.expectedMetadata),
          input.expectedDir,
          input.expectedDescription,
          input.expectedLastUsedAt,
        ],
      );
      const removed = result.rowCount === 1;
      return finish(removed, !removed);
    });
  }

  async remove(tool: string, name: string): Promise<boolean> {
    return this.client.transaction(async (client) => {
      const existing = await this.getWith(client, tool, name, { forUpdate: true });
      if (!existing) return false;
      const result = await client.query<AccountRow>(
        "DELETE FROM accounts WHERE tool = $1 AND name = $2 RETURNING tool",
        [tool, name],
      );
      if (result.rowCount === 0) return false;
      return true;
    });
  }

  async listCurrent(): Promise<CurrentSelection[]> {
    const rows = await this.client.many<{ tool: string; name: string; updated_at: string | Date; revision: string | number }>(
      "SELECT tool, name, updated_at, revision FROM current_selections ORDER BY tool",
    );
    return rows.map((r) => ({ tool: r.tool, name: r.name, updatedAt: iso(r.updated_at)!, revision: String(r.revision) }));
  }

  async getCurrent(tool: string): Promise<CurrentSelection | null> {
    const row = await this.client.get<{ tool: string; name: string; updated_at: string | Date; revision: string | number }>(
      "SELECT tool, name, updated_at, revision FROM current_selections WHERE tool = $1",
      [tool],
    );
    return row
      ? { tool: row.tool, name: row.name, updatedAt: iso(row.updated_at)!, revision: String(row.revision) }
      : null;
  }

  async setCurrent(tool: string, name: string): Promise<CurrentSelection> {
    return this.client.transaction(async (client) => {
      const account = await this.getWith(client, tool, name, { forUpdate: true });
      if (!account) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
      const row = await client.one<{
        tool: string;
        name: string;
        updated_at: string | Date;
        revision: string | number;
      }>(
        `WITH stamp AS (
           SELECT date_trunc('milliseconds', now()) AS at
         ), touched_account AS (
           UPDATE accounts
              SET last_used_at = stamp.at
             FROM stamp
            WHERE tool = $1 AND name = $2
            RETURNING stamp.at
         )
         INSERT INTO current_selections (tool, name, updated_at)
         SELECT $1, $2, at FROM touched_account
         ON CONFLICT (tool) DO UPDATE
           SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at,
               revision = DEFAULT, login_operation_id = NULL
         RETURNING tool, name, updated_at, revision`,
        [tool, name],
      );
      return {
        tool: row.tool,
        name: row.name,
        updatedAt: iso(row.updated_at)!,
        revision: String(row.revision),
      };
    });
  }

  async setCurrentForLogin(
    tool: string,
    name: string,
    operationId: string,
    expectedIncarnationId: string,
  ): Promise<LoginCurrentSelection> {
    return this.client.transaction(async (client) => {
      // Serialize duplicate operation IDs independently of the mutable current
      // row. The durable result makes response-loss retries no-ops even after
      // another actor has selected a newer profile.
      await this.lockLoginOperation(client, operationId);
      const completed = await client.get<{
        operation_id: string;
        tool: string;
        name: string;
        state: "completed" | "cancelled";
        updated_at: string | Date | null;
        revision: string | number | null;
        previous_name: string | null;
        previous_incarnation_id: string | null;
        previous_target_last_used_at: string | Date | null;
        target_incarnation_id: string | null;
      }>(
        `SELECT operation_id, tool, name, state, updated_at, revision,
                previous_name, previous_incarnation_id, previous_target_last_used_at,
                target_incarnation_id
           FROM current_login_operations
          WHERE operation_id = $1`,
        [operationId],
      );
      if (completed) {
        if (completed.tool !== tool || completed.name !== name) {
          throw new AccountsError("login operation id is already bound to another profile");
        }
        if (completed.state === "cancelled") {
          throw new AccountsError("login operation was cancelled before activation");
        }
        if (completed.updated_at === null || completed.revision === null) {
          throw new AccountsError("completed login operation is missing its activation result");
        }
        if (!completed.target_incarnation_id) {
          throw new AccountsError("completed login operation is missing its target incarnation");
        }
        if (completed.target_incarnation_id !== expectedIncarnationId) {
          throw new AccountsError("login operation id is already bound to another profile incarnation");
        }
        const account = await this.getWith(client, tool, name, { forUpdate: true });
        if (!account || account.incarnationId !== completed.target_incarnation_id) {
          throw new AccountsError("profile changed while login activation was in progress");
        }
        return {
          tool: completed.tool,
          name: completed.name,
          updatedAt: iso(completed.updated_at)!,
          revision: String(completed.revision),
          operationId: completed.operation_id,
          ...(completed.previous_name ? { previousName: completed.previous_name } : {}),
          ...(completed.previous_target_last_used_at
            ? { previousTargetLastUsedAt: iso(completed.previous_target_last_used_at)! }
            : {}),
        };
      }
      const account = await this.getWith(client, tool, name, { forUpdate: true });
      if (!account) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
      if (account.incarnationId !== expectedIncarnationId) {
        throw new AccountsError("profile changed while login activation was in progress");
      }
      const displaced = await client.get<{ name: string; incarnation_id: string }>(
        `SELECT current.name, account.incarnation_id
           FROM current_selections AS current
           JOIN accounts AS account ON account.tool = current.tool AND account.name = current.name
          WHERE current.tool = $1
          FOR UPDATE OF current`,
        [tool],
      );
      const row = await client.one<{
        tool: string;
        name: string;
        updated_at: string | Date;
        revision: string | number;
        login_operation_id: string;
      }>(
        `WITH stamp AS (
           SELECT date_trunc('milliseconds', now()) AS at
         ), touched_account AS (
           UPDATE accounts
              SET last_used_at = stamp.at
             FROM stamp
            WHERE tool = $1 AND name = $2
            RETURNING stamp.at
         )
         INSERT INTO current_selections (tool, name, updated_at, login_operation_id)
         SELECT $1, $2, at, $3 FROM touched_account
         ON CONFLICT (tool) DO UPDATE
           SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at,
               revision = DEFAULT, login_operation_id = EXCLUDED.login_operation_id
         RETURNING tool, name, updated_at, revision, login_operation_id`,
        [tool, name, operationId],
      );
      await client.execute(
        `INSERT INTO current_login_operations
           (operation_id, tool, name, state, updated_at, revision, previous_name,
            previous_incarnation_id, previous_target_last_used_at, target_incarnation_id)
         VALUES ($1::uuid, $2, $3, 'completed', $4::timestamptz, $5::bigint, $6, $7::uuid, $8::timestamptz, $9::uuid)`,
        [
          operationId,
          row.tool,
          row.name,
          iso(row.updated_at),
          String(row.revision),
          displaced?.name ?? null,
          displaced?.incarnation_id ?? null,
          account.lastUsedAt ?? null,
          account.incarnationId,
        ],
      );
      return {
        tool: row.tool,
        name: row.name,
        updatedAt: iso(row.updated_at)!,
        revision: String(row.revision),
        operationId: row.login_operation_id,
        ...(displaced?.name ? { previousName: displaced.name } : {}),
        ...(account.lastUsedAt ? { previousTargetLastUsedAt: account.lastUsedAt } : {}),
      };
    });
  }

  async restoreCurrent(
    tool: string,
    expectedName: string,
    expectedRevision?: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean> {
    return this.client.transaction(async (client) => {
      let ownedUpdatedAt: string | undefined;
      if (restoreLastUsedAt !== undefined) {
        const lockedNames = await this.lockAccounts(client, tool, name ? [expectedName, name] : [expectedName]);
        if (!lockedNames.has(expectedName)) return false;
        if (name && !lockedNames.has(name)) {
          throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
        }
        const owned = expectedRevision
          ? await client.get<{ updated_at: string | Date }>(
              `SELECT updated_at
                 FROM current_selections
                WHERE tool = $1 AND name = $2 AND revision = $3::bigint
                FOR UPDATE`,
              [tool, expectedName, expectedRevision],
            )
          : await client.get<{ updated_at: string | Date }>(
              `SELECT updated_at
                 FROM current_selections
                WHERE tool = $1 AND name = $2
                FOR UPDATE`,
              [tool, expectedName],
            );
        if (!owned) return false;
        ownedUpdatedAt = iso(owned.updated_at);
      } else if (name) {
        const account = await this.getWith(client, tool, name, { forUpdate: true });
        if (!account) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
      }
      let restored: boolean;
      if (name) {
        const result = expectedRevision
          ? await client.query(
              `UPDATE current_selections
                  SET name = $4, updated_at = now(), revision = DEFAULT
                WHERE tool = $1 AND name = $2 AND revision = $3::bigint
                RETURNING tool`,
              [tool, expectedName, expectedRevision, name],
            )
          : await client.query(
              `UPDATE current_selections
                  SET name = $3, updated_at = now()
                WHERE tool = $1 AND name = $2
                RETURNING tool`,
              [tool, expectedName, name],
            );
        restored = result.rowCount > 0;
      } else {
        const result = expectedRevision
          ? await client.query(
              "DELETE FROM current_selections WHERE tool = $1 AND name = $2 AND revision = $3::bigint RETURNING tool",
              [tool, expectedName, expectedRevision],
            )
          : await client.query(
              "DELETE FROM current_selections WHERE tool = $1 AND name = $2 RETURNING tool",
              [tool, expectedName],
            );
        restored = result.rowCount > 0;
      }
      if (restored && restoreLastUsedAt !== undefined && ownedUpdatedAt) {
        await client.execute(
          `UPDATE accounts
              SET last_used_at = $4::timestamptz
            WHERE tool = $1 AND name = $2
              AND last_used_at IS NOT DISTINCT FROM $3::timestamptz`,
          [tool, expectedName, ownedUpdatedAt, restoreLastUsedAt],
        );
      }
      return restored;
    });
  }

  async restoreCurrentOperation(
    tool: string,
    expectedName: string,
    operationId: string,
    _name?: string,
    _restoreLastUsedAt?: string | null,
  ): Promise<boolean> {
    return this.client.transaction(async (client) => {
      await this.lockLoginOperation(client, operationId);
      const operation = await client.get<{
        tool: string;
        name: string;
        state: "completed" | "cancelled";
        updated_at: string | Date | null;
        previous_name: string | null;
        previous_incarnation_id: string | null;
        previous_target_last_used_at: string | Date | null;
      }>(
        `SELECT tool, name, state, updated_at, previous_name, previous_incarnation_id,
                previous_target_last_used_at
           FROM current_login_operations
          WHERE operation_id = $1::uuid`,
        [operationId],
      );
      if (!operation) {
        // A rollback can overtake a timed-out activation that is still queued
        // before this advisory lock. Persisting cancellation under the same
        // operation lock makes that later activation fail closed.
        await client.execute(
          `INSERT INTO current_login_operations (operation_id, tool, name, state, updated_at, revision)
           VALUES ($1::uuid, $2, $3, 'cancelled', NULL, NULL)`,
          [operationId, tool, expectedName],
        );
        return true;
      }
      if (operation.tool !== tool || operation.name !== expectedName) {
        throw new AccountsError("login operation id is already bound to another profile");
      }
      if (operation.state === "cancelled") return true;
      if (operation.updated_at === null) {
        throw new AccountsError("completed login operation is missing its activation timestamp");
      }

      // Account rows are always locked in name order before the current row.
      // This matches activation's account-before-current order and prevents a
      // rollback-to-prior / concurrent-activation deadlock cycle.
      const previousName = operation.previous_name ?? undefined;
      const requiredNames = previousName ? [expectedName, previousName] : [expectedName];
      const lockedNames = await this.lockAccounts(client, tool, requiredNames);
      if (!lockedNames.has(expectedName)) return false;
      const restoreAccount = previousName && lockedNames.has(previousName)
        ? await this.getWith(client, tool, previousName)
        : null;
      const restoreName = previousName &&
        restoreAccount?.incarnationId === operation.previous_incarnation_id
        ? previousName
        : undefined;
      const owned = await client.get<{ updated_at: string | Date }>(
        `SELECT updated_at
           FROM current_selections
          WHERE tool = $1
            AND name = $2
            AND login_operation_id = $3
          FOR UPDATE`,
        [tool, expectedName, operationId],
      );
      if (!owned) return false;
      if (restoreName) {
        const result = await client.query(
          `UPDATE current_selections
              SET name = $4, updated_at = now(), revision = DEFAULT, login_operation_id = NULL
            WHERE tool = $1 AND name = $2 AND login_operation_id = $3
            RETURNING tool`,
          [tool, expectedName, operationId, restoreName],
        );
        if (result.rowCount === 0) return false;
      } else {
        const result = await client.query(
          "DELETE FROM current_selections WHERE tool = $1 AND name = $2 AND login_operation_id = $3 RETURNING tool",
          [tool, expectedName, operationId],
        );
        if (result.rowCount === 0) return false;
      }
      if (operation.previous_target_last_used_at != null) {
        await client.execute(
          `UPDATE accounts
              SET last_used_at = $4::timestamptz
            WHERE tool = $1 AND name = $2
              AND last_used_at IS NOT DISTINCT FROM $3::timestamptz`,
          [tool, expectedName, iso(operation.updated_at), iso(operation.previous_target_last_used_at)],
        );
      } else {
        await client.execute(
          `UPDATE accounts
              SET last_used_at = NULL
            WHERE tool = $1 AND name = $2
              AND last_used_at IS NOT DISTINCT FROM $3::timestamptz`,
          [tool, expectedName, iso(operation.updated_at)],
        );
      }
      return true;
    });
  }

  async listCustomTools(): Promise<ToolDef[]> {
    const rows = await this.client.many<{ definition: unknown }>(
      "SELECT definition FROM custom_tools ORDER BY id",
    );
    const tools: ToolDef[] = [];
    for (const row of rows) {
      const raw = typeof row.definition === "string" ? safeJsonParse(row.definition) : row.definition;
      const parsed = toolDefSchema.safeParse(raw);
      if (parsed.success) tools.push(parsed.data);
    }
    return tools;
  }

  async addCustomTool(def: ToolDef): Promise<ToolDef> {
    const parsed = toolDefSchema.safeParse(def);
    if (!parsed.success) {
      throw new AccountsError(parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
    }
    const tool = parsed.data;
    return this.client.transaction(async (client) => {
      await this.lockToolRegistry(client, tool.id);
      await client.execute("DELETE FROM custom_tool_tombstones WHERE id = $1", [tool.id]);
      const row = await client.one<{ definition: unknown }>(
        `INSERT INTO custom_tools (id, definition)
         VALUES ($1, $2::jsonb)
         ON CONFLICT (id) DO UPDATE SET definition = EXCLUDED.definition
         RETURNING definition`,
        [tool.id, JSON.stringify(tool)],
      );
      const stored = typeof row.definition === "string" ? safeJsonParse(row.definition) : row.definition;
      return toolDefSchema.parse(stored);
    });
  }

  async removeCustomTool(id: string): Promise<boolean> {
    return this.client.transaction(async (client) => {
      await this.lockToolRegistry(client, id);
      const inUse = await client.many<{ name: string }>(
        "SELECT name FROM accounts WHERE tool = $1 ORDER BY name",
        [id],
      );
      if (inUse.length > 0) {
        throw new AccountsError(
          `cannot remove "${id}": still used by profile(s) ${inUse.map((r) => r.name).join(", ")}`,
        );
      }
      const result = await client.query<{ id: string }>(
        "DELETE FROM custom_tools WHERE id = $1 RETURNING id",
        [id],
      );
      await client.execute(
        "INSERT INTO custom_tool_tombstones (id) VALUES ($1) ON CONFLICT (id) DO NOTHING",
        [id],
      );
      return result.rowCount > 0;
    });
  }
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}
