// Postgres-backed accounts repository for the cloud service.
//
// PURE REMOTE (Amendment A1): every method reads/writes the cloud Postgres
// directly through the vendored kit's typed client — no cache, no local mirror.
// Domain semantics mirror the local library (src/lib/profiles.ts): duplicate
// (tool,name) rejected, delete clears the current selection, set-current
// requires the account to exist and stamps last_used_at.

import { AccountsError, type ToolDef, toolDefSchema } from "../types.js";
import type { PoolQueryClient, TypedQueryClient } from "../generated/storage-kit/index.js";
import type { CreateAccountInput, UpdateAccountInput } from "./schema.js";

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
  lastUsedAt?: string;
}

export interface CurrentSelection {
  tool: string;
  name: string;
  updatedAt: string;
}

/** The storage surface the HTTP handler depends on (implemented by AccountsRepo). */
export interface AccountsStore {
  list(tool?: string): Promise<Account[]>;
  get(tool: string, name: string): Promise<Account | null>;
  create(input: CreateAccountInput): Promise<Account>;
  update(tool: string, name: string, input: UpdateAccountInput): Promise<Account>;
  rename(tool: string, oldName: string, newName: string): Promise<Account>;
  remove(tool: string, name: string): Promise<boolean>;
  listCurrent(): Promise<CurrentSelection[]>;
  getCurrent(tool: string): Promise<CurrentSelection | null>;
  setCurrent(tool: string, name: string): Promise<CurrentSelection>;
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
    const rows = await this.client.many<{ tool: string; name: string; updated_at: string | Date }>(
      "SELECT tool, name, updated_at FROM current_selections ORDER BY tool",
    );
    return rows.map((r) => ({ tool: r.tool, name: r.name, updatedAt: iso(r.updated_at)! }));
  }

  async getCurrent(tool: string): Promise<CurrentSelection | null> {
    const row = await this.client.get<{ tool: string; name: string; updated_at: string | Date }>(
      "SELECT tool, name, updated_at FROM current_selections WHERE tool = $1",
      [tool],
    );
    return row ? { tool: row.tool, name: row.name, updatedAt: iso(row.updated_at)! } : null;
  }

  async setCurrent(tool: string, name: string): Promise<CurrentSelection> {
    return this.client.transaction(async (client) => {
      const account = await this.getWith(client, tool, name, { forUpdate: true });
      if (!account) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
      await client.execute("UPDATE accounts SET last_used_at = now() WHERE tool = $1 AND name = $2", [
        tool,
        name,
      ]);
      const row = await client.one<{ tool: string; name: string; updated_at: string | Date }>(
        `INSERT INTO current_selections (tool, name, updated_at)
         VALUES ($1, $2, now())
         ON CONFLICT (tool) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
         RETURNING tool, name, updated_at`,
        [tool, name],
      );
      return { tool: row.tool, name: row.name, updatedAt: iso(row.updated_at)! };
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
