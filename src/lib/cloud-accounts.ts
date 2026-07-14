// Self-hosted (`mode=self_hosted`) registry backend for the accounts CLI.
//
// LOCKED ARCHITECTURE: when `HASNA_ACCOUNTS_API_URL` + `HASNA_ACCOUNTS_API_KEY`
// are set, the account *registry* (profiles + current selections) is read from
// and written to the app's cloud HTTP API at `<API_URL>/v1` with the bearer key
// — never the local JSON store, never a raw DSN. Built on the `@hasna/contracts`
// HTTP storage client, so it inherits retries, timeout, idempotency and JSON
// error mapping.
//
// Without an explicit mode, both API env vars select cloud and an incomplete
// pair stays local. Explicit `self_hosted`/`cloud` fails closed unless both
// vars exist; explicit `local` forces local. Only the retired
// `remote`/`hybrid`/`s3` aliases are ignored.
//
// Registry vs local: the cloud is the source of truth for account metadata
// (name, tool, email, displayName, identity, cardLast4, metadata, description,
// createdAt, lastUsedAt) and current selections. A profile's local config `dir`,
// the per-machine `applied` map and `toolLocks` are inherently machine-local and
// stay local; launch/apply/env commands therefore remain local operations.
//
// SAFETY: the API key never appears in logs or return values; it lives only
// inside the contracts transport.

import type { Profile, ToolDef } from "../types.js";
import { AccountsError, toolDefSchema } from "../types.js";
import { resolveStorageClient, type HasnaStorageClient } from "@hasna/contracts";

const APP_SLUG = "accounts";

/** The `/v1/accounts` entity as returned by the serve API. */
export interface CloudAccount {
  tool: string;
  name: string;
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata?: Record<string, string | number | boolean | null>;
  dir?: string;
  description?: string;
  createdAt: string;
  lastUsedAt?: string;
}

export interface CloudCurrentSelection {
  tool: string;
  name: string;
  updatedAt: string;
}

export interface CloudCreateInput {
  name: string;
  tool: string;
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata?: Record<string, string | number | boolean | null>;
  dir?: string;
  description?: string;
}

/** Fields updatable through `PATCH /v1/accounts/:tool/:name`. */
export interface CloudUpdateInput {
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata?: Record<string, string | number | boolean | null>;
  dir?: string;
  description?: string;
  lastUsedAt?: string;
}

/**
 * Tool payload accepted from GET /v1/tools. Older servers only guaranteed
 * id/label, so all enriched ToolDef fields and builtin remain optional on read.
 */
export type CloudTool = Pick<ToolDef, "id" | "label"> & Partial<ToolDef> & { builtin?: boolean };

/** Registry surface backed by `<API_URL>/v1`. */
export interface AccountsCloudApi {
  readonly baseUrl: string;
  list(tool?: string): Promise<Profile[]>;
  get(name: string, tool?: string): Promise<Profile | undefined>;
  create(input: CloudCreateInput): Promise<Profile>;
  update(name: string, tool: string, input: CloudUpdateInput): Promise<Profile>;
  rename(oldName: string, newName: string, tool: string): Promise<Profile>;
  remove(name: string, tool?: string): Promise<Profile>;
  listCurrent(): Promise<CloudCurrentSelection[]>;
  getCurrent(tool: string): Promise<CloudCurrentSelection | null>;
  setCurrent(tool: string, name: string): Promise<CloudCurrentSelection>;
  listTools(): Promise<CloudTool[]>;
  createTool(def: ToolDef): Promise<ToolDef>;
  removeTool(id: string): Promise<void>;
}

export type ResolveAccountsCloudResult =
  | { transport: "cloud-http"; api: AccountsCloudApi }
  | { transport: "local"; api: null };

function toProfile(account: CloudAccount): Profile {
  return {
    name: account.name,
    tool: account.tool,
    ...(account.email ? { email: account.email } : {}),
    ...(account.displayName ? { displayName: account.displayName } : {}),
    ...(account.identity ? { identity: account.identity } : {}),
    ...(account.cardLast4 ? { cardLast4: account.cardLast4 } : {}),
    ...(account.metadata && Object.keys(account.metadata).length > 0 ? { metadata: account.metadata } : {}),
    dir: account.dir ?? "",
    ...(account.description ? { description: account.description } : {}),
    createdAt: account.createdAt,
    ...(account.lastUsedAt ? { lastUsedAt: account.lastUsedAt } : {}),
  };
}

/** Canonical storage modes. Unknown words are rejected; retired aliases are
 * stripped and treated as unset. */
const CANONICAL_MODES = new Set(["local", "self_hosted", "cloud"]);
const RETIRED_MODES = new Set(["remote", "hybrid", "s3"]);

/** Env keys the contracts resolver reads for the storage mode. We compute the
 * mode ourselves and clear these so no stale/legacy value can reach it. */
const MODE_ENV_KEYS = ["HASNA_ACCOUNTS_STORAGE_MODE", "ACCOUNTS_STORAGE_MODE", "HASNA_ACCOUNTS_MODE"] as const;

/**
 * Bridge the fleet flip's two-var convention to the contracts resolver. The
 * toggle is the presence of BOTH `HASNA_ACCOUNTS_API_URL` and
 * `HASNA_ACCOUNTS_API_KEY`: when both are set (and mode is not explicitly
 * `local`) the client uses the cloud HTTP transport; otherwise local.
 *
 * Canonical modes are enforced here. Explicit `self_hosted`/`cloud` requires
 * both API variables and fails before the contracts resolver if either is
 * absent. Only stale `remote|hybrid|s3` aliases are ignored and stripped.
 */
function deriveEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const url = env.HASNA_ACCOUNTS_API_URL || env.ACCOUNTS_API_URL;
  const key = env.HASNA_ACCOUNTS_API_KEY || env.ACCOUNTS_API_KEY;
  const rawMode = (
    env.HASNA_ACCOUNTS_STORAGE_MODE ||
    env.ACCOUNTS_STORAGE_MODE ||
    env.HASNA_ACCOUNTS_MODE ||
    ""
  ).trim().toLowerCase();
  const explicitMode = CANONICAL_MODES.has(rawMode) ? rawMode : "";

  if (rawMode && !explicitMode && !RETIRED_MODES.has(rawMode)) {
    throw new AccountsError(
      `invalid accounts storage mode "${rawMode}"; expected local, self_hosted, or cloud`,
    );
  }

  const next: NodeJS.ProcessEnv = { ...env };
  for (const k of MODE_ENV_KEYS) delete next[k];

  if (explicitMode === "local") {
    // Force local even when URL+KEY are present.
    next.HASNA_ACCOUNTS_STORAGE_MODE = "local";
  } else if (explicitMode === "self_hosted" || explicitMode === "cloud") {
    if (!url || !key) {
      const missing = [!url ? "HASNA_ACCOUNTS_API_URL" : "", !key ? "HASNA_ACCOUNTS_API_KEY" : ""]
        .filter(Boolean)
        .join(" and ");
      throw new AccountsError(`${explicitMode} storage mode requires ${missing}`);
    }
    next.HASNA_ACCOUNTS_STORAGE_MODE = "cloud";
  } else if (url && key) {
    // Both self_hosted and cloud use the identical cloud-http transport; the
    // canonical runtime word contracts expects is `cloud`.
    next.HASNA_ACCOUNTS_STORAGE_MODE = "cloud";
  }
  // Otherwise leave the mode unset so contracts defaults to local. Only the
  // explicitly retired aliases are silently ignored.
  return next;
}

/**
 * Resolve the accounts registry backend for this process. Returns a `cloud-http`
 * API wired to `<API_URL>/v1` when self_hosted is configured, else
 * `{ transport: 'local' }`. Throws (via the contracts resolver) if cloud is
 * requested but misconfigured, so a client never silently drifts to local.
 */
export function resolveAccountsCloud(
  env: NodeJS.ProcessEnv = process.env,
  overrides?: Parameters<typeof resolveStorageClient>[2],
): ResolveAccountsCloudResult {
  const resolved = resolveStorageClient(APP_SLUG, deriveEnv(env), overrides);
  if (resolved.transport !== "cloud-http") return { transport: "local", api: null };
  return { transport: "cloud-http", api: makeApi(resolved.client) };
}

function makeApi(client: HasnaStorageClient): AccountsCloudApi {
  const t = client.transport;

  const listAll = async (tool?: string): Promise<CloudAccount[]> => {
    const raw = await t.get<{ accounts?: CloudAccount[] }>("/accounts", tool ? { query: { tool } } : undefined);
    return Array.isArray(raw?.accounts) ? raw.accounts : [];
  };

  const api: AccountsCloudApi = {
    baseUrl: client.baseUrl,

    async list(tool?: string): Promise<Profile[]> {
      const accounts = await listAll(tool);
      return accounts
        .map(toProfile)
        .sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name));
    },

    async get(name: string, tool?: string): Promise<Profile | undefined> {
      if (tool) {
        try {
          const account = await t.get<CloudAccount>(`/accounts/${encodeURIComponent(tool)}/${encodeURIComponent(name)}`);
          return account ? toProfile(account) : undefined;
        } catch (err) {
          if (isNotFound(err)) return undefined;
          throw err;
        }
      }
      const matches = (await listAll()).filter((a) => a.name === name);
      if (matches.length === 1) return toProfile(matches[0]!);
      return undefined;
    },

    async create(input: CloudCreateInput): Promise<Profile> {
      const body: Record<string, unknown> = { name: input.name, tool: input.tool };
      if (input.email) body.email = input.email;
      if (input.displayName) body.displayName = input.displayName;
      if (input.identity) body.identity = input.identity;
      if (input.cardLast4) body.cardLast4 = input.cardLast4;
      if (input.metadata && Object.keys(input.metadata).length > 0) body.metadata = input.metadata;
      if (input.dir) body.dir = input.dir;
      if (input.description) body.description = input.description;
      const created = await client.create<CloudAccount>("accounts", body);
      return toProfile(created);
    },

    async update(name: string, tool: string, input: CloudUpdateInput): Promise<Profile> {
      const body: Record<string, unknown> = {};
      if (input.email !== undefined) body.email = input.email;
      if (input.displayName !== undefined) body.displayName = input.displayName;
      if (input.identity !== undefined) body.identity = input.identity;
      if (input.cardLast4 !== undefined) body.cardLast4 = input.cardLast4;
      if (input.metadata !== undefined) body.metadata = input.metadata;
      if (input.dir !== undefined) body.dir = input.dir;
      if (input.description !== undefined) body.description = input.description;
      if (input.lastUsedAt !== undefined) body.lastUsedAt = input.lastUsedAt;
      const updated = await t.patch<CloudAccount>(
        `/accounts/${encodeURIComponent(tool)}/${encodeURIComponent(name)}`,
        body,
      );
      return toProfile(updated);
    },

    async rename(oldName: string, newName: string, tool: string): Promise<Profile> {
      try {
        const renamed = await t.post<CloudAccount>(
          `/accounts/${encodeURIComponent(tool)}/${encodeURIComponent(oldName)}/rename`,
          { name: newName },
        );
        return toProfile(renamed);
      } catch (err) {
        if (isEndpointMissing(err)) throw endpointMissingError("accounts rename");
        throw err;
      }
    },

    async remove(name: string, tool?: string): Promise<Profile> {
      const resolvedTool = tool ?? (await resolveSingleTool(name, listAll));
      const existing = await t.get<CloudAccount>(
        `/accounts/${encodeURIComponent(resolvedTool)}/${encodeURIComponent(name)}`,
      ).catch((err) => {
        if (isNotFound(err)) return null;
        throw err;
      });
      if (!existing) {
        const suffix = tool ? ` for tool "${tool}"` : "";
        throw new AccountsError(`no profile named "${name}"${suffix}`);
      }
      await t.del(`/accounts/${encodeURIComponent(resolvedTool)}/${encodeURIComponent(name)}`);
      return toProfile(existing);
    },

    async listCurrent(): Promise<CloudCurrentSelection[]> {
      const raw = await t.get<{ current?: CloudCurrentSelection[] }>("/current");
      return Array.isArray(raw?.current) ? raw.current : [];
    },

    async getCurrent(tool: string): Promise<CloudCurrentSelection | null> {
      try {
        return await t.get<CloudCurrentSelection>(`/current/${encodeURIComponent(tool)}`);
      } catch (err) {
        if (isNotFound(err)) return null;
        throw err;
      }
    },

    async setCurrent(tool: string, name: string): Promise<CloudCurrentSelection> {
      return t.put<CloudCurrentSelection>(`/current/${encodeURIComponent(tool)}`, { name });
    },

    async listTools(): Promise<CloudTool[]> {
      const raw = await t.get<{ tools?: CloudTool[] }>("/tools");
      return Array.isArray(raw?.tools) ? raw.tools : [];
    },

    async createTool(def: ToolDef): Promise<ToolDef> {
      try {
        const created = await t.post<CloudTool>("/tools", def);
        const { builtin: _builtin, ...toolDef } = created;
        const parsed = toolDefSchema.safeParse(toolDef);
        if (!parsed.success) {
          throw new AccountsError("accounts-serve returned an invalid custom tool after creation");
        }
        return parsed.data;
      } catch (err) {
        if (isEndpointMissing(err)) throw endpointMissingError("accounts tools add");
        throw err;
      }
    },

    async removeTool(id: string): Promise<void> {
      try {
        await t.del(`/tools/${encodeURIComponent(id)}`);
      } catch (err) {
        if (isEndpointMissing(err)) throw endpointMissingError("accounts tools remove");
        throw err;
      }
    },
  };
  return api;
}

async function resolveSingleTool(name: string, listAll: (tool?: string) => Promise<CloudAccount[]>): Promise<string> {
  const matches = (await listAll()).filter((a) => a.name === name);
  if (matches.length === 0) throw new AccountsError(`no profile named "${name}"`);
  if (matches.length > 1) {
    throw new AccountsError(`profile "${name}" exists for multiple tools (${matches.map((a) => a.tool).join(", ")}); pass --tool`);
  }
  return matches[0]!.tool;
}

function isNotFound(err: unknown): boolean {
  return Boolean(err && typeof err === "object" && (err as { status?: number }).status === 404);
}

/** Pull the `error` message out of a JSON error body (object or JSON string). */
function errorMessageOf(body: unknown): string | undefined {
  if (typeof body === "string") {
    try {
      const parsed = JSON.parse(body) as { error?: unknown };
      if (parsed && typeof parsed === "object" && typeof parsed.error === "string") return parsed.error;
      return undefined;
    } catch {
      return body;
    }
  }
  if (body && typeof body === "object") {
    const msg = (body as { error?: unknown }).error;
    return typeof msg === "string" ? msg : undefined;
  }
  return undefined;
}

/**
 * True for a *route-missing* 404 — the generic `{ "error": "not found" }` the
 * server returns when no route matches — as opposed to an entity-level 404
 * (`no profile named ...`, `no custom tool ...`). A route-missing 404 on a
 * mutating call means the connected self-hosted server is running an older
 * build that predates this endpoint.
 */
function isEndpointMissing(err: unknown): boolean {
  if (!(err && typeof err === "object")) return false;
  const e = err as { status?: number; body?: unknown };
  if (e.status !== 404) return false;
  return errorMessageOf(e.body) === "not found";
}

/** Actionable error for a mutating op whose endpoint is absent on the server. */
function endpointMissingError(op: string): AccountsError {
  return new AccountsError(
    `the self-hosted accounts server does not support \`${op}\` — it is running an older build that predates this endpoint. ` +
      `Redeploy accounts-serve to the cloud (ECS) so the API exposes it, then retry. (Local mode is unaffected.)`,
  );
}
