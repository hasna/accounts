// HTTP application for accounts-serve.
//
// Framework-agnostic request handler (a `(Request) => Promise<Response>`) plus a
// context builder that wires the vendored storage kit (cloud Postgres, PURE
// REMOTE per Amendment A1) and API-key auth from @hasna/contracts. Health/ready/
// version are public; every /v1 route requires a valid API key with the right
// scope (accounts:read for GET, accounts:write for mutations).

import { ApiKeyStore, verifyApiKey, type ApiKeyVerifier } from "@hasna/contracts/auth";
import {
  createCloudPoolFromEnv,
  resolveStorageMode,
  checkHealth,
} from "../generated/storage-kit/index.js";
import { AccountsError } from "../types.js";
import { listTools, isBuiltinTool } from "../lib/tools.js";
import { AccountsRepo, type AccountsStore } from "./repo.js";
import { accountsMigrations, readMigrationStatus } from "./migrations.js";
import { createAccountSchema, updateAccountSchema, renameAccountSchema, setCurrentSchema, toolIdSchema } from "./schema.js";
import { APP_SLUG, API_KEYS_TABLE, SCOPES, resolveSigningSecret } from "./config.js";
import { packageVersion } from "./version.js";

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
};

export interface HealthProbe {
  ok: boolean;
  error?: string;
}
export interface ReadyProbe {
  ready: boolean;
  reason?: string;
}

export interface ServiceContext {
  repo: AccountsStore;
  verifier: ApiKeyVerifier;
  health: () => Promise<HealthProbe>;
  ready: () => Promise<ReadyProbe>;
  mode: "local" | "cloud";
  version: string;
  close: () => Promise<void>;
}

export interface BuildContextOptions {
  env?: NodeJS.ProcessEnv;
}

/** Build the live service context from the environment (cloud Postgres + auth). */
export function buildServiceContext(options: BuildContextOptions = {}): ServiceContext {
  const env = options.env ?? process.env;
  const resolution = resolveStorageMode(APP_SLUG, env);
  if (resolution.mode !== "cloud") {
    throw new AccountsError(
      "accounts-serve requires cloud storage. Set HASNA_ACCOUNTS_STORAGE_MODE=cloud and HASNA_ACCOUNTS_DATABASE_URL.",
    );
  }
  const signingSecret = resolveSigningSecret(env);
  if (!signingSecret) {
    throw new AccountsError(
      "accounts-serve requires an API-key signing secret. Set HASNA_ACCOUNTS_API_SIGNING_KEY (or HASNA_API_SIGNING_KEY).",
    );
  }
  const { client } = createCloudPoolFromEnv(APP_SLUG, {
    env,
    applicationName: "accounts-serve",
    max: 5,
  });
  const repo = new AccountsRepo(client);
  const keyStore = new ApiKeyStore(client, { table: API_KEYS_TABLE });
  const verifier = verifyApiKey({
    app: APP_SLUG,
    signingSecret,
    isRevoked: keyStore.isRevoked,
    audit: (e) => {
      // Structured, secret-free audit line.
      console.log(
        JSON.stringify({ evt: "api_auth", outcome: e.outcome, kid: e.kid, reason: e.reason, method: e.method, path: e.path, status: e.status }),
      );
    },
  });
  const migrations = accountsMigrations();
  return {
    repo,
    verifier,
    health: async () => {
      const h = await checkHealth(client);
      return h.ok ? { ok: true } : { ok: false, error: h.error ?? "database unreachable" };
    },
    ready: async () => {
      const h = await checkHealth(client);
      if (!h.ok) return { ready: false, reason: h.error ?? "database unreachable" };
      // Privilege-safe readiness: probe the ledger without any DDL, so the
      // DML-only app role can report readiness.
      const status = await readMigrationStatus(client, migrations);
      if (!status.ledgerPresent) return { ready: false, reason: "schema not migrated (ledger table missing)" };
      if (status.pending.length > 0) return { ready: false, reason: `pending migrations: ${status.pending.join(", ")}` };
      return { ready: true };
    },
    mode: "cloud",
    version: packageVersion(),
    close: () => client.close(),
  };
}

// --- helpers ---

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...SECURITY_HEADERS, ...extra },
  });
}

function errorBody(message: string, reason?: string): { error: string; reason?: string } {
  return reason ? { error: message, reason } : { error: message };
}

function zodMessage(err: { issues: { path: (string | number)[]; message: string }[] }): string {
  return err.issues.map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`).join("; ");
}

/** Build the request handler. Auth + routing over the given context. */
export function createHandler(ctx: ServiceContext): (req: Request) => Promise<Response> {
  async function authorize(req: Request, url: URL, scope: string): Promise<Response | null> {
    const decision = await ctx.verifier.authenticate((name) => req.headers.get(name), {
      method: req.method,
      path: url.pathname,
      requiredScopes: [scope],
    });
    if (decision.ok) return null;
    return json(errorBody(decision.message, decision.reason), decision.status);
  }

  async function parseJson(req: Request): Promise<{ ok: true; value: unknown } | { ok: false; res: Response }> {
    try {
      const value = await req.json();
      return { ok: true, value };
    } catch {
      return { ok: false, res: json(errorBody("invalid JSON body"), 400) };
    }
  }

  return async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method.toUpperCase();

    try {
      // --- public probes ---
      if (pathname === "/health" && method === "GET") {
        const health = await ctx.health();
        const status = health.ok ? "ok" : "unavailable";
        return json({ status, version: ctx.version, mode: ctx.mode }, health.ok ? 200 : 503);
      }
      if (pathname === "/ready" && method === "GET") {
        const ready = await ctx.ready();
        return json(ready.reason ? { ready: ready.ready, reason: ready.reason } : { ready: ready.ready }, ready.ready ? 200 : 503);
      }
      if (pathname === "/version" && method === "GET") {
        return json({ version: ctx.version }, 200);
      }
      if ((pathname === "/" || pathname === "") && method === "GET") {
        return json({ service: "accounts-serve", version: ctx.version, mode: ctx.mode }, 200);
      }

      // --- /v1 (authenticated) ---
      if (pathname === "/v1/accounts" && method === "GET") {
        const denied = await authorize(req, url, SCOPES.read);
        if (denied) return denied;
        const tool = url.searchParams.get("tool") ?? undefined;
        if (tool !== undefined) {
          const parsed = toolIdSchema.safeParse(tool);
          if (!parsed.success) return json(errorBody(zodMessage(parsed.error)), 400);
        }
        const accounts = await ctx.repo.list(tool);
        return json({ accounts }, 200);
      }

      if (pathname === "/v1/accounts" && method === "POST") {
        const denied = await authorize(req, url, SCOPES.write);
        if (denied) return denied;
        const parsedBody = await parseJson(req);
        if (!parsedBody.ok) return parsedBody.res;
        const input = createAccountSchema.safeParse(parsedBody.value);
        if (!input.success) return json(errorBody(zodMessage(input.error)), 400);
        const created = await ctx.repo.create(input.data);
        return json(created, 201);
      }

      const renameMatch = pathname.match(/^\/v1\/accounts\/([^/]+)\/([^/]+)\/rename$/);
      if (renameMatch && method === "POST") {
        const denied = await authorize(req, url, SCOPES.write);
        if (denied) return denied;
        const tool = decodeURIComponent(renameMatch[1]!);
        const name = decodeURIComponent(renameMatch[2]!);
        const parsedBody = await parseJson(req);
        if (!parsedBody.ok) return parsedBody.res;
        const input = renameAccountSchema.safeParse(parsedBody.value);
        if (!input.success) return json(errorBody(zodMessage(input.error)), 400);
        const renamed = await ctx.repo.rename(tool, name, input.data.name);
        return json(renamed, 200);
      }

      const accountMatch = pathname.match(/^\/v1\/accounts\/([^/]+)\/([^/]+)$/);
      if (accountMatch) {
        const tool = decodeURIComponent(accountMatch[1]!);
        const name = decodeURIComponent(accountMatch[2]!);
        if (method === "GET") {
          const denied = await authorize(req, url, SCOPES.read);
          if (denied) return denied;
          const account = await ctx.repo.get(tool, name);
          if (!account) return json(errorBody(`no profile named "${name}" for tool "${tool}"`), 404);
          return json(account, 200);
        }
        if (method === "PATCH") {
          const denied = await authorize(req, url, SCOPES.write);
          if (denied) return denied;
          const parsedBody = await parseJson(req);
          if (!parsedBody.ok) return parsedBody.res;
          const input = updateAccountSchema.safeParse(parsedBody.value);
          if (!input.success) return json(errorBody(zodMessage(input.error)), 400);
          const updated = await ctx.repo.update(tool, name, input.data);
          return json(updated, 200);
        }
        if (method === "DELETE") {
          const denied = await authorize(req, url, SCOPES.write);
          if (denied) return denied;
          const removed = await ctx.repo.remove(tool, name);
          if (!removed) return json(errorBody(`no profile named "${name}" for tool "${tool}"`), 404);
          return new Response(null, { status: 204, headers: SECURITY_HEADERS });
        }
      }

      if (pathname === "/v1/current" && method === "GET") {
        const denied = await authorize(req, url, SCOPES.read);
        if (denied) return denied;
        const current = await ctx.repo.listCurrent();
        return json({ current }, 200);
      }

      const currentMatch = pathname.match(/^\/v1\/current\/([^/]+)$/);
      if (currentMatch) {
        const tool = decodeURIComponent(currentMatch[1]!);
        if (method === "GET") {
          const denied = await authorize(req, url, SCOPES.read);
          if (denied) return denied;
          const current = await ctx.repo.getCurrent(tool);
          if (!current) return json(errorBody(`no current selection for tool "${tool}"`), 404);
          return json(current, 200);
        }
        if (method === "PUT") {
          const denied = await authorize(req, url, SCOPES.write);
          if (denied) return denied;
          const parsedBody = await parseJson(req);
          if (!parsedBody.ok) return parsedBody.res;
          const input = setCurrentSchema.safeParse(parsedBody.value);
          if (!input.success) return json(errorBody(zodMessage(input.error)), 400);
          const current = await ctx.repo.setCurrent(tool, input.data.name);
          return json(current, 200);
        }
      }

      if (pathname === "/v1/tools" && method === "GET") {
        const denied = await authorize(req, url, SCOPES.read);
        if (denied) return denied;
        const tools = listTools().map((t) => ({
          id: t.id,
          label: t.label,
          envVar: t.envVar,
          bin: t.bin,
          builtin: isBuiltinTool(t.id),
        }));
        return json({ tools }, 200);
      }

      return json(errorBody("not found"), 404);
    } catch (err) {
      if (err instanceof AccountsError) {
        const msg = err.message;
        const status = /already exists/.test(msg) ? 409 : /no profile named/.test(msg) ? 404 : 400;
        return json(errorBody(msg), status);
      }
      const message = err instanceof Error ? err.message : String(err);
      console.error(JSON.stringify({ evt: "server_error", message }));
      return json(errorBody("internal error"), 500);
    }
  };
}
