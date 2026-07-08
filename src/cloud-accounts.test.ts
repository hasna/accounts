import { describe, expect, test } from "bun:test";
import { resolveAccountsCloud } from "./lib/cloud-accounts.js";
import { AccountsError } from "./types.js";

const BASE = "https://accounts.hasna.xyz";
const KEY = "hasna_accounts_testkey_0000";

type Call = { method: string; url: string; headers: Record<string, string>; body: unknown };

function mockFetch(routes: (call: Call) => { status: number; body: unknown }) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers as Record<string, string>) ?? {})) headers[k.toLowerCase()] = v;
    const body = init?.body ? JSON.parse(init.body as string) : null;
    const call: Call = { method: init?.method ?? "GET", url, headers, body };
    calls.push(call);
    const { status, body: resBody } = routes(call);
    return new Response(status === 204 ? null : JSON.stringify(resBody), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

const cloudEnv = { HASNA_ACCOUNTS_API_URL: BASE, HASNA_ACCOUNTS_API_KEY: KEY } as NodeJS.ProcessEnv;

describe("resolveAccountsCloud", () => {
  test("local when env unset", () => {
    expect(resolveAccountsCloud({} as NodeJS.ProcessEnv).transport).toBe("local");
  });

  test("local when only URL set", () => {
    expect(resolveAccountsCloud({ HASNA_ACCOUNTS_API_URL: BASE } as NodeJS.ProcessEnv).transport).toBe("local");
  });

  test("cloud-http when URL+KEY set; baseUrl is <url>/v1", () => {
    const r = resolveAccountsCloud(cloudEnv);
    expect(r.transport).toBe("cloud-http");
    if (r.transport === "cloud-http") expect(r.api.baseUrl).toBe(`${BASE}/v1`);
  });

  test("explicit STORAGE_MODE=local forces local even with URL+KEY", () => {
    expect(resolveAccountsCloud({ ...cloudEnv, HASNA_ACCOUNTS_STORAGE_MODE: "local" } as NodeJS.ProcessEnv).transport).toBe("local");
  });

  test("list GETs /v1/accounts (with tool filter) and maps accounts->profiles", async () => {
    const { calls, fetchImpl } = mockFetch(() => ({
      status: 200,
      body: { accounts: [{ tool: "claude", name: "work", email: "w@x.com", dir: "/d", createdAt: "2020-01-01T00:00:00Z" }] },
    }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const profiles = await r.api.list("claude");
    expect(profiles).toHaveLength(1);
    expect(profiles[0]!.name).toBe("work");
    expect(profiles[0]!.dir).toBe("/d");
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.url).toContain(`${BASE}/v1/accounts`);
    expect(calls[0]!.url).toContain("tool=claude");
    expect(calls[0]!.headers["authorization"]).toBe(`Bearer ${KEY}`);
  });

  test("create POSTs /v1/accounts with tool+name+idempotency key", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      expect(c.method).toBe("POST");
      expect((c.body as { tool: string }).tool).toBe("codex");
      return { status: 201, body: { tool: "codex", name: "new", createdAt: "2020-01-01T00:00:00Z" } };
    });
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const p = await r.api.create({ name: "new", tool: "codex", email: "n@x.com" });
    expect(p.name).toBe("new");
    expect(calls[0]!.url).toBe(`${BASE}/v1/accounts`);
    expect(calls[0]!.headers["idempotency-key"]).toBeDefined();
  });

  test("remove looks up then DELETEs /v1/accounts/:tool/:name", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.method === "GET") return { status: 200, body: { tool: "claude", name: "work", createdAt: "2020-01-01T00:00:00Z" } };
      return { status: 204, body: null };
    });
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const p = await r.api.remove("work", "claude");
    expect(p.name).toBe("work");
    const del = calls.find((c) => c.method === "DELETE")!;
    expect(del.url).toBe(`${BASE}/v1/accounts/claude/work`);
  });

  test("remove of a nonexistent profile (with tool) throws AccountsError, not a raw Error", async () => {
    // Entity-level 404 on the lookup: the profile does not exist. This must
    // surface as an AccountsError so the CLI prints a clean `error: ...` line
    // (exit 1) instead of dumping an unhandled stack trace leaking cli.js.
    const { fetchImpl } = mockFetch(() => ({ status: 404, body: { error: "no profile named \"ghost\"" } }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const err = await r.api.remove("ghost", "claude").then(
      () => { throw new Error("expected remove to reject"); },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AccountsError);
    expect((err as AccountsError).message).toBe('no profile named "ghost" for tool "claude"');
  });

  test("remove of a nonexistent profile (no tool) throws AccountsError from tool resolution", async () => {
    // No --tool: resolveSingleTool lists accounts, finds no match, must throw
    // AccountsError (clean CLI line) rather than a raw Error (stack trace).
    const { fetchImpl } = mockFetch(() => ({ status: 200, body: { accounts: [] } }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const err = await r.api.remove("ghost").then(
      () => { throw new Error("expected remove to reject"); },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AccountsError);
    expect((err as AccountsError).message).toBe('no profile named "ghost"');
  });

  test("setCurrent PUTs /v1/current/:tool", async () => {
    const { calls, fetchImpl } = mockFetch(() => ({ status: 200, body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z" } }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const c = await r.api.setCurrent("claude", "work");
    expect(c.name).toBe("work");
    expect(calls[0]!.method).toBe("PUT");
    expect(calls[0]!.url).toBe(`${BASE}/v1/current/claude`);
    expect((calls[0]!.body as { name: string }).name).toBe("work");
  });

  test("getCurrent returns null on 404", async () => {
    const { fetchImpl } = mockFetch(() => ({ status: 404, body: { error: "none" } }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    expect(await r.api.getCurrent("claude")).toBeNull();
  });

  test("update PATCHes /v1/accounts/:tool/:name with only provided fields", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      expect(c.method).toBe("PATCH");
      return { status: 200, body: { tool: "claude", name: "work", description: "d", createdAt: "2020-01-01T00:00:00Z" } };
    });
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const p = await r.api.update("work", "claude", { description: "d" });
    expect(p.description).toBe("d");
    expect(calls[0]!.url).toBe(`${BASE}/v1/accounts/claude/work`);
    expect(calls[0]!.body).toEqual({ description: "d" });
    expect((calls[0]!.body as Record<string, unknown>).email).toBeUndefined();
  });

  test("rename POSTs /v1/accounts/:tool/:name/rename with the new name", async () => {
    const { calls, fetchImpl } = mockFetch(() => ({
      status: 200,
      body: { tool: "claude", name: "home", createdAt: "2020-01-01T00:00:00Z" },
    }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    const p = await r.api.rename("personal", "home", "claude");
    expect(p.name).toBe("home");
    expect(calls[0]!.method).toBe("POST");
    expect(calls[0]!.url).toBe(`${BASE}/v1/accounts/claude/personal/rename`);
    expect((calls[0]!.body as { name: string }).name).toBe("home");
  });

  // Regression: a stale self-hosted server (older deployed build) lacks the
  // rename + tools endpoints and returns the generic route-missing 404
  // (`{ error: "not found" }`). The client must surface an actionable
  // "redeploy accounts-serve" message, not a raw HTTP failure.
  const routeMissing = () => ({ status: 404, body: { error: "not found" } });

  test("rename on a stale server (route-missing 404) yields an actionable redeploy error", async () => {
    const { fetchImpl } = mockFetch(routeMissing);
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    await expect(r.api.rename("personal", "home", "claude")).rejects.toThrow(/older build.*Redeploy accounts-serve/s);
  });

  test("tools add on a stale server (route-missing 404) yields an actionable redeploy error", async () => {
    const { fetchImpl } = mockFetch(routeMissing);
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    await expect(r.api.createTool({ id: "x", name: "X", configEnv: "X_DIR" } as never)).rejects.toThrow(
      /accounts tools add.*Redeploy accounts-serve/s,
    );
  });

  test("tools remove on a stale server (route-missing 404) yields an actionable redeploy error", async () => {
    const { fetchImpl } = mockFetch(routeMissing);
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    await expect(r.api.removeTool("x")).rejects.toThrow(/accounts tools remove.*Redeploy accounts-serve/s);
  });

  test("tools remove entity-404 (real 'no custom tool') is NOT masked as a redeploy error", async () => {
    const { fetchImpl } = mockFetch(() => ({ status: 404, body: { error: 'no custom tool "x"' } }));
    const r = resolveAccountsCloud(cloudEnv, { fetchImpl });
    if (r.transport !== "cloud-http") throw new Error("expected cloud");
    // The entity-404 must pass through as-is (a real 404), never be rewritten
    // into the "server predates this endpoint / Redeploy" diagnostic.
    await expect(r.api.removeTool("x")).rejects.toThrow(/404/);
    await expect(r.api.removeTool("x")).rejects.not.toThrow(/Redeploy/);
  });
});
