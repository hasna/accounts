import { describe, expect, test } from "bun:test";
import { resolveAccountsCloud } from "./lib/cloud-accounts.js";

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
});
