import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveStore } from "./lib/store.js";
import { resolveSupervisorLaunch } from "./lib/supervisor.js";
import { clearCustomToolsCache, getTool } from "./lib/tools.js";

const BASE = "https://accounts.hasna.xyz";
const KEY = "hasna_accounts_testkey_0000";
const cloudEnv = { HASNA_ACCOUNTS_API_URL: BASE, HASNA_ACCOUNTS_API_KEY: KEY } as NodeJS.ProcessEnv;

type Call = { method: string; url: string; body: unknown };

function mockFetch(routes: (call: Call) => { status: number; body: unknown }) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ method: init?.method ?? "GET", url, body });
    const { status, body: resBody } = routes(calls[calls.length - 1]!);
    return new Response(status === 204 ? null : JSON.stringify(resBody), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

describe("resolveStore transport selection", () => {
  test("LocalStore when API env is unset", () => {
    expect(resolveStore({} as NodeJS.ProcessEnv).transport).toBe("local");
  });

  test("ApiStore when API URL+KEY are set", () => {
    expect(resolveStore(cloudEnv).transport).toBe("api");
  });

  test("forced local mode uses LocalStore even with URL+KEY", () => {
    expect(
      resolveStore({ ...cloudEnv, HASNA_ACCOUNTS_STORAGE_MODE: "local" } as NodeJS.ProcessEnv).transport,
    ).toBe("local");
  });
});

describe("ApiStore routes registry ops to /v1", () => {
  test("useProfile resolves then PUTs the current selection", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.method === "GET") return { status: 200, body: { tool: "claude", name: "work", createdAt: "2020-01-01T00:00:00Z" } };
      return { status: 200, body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z" } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    const { toolId } = await store.useProfile("work", "claude");
    expect(toolId).toBe("claude");
    expect(calls.some((c) => c.method === "PUT" && c.url === `${BASE}/v1/current/claude`)).toBe(true);
  });

  test("getProfile throws AccountsError on unknown profile (no local fallthrough)", async () => {
    const { fetchImpl } = mockFetch(() => ({ status: 404, body: { error: "nope" } }));
    const store = resolveStore(cloudEnv, { fetchImpl });
    await expect(store.getProfile("ghost", "claude")).rejects.toThrow(/no profile named "ghost"/);
  });

  test("currentProfile follows getCurrent then get", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.url.endsWith("/current/claude")) return { status: 200, body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z" } };
      return { status: 200, body: { tool: "claude", name: "work", createdAt: "2020-01-01T00:00:00Z" } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    const p = await store.currentProfile("claude");
    expect(p?.name).toBe("work");
    expect(calls[0]!.url).toBe(`${BASE}/v1/current/claude`);
  });

  describe("custom tools route to the cloud registry (not the local file)", () => {
    let home: string;
    const acme = { id: "acme", label: "Acme", envVar: "ACME_HOME", defaultDir: "/tmp/.acme", bin: "acme" };
    beforeEach(() => {
      home = mkdtempSync(join(tmpdir(), "accounts-store-tools-"));
      process.env.ACCOUNTS_HOME = home;
      delete process.env.ACCOUNTS_STORE_PATH;
    });
    afterEach(() => {
      clearCustomToolsCache();
      rmSync(home, { recursive: true, force: true });
      delete process.env.ACCOUNTS_HOME;
    });

    test("addTool POSTs /v1/tools and never writes only-local", async () => {
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.method === "POST" && c.url.endsWith("/tools")) return { status: 201, body: { ...acme, builtin: false } };
        if (c.method === "GET" && c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        return { status: 200, body: {} };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const created = await store.addTool(acme);
      expect(created.id).toBe("acme");
      expect(calls.some((c) => c.method === "POST" && c.url === `${BASE}/v1/tools`)).toBe(true);
    });

    test("addTool rejects a built-in id before any network call", async () => {
      const { calls, fetchImpl } = mockFetch(() => ({ status: 500, body: {} }));
      const store = resolveStore(cloudEnv, { fetchImpl });
      await expect(store.addTool({ ...acme, id: "claude" })).rejects.toThrow(/built-in/);
      expect(calls.length).toBe(0);
    });

    test("removeTool DELETEs /v1/tools/:id", async () => {
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.method === "DELETE") return { status: 204, body: null };
        if (c.method === "GET" && c.url.endsWith("/tools")) return { status: 200, body: { tools: [] } };
        return { status: 200, body: {} };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await store.removeTool("acme");
      expect(calls.some((c) => c.method === "DELETE" && c.url === `${BASE}/v1/tools/acme`)).toBe(true);
    });

    test("listTools GETs /v1/tools and merges built-ins", async () => {
      const { calls, fetchImpl } = mockFetch(() => ({ status: 200, body: { tools: [{ ...acme, builtin: false }] } }));
      const store = resolveStore(cloudEnv, { fetchImpl });
      const tools = await store.listTools();
      expect(calls.some((c) => c.method === "GET" && c.url === `${BASE}/v1/tools`)).toBe(true);
      expect(tools.some((t) => t.id === "acme")).toBe(true);
      expect(tools.some((t) => t.id === "claude")).toBe(true);
    });

    test("new client accepts an old server's minimal builtin Tool response", async () => {
      const { fetchImpl } = mockFetch(() => ({
        status: 200,
        body: { tools: [{ id: "claude", label: "Claude Code", builtin: true }] },
      }));
      const store = resolveStore(cloudEnv, { fetchImpl });
      const claude = (await store.listTools()).find((tool) => tool.id === "claude");
      expect(claude?.envVar).toBe("CLAUDE_CONFIG_DIR");
      expect(claude?.defaultDir).toBeDefined();
      expect(existsSync(join(home, "accounts.json"))).toBe(false);
    });

    test("listTools hydrates custom tools without creating accounts.json", async () => {
      const { fetchImpl } = mockFetch(() => ({
        status: 200,
        body: { tools: [{ ...acme, builtin: false }] },
      }));
      const store = resolveStore(cloudEnv, { fetchImpl });
      expect(existsSync(join(home, "accounts.json"))).toBe(false);
      expect((await store.listTools()).some((tool) => tool.id === "acme")).toBe(true);
      expect(getTool("acme").bin).toBe("acme");
      expect(existsSync(join(home, "accounts.json"))).toBe(false);
    });

    test("cold add hydrates a cloud custom tool before validation", async () => {
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.method === "GET" && c.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        }
        if (c.method === "POST" && c.url.endsWith("/accounts")) {
          return {
            status: 201,
            body: { tool: "acme", name: "work", dir: join(home, "profiles", "acme", "work"), createdAt: "2020-01-01T00:00:00Z" },
          };
        }
        return { status: 404, body: { error: "not found" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const profile = await store.addProfile({ name: "work", tool: "acme" });
      expect(profile.tool).toBe("acme");
      expect(calls.map((c) => c.method + " " + new URL(c.url).pathname)).toEqual([
        "GET /v1/tools",
        "POST /v1/accounts",
      ]);
    });

    test("cold custom-profile lookup hydrates launch resolution", async () => {
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/accounts/acme/work")) {
          return {
            status: 200,
            body: { tool: "acme", name: "work", dir: join(home, "profiles", "acme", "work"), createdAt: "2020-01-01T00:00:00Z" },
          };
        }
        if (c.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        }
        return { status: 404, body: { error: "not found" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const plan = await resolveSupervisorLaunch("work", { tool: "acme" }, store);
      expect(plan.tool.id).toBe("acme");
      expect(plan.tool.bin).toBe("acme");
      expect(calls.map((c) => new URL(c.url).pathname)).toEqual([
        "/v1/accounts/acme/work",
        "/v1/tools",
      ]);
    });

    test("switching from cloud to explicit local mode clears remote tool state", async () => {
      const { fetchImpl } = mockFetch(() => ({
        status: 200,
        body: { tools: [{ ...acme, builtin: false }] },
      }));
      const cloudStore = resolveStore(cloudEnv, { fetchImpl });
      expect((await cloudStore.listTools()).some((tool) => tool.id === "acme")).toBe(true);

      const localStore = resolveStore({
        ACCOUNTS_HOME: home,
        HASNA_ACCOUNTS_STORAGE_MODE: "local",
      } as NodeJS.ProcessEnv);
      expect((await localStore.listTools()).some((tool) => tool.id === "acme")).toBe(false);
    });
  });
});

describe("LocalStore reads/writes the on-box registry", () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "accounts-store-test-"));
    process.env.ACCOUNTS_HOME = home;
    delete process.env.ACCOUNTS_STORE_PATH;
    delete process.env.HASNA_ACCOUNTS_API_URL;
    delete process.env.HASNA_ACCOUNTS_API_KEY;
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    delete process.env.ACCOUNTS_HOME;
  });

  test("add, use, then currentProfile round-trips through the store", async () => {
    const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    expect(store.transport).toBe("local");
    await store.addProfile({ name: "work", tool: "claude", email: "w@x.com" });
    await store.useProfile("work", "claude");
    const active = await store.currentProfile("claude");
    expect(active?.name).toBe("work");
    const list = await store.listProfiles("claude");
    expect(list.map((p) => p.name)).toContain("work");
  });
});
