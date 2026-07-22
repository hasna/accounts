import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { createHash } from "node:crypto";
import {
  resolveStore,
  setLoginCleanupFaultInjectorForTests,
  type AccountsStore,
  type LoginCleanupFaultPoint,
} from "./lib/store.js";
import { resolveSupervisorLaunch } from "./lib/supervisor.js";
import { clearCustomToolsCache, getTool } from "./lib/tools.js";
import {
  commitLoginPreparation,
  loginToolChoices,
  prepareLogin,
  rollbackLoginPreparation,
} from "./lib/login.js";
import { importProfile } from "./lib/import-profile.js";
import {
  loadMachineStore,
  profileAuthIncarnation,
  profileAuthRevisionKey,
  saveStore,
} from "./storage.js";

const BASE = "https://accounts.hasna.xyz";
const KEY = "hasna_accounts_testkey_0000";
const cloudEnv = { HASNA_ACCOUNTS_API_URL: BASE, HASNA_ACCOUNTS_API_KEY: KEY } as NodeJS.ProcessEnv;

type Call = { method: string; url: string; body: unknown };

function mockFetch(
  routes: (call: Call) => { status: number; body: unknown } | Promise<{ status: number; body: unknown }>,
) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ method: init?.method ?? "GET", url, body });
    const { status, body: resBody } = await routes(calls[calls.length - 1]!);
    return new Response(status === 204 ? null : JSON.stringify(resBody), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

function deferredRejection() {
  let reject!: (reason: Error) => void;
  const promise = new Promise<void>((_resolve, rejectPromise) => {
    reject = rejectPromise;
  });
  // The pre-fix implementation drops the returned promise. Keep the red test
  // deterministic instead of letting that known bug become an unhandled rejection.
  void promise.catch(() => {});
  return { promise, reject };
}

function trackProfilePersistence(store: AccountsStore, operations: string[]): AccountsStore {
  return new Proxy(store, {
    get(target, property, receiver) {
      if (property === "findProfile") {
        return (...args: Parameters<AccountsStore["findProfile"]>) => {
          operations.push("find");
          return target.findProfile(...args);
        };
      }
      if (property === "addProfile") {
        return (...args: Parameters<AccountsStore["addProfile"]>) => {
          operations.push("add");
          return target.addProfile(...args);
        };
      }
      const value = Reflect.get(target, property, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function nextEventLoopTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
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
      return { status: 200, body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z", revision: "7" } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    const { toolId } = await store.useProfile("work", "claude");
    expect(toolId).toBe("claude");
    expect(calls.some((c) => c.method === "PUT" && c.url === `${BASE}/v1/current/claude`)).toBe(true);
  });

  test("useProfileForLogin resolves then PUTs the transactional activation route", async () => {
    const operationId = "11111111-1111-4111-8111-111111111111";
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.method === "GET") {
        return {
          status: 200,
          body: {
            tool: "claude",
            name: "work",
            createdAt: "2020-01-01T00:00:00Z",
            incarnationId: "11111111-1111-4111-8111-111111111111",
          },
        };
      }
      return {
        status: 200,
        body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z", revision: "8", operationId },
      };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    expect((await store.useProfileForLogin!(
      "work",
      "claude",
      operationId,
    )).currentRevision).toBe("8");
    expect(calls.some((c) => c.method === "PUT" && c.url === `${BASE}/v1/current/claude/login/activate`)).toBe(true);
  });

  test("rollback helpers restore nullable profile state and conditionally clear API current", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.url.endsWith("/accounts/claude/work/login/restore")) {
        return { status: 200, body: { tool: "claude", name: "work", createdAt: "2020-01-01T00:00:00Z" } };
      }
      return { status: 200, body: { restored: true } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    await store.restoreProfileState!(
      {
        name: "work",
        tool: "claude",
        dir: "/profiles/work",
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "11111111-1111-4111-8111-111111111111",
      },
      { email: { expected: "failed@example.com", restore: null } },
    );
    expect(calls[0]).toMatchObject({
      method: "POST",
      url: `${BASE}/v1/accounts/claude/work/login/restore`,
      body: {
        expectedIncarnationId: "11111111-1111-4111-8111-111111111111",
        email: { expected: "failed@example.com", restore: null },
      },
    });
    expect(await store.restoreCurrentGeneration!("claude", "work", "7")).toBe(true);
    expect(calls[1]).toMatchObject({
      method: "POST",
      url: `${BASE}/v1/current/claude/login/restore`,
      body: { expectedName: "work", expectedRevision: "7" },
    });
  });

  test("getProfile throws AccountsError on unknown profile (no local fallthrough)", async () => {
    const { fetchImpl } = mockFetch(() => ({ status: 404, body: { error: "nope" } }));
    const store = resolveStore(cloudEnv, { fetchImpl });
    await expect(store.getProfile("ghost", "claude")).rejects.toThrow(/no profile named "ghost"/);
  });

  test("new client reads a legacy Account response without incarnation or email", async () => {
    const { fetchImpl } = mockFetch(() => ({
      status: 200,
      body: {
        tool: "claude",
        name: "legacy",
        metadata: {},
        createdAt: "2020-01-01T00:00:00Z",
      },
    }));
    const store = resolveStore(cloudEnv, { fetchImpl });

    const profile = await store.getProfile("legacy", "claude");

    expect(profile.name).toBe("legacy");
    expect(profile.email).toBeUndefined();
    expect(profile.incarnationId).toBeUndefined();
  });

  test("currentProfile follows getCurrent then get", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.url.endsWith("/current/claude")) {
        return {
          status: 200,
          body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z", revision: "7" },
        };
      }
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
      setLoginCleanupFaultInjectorForTests();
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
        "/v1/tools",
        "/v1/accounts/acme/work",
        "/v1/tools",
      ]);
    });

    test("cold login choices include cloud custom tools", async () => {
      const { fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/accounts")) return { status: 200, body: { accounts: [] } };
        if (c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        return { status: 404, body: { error: "not found" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const choices = await loginToolChoices("work", process.env, store);
      expect(choices.some((choice) => choice.tool.id === "acme")).toBe(true);
    });

    test("cold explicit login resolves a cloud custom tool before profile creation", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (c.method === "GET" && c.url.endsWith("/accounts/acme/work")) {
          return { status: 404, body: { error: "not found" } };
        }
        if (c.method === "GET" && c.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (c.method === "POST" && c.url.endsWith("/accounts/login/create")) {
          const incarnationId = String((c.body as { expectedIncarnationId?: string }).expectedIncarnationId);
          return {
            status: 201,
            body: {
              tool: "acme",
              name: "work",
              dir: join(home, "profiles", "acme", "work"),
              createdAt: "2020-01-01T00:00:00Z",
              incarnationId,
            },
          };
        }
        return { status: 404, body: { error: "not found" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const prepared = await prepareLogin("work", { toolId: "acme", env: process.env, store });
      expect(prepared.status).toBe("ready");
      expect(prepared.tool.id).toBe("acme");
      expect(calls[0]!.url).toBe(`${BASE}/v1/tools`);
    });

    test("lost transactional create response recovers only the exact server incarnation", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      let committed: Record<string, unknown> | undefined;
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/response-loss")) {
          return committed
            ? { status: 200, body: committed }
            : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          const expectedIncarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          committed ??= {
            tool: "acme",
            name: "response-loss",
            dir: join(home, "profiles", "acme", "response-loss"),
            createdAt: "2020-01-01T00:00:00Z",
            incarnationId: expectedIncarnationId,
          };
          throw new TypeError("simulated lost create response");
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/response-loss/login/remove-created-operation")) {
          committed = undefined;
          return { status: 200, body: { removed: true, currentExists: false, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });

      const preparation = await prepareLogin("response-loss", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");

      expect(preparation.created).toBe(true);
      expect(preparation.profile.incarnationId).toBe(committed?.incarnationId);
      expect(calls.some((call) =>
        call.method === "POST" && new URL(call.url).pathname === "/v1/accounts",
      )).toBe(false);
      await rollbackLoginPreparation(preparation, store);
      expect(committed).toBeUndefined();
      expect(existsSync(preparation.profile.dir)).toBe(false);
    });

    test("mixed-rollout login create fails closed without calling the legacy create route", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const managedDir = join(home, "profiles", "acme", "old-replica");
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/old-replica")) {
          return { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          return { status: 404, body: { error: "not found" } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });

      await expect(prepareLogin("old-replica", {
        toolId: "acme",
        env: process.env,
        store,
      })).rejects.toThrow(/transactional login profile creation/);

      expect(calls.some((call) =>
        call.method === "POST" && new URL(call.url).pathname === "/v1/accounts",
      )).toBe(false);
      expect(existsSync(managedDir)).toBe(false);
    });

    test("failed cloud login rollback conditionally removes the exact created profile and managed directory", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "failed",
        dir: join(home, "profiles", "acme", "failed"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "11111111-1111-4111-8111-111111111111",
      };
      let created = false;
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/failed")) {
          return created ? { status: 200, body: profile } : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts?tool=acme")) {
          return { status: 200, body: { accounts: created ? [profile] : [] } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          profile.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/failed/login/remove-created-operation")) {
          created = false;
          return { status: 200, body: { removed: true, currentExists: false, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const prepared = await prepareLogin("failed", { toolId: "acme", env: process.env, store });
      if (prepared.status !== "ready") throw new Error("expected ready login preparation");

      expect(prepared.created).toBe(true);
      expect(existsSync(profile.dir)).toBe(true);
      await rollbackLoginPreparation(prepared, store);

      expect(created).toBe(false);
      expect(existsSync(profile.dir)).toBe(false);
      expect(calls.some((call) =>
        call.method === "POST" && call.url.endsWith("/accounts/acme/failed/login/remove-created-operation"),
      )).toBe(true);
    });

    test("failed cloud login cleans its directory after a concurrent exact profile deletion", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "deleted-before-cleanup",
        dir: join(home, "profiles", "acme", "deleted-before-cleanup"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      };
      let created = false;
      const { fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/deleted-before-cleanup")) {
          return created
            ? { status: 200, body: profile }
            : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          profile.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/deleted-before-cleanup/login/remove-created-operation")) {
          created = false;
          return { status: 200, body: { removed: false, currentExists: false, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("deleted-before-cleanup", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");

      await rollbackLoginPreparation(preparation, store);

      expect(created).toBe(false);
      expect(existsSync(profile.dir)).toBe(false);
    });

    test("terminal cleanup response loss reconciles the committed delete and removes the directory", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "cleanup-response-loss",
        dir: join(home, "profiles", "acme", "cleanup-response-loss"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "66666666-6666-4666-8666-666666666666",
      };
      let created = false;
      let cleanupAttempts = 0;
      const cleanupBodies: unknown[] = [];
      const { fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/cleanup-response-loss")) {
          return created ? { status: 200, body: profile } : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          profile.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/cleanup-response-loss/login/remove-created-operation")) {
          cleanupAttempts += 1;
          cleanupBodies.push(call.body);
          created = false;
          throw new TypeError("simulated lost cleanup response");
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("cleanup-response-loss", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");

      await rollbackLoginPreparation(preparation, store);

      expect(cleanupAttempts).toBeGreaterThan(1);
      expect(cleanupBodies.every((body) => JSON.stringify(body) === JSON.stringify(cleanupBodies[0]))).toBe(true);
      expect(existsSync(profile.dir)).toBe(false);
    });

    test("cleanup replay preserves a replacement server incarnation and its replacement-owned file", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const dir = join(home, "profiles", "acme", "cleanup-aba-replacement");
      const original = {
        tool: "acme",
        name: "cleanup-aba-replacement",
        dir,
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      };
      const replacement = {
        ...original,
        createdAt: "2020-01-02T00:00:00Z",
        incarnationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        description: "replacement",
      };
      let current: typeof original | typeof replacement | undefined;
      let cleanupAttempts = 0;
      const { fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/cleanup-aba-replacement")) {
          return current
            ? { status: 200, body: current }
            : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          original.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          current = original;
          return { status: 201, body: original };
        }
        if (
          call.method === "POST" &&
          call.url.endsWith("/accounts/acme/cleanup-aba-replacement/login/remove-created-operation")
        ) {
          cleanupAttempts += 1;
          if (cleanupAttempts === 1) {
            current = replacement;
            writeFileSync(join(dir, "replacement-owned.json"), "{}\n", { mode: 0o600 });
            throw new TypeError("simulated committed cleanup response loss");
          }
          // Durable replay returns the old operation result. The client must
          // still consult the authoritative current row before local purge.
          return { status: 200, body: { removed: true, currentExists: true, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("cleanup-aba-replacement", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");

      await rollbackLoginPreparation(preparation, store);

      expect(cleanupAttempts).toBeGreaterThan(1);
      expect(current).toEqual(replacement);
      expect(existsSync(dir)).toBe(true);
      expect(existsSync(join(dir, "replacement-owned.json"))).toBe(true);
    });

    test("expired cleanup replay preserves local directory state without a destructive retry", async () => {
      const profile = {
        tool: "acme",
        name: "expired-cleanup",
        dir: join(home, "profiles", "acme", "expired-cleanup"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      };
      mkdirSync(profile.dir, { recursive: true });
      writeFileSync(join(profile.dir, "preserve.json"), "{}\n", { mode: 0o600 });
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/login/remove-created-operation")) {
          return {
            status: 200,
            body: { removed: false, currentExists: false, expired: true },
          };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });

      const result = await store.removeProfileIncarnation!(
        profile,
        {
          cleanupOperationId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
          cleanupRequestedAt: "2020-01-01T00:00:00.000Z",
        },
        { tool: profile.tool, purge: true },
      );

      expect(result).toBeUndefined();
      expect(existsSync(join(profile.dir, "preserve.json"))).toBe(true);
      expect(calls.filter((call) => call.method === "GET")).toHaveLength(0);
    });

    test("API preparation intent recovers crashes before and after profile creation", async () => {
      for (const point of ["pre-create", "post-create"] as const) {
        const name = `api-${point}`;
        const dir = join(home, "profiles", "acme", name);
        const executableTool = { ...acme, bin: process.execPath };
        let current: Record<string, unknown> | undefined;
        const { fetchImpl } = mockFetch((call) => {
          if (call.url.endsWith("/tools")) {
            return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
          }
          if (call.method === "GET" && call.url.endsWith(`/accounts/acme/${name}`)) {
            return current
              ? { status: 200, body: current }
              : { status: 404, body: { error: "not found" } };
          }
          if (call.method === "GET" && call.url.endsWith("/current")) {
            return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
          }
          if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
            current = {
              tool: "acme",
              name,
              dir,
              createdAt: "2020-01-01T00:00:00Z",
              incarnationId: String(
                (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
              ),
            };
            return { status: 201, body: current };
          }
          if (
            call.method === "POST" &&
            call.url.endsWith(`/accounts/acme/${name}/login/remove-created-operation`)
          ) {
            current = undefined;
            return {
              status: 200,
              body: { removed: true, currentExists: false, expired: false },
            };
          }
          return { status: 500, body: { error: "unexpected request" } };
        });
        const store = resolveStore(cloudEnv, { fetchImpl });
        setLoginCleanupFaultInjectorForTests((candidate) => {
          if (candidate === point) throw new Error(`crash:${point}`);
        });

        await expect(prepareLogin(name, {
          toolId: "acme",
          env: process.env,
          store,
        })).rejects.toThrow(`injected login cleanup fault at ${point}`);
        setLoginCleanupFaultInjectorForTests();
        await store.reconcileInterruptedLoginCleanup!(name, "acme");

        expect(current).toBeUndefined();
        expect(existsSync(dir)).toBe(false);
      }
    });

    test("cleanup response loss fails closed on a legacy replica response missing the rollback fence", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "cleanup-legacy-replica",
        dir: join(home, "profiles", "acme", "cleanup-legacy-replica"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      };
      let created = false;
      let cleanupStarted = false;
      const { fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/cleanup-legacy-replica")) {
          if (!created) return { status: 404, body: { error: "not found" } };
          return {
            status: 200,
            body: cleanupStarted
              ? { ...profile, incarnationId: undefined }
              : profile,
          };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          profile.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/cleanup-legacy-replica/login/remove-created-operation")) {
          cleanupStarted = true;
          throw new TypeError("simulated lost cleanup response");
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("cleanup-legacy-replica", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");

      await expect(rollbackLoginPreparation(preparation, store)).rejects.toThrow(
        /simulated lost cleanup response/,
      );

      expect(created).toBe(true);
      expect(existsSync(profile.dir)).toBe(true);
    });

    test("cloud login reconciles a journaled delete before recreating the same managed directory", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const dir = join(home, "profiles", "acme", "journal-recovery");
      let profile: Record<string, unknown> | undefined;
      let createCount = 0;
      const { fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/journal-recovery")) {
          return profile
            ? { status: 200, body: profile }
            : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          createCount += 1;
          profile = {
            tool: "acme",
            name: "journal-recovery",
            dir,
            createdAt: `2020-01-0${createCount}T00:00:00Z`,
            incarnationId: String(
              (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
            ),
          };
          return { status: 201, body: profile };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const first = await prepareLogin("journal-recovery", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (first.status !== "ready") throw new Error("expected ready login preparation");
      commitLoginPreparation(first, store);
      writeFileSync(join(dir, "stale-auth.json"), "{}\n", { mode: 0o600 });
      writeFileSync(join(dir, ".accounts-login-cleanup.json"), JSON.stringify({
        version: 1,
        cleanupOperationId: "77777777-7777-4777-8777-777777777777",
        profile: first.profile,
        ownership: {},
      }) + "\n", { mode: 0o600 });
      profile = undefined;

      const second = await prepareLogin("journal-recovery", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (second.status !== "ready") throw new Error("expected ready login preparation");

      expect(createCount).toBe(2);
      expect(second.profile.incarnationId).not.toBe(first.profile.incarnationId);
      expect(existsSync(join(dir, "stale-auth.json"))).toBe(false);
      expect(existsSync(join(dir, ".accounts-login-cleanup.json"))).toBe(false);
    });

    test("failed cloud login cleanup preserves a concurrently changed incarnation and its directory", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "changed",
        dir: join(home, "profiles", "acme", "changed"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "22222222-2222-4222-8222-222222222222",
      };
      let created = false;
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/changed")) {
          return created ? { status: 200, body: { ...profile, description: "concurrent" } } : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          profile.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/changed/login/remove-created-operation")) {
          return { status: 200, body: { removed: false, currentExists: true, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("changed", { toolId: "acme", env: process.env, store });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");
      writeFileSync(join(profile.dir, "concurrent.json"), "{}\n", { mode: 0o600 });

      await rollbackLoginPreparation(preparation, store);

      expect(created).toBe(true);
      expect(existsSync(join(profile.dir, "concurrent.json"))).toBe(true);
      expect(calls.some((call) => call.url.endsWith("/login/remove-created-operation"))).toBe(true);
    });

    test("cloud cleanup finishes owned directory removal before a same-name recreation can adopt it", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const original = {
        tool: "acme",
        name: "directory-race",
        dir: join(home, "profiles", "acme", "directory-race"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "33333333-3333-4333-8333-333333333333",
      };
      const replacement = {
        ...original,
        createdAt: "2020-01-02T00:00:00Z",
        incarnationId: "44444444-4444-4444-8444-444444444444",
      };
      let generation = 0;
      let createCount = 0;
      let cleanupStarted!: () => void;
      let releaseCleanup!: () => void;
      const cleanupStartedPromise = new Promise<void>((resolveStarted) => { cleanupStarted = resolveStarted; });
      const cleanupReleasePromise = new Promise<void>((resolveRelease) => { releaseCleanup = resolveRelease; });
      const { calls, fetchImpl } = mockFetch(async (call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/directory-race")) {
          return generation === 0
            ? { status: 404, body: { error: "not found" } }
            : { status: 200, body: generation === 1 ? original : replacement };
        }
        if (call.method === "GET" && call.url.endsWith("/current")) {
          return { status: 200, body: { current: [], transactionalLoginProfileCleanup: true } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/login/create")) {
          createCount += 1;
          generation = 1;
          original.incarnationId = String(
            (call.body as { expectedIncarnationId?: string }).expectedIncarnationId,
          );
          return { status: 201, body: original };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts")) {
          generation = 2;
          return { status: 201, body: replacement };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts/acme/directory-race/login/remove-created-operation")) {
          cleanupStarted();
          await cleanupReleasePromise;
          generation = 0;
          return { status: 200, body: { removed: true, currentExists: false, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const preparation = await prepareLogin("directory-race", {
        toolId: "acme",
        env: process.env,
        store,
      });
      if (preparation.status !== "ready") throw new Error("expected ready login preparation");
      writeFileSync(join(original.dir, "old-operation.json"), "{}\n", { mode: 0o600 });

      const rollback = rollbackLoginPreparation(preparation, store);
      await cleanupStartedPromise;
      const recreate = store.addProfile({ name: original.name, tool: original.tool });
      await nextEventLoopTurn();
      await Bun.sleep(50);
      expect(calls.filter((call) => call.method === "POST" && call.url.endsWith("/accounts/login/create"))).toHaveLength(1);

      releaseCleanup();
      await rollback;
      const recreated = await recreate;

      expect(recreated.incarnationId).toBe(replacement.incarnationId);
      expect(existsSync(recreated.dir)).toBe(true);
      expect(existsSync(join(recreated.dir, "old-operation.json"))).toBe(false);
    });

    test("cloud Claude cleanup preserves auth and directory adopted during the conditional request", async () => {
      const profile = {
        tool: "claude",
        name: "claude-auth-race",
        dir: join(home, "profiles", "claude", "claude-auth-race"),
        createdAt: "2020-01-01T00:00:00Z",
        incarnationId: "55555555-5555-4555-8555-555555555555",
      };
      mkdirSync(profile.dir, { recursive: true });
      writeFileSync(join(profile.dir, "adopted.json"), "{}\n", { mode: 0o600 });
      const authKey = profileAuthRevisionKey(profile.tool, profile.name);
      const before = loadMachineStore();
      before.profileAuthRevisions[authKey] = "owned-auth";
      before.profileAuthCommitRevisions[authKey] = "owned-commit";
      before.profileAuthIncarnations[authKey] = profileAuthIncarnation(profile);
      saveStore(before);
      const { fetchImpl } = mockFetch((call) => {
        if (call.method === "GET" && call.url.endsWith("/accounts/claude/claude-auth-race")) {
          return { status: 404, body: { error: "not found" } };
        }
        if (call.url.endsWith("/accounts/claude/claude-auth-race/login/remove-created-operation")) {
          const concurrent = loadMachineStore();
          concurrent.profileAuthRevisions[authKey] = "concurrent-auth";
          concurrent.profileAuthCommitRevisions[authKey] = "concurrent-commit";
          saveStore(concurrent);
          return { status: 200, body: { removed: true, currentExists: false, expired: false } };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });

      const removed = await store.removeProfileIncarnation!(
        profile,
        { authIdentity: "owned-auth", authCommitRevision: "owned-commit" },
        { tool: profile.tool, purge: true },
      );

      expect(removed).toMatchObject({ purged: false });
      expect(existsSync(join(profile.dir, "adopted.json"))).toBe(true);
      expect(loadMachineStore()).toMatchObject({
        profileAuthRevisions: { [authKey]: "concurrent-auth" },
        profileAuthCommitRevisions: { [authKey]: "concurrent-commit" },
      });
    });

    test("login validation rejects a cloud custom tool before profile creation", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        return { status: 500, body: { error: "unexpected mutation" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });

      await expect(
        prepareLogin("new-invalid", {
          toolId: "acme",
          env: process.env,
          store,
          validateTool: () => {
            throw new Error("permission rejected");
          },
        }),
      ).rejects.toThrow("permission rejected");

      expect(calls.map((c) => c.method + " " + new URL(c.url).pathname)).toEqual(["GET /v1/tools"]);
      expect(existsSync(join(home, "profiles", "acme", "new-invalid"))).toBe(false);
    });

    test("delayed login validation rejects before local find, add, profile directory, or tool lock", async () => {
      const tool = { ...acme, id: "async-local", bin: process.execPath };
      const baseStore = resolveStore({
        ACCOUNTS_HOME: home,
        HASNA_ACCOUNTS_STORAGE_MODE: "local",
      } as NodeJS.ProcessEnv);
      await baseStore.addTool(tool);
      const operations: string[] = [];
      const store = trackProfilePersistence(baseStore, operations);
      const validation = deferredRejection();
      let markValidationStarted!: () => void;
      const validationStarted = new Promise<void>((resolve) => {
        markValidationStarted = resolve;
      });

      const preparation = prepareLogin("new-async-local", {
        toolId: tool.id,
        env: process.env,
        store,
        validateTool: () => {
          markValidationStarted();
          return validation.promise;
        },
      });
      await validationStarted;
      await nextEventLoopTurn();
      const profileDir = join(home, "profiles", tool.id, "new-async-local");
      const stateBeforeRejection = {
        operations: [...operations],
        profileDirectoryExists: existsSync(profileDir),
        profileExists: loadMachineStore().profiles.some((profile) => profile.name === "new-async-local"),
        toolLock: loadMachineStore().toolLocks?.["new-async-local"],
      };

      validation.reject(new Error("delayed permission rejection"));
      expect(stateBeforeRejection.operations).toEqual([]);
      expect(stateBeforeRejection.profileDirectoryExists).toBe(false);
      expect(stateBeforeRejection.toolLock).toBeUndefined();
      expect(stateBeforeRejection.profileExists).toBe(false);
      await expect(preparation).rejects.toThrow("delayed permission rejection");
    });

    test("delayed validation on unavailable keep rejects before API profile persistence", async () => {
      const unavailableTool = { ...acme, bin: join(home, "missing-acme") };
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...unavailableTool, builtin: false }] } };
        }
        if (c.method === "GET" && c.url.includes("/accounts")) {
          return c.url.includes("/accounts?")
            ? { status: 200, body: { accounts: [] } }
            : { status: 404, body: { error: "not found" } };
        }
        if (c.method === "POST" && c.url.endsWith("/accounts")) {
          return {
            status: 201,
            body: {
              tool: "acme",
              name: "new-async-api",
              dir: join(home, "profiles", "acme", "new-async-api"),
              createdAt: "2020-01-01T00:00:00Z",
            },
          };
        }
        return { status: 500, body: { error: "unexpected request" } };
      });
      const operations: string[] = [];
      const store = trackProfilePersistence(resolveStore(cloudEnv, { fetchImpl }), operations);
      const validation = deferredRejection();
      let markValidationStarted!: () => void;
      const validationStarted = new Promise<void>((resolve) => {
        markValidationStarted = resolve;
      });
      const input = new PassThrough();
      const output = new PassThrough();
      input.end("2\n");

      const preparation = prepareLogin("new-async-api", {
        toolId: "acme",
        env: process.env,
        forceInteractive: true,
        input: input as unknown as NodeJS.ReadStream,
        output: output as unknown as NodeJS.WriteStream,
        store,
        validateTool: () => {
          markValidationStarted();
          return validation.promise;
        },
      });
      await validationStarted;
      await nextEventLoopTurn();
      const stateBeforeRejection = {
        operations: [...operations],
        hasApiPost: calls.some((call) => call.method === "POST"),
        profileDirectoryExists: existsSync(join(home, "profiles", "acme", "new-async-api")),
      };

      validation.reject(new Error("delayed keep rejection"));
      expect(stateBeforeRejection.operations).toEqual([]);
      expect(stateBeforeRejection.hasApiPost).toBe(false);
      expect(stateBeforeRejection.profileDirectoryExists).toBe(false);
      await expect(preparation).rejects.toThrow("delayed keep rejection");
    });

    test("cold import resolves a cloud custom tool", async () => {
      const source = join(home, "source");
      mkdirSync(source, { recursive: true });
      const { calls, fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, defaultDir: source, builtin: false }] } };
        if (c.method === "POST" && c.url.endsWith("/accounts")) {
          return {
            status: 201,
            body: { tool: "acme", name: "imported", dir: source, createdAt: "2020-01-01T00:00:00Z" },
          };
        }
        return { status: 404, body: { error: "not found" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const profile = await importProfile({ name: "imported", tool: "acme", dir: source }, store);
      expect(profile.tool).toBe("acme");
      expect(calls[0]!.url).toBe(`${BASE}/v1/tools`);
    });

    test("invalid API profile names fail before network or filesystem mutation", async () => {
      const { calls, fetchImpl } = mockFetch(() => ({ status: 500, body: { error: "unexpected" } }));
      const store = resolveStore(cloudEnv, { fetchImpl });
      await expect(store.addProfile({ name: "../escape", tool: "claude" })).rejects.toThrow(/lowercase/);
      expect(calls).toEqual([]);
      expect(existsSync(join(home, "profiles"))).toBe(false);
    });

    test("API add and update remove only directories created by failed writes", async () => {
      const addDir = join(home, "profiles", "claude", "failed-add");
      const updateDir = join(home, "failed-update");
      const { fetchImpl } = mockFetch((c) => {
        if (c.method === "GET") {
          return {
            status: 200,
            body: { tool: "claude", name: "work", dir: join(home, "existing"), createdAt: "2020-01-01T00:00:00Z" },
          };
        }
        return { status: 500, body: { error: "write failed" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await expect(store.addProfile({ name: "failed-add", tool: "claude" })).rejects.toThrow(/500/);
      expect(existsSync(addDir)).toBe(false);
      await expect(store.updateProfile("work", { tool: "claude", dir: updateDir })).rejects.toThrow(/500/);
      expect(existsSync(updateDir)).toBe(false);
    });

    test("failed copied import cleans its newly copied managed directory", async () => {
      const source = join(home, "source-copy");
      mkdirSync(source, { recursive: true });
      const target = join(home, "profiles", "acme", "copied");
      const { fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        return { status: 500, body: { error: "write failed" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await expect(importProfile({ name: "copied", tool: "acme", dir: source, copy: true }, store)).rejects.toThrow(/500/);
      expect(existsSync(target)).toBe(false);
    });

    test("partial copy failure removes the newly created managed target", async () => {
      const source = join(home, "source-partial");
      mkdirSync(source, { recursive: true });
      const target = join(home, "profiles", "acme", "partial");
      const { fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        return { status: 500, body: { error: "unexpected network call" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await expect(
        importProfile(
          { name: "partial", tool: "acme", dir: source, copy: true },
          store,
          (_source, destination) => {
            mkdirSync(destination, { recursive: true });
            writeFileSync(join(destination, "partially-copied"), "incomplete");
            throw new Error("simulated partial copy failure");
          },
        ),
      ).rejects.toThrow("simulated partial copy failure");
      expect(existsSync(target)).toBe(false);
    });

    test("API rename/remove reconcile unpruned machine-local pointers", async () => {
      saveStore({
        version: 1,
        current: { acme: "old" },
        currentRevisions: { acme: "current-old" },
        applied: { acme: "old" },
        appliedRevisions: { acme: "applied-old" },
        toolLocks: { old: "acme" },
        profiles: [],
        tools: [],
      });
      const { fetchImpl } = mockFetch((c) => {
        if (c.url.endsWith("/tools")) return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        if (c.method === "POST" && c.url.endsWith("/rename")) {
          return { status: 200, body: { tool: "acme", name: "new", createdAt: "2020-01-01T00:00:00Z" } };
        }
        if (c.method === "DELETE") return { status: 204, body: null };
        const name = c.url.endsWith("/new") ? "new" : "old";
        return { status: 200, body: { tool: "acme", name, createdAt: "2020-01-01T00:00:00Z" } };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await store.renameProfile("old", "new", "acme");
      expect(loadMachineStore().current).toEqual({ acme: "new" });
      expect(loadMachineStore().applied).toEqual({ acme: "new" });
      await store.removeProfile("new", { tool: "acme" });
      expect(loadMachineStore().current).toEqual({});
      expect(loadMachineStore().applied).toEqual({});
    });

    for (const operation of ["rename", "remove"] as const) {
      test(`delayed API ${operation} reconciliation cannot overwrite a newer local profile generation`, async () => {
        const createdAt = "2020-01-01T00:00:00Z";
        const profile = { tool: "acme", name: "old", dir: "", createdAt };
        const authKey = "acme/old";
        const initialIncarnation = profileAuthIncarnation(profile);
        saveStore({
          version: 1,
          current: { acme: "old" },
          currentRevisions: { acme: "current-initial" },
          applied: { acme: "old" },
          appliedRevisions: { acme: "applied-initial" },
          profileAuthRevisions: { [authKey]: "auth-initial" },
          profileAuthCommitRevisions: { [authKey]: "commit-initial" },
          profileAuthIncarnations: { [authKey]: initialIncarnation },
          toolLocks: { old: "acme" },
          profiles: [],
          tools: [],
        });

        let releaseResponse!: () => void;
        const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
        let requestStarted!: () => void;
        const requestReachedServer = new Promise<void>((resolve) => { requestStarted = resolve; });
        const { fetchImpl } = mockFetch(async (call) => {
          if (call.url.endsWith("/tools")) {
            return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
          }
          if (call.method === "POST" && call.url.endsWith("/rename")) {
            requestStarted();
            await responseReleased;
            return { status: 200, body: { ...profile, name: "new" } };
          }
          if (call.method === "DELETE") {
            requestStarted();
            await responseReleased;
            return { status: 204, body: null };
          }
          return { status: 200, body: profile };
        });
        const store = resolveStore(cloudEnv, { fetchImpl });
        const pending = operation === "rename"
          ? store.renameProfile("old", "new", "acme")
          : store.removeProfile("old", { tool: "acme" });
        await requestReachedServer;

        const concurrent = loadMachineStore();
        concurrent.current.acme = "old";
        concurrent.currentRevisions.acme = "current-concurrent";
        concurrent.applied.acme = "old";
        concurrent.appliedRevisions.acme = "applied-concurrent";
        concurrent.profileAuthRevisions[authKey] = "auth-concurrent";
        concurrent.profileAuthCommitRevisions[authKey] = "commit-concurrent";
        concurrent.profileAuthIncarnations[authKey] = profileAuthIncarnation({
          ...profile,
          createdAt: "2020-01-02T00:00:00Z",
        });
        saveStore(concurrent);

        releaseResponse();
        await pending;
        expect(loadMachineStore()).toMatchObject({
          current: { acme: "old" },
          currentRevisions: { acme: "current-concurrent" },
          applied: { acme: "old" },
          appliedRevisions: { acme: "applied-concurrent" },
          profileAuthRevisions: { [authKey]: "auth-concurrent" },
          profileAuthCommitRevisions: { [authKey]: "commit-concurrent" },
          toolLocks: { old: "acme" },
        });
      });
    }

    test("delayed API remove deletes only its parked auth alias, not a recreated direct generation", async () => {
      const profile = { tool: "acme", name: "old", dir: "", createdAt: "2020-01-01T00:00:00Z" };
      const incarnation = profileAuthIncarnation(profile);
      const parkedKey = `@incarnation/${incarnation}`;
      const directKey = "acme/old";
      saveStore({
        version: 1,
        current: {},
        applied: {},
        profileAuthRevisions: { [parkedKey]: "auth-removed" },
        profileAuthCommitRevisions: { [parkedKey]: "commit-removed" },
        profileAuthIncarnations: { [parkedKey]: incarnation },
        toolLocks: {},
        profiles: [],
        tools: [],
      });
      let requestStarted!: () => void;
      const requestReachedServer = new Promise<void>((resolve) => { requestStarted = resolve; });
      let releaseResponse!: () => void;
      const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
      const { fetchImpl } = mockFetch(async (call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...acme, builtin: false }] } };
        }
        if (call.method === "DELETE") {
          requestStarted();
          await responseReleased;
          return { status: 204, body: null };
        }
        return { status: 200, body: profile };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const pending = store.removeProfile(profile.name, { tool: profile.tool });
      await requestReachedServer;

      const concurrent = loadMachineStore();
      concurrent.profileAuthRevisions[directKey] = "auth-recreated-apply";
      concurrent.profileAuthCommitRevisions[directKey] = "commit-recreated-apply";
      concurrent.profileAuthIncarnations[directKey] = incarnation;
      saveStore(concurrent);
      releaseResponse();
      await pending;

      const machine = loadMachineStore();
      expect(machine.profileAuthRevisions[parkedKey]).toBeUndefined();
      expect(machine.profileAuthCommitRevisions[parkedKey]).toBeUndefined();
      expect(machine.profileAuthIncarnations[parkedKey]).toBeUndefined();
      expect(machine.profileAuthRevisions[directKey]).toBe("auth-recreated-apply");
      expect(machine.profileAuthCommitRevisions[directKey]).toBe("commit-recreated-apply");
      expect(machine.profileAuthIncarnations[directKey]).toBe(incarnation);
    });

    test("API create rotates stale same-incarnation auth ownership", async () => {
      const profile = {
        tool: "claude",
        name: "acct",
        dir: join(home, "profiles", "claude", "acct"),
        createdAt: "2020-01-01T00:00:00Z",
      };
      const authKey = "claude/acct";
      saveStore({
        version: 1,
        current: {},
        applied: {},
        profileAuthRevisions: { [authKey]: "auth-removed-profile" },
        profileAuthCommitRevisions: { [authKey]: "commit-removed-profile" },
        profileAuthIncarnations: { [authKey]: profileAuthIncarnation(profile) },
        toolLocks: {},
        profiles: [],
        tools: [],
      });
      const { fetchImpl } = mockFetch(() => ({ status: 201, body: profile }));
      const store = resolveStore(cloudEnv, { fetchImpl });

      await store.addProfile({ name: profile.name, tool: profile.tool });

      const machine = loadMachineStore();
      expect(machine.profileAuthRevisions[authKey]).not.toBe("auth-removed-profile");
      expect(machine.profileAuthRevisions[authKey]).toBeTruthy();
      expect(machine.profileAuthCommitRevisions[authKey]).toBeUndefined();
      expect(machine.profileAuthIncarnations[authKey]).toBe(profileAuthIncarnation(profile));
    });

    test("API remove owns a just-created auth identity before its first commit", async () => {
      const profile = {
        tool: "claude",
        name: "acct",
        dir: join(home, "profiles", "claude", "acct"),
        createdAt: "2020-01-01T00:00:00Z",
      };
      const authKey = "claude/acct";
      const { fetchImpl } = mockFetch((call) => {
        if (call.method === "POST") return { status: 201, body: profile };
        if (call.method === "DELETE") return { status: 204, body: null };
        return { status: 200, body: profile };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      await store.addProfile({ name: profile.name, tool: profile.tool });
      expect(loadMachineStore().profileAuthRevisions[authKey]).toBeTruthy();
      expect(loadMachineStore().profileAuthCommitRevisions[authKey]).toBeUndefined();

      await store.removeProfile(profile.name, { tool: profile.tool });

      expect(loadMachineStore().profileAuthRevisions[authKey]).toBeUndefined();
      expect(loadMachineStore().profileAuthCommitRevisions[authKey]).toBeUndefined();
      expect(loadMachineStore().profileAuthIncarnations[authKey]).toBeUndefined();
    });

    test("delayed API create cannot rotate a newer apply-owned auth generation", async () => {
      const profile = {
        tool: "claude",
        name: "acct",
        dir: join(home, "profiles", "claude", "acct"),
        createdAt: "2020-01-01T00:00:00Z",
      };
      const authKey = "claude/acct";
      saveStore({
        version: 1,
        current: {},
        applied: {},
        profileAuthRevisions: { [authKey]: "auth-before-create" },
        profileAuthCommitRevisions: { [authKey]: "commit-before-create" },
        profileAuthIncarnations: { [authKey]: profileAuthIncarnation(profile) },
        toolLocks: {},
        profiles: [],
        tools: [],
      });
      let requestStarted!: () => void;
      const requestReachedServer = new Promise<void>((resolve) => { requestStarted = resolve; });
      let releaseResponse!: () => void;
      const responseReleased = new Promise<void>((resolve) => { releaseResponse = resolve; });
      const { fetchImpl } = mockFetch(async () => {
        requestStarted();
        await responseReleased;
        return { status: 201, body: profile };
      });
      const store = resolveStore(cloudEnv, { fetchImpl });
      const pending = store.addProfile({ name: profile.name, tool: profile.tool });
      await requestReachedServer;

      const concurrent = loadMachineStore();
      concurrent.profileAuthRevisions[authKey] = "auth-concurrent-apply";
      concurrent.profileAuthCommitRevisions[authKey] = "commit-concurrent-apply";
      concurrent.profileAuthIncarnations[authKey] = "incarnation-concurrent-apply";
      saveStore(concurrent);
      releaseResponse();
      await pending;

      expect(loadMachineStore()).toMatchObject({
        profileAuthRevisions: { [authKey]: "auth-concurrent-apply" },
        profileAuthCommitRevisions: { [authKey]: "commit-concurrent-apply" },
        profileAuthIncarnations: { [authKey]: "incarnation-concurrent-apply" },
      });
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
  let previousUrl: string | undefined;
  let previousKey: string | undefined;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "accounts-store-test-"));
    process.env.ACCOUNTS_HOME = home;
    delete process.env.ACCOUNTS_STORE_PATH;
    previousUrl = process.env.HASNA_ACCOUNTS_API_URL;
    previousKey = process.env.HASNA_ACCOUNTS_API_KEY;
    delete process.env.HASNA_ACCOUNTS_API_URL;
    delete process.env.HASNA_ACCOUNTS_API_KEY;
  });
  afterEach(() => {
    setLoginCleanupFaultInjectorForTests();
    rmSync(home, { recursive: true, force: true });
    delete process.env.ACCOUNTS_HOME;
    if (previousUrl === undefined) delete process.env.HASNA_ACCOUNTS_API_URL;
    else process.env.HASNA_ACCOUNTS_API_URL = previousUrl;
    if (previousKey === undefined) delete process.env.HASNA_ACCOUNTS_API_KEY;
    else process.env.HASNA_ACCOUNTS_API_KEY = previousKey;
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

  test("profile directory mutation reclaims an exact dead-owner lease", async () => {
    const dir = join(home, "profiles", "codex", "stale-directory-lease");
    const uid = typeof process.getuid === "function" ? process.getuid() : "user";
    const identity = createHash("sha256").update(dir).digest("hex").slice(0, 32);
    const lockRoot = process.platform === "win32" ? tmpdir() : "/tmp";
    const leasePath = join(lockRoot, `accounts-profile-directory-${uid}-${identity}.lock`);
    writeFileSync(
      leasePath,
      "v2:2147483647:linux-1:11111111-1111-4111-8111-111111111111",
      { mode: 0o600 },
    );
    try {
      const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
      const profile = await store.addProfile({ name: "stale-directory-lease", tool: "codex" });
      expect(profile.dir).toBe(dir);
      expect(existsSync(leasePath)).toBe(false);
    } finally {
      rmSync(leasePath, { force: true });
    }
  });

  test("failed local profile creation removes only its newly-created directory", async () => {
    const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    const dir = join(home, "profiles", "codex", "invalid-created-profile");

    await expect(store.addProfile({
      name: "invalid-created-profile",
      tool: "codex",
      cardLast4: "12" as never,
    })).rejects.toThrow(/4 digits/);

    expect(existsSync(dir)).toBe(false);
    expect(await store.findProfile("invalid-created-profile", "codex")).toBeUndefined();

    const existingDir = join(home, "profiles", "codex", "invalid-existing-profile");
    mkdirSync(existingDir, { recursive: true });
    writeFileSync(join(existingDir, "keep.json"), "{}\n", { mode: 0o600 });
    await expect(store.addProfile({
      name: "invalid-existing-profile",
      tool: "codex",
      cardLast4: "12" as never,
    })).rejects.toThrow(/4 digits/);
    expect(existsSync(join(existingDir, "keep.json"))).toBe(true);
  });

  test("local login reconciles a journaled delete before recreating the same managed directory", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const tool = {
      id: "journal-tool",
      label: "Journal Tool",
      envVar: "JOURNAL_TOOL_HOME",
      defaultDir: join(home, "journal-default"),
      bin: process.execPath,
    };
    await store.addTool(tool);
    await store.addProfile({ name: "journal-recovery", tool: "codex" });
    await store.useProfile("journal-recovery", "codex");
    const displaced = loadMachineStore();
    const displacedToolLockRevision = displaced.toolLockRevisions["journal-recovery"];
    const first = await prepareLogin("journal-recovery", {
      toolId: tool.id,
      env: process.env,
      store,
    });
    if (first.status !== "ready") throw new Error("expected ready login preparation");
    commitLoginPreparation(first, store);
    writeFileSync(join(first.profile.dir, "stale-auth.json"), "{}\n", { mode: 0o600 });
    writeFileSync(join(first.profile.dir, ".accounts-login-cleanup.json"), JSON.stringify({
      version: 1,
      cleanupOperationId: first.cleanupOperationId,
      profile: first.profile,
      ownership: {
        cleanupOperationId: first.cleanupOperationId,
        cleanupRequestedAt: first.cleanupRequestedAt,
        toolLockRevision: first.toolLockRevision,
        previousToolLock: first.previousToolLock,
        previousToolLockRevision: first.previousToolLockRevision,
        previousToolLockProfileIncarnation: first.previousToolLockProfileIncarnation,
      },
    }) + "\n", { mode: 0o600 });
    await store.removeProfile(first.profile.name, { tool: first.profile.tool });
    await store.reconcileInterruptedLoginCleanup!(first.profile.name, first.profile.tool);
    const recovered = loadMachineStore();
    expect(recovered.toolLocks["journal-recovery"]).toBe("codex");
    expect(recovered.toolLockRevisions["journal-recovery"]).toBe(displacedToolLockRevision);

    const second = await prepareLogin("journal-recovery", {
      toolId: tool.id,
      env: process.env,
      store,
    });
    if (second.status !== "ready") throw new Error("expected ready login preparation");

    expect(second.profile.incarnationId).not.toBe(first.profile.incarnationId);
    expect(existsSync(join(second.profile.dir, "stale-auth.json"))).toBe(false);
    expect(existsSync(join(second.profile.dir, ".accounts-login-cleanup.json"))).toBe(false);
  });

  test("local login replays an exact cleanup journal interrupted before profile deletion", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const tool = {
      id: "journal-replay-tool",
      label: "Journal Replay Tool",
      envVar: "JOURNAL_REPLAY_TOOL_HOME",
      defaultDir: join(home, "journal-replay-default"),
      bin: process.execPath,
    };
    await store.addTool(tool);
    const first = await prepareLogin("journal-replay", {
      toolId: tool.id,
      env: process.env,
      store,
    });
    if (first.status !== "ready") throw new Error("expected ready login preparation");
    commitLoginPreparation(first, store);
    writeFileSync(join(first.profile.dir, "stale-auth.json"), "{}\n", { mode: 0o600 });
    writeFileSync(join(first.profile.dir, ".accounts-login-cleanup.json"), JSON.stringify({
      version: 1,
      cleanupOperationId: "99999999-9999-4999-8999-999999999999",
      profile: first.profile,
      ownership: {
        toolLockRevision: first.toolLockRevision,
        previousToolLock: first.previousToolLock,
        previousToolLockRevision: first.previousToolLockRevision,
        previousToolLockProfileIncarnation: first.previousToolLockProfileIncarnation,
      },
    }) + "\n", { mode: 0o600 });

    const second = await prepareLogin("journal-replay", {
      toolId: tool.id,
      env: process.env,
      store,
    });
    if (second.status !== "ready") throw new Error("expected ready login preparation");

    expect(second.profile.incarnationId).not.toBe(first.profile.incarnationId);
    expect(existsSync(join(second.profile.dir, "stale-auth.json"))).toBe(false);
    expect(existsSync(join(second.profile.dir, ".accounts-login-cleanup.json"))).toBe(false);
  });

  test("durable preparation intent recovers every local preparation and rollback crash boundary", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const tool = {
      id: "intent-tool",
      label: "Intent Tool",
      envVar: "INTENT_TOOL_HOME",
      defaultDir: join(home, "intent-default"),
      bin: process.execPath,
    };
    await store.addTool(tool);
    const preparationFaults: LoginCleanupFaultPoint[] = ["pre-create", "post-create", "post-lock"];
    const rollbackFaults: LoginCleanupFaultPoint[] = [
      "post-delete",
      "post-lock-restore",
      "pre-purge",
    ];

    for (const point of [...preparationFaults, ...rollbackFaults]) {
      const name = `intent-${point}`;
      await store.addProfile({ name, tool: "codex" });
      await store.useProfile(name, "codex");
      const before = loadMachineStore();
      const previousRevision = before.toolLockRevisions[name];
      setLoginCleanupFaultInjectorForTests((candidate) => {
        if (candidate === point) throw new Error(`crash:${point}`);
      });

      if (preparationFaults.includes(point)) {
        await expect(prepareLogin(name, {
          toolId: tool.id,
          env: process.env,
          store,
        })).rejects.toThrow(`injected login cleanup fault at ${point}`);
      } else {
        const prepared = await prepareLogin(name, {
          toolId: tool.id,
          env: process.env,
          store,
        });
        if (prepared.status !== "ready") throw new Error("expected ready login preparation");
        writeFileSync(join(prepared.profile.dir, "interrupted.json"), "{}\n", { mode: 0o600 });
        await expect(rollbackLoginPreparation(prepared, store)).rejects.toThrow(
          `injected login cleanup fault at ${point}`,
        );
      }

      setLoginCleanupFaultInjectorForTests();
      await store.reconcileInterruptedLoginCleanup!(name, tool.id);
      const recovered = loadMachineStore();
      expect({
        point,
        createdProfileSurvived: recovered.profiles.some(
          (profile) => profile.name === name && profile.tool === tool.id,
        ),
      }).toEqual({ point, createdProfileSurvived: false });
      expect(recovered.profiles.some((profile) => profile.name === name && profile.tool === "codex")).toBe(true);
      expect(recovered.toolLocks[name]).toBe("codex");
      expect(recovered.toolLockRevisions[name]).toBe(previousRevision);
      expect(existsSync(join(home, "profiles", tool.id, name))).toBe(false);
    }
  });

  test("a concurrent same-target login cannot reconcile a live preparation intent", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const tool = {
      id: "live-intent-tool",
      label: "Live Intent Tool",
      envVar: "LIVE_INTENT_TOOL_HOME",
      defaultDir: join(home, "live-intent-default"),
      bin: process.execPath,
    };
    await store.addTool(tool);
    const first = await prepareLogin("live-intent", {
      toolId: tool.id,
      env: process.env,
      store,
    });
    if (first.status !== "ready") throw new Error("expected ready login preparation");
    writeFileSync(join(first.profile.dir, "first-owned.json"), "{}\n", { mode: 0o600 });
    const before = loadMachineStore();

    await expect(prepareLogin("live-intent", {
      toolId: tool.id,
      env: process.env,
      store,
    })).rejects.toThrow(/login preparation is still in progress/);

    expect(await store.getProfile("live-intent", tool.id)).toEqual(first.profile);
    expect(existsSync(join(first.profile.dir, "first-owned.json"))).toBe(true);
    const after = loadMachineStore();
    expect(after.toolLocks["live-intent"]).toBe(before.toolLocks["live-intent"]);
    expect(after.toolLockRevisions["live-intent"]).toBe(
      before.toolLockRevisions["live-intent"],
    );

    await rollbackLoginPreparation(first, store);
    expect(await store.findProfile("live-intent", tool.id)).toBeUndefined();
    expect(existsSync(first.profile.dir)).toBe(false);
  });

  test("legacy three-argument restoreCurrent still restores the named prior profile", async () => {
    const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    await store.addProfile({ name: "prior", tool: "claude" });
    await store.addProfile({ name: "failed", tool: "claude" });
    await store.useProfile("failed", "claude");

    expect(await store.restoreCurrent("claude", "failed", "prior")).toBe(true);
    expect((await store.currentProfile("claude"))?.name).toBe("prior");
  });

  test("local login operation replay rejects a replacement target incarnation", async () => {
    const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    const original = await store.addProfile({ name: "target", tool: "claude" });
    const operationId = "local-target-incarnation-binding";
    await store.useProfileForLogin!("target", "claude", operationId, original);
    await store.removeProfile("target", { tool: "claude" });
    const replacement = await store.addProfile({ name: "target", tool: "claude" });

    await expect(
      store.useProfileForLogin!("target", "claude", operationId, replacement),
    ).rejects.toThrow(/operation id is already bound to another profile incarnation/);
    expect(await store.currentProfile("claude")).toBeUndefined();
  });

  test("operation rollback never restores a recreated local profile with colliding legacy fields", async () => {
    const store = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    const prior = await store.addProfile({ name: "prior", tool: "claude" });
    const failed = await store.addProfile({ name: "failed", tool: "claude" });
    await store.useProfile("prior", "claude");
    const operationId = "local-incarnation-collision";
    await store.useProfileForLogin!("failed", "claude", operationId, failed);

    await store.removeProfile("prior", { tool: "claude" });
    const replacement = await store.addProfile({ name: "prior", tool: "claude" });
    const machine = loadMachineStore();
    const replacementRecord = machine.profiles.find(
      (profile) => profile.name === replacement.name && profile.tool === replacement.tool,
    );
    if (!replacementRecord) throw new Error("missing local incarnation replacement fixture");
    replacementRecord.createdAt = prior.createdAt;
    replacementRecord.dir = prior.dir;
    saveStore(machine);

    expect(await store.restoreCurrentOperation!("claude", "failed", operationId)).toBe(true);
    expect(await store.currentProfile("claude")).toBeUndefined();
  });

  test("failed new-login preparation does not remove a same-metadata profile with a newer auth commit", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const original = await store.addProfile({ name: "recreated", tool: "claude" });
    const preparation = {
      status: "ready" as const,
      profile: original,
      tool: getTool("claude"),
      args: [],
      created: true,
      createdProfileDir: true,
    };
    const originalIdentity = "failed-login-auth-identity";
    const originalCommit = "failed-login-auth-commit";
    const originalKey = profileAuthRevisionKey(original.tool, original.name);
    const originalMachine = loadMachineStore();
    originalMachine.profileAuthRevisions[originalKey] = originalIdentity;
    originalMachine.profileAuthCommitRevisions[originalKey] = originalCommit;
    originalMachine.profileAuthIncarnations[originalKey] = profileAuthIncarnation(original);
    saveStore(originalMachine);
    await store.removeProfile(original.name, { tool: original.tool });
    const replacement = await store.addProfile({ name: original.name, tool: original.tool });
    const replacementIdentity = originalIdentity;
    const replacementMachine = loadMachineStore();
    const replacementRecord = replacementMachine.profiles.find(
      (profile) => profile.name === replacement.name && profile.tool === replacement.tool,
    );
    if (!replacementRecord) throw new Error("missing replacement profile fixture");
    replacementRecord.createdAt = original.createdAt;
    replacementMachine.profileAuthRevisions[originalKey] = replacementIdentity;
    replacementMachine.profileAuthCommitRevisions[originalKey] = "replacement-auth-commit";
    replacementMachine.profileAuthIncarnations[originalKey] = profileAuthIncarnation(replacementRecord);
    saveStore(replacementMachine);
    writeFileSync(join(replacement.dir, "replacement.json"), '{"keep":true}\n', { mode: 0o600 });

    await rollbackLoginPreparation(preparation, store, originalIdentity, originalCommit);

    expect((await store.getProfile(replacement.name, replacement.tool)).createdAt).toBe(original.createdAt);
    expect(loadMachineStore().profileAuthRevisions[originalKey]).toBe(replacementIdentity);
    expect(existsSync(join(replacement.dir, "replacement.json"))).toBe(true);
  });

  test("failed non-Claude login removes only its created profile and restores the exact prior tool lock", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    await store.addProfile({ name: "cleanup", tool: "codex" });
    await store.useProfile("cleanup", "codex");
    const before = loadMachineStore();
    const previousToolLock = before.toolLocks.cleanup;
    const previousToolLockRevision = before.toolLockRevisions.cleanup;
    const customTool = {
      id: "cleanup-tool",
      label: "Cleanup Tool",
      envVar: "CLEANUP_HOME",
      defaultDir: join(home, "cleanup-default"),
      bin: process.execPath,
    };
    await store.addTool(customTool);

    const preparation = await prepareLogin("cleanup", {
      toolId: customTool.id,
      env: process.env,
      store,
    });
    if (preparation.status !== "ready") throw new Error("expected ready login preparation");
    expect(preparation.created).toBe(true);
    expect(loadMachineStore().toolLocks.cleanup).toBe(customTool.id);

    await rollbackLoginPreparation(preparation, store);

    expect(await store.findProfile("cleanup", customTool.id)).toBeUndefined();
    expect(existsSync(preparation.profile.dir)).toBe(false);
    const after = loadMachineStore();
    expect(after.toolLocks.cleanup).toBe(previousToolLock);
    expect(after.toolLockRevisions.cleanup).toBe(previousToolLockRevision);
    expect(after.current.codex).toBe("cleanup");
  });

  test("failed local login cleans its directory after a concurrent exact profile deletion", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    await store.addProfile({ name: "deleted-before-rollback", tool: "codex" });
    await store.useProfile("deleted-before-rollback", "codex");
    const displaced = loadMachineStore();
    const displacedRevision = displaced.toolLockRevisions["deleted-before-rollback"];
    const customTool = {
      id: "deleted-cleanup-tool",
      label: "Deleted Cleanup Tool",
      envVar: "DELETED_CLEANUP_HOME",
      defaultDir: join(home, "deleted-cleanup-default"),
      bin: process.execPath,
    };
    await store.addTool(customTool);
    const preparation = await prepareLogin("deleted-before-rollback", {
      toolId: customTool.id,
      env: process.env,
      store,
    });
    if (preparation.status !== "ready") throw new Error("expected ready login preparation");
    writeFileSync(join(preparation.profile.dir, "failed-auth.json"), "{}\n", { mode: 0o600 });
    await store.removeProfile(preparation.profile.name, { tool: preparation.profile.tool });

    await rollbackLoginPreparation(preparation, store);

    expect(existsSync(preparation.profile.dir)).toBe(false);
    const after = loadMachineStore();
    expect(after.toolLocks[preparation.profile.name]).toBe("codex");
    expect(after.toolLockRevisions[preparation.profile.name]).toBe(displacedRevision);
  });

  test("failed login never restores a displaced tool lock onto a recreated profile", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const displaced = await store.addProfile({ name: "recreated-lock", tool: "codex" });
    await store.useProfile(displaced.name, displaced.tool);
    const customTool = {
      id: "recreated-lock-tool",
      label: "Recreated Lock Tool",
      envVar: "RECREATED_LOCK_HOME",
      defaultDir: join(home, "recreated-lock-default"),
      bin: process.execPath,
    };
    await store.addTool(customTool);
    const preparation = await prepareLogin(displaced.name, {
      toolId: customTool.id,
      env: process.env,
      store,
    });
    if (preparation.status !== "ready") throw new Error("expected ready login preparation");

    await store.removeProfile(displaced.name, { tool: displaced.tool });
    const replacement = await store.addProfile({ name: displaced.name, tool: displaced.tool });
    expect(replacement.incarnationId).not.toBe(displaced.incarnationId);
    await rollbackLoginPreparation(preparation, store);

    expect(await store.findProfile(preparation.profile.name, customTool.id)).toBeUndefined();
    expect((await store.getProfile(replacement.name, replacement.tool)).incarnationId)
      .toBe(replacement.incarnationId);
    expect(loadMachineStore().toolLocks[replacement.name]).toBeUndefined();
  });

  test("failed-login email rollback does not mutate a recreated Claude profile", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const original = await store.addProfile({
      name: "email-aba",
      tool: "claude",
      email: "failed@example.test",
    });
    const authKey = profileAuthRevisionKey(original.tool, original.name);
    const originalMachine = loadMachineStore();
    originalMachine.profileAuthRevisions[authKey] = "original-auth-identity";
    originalMachine.profileAuthCommitRevisions[authKey] = "original-auth-commit";
    originalMachine.profileAuthIncarnations[authKey] = profileAuthIncarnation(original);
    saveStore(originalMachine);

    await store.removeProfile(original.name, { tool: original.tool });
    const replacement = await store.addProfile({
      name: original.name,
      tool: original.tool,
      email: "failed@example.test",
    });
    const replacementMachine = loadMachineStore();
    replacementMachine.profileAuthRevisions[authKey] = "replacement-auth-identity";
    replacementMachine.profileAuthCommitRevisions[authKey] = "replacement-auth-commit";
    replacementMachine.profileAuthIncarnations[authKey] = profileAuthIncarnation(replacement);
    saveStore(replacementMachine);

    await store.restoreProfileState!(
      original,
      { email: { expected: "failed@example.test", restore: null } },
      { authIdentity: "original-auth-identity", authCommitRevision: "original-auth-commit" },
    );

    expect((await store.getProfile(replacement.name, replacement.tool)).email).toBe("failed@example.test");
  });

  test("LocalStore resolution plus list/show reads create no lock, store, or directory", async () => {
    const absentHome = join(home, "read-only-absent");
    process.env.ACCOUNTS_HOME = absentHome;
    const store = resolveStore({
      ACCOUNTS_HOME: absentHome,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);

    expect(await store.listProfiles()).toEqual([]);
    await expect(store.getProfile("missing", "codex")).rejects.toThrow(/no profile named/);
    expect(await store.listTools()).toEqual(expect.arrayContaining([expect.objectContaining({ id: "codex" })]));

    expect(existsSync(absentHome)).toBe(false);
    expect(existsSync(join(absentHome, ".store.lock"))).toBe(false);
    expect(existsSync(join(absentHome, "accounts.json"))).toBe(false);
    expect(existsSync(join(absentHome, "profiles"))).toBe(false);
    process.env.ACCOUNTS_HOME = home;
  });

  test("LocalStore read-only resolution and list/show do not rewrite legacy JSON", async () => {
    const initial = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    const profile = await initial.addProfile({ name: "legacy-upgrade", tool: "codex" });
    const legacy = loadMachineStore();
    const record = legacy.profiles.find(
      (candidate) => candidate.name === profile.name && candidate.tool === profile.tool,
    );
    if (!record) throw new Error("missing legacy upgrade fixture");
    delete record.incarnationId;
    saveStore(legacy);
    const registryPath = join(home, "accounts.json");
    const before = readFileSync(registryPath, "utf8");

    const readOnly = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    expect((await readOnly.listProfiles(profile.tool))[0]?.incarnationId).toBeUndefined();
    expect((await readOnly.getProfile(profile.name, profile.tool)).incarnationId).toBeUndefined();

    expect(readFileSync(registryPath, "utf8")).toBe(before);
    expect(existsSync(join(home, ".store.lock"))).toBe(false);
  });

  test("validated login preparation assigns a legacy incarnation inside its mutating transaction", async () => {
    const initial = resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv);
    const customTool = {
      id: "legacy-login-tool",
      label: "Legacy Login Tool",
      envVar: "LEGACY_LOGIN_HOME",
      defaultDir: join(home, "legacy-login-default"),
      bin: process.execPath,
    };
    await initial.addTool(customTool);
    const profile = await initial.addProfile({ name: "legacy-login", tool: customTool.id });
    const legacy = loadMachineStore();
    const record = legacy.profiles.find(
      (candidate) => candidate.name === profile.name && candidate.tool === profile.tool,
    );
    if (!record) throw new Error("missing legacy login fixture");
    delete record.incarnationId;
    saveStore(legacy);
    let validated = false;

    const preparation = await prepareLogin(profile.name, {
      toolId: profile.tool,
      env: process.env,
      store: resolveStore({ ACCOUNTS_HOME: home } as NodeJS.ProcessEnv),
      validateTool: () => {
        validated = true;
      },
    });

    expect(validated).toBe(true);
    expect(preparation.profile.incarnationId).toMatch(/^[0-9a-f-]{36}$/i);
    expect((await initial.getProfile(profile.name, profile.tool)).incarnationId).toBe(preparation.profile.incarnationId);
  });

  test("local non-Claude profile-field rollback fails closed without an incarnation token", async () => {
    const store = resolveStore({
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
    } as NodeJS.ProcessEnv);
    const profile = await store.addProfile({
      name: "legacy-field-rollback",
      tool: "codex",
      email: "failed@example.test",
    });
    const legacy = loadMachineStore();
    const legacyRecord = legacy.profiles.find(
      (candidate) => candidate.name === profile.name && candidate.tool === profile.tool,
    );
    if (!legacyRecord) throw new Error("missing legacy non-Claude rollback fixture");
    delete legacyRecord.incarnationId;
    delete profile.incarnationId;
    saveStore(legacy);

    await store.restoreProfileState!(profile, {
      email: { expected: "failed@example.test", restore: null },
    });

    expect((await store.getProfile(profile.name, profile.tool)).email).toBe("failed@example.test");
  });
});
