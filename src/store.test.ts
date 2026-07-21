import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { resolveStore, type AccountsStore } from "./lib/store.js";
import { resolveSupervisorLaunch } from "./lib/supervisor.js";
import { clearCustomToolsCache, getTool } from "./lib/tools.js";
import { loginToolChoices, prepareLogin, rollbackLoginPreparation } from "./lib/login.js";
import { importProfile } from "./lib/import-profile.js";
import { loadMachineStore, saveStore } from "./storage.js";

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
      return { status: 200, body: { tool: "claude", name: "work", updatedAt: "2020-01-01T00:00:00Z" } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    const { toolId } = await store.useProfile("work", "claude");
    expect(toolId).toBe("claude");
    expect(calls.some((c) => c.method === "PUT" && c.url === `${BASE}/v1/current/claude`)).toBe(true);
  });

  test("rollback helpers restore nullable profile state and conditionally clear API current", async () => {
    const { calls, fetchImpl } = mockFetch((c) => {
      if (c.method === "PATCH") {
        return { status: 200, body: { tool: "claude", name: "work", createdAt: "2020-01-01T00:00:00Z" } };
      }
      return { status: 200, body: { restored: true } };
    });
    const store = resolveStore(cloudEnv, { fetchImpl });
    await store.restoreProfileState({
      name: "work",
      tool: "claude",
      dir: "/profiles/work",
      createdAt: "2020-01-01T00:00:00Z",
    });
    expect(calls[0]).toMatchObject({
      method: "PATCH",
      url: `${BASE}/v1/accounts/claude/work`,
      body: { email: null, lastUsedAt: null },
    });
    expect(await store.restoreCurrent("claude", "work")).toBe(true);
    expect(calls[1]).toMatchObject({
      method: "POST",
      url: `${BASE}/v1/current/claude/restore`,
      body: { expectedName: "work" },
    });
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
        if (c.method === "POST" && c.url.endsWith("/accounts")) {
          return {
            status: 201,
            body: {
              tool: "acme",
              name: "work",
              dir: join(home, "profiles", "acme", "work"),
              createdAt: "2020-01-01T00:00:00Z",
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

    test("failed cloud login rollback removes its registry profile and newly created managed directory", async () => {
      const executableTool = { ...acme, bin: process.execPath };
      const profile = {
        tool: "acme",
        name: "failed",
        dir: join(home, "profiles", "acme", "failed"),
        createdAt: "2020-01-01T00:00:00Z",
      };
      let created = false;
      const { calls, fetchImpl } = mockFetch((call) => {
        if (call.url.endsWith("/tools")) {
          return { status: 200, body: { tools: [{ ...executableTool, builtin: false }] } };
        }
        if (call.method === "GET" && call.url.endsWith("/accounts/acme/failed")) {
          return created ? { status: 200, body: profile } : { status: 404, body: { error: "not found" } };
        }
        if (call.method === "POST" && call.url.endsWith("/accounts")) {
          created = true;
          return { status: 201, body: profile };
        }
        if (call.method === "DELETE" && call.url.endsWith("/accounts/acme/failed")) {
          created = false;
          return { status: 204, body: {} };
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
      expect(calls.some((call) => call.method === "DELETE" && call.url.endsWith("/accounts/acme/failed"))).toBe(true);
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
        applied: { acme: "old" },
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
});
