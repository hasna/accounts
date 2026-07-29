/**
 * Regression coverage for the published-consumer contract of the root
 * synchronous compatibility exports.
 *
 * The hazard this file exists for, measured on the fleet before it was fixed:
 * `@hasna/economy`'s `resolveAccountForAgent` wraps EVERY root accounts call in
 * `try {} catch {}`, so making the read exports throw under hosted authority did
 * not produce the intended loud failure — it produced a silent `null`, zeroing
 * per-account cost attribution on every cloud-mode machine with no error, no log
 * and no alert. Reads therefore stay readable and announce themselves through
 * `process.emitWarning`, which a `catch` block cannot swallow; only writes fail
 * closed, because a synchronous root write under hosted authority would diverge
 * the local file from the authoritative registry.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCustomTool,
  addProfile,
  appliedProfile,
  appliedProfileName,
  currentProfile,
  ensureProfileForLogin,
  findProfile,
  getProfile,
  getProfileToolLock,
  getTool,
  listProfiles,
  listTools,
  loadStore,
  lockProfileTool,
  redetectEmail,
  removeCustomTool,
  removeProfile,
  renameProfile,
  saveStore,
  updateProfile,
  useProfile,
} from "./index.js";
import { resetRootCompatWarnings } from "./lib/local-compat.js";
import type { Profile, Store } from "./types.js";

const AUTHORITY_KEYS = [
  "HASNA_ACCOUNTS_STORAGE_MODE",
  "ACCOUNTS_STORAGE_MODE",
  "HASNA_ACCOUNTS_MODE",
  "HASNA_ACCOUNTS_API_URL",
  "ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_KEY",
  "HASNA_ACCOUNTS_STRICT_ROOT_COMPAT",
] as const;

const HOSTED_AUTHORITY = {
  HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
  HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
  HASNA_ACCOUNTS_API_KEY: "fixture-authority",
} as const;

/**
 * Faithful replay of `@hasna/economy` 0.3.7 `resolveAccountForAgent`
 * (dist/cli/index.js): every accounts call is individually try/caught, a
 * throwing `listTools()` yields an empty id set, and an empty id set skips the
 * whole per-tool loop and returns `null`.
 */
function economyResolveAccount(
  toolId: string,
  env: NodeJS.ProcessEnv,
): { source: string; name: string } | null {
  let toolIds: Set<string>;
  try {
    toolIds = new Set(listTools().map((tool) => tool.id));
  } catch {
    toolIds = new Set();
  }
  if (!toolIds.has(toolId)) return null;

  let tool;
  try {
    tool = getTool(toolId);
  } catch {
    return null;
  }

  const configuredDir = env[tool.envVar];
  if (configuredDir) {
    try {
      const match = listProfiles(tool.id).find(
        (profile) => profile.dir.replace(/\/+$/, "") === configuredDir.replace(/\/+$/, ""),
      );
      if (match) return { source: "env", name: match.name };
    } catch {
      /* economy swallows this */
    }
  }

  try {
    const applied = appliedProfile(toolId);
    if (applied) return { source: "applied", name: applied.name };
  } catch {
    /* economy swallows this */
  }

  try {
    const current = currentProfile(toolId);
    if (current) return { source: "current", name: current.name };
  } catch {
    /* economy swallows this */
  }

  return null;
}

describe("root compatibility exports under a swallowing consumer", () => {
  let home: string;
  let saved: Partial<Record<(typeof AUTHORITY_KEYS)[number], string>>;
  let warnings: { code: string; message: string }[];
  let onWarning: (warning: Error & { code?: string }) => void;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "accounts-root-consumer-"));
    process.env.ACCOUNTS_HOME = home;
    saved = {};
    for (const key of AUTHORITY_KEYS) {
      if (process.env[key] !== undefined) saved[key] = process.env[key];
      delete process.env[key];
    }
    resetRootCompatWarnings();
    warnings = [];
    onWarning = (warning) => warnings.push({ code: warning.code ?? "", message: warning.message });
    process.on("warning", onWarning);
  });

  afterEach(() => {
    process.off("warning", onWarning);
    rmSync(home, { recursive: true, force: true });
    delete process.env.ACCOUNTS_HOME;
    for (const key of AUTHORITY_KEYS) {
      delete process.env[key];
      if (saved[key] !== undefined) process.env[key] = saved[key];
    }
    resetRootCompatWarnings();
  });

  test("hosted authority keeps a try/caught consumer's account attribution intact", () => {
    const profile = seedAppliedProfile("attributed");
    const localAttribution = economyResolveAccount("claude", { CLAUDE_CONFIG_DIR: profile.dir });
    expect(localAttribution).toEqual({ source: "env", name: "attributed" });

    Object.assign(process.env, HOSTED_AUTHORITY);
    // The whole point: identical answer under hosted authority, not a silent null.
    expect(economyResolveAccount("claude", { CLAUDE_CONFIG_DIR: profile.dir })).toEqual({
      source: "env",
      name: "attributed",
    });
    expect(economyResolveAccount("claude", {})).toEqual({ source: "applied", name: "attributed" });
  });

  test("every read that a consumer can swallow still answers under hosted authority", () => {
    const profile = seedAppliedProfile("readable");
    Object.assign(process.env, HOSTED_AUTHORITY);

    expect(loadStore().version).toBe(1);
    expect(listTools().some((tool) => tool.id === "claude")).toBe(true);
    expect(getTool("claude").id).toBe("claude");
    expect(listProfiles("claude").map((p) => p.name)).toEqual(["readable"]);
    expect(findProfile("readable", "claude")?.name).toBe("readable");
    expect(getProfile("readable", "claude").name).toBe("readable");
    expect(getProfileToolLock("readable")).toBe("claude");
    expect(appliedProfile("claude")?.name).toBe("readable");
    expect(appliedProfileName("claude")).toBe("readable");
    expect(currentProfile("claude")?.name).toBe(profile.name);
  });

  test("a swallowed read still emits an unswallowable process warning", async () => {
    seedAppliedProfile("noisy");
    Object.assign(process.env, HOSTED_AUTHORITY);
    warnings.length = 0;

    let threw = false;
    try {
      listTools();
    } catch {
      threw = true;
    }
    expect(threw).toBe(false);

    await flushWarnings();
    expect(warnings.map((w) => w.code)).toContain("HASNA_ACCOUNTS_LOCAL_COMPAT_READ");
    expect(warnings.some((w) => w.message.includes("listTools"))).toBe(true);
  });

  test("the warning is emitted once per operation, not once per call", async () => {
    seedAppliedProfile("quiet");
    Object.assign(process.env, HOSTED_AUTHORITY);
    warnings.length = 0;

    for (let i = 0; i < 5; i += 1) listProfiles("claude");
    await flushWarnings();
    expect(warnings.filter((w) => w.message.includes("listProfiles")).length).toBe(1);

    listTools();
    await flushWarnings();
    expect(warnings.filter((w) => w.message.includes("listTools")).length).toBe(1);
  });

  test("no warning is emitted while local authority is in force", async () => {
    seedAppliedProfile("local-only");
    warnings.length = 0;
    listTools();
    listProfiles("claude");
    loadStore();
    await flushWarnings();
    expect(warnings.filter((w) => w.code === "HASNA_ACCOUNTS_LOCAL_COMPAT_READ")).toEqual([]);
  });

  test.each([
    ["saveStore", () => saveStore(emptyStore())],
    ["addProfile", () => addProfile({ name: "must-not-write", tool: "claude" })],
    ["removeProfile", () => removeProfile("writable")],
    ["renameProfile", () => renameProfile("writable", "renamed", "claude")],
    ["updateProfile", () => updateProfile("writable", { description: "no" })],
    ["redetectEmail", () => redetectEmail("writable", "claude")],
    ["useProfile", () => useProfile("writable", "claude")],
    ["lockProfileTool", () => lockProfileTool("writable", "claude")],
    ["ensureProfileForLogin", () => ensureProfileForLogin("must-not-write")],
    [
      "addCustomTool",
      () =>
        addCustomTool({
          id: "fixture-tool",
          label: "Fixture",
          envVar: "FIXTURE_HOME",
          defaultDir: "/fixture",
          bin: "fixture",
        }),
    ],
    ["removeCustomTool", () => removeCustomTool("fixture-tool")],
  ])("the write export %s still fails closed under hosted authority", (_label, call) => {
    seedAppliedProfile("writable");
    const before = Bun.file(join(home, "accounts.json")).size;
    Object.assign(process.env, HOSTED_AUTHORITY);

    expect(call).toThrow(/local-only compatibility/);
    // Nothing was written on the way to the throw.
    expect(Bun.file(join(home, "accounts.json")).size).toBe(before);
  });

  test("strict mode restores fail-closed reads for callers that want them", () => {
    seedAppliedProfile("strict");
    Object.assign(process.env, HOSTED_AUTHORITY, { HASNA_ACCOUNTS_STRICT_ROOT_COMPAT: "1" });

    expect(() => listTools()).toThrow(/local-only compatibility/);
    expect(() => listProfiles("claude")).toThrow(/local-only compatibility/);
    expect(() => appliedProfile("claude")).toThrow(/local-only compatibility/);
    expect(() => loadStore()).toThrow(/local-only compatibility/);
    // The machine-local pointer is exempt in every mode.
    expect(appliedProfileName("claude")).toBe("strict");
    // A swallowing consumer loses attribution here — that is the opt-in cost.
    expect(economyResolveAccount("claude", {})).toBeNull();
  });

  test("strict mode is off unless explicitly enabled", () => {
    seedAppliedProfile("default-lenient");
    Object.assign(process.env, HOSTED_AUTHORITY, { HASNA_ACCOUNTS_STRICT_ROOT_COMPAT: "0" });
    expect(listTools().some((tool) => tool.id === "claude")).toBe(true);
    expect(economyResolveAccount("claude", {})).toEqual({
      source: "applied",
      name: "default-lenient",
    });
  });

  test("reads never create the local store when it does not exist yet", () => {
    Object.assign(process.env, HOSTED_AUTHORITY);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
    expect(listProfiles()).toEqual([]);
    expect(loadStore().profiles).toEqual([]);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
  });

  /** Seed a local profile plus the machine-local applied pointer for it. */
  function seedAppliedProfile(name: string, toolId = "claude"): Profile {
    const profile = addProfile({ name, tool: toolId });
    lockProfileTool(profile.name, profile.tool);
    useProfile(name, toolId);
    const store = loadStore();
    store.applied[toolId] = name;
    saveStore(store);
    return profile;
  }
});

/**
 * `process.emitWarning` dispatches on the next tick, so a synchronous assertion
 * would read the collector before the listener has run.
 */
async function flushWarnings(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

function emptyStore(): Store {
  return {
    version: 1,
    current: {},
    applied: {},
    toolLocks: {},
    profiles: [],
    tools: [],
  };
}
