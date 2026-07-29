import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCustomTool,
  addProfile,
  appliedProfile,
  appliedProfileName,
  ensureProfileForLogin,
  listProfiles,
  listTools,
  loadStore,
  saveStore,
} from "./index.js";
import type { Store } from "./types.js";

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

describe("root synchronous compatibility exports", () => {
  let home: string;
  let saved: Partial<Record<(typeof AUTHORITY_KEYS)[number], string>>;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "accounts-root-compat-"));
    process.env.ACCOUNTS_HOME = home;
    saved = {};
    for (const key of AUTHORITY_KEYS) {
      if (process.env[key] !== undefined) saved[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    delete process.env.ACCOUNTS_HOME;
    for (const key of AUTHORITY_KEYS) {
      delete process.env[key];
      if (saved[key] !== undefined) process.env[key] = saved[key];
    }
  });

  test("explicit local authority wins over retained hosted URL and key", () => {
    process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
    process.env.HASNA_ACCOUNTS_API_URL = "https://accounts.example.test";
    process.env.HASNA_ACCOUNTS_API_KEY = "fixture-authority";
    expect(loadStore().version).toBe(1);
    expect(listTools().some((tool) => tool.id === "claude")).toBe(true);
    expect(listProfiles()).toEqual([]);
    expect(addProfile({ name: "local-only", tool: "claude" }).name).toBe("local-only");
    expect(listProfiles().map((profile) => profile.name)).toEqual(["local-only"]);
  });

  test("an incomplete retained hosted configuration resolves to local authority", () => {
    process.env.HASNA_ACCOUNTS_API_URL = "https://accounts.example.test";
    expect(loadStore().version).toBe(1);
    expect(addProfile({ name: "still-local", tool: "claude" }).name).toBe("still-local");
  });

  test.each([
    [
      "implicit hosted URL and key",
      {
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
    [
      "cloud mode",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
    [
      "self-hosted mode",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "self_hosted",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
  ])("writes fail closed for %s while reads stay answerable", (_label, env) => {
    Object.assign(process.env, env);
    expect(() => addProfile({ name: "must-not-write" })).toThrow(/local-only compatibility/);
    expect(() => saveStore(emptyStore())).toThrow(/local-only compatibility/);
    expect(() =>
      addCustomTool({
        id: "fixture-tool",
        label: "Fixture",
        envVar: "FIXTURE_HOME",
        defaultDir: "/fixture",
        bin: "fixture",
      }),
    ).toThrow(/local-only compatibility/);
    // Reads answer from the machine-local registry and announce themselves via
    // process.emitWarning instead of throwing, because the measured consumers
    // swallow throws and would silently lose their answer. See
    // root-compat-consumer.test.ts for the full contract.
    expect(listProfiles()).toEqual([]);
    expect(loadStore().version).toBe(1);
    expect(listTools().some((tool) => tool.id === "claude")).toBe(true);
    // No read created the local store on its way to answering.
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
    expect(existsSync(join(home, "profiles"))).toBe(false);
  });

  test.each([
    [
      "incomplete explicit cloud",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
      },
      /requires HASNA_ACCOUNTS_API_KEY/,
    ],
    ["unknown mode", { HASNA_ACCOUNTS_STORAGE_MODE: "typo" }, /invalid accounts storage mode/],
    [
      "retired alias before unknown mode",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "remote",
        ACCOUNTS_STORAGE_MODE: "typo",
      },
      /invalid accounts storage mode/,
    ],
  ])("propagates canonical resolver errors for %s", (_label, env, error) => {
    Object.assign(process.env, env);
    expect(() => listProfiles()).toThrow(error);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
  });

  test.each([
    [
      "retired storage aliases before canonical cloud",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "remote",
        ACCOUNTS_STORAGE_MODE: "hybrid",
        HASNA_ACCOUNTS_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
      },
      /requires HASNA_ACCOUNTS_API_KEY/,
    ],
    [
      "retired storage alias before canonical self-hosted",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "s3",
        ACCOUNTS_STORAGE_MODE: "self_hosted",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
      /requires HASNA_ACCOUNTS_API_URL/,
    ],
  ])("retired aliases cannot mask hosted authority for %s", (_label, env, error) => {
    Object.assign(process.env, env);
    expect(() => ensureProfileForLogin("must-not-write")).toThrow(error);
    expect(() => addProfile({ name: "must-not-write" })).toThrow(error);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
    expect(existsSync(join(home, "profiles"))).toBe(false);
  });

  test("retired aliases cannot mask a lower explicit local authority", () => {
    Object.assign(process.env, {
      HASNA_ACCOUNTS_STORAGE_MODE: "remote",
      ACCOUNTS_STORAGE_MODE: "hybrid",
      HASNA_ACCOUNTS_MODE: "local",
      HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
      HASNA_ACCOUNTS_API_KEY: "fixture-authority",
    });
    expect(ensureProfileForLogin("local-after-retired")).toMatchObject({
      name: "local-after-retired",
      tool: "claude",
    });
    expect(existsSync(join(home, "accounts.json"))).toBe(true);
    expect(existsSync(join(home, "profiles"))).toBe(true);
  });

  test.each([
    [
      "implicit hosted URL and key",
      {
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
    [
      "cloud mode",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
  ])(
    "appliedProfile stays readable for %s and so does the machine-local pointer",
    (_label, env) => {
      seedAppliedProfile("ghost-local");
      expect(appliedProfile("claude")).toMatchObject({ name: "ghost-local", tool: "claude" });

      Object.assign(process.env, env);
      // The registry record behind the pointer belongs to the hosted registry,
      // so this answer is machine-local and is announced as such (see
      // root-compat-consumer.test.ts). It is not withheld: the consumers that
      // read it wrap every call in try/catch, so withholding it produced a
      // silent null rather than the intended loud failure.
      expect(appliedProfile("claude")).toMatchObject({ name: "ghost-local", tool: "claude" });
      // The pointer itself is machine-local state and stays readable.
      expect(appliedProfileName("claude")).toBe("ghost-local");
      // Opting into the end-state behaviour makes the record read fail closed.
      process.env.HASNA_ACCOUNTS_STRICT_ROOT_COMPAT = "1";
      try {
        expect(() => appliedProfile("claude")).toThrow(/local-only compatibility/);
        expect(appliedProfileName("claude")).toBe("ghost-local");
      } finally {
        delete process.env.HASNA_ACCOUNTS_STRICT_ROOT_COMPAT;
      }
    },
  );

  test.each([
    ["default local", {}],
    [
      "explicit local",
      {
        HASNA_ACCOUNTS_MODE: "local",
      },
    ],
    [
      "explicit local with retained hosted URL and key",
      {
        HASNA_ACCOUNTS_MODE: "local",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
    [
      "implicit local with only a hosted URL",
      {
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
      },
    ],
    [
      "implicit local with only a hosted key",
      {
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
  ])("ensureProfileForLogin preserves the documented v1 local boundary for %s", (_label, env) => {
    Object.assign(process.env, env);
    const profile = ensureProfileForLogin("login-local");
    expect(profile).toMatchObject({ name: "login-local", tool: "claude" });
    expect(existsSync(join(home, "accounts.json"))).toBe(true);
    expect(existsSync(join(home, "profiles"))).toBe(true);
  });

  test.each([
    [
      "implicit hosted URL and key",
      {
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
      /local-only compatibility/,
    ],
    [
      "explicit cloud with URL and key",
      {
        HASNA_ACCOUNTS_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
      /local-only compatibility/,
    ],
    [
      "explicit self-hosted with URL and key",
      {
        HASNA_ACCOUNTS_MODE: "self_hosted",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
      /local-only compatibility/,
    ],
    [
      "incomplete explicit cloud",
      {
        HASNA_ACCOUNTS_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
      },
      /requires HASNA_ACCOUNTS_API_KEY/,
    ],
    [
      "incomplete explicit self-hosted",
      {
        HASNA_ACCOUNTS_MODE: "self_hosted",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
      /requires HASNA_ACCOUNTS_API_URL/,
    ],
    [
      "invalid explicit mode",
      {
        HASNA_ACCOUNTS_MODE: "typo",
      },
      /invalid accounts storage mode/,
    ],
  ])("ensureProfileForLogin fails closed without local writes for %s", (_label, env, error) => {
    Object.assign(process.env, env);
    expect(() => ensureProfileForLogin("must-not-write")).toThrow(error);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
    expect(existsSync(join(home, "profiles"))).toBe(false);
  });
});

/** Seed a local profile plus the machine-local applied pointer for it. */
function seedAppliedProfile(name: string, toolId = "claude"): void {
  addProfile({ name, tool: toolId });
  const store = loadStore();
  store.applied[toolId] = name;
  saveStore(store);
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
