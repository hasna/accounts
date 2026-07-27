import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addCustomTool,
  addProfile,
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

  test("preserves synchronous behavior with explicit local authority", () => {
    process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
    expect(loadStore().version).toBe(1);
    expect(listTools().some((tool) => tool.id === "claude")).toBe(true);
    expect(listProfiles()).toEqual([]);
    expect(addProfile({ name: "local-only", tool: "claude" }).name).toBe("local-only");
    expect(listProfiles().map((profile) => profile.name)).toEqual(["local-only"]);
  });

  test.each([
    ["cloud mode", { HASNA_ACCOUNTS_STORAGE_MODE: "cloud" }],
    ["self-hosted mode", { HASNA_ACCOUNTS_STORAGE_MODE: "self_hosted" }],
    ["partial hosted URL", { HASNA_ACCOUNTS_API_URL: "https://accounts.example.test" }],
    [
      "explicit local with hosted configuration",
      {
        HASNA_ACCOUNTS_STORAGE_MODE: "local",
        HASNA_ACCOUNTS_API_URL: "https://accounts.example.test",
        HASNA_ACCOUNTS_API_KEY: "fixture-authority",
      },
    ],
  ])("fails closed for %s before local reads or writes", (_label, env) => {
    Object.assign(process.env, env);
    expect(() => listProfiles()).toThrow(/local-only compatibility/);
    expect(() => addProfile({ name: "must-not-write" })).toThrow(/local-only compatibility/);
    expect(() => loadStore()).toThrow(/local-only compatibility/);
    expect(() => saveStore(emptyStore())).toThrow(/local-only compatibility/);
    expect(() => listTools()).toThrow(/local-only compatibility/);
    expect(() =>
      addCustomTool({
        id: "fixture-tool",
        label: "Fixture",
        envVar: "FIXTURE_HOME",
        defaultDir: "/fixture",
        bin: "fixture",
      }),
    ).toThrow(/local-only compatibility/);
    expect(existsSync(join(home, "accounts.json"))).toBe(false);
    expect(existsSync(join(home, "profiles"))).toBe(false);
  });
});

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
