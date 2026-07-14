import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  accountsHome,
  loadAppliedMap,
  loadCurrentMap,
  loadMachineStore,
  loadStore,
  profilesDir,
  reconcileMachineProfileRemove,
  reconcileMachineProfileRename,
  saveStore,
  storePath,
} from "./storage.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-storage-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

test("local path helpers resolve under ACCOUNTS_HOME", () => {
  expect(accountsHome()).toBe(home);
  expect(storePath()).toBe(join(home, "accounts.json"));
  expect(profilesDir()).toBe(join(home, "profiles"));
});

test("loadStore returns an empty store before anything is written", () => {
  const store = loadStore();
  expect(store.profiles).toEqual([]);
  expect(existsSync(storePath())).toBe(false);
});

test("saveStore/loadStore round-trips the registry", () => {
  addProfile({ name: "work", tool: "claude", email: "work@example.test" });
  const store = loadStore();
  expect(store.profiles[0]?.name).toBe("work");
  expect(store.profiles[0]?.email).toBe("work@example.test");

  store.profiles.push({ name: "home", tool: "claude", dir: join(home, "profiles/claude/home"), createdAt: new Date().toISOString() });
  saveStore(store);
  expect(loadStore().profiles.map((p) => p.name).sort()).toEqual(["home", "work"]);
});

test("raw machine pointers survive cloud-only profiles and reconcile rename/remove", () => {
  saveStore({
    version: 1,
    current: { acme: "old" },
    applied: { acme: "old" },
    toolLocks: { old: "acme" },
    profiles: [],
    tools: [],
  });
  expect(loadCurrentMap()).toEqual({ acme: "old" });
  expect(loadAppliedMap()).toEqual({ acme: "old" });
  expect(loadStore().current).toEqual({});

  reconcileMachineProfileRename("acme", "old", "new");
  expect(loadMachineStore().current).toEqual({ acme: "new" });
  expect(loadMachineStore().applied).toEqual({ acme: "new" });
  expect(loadMachineStore().toolLocks).toEqual({ new: "acme" });

  reconcileMachineProfileRemove("acme", "new");
  expect(loadMachineStore().current).toEqual({});
  expect(loadMachineStore().applied).toEqual({});
  expect(loadMachineStore().toolLocks).toEqual({});
});

test("saveStore atomically replaces the registry without leaving temp files", () => {
  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });
  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });
  expect(JSON.parse(readFileSync(storePath(), "utf8")).version).toBe(1);
  expect(readdirSync(accountsHome()).filter((name) => name.endsWith(".tmp"))).toEqual([]);
});

function runCli(env: Record<string, string>, ...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ...env },
  });
}

test("the legacy storage command group is a fail-explicit compatibility shim", () => {
  const result = runCli({}, "storage", "status");
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("legacy provider-backed sync is retired");
  for (const operation of ["push", "pull", "sync"]) {
    for (const args of [[operation], [operation, "--json"]]) {
      const retired = runCli({}, "storage", ...args);
      expect(retired.status).not.toBe(0);
      expect(retired.stderr).toContain("legacy storage sync was retired");
      expect(retired.stderr).not.toContain("unknown option");
    }
  }
});

// Regression: a machine still carrying a stale S3-era storage-mode word must not
// crash — the legacy value is ignored and the client stays local.
for (const legacy of ["remote", "hybrid", "s3"]) {
  test(`stale HASNA_ACCOUNTS_STORAGE_MODE=${legacy} does not crash registry commands`, () => {
    const result = runCli(
      { HASNA_ACCOUNTS_STORAGE_MODE: legacy, ACCOUNTS_STORAGE_MODE: legacy },
      "list",
      "--json",
    );
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("Unknown storage mode");
    expect(result.stderr).not.toContain("misconfigured");
  });
}

for (const mode of ["cloud", "self_hosted"]) {
  test(`explicit ${mode} CLI mode fails closed without API configuration`, () => {
    const result = runCli(
      {
        HASNA_ACCOUNTS_STORAGE_MODE: mode,
        HASNA_ACCOUNTS_API_URL: "",
        HASNA_ACCOUNTS_API_KEY: "",
      },
      "list",
      "--json",
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`${mode} storage mode requires HASNA_ACCOUNTS_API_URL and HASNA_ACCOUNTS_API_KEY`);
    expect(existsSync(storePath())).toBe(false);
  });
}

test("unknown CLI storage modes fail validation instead of falling back", () => {
  const result = runCli({ HASNA_ACCOUNTS_STORAGE_MODE: "typo" }, "list", "--json");
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("invalid accounts storage mode");
  expect(existsSync(storePath())).toBe(false);
});
