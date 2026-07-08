import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { accountsHome, loadStore, profilesDir, saveStore, storePath } from "./storage.js";

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

function runCli(env: Record<string, string>, ...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ...env },
  });
}

test("the legacy `storage` command group is gone", () => {
  const result = runCli({}, "storage", "status");
  expect(result.status).not.toBe(0);
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
