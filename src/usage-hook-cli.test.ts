import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * End-to-end guards for the hook's two non-negotiables, exercised through the
 * real CLI rather than the injectable brain: it must ALWAYS exit 0, and it must
 * never fail silently.
 *
 * The silent half is what these cover that the unit tests cannot. `runUsageHook`
 * has its own catch, but anything thrown BEFORE it — resolving the tool, the
 * store, or the session dir — lands in the CLI's outer catch, which used to log
 * and print nothing. Measured against the shipped build, that made a
 * misconfigured registry indistinguishable from a healthy session.
 */

let home: string;
let dir: string;

function runHook(env: Record<string, string> = {}) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", "usage-hook", "--dir", dir], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      ACCOUNTS_STORE_PATH: join(home, "accounts.json"),
      HASNA_ACCOUNTS_MODE: "local",
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
      ACCOUNTS_STORAGE_MODE: "local",
      ...env,
    },
  });
}

function systemMessage(stdout: string): string | undefined {
  const line = stdout.trim().split("\n").filter(Boolean).pop();
  if (!line) return undefined;
  return (JSON.parse(line) as { systemMessage?: string }).systemMessage;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-hookcli-"));
  dir = join(home, "session-dir");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" } }),
  );
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

test("a failure before the hook brain runs still exits 0 AND says something", () => {
  // Storage mode set to `api` with no URL or key: `resolveStore()` throws, so
  // the error never reaches runUsageHook's own handler.
  const result = runHook({ HASNA_ACCOUNTS_STORAGE_MODE: "api", ACCOUNTS_STORAGE_MODE: "api" });

  expect(result.status).toBe(0);
  expect(systemMessage(result.stdout)).toMatch(/auto-switching is NOT running/i);
});

test("POSITIVE CONTROL: the healthy path is silent, so the assertion above means something", () => {
  // Same harness, no induced failure. If this also printed a message, the test
  // above would pass no matter what the hook did.
  const result = runHook();

  expect(result.status).toBe(0);
  // No usage cache exists, so this is the degraded no-measurement notice —
  // visible by design — but it must NOT be the fail-open one.
  expect(systemMessage(result.stdout) ?? "").not.toMatch(/auto-switching is NOT running/i);
});

test("an unparseable registry exits 0 rather than blocking the prompt", () => {
  writeFileSync(join(home, "accounts.json"), "{{{ NOT JSON");
  const result = runHook();
  expect(result.status).toBe(0);
});
