import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { convergeDirCredential } from "./lib/credential-broker.js";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { getTool } from "./lib/tools.js";

/**
 * Regression tests for bug 2865f9f5 (OPE-00194): `convergeDirCredential`
 * resolved its security allowlist from the LOCAL registry file
 * (`listProfiles()` → `<home>/accounts.json`) while every other registry
 * surface goes through `resolveStore()` — the cloud ApiStore when the machine
 * is configured for it. On a cloud-mode machine every cloud-only profile dir
 * was therefore refused ("not a registered profile dir"), the usage-hook
 * swallowed the refusal into a log line, and per-session convergence was
 * silently dead for those dirs (measured on station01: 253 of 290 hook
 * attempts refused, 2026-08-04; 1,175 refusals in one log file, 2026-08-03).
 *
 * TWO-SIDED BY CONSTRUCTION:
 *  - "cloud-only profile dir converges" FAILS on the pre-fix code (the local
 *    allowlist refuses the dir) and passes after the fix.
 *  - the guard tests ("dir in NEITHER registry is refused") pass on BOTH
 *    sides, proving the fix re-pointed the allowlist rather than removing it.
 *
 * All credential material below is synthetic (invented tokens, invented
 * uuids); nothing here reads or writes a live profile dir — every path is
 * under a mkdtemp home, and the live-dir half of the allowlist is pinned to a
 * temp base via ACCOUNTS_TEST_LIVE_DIR.
 */

const UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const tool = getTool("claude");
const HOUR = 60 * 60 * 1000;

interface Cred {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function credBytes(cred: Cred): string {
  return JSON.stringify({ claudeAiOauth: { ...cred, scopes: ["user:inference"] } });
}

function makeDir(home: string, label: string, uuid: string, cred: Cred): string {
  const dir = join(home, "profiles", label);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credBytes(cred));
  return dir;
}

/** Env keys this suite touches; saved/restored around every test. */
const ENV_KEYS = [
  "ACCOUNTS_HOME",
  "ACCOUNTS_STORE_PATH",
  "ACCOUNTS_TEST_LIVE_DIR",
  "HASNA_ACCOUNTS_STORAGE_MODE",
  "ACCOUNTS_STORAGE_MODE",
  "HASNA_ACCOUNTS_MODE",
  "HASNA_ACCOUNTS_API_URL",
  "ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_KEY",
] as const;

let home: string;
let liveBase: string;
let saved: Record<string, string | undefined>;
let server: ReturnType<typeof Bun.serve> | undefined;

beforeEach(() => {
  saved = {};
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  home = mkdtempSync(join(tmpdir(), "accounts-allowlist-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-allowlist-live-"));
  process.env.ACCOUNTS_HOME = home;
  // Pin the live-config-dir half of the allowlist to a temp base so no test
  // dir can ever accidentally BE the machine's live dir.
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
});

afterEach(() => {
  server?.stop(true);
  server = undefined;
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
});

/** A minimal `/v1/accounts` registry stub speaking the contracts list shape. */
function serveCloudRegistry(accounts: Array<{ name: string; dir: string }>): string {
  server = Bun.serve({
    port: 0,
    fetch(req) {
      const url = new URL(req.url);
      if (req.method === "GET" && url.pathname === "/v1/accounts") {
        return Response.json({
          accounts: accounts.map((account) => ({
            tool: "claude",
            name: account.name,
            dir: account.dir,
            createdAt: "2026-08-04T00:00:00.000Z",
          })),
        });
      }
      return new Response("not found", { status: 404 });
    },
  });
  return `http://127.0.0.1:${server.port}`;
}

function configureCloudMode(url: string): void {
  // Explicit cloud mode wins over the ACCOUNTS_HOME override (deriveEnv in
  // cloud-accounts.ts), which is exactly the fleet shape: cloud registry,
  // local files.
  process.env.HASNA_ACCOUNTS_STORAGE_MODE = "cloud";
  process.env.HASNA_ACCOUNTS_API_URL = url;
  process.env.HASNA_ACCOUNTS_API_KEY = "synthetic-test-key";
}

/** Await-safe error capture: correct whether the callee throws sync or async. */
async function errorMessageOf(fn: () => unknown): Promise<string> {
  try {
    await fn();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  return "";
}

// --- the defect: cloud-only dirs must converge ------------------------------

test("cloud mode: a cloud-only profile dir converges (bug 2865f9f5)", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const cloudOnlyDir = makeDir(home, "cloud-only", UUID, fresh);
  // The LOCAL registry file does not exist → empty local registry. That is the
  // measured station01 shape: the dir is registered in the cloud store only.
  configureCloudMode(serveCloudRegistry([{ name: "cloud-only", dir: cloudOnlyDir }]));

  const report = await convergeDirCredential(cloudOnlyDir, { tool });

  expect(report).toBeDefined();
  expect(report?.accountUuid).toBe(UUID);
  // Convergence really ran: the account's central credential of record was
  // created from the dir's copy — not merely "no exception was thrown".
  expect(existsSync(centralCredentialsSnapshot(UUID))).toBe(true);
});

// --- the guard: same registry, still a fence --------------------------------

test("cloud mode: a dir in NEITHER registry is still refused, with the registry reachable", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const registeredDir = makeDir(home, "registered", UUID, fresh);
  const plantedDir = makeDir(home, "planted-unregistered", UUID, {
    accessToken: "at-planted",
    refreshToken: "rt-planted",
    expiresAt: Date.now() - HOUR,
  });
  // The stub is UP and lists a profile, so a refusal below is attributable to
  // the allowlist — not to an unreachable store.
  configureCloudMode(serveCloudRegistry([{ name: "registered", dir: registeredDir }]));
  const before = readFileSync(join(plantedDir, ".credentials.json"), "utf8");

  const message = await errorMessageOf(() => convergeDirCredential(plantedDir, { tool }));

  expect(message).toMatch(/not a registered profile dir/);
  // Nothing moved: the planted file is exactly as planted.
  expect(readFileSync(join(plantedDir, ".credentials.json"), "utf8")).toBe(before);
});

test("cloud mode: an unreachable registry is an error, never a silent local fallback", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const dir = makeDir(home, "cloud-only", UUID, fresh);
  // Reserved port 1: connection refused immediately, no server involved.
  configureCloudMode("http://127.0.0.1:1");

  const message = await errorMessageOf(() => convergeDirCredential(dir, { tool }));

  expect(message).not.toBe("");
  // The failure is distinguishable from an allowlist refusal: a dead registry
  // must not masquerade as "this dir is not registered" (nor silently fall
  // back to the local file, which is the defect class this suite pins).
  expect(message).not.toMatch(/not a registered profile dir/);
  expect(existsSync(centralCredentialsSnapshot(UUID))).toBe(false);
});

// --- local mode unchanged ---------------------------------------------------

test("local mode: the local registry still governs the allowlist by default", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const registeredDir = makeDir(home, "local-registered", UUID, fresh);
  const unregisteredDir = makeDir(home, "local-unregistered", UUID, fresh);
  writeFileSync(
    join(home, "accounts.json"),
    JSON.stringify({
      version: 1,
      current: {},
      applied: {},
      toolLocks: {},
      profiles: [{ name: "local-registered", tool: "claude", dir: registeredDir, createdAt: "2026-08-04T00:00:00.000Z" }],
    }),
  );

  const report = await convergeDirCredential(registeredDir, { tool });
  expect(report?.accountUuid).toBe(UUID);

  const message = await errorMessageOf(() => convergeDirCredential(unregisteredDir, { tool }));
  expect(message).toMatch(/not a registered profile dir/);
});

// --- the silent half: the hook must SAY it is degraded ----------------------

test("usage-hook surfaces a refused convergence as a systemMessage, and still fails open", () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const plantedDir = makeDir(home, "hook-unregistered", UUID, fresh);

  const result = spawnSync(process.execPath, ["run", "src/cli.ts", "usage-hook", "--dir", plantedDir], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      NODE_ENV: "test",
      ACCOUNTS_HOME: home,
      ACCOUNTS_TEST_LIVE_DIR: liveBase,
      // Local mode with an empty registry: the dir is unregistered, so the
      // converge refuses — the hook must SAY so on stdout, not only log it.
      HASNA_ACCOUNTS_STORAGE_MODE: undefined,
      ACCOUNTS_STORAGE_MODE: undefined,
      HASNA_ACCOUNTS_MODE: undefined,
      HASNA_ACCOUNTS_API_URL: undefined,
      ACCOUNTS_API_URL: undefined,
      HASNA_ACCOUNTS_API_KEY: undefined,
      ACCOUNTS_API_KEY: undefined,
    },
  });

  // Fail-open is preserved: the prompt always goes through.
  expect(result.status).toBe(0);
  // The refusal reaches the operator, not just a log nobody reads.
  expect(result.stdout).toMatch(/per-session credential convergence is NOT running/);
  expect(result.stdout).toMatch(/not a registered profile dir/);
});
