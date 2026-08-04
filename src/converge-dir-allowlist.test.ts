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

/**
 * A registry that answers correctly but SLOWLY — the shape the real one has.
 * The delay models the measured floor of a live `GET /accounts` on station01
 * (min 2.82s, median ~4.65s at load 16.16), which is what made a 2s budget a
 * permanent failure rather than a safety valve.
 */
function serveSlowCloudRegistry(delayMs: number, accounts: Array<{ name: string; dir: string }>): string {
  server = Bun.serve({
    port: 0,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method === "GET" && url.pathname === "/v1/accounts") {
        await Bun.sleep(delayMs);
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

/** Accept the registry request but never produce headers or a body. */
function serveHangingCloudRegistry(): string {
  server = Bun.serve({
    port: 0,
    fetch() {
      return new Promise<Response>(() => {});
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

test("usage-hook fails open before its 15-second deadline when the cloud registry hangs", async () => {
  const dir = makeDir(home, "cloud-hang", UUID, {
    accessToken: "at-cloud-hang",
    refreshToken: "rt-cloud-hang",
    expiresAt: Date.now() + 7 * HOUR,
  });
  configureCloudMode(serveHangingCloudRegistry());
  const childEnv = { ...process.env };
  delete childEnv.BUN_CONFIG_VERBOSE_FETCH;
  delete childEnv.NODE_DEBUG;
  delete childEnv.NODE_DEBUG_NATIVE;
  const child = Bun.spawn(
    [process.execPath, "run", "src/cli.ts", "usage-hook", "--dir", dir],
    {
      cwd: process.cwd(),
      env: childEnv,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  let timedOut = false;
  // 14s, not 7s. The property this test is named for is Claude Code's real
  // 15-second hook deadline; 7s was a proxy chosen when the registry budget
  // was 2s, and it would now fail purely because that budget was raised to 8s
  // to clear the call's measured floor. Killing at 14s keeps the assertion
  // strictly inside the deadline it claims to test, and the explicit elapsed
  // bound below states the contract directly rather than by proxy — so an
  // over-budget regression (say, a return to the 30s transport default) is
  // still caught, by both.
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, 14_000);

  const startedAt = Date.now();
  const status = await child.exited;
  const elapsed = Date.now() - startedAt;
  clearTimeout(timer);
  const stdout = await new Response(child.stdout).text();

  expect(timedOut).toBe(false);
  expect(elapsed).toBeLessThan(15_000);
  expect(status).toBe(0);
  expect(stdout).toMatch(/per-session credential convergence is NOT running/);
  // 30s: this test deliberately waits out the 8s registry budget plus process
  // start, which exceeds bun's 5s default and would otherwise be killed with
  // SIGTERM (status 143) and read as a product failure.
}, 30_000);

// --- the allowlist is the UNION of both registries --------------------------

/** Write a local registry file with the given profile rows. */
function writeLocalRegistry(rows: Array<{ name: string; dir: string }>): void {
  writeFileSync(
    join(home, "accounts.json"),
    JSON.stringify({
      version: 1,
      current: {},
      applied: {},
      toolLocks: {},
      profiles: rows.map((row) => ({
        name: row.name,
        tool: "claude",
        dir: row.dir,
        createdAt: "2026-08-04T00:00:00.000Z",
      })),
    }),
  );
}

test("cloud mode: a LOCAL-ONLY dir still converges (the #123 regression)", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const cloudOnlyDir = makeDir(home, "cloud-only", UUID, fresh);
  const localOnlyDir = makeDir(home, "local-only", UUID, fresh);
  // The measured station01 shape at merge 931feae9, unfiltered by tool
  // because the allowlist read is unfiltered: active 60 rows / 56 dirs,
  // local 22, intersection 21, LOCAL-ONLY 1 (account022). The registries are
  // NOT nested, so an active-registry-only allowlist refuses a dir the
  // pre-#123 allowlist accepted.
  //
  // HONEST SCOPE OF THAT ONE DIR, re-verified directly rather than taken on
  // report: account022 has `.credentials.json exists: False` and
  // `has oauthAccount key: False`, so `dirAccountUuid` returns undefined and
  // `convergeDirCredential` returns early WHATEVER the allowlist decides.
  // Today the union changes nothing observable for the only local-only dir on
  // this box. That lowers the union's urgency, not its correctness: the
  // allowlist must not narrow relative to what it accepted before, and a dir
  // that gains a credential tomorrow must not need a registry migration to be
  // converged. This fixture is populated so the property is actually
  // exercised.
  writeLocalRegistry([{ name: "local-only", dir: localOnlyDir }]);
  configureCloudMode(serveCloudRegistry([{ name: "cloud-only", dir: cloudOnlyDir }]));

  const localReport = await convergeDirCredential(localOnlyDir, { tool });
  expect(localReport?.accountUuid).toBe(UUID);

  // ...and the cloud-only dir, the original defect, still converges too.
  const cloudReport = await convergeDirCredential(cloudOnlyDir, { tool });
  expect(cloudReport?.accountUuid).toBe(UUID);
});

test("a SLOW-but-working registry still lets the union form (the 2s-budget compounding)", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const cloudOnlyDir = makeDir(home, "cloud-only", UUID, fresh);
  const localOnlyDir = makeDir(home, "local-only", UUID, fresh);
  writeLocalRegistry([{ name: "local-only", dir: localOnlyDir }]);
  // 3s: above the old 2_000 budget, below the new 8_000, and just above the
  // 2.82s fastest real sample — i.e. a registry behaving NORMALLY, not a
  // pathological one.
  configureCloudMode(serveSlowCloudRegistry(3_000, [{ name: "cloud-only", dir: cloudOnlyDir }]));

  // THE COMPOUNDING, and why one constant defeated two fixes: the active half
  // is read FIRST and unguarded, so its rejection short-circuits
  // allowlistProfiles and the local half never merges. Under a 2s budget this
  // dir is refused even though it is in the local registry the union exists
  // to preserve.
  const localReport = await convergeDirCredential(localOnlyDir, { tool });
  expect(localReport?.accountUuid).toBe(UUID);

  const cloudReport = await convergeDirCredential(cloudOnlyDir, { tool });
  expect(cloudReport?.accountUuid).toBe(UUID);
  // 20s: two sequential 3s registry reads exceed bun's 5s default; without
  // this the server is torn down by afterEach mid-flight and the failure
  // reads as ConnectionRefused rather than as a timeout.
}, 20_000);

test("the union does NOT widen to a dir absent from BOTH registries", async () => {
  const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
  const cloudDir = makeDir(home, "cloud-known", UUID, fresh);
  const localDir = makeDir(home, "local-known", UUID, fresh);
  const plantedDir = makeDir(home, "planted-neither", UUID, fresh);
  writeLocalRegistry([{ name: "local-known", dir: localDir }]);
  configureCloudMode(serveCloudRegistry([{ name: "cloud-known", dir: cloudDir }]));
  const before = readFileSync(join(plantedDir, ".credentials.json"), "utf8");

  const message = await errorMessageOf(() => convergeDirCredential(plantedDir, { tool }));

  expect(message).toMatch(/not a registered profile dir/);
  expect(readFileSync(join(plantedDir, ".credentials.json"), "utf8")).toBe(before);
});

// --- the detached token exchange is a DELIBERATE, logged decision -----------

/**
 * Run the hook against a dir whose credential is inside the ensure-fresh
 * trigger window, in local mode with that dir registered, and return the
 * usage-hook log. `ACCOUNTS_CLAUDE_OAUTH_TOKEN_URL` is pinned to a dead port
 * so that even the enabled branch cannot reach a real token endpoint.
 */
function runHookWithNearExpiryCredential(env: Record<string, string | undefined>): string {
  const nearExpiry: Cred = {
    accessToken: "at-near-expiry",
    refreshToken: "rt-near-expiry",
    // Inside ENSURE_FRESH_TRIGGER_TTL_MS (30 min), so the branch is reached.
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
  const dir = makeDir(home, "ensure-fresh-dir", UUID, nearExpiry);
  writeLocalRegistry([{ name: "ensure-fresh-dir", dir }]);

  const result = spawnSync(process.execPath, ["run", "src/cli.ts", "usage-hook", "--dir", dir], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      NODE_ENV: "test",
      ACCOUNTS_HOME: home,
      ACCOUNTS_TEST_LIVE_DIR: liveBase,
      ACCOUNTS_CLAUDE_OAUTH_TOKEN_URL: "http://127.0.0.1:1/oauth/token",
      HASNA_ACCOUNTS_STORAGE_MODE: undefined,
      ACCOUNTS_STORAGE_MODE: undefined,
      HASNA_ACCOUNTS_MODE: undefined,
      HASNA_ACCOUNTS_API_URL: undefined,
      ACCOUNTS_API_URL: undefined,
      HASNA_ACCOUNTS_API_KEY: undefined,
      ACCOUNTS_API_KEY: undefined,
      ...env,
    },
  });
  expect(result.status).toBe(0);
  const logPath = join(home, "logs", "usage-hook.log");
  return existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
}

test("the hook's detached token exchange is OFF by default, and says so", () => {
  const log = runHookWithNearExpiryCredential({ ACCOUNTS_HOOK_ENSURE_FRESH: undefined });

  // The converge itself ran — this is the branch guard, not a dead path.
  expect(log).toMatch(/broker-converge uuid=/);
  expect(log).toMatch(/broker-ensure-fresh skipped/);
  expect(log).not.toMatch(/broker-ensure-fresh spawned/);
});

test("POSITIVE CONTROL for the gate: ACCOUNTS_HOOK_ENSURE_FRESH=1 spawns it", () => {
  const log = runHookWithNearExpiryCredential({ ACCOUNTS_HOOK_ENSURE_FRESH: "1" });

  // Without this, the test above would pass on a branch that can never fire —
  // the vacuous-gate shape. Both branches are reachable and distinguishable.
  expect(log).toMatch(/broker-ensure-fresh spawned/);
  expect(log).not.toMatch(/broker-ensure-fresh skipped/);
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
