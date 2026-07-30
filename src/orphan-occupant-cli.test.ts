import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * The operator surface for the orphan-occupant defect.
 *
 * These run the real CLI, because the measured failure was an operator being
 * told "no eligible account (valid credentials, not the current one) was found"
 * while an account with 97% headroom sat right there — a message no unit test
 * of the selector would have caught.
 */

let home: string;
let sessionDir: string;
let liveBase: string;

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const UUID_SPARE = "cccccccc-3333-4333-8333-cccccccccccc";

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    // Two DIFFERENT dirs, and conflating them cost a wrong assertion once:
    //  - CLAUDE_CONFIG_DIR is what `resolveSessionConfigDir` reads for "the
    //    account this session runs as", which must be excluded from candidates;
    //  - ACCOUNTS_TEST_LIVE_DIR is where `apply` actually writes, via
    //    `liveClaudePaths()` — it does NOT honour CLAUDE_CONFIG_DIR.
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      CLAUDE_CONFIG_DIR: sessionDir,
      ACCOUNTS_TEST_LIVE_DIR: liveBase,
    },
  });
}

/** Obviously synthetic. No real credential material appears in this file. */
function credentialJson(label: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + 3_600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 3_600_000,
    },
  });
}

function identityJson(uuid: string, email: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } });
}

function park(dir: string, uuid: string, email: string, label: string): void {
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(join(dir, ".accounts-auth", "oauth-account.json"), identityJson(uuid, email));
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson(label));
}

function occupy(dir: string, uuid: string, email: string, label: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, email));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
}

/** Pre-seed the usage cache so `pick --healthiest` never touches the network. */
function seedUsage(uuid: string, percentUsed: number): void {
  const dir = join(home, "cache", "usage");
  mkdirSync(dir, { recursive: true });
  const resets = new Date(Date.now() + 3_600_000).toISOString();
  writeFileSync(
    join(dir, `${uuid}.json`),
    JSON.stringify({
      accountUuid: uuid,
      fetchedAt: new Date().toISOString(),
      usage: {
        windows: [
          { id: "session", utilization: percentUsed, scoped: false, resetsAt: resets, group: "session" },
          { id: "weekly_all", utilization: percentUsed, scoped: false, resetsAt: resets, group: "weekly" },
        ],
        headroom: 100 - percentUsed,
        bindingWindow: "session",
        fetchedAt: new Date().toISOString(),
      },
    }),
  );
}

/**
 * Managed profile dirs are `<ACCOUNTS_HOME>/profiles/<tool>/<name>`. Derived
 * rather than read back with `accounts show`, because each CLI invocation costs
 * a bun start plus a TypeScript compile and every avoidable spawn pushes these
 * toward a timeout that would read as a product failure.
 */
function managedDir(name: string): string {
  return join(home, "profiles", "claude", name);
}

function addFixtureProfile(name: string): string {
  const add = runCli("add", name);
  expect(add.status).toBe(0);
  return managedDir(name);
}

/**
 * Explicit timeout: these spawn the real CLI 3-4 times, and a single spawn pays
 * ~1s of bun startup plus compile before it does any work. bun's 5s default is
 * a coin flip at that cost under parallel load — measured as an intermittent
 * timeout reported as an assertion failure, which is worse than a slow test.
 */
const CLI_TIMEOUT_MS = 60_000;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-orphan-cli-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-orphan-live-"));
  sessionDir = join(home, "session-claude");
  // The session runs as a fourth account so nothing under test is excluded as
  // "the current one".
  occupy(sessionDir, "dddddddd-4444-4444-8444-dddddddddddd", "session@example.com", "session");
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
});

test("pick --healthiest names the unreachable account instead of claiming none was eligible", () => {
  const occupied = addFixtureProfile("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");
  seedUsage(UUID_GUEST, 3); // 97% headroom — the fleet's healthiest
  seedUsage(UUID_HOST, 95); // below the bar

  const picked = runCli("pick", "--healthiest", "--no-act");

  expect(picked.status).not.toBe(0);
  // The shipped message sent operators to add capacity they already had.
  expect(picked.stderr).not.toContain("no eligible account");
  expect(picked.stderr).toContain("unreachable");
  expect(picked.stderr).toContain("accounts auth adopt");
}, CLI_TIMEOUT_MS);

test("pick --healthiest falls through to a reachable runner-up", () => {
  const occupied = addFixtureProfile("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");
  const spare = addFixtureProfile("spare");
  park(spare, UUID_SPARE, "spare@example.com", "spare");
  occupy(spare, UUID_SPARE, "spare@example.com", "spare");
  seedUsage(UUID_GUEST, 3); // rank 1, no profile owns it
  seedUsage(UUID_SPARE, 40); // rank 2, reachable
  seedUsage(UUID_HOST, 95);

  const picked = runCli("pick", "--healthiest", "--no-act");

  expect(picked.status).toBe(0);
  expect(picked.stdout).toContain("spare");
}, CLI_TIMEOUT_MS);

test("auth adopt --list surfaces the nameless account, and adopt gives it a name", () => {
  const occupied = addFixtureProfile("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");
  const guestBytes = readFileSync(join(occupied, ".credentials.json"));

  const list = runCli("auth", "adopt", "--list", "--json");
  expect(list.status).toBe(0);
  const listed = JSON.parse(list.stdout) as { orphans: Array<{ accountUuid: string; email?: string }> };
  expect(listed.orphans.map((o) => o.accountUuid)).toEqual([UUID_GUEST]);

  const adopted = runCli("auth", "adopt", "anya", "--account", "guest@example.com");
  expect(adopted.status).toBe(0);
  expect(adopted.stdout).toContain("adopted as");

  // Named, and reachable through the reporting path that showed the symptom.
  const status = JSON.parse(runCli("auth", "status", "--json").stdout) as Array<{
    accountUuid: string;
    doors: Array<{ role: string; profileName?: string }>;
  }>;
  const guest = status.find((r) => r.accountUuid === UUID_GUEST)!;
  expect(guest.doors.filter((d) => d.role === "own-identity").map((d) => d.profileName)).toEqual(["anya"]);

  expect(readFileSync(join(managedDir("anya"), ".accounts-auth", "credentials.json"))).toEqual(guestBytes);
  // Moved, not copied: the host dir is back on its own account.
  expect(readFileSync(join(occupied, ".credentials.json"))).not.toEqual(guestBytes);

  // "Named" is not "routable". Apply it and check the session dir actually
  // RUNS as the adopted account — a profile that carries a park nothing can
  // restore would satisfy every assertion above and still be useless.
  const applied = runCli("apply", "anya");
  expect(applied.status).toBe(0);
  // PAYLOAD, not bytes: apply can serve the credential from the central mirror,
  // which `syncProfileSnapshotToCentral` writes as pretty-printed JSON rather
  // than a byte copy. The discriminating question is whose token landed —
  // asserting it is the guest's AND not the host's separates "routed to the
  // adopted account" from "routed to the dir's original owner".
  const appliedPayload = JSON.parse(readFileSync(join(liveBase, ".claude", ".credentials.json"), "utf8")) as {
    claudeAiOauth?: { accessToken?: string };
  };
  const guestPayload = JSON.parse(guestBytes.toString()) as { claudeAiOauth?: { accessToken?: string } };
  expect(appliedPayload.claudeAiOauth?.accessToken).toBe(guestPayload.claudeAiOauth?.accessToken);
  expect(appliedPayload.claudeAiOauth?.accessToken).not.toBe("host-access");
  const liveNow = JSON.parse(readFileSync(join(liveBase, ".claude.json"), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(liveNow.oauthAccount?.accountUuid).toBe(UUID_GUEST);
}, CLI_TIMEOUT_MS);

test("auth adopt refuses a live-session dir and exits non-zero", () => {
  const occupied = addFixtureProfile("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");
  mkdirSync(join(occupied, "sessions"), { recursive: true });
  writeFileSync(join(occupied, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
  const before = readFileSync(join(occupied, ".credentials.json"));

  const adopted = runCli("auth", "adopt", "anya", "--account", UUID_GUEST);

  expect(adopted.status).not.toBe(0);
  expect(adopted.stderr).toContain("sessions-live");
  expect(readFileSync(join(occupied, ".credentials.json"))).toEqual(before);
  expect(existsSync(managedDir("anya"))).toBe(false);
}, CLI_TIMEOUT_MS);
