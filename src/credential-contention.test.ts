import { test, expect } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountIdentity } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import type { UsageCacheEntry } from "./lib/auto-switch.js";
import { selectHealthiestAccount } from "./lib/auto-switch.js";
import { runUsageHook, type UsageHookDeps, type UsageHookOptions } from "./lib/usage-hook.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { profileCredentialsSnapshot } from "./lib/claude-layout.js";
import { classifyCredentialFile } from "./lib/credential-state.js";
import { getTool } from "./lib/tools.js";

/**
 * 5d4f2bf0 → af39fff3 — sharing an account across sessions, supported.
 *
 * HISTORY, because this file used to assert the OPPOSITE. The two-copies-one-
 * account state destroyed credentials via refresh-token rotation, so the hook
 * EXCLUDED any account another dir was running ("contended"). That refusal cost
 * the fleet every healthy account at once — measured 2026-07-29 as "8 accounts
 * are already being run by another session and cannot be shared" while the
 * session hit its weekly wall. The credential broker
 * (`lib/credential-broker.ts`, tested in credential-broker.test.ts) dissolved
 * the underlying hazard: every dir sharing an account converges on the newest
 * rotation and refreshes happen once, under a per-account cross-process lock.
 *
 * So the contract THIS file now locks in:
 *  - an account live in another dir is a first-class switch target;
 *  - the switch is ANNOUNCED as shared, never silent;
 *  - the blanked-husk containment (snapshot never downgraded) still holds —
 *    that guard is unchanged and still the last line when a tool-side refresh
 *    loses a race the broker did not get to serialize.
 */

const NOW = new Date("2026-07-29T07:00:00Z");
const ACCOUNT_SHARED = "shared-account-uuid";

function usage(headroom: number): AccountUsage {
  return {
    windows: [
      { id: "weekly_all", utilization: 100 - headroom, scoped: false, resetsAt: "2026-08-05T00:00:00Z" },
    ],
    headroom,
    bindingWindow: "weekly_all",
    fetchedAt: NOW.toISOString(),
  };
}

function cacheEntry(uuid: string, headroom: number): UsageCacheEntry {
  return { accountUuid: uuid, fetchedAt: NOW.toISOString(), usage: usage(headroom) };
}

function identity(uuid: string, doors: Array<{ dir: string; profileName: string }>): AccountIdentity {
  return {
    accountUuid: uuid,
    email: `${uuid}@example.com`,
    doors: doors.map((d) => ({ dir: d.dir, role: "own-identity" as const, profileName: d.profileName })),
    credential: {
      path: "/fake/c.json",
      source: "central",
      expiresAt: NOW.getTime() + 60_000,
      hasAccessToken: true,
      hasRefreshToken: true,
      valid: true,
      renewable: true,
    },
    status: "ok",
  };
}

// --- the selector -----------------------------------------------------------

test("an account another dir is running is a FIRST-CLASS candidate — sharing is supported", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-current", []), usage: usage(4) },
      // Most headroom of all — and already live somewhere else. Under the
      // broker that is exactly the account the session should get.
      { identity: identity(ACCOUNT_SHARED, [{ dir: "/fake/other", profileName: "p-OTHER" }]), usage: usage(95) },
      { identity: identity("uuid-free", [{ dir: "/fake/free", profileName: "p-FREE" }]), usage: usage(60) },
    ],
    { currentUuid: "uuid-current", now: NOW },
  );

  expect(picked.candidate?.accountUuid).toBe(ACCOUNT_SHARED);
  expect(picked.excluded.map((e) => e.accountUuid)).not.toContain(ACCOUNT_SHARED);
});

// --- the hook, against the shared two-dir state ------------------------------

function hookHarness(opts: {
  configDir: string;
  identities: AccountIdentity[];
  cache: Record<string, UsageCacheEntry>;
  liveDirs: Set<string>;
  switchesTo?: string;
}) {
  const calls = { switches: [] as string[] };
  const deps: UsageHookDeps = {
    currentAccountUuid: () => (calls.switches.length > 0 && opts.switchesTo ? opts.switchesTo : "uuid-current"),
    readCache: (uuid) => opts.cache[uuid],
    listIdentities: async () => opts.identities,
    triggerRefresh: () => {},
    performSwitch: async (profileName) => {
      calls.switches.push(profileName);
      return { liveSessions: 1 };
    },
    readState: () => undefined,
    writeState: () => {},
    liveSessionsIn: (dir: string) => (opts.liveDirs.has(dir) ? 1 : 0),
    now: () => NOW,
  };
  return { deps, calls };
}

const hookOptions = (configDir: string): UsageHookOptions => ({
  configDir,
  thresholdPercent: 90,
  minHeadroom: 25,
  minSessionHeadroom: 10,
  cooldownMs: 600_000,
  cacheMaxAgeMs: 300_000,
});

test("the hook switches ONTO an account that is live in another dir, and announces the sharing", async () => {
  // Dir A runs the shared account with a live session; our session is in dir B
  // and is over its threshold. This exact input used to produce a refusal
  // ("cannot be shared"); it must now produce the switch.
  const dirA = "/fake/profiles/account-a";
  const dirB = "/fake/profiles/account-b";
  const identities = [
    identity("uuid-current", [{ dir: dirB, profileName: "p-B" }]),
    identity(ACCOUNT_SHARED, [{ dir: dirA, profileName: "p-A" }]),
  ];
  const cache = { "uuid-current": cacheEntry("uuid-current", 4), [ACCOUNT_SHARED]: cacheEntry(ACCOUNT_SHARED, 95) };

  const h = hookHarness({
    configDir: dirB,
    identities,
    cache,
    liveDirs: new Set([dirA]),
    switchesTo: ACCOUNT_SHARED,
  });
  const outcome = await runUsageHook(hookOptions(dirB), h.deps);

  expect(outcome.action).toBe("switched");
  expect(h.calls.switches).toEqual(["p-A"]);
  // Loud, not silent: the shared state is announced in the switch message.
  expect(outcome.systemMessage ?? "").toMatch(/also live in 1 other session dir/i);
  expect(outcome.systemMessage ?? "").toMatch(/credential broker/i);
  // The refusal wording is retired.
  expect(outcome.systemMessage ?? "").not.toMatch(/cannot be shared/i);
});

test("POSITIVE CONTROL for the note: switching onto an idle account carries no sharing note", async () => {
  // Without this, the note test above could pass because the note appears on
  // EVERY switch — which would make "shared" indistinguishable from "idle".
  const dirA = "/fake/profiles/account-a";
  const dirB = "/fake/profiles/account-b";
  const identities = [
    identity("uuid-current", [{ dir: dirB, profileName: "p-B" }]),
    identity(ACCOUNT_SHARED, [{ dir: dirA, profileName: "p-A" }]),
  ];
  const cache = { "uuid-current": cacheEntry("uuid-current", 4), [ACCOUNT_SHARED]: cacheEntry(ACCOUNT_SHARED, 95) };

  const h = hookHarness({
    configDir: dirB,
    identities,
    cache,
    liveDirs: new Set(), // door exists, nothing attached to it
    switchesTo: ACCOUNT_SHARED,
  });
  const outcome = await runUsageHook(hookOptions(dirB), h.deps);

  expect(outcome.action).toBe("switched");
  expect(outcome.systemMessage ?? "").not.toMatch(/also live in/i);
});

test("our own config dir never reads as sharing with itself", async () => {
  const dirB = "/fake/profiles/account-b";
  const identities = [
    identity("uuid-current", [{ dir: dirB, profileName: "p-B" }]),
    identity(ACCOUNT_SHARED, [{ dir: dirB, profileName: "p-B" }]),
  ];
  const cache = { "uuid-current": cacheEntry("uuid-current", 4), [ACCOUNT_SHARED]: cacheEntry(ACCOUNT_SHARED, 95) };

  const h = hookHarness({
    configDir: dirB,
    identities,
    cache,
    liveDirs: new Set([dirB]),
    switchesTo: ACCOUNT_SHARED,
  });
  const outcome = await runUsageHook(hookOptions(dirB), h.deps);
  expect(outcome.action).toBe("switched");
  expect(outcome.systemMessage ?? "").not.toMatch(/also live in/i);
});

// --- the destruction containment, on real files ------------------------------

test("two dirs, one account: a blanked loser never poisons the parked snapshot", () => {
  // The broker converges copies and serializes refreshes, but the TOOL still
  // refreshes on its own schedule and can still lose a race the broker never
  // saw. This containment — a rotated-away husk is never snapshotted over a
  // usable parked copy — is unchanged and still load-bearing.
  const home = mkdtempSync(join(tmpdir(), "accounts-contend-"));
  const live = mkdtempSync(join(tmpdir(), "accounts-contend-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = live;
  try {
    const tool = getTool("claude");
    const mkDir = (label: string) => {
      const dir = mkdtempSync(join(tmpdir(), `contend-${label}-`));
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, ".claude.json"),
        JSON.stringify({ oauthAccount: { accountUuid: ACCOUNT_SHARED, emailAddress: "shared@example.com" } }),
      );
      writeFileSync(
        join(dir, ".credentials.json"),
        JSON.stringify({
          claudeAiOauth: {
            accessToken: "shared-access",
            refreshToken: "shared-refresh",
            expiresAt: Date.now() + 60_000,
          },
        }),
      );
      ensureProfileAuthSnapshot(dir, tool);
      return dir;
    };

    // Two dirs, ONE account.
    const winner = mkDir("winner");
    const loser = mkDir("loser");
    expect(classifyCredentialFile(profileCredentialsSnapshot(loser)).state).toBe("usable");

    // The server rotates; the loser's refresh fails and Claude Code blanks it.
    writeFileSync(
      join(loser, ".credentials.json"),
      JSON.stringify({
        claudeAiOauth: { accessToken: "", refreshToken: "", expiresAt: 0, refreshTokenExpiresAt: Date.now() + 1e9 },
      }),
    );
    expect(classifyCredentialFile(join(loser, ".credentials.json")).state).toBe("rotated-away");

    // The next ordinary launch refreshes snapshots. The blank must not
    // propagate into the parked copy — the last copy under that dir.
    ensureProfileAuthSnapshot(loser, tool);

    expect(classifyCredentialFile(profileCredentialsSnapshot(loser)).state).toBe("usable");
    expect(classifyCredentialFile(profileCredentialsSnapshot(winner)).state).toBe("usable");
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(live, { recursive: true, force: true });
    delete process.env.ACCOUNTS_HOME;
    delete process.env.ACCOUNTS_TEST_LIVE_DIR;
  }
});
