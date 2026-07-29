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
 * 5d4f2bf0 — the two-copies-one-account state, built for real.
 *
 * Rotation is a TIMING defect, so a test that cannot construct the state proves
 * nothing about it. These build it: two config dirs holding ONE account, both
 * with a live session attached.
 *
 * What is REPRODUCED and what is MODELLED, stated plainly because the
 * difference matters:
 *  - REPRODUCED: the two-copies-one-account state, the live-session attachment,
 *    the blanked-payload file shape, and the selector/hook decision that either
 *    does or does not create a second copy.
 *  - MODELLED: the OAuth server rotating the refresh token. No test here talks
 *    to Anthropic. The destruction step writes the exact payload Claude Code was
 *    measured leaving behind when its refresh failed — it does not cause a real
 *    refresh to fail. So these tests prove the state is detected and no longer
 *    created; they do not re-derive that rotation happens.
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

test("an account another dir is already running is excluded, with the reason named", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-current", []), usage: usage(4) },
      // Most headroom of all — and already live somewhere else.
      { identity: identity(ACCOUNT_SHARED, [{ dir: "/fake/other", profileName: "p-OTHER" }]), usage: usage(95) },
      { identity: identity("uuid-free", [{ dir: "/fake/free", profileName: "p-FREE" }]), usage: usage(60) },
    ],
    { currentUuid: "uuid-current", contendedAccounts: new Set([ACCOUNT_SHARED]), now: NOW },
  );

  expect(picked.candidate?.accountUuid).toBe("uuid-free");
  expect(picked.excluded.find((e) => e.accountUuid === ACCOUNT_SHARED)?.reason).toBe("contended");
});

test("POSITIVE CONTROL: with no contention the same account IS selected", () => {
  // Without this, the test above passes for any reason at all — including the
  // selector simply never picking that account.
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-current", []), usage: usage(4) },
      { identity: identity(ACCOUNT_SHARED, [{ dir: "/fake/other", profileName: "p-OTHER" }]), usage: usage(95) },
      { identity: identity("uuid-free", [{ dir: "/fake/free", profileName: "p-FREE" }]), usage: usage(60) },
    ],
    { currentUuid: "uuid-current", now: NOW },
  );

  expect(picked.candidate?.accountUuid).toBe(ACCOUNT_SHARED);
});

// --- the hook, against a real two-dir state ---------------------------------

function hookHarness(opts: {
  configDir: string;
  identities: AccountIdentity[];
  cache: Record<string, UsageCacheEntry>;
  liveDirs: Set<string>;
  switchesTo?: string;
  withGuard: boolean;
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
    // The guard is opt-in via this dep; omitting it is exactly the pre-fix hook.
    ...(opts.withGuard ? { liveSessionsIn: (dir: string) => (opts.liveDirs.has(dir) ? 1 : 0) } : {}),
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

test("the hook creates a SECOND live copy of one account without the guard, and refuses with it", async () => {
  // Build the state for real: dir A runs the shared account with a live session;
  // our session is in dir B and is over its threshold.
  const dirA = "/fake/profiles/account-a";
  const dirB = "/fake/profiles/account-b";
  const identities = [
    identity("uuid-current", [{ dir: dirB, profileName: "p-B" }]),
    identity(ACCOUNT_SHARED, [{ dir: dirA, profileName: "p-A" }]),
  ];
  const cache = { "uuid-current": cacheEntry("uuid-current", 4), [ACCOUNT_SHARED]: cacheEntry(ACCOUNT_SHARED, 95) };
  const liveDirs = new Set([dirA]);

  // WITHOUT the guard: the hook takes the second copy — the precondition for
  // the destruction. This is the shipped behaviour.
  const before = hookHarness({
    configDir: dirB,
    identities,
    cache,
    liveDirs,
    switchesTo: ACCOUNT_SHARED,
    withGuard: false,
  });
  const beforeOutcome = await runUsageHook(hookOptions(dirB), before.deps);
  expect(beforeOutcome.action).toBe("switched");
  expect(before.calls.switches).toEqual(["p-A"]);

  // WITH the guard: identical input, no second copy created, and it says why.
  const after = hookHarness({
    configDir: dirB,
    identities,
    cache,
    liveDirs,
    switchesTo: ACCOUNT_SHARED,
    withGuard: true,
  });
  const afterOutcome = await runUsageHook(hookOptions(dirB), after.deps);
  expect(after.calls.switches).toEqual([]);
  expect(afterOutcome.action).toBe("none");
  expect(afterOutcome.systemMessage ?? "").toMatch(/already being run by another session/i);
});

test("a dir running the account is only contention when the session is LIVE", async () => {
  // The guard must key on liveness, not on the door existing — otherwise every
  // account with a registered profile dir would be permanently unavailable and
  // the hook could never switch at all.
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
    withGuard: true,
  });
  const outcome = await runUsageHook(hookOptions(dirB), h.deps);
  expect(outcome.action).toBe("switched");
  expect(h.calls.switches).toEqual(["p-A"]);
});

test("our own config dir never counts as contention with itself", async () => {
  // The dir being switched AWAY from always has a live session — this one. If it
  // counted, the hook would refuse every switch.
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
    withGuard: true,
  });
  const outcome = await runUsageHook(hookOptions(dirB), h.deps);
  expect(outcome.action).toBe("switched");
});

// --- the destruction, on real files -----------------------------------------

test("two dirs, one account: the loser is blanked and the survivor's parked copy holds", () => {
  // The full state on disk. The rotation itself is MODELLED — we write the
  // payload Claude Code was measured leaving behind rather than causing a real
  // refresh to fail — but everything around it is real files going through the
  // real snapshot path.
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

    // Two dirs, ONE account — the precondition.
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

    // The next ordinary launch refreshes snapshots. Before the guard this
    // propagated the blank into the parked copy — the last copy under that dir.
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
