import { test, expect } from "bun:test";
import type { AccountIdentity, AccountCredentialRef } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import type { AutoSwitchState, UsageCacheEntry } from "./lib/auto-switch.js";
import {
  hookOutputJson,
  runUsageHook,
  type HookNoticeState,
  type UsageHookDeps,
  type UsageHookOptions,
} from "./lib/usage-hook.js";

/**
 * Regressions for the "not fit to run unattended" review (tasks 069f16d9,
 * db03b031, 63e642c1, and the hook half of ccc23767).
 *
 * The theme every case here shares: an unattended session is one nobody is
 * watching, so a hook that declines to act must SAY so. Each test below failed
 * against the pre-fix implementation by returning `hookOutputJson(...) ===
 * undefined` or by switching nothing at all.
 */

const NOW = new Date("2026-07-28T12:00:00Z");

function usage(headroom: number, opts: { fetchedAt?: Date; resetsAt?: string } = {}): AccountUsage {
  return {
    windows: [
      {
        id: "weekly_all",
        utilization: 100 - headroom,
        scoped: false,
        resetsAt: opts.resetsAt ?? "2026-08-01T14:00:00Z",
      },
    ],
    headroom,
    bindingWindow: "weekly_all",
    fetchedAt: (opts.fetchedAt ?? NOW).toISOString(),
  };
}

function cacheEntry(uuid: string, headroom: number, ageMs = 0): UsageCacheEntry {
  const fetchedAt = new Date(NOW.getTime() - ageMs);
  return { accountUuid: uuid, fetchedAt: fetchedAt.toISOString(), usage: usage(headroom, { fetchedAt }) };
}

function credential(opts: { valid: boolean; renewable: boolean }): AccountCredentialRef {
  return {
    path: "/fake/credentials.json",
    source: "central",
    expiresAt: opts.valid ? NOW.getTime() + 60_000 : NOW.getTime() - 60_000,
    hasAccessToken: true,
    hasRefreshToken: opts.renewable,
    valid: opts.valid,
    renewable: opts.renewable,
  };
}

function identity(
  uuid: string,
  email: string,
  profileName: string | undefined,
  status: AccountIdentity["status"] = "ok",
): AccountIdentity {
  return {
    accountUuid: uuid,
    email,
    doors: profileName ? [{ dir: `/fake/${profileName}`, role: "own-identity", profileName, email }] : [],
    credential: credential({ valid: status === "ok", renewable: true }),
    status,
  };
}

interface HarnessOptions {
  currentUuid?: string | ((calls: number) => string | undefined);
  /**
   * The uuid the config dir reads as AFTER a switch. The hook re-reads the dir
   * and treats an unchanged uuid as a failure, so a success case must move.
   */
  switchesTo?: string;
  cache?: Record<string, UsageCacheEntry>;
  identities?: AccountIdentity[];
  state?: AutoSwitchState;
  notices?: HookNoticeState;
  /** Omit the notice deps entirely (the "caller opted out of throttling" path). */
  noNoticeStore?: boolean;
  listIdentitiesError?: Error;
}

function harness(opts: HarnessOptions) {
  const calls = {
    refreshes: 0,
    switches: [] as { profileName: string; dir: string }[],
    writtenStates: [] as AutoSwitchState[],
    writtenNotices: [] as HookNoticeState[],
    uuidReads: 0,
    cacheReads: [] as { uuid: string; maxAgeMs: number }[],
  };
  let notices = opts.notices ? { ...opts.notices } : {};
  const deps: UsageHookDeps = {
    currentAccountUuid: () => {
      calls.uuidReads += 1;
      const cur = opts.currentUuid;
      if (typeof cur === "function") return cur(calls.uuidReads);
      if (opts.switchesTo && calls.switches.length > 0) return opts.switchesTo;
      return cur;
    },
    readCache: (uuid, maxAgeMs) => {
      calls.cacheReads.push({ uuid, maxAgeMs });
      const entry = opts.cache?.[uuid];
      if (!entry) return undefined;
      const age = NOW.getTime() - Date.parse(entry.fetchedAt);
      return age <= maxAgeMs ? entry : undefined;
    },
    listIdentities: async () => {
      if (opts.listIdentitiesError) throw opts.listIdentitiesError;
      return opts.identities ?? [];
    },
    triggerRefresh: () => {
      calls.refreshes += 1;
    },
    performSwitch: async (profileName, dir) => {
      calls.switches.push({ profileName, dir });
      return { liveSessions: 1 };
    },
    readState: () => opts.state,
    writeState: (s) => {
      calls.writtenStates.push(s);
    },
    ...(opts.noNoticeStore
      ? {}
      : {
          readNotices: () => notices,
          writeNotices: (s: HookNoticeState) => {
            notices = { ...s };
            calls.writtenNotices.push({ ...s });
          },
        }),
    now: () => NOW,
  };
  return { deps, calls, seenNotices: () => notices };
}

const options: UsageHookOptions = {
  configDir: "/fake/session",
  thresholdPercent: 90,
  minHeadroom: 25,
  minSessionHeadroom: 10,
  cooldownMs: 600_000,
  cacheMaxAgeMs: 300_000,
};

/** The hook is only "visible" if Claude Code would actually print something. */
function spoken(outcome: { systemMessage?: string; additionalContext?: string }): string | undefined {
  const json = hookOutputJson(outcome);
  return json === undefined ? undefined : (JSON.parse(json) as { systemMessage?: string }).systemMessage;
}

// --- 069f16d9: silent degradation -------------------------------------------

test("no usable cache at all: says so out loud instead of exiting silently", async () => {
  const { deps, calls } = harness({ currentUuid: "uuid-a", cache: {} });
  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("refresh-triggered");
  expect(calls.refreshes).toBe(1);
  // The defect: hookOutputJson returned undefined here, so 31% of production
  // invocations reached no decision with nothing on screen.
  expect(spoken(outcome)).toMatch(/auto-switch/i);
  expect(spoken(outcome)).toMatch(/no usage measurement/i);
});

test("a stale-but-usable reading still decides instead of degrading to a no-op", async () => {
  // 20 minutes old: far past the 300s freshness TTL, which is what an unattended
  // session's sparse prompts produce. Usage inside a window only ever rises, so
  // a stale reading can under-report but never invent a breach.
  const { deps, calls } = harness({
    currentUuid: "uuid-a",
    switchesTo: "uuid-b",
    cache: {
      "uuid-a": cacheEntry("uuid-a", 4, 20 * 60_000),
      "uuid-b": cacheEntry("uuid-b", 80, 20 * 60_000),
    },
    identities: [identity("uuid-a", "a@x.com", "p-A"), identity("uuid-b", "b@x.com", "p-B")],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "p-B", dir: "/fake/session" }]);
  // Deciding on stale data must still warm the cache for the next prompt.
  expect(calls.refreshes).toBe(1);
});

test("a reading older than the stale bound is refused, not silently trusted", async () => {
  const { deps } = harness({
    currentUuid: "uuid-a",
    cache: { "uuid-a": cacheEntry("uuid-a", 4, 5 * 60 * 60_000) },
    identities: [identity("uuid-a", "a@x.com", "p-A")],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("refresh-triggered");
  expect(spoken(outcome)).toMatch(/no usage measurement/i);
});

test("cooldown refusal is announced, not swallowed", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-a",
    cache: { "uuid-a": cacheEntry("uuid-a", 4) },
    identities: [identity("uuid-a", "a@x.com", "p-A"), identity("uuid-b", "b@x.com", "p-B")],
    state: { lastSwitchAt: new Date(NOW.getTime() - 60_000).toISOString() },
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("none");
  expect(outcome.reason).toBe("cooldown");
  expect(calls.switches).toEqual([]);
  expect(spoken(outcome)).toMatch(/cooldown/i);
});

test("a thrown dependency fails open AND tells the user auto-switching is not running", async () => {
  const { deps } = harness({
    currentUuid: "uuid-a",
    cache: { "uuid-a": cacheEntry("uuid-a", 4) },
    identities: [identity("uuid-a", "a@x.com", "p-A")],
    listIdentitiesError: new Error("Hasna cloud request failed: GET /accounts?tool=claude -> 401"),
  });

  const outcome = await runUsageHook(options, deps);

  // Fail-open is preserved: an action, never a throw.
  expect(outcome.action).toBe("fail-open");
  expect(outcome.reason).toMatch(/401/);
  // ...but it is no longer invisible. This is the production 01:07/01:17/01:27 case.
  expect(spoken(outcome)).toMatch(/401/);
});

test("repeat notices are throttled so a degraded hook cannot spam every prompt", async () => {
  const shared: HarnessOptions = { currentUuid: "uuid-a", cache: {} };
  const first = harness(shared);
  const firstOutcome = await runUsageHook(options, first.deps);
  expect(spoken(firstOutcome)).toBeDefined();

  const second = harness({ ...shared, notices: first.seenNotices() });
  const secondOutcome = await runUsageHook(options, second.deps);

  expect(secondOutcome.action).toBe("refresh-triggered");
  // Same degraded state a moment later: acted on identically, said once.
  expect(spoken(secondOutcome)).toBeUndefined();

  // ...and speaks again once the interval has elapsed: same recorded notices,
  // back-dated an hour past the default 15-minute gap.
  const backdated: HookNoticeState = Object.fromEntries(
    Object.keys(first.seenNotices()).map((key) => [key, new Date(NOW.getTime() - 60 * 60_000).toISOString()]),
  );
  expect(Object.keys(backdated).length).toBeGreaterThan(0);
  const later = harness({ ...shared, notices: backdated });
  const laterOutcome = await runUsageHook(options, later.deps);
  expect(spoken(laterOutcome)).toBeDefined();
});

test("healthy headroom stays silent — the throttle must not make the quiet path chatty", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-a",
    cache: { "uuid-a": cacheEntry("uuid-a", 80) },
    identities: [identity("uuid-a", "a@x.com", "p-A")],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("none");
  expect(spoken(outcome)).toBeUndefined();
  expect(calls.refreshes).toBe(0);
  expect(calls.writtenNotices).toEqual([]);
});

// --- db03b031: door-less top candidate ---------------------------------------

test("a door-less top candidate falls through to the next-ranked account", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    switchesTo: "uuid-healthy",
    cache: {
      "uuid-cur": cacheEntry("uuid-cur", 4),
      "uuid-nodoor": cacheEntry("uuid-nodoor", 95),
      "uuid-healthy": cacheEntry("uuid-healthy", 70),
    },
    identities: [
      identity("uuid-cur", "cur@x.com", "p-CUR"),
      // Ranks FIRST on headroom and has no own-identity door to switch through.
      identity("uuid-nodoor", "nodoor@x.com", undefined),
      identity("uuid-healthy", "healthy@x.com", "p-HEALTHY"),
    ],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "p-HEALTHY", dir: "/fake/session" }]);
});

test("a current-occupant door is not a switch door — only own-identity counts", async () => {
  const occupantOnly: AccountIdentity = {
    accountUuid: "uuid-occupant",
    email: "occupant@x.com",
    doors: [{ dir: "/fake/elsewhere", role: "current-occupant", profileName: "p-SOMEONE" }],
    credential: credential({ valid: true, renewable: true }),
    status: "ok",
  };
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    switchesTo: "uuid-healthy",
    cache: {
      "uuid-cur": cacheEntry("uuid-cur", 4),
      "uuid-occupant": cacheEntry("uuid-occupant", 95),
      "uuid-healthy": cacheEntry("uuid-healthy", 70),
    },
    identities: [
      identity("uuid-cur", "cur@x.com", "p-CUR"),
      occupantOnly,
      identity("uuid-healthy", "healthy@x.com", "p-HEALTHY"),
    ],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "p-HEALTHY", dir: "/fake/session" }]);
});

test("when NO candidate has a door the hook says so instead of returning nothing", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: {
      "uuid-cur": cacheEntry("uuid-cur", 4),
      "uuid-nodoor": cacheEntry("uuid-nodoor", 95),
    },
    identities: [identity("uuid-cur", "cur@x.com", "p-CUR"), identity("uuid-nodoor", "nodoor@x.com", undefined)],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("none");
  expect(calls.switches).toEqual([]);
  expect(spoken(outcome)).toMatch(/no profile on this machine/i);
});

// --- 63e642c1: expired ≠ unusable -------------------------------------------

test("an expired-but-refreshable account is a usable switch target", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    switchesTo: "uuid-expired",
    cache: {
      "uuid-cur": cacheEntry("uuid-cur", 4),
      "uuid-expired": cacheEntry("uuid-expired", 90),
    },
    identities: [
      identity("uuid-cur", "cur@x.com", "p-CUR"),
      identity("uuid-expired", "expired@x.com", "p-EXPIRED", "expired"),
    ],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "p-EXPIRED", dir: "/fake/session" }]);
  expect(outcome.systemMessage).toMatch(/token refresh/i);
});

test("a valid credential outranks an expired one even with less headroom", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    switchesTo: "uuid-valid",
    cache: {
      "uuid-cur": cacheEntry("uuid-cur", 4),
      "uuid-expired": cacheEntry("uuid-expired", 95),
      "uuid-valid": cacheEntry("uuid-valid", 60),
    },
    identities: [
      identity("uuid-cur", "cur@x.com", "p-CUR"),
      identity("uuid-expired", "expired@x.com", "p-EXPIRED", "expired"),
      identity("uuid-valid", "valid@x.com", "p-VALID"),
    ],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "p-VALID", dir: "/fake/session" }]);
});

test("an account with no refresh token stays excluded", async () => {
  const dead: AccountIdentity = {
    accountUuid: "uuid-dead",
    email: "dead@x.com",
    doors: [{ dir: "/fake/p-DEAD", role: "own-identity", profileName: "p-DEAD" }],
    credential: credential({ valid: false, renewable: false }),
    status: "expired",
  };
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: { "uuid-cur": cacheEntry("uuid-cur", 4), "uuid-dead": cacheEntry("uuid-dead", 95) },
    identities: [identity("uuid-cur", "cur@x.com", "p-CUR"), dead],
  });

  const outcome = await runUsageHook(options, deps);

  expect(outcome.action).toBe("none");
  expect(calls.switches).toEqual([]);
});

// --- ccc23767: the state the hook writes must name its own dir ---------------

test("the written switch state records the config dir it belongs to", async () => {
  const { deps, calls } = harness({
    currentUuid: (n) => (n === 1 ? "uuid-cur" : "uuid-healthy"),
    cache: { "uuid-cur": cacheEntry("uuid-cur", 4), "uuid-healthy": cacheEntry("uuid-healthy", 70) },
    identities: [identity("uuid-cur", "cur@x.com", "p-CUR"), identity("uuid-healthy", "healthy@x.com", "p-HEALTHY")],
  });

  await runUsageHook(options, deps);

  expect(calls.writtenStates).toHaveLength(1);
  expect(calls.writtenStates[0]?.configDir).toBe("/fake/session");
});
