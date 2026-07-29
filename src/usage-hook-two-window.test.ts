import { test, expect } from "bun:test";
import type { AccountIdentity } from "./lib/identity-index.js";
import type { AutoSwitchState, UsageCacheEntry } from "./lib/auto-switch.js";
import { parseUsageResponse, type AccountUsage } from "./lib/usage.js";
import {
  hookOutputJson,
  runUsageHook,
  type UsageHookAction,
  type UsageHookDeps,
  type UsageHookOptions,
} from "./lib/usage-hook.js";
import type { RecordExhaustionInput } from "./lib/exhaustion-ledger.js";

/**
 * Hook-level behaviour for the two-window model, plus the invariant that keeps
 * the owner's unattended session alive: this hook must NEVER block a prompt.
 *
 * Hook exit 2 / a block decision on UserPromptSubmit refuses the message. A
 * hook that blocks when it cannot find a healthy account would brick the
 * session entirely — the failure mode is not "no switch happened", it is "the
 * session refuses every message until a human returns".
 */

const NOW = new Date("2026-07-28T12:00:00.000Z");
const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();
const hours = (n: number) => n * 3_600_000;
const days = (n: number) => n * 86_400_000;
const minutes = (n: number) => n * 60_000;

const OPTS: UsageHookOptions = {
  configDir: "/fake/session-dir",
  thresholdPercent: 90,
  minHeadroom: 25,
  cooldownMs: 600_000,
  cacheMaxAgeMs: 300_000,
};

function usage(
  spec: {
    session?: { percent: number; resetsAt?: string };
    weekly?: { percent: number; resetsAt?: string };
  },
  /** When the reading was taken. A reset boundary is only a "roll" if it fell
   *  after the reading — a boundary already past at read time is a bad payload. */
  fetchedAtMs = 0,
): AccountUsage {
  const limits: Record<string, unknown>[] = [];
  if (spec.session) {
    limits.push({
      kind: "session",
      group: "session",
      percent: spec.session.percent,
      ...(spec.session.resetsAt ? { resets_at: spec.session.resetsAt } : {}),
    });
  }
  if (spec.weekly) {
    limits.push({
      kind: "weekly_all",
      group: "weekly",
      percent: spec.weekly.percent,
      ...(spec.weekly.resetsAt ? { resets_at: spec.weekly.resetsAt } : {}),
    });
  }
  return parseUsageResponse({ limits }, new Date(NOW.getTime() + fetchedAtMs));
}

function identity(uuid: string, profileName?: string): AccountIdentity {
  return {
    accountUuid: uuid,
    email: `${uuid}@example.com`,
    doors: profileName
      ? [{ dir: `/fake/${profileName}`, role: "own-identity", profileName, email: `${uuid}@example.com` }]
      : [],
    status: "ok",
  };
}

interface HarnessOptions {
  currentUuid?: string;
  cache?: Record<string, UsageCacheEntry>;
  identities?: AccountIdentity[];
  cooldowns?: Map<string, string>;
  switchError?: Error;
  /** uuid the config dir reports AFTER a switch (defaults to the target). */
  afterSwitchUuid?: string;
}

function harness(opts: HarnessOptions) {
  const calls = {
    switches: [] as string[],
    recorded: [] as RecordExhaustionInput[],
    cleared: [] as string[],
    states: [] as AutoSwitchState[],
    cooldownReads: 0,
  };
  let switched = false;
  const deps: UsageHookDeps = {
    currentAccountUuid: () =>
      switched ? (opts.afterSwitchUuid ?? calls.switches.at(-1)?.replace("profile-", "")) : opts.currentUuid,
    readCache: (uuid) => opts.cache?.[uuid],
    listIdentities: async () => opts.identities ?? [],
    triggerRefresh: () => {},
    performSwitch: async (profileName) => {
      calls.switches.push(profileName);
      if (opts.switchError) throw opts.switchError;
      switched = true;
      return { liveSessions: 1 };
    },
    readState: () => undefined,
    writeState: (s) => {
      calls.states.push(s);
    },
    activeCooldowns: () => {
      calls.cooldownReads += 1;
      return opts.cooldowns ?? new Map();
    },
    recordExhaustion: (input) => {
      calls.recorded.push(input);
    },
    clearExhaustion: (uuid) => {
      calls.cleared.push(uuid);
    },
    now: () => NOW,
  };
  return { deps, calls };
}

function cacheEntry(accountUuid: string, u: AccountUsage): UsageCacheEntry {
  return { accountUuid, usage: u, fetchedAt: u.fetchedAt };
}

// ---------------------------------------------------------------------------
// FAIL OPEN. The session must survive every one of these unattended.
// ---------------------------------------------------------------------------

test("the hook never emits a blocking decision, for any outcome it can produce", () => {
  const actions: UsageHookAction[] = [
    "none",
    "refresh-triggered",
    "switched",
    "switch-failed",
    "fail-open",
  ];
  for (const action of actions) {
    const json = hookOutputJson({
      action,
      reason: "any",
      systemMessage: "something happened",
      additionalContext: "context",
    });
    const parsed = JSON.parse(json!);
    // UserPromptSubmit blocks via `decision: "block"` or `continue: false`.
    expect(parsed.decision).toBeUndefined();
    expect(parsed.continue).toBeUndefined();
    expect(parsed.permissionDecision).toBeUndefined();
    expect(Object.keys(parsed).sort()).toEqual(["hookSpecificOutput", "systemMessage"]);
  }
});

test("every account exhausted: the prompt passes through with a warning, nothing switches", () => {
  const dead = usage({
    session: { percent: 100, resetsAt: at(hours(3)) },
    weekly: { percent: 100, resetsAt: at(days(4)) },
  });
  const { deps, calls } = harness({
    currentUuid: "acct-current",
    identities: [identity("acct-current", "profile-current"), identity("acct-other", "profile-other")],
    cache: {
      "acct-current": cacheEntry("acct-current", dead),
      "acct-other": cacheEntry("acct-other", dead),
    },
  });

  return runUsageHook(OPTS, deps).then((outcome) => {
    expect(outcome.action).toBe("none");
    expect(outcome.reason).toBe("all-limited");
    expect(calls.switches).toHaveLength(0);
    // The user is told, and the prompt still goes through.
    expect(outcome.systemMessage).toContain("all known accounts are limited");
    const parsed = JSON.parse(hookOutputJson(outcome)!);
    expect(parsed.decision).toBeUndefined();
  });
});

test("positive control: with one healthy peer the same setup DOES switch", async () => {
  // Identical to the test above except acct-other is healthy. Proves the
  // no-switch outcome there is caused by exhaustion and not by a hook that
  // never switches at all.
  const dead = usage({
    session: { percent: 100, resetsAt: at(hours(3)) },
    weekly: { percent: 100, resetsAt: at(days(4)) },
  });
  const healthy = usage({
    session: { percent: 5, resetsAt: at(hours(4)) },
    weekly: { percent: 15, resetsAt: at(days(4)) },
  });
  const { deps, calls } = harness({
    currentUuid: "acct-current",
    afterSwitchUuid: "acct-other",
    identities: [identity("acct-current", "profile-current"), identity("acct-other", "profile-other")],
    cache: {
      "acct-current": cacheEntry("acct-current", dead),
      "acct-other": cacheEntry("acct-other", healthy),
    },
  });

  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual(["profile-other"]);
});

// ---------------------------------------------------------------------------
// Two-window discrimination, end to end through the hook.
// ---------------------------------------------------------------------------

test("switches to the weekly-healthy account, not the weekly-dead one", async () => {
  const current = usage({
    session: { percent: 95, resetsAt: at(hours(2)) },
    weekly: { percent: 40, resetsAt: at(days(4)) },
  });
  // Both alternatives read 0 headroom under a collapsed single-scalar model.
  const weeklyDead = usage({
    session: { percent: 0, resetsAt: at(hours(4)) },
    weekly: { percent: 100, resetsAt: at(days(6)) },
  });
  // Read an hour ago at a saturated 5-hour window that has since rolled.
  const sessionRolled = usage(
    {
      session: { percent: 100, resetsAt: at(-minutes(5)) },
      weekly: { percent: 20, resetsAt: at(days(6)) },
    },
    -hours(1),
  );

  const { deps, calls } = harness({
    currentUuid: "acct-current",
    afterSwitchUuid: "acct-rolled",
    identities: [
      identity("acct-current", "profile-current"),
      identity("acct-weekly-dead", "profile-weekly-dead"),
      identity("acct-rolled", "profile-rolled"),
    ],
    cache: {
      "acct-current": cacheEntry("acct-current", current),
      "acct-weekly-dead": cacheEntry("acct-weekly-dead", weeklyDead),
      "acct-rolled": cacheEntry("acct-rolled", sessionRolled),
    },
  });

  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual(["profile-rolled"]);
});

// ---------------------------------------------------------------------------
// Ledger integration.
// ---------------------------------------------------------------------------

test("records the current account's exhaustion durably, tagged with the window that died", async () => {
  const current = usage({
    session: { percent: 30, resetsAt: at(hours(2)) },
    weekly: { percent: 100, resetsAt: at(days(6)) },
  });
  const { deps, calls } = harness({
    currentUuid: "acct-current",
    identities: [identity("acct-current", "profile-current")],
    cache: { "acct-current": cacheEntry("acct-current", current) },
  });

  await runUsageHook(OPTS, deps);
  expect(calls.recorded).toHaveLength(1);
  expect(calls.recorded[0]?.accountUuid).toBe("acct-current");
  expect(calls.recorded[0]?.windowClass).toBe("weekly");
  expect(calls.recorded[0]?.resetsAt).toBe(at(days(6)));
});

test("a healthy current account clears its record rather than accumulating one", async () => {
  const healthy = usage({
    session: { percent: 10, resetsAt: at(hours(4)) },
    weekly: { percent: 20, resetsAt: at(days(6)) },
  });
  const { deps, calls } = harness({
    currentUuid: "acct-current",
    identities: [identity("acct-current", "profile-current")],
    cache: { "acct-current": cacheEntry("acct-current", healthy) },
  });

  await runUsageHook(OPTS, deps);
  expect(calls.recorded).toHaveLength(0);
  expect(calls.cleared).toEqual(["acct-current"]);
});

test("an account under cooldown is not switched to; the same account is taken after release", async () => {
  const current = usage({
    session: { percent: 95, resetsAt: at(hours(2)) },
    weekly: { percent: 40, resetsAt: at(days(4)) },
  });
  const target = usage({
    session: { percent: 5, resetsAt: at(hours(4)) },
    weekly: { percent: 10, resetsAt: at(days(4)) },
  });
  const setup = (cooldowns: Map<string, string>) =>
    harness({
      currentUuid: "acct-current",
      afterSwitchUuid: "acct-target",
      cooldowns,
      identities: [identity("acct-current", "profile-current"), identity("acct-target", "profile-target")],
      cache: {
        "acct-current": cacheEntry("acct-current", current),
        "acct-target": cacheEntry("acct-target", target),
      },
    });

  const blocked = setup(new Map([["acct-target", at(hours(1))]]));
  const blockedOutcome = await runUsageHook(OPTS, blocked.deps);
  expect(blocked.calls.switches).toHaveLength(0);
  expect(blockedOutcome.action).toBe("none");

  // POSITIVE CONTROL: identical inputs, cooldown already released. Without
  // this the test above would also pass against a hook that never switches.
  const released = setup(new Map([["acct-target", at(-hours(1))]]));
  const releasedOutcome = await runUsageHook(OPTS, released.deps);
  expect(released.calls.switches).toEqual(["profile-target"]);
  expect(releasedOutcome.action).toBe("switched");
});

test("a hook with no ledger wired still decides and never throws", async () => {
  const current = usage({
    session: { percent: 95, resetsAt: at(hours(2)) },
    weekly: { percent: 40, resetsAt: at(days(4)) },
  });
  const target = usage({
    session: { percent: 5, resetsAt: at(hours(4)) },
    weekly: { percent: 10, resetsAt: at(days(4)) },
  });
  const { deps } = harness({
    currentUuid: "acct-current",
    afterSwitchUuid: "acct-target",
    identities: [identity("acct-current", "profile-current"), identity("acct-target", "profile-target")],
    cache: {
      "acct-current": cacheEntry("acct-current", current),
      "acct-target": cacheEntry("acct-target", target),
    },
  });
  delete (deps as { activeCooldowns?: unknown }).activeCooldowns;
  delete (deps as { recordExhaustion?: unknown }).recordExhaustion;
  delete (deps as { clearExhaustion?: unknown }).clearExhaustion;

  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("switched");
});
