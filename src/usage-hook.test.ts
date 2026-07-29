import { test, expect } from "bun:test";
import type { AccountIdentity } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import type { AutoSwitchState, UsageCacheEntry } from "./lib/auto-switch.js";
import { hookOutputJson, runUsageHook, type UsageHookDeps } from "./lib/usage-hook.js";

function usage(headroom: number): AccountUsage {
  return {
    windows: [{ id: "weekly_all", utilization: 100 - headroom, scoped: false, resetsAt: "2026-08-01T14:00:00Z" }],
    headroom,
    bindingWindow: "weekly_all",
    fetchedAt: new Date().toISOString(),
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
    status,
  };
}

interface HarnessOptions {
  currentUuid?: string | ((calls: number) => string | undefined);
  cache?: Record<string, UsageCacheEntry>;
  identities?: AccountIdentity[];
  state?: AutoSwitchState;
  switchLiveSessions?: number;
  switchError?: Error;
}

function harness(opts: HarnessOptions) {
  const calls = {
    refreshes: 0,
    switches: [] as { profileName: string; dir: string }[],
    writtenStates: [] as AutoSwitchState[],
    uuidReads: 0,
  };
  const deps: UsageHookDeps = {
    currentAccountUuid: () => {
      calls.uuidReads += 1;
      const cur = opts.currentUuid;
      return typeof cur === "function" ? cur(calls.uuidReads) : cur;
    },
    readCache: (uuid) => opts.cache?.[uuid],
    listIdentities: async () => opts.identities ?? [],
    triggerRefresh: () => {
      calls.refreshes += 1;
    },
    performSwitch: async (profileName, dir) => {
      calls.switches.push({ profileName, dir });
      if (opts.switchError) throw opts.switchError;
      return { liveSessions: opts.switchLiveSessions ?? 1 };
    },
    readState: () => opts.state,
    writeState: (s) => {
      calls.writtenStates.push(s);
    },
    now: () => new Date("2026-07-28T12:00:00Z"),
  };
  return { deps, calls };
}

const OPTS = {
  configDir: "/fake/session-dir",
  thresholdPercent: 90,
  minHeadroom: 25,
  cooldownMs: 600_000,
  cacheMaxAgeMs: 300_000,
};

test("healthy headroom: no switch, no messages, no refresh", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: { "uuid-cur": { accountUuid: "uuid-cur", usage: usage(70), fetchedAt: "x" } },
  });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("none");
  expect(calls.switches).toHaveLength(0);
  expect(outcome.systemMessage).toBeUndefined();
});

test("missing cache fails open and triggers a background refresh — never blocks the prompt", async () => {
  const { deps, calls } = harness({ currentUuid: "uuid-cur", cache: {} });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("refresh-triggered");
  expect(calls.refreshes).toBe(1);
  expect(calls.switches).toHaveLength(0);
});

test("no readable current account fails open", async () => {
  const { deps, calls } = harness({});
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("fail-open");
  expect(calls.switches).toHaveLength(0);
});

test("a throwing dependency fails open instead of blocking the prompt", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: { "uuid-cur": { accountUuid: "uuid-cur", usage: usage(2), fetchedAt: "x" } },
  });
  deps.listIdentities = async () => {
    throw new Error("registry unreachable");
  };
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("fail-open");
  expect(calls.switches).toHaveLength(0);
});

test("breach + healthy sibling account: switches, asserts the uuid CHANGED, announces loudly", async () => {
  const { deps, calls } = harness({
    // First read: the exhausted current account. After the switch the dir
    // re-reads as the target — the post-switch assertion must see the change.
    currentUuid: (n) => (calls.switches.length === 0 ? "uuid-cur" : "uuid-fresh"),
    cache: {
      "uuid-cur": { accountUuid: "uuid-cur", usage: usage(5), fetchedAt: "x" },
      "uuid-fresh": { accountUuid: "uuid-fresh", usage: usage(85), fetchedAt: "x" },
    },
    identities: [
      identity("uuid-cur", "tired@example.com", "tired-profile"),
      identity("uuid-fresh", "fresh@example.com", "fresh-profile"),
    ],
    switchLiveSessions: 2,
  });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("switched");
  expect(calls.switches).toEqual([{ profileName: "fresh-profile", dir: "/fake/session-dir" }]);
  expect(outcome.systemMessage).toContain("tired@example.com");
  expect(outcome.systemMessage).toContain("fresh@example.com");
  expect(outcome.systemMessage).toContain("2 live session");
  expect(calls.writtenStates).toHaveLength(1);
  expect(calls.writtenStates[0]!.toUuid).toBe("uuid-fresh");
  // The announcement must never carry credential material.
  expect(outcome.systemMessage).not.toContain("token");
  expect(outcome.additionalContext).toContain("fresh@example.com");
});

test("a switch that does NOT change the active uuid is a loud failure, not a success", async () => {
  // The silent-no-op hazard: two dirs holding one account. performSwitch
  // "succeeds" but the dir still reads as the same uuid.
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: {
      "uuid-cur": { accountUuid: "uuid-cur", usage: usage(5), fetchedAt: "x" },
      "uuid-dup": { accountUuid: "uuid-dup", usage: usage(85), fetchedAt: "x" },
    },
    identities: [
      identity("uuid-cur", "tired@example.com", "tired-profile"),
      identity("uuid-dup", "same@example.com", "dup-profile"),
    ],
  });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("switch-failed");
  expect(calls.switches).toHaveLength(1);
  expect(outcome.systemMessage).toMatch(/did not change|FAILED/i);
});

test("cooldown suppresses a second switch even when the threshold is breached", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: {
      "uuid-cur": { accountUuid: "uuid-cur", usage: usage(5), fetchedAt: "x" },
      "uuid-fresh": { accountUuid: "uuid-fresh", usage: usage(85), fetchedAt: "x" },
    },
    identities: [identity("uuid-fresh", "fresh@example.com", "fresh-profile")],
    state: { lastSwitchAt: "2026-07-28T11:55:00Z", fromUuid: "a", toUuid: "uuid-cur" },
  });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("none");
  expect(outcome.reason).toBe("cooldown");
  expect(calls.switches).toHaveLength(0);
});

test("all accounts limited: reports honestly, switches nothing, does not flap", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: {
      "uuid-cur": { accountUuid: "uuid-cur", usage: usage(5), fetchedAt: "x" },
      "uuid-b": { accountUuid: "uuid-b", usage: usage(3), fetchedAt: "x" },
    },
    identities: [
      identity("uuid-cur", "tired@example.com", "tired-profile"),
      identity("uuid-b", "also-tired@example.com", "b-profile"),
    ],
  });
  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("none");
  expect(outcome.reason).toBe("all-limited");
  expect(calls.switches).toHaveLength(0);
  expect(outcome.systemMessage).toMatch(/all .*limited|no account has headroom/i);
});

test("a usage-endpoint 429 is unknown health, not evidence that all accounts are limited", async () => {
  const { deps, calls } = harness({
    currentUuid: "uuid-cur",
    cache: {
      "uuid-cur": { accountUuid: "uuid-cur", usage: usage(5), fetchedAt: "x" },
      "uuid-limited": { accountUuid: "uuid-limited", usage: usage(3), fetchedAt: "x" },
      "uuid-throttled": {
        accountUuid: "uuid-throttled",
        fetchedAt: "x",
        error: { kind: "http", message: "usage endpoint returned HTTP 429", status: 429 },
      },
    },
    identities: [
      identity("uuid-cur", "tired@example.com", "tired-profile"),
      identity("uuid-limited", "also-tired@example.com", "limited-profile"),
      identity("uuid-throttled", "unknown@example.com", "unknown-profile"),
    ],
  });

  const outcome = await runUsageHook(OPTS, deps);
  expect(outcome.action).toBe("none");
  expect(outcome.reason).toBe("no-usage-data");
  expect(calls.switches).toHaveLength(0);
  expect(outcome.systemMessage).not.toMatch(/all known accounts are limited/i);
});

test("hookOutputJson emits UserPromptSubmit hookSpecificOutput and omits empty outcomes", () => {
  expect(hookOutputJson({ action: "none" })).toBeUndefined();
  const json = hookOutputJson({
    action: "switched",
    systemMessage: "switched a -> b",
    additionalContext: "session identity changed",
  });
  const parsed = JSON.parse(json!) as {
    systemMessage: string;
    hookSpecificOutput: { hookEventName: string; additionalContext: string };
  };
  expect(parsed.systemMessage).toBe("switched a -> b");
  expect(parsed.hookSpecificOutput.hookEventName).toBe("UserPromptSubmit");
  expect(parsed.hookSpecificOutput.additionalContext).toBe("session identity changed");
});
