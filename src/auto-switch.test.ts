import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountIdentity } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import {
  cooldownActive,
  readAutoSwitchState,
  readUsageCache,
  selectHealthiestAccount,
  thresholdBreached,
  writeAutoSwitchState,
  writeUsageCache,
  type UsageCacheEntry,
} from "./lib/auto-switch.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-asw-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

function identity(uuid: string, email: string, status: AccountIdentity["status"] = "ok"): AccountIdentity {
  return { accountUuid: uuid, email, doors: [], status };
}

function usage(headroom: number, opts: { binding?: string; resetsAt?: string } = {}): AccountUsage {
  const utilization = 100 - headroom;
  return {
    windows: [
      {
        id: opts.binding ?? "weekly_all",
        utilization,
        scoped: false,
        ...(opts.resetsAt ? { resetsAt: opts.resetsAt } : {}),
      },
    ],
    headroom,
    bindingWindow: opts.binding ?? "weekly_all",
    fetchedAt: new Date().toISOString(),
  };
}

test("selector returns the account with the most headroom, never the current one", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-current", "cur@x.com"), usage: usage(95) },
      { identity: identity("uuid-mid", "mid@x.com"), usage: usage(60) },
      { identity: identity("uuid-best", "best@x.com"), usage: usage(90) },
    ],
    { currentUuid: "uuid-current" },
  );
  expect(picked.candidate?.accountUuid).toBe("uuid-best");
});

test("selector excludes expired and credential-less accounts", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-exp", "exp@x.com", "expired"), usage: usage(100) },
      { identity: identity("uuid-nc", "nc@x.com", "no-credentials") },
      { identity: identity("uuid-ok", "ok@x.com"), usage: usage(40) },
    ],
    { currentUuid: "uuid-other" },
  );
  expect(picked.candidate?.accountUuid).toBe("uuid-ok");
});

test("selector reports all-limited honestly instead of flapping to an exhausted account", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-a", "a@x.com"), usage: usage(0) },
      { identity: identity("uuid-b", "b@x.com"), usage: usage(5) },
    ],
    { currentUuid: "uuid-a", minHeadroom: 25 },
  );
  expect(picked.candidate).toBeUndefined();
  expect(picked.reason).toBe("all-limited");
});

test("selector reports no-usage-data when nothing eligible has been measured", () => {
  const picked = selectHealthiestAccount(
    [{ identity: identity("uuid-a", "a@x.com") }],
    { currentUuid: "uuid-b" },
  );
  expect(picked.candidate).toBeUndefined();
  expect(picked.reason).toBe("no-usage-data");
});

test("selector is deterministic on headroom ties (lowest uuid wins)", () => {
  const entries = [
    { identity: identity("uuid-zzz", "z@x.com"), usage: usage(80) },
    { identity: identity("uuid-aaa", "a@x.com"), usage: usage(80) },
  ];
  const first = selectHealthiestAccount(entries, {});
  const second = selectHealthiestAccount([...entries].reverse(), {});
  expect(first.candidate?.accountUuid).toBe("uuid-aaa");
  expect(second.candidate?.accountUuid).toBe("uuid-aaa");
});

test("the current account alone is never a candidate, even with full headroom", () => {
  const picked = selectHealthiestAccount(
    [{ identity: identity("uuid-current", "cur@x.com"), usage: usage(100) }],
    { currentUuid: "uuid-current" },
  );
  expect(picked.candidate).toBeUndefined();
});

test("thresholdBreached fires on any unscoped window at/over the threshold", () => {
  const breached = thresholdBreached(
    {
      windows: [
        { id: "session", utilization: 10, scoped: false },
        { id: "weekly_all", utilization: 92, scoped: false },
        { id: "weekly_scoped", utilization: 99, scoped: true },
      ],
      headroom: 8,
      bindingWindow: "weekly_all",
      fetchedAt: new Date().toISOString(),
    },
    90,
  );
  expect(breached.breached).toBe(true);
  expect(breached.window?.id).toBe("weekly_all");

  const scopedOnly = thresholdBreached(
    {
      windows: [
        { id: "session", utilization: 10, scoped: false },
        { id: "weekly_scoped", utilization: 99, scoped: true },
      ],
      headroom: 90,
      bindingWindow: "session",
      fetchedAt: new Date().toISOString(),
    },
    90,
  );
  expect(scopedOnly.breached).toBe(false);
});

test("usage cache round-trips per account uuid and expires by max age", () => {
  const entry: UsageCacheEntry = {
    accountUuid: "uuid-cache",
    usage: usage(55),
    fetchedAt: new Date().toISOString(),
  };
  writeUsageCache(entry);
  expect(readUsageCache("uuid-cache", 60_000)?.usage?.headroom).toBe(55);
  expect(readUsageCache("uuid-cache", 60_000, new Date(Date.now() + 120_000))).toBeUndefined();
  expect(readUsageCache("uuid-unknown", 60_000)).toBeUndefined();
});

test("usage cache refuses path-hostile account uuids", () => {
  expect(() =>
    writeUsageCache({ accountUuid: "../escape", fetchedAt: new Date().toISOString() }),
  ).toThrow();
  expect(readUsageCache("../escape", 60_000)).toBeUndefined();
});

test("auto-switch cooldown blocks re-switching until the window passes", () => {
  const now = new Date();
  writeAutoSwitchState({ lastSwitchAt: now.toISOString(), fromUuid: "a", toUuid: "b" });
  const state = readAutoSwitchState();
  expect(state?.toUuid).toBe("b");
  expect(cooldownActive(state, 600_000, now)).toBe(true);
  expect(cooldownActive(state, 600_000, new Date(now.getTime() + 601_000))).toBe(false);
  expect(cooldownActive(undefined, 600_000, now)).toBe(false);
});
