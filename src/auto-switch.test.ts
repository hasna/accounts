import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountCredentialRef, AccountIdentity } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import {
  autoSwitchStatePath,
  cooldownActive,
  readAutoSwitchState,
  readHookNoticeState,
  readUsageCache,
  selectHealthiestAccount,
  thresholdBreached,
  writeAutoSwitchState,
  writeHookNoticeState,
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

/**
 * `status` is DERIVED from the credential in the real index, so a fixture that
 * sets one without the other describes a state that cannot occur. Renewability
 * is an explicit parameter because it is exactly what separates an account that
 * merely needs a token refresh from one that is genuinely dead.
 */
function credentialFor(
  status: AccountIdentity["status"],
  renewable: boolean,
): AccountCredentialRef | undefined {
  if (status === "no-credentials") return undefined;
  const valid = status === "ok";
  return {
    path: "/fake/credentials.json",
    source: "central",
    expiresAt: Date.now() + (valid ? 60_000 : -60_000),
    hasAccessToken: true,
    hasRefreshToken: valid || renewable,
    valid,
    renewable: valid || renewable,
  };
}

function identity(
  uuid: string,
  email: string,
  status: AccountIdentity["status"] = "ok",
  renewable = false,
): AccountIdentity {
  const credential = credentialFor(status, renewable);
  return { accountUuid: uuid, email, doors: [], ...(credential ? { credential } : {}), status };
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

// --- 63e642c1: `expired` means aged-out, not unusable ------------------------
//
// Both arms are asserted deliberately. A test that only proved the renewable
// case is accepted would ship a hole: it could not tell the fix from "stop
// checking expiry at all", which would hand sessions genuinely dead accounts.

test("selector excludes credential-less accounts and credentials with NO refresh token", () => {
  const picked = selectHealthiestAccount(
    [
      // Expired AND no refresh token: genuinely dead, however much headroom.
      { identity: identity("uuid-exp", "exp@x.com", "expired", false), usage: usage(100) },
      { identity: identity("uuid-nc", "nc@x.com", "no-credentials") },
      { identity: identity("uuid-ok", "ok@x.com"), usage: usage(40) },
    ],
    { currentUuid: "uuid-other" },
  );
  expect(picked.candidate?.accountUuid).toBe("uuid-ok");
  expect(picked.excluded.find((e) => e.accountUuid === "uuid-exp")?.reason).toBe("credential");
});

test("an aged-out access token WITH a refresh token is still a candidate", () => {
  // The measured state of an idle fleet: access tokens live 8 hours, so most
  // profiles read `expired` overnight while holding a refresh token good for
  // weeks. Excluding them empties the pool exactly when unattended sessions
  // depend on it.
  const picked = selectHealthiestAccount(
    [{ identity: identity("uuid-renewable", "r@x.com", "expired", true), usage: usage(90) }],
    { currentUuid: "uuid-other" },
  );
  expect(picked.candidate?.accountUuid).toBe("uuid-renewable");
  expect(picked.reason).toBeUndefined();
});

test("a valid credential outranks a renewable one even with far less headroom", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-renewable", "r@x.com", "expired", true), usage: usage(95) },
      { identity: identity("uuid-valid", "v@x.com"), usage: usage(40) },
    ],
    { currentUuid: "uuid-other" },
  );
  expect(picked.candidate?.accountUuid).toBe("uuid-valid");
  expect(picked.ranked.map((c) => c.accountUuid)).toEqual(["uuid-valid", "uuid-renewable"]);
});

test("the selector returns the whole ranking, not only the winner", () => {
  const picked = selectHealthiestAccount(
    [
      { identity: identity("uuid-a", "a@x.com"), usage: usage(90) },
      { identity: identity("uuid-b", "b@x.com"), usage: usage(70) },
      { identity: identity("uuid-c", "c@x.com"), usage: usage(50) },
    ],
    { currentUuid: "uuid-other" },
  );
  expect(picked.ranked.map((c) => c.accountUuid)).toEqual(["uuid-a", "uuid-b", "uuid-c"]);
  expect(picked.candidate).toBe(picked.ranked[0]!);
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
  const dir = "/home/someone/.claude";
  writeAutoSwitchState({ lastSwitchAt: now.toISOString(), fromUuid: "a", toUuid: "b" }, dir);
  const state = readAutoSwitchState(dir);
  expect(state?.toUuid).toBe("b");
  expect(cooldownActive(state, 600_000, now)).toBe(true);
  expect(cooldownActive(state, 600_000, new Date(now.getTime() + 601_000))).toBe(false);
  expect(cooldownActive(undefined, 600_000, now)).toBe(false);
});

test("one session's cooldown does not block a different session's config dir", () => {
  // ccc23767: a single machine-wide state file meant a session at 96%
  // utilization was refused because an UNRELATED session had switched three
  // minutes earlier. With ~18 live sessions that capped the fleet at one switch
  // per ten minutes.
  const now = new Date();
  const mine = "/home/someone/.hasna/accounts/profiles/claude/account003";
  const theirs = "/home/someone/.hasna/accounts/profiles/claude/account004";

  writeAutoSwitchState({ lastSwitchAt: now.toISOString(), fromUuid: "a", toUuid: "b" }, theirs);

  expect(cooldownActive(readAutoSwitchState(theirs), 600_000, now)).toBe(true);
  expect(readAutoSwitchState(mine)).toBeUndefined();
  expect(cooldownActive(readAutoSwitchState(mine), 600_000, now)).toBe(false);
  // Distinct dirs must land in distinct files, and the record must name its dir.
  expect(autoSwitchStatePath(mine)).not.toBe(autoSwitchStatePath(theirs));
  expect(readAutoSwitchState(theirs)?.configDir).toBe(theirs);
});

test("the state path is stable per dir and insensitive to trailing separators", () => {
  const dir = "/home/someone/.claude";
  expect(autoSwitchStatePath(dir)).toBe(autoSwitchStatePath(`${dir}/`));
  expect(autoSwitchStatePath(dir)).toBe(autoSwitchStatePath(`${dir}/../.claude`));
  // The filename must never carry the dir's own characters.
  expect(autoSwitchStatePath(dir)).toMatch(/\/[0-9a-f]{32}\.json$/);
});

test("hook notice state round-trips and survives a corrupt file", () => {
  expect(readHookNoticeState()).toBeUndefined();
  writeHookNoticeState({ "no-usage": "2026-07-28T12:00:00.000Z", bogus: "x" });
  expect(readHookNoticeState()?.["no-usage"]).toBe("2026-07-28T12:00:00.000Z");
});
