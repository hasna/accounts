import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import {
  activeCooldowns,
  backoffMs,
  clearExhaustion,
  exhaustionLedgerPath,
  readExhaustionLedger,
  recordExhaustion,
  DEFAULT_BACKOFF_BASE_MS,
  SESSION_BACKOFF_CAP_MS,
  WEEKLY_BACKOFF_CAP_MS,
} from "./lib/exhaustion-ledger.js";
import { selectHealthiestAccount, type SelectionEntry } from "./lib/auto-switch.js";
import { parseUsageResponse } from "./lib/usage.js";
import type { AccountIdentity } from "./lib/identity-index.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-ledger-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

const T0 = new Date("2026-07-28T12:00:00.000Z");
const at = (ms: number) => new Date(T0.getTime() + ms);
const minutes = (n: number) => n * 60_000;
const hours = (n: number) => n * 3_600_000;
const days = (n: number) => n * 86_400_000;

function healthyEntry(uuid: string): SelectionEntry {
  const identity: AccountIdentity = {
    accountUuid: uuid,
    email: `${uuid}@example.com`,
    doors: [],
    status: "ok",
  };
  return {
    identity,
    usage: parseUsageResponse(
      {
        limits: [
          { kind: "session", group: "session", percent: 5, resets_at: at(hours(4)).toISOString() },
          { kind: "weekly_all", group: "weekly", percent: 10, resets_at: at(days(5)).toISOString() },
        ],
      },
      T0,
    ),
  };
}

// ---------------------------------------------------------------------------
// Durability across process restarts.
// ---------------------------------------------------------------------------

test("an exhaustion record survives a process restart", () => {
  recordExhaustion({
    accountUuid: "acct-dead",
    windowClass: "weekly",
    resetsAt: at(days(5)).toISOString(),
    now: T0,
  });

  // Simulate a restart: nothing in memory, read the store back off disk.
  const reloaded = readExhaustionLedger();
  expect(reloaded["acct-dead"]?.windowClass).toBe("weekly");
  expect(reloaded["acct-dead"]?.releaseAt).toBe(at(days(5)).toISOString());
  expect(activeCooldowns(reloaded, at(hours(1))).has("acct-dead")).toBe(true);
});

test("a restarted selector still refuses the account it fled, then takes it back after release", () => {
  recordExhaustion({
    accountUuid: "acct-dead",
    windowClass: "session",
    resetsAt: at(minutes(45)).toISOString(),
    now: T0,
  });
  const entries = [healthyEntry("acct-dead")];

  // The cache says healthy (a stale or refreshed reading); the ledger is the
  // reason we do not go back. Without durable state this is the loop that puts
  // a restarted session straight back onto a dead account.
  const during = selectHealthiestAccount(entries, {
    currentUuid: "other",
    now: at(minutes(10)),
    cooldowns: activeCooldowns(readExhaustionLedger(), at(minutes(10))),
  });
  expect(during.candidate).toBeUndefined();
  expect(during.excluded[0]?.reason).toBe("cooldown");
  expect(during.excluded[0]?.eligibleAt).toBe(at(minutes(45)).toISOString());

  // POSITIVE CONTROL: same entries, same ledger, clock past the release. If
  // this does not return the account, the cooldown is a permanent blocklist
  // rather than a cooldown, and the pool drains to nothing over time.
  const after = selectHealthiestAccount(entries, {
    currentUuid: "other",
    now: at(minutes(46)),
    cooldowns: activeCooldowns(readExhaustionLedger(), at(minutes(46))),
  });
  expect(after.candidate?.accountUuid).toBe("acct-dead");
});

// ---------------------------------------------------------------------------
// Backoff is bounded — a switch storm must not be possible, and a data problem
// must not permanently drain the pool.
// ---------------------------------------------------------------------------

test("repeated exhaustion escalates the cooldown instead of retrying immediately", () => {
  const first = recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  expect(Date.parse(first.releaseAt) - T0.getTime()).toBe(DEFAULT_BACKOFF_BASE_MS);
  expect(first.consecutive).toBe(1);

  // Re-exhausted right after release -> same episode, doubled.
  const secondAt = at(DEFAULT_BACKOFF_BASE_MS + minutes(1));
  const second = recordExhaustion({ accountUuid: "acct", windowClass: "session", now: secondAt });
  expect(second.consecutive).toBe(2);
  expect(Date.parse(second.releaseAt) - secondAt.getTime()).toBe(DEFAULT_BACKOFF_BASE_MS * 2);
});

test("backoff is capped, so a misread window can never retire an account forever", () => {
  expect(backoffMs("session", 50)).toBe(SESSION_BACKOFF_CAP_MS);
  expect(backoffMs("weekly", 50)).toBe(WEEKLY_BACKOFF_CAP_MS);
  expect(backoffMs("unknown", 50)).toBe(SESSION_BACKOFF_CAP_MS);
  // Bounded means bounded: never longer than a day without a reported reset.
  expect(backoffMs("weekly", 999)).toBeLessThanOrEqual(days(1));
});

test("a long healthy stretch restarts the backoff rather than escalating", () => {
  recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  const later = at(hours(6));
  const fresh = recordExhaustion({ accountUuid: "acct", windowClass: "session", now: later });
  expect(fresh.consecutive).toBe(1);
  expect(Date.parse(fresh.releaseAt) - later.getTime()).toBe(DEFAULT_BACKOFF_BASE_MS);
});

test("a reported reset always wins when it is the longer wait", () => {
  // Weekly reset 5 days out must not be shortened to the 15-minute backoff.
  const record = recordExhaustion({
    accountUuid: "acct",
    windowClass: "weekly",
    resetsAt: at(days(5)).toISOString(),
    now: T0,
  });
  expect(record.releaseAt).toBe(at(days(5)).toISOString());
});

test("an already-past reset still yields a bounded cooldown, not an instant retry", () => {
  const record = recordExhaustion({
    accountUuid: "acct",
    windowClass: "session",
    resetsAt: at(-hours(1)).toISOString(),
    now: T0,
  });
  expect(Date.parse(record.releaseAt)).toBe(T0.getTime() + DEFAULT_BACKOFF_BASE_MS);
});

// ---------------------------------------------------------------------------
// Degradation: a broken ledger must never crash the hook or block a prompt.
// ---------------------------------------------------------------------------

test("a corrupt ledger reads as no cooldowns instead of throwing", () => {
  mkdirSync(join(home, "state"), { recursive: true });
  writeFileSync(exhaustionLedgerPath(), "{ not json at all");
  expect(() => readExhaustionLedger()).not.toThrow();
  expect(readExhaustionLedger()).toEqual({});

  // POSITIVE CONTROL: a well-formed ledger written to the same path IS read,
  // so the empty result above reflects the corruption and not a broken reader.
  recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  expect(Object.keys(readExhaustionLedger())).toEqual(["acct"]);
});

test("path-hostile uuids are never persisted as ledger keys", () => {
  const record = recordExhaustion({ accountUuid: "../escape", windowClass: "session", now: T0 });
  expect(record.releaseAt).toBe(T0.toISOString()); // inert, no cooldown
  expect(readExhaustionLedger()["../escape"]).toBeUndefined();
});

test("entries with a garbage shape are dropped, the rest survive", () => {
  recordExhaustion({ accountUuid: "good", windowClass: "session", now: T0 });
  const raw = JSON.parse(readFileSync(exhaustionLedgerPath(), "utf8"));
  raw["bad"] = { accountUuid: "bad", observedAt: "not-a-date", releaseAt: "also-not" };
  writeFileSync(exhaustionLedgerPath(), JSON.stringify(raw));

  const ledger = readExhaustionLedger();
  expect(ledger["bad"]).toBeUndefined();
  expect(ledger["good"]).toBeDefined();
});

test("clearing an account removes its cooldown", () => {
  recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  expect(activeCooldowns(readExhaustionLedger(), T0).has("acct")).toBe(true);
  clearExhaustion("acct");
  expect(activeCooldowns(readExhaustionLedger(), T0).has("acct")).toBe(false);
  expect(() => clearExhaustion("never-recorded")).not.toThrow();
});

test("the ledger lives in durable state, never under cache/", () => {
  // Holds on naming grounds alone: a store whose only job is surviving restarts
  // cannot sit in a directory named `cache`, which licenses deletion. (A live
  // observation motivated the check — cache/auto-switch-state.json is absent
  // despite two switches 60s apart under a 10-minute cooldown — but the cause
  // is not established, so the test rests on the naming argument, not on it.)
  recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  const path = exhaustionLedgerPath();
  expect(path.includes(`${sep}cache${sep}`)).toBe(false);
  expect(path.endsWith(join("state", "exhaustion-ledger.json"))).toBe(true);

  // POSITIVE CONTROL: the record really is retrievable from that path, so the
  // assertions above are about a live store and not a path that nothing uses.
  expect(readExhaustionLedger()["acct"]).toBeDefined();
});

test("the ledger file is written owner-only", () => {
  recordExhaustion({ accountUuid: "acct", windowClass: "session", now: T0 });
  const { statSync } = require("node:fs") as typeof import("node:fs");
  expect(statSync(exhaustionLedgerPath()).mode & 0o777).toBe(0o600);
});

test("an unpersistable ledger degrades to no-cooldown instead of throwing", () => {
  // A ledger that cannot be written must not become a gate: the right outcome
  // is a switch that forgets its cooldown, never a hook that fails open and
  // strands the session on an exhausted account.
  rmSync(join(home, "state"), { recursive: true, force: true });
  writeFileSync(join(home, "state"), "not a directory");

  expect(() =>
    recordExhaustion({ accountUuid: "acct", windowClass: "weekly", now: T0 }),
  ).not.toThrow();
  expect(() => readExhaustionLedger()).not.toThrow();
  expect(activeCooldowns(readExhaustionLedger(), T0).size).toBe(0);

  // POSITIVE CONTROL: with the obstruction removed the very same call DOES
  // persist, so the no-op above is the failure being absorbed and not
  // recordExhaustion being inert.
  rmSync(join(home, "state"), { force: true });
  recordExhaustion({ accountUuid: "acct", windowClass: "weekly", now: T0 });
  expect(activeCooldowns(readExhaustionLedger(), T0).has("acct")).toBe(true);
});
