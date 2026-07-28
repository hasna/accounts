import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountIdentity } from "./lib/identity-index.js";
import { parseUsageResponse, type AccountUsage } from "./lib/usage.js";
import { selectHealthiestAccount, thresholdBreached, type SelectionEntry } from "./lib/auto-switch.js";

/**
 * Two-window (5-hour session vs 7-day weekly) selection.
 *
 * Anthropic enforces two independent limits and they fail differently:
 *   - session exhausted, weekly healthy -> temporarily unavailable, self-heals
 *     within hours; the account MUST return to candidacy once the window rolls.
 *   - weekly exhausted -> unavailable for days; the account MUST NOT be
 *     re-selected until the weekly window resets, however good its 5h number is.
 *
 * A selector that collapses both into one "usage %" cannot tell these apart.
 * Every test below is paired with a POSITIVE CONTROL: an assertion that the
 * selector still returns something under a minimally different input, so that
 * "correctly excluded the dead account" can never be satisfied by a selector
 * that simply excludes everything.
 *
 * Window shapes are the ones measured live on 2026-07-28 across 8 real
 * accounts (`limits[]` entries carry kind + group + percent + resets_at).
 */

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-tws-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

const T0 = new Date("2026-07-28T12:00:00.000Z");
const minutes = (n: number) => n * 60_000;
const hours = (n: number) => n * 3_600_000;
const days = (n: number) => n * 86_400_000;
const at = (offsetMs: number) => new Date(T0.getTime() + offsetMs);
const iso = (offsetMs: number) => at(offsetMs).toISOString();

function identity(uuid: string, status: AccountIdentity["status"] = "ok"): AccountIdentity {
  return { accountUuid: uuid, email: `${uuid}@example.com`, doors: [], status };
}

interface WindowSpec {
  percent: number;
  resetsAt?: string;
}

/**
 * Build an AccountUsage in the exact live wire shape, through the real parser,
 * so these tests are pinned to the measured contract rather than to a
 * hand-rolled struct.
 */
function usage(
  spec: { session?: WindowSpec; weekly?: WindowSpec; weeklyScoped?: WindowSpec },
  fetchedAtMs = 0,
): AccountUsage {
  const limits: Record<string, unknown>[] = [];
  if (spec.session) {
    limits.push({
      kind: "session",
      group: "session",
      percent: spec.session.percent,
      severity: "normal",
      is_active: false,
      ...(spec.session.resetsAt ? { resets_at: spec.session.resetsAt } : {}),
    });
  }
  if (spec.weekly) {
    limits.push({
      kind: "weekly_all",
      group: "weekly",
      percent: spec.weekly.percent,
      severity: "normal",
      is_active: true,
      ...(spec.weekly.resetsAt ? { resets_at: spec.weekly.resetsAt } : {}),
    });
  }
  if (spec.weeklyScoped) {
    limits.push({
      kind: "weekly_scoped",
      group: "weekly",
      percent: spec.weeklyScoped.percent,
      severity: "normal",
      is_active: false,
      scope: { model: "claude-opus-4" },
      ...(spec.weeklyScoped.resetsAt ? { resets_at: spec.weeklyScoped.resetsAt } : {}),
    });
  }
  return parseUsageResponse({ limits }, at(fetchedAtMs));
}

function entry(
  uuid: string,
  spec: { session?: WindowSpec; weekly?: WindowSpec; weeklyScoped?: WindowSpec },
  fetchedAtMs = 0,
): SelectionEntry {
  return { identity: identity(uuid), usage: usage(spec, fetchedAtMs) };
}

function excludedReason(result: ReturnType<typeof selectHealthiestAccount>, uuid: string) {
  return result.excluded?.find((e) => e.accountUuid === uuid)?.reason;
}

// ---------------------------------------------------------------------------
// A. Weekly exhaustion is a hard exclusion — with a positive control proving
//    the selector has not simply stopped returning anything.
// ---------------------------------------------------------------------------

test("excludes a weekly-exhausted account AND still returns the healthy peer", () => {
  const result = selectHealthiestAccount(
    [
      entry("weekly-dead", {
        session: { percent: 0, resetsAt: iso(hours(4)) },
        weekly: { percent: 100, resetsAt: iso(days(5)) },
      }),
      entry("healthy", {
        session: { percent: 10, resetsAt: iso(hours(4)) },
        weekly: { percent: 20, resetsAt: iso(days(5)) },
      }),
    ],
    { currentUuid: "someone-else", now: T0 },
  );

  // POSITIVE CONTROL: a selector that excludes everything fails this line.
  expect(result.candidate?.accountUuid).toBe("healthy");
  // And the dead one was excluded for the RIGHT reason.
  expect(excludedReason(result, "weekly-dead")).toBe("weekly-exhausted");
});

test("control: the same account IS selected when only its weekly window differs", () => {
  // Identical to `weekly-dead` above except weekly percent. If this returns a
  // candidate, the exclusion above is attributable to the weekly window and not
  // to an unrelated filter (credential state, current-account, missing data).
  const result = selectHealthiestAccount(
    [
      entry("weekly-dead", {
        session: { percent: 0, resetsAt: iso(hours(4)) },
        weekly: { percent: 30, resetsAt: iso(days(5)) },
      }),
    ],
    { currentUuid: "someone-else", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("weekly-dead");
});

// ---------------------------------------------------------------------------
// B. THE DISCRIMINATION. Same elapsed time, two accounts, opposite outcomes.
//    This is the pair that a single-scalar "usage %" selector cannot pass.
// ---------------------------------------------------------------------------

test("5h-exhausted, weekly-healthy account returns to candidacy once its window rolls", () => {
  const sessionResets = iso(minutes(20));
  const entries = [
    entry("session-dead", {
      session: { percent: 100, resetsAt: sessionResets },
      weekly: { percent: 10, resetsAt: iso(days(5)) },
    }),
  ];

  // Before the roll: unavailable, but labelled as the RECOVERABLE kind and
  // carrying the time at which it becomes a candidate again.
  const before = selectHealthiestAccount(entries, { currentUuid: "other", now: T0 });
  expect(before.candidate).toBeUndefined();
  expect(excludedReason(before, "session-dead")).toBe("session-exhausted");
  expect(before.excluded?.[0]?.eligibleAt).toBe(sessionResets);

  // After the roll: candidate again, with no new usage fetch. The 5-hour window
  // reset by the clock; the cached reading is simply superseded.
  const after = selectHealthiestAccount(entries, { currentUuid: "other", now: at(minutes(21)) });
  expect(after.candidate?.accountUuid).toBe("session-dead");
});

test("weekly-exhausted account stays excluded across the SAME clock advance", () => {
  // POSITIVE CONTROL for the test above: the identical +21m advance that
  // rescued the session-exhausted account must NOT rescue a weekly-exhausted
  // one. If both recover, the selector is keying on elapsed time, not on which
  // window was hit. If neither recovers, the selector excludes everything.
  const entries = [
    entry("weekly-dead", {
      session: { percent: 0, resetsAt: iso(hours(4)) },
      weekly: { percent: 100, resetsAt: iso(days(5)) },
    }),
  ];

  const after = selectHealthiestAccount(entries, { currentUuid: "other", now: at(minutes(21)) });
  expect(after.candidate).toBeUndefined();
  expect(excludedReason(after, "weekly-dead")).toBe("weekly-exhausted");
  expect(after.excluded?.[0]?.eligibleAt).toBe(iso(days(5)));
});

test("the two exhaustion kinds are not collapsed: their recovery times differ by days", () => {
  const result = selectHealthiestAccount(
    [
      entry("session-dead", {
        session: { percent: 100, resetsAt: iso(minutes(20)) },
        weekly: { percent: 10, resetsAt: iso(days(5)) },
      }),
      entry("weekly-dead", {
        session: { percent: 0, resetsAt: iso(hours(4)) },
        weekly: { percent: 100, resetsAt: iso(days(5)) },
      }),
    ],
    { currentUuid: "other", now: T0 },
  );

  expect(result.candidate).toBeUndefined();
  const sessionEligible = Date.parse(
    result.excluded!.find((e) => e.accountUuid === "session-dead")!.eligibleAt!,
  );
  const weeklyEligible = Date.parse(
    result.excluded!.find((e) => e.accountUuid === "weekly-dead")!.eligibleAt!,
  );
  // A collapsed "usage %" selector gives these two the same score and the same
  // (absent) recovery time. They must differ, and by days.
  expect(weeklyEligible - sessionEligible).toBeGreaterThan(days(4));
});

test("a weekly-exhausted account is never preferred over a 5h-exhausted one on raw headroom", () => {
  // Both read 0 headroom under the collapsed model, so the old selector would
  // rank them by uuid. Once the session window rolls, only one is usable.
  const entries = [
    entry("aaa-weekly-dead", {
      session: { percent: 0, resetsAt: iso(hours(4)) },
      weekly: { percent: 100, resetsAt: iso(days(6)) },
    }),
    entry("zzz-session-dead", {
      session: { percent: 100, resetsAt: iso(minutes(30)) },
      weekly: { percent: 15, resetsAt: iso(days(6)) },
    }),
  ];
  const result = selectHealthiestAccount(entries, { currentUuid: "other", now: at(minutes(31)) });
  expect(result.candidate?.accountUuid).toBe("zzz-session-dead");
});

// ---------------------------------------------------------------------------
// C. Staleness: a cached reading whose window has since reset must not keep an
//    account excluded forever (the "forgets to come back" failure).
// ---------------------------------------------------------------------------

test("a cached weekly reading whose reset has passed no longer excludes the account", () => {
  // Fetched 6 days ago at 100% weekly, reset 1 hour ago. The number on disk is
  // stale, and the account is in fact fresh.
  const result = selectHealthiestAccount(
    [
      entry(
        "recovered",
        {
          session: { percent: 100, resetsAt: iso(-hours(2)) },
          weekly: { percent: 100, resetsAt: iso(-hours(1)) },
        },
        -days(6),
      ),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("recovered");
});

test("control: an equally stale reading whose reset is still in the future stays excluded", () => {
  // Same 6-day-old fetch, same 100% weekly — only resets_at differs. Proves the
  // rule above keys on the reset boundary and not merely on cache age.
  const result = selectHealthiestAccount(
    [
      entry(
        "still-dead",
        {
          session: { percent: 100, resetsAt: iso(-hours(2)) },
          weekly: { percent: 100, resetsAt: iso(days(1)) },
        },
        -days(6),
      ),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate).toBeUndefined();
  expect(excludedReason(result, "still-dead")).toBe("weekly-exhausted");
});

// ---------------------------------------------------------------------------
// D. Ranking: prefer a rolled-over 5h window; let the weekly window dominate.
// ---------------------------------------------------------------------------

test("prefers the account whose 5-hour window has already rolled over", () => {
  const result = selectHealthiestAccount(
    [
      entry("mid-session", {
        session: { percent: 50, resetsAt: iso(hours(2)) },
        weekly: { percent: 40, resetsAt: iso(days(3)) },
      }),
      entry(
        "rolled",
        {
          session: { percent: 95, resetsAt: iso(-minutes(5)) },
          weekly: { percent: 40, resetsAt: iso(days(3)) },
        },
        -hours(1),
      ),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("rolled");
});

test("control: weekly headroom outranks a rolled 5h window", () => {
  // Identical to the test above except the rolled account's weekly is worse.
  // Proves the 5h preference is a tie-break, not the dominant key — otherwise
  // we would burn down the scarce weekly budget first.
  const result = selectHealthiestAccount(
    [
      entry("mid-session", {
        session: { percent: 50, resetsAt: iso(hours(2)) },
        weekly: { percent: 40, resetsAt: iso(days(3)) },
      }),
      entry(
        "rolled",
        {
          session: { percent: 95, resetsAt: iso(-minutes(5)) },
          weekly: { percent: 70, resetsAt: iso(days(3)) },
        },
        -hours(1),
      ),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("mid-session");
});

test("a model-scoped weekly window never gates selection", () => {
  // weekly_scoped at 100% must not make an otherwise-healthy account ineligible:
  // a saturated Opus cap does not block work on other models.
  const result = selectHealthiestAccount(
    [
      entry("scoped-capped", {
        session: { percent: 5, resetsAt: iso(hours(4)) },
        weekly: { percent: 20, resetsAt: iso(days(3)) },
        weeklyScoped: { percent: 100, resetsAt: iso(days(3)) },
      }),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("scoped-capped");
});

// ---------------------------------------------------------------------------
// E. Graceful degradation — never a crash, never a partially-applied switch.
// ---------------------------------------------------------------------------

test("reports all-limited without throwing when every account is exhausted", () => {
  const run = () =>
    selectHealthiestAccount(
      [
        entry("a", { session: { percent: 100, resetsAt: iso(hours(1)) }, weekly: { percent: 100, resetsAt: iso(days(2)) } }),
        entry("b", { session: { percent: 100, resetsAt: iso(hours(2)) }, weekly: { percent: 100, resetsAt: iso(days(3)) } }),
      ],
      { currentUuid: "other", now: T0 },
    );
  expect(run).not.toThrow();
  const result = run();
  expect(result.candidate).toBeUndefined();
  expect(result.reason).toBe("all-limited");
  expect(result.excluded).toHaveLength(2);
});

// ---------------------------------------------------------------------------
// F. The trigger side. A breach read off a window that has since rolled would
//    switch the session away from a perfectly healthy account.
// ---------------------------------------------------------------------------

test("no breach is reported for a window that has already rolled over", () => {
  // Read an hour ago at 95% of the 5-hour window, which reset 5 minutes ago.
  // The account is fine; acting on the stale number is a spurious switch, and
  // spurious switches are how a switch storm starts.
  const stale = usage(
    {
      session: { percent: 95, resetsAt: iso(-minutes(5)) },
      weekly: { percent: 20, resetsAt: iso(days(3)) },
    },
    -hours(1),
  );
  expect(thresholdBreached(stale, 90, T0).breached).toBe(false);

  // POSITIVE CONTROL: the identical reading evaluated BEFORE the roll does
  // breach — so the false above is the roll being honoured, not a threshold
  // check that never fires.
  const beforeRoll = thresholdBreached(stale, 90, at(-minutes(10)));
  expect(beforeRoll.breached).toBe(true);
  expect(beforeRoll.window?.id).toBe("session");
});

test("a rolled window does not mask a genuine breach on the other axis", () => {
  const mixed = usage(
    {
      session: { percent: 99, resetsAt: iso(-minutes(5)) },
      weekly: { percent: 94, resetsAt: iso(days(3)) },
    },
    -hours(1),
  );
  const result = thresholdBreached(mixed, 90, T0);
  expect(result.breached).toBe(true);
  expect(result.window?.id).toBe("weekly_all");
});

// ---------------------------------------------------------------------------
// G. Ranking must not hand back an account that cannot serve the next hour.
// ---------------------------------------------------------------------------

test("prefers usable-now runway over a better weekly with almost none", () => {
  // A has the far better week but only 15% of its 5-hour window left: it
  // re-breaches within the hour and the global cooldown then blocks the
  // follow-up switch, stranding the session. B is the survivable choice.
  const result = selectHealthiestAccount(
    [
      entry("a-great-week-thin-session", {
        session: { percent: 85, resetsAt: iso(hours(3)) },
        weekly: { percent: 10, resetsAt: iso(days(4)) },
      }),
      entry("b-ok-week-full-session", {
        session: { percent: 0, resetsAt: iso(hours(5)) },
        weekly: { percent: 74, resetsAt: iso(days(4)) },
      }),
    ],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("b-ok-week-full-session");
});

test("an account with no window data at all is usable rather than fatal", () => {
  // The API omits a window when it is not constraining. Absent must read as
  // "no constraint reported", not as "exhausted".
  const result = selectHealthiestAccount(
    [entry("sparse", { weekly: { percent: 10, resetsAt: iso(days(3)) } })],
    { currentUuid: "other", now: T0 },
  );
  expect(result.candidate?.accountUuid).toBe("sparse");
});
