import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountCredentialRef, AccountIdentity } from "./lib/identity-index.js";
import type { AccountUsage } from "./lib/usage.js";
import {
  readRecentTargetClaims,
  selectHealthiestAccount,
  writeAutoSwitchState,
} from "./lib/auto-switch.js";

/**
 * A3-00458 — THUNDERING HERD.
 *
 * MEASURED on station01 2026-08-07: twelve config dirs switched to the SAME
 * replacement account inside 25.2 seconds (21:12:11.033 -> 21:12:36.188,
 * `cache/auto-switch/*.json`), and that target read `session=100` — fully
 * exhausted — 25 minutes later, with one dir already fleeing it again by
 * 21:30:43. Seven such clusters occurred in 42 hours; the largest was 13
 * distinct dirs.
 *
 * The mechanism is that every dir ranks from the SAME usage cache and nothing
 * records that a target was just claimed. The two cooldowns that exist cannot
 * damp it:
 *   - the anti-flap state is keyed per config dir, so N dirs hold N independent
 *     cooldowns (deliberate — ccc23767, see auto-switch.test.ts);
 *   - the exhaustion ledger is keyed on the account a session LEAVES, and only
 *     at DEFAULT_EXHAUSTION_PERCENT=100, while switches fire at
 *     DEFAULT_SWITCH_THRESHOLD=90.
 *
 * The fix must SPREAD without ever WITHHOLDING: PR #87 removed the `contended`
 * exclusion on an owner directive precisely because refusing shared accounts
 * withheld every healthy account at once. So these tests assert both halves —
 * the herd spreads when there is somewhere to spread to, and the herd is still
 * allowed when there is not.
 */

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-herd-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

function credentialFor(status: AccountIdentity["status"]): AccountCredentialRef | undefined {
  if (status === "no-credentials") return undefined;
  const valid = status === "ok";
  return {
    path: "/fake/credentials.json",
    source: "central",
    expiresAt: Date.now() + (valid ? 60_000 : -60_000),
    hasAccessToken: true,
    hasRefreshToken: true,
    valid,
    renewable: true,
  };
}

function identity(uuid: string, email: string): AccountIdentity {
  const credential = credentialFor("ok");
  return { accountUuid: uuid, email, doors: [], ...(credential ? { credential } : {}), status: "ok" };
}

/** Two unscoped windows, so both selector gates are exercised explicitly. */
function usage(sessionHeadroom: number, weeklyHeadroom: number): AccountUsage {
  return {
    windows: [
      { id: "session", utilization: 100 - sessionHeadroom, scoped: false },
      { id: "weekly_all", utilization: 100 - weeklyHeadroom, scoped: false },
    ],
    headroom: Math.min(sessionHeadroom, weeklyHeadroom),
    bindingWindow: "session",
    fetchedAt: new Date().toISOString(),
  };
}

const dirFor = (n: number) => `/home/someone/.hasna/accounts/profiles/claude/account${n}`;

// ---------------------------------------------------------------------------
// The claim reader itself, with both directions asserted.
// ---------------------------------------------------------------------------

test("readRecentTargetClaims counts targets other dirs just switched to, and ages them out", () => {
  const now = new Date();
  const old = new Date(now.getTime() - 10 * 60_000);

  writeAutoSwitchState(
    { lastSwitchAt: now.toISOString(), fromUuid: "src", toUuid: "target", outcome: "switched" },
    dirFor(1),
  );
  writeAutoSwitchState(
    { lastSwitchAt: now.toISOString(), fromUuid: "src", toUuid: "target", outcome: "switched" },
    dirFor(2),
  );
  writeAutoSwitchState(
    { lastSwitchAt: old.toISOString(), fromUuid: "src", toUuid: "stale-target", outcome: "switched" },
    dirFor(3),
  );

  const claims = readRecentTargetClaims(120_000, now);
  // POSITIVE: the two fresh claims are seen and counted.
  expect(claims.get("target")).toBe(2);
  // NEGATIVE: a claim outside the window is not seen at all. Without this the
  // reader could "pass" by simply returning every record it can find.
  expect(claims.has("stale-target")).toBe(false);

  // The caller's own dir is not a claim against itself: its own repeat switch is
  // what the per-dir anti-flap cooldown already governs.
  const excludingSelf = readRecentTargetClaims(120_000, now, dirFor(1));
  expect(excludingSelf.get("target")).toBe(1);
});

// ---------------------------------------------------------------------------
// The herd itself.
// ---------------------------------------------------------------------------

test("a just-claimed target is demoted so simultaneous breachers SPREAD across accounts", () => {
  // Three adequate targets. `best` leads on headroom, so every dir ranking from
  // the same cache picks it — this is the shipped behaviour and the defect.
  const entries = [
    { identity: identity("best", "best@x.com"), usage: usage(90, 90) },
    { identity: identity("second", "second@x.com"), usage: usage(80, 80) },
    { identity: identity("third", "third@x.com"), usage: usage(70, 70) },
  ];

  const now = new Date();

  // Dir 1 breaches first and correctly takes the healthiest account.
  const first = selectHealthiestAccount(entries, {
    currentUuid: "exhausted",
    now,
    recentClaims: readRecentTargetClaims(120_000, now, dirFor(1)),
  });
  expect(first.candidate?.accountUuid).toBe("best");
  writeAutoSwitchState(
    {
      lastSwitchAt: now.toISOString(),
      fromUuid: "exhausted",
      toUuid: first.candidate!.accountUuid,
      outcome: "switched",
    },
    dirFor(1),
  );

  // Dir 2 breaches four seconds later, reading the SAME usage cache — the exact
  // condition measured on station01. It must not pile onto `best`.
  const later = new Date(now.getTime() + 4_000);
  const second = selectHealthiestAccount(entries, {
    currentUuid: "exhausted",
    now: later,
    recentClaims: readRecentTargetClaims(120_000, later, dirFor(2)),
  });
  expect(second.candidate?.accountUuid).toBe("second");
  writeAutoSwitchState(
    {
      lastSwitchAt: later.toISOString(),
      fromUuid: "exhausted",
      toUuid: second.candidate!.accountUuid,
      outcome: "switched",
    },
    dirFor(2),
  );

  // Dir 3, four seconds later again.
  const later2 = new Date(now.getTime() + 8_000);
  const third = selectHealthiestAccount(entries, {
    currentUuid: "exhausted",
    now: later2,
    recentClaims: readRecentTargetClaims(120_000, later2, dirFor(3)),
  });
  expect(third.candidate?.accountUuid).toBe("third");

  // The claimed accounts stay IN the ranking — demoted, never excluded. This is
  // the property that keeps the fix from becoming `contended` again.
  expect(third.ranked.map((c) => c.accountUuid).sort()).toEqual(["best", "second", "third"]);
  expect(third.excluded.some((e) => e.reason === "cooldown")).toBe(false);
});

test("THE FIX MUST NOT WITHHOLD: the last healthy account is still selected when every candidate is claimed", () => {
  // PR #87 (owner directive: "i should be able to resume a profile in any
  // session what so ever even if its used somewhere else") deleted the
  // `contended` exclusion because withholding shared accounts stranded sessions
  // on exhausted ones — "8 accounts are already being run by another session and
  // cannot be shared". A damper that excluded rather than demoted would
  // reintroduce exactly that, time-boxed. It must not.
  const entries = [{ identity: identity("only", "only@x.com"), usage: usage(90, 90) }];
  const now = new Date();

  for (let i = 1; i <= 12; i += 1) {
    writeAutoSwitchState(
      { lastSwitchAt: now.toISOString(), fromUuid: "exhausted", toUuid: "only", outcome: "switched" },
      dirFor(100 + i),
    );
  }

  const claims = readRecentTargetClaims(120_000, now);
  expect(claims.get("only")).toBe(12);

  const picked = selectHealthiestAccount(entries, {
    currentUuid: "exhausted",
    now,
    recentClaims: claims,
  });
  // Twelve dirs already there and it is STILL the answer, because it is the only
  // one. A herd onto the single healthy account is correct behaviour.
  expect(picked.candidate?.accountUuid).toBe("only");
  expect(picked.reason).toBeUndefined();
});

test("a claimed account still outranks one that fails the headroom gates", () => {
  // Spreading happens only among candidates that already cleared the bar.
  // Demotion must never promote an inadequate account over an adequate one.
  const entries = [
    { identity: identity("claimed-good", "cg@x.com"), usage: usage(90, 90) },
    // weekly headroom 5 < DEFAULT_MIN_HEADROOM (25): not a candidate at all.
    { identity: identity("unclaimed-poor", "up@x.com"), usage: usage(90, 5) },
  ];
  const now = new Date();
  writeAutoSwitchState(
    { lastSwitchAt: now.toISOString(), fromUuid: "x", toUuid: "claimed-good", outcome: "switched" },
    dirFor(200),
  );

  const picked = selectHealthiestAccount(entries, {
    currentUuid: "exhausted",
    now,
    recentClaims: readRecentTargetClaims(120_000, now),
  });
  expect(picked.candidate?.accountUuid).toBe("claimed-good");
  expect(picked.excluded.find((e) => e.accountUuid === "unclaimed-poor")?.reason).toBe(
    "insufficient-headroom",
  );
});

test("no claim data at all leaves ranking exactly as it was", () => {
  // The damper is opt-in. A caller that passes nothing must get the shipped
  // ordering, or this change would alter every other selection path.
  const entries = [
    { identity: identity("best", "best@x.com"), usage: usage(90, 90) },
    { identity: identity("second", "second@x.com"), usage: usage(80, 80) },
  ];
  const picked = selectHealthiestAccount(entries, { currentUuid: "exhausted" });
  expect(picked.ranked.map((c) => c.accountUuid)).toEqual(["best", "second"]);
});
