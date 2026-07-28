import { test, expect } from "bun:test";
import {
  classifyUsageWindow,
  deriveWindowHealth,
  SESSION_WINDOW_MAX_MS,
} from "./lib/usage-windows.js";
import { parseUsageResponse } from "./lib/usage.js";
import type { UsageWindow } from "./lib/usage.js";

const NOW = new Date("2026-07-28T12:00:00.000Z");
const at = (ms: number) => new Date(NOW.getTime() + ms).toISOString();
const hours = (n: number) => n * 3_600_000;
const days = (n: number) => n * 86_400_000;
const minutes = (n: number) => n * 60_000;

function window(partial: Partial<UsageWindow> & { id: string }): UsageWindow {
  return { utilization: 0, scoped: false, ...partial };
}

// ---------------------------------------------------------------------------
// Classification. `group` is DATA on the happy path — measured live across 8
// accounts on 2026-07-28. Everything else is a documented fallback.
// ---------------------------------------------------------------------------

test("classifies the live wire shape from `group`, with nothing inferred", () => {
  const session = classifyUsageWindow(window({ id: "session", group: "session" }), NOW);
  expect(session).toEqual({ windowClass: "session", classSource: "group", inferred: false });

  const weekly = classifyUsageWindow(window({ id: "weekly_all", group: "weekly" }), NOW);
  expect(weekly).toEqual({ windowClass: "weekly", classSource: "group", inferred: false });

  const scoped = classifyUsageWindow(
    window({ id: "weekly_scoped", group: "weekly", scoped: true }),
    NOW,
  );
  expect(scoped).toEqual({ windowClass: "scoped", classSource: "scope", inferred: false });
});

test("falls back to the window id when `group` is absent", () => {
  expect(classifyUsageWindow(window({ id: "session" }), NOW).windowClass).toBe("session");
  expect(classifyUsageWindow(window({ id: "five_hour" }), NOW).windowClass).toBe("session");
  expect(classifyUsageWindow(window({ id: "seven_day" }), NOW).windowClass).toBe("weekly");
  expect(classifyUsageWindow(window({ id: "weekly_all" }), NOW).classSource).toBe("kind");
});

test("a long reset horizon soundly implies weekly, and is flagged INFERRED", () => {
  const classified = classifyUsageWindow(
    window({ id: "mystery_cap", resetsAt: at(days(3)) }),
    NOW,
  );
  expect(classified.windowClass).toBe("weekly");
  expect(classified.classSource).toBe("reset-horizon");
  expect(classified.inferred).toBe(true);
});

test("ASYMMETRY: a short reset horizon does NOT imply session", () => {
  // Measured counterexample: a live weekly_all window sat 0.86h from its reset
  // on 2026-07-28. By horizon alone it is indistinguishable from a session
  // window, so a short horizon must yield `unknown`, never `session`. Guessing
  // "session" here would let a weekly-dead account back into the pool after a
  // few hours.
  const classified = classifyUsageWindow(
    window({ id: "mystery_cap", resetsAt: at(minutes(52)) }),
    NOW,
  );
  expect(classified.windowClass).toBe("unknown");
  expect(classified.classSource).toBe("unclassified");

  // Positive control: the same unknown id WITH a long horizon does classify,
  // so the `unknown` above is the horizon rule declining to guess and not the
  // fallback being dead code.
  expect(
    classifyUsageWindow(window({ id: "mystery_cap", resetsAt: at(days(2)) }), NOW).windowClass,
  ).toBe("weekly");
});

test("the horizon boundary sits at the session window's maximum life", () => {
  const justUnder = classifyUsageWindow(
    window({ id: "x", resetsAt: at(SESSION_WINDOW_MAX_MS) }),
    NOW,
  );
  const justOver = classifyUsageWindow(
    window({ id: "x", resetsAt: at(SESSION_WINDOW_MAX_MS + 1000) }),
    NOW,
  );
  expect(justUnder.windowClass).toBe("unknown");
  expect(justOver.windowClass).toBe("weekly");
});

// ---------------------------------------------------------------------------
// Health derivation.
// ---------------------------------------------------------------------------

test("an absent window reads as unconstrained, never as exhausted", () => {
  // The API omits a window when it is not limiting.
  const health = deriveWindowHealth(
    parseUsageResponse({ limits: [{ kind: "weekly_all", group: "weekly", percent: 10 }] }, NOW),
    { now: NOW },
  );
  expect(health.session).toBeUndefined();
  expect(health.sessionHeadroom).toBe(100);
  expect(health.weeklyHeadroom).toBe(90);
});

test("a rolled window reports full headroom and marks the headroom INFERRED", () => {
  const usage = parseUsageResponse(
    {
      limits: [
        { kind: "session", group: "session", percent: 100, resets_at: at(-minutes(10)) },
        { kind: "weekly_all", group: "weekly", percent: 30, resets_at: at(days(3)) },
      ],
    },
    new Date(NOW.getTime() - hours(2)),
  );
  const health = deriveWindowHealth(usage, { now: NOW });
  expect(health.session?.rolled).toBe(true);
  expect(health.session?.exhausted).toBe(false);
  expect(health.session?.effectiveHeadroom).toBe(100);
  expect(health.session?.headroomInferred).toBe(true);
  // The weekly window did not roll, so its number stands as measured.
  expect(health.weekly?.headroomInferred).toBe(false);
  expect(health.weeklyHeadroom).toBe(70);
});

test("a reset already past at read time is a bad payload, not a roll", () => {
  // resets_at BEFORE fetchedAt cannot describe a window that rolled since the
  // reading. Treating it as a roll would hand out free headroom on malformed
  // data — exactly the optimistic error that strands a session.
  const usage = parseUsageResponse(
    {
      limits: [{ kind: "session", group: "session", percent: 100, resets_at: at(-hours(3)) }],
    },
    new Date(NOW.getTime() - hours(1)),
  );
  const health = deriveWindowHealth(usage, { now: NOW });
  expect(health.session?.rolled).toBe(false);
  expect(health.session?.exhausted).toBe(true);
  expect(health.sessionHeadroom).toBe(0);
});

test("a model-scoped window is dropped from both axes", () => {
  const usage = parseUsageResponse(
    {
      limits: [
        { kind: "session", group: "session", percent: 5 },
        { kind: "weekly_all", group: "weekly", percent: 20 },
        { kind: "weekly_scoped", group: "weekly", percent: 100, scope: { model: "opus" } },
      ],
    },
    NOW,
  );
  const health = deriveWindowHealth(usage, { now: NOW });
  expect(health.weeklyHeadroom).toBe(80);
  expect(health.unknown).toHaveLength(0);
});

test("an unclassifiable unscoped window gates on the slow axis", () => {
  // Unknown caps are treated as weekly-like for headroom: the optimistic error
  // (assuming a short window) is the one that strands a session on a dead
  // account, so the conservative reading wins.
  const usage = parseUsageResponse(
    {
      limits: [
        { kind: "session", group: "session", percent: 5 },
        { kind: "mystery", percent: 80, resets_at: at(minutes(30)) },
      ],
    },
    NOW,
  );
  const health = deriveWindowHealth(usage, { now: NOW });
  expect(health.unknown).toHaveLength(1);
  expect(health.weeklyHeadroom).toBe(20);
  expect(health.sessionHeadroom).toBe(95);
});

test("the worse of two windows of the same class wins", () => {
  const usage = parseUsageResponse(
    {
      limits: [
        { kind: "weekly_all", group: "weekly", percent: 20 },
        { kind: "weekly_other", group: "weekly", percent: 65 },
      ],
    },
    NOW,
  );
  const health = deriveWindowHealth(usage, { now: NOW });
  expect(health.weekly?.utilization).toBe(65);
  expect(health.weeklyHeadroom).toBe(35);
});

test("no severity string declares exhaustion below the utilization cap", () => {
  // MEASURED in the Claude Code 2.1.220 bundle (binary-safe grep -a):
  //     severity:"normal" 0, severity:"critical" 0, severity:"exhausted" 0
  // Positive controls on the same file by the same method: severity:"error" 27,
  // severity:"warning" 22, severity:"fatal" 6, bare severity 295 — so the zeros
  // discriminate. The reference client reads kind, scope, percent, resets_at
  // and extra_usage.* off a limit entry and never reads severity from the usage
  // payload. Branching on it means branching on a string with no evidence of
  // existing; utilization is the field the client itself acts on.
  for (const severity of ["critical", "exhausted", "warning", "anything-else"]) {
    const health = deriveWindowHealth(
      parseUsageResponse(
        { limits: [{ kind: "weekly_all", group: "weekly", percent: 61, severity, resets_at: at(days(2)) }] },
        NOW,
      ),
      { now: NOW },
    );
    expect(health.weekly?.exhausted).toBe(false);
  }
});

test("the live `critical` reading is still caught, by utilization", () => {
  // POSITIVE CONTROL for the test above: dropping the severity branch must not
  // lose the one real exhausted window in the live cache (weekly_all at 100%,
  // severity "critical"). The utilization path catches it, so nothing regresses.
  const health = deriveWindowHealth(
    parseUsageResponse(
      {
        limits: [
          { kind: "weekly_all", group: "weekly", percent: 100, severity: "critical", resets_at: at(days(2)) },
        ],
      },
      NOW,
    ),
    { now: NOW },
  );
  expect(health.weekly?.exhausted).toBe(true);
  expect(health.weeklyHeadroom).toBe(0);
});
