import type { AccountUsage, UsageWindow } from "./usage.js";

/**
 * Two-window model for Anthropic rate limits.
 *
 * Anthropic enforces TWO independent limits and they fail differently:
 *
 *   - the rolling 5-hour SESSION window — exhaustion is temporary and
 *     self-heals within hours;
 *   - the 7-day WEEKLY window — exhaustion means the account is unusable for
 *     days.
 *
 * Collapsing them into one "usage %" (as a single worst-window headroom does)
 * makes the selector either abandon accounts that would have recovered in
 * minutes, or keep returning to accounts that are dead until next week. Every
 * consumer that ranks or excludes accounts must see both windows separately.
 *
 * MEASURED 2026-07-28 across 8 live accounts (`limits[]` from
 * GET /api/oauth/usage). Every entry carried a `group` discriminator:
 *
 *   kind=session       group=session  scoped=false   reset horizon 2.36–4.86h
 *   kind=weekly_all    group=weekly   scoped=false   reset horizon 0.86–155.86h
 *   kind=weekly_scoped group=weekly   scoped=true    (model-scoped)
 *
 * So window identity is DATA, not inference, on the happy path.
 */

/** Longest life of the rolling session window. Measured max horizon: 4.86h. */
export const SESSION_WINDOW_MAX_MS = 5 * 60 * 60 * 1000;

/**
 * Utilization at which a window is treated as exhausted rather than merely
 * low. Kept at the cap: the near-cap band is handled by the headroom floors in
 * selection, so nothing here depends on an invented threshold.
 *
 * `severity` is deliberately NOT used to decide exhaustion. The complete
 * vocabulary observed in the live usage cache (2026-07-28) is:
 *
 *     severity="normal"    n=23  utilization 0–72
 *     severity="critical"  n=1   utilization 100
 *
 * One sample of one non-normal value cannot distinguish "at the cap" from
 * "approaching the cap". Reading it as exhaustion would hard-exclude a WEEKLY
 * window for days on an account that may still have headroom, and the only
 * live `critical` window is at 100% anyway — so the utilization path already
 * catches it and the severity branch would buy nothing it could not also get
 * wrong. Utilization is the measured, unambiguous signal; it decides alone.
 */
export const DEFAULT_EXHAUSTION_PERCENT = 100;

export type WindowClass = "session" | "weekly" | "scoped" | "unknown";

/**
 * Where the classification came from. `reset-horizon` is the only INFERRED
 * source — everything else is read directly off the payload.
 */
export type WindowClassSource = "group" | "kind" | "scope" | "reset-horizon" | "unclassified";

export interface WindowClassification {
  windowClass: WindowClass;
  classSource: WindowClassSource;
  /** True when the class was inferred rather than read from the payload. */
  inferred: boolean;
}

function fromGroup(group: string | undefined): WindowClass | undefined {
  if (group === "session") return "session";
  if (group === "weekly") return "weekly";
  return undefined;
}

function fromKind(kind: string): WindowClass | undefined {
  if (kind === "session" || kind === "five_hour") return "session";
  if (kind.startsWith("weekly") || kind.startsWith("seven_day")) return "weekly";
  return undefined;
}

/**
 * Classify one usage window.
 *
 * The reset-horizon fallback is deliberately ASYMMETRIC. A horizon longer than
 * the session window's maximum life cannot be a session window, so `> 5h`
 * soundly implies weekly. The converse does NOT hold: a live weekly window was
 * measured 0.86h from its reset, which is indistinguishable by horizon from a
 * session window. A short horizon therefore yields `unknown`, never `session`.
 */
export function classifyUsageWindow(
  window: UsageWindow,
  fetchedAt: Date | undefined,
): WindowClassification {
  if (window.scoped) return { windowClass: "scoped", classSource: "scope", inferred: false };

  const byGroup = fromGroup(window.group);
  if (byGroup) return { windowClass: byGroup, classSource: "group", inferred: false };

  const byKind = fromKind(window.id);
  if (byKind) return { windowClass: byKind, classSource: "kind", inferred: false };

  if (window.resetsAt && fetchedAt) {
    const resetsAt = Date.parse(window.resetsAt);
    if (Number.isFinite(resetsAt) && resetsAt - fetchedAt.getTime() > SESSION_WINDOW_MAX_MS) {
      return { windowClass: "weekly", classSource: "reset-horizon", inferred: true };
    }
  }

  return { windowClass: "unknown", classSource: "unclassified", inferred: false };
}

export interface WindowHealth {
  /** Window id as reported (`session`, `weekly_all`, …). */
  id: string;
  windowClass: "session" | "weekly" | "unknown";
  classSource: WindowClassSource;
  /** True when the window class itself was inferred. */
  inferred: boolean;
  /** Utilization percent as measured. */
  utilization: number;
  resetsAt?: string;
  /**
   * The reset boundary has passed since the reading was taken, so the measured
   * utilization no longer describes the window.
   */
  rolled: boolean;
  /**
   * Headroom to rank on. For a rolled window this is 100 — INFERRED: a window
   * returns to zero consumption at its reset boundary by definition, and a
   * refresh corrects the number if anything has been spent since.
   */
  effectiveHeadroom: number;
  /** True when effectiveHeadroom came from the rolled-window inference. */
  headroomInferred: boolean;
  /** At the cap, and not rolled. */
  exhausted: boolean;
}

function clampHeadroom(value: number): number {
  return Math.max(0, Math.min(100, value));
}

function toHealth(
  window: UsageWindow,
  classification: WindowClassification,
  now: Date,
  fetchedAt: Date | undefined,
  exhaustionPercent: number,
): WindowHealth {
  const resetsAtMs = window.resetsAt ? Date.parse(window.resetsAt) : Number.NaN;
  // A reset boundary that already passed relative to the READING supersedes it.
  // Guard on the reading time too: a boundary that was already in the past when
  // the reading was taken is not a roll, it is a stale/odd payload.
  const hasReset = Number.isFinite(resetsAtMs);
  const rolled =
    hasReset && resetsAtMs <= now.getTime() && (!fetchedAt || resetsAtMs > fetchedAt.getTime());

  return {
    id: window.id,
    windowClass: classification.windowClass === "scoped" ? "unknown" : classification.windowClass,
    classSource: classification.classSource,
    inferred: classification.inferred,
    utilization: window.utilization,
    ...(window.resetsAt ? { resetsAt: window.resetsAt } : {}),
    rolled,
    effectiveHeadroom: rolled ? 100 : clampHeadroom(100 - window.utilization),
    headroomInferred: rolled,
    exhausted: !rolled && window.utilization >= exhaustionPercent,
  };
}

export interface AccountWindowHealth {
  /** Worst 5-hour window, when one was reported. */
  session?: WindowHealth;
  /** Worst 7-day window, when one was reported. */
  weekly?: WindowHealth;
  /** Unscoped windows we could not classify — they gate, conservatively. */
  unknown: WindowHealth[];
  /**
   * Headroom for each axis, with an absent window read as unconstrained. The
   * API omits a window when it is not limiting, so absent means "no constraint
   * reported", never "exhausted".
   */
  sessionHeadroom: number;
  weeklyHeadroom: number;
}

export interface DeriveWindowHealthOptions {
  now?: Date;
  exhaustionPercent?: number;
}

/** Keep the worse (lower-headroom) of two windows of the same class. */
function worse(a: WindowHealth | undefined, b: WindowHealth): WindowHealth {
  if (!a) return b;
  return b.effectiveHeadroom < a.effectiveHeadroom ? b : a;
}

/**
 * Split an account's usage into its two independent windows.
 *
 * Model/surface-scoped windows are dropped: a saturated Opus cap does not gate
 * work on other models, so it must never make an account ineligible.
 */
export function deriveWindowHealth(
  usage: AccountUsage,
  opts: DeriveWindowHealthOptions = {},
): AccountWindowHealth {
  const now = opts.now ?? new Date();
  const exhaustionPercent = opts.exhaustionPercent ?? DEFAULT_EXHAUSTION_PERCENT;
  const fetchedAtMs = Date.parse(usage.fetchedAt);
  const fetchedAt = Number.isFinite(fetchedAtMs) ? new Date(fetchedAtMs) : undefined;

  let session: WindowHealth | undefined;
  let weekly: WindowHealth | undefined;
  const unknown: WindowHealth[] = [];

  for (const window of usage.windows) {
    const classification = classifyUsageWindow(window, fetchedAt);
    if (classification.windowClass === "scoped") continue;
    const health = toHealth(window, classification, now, fetchedAt, exhaustionPercent);
    if (classification.windowClass === "session") session = worse(session, health);
    else if (classification.windowClass === "weekly") weekly = worse(weekly, health);
    else unknown.push(health);
  }

  const unknownHeadroom = unknown.reduce((lowest, w) => Math.min(lowest, w.effectiveHeadroom), 100);

  return {
    ...(session ? { session } : {}),
    ...(weekly ? { weekly } : {}),
    unknown,
    sessionHeadroom: session?.effectiveHeadroom ?? 100,
    // Unclassified windows gate on the slow axis: treating an unknown cap as a
    // short-lived session limit would be the optimistic error, and the one that
    // strands a session on a dead account.
    weeklyHeadroom: Math.min(weekly?.effectiveHeadroom ?? 100, unknownHeadroom),
  };
}
