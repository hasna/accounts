import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import { writeFileAtomic } from "./safe-path.js";

/**
 * Per-account exhaustion ledger — the memory that survives process restarts.
 *
 * The usage cache expires and a refresh can fail; neither is a durable record
 * of "this account told us it was out". Without one, a restarted hook re-reads
 * a stale or empty cache and switches straight back onto the account it just
 * fled, and a run of near-simultaneous breaches turns into a switch storm
 * across every account in the pool.
 *
 * The ledger is a COOLDOWN, not a blocklist: every record carries a computed
 * `releaseAt` and goes inert on its own. Records are never required to be
 * cleaned up for an account to come back.
 */

/**
 * Durable state, NOT cache. This holds on naming grounds alone: a store whose
 * entire purpose is surviving restarts must not live in a directory named
 * `cache`, because that name licenses deletion by anything that wants space.
 *
 * There is a supporting observation, but it is weaker than a root cause and is
 * recorded here at its true strength. On 2026-07-28 two `switched` events 60s
 * apart (14:08:30, 14:09:30) appear in `logs/usage-hook.log` under a 10-minute
 * cooldown, while `cache/auto-switch-state.json` exists nowhere on the
 * filesystem — and `writeAutoSwitchState` plus `cooldownActive` both verify
 * correct in isolation. Something is losing that file; WHAT is not established.
 *
 * An earlier version of this note also cited the `cache/` mtime as evidence of
 * a wipe. It is not evidence: the second switch writing the file into `cache/`
 * would set the same mtime, so the datum is equally expected under the benign
 * story and does not discriminate. Tracked separately — this module does not
 * depend on the answer.
 */
const STATE_DIR = "state";
const LEDGER_FILE = "exhaustion-ledger.json";

/** Account uuids are used as object keys only, but they arrive from JSON. */
const SAFE_UUID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;

export type ExhaustedWindowClass = "session" | "weekly" | "unknown";

export interface ExhaustionRecord {
  accountUuid: string;
  observedAt: string;
  windowClass: ExhaustedWindowClass;
  /** Reset boundary reported for the exhausted window, when it gave one. */
  resetsAt?: string;
  /** Consecutive exhaustions without a healthy stretch in between. */
  consecutive: number;
  /** Computed at record time and persisted, so a restart cannot lose it. */
  releaseAt: string;
}

export type ExhaustionLedger = Record<string, ExhaustionRecord>;

/** First backoff step when the payload gave us no reset time to work with. */
export const DEFAULT_BACKOFF_BASE_MS = 15 * 60 * 1000;

/**
 * Backoff ceilings. Both are BOUNDED on purpose: a misclassified window or a
 * malformed payload must never take an account out of the pool permanently.
 * The session cap matches the window's own maximum life; the weekly cap is far
 * shorter than a week because a reset-less weekly reading is a data problem,
 * not evidence the account is out for seven days.
 */
export const SESSION_BACKOFF_CAP_MS = 5 * 60 * 60 * 1000;
export const WEEKLY_BACKOFF_CAP_MS = 24 * 60 * 60 * 1000;

/**
 * A fresh exhaustion this soon after the previous one was released counts as
 * the same episode and escalates the backoff instead of restarting it.
 */
export const STREAK_WINDOW_MS = 30 * 60 * 1000;

export function exhaustionLedgerPath(): string {
  return join(accountsHome(), STATE_DIR, LEDGER_FILE);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validRecord(value: unknown, uuid: string): ExhaustionRecord | undefined {
  if (!isRecord(value)) return undefined;
  const { accountUuid, observedAt, releaseAt, windowClass, consecutive, resetsAt } = value;
  if (accountUuid !== uuid || typeof observedAt !== "string" || typeof releaseAt !== "string") {
    return undefined;
  }
  if (!Number.isFinite(Date.parse(observedAt)) || !Number.isFinite(Date.parse(releaseAt))) {
    return undefined;
  }
  const cls: ExhaustedWindowClass =
    windowClass === "session" || windowClass === "weekly" ? windowClass : "unknown";
  return {
    accountUuid: uuid,
    observedAt,
    windowClass: cls,
    ...(typeof resetsAt === "string" ? { resetsAt } : {}),
    consecutive: typeof consecutive === "number" && consecutive >= 1 ? Math.floor(consecutive) : 1,
    releaseAt,
  };
}

/** Never throws: a corrupt ledger degrades to "no cooldowns", never to a crash. */
export function readExhaustionLedger(): ExhaustionLedger {
  const path = exhaustionLedgerPath();
  if (!existsSync(path)) return {};
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return {};
  }
  if (!isRecord(raw)) return {};
  const ledger: ExhaustionLedger = {};
  for (const [uuid, value] of Object.entries(raw)) {
    if (!SAFE_UUID.test(uuid)) continue;
    const record = validRecord(value, uuid);
    if (record) ledger[uuid] = record;
  }
  return ledger;
}

/**
 * Never throws. The ledger is an optimization, not a gate: if it cannot be
 * persisted (unwritable dir, `state` occupied by a file, full disk) the correct
 * outcome is a switch that forgets its cooldown, NOT a hook that fails open and
 * leaves the session on an exhausted account. Returns whether it persisted so
 * callers can tell the difference.
 */
export function writeExhaustionLedger(ledger: ExhaustionLedger): boolean {
  try {
    mkdirSync(join(accountsHome(), STATE_DIR), { recursive: true });
    writeFileAtomic(exhaustionLedgerPath(), JSON.stringify(ledger, null, 2) + "\n", {
      mode: 0o600,
      mustStayUnder: accountsHome(),
    });
    return true;
  } catch {
    return false;
  }
}

function backoffCap(windowClass: ExhaustedWindowClass): number {
  return windowClass === "weekly" ? WEEKLY_BACKOFF_CAP_MS : SESSION_BACKOFF_CAP_MS;
}

export function backoffMs(windowClass: ExhaustedWindowClass, consecutive: number): number {
  const steps = Math.max(0, consecutive - 1);
  const raw = DEFAULT_BACKOFF_BASE_MS * 2 ** Math.min(steps, 20);
  return Math.min(raw, backoffCap(windowClass));
}

export interface RecordExhaustionInput {
  accountUuid: string;
  windowClass: ExhaustedWindowClass;
  resetsAt?: string;
  now?: Date;
}

/**
 * Note that an account reported exhaustion, and compute when it may be picked
 * again.
 *
 * `releaseAt` is the LATER of the window's own reset and the backoff step, so
 * a reported reset time always wins when it is the longer wait (a weekly reset
 * days out is respected in full) while a missing or already-past reset still
 * yields a bounded, escalating cooldown rather than an immediate retry.
 */
export function recordExhaustion(input: RecordExhaustionInput): ExhaustionRecord {
  const now = input.now ?? new Date();
  if (!SAFE_UUID.test(input.accountUuid)) {
    // Not persistable as a key; return an inert record rather than throwing in
    // the hook path.
    return {
      accountUuid: input.accountUuid,
      observedAt: now.toISOString(),
      windowClass: input.windowClass,
      consecutive: 1,
      releaseAt: now.toISOString(),
    };
  }

  const ledger = readExhaustionLedger();
  const prior = ledger[input.accountUuid];
  const priorRelease = prior ? Date.parse(prior.releaseAt) : Number.NaN;
  const sameEpisode =
    !!prior && Number.isFinite(priorRelease) && now.getTime() - priorRelease <= STREAK_WINDOW_MS;
  const consecutive = sameEpisode ? prior!.consecutive + 1 : 1;

  const backoffUntil = now.getTime() + backoffMs(input.windowClass, consecutive);
  const resetsAtMs = input.resetsAt ? Date.parse(input.resetsAt) : Number.NaN;
  const releaseAtMs = Number.isFinite(resetsAtMs)
    ? Math.max(backoffUntil, resetsAtMs)
    : backoffUntil;

  const record: ExhaustionRecord = {
    accountUuid: input.accountUuid,
    observedAt: now.toISOString(),
    windowClass: input.windowClass,
    ...(input.resetsAt ? { resetsAt: input.resetsAt } : {}),
    consecutive,
    releaseAt: new Date(releaseAtMs).toISOString(),
  };
  ledger[input.accountUuid] = record;
  writeExhaustionLedger(ledger);
  return record;
}

/** Drop an account's record once it reads healthy again. */
export function clearExhaustion(accountUuid: string): void {
  const ledger = readExhaustionLedger();
  if (!(accountUuid in ledger)) return;
  delete ledger[accountUuid];
  writeExhaustionLedger(ledger);
}

/**
 * uuid -> releaseAt for records still in force. Expired records are simply
 * absent, so an account returns to candidacy without any cleanup step.
 */
export function activeCooldowns(
  ledger: ExhaustionLedger = readExhaustionLedger(),
  now: Date = new Date(),
): Map<string, string> {
  const active = new Map<string, string>();
  for (const [uuid, record] of Object.entries(ledger)) {
    const release = Date.parse(record.releaseAt);
    if (Number.isFinite(release) && release > now.getTime()) active.set(uuid, record.releaseAt);
  }
  return active;
}
