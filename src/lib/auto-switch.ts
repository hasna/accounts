import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError } from "../types.js";
import type { AccountIdentity } from "./identity-index.js";
import type { AccountUsage, UsageFetchError, UsageWindow } from "./usage.js";
import { writeFileAtomic } from "./safe-path.js";

/**
 * Decision layer for usage-aware switching: per-account usage cache, the
 * healthiest-account selector, threshold check, and the anti-flap cooldown.
 * Everything here is pure/filesystem-local so the UserPromptSubmit hook makes
 * every decision from cached data — it must never block a prompt on a network
 * call.
 */

const CACHE_DIR = "cache";
const USAGE_CACHE_DIR = "usage";
const STATE_FILE = "auto-switch-state.json";

/** Account uuids come from JSON on disk; refuse anything path-hostile. */
const SAFE_UUID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;

function safeUuid(accountUuid: string): string | undefined {
  return SAFE_UUID.test(accountUuid) ? accountUuid : undefined;
}

export function usageCacheDir(): string {
  return join(accountsHome(), CACHE_DIR, USAGE_CACHE_DIR);
}

export function usageCachePath(accountUuid: string): string {
  const uuid = safeUuid(accountUuid);
  if (!uuid) throw new AccountsError("account uuid is not a safe cache key");
  return join(usageCacheDir(), `${uuid}.json`);
}

export interface UsageCacheEntry {
  accountUuid: string;
  fetchedAt: string;
  usage?: AccountUsage;
  error?: UsageFetchError;
}

export function writeUsageCache(entry: UsageCacheEntry): void {
  const path = usageCachePath(entry.accountUuid);
  mkdirSync(usageCacheDir(), { recursive: true });
  writeFileAtomic(path, JSON.stringify(entry, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

export function readUsageCache(
  accountUuid: string,
  maxAgeMs: number,
  now: Date = new Date(),
): UsageCacheEntry | undefined {
  if (!safeUuid(accountUuid)) return undefined;
  const path = usageCachePath(accountUuid);
  if (!existsSync(path)) return undefined;
  let entry: UsageCacheEntry;
  try {
    entry = JSON.parse(readFileSync(path, "utf8")) as UsageCacheEntry;
  } catch {
    return undefined;
  }
  if (entry.accountUuid !== accountUuid || typeof entry.fetchedAt !== "string") return undefined;
  const fetchedAt = Date.parse(entry.fetchedAt);
  if (!Number.isFinite(fetchedAt) || now.getTime() - fetchedAt > maxAgeMs) return undefined;
  return entry;
}

export interface SelectionEntry {
  identity: AccountIdentity;
  usage?: AccountUsage;
}

export interface SwitchCandidate {
  accountUuid: string;
  email?: string;
  headroom: number;
  usage: AccountUsage;
  identity: AccountIdentity;
}

export type NoCandidateReason = "no-accounts" | "no-usage-data" | "all-limited";

export interface SelectionResult {
  candidate?: SwitchCandidate;
  reason?: NoCandidateReason;
  /** Accounts that had headroom data but fell below the bar (for reporting). */
  considered: number;
}

export interface SelectionOptions {
  /** The uuid the session currently runs as — never a candidate (the no-op case). */
  currentUuid?: string;
  /** Minimum headroom a target must have to be worth switching to. */
  minHeadroom?: number;
}

export const DEFAULT_MIN_HEADROOM = 25;

/**
 * Rank distinct ACCOUNTS (not directories) by headroom. Only accounts with a
 * valid credential and measured usage are eligible; the current account never
 * is — selecting it would be the silent-no-op failure this feature exists to
 * kill. Deterministic: headroom desc, then uuid asc.
 */
export function selectHealthiestAccount(
  entries: ReadonlyArray<SelectionEntry>,
  opts: SelectionOptions = {},
): SelectionResult {
  const minHeadroom = opts.minHeadroom ?? DEFAULT_MIN_HEADROOM;
  const eligible = entries.filter(
    (e) => e.identity.status === "ok" && e.identity.accountUuid !== opts.currentUuid,
  );
  if (eligible.length === 0) return { reason: "no-accounts", considered: 0 };

  const measured = eligible.filter((e): e is Required<SelectionEntry> => !!e.usage);
  if (measured.length === 0) return { reason: "no-usage-data", considered: 0 };

  const ranked = [...measured].sort(
    (a, b) =>
      b.usage.headroom - a.usage.headroom || a.identity.accountUuid.localeCompare(b.identity.accountUuid),
  );
  const best = ranked[0]!;
  if (best.usage.headroom < minHeadroom) return { reason: "all-limited", considered: measured.length };
  return {
    candidate: {
      accountUuid: best.identity.accountUuid,
      ...(best.identity.email ? { email: best.identity.email } : {}),
      headroom: best.usage.headroom,
      usage: best.usage,
      identity: best.identity,
    },
    considered: measured.length,
  };
}

export interface ThresholdResult {
  breached: boolean;
  /** The worst unscoped window at/over the threshold, when breached. */
  window?: UsageWindow;
}

export const DEFAULT_SWITCH_THRESHOLD = 90;

/** Breached when any UNSCOPED window is at/over the threshold percent used. */
export function thresholdBreached(usage: AccountUsage, thresholdPercent: number): ThresholdResult {
  const over = usage.windows
    .filter((w) => !w.scoped && w.utilization >= thresholdPercent)
    .sort((a, b) => b.utilization - a.utilization);
  return over.length > 0 ? { breached: true, window: over[0]! } : { breached: false };
}

export interface AutoSwitchState {
  lastSwitchAt: string;
  fromUuid?: string;
  toUuid?: string;
  outcome?: "switched" | "failed";
}

export function autoSwitchStatePath(): string {
  return join(accountsHome(), CACHE_DIR, STATE_FILE);
}

export function writeAutoSwitchState(state: AutoSwitchState): void {
  mkdirSync(join(accountsHome(), CACHE_DIR), { recursive: true });
  writeFileAtomic(autoSwitchStatePath(), JSON.stringify(state, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

export function readAutoSwitchState(): AutoSwitchState | undefined {
  const path = autoSwitchStatePath();
  if (!existsSync(path)) return undefined;
  try {
    const state = JSON.parse(readFileSync(path, "utf8")) as AutoSwitchState;
    return typeof state.lastSwitchAt === "string" ? state : undefined;
  } catch {
    return undefined;
  }
}

export const DEFAULT_COOLDOWN_MS = 10 * 60 * 1000;

/**
 * True while a recent switch (or failed attempt) is still cooling down —
 * the anti-flap guard: one switch per window, never a ping-pong between
 * two nearly-exhausted accounts, never a retry storm on a broken switch.
 */
export function cooldownActive(
  state: AutoSwitchState | undefined,
  cooldownMs: number,
  now: Date = new Date(),
): boolean {
  if (!state) return false;
  const last = Date.parse(state.lastSwitchAt);
  if (!Number.isFinite(last)) return false;
  return now.getTime() - last <= cooldownMs;
}
