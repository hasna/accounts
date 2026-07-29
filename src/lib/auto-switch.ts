import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError } from "../types.js";
import { isUsableIdentity, type AccountIdentity } from "./identity-index.js";
import type { AccountUsage, UsageFetchError, UsageWindow } from "./usage.js";
import { deriveWindowHealth, type AccountWindowHealth } from "./usage-windows.js";
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
const STATE_DIR = "auto-switch";
const NOTICE_FILE = "usage-hook-notices.json";

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
  /** Worst of the two windows — kept for reporting continuity. */
  headroom: number;
  /** Headroom in the rolling 5-hour window (100 when none is reported). */
  sessionHeadroom: number;
  /** Headroom in the 7-day window (100 when none is reported). */
  weeklyHeadroom: number;
  windows: AccountWindowHealth;
  usage: AccountUsage;
  identity: AccountIdentity;
}

export type NoCandidateReason = "no-accounts" | "no-usage-data" | "all-limited";

/**
 * Why an account was not a candidate.
 *
 * `contended` is the one that is not about the account's own health: another
 * config dir on this machine is already running a live session as it. Switching
 * a second dir onto the same account puts two Claude Code processes behind one
 * OAuth refresh token, and refresh tokens ROTATE — the first to refresh
 * invalidates the copy the other still holds, the loser's refresh fails, and its
 * `.credentials.json` is blanked in place. Measured on this fleet 2026-07-29:
 * six of twenty-three profile dirs had been blanked that way, each within
 * seconds to minutes of a sibling dir holding the same account refreshing.
 * Because the usage hook switches automatically, every unguarded switch could
 * add another pair.
 */
export type ExclusionReason =
  | "current-account"
  | "credential"
  | "contended"
  | "no-usage-data"
  | "weekly-exhausted"
  | "session-exhausted"
  | "window-exhausted"
  | "cooldown"
  | "insufficient-headroom";

export interface ExcludedAccount {
  accountUuid: string;
  reason: ExclusionReason;
  /** When the account becomes a candidate again, when that time is known. */
  eligibleAt?: string;
  sessionHeadroom?: number;
  weeklyHeadroom?: number;
}

export interface SelectionResult {
  /** The top-ranked candidate; identical to `ranked[0]`. */
  candidate?: SwitchCandidate;
  /**
   * EVERY eligible candidate, best first. The caller needs the whole list, not
   * just the winner: a candidate can be eligible on headroom yet unreachable
   * because no profile on this machine is a door onto it, and giving up at that
   * point strands the session on an exhausted account while a usable runner-up
   * sits one rank down.
   */
  ranked: SwitchCandidate[];
  reason?: NoCandidateReason;
  /** Accounts that had headroom data but fell below the bar (for reporting). */
  considered: number;
  /** Every account that was not selected, with the reason and recovery time. */
  excluded: ExcludedAccount[];
}

export interface SelectionOptions {
  /** The uuid the session currently runs as — never a candidate (the no-op case). */
  currentUuid?: string;
  /** Minimum WEEKLY headroom a target must have to be worth switching to. */
  minHeadroom?: number;
  /** Minimum SESSION headroom a target must have to be usable right now. */
  minSessionHeadroom?: number;
  /** uuid -> ISO time before which the account must not be re-selected. */
  cooldowns?: ReadonlyMap<string, string>;
  /**
   * Accounts a live session in ANOTHER config dir is already running. Switching
   * onto one of these creates the two-copies-one-account state that
   * refresh-token rotation then resolves by destroying a credential.
   */
  contendedAccounts?: ReadonlySet<string>;
  now?: Date;
}

export const DEFAULT_MIN_HEADROOM = 25;

/**
 * A target with less than this much of its 5-hour window left will re-breach
 * almost immediately; the switch that follows is then blocked by the cooldown,
 * stranding the session on an account that cannot serve it. Switching is only
 * worth doing to somewhere with real immediate runway.
 */
export const DEFAULT_MIN_SESSION_HEADROOM = 10;

/**
 * The constraint that will bite first. Ranking on this rather than on either
 * window alone keeps the selector from handing back an account with a great
 * week and no runway for the next hour — that account re-breaches immediately
 * and the cooldown then blocks the follow-up switch.
 */
function bindingHeadroom(windows: AccountWindowHealth): number {
  return Math.min(windows.sessionHeadroom, windows.weeklyHeadroom);
}

/**
 * Rank distinct ACCOUNTS (not directories) by headroom in BOTH rate-limit
 * windows. Only accounts with a valid credential and measured usage are
 * eligible; the current account never is — selecting it would be the
 * silent-no-op failure this feature exists to kill.
 *
 * The two windows are never blended:
 *
 *   - a WEEKLY-exhausted account is excluded until its weekly reset, however
 *     healthy its 5-hour number looks — it is dead for days;
 *   - a SESSION-exhausted account is excluded only until its 5-hour window
 *     rolls, after which it returns to candidacy with no new fetch needed;
 *   - ranking leads with the BINDING window (whichever of the two will bite
 *     first), then weekly headroom (the scarce resource that does not self-heal
 *     within a session), then session headroom — which is what makes an
 *     already-rolled 5-hour window win a tie — then uuid for determinism.
 */
export function selectHealthiestAccount(
  entries: ReadonlyArray<SelectionEntry>,
  opts: SelectionOptions = {},
): SelectionResult {
  const now = opts.now ?? new Date();
  const minHeadroom = opts.minHeadroom ?? DEFAULT_MIN_HEADROOM;
  const minSessionHeadroom = opts.minSessionHeadroom ?? DEFAULT_MIN_SESSION_HEADROOM;

  const excluded: ExcludedAccount[] = [];
  const eligible: Array<{ entry: Required<SelectionEntry>; windows: AccountWindowHealth }> = [];
  let considered = 0;
  let measurable = 0;

  for (const entry of entries) {
    const uuid = entry.identity.accountUuid;
    if (uuid === opts.currentUuid) {
      excluded.push({ accountUuid: uuid, reason: "current-account" });
      continue;
    }
    // "valid OR renewable", not "status === ok": an account whose access token
    // aged out but whose refresh token is intact is a usable target, ranked
    // below every currently-valid one. See isUsableIdentity.
    if (!isUsableIdentity(entry.identity)) {
      excluded.push({ accountUuid: uuid, reason: "credential" });
      continue;
    }
    // Before health, because this is not a question about the account: taking a
    // second live copy of it is what destroys credentials, however healthy it
    // looks.
    if (opts.contendedAccounts?.has(uuid)) {
      excluded.push({ accountUuid: uuid, reason: "contended" });
      continue;
    }
    if (!entry.usage) {
      measurable += 1;
      excluded.push({ accountUuid: uuid, reason: "no-usage-data" });
      continue;
    }

    considered += 1;
    const windows = deriveWindowHealth(entry.usage, { now });
    const base = {
      accountUuid: uuid,
      sessionHeadroom: windows.sessionHeadroom,
      weeklyHeadroom: windows.weeklyHeadroom,
    };

    // Weekly first: it is the more severe verdict, and an account that is both
    // weekly- and session-exhausted must be reported as the one that keeps it
    // out for days, not the one that keeps it out for minutes.
    if (windows.weekly?.exhausted) {
      excluded.push({
        ...base,
        reason: "weekly-exhausted",
        ...(windows.weekly.resetsAt ? { eligibleAt: windows.weekly.resetsAt } : {}),
      });
      continue;
    }
    const exhaustedUnknown = windows.unknown.find((w) => w.exhausted);
    if (exhaustedUnknown) {
      excluded.push({
        ...base,
        reason: "window-exhausted",
        ...(exhaustedUnknown.resetsAt ? { eligibleAt: exhaustedUnknown.resetsAt } : {}),
      });
      continue;
    }
    if (windows.session?.exhausted) {
      excluded.push({
        ...base,
        reason: "session-exhausted",
        ...(windows.session.resetsAt ? { eligibleAt: windows.session.resetsAt } : {}),
      });
      continue;
    }

    const cooldownUntil = opts.cooldowns?.get(uuid);
    if (cooldownUntil) {
      const until = Date.parse(cooldownUntil);
      if (Number.isFinite(until) && until > now.getTime()) {
        excluded.push({ ...base, reason: "cooldown", eligibleAt: cooldownUntil });
        continue;
      }
    }

    if (windows.weeklyHeadroom < minHeadroom || windows.sessionHeadroom < minSessionHeadroom) {
      excluded.push({ ...base, reason: "insufficient-headroom" });
      continue;
    }

    eligible.push({ entry: entry as Required<SelectionEntry>, windows });
  }

  if (eligible.length === 0) {
    if (considered > 0) return { ranked: [], reason: "all-limited", considered, excluded };
    if (measurable > 0) return { ranked: [], reason: "no-usage-data", considered, excluded };
    return { ranked: [], reason: "no-accounts", considered, excluded };
  }

  const ranked = [...eligible]
    .sort(
      (a, b) =>
        // A credential that works NOW beats one the tool must renew first. This
        // is the only place the valid/renewable distinction shows up in
        // ordering, and it is deliberately the FIRST key: widening the pool
        // must never demote a healthy account behind one that needs a round
        // trip to become usable.
        Number(b.entry.identity.status === "ok") - Number(a.entry.identity.status === "ok") ||
        bindingHeadroom(b.windows) - bindingHeadroom(a.windows) ||
        b.windows.weeklyHeadroom - a.windows.weeklyHeadroom ||
        b.windows.sessionHeadroom - a.windows.sessionHeadroom ||
        a.entry.identity.accountUuid.localeCompare(b.entry.identity.accountUuid),
    )
    .map(({ entry, windows }) => ({
      accountUuid: entry.identity.accountUuid,
      ...(entry.identity.email ? { email: entry.identity.email } : {}),
      headroom: Math.min(windows.sessionHeadroom, windows.weeklyHeadroom),
      sessionHeadroom: windows.sessionHeadroom,
      weeklyHeadroom: windows.weeklyHeadroom,
      windows,
      usage: entry.usage,
      identity: entry.identity,
    }));

  return { candidate: ranked[0]!, ranked, considered, excluded };
}

export interface ThresholdResult {
  breached: boolean;
  /** The worst unscoped window at/over the threshold, when breached. */
  window?: UsageWindow;
}

export const DEFAULT_SWITCH_THRESHOLD = 90;

/**
 * Breached when any gating (unscoped, unrolled) window is at/over the threshold
 * percent used.
 *
 * A window whose reset boundary has already passed is NOT a breach however high
 * its cached number reads: the window has rolled and the account is healthy
 * again. Acting on that stale number would switch the session away from a
 * perfectly good account — a spurious switch, which is how a switch storm
 * starts.
 */
export function thresholdBreached(
  usage: AccountUsage,
  thresholdPercent: number,
  now: Date = new Date(),
): ThresholdResult {
  const health = deriveWindowHealth(usage, { now });
  const gating = [
    ...(health.session ? [health.session] : []),
    ...(health.weekly ? [health.weekly] : []),
    ...health.unknown,
  ];
  const over = gating
    .filter((w) => !w.rolled && w.utilization >= thresholdPercent)
    .sort((a, b) => b.utilization - a.utilization);
  const worst = over[0];
  if (!worst) return { breached: false };
  const original = usage.windows.find((w) => w.id === worst.id);
  return {
    breached: true,
    window: original ?? {
      id: worst.id,
      utilization: worst.utilization,
      scoped: false,
      ...(worst.resetsAt ? { resetsAt: worst.resetsAt } : {}),
    },
  };
}

export interface AutoSwitchState {
  lastSwitchAt: string;
  fromUuid?: string;
  toUuid?: string;
  outcome?: "switched" | "failed";
  /** The session config dir this cooldown belongs to (diagnostics). */
  configDir?: string;
}

/**
 * Anti-flap state is PER SESSION CONFIG DIR, never fleet-wide.
 *
 * It used to be one `cache/auto-switch-state.json` for the whole machine, with
 * nothing in the record naming a session. Measured against the shipped bytes:
 * a session at 96% utilization was refused with `reason="cooldown"` because an
 * UNRELATED session had switched three minutes earlier; the control, identical
 * but with a 20-minute-old state, reached `performSwitch`. With ~18 live
 * sessions that capped the entire fleet at one switch per ten minutes — and the
 * losers were told nothing.
 *
 * The cooldown exists to stop ONE session ping-ponging between two exhausted
 * accounts. That is a per-session property, so the file is keyed by a digest of
 * the resolved config dir. The digest (rather than the path) keeps the filename
 * fixed-length, traversal-free and free of the dir's own characters; the path
 * itself is stored inside the file for diagnosis.
 *
 * No fallback to the old shared file on read: inheriting it would re-import the
 * bug it fixes. The cost is that the first invocation per dir after upgrading
 * ignores an in-flight cooldown — bounded, one-off, and self-correcting once
 * that dir has written its own state.
 */
export function autoSwitchStateDir(): string {
  return join(accountsHome(), CACHE_DIR, STATE_DIR);
}

export function autoSwitchStatePath(configDir: string): string {
  const key = createHash("sha256").update(resolve(configDir)).digest("hex").slice(0, 32);
  return join(autoSwitchStateDir(), `${key}.json`);
}

export function writeAutoSwitchState(state: AutoSwitchState, configDir: string): void {
  mkdirSync(autoSwitchStateDir(), { recursive: true });
  const record: AutoSwitchState = { ...state, configDir: state.configDir ?? resolve(configDir) };
  writeFileAtomic(autoSwitchStatePath(configDir), JSON.stringify(record, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

export function readAutoSwitchState(configDir: string): AutoSwitchState | undefined {
  const path = autoSwitchStatePath(configDir);
  if (!existsSync(path)) return undefined;
  try {
    const state = JSON.parse(readFileSync(path, "utf8")) as AutoSwitchState;
    return typeof state.lastSwitchAt === "string" ? state : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Last time each degraded hook outcome was announced, so a session that stays
 * degraded for an hour reports it rather than either spamming every prompt or
 * (the shipped behaviour) saying nothing at all. Machine-wide on purpose: the
 * conditions it throttles — an unreachable registry, a cold cache, a fleet with
 * no headroom anywhere — are machine-wide too.
 */
export type HookNoticeState = Record<string, string>;

export function hookNoticeStatePath(): string {
  return join(accountsHome(), CACHE_DIR, NOTICE_FILE);
}

export function readHookNoticeState(): HookNoticeState | undefined {
  const path = hookNoticeStatePath();
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const state: HookNoticeState = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value === "string") state[key] = value;
    }
    return state;
  } catch {
    return undefined;
  }
}

export function writeHookNoticeState(state: HookNoticeState): void {
  mkdirSync(join(accountsHome(), CACHE_DIR), { recursive: true });
  writeFileAtomic(hookNoticeStatePath(), JSON.stringify(state, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

export const DEFAULT_COOLDOWN_MS = 10 * 60 * 1000;

/**
 * True while a recent switch (or failed attempt) is still cooling down —
 * the anti-flap guard: one switch per window FOR THIS SESSION, never a
 * ping-pong between two nearly-exhausted accounts, never a retry storm on a
 * broken switch.
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
