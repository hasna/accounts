import type { AccountIdentity } from "./identity-index.js";
import {
  cooldownActive,
  selectHealthiestAccount,
  thresholdBreached,
  type AutoSwitchState,
  type HookNoticeState,
  type SwitchCandidate,
  type UsageCacheEntry,
} from "./auto-switch.js";
import { deriveWindowHealth } from "./usage-windows.js";
import type { RecordExhaustionInput } from "./exhaustion-ledger.js";

export type { HookNoticeState } from "./auto-switch.js";

/**
 * UserPromptSubmit hook brain. Proactive by design: a limit arrives as a
 * mid-turn API failure with no on-error hook, but UserPromptSubmit fires
 * BEFORE the message is processed — check headroom here, switch when low, and
 * the message runs on the fresh account without ever hitting the wall.
 *
 * Non-negotiables encoded here:
 *  - FAST: decisions use cached usage only; refreshes are fired detached.
 *  - FAIL-OPEN: any error lets the prompt through untouched.
 *  - LOUD: every switch (and every failed switch) emits a systemMessage —
 *    a silent identity change is the half-switch nightmare in a new costume.
 *  - HONEST: after switching, the active accountUuid is re-read and must have
 *    CHANGED to the target; "switched" onto the same account is a failure.
 *  - LOUD ABOUT NOT ACTING TOO: every outcome that means "this session is no
 *    longer protected" emits a systemMessage as well, throttled per reason.
 *    Measured on the shipped build: 50 of 161 production invocations (31%)
 *    reached no decision and said nothing, the longest unbroken run spanning
 *    70 minutes. Only `all-limited` — the rarest branch — ever spoke. An
 *    unattended session is by definition one nobody is watching, so the first
 *    symptom of a degraded hook was the session hitting the wall unexplained.
 */

export interface UsageHookOptions {
  /** The session's Claude config dir (CLAUDE_CONFIG_DIR or the live default). */
  configDir: string;
  /** Switch when any unscoped window is at/over this percent used. */
  thresholdPercent: number;
  /** A target account must have at least this much WEEKLY headroom. */
  minHeadroom: number;
  /** A target account must have at least this much 5-hour headroom. */
  minSessionHeadroom?: number;
  /** No second auto-switch (or retry of a failed one) within this window. */
  cooldownMs: number;
  /** Cached usage older than this is refreshed in the background. */
  cacheMaxAgeMs: number;
  /**
   * Cached usage older than `cacheMaxAgeMs` but younger than this still
   * decides. Beyond it the reading is discarded.
   *
   * Freshness used to be a hard gate, which coupled the hook to prompt
   * frequency: a sparse session always arrived to an expired cache and the hook
   * degraded to a pure no-op (median gap for a decision-reaching invocation was
   * 66.7s; for a no-decision one, 340.2s against a 300s TTL). A stale reading is
   * still safe to act on because utilization inside a window only ever RISES —
   * so an old number can under-report and cause a missed switch, but can never
   * invent a breach — and a window whose reset boundary has passed is already
   * discarded as "rolled" by thresholdBreached.
   */
  staleCacheMaxAgeMs?: number;
  /** Minimum gap between repeats of the same degraded notice. */
  noticeIntervalMs?: number;
}

export interface UsageHookDeps {
  /** Active accountUuid of the config dir — re-read after switching. */
  currentAccountUuid(configDir: string): string | undefined;
  readCache(accountUuid: string, maxAgeMs: number): UsageCacheEntry | undefined;
  listIdentities(): Promise<AccountIdentity[]>;
  /** Fire-and-forget background usage refresh; must not block. */
  triggerRefresh(): void;
  performSwitch(profileName: string, configDir: string): Promise<{ liveSessions: number }>;
  readState(): AutoSwitchState | undefined;
  writeState(state: AutoSwitchState): void;
  /**
   * Restart-durable per-account cooldowns. Optional so a caller can opt out;
   * without them the selector still works, it just forgets exhaustion across
   * restarts.
   */
  activeCooldowns?(now: Date): Map<string, string>;
  recordExhaustion?(input: RecordExhaustionInput): void;
  clearExhaustion?(accountUuid: string): void;
  /**
   * Per-reason "last announced at" store backing the notice throttle. Both
   * halves are optional and only take effect together; without them every
   * degraded outcome speaks, which is what a caller that wants no throttling
   * (and every unit test) gets.
   */
  readNotices?(): HookNoticeState | undefined;
  writeNotices?(state: HookNoticeState): void;
  /**
   * Live sessions attached to a config dir. REPORTING ONLY: when the chosen
   * target account is also live in other dirs, the switch message says so.
   *
   * This dep used to power an EXCLUSION — an account live in another dir could
   * not be a switch target at all, because two independent credential copies
   * behind one refresh token end with rotation destroying the loser. The
   * credential broker (`credential-broker.ts`) removed the independent copies:
   * every dir sharing an account now converges on the newest rotation and the
   * refresh happens once, under the account's lock. Sharing an account across
   * sessions is supported, exactly as it is within one config dir.
   */
  liveSessionsIn?(dir: string): number;
  now?: () => Date;
}

export type UsageHookAction = "none" | "refresh-triggered" | "switched" | "switch-failed" | "fail-open";

export interface UsageHookOutcome {
  action: UsageHookAction;
  reason?: string;
  systemMessage?: string;
  additionalContext?: string;
}

/**
 * A stale reading is worth acting on for far longer than it is worth calling
 * fresh. One hour covers the 70-minute no-decision run measured in production
 * without letting a session act on a reading old enough for a 5-hour window to
 * have rolled and been re-consumed.
 */
export const DEFAULT_USAGE_CACHE_STALE_MAX_AGE_MS = 60 * 60 * 1000;

/**
 * Long enough that a persistently degraded hook does not put a line above every
 * prompt; short enough that a session degraded overnight says so more than once.
 */
export const DEFAULT_HOOK_NOTICE_INTERVAL_MS = 15 * 60 * 1000;

/** Stable keys for the notice throttle — never the free-text reason. */
type NoticeKey =
  | "no-account"
  | "no-usage"
  | "cooldown"
  | "all-limited"
  | "no-candidate"
  | "no-door"
  | "fail-open";

/** Path comparison for config dirs, tolerant of trailing separators. */
function sameDir(a: string, b: string): boolean {
  const norm = (v: string) => v.replace(/\/+$/, "");
  return norm(a) === norm(b);
}

function pct(value: number): string {
  return `${Math.round(value)}%`;
}

function minutes(ms: number): string {
  const value = Math.round(ms / 60_000);
  return value === 1 ? "1 minute" : `${value} minutes`;
}

function windowLabel(id: string): string {
  switch (id) {
    case "session":
    case "five_hour":
      return "session limit";
    case "weekly_all":
    case "seven_day":
      return "weekly limit";
    default:
      return `${id} limit`;
  }
}

/**
 * Has this reason been announced recently enough to stay quiet about?
 *
 * Deliberately fail-OPEN in the noisy direction: any problem reading or writing
 * the throttle state means the message is emitted. Losing a warning is worse
 * than repeating one, and this runs inside the hook, so it must never throw.
 */
function announce(opts: UsageHookOptions, deps: UsageHookDeps, key: NoticeKey, now: Date): boolean {
  if (!deps.readNotices || !deps.writeNotices) return true;
  try {
    const state = deps.readNotices() ?? {};
    const last = Date.parse(state[key] ?? "");
    const interval = opts.noticeIntervalMs ?? DEFAULT_HOOK_NOTICE_INTERVAL_MS;
    if (Number.isFinite(last) && now.getTime() - last < interval) return false;
    deps.writeNotices({ ...state, [key]: now.toISOString() });
    return true;
  } catch {
    return true;
  }
}

/** An outcome the user should hear about, subject to the notice throttle. */
function degraded(
  opts: UsageHookOptions,
  deps: UsageHookDeps,
  now: Date,
  key: NoticeKey,
  outcome: UsageHookOutcome & { systemMessage: string },
): UsageHookOutcome {
  if (announce(opts, deps, key, now)) return outcome;
  const { systemMessage: _suppressed, ...quiet } = outcome;
  return quiet;
}

export async function runUsageHook(opts: UsageHookOptions, deps: UsageHookDeps): Promise<UsageHookOutcome> {
  try {
    return await decide(opts, deps);
  } catch (error) {
    // Fail open: the user's prompt always goes through. The error reason is
    // surfaced in the outcome for logging, never as a blocking condition.
    const reason = error instanceof Error ? error.message : String(error);
    const outcome: UsageHookOutcome = { action: "fail-open", reason };
    try {
      // Loud, but throttled — and wrapped so a throttle failure cannot turn
      // fail-open into fail-closed. This is the branch that fired unseen in
      // production against a registry 401 three invocations running.
      const now = (deps.now ?? (() => new Date()))();
      if (announce(opts, deps, "fail-open", now)) {
        outcome.systemMessage =
          `accounts: usage-based auto-switching is NOT running for this session — ${reason}. ` +
          `The session keeps working, but nothing will move it off an account that runs out. ` +
          `Check with \`accounts usage\`.`;
      }
    } catch {
      // Never let the notice path break the fail-open guarantee.
    }
    return outcome;
  }
}

/** Age of a cache entry in ms, or undefined when it carries no usable stamp. */
function cacheAgeMs(entry: UsageCacheEntry, now: Date): number | undefined {
  const fetchedAt = Date.parse(entry.fetchedAt);
  if (!Number.isFinite(fetchedAt)) return undefined;
  return Math.max(0, now.getTime() - fetchedAt);
}

async function decide(opts: UsageHookOptions, deps: UsageHookDeps): Promise<UsageHookOutcome> {
  const now = deps.now ?? (() => new Date());
  const clock = now();
  const staleMaxAgeMs = Math.max(
    opts.staleCacheMaxAgeMs ?? DEFAULT_USAGE_CACHE_STALE_MAX_AGE_MS,
    opts.cacheMaxAgeMs,
  );

  const currentUuid = deps.currentAccountUuid(opts.configDir);
  if (!currentUuid) {
    return degraded(opts, deps, clock, "no-account", {
      action: "fail-open",
      reason: "no readable account in config dir",
      systemMessage:
        `accounts: usage-based auto-switching is NOT running for this session — ` +
        `${opts.configDir} holds no readable Claude account, so there is nothing to measure. ` +
        `Nothing will move this session off an account that runs out.`,
    });
  }

  const cached = deps.readCache(currentUuid, staleMaxAgeMs);
  if (!cached?.usage) {
    // No measurement at all within the stale bound — let the prompt through and
    // warm the cache for the next one. Never block a prompt on the network.
    deps.triggerRefresh();
    return degraded(opts, deps, clock, "no-usage", {
      action: "refresh-triggered",
      reason: cached ? "cached entry has no usage" : "no usage cache within the stale bound",
      systemMessage:
        `accounts: no usage measurement for this session's account within the last ` +
        `${minutes(staleMaxAgeMs)}, so auto-switching cannot decide anything. A refresh was started ` +
        `in the background. If this repeats, the cache warmer is not running: ` +
        `\`accounts usage --refresh --quiet\`.`,
    });
  }

  const ageMs = cacheAgeMs(cached, clock);
  const staleReading = ageMs !== undefined && ageMs > opts.cacheMaxAgeMs;
  // Acting on a stale reading is still worth a background refresh so the NEXT
  // prompt is fresh — the original code only refreshed when it gave up.
  if (staleReading) deps.triggerRefresh();

  // Durable record of THIS account's exhaustion, written before any switch
  // decision. The usage cache expires and a refresh can fail; without a
  // persisted note, a restarted hook re-reads an empty cache and walks straight
  // back onto the account it just fled. Weekly is checked first so the recorded
  // cooldown reflects the days-long verdict rather than the hours-long one.
  const currentWindows = deriveWindowHealth(cached.usage, { now: clock });
  const exhausted =
    (currentWindows.weekly?.exhausted ? currentWindows.weekly : undefined) ??
    currentWindows.unknown.find((w) => w.exhausted) ??
    (currentWindows.session?.exhausted ? currentWindows.session : undefined);
  if (exhausted) {
    deps.recordExhaustion?.({
      accountUuid: currentUuid,
      windowClass: exhausted.windowClass,
      ...(exhausted.resetsAt ? { resetsAt: exhausted.resetsAt } : {}),
      now: clock,
    });
  } else {
    deps.clearExhaustion?.(currentUuid);
  }

  const breach = thresholdBreached(cached.usage, opts.thresholdPercent, clock);
  if (!breach.breached) {
    return { action: "none", reason: staleReading ? "headroom ok (stale reading)" : "headroom ok" };
  }

  const state = deps.readState();
  if (cooldownActive(state, opts.cooldownMs, clock)) {
    const since = Date.parse(state?.lastSwitchAt ?? "");
    const waited = Number.isFinite(since) ? clock.getTime() - since : undefined;
    return degraded(opts, deps, clock, "cooldown", {
      action: "none",
      reason: "cooldown",
      systemMessage:
        `accounts: this session is over its usage threshold but the anti-flap cooldown is still ` +
        `active${waited === undefined ? "" : ` (last attempt ${minutes(waited)} ago)`} — not switching yet. ` +
        `It will retry on a later prompt; \`accounts switch-account\` overrides it now.`,
    });
  }

  const identities = await deps.listIdentities();
  const entries = identities.map((identity) => {
    const entry = deps.readCache(identity.accountUuid, staleMaxAgeMs);
    return { identity, ...(entry?.usage ? { usage: entry.usage } : {}) };
  });

  // An account another dir is running IS a valid target. It used to be
  // excluded here ("contended"): two independent credential copies behind one
  // refresh token ended with rotation blanking the loser, so the hook refused
  // to create the second copy — and on a busy fleet that refusal withheld
  // every healthy account at once ("8 accounts are already being run by
  // another session and cannot be shared"). The credential broker removed the
  // independent copies: `switchAccount` converges the target account to its
  // newest rotation before writing, every sharing dir converges on each
  // prompt, and the refresh itself happens once under the account's
  // cross-process lock (`credential-broker.ts`). Sharing across dirs is now
  // the same regime as the long-supported sharing within one dir.
  const selection = selectHealthiestAccount(entries, {
    currentUuid,
    minHeadroom: opts.minHeadroom,
    ...(opts.minSessionHeadroom !== undefined ? { minSessionHeadroom: opts.minSessionHeadroom } : {}),
    now: clock,
    ...(deps.activeCooldowns ? { cooldowns: deps.activeCooldowns(clock) } : {}),
  });

  const breachedWindow = breach.window!;
  const breachText =
    `${windowLabel(breachedWindow.id)} at ${pct(breachedWindow.utilization)}` +
    (breachedWindow.resetsAt ? ` (resets ${breachedWindow.resetsAt})` : "");

  if (selection.ranked.length === 0) {
    deps.triggerRefresh();
    if (selection.reason === "all-limited") {
      return degraded(opts, deps, clock, "all-limited", {
        action: "none",
        reason: "all-limited",
        systemMessage:
          `accounts: ${breachText}, and all known accounts are limited too ` +
          `(${selection.considered} checked) — no account has headroom to switch to. Staying put.`,
      });
    }
    const detail =
      selection.reason === "no-usage-data"
        ? `no other account has been measured yet (${selection.excluded.length} known)`
        : `no other usable account is registered on this machine`;
    return degraded(opts, deps, clock, "no-candidate", {
      action: "none",
      reason: selection.reason ?? "no-candidate",
      systemMessage:
        `accounts: ${breachText}, and there is nowhere to switch to — ${detail}. ` +
        `This session will hit the wall unless an account is added or measured ` +
        `(\`accounts usage --refresh\`).`,
    });
  }

  // A candidate is only reachable through an own-identity door: a profile dir on
  // THIS machine whose own account is that candidate. The shipped code took the
  // top-ranked candidate alone and gave up when it had none, which measured as
  // `performSwitch` never being called at all while a door-having runner-up sat
  // one rank down — and it gave up silently. Walk the ranking instead.
  let candidate: SwitchCandidate | undefined;
  let door: { profileName?: string } | undefined;
  let doorless = 0;
  for (const entry of selection.ranked) {
    const found = entry.identity.doors
      .filter((d) => d.role === "own-identity" && d.profileName)
      .sort((a, b) => (a.profileName ?? "").localeCompare(b.profileName ?? ""))[0];
    if (found?.profileName) {
      candidate = entry;
      door = found;
      break;
    }
    doorless += 1;
  }

  if (!candidate || !door?.profileName) {
    return degraded(opts, deps, clock, "no-door", {
      action: "none",
      reason: `no candidate has a profile door to switch through (${doorless} skipped)`,
      systemMessage:
        `accounts: ${breachText}, and ${doorless === 1 ? "the one account" : `all ${doorless} accounts`} ` +
        `with headroom cannot be switched to — no profile on this machine owns them. ` +
        `Import or log in to one with \`accounts add\` / \`accounts login\`, or switch manually.`,
    });
  }

  const currentEmail = identities.find((i) => i.accountUuid === currentUuid)?.email ?? currentUuid;
  const targetEmail = candidate.email ?? candidate.accountUuid;

  let liveSessions = 0;
  let switchErrorMessage: string | undefined;
  try {
    liveSessions = (await deps.performSwitch(door.profileName, opts.configDir)).liveSessions;
  } catch (error) {
    switchErrorMessage = error instanceof Error ? error.message : String(error);
  }

  // The one check that converts a silent no-op into a detectable error: the
  // dir must now read as the TARGET account. "Success" without a changed uuid
  // (e.g. two doors onto one account) is a failure.
  const afterUuid = switchErrorMessage ? undefined : deps.currentAccountUuid(opts.configDir);
  const changed = afterUuid === candidate.accountUuid && afterUuid !== currentUuid;

  if (!changed) {
    deps.writeState({
      lastSwitchAt: now().toISOString(),
      fromUuid: currentUuid,
      toUuid: candidate.accountUuid,
      outcome: "failed",
      configDir: opts.configDir,
    });
    const detail =
      switchErrorMessage ??
      (afterUuid === currentUuid
        ? "the active account did not change (same account behind another profile?)"
        : `the dir now reads as ${afterUuid ?? "no account"} instead of the selected target`);
    return {
      action: "switch-failed",
      reason: detail,
      systemMessage:
        `accounts: auto-switch FAILED — ${breachText}; tried to switch this session ` +
        `from ${currentEmail} to ${targetEmail} via profile "${door.profileName}" but ${detail}. ` +
        `The session may hit the usage wall. Run \`accounts usage\` and \`accounts switch-account\` manually.`,
    };
  }

  deps.writeState({
    lastSwitchAt: now().toISOString(),
    fromUuid: currentUuid,
    toUuid: candidate.accountUuid,
    outcome: "switched",
    configDir: opts.configDir,
  });

  const sessionsNote =
    liveSessions > 1
      ? ` ${liveSessions} live sessions share this config dir and ALL of them switched together.`
      : "";
  // Sharing is supported, not silent: a switch onto an account that is also
  // live elsewhere says so, so "two sessions on one account" is always an
  // announced state and never a surprise found in the logs.
  let sharedDirs = 0;
  if (deps.liveSessionsIn) {
    for (const door of candidate.identity.doors) {
      if (sameDir(door.dir, opts.configDir)) continue;
      try {
        if (deps.liveSessionsIn(door.dir) > 0) sharedDirs += 1;
      } catch {
        // A dir we cannot inspect contributes nothing to the note.
      }
    }
  }
  const sharedNote =
    sharedDirs > 0
      ? ` The account is also live in ${sharedDirs} other session dir${sharedDirs === 1 ? "" : "s"}; ` +
        `the accounts credential broker keeps every copy on its newest rotation.`
      : "";
  const staleNote = staleReading
    ? ` (decided from a ${minutes(ageMs ?? 0)}-old usage reading — a fresh one is being fetched)`
    : "";
  // An expired-but-renewable target is a deliberate last resort; say so, because
  // "the switch worked but the next request 401s" is otherwise indistinguishable
  // from the hook misbehaving.
  const renewalNote =
    candidate.identity.credential?.valid === false
      ? ` The target's access token has aged out and needs a token refresh on the next request.`
      : "";
  const skippedNote =
    doorless > 0
      ? ` ${doorless} account${doorless === 1 ? "" : "s"} with more headroom had no profile on this machine to switch through.`
      : "";
  // Report BOTH windows: "80% headroom" hides whether the new account has a
  // healthy week or is one 5-hour roll away from the same wall.
  const message =
    `accounts: auto-switched this session from ${currentEmail} (${breachText}) ` +
    `to ${targetEmail} (${pct(candidate.sessionHeadroom)} session / ` +
    `${pct(candidate.weeklyHeadroom)} weekly headroom)${staleNote}.` +
    `${renewalNote}${sharedNote}${skippedNote}${sessionsNote}`;
  return {
    action: "switched",
    systemMessage: message,
    additionalContext:
      `The Claude account behind this session was switched automatically because the previous account ` +
      `was near its usage limit: ${currentEmail} → ${targetEmail}. The conversation continues unchanged.`,
  };
}

/**
 * stdout payload for Claude Code. systemMessage is shown to the user;
 * additionalContext is injected for the model via hookSpecificOutput.
 */
export function hookOutputJson(outcome: UsageHookOutcome): string | undefined {
  if (!outcome.systemMessage && !outcome.additionalContext) return undefined;
  return JSON.stringify({
    ...(outcome.systemMessage ? { systemMessage: outcome.systemMessage } : {}),
    ...(outcome.additionalContext
      ? {
          hookSpecificOutput: {
            hookEventName: "UserPromptSubmit",
            additionalContext: outcome.additionalContext,
          },
        }
      : {}),
  });
}
