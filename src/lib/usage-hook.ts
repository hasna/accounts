import type { AccountIdentity } from "./identity-index.js";
import {
  cooldownActive,
  selectHealthiestAccount,
  thresholdBreached,
  type AutoSwitchState,
  type UsageCacheEntry,
} from "./auto-switch.js";

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
 */

export interface UsageHookOptions {
  /** The session's Claude config dir (CLAUDE_CONFIG_DIR or the live default). */
  configDir: string;
  /** Switch when any unscoped window is at/over this percent used. */
  thresholdPercent: number;
  /** A target account must have at least this much headroom. */
  minHeadroom: number;
  /** No second auto-switch (or retry of a failed one) within this window. */
  cooldownMs: number;
  /** Cached usage older than this is treated as absent. */
  cacheMaxAgeMs: number;
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
  now?: () => Date;
}

export type UsageHookAction = "none" | "refresh-triggered" | "switched" | "switch-failed" | "fail-open";

export interface UsageHookOutcome {
  action: UsageHookAction;
  reason?: string;
  systemMessage?: string;
  additionalContext?: string;
}

function pct(value: number): string {
  return `${Math.round(value)}%`;
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

export async function runUsageHook(opts: UsageHookOptions, deps: UsageHookDeps): Promise<UsageHookOutcome> {
  try {
    return await decide(opts, deps);
  } catch (error) {
    // Fail open: the user's prompt always goes through. The error reason is
    // surfaced in the outcome for logging, never as a blocking condition.
    return {
      action: "fail-open",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

async function decide(opts: UsageHookOptions, deps: UsageHookDeps): Promise<UsageHookOutcome> {
  const now = deps.now ?? (() => new Date());

  const currentUuid = deps.currentAccountUuid(opts.configDir);
  if (!currentUuid) return { action: "fail-open", reason: "no readable account in config dir" };

  const cached = deps.readCache(currentUuid, opts.cacheMaxAgeMs);
  if (!cached?.usage) {
    // No (fresh) measurement — let the prompt through and warm the cache for
    // the next one. Never block a prompt on the network.
    deps.triggerRefresh();
    return { action: "refresh-triggered", reason: cached ? "cached entry has no usage" : "no fresh cache" };
  }

  const breach = thresholdBreached(cached.usage, opts.thresholdPercent);
  if (!breach.breached) return { action: "none", reason: "headroom ok" };

  const state = deps.readState();
  if (cooldownActive(state, opts.cooldownMs, now())) {
    return { action: "none", reason: "cooldown" };
  }

  const identities = await deps.listIdentities();
  const entries = identities.map((identity) => {
    const entry = deps.readCache(identity.accountUuid, opts.cacheMaxAgeMs);
    return { identity, ...(entry?.usage ? { usage: entry.usage } : {}) };
  });
  const selection = selectHealthiestAccount(entries, {
    currentUuid,
    minHeadroom: opts.minHeadroom,
  });

  const breachedWindow = breach.window!;
  const breachText =
    `${windowLabel(breachedWindow.id)} at ${pct(breachedWindow.utilization)}` +
    (breachedWindow.resetsAt ? ` (resets ${breachedWindow.resetsAt})` : "");

  if (!selection.candidate) {
    deps.triggerRefresh();
    if (selection.reason === "all-limited") {
      return {
        action: "none",
        reason: "all-limited",
        systemMessage:
          `accounts: ${breachText}, and all known accounts are limited too ` +
          `(${selection.considered} checked) — no account has headroom to switch to. Staying put.`,
      };
    }
    return { action: "none", reason: selection.reason ?? "no-candidate" };
  }

  const candidate = selection.candidate;
  const door = candidate.identity.doors
    .filter((d) => d.role === "own-identity" && d.profileName)
    .sort((a, b) => (a.profileName ?? "").localeCompare(b.profileName ?? ""))[0];
  if (!door?.profileName) {
    return { action: "none", reason: "candidate has no profile door to switch through" };
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
  });

  const sessionsNote =
    liveSessions > 1
      ? ` ${liveSessions} live sessions share this config dir and ALL of them switched together.`
      : "";
  const message =
    `accounts: auto-switched this session from ${currentEmail} (${breachText}) ` +
    `to ${targetEmail} (${pct(candidate.headroom)} headroom).${sessionsNote}`;
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
