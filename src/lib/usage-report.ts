import { resolveStore, type AccountsStore } from "./store.js";
import { getTool } from "./tools.js";
import {
  accessTokenForAccount,
  buildIdentityIndex,
  statusWithoutValidAccessToken,
  type AccountIdentity,
  type AccountStatus,
} from "./identity-index.js";
import {
  readUsageCache,
  selectHealthiestAccount,
  writeUsageCache,
  type SelectionOptions,
  type SelectionResult,
  type SwitchCandidate,
} from "./auto-switch.js";
import { fetchAccountUsage, type AccountUsage, type UsageFetchError } from "./usage.js";
import { activeCooldowns, readExhaustionLedger } from "./exhaustion-ledger.js";

/**
 * `accounts usage` collector: one usage query per distinct ACCOUNT (uuid),
 * never per directory — three doors onto one account are one quota and one
 * call. Results are cached per uuid for the hook's cached-only decisions.
 */

export type UsageSource = "cache" | "fetch" | "none";

export interface AccountUsageEntry {
  accountUuid: string;
  email?: string;
  status: AccountStatus;
  /** Profiles whose OWN identity is this account. */
  profiles: string[];
  /** Profiles whose dir currently RUNS as this account (occupancy). */
  occupies: string[];
  /**
   * Profiles this account OWNS but is currently displaced from — another
   * account's credential is in those dirs' live files right now. Always a
   * subset of `profiles`.
   *
   * Reported separately from `status` on purpose. Displacement says nothing
   * about whether the parked credential is alive, and liveness says nothing
   * about who is in the dir; an operator needs both to know whether the fix is
   * `accounts repair-auth` (parked copy is fine, put it back) or a re-login
   * (the account is genuinely dead). Collapsing them is the defect this field
   * exists to close.
   */
  displacedFrom: string[];
  usage?: AccountUsage;
  error?: UsageFetchError;
  source: UsageSource;
}

export interface CollectUsageOptions {
  tool?: string;
  /** Ignore the cache and query the endpoint for every account. */
  refresh?: boolean;
  /** Cache tolerance for reads (ms). */
  maxAgeMs?: number;
  fetchImpl?: typeof fetch;
}

export const DEFAULT_USAGE_CACHE_MAX_AGE_MS = 5 * 60 * 1000;

export async function collectAccountsUsage(
  opts: CollectUsageOptions = {},
  store: AccountsStore = resolveStore(),
): Promise<AccountUsageEntry[]> {
  const toolId = opts.tool ?? "claude";
  const tool = getTool(toolId);
  const profiles = (await store.listProfiles(toolId)).map((p) => ({ name: p.name, dir: p.dir }));
  const identities = buildIdentityIndex(profiles, tool);
  const maxAgeMs = opts.maxAgeMs ?? DEFAULT_USAGE_CACHE_MAX_AGE_MS;

  return Promise.all(
    identities.map(async (identity): Promise<AccountUsageEntry> => {
      const base: AccountUsageEntry = {
        accountUuid: identity.accountUuid,
        ...(identity.email ? { email: identity.email } : {}),
        status: identity.status,
        profiles: doorNames(identity, "own-identity"),
        occupies: doorNames(identity, "current-occupant"),
        displacedFrom: displacedProfileNames(identity),
        source: "none",
      };
      if (identity.status !== "ok") {
        // Only `ok` carries an access token the endpoint will accept, so
        // `needs-refresh` accounts are reported without being queried — the
        // widened STATUS must not widen what gets called. This is not a demotion:
        // `accounts` never mints tokens, so a renewable-but-aged-out credential
        // has nothing to authenticate with until the tool itself renews it.
        // Non-ok accounts are REPORTED, never queried and never crashed on.
        return base;
      }

      if (!opts.refresh) {
        const cached = readUsageCache(identity.accountUuid, maxAgeMs);
        if (cached?.usage) return { ...base, usage: cached.usage, source: "cache" };
      }

      const token = accessTokenForAccount(identity);
      // The index said `ok`, so the file was readable and unexpired when it was
      // scanned; getting nothing back now means it changed underneath us (a
      // concurrent refresh or park rewrites it in place). Downgrade to what the
      // credential can still do rather than to the word for "dead" — the same
      // conflation, one layer up.
      if (!token) {
        return { ...base, status: statusWithoutValidAccessToken(identity.credential) };
      }

      const result = await fetchAccountUsage(token, {
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
      });
      if (result.ok) {
        writeUsageCache({
          accountUuid: identity.accountUuid,
          fetchedAt: result.usage.fetchedAt,
          usage: result.usage,
        });
        return { ...base, usage: result.usage, source: "fetch" };
      }
      writeUsageCache({
        accountUuid: identity.accountUuid,
        fetchedAt: new Date().toISOString(),
        error: result.error,
      });
      return { ...base, error: result.error, source: "fetch" };
    }),
  );
}

function doorNames(identity: AccountIdentity, role: "own-identity" | "current-occupant"): string[] {
  return [...new Set(identity.doors.filter((d) => d.role === role && d.profileName).map((d) => d.profileName!))].sort();
}

/**
 * The door line an operator reads under an account: which profiles own it, which
 * are currently running it, and which it has been displaced from.
 *
 * Exported and pure so the wording is testable without spawning the CLI. Before
 * this, the rendering lived inline in `cli.ts` and the displacement half of the
 * swap was simply missing from the output: a squatted account printed
 * `profiles: account004` with nothing to say that account004's dir was serving
 * somebody else.
 */
export function usageDoorSummary(entry: AccountUsageEntry): string[] {
  const parts: string[] = [];
  if (entry.profiles.length) parts.push(`profiles: ${entry.profiles.join(", ")}`);
  if (entry.occupies.length) parts.push(`running in: ${entry.occupies.join(", ")}`);
  if (entry.displacedFrom.length) parts.push(`displaced from: ${entry.displacedFrom.join(", ")}`);
  return parts;
}

/** Own-identity doors another account is sitting in right now. */
function displacedProfileNames(identity: AccountIdentity): string[] {
  return [
    ...new Set(
      identity.doors
        .filter((d) => d.role === "own-identity" && d.occupiedBy && d.profileName)
        .map((d) => d.profileName!),
    ),
  ].sort();
}

export interface HealthiestPickResult {
  selection: SelectionResult;
  /**
   * The highest-ranked candidate that is actually REACHABLE — i.e. one a
   * profile on this machine owns. Not necessarily `selection.candidate`, which
   * stays the true healthiest account for reporting even when nothing can
   * route to it.
   */
  candidate?: SwitchCandidate;
  /** Profile that can serve `candidate` (own-identity door). */
  profileName?: string;
  /**
   * Candidates skipped because no profile on this machine owns them. Non-zero
   * means the fleet's healthiest account is unreachable by name, which is a
   * different operator problem from "nothing has headroom" and must not be
   * reported as one.
   */
  doorless: number;
  entries: AccountUsageEntry[];
}

/**
 * The profile a candidate can be switched to through, or undefined.
 *
 * ONLY own-identity doors qualify, and that is not an oversight to relax: a
 * `current-occupant` door is a dir whose LIVE files happen to hold this
 * account while the profile's own parked identity is someone else's. Switching
 * to that profile applies the profile's OWN credential, so it would land on a
 * different account than the one selected — the silent no-op this selector
 * exists to prevent. An occupant is made reachable by giving it a profile of
 * its own (`accounts auth adopt`), not by pretending its host is one.
 */
function ownIdentityDoor(candidate: SwitchCandidate): string | undefined {
  return candidate.identity.doors
    .filter((d) => d.role === "own-identity" && d.profileName)
    .sort((a, b) => (a.profileName ?? "").localeCompare(b.profileName ?? ""))[0]?.profileName;
}

/**
 * Non-interactive healthiest-account pick: rank by headroom over the freshest
 * data available (cache within maxAge, else live fetch), then resolve the
 * account to a profile door. No exclusions by identity — switching across all
 * client identities is fine (user-ratified 2026-07-28).
 */
export async function pickHealthiestAccount(
  opts: CollectUsageOptions & SelectionOptions = {},
  store: AccountsStore = resolveStore(),
): Promise<HealthiestPickResult> {
  const toolId = opts.tool ?? "claude";
  const tool = getTool(toolId);
  const entries = await collectAccountsUsage(opts, store);
  const profiles = (await store.listProfiles(toolId)).map((p) => ({ name: p.name, dir: p.dir }));
  const identities = buildIdentityIndex(profiles, tool);
  const byUuid = new Map(identities.map((i) => [i.accountUuid, i]));
  const now = opts.now ?? new Date();

  const selection = selectHealthiestAccount(
    entries
      .filter((e) => byUuid.has(e.accountUuid))
      .map((e) => ({
        identity: byUuid.get(e.accountUuid)!,
        ...(e.usage ? { usage: e.usage } : {}),
      })),
    {
      ...(opts.currentUuid ? { currentUuid: opts.currentUuid } : {}),
      ...(opts.minHeadroom !== undefined ? { minHeadroom: opts.minHeadroom } : {}),
      ...(opts.minSessionHeadroom !== undefined
        ? { minSessionHeadroom: opts.minSessionHeadroom }
        : {}),
      now,
      // Default to the same durable ledger the hook writes. Without this,
      // `accounts pick --healthiest` happily recommends the account the hook
      // just fled, and the CLI and the hook disagree about the same pool.
      cooldowns: opts.cooldowns ?? activeCooldowns(readExhaustionLedger(), now),
    },
  );

  // WALK THE RANKING, do not stop at the winner. `selection.candidate` is
  // `ranked[0]`, and an account can be eligible on headroom yet owned by no
  // profile on this machine — the measured case is an account that exists only
  // as the current occupant of ANOTHER profile's dir (`profiles: []`). Taking
  // rank 1 alone let one nameless account veto the whole selection while a
  // reachable runner-up sat one place down, and reported it as "no eligible
  // account was found", which is false. usage-hook.ts already walks; this is
  // the same rule on the CLI path, so the two agree about one pool.
  let candidate: SwitchCandidate | undefined;
  let profileName: string | undefined;
  let doorless = 0;
  for (const entry of selection.ranked) {
    const door = ownIdentityDoor(entry);
    if (door) {
      candidate = entry;
      profileName = door;
      break;
    }
    doorless += 1;
  }

  return {
    selection,
    ...(candidate ? { candidate } : {}),
    ...(profileName ? { profileName } : {}),
    doorless,
    entries,
  };
}
