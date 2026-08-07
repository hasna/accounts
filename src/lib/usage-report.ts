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
import { ensureFreshIdentityCredential } from "./credential-broker.js";
import { activeCooldowns, readExhaustionLedger } from "./exhaustion-ledger.js";
import { deriveWindowHealth } from "./usage-windows.js";
import {
  getAccountsReadiness,
  type AccountsProfileReadiness,
  type AccountsReadinessStatus,
} from "./readiness.js";
import { readSwitchedAccountMarker } from "./claude-auth.js";
import { sameConfigDir } from "./safe-path.js";
import {
  scanToolProcessesWithAvailability,
  type ProcessInfo,
  type ProcessScanner,
  type ProcessScanResult,
} from "./agents.js";
import type { Profile } from "../types.js";

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
  /** Return cache misses as unknown instead of querying the provider. */
  cachedOnly?: boolean;
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
      // `expired` (no refresh token) and `no-credentials` are genuinely dead:
      // reported, never queried, never crashed on. `needs-refresh` is NOT dead
      // — its access token aged out but its refresh token is intact — so it is
      // handled below on the refresh path rather than dropped here.
      if (identity.status !== "ok" && identity.status !== "needs-refresh") {
        return base;
      }

      if (!opts.refresh) {
        // The cache-only path is OFFLINE: it never mints a token and never
        // queries the provider. A `needs-refresh` account has an aged-out
        // access token, so with no fresh cache it stays unmeasured HERE — the
        // warmer's `--refresh` path below is what mints a token and measures it.
        const cached = readUsageCache(identity.accountUuid, maxAgeMs);
        if (cached?.usage) return { ...base, usage: cached.usage, source: "cache" };
        if (identity.status !== "ok" || opts.cachedOnly) return base;
      }

      // REFRESH-THEN-FETCH. A `needs-refresh` account cannot authenticate the
      // usage endpoint with its aged-out access token, so it was previously
      // reported unmeasurable (readiness-proxy / no-cached-rate-limit-data) even
      // under `--refresh` (task d3845278). Mint a fresh access token FIRST —
      // once, under the account's identity lock, converging the single-inode
      // model before it writes (no second credential copy). This runs in the
      // warmer's env OUTSIDE any session, and only for an account whose token is
      // already aged out, so it is a scoped refresh-for-MEASUREMENT, not the
      // blanket proactive refresh that was mitigated on the in-session hook and
      // the credential-broker cron.
      let queryIdentity = identity;
      if (opts.refresh && identity.status === "needs-refresh") {
        try {
          const fresh = await ensureFreshIdentityCredential(identity.accountUuid, {
            tool,
            profiles,
            ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
          });
          // Re-derive the identity from the world the exchange just created:
          // ensureFresh wrote the rotated credential to the central snapshot and
          // fanned it out, so the fresh access token is visible to a rebuilt
          // index. `refreshed` OR a converged winner can both make it usable.
          const rebuilt = fresh.winner
            ? buildIdentityIndex(profiles, tool).find(
                (candidate) => candidate.accountUuid === identity.accountUuid,
              )
            : undefined;
          if (rebuilt) queryIdentity = rebuilt;
          if (queryIdentity.status !== "ok") {
            // No usable access token after the attempt (no refresh token, or the
            // exchange failed). Report the account without querying — fail-safe,
            // never a crash.
            return { ...base, status: queryIdentity.status };
          }
        } catch {
          // One account's refresh failure must never take down usage collection
          // for the rest of the fleet.
          return base;
        }
      }

      const token = accessTokenForAccount(queryIdentity);
      // The index said `ok`, so the file was readable and unexpired when it was
      // scanned; getting nothing back now means it changed underneath us (a
      // concurrent refresh or park rewrites it in place). Downgrade to what the
      // credential can still do rather than to the word for "dead" — the same
      // conflation, one layer up.
      if (!token) {
        return { ...base, status: statusWithoutValidAccessToken(queryIdentity.credential) };
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
        return { ...base, status: queryIdentity.status, usage: result.usage, source: "fetch" };
      }
      writeUsageCache({
        accountUuid: identity.accountUuid,
        fetchedAt: new Date().toISOString(),
        error: result.error,
      });
      return { ...base, status: queryIdentity.status, error: result.error, source: "fetch" };
    }),
  );
}

export type ProfileUsageAvailability =
  | {
      kind: "rate-limit";
      source: "cache" | "fetch";
      fetchedAt: string;
      sessionHeadroom: number | null;
      weeklyHeadroom: number | null;
    }
  | {
      kind: "readiness-proxy";
      status: AccountsReadinessStatus;
      reason: "no-cached-rate-limit-data" | "provider-rate-limit-unavailable";
    }
  | {
      kind: "unknown";
      reason: "profile-readiness-unavailable";
    };

export type ProfileOccupancy = {
  status: "occupied" | "vacant" | "unknown";
  scanAvailable: boolean;
  processCount: number;
  /** Tool processes that could not be attributed to any registered profile. */
  unattributedProcessCount: number;
};

export type ProfileLaunchability = {
  status: "yes" | "no" | "unknown";
  reason:
    | "ready"
    | "provider-unavailable"
    | "profile-directory-missing"
    | "profile-directory-occupied"
    | "profile-unavailable"
    | "auth-unavailable"
    | "auth-renewable"
    | "auth-not-locally-verifiable"
    | "profile-readiness-unavailable";
};

/**
 * Safe, operator-facing row for the cross-tool usage view. Deliberately omits
 * config paths, process commands, auth payloads, and provider responses: the
 * coordinator needs selection signals, not the underlying credential surface.
 */
export interface ProfileUsageEntry {
  name: string;
  tool: string;
  usage: ProfileUsageAvailability;
  lastSwitchAt: string | null;
  lastSwitchSource: "profile-selection" | "in-place-switch" | "unknown";
  occupancy: ProfileOccupancy;
  active: boolean;
  applied: boolean;
  launchable: ProfileLaunchability;
}

export interface ProfilesUsageReport {
  schema: "hasna.accounts.usage-profiles/v1";
  generatedAt: string;
  profiles: ProfileUsageEntry[];
  /** Existing Claude account-level data retained for backwards compatibility. */
  accounts: AccountUsageEntry[];
}

export interface CollectProfilesUsageOptions {
  /** Filter the registered profile view to one tool. */
  tool?: string;
  /** Explicitly refresh provider usage. Default is cache-only. */
  refresh?: boolean;
  maxAgeMs?: number;
  fetchImpl?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  processScanner?: ProcessScanner;
}

function readinessKey(tool: string, name: string): string {
  return `${tool}\0${name}`;
}

function latestSwitch(profile: Profile): Pick<ProfileUsageEntry, "lastSwitchAt" | "lastSwitchSource"> {
  const selectedAt = profile.lastUsedAt;
  const switchedAt =
    profile.tool === "claude" ? readSwitchedAccountMarker(profile.dir)?.switchedAt : undefined;
  const selectedMs = selectedAt ? Date.parse(selectedAt) : Number.NaN;
  const switchedMs = switchedAt ? Date.parse(switchedAt) : Number.NaN;

  if (Number.isFinite(switchedMs) && (!Number.isFinite(selectedMs) || switchedMs > selectedMs)) {
    return { lastSwitchAt: switchedAt!, lastSwitchSource: "in-place-switch" };
  }
  if (selectedAt) return { lastSwitchAt: selectedAt, lastSwitchSource: "profile-selection" };
  if (switchedAt) return { lastSwitchAt: switchedAt, lastSwitchSource: "in-place-switch" };
  return { lastSwitchAt: null, lastSwitchSource: "unknown" };
}

function profileUsageAvailability(
  profile: Profile,
  readiness: AccountsProfileReadiness | undefined,
  account: AccountUsageEntry | undefined,
  now: Date,
): ProfileUsageAvailability {
  if (account?.usage) {
    const health = deriveWindowHealth(account.usage, { now });
    return {
      kind: "rate-limit",
      source: account.source === "fetch" ? "fetch" : "cache",
      fetchedAt: account.usage.fetchedAt,
      // A missing window is UNKNOWN, not 100% headroom. deriveWindowHealth's
      // 100 defaults are ranking identities and must not become measurements.
      sessionHeadroom: health.session ? health.sessionHeadroom : null,
      weeklyHeadroom:
        health.weekly || health.unknown.length > 0 ? health.weeklyHeadroom : null,
    };
  }
  if (!readiness) return { kind: "unknown", reason: "profile-readiness-unavailable" };
  return {
    kind: "readiness-proxy",
    status: readiness.status,
    reason:
      profile.tool === "claude"
        ? "no-cached-rate-limit-data"
        : "provider-rate-limit-unavailable",
  };
}

function profileLaunchability(
  readiness: AccountsProfileReadiness | undefined,
  providerAvailable: boolean | undefined,
): ProfileLaunchability {
  if (!readiness) {
    return { status: "unknown", reason: "profile-readiness-unavailable" };
  }
  if (providerAvailable === false) return { status: "no", reason: "provider-unavailable" };
  if (!readiness.dir.exists) return { status: "no", reason: "profile-directory-missing" };
  if (readiness.login.dirOccupiedByAnotherAccount) {
    return { status: "no", reason: "profile-directory-occupied" };
  }
  if (readiness.status === "unavailable") {
    return { status: "no", reason: "profile-unavailable" };
  }
  if (readiness.login.validator !== "claude-auth-snapshot") {
    return { status: "unknown", reason: "auth-not-locally-verifiable" };
  }
  if (readiness.login.valid) return { status: "yes", reason: "ready" };
  if (readiness.login.renewable) return { status: "yes", reason: "auth-renewable" };
  return { status: "no", reason: "auth-unavailable" };
}

function profileOccupancy(
  profile: Profile,
  processes: readonly ProcessInfo[],
  profilesForTool: readonly Profile[],
  scanAvailable: boolean,
): ProfileOccupancy {
  const processCount = processes.filter(
    (process) => process.configDir && sameConfigDir(process.configDir, profile.dir),
  ).length;
  const unattributedProcessCount = processes.filter(
    (process) =>
      !process.configDir ||
      !profilesForTool.some((candidate) => sameConfigDir(candidate.dir, process.configDir!)),
  ).length;
  if (!scanAvailable) {
    return { status: "unknown", scanAvailable: false, processCount: 0, unattributedProcessCount: 0 };
  }
  return {
    status: processCount > 0 ? "occupied" : unattributedProcessCount > 0 ? "unknown" : "vacant",
    scanAvailable: true,
    processCount,
    unattributedProcessCount,
  };
}

/**
 * Build one fast cross-tool view. The default path is cache-only for provider
 * usage and runs one generic process scan per represented tool; it never
 * invokes a provider once per profile. `refresh` is the explicit network gate
 * and still queries Claude once per distinct account via collectAccountsUsage.
 */
export async function collectProfilesUsage(
  opts: CollectProfilesUsageOptions = {},
  store: AccountsStore = resolveStore(opts.env),
): Promise<ProfilesUsageReport> {
  const now = opts.now ?? new Date();
  if (opts.tool) await store.resolveTool(opts.tool);

  const [profiles, readiness, accounts] = await Promise.all([
    store.listProfiles(opts.tool),
    getAccountsReadiness({ env: opts.env, now, store }),
    opts.tool && opts.tool !== "claude"
      ? Promise.resolve([])
      : collectAccountsUsage(
          {
            tool: "claude",
            ...(opts.refresh ? { refresh: true } : { cachedOnly: true }),
            ...(opts.maxAgeMs !== undefined ? { maxAgeMs: opts.maxAgeMs } : {}),
            ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
          },
          store,
        ),
  ]);

  const readinessByProfile = new Map(
    readiness.profiles.map((entry) => [readinessKey(entry.tool, entry.name), entry]),
  );
  const providerAvailableByTool = new Map(
    readiness.providers.map((provider) => [provider.id, provider.available]),
  );
  const claudeAccountByProfile = new Map<string, AccountUsageEntry>();
  for (const account of accounts) {
    for (const name of account.profiles) claudeAccountByProfile.set(name, account);
  }

  const profilesByTool = new Map<string, Profile[]>();
  for (const profile of profiles) {
    const entries = profilesByTool.get(profile.tool) ?? [];
    entries.push(profile);
    profilesByTool.set(profile.tool, entries);
  }
  const scanner = opts.processScanner ?? scanToolProcessesWithAvailability;
  const processesByTool = new Map<string, ProcessInfo[]>();
  const scanFailedTools = new Set<string>();
  for (const tool of profilesByTool.keys()) {
    try {
      const scanned = scanner(tool);
      const result: ProcessScanResult = Array.isArray(scanned)
        ? { available: true, processes: scanned }
        : scanned;
      if (!result.available) scanFailedTools.add(tool);
      processesByTool.set(tool, result.processes);
    } catch {
      scanFailedTools.add(tool);
      processesByTool.set(tool, []);
    }
  }

  return {
    schema: "hasna.accounts.usage-profiles/v1",
    generatedAt: now.toISOString(),
    profiles: profiles
      .slice()
      .sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name))
      .map((profile) => {
        const profileReadiness = readinessByProfile.get(readinessKey(profile.tool, profile.name));
        return {
          name: profile.name,
          tool: profile.tool,
          usage: profileUsageAvailability(
            profile,
            profileReadiness,
            profile.tool === "claude" ? claudeAccountByProfile.get(profile.name) : undefined,
            now,
          ),
          ...latestSwitch(profile),
          occupancy: profileOccupancy(
            profile,
            processesByTool.get(profile.tool) ?? [],
            profilesByTool.get(profile.tool) ?? [],
            !scanFailedTools.has(profile.tool),
          ),
          active: profileReadiness?.active ?? false,
          applied: profileReadiness?.applied ?? false,
          launchable: profileLaunchability(
            profileReadiness,
            providerAvailableByTool.get(profile.tool),
          ),
        };
      }),
    accounts,
  };
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
