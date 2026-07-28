import { resolveStore, type AccountsStore } from "./store.js";
import { getTool } from "./tools.js";
import {
  accessTokenForAccount,
  buildIdentityIndex,
  type AccountIdentity,
  type AccountStatus,
} from "./identity-index.js";
import {
  readUsageCache,
  selectHealthiestAccount,
  writeUsageCache,
  type SelectionOptions,
  type SelectionResult,
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
        source: "none",
      };
      if (identity.status !== "ok") {
        // Expired / credential-less accounts are REPORTED, never queried and
        // never crashed on — expiry is a state, not an error.
        return base;
      }

      if (!opts.refresh) {
        const cached = readUsageCache(identity.accountUuid, maxAgeMs);
        if (cached?.usage) return { ...base, usage: cached.usage, source: "cache" };
      }

      const token = accessTokenForAccount(identity);
      if (!token) return { ...base, status: "expired" };

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

export interface HealthiestPickResult {
  selection: SelectionResult;
  /** Profile that can serve the selected account (own-identity door). */
  profileName?: string;
  entries: AccountUsageEntry[];
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

  const door = selection.candidate?.identity.doors
    .filter((d) => d.role === "own-identity" && d.profileName)
    .sort((a, b) => (a.profileName ?? "").localeCompare(b.profileName ?? ""))[0];
  return {
    selection,
    ...(door?.profileName ? { profileName: door.profileName } : {}),
    entries,
  };
}
