import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";
import {
  CREDENTIALS_SNAPSHOT,
  OAUTH_SNAPSHOT,
  profileAccountJsonPaths,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
} from "./claude-layout.js";
import { centralAuthRoot, isAccountUuid } from "./auth-store.js";

/**
 * UUID-keyed account enumeration. Directories are DOORS; accounts are the
 * THING: several profile dirs routinely hold the same OAuth account (imports,
 * in-place switches), so anything that reasons about quota, selection, or
 * "switch to a fresh account" must be keyed on `oauthAccount.accountUuid` —
 * a directory-keyed selector can "switch" between two doors of the same
 * exhausted account and report success while nothing changed.
 *
 * All reads go through this module so the auth-store migration (per-profile
 * `.accounts-auth/` → central `~/.hasna/accounts/auth/<accountUuid>/`, task
 * 7840d1da) changes ONE implementation, not call sites: the central home is
 * read first, per-profile stores remain as fallback for the compat window.
 */

export type AccountDoorRole = "own-identity" | "current-occupant";

export interface AccountDoor {
  dir: string;
  role: AccountDoorRole;
  profileName?: string;
  email?: string;
}

export type CredentialSource = "central" | "profile-snapshot" | "dir-live";

export interface AccountCredentialRef {
  /** File holding the claudeAiOauth payload; the token itself is read lazily. */
  path: string;
  source: CredentialSource;
  expiresAt: number;
  hasAccessToken: boolean;
  hasRefreshToken: boolean;
  /** Usable AS IS: an unexpired access token. */
  valid: boolean;
  /**
   * Usable AFTER the tool renews it: a refresh token is present, so an aged-out
   * access token is a stale artefact rather than a dead account.
   *
   * Measured on this fleet 2026-07-29: Claude Code mints 8-hour access tokens
   * and renews them IN PLACE. One profile dir was observed holding
   * `expiresAt = 05:43:02Z` at 05:23Z and `expiresAt = 13:38:04Z` at 05:38Z —
   * same file, same account, a fresh 8-hour token written over the old one
   * without any operator action. An access token past its expiry therefore says
   * nothing about whether the account works; only the refresh token does.
   *
   * `renewable` never OUTRANKS `valid` anywhere it is consumed: it widens the
   * usable set, it does not reorder it.
   */
  renewable: boolean;
}

export type AccountStatus = "ok" | "expired" | "no-credentials";

export interface AccountIdentity {
  accountUuid: string;
  email?: string;
  doors: AccountDoor[];
  /** Best credential across every store that pairs with this uuid. */
  credential?: AccountCredentialRef;
  status: AccountStatus;
}

// Central store paths are owned by auth-store.ts (which also validates uuids
// on the write side); this module only re-exports them for its callers.
export { centralAuthDir, centralAuthRoot } from "./auth-store.js";

type JsonRecord = Record<string, unknown>;

function readJson(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as JsonRecord) : undefined;
  } catch {
    return undefined;
  }
}

interface OAuthIdentity {
  accountUuid: string;
  email?: string;
}

function oauthIdentityFrom(record: JsonRecord | undefined): OAuthIdentity | undefined {
  const oauth = record?.oauthAccount;
  if (!oauth || typeof oauth !== "object") return undefined;
  const { accountUuid, emailAddress } = oauth as JsonRecord;
  if (typeof accountUuid !== "string" || !accountUuid) return undefined;
  return {
    // Lowercase well-formed uuids so case-variant spellings of one account
    // dedupe into a single identity; malformed values pass through as-is —
    // they are still shown to diagnostics, but must never reach the central
    // path helpers (which throw): guard with isAccountUuid first.
    accountUuid: isAccountUuid(accountUuid) ? accountUuid.toLowerCase() : accountUuid,
    ...(typeof emailAddress === "string" && emailAddress ? { email: emailAddress } : {}),
  };
}

function credentialRef(path: string, source: CredentialSource): AccountCredentialRef | undefined {
  const raw = readJson(path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return undefined;
  const record = oauth as JsonRecord;
  const hasAccessToken = typeof record.accessToken === "string" && record.accessToken.length > 0;
  const hasRefreshToken = typeof record.refreshToken === "string" && record.refreshToken.length > 0;
  const expiresAtRaw = record.expiresAt;
  const expiresAt =
    typeof expiresAtRaw === "number"
      ? expiresAtRaw
      : typeof expiresAtRaw === "string"
        ? Date.parse(expiresAtRaw)
        : 0;
  const normalizedExpiry = Number.isFinite(expiresAt) ? expiresAt : 0;
  return {
    path,
    source,
    expiresAt: normalizedExpiry,
    hasAccessToken,
    hasRefreshToken,
    valid: hasAccessToken && normalizedExpiry > Date.now(),
    renewable: hasRefreshToken,
  };
}

/**
 * Can this account take a session over — now, or after the tool renews it?
 *
 * `status === "expired"` is not a verdict of unusable: it means the ACCESS
 * token aged out, which on a fleet that idles overnight is the majority state
 * (access tokens live 8 hours). Excluding those shrinks the switch pool exactly
 * when unattended sessions need it, so the pool is "valid OR renewable" and
 * ranking — not filtering — keeps valid credentials first.
 *
 * A credential with no refresh token is still unusable. That distinction is the
 * whole point: `needs-refresh` and `unusable` are different verdicts.
 */
export function isUsableIdentity(identity: AccountIdentity): boolean {
  // Status-led on purpose, so this is a strict SUPERSET of the rule it
  // replaces (`status === "ok"`): everything that was usable stays usable, and
  // the aged-out-but-refreshable case is added. A widening fix must not be able
  // to narrow anything by accident.
  if (identity.status === "ok") return true;
  return identity.status === "expired" && identity.credential?.renewable === true;
}

const SOURCE_RANK: Record<CredentialSource, number> = { central: 3, "profile-snapshot": 2, "dir-live": 1 };

/**
 * Valid beats invalid; later expiry beats earlier; central store breaks ties.
 *
 * Deliberately DIFFERENT from auth-store's `betterCredential`: this ranking
 * answers "which credential can a caller USE right now" (selection), while
 * `betterCredential` answers "which bytes must SURVIVE a sync/restore"
 * (refresh-token presence and write recency first, because restoring a
 * rotated-out refresh token logs the account out). Do not unify them.
 */
function betterCredentialRef(a: AccountCredentialRef, b: AccountCredentialRef): AccountCredentialRef {
  if (a.valid !== b.valid) return a.valid ? a : b;
  if (a.expiresAt !== b.expiresAt) return a.expiresAt > b.expiresAt ? a : b;
  if (a.hasRefreshToken !== b.hasRefreshToken) return a.hasRefreshToken ? a : b;
  return SOURCE_RANK[a.source] >= SOURCE_RANK[b.source] ? a : b;
}

interface MutableIdentity {
  accountUuid: string;
  email?: string;
  doors: AccountDoor[];
  credential?: AccountCredentialRef;
}

function record(
  byUuid: Map<string, MutableIdentity>,
  identity: OAuthIdentity,
  door: AccountDoor | undefined,
  credential: AccountCredentialRef | undefined,
): void {
  let entry = byUuid.get(identity.accountUuid);
  if (!entry) {
    entry = { accountUuid: identity.accountUuid, doors: [] };
    byUuid.set(identity.accountUuid, entry);
  }
  if (!entry.email && identity.email) entry.email = identity.email;
  if (door && !entry.doors.some((d) => d.dir === door.dir && d.role === door.role)) {
    entry.doors.push(door);
  }
  if (credential) {
    entry.credential = entry.credential ? betterCredentialRef(entry.credential, credential) : credential;
  }
}

/**
 * Enumerate every account we know about, deduplicated by accountUuid.
 *
 * Identity/credential pairing is per LAYER — each layer pairs an identity file
 * with the credential file written alongside it, so a dir whose live files were
 * switched to another account can never attribute the guest's token to the
 * dir's own uuid:
 *  - central:   auth/<uuid>/oauth-account.json + auth/<uuid>/credentials.json
 *  - snapshot:  .accounts-auth/oauth-account.json + .accounts-auth/credentials.json
 *  - dir-live:  .claude.json#oauthAccount + .credentials.json
 */
export function buildIdentityIndex(
  profiles: ReadonlyArray<{ name?: string; dir: string }>,
  tool: ToolDef,
): AccountIdentity[] {
  const byUuid = new Map<string, MutableIdentity>();

  // Central home first: the post-migration source of truth, and the only
  // place that knows accounts with no profile door at all.
  const centralRoot = centralAuthRoot();
  if (existsSync(centralRoot)) {
    for (const entry of readdirSync(centralRoot)) {
      // Strict-uuid parity with listCentralAccounts: a planted non-uuid dir
      // must not become an identity (and must never reach path helpers that
      // throw on malformed uuids).
      if (!isAccountUuid(entry)) continue;
      const dir = join(centralRoot, entry);
      try {
        if (!statSync(dir).isDirectory()) continue;
      } catch {
        continue;
      }
      const identity = oauthIdentityFrom(readJson(join(dir, OAUTH_SNAPSHOT)));
      // The store writes lowercased dir names; tolerate case-variant payloads.
      if (!identity || identity.accountUuid !== entry.toLowerCase()) continue;
      record(byUuid, identity, undefined, credentialRef(join(dir, CREDENTIALS_SNAPSHOT), "central"));
    }
  }

  for (const profile of profiles) {
    const { dir } = profile;
    if (!existsSync(dir)) continue;

    // Layer B — the dir's OWN identity (survives in-place switches away).
    const own = oauthIdentityFrom(readJson(profileOAuthSnapshot(dir)));
    if (own) {
      record(
        byUuid,
        own,
        {
          dir,
          role: "own-identity",
          ...(profile.name ? { profileName: profile.name } : {}),
          ...(own.email ? { email: own.email } : {}),
        },
        credentialRef(profileCredentialsSnapshot(dir), "profile-snapshot"),
      );
    }

    // Layer A — whoever's account currently occupies the dir's live files.
    const livePaths = profileAccountJsonPaths(dir, tool);
    const occupant = oauthIdentityFrom(livePaths.length > 0 ? readJson(livePaths[0]!) : undefined);
    if (occupant) {
      record(
        byUuid,
        occupant,
        {
          dir,
          role: "current-occupant",
          ...(profile.name ? { profileName: profile.name } : {}),
          ...(occupant.email ? { email: occupant.email } : {}),
        },
        credentialRef(join(dir, ".credentials.json"), "dir-live"),
      );
    }
  }

  return [...byUuid.values()]
    .map((entry) => ({
      accountUuid: entry.accountUuid,
      ...(entry.email ? { email: entry.email } : {}),
      doors: entry.doors,
      ...(entry.credential ? { credential: entry.credential } : {}),
      status: (entry.credential
        ? entry.credential.valid
          ? "ok"
          : "expired"
        : "no-credentials") as AccountStatus,
    }))
    .sort((a, b) => a.accountUuid.localeCompare(b.accountUuid));
}

/** The accountUuid currently occupying a config dir's live account file. */
export function dirAccountUuid(dir: string, tool: ToolDef): string | undefined {
  const paths = profileAccountJsonPaths(dir, tool);
  if (paths.length === 0) return undefined;
  return oauthIdentityFrom(readJson(paths[0]!))?.accountUuid;
}

/**
 * The account's current access token, or undefined when none is valid. Read
 * lazily from the winning credential file so index building never holds
 * secrets in memory longer than a caller needs.
 */
export function accessTokenForAccount(identity: AccountIdentity): string | undefined {
  if (!identity.credential?.valid) return undefined;
  const raw = readJson(identity.credential.path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return undefined;
  const token = (oauth as JsonRecord).accessToken;
  return typeof token === "string" && token ? token : undefined;
}
