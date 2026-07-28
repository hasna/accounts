// Central, identity-keyed auth-snapshot store.
//
// `~/.hasna/accounts/auth/<accountUuid>/{credentials.json,oauth-account.json}`
// is the canonical home for an account's auth snapshot. The account uuid is the
// stable identity; profile config dirs are not — they get deleted, renamed and
// rebound while the account lives on, and (worse) the legacy per-profile store
// `.accounts-auth/` sits INSIDE $CLAUDE_CONFIG_DIR, a namespace Claude Code
// owns, not us.
//
// Compatibility window (introduced 0.2.16): binaries <= 0.2.15 read and rotate
// the per-profile `.accounts-auth/` files only. So this release:
//   - WRITES both: every per-profile snapshot write is mirrored here;
//   - READS best-of-both: credential reads compare the central and per-profile
//     copies with `betterCredential` and use the winner. Deliberately NOT
//     "central first": an old binary may have rotated a fresher token into the
//     per-profile copy, and restoring a stale central token would log the
//     account out (rotated-out refresh tokens are revoked server-side).
//   - NEVER deletes a per-profile `.accounts-auth/` directory.
// The mirror writes can only be dropped once every fleet machine runs >= 0.2.16
// and central hashes have been observed advancing through a full rotation
// cycle; even then, legacy dirs are removed only by an explicit sweep verb.
//
// This module is a lower layer than claude-auth.ts (which imports it); it must
// not import claude-auth.ts.

import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";
import { accountsHome, loadStore } from "../storage.js";
import type { ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  profileAccountJsonPaths,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
  profileSwitchedAccountMarker,
} from "./claude-layout.js";
import { assertSafeWritePath, writeFileAtomic } from "./safe-path.js";

type JsonRecord = Record<string, unknown>;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const CENTRAL_AUTH_DIR_NAME = "auth";
export const CENTRAL_AUTH_TRASH_DIR_NAME = "auth-trash";

function readJsonFile(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
  } catch {
    return undefined;
  }
}

/** Root of the central store: `<accountsHome>/auth`. */
export function centralAuthRoot(): string {
  return join(accountsHome(), CENTRAL_AUTH_DIR_NAME);
}

/**
 * The account uuid becomes a path segment, so it is validated strictly: a
 * hostile oauth-account.json must not be able to steer writes outside the
 * store (e.g. `accountUuid: "../../evil"`).
 */
function assertAccountUuid(accountUuid: string): string {
  if (!UUID_RE.test(accountUuid)) {
    throw new AccountsError(`invalid account uuid for central auth store: ${JSON.stringify(accountUuid)}`);
  }
  return accountUuid;
}

export function centralAuthDir(accountUuid: string): string {
  return join(centralAuthRoot(), assertAccountUuid(accountUuid));
}

export function centralOAuthSnapshot(accountUuid: string): string {
  return join(centralAuthDir(accountUuid), "oauth-account.json");
}

export function centralCredentialsSnapshot(accountUuid: string): string {
  return join(centralAuthDir(accountUuid), "credentials.json");
}

// --- credential health ordering ---------------------------------------------
// Moved here from claude-auth.ts (which re-exports the behaviour through its
// own read paths) so both layers rank credentials with the same rule and no
// import cycle forms.

export interface CredentialHealthPresent {
  exists: true;
  expiresAt: number;
  refreshTokenLength: number;
  mtimeMs: number;
}

export type CredentialHealth = { exists: false } | CredentialHealthPresent;

export function credentialHealth(path: string): CredentialHealth {
  if (!existsSync(path)) return { exists: false };
  const mtimeMs = statSync(path).mtimeMs;
  const raw = readJsonFile(path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") {
    return { exists: true, expiresAt: 0, refreshTokenLength: 0, mtimeMs };
  }

  const record = oauth as JsonRecord;
  const expiresAtRaw = record.expiresAt;
  const expiresAt =
    typeof expiresAtRaw === "number"
      ? expiresAtRaw
      : typeof expiresAtRaw === "string"
        ? Date.parse(expiresAtRaw)
        : 0;
  const refreshTokenLength = typeof record.refreshToken === "string" ? record.refreshToken.length : 0;
  return {
    exists: true,
    expiresAt: Number.isFinite(expiresAt) ? expiresAt : 0,
    refreshTokenLength,
    mtimeMs,
  };
}

/**
 * Rank two existing credential payloads: refresh-token presence, then
 * usability (unexpired with a refresh token), then newer mtime, then later
 * expiry. This is the ONLY merge rule for duplicate custody of one account —
 * the central store is never downgraded through it.
 */
export function betterCredential(a: CredentialHealthPresent, b: CredentialHealthPresent): CredentialHealthPresent {
  const now = Date.now();
  const aHasRefresh = a.refreshTokenLength > 0;
  const bHasRefresh = b.refreshTokenLength > 0;
  if (aHasRefresh !== bHasRefresh) return aHasRefresh ? a : b;

  const aUsable = aHasRefresh && a.expiresAt > now;
  const bUsable = bHasRefresh && b.expiresAt > now;
  if (aUsable !== bUsable) return aUsable ? a : b;
  if (a.mtimeMs !== b.mtimeMs) return a.mtimeMs > b.mtimeMs ? a : b;
  if (a.expiresAt !== b.expiresAt) return a.expiresAt > b.expiresAt ? a : b;
  return a.mtimeMs > b.mtimeMs ? a : b;
}

// --- binding resolution ------------------------------------------------------

function oauthRecordFromSnapshot(profileDir: string): JsonRecord | undefined {
  const snap = readJsonFile(profileOAuthSnapshot(profileDir));
  const oauth = snap?.oauthAccount;
  return oauth && typeof oauth === "object" ? (oauth as JsonRecord) : undefined;
}

function oauthRecordFromAccountFiles(profileDir: string, tool?: ToolDef): JsonRecord | undefined {
  // A switched-away dir's live account file carries ANOTHER profile's account;
  // binding from it would attach this profile to a foreign identity. The
  // snapshot (checked first by callers) stays owner-true; without one, a
  // marked dir simply has no resolvable binding.
  const marker = readJsonFile(profileSwitchedAccountMarker(profileDir));
  if (marker && typeof marker.profile === "string" && marker.profile) return undefined;
  const paths = tool ? profileAccountJsonPaths(profileDir, tool) : [join(profileDir, ".claude.json")];
  for (const p of paths) {
    const oauth = readJsonFile(p)?.oauthAccount;
    if (oauth && typeof oauth === "object") return oauth as JsonRecord;
  }
  return undefined;
}

function uuidFromOAuthRecord(oauth: JsonRecord | undefined): string | undefined {
  const uuid = oauth?.accountUuid;
  return typeof uuid === "string" && UUID_RE.test(uuid) ? uuid : undefined;
}

/**
 * The account uuid a profile dir is bound to: per-profile snapshot first
 * (owner-true even when the dir's live files were switched to another
 * account), then the dir's account file. Without `tool` the claude default
 * account-file layout is assumed — every caller in this package is
 * claude-specific.
 */
export function profileAccountUuid(profileDir: string, tool?: ToolDef): string | undefined {
  return (
    uuidFromOAuthRecord(oauthRecordFromSnapshot(profileDir)) ??
    uuidFromOAuthRecord(oauthRecordFromAccountFiles(profileDir, tool))
  );
}

/** Central oauthAccount record for the account a profile is bound to, if stored. */
export function centralOAuthRecordForProfile(profileDir: string, tool?: ToolDef): JsonRecord | undefined {
  const uuid = profileAccountUuid(profileDir, tool);
  if (!uuid) return undefined;
  const snap = readJsonFile(centralOAuthSnapshot(uuid));
  const oauth = snap?.oauthAccount;
  return oauth && typeof oauth === "object" ? (oauth as JsonRecord) : undefined;
}

/** Path to the central credentials for a profile's bound account, when present. */
export function centralCredentialsPathForProfile(profileDir: string, tool?: ToolDef): string | undefined {
  const uuid = profileAccountUuid(profileDir, tool);
  if (!uuid) return undefined;
  const path = centralCredentialsSnapshot(uuid);
  return existsSync(path) ? path : undefined;
}

// --- write path: mirror per-profile snapshots into the central store ---------

export type SyncFileAction = "created" | "updated" | "kept" | "none";

export interface SyncResult {
  synced: boolean;
  reason?: string;
  uuid?: string;
  email?: string;
  centralDir?: string;
  credentials?: SyncFileAction;
  oauth?: SyncFileAction;
}

function writeCentralFile(path: string, bytes: Buffer | string): void {
  // writeFileAtomic validates the path, creates the parent dir, and chmods
  // 0600 explicitly after the rename.
  writeFileAtomic(path, bytes, { mode: 0o600, mustStayUnder: accountsHome() });
}

function syncOAuthFile(uuid: string, source: JsonRecord): SyncFileAction {
  const centralPath = centralOAuthSnapshot(uuid);
  const payload = JSON.stringify({ oauthAccount: source }, null, 2) + "\n";
  const existing = existsSync(centralPath) ? readFileSync(centralPath, "utf8") : undefined;
  if (existing === payload) return "kept";
  const action: SyncFileAction = existing === undefined ? "created" : "updated";
  writeCentralFile(centralPath, payload);
  return action;
}

function syncCredentialsFile(uuid: string, profileDir: string): SyncFileAction {
  // Candidates: the per-profile snapshot, plus the dir's live credential file
  // when no switch marker claims it for another account. The best one competes
  // against central; central is only ever replaced by a strict winner.
  const marker = readJsonFile(profileSwitchedAccountMarker(profileDir));
  const markerActive = Boolean(marker && typeof marker.profile === "string" && marker.profile);
  const candidatePaths = markerActive
    ? [profileCredentialsSnapshot(profileDir)]
    : [profileCredentialsSnapshot(profileDir), join(profileDir, ".credentials.json")];
  const candidates = candidatePaths
    .map((path) => ({ path, health: credentialHealth(path) }))
    .filter((c): c is { path: string; health: CredentialHealthPresent } => c.health.exists);
  if (candidates.length === 0) return "none";
  const best = candidates.reduce((a, b) => (betterCredential(a.health, b.health) === a.health ? a : b));

  const centralPath = centralCredentialsSnapshot(uuid);
  const centralHealth = credentialHealth(centralPath);
  const bytes = readFileSync(best.path);
  if (!centralHealth.exists) {
    writeCentralFile(centralPath, bytes);
    return "created";
  }
  if (betterCredential(best.health, centralHealth) !== best.health) return "kept";
  if (readFileSync(centralPath).equals(bytes)) return "kept";
  writeCentralFile(centralPath, bytes);
  return "updated";
}

/**
 * Mirror a profile's auth snapshot into the central store, keyed by its bound
 * account uuid. Loses nothing: per-profile files are never touched, and the
 * central copy is only replaced by a `betterCredential` winner (so duplicate
 * custody of one account collapses to the newest valid refresh token, and an
 * old binary's fresher rotation is picked up rather than clobbered).
 */
export function syncProfileSnapshotToCentral(profileDir: string, tool?: ToolDef): SyncResult {
  const oauthSource = oauthRecordFromSnapshot(profileDir) ?? oauthRecordFromAccountFiles(profileDir, tool);
  const uuid = uuidFromOAuthRecord(oauthSource);
  if (!oauthSource || !uuid) {
    return { synced: false, reason: "no account identity (uuid) resolvable for this profile dir" };
  }

  const oauth = syncOAuthFile(uuid, oauthSource);
  const credentials = syncCredentialsFile(uuid, profileDir);
  const email = typeof oauthSource.emailAddress === "string" ? oauthSource.emailAddress : undefined;
  return {
    synced: true,
    uuid,
    ...(email ? { email } : {}),
    centralDir: centralAuthDir(uuid),
    credentials,
    oauth,
  };
}

// --- enumeration -------------------------------------------------------------

export interface CentralAccount {
  uuid: string;
  email?: string;
  credentialsPresent: boolean;
  oauthPresent: boolean;
}

/** Accounts stored centrally, keyed by uuid (sorted for stable output). */
export function listCentralAccounts(): CentralAccount[] {
  const root = centralAuthRoot();
  if (!existsSync(root)) return [];
  const accounts: CentralAccount[] = [];
  for (const entry of readdirSync(root).sort()) {
    if (!UUID_RE.test(entry)) continue;
    const oauth = readJsonFile(centralOAuthSnapshot(entry))?.oauthAccount as JsonRecord | undefined;
    const email = typeof oauth?.emailAddress === "string" ? oauth.emailAddress : undefined;
    accounts.push({
      uuid: entry,
      ...(email ? { email } : {}),
      credentialsPresent: existsSync(centralCredentialsSnapshot(entry)),
      oauthPresent: oauth !== undefined,
    });
  }
  return accounts;
}

export interface KnownAccount {
  uuid: string;
  email?: string;
  central: boolean;
  /** Names of registered claude profiles bound to this account. */
  profiles: string[];
}

/**
 * THE identity-enumeration accessor: every account known to this machine,
 * central store first, then per-profile bindings as fallback, deduped by uuid.
 * Consumers (e.g. usage-aware auto-switching) should reason over this list
 * instead of walking profile dirs themselves.
 */
export function listKnownAccounts(): KnownAccount[] {
  const byUuid = new Map<string, KnownAccount>();
  for (const account of listCentralAccounts()) {
    byUuid.set(account.uuid, {
      uuid: account.uuid,
      ...(account.email ? { email: account.email } : {}),
      central: true,
      profiles: [],
    });
  }

  const store = loadStore();
  for (const profile of store.profiles) {
    if (profile.tool !== "claude" || !existsSync(profile.dir)) continue;
    const uuid = profileAccountUuid(profile.dir);
    if (!uuid) continue;
    const known = byUuid.get(uuid);
    if (known) {
      known.profiles.push(profile.name);
      if (!known.email) {
        const oauth = oauthRecordFromSnapshot(profile.dir) ?? oauthRecordFromAccountFiles(profile.dir);
        if (typeof oauth?.emailAddress === "string") known.email = oauth.emailAddress;
      }
    } else {
      const oauth = oauthRecordFromSnapshot(profile.dir) ?? oauthRecordFromAccountFiles(profile.dir);
      const email = typeof oauth?.emailAddress === "string" ? oauth.emailAddress : undefined;
      byUuid.set(uuid, { uuid, ...(email ? { email } : {}), central: false, profiles: [profile.name] });
    }
  }
  return [...byUuid.values()].sort((a, b) => a.uuid.localeCompare(b.uuid));
}

// --- orphan sweep ------------------------------------------------------------

export interface SweptOrphan {
  uuid: string;
  email?: string;
  trashedTo?: string;
}

export interface SweepResult {
  deleted: boolean;
  orphans: SweptOrphan[];
  referenced: string[];
}

/**
 * Central entries no registered claude profile is bound to. `--purge` on a
 * profile deliberately NEVER touches the central store (credential survival
 * across dir deletion is the store's whole point), so orphans accumulate only
 * through explicit removals — and are only ever cleaned by this explicit verb.
 * Dry-run by default; `delete` MOVES the entry to a timestamped dir under
 * `<accountsHome>/auth-trash/` rather than destroying credential bytes.
 */
export function sweepCentralAuth(opts: { delete?: boolean } = {}): SweepResult {
  const store = loadStore();
  const referencedUuids = new Set<string>();
  for (const profile of store.profiles) {
    if (profile.tool !== "claude" || !existsSync(profile.dir)) continue;
    const uuid = profileAccountUuid(profile.dir);
    if (uuid) referencedUuids.add(uuid);
  }

  const orphans: SweptOrphan[] = [];
  for (const account of listCentralAccounts()) {
    if (referencedUuids.has(account.uuid)) continue;
    orphans.push({ uuid: account.uuid, ...(account.email ? { email: account.email } : {}) });
  }

  if (opts.delete && orphans.length > 0) {
    const batchDir = join(
      accountsHome(),
      CENTRAL_AUTH_TRASH_DIR_NAME,
      new Date().toISOString().replace(/[:.]/g, "-"),
    );
    for (const orphan of orphans) {
      const target = join(batchDir, orphan.uuid);
      assertSafeWritePath(target, { mustStayUnder: accountsHome() });
      mkdirSync(batchDir, { recursive: true });
      renameSync(centralAuthDir(orphan.uuid), target);
      orphan.trashedTo = target;
    }
  }

  return {
    deleted: Boolean(opts.delete),
    orphans,
    referenced: [...referencedUuids].sort(),
  };
}
