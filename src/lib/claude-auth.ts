import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  CLAUDE_KEYCHAIN_SERVICE,
  listDirLiveSessions,
  liveClaudeBase,
  liveClaudePaths,
  profileAccountJsonPaths,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileKeychainSnapshot,
  profileOAuthSnapshot,
  profileSwitchedAccountMarker,
  OAUTH_SNAPSHOT,
} from "./claude-layout.js";
import {
  assertAllowedKeychainCredential,
  keychainSupported,
  readClaudeKeychain,
  type KeychainCredential,
  writeClaudeKeychain,
} from "./keychain.js";
import { assertSafeWritePath, writeFileAtomic } from "./safe-path.js";
import {
  betterCredential,
  centralCredentialsPathForProfile,
  centralOAuthRecordForProfile,
  credentialHealth,
  type CredentialHealthPresent,
  type SyncResult,
  syncProfileSnapshotToCentral,
} from "./auth-store.js";
import { accountsHome } from "../storage.js";

type JsonRecord = Record<string, unknown>;

export const CLAUDE_API_AUTH_ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "CLAUDE_CODE_API_KEY_HELPER",
  "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
] as const;

function readJsonFile(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
  } catch {
    return undefined;
  }
}

function writeJsonFile(path: string, data: JsonRecord, stayUnder?: string): void {
  // Atomic write: these files (account json, credentials, markers) are read
  // concurrently by running tools, and `writeFileSync`'s mode never tightens a
  // pre-existing file — writeFileAtomic chmods explicitly after the rename.
  writeFileAtomic(path, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
    ...(stayUnder ? { mustStayUnder: stayUnder } : {}),
  });
}

function readOAuthFromPaths(paths: string[]): JsonRecord | undefined {
  return findOAuthSource(paths)?.oauth;
}

function readOAuthSnapshot(profileDir: string): JsonRecord | undefined {
  const snap = readJsonFile(profileOAuthSnapshot(profileDir));
  const oauth = snap?.oauthAccount;
  return oauth && typeof oauth === "object" ? (oauth as JsonRecord) : undefined;
}

function profileCredentialFile(profileDir: string): string {
  return join(profileDir, ".credentials.json");
}

export interface SwitchedAccountMarker {
  profile: string;
  email?: string;
  switchedAt?: string;
}

/**
 * When present, the dir's live `.credentials.json`/`oauthAccount` belong to the
 * named OTHER profile (an in-place session switch), so snapshot refreshes from
 * those files would contaminate the dir's own profile and must be skipped.
 */
export function readSwitchedAccountMarker(dir: string): SwitchedAccountMarker | undefined {
  const raw = readJsonFile(profileSwitchedAccountMarker(dir));
  if (!raw || typeof raw.profile !== "string" || !raw.profile) return undefined;
  return {
    profile: raw.profile,
    ...(typeof raw.email === "string" && raw.email ? { email: raw.email } : {}),
    ...(typeof raw.switchedAt === "string" && raw.switchedAt ? { switchedAt: raw.switchedAt } : {}),
  };
}

export function writeSwitchedAccountMarker(dir: string, marker: SwitchedAccountMarker): void {
  const path = profileSwitchedAccountMarker(dir);
  assertSafeWritePath(path, { mustStayUnder: dir });
  mkdirSync(profileAuthDir(dir), { recursive: true });
  writeJsonFile(path, { ...marker, switchedAt: marker.switchedAt ?? new Date().toISOString() }, dir);
}

export function clearSwitchedAccountMarker(dir: string): void {
  const path = profileSwitchedAccountMarker(dir);
  if (existsSync(path)) unlinkSync(path);
}

function profileHasOAuthAccount(profileDir: string, tool: ToolDef): boolean {
  return !!readOAuthSnapshot(profileDir) || !!readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool));
}

function profileHasCredentialPayload(profileDir: string): boolean {
  return (
    existsSync(profileCredentialFile(profileDir)) ||
    existsSync(profileCredentialsSnapshot(profileDir)) ||
    centralCredentialsPathForProfile(profileDir) !== undefined
  );
}

export function assertRestorableProfileAuth(profileDir: string, tool: ToolDef, profileName?: string): void {
  const label = profileName ?? "NAME";
  if (!profileHasOAuthAccount(profileDir, tool)) {
    throw new AccountsError(
      `profile "${label}" has no auth to apply — run \`accounts login ${label}\` then \`accounts detect ${label}\` first`,
    );
  }
  if (!profileHasCredentialPayload(profileDir)) {
    throw new AccountsError(
      `profile "${label}" has no Claude credentials to apply — run \`accounts login ${label}\` and complete /login first`,
    );
  }
}

function findOAuthSource(paths: string[]): { path: string; oauth: JsonRecord } | undefined {
  for (const p of paths) {
    const data = readJsonFile(p);
    const oauth = data?.oauthAccount;
    if (oauth && typeof oauth === "object") return { path: p, oauth: oauth as JsonRecord };
  }
  return undefined;
}

/** True when the snapshot is missing or strictly older than its source file. */
function snapshotIsStale(sourcePath: string, snapshotPath: string): boolean {
  if (!existsSync(snapshotPath)) return true;
  try {
    return statSync(sourcePath).mtimeMs > statSync(snapshotPath).mtimeMs;
  } catch {
    return false;
  }
}

// credentialHealth/betterCredential live in auth-store.ts (the lower layer)
// so the central store and these read paths rank credentials identically.

/**
 * Best restorable credential snapshot for a profile: the per-profile copy vs
 * the central identity-keyed copy, `betterCredential` winner. Not "central
 * first" — during the 0.2.15/0.2.16 window an old binary may have rotated a
 * fresher token into the per-profile copy, and restoring a stale central one
 * would log the account out. `stayUnder` is the containment root for source
 * symlink checks on the winning path.
 */
function bestRestorableCredentialPath(
  profileDir: string,
  tool?: ToolDef,
): { path: string; stayUnder: string } | undefined {
  const candidates: { path: string; stayUnder: string }[] = [
    { path: profileCredentialsSnapshot(profileDir), stayUnder: profileDir },
  ];
  const central = centralCredentialsPathForProfile(profileDir, tool);
  if (central) candidates.push({ path: central, stayUnder: accountsHome() });
  const existing = candidates
    .filter((c) => existsSync(c.path) && !lstatSync(c.path).isSymbolicLink())
    .map((c) => ({ ...c, health: credentialHealth(c.path) }))
    .filter((c): c is typeof c & { health: CredentialHealthPresent } => c.health.exists);
  if (existing.length === 0) return undefined;
  const best = existing.reduce((a, b) => (betterCredential(a.health, b.health) === a.health ? a : b));
  return { path: best.path, stayUnder: best.stayUnder };
}

export function liveCredentialShouldUpdateProfile(profileDir: string): boolean {
  return sourceCredentialShouldUpdateProfile(liveClaudePaths().credentialsFile, profileDir);
}

/** True when `sourceCredentialsFile` holds a better credential than the profile already has. */
export function dirCredentialShouldUpdateProfile(sourceDir: string, profileDir: string): boolean {
  return sourceCredentialShouldUpdateProfile(profileCredentialFile(sourceDir), profileDir);
}

function sourceCredentialShouldUpdateProfile(sourceCredentialsFile: string, profileDir: string): boolean {
  const source = credentialHealth(sourceCredentialsFile);
  if (!source.exists) return false;

  const profileRoot = credentialHealth(profileCredentialFile(profileDir));
  const profileSnapshot = credentialHealth(profileCredentialsSnapshot(profileDir));
  const centralPath = centralCredentialsPathForProfile(profileDir);
  const profileCentral = centralPath ? credentialHealth(centralPath) : ({ exists: false } as const);
  const profileCreds = [profileRoot, profileSnapshot, profileCentral].filter(
    (c): c is Exclude<typeof c, { exists: false }> => c.exists,
  );
  if (profileCreds.length === 0) return true;

  const bestProfileCred = profileCreds.reduce((best, candidate) => betterCredential(best, candidate));
  return betterCredential(source, bestProfileCred) === source;
}

function mergeOAuthInto(
  paths: string[],
  oauth: JsonRecord | undefined,
  allowDelete: boolean,
  stayUnder?: string,
): void {
  const primary = paths[0];
  if (!primary) return;
  const data = readJsonFile(primary) ?? {};
  if (oauth) {
    data.oauthAccount = oauth;
    writeJsonFile(primary, data, stayUnder);
  } else if (allowDelete) {
    delete data.oauthAccount;
    writeJsonFile(primary, data, stayUnder);
  }
  if (paths[1] && paths[1] !== primary) {
    const parent = readJsonFile(paths[1]) ?? {};
    if (oauth) {
      parent.oauthAccount = oauth;
      writeJsonFile(paths[1], parent, stayUnder);
    } else if (allowDelete) {
      delete parent.oauthAccount;
      writeJsonFile(paths[1], parent, stayUnder);
    }
  }
}

function sanitizeSettingsFile(configDir: string, stayUnder: string): boolean {
  const settingsPath = join(configDir, "settings.json");
  const settings = readJsonFile(settingsPath);
  if (!settings) return false;

  let changed = false;
  if ("apiKeyHelper" in settings) {
    delete settings.apiKeyHelper;
    changed = true;
  }

  const env = settings.env;
  if (env && typeof env === "object" && !Array.isArray(env)) {
    const envRecord = env as JsonRecord;
    for (const key of CLAUDE_API_AUTH_ENV_KEYS) {
      if (key in envRecord) {
        delete envRecord[key];
        changed = true;
      }
    }
  }

  if (changed) writeJsonFile(settingsPath, settings, stayUnder);
  return changed;
}

export function sanitizeClaudeProfileApiSettings(profileDir: string, tool: ToolDef): boolean {
  if (tool.id !== "claude") return false;
  return sanitizeSettingsFile(profileDir, profileDir);
}

export function sanitizeClaudeOAuthProfileSettings(profileDir: string, tool: ToolDef): boolean {
  if (tool.id !== "claude") return false;
  if (!readOAuthSnapshot(profileDir) && !readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))) {
    return false;
  }
  return sanitizeClaudeProfileApiSettings(profileDir, tool);
}

export function sanitizeLiveClaudeOAuthSettings(): boolean {
  return sanitizeSettingsFile(liveClaudePaths().configDir, liveClaudeBase());
}

/** Email address of the account currently authenticated on the live Claude paths. */
export function liveOAuthEmail(): string | undefined {
  const live = liveClaudePaths();
  const oauth = readOAuthFromPaths([live.homeJson]);
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

/** Snapshot live Claude auth into a profile directory (used when switching away on apply). */
export function snapshotLiveAuthToProfile(profileDir: string, _tool: ToolDef): void {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  const live = liveClaudePaths();
  const oauth = readOAuthFromPaths([live.homeJson]);
  if (oauth) writeJsonFile(profileOAuthSnapshot(profileDir), { oauthAccount: oauth }, profileDir);

  if (existsSync(live.credentialsFile)) {
    const dest = profileCredentialsSnapshot(profileDir);
    assertSafeWritePath(dest, { mustStayUnder: profileDir });
    copyFileSync(live.credentialsFile, dest);

    if (keychainSupported()) {
      const kc = readClaudeKeychain();
      if (kc) writeJsonFile(profileKeychainSnapshot(profileDir), kc as unknown as JsonRecord, profileDir);
    }
  }

  syncProfileSnapshotToCentral(profileDir, _tool);
}

/** @deprecated Use snapshotLiveAuthToProfile */
export function snapshotClaudeAuthToProfile(profileDir: string, tool: ToolDef): void {
  snapshotLiveAuthToProfile(profileDir, tool);
}

/**
 * Snapshot the auth currently living in an arbitrary session config dir into a
 * profile's snapshot store (the in-place switch counterpart of
 * `snapshotLiveAuthToProfile`, for sessions not on the live default paths).
 */
export function snapshotDirAuthToProfile(sourceDir: string, tool: ToolDef, profileDir: string): void {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  const oauth = readOAuthFromPaths([join(sourceDir, tool.accountFile ?? ".claude.json")]);
  if (oauth) writeJsonFile(profileOAuthSnapshot(profileDir), { oauthAccount: oauth }, profileDir);

  const sourceCredentials = join(sourceDir, ".credentials.json");
  if (existsSync(sourceCredentials)) {
    const dest = profileCredentialsSnapshot(profileDir);
    assertSafeWritePath(dest, { mustStayUnder: profileDir });
    copyFileSync(sourceCredentials, dest);
  }

  syncProfileSnapshotToCentral(profileDir, tool);
}

/**
 * Restore a profile's auth into an arbitrary session config dir: the write half
 * of an in-place account switch. Merges `oauthAccount` into the dir's account
 * file (preserving unrelated session state) and installs the profile's
 * credential snapshot as the dir's live `.credentials.json`. A running Claude
 * session bound to the dir picks the new identity up on its next API request.
 */
export function restoreClaudeAuthIntoDir(
  profileDir: string,
  tool: ToolDef,
  targetDir: string,
  profileName?: string,
): void {
  ensureProfileAuthSnapshot(profileDir, tool);
  assertRestorableProfileAuth(profileDir, tool, profileName);

  const oauth =
    readOAuthSnapshot(profileDir) ??
    centralOAuthRecordForProfile(profileDir, tool) ??
    (readSwitchedAccountMarker(profileDir)
      ? undefined
      : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));
  if (!oauth) throw new AccountsError("profile has no OAuth account data to apply");

  const credSnap = bestRestorableCredentialPath(profileDir, tool);
  if (!credSnap) {
    throw new AccountsError(
      `profile "${profileName ?? "NAME"}" has no restorable Claude credential snapshot`,
    );
  }

  mkdirSync(targetDir, { recursive: true });

  // Validate EVERY write path before mutating anything: a refused credential
  // write (e.g. a symlinked target) must not leave the dir with a new
  // oauthAccount over the old credentials.
  const accountFile = join(targetDir, tool.accountFile ?? ".claude.json");
  const targetCredentials = join(targetDir, ".credentials.json");
  assertSafeWritePath(accountFile, { mustStayUnder: targetDir });
  assertSafeWritePath(targetCredentials, { mustStayUnder: targetDir });
  const credentialBytes = readFileSync(credSnap.path);

  sanitizeSettingsFile(targetDir, targetDir);
  mergeOAuthInto([accountFile], oauth, false, targetDir);
  // Atomic: the running session reads this file on every request.
  writeFileAtomic(targetCredentials, credentialBytes, { mode: 0o600, mustStayUnder: targetDir });
}

/**
 * If a profile's own dir was switched to another account (agreeing marker) and
 * no live session is using it, restore the profile's own auth so a fresh launch
 * runs as the profile it claims to be. Throws when live sessions still run on
 * the dir — yanking their identity out from under them is never right.
 */
export function healSwitchedProfileDir(profileDir: string, tool: ToolDef, profileName?: string): boolean {
  if (tool.id !== "claude") return false;
  const marker = readSwitchedAccountMarker(profileDir);
  if (!marker) return false;

  const liveEmailNow = readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))?.emailAddress;
  if (typeof liveEmailNow === "string" && liveEmailNow && marker.email && marker.email !== liveEmailNow) {
    // Stale marker (a later login changed the dir); normal flows own it again.
    clearSwitchedAccountMarker(profileDir);
    return false;
  }

  const live = listDirLiveSessions(profileDir).filter((s) => s.alive).length;
  if (live > 0) {
    throw new AccountsError(
      `profile "${profileName ?? "NAME"}" cannot launch: its config dir currently carries the account of "${marker.profile}" (in-place switch) with ${live} live session(s) attached. Switch the running session back first — accounts switch-account ${profileName ?? "NAME"} --dir ${profileDir}`,
    );
  }

  restoreClaudeAuthIntoDir(profileDir, tool, profileDir, profileName);
  clearSwitchedAccountMarker(profileDir);
  return true;
}

/**
 * Build auth snapshots from files already present in the profile config dir.
 * Snapshots are refreshed per-file whenever the source in the profile dir is
 * newer than the existing snapshot — a running tool rotates its OAuth tokens
 * in place, and restoring a login-time snapshot over rotated tokens logs the
 * account out (rotated-out refresh tokens are revoked server-side).
 */
export function ensureProfileAuthSnapshot(
  profileDir: string,
  tool: ToolDef,
  opts: { overwrite?: boolean } = {},
): SyncResult {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  // A fresh login (overwrite) makes the dir's files the profile's truth again;
  // otherwise a switched-away dir holds ANOTHER profile's live auth, and
  // refreshing snapshots from it would overwrite this profile's real tokens.
  // A marker contradicted by the dir's live email is stale (e.g. an in-session
  // /login landed after the switch) — the dir's files are the truth again, so
  // the marker is dropped and the normal refresh resumes.
  if (opts.overwrite) clearSwitchedAccountMarker(profileDir);
  else {
    const marker = readSwitchedAccountMarker(profileDir);
    if (marker) {
      const liveEmailNow = readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))?.emailAddress;
      const stale =
        typeof liveEmailNow === "string" && liveEmailNow && marker.email && marker.email !== liveEmailNow;
      if (stale) clearSwitchedAccountMarker(profileDir);
      else {
        sanitizeClaudeOAuthProfileSettings(profileDir, tool);
        // The dir's live files belong to another account, but the profile's
        // own snapshot is owner-true — still mirror it centrally.
        return syncProfileSnapshotToCentral(profileDir, tool);
      }
    }
  }

  const oauthSource = findOAuthSource(profileAccountJsonPaths(profileDir, tool));
  const oauthSnap = profileOAuthSnapshot(profileDir);
  if (oauthSource && (opts.overwrite || snapshotIsStale(oauthSource.path, oauthSnap))) {
    writeJsonFile(oauthSnap, { oauthAccount: oauthSource.oauth }, profileDir);
  }

  const credFile = profileCredentialFile(profileDir);
  const credSnap = profileCredentialsSnapshot(profileDir);
  if (existsSync(credFile) && (opts.overwrite || snapshotIsStale(credFile, credSnap))) {
    assertSafeWritePath(credSnap, { mustStayUnder: profileDir });
    copyFileSync(credFile, credSnap);
  }

  sanitizeClaudeOAuthProfileSettings(profileDir, tool);
  // Write-new half of the compat window: every per-profile snapshot write is
  // mirrored into the central identity-keyed store.
  return syncProfileSnapshotToCentral(profileDir, tool);
}

export function profileHasAuth(profileDir: string, tool: ToolDef): boolean {
  return profileHasOAuthAccount(profileDir, tool) && profileHasCredentialPayload(profileDir);
}

export type ClaudeProfileAuthStatus = "ok" | "missing" | "expired" | "invalid" | "unknown";

export interface ClaudeProfileAuthHealth {
  status: ClaudeProfileAuthStatus;
  valid: boolean;
  oauthAccountPresent: boolean;
  credentialPayloadPresent: boolean;
  credentialPayloadValid: boolean;
  credentialPayloadExpired: boolean;
  credentialExpiresAt?: string;
  keychainSnapshotPresent: boolean;
  snapshotPresent: boolean;
  reasons: string[];
}

interface CredentialPayloadReadiness {
  exists: boolean;
  parseableOauth: boolean;
  refreshTokenPresent: boolean;
  expired: boolean;
  expiresAt?: string;
  valid: boolean;
}

function credentialPayloadReadiness(path: string): CredentialPayloadReadiness {
  if (!existsSync(path)) {
    return {
      exists: false,
      parseableOauth: false,
      refreshTokenPresent: false,
      expired: false,
      valid: false,
    };
  }

  const health = credentialHealth(path);
  const raw = readJsonFile(path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") {
    return {
      exists: true,
      parseableOauth: false,
      refreshTokenPresent: false,
      expired: false,
      valid: false,
    };
  }

  const expiresAtMs = health.exists ? health.expiresAt : 0;
  const expired = expiresAtMs > 0 && expiresAtMs <= Date.now();
  const refreshTokenPresent = health.exists && health.refreshTokenLength > 0;
  const valid = refreshTokenPresent && expiresAtMs > Date.now();
  return {
    exists: true,
    parseableOauth: true,
    refreshTokenPresent,
    expired,
    ...(expiresAtMs > 0 ? { expiresAt: new Date(expiresAtMs).toISOString() } : {}),
    valid,
  };
}

/**
 * The profile's own account email: snapshot first (owner-true even when the
 * dir's live files were switched to another account), then the account file
 * unless a switch marker says those files belong to someone else.
 */
export function profileOAuthEmail(profileDir: string, tool: ToolDef): string | undefined {
  const snapshot = readOAuthSnapshot(profileDir);
  const oauth =
    snapshot ??
    (readSwitchedAccountMarker(profileDir) ? undefined : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

/** OAuth account email carried by a config dir's live account file, if any. */
export function dirOAuthEmail(dir: string, tool: ToolDef): string | undefined {
  const oauth = readOAuthFromPaths([join(dir, tool.accountFile ?? ".claude.json")]);
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

export function claudeProfileAuthHealth(
  profileDir: string,
  tool: ToolDef,
  opts: { restoreView?: boolean } = {},
): ClaudeProfileAuthHealth {
  if (tool.id !== "claude") {
    return {
      status: "unknown",
      valid: false,
      oauthAccountPresent: false,
      credentialPayloadPresent: false,
      credentialPayloadValid: false,
      credentialPayloadExpired: false,
      keychainSnapshotPresent: false,
      snapshotPresent: false,
      reasons: [`auth validation is only available for Claude profiles, not ${tool.id}`],
    };
  }

  const oauthAccountPresent = profileHasOAuthAccount(profileDir, tool);
  // In restore view, a switched-away dir's root credential belongs to another
  // account — only the snapshot answers "can THIS profile's auth be restored".
  const centralCredentialPath = centralCredentialsPathForProfile(profileDir, tool);
  const credentialPaths =
    opts.restoreView && readSwitchedAccountMarker(profileDir)
      ? [profileCredentialsSnapshot(profileDir), ...(centralCredentialPath ? [centralCredentialPath] : [])]
      : [
          profileCredentialFile(profileDir),
          profileCredentialsSnapshot(profileDir),
          ...(centralCredentialPath ? [centralCredentialPath] : []),
        ];
  const credentials = credentialPaths.map((path) => credentialPayloadReadiness(path));
  const existingCredentials = credentials.filter((credential) => credential.exists);
  const credentialPayloadPresent = existingCredentials.length > 0;
  const validCredential = existingCredentials.find((credential) => credential.valid);
  const expiredCredential = existingCredentials.find((credential) => credential.expired);
  const parseableInvalidCredential = existingCredentials.find(
    (credential) => credential.parseableOauth && !credential.refreshTokenPresent,
  );
  const keychainSnapshotPresent = existsSync(profileKeychainSnapshot(profileDir));
  const snapshotPresent = hasAuthSnapshot(profileDir);

  const reasons: string[] = [];
  if (!oauthAccountPresent) reasons.push("OAuth account snapshot is missing");
  if (!credentialPayloadPresent) reasons.push("credential payload is missing");
  if (!validCredential && expiredCredential) reasons.push("credential payload is expired");
  if (!validCredential && parseableInvalidCredential) reasons.push("credential payload has no refresh token");
  if (credentialPayloadPresent && !validCredential && !expiredCredential && !parseableInvalidCredential) {
    reasons.push("credential payload expiry is unknown");
  }

  let status: ClaudeProfileAuthStatus = "ok";
  if (!oauthAccountPresent || !credentialPayloadPresent) status = "missing";
  else if (!validCredential && expiredCredential) status = "expired";
  else if (!validCredential && parseableInvalidCredential) status = "invalid";
  else if (!validCredential) status = "unknown";

  return {
    status,
    valid: status === "ok",
    oauthAccountPresent,
    credentialPayloadPresent,
    credentialPayloadValid: Boolean(validCredential),
    credentialPayloadExpired: !validCredential && Boolean(expiredCredential),
    ...(validCredential?.expiresAt ?? expiredCredential?.expiresAt
      ? { credentialExpiresAt: validCredential?.expiresAt ?? expiredCredential?.expiresAt }
      : {}),
    keychainSnapshotPresent,
    snapshotPresent,
    reasons,
  };
}

function profileCredentialSource(path: string):
  | { secret: string; health: { exists: true; expiresAt: number; refreshTokenLength: number; mtimeMs: number } }
  | undefined {
  if (!existsSync(path) || lstatSync(path).isSymbolicLink()) return undefined;
  const secret = readFileSync(path, "utf8").trim();
  if (!secret) return undefined;
  const health = credentialHealth(path);
  return health.exists ? { secret, health } : undefined;
}

function profileFileCredentialSecret(profileDir: string): string | undefined {
  // A switched-away dir's root credential belongs to another profile; only the
  // snapshot (and the central copy of the profile's own account, whose binding
  // resolves through that snapshot) still holds this profile's own tokens.
  const central = centralCredentialsPathForProfile(profileDir);
  const paths = readSwitchedAccountMarker(profileDir)
    ? [profileCredentialsSnapshot(profileDir), ...(central ? [central] : [])]
    : [profileCredentialsSnapshot(profileDir), profileCredentialFile(profileDir), ...(central ? [central] : [])];
  const sources = paths
    .map((path) => profileCredentialSource(path))
    .filter((source): source is NonNullable<typeof source> => !!source);
  if (sources.length === 0) return undefined;
  return sources.reduce((best, candidate) =>
    betterCredential(candidate.health, best.health) === candidate.health ? candidate : best,
  ).secret;
}

function profileKeychainSnapshotAccount(profileDir: string): string | undefined {
  const kcRaw = readJsonFile(profileKeychainSnapshot(profileDir));
  if (!kcRaw || typeof kcRaw.account !== "string") return undefined;
  try {
    assertAllowedKeychainCredential({
      service: CLAUDE_KEYCHAIN_SERVICE,
      account: kcRaw.account,
      secret: "metadata-only",
    });
    return kcRaw.account;
  } catch {
    return undefined;
  }
}

function assertKeychainSnapshotAllowed(profileDir: string): KeychainCredential | undefined {
  const kcRaw = readJsonFile(profileKeychainSnapshot(profileDir));
  if (!kcRaw || typeof kcRaw.secret !== "string" || typeof kcRaw.account !== "string") return undefined;
  const cred = {
    service: typeof kcRaw.service === "string" ? kcRaw.service : CLAUDE_KEYCHAIN_SERVICE,
    account: kcRaw.account,
    secret: kcRaw.secret,
  };
  assertAllowedKeychainCredential(cred);
  return {
    service: CLAUDE_KEYCHAIN_SERVICE,
    account: cred.account,
    secret: cred.secret,
  };
}

export function claudeKeychainCredentialFromProfile(
  profileDir: string,
  profileName?: string,
): KeychainCredential | undefined {
  const fileSecret = profileFileCredentialSecret(profileDir);
  if (!fileSecret) return assertKeychainSnapshotAllowed(profileDir);
  const cred = {
    service: CLAUDE_KEYCHAIN_SERVICE,
    account: profileKeychainSnapshotAccount(profileDir) ?? profileName ?? "claude",
    secret: fileSecret,
  };
  assertAllowedKeychainCredential(cred);
  return cred;
}

export function prepareClaudeProfileKeychain(profileDir: string, tool: ToolDef, profileName?: string): boolean {
  if (tool.id !== "claude" || !keychainSupported()) return false;
  try {
    ensureProfileAuthSnapshot(profileDir, tool);
    const cred = claudeKeychainCredentialFromProfile(profileDir, profileName);
    if (!cred) return false;
    writeClaudeKeychain(cred);
    return true;
  } catch {
    return false;
  }
}

/** Restore profile auth snapshots onto live Claude paths. */
export function restoreClaudeAuthFromProfile(
  profileDir: string,
  tool: ToolDef,
  profileName?: string,
): void {
  ensureProfileAuthSnapshot(profileDir, tool);
  assertRestorableProfileAuth(profileDir, tool, profileName);

  const live = liveClaudePaths();
  const liveRoot = liveClaudeBase();
  mkdirSync(live.configDir, { recursive: true });

  const oauth =
    readOAuthSnapshot(profileDir) ??
    centralOAuthRecordForProfile(profileDir, tool) ??
    (readSwitchedAccountMarker(profileDir)
      ? undefined
      : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));

  if (!oauth) {
    throw new AccountsError("profile has no OAuth account data to apply");
  }

  sanitizeClaudeOAuthProfileSettings(profileDir, tool);
  sanitizeLiveClaudeOAuthSettings();

  assertSafeWritePath(live.homeJson, { mustStayUnder: liveRoot });
  mergeOAuthInto([live.homeJson], oauth, false, liveRoot);

  const credSnap = bestRestorableCredentialPath(profileDir, tool);
  if (credSnap) {
    assertSafeWritePath(live.credentialsFile, { mustStayUnder: liveRoot });
    assertSafeWritePath(credSnap.path, { mustStayUnder: credSnap.stayUnder });
    copyFileSync(credSnap.path, live.credentialsFile);
    writeFileSync(live.credentialsFile, readFileSync(live.credentialsFile), { mode: 0o600 });
  } else if (existsSync(live.credentialsFile)) {
    if (!lstatSync(live.credentialsFile).isSymbolicLink()) unlinkSync(live.credentialsFile);
  }

  prepareClaudeProfileKeychain(profileDir, tool, profileName);
}

export function hasAuthSnapshot(profileDir: string): boolean {
  return (
    existsSync(profileOAuthSnapshot(profileDir)) ||
    existsSync(profileCredentialsSnapshot(profileDir)) ||
    existsSync(profileKeychainSnapshot(profileDir))
  );
}
