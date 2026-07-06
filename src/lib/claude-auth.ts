import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  CLAUDE_KEYCHAIN_SERVICE,
  liveClaudeBase,
  liveClaudePaths,
  profileAccountJsonPaths,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileKeychainSnapshot,
  profileOAuthSnapshot,
  OAUTH_SNAPSHOT,
} from "./claude-layout.js";
import {
  assertAllowedKeychainCredential,
  keychainSupported,
  readClaudeKeychain,
  type KeychainCredential,
  writeClaudeKeychain,
} from "./keychain.js";
import { assertSafeWritePath } from "./safe-path.js";

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
  assertSafeWritePath(path, stayUnder ? { mustStayUnder: stayUnder } : undefined);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
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

function profileHasOAuthAccount(profileDir: string, tool: ToolDef): boolean {
  return !!readOAuthSnapshot(profileDir) || !!readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool));
}

function profileHasCredentialPayload(profileDir: string): boolean {
  return existsSync(profileCredentialFile(profileDir)) || existsSync(profileCredentialsSnapshot(profileDir));
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

function credentialHealth(path: string):
  | { exists: false }
  | { exists: true; expiresAt: number; refreshTokenLength: number; mtimeMs: number } {
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

function betterCredential(
  a: { exists: true; expiresAt: number; refreshTokenLength: number; mtimeMs: number },
  b: { exists: true; expiresAt: number; refreshTokenLength: number; mtimeMs: number },
): typeof a {
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

export function liveCredentialShouldUpdateProfile(profileDir: string): boolean {
  const live = credentialHealth(liveClaudePaths().credentialsFile);
  if (!live.exists) return false;

  const profileRoot = credentialHealth(profileCredentialFile(profileDir));
  const profileSnapshot = credentialHealth(profileCredentialsSnapshot(profileDir));
  const profileCreds = [profileRoot, profileSnapshot].filter((c): c is Exclude<typeof c, { exists: false }> => c.exists);
  if (profileCreds.length === 0) return true;

  const bestProfileCred = profileCreds.reduce((best, candidate) => betterCredential(best, candidate));
  return betterCredential(live, bestProfileCred) === live;
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
}

/** @deprecated Use snapshotLiveAuthToProfile */
export function snapshotClaudeAuthToProfile(profileDir: string, tool: ToolDef): void {
  snapshotLiveAuthToProfile(profileDir, tool);
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
): void {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

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
  const valid = refreshTokenPresent && !expired;
  return {
    exists: true,
    parseableOauth: true,
    refreshTokenPresent,
    expired,
    ...(expiresAtMs > 0 ? { expiresAt: new Date(expiresAtMs).toISOString() } : {}),
    valid,
  };
}

export function claudeProfileAuthHealth(profileDir: string, tool: ToolDef): ClaudeProfileAuthHealth {
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
  const credentialPaths = [profileCredentialFile(profileDir), profileCredentialsSnapshot(profileDir)];
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
  const sources = [profileCredentialsSnapshot(profileDir), profileCredentialFile(profileDir)]
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

  const oauthSnap = readJsonFile(profileOAuthSnapshot(profileDir));
  const oauth =
    oauthSnap?.oauthAccount && typeof oauthSnap.oauthAccount === "object"
      ? (oauthSnap.oauthAccount as JsonRecord)
      : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool));

  if (!oauth) {
    throw new AccountsError("profile has no OAuth account data to apply");
  }

  sanitizeClaudeOAuthProfileSettings(profileDir, tool);
  sanitizeLiveClaudeOAuthSettings();

  assertSafeWritePath(live.homeJson, { mustStayUnder: liveRoot });
  mergeOAuthInto([live.homeJson], oauth, false, liveRoot);

  const credSnap = profileCredentialsSnapshot(profileDir);
  if (existsSync(credSnap)) {
    assertSafeWritePath(live.credentialsFile, { mustStayUnder: liveRoot });
    assertSafeWritePath(credSnap, { mustStayUnder: profileDir });
    copyFileSync(credSnap, live.credentialsFile);
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
