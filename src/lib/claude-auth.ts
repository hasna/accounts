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

/**
 * Claude Code 2.1.220 credential, provider-selection, and provider-routing
 * environment surface. A selected Accounts profile is the sole auth authority:
 * inherited process variables must not redirect the client or inject alternate
 * credentials, headers, file descriptors, cloud profiles, or provider modes.
 *
 * Keep this explicit and version-reviewed with the continuation adapter. Broad
 * prefix deletion would also erase unrelated Claude feature flags.
 */
export const CLAUDE_API_AUTH_ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_CUSTOM_HEADERS",
  "ANTHROPIC_CONFIG_DIR",
  "ANTHROPIC_AWS_API_KEY",
  "ANTHROPIC_AWS_BASE_URL",
  "ANTHROPIC_AWS_WORKSPACE_ID",
  "ANTHROPIC_BEDROCK_BASE_URL",
  "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
  "ANTHROPIC_BEDROCK_SERVICE_TIER",
  "ANTHROPIC_BETAS",
  "ANTHROPIC_ENVIRONMENT_ID",
  "ANTHROPIC_ENVIRONMENT_KEY",
  "ANTHROPIC_CUSTOM_MODEL_OPTION",
  "ANTHROPIC_CUSTOM_MODEL_OPTION_DESCRIPTION",
  "ANTHROPIC_CUSTOM_MODEL_OPTION_NAME",
  "ANTHROPIC_CUSTOM_MODEL_OPTION_SUPPORTED_CAPABILITIES",
  "ANTHROPIC_DEFAULT_FABLE_MODEL",
  "ANTHROPIC_DEFAULT_FABLE_MODEL_DESCRIPTION",
  "ANTHROPIC_DEFAULT_FABLE_MODEL_NAME",
  "ANTHROPIC_DEFAULT_FABLE_MODEL_SUPPORTED_CAPABILITIES",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL_DESCRIPTION",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL_SUPPORTED_CAPABILITIES",
  "ANTHROPIC_DEFAULT_OPUS_MODEL",
  "ANTHROPIC_DEFAULT_OPUS_MODEL_DESCRIPTION",
  "ANTHROPIC_DEFAULT_OPUS_MODEL_NAME",
  "ANTHROPIC_DEFAULT_OPUS_MODEL_SUPPORTED_CAPABILITIES",
  "ANTHROPIC_DEFAULT_SONNET_MODEL",
  "ANTHROPIC_DEFAULT_SONNET_MODEL_DESCRIPTION",
  "ANTHROPIC_DEFAULT_SONNET_MODEL_NAME",
  "ANTHROPIC_DEFAULT_SONNET_MODEL_SUPPORTED_CAPABILITIES",
  "ANTHROPIC_FEDERATION_RULE_ID",
  "ANTHROPIC_FOUNDRY_API_KEY",
  "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
  "ANTHROPIC_FOUNDRY_BASE_URL",
  "ANTHROPIC_FOUNDRY_RESOURCE",
  "ANTHROPIC_GOOGLE_CLOUD_BASE_URL",
  "ANTHROPIC_GOOGLE_CLOUD_LOCATION",
  "ANTHROPIC_GOOGLE_CLOUD_PROJECT",
  "ANTHROPIC_GOOGLE_CLOUD_WORKSPACE_ID",
  "ANTHROPIC_IDENTITY_TOKEN",
  "ANTHROPIC_IDENTITY_TOKEN_FILE",
  "ANTHROPIC_MODEL",
  "ANTHROPIC_ORGANIZATION_ID",
  "ANTHROPIC_PROFILE",
  "ANTHROPIC_SCOPE",
  "ANTHROPIC_SERVICE_ACCOUNT_ID",
  "ANTHROPIC_SMALL_FAST_MODEL",
  "ANTHROPIC_SMALL_FAST_MODEL_AWS_REGION",
  "ANTHROPIC_UNIX_SOCKET",
  "ANTHROPIC_VERTEX_BASE_URL",
  "ANTHROPIC_VERTEX_PROJECT_ID",
  "ANTHROPIC_WORKSPACE_ID",
  "AWS_ACCESS_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_ACCOUNT_ID",
  "AWS_AUTH_SCHEME_PREFERENCE",
  "AWS_BEARER_TOKEN_BEDROCK",
  "AWS_CA_BUNDLE",
  "AWS_CHAIN_RESOLVE_REQUEST_TIMEOUT_MS",
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CREDENTIAL_EXPIRATION",
  "AWS_CREDENTIAL_SCOPE",
  "AWS_DEFAULTS_MODE",
  "AWS_DEFAULT_REGION",
  "AWS_EC2_METADATA_DISABLED",
  "AWS_EC2_METADATA_IPV4_ADDRESS",
  "AWS_EC2_METADATA_IPV6_ADDRESS",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
  "AWS_EC2_METADATA_V1_DISABLED",
  "AWS_ENDPOINT_URL",
  "AWS_LOGIN_CACHE_DIRECTORY",
  "AWS_MAX_ATTEMPTS",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_RETRY_MODE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SECRET_KEY",
  "AWS_SERVICE_ENDPOINT",
  "AWS_SERVICE_ENDPOINT_MODE",
  "AWS_SESSION_TOKEN",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_SDK_UA_APP_ID",
  "AWS_SIGV4A_SIGNING_REGION_SET",
  "AWS_USE_DUALSTACK_ENDPOINT",
  "AWS_USE_FIPS_ENDPOINT",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AZURE_ADDITIONALLY_ALLOWED_TENANTS",
  "AZURE_AUTHORITY_HOST",
  "AZURE_CLIENT_CERTIFICATE_PASSWORD",
  "AZURE_CLIENT_CERTIFICATE_PATH",
  "AZURE_CLIENT_ID",
  "AZURE_CLIENT_SECRET",
  "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN",
  "AZURE_FEDERATED_TOKEN_FILE",
  "AZURE_IDENTITY_DISABLE_MULTITENANTAUTH",
  "AZURE_PASSWORD",
  "AZURE_POD_IDENTITY_AUTHORITY_HOST",
  "AZURE_REGIONAL_AUTHORITY_NAME",
  "AZURE_REGION_AUTO_DISCOVER_FLAG",
  "AZURE_TENANT_ID",
  "AZURE_TOKEN_CREDENTIALS",
  "AZURE_USERNAME",
  "CLAUDE_API_KEY",
  "CLAUDE_BG_AUTH_SNAPSHOT_PATH",
  "CLAUDE_BRIDGE_BASE_URL",
  "CLAUDE_BRIDGE_OAUTH_TOKEN",
  "CLAUDE_BRIDGE_SESSION_INGRESS_URL",
  "CLAUDE_CODE_API_BASE_URL",
  "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
  "CLAUDE_CODE_ATTRIBUTION_HEADER",
  "CLAUDE_CODE_AWS_CHAIN_RESOLVE_TIMEOUT_MS",
  "CLOUDSDK_AUTH_ACCESS_TOKEN",
  "CLOUDSDK_CONFIG",
  "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
  "CLOUDSDK_PROXY_ADDRESS",
  "CLOUDSDK_PROXY_PASSWORD",
  "CLOUDSDK_PROXY_PORT",
  "CLOUDSDK_PROXY_TYPE",
  "CLOUDSDK_PROXY_USERNAME",
  "CLOUD_ML_REGION",
  "CLAUDE_CODE_API_KEY_HELPER",
  "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
  "CLAUDE_CODE_CERT_STORE",
  "CLAUDE_CODE_CLIENT_CERT",
  "CLAUDE_CODE_CLIENT_KEY",
  "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
  "CLAUDE_CODE_CUSTOM_OAUTH_URL",
  "CLAUDE_CODE_DESIGN_OAUTH_CLIENT_ID",
  "CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER",
  "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY",
  "CLAUDE_CODE_EXTRA_BODY",
  "CLAUDE_CODE_EXTRA_METADATA",
  "CLAUDE_CODE_GB_BASE_URL",
  "CLAUDE_CODE_HFI_BEARER_TOKEN",
  "CLAUDE_CODE_HOST_AUTH_ENV_VAR",
  "CLAUDE_CODE_HOST_AUTH_REFRESH_TIMEOUT_MS",
  "CLAUDE_CODE_HOST_CREDS_FILE",
  "CLAUDE_CODE_HOST_HTTP_PROXY_PORT",
  "CLAUDE_CODE_HOST_SOCKS_PROXY_PORT",
  "CLAUDE_CODE_HTTPS_PROXY",
  "CLAUDE_CODE_HTTP_PROXY",
  "CLAUDE_CODE_MANAGED_SETTINGS_PATH",
  "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
  "CLAUDE_CODE_OAUTH_CLIENT_ID",
  "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
  "CLAUDE_CODE_OAUTH_SCOPES",
  "CLAUDE_CODE_OAUTH_TOKEN",
  "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
  "CLAUDE_CODE_PROXY_AUTHENTICATE",
  "CLAUDE_CODE_PROXY_AUTH_HELPER_TTL_MS",
  "CLAUDE_CODE_PROXY_HOST",
  "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
  "CLAUDE_CODE_PROXY_RESOLVES_HOSTS",
  "CLAUDE_CODE_PROXY_URL",
  "CLAUDE_CODE_REMOTE_SETTINGS_PATH",
  "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH",
  "CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH",
  "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
  "CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH",
  "CLAUDE_CODE_SKIP_ANTHROPIC_GOOGLE_CLOUD_AUTH",
  "CLAUDE_CODE_SKIP_AWS_CRED_CACHE",
  "CLAUDE_CODE_SKIP_BEDROCK_AUTH",
  "CLAUDE_CODE_SKIP_FOUNDRY_AUTH",
  "CLAUDE_CODE_SKIP_MANTLE_AUTH",
  "CLAUDE_CODE_SKIP_VERTEX_AUTH",
  "CLAUDE_CODE_USE_ANTHROPIC_AWS",
  "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_FOUNDRY",
  "CLAUDE_CODE_USE_GATEWAY",
  "CLAUDE_CODE_USE_MANTLE",
  "CLAUDE_CODE_USE_VERTEX",
  "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
  "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
  "CLAUDE_ENV_FILE",
  "CLAUDE_TRUSTED_DEVICE_TOKEN",
  "DEFAULT_IDENTITY_CLIENT_ID",
  "GCE_METADATA_HOST",
  "GCE_METADATA_IP",
  "GCLOUD_PROJECT",
  "GOOGLE_API_CERTIFICATE_CONFIG",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GOOGLE_CLOUD_PROJECT",
  "GOOGLE_CLOUD_QUOTA_PROJECT",
  "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
  "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE",
  "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL",
  "GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE",
  "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE",
  "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE",
  "GOOGLE_TOKEN_INFO_URL",
  "IDENTITY_ENDPOINT",
  "IDENTITY_HEADER",
  "IDENTITY_SERVER_THUMBPRINT",
  "IMDS_ENDPOINT",
  "METADATA_SERVER_DETECTION",
  "MSI_ENDPOINT",
  ["MSI", "SECRET"].join("_"),
  "VERTEX_REGION_CLAUDE_3_5_HAIKU",
  "VERTEX_REGION_CLAUDE_3_5_SONNET",
  "VERTEX_REGION_CLAUDE_3_7_SONNET",
  "VERTEX_REGION_CLAUDE_4_0_OPUS",
  "VERTEX_REGION_CLAUDE_4_0_SONNET",
  "VERTEX_REGION_CLAUDE_4_1_OPUS",
  "VERTEX_REGION_CLAUDE_4_5_OPUS",
  "VERTEX_REGION_CLAUDE_4_5_SONNET",
  "VERTEX_REGION_CLAUDE_4_6_OPUS",
  "VERTEX_REGION_CLAUDE_4_6_SONNET",
  "VERTEX_REGION_CLAUDE_4_7_OPUS",
  "VERTEX_REGION_CLAUDE_4_8_OPUS",
  "VERTEX_REGION_CLAUDE_5_OPUS",
  "VERTEX_REGION_CLAUDE_5_SONNET",
  "VERTEX_REGION_CLAUDE_FABLE_5",
  "VERTEX_REGION_CLAUDE_HAIKU_4_5",
  "gcloud_project",
  "google_application_credentials",
  "google_cloud_project",
] as const;

/**
 * Generic proxy and TLS-trust variables Claude Code honors without a vendor
 * prefix. A caller that keeps these can point the launched session at its own
 * endpoint and disable transport verification, which leaks the profile bearer
 * token just as directly as an injected credential would.
 *
 * These stay out of CLAUDE_API_AUTH_ENV_KEYS on purpose: `accounts env`,
 * `accounts run`, and `accounts use` must leave a caller's network
 * configuration alone, while the cross-account continuation broker fails
 * closed on it.
 */
export const CLAUDE_NETWORK_ROUTING_ENV_KEYS = [
  "ALL_PROXY",
  "CURL_CA_BUNDLE",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NO_PROXY",
  "REQUESTS_CA_BUNDLE",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "all_proxy",
  "http_proxy",
  "https_proxy",
  "no_proxy",
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
