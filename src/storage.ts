import { homedir } from "node:os";
import { hostname } from "node:os";
import { join } from "node:path";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { type Store, storeSchema, AccountsError, profileNameSchema } from "./types.js";
import { assertSafeWritePath } from "./lib/safe-path.js";

export const ACCOUNTS_STORAGE_ENV = {
  mode: "HASNA_ACCOUNTS_STORAGE_MODE",
  s3Bucket: "HASNA_ACCOUNTS_S3_BUCKET",
  s3Prefix: "HASNA_ACCOUNTS_S3_PREFIX",
  awsRegion: "HASNA_ACCOUNTS_AWS_REGION",
  s3Endpoint: "HASNA_ACCOUNTS_S3_ENDPOINT",
  s3ForcePathStyle: "HASNA_ACCOUNTS_S3_FORCE_PATH_STYLE",
  machineId: "HASNA_ACCOUNTS_MACHINE_ID",
} as const;

export const ACCOUNTS_STORAGE_FALLBACK_ENV = {
  mode: "ACCOUNTS_STORAGE_MODE",
  s3Bucket: "ACCOUNTS_S3_BUCKET",
  s3Prefix: "ACCOUNTS_S3_PREFIX",
  awsRegion: "ACCOUNTS_AWS_REGION",
  s3Endpoint: "ACCOUNTS_S3_ENDPOINT",
  s3ForcePathStyle: "ACCOUNTS_S3_FORCE_PATH_STYLE",
  machineId: "ACCOUNTS_MACHINE_ID",
} as const;

export const STORAGE_MODE_ENV = ACCOUNTS_STORAGE_ENV.mode;
export const STORAGE_TABLES = [] as const;

export type AccountsStorageMode = "local" | "remote" | "hybrid";

export interface AccountsStorageConfig {
  mode: AccountsStorageMode;
  s3Bucket?: string;
  s3Prefix: string;
  awsRegion?: string;
  s3Endpoint?: string;
  s3ForcePathStyle?: boolean;
  machineId: string;
}

export interface AccountsStorageStatus {
  configured: boolean;
  mode: AccountsStorageMode;
  local: {
    home: string;
    storePath: string;
    profilesDir: string;
  };
  remote: {
    configured: boolean;
    bucketEnv: string;
    bucket?: string;
    prefix: string;
    regionEnv: string;
    endpointConfigured: boolean;
  };
  env: typeof ACCOUNTS_STORAGE_ENV;
  fallbackEnv: typeof ACCOUNTS_STORAGE_FALLBACK_ENV;
  tables: readonly [];
}

export interface AccountsStorageSnapshot {
  schemaVersion: 1;
  source: "accounts";
  createdAt: string;
  machineId: string;
  store: Store;
}

export interface AccountsStorageSyncResult {
  mode: AccountsStorageMode;
  pushed: number;
  pulled: number;
  skipped: boolean;
  key: string;
  reason?: string;
}

function validateEnvPath(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed || trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new AccountsError(`invalid ${label}`);
  }
  return trimmed;
}

/** Base directory for all accounts state. Override with `ACCOUNTS_HOME`. */
export function accountsHome(): string {
  const override = process.env.ACCOUNTS_HOME;
  if (override && override.trim()) return validateEnvPath(override, "ACCOUNTS_HOME");
  return join(homedir(), ".hasna", "accounts");
}

/** Path to the registry file. Override with `ACCOUNTS_STORE_PATH`. */
export function storePath(): string {
  const override = process.env.ACCOUNTS_STORE_PATH;
  if (override && override.trim()) return validateEnvPath(override, "ACCOUNTS_STORE_PATH");
  return join(accountsHome(), "accounts.json");
}

/** Base directory under which managed profile config dirs are created. */
export function profilesDir(): string {
  return join(accountsHome(), "profiles");
}

const EMPTY_STORE: Store = { version: 1, current: {}, applied: {}, profiles: [], tools: [] };

export function loadStore(): Store {
  const path = storePath();
  if (!existsSync(path)) return structuredClone(EMPTY_STORE);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new AccountsError(`could not parse store at ${path}: ${(err as Error).message}`);
  }
  const parsed = storeSchema.safeParse(raw);
  if (!parsed.success) {
    throw new AccountsError(`invalid store at ${path}: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  }
  const store = parsed.data;
  for (const p of store.profiles) {
    const check = profileNameSchema.safeParse(p.name);
    if (!check.success) {
      throw new AccountsError(`invalid profile name in store "${p.name}": ${check.error.issues[0]?.message}`);
    }
  }
  for (const toolId of Object.keys(store.current)) {
    const name = store.current[toolId];
    if (!name || !profileNameSchema.safeParse(name).success) delete store.current[toolId];
    else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) delete store.current[toolId];
  }
  for (const toolId of Object.keys(store.applied)) {
    const name = store.applied[toolId];
    if (!name || !profileNameSchema.safeParse(name).success) delete store.applied[toolId];
    else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) delete store.applied[toolId];
  }
  return store;
}

export function saveStore(store: Store): void {
  const path = storePath();
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  mkdirSync(join(path, ".."), { recursive: true });
  if (existsSync(path)) chmodSync(path, 0o600);
  writeFileSync(path, JSON.stringify(store, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
}

function firstEnv(env: NodeJS.ProcessEnv, primary: string, fallback: string): string | undefined {
  return env[primary] || env[fallback] || undefined;
}

function parseMode(value: string | undefined): AccountsStorageMode {
  if (value === "remote" || value === "s3") return "remote";
  if (value === "hybrid") return "hybrid";
  return "local";
}

function parseBoolean(value: string | undefined): boolean | undefined {
  if (!value) return undefined;
  if (["1", "true", "yes"].includes(value.toLowerCase())) return true;
  if (["0", "false", "no"].includes(value.toLowerCase())) return false;
  return undefined;
}

function normalizePrefix(prefix: string | undefined): string {
  if (!prefix) return "accounts/";
  return prefix.endsWith("/") ? prefix : `${prefix}/`;
}

export function getAccountsStorageConfig(env: NodeJS.ProcessEnv = process.env): AccountsStorageConfig {
  return {
    mode: parseMode(firstEnv(env, ACCOUNTS_STORAGE_ENV.mode, ACCOUNTS_STORAGE_FALLBACK_ENV.mode)),
    s3Bucket: firstEnv(env, ACCOUNTS_STORAGE_ENV.s3Bucket, ACCOUNTS_STORAGE_FALLBACK_ENV.s3Bucket),
    s3Prefix: normalizePrefix(firstEnv(env, ACCOUNTS_STORAGE_ENV.s3Prefix, ACCOUNTS_STORAGE_FALLBACK_ENV.s3Prefix)),
    awsRegion: firstEnv(env, ACCOUNTS_STORAGE_ENV.awsRegion, ACCOUNTS_STORAGE_FALLBACK_ENV.awsRegion),
    s3Endpoint: firstEnv(env, ACCOUNTS_STORAGE_ENV.s3Endpoint, ACCOUNTS_STORAGE_FALLBACK_ENV.s3Endpoint),
    s3ForcePathStyle: parseBoolean(firstEnv(env, ACCOUNTS_STORAGE_ENV.s3ForcePathStyle, ACCOUNTS_STORAGE_FALLBACK_ENV.s3ForcePathStyle)),
    machineId: firstEnv(env, ACCOUNTS_STORAGE_ENV.machineId, ACCOUNTS_STORAGE_FALLBACK_ENV.machineId) ?? hostname(),
  };
}

export function getAccountsStorageStatus(env: NodeJS.ProcessEnv = process.env): AccountsStorageStatus {
  const config = getAccountsStorageConfig(env);
  return {
    configured: config.mode === "local" || Boolean(config.s3Bucket),
    mode: config.mode,
    local: {
      home: accountsHome(),
      storePath: storePath(),
      profilesDir: profilesDir(),
    },
    remote: {
      configured: Boolean(config.s3Bucket),
      bucketEnv: env[ACCOUNTS_STORAGE_ENV.s3Bucket] ? ACCOUNTS_STORAGE_ENV.s3Bucket : ACCOUNTS_STORAGE_FALLBACK_ENV.s3Bucket,
      bucket: config.s3Bucket,
      prefix: config.s3Prefix,
      regionEnv: env[ACCOUNTS_STORAGE_ENV.awsRegion] ? ACCOUNTS_STORAGE_ENV.awsRegion : ACCOUNTS_STORAGE_FALLBACK_ENV.awsRegion,
      endpointConfigured: Boolean(config.s3Endpoint),
    },
    env: ACCOUNTS_STORAGE_ENV,
    fallbackEnv: ACCOUNTS_STORAGE_FALLBACK_ENV,
    tables: STORAGE_TABLES,
  };
}

export function createAccountsStorageSnapshot(env: NodeJS.ProcessEnv = process.env): AccountsStorageSnapshot {
  const config = getAccountsStorageConfig(env);
  return {
    schemaVersion: 1,
    source: "accounts",
    createdAt: new Date().toISOString(),
    machineId: config.machineId,
    store: loadStore(),
  };
}

export function restoreAccountsStorageSnapshot(snapshot: AccountsStorageSnapshot): void {
  if (snapshot.schemaVersion !== 1 || snapshot.source !== "accounts") {
    throw new AccountsError("invalid accounts storage snapshot");
  }
  saveStore(snapshot.store);
}

export function accountsStorageSnapshotKey(env: NodeJS.ProcessEnv = process.env): string {
  const config = getAccountsStorageConfig(env);
  return `${config.s3Prefix}accounts.json`;
}

async function getS3Client(config: AccountsStorageConfig) {
  const { S3Client } = await import("@aws-sdk/client-s3");
  return new S3Client({
    region: config.awsRegion,
    endpoint: config.s3Endpoint,
    forcePathStyle: config.s3ForcePathStyle,
  });
}

async function bodyToString(body: unknown): Promise<string> {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body && typeof (body as { transformToString?: () => Promise<string> }).transformToString === "function") {
    return (body as { transformToString: () => Promise<string> }).transformToString();
  }
  throw new AccountsError("unsupported S3 response body");
}

export async function storagePush(env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  const config = getAccountsStorageConfig(env);
  const key = accountsStorageSnapshotKey(env);
  if (!config.s3Bucket) {
    return { mode: config.mode, pushed: 0, pulled: 0, skipped: true, key, reason: "S3 bucket is not configured" };
  }

  const { PutObjectCommand } = await import("@aws-sdk/client-s3");
  const client = await getS3Client(config);
  const snapshot = createAccountsStorageSnapshot(env);
  await client.send(new PutObjectCommand({
    Bucket: config.s3Bucket,
    Key: key,
    Body: JSON.stringify(snapshot, null, 2) + "\n",
    ContentType: "application/json",
  }));
  return { mode: config.mode, pushed: 1, pulled: 0, skipped: false, key };
}

export async function storagePull(env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  const config = getAccountsStorageConfig(env);
  const key = accountsStorageSnapshotKey(env);
  if (!config.s3Bucket) {
    return { mode: config.mode, pushed: 0, pulled: 0, skipped: true, key, reason: "S3 bucket is not configured" };
  }

  const { GetObjectCommand } = await import("@aws-sdk/client-s3");
  const client = await getS3Client(config);
  const result = await client.send(new GetObjectCommand({ Bucket: config.s3Bucket, Key: key }));
  const snapshot = JSON.parse(await bodyToString(result.Body)) as AccountsStorageSnapshot;
  restoreAccountsStorageSnapshot(snapshot);
  return { mode: config.mode, pushed: 0, pulled: 1, skipped: false, key };
}

export async function storageSync(env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  const config = getAccountsStorageConfig(env);
  const key = accountsStorageSnapshotKey(env);
  if (!config.s3Bucket) {
    return { mode: config.mode, pushed: 0, pulled: 0, skipped: true, key, reason: "S3 bucket is not configured" };
  }
  const pull = await storagePull(env);
  const push = await storagePush(env);
  return { mode: config.mode, pushed: push.pushed, pulled: pull.pulled, skipped: false, key };
}

export const getStorageStatus = getAccountsStorageStatus;
