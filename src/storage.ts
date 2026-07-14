// Local, on-box primitives for the accounts registry file.
//
// This module owns ONLY the machine-local JSON registry at
// `~/.hasna/accounts/accounts.json` (and the managed profiles dir). It is the
// filesystem backend behind `LocalStore` in `./lib/store.ts`. There is no S3 /
// "remote" / "hybrid" storage tier here: the single storage abstraction is the
// `AccountsStore` in `./lib/store.ts`, whose only two transports are LocalStore
// (these primitives) and ApiStore (the `<API_URL>/v1` HTTP client). Self-hosted
// and cloud both route through ApiStore; nothing bypasses the Store.

import { homedir, hostname } from "node:os";
import { join } from "node:path";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { type Store, storeSchema, AccountsError, profileNameSchema } from "./types.js";
import { assertSafeWritePath } from "./lib/safe-path.js";

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

const EMPTY_STORE: Store = { version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] };

/**
 * Parse and schema-validate the on-box registry file WITHOUT the profile
 * cross-pruning that `loadStore()` applies. Returns the empty store when the
 * file is absent. Used by both `loadStore()` (which then prunes against the
 * local profile list) and the machine-local pointer readers, which must NOT
 * prune: in api mode the profile records live in the cloud, so pruning a
 * machine-local `applied`/`current` pointer against the (empty) local profile
 * list would wrongly erase a valid pointer.
 */
function parseStoreFile(): Store {
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
  return parsed.data;
}

/** Raw validated machine state without pruning pointers against local profiles. */
export function loadMachineStore(): Store {
  return parseStoreFile();
}

/**
 * The machine-local `applied` pointer map (toolId -> profile name): which
 * profile's auth is currently restored to each tool's live default paths on
 * THIS machine. This is genuinely machine-local state (never in the shared
 * cloud registry), so readiness/doctor read it here regardless of storage mode.
 * Entries are validated for name shape only — a pointer to a profile that no
 * longer exists is preserved so `accounts doctor` can flag it as stale.
 */
export function loadAppliedMap(): Record<string, string> {
  const applied: Record<string, string> = {};
  for (const [toolId, name] of Object.entries(parseStoreFile().applied)) {
    if (name && profileNameSchema.safeParse(name).success) applied[toolId] = name;
  }
  return applied;
}

export function loadCurrentMap(): Record<string, string> {
  const current: Record<string, string> = {};
  for (const [toolId, name] of Object.entries(parseStoreFile().current)) {
    if (name && profileNameSchema.safeParse(name).success) current[toolId] = name;
  }
  return current;
}

export function reconcileMachineProfileRename(toolId: string, oldName: string, newName: string): void {
  const store = parseStoreFile();
  let changed = false;
  if (store.current[toolId] === oldName) {
    store.current[toolId] = newName;
    changed = true;
  }
  if (store.applied[toolId] === oldName) {
    store.applied[toolId] = newName;
    changed = true;
  }
  if (store.toolLocks[oldName] === toolId) {
    delete store.toolLocks[oldName];
    store.toolLocks[newName] = toolId;
    changed = true;
  }
  if (changed) saveStore(store);
}

export function reconcileMachineProfileRemove(toolId: string, name: string): void {
  const store = parseStoreFile();
  let changed = false;
  if (store.current[toolId] === name) {
    delete store.current[toolId];
    changed = true;
  }
  if (store.applied[toolId] === name) {
    delete store.applied[toolId];
    changed = true;
  }
  if (store.toolLocks[name] === toolId) {
    delete store.toolLocks[name];
    changed = true;
  }
  if (changed) saveStore(store);
}

export function loadStore(): Store {
  const store = parseStoreFile();
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
  for (const name of Object.keys(store.toolLocks)) {
    const toolId = store.toolLocks[name];
    if (!profileNameSchema.safeParse(name).success || !toolId) delete store.toolLocks[name];
    else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) delete store.toolLocks[name];
  }
  return store;
}

export function saveStore(store: Store): void {
  const path = storePath();
  const parsed = storeSchema.safeParse(store);
  if (!parsed.success) {
    throw new AccountsError(`invalid store: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  }
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  mkdirSync(join(path, ".."), { recursive: true });
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, { mustStayUnder: accountsHome() });
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    writeFileSync(fd, JSON.stringify(parsed.data, null, 2) + "\n", "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    chmodSync(path, 0o600);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

/**
 * Deprecated source-compatibility shims for the pre-AccountsStore storage API.
 * They intentionally contain no cloud-provider implementation.
 */
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
export type AccountsStorageMode = "local" | "self_hosted" | "cloud" | "remote" | "hybrid";

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
  local: { home: string; storePath: string; profilesDir: string };
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

function compatibilityMode(env: NodeJS.ProcessEnv): AccountsStorageMode {
  const value = (env.HASNA_ACCOUNTS_STORAGE_MODE || env.ACCOUNTS_STORAGE_MODE || "").trim().toLowerCase();
  if (value === "cloud" || value === "self_hosted") return value;
  return "local";
}

/** @deprecated Use resolveStore() and AccountsStore.transport. */
export function getAccountsStorageConfig(env: NodeJS.ProcessEnv = process.env): AccountsStorageConfig {
  return {
    mode: compatibilityMode(env),
    s3Prefix: "accounts/",
    machineId: env.HASNA_ACCOUNTS_MACHINE_ID || env.ACCOUNTS_MACHINE_ID || hostname(),
  };
}

/** @deprecated Use resolveStore(), health, or readiness. */
export function getAccountsStorageStatus(env: NodeJS.ProcessEnv = process.env): AccountsStorageStatus {
  const config = getAccountsStorageConfig(env);
  const apiConfigured = Boolean(
    (env.HASNA_ACCOUNTS_API_URL || env.ACCOUNTS_API_URL) &&
    (env.HASNA_ACCOUNTS_API_KEY || env.ACCOUNTS_API_KEY),
  );
  return {
    configured: config.mode === "local" || apiConfigured,
    mode: config.mode,
    local: { home: accountsHome(), storePath: storePath(), profilesDir: profilesDir() },
    remote: {
      configured: false,
      bucketEnv: ACCOUNTS_STORAGE_ENV.s3Bucket,
      prefix: config.s3Prefix,
      regionEnv: ACCOUNTS_STORAGE_ENV.awsRegion,
      endpointConfigured: false,
    },
    env: ACCOUNTS_STORAGE_ENV,
    fallbackEnv: ACCOUNTS_STORAGE_FALLBACK_ENV,
    tables: STORAGE_TABLES,
  };
}

/** @deprecated Local snapshot compatibility only. */
export function createAccountsStorageSnapshot(env: NodeJS.ProcessEnv = process.env): AccountsStorageSnapshot {
  return {
    schemaVersion: 1,
    source: "accounts",
    createdAt: new Date().toISOString(),
    machineId: getAccountsStorageConfig(env).machineId,
    store: loadMachineStore(),
  };
}

/** @deprecated Local snapshot compatibility only. */
export function restoreAccountsStorageSnapshot(snapshot: AccountsStorageSnapshot): void {
  if (snapshot.schemaVersion !== 1 || snapshot.source !== "accounts") {
    throw new AccountsError("invalid accounts storage snapshot");
  }
  saveStore(snapshot.store);
}

/** @deprecated The provider-backed snapshot transport was retired. */
export function accountsStorageSnapshotKey(_env: NodeJS.ProcessEnv = process.env): string {
  return "accounts/accounts.json";
}

function retiredSyncError(): AccountsError {
  return new AccountsError(
    "legacy storage sync was retired; use local mode or configure the Accounts API for self_hosted/cloud mode",
  );
}

/** @deprecated Always rejects; provider-backed sync was retired. */
export async function storagePush(_env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  throw retiredSyncError();
}

/** @deprecated Always rejects; provider-backed sync was retired. */
export async function storagePull(_env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  throw retiredSyncError();
}

/** @deprecated Always rejects; provider-backed sync was retired. */
export async function storageSync(_env: NodeJS.ProcessEnv = process.env): Promise<AccountsStorageSyncResult> {
  throw retiredSyncError();
}

/** @deprecated Alias retained for source compatibility. */
export const getStorageStatus = getAccountsStorageStatus;
