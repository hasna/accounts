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
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import {
  type NormalizedStore,
  type Store,
  storeSchema,
  AccountsError,
  profileNameSchema,
} from "./types.js";
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

const EMPTY_STORE: NormalizedStore = {
  version: 1,
  current: {},
  currentRevisions: {},
  applied: {},
  appliedRevisions: {},
  toolLocks: {},
  profiles: [],
  tools: [],
};

const storeSnapshots = new WeakMap<object, string | null>();
let storeLockDepth = 0;
const REGISTRY_RECLAIM_CLAIM_STALE_MS = 1_000;

function delayRegistryLockInitializationForTest(): void {
  if (process.env.NODE_ENV !== "test") return;
  const marker = process.env.ACCOUNTS_TEST_STORE_LOCK_INIT_MARKER;
  if (marker) {
    assertSafeWritePath(marker, { mustStayUnder: accountsHome() });
    writeFileSync(marker, "initializing\n", { mode: 0o600 });
  }
  const delayMs = Number(process.env.ACCOUNTS_TEST_STORE_LOCK_INIT_DELAY_MS ?? 0);
  if (Number.isFinite(delayMs) && delayMs > 0) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
  }
}

function currentStoreText(): string | null {
  const path = storePath();
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

interface RegistryLockObservation {
  text: string;
  dev: number;
  ino: number;
  stale: boolean;
}

function linuxProcessStartId(pid: number): string | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd < 0) return undefined;
    // Fields after the command begin at procfs field 3 (state); starttime is
    // field 22, so it is index 19 in this suffix.
    const startTime = stat.slice(commandEnd + 1).trim().split(/\s+/)[19];
    return startTime && /^\d+$/.test(startTime) ? `linux-${startTime}` : undefined;
  } catch {
    return undefined;
  }
}

function portableProcessStartId(pid: number): string | undefined {
  if (process.env.NODE_ENV === "test") {
    const override = process.env.ACCOUNTS_TEST_PROCESS_START_ID;
    const separator = override?.indexOf(":") ?? -1;
    if (override && separator > 0 && Number(override.slice(0, separator)) === pid) {
      return override.slice(separator + 1) || undefined;
    }
  }
  const linux = linuxProcessStartId(pid);
  if (linux) return linux;
  if (process.platform !== "darwin") return undefined;
  try {
    const result = spawnSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      // `lstart` is rendered in the child's timezone. Pin it so two Accounts
      // processes with different TZ environments derive the same identity for
      // one kernel process and never steal a live owner's lock.
      env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1_000,
    });
    const startedAt = result.status === 0 ? result.stdout.trim().replace(/\s+/g, " ") : "";
    if (!startedAt) return undefined;
    return `darwin-${createHash("sha256").update(startedAt).digest("hex").slice(0, 24)}`;
  } catch {
    return undefined;
  }
}

function isVerifiableProcessIncarnation(value: string | undefined): value is string {
  return Boolean(value && /^(?:linux|darwin)-/.test(value));
}

const processIncarnation = portableProcessStartId(process.pid) ?? `fallback-${randomUUID()}`;

function registryLockOwner(text: string): { pid?: number; incarnation?: string } {
  const owner = text.trim();
  const parts = owner.split(":");
  if (parts[0] === "v2") {
    const pid = Number(parts[1]);
    return {
      ...(Number.isSafeInteger(pid) && pid > 0 ? { pid } : {}),
      ...(parts[2] ? { incarnation: parts[2] } : {}),
    };
  }
  const pid = Number(parts[0]);
  return Number.isSafeInteger(pid) && pid > 0 ? { pid } : {};
}

function observeRegistryLock(path: string): RegistryLockObservation | undefined {
  let text = "";
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new AccountsError(`invalid accounts registry lock at ${path}`);
    }
    text = readFileSync(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  const owner = registryLockOwner(text);
  let stale: boolean;
  if (owner.pid) {
    if (owner.pid === process.pid) {
      // No in-process lease exists while this acquisition loop is running.
      // A different token for our PID therefore belongs to an earlier process
      // incarnation (notably PID 1 after a container restart), but only when
      // both identities came from an OS start-time source. Worker/module
      // isolates share a PID and may have distinct fallback tokens.
      stale =
        isVerifiableProcessIncarnation(owner.incarnation) &&
        isVerifiableProcessIncarnation(processIncarnation) &&
        owner.incarnation !== processIncarnation;
    } else {
      const observedIncarnation = portableProcessStartId(owner.pid);
      if (
        isVerifiableProcessIncarnation(owner.incarnation) &&
        isVerifiableProcessIncarnation(observedIncarnation)
      ) {
        stale = owner.incarnation !== observedIncarnation;
      } else {
        try {
          process.kill(owner.pid, 0);
          stale = false;
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code !== "ESRCH") throw error;
          stale = true;
        }
      }
    }
  } else {
    // A process can die between exclusive creation and writing its identity.
    // Do not steal a freshly created empty lock, but reclaim it after that tiny
    // initialization window.
    stale = Date.now() - stat.mtimeMs >= 1_000;
  }
  return { text, dev: stat.dev, ino: stat.ino, stale };
}

function removeObservedRegistryLock(path: string, observed: RegistryLockObservation): boolean {
  const claimHash = createHash("sha256")
    .update(`${observed.dev}:${observed.ino}:`)
    .update(observed.text)
    .digest("hex")
    .slice(0, 24);
  const claimPath = `${path}.reclaim-${claimHash}`;
  assertSafeWritePath(claimPath, { mustStayUnder: accountsHome() });
  let claimed = false;
  try {
    // Hard-linking is the atomic claim. Every reclaimer for this exact inode
    // and owner token targets the same claim path, so only one can progress to
    // unlinking the shared lock name. A loser re-observes on its next loop and
    // cannot delete a replacement lease.
    try {
      linkSync(path, claimPath);
      claimed = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return false;
      if (code === "EEXIST") {
        // The claimant can die after creating the hard link. A fresh claim is
        // left alone because its synchronous owner may still be validating it;
        // an old claim bound to this exact stale inode is safe to discard and
        // retry. The inode checks prevent touching a replacement registry lock.
        let claim: ReturnType<typeof lstatSync>;
        let current: ReturnType<typeof lstatSync>;
        try {
          claim = lstatSync(claimPath);
          current = lstatSync(path);
        } catch (claimError) {
          if ((claimError as NodeJS.ErrnoException).code === "ENOENT") return false;
          throw claimError;
        }
        if (
          !claim.isFile() ||
          claim.isSymbolicLink() ||
          claim.dev !== observed.dev ||
          claim.ino !== observed.ino ||
          current.dev !== observed.dev ||
          current.ino !== observed.ino ||
          Date.now() - claim.ctimeMs < REGISTRY_RECLAIM_CLAIM_STALE_MS ||
          readFileSync(path, "utf8") !== observed.text
        ) {
          return false;
        }
        rmSync(claimPath);
        try {
          linkSync(path, claimPath);
          claimed = true;
        } catch (retryError) {
          const retryCode = (retryError as NodeJS.ErrnoException).code;
          if (retryCode === "EEXIST" || retryCode === "ENOENT") return false;
          throw retryError;
        }
      } else {
        throw error;
      }
    }
    const claim = lstatSync(claimPath);
    if (claim.dev !== observed.dev || claim.ino !== observed.ino) return false;
    const current = lstatSync(path);
    if (!current.isFile() || current.isSymbolicLink()) return false;
    if (current.dev !== observed.dev || current.ino !== observed.ino) return false;
    if (readFileSync(path, "utf8") !== observed.text) return false;
    rmSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  } finally {
    if (claimed) {
      try {
        const claim = lstatSync(claimPath);
        if (claim.dev === observed.dev && claim.ino === observed.ino) rmSync(claimPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
}

/** Serialize cross-process registry transactions. Nested calls in one process reuse the lease. */
export function withStoreLock<T>(fn: () => T, timeoutMs = 5_000): T {
  if (storeLockDepth > 0) return fn();
  const home = accountsHome();
  mkdirSync(home, { recursive: true });
  const path = join(home, ".store.lock");
  assertSafeWritePath(path, { mustStayUnder: home });
  const deadline = Date.now() + timeoutMs;
  let acquired: RegistryLockObservation | undefined;
  while (!acquired) {
    if (Date.now() >= deadline) {
      throw new AccountsError(`timed out waiting for the accounts registry lock at ${path}`);
    }
    const candidatePath = `${path}.candidate-${process.pid}-${randomUUID()}`;
    assertSafeWritePath(candidatePath, { mustStayUnder: home });
    let candidateFd: number | undefined;
    let linked = false;
    let published: RegistryLockObservation | undefined;
    try {
      candidateFd = openSync(candidatePath, "wx", 0o600);
      delayRegistryLockInitializationForTest();
      const text = `v2:${process.pid}:${processIncarnation}:${randomUUID()}\n`;
      writeFileSync(candidateFd, text, { encoding: "utf8", mode: 0o600 });
      fsyncSync(candidateFd);
      const candidate = fstatSync(candidateFd);
      published = { text, dev: candidate.dev, ino: candidate.ino, stale: false };
      try {
        // Publish only a fully initialized inode. Unlike opening the canonical
        // path directly, this leaves no empty-lock window for a reclaimer to
        // unlink while the creator is suspended.
        linkSync(candidatePath, path);
        linked = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      if (linked) {
        try {
          const current = lstatSync(path);
          if (
            current.isFile() &&
            !current.isSymbolicLink() &&
            current.dev === candidate.dev &&
            current.ino === candidate.ino &&
            readFileSync(path, "utf8") === text
          ) {
            acquired = published;
          }
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      }
    } finally {
      if (candidateFd !== undefined) closeSync(candidateFd);
      rmSync(candidatePath, { force: true });
    }
    if (linked && !acquired && published) removeObservedRegistryLock(path, published);
    if (!acquired) {
      const observed = observeRegistryLock(path);
      if (!observed) continue;
      if (observed.stale && removeObservedRegistryLock(path, observed)) {
        continue;
      }
      if (Date.now() >= deadline) {
        throw new AccountsError(`timed out waiting for the accounts registry lock at ${path}`);
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  storeLockDepth += 1;
  try {
    return fn();
  } finally {
    storeLockDepth -= 1;
    removeObservedRegistryLock(path, acquired);
  }
}

/**
 * Parse and schema-validate the on-box registry file WITHOUT the profile
 * cross-pruning that `loadStore()` applies. Returns the empty store when the
 * file is absent. Used by both `loadStore()` (which then prunes against the
 * local profile list) and the machine-local pointer readers, which must NOT
 * prune: in api mode the profile records live in the cloud, so pruning a
 * machine-local `applied`/`current` pointer against the (empty) local profile
 * list would wrongly erase a valid pointer.
 */
function parseStoreFile(): NormalizedStore {
  const path = storePath();
  const source = currentStoreText();
  if (source === null) {
    const empty = structuredClone(EMPTY_STORE);
    storeSnapshots.set(empty, null);
    return empty;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch (err) {
    throw new AccountsError(`could not parse store at ${path}: ${(err as Error).message}`);
  }
  const parsed = storeSchema.safeParse(raw);
  if (!parsed.success) {
    throw new AccountsError(`invalid store at ${path}: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  }
  storeSnapshots.set(parsed.data, source);
  return parsed.data;
}

/** Raw validated machine state without pruning pointers against local profiles. */
export function loadMachineStore(): NormalizedStore {
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
  withStoreLock(() => {
    const store = parseStoreFile();
    let changed = false;
    if (store.current[toolId] === oldName) {
      store.current[toolId] = newName;
      store.currentRevisions[toolId] = randomUUID();
      changed = true;
    }
    if (store.applied[toolId] === oldName) {
      store.applied[toolId] = newName;
      store.appliedRevisions[toolId] = randomUUID();
      changed = true;
    }
    if (store.toolLocks[oldName] === toolId) {
      delete store.toolLocks[oldName];
      store.toolLocks[newName] = toolId;
      changed = true;
    }
    if (changed) saveStoreLocked(store);
  });
}

export function reconcileMachineProfileRemove(toolId: string, name: string): void {
  withStoreLock(() => {
    const store = parseStoreFile();
    let changed = false;
    if (store.current[toolId] === name) {
      delete store.current[toolId];
      delete store.currentRevisions[toolId];
      changed = true;
    }
    if (store.applied[toolId] === name) {
      delete store.applied[toolId];
      delete store.appliedRevisions[toolId];
      changed = true;
    }
    if (store.toolLocks[name] === toolId) {
      delete store.toolLocks[name];
      changed = true;
    }
    if (changed) saveStoreLocked(store);
  });
}

export function loadStore(): NormalizedStore {
  const store = parseStoreFile();
  for (const p of store.profiles) {
    const check = profileNameSchema.safeParse(p.name);
    if (!check.success) {
      throw new AccountsError(`invalid profile name in store "${p.name}": ${check.error.issues[0]?.message}`);
    }
  }
  for (const toolId of Object.keys(store.current)) {
    const name = store.current[toolId];
    if (!name || !profileNameSchema.safeParse(name).success) {
      delete store.current[toolId];
      delete store.currentRevisions[toolId];
    } else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) {
      delete store.current[toolId];
      delete store.currentRevisions[toolId];
    }
  }
  for (const toolId of Object.keys(store.currentRevisions)) {
    if (!store.current[toolId]) delete store.currentRevisions[toolId];
  }
  for (const toolId of Object.keys(store.applied)) {
    const name = store.applied[toolId];
    if (!name || !profileNameSchema.safeParse(name).success) {
      delete store.applied[toolId];
      delete store.appliedRevisions[toolId];
    } else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) {
      delete store.applied[toolId];
      delete store.appliedRevisions[toolId];
    }
  }
  for (const toolId of Object.keys(store.appliedRevisions)) {
    if (!store.applied[toolId]) delete store.appliedRevisions[toolId];
  }
  for (const name of Object.keys(store.toolLocks)) {
    const toolId = store.toolLocks[name];
    if (!profileNameSchema.safeParse(name).success || !toolId) delete store.toolLocks[name];
    else if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) delete store.toolLocks[name];
  }
  return store;
}

function saveStoreLocked(store: Store): void {
  const path = storePath();
  const parsed = storeSchema.safeParse(store);
  if (!parsed.success) {
    throw new AccountsError(`invalid store: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  }
  const expected = storeSnapshots.get(store);
  if (expected !== undefined && currentStoreText() !== expected) {
    throw new AccountsError("accounts registry changed concurrently; retry the operation");
  }
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  mkdirSync(join(path, ".."), { recursive: true });
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, { mustStayUnder: accountsHome() });
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    const serialized = JSON.stringify(parsed.data, null, 2) + "\n";
    writeFileSync(fd, serialized, "utf8");
    chmodSync(temp, 0o600);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    storeSnapshots.set(store, serialized);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

export function saveStore(store: Store): void {
  withStoreLock(() => saveStoreLocked(store));
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
