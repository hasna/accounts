// The single storage abstraction for the accounts *registry*.
//
// One `AccountsStore` interface, two transports behind it:
//   - LocalStore: on-box JSON registry (`~/.hasna/accounts/accounts.json`).
//   - ApiStore:   the self-hosted/cloud HTTP API at `<API_URL>/v1` + bearer key.
//
// `resolveStore()` is the mode resolver: when `HASNA_ACCOUNTS_API_URL` +
// `HASNA_ACCOUNTS_API_KEY` are set (and mode is not explicitly `local`), every
// registry read/write routes to the cloud ApiStore. Explicit API modes fail
// closed when either value is missing; an unset mode defaults to local. Both
// `self_hosted` and `cloud` deployments use the SAME ApiStore code — only the
// URL/key differ (server-side tenancy, not client logic).
//
// SCOPE: the Store owns the shared registry — profiles, their metadata, and the
// per-tool "current" selection. Genuinely machine-local state (a profile's
// on-disk config `dir`, the `applied` auth map, tool locks, launching a tool)
// is not part of the shared registry and is handled by the local orchestration
// modules (apply.ts, switch.ts, launch). Those read the profile record through
// this Store, then act on the local machine.
//
// No CLI command, MCP tool, or SDK method touches sqlite or issues raw fetch —
// the only two backends are LocalStore (fs) and ApiStore (@hasna/contracts HTTP
// transport). The bearer key never appears in output or logs.

import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  captureMachineProfileAuthSlotExpectation,
  captureMachineProfileReconcileExpectation,
  findProfileAuthRevisionKey,
  profilesDir,
  profileAuthIncarnation,
  reconcileMachineProfileCreate,
  reconcileMachineProfileRemove,
  reconcileMachineProfileRename,
} from "../storage.js";
import {
  DEFAULT_TOOL,
  getTool,
  isBuiltinTool,
  listTools as localListTools,
  addCustomTool as localAddCustomTool,
  removeCustomTool as localRemoveCustomTool,
  setCustomToolsCache,
  clearCustomToolsCache,
  BUILTIN_TOOLS,
} from "./tools.js";
import { profileNameSchema, profileSchema, toolDefSchema } from "../types.js";
import { detectEmail } from "./detect.js";
import {
  addProfile as localAdd,
  currentProfile as localCurrent,
  expandPath,
  findProfile as localFind,
  getProfile as localGet,
  listProfiles as localList,
  redetectEmail as localRedetect,
  removeProfile as localRemove,
  renameProfile as localRename,
  updateProfile as localUpdate,
  useProfile as localUse,
  type AddOptions,
  type RemoveOptions,
  type UpdateOptions,
} from "./profiles.js";
import { accountsHome, loadMachineStore, loadStore, saveStore, withStoreLock } from "../storage.js";
import { resolveAccountsCloud, type AccountsCloudApi } from "./cloud-accounts.js";
import { assertSafeWritePath } from "./safe-path.js";

export interface CurrentEntry {
  tool: string;
  name: string;
  /** Present for generation-aware stores; optional for source compatibility with custom stores. */
  revision?: string;
}

export interface ProfileRollbackFields {
  email?: { expected: string | null; restore: string | null };
  lastUsedAt?: { expected: string | null; restore: string | null };
}

export interface ProfileRollbackOwnership {
  authIdentity?: string;
  authCommitRevision?: string;
}

export interface UseProfileResult {
  profile: Profile;
  toolId: string;
  currentRevision?: string;
  /** Selection displaced by this exact activation, captured atomically at the write. */
  previousCurrentName?: string;
  /** Target profile timestamp displaced by this exact activation. */
  previousProfileLastUsedAt?: string;
}

export interface RemoveResult {
  profile: Profile;
  purged: boolean;
  purgeNote?: string;
}

export interface LoginCreatedProfile {
  profile: Profile;
  createdProfileDir: boolean;
}

export interface LoginProfileCreationPlan {
  cleanupOperationId: string;
  cleanupRequestedAt: string;
  plannedIncarnationId: string;
  plannedAuthIdentity?: string;
}

export interface CreatedProfileRollbackOwnership {
  /** Durable cleanup replay token; supplied internally when resuming an interrupted rollback. */
  cleanupOperationId?: string;
  /** Original operation time used to bound destructive replay retention. */
  cleanupRequestedAt?: string;
  toolLockRevision?: string;
  previousToolLock?: string;
  previousToolLockRevision?: string;
  previousToolLockProfileIncarnation?: string;
  authIdentity?: string;
  authCommitRevision?: string;
}

/** The single registry surface. LocalStore and ApiStore both implement it. */
export interface AccountsStore {
  readonly transport: "local" | "api";
  /** Real API stores require a server-issued profile incarnation before login can launch. */
  readonly requiresProfileIncarnationRollback?: boolean;
  listProfiles(tool?: string): Promise<Profile[]>;
  getProfile(name: string, tool?: string): Promise<Profile>;
  findProfile(name: string, tool?: string): Promise<Profile | undefined>;
  addProfile(opts: AddOptions): Promise<Profile>;
  /** Create a login profile while atomically recording ownership of its managed directory. */
  addProfileForLogin?(
    opts: AddOptions,
    plan?: LoginProfileCreationPlan,
  ): Promise<LoginCreatedProfile>;
  updateProfile(name: string, opts: UpdateOptions): Promise<Profile>;
  renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile>;
  removeProfile(name: string, opts?: RemoveOptions): Promise<RemoveResult>;
  /** Upgrade a legacy local profile only after login permission/tool validation authorized mutation. */
  upgradeProfileIncarnationForLogin?(
    profile: Profile,
    plannedIncarnationId?: string,
  ): Promise<Profile>;
  /** Fail closed before creating an API profile unless exact conditional cleanup is supported. */
  assertCreatedProfileCleanup?(): Promise<void>;
  /** Finish directory cleanup journaled by an interrupted, already-authorized login rollback. */
  reconcileInterruptedLoginCleanup?(name: string, tool: string): Promise<void>;
  /** Remove a login-created profile only while every recorded ownership generation still matches. */
  removeProfileIncarnation?(
    profile: Profile,
    ownership: CreatedProfileRollbackOwnership,
    opts?: RemoveOptions,
  ): Promise<RemoveResult | undefined>;
  redetectEmail(name: string, tool?: string, expectedProfile?: Profile): Promise<Profile>;
  /** Restore fields that login finalization may have changed. */
  restoreProfileState?(
    profile: Profile,
    fields: ProfileRollbackFields,
    ownership?: ProfileRollbackOwnership,
  ): Promise<Profile>;
  useProfile(name: string, tool?: string): Promise<UseProfileResult>;
  /** Activate through a generation-capable endpoint that old API replicas cannot mutate. */
  useProfileForLogin?(
    name: string,
    tool: string | undefined,
    operationId: string,
    expectedProfile?: Profile,
  ): Promise<UseProfileResult>;
  /** Legacy name-only conditional restore/clear retained for public API compatibility. */
  restoreCurrent(tool: string, expectedName: string, name?: string): Promise<boolean>;
  /** Conditionally restore/clear current only when it still has the failed login write generation. */
  restoreCurrentGeneration?(tool: string, expectedName: string, expectedRevision: string, name?: string): Promise<boolean>;
  restoreCurrentOperation?(
    tool: string,
    expectedName: string,
    operationId: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean>;
  currentProfile(tool: string): Promise<Profile | undefined>;
  listCurrent(): Promise<CurrentEntry[]>;
  /** Strict generation-aware current snapshot used only before transactional login. */
  listCurrentForLoginRollback?(): Promise<CurrentEntry[]>;
  /** All tools (built-in + custom) known to the active registry. */
  listTools(): Promise<ToolDef[]>;
  /** Resolve a tool after hydrating the active registry's custom definitions. */
  resolveTool(toolId: string): Promise<ToolDef>;
  /** Register (or update) a custom tool in the active registry. */
  addTool(def: ToolDef): Promise<ToolDef>;
  /** Remove a custom tool from the active registry. */
  removeTool(id: string): Promise<void>;
}

function profileDirectoryLeasePath(dir: string): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  const identity = createHash("sha256").update(resolve(dir)).digest("hex").slice(0, 32);
  const lockRoot = process.platform === "win32" ? tmpdir() : "/tmp";
  return join(lockRoot, `accounts-profile-directory-${uid}-${identity}.lock`);
}

function profileDirectoryLeaseTimeout(): number {
  if (process.env.NODE_ENV !== "test") return 600_000;
  const configured = Number(process.env.ACCOUNTS_TEST_PROFILE_DIRECTORY_LOCK_TIMEOUT_MS);
  return Number.isFinite(configured) && configured > 0 ? configured : 600_000;
}

function profileDirectoryProcessStartId(pid: number): string | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd >= 0) {
      const startTime = stat.slice(commandEnd + 1).trim().split(/\s+/)[19];
      if (startTime && /^\d+$/.test(startTime)) return `linux-${startTime}`;
    }
  } catch {
    // procfs is unavailable on non-Linux hosts.
  }
  if (process.platform !== "darwin") return undefined;
  try {
    const result = spawnSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8",
      env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 1_000,
    });
    const startedAt = result.status === 0 ? result.stdout.trim().replace(/\s+/g, " ") : "";
    return startedAt
      ? `darwin-${createHash("sha256").update(startedAt).digest("hex").slice(0, 24)}`
      : undefined;
  } catch {
    return undefined;
  }
}

function isVerifiableDirectoryProcessStartId(value: string | undefined): value is string {
  return Boolean(value && /^(?:linux|darwin)-/.test(value));
}

const profileDirectoryProcessIncarnation =
  profileDirectoryProcessStartId(process.pid) ?? `fallback-${randomUUID()}`;
const PROFILE_DIRECTORY_RECLAIM_CLAIM_STALE_MS = 1_000;

interface ProfileDirectoryLeaseObservation {
  text: string;
  dev: number;
  ino: number;
  stale: boolean;
}

function observeProfileDirectoryLease(path: string): ProfileDirectoryLeaseObservation | undefined {
  let stat: ReturnType<typeof lstatSync>;
  let text: string;
  try {
    stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new AccountsError("invalid profile directory lease; refusing unsafe reclaim");
    }
    text = readFileSync(path, "utf8");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ENOENT") return undefined;
    if (error instanceof AccountsError) throw error;
    throw new AccountsError(`failed to inspect profile directory lease: ${String(error)}`);
  }
  const match = text.trim().match(
    /^v2:([1-9]\d*):((?:linux|darwin)-[A-Za-z0-9-]+|fallback-[0-9a-f-]+):[0-9a-f-]+$/i,
  );
  const owner = match ? Number(match[1]) : Number.NaN;
  const ownerIncarnation = match?.[2];
  if (!Number.isSafeInteger(owner)) {
    return { text, dev: stat.dev, ino: stat.ino, stale: false };
  }
  let stale = false;
  if (owner === process.pid) {
    stale =
      isVerifiableDirectoryProcessStartId(ownerIncarnation) &&
      isVerifiableDirectoryProcessStartId(profileDirectoryProcessIncarnation) &&
      ownerIncarnation !== profileDirectoryProcessIncarnation;
  } else {
    const observedIncarnation = profileDirectoryProcessStartId(owner);
    if (
      isVerifiableDirectoryProcessStartId(ownerIncarnation) &&
      isVerifiableDirectoryProcessStartId(observedIncarnation)
    ) {
      stale = ownerIncarnation !== observedIncarnation;
    } else {
      try {
        process.kill(owner, 0);
      } catch (error) {
        stale = (error as NodeJS.ErrnoException).code === "ESRCH";
      }
    }
  }
  return { text, dev: stat.dev, ino: stat.ino, stale };
}

function removeObservedProfileDirectoryLease(
  path: string,
  observed: ProfileDirectoryLeaseObservation,
): boolean {
  const claimHash = createHash("sha256")
    .update(`${observed.dev}:${observed.ino}:`)
    .update(observed.text)
    .digest("hex")
    .slice(0, 24);
  const claimPath = `${path}.reclaim-${claimHash}`;
  let claimed = false;
  try {
    try {
      linkSync(path, claimPath);
      claimed = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return false;
      if (code !== "EEXIST") throw error;
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
        !claim.isFile() || claim.isSymbolicLink() ||
        claim.dev !== observed.dev || claim.ino !== observed.ino ||
        current.dev !== observed.dev || current.ino !== observed.ino ||
        Date.now() - claim.ctimeMs < PROFILE_DIRECTORY_RECLAIM_CLAIM_STALE_MS ||
        readFileSync(path, "utf8") !== observed.text
      ) {
        return false;
      }
      unlinkSync(claimPath);
      try {
        linkSync(path, claimPath);
        claimed = true;
      } catch (retryError) {
        const retryCode = (retryError as NodeJS.ErrnoException).code;
        if (retryCode === "EEXIST" || retryCode === "ENOENT") return false;
        throw retryError;
      }
    }
    const claim = lstatSync(claimPath);
    const current = lstatSync(path);
    if (
      claim.dev !== observed.dev || claim.ino !== observed.ino ||
      !current.isFile() || current.isSymbolicLink() ||
      current.dev !== observed.dev || current.ino !== observed.ino ||
      readFileSync(path, "utf8") !== observed.text
    ) {
      return false;
    }
    unlinkSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new AccountsError(`failed to reclaim profile directory lease: ${String(error)}`);
  } finally {
    if (claimed) {
      try {
        const claim = lstatSync(claimPath);
        if (claim.dev === observed.dev && claim.ino === observed.ino) unlinkSync(claimPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
}

async function acquireProfileDirectoryLease(dir: string): Promise<() => void> {
  const path = profileDirectoryLeasePath(dir);
  const token = `v2:${process.pid}:${profileDirectoryProcessIncarnation}:${randomUUID()}`;
  const deadline = Date.now() + profileDirectoryLeaseTimeout();

  while (true) {
    const candidate = `${path}.candidate-${process.pid}-${randomUUID()}`;
    let candidateFd: number | undefined;
    let published = false;
    try {
      candidateFd = openSync(candidate, "wx", 0o600);
      writeFileSync(candidateFd, token, { encoding: "utf8" });
      fsyncSync(candidateFd);
      closeSync(candidateFd);
      candidateFd = undefined;
      try {
        linkSync(candidate, path);
        published = true;
      } catch (error) {
        const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
        if (code !== "EEXIST") throw error;
      }
      if (published) {
        const owned = lstatSync(path);
        return () => {
          try {
            const current = lstatSync(path);
            if (
              current.isFile() &&
              !current.isSymbolicLink() &&
              current.dev === owned.dev &&
              current.ino === owned.ino &&
              readFileSync(path, "utf8") === token
            ) {
              unlinkSync(path);
            }
          } catch {
            // A missing or replaced lease belongs to no cleanup in this process.
          }
        };
      }
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
      if (code !== "EEXIST") {
        throw new AccountsError(`failed to acquire profile directory lease: ${String(error)}`);
      }
    } finally {
      if (candidateFd !== undefined) closeSync(candidateFd);
      rmSync(candidate, { force: true });
    }

    const observed = observeProfileDirectoryLease(path);
    if (!observed) continue;
    if (observed.stale && removeObservedProfileDirectoryLease(path, observed)) continue;
    if (Date.now() >= deadline) throw new AccountsError("timed out waiting for profile directory lease");
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
}

async function withProfileDirectoryLease<T>(dir: string, operation: () => Promise<T> | T): Promise<T> {
  const release = await acquireProfileDirectoryLease(dir);
  try {
    return await operation();
  } finally {
    release();
  }
}

const LOGIN_CLEANUP_MARKER = ".accounts-login-cleanup.json";
const LOGIN_CLEANUP_INTENTS_DIR = "login-cleanup-intents";

export type LoginCleanupFaultPoint =
  | "pre-create"
  | "post-create"
  | "post-lock"
  | "post-delete"
  | "post-lock-restore"
  | "pre-purge";

let loginCleanupFaultInjector: ((point: LoginCleanupFaultPoint) => void) | undefined;
const activeLoginCleanupOperations = new Set<string>();

export class LoginCleanupInProgressError extends AccountsError {}

class InjectedLoginCleanupFault extends Error {
  constructor(readonly point: LoginCleanupFaultPoint, options?: ErrorOptions) {
    super(`injected login cleanup fault at ${point}`, options);
    this.name = "InjectedLoginCleanupFault";
  }
}

/** Test-only abrupt-fault injection; production callers never install it. */
export function setLoginCleanupFaultInjectorForTests(
  injector?: (point: LoginCleanupFaultPoint) => void,
): void {
  if (process.env.NODE_ENV !== "test") {
    throw new AccountsError("login cleanup fault injection is test-only");
  }
  loginCleanupFaultInjector = injector;
}

export function injectLoginCleanupFaultForTests(
  point: LoginCleanupFaultPoint,
  cleanupOperationId?: string,
): void {
  if (!loginCleanupFaultInjector) return;
  try {
    loginCleanupFaultInjector(point);
  } catch (error) {
    if (cleanupOperationId) activeLoginCleanupOperations.delete(cleanupOperationId);
    throw new InjectedLoginCleanupFault(point, { cause: error });
  }
}

export function isInjectedLoginCleanupFault(error: unknown): boolean {
  return error instanceof InjectedLoginCleanupFault;
}

type LoginCleanupPhase =
  | "planned"
  | "profile-created"
  | "lock-planned"
  | "rollback";

export interface LoginCleanupIntent {
  version: 1;
  transport: "local" | "api";
  cleanupOperationId: string;
  cleanupRequestedAt: string;
  plannedIncarnationId: string;
  name: string;
  tool: string;
  dir: string;
  profileExisted: boolean;
  createdProfileDir: boolean;
  phase: LoginCleanupPhase;
  ownership: CreatedProfileRollbackOwnership;
  ownerPid: number;
  ownerProcessStartId: string;
}

interface LoginCleanupMarker {
  version: 1;
  cleanupOperationId: string;
  profile: Profile;
  ownership: CreatedProfileRollbackOwnership;
}

function fsyncDirectoryIfSupported(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Windows and a few filesystems reject directory handles/fsync. File data
    // is still fsynced, but we intentionally make no power-loss claim there.
    if (!["EINVAL", "ENOTSUP", "EOPNOTSUPP", "EPERM", "EACCES", "EISDIR"].includes(code ?? "")) {
      throw error;
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function publishAtomicJson(path: string, value: unknown, mustStayUnder: string): void {
  const parent = dirname(path);
  assertSafeWritePath(path, { mustStayUnder });
  const boundaryExisted = existsSync(mustStayUnder);
  mkdirSync(mustStayUnder, { recursive: true });
  if (!boundaryExisted) fsyncDirectoryIfSupported(dirname(mustStayUnder));
  const parentExisted = existsSync(parent);
  mkdirSync(parent, { recursive: true });
  if (!parentExisted) fsyncDirectoryIfSupported(dirname(parent));
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, { mustStayUnder });
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    writeFileSync(fd, JSON.stringify(value) + "\n", "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    fsyncDirectoryIfSupported(parent);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

function removePublishedFile(path: string, mustStayUnder: string): void {
  assertSafeWritePath(path, { mustStayUnder });
  if (!existsSync(path)) return;
  unlinkSync(path);
  fsyncDirectoryIfSupported(dirname(path));
}

function loginCleanupIntentPath(
  name: string,
  tool: string,
  transport: "local" | "api",
): string {
  const identity = createHash("sha256")
    .update(JSON.stringify([transport, tool, name]))
    .digest("hex");
  return join(accountsHome(), LOGIN_CLEANUP_INTENTS_DIR, `${identity}.json`);
}

function parseLoginCleanupIntent(
  name: string,
  tool: string,
  transport: "local" | "api",
): LoginCleanupIntent | undefined {
  const path = loginCleanupIntentPath(name, tool, transport);
  if (!existsSync(path)) return undefined;
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  let value: unknown;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("not a regular file");
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new AccountsError(`invalid interrupted login cleanup intent: ${String(error)}`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError("invalid interrupted login cleanup intent");
  }
  const intent = value as Partial<LoginCleanupIntent>;
  const ownership = intent.ownership;
  const allowedIntent = new Set([
    "version",
    "transport",
    "cleanupOperationId",
    "cleanupRequestedAt",
    "plannedIncarnationId",
    "name",
    "tool",
    "dir",
    "profileExisted",
    "createdProfileDir",
    "phase",
    "ownership",
    "ownerPid",
    "ownerProcessStartId",
  ]);
  const allowedOwnership = new Set([
    "cleanupOperationId",
    "cleanupRequestedAt",
    "toolLockRevision",
    "previousToolLock",
    "previousToolLockRevision",
    "previousToolLockProfileIncarnation",
    "authIdentity",
    "authCommitRevision",
  ]);
  if (
    Reflect.ownKeys(intent).some(
      (key) => typeof key !== "string" || !allowedIntent.has(key),
    ) ||
    intent.version !== 1 ||
    intent.transport !== transport ||
    intent.name !== name ||
    intent.tool !== tool ||
    typeof intent.cleanupOperationId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(intent.cleanupOperationId) ||
    typeof intent.cleanupRequestedAt !== "string" ||
    !Number.isFinite(Date.parse(intent.cleanupRequestedAt)) ||
    typeof intent.plannedIncarnationId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(intent.plannedIncarnationId) ||
    typeof intent.dir !== "string" ||
    !isAbsolute(intent.dir) ||
    !profileNameSchema.safeParse(intent.name).success ||
    typeof intent.tool !== "string" ||
    intent.tool.length === 0 ||
    intent.tool.includes("\0") ||
    /[\r\n]/.test(intent.tool) ||
    typeof intent.profileExisted !== "boolean" ||
    typeof intent.createdProfileDir !== "boolean" ||
    typeof intent.ownerPid !== "number" ||
    !Number.isSafeInteger(intent.ownerPid) ||
    intent.ownerPid <= 0 ||
    typeof intent.ownerProcessStartId !== "string" ||
    !/^(?:(?:linux|darwin)-[A-Za-z0-9-]+|fallback-[0-9a-f-]+)$/i.test(intent.ownerProcessStartId) ||
    (!intent.profileExisted &&
      resolve(intent.dir) !== resolve(managedProfileDirectory(name, tool))) ||
    !["planned", "profile-created", "lock-planned", "rollback"].includes(intent.phase ?? "") ||
    !ownership ||
    typeof ownership !== "object" ||
    Array.isArray(ownership) ||
    Reflect.ownKeys(ownership).some(
      (key) => typeof key !== "string" || !allowedOwnership.has(key),
    ) ||
    Object.values(ownership).some((entry) => entry !== undefined && typeof entry !== "string")
  ) {
    throw new AccountsError("invalid interrupted login cleanup intent");
  }
  if (
    ownership.cleanupOperationId !== intent.cleanupOperationId ||
    ownership.cleanupRequestedAt !== intent.cleanupRequestedAt
  ) {
    throw new AccountsError("invalid interrupted login cleanup intent");
  }
  return intent as LoginCleanupIntent;
}

export function beginLoginCleanupIntent(
  name: string,
  tool: string,
  transport: "local" | "api",
  dir: string,
  profileExisted: boolean,
  plannedIncarnationId: string = randomUUID(),
): LoginCleanupIntent {
  return withStoreLock(() => {
    const existing = parseLoginCleanupIntent(name, tool, transport);
    if (existing) {
      throw new AccountsError("an interrupted login cleanup must be reconciled before preparing another login");
    }
    const cleanupOperationId = randomUUID();
    const cleanupRequestedAt = new Date().toISOString();
    const intent: LoginCleanupIntent = {
      version: 1,
      transport,
      cleanupOperationId,
      cleanupRequestedAt,
      plannedIncarnationId,
      name,
      tool,
      dir,
      profileExisted,
      createdProfileDir: !profileExisted && !existsSync(dir),
      phase: "planned",
      ownership: { cleanupOperationId, cleanupRequestedAt },
      ownerPid: process.pid,
      ownerProcessStartId: profileDirectoryProcessIncarnation,
    };
    publishAtomicJson(
      loginCleanupIntentPath(name, tool, transport),
      intent,
      accountsHome(),
    );
    activeLoginCleanupOperations.add(cleanupOperationId);
    return intent;
  });
}

export function evolveLoginCleanupIntent(
  intent: LoginCleanupIntent,
  patch: Partial<Pick<
    LoginCleanupIntent,
    "phase" | "createdProfileDir" | "ownership" | "plannedIncarnationId"
  >>,
): LoginCleanupIntent {
  return withStoreLock(() => {
    const current = parseLoginCleanupIntent(intent.name, intent.tool, intent.transport);
    if (!current || current.cleanupOperationId !== intent.cleanupOperationId) {
      throw new AccountsError("login cleanup intent changed concurrently");
    }
    const next: LoginCleanupIntent = {
      ...current,
      ...patch,
      ownership: patch.ownership ? { ...patch.ownership } : current.ownership,
    };
    publishAtomicJson(
      loginCleanupIntentPath(next.name, next.tool, next.transport),
      next,
      accountsHome(),
    );
    return next;
  });
}

export function clearLoginCleanupIntent(intent: LoginCleanupIntent): void {
  withStoreLock(() => {
    const current = parseLoginCleanupIntent(intent.name, intent.tool, intent.transport);
    if (!current || current.cleanupOperationId !== intent.cleanupOperationId) {
      activeLoginCleanupOperations.delete(intent.cleanupOperationId);
      return;
    }
    removePublishedFile(
      loginCleanupIntentPath(intent.name, intent.tool, intent.transport),
      accountsHome(),
    );
    activeLoginCleanupOperations.delete(intent.cleanupOperationId);
  });
}

export function abandonLoginCleanupIntentInProcess(cleanupOperationId: string): void {
  activeLoginCleanupOperations.delete(cleanupOperationId);
}

function loginCleanupIntentOwnerIsLive(intent: LoginCleanupIntent): boolean {
  if (activeLoginCleanupOperations.has(intent.cleanupOperationId)) return true;
  if (intent.ownerPid === process.pid) {
    if (
      isVerifiableDirectoryProcessStartId(intent.ownerProcessStartId) &&
      isVerifiableDirectoryProcessStartId(profileDirectoryProcessIncarnation)
    ) {
      return intent.ownerProcessStartId === profileDirectoryProcessIncarnation &&
        activeLoginCleanupOperations.has(intent.cleanupOperationId);
    }
    return false;
  }
  const observed = profileDirectoryProcessStartId(intent.ownerPid);
  if (
    isVerifiableDirectoryProcessStartId(intent.ownerProcessStartId) &&
    isVerifiableDirectoryProcessStartId(observed)
  ) {
    return intent.ownerProcessStartId === observed;
  }
  try {
    process.kill(intent.ownerPid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

function assertLoginCleanupIntentRecoverable(intent: LoginCleanupIntent): void {
  if (loginCleanupIntentOwnerIsLive(intent)) {
    throw new LoginCleanupInProgressError(
      `login preparation is still in progress for profile "${intent.name}" and tool "${intent.tool}"`,
    );
  }
}

export function clearLoginCleanupIntentByOperation(
  name: string,
  tool: string,
  transport: "local" | "api",
  cleanupOperationId: string | undefined,
): void {
  if (!cleanupOperationId) return;
  const intent = parseLoginCleanupIntent(name, tool, transport);
  if (!intent || intent.cleanupOperationId !== cleanupOperationId) {
    activeLoginCleanupOperations.delete(cleanupOperationId);
    return;
  }
  if (existsSync(loginCleanupMarkerPath(intent.dir))) {
    clearLoginCleanupMarker(intent.dir, cleanupOperationId);
  }
  clearLoginCleanupIntent(intent);
}

function managedProfileDirectory(name: string, tool: string): string {
  return join(profilesDir(), tool, name);
}

function isExactManagedProfileDirectory(profile: Profile): boolean {
  return resolve(profile.dir) === resolve(managedProfileDirectory(profile.name, profile.tool));
}

function loginCleanupMarkerPath(dir: string): string {
  return join(dir, LOGIN_CLEANUP_MARKER);
}

function parseLoginCleanupMarker(dir: string): LoginCleanupMarker | undefined {
  const path = loginCleanupMarkerPath(dir);
  if (!existsSync(path)) return undefined;
  assertSafeWritePath(path, { mustStayUnder: profilesDir() });
  let stat: ReturnType<typeof lstatSync>;
  let value: unknown;
  try {
    stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new AccountsError("invalid interrupted login cleanup marker");
    }
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    if (error instanceof AccountsError) throw error;
    throw new AccountsError(`invalid interrupted login cleanup marker: ${String(error)}`);
  }
  if (!value || typeof value !== "object") {
    throw new AccountsError("invalid interrupted login cleanup marker");
  }
  const marker = value as Partial<LoginCleanupMarker>;
  const profile = profileSchema.safeParse(marker.profile);
  const ownership = marker.ownership;
  const markerKeys = new Set(["version", "cleanupOperationId", "profile", "ownership"]);
  const ownershipKeys = new Set([
    "cleanupOperationId",
    "cleanupRequestedAt",
    "toolLockRevision",
    "previousToolLock",
    "previousToolLockRevision",
    "previousToolLockProfileIncarnation",
    "authIdentity",
    "authCommitRevision",
  ]);
  if (
    Reflect.ownKeys(marker).some(
      (key) => typeof key !== "string" || !markerKeys.has(key),
    ) ||
    marker.version !== 1 ||
    typeof marker.cleanupOperationId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(marker.cleanupOperationId) ||
    !profile.success ||
    !profile.data.incarnationId ||
    !ownership ||
    typeof ownership !== "object" ||
    Array.isArray(ownership) ||
    Reflect.ownKeys(ownership).some(
      (key) => typeof key !== "string" || !ownershipKeys.has(key),
    ) ||
    Object.values(ownership).some((field) => field !== undefined && typeof field !== "string")
  ) {
    throw new AccountsError("invalid interrupted login cleanup marker");
  }
  return {
    version: 1,
    cleanupOperationId: marker.cleanupOperationId,
    profile: profile.data,
    ownership: { ...ownership, cleanupOperationId: marker.cleanupOperationId },
  };
}

function writeLoginCleanupMarker(
  profile: Profile,
  ownership: CreatedProfileRollbackOwnership,
  cleanupOperationId: string,
): boolean {
  if (!profile.incarnationId || !isExactManagedProfileDirectory(profile) || !existsSync(profile.dir)) {
    return false;
  }
  assertManagedDirectory(profile.dir);
  const path = loginCleanupMarkerPath(profile.dir);
  publishAtomicJson(
    path,
    {
      version: 1,
      cleanupOperationId,
      profile,
      ownership: { ...ownership, cleanupOperationId },
    } satisfies LoginCleanupMarker,
    profilesDir(),
  );
  return true;
}

function clearLoginCleanupMarker(dir: string, cleanupOperationId: string): void {
  const marker = parseLoginCleanupMarker(dir);
  if (marker?.cleanupOperationId !== cleanupOperationId) return;
  removePublishedFile(loginCleanupMarkerPath(dir), profilesDir());
}

function canPurgeInterruptedLoginDirectory(profile: Profile): boolean {
  const machine = loadMachineStore();
  return machine.current[profile.tool] !== profile.name && machine.applied[profile.tool] !== profile.name;
}

function reconcileInterruptedLoginDirectory(
  dir: string,
  name: string,
  tool: string,
  current: Profile | undefined,
): void {
  const marker = parseLoginCleanupMarker(dir);
  if (!marker) return;
  if (
    marker.profile.name !== name ||
    marker.profile.tool !== tool ||
    !isExactManagedProfileDirectory(marker.profile)
  ) {
    throw new AccountsError("interrupted login cleanup marker does not match its managed directory");
  }
  if (current) {
    throw new AccountsError(
      "profile changed or survived interrupted login cleanup; refusing to reuse its managed directory",
    );
  }
  if (!canPurgeInterruptedLoginDirectory(marker.profile)) {
    throw new AccountsError(
      "interrupted login cleanup no longer owns the machine profile state; refusing directory reuse",
    );
  }
  assertManagedDirectory(dir);
  rmSync(dir, { recursive: true, force: true });
}

function reconcileInterruptedLocalLoginCleanup(
  dir: string,
  marker: LoginCleanupMarker,
): void {
  withStoreLock(() => {
    const machine = loadMachineStore();
    const current = machine.profiles.find(
      (profile) => profile.name === marker.profile.name && profile.tool === marker.profile.tool,
    );
    if (current) {
      throw new AccountsError(
        "profile changed or survived interrupted login cleanup; refusing to reuse its managed directory",
      );
    }
    if (
      machine.current[marker.profile.tool] === marker.profile.name ||
      machine.applied[marker.profile.tool] === marker.profile.name
    ) {
      throw new AccountsError(
        "interrupted login cleanup no longer owns the machine profile state; refusing directory reuse",
      );
    }

    const expectedPrevious = marker.ownership.previousToolLock
      ? machine.profiles.find(
          (profile) =>
            profile.name === marker.profile.name &&
            profile.tool === marker.ownership.previousToolLock &&
            (!marker.ownership.previousToolLockProfileIncarnation ||
              profileAuthIncarnation(profile) === marker.ownership.previousToolLockProfileIncarnation),
        )
      : undefined;
    const currentToolLock = machine.toolLocks[marker.profile.name];
    const currentToolLockRevision = machine.toolLockRevisions[marker.profile.name];
    const previousLockAlreadyRestored = Boolean(
      expectedPrevious &&
      currentToolLock === marker.ownership.previousToolLock &&
      currentToolLockRevision === marker.ownership.previousToolLockRevision,
    );
    if (currentToolLock || currentToolLockRevision) {
      if (!previousLockAlreadyRestored) {
        throw new AccountsError(
          "interrupted login cleanup no longer owns the profile tool lock; refusing directory reuse",
        );
      }
    } else if (expectedPrevious) {
      machine.toolLocks[marker.profile.name] = expectedPrevious.tool;
      if (marker.ownership.previousToolLockRevision) {
        machine.toolLockRevisions[marker.profile.name] = marker.ownership.previousToolLockRevision;
      }
      saveStore(machine);
    }

    assertManagedDirectory(dir);
    rmSync(dir, { recursive: true, force: true });
  });
}

function ownsCreatedProfileMachineState(
  profile: Profile,
  ownership: CreatedProfileRollbackOwnership,
): boolean {
  const machine = loadMachineStore();
  if (
    machine.current[profile.tool] === profile.name ||
    machine.applied[profile.tool] === profile.name
  ) {
    return false;
  }
  if (profile.tool !== "claude") return true;
  const authKey = findProfileAuthRevisionKey(machine, profile);
  const hasAuthOwnership = Boolean(
    authKey && (
      machine.profileAuthRevisions[authKey] ||
      machine.profileAuthCommitRevisions[authKey]
    ),
  );
  return !hasAuthOwnership || Boolean(
    authKey &&
    ownership.authIdentity &&
    machine.profileAuthRevisions[authKey] === ownership.authIdentity &&
    (
      machine.profileAuthCommitRevisions[authKey]
        ? Boolean(
            ownership.authCommitRevision &&
            machine.profileAuthCommitRevisions[authKey] === ownership.authCommitRevision
          )
        : !ownership.authCommitRevision
    ),
  );
}

function restoreLoginIntentToolLock(
  intent: LoginCleanupIntent,
  injectFault: boolean,
): boolean {
  const ownership = intent.ownership;
  if (!ownership.toolLockRevision) return true;
  return withStoreLock(() => {
    const machine = loadMachineStore();
    const currentTool = machine.toolLocks[intent.name];
    const currentRevision = machine.toolLockRevisions[intent.name];
    const previousProfile = ownership.previousToolLock
      ? machine.profiles.find(
          (profile) =>
            profile.name === intent.name &&
            profile.tool === ownership.previousToolLock &&
            (!ownership.previousToolLockProfileIncarnation ||
              profileAuthIncarnation(profile) === ownership.previousToolLockProfileIncarnation),
        )
      : undefined;
    const previousAlreadyRestored = ownership.previousToolLock
      ? Boolean(
          previousProfile &&
          currentTool === ownership.previousToolLock &&
          currentRevision === ownership.previousToolLockRevision
        )
      : currentTool === undefined && currentRevision === undefined;
    if (previousAlreadyRestored) return true;

    const ownsWrittenLock =
      currentTool === intent.tool && currentRevision === ownership.toolLockRevision;
    const deletionClearedOwnedLock =
      intent.phase === "rollback" && currentTool === undefined && currentRevision === undefined;
    if (!ownsWrittenLock && !deletionClearedOwnedLock) return false;
    if (ownership.previousToolLock) {
      if (!previousProfile) return false;
      machine.toolLocks[intent.name] = ownership.previousToolLock;
      if (ownership.previousToolLockRevision) {
        machine.toolLockRevisions[intent.name] = ownership.previousToolLockRevision;
      } else {
        delete machine.toolLockRevisions[intent.name];
      }
    } else {
      delete machine.toolLocks[intent.name];
      delete machine.toolLockRevisions[intent.name];
    }
    saveStore(machine);
    if (injectFault) {
      injectLoginCleanupFaultForTests("post-lock-restore", intent.cleanupOperationId);
    }
    return true;
  });
}

function profileFromLoginCleanupIntent(intent: LoginCleanupIntent): Profile {
  return {
    name: intent.name,
    tool: intent.tool,
    dir: intent.dir,
    createdAt: new Date(0).toISOString(),
    incarnationId: intent.plannedIncarnationId,
  };
}

/** On-box JSON registry. Delegates to the core profile library. */
class LocalStore implements AccountsStore {
  readonly transport = "local" as const;
  private readonly loginOperations = new Map<string, {
    tool: string;
    name: string;
    targetIncarnation: string;
    activatedProfileLastUsedAt: string;
    previousCurrentName?: string;
    previousCurrentIncarnation?: string;
    previousProfileLastUsedAt?: string;
    previousToolLock?: string;
    previousToolLockRevision?: string;
    writtenToolLockRevision: string;
  }>();

  async listProfiles(tool?: string): Promise<Profile[]> {
    return localList(tool);
  }
  async getProfile(name: string, tool?: string): Promise<Profile> {
    return localGet(name, tool);
  }
  async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    return localFind(name, tool);
  }
  async addProfile(opts: AddOptions): Promise<Profile> {
    return (await this.addProfileForLogin(opts)).profile;
  }
  async addProfileForLogin(
    opts: AddOptions,
    plan?: LoginProfileCreationPlan,
  ): Promise<LoginCreatedProfile> {
    const toolId = opts.tool ?? DEFAULT_TOOL;
    const dir = opts.dir ? expandPath(opts.dir) : join(profilesDir(), toolId, opts.name);
    return withProfileDirectoryLease(dir, () => {
      const existed = existsSync(dir);
      const profileExisted = Boolean(localFind(opts.name, toolId));
      try {
        const profile = localAdd({
          ...opts,
          ...(plan ? { incarnationId: plan.plannedIncarnationId } : {}),
        });
        if (plan) {
          injectLoginCleanupFaultForTests("post-create", plan.cleanupOperationId);
        }
        return { profile, createdProfileDir: !existed };
      } catch (error) {
        if (isInjectedLoginCleanupFault(error)) throw error;
        const committed = localFind(opts.name, toolId);
        if (!profileExisted && committed && resolve(committed.dir) === resolve(dir)) {
          return { profile: committed, createdProfileDir: !existed };
        }
        if (!existed && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
        throw error;
      }
    });
  }
  async updateProfile(name: string, opts: UpdateOptions): Promise<Profile> {
    return localUpdate(name, opts);
  }
  async renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile> {
    return localRename(oldName, newName, tool);
  }
  async removeProfile(name: string, opts: RemoveOptions = {}): Promise<RemoveResult> {
    const expected = localGet(name, opts.tool);
    return withProfileDirectoryLease(expected.dir, () => withStoreLock(() => {
      const current = localGet(name, opts.tool);
      if (!isDeepStrictEqual(current, expected)) {
        throw new AccountsError("profile changed while directory removal was in progress");
      }
      return localRemove(name, opts);
    }));
  }
  async upgradeProfileIncarnationForLogin(
    profile: Profile,
    plannedIncarnationId: string = randomUUID(),
  ): Promise<Profile> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      const current = machine.profiles.find(
        (candidate) => candidate.name === profile.name && candidate.tool === profile.tool,
      );
      if (!current) throw new AccountsError(`no profile named "${profile.name}" for tool "${profile.tool}"`);
      if (
        current.createdAt !== profile.createdAt ||
        resolve(current.dir) !== resolve(profile.dir)
      ) {
        throw new AccountsError("profile changed while login preparation was in progress");
      }
      if (!current.incarnationId) {
        current.incarnationId = plannedIncarnationId;
        saveStore(machine);
      }
      return structuredClone(current);
    });
  }
  async reconcileInterruptedLoginCleanup(name: string, tool: string): Promise<void> {
    const dir = managedProfileDirectory(name, tool);
    const intent = parseLoginCleanupIntent(name, tool, this.transport);
    if (intent) {
      assertLoginCleanupIntentRecoverable(intent);
      const observed = intent.profileExisted ? undefined : localFind(name, tool);
      if (observed && observed.incarnationId !== intent.plannedIncarnationId) {
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
        return;
      }
      if (observed) {
        await this.removeProfileIncarnation(
          observed,
          intent.ownership,
          { tool, purge: intent.createdProfileDir },
        );
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
        return;
      }
      return withProfileDirectoryLease(intent.dir, () => {
        if (intent.profileExisted) {
          restoreLoginIntentToolLock(intent, false);
          clearLoginCleanupIntentByOperation(
            name,
            tool,
            this.transport,
            intent.cleanupOperationId,
          );
          return;
        }
        const latest = localFind(name, tool);
        if (latest) {
          clearLoginCleanupIntentByOperation(
            name,
            tool,
            this.transport,
            intent.cleanupOperationId,
          );
          return;
        }
        const marker = existsSync(loginCleanupMarkerPath(intent.dir))
          ? parseLoginCleanupMarker(intent.dir)
          : undefined;
        const recoveryIntent = marker?.cleanupOperationId === intent.cleanupOperationId
          ? evolveLoginCleanupIntent(intent, {
              phase: "rollback",
              ownership: marker.ownership,
            })
          : intent;
        if (!restoreLoginIntentToolLock(recoveryIntent, false)) {
          clearLoginCleanupIntentByOperation(
            name,
            tool,
            this.transport,
            intent.cleanupOperationId,
          );
          return;
        }
        const synthetic = profileFromLoginCleanupIntent(recoveryIntent);
        if (
          recoveryIntent.createdProfileDir &&
          existsSync(recoveryIntent.dir) &&
          isExactManagedProfileDirectory(synthetic) &&
          ownsCreatedProfileMachineState(synthetic, recoveryIntent.ownership)
        ) {
          injectLoginCleanupFaultForTests("pre-purge", recoveryIntent.cleanupOperationId);
          assertManagedDirectory(recoveryIntent.dir);
          rmSync(recoveryIntent.dir, { recursive: true, force: true });
        }
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
      });
    }
    if (!existsSync(loginCleanupMarkerPath(dir))) return;
    const marker = parseLoginCleanupMarker(dir)!;
    if (marker.profile.name !== name || marker.profile.tool !== tool) {
      throw new AccountsError("interrupted login cleanup marker does not match its managed directory");
    }
    const resumed = await this.removeProfileIncarnation(
      marker.profile,
      marker.ownership,
      { tool, purge: true },
    );
    if (resumed?.purged) return;
    return withProfileDirectoryLease(dir, () => {
      reconcileInterruptedLocalLoginCleanup(dir, marker);
    });
  }
  async removeProfileIncarnation(
    profile: Profile,
    ownership: CreatedProfileRollbackOwnership,
    opts: RemoveOptions = {},
  ): Promise<RemoveResult | undefined> {
    const cleanupOperationId = ownership.cleanupOperationId ?? randomUUID();
    ownership = {
      ...ownership,
      cleanupOperationId,
      cleanupRequestedAt: ownership.cleanupRequestedAt ?? new Date().toISOString(),
    };
    const intent = parseLoginCleanupIntent(profile.name, profile.tool, this.transport);
    const createdBeforeToolLock = Boolean(
      intent?.cleanupOperationId === cleanupOperationId &&
      (intent.phase === "planned" || intent.phase === "profile-created") &&
      !intent.ownership.toolLockRevision,
    );
    if (intent?.cleanupOperationId === cleanupOperationId) {
      ownership = evolveLoginCleanupIntent(intent, {
        phase: "rollback",
        ownership,
      }).ownership;
    }
    return withProfileDirectoryLease(profile.dir, () => {
      let absentMarker: LoginCleanupMarker | undefined;
      const result = withStoreLock(() => {
      if (!profile.incarnationId || (!ownership.toolLockRevision && !createdBeforeToolLock)) {
        return undefined;
      }
      const machine = loadMachineStore();
      const current = machine.profiles.find(
        (candidate) =>
          candidate.name === profile.name &&
          candidate.tool === profile.tool,
      );
      if (!current) {
        if (
          opts.purge &&
          isExactManagedProfileDirectory(profile) &&
          existsSync(profile.dir) &&
          ownsCreatedProfileMachineState(profile, ownership)
        ) {
          if (writeLoginCleanupMarker(profile, ownership, cleanupOperationId)) {
            absentMarker = {
              version: 1,
              cleanupOperationId,
              profile,
              ownership: { ...ownership, cleanupOperationId },
            };
          }
        }
        return undefined;
      }
      if (
        current.incarnationId !== profile.incarnationId ||
        !isDeepStrictEqual(current, profile) ||
        (
          ownership.toolLockRevision
            ? machine.toolLockRevisions[current.name] !== ownership.toolLockRevision
            : machine.toolLocks[current.name] === current.tool
        ) ||
        machine.current[current.tool] === current.name ||
        machine.applied[current.tool] === current.name
      ) {
        return undefined;
      }
      if (profile.tool === "claude") {
        const authKey = findProfileAuthRevisionKey(machine, current);
        const hasAuthOwnership = Boolean(
          authKey && (
            machine.profileAuthRevisions[authKey] ||
            machine.profileAuthCommitRevisions[authKey]
          ),
        );
        if (
          hasAuthOwnership && (
            !authKey ||
            !ownership.authIdentity ||
            machine.profileAuthRevisions[authKey] !== ownership.authIdentity ||
            (
              machine.profileAuthCommitRevisions[authKey]
                ? !ownership.authCommitRevision ||
                  machine.profileAuthCommitRevisions[authKey] !== ownership.authCommitRevision
                : Boolean(ownership.authCommitRevision)
            )
          )
        ) {
          return undefined;
        }
      }
      const journaled = Boolean(
        opts.purge && writeLoginCleanupMarker(current, ownership, cleanupOperationId),
      );
      const removed = localRemove(current.name, { tool: current.tool });
      injectLoginCleanupFaultForTests("post-delete", cleanupOperationId);
      const after = loadMachineStore();
      if (
        ownership.previousToolLock &&
        after.profiles.some(
          (candidate) =>
            candidate.name === current.name &&
            candidate.tool === ownership.previousToolLock &&
            (!ownership.previousToolLockProfileIncarnation ||
              profileAuthIncarnation(candidate) === ownership.previousToolLockProfileIncarnation),
        )
      ) {
        after.toolLocks[current.name] = ownership.previousToolLock;
        if (ownership.previousToolLockRevision) {
          after.toolLockRevisions[current.name] = ownership.previousToolLockRevision;
        } else {
          delete after.toolLockRevisions[current.name];
        }
        saveStore(after);
      }
      injectLoginCleanupFaultForTests("post-lock-restore", cleanupOperationId);
      let purged = false;
      if (
        opts.purge &&
        resolve(profile.dir) === resolve(join(profilesDir(), profile.tool, profile.name)) &&
        existsSync(profile.dir)
      ) {
        injectLoginCleanupFaultForTests("pre-purge", cleanupOperationId);
        assertManagedDirectory(profile.dir);
        rmSync(profile.dir, { recursive: true, force: true });
        purged = true;
      }
      if (journaled && !purged) clearLoginCleanupMarker(profile.dir, cleanupOperationId);
      return { ...removed, purged };
      });
      if (absentMarker) {
        reconcileInterruptedLocalLoginCleanup(profile.dir, absentMarker);
        return { profile, purged: !existsSync(profile.dir) };
      }
      return result;
    });
  }
  async redetectEmail(name: string, tool?: string, expectedProfile?: Profile): Promise<Profile> {
    if (!expectedProfile) return localRedetect(name, tool);
    return withStoreLock(() => {
      const machine = loadMachineStore();
      const current = machine.profiles.find((profile) => profile.name === name && (!tool || profile.tool === tool));
      if (
        !current ||
        current.tool !== expectedProfile.tool ||
        profileAuthIncarnation(current) !== profileAuthIncarnation(expectedProfile)
      ) {
        throw new AccountsError("profile changed while login finalization was in progress");
      }
      const email = detectEmail(current.dir, getTool(current.tool));
      if (email && (current.email ?? null) === (expectedProfile.email ?? null)) {
        current.email = email;
        saveStore(machine);
      }
      return structuredClone(current);
    });
  }
  async restoreProfileState(
    profile: Profile,
    fields: ProfileRollbackFields,
    ownership?: ProfileRollbackOwnership,
  ): Promise<Profile> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      const index = machine.profiles.findIndex(
        (candidate) => candidate.name === profile.name && candidate.tool === profile.tool,
      );
      if (index < 0) throw new AccountsError(`no profile named "${profile.name}" for tool "${profile.tool}"`);
      const current = machine.profiles[index]!;
      if (profile.tool === "claude") {
        const authKey = findProfileAuthRevisionKey(machine, current);
        if (
          !authKey ||
          !ownership?.authIdentity ||
          !ownership.authCommitRevision ||
          machine.profileAuthRevisions[authKey] !== ownership.authIdentity ||
          machine.profileAuthCommitRevisions[authKey] !== ownership.authCommitRevision
        ) {
          return structuredClone(current);
        }
      } else if (
        !profile.incarnationId ||
        !current.incarnationId ||
        current.incarnationId !== profile.incarnationId
      ) {
        // Truly legacy records that have not crossed the LocalStore upgrade
        // boundary fail closed instead of trusting timestamp/path equality.
        return structuredClone(current);
      }
      if (fields.email && (current.email ?? null) === fields.email.expected) {
        if (fields.email.restore === null) delete current.email;
        else current.email = fields.email.restore;
      }
      if (fields.lastUsedAt && (current.lastUsedAt ?? null) === fields.lastUsedAt.expected) {
        if (fields.lastUsedAt.restore === null) delete current.lastUsedAt;
        else current.lastUsedAt = fields.lastUsedAt.restore;
      }
      saveStore(machine);
      return structuredClone(current);
    });
  }
  async useProfile(name: string, tool?: string): Promise<UseProfileResult> {
    return localUse(name, tool);
  }
  async useProfileForLogin(
    name: string,
    tool: string | undefined,
    operationId: string,
    expectedProfile?: Profile,
  ): Promise<UseProfileResult> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      const matches = machine.profiles.filter(
        (profile) => profile.name === name && (!tool || profile.tool === tool),
      );
      if (matches.length === 0) {
        const suffix = tool ? ` for tool "${tool}"` : "";
        throw new AccountsError(`no profile named "${name}"${suffix}. Run \`accounts list\` to see profiles.`);
      }
      if (matches.length > 1) {
        throw new AccountsError(
          `profile "${name}" exists for multiple tools (${matches.map((profile) => profile.tool).join(", ")}); pass --tool`,
        );
      }
      const profile = matches[0]!;
      const targetIncarnation = profileAuthIncarnation(profile);
      if (expectedProfile && targetIncarnation !== profileAuthIncarnation(expectedProfile)) {
        throw new AccountsError("profile changed while login activation was in progress");
      }
      const completed = this.loginOperations.get(operationId);
      if (completed) {
        if (completed.tool !== profile.tool || completed.name !== profile.name) {
          throw new AccountsError("login operation id is already bound to another profile");
        }
        if (completed.targetIncarnation !== targetIncarnation) {
          throw new AccountsError("login operation id is already bound to another profile incarnation");
        }
        return {
          profile: structuredClone({
            ...profile,
            lastUsedAt: completed.activatedProfileLastUsedAt,
          }),
          toolId: profile.tool,
          currentRevision: operationId,
          ...(completed.previousCurrentName
            ? { previousCurrentName: completed.previousCurrentName }
            : {}),
          ...(completed.previousProfileLastUsedAt
            ? { previousProfileLastUsedAt: completed.previousProfileLastUsedAt }
            : {}),
        };
      }
      const previousCurrentName = machine.current[profile.tool];
      const previousCurrentProfile = previousCurrentName
        ? machine.profiles.find((candidate) => candidate.name === previousCurrentName && candidate.tool === profile.tool)
        : undefined;
      const previousProfileLastUsedAt = profile.lastUsedAt;
      const previousToolLock = machine.toolLocks[profile.name];
      const previousToolLockRevision = machine.toolLockRevisions[profile.name];
      machine.current[profile.tool] = profile.name;
      machine.currentRevisions[profile.tool] = operationId;
      const writtenToolLockRevision = randomUUID();
      machine.toolLocks[profile.name] = profile.tool;
      machine.toolLockRevisions[profile.name] = writtenToolLockRevision;
      profile.lastUsedAt = new Date().toISOString();
      saveStore(machine);
      this.loginOperations.set(operationId, {
        tool: profile.tool,
        name: profile.name,
        targetIncarnation,
        activatedProfileLastUsedAt: profile.lastUsedAt,
        ...(previousCurrentName ? { previousCurrentName } : {}),
        ...(previousCurrentProfile
          ? { previousCurrentIncarnation: profileAuthIncarnation(previousCurrentProfile) }
          : {}),
        ...(previousProfileLastUsedAt ? { previousProfileLastUsedAt } : {}),
        ...(previousToolLock ? { previousToolLock } : {}),
        ...(previousToolLockRevision ? { previousToolLockRevision } : {}),
        writtenToolLockRevision,
      });
      return {
        profile: structuredClone(profile),
        toolId: profile.tool,
        currentRevision: operationId,
        ...(previousCurrentName ? { previousCurrentName } : {}),
        ...(previousProfileLastUsedAt ? { previousProfileLastUsedAt } : {}),
      };
    });
  }
  async restoreCurrent(tool: string, expectedName: string, name?: string): Promise<boolean> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      if (machine.current[tool] !== expectedName) return false;
      if (name) {
        if (!machine.profiles.some((profile) => profile.name === name && profile.tool === tool)) {
          throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
        }
        machine.current[tool] = name;
        machine.currentRevisions[tool] = randomUUID();
      } else {
        delete machine.current[tool];
        delete machine.currentRevisions[tool];
      }
      saveStore(machine);
      return true;
    });
  }
  async restoreCurrentGeneration(
    tool: string,
    expectedName: string,
    expectedRevision: string,
    name?: string,
  ): Promise<boolean> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      if (machine.current[tool] !== expectedName || machine.currentRevisions[tool] !== expectedRevision) return false;
      if (name) {
        if (!machine.profiles.some((profile) => profile.name === name && profile.tool === tool)) {
          throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
        }
        machine.current[tool] = name;
        machine.currentRevisions[tool] = randomUUID();
      } else {
        delete machine.current[tool];
        delete machine.currentRevisions[tool];
      }
      saveStore(machine);
      return true;
    });
  }
  async restoreCurrentOperation(
    tool: string,
    expectedName: string,
    operationId: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean> {
    return withStoreLock(() => {
      const machine = loadMachineStore();
      if (machine.current[tool] !== expectedName || machine.currentRevisions[tool] !== operationId) return false;
      const operation = this.loginOperations.get(operationId);
      if (operation && (operation.tool !== tool || operation.name !== expectedName)) {
        throw new AccountsError("login operation id is already bound to another profile");
      }
      const requestedRestoreName = operation ? operation.previousCurrentName : name;
      const restoreName = requestedRestoreName && operation?.previousCurrentIncarnation
        ? machine.profiles.some(
            (profile) =>
              profile.name === requestedRestoreName &&
              profile.tool === tool &&
              profileAuthIncarnation(profile) === operation.previousCurrentIncarnation,
          )
          ? requestedRestoreName
          : undefined
        : requestedRestoreName;
      const restoreProfileLastUsedAt = operation
        ? operation.previousProfileLastUsedAt ?? null
        : restoreLastUsedAt;
      const failedProfile = machine.profiles.find(
        (profile) => profile.name === expectedName && profile.tool === tool,
      );
      if (restoreProfileLastUsedAt !== undefined && failedProfile) {
        if (restoreProfileLastUsedAt === null) delete failedProfile.lastUsedAt;
        else failedProfile.lastUsedAt = restoreProfileLastUsedAt;
      }
      if (operation && machine.toolLockRevisions[expectedName] === operation.writtenToolLockRevision) {
        if (operation.previousToolLock) {
          machine.toolLocks[expectedName] = operation.previousToolLock;
          if (operation.previousToolLockRevision) {
            machine.toolLockRevisions[expectedName] = operation.previousToolLockRevision;
          } else {
            delete machine.toolLockRevisions[expectedName];
          }
        } else {
          delete machine.toolLocks[expectedName];
          delete machine.toolLockRevisions[expectedName];
        }
      }
      if (restoreName) {
        if (!machine.profiles.some((profile) => profile.name === restoreName && profile.tool === tool)) {
          throw new AccountsError(`no profile named "${restoreName}" for tool "${tool}"`);
        }
        machine.current[tool] = restoreName;
        machine.currentRevisions[tool] = randomUUID();
      } else {
        delete machine.current[tool];
        delete machine.currentRevisions[tool];
      }
      saveStore(machine);
      this.loginOperations.delete(operationId);
      return true;
    });
  }
  async currentProfile(tool: string): Promise<Profile | undefined> {
    return localCurrent(tool);
  }
  async listCurrent(): Promise<CurrentEntry[]> {
    const machine = loadStore();
    return Object.entries(machine.current).map(([tool, name]) => ({
      tool,
      name,
      revision: machine.currentRevisions[tool] ?? "",
    }));
  }
  async listCurrentForLoginRollback(): Promise<CurrentEntry[]> {
    return this.listCurrent();
  }
  async listTools(): Promise<ToolDef[]> {
    return localListTools();
  }
  async resolveTool(toolId: string): Promise<ToolDef> {
    return getTool(toolId);
  }
  async addTool(def: ToolDef): Promise<ToolDef> {
    return localAddCustomTool(def);
  }
  async removeTool(id: string): Promise<void> {
    localRemoveCustomTool(id);
  }
}

/**
 * Self-hosted/cloud registry over `<API_URL>/v1`. The account `dir` is
 * machine-local, so create/update materialize a managed local config dir on
 * this machine and record its path in the cloud record (so the creating machine
 * can immediately launch the profile).
 */
class ApiStore implements AccountsStore {
  readonly transport = "api" as const;
  readonly requiresProfileIncarnationRollback = true;

  constructor(private readonly api: AccountsCloudApi) {}

  async listProfiles(tool?: string): Promise<Profile[]> {
    const profiles = await this.api.list(tool);
    await this.hydrateProfileTools(profiles);
    return profiles;
  }

  async getProfile(name: string, tool?: string): Promise<Profile> {
    const profile = await this.resolve(name, tool);
    return profile;
  }

  async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    const profile = await this.api.get(name, tool);
    if (profile) await this.hydrateProfileTools([profile]);
    return profile;
  }

  async addProfile(opts: AddOptions): Promise<Profile> {
    return (await this.createProfile(opts, false)).profile;
  }

  async addProfileForLogin(
    opts: AddOptions,
    plan?: LoginProfileCreationPlan,
  ): Promise<LoginCreatedProfile> {
    return this.createProfile(opts, true, plan);
  }

  private async createProfile(
    opts: AddOptions,
    forLogin: boolean,
    plan?: LoginProfileCreationPlan,
  ): Promise<LoginCreatedProfile> {
    assertProfileName(opts.name);
    const toolId = opts.tool ?? DEFAULT_TOOL;
    const tool = await this.resolveTool(toolId);
    const managed = opts.dir === undefined;
    const dir = managed ? join(profilesDir(), toolId, opts.name) : validatedDirectoryPath(opts.dir!);
    return withProfileDirectoryLease(dir, async () => {
      const authExpectation = toolId === "claude"
        ? captureMachineProfileAuthSlotExpectation(toolId, opts.name)
        : undefined;
      const createdProfileDir = prepareProfileDirectory(dir, managed);
      const email = opts.email ?? detectEmail(dir, tool) ?? undefined;
      const input = {
        name: opts.name,
        tool: toolId,
        email,
        displayName: opts.displayName,
        identity: opts.identity,
        cardLast4: opts.cardLast4,
        metadata: opts.metadata,
        dir,
        description: opts.description,
      };
      const expectedIncarnationId = forLogin
        ? plan?.plannedIncarnationId ?? randomUUID()
        : undefined;
      try {
        if (forLogin && !this.api.createForLogin) {
          throw new AccountsError(
            "the configured Accounts API store does not support transactional login profile creation",
          );
        }
        const profile = forLogin
          ? await this.api.createForLogin!(input, expectedIncarnationId!)
          : await this.api.create(input);
        if (forLogin && profile.incarnationId !== expectedIncarnationId) {
          throw new AccountsError(
            "the Accounts API returned a different login profile incarnation than the requested rollback fence",
          );
        }
        if (authExpectation) {
          reconcileMachineProfileCreate(profile, authExpectation, plan?.plannedAuthIdentity);
        }
        if (plan) {
          injectLoginCleanupFaultForTests("post-create", plan.cleanupOperationId);
        }
        return { profile, createdProfileDir };
      } catch (error) {
        if (isInjectedLoginCleanupFault(error)) throw error;
        if (forLogin && expectedIncarnationId) {
          try {
            const committed = await this.api.get(opts.name, toolId);
            if (committed?.incarnationId === expectedIncarnationId) {
              if (authExpectation) {
                reconcileMachineProfileCreate(
                  committed,
                  authExpectation,
                  plan?.plannedAuthIdentity,
                );
              }
              return { profile: committed, createdProfileDir };
            }
            if (!committed && createdProfileDir) rmSync(dir, { recursive: true, force: true });
          } catch {
            // Ambiguous response loss must retain the directory: a committed
            // server profile may already own it.
          }
        } else if (createdProfileDir) {
          rmSync(dir, { recursive: true, force: true });
        }
        throw error;
      }
    });
  }

  async updateProfile(name: string, opts: UpdateOptions): Promise<Profile> {
    const existing = await this.resolve(name, opts.tool);
    const dir = opts.dir !== undefined ? validatedDirectoryPath(opts.dir) : undefined;
    const created = dir !== undefined ? prepareProfileDirectory(dir, false) : false;
    try {
      return await this.api.update(name, existing.tool, {
        email: opts.email,
        displayName: opts.displayName,
        identity: opts.identity,
        cardLast4: opts.cardLast4,
        metadata: opts.metadata,
        dir,
        description: opts.description,
      });
    } catch (error) {
      if (dir && created) rmSync(dir, { recursive: true, force: true });
      throw error;
    }
  }

  async renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile> {
    assertProfileName(newName);
    const existing = await this.resolve(oldName, tool);
    const expectation = captureMachineProfileReconcileExpectation(existing);
    const renamed = await this.api.rename(oldName, newName, existing.tool);
    reconcileMachineProfileRename(existing.tool, oldName, newName, expectation);
    return renamed;
  }

  async removeProfile(name: string, opts: RemoveOptions = {}): Promise<RemoveResult> {
    const existing = await this.resolve(name, opts.tool);
    const expectation = captureMachineProfileReconcileExpectation(existing);
    const profile = await this.api.remove(existing.name, existing.tool);
    reconcileMachineProfileRemove(
      profile.tool,
      profile.name,
      profileAuthIncarnation(profile),
      expectation,
    );
    const purgeNote = opts.purge
      ? "--purge is a local-only operation; the config dir (if any) was not touched in self_hosted mode"
      : undefined;
    return { profile, purged: false, ...(purgeNote ? { purgeNote } : {}) };
  }

  async assertCreatedProfileCleanup(): Promise<void> {
    if (!this.api.assertLoginProfileCleanup || !this.api.createForLogin) {
      throw new AccountsError(
        "the configured Accounts API store does not support conditional login-created profile cleanup; " +
        "upgrade accounts-serve before running accounts login",
      );
    }
    await this.api.assertLoginProfileCleanup();
  }

  async reconcileInterruptedLoginCleanup(name: string, tool: string): Promise<void> {
    const dir = managedProfileDirectory(name, tool);
    const intent = parseLoginCleanupIntent(name, tool, this.transport);
    if (intent) {
      assertLoginCleanupIntentRecoverable(intent);
      if (intent.profileExisted) {
        restoreLoginIntentToolLock(intent, false);
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
        return;
      }
      const observed = await this.api.get(name, tool);
      if (observed && observed.incarnationId !== intent.plannedIncarnationId) {
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
        return;
      }
      if (observed) {
        await this.removeProfileIncarnation(
          observed,
          intent.ownership,
          { tool, purge: intent.createdProfileDir },
        );
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
        return;
      }
      return withProfileDirectoryLease(intent.dir, async () => {
        const authoritative = await this.api.get(name, tool);
        if (authoritative) {
          clearLoginCleanupIntentByOperation(
            name,
            tool,
            this.transport,
            intent.cleanupOperationId,
          );
          return;
        }
        const synthetic = profileFromLoginCleanupIntent(intent);
        const expectation = withStoreLock(() => {
          if (!ownsCreatedProfileMachineState(synthetic, intent.ownership)) return undefined;
          return captureMachineProfileReconcileExpectation(synthetic);
        });
        if (!expectation) {
          clearLoginCleanupIntentByOperation(
            name,
            tool,
            this.transport,
            intent.cleanupOperationId,
          );
          return;
        }
        reconcileMachineProfileRemove(
          tool,
          name,
          profileAuthIncarnation(synthetic),
          expectation,
        );
        if (
          intent.createdProfileDir &&
          existsSync(intent.dir) &&
          isExactManagedProfileDirectory(synthetic)
        ) {
          injectLoginCleanupFaultForTests("pre-purge", intent.cleanupOperationId);
          assertManagedDirectory(intent.dir);
          rmSync(intent.dir, { recursive: true, force: true });
        }
        clearLoginCleanupIntentByOperation(
          name,
          tool,
          this.transport,
          intent.cleanupOperationId,
        );
      });
    }
    if (!existsSync(loginCleanupMarkerPath(dir))) return;
    const marker = parseLoginCleanupMarker(dir)!;
    if (marker.profile.name !== name || marker.profile.tool !== tool) {
      throw new AccountsError("interrupted login cleanup marker does not match its managed directory");
    }
    const resumed = await this.removeProfileIncarnation(
      marker.profile,
      marker.ownership,
      { tool, purge: true },
    );
    if (resumed?.purged) return;
    return withProfileDirectoryLease(dir, async () => {
      const current = await this.api.get(name, tool);
      reconcileInterruptedLoginDirectory(dir, name, tool, current);
    });
  }

  async removeProfileIncarnation(
    profile: Profile,
    ownership: CreatedProfileRollbackOwnership,
    opts: RemoveOptions = {},
  ): Promise<RemoveResult | undefined> {
    if (!profile.incarnationId || !this.api.removeCreatedProfile) return undefined;
    const cleanupOperationId = ownership.cleanupOperationId ?? randomUUID();
    const cleanupRequestedAt = ownership.cleanupRequestedAt ?? new Date().toISOString();
    ownership = { ...ownership, cleanupOperationId, cleanupRequestedAt };
    const intent = parseLoginCleanupIntent(profile.name, profile.tool, this.transport);
    if (intent?.cleanupOperationId === cleanupOperationId) {
      ownership = evolveLoginCleanupIntent(intent, {
        phase: "rollback",
        ownership,
      }).ownership;
    }
    return withProfileDirectoryLease(profile.dir, async () => {
      const expectation = withStoreLock(() => {
        if (!ownsCreatedProfileMachineState(profile, ownership)) return undefined;
        return captureMachineProfileReconcileExpectation(profile);
      });
      if (!expectation) return undefined;
      const journaled = Boolean(
        opts.purge && writeLoginCleanupMarker(
          profile,
          { ...ownership, cleanupRequestedAt },
          cleanupOperationId,
        ),
      );
      try {
        const result = await this.api.removeCreatedProfile!(
          profile,
          cleanupOperationId,
          cleanupRequestedAt,
        );
        if (result.expired || result.currentExists) {
          if (journaled) clearLoginCleanupMarker(profile.dir, cleanupOperationId);
          return undefined;
        }
        injectLoginCleanupFaultForTests("post-delete", cleanupOperationId);
      } catch (error) {
        try {
          const current = await this.api.get(profile.name, profile.tool);
          if (current) {
            if (!current.incarnationId || current.incarnationId === profile.incarnationId) {
              throw error;
            }
            if (journaled) clearLoginCleanupMarker(profile.dir, cleanupOperationId);
            return undefined;
          }
        } catch (reconcileError) {
          if (reconcileError === error) throw error;
          throw error;
        }
      }
      // A durable replay may truthfully return the old removal result after a
      // replacement incarnation was created. Consult the authoritative row on
      // every terminal path before local recursive purge; the directory lease
      // closes the same-machine recreation window around this final check.
      const authoritativeCurrent = await this.api.get(profile.name, profile.tool);
      if (authoritativeCurrent) {
        if (journaled) clearLoginCleanupMarker(profile.dir, cleanupOperationId);
        return undefined;
      }
      // Either this operation removed the row or another exact deletion won.
      // Both are locally purgeable only after the authoritative absence above.
      return withStoreLock(() => {
        const currentExpectation = captureMachineProfileReconcileExpectation(profile);
        if (
          !ownsCreatedProfileMachineState(profile, ownership) ||
          !isDeepStrictEqual(currentExpectation, expectation)
        ) {
          return { profile, purged: false };
        }
        reconcileMachineProfileRemove(
          profile.tool,
          profile.name,
          profileAuthIncarnation(profile),
          expectation,
        );
        let purged = false;
        if (
          opts.purge &&
          resolve(profile.dir) === resolve(join(profilesDir(), profile.tool, profile.name)) &&
          existsSync(profile.dir)
        ) {
          injectLoginCleanupFaultForTests("pre-purge", cleanupOperationId);
          assertManagedDirectory(profile.dir);
          rmSync(profile.dir, { recursive: true, force: true });
          purged = true;
        }
        if (journaled && !purged) clearLoginCleanupMarker(profile.dir, cleanupOperationId);
        return { profile, purged };
      });
    });
  }

  async redetectEmail(name: string, tool?: string, expectedProfile?: Profile): Promise<Profile> {
    const profile = await this.resolve(name, tool);
    if (expectedProfile?.incarnationId && profile.incarnationId !== expectedProfile.incarnationId) {
      throw new AccountsError("profile changed while login finalization was in progress");
    }
    if (!profile.dir || !existsSync(profile.dir)) return profile;
    const email = detectEmail(profile.dir, getTool(profile.tool));
    if (!email || email === profile.email) return profile;
    if (expectedProfile) {
      if (!expectedProfile.incarnationId || !this.api.redetectEmailForLogin) {
        throw new AccountsError(
          "the configured Accounts API store does not support incarnation-aware login profile updates",
        );
      }
      return this.api.redetectEmailForLogin(
        name,
        profile.tool,
        email,
        expectedProfile.incarnationId,
        expectedProfile.email ?? null,
      );
    }
    return this.api.update(name, profile.tool, { email });
  }

  async restoreProfileState(
    profile: Profile,
    fields: ProfileRollbackFields,
    _ownership?: ProfileRollbackOwnership,
  ): Promise<Profile> {
    if (!this.api.restoreProfile) {
      throw new AccountsError(
        "the configured Accounts API store does not support transactional profile rollback; " +
        "upgrade the custom store before running accounts login",
      );
    }
    if (!profile.incarnationId) {
      throw new AccountsError(
        "accounts-serve did not return an account incarnation for transactional profile rollback; " +
        "redeploy accounts-serve 0.2.9 or newer before running accounts login",
      );
    }
    return this.api.restoreProfile(profile.name, profile.tool, fields, profile.incarnationId);
  }

  async useProfile(name: string, tool?: string): Promise<UseProfileResult> {
    const profile = await this.resolve(name, tool);
    const current = await this.api.setCurrent(profile.tool, profile.name);
    return {
      profile: { ...profile, lastUsedAt: current.updatedAt },
      toolId: profile.tool,
      currentRevision: current.revision,
      ...(current.previousName ? { previousCurrentName: current.previousName } : {}),
      ...(current.previousTargetLastUsedAt
        ? { previousProfileLastUsedAt: current.previousTargetLastUsedAt }
        : {}),
    };
  }

  async useProfileForLogin(
    name: string,
    tool: string | undefined,
    operationId: string,
    expectedProfile?: Profile,
  ): Promise<UseProfileResult> {
    if (!this.api.setCurrentForLogin) {
      throw new AccountsError(
        "the configured Accounts API store does not support transactional login activation; " +
        "upgrade the custom store before running accounts login",
      );
    }
    const profile = await this.resolve(name, tool);
    const expectedIncarnationId = expectedProfile?.incarnationId ?? profile.incarnationId;
    if (!expectedIncarnationId || profile.incarnationId !== expectedIncarnationId) {
      throw new AccountsError("profile changed while login activation was in progress");
    }
    const current = await this.api.setCurrentForLogin(
      profile.tool,
      profile.name,
      operationId,
      expectedIncarnationId,
    );
    return {
      profile: { ...profile, lastUsedAt: current.updatedAt },
      toolId: profile.tool,
      currentRevision: current.revision,
    };
  }

  async restoreCurrent(tool: string, expectedName: string, name?: string): Promise<boolean> {
    return this.api.restoreCurrent(tool, expectedName, name);
  }

  async restoreCurrentGeneration(
    tool: string,
    expectedName: string,
    expectedRevision: string,
    name?: string,
  ): Promise<boolean> {
    if (!this.api.restoreCurrentGeneration) {
      throw new AccountsError(
        "the configured Accounts API store does not support generation-aware current rollback; " +
        "upgrade the custom store before running accounts login",
      );
    }
    return this.api.restoreCurrentGeneration(tool, expectedName, expectedRevision, name);
  }

  async restoreCurrentOperation(
    tool: string,
    expectedName: string,
    operationId: string,
    name?: string,
    restoreLastUsedAt?: string | null,
  ): Promise<boolean> {
    if (!this.api.restoreCurrentOperation) {
      throw new AccountsError(
        "the configured Accounts API store does not support operation-owned current rollback; " +
        "upgrade the custom store before running accounts login",
      );
    }
    return this.api.restoreCurrentOperation(tool, expectedName, operationId, name, restoreLastUsedAt);
  }

  async currentProfile(tool: string): Promise<Profile | undefined> {
    const current = await this.api.getCurrent(tool);
    if (!current) return undefined;
    const profile = await this.api.get(current.name, tool);
    if (profile) await this.hydrateProfileTools([profile]);
    return profile;
  }

  async listCurrent(): Promise<CurrentEntry[]> {
    const current = await this.api.listCurrent();
    return current.map((c) => ({
      tool: c.tool,
      name: c.name,
      ...(c.revision ? { revision: c.revision } : {}),
    }));
  }

  async listCurrentForLoginRollback(): Promise<CurrentEntry[]> {
    if (!this.api.listCurrentForLoginRollback) {
      throw new AccountsError(
        "the configured Accounts API store does not support transactional login rollback; " +
        "upgrade the custom store before running accounts login",
      );
    }
    return this.api.listCurrentForLoginRollback();
  }

  async listTools(): Promise<ToolDef[]> {
    const cloud = await this.api.listTools();
    const custom = this.customToolsFrom(cloud);
    setCustomToolsCache(custom);
    const byId = new Map<string, ToolDef>();
    for (const t of BUILTIN_TOOLS) byId.set(t.id, t);
    for (const t of custom) byId.set(t.id, t);
    return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  async resolveTool(toolId: string): Promise<ToolDef> {
    if (!isBuiltinTool(toolId)) await this.refreshToolCache();
    return getTool(toolId);
  }

  async addTool(def: ToolDef): Promise<ToolDef> {
    if (isBuiltinTool(def.id)) throw new AccountsError(`"${def.id}" is a built-in tool and cannot be redefined`);
    const created = await this.api.createTool(def);
    // Write through to the process cache so this process can launch it now.
    await this.refreshToolCache();
    return created;
  }

  async removeTool(id: string): Promise<void> {
    if (isBuiltinTool(id)) throw new AccountsError(`"${id}" is a built-in tool and cannot be removed`);
    await this.api.removeTool(id);
    await this.refreshToolCache();
  }

  /** Pull the cloud custom-tool set into the process-local resolution cache. */
  private async refreshToolCache(): Promise<void> {
    const cloud = await this.api.listTools();
    setCustomToolsCache(this.customToolsFrom(cloud));
  }

  private customToolsFrom(cloud: Awaited<ReturnType<AccountsCloudApi["listTools"]>>): ToolDef[] {
    const custom: ToolDef[] = [];
    for (const item of cloud) {
      if (item.builtin !== false) continue;
      const { builtin: _builtin, ...definition } = item;
      const parsed = toolDefSchema.safeParse(definition);
      if (!parsed.success) {
        throw new AccountsError(
          `invalid custom tool "${item.id}" returned by accounts-serve: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`,
        );
      }
      custom.push(parsed.data);
    }
    return custom;
  }

  private async hydrateProfileTools(profiles: readonly Profile[]): Promise<void> {
    if (profiles.some((profile) => !isBuiltinTool(profile.tool))) await this.refreshToolCache();
  }

  /** Resolve a profile by name (+optional tool), mirroring local error text. */
  private async resolve(name: string, tool?: string): Promise<Profile> {
    if (tool) {
      const profile = await this.api.get(name, tool);
      if (!profile) throw new AccountsError(`no profile named "${name}" for tool "${tool}". Run \`accounts list\` to see profiles.`);
      await this.hydrateProfileTools([profile]);
      return profile;
    }
    const matches = (await this.api.list()).filter((p) => p.name === name);
    if (matches.length === 0) {
      throw new AccountsError(`no profile named "${name}". Run \`accounts list\` to see profiles.`);
    }
    if (matches.length > 1) {
      throw new AccountsError(
        `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
      );
    }
    const profile = matches[0]!;
    await this.hydrateProfileTools([profile]);
    return profile;
  }
}

function assertProfileName(name: string): void {
  const parsed = profileNameSchema.safeParse(name);
  if (!parsed.success) throw new AccountsError(parsed.error.issues[0]?.message ?? "invalid profile name");
}

function validatedDirectoryPath(input: string): string {
  if (!input.trim() || input.includes("\0") || /[\r\n]/.test(input)) {
    throw new AccountsError("invalid profile directory");
  }
  return expandPath(input);
}

function assertManagedDirectory(dir: string): void {
  const base = resolve(profilesDir());
  const rel = relative(base, resolve(dir));
  if (!rel || rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) {
    throw new AccountsError(`refusing to create managed profile outside ${base}`);
  }
}

function prepareProfileDirectory(dir: string, managed: boolean): boolean {
  if (managed) assertManagedDirectory(dir);
  const existed = existsSync(dir);
  assertSafeWritePath(
    join(dir, ".accounts-directory-check"),
    managed ? { mustStayUnder: profilesDir() } : { mustStayUnder: dir },
  );
  mkdirSync(dir, { recursive: true });
  return !existed;
}

/**
 * Resolve the active registry store for this process. ApiStore when the
 * self-hosted API is configured (URL + key present, mode not forced local),
 * else LocalStore.
 */
export function resolveStore(
  env: NodeJS.ProcessEnv = process.env,
  overrides?: Parameters<typeof resolveAccountsCloud>[1],
): AccountsStore {
  const cloud = resolveAccountsCloud(env, overrides);
  if (cloud.transport === "cloud-http") return new ApiStore(cloud.api);
  clearCustomToolsCache();
  return new LocalStore();
}
