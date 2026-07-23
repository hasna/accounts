import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { deserialize, serialize } from "node:v8";
import { AccountsError } from "../types.js";
import { accountsHome, withStoreLock } from "../storage.js";
import { assertSafeWritePath } from "./safe-path.js";
import type {
  LoginFinalizationState,
  LoginPreparationReady,
} from "./login.js";
import type { KeychainCredential } from "./keychain.js";
import {
  exactProcessLockHasLiveReclaimClaims,
  observeExactProcessLock,
  removeObservedExactProcessLock,
} from "./exact-process-lock.js";

const JOURNAL_VERSION = 1;
const JOURNAL_DIR = "login-finalization-journals";
const JOURNAL_NAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin$/i;
const LEASE_NAME = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.lease$/i;
const PROCESS_LOCK_TOKEN = /^[1-9]\d*:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type DurablePreparation = Omit<LoginPreparationReady, "releaseProfileLease">;

export interface LoginRecoveryJournal {
  version: 1;
  id: string;
  phase: "rollback" | "committed";
  transport: "local" | "api";
  storeAuthority: string;
  ownerPid: number;
  ownerProcessStartId: string;
  preparation: DurablePreparation;
  finalizationState: LoginFinalizationState;
  keychainCaptured: boolean;
  priorKeychain?: KeychainCredential;
}

export interface LoginLeaseRecoveryIntent {
  version: 1;
  id: string;
  ownerPid: number;
  ownerProcessStartId: string;
  profileDir: string;
  profileLockToken?: string;
}

function journalDirectory(): string {
  return join(accountsHome(), JOURNAL_DIR);
}

function journalPath(id: string): string {
  if (!JOURNAL_NAME.test(`${id}.bin`)) throw new AccountsError("invalid login recovery journal id");
  return join(journalDirectory(), `${id}.bin`);
}

function leasePath(id: string): string {
  if (!LEASE_NAME.test(`${id}.lease`)) throw new AccountsError("invalid login lease recovery id");
  return join(journalDirectory(), `${id}.lease`);
}

function fsyncDirectory(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!["EINVAL", "ENOTSUP", "EOPNOTSUPP", "EPERM", "EACCES", "EISDIR"].includes(code ?? "")) {
      throw error;
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function ensureJournalDirectory(): string {
  const home = accountsHome();
  const path = journalDirectory();
  assertSafeWritePath(path, { mustStayUnder: home });
  if (existsSync(path)) {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new AccountsError("invalid login recovery journal directory");
    }
    chmodSync(path, 0o700);
    return path;
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
  fsyncDirectory(dirname(path));
  return path;
}

function durableState(state: LoginFinalizationState): LoginFinalizationState {
  const { persist: _persist, ...writes } = state.writes;
  return {
    ...state,
    writes,
  };
}

function durablePreparation(preparation: LoginPreparationReady): DurablePreparation {
  const { releaseProfileLease: _releaseProfileLease, ...durable } = preparation;
  return durable;
}

function processStartId(pid: number): string | undefined {
  if (process.platform === "linux") {
    try {
      const text = readFileSync(`/proc/${pid}/stat`, "utf8");
      const commandEnd = text.lastIndexOf(")");
      const start = commandEnd < 0
        ? undefined
        : text.slice(commandEnd + 1).trim().split(/\s+/)[19];
      return start && /^\d+$/.test(start) ? `linux-${start}` : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

const currentProcessStartId = processStartId(process.pid) ?? `fallback-${randomUUID()}`;

/** Nonsecret, exact storage authority binding for crash replay. */
export function loginRecoveryStoreAuthority(
  transport: "local" | "api",
  localHome: string,
  configuredApiUrl?: string,
): string {
  let canonical: string;
  if (transport === "local") {
    canonical = `local:${resolve(localHome)}`;
  } else {
    if (!configuredApiUrl) throw new AccountsError("Accounts API authority is unavailable for login recovery");
    const url = new URL(configuredApiUrl);
    url.username = "";
    url.password = "";
    url.hash = "";
    url.search = "";
    url.pathname = url.pathname.replace(/\/+$/, "");
    canonical = url.toString();
  }
  return createHash("sha256").update(canonical).digest("hex");
}

function publishJournal(journal: LoginRecoveryJournal): void {
  const parent = ensureJournalDirectory();
  const path = journalPath(journal.id);
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, { mustStayUnder: accountsHome() });
  const bytes = serialize(journal);
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    chmodSync(path, 0o600);
    fsyncDirectory(parent);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

function publishLeaseIntent(intent: LoginLeaseRecoveryIntent): void {
  const parent = ensureJournalDirectory();
  const path = leasePath(intent.id);
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, { mustStayUnder: accountsHome() });
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    writeFileSync(fd, serialize(intent));
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    chmodSync(path, 0o600);
    fsyncDirectory(parent);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

export function createLoginLeaseRecoveryIntent(
  profileDir: string,
  profileLockToken: string,
): Pick<LoginLeaseRecoveryIntent, "id" | "profileLockToken"> & { profileLockToken: string } {
  if (
    !PROCESS_LOCK_TOKEN.test(profileLockToken) ||
    !profileLockToken.startsWith(`${process.pid}:`)
  ) {
    throw new AccountsError("invalid login profile lock ownership token");
  }
  const id = randomUUID();
  publishLeaseIntent({
    version: JOURNAL_VERSION,
    id,
    ownerPid: process.pid,
    ownerProcessStartId: currentProcessStartId,
    profileDir: resolve(profileDir),
    profileLockToken,
  });
  return { id, profileLockToken };
}

export function clearLoginLeaseRecoveryIntent(id: string): void {
  const path = leasePath(id);
  if (!existsSync(path)) return;
  unlinkSync(path);
  fsyncDirectory(dirname(path));
}

export function createLoginRecoveryJournal(
  preparation: LoginPreparationReady,
  state: LoginFinalizationState,
  priorKeychain: KeychainCredential | undefined,
  keychainCaptured: boolean,
  transport: LoginRecoveryJournal["transport"],
  storeAuthority: string,
): string {
  const id = randomUUID();
  publishJournal({
    version: JOURNAL_VERSION,
    id,
    phase: "rollback",
    transport,
    storeAuthority,
    ownerPid: process.pid,
    ownerProcessStartId: currentProcessStartId,
    preparation: durablePreparation(preparation),
    finalizationState: durableState(state),
    keychainCaptured,
    ...(priorKeychain ? { priorKeychain } : {}),
  });
  return id;
}

export function persistLoginRecoveryJournal(
  id: string,
  preparation: LoginPreparationReady,
  state: LoginFinalizationState,
  priorKeychain: KeychainCredential | undefined,
  keychainCaptured: boolean,
  transport: LoginRecoveryJournal["transport"],
  storeAuthority: string,
  phase: LoginRecoveryJournal["phase"] = "rollback",
): void {
  publishJournal({
    version: JOURNAL_VERSION,
    id,
    phase,
    transport,
    storeAuthority,
    ownerPid: process.pid,
    ownerProcessStartId: currentProcessStartId,
    preparation: durablePreparation(preparation),
    finalizationState: durableState(state),
    keychainCaptured,
    ...(priorKeychain ? { priorKeychain } : {}),
  });
}

export function clearLoginRecoveryJournal(id: string): void {
  const path = journalPath(id);
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  if (!existsSync(path)) return;
  unlinkSync(path);
  fsyncDirectory(dirname(path));
}

function validateJournal(value: unknown, expectedId: string): LoginRecoveryJournal {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError("invalid login recovery journal");
  }
  const journal = value as Partial<LoginRecoveryJournal>;
  if (
    journal.version !== JOURNAL_VERSION ||
    journal.id !== expectedId ||
    !["rollback", "committed"].includes(journal.phase ?? "") ||
    !["local", "api"].includes(journal.transport ?? "") ||
    typeof journal.storeAuthority !== "string" ||
    journal.storeAuthority.length === 0 ||
    journal.storeAuthority.length > 2048 ||
    typeof journal.ownerPid !== "number" ||
    !Number.isSafeInteger(journal.ownerPid) ||
    journal.ownerPid <= 0 ||
    typeof journal.ownerProcessStartId !== "string" ||
    !/^(?:linux-\d+|fallback-[0-9a-f-]+)$/i.test(journal.ownerProcessStartId) ||
    !journal.preparation ||
    journal.preparation.status !== "ready" ||
    !journal.finalizationState ||
    !journal.finalizationState.writes ||
    typeof journal.keychainCaptured !== "boolean" ||
    (journal.finalizationState.writes.keychainLockToken !== undefined &&
      (!PROCESS_LOCK_TOKEN.test(journal.finalizationState.writes.keychainLockToken) ||
        !journal.finalizationState.writes.keychainLockToken.startsWith(`${journal.ownerPid}:`))) ||
    (journal.finalizationState.writes.applyLockToken !== undefined &&
      (!PROCESS_LOCK_TOKEN.test(journal.finalizationState.writes.applyLockToken) ||
        !journal.finalizationState.writes.applyLockToken.startsWith(`${journal.ownerPid}:`)))
  ) {
    throw new AccountsError("invalid login recovery journal");
  }
  return journal as LoginRecoveryJournal;
}

function readLoginRecoveryJournalFile(id: string): LoginRecoveryJournal | undefined {
  const path = journalPath(id);
  assertSafeWritePath(path, { mustStayUnder: accountsHome() });
  let file: ReturnType<typeof lstatSync>;
  try {
    file = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0) {
    throw new AccountsError("unsafe login recovery journal permissions");
  }
  let decoded: unknown;
  try {
    decoded = reviveBuffers(deserialize(readFileSync(path)));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new AccountsError(`invalid login recovery journal: ${String(error)}`);
  }
  return validateJournal(decoded, id);
}

/** Read one exact journal regardless of whether its recorded owner is live. */
export function readLoginRecoveryJournal(id: string): LoginRecoveryJournal | undefined {
  return readLoginRecoveryJournalFile(id);
}

/** Stable byte-level identity for detecting replacement or mutation after a wait. */
export function loginRecoveryJournalFingerprint(journal: LoginRecoveryJournal): string {
  return createHash("sha256").update(serialize(journal)).digest("hex");
}

function reviveBuffers(value: unknown): unknown {
  if (value instanceof Uint8Array && !Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(reviveBuffers);
  if (value && typeof value === "object") {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key === "string") {
        (value as Record<string, unknown>)[key] = reviveBuffers(
          (value as Record<string, unknown>)[key],
        );
      }
    }
  }
  return value;
}

function ownerIsLive(pid: number, expectedStartId?: string): boolean {
  const observedStartId = processStartId(pid);
  if (
    expectedStartId?.startsWith("linux-") &&
    observedStartId?.startsWith("linux-")
  ) {
    return expectedStartId === observedStartId;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

/** Return only journals whose owning process is provably gone. */
export function readRecoverableLoginJournals(): LoginRecoveryJournal[] {
  const directory = journalDirectory();
  if (!existsSync(directory)) return [];
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new AccountsError("invalid login recovery journal directory");
  }
  const journals: LoginRecoveryJournal[] = [];
  for (const name of readdirSync(directory).sort()) {
    if (!JOURNAL_NAME.test(name)) continue;
    const id = name.slice(0, -4);
    const journal = readLoginRecoveryJournalFile(id);
    if (!journal) continue;
    if (!ownerIsLive(journal.ownerPid, journal.ownerProcessStartId)) journals.push(journal);
  }
  return journals;
}

/** Re-read one journal only if its exact recorded owner is still provably dead. */
export function readRecoverableLoginJournal(id: string): LoginRecoveryJournal | undefined {
  const journal = readLoginRecoveryJournalFile(id);
  if (!journal) return undefined;
  return ownerIsLive(journal.ownerPid, journal.ownerProcessStartId)
    ? undefined
    : journal;
}

export function readRecoverableLoginLeaseIntents(): LoginLeaseRecoveryIntent[] {
  const directory = journalDirectory();
  if (!existsSync(directory)) return [];
  const intents: LoginLeaseRecoveryIntent[] = [];
  for (const name of readdirSync(directory).sort()) {
    if (!LEASE_NAME.test(name)) continue;
    const path = join(directory, name);
    const file = lstatSync(path);
    if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0) {
      throw new AccountsError("unsafe login lease recovery intent");
    }
    const value = deserialize(readFileSync(path)) as Partial<LoginLeaseRecoveryIntent>;
    const id = name.slice(0, -".lease".length);
    if (
      value.version !== JOURNAL_VERSION ||
      value.id !== id ||
      typeof value.ownerPid !== "number" ||
      typeof value.ownerProcessStartId !== "string" ||
      typeof value.profileDir !== "string" ||
      (value.profileLockToken !== undefined &&
        (!PROCESS_LOCK_TOKEN.test(value.profileLockToken) ||
          !value.profileLockToken.startsWith(`${value.ownerPid}:`)))
    ) {
      throw new AccountsError("invalid login lease recovery intent");
    }
    const intent = value as LoginLeaseRecoveryIntent;
    if (!ownerIsLive(intent.ownerPid, intent.ownerProcessStartId)) intents.push(intent);
  }
  return intents;
}

function abandonedProfileLoginLockPath(profileDir: string): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  const identity = createHash("sha256").update(resolve(profileDir)).digest("hex").slice(0, 32);
  return join(
    process.platform === "win32" ? tmpdir() : "/tmp",
    `accounts-claude-login-${uid}-${identity}.lock`,
  );
}

function abandonedKeychainLockPath(): string {
  if (process.env.NODE_ENV === "test" && process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH) {
    return process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  return join(
    process.platform === "win32" ? tmpdir() : "/tmp",
    `accounts-claude-keychain-${uid}.lock`,
  );
}

function removeExactAbandonedProcessLock(
  path: string,
  exactToken: string | undefined,
  ownerPid: number,
  ownerProcessStartId: string,
): boolean {
  // A preparation that never acquired this lock has no cleanup authority and
  // must neither wait on nor clear another acquisition's reclaim aliases.
  if (!exactToken) return true;
  const observation = observeExactProcessLock(path, exactToken);
  if (observation) {
    if (ownerIsLive(ownerPid, ownerProcessStartId)) {
      throw new AccountsError(`login recovery owner ${ownerPid} became live while reclaiming its lock`);
    }
    removeObservedExactProcessLock(observation);
  }
  return (
    !exactProcessLockHasLiveReclaimClaims(path, exactToken) &&
    !observeExactProcessLock(path, exactToken)
  );
}

function removeExactAbandonedApplyLock(journal: LoginRecoveryJournal): void {
  const exactToken = journal.finalizationState?.writes?.applyLockToken;
  if (!exactToken) return;
  withStoreLock(() => {
    const path = join(accountsHome(), ".apply.lock");
    if (!existsSync(path)) return;
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return;
    }
    if (readFileSync(path, "utf8") !== `${exactToken}\n`) return;
    if (ownerIsLive(journal.ownerPid, journal.ownerProcessStartId)) {
      throw new AccountsError("login recovery owner became live while reclaiming its apply lock");
    }
    unlinkSync(path);
    fsyncDirectory(dirname(path));
  });
}

function releaseAbandonedLeaseIntentLocks(intent: LoginLeaseRecoveryIntent): boolean {
  return removeExactAbandonedProcessLock(
    abandonedProfileLoginLockPath(intent.profileDir),
    intent.profileLockToken,
    intent.ownerPid,
    intent.ownerProcessStartId,
  );
}

/** Verify that this process still owns both the durable intent and exact profile lock. */
export function ownsLoginRecoveryProfileClaim(
  intentId: string,
  profileDir: string,
  profileLockToken: string,
): boolean {
  const path = leasePath(intentId);
  if (!existsSync(path)) return false;
  const file = lstatSync(path);
  if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0) {
    throw new AccountsError("unsafe login lease recovery intent");
  }
  const value = deserialize(readFileSync(path)) as Partial<LoginLeaseRecoveryIntent>;
  if (
    value.version !== JOURNAL_VERSION ||
    value.id !== intentId ||
    value.ownerPid !== process.pid ||
    value.ownerProcessStartId !== currentProcessStartId ||
    resolve(value.profileDir ?? "") !== resolve(profileDir) ||
    value.profileLockToken !== profileLockToken
  ) {
    return false;
  }
  return Boolean(
    observeExactProcessLock(
      abandonedProfileLoginLockPath(profileDir),
      profileLockToken,
    ),
  );
}

export function recoverAbandonedLoginLeaseIntents(): void {
  for (const intent of readRecoverableLoginLeaseIntents()) {
    if (releaseAbandonedLeaseIntentLocks(intent)) {
      clearLoginLeaseRecoveryIntent(intent.id);
    }
  }
}

/** Reclaim only the exact dead owner's leases before taking fresh recovery leases. */
export function releaseAbandonedLoginJournalLocks(journal: LoginRecoveryJournal): void {
  if (journal.preparation.tool.id !== "claude") return;
  removeExactAbandonedProcessLock(
    abandonedKeychainLockPath(),
    journal.finalizationState.writes.keychainLockToken,
    journal.ownerPid,
    journal.ownerProcessStartId,
  );
  removeExactAbandonedApplyLock(journal);
}
