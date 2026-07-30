import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError } from "../types.js";
import { isAccountUuid } from "./auth-store.js";
import { writeFileAtomic } from "./safe-path.js";

/**
 * Per-ACCOUNT cross-process mutex — the single-writer half of the credential
 * broker.
 *
 * Ported from the credential-zero subscription broker in iapp-infinity
 * (`src/lanes/file-lock.ts` + `subscription-token-refresh.ts`), which runs the
 * same shape against OpenAI tokens: a `mkdir` mutex keyed by the credential's
 * identity, held across the whole read → (maybe refresh) → persist sequence, so
 * two processes can never both hold a stale refresh token at the exchange.
 * `mkdir` is atomic on every platform this package supports (POSIX and NTFS
 * both), needs no flock semantics, and its failure mode is a leftover
 * directory — visible, inspectable, and breakable — rather than a silently
 * shared lock.
 *
 * Keyed on the account uuid, NOT a file path: the whole defect class this
 * serializes is one account's credential living in SEVERAL files (central
 * store, profile snapshots, live config dirs). A path-keyed lock would let two
 * writers of the same account proceed under two different locks.
 */

interface LockOwner {
  pid: number;
  host: string;
  acquiredAt: string;
  token: string;
}

export interface IdentityLockOptions {
  /** Give up acquiring after this long. */
  timeoutMs?: number;
  /**
   * A held lock older than this is presumed abandoned even when its pid cannot
   * be probed (other host, pid recycled). Must comfortably exceed the longest
   * legitimate hold: one converge (file I/O) plus one token exchange
   * (network, itself capped well below this).
   */
  staleMs?: number;
  /** Poll interval while waiting; jittered. */
  pollMs?: number;
  /** Lock root override (tests). Default: `<accountsHome>/locks`. */
  root?: string;
  now?: () => number;
}

export const DEFAULT_IDENTITY_LOCK_TIMEOUT_MS = 20_000;
export const DEFAULT_IDENTITY_LOCK_STALE_MS = 120_000;
const DEFAULT_POLL_MS = 40;

function lockRoot(opts: IdentityLockOptions): string {
  return opts.root ?? join(accountsHome(), "locks");
}

function lockDirFor(accountUuid: string, opts: IdentityLockOptions): string {
  if (!isAccountUuid(accountUuid)) {
    throw new AccountsError(`invalid account uuid for identity lock: ${JSON.stringify(accountUuid)}`);
  }
  return join(lockRoot(opts), `identity-${accountUuid.toLowerCase()}.lock`);
}

function readOwner(lockDir: string): LockOwner | undefined {
  try {
    const parsed = JSON.parse(readFileSync(join(lockDir, "owner.json"), "utf8")) as Partial<LockOwner>;
    if (typeof parsed.pid !== "number" || typeof parsed.acquiredAt !== "string") return undefined;
    return {
      pid: parsed.pid,
      host: typeof parsed.host === "string" ? parsed.host : "",
      acquiredAt: parsed.acquiredAt,
      token: typeof parsed.token === "string" ? parsed.token : "",
    };
  } catch {
    return undefined;
  }
}

function ownerIsDead(owner: LockOwner): boolean {
  if (owner.host !== hostname()) return false; // cannot probe a foreign pid
  try {
    process.kill(owner.pid, 0);
    return false;
  } catch (error) {
    // EPERM: alive but not ours. Anything else (ESRCH): gone.
    return !(error instanceof Error && "code" in error && (error as { code?: string }).code === "EPERM");
  }
}

/**
 * Break an abandoned lock by ATOMIC RENAME, then delete the renamed corpse.
 * Two processes both deciding to break race on the rename; exactly one wins,
 * the loser's rename throws, and neither ever deletes a lock a third process
 * just validly acquired at the original path.
 */
function breakLock(lockDir: string): void {
  const corpse = `${lockDir}.stale.${process.pid}.${randomUUID()}`;
  try {
    renameSync(lockDir, corpse);
  } catch {
    return; // somebody else broke it (or the owner released); either way it is gone
  }
  rmSync(corpse, { recursive: true, force: true });
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function tryAcquire(lockDir: string): boolean {
  try {
    mkdirSync(lockDir, { recursive: false });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    // Parent missing: create it and retry once.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      mkdirSync(join(lockDir, ".."), { recursive: true });
      try {
        mkdirSync(lockDir, { recursive: false });
      } catch (retryError) {
        if ((retryError as NodeJS.ErrnoException).code === "EEXIST") return false;
        throw retryError;
      }
      return true;
    }
    throw error;
  }
  return true;
}

/** One acquire attempt: take it, break an abandoned holder, or say how long to wait. */
function attemptAcquire(
  accountUuid: string,
  lockDir: string,
  opts: IdentityLockOptions,
  deadline: number,
): { state: "acquired" } | { state: "retry"; waitMs: number } {
  const now = opts.now ?? Date.now;
  const staleMs = opts.staleMs ?? DEFAULT_IDENTITY_LOCK_STALE_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;

  if (tryAcquire(lockDir)) {
    const owner: LockOwner = {
      pid: process.pid,
      host: hostname(),
      acquiredAt: new Date(now()).toISOString(),
      token: randomUUID(),
    };
    try {
      writeFileAtomic(join(lockDir, "owner.json"), JSON.stringify(owner, null, 2) + "\n", { mode: 0o600 });
    } catch {
      // A lock without an owner file is still a lock; it just breaks by age.
    }
    return { state: "acquired" };
  }

  const owner = readOwner(lockDir);
  const age = owner ? now() - Date.parse(owner.acquiredAt) : Number.POSITIVE_INFINITY;
  if ((owner && ownerIsDead(owner)) || !Number.isFinite(age) || age > staleMs) {
    breakLock(lockDir);
    return { state: "retry", waitMs: 0 }; // immediately retry the acquire
  }

  if (now() >= deadline) {
    throw new AccountsError(
      `could not acquire the credential lock for account ${accountUuid} within ${opts.timeoutMs ?? DEFAULT_IDENTITY_LOCK_TIMEOUT_MS}ms — ` +
        `held by pid ${owner?.pid ?? "unknown"} on ${owner?.host ?? "unknown host"} since ${owner?.acquiredAt ?? "unknown"}. ` +
        `If that process is gone, the lock breaks itself after ${Math.round(staleMs / 1000)}s.`,
    );
  }
  return { state: "retry", waitMs: pollMs + Math.floor(Math.random() * pollMs) };
}

function acquire(accountUuid: string, opts: IdentityLockOptions): string {
  const lockDir = lockDirFor(accountUuid, opts);
  const now = opts.now ?? Date.now;
  const deadline = now() + (opts.timeoutMs ?? DEFAULT_IDENTITY_LOCK_TIMEOUT_MS);
  for (;;) {
    const attempt = attemptAcquire(accountUuid, lockDir, opts, deadline);
    if (attempt.state === "acquired") return lockDir;
    if (attempt.waitMs > 0) sleepSync(attempt.waitMs);
  }
}

/**
 * The async acquire YIELDS between attempts instead of blocking the event
 * loop. This is load-bearing, not stylistic: two `ensureFresh` calls racing in
 * ONE process must let the lock holder's awaited exchange continue — a
 * synchronous sleep here would starve it and turn the race into a deadlock
 * that only the acquire timeout unwinds.
 */
async function acquireAsync(accountUuid: string, opts: IdentityLockOptions): Promise<string> {
  const lockDir = lockDirFor(accountUuid, opts);
  const now = opts.now ?? Date.now;
  const deadline = now() + (opts.timeoutMs ?? DEFAULT_IDENTITY_LOCK_TIMEOUT_MS);
  for (;;) {
    const attempt = attemptAcquire(accountUuid, lockDir, opts, deadline);
    if (attempt.state === "acquired") return lockDir;
    await new Promise((resolve) => setTimeout(resolve, Math.max(attempt.waitMs, 1)));
  }
}

function release(lockDir: string): void {
  rmSync(lockDir, { recursive: true, force: true });
}

/** Run `fn` holding the account's credential lock. Synchronous critical sections. */
export function withIdentityLockSync<T>(accountUuid: string, fn: () => T, opts: IdentityLockOptions = {}): T {
  const lockDir = acquire(accountUuid, opts);
  try {
    return fn();
  } finally {
    release(lockDir);
  }
}

/**
 * Run `fn` holding the account's credential lock, for critical sections that
 * await (the token exchange). The lock spans the entire async section — that is
 * the point: nothing else may read-modify-write this account's credential
 * between the re-read and the persist.
 */
export async function withIdentityLock<T>(
  accountUuid: string,
  fn: () => Promise<T>,
  opts: IdentityLockOptions = {},
): Promise<T> {
  const lockDir = await acquireAsync(accountUuid, opts);
  try {
    return await fn();
  } finally {
    release(lockDir);
  }
}
