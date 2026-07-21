import { closeSync, existsSync, mkdirSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError } from "../types.js";

function lockPath(): string {
  return join(accountsHome(), ".apply.lock");
}

interface ApplyLockLease {
  fd: number;
  path: string;
}

function tryAcquireApplyLock(): ApplyLockLease | undefined {
  const home = accountsHome();
  mkdirSync(home, { recursive: true });
  const path = lockPath();
  let fd: number | undefined;
  try {
    fd = openSync(path, "wx", 0o600);
    writeFileSync(fd, `${process.pid}\n`, { encoding: "utf8", mode: 0o600 });
    return { fd, path };
  } catch (err) {
    if (fd !== undefined) {
      closeSync(fd);
      try {
        if (existsSync(path)) unlinkSync(path);
      } catch {
        /* ignore cleanup failure; preserve the original error */
      }
    }
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EEXIST") return undefined;
    if (code === "ENOENT") {
      throw new AccountsError(`could not create apply lock at ${path}: accounts home missing`);
    }
    throw err;
  }
}

function releaseApplyLock(lease: ApplyLockLease): void {
  closeSync(lease.fd);
  try {
    if (existsSync(lease.path)) unlinkSync(lease.path);
  } catch {
    /* ignore */
  }
}

/** Exclusive lock for apply operations (best-effort cross-process). */
export function withApplyLock<T>(fn: () => T): T {
  const lease = tryAcquireApplyLock();
  if (!lease) {
    throw new AccountsError(
      `another accounts apply is in progress at ${lockPath()}; ` +
      "automatic stale-lock reclaim is disabled because ownership cannot be proven",
    );
  }
  try {
    return fn();
  } finally {
    releaseApplyLock(lease);
  }
}

/** Wait for an in-flight apply, then run a synchronous rollback check under the same lock. */
export async function withApplyLockWait<T>(
  fn: () => T,
  opts: { timeoutMs?: number; pollMs?: number } = {},
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const pollMs = opts.pollMs ?? 25;
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const lease = tryAcquireApplyLock();
    if (lease) {
      try {
        return fn();
      } finally {
        releaseApplyLock(lease);
      }
    }
    if (Date.now() >= deadline) {
      throw new AccountsError(`timed out waiting for the accounts apply lock at ${lockPath()}`);
    }
    await new Promise<void>((resolve) => setTimeout(resolve, Math.min(pollMs, Math.max(1, deadline - Date.now()))));
  }
}
