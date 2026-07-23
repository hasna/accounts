import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

export interface ExactProcessLockObservation {
  path: string;
  text: string;
  dev: number;
  ino: number;
}

let beforeClaimForTest:
  | ((observation: ExactProcessLockObservation) => void)
  | undefined;
let afterClaimForTest:
  | ((observation: ExactProcessLockObservation) => void)
  | undefined;

export function setBeforeExactProcessLockClaimForTest(
  hook: ((observation: ExactProcessLockObservation) => void) | undefined,
): void {
  if (process.env.NODE_ENV !== "test") {
    throw new Error("exact process lock test hook is unavailable outside tests");
  }
  beforeClaimForTest = hook;
}

export function setAfterExactProcessLockClaimForTest(
  hook: ((observation: ExactProcessLockObservation) => void) | undefined,
): void {
  if (process.env.NODE_ENV !== "test") {
    throw new Error("exact process lock test hook is unavailable outside tests");
  }
  afterClaimForTest = hook;
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

const UNIQUE_RECLAIM_SUFFIX =
  /^([1-9]\d*)-([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const INCARNATION_RECLAIM_SUFFIX =
  /^v2-([1-9]\d*)-((?:linux|darwin)-[A-Za-z0-9-]+|fallback-[0-9a-f-]+)-([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const LEGACY_RECLAIM_SUFFIX = /^[0-9a-f]{24}$/i;

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function linuxProcessStartId(pid: number): string | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(")");
    if (commandEnd < 0) return undefined;
    const startTime = stat.slice(commandEnd + 1).trim().split(/\s+/)[19];
    return startTime && /^\d+$/.test(startTime)
      ? `linux-${startTime}`
      : undefined;
  } catch {
    return undefined;
  }
}

function portableProcessStartId(pid: number): string | undefined {
  if (process.env.NODE_ENV === "test") {
    const override = process.env.ACCOUNTS_TEST_PROCESS_START_ID;
    const separator = override?.indexOf(":") ?? -1;
    if (
      override &&
      separator > 0 &&
      Number(override.slice(0, separator)) === pid
    ) {
      return override.slice(separator + 1) || undefined;
    }
  }
  const linux = linuxProcessStartId(pid);
  if (linux) return linux;
  if (process.platform !== "darwin") return undefined;
  try {
    const result = spawnSync(
      "/bin/ps",
      ["-o", "lstart=", "-p", String(pid)],
      {
        encoding: "utf8",
        env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 1_000,
      },
    );
    const startedAt =
      result.status === 0
        ? result.stdout.trim().replace(/\s+/g, " ")
        : "";
    return startedAt
      ? `darwin-${createHash("sha256").update(startedAt).digest("hex").slice(0, 24)}`
      : undefined;
  } catch {
    return undefined;
  }
}

function isVerifiableProcessIncarnation(
  value: string | undefined,
): value is string {
  return Boolean(value && /^(?:linux|darwin)-/.test(value));
}

const fallbackProcessIncarnation = `fallback-${randomUUID()}`;

function currentProcessIncarnation(): string {
  return portableProcessStartId(process.pid) ?? fallbackProcessIncarnation;
}

function reclaimClaimantIsLive(pid: number, incarnation?: string): boolean {
  if (isVerifiableProcessIncarnation(incarnation)) {
    const observed = portableProcessStartId(pid);
    if (isVerifiableProcessIncarnation(observed)) {
      return observed === incarnation;
    }
  }
  return processAlive(pid);
}

function reclaimPrefix(path: string): string {
  return `${basename(path)}.reclaim-`;
}

/**
 * Remove abandoned unique reclaim aliases for one exact acquisition and report
 * whether a live claimant still fences that acquisition.
 *
 * Reclaim aliases are same-directory hard links. Their unique names are never
 * reused, so a dead claimant's alias can be removed without risking a later
 * owner. Aliases for byte- or inode-distinct acquisitions are not cleanup
 * authority and are ignored. Legacy deterministic aliases have no reclaimer
 * identity and therefore remain fail-closed when they match the acquisition:
 * an old process could still be paused immediately before its canonical
 * unlink.
 */
interface ExactProcessLockReclaimScan {
  liveClaim: boolean;
  deletionBlocked: boolean;
}

interface ExactProcessLockReclaimScope {
  text: string;
  dev?: number;
  ino?: number;
}

function currentExactProcessLockScope(
  path: string,
): ExactProcessLockReclaimScope | undefined {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
    return {
      text: readFileSync(path, "utf8"),
      dev: stat.dev,
      ino: stat.ino,
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function claimMatchesScope(
  claimPath: string,
  claim: NonNullable<ReturnType<typeof lstatSync>>,
  scope: ExactProcessLockReclaimScope,
): boolean {
  if (
    scope.dev !== undefined &&
    scope.ino !== undefined &&
    (claim.dev !== scope.dev || claim.ino !== scope.ino)
  ) {
    return false;
  }
  try {
    return readFileSync(claimPath, "utf8") === scope.text;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function scanExactProcessLockReclaimClaims(
  path: string,
  requestedScope?: ExactProcessLockReclaimScope,
  ignoredClaimPath?: string,
): ExactProcessLockReclaimScan {
  const directory = dirname(path);
  const prefix = reclaimPrefix(path);
  const scope = requestedScope ?? currentExactProcessLockScope(path);
  let liveClaim = false;
  let deletionBlocked = false;
  let removed = false;
  let names: string[];
  try {
    names = readdirSync(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { liveClaim: false, deletionBlocked: false };
    }
    throw error;
  }
  for (const name of names) {
    if (!name.startsWith(prefix)) continue;
    const suffix = name.slice(prefix.length);
    const incarnation = suffix.match(INCARNATION_RECLAIM_SUFFIX);
    const unique = suffix.match(UNIQUE_RECLAIM_SUFFIX);
    const legacy = LEGACY_RECLAIM_SUFFIX.test(suffix);
    const claimPath = join(directory, name);
    if (claimPath === ignoredClaimPath) continue;
    let claim: ReturnType<typeof lstatSync>;
    try {
      claim = lstatSync(claimPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (!scope) continue;
    if (!claim.isFile() || claim.isSymbolicLink()) {
      liveClaim = true;
      deletionBlocked = true;
      continue;
    }
    if (!claimMatchesScope(claimPath, claim, scope)) continue;
    if (!incarnation && !unique && !legacy) {
      liveClaim = true;
      deletionBlocked = true;
      continue;
    }
    // Legacy deterministic claims have no reclaimer identity. A still-live old
    // process may be paused after validating the canonical inode but before
    // unlinking it, so both publication and another deletion must fail closed.
    if (legacy) {
      liveClaim = true;
      deletionBlocked = true;
      continue;
    }
    if (
      (incarnation &&
        reclaimClaimantIsLive(Number(incarnation[1]), incarnation[2])) ||
      (unique && processAlive(Number(unique[1])))
    ) {
      liveClaim = true;
      continue;
    }
    try {
      unlinkSync(claimPath);
      removed = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (removed) fsyncDirectory(directory);
  return { liveClaim, deletionBlocked };
}

export function exactProcessLockHasLiveReclaimClaims(
  path: string,
  exactText?: string,
): boolean {
  return scanExactProcessLockReclaimClaims(
    path,
    exactText === undefined ? undefined : { text: exactText },
  ).liveClaim;
}

export function observeExactProcessLock(
  path: string,
  exactText: string,
): ExactProcessLockObservation | undefined {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return undefined;
    if (readFileSync(path, "utf8") !== exactText) return undefined;
    return { path, text: exactText, dev: stat.dev, ino: stat.ino };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

/**
 * Remove one byte- and inode-exact process lock observation.
 *
 * Each deleter uses a unique hard-link claim carrying its PID, verifiable
 * process incarnation when the host provides one, and a UUID. Scans are
 * byte/inode scoped so a paused live claimant fences only the exact acquisition
 * it can still unlink. A later process can safely remove that acquisition's
 * abandoned, never-reused alias without touching replacement ownership.
 */
export function removeObservedExactProcessLock(
  observation: ExactProcessLockObservation,
): boolean {
  beforeClaimForTest?.(observation);
  if (
    scanExactProcessLockReclaimClaims(observation.path, observation)
      .deletionBlocked
  ) {
    return false;
  }
  const claimPath =
    `${observation.path}.reclaim-v2-${process.pid}-` +
    `${currentProcessIncarnation()}-${randomUUID()}`;
  let claim: ReturnType<typeof lstatSync> | undefined;
  let removed = false;
  try {
    try {
      linkSync(observation.path, claimPath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return false;
      throw error;
    }
    claim = lstatSync(claimPath);
    if (
      !claim.isFile() ||
      claim.isSymbolicLink() ||
      claim.dev !== observation.dev ||
      claim.ino !== observation.ino
    ) {
      return false;
    }
    afterClaimForTest?.(observation);
    if (
      scanExactProcessLockReclaimClaims(
        observation.path,
        observation,
        claimPath,
      ).liveClaim
    ) {
      return false;
    }
    const current = lstatSync(observation.path);
    if (
      !current.isFile() ||
      current.isSymbolicLink() ||
      current.dev !== observation.dev ||
      current.ino !== observation.ino ||
      readFileSync(observation.path, "utf8") !== observation.text
    ) {
      return false;
    }
    unlinkSync(observation.path);
    removed = true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  } finally {
    if (claim) {
      try {
        const currentClaim = lstatSync(claimPath);
        if (currentClaim.dev === claim.dev && currentClaim.ino === claim.ino) {
          unlinkSync(claimPath);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
  if (removed) fsyncDirectory(dirname(observation.path));
  return removed;
}
