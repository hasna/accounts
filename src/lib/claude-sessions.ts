import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  type Dirent,
  type Stats,
} from "node:fs";
import { basename, isAbsolute, join, resolve } from "node:path";
import type { Profile } from "../types.js";
import { profilesDir } from "../storage.js";
import { getTool } from "./tools.js";

export const CLAUDE_SESSION_METADATA_MAX_BYTES = 64 * 1024;
export const CLAUDE_SESSION_METADATA_MAX_LINES = 32;

/**
 * A live machine writes sessions while the catalog is being read. Retry the
 * benign races a couple of times before reporting a path as unobserved.
 */
const SCAN_ATTEMPTS = 3;

const UUID_JSONL = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/i;

export interface ClaudeSessionIdentity {
  ownerProfile: string;
  profileIdentity: string;
  profilePath: string;
  encodedProject: string;
  projectIdentity: string;
  uuid: string;
  sourcePath: string;
}

export interface ClaudeSessionCatalogEntry {
  identity: ClaudeSessionIdentity;
  /** Opaque, globally unique reference derived only from canonical source coordinates. */
  catalogRef: string;
  ownerProfile: string;
  profileIdentity: string;
  profilePath: string;
  encodedProject: string;
  projectIdentity: string;
  cwd?: string;
  uuid: string;
  sourcePath: string;
  /**
   * A bounded metadata observation, not whole-transcript validation.
   * Continuation brokers must still perform their own strict validation.
   */
  sessionIdCheck: "bounded-match" | "bounded-mismatch" | "not-observed";
  sizeBytes: number;
  updatedAt: string;
}

/** A listed path the scan refused to report because it kept changing underneath. */
export interface ClaudeSessionScanSkip {
  path: string;
  reason: "unstable-directory" | "unstable-session";
}

export interface ClaudeSessionCatalogOptions {
  /** Accounts-managed profiles root. Overridable for isolated tests. */
  profilesRoot?: string;
  /** Claude's live/default config dir. Overridable for isolated tests. */
  defaultDir?: string;
  profile?: string;
  project?: string;
  uuid?: string;
  metadataMaxBytes?: number;
  metadataMaxLines?: number;
  /**
   * Receives every path that was listed but could not be observed safely, so
   * callers can tell "no such session" apart from "not observed on this pass"
   * instead of reading a silently truncated catalog.
   */
  onSkip?: (skip: ClaudeSessionScanSkip) => void;
}

interface VerifiedProfileRoot {
  ownerProfile: string;
  profileIdentity: string;
  dir: string;
  profilePath: string;
  snapshot: DirectorySnapshot;
}

interface DirectorySnapshot {
  path: string;
  realPath: string;
  stat: Stats;
}

interface BoundedMetadata {
  cwd?: string;
  sessionIdCheck: ClaudeSessionCatalogEntry["sessionIdCheck"];
  sourcePath: string;
  stat: Stats;
}

/**
 * `excluded` means the path is deliberately not a catalog entry (foreign,
 * multiply linked, gone); `unstable` means a guard could not be satisfied while
 * the path was being written and the caller must retry or report the skip.
 */
type SessionObservation =
  | { status: "observed"; metadata: BoundedMetadata }
  | { status: "excluded" }
  | { status: "unstable" };

const EXCLUDED: SessionObservation = { status: "excluded" };
const UNSTABLE: SessionObservation = { status: "unstable" };

function safeResolve(path: string): string | undefined {
  if (!path || !isAbsolute(path) || path.includes("\0") || /[\r\n]/.test(path)) return undefined;
  try {
    return resolve(path);
  } catch {
    return undefined;
  }
}

function lstatNoThrow(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function comparablePath(path: string): string {
  return process.platform === "win32" ? path.toLocaleLowerCase("en-US") : path;
}

function samePath(left: string, right: string): boolean {
  return comparablePath(left) === comparablePath(right);
}

function sameFile(left: Stats, right: Stats): boolean {
  if (left.isFile() !== right.isFile() || left.isDirectory() !== right.isDirectory()) return false;
  if (left.dev !== 0 && right.dev !== 0 && left.ino !== 0 && right.ino !== 0) {
    if (left.dev !== right.dev || left.ino !== right.ino) return false;
  }
  return (
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
}

/**
 * Directories are re-verified by identity, never by content-derived stat
 * fields: writing a session legitimately bumps the parent's mtime, ctime, size,
 * and — when a project directory appears or disappears — its nlink. Comparing
 * those made every concurrent write look like a TOCTOU swap and silently
 * dropped the rest of the subtree. Device, inode, real path, ownership, and
 * mode still have to match, so a substituted, re-owned, or re-permissioned
 * directory is still caught.
 */
function sameDirectory(left: Stats, right: Stats): boolean {
  if (!left.isDirectory() || !right.isDirectory()) return false;
  if (left.dev !== 0 && right.dev !== 0 && left.ino !== 0 && right.ino !== 0) {
    if (left.dev !== right.dev || left.ino !== right.ino) return false;
  }
  return left.mode === right.mode && left.uid === right.uid && left.gid === right.gid;
}

function snapshotDirectory(path: string): DirectorySnapshot | undefined {
  const stat = lstatNoThrow(path);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) return undefined;
  try {
    return { path, realPath: realpathSync.native(path), stat };
  } catch {
    return undefined;
  }
}

/** Re-snapshots the directory on every call; never trusts a scan-old stat. */
function unchangedDirectory(snapshot: DirectorySnapshot): boolean {
  const current = snapshotDirectory(snapshot.path);
  return Boolean(
    current &&
      samePath(current.realPath, snapshot.realPath) &&
      sameDirectory(current.stat, snapshot.stat),
  );
}

function readVerifiedDirectoryOnce(
  path: string,
  expectedParent?: DirectorySnapshot,
): { entries: Dirent[]; snapshot: DirectorySnapshot } | undefined {
  const snapshot = snapshotDirectory(path);
  if (!snapshot) return undefined;
  if (
    expectedParent &&
    (!unchangedDirectory(expectedParent) ||
      !samePath(snapshot.realPath, join(expectedParent.realPath, basename(path))))
  ) {
    return undefined;
  }
  try {
    const entries = readdirSync(path, { withFileTypes: true });
    if (!unchangedDirectory(snapshot) || (expectedParent && !unchangedDirectory(expectedParent))) {
      return undefined;
    }
    return { entries, snapshot };
  } catch {
    return undefined;
  }
}

function readVerifiedDirectory(
  path: string,
  expectedParent?: DirectorySnapshot,
): { entries: Dirent[]; snapshot: DirectorySnapshot } | undefined {
  for (let attempt = 0; attempt < SCAN_ATTEMPTS; attempt++) {
    const listing = readVerifiedDirectoryOnce(path, expectedParent);
    if (listing) return listing;
  }
  return undefined;
}

/**
 * Accept only profile roots represented by Accounts on this machine:
 * the exact managed `profiles/claude/<owner>` path, or Claude's exact default
 * dir when a registry profile explicitly points at it. Cloud-stale `/Users`,
 * `/tmp`, and other foreign paths therefore never become discovery roots.
 */
function verifyProfileRoot(
  profile: Profile,
  managedRoot: string,
  defaultRoot: string,
): VerifiedProfileRoot | undefined {
  if (profile.tool !== "claude") return undefined;
  const dir = safeResolve(profile.dir);
  if (!dir) return undefined;
  const expectedManaged = resolve(managedRoot, "claude", profile.name);
  const isManaged = samePath(dir, expectedManaged);
  if (!isManaged && !samePath(dir, defaultRoot)) return undefined;
  let managedClaudeSnapshot: DirectorySnapshot | undefined;
  if (isManaged) {
    const managedSnapshot = snapshotDirectory(managedRoot);
    const claudeSnapshot = snapshotDirectory(resolve(managedRoot, "claude"));
    if (
      !managedSnapshot ||
      !claudeSnapshot ||
      !samePath(claudeSnapshot.realPath, join(managedSnapshot.realPath, "claude"))
    ) {
      return undefined;
    }
    managedClaudeSnapshot = claudeSnapshot;
  }
  const snapshot = snapshotDirectory(dir);
  if (!snapshot) return undefined;
  if (
    managedClaudeSnapshot &&
    (!unchangedDirectory(managedClaudeSnapshot) ||
      !samePath(snapshot.realPath, join(managedClaudeSnapshot.realPath, profile.name)))
  ) {
    return undefined;
  }
  return {
    ownerProfile: profile.name,
    profileIdentity: profile.identity ?? snapshot.realPath,
    dir,
    profilePath: snapshot.realPath,
    snapshot,
  };
}

function scanJsonStringEnd(value: string, start: number): number {
  if (value[start] !== '"') return -1;
  let escaped = false;
  for (let i = start + 1; i < value.length; i++) {
    const char = value[i]!;
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === '"') {
      return i + 1;
    }
  }
  return -1;
}

function skipWhitespace(value: string, start: number): number {
  let i = start;
  while (i < value.length && /\s/.test(value[i]!)) i++;
  return i;
}

/** Skip one JSON value without decoding transcript-owned nested content. */
function skipJsonValue(value: string, start: number): number {
  const first = value[start];
  if (!first) return -1;
  if (first === '"') return scanJsonStringEnd(value, start);
  if (first !== "{" && first !== "[") {
    let i = start;
    while (i < value.length && value[i] !== "," && value[i] !== "}") i++;
    return i;
  }

  const stack: string[] = [first];
  for (let i = start + 1; i < value.length; i++) {
    const char = value[i]!;
    if (char === '"') {
      const end = scanJsonStringEnd(value, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (char === "{" || char === "[") {
      stack.push(char);
      continue;
    }
    if (char === "}" || char === "]") {
      const expected = char === "}" ? "{" : "[";
      if (stack.pop() !== expected) return -1;
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

/**
 * Extract one top-level string field while skipping every other value.
 * Only the requested JSON string token is decoded; prompts/messages are never
 * parsed into application objects or returned by the catalog.
 */
function topLevelString(line: string, wantedKey: string): string | undefined {
  let i = skipWhitespace(line, 0);
  if (line[i] !== "{") return undefined;
  i++;

  while (i < line.length) {
    i = skipWhitespace(line, i);
    if (line[i] === "}") return undefined;
    const keyEnd = scanJsonStringEnd(line, i);
    if (keyEnd < 0) return undefined;

    let key: unknown;
    try {
      key = JSON.parse(line.slice(i, keyEnd));
    } catch {
      return undefined;
    }

    i = skipWhitespace(line, keyEnd);
    if (line[i] !== ":") return undefined;
    i = skipWhitespace(line, i + 1);
    const valueStart = i;
    const valueEnd = skipJsonValue(line, valueStart);
    if (valueEnd < 0) return undefined;

    if (key === wantedKey && line[valueStart] === '"') {
      try {
        const decoded = JSON.parse(line.slice(valueStart, valueEnd)) as unknown;
        return typeof decoded === "string" ? decoded : undefined;
      } catch {
        return undefined;
      }
    }

    i = skipWhitespace(line, valueEnd);
    if (line[i] === ",") {
      i++;
      continue;
    }
    if (line[i] === "}") return undefined;
    return undefined;
  }
  return undefined;
}

function canonicalCwd(value: string): string | undefined {
  const resolved = safeResolve(value);
  if (!resolved) return undefined;
  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function safeOpenReadOnly(path: string): number | undefined {
  const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
  const baseFlags = constants.O_RDONLY | noFollow;
  const noAtime = typeof constants.O_NOATIME === "number" ? constants.O_NOATIME : 0;
  if (noAtime !== 0) {
    try {
      return openSync(path, baseFlags | noAtime);
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? String((error as { code?: unknown }).code)
          : "";
      if (!["EPERM", "EINVAL", "ENOTSUP", "EOPNOTSUPP"].includes(code)) return undefined;
    }
  }
  try {
    return openSync(path, baseFlags);
  } catch {
    return undefined;
  }
}

function readBoundedMetadata(
  path: string,
  initialStat: Stats,
  projectSnapshot: DirectorySnapshot,
  expectedUuid: string,
  maxBytes: number,
  maxLines: number,
): SessionObservation {
  if (initialStat.nlink !== 1) return EXCLUDED;
  if (!unchangedDirectory(projectSnapshot)) return UNSTABLE;
  let sourcePath: string;
  try {
    sourcePath = realpathSync.native(path);
  } catch {
    return EXCLUDED;
  }
  if (!samePath(sourcePath, join(projectSnapshot.realPath, basename(path)))) return EXCLUDED;

  const readLength = maxBytes > 0 ? Math.min(initialStat.size, maxBytes) : 0;
  const buffer = Buffer.allocUnsafe(readLength);
  let fd: number | undefined;
  let bytesRead = 0;
  let openedStat: Stats | undefined;
  try {
    fd = safeOpenReadOnly(path);
    // Still a regular file but refusing to open (permissions, descriptor
    // exhaustion) means unobserved; vanished or symlinked means absent.
    if (fd === undefined) return lstatNoThrow(path)?.isFile() ? UNSTABLE : EXCLUDED;
    openedStat = fstatSync(fd);
    if (!openedStat.isFile() || openedStat.nlink !== 1) return EXCLUDED;
    if (!sameFile(initialStat, openedStat)) return UNSTABLE;
    bytesRead = readSync(fd, buffer, 0, readLength, 0);
    const afterRead = fstatSync(fd);
    if (afterRead.nlink !== 1) return EXCLUDED;
    if (!sameFile(openedStat, afterRead)) return UNSTABLE;
  } catch {
    return UNSTABLE;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  const finalStat = lstatNoThrow(path);
  if (!openedStat || !finalStat) return EXCLUDED;
  if (!finalStat.isFile() || finalStat.isSymbolicLink() || finalStat.nlink !== 1) return EXCLUDED;
  if (!sameFile(openedStat, finalStat) || !unchangedDirectory(projectSnapshot)) return UNSTABLE;
  try {
    if (!samePath(realpathSync.native(path), sourcePath)) return EXCLUDED;
  } catch {
    return EXCLUDED;
  }

  const text = buffer.subarray(0, bytesRead).toString("utf8");
  const lines = maxLines > 0 ? text.split("\n") : [];
  if (maxBytes >= 0 && openedStat.size > maxBytes && !text.endsWith("\n")) lines.pop();

  let cwd: string | undefined;
  let observedSessionId = false;
  let mismatchedSessionId = false;
  for (const rawLine of lines.slice(0, maxLines)) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (cwd === undefined) {
      const candidate = topLevelString(line, "cwd");
      if (candidate !== undefined) cwd = canonicalCwd(candidate);
    }
    const sessionId = topLevelString(line, "sessionId");
    if (sessionId !== undefined) {
      observedSessionId = true;
      if (sessionId.toLowerCase() !== expectedUuid) mismatchedSessionId = true;
    }
  }
  return {
    status: "observed",
    metadata: {
      ...(cwd ? { cwd } : {}),
      sessionIdCheck: mismatchedSessionId
        ? "bounded-mismatch"
        : observedSessionId
          ? "bounded-match"
          : "not-observed",
      sourcePath,
      stat: finalStat,
    },
  };
}

/** Re-stats and retries the file, so a session being appended to is not lost. */
function observeSession(
  path: string,
  projectSnapshot: DirectorySnapshot,
  expectedUuid: string,
  maxBytes: number,
  maxLines: number,
): SessionObservation {
  let observation: SessionObservation = UNSTABLE;
  for (let attempt = 0; attempt < SCAN_ATTEMPTS; attempt++) {
    const stat = lstatNoThrow(path);
    if (!stat?.isFile() || stat.isSymbolicLink()) return EXCLUDED;
    observation = readBoundedMetadata(path, stat, projectSnapshot, expectedUuid, maxBytes, maxLines);
    if (observation.status !== "unstable") return observation;
  }
  return observation;
}

function matchesFilters(entry: ClaudeSessionCatalogEntry, options: ClaudeSessionCatalogOptions): boolean {
  if (options.profile && entry.ownerProfile !== options.profile) return false;
  if (options.uuid && entry.uuid !== options.uuid.toLowerCase()) return false;
  const projectFilter = options.project ? (canonicalCwd(options.project) ?? options.project) : undefined;
  if (
    projectFilter &&
    entry.projectIdentity !== projectFilter &&
    entry.encodedProject !== projectFilter &&
    entry.cwd !== projectFilter &&
    !(
      isAbsolute(projectFilter) &&
      ((isAbsolute(entry.projectIdentity) && samePath(entry.projectIdentity, projectFilter)) ||
        (entry.cwd && samePath(entry.cwd, projectFilter)))
    )
  ) {
    return false;
  }
  return true;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function catalogRef(
  profileIdentity: string,
  profilePath: string,
  encodedProject: string,
  uuid: string,
  sourcePath: string,
): string {
  return `claude-session:v1:${[
    profileIdentity,
    profilePath,
    encodedProject,
    uuid,
    sourcePath,
  ].map((part) => encodeURIComponent(part)).join(":")}`;
}

/**
 * Report a directory the scan listed but could not read. A directory that is
 * simply gone is absent rather than unobserved, so it stays silent.
 */
function reportSkip(options: ClaudeSessionCatalogOptions, path: string): void {
  if (!options.onSkip) return;
  if (lstatNoThrow(path)?.isDirectory()) options.onSkip({ path, reason: "unstable-directory" });
}

/**
 * Discover root Claude JSONL sessions under Accounts-owned local profiles.
 * This function never mutates transcript content and never follows direct
 * session-store symlinks. It requests O_NOATIME where the platform and
 * permissions support it; fallback reads can still update filesystem atime.
 * Concurrent writers never truncate the result silently: a path that stays
 * unreadable after `SCAN_ATTEMPTS` is reported through `options.onSkip`.
 */
export function listClaudeSessions(
  profiles: readonly Profile[],
  options: ClaudeSessionCatalogOptions = {},
): ClaudeSessionCatalogEntry[] {
  const managedRoot = resolve(options.profilesRoot ?? profilesDir());
  const defaultRoot = resolve(options.defaultDir ?? getTool("claude").defaultDir);
  const maxBytes = options.metadataMaxBytes ?? CLAUDE_SESSION_METADATA_MAX_BYTES;
  const maxLines = options.metadataMaxLines ?? CLAUDE_SESSION_METADATA_MAX_LINES;
  const results: ClaudeSessionCatalogEntry[] = [];

  for (const profile of profiles) {
    const verified = verifyProfileRoot(profile, managedRoot, defaultRoot);
    if (!verified) continue;
    const projectsPath = join(verified.dir, "projects");
    const projects = readVerifiedDirectory(projectsPath, verified.snapshot);
    if (!projects) {
      reportSkip(options, projectsPath);
      continue;
    }

    for (const projectDirent of projects.entries) {
      if (!projectDirent.isDirectory() || projectDirent.isSymbolicLink()) continue;
      const encodedProject = projectDirent.name;
      const projectPath = join(projectsPath, encodedProject);
      const project = readVerifiedDirectory(projectPath, projects.snapshot);
      if (!project) {
        reportSkip(options, projectPath);
        continue;
      }

      for (const sessionDirent of project.entries) {
        if (!sessionDirent.isFile() || sessionDirent.isSymbolicLink()) continue;
        const match = sessionDirent.name.match(UUID_JSONL);
        if (!match) continue;

        const candidatePath = join(projectPath, sessionDirent.name);
        const uuid = match[1]!.toLowerCase();
        const observation = observeSession(
          candidatePath,
          project.snapshot,
          uuid,
          maxBytes,
          maxLines,
        );
        if (observation.status === "excluded") continue;
        if (observation.status === "unstable") {
          options.onSkip?.({ path: candidatePath, reason: "unstable-session" });
          continue;
        }
        const { cwd, sessionIdCheck, sourcePath } = observation.metadata;
        const projectIdentity = cwd ?? `encoded:${encodedProject}`;
        const entry: ClaudeSessionCatalogEntry = {
          identity: {
            ownerProfile: verified.ownerProfile,
            profileIdentity: verified.profileIdentity,
            profilePath: verified.profilePath,
            encodedProject,
            projectIdentity,
            uuid,
            sourcePath,
          },
          catalogRef: catalogRef(
            verified.profileIdentity,
            verified.profilePath,
            encodedProject,
            uuid,
            sourcePath,
          ),
          ownerProfile: verified.ownerProfile,
          profileIdentity: verified.profileIdentity,
          profilePath: verified.profilePath,
          encodedProject,
          projectIdentity,
          ...(cwd ? { cwd } : {}),
          uuid,
          sourcePath,
          sessionIdCheck,
          sizeBytes: observation.metadata.stat.size,
          updatedAt: new Date(observation.metadata.stat.mtimeMs).toISOString(),
        };
        if (matchesFilters(entry, options)) results.push(entry);
      }
    }
  }

  return results.sort(
    (a, b) =>
      compareText(a.ownerProfile, b.ownerProfile) ||
      compareText(a.projectIdentity, b.projectIdentity) ||
      compareText(a.uuid, b.uuid) ||
      compareText(a.sourcePath, b.sourcePath),
  );
}
