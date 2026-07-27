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
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { AccountsError, type Profile } from "../types.js";
import { profilesDir } from "../storage.js";
import { getTool } from "./tools.js";

export const CLAUDE_SESSION_METADATA_MAX_BYTES = 64 * 1024;
export const CLAUDE_SESSION_METADATA_MAX_LINES = 32;

/**
 * A live machine writes sessions while the catalog is being read. Retry the
 * benign races a couple of times before reporting a path as unobserved.
 */
const SCAN_ATTEMPTS = 3;

const UUID_SOURCE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const UUID = new RegExp(`^${UUID_SOURCE}$`, "i");
const UUID_JSONL = new RegExp(`^(${UUID_SOURCE})\\.jsonl$`, "i");

export function isClaudeSessionUuid(value: string): boolean {
  return UUID.test(value);
}

export interface ClaudeSessionIdentity {
  ownerProfile: string;
  profileIdentity: string;
  profilePath: string;
  encodedProject: string;
  projectIdentity: string;
  uuid: string;
  sourcePath: string;
}

/** Canonical on-disk coordinates that identify one session independently of Accounts metadata. */
export interface ClaudeSessionStorageIdentity {
  profilePath: string;
  encodedProject: string;
  uuid: string;
  sourcePath: string;
}

/** One Accounts registry record that represents the canonical session storage root. */
export interface ClaudeSessionProfileRepresentation {
  ownerProfile: string;
  profileIdentity: string;
  profilePath: string;
  /** Exact reference shape emitted by the landed v1 catalog for this representation. */
  catalogRefAlias: string;
}

export interface ClaudeSessionCatalogEntry {
  /** Backward-compatible primary representation plus canonical source coordinates. */
  identity: ClaudeSessionIdentity;
  /** Canonical storage/session tuple used by the opaque reference. */
  storageIdentity: ClaudeSessionStorageIdentity;
  /** Opaque reference derived only from immutable canonical storage coordinates. */
  catalogRef: string;
  /** Deterministic legacy v1 references accepted as aliases for this entry. */
  catalogRefAliases: string[];
  /** All sorted registry records that represent this one canonical source root. */
  representations: ClaudeSessionProfileRepresentation[];
  /** Deterministic primary display representation (the first item in `representations`). */
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

/** A source path omitted from this pass, with a content-free reason. */
export interface ClaudeSessionScanSkip {
  path: string;
  reason:
    | "unstable-directory"
    | "unstable-session"
    | "invalid-profile-identity"
    | "invalid-source-identity"
    | "missing-profile-root"
    | "untrusted-profile-root";
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

interface VerifiedStorageRoot {
  dir: string;
  profilePath: string;
  snapshot: DirectorySnapshot;
  representations: VerifiedProfileRoot[];
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

/** Match either the canonical storage reference or one explicitly exposed legacy alias. */
export function matchesClaudeSessionReference(
  entry: ClaudeSessionCatalogEntry,
  reference: string,
): boolean {
  return entry.catalogRef === reference || entry.catalogRefAliases.includes(reference);
}

/**
 * Resolve a canonical/legacy catalog reference or an unambiguous bare UUID.
 * Unknown legacy references fail closed; callers must never reinterpret them
 * as a new transaction identity.
 */
export function resolveClaudeSessionReference(
  entries: readonly ClaudeSessionCatalogEntry[],
  referenceOrUuid: string,
): ClaudeSessionCatalogEntry {
  const uuidMatch = isClaudeSessionUuid(referenceOrUuid);
  const matches = uuidMatch
    ? entries.filter((entry) => entry.uuid === referenceOrUuid.toLowerCase())
    : entries.filter((entry) => matchesClaudeSessionReference(entry, referenceOrUuid));
  if (matches.length === 0) {
    throw new AccountsError(
      uuidMatch
        ? "no Accounts-owned Claude session matches that UUID"
        : "invalid or stale Claude session catalogRef",
    );
  }
  if (matches.length > 1) {
    throw new AccountsError(
      uuidMatch
        ? "Claude session UUID is ambiguous; use the opaque catalogRef from accounts sessions --json"
        : "Claude session catalogRef is ambiguous; refresh the catalog before continuing",
    );
  }
  return matches[0]!;
}

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

/** encodeURIComponent rejects lone surrogates, so reject them at the record boundary. */
function isWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index++;
      continue;
    }
    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) return false;
  }
  return true;
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

function hasPathTraversal(path: string): boolean {
  return path.split(/[\\/]+/).some((part) => part === "..");
}

/** Return the stored direct-child name, rejecting traversal and nested roots. */
function directChildName(parent: string, child: string): string | undefined {
  const rel = relative(parent, child);
  if (
    !rel ||
    rel === ".." ||
    rel.startsWith(`..${sep}`) ||
    isAbsolute(rel) ||
    dirname(rel) !== "."
  ) {
    return undefined;
  }
  return rel;
}

function reportProfileRootSkip(
  profile: Profile,
  reason: "missing-profile-root" | "untrusted-profile-root",
  onSkip?: ClaudeSessionCatalogOptions["onSkip"],
  resolvedPath?: string,
): void {
  onSkip?.({ path: resolvedPath ?? profile.dir, reason });
}

/**
 * Accept only profile roots represented by Accounts on this machine:
 * the stored canonical direct child of `profiles/claude` (independent of the
 * mutable profile name), or Claude's exact default dir. Cloud-stale, foreign,
 * traversal, nested, and symlink roots are rejected and reported.
 */
function verifyProfileRoot(
  profile: Profile,
  managedRoot: string,
  defaultRoot: string,
  onSkip?: ClaudeSessionCatalogOptions["onSkip"],
): VerifiedProfileRoot | undefined {
  if (profile.tool !== "claude") return undefined;
  const dir = safeResolve(profile.dir);
  if (!dir || hasPathTraversal(profile.dir)) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }
  const managedClaudePath = resolve(managedRoot, "claude");
  const managedChild = directChildName(managedClaudePath, dir);
  const isDefault = samePath(dir, defaultRoot);
  if (!managedChild && !isDefault) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }

  const rootStat = lstatNoThrow(dir);
  if (!rootStat) {
    reportProfileRootSkip(profile, "missing-profile-root", onSkip, dir);
    return undefined;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }

  let managedClaudeSnapshot: DirectorySnapshot | undefined;
  if (managedChild) {
    const managedSnapshot = snapshotDirectory(managedRoot);
    const claudeSnapshot = snapshotDirectory(managedClaudePath);
    if (
      !managedSnapshot ||
      !claudeSnapshot ||
      !samePath(claudeSnapshot.realPath, join(managedSnapshot.realPath, "claude"))
    ) {
      reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
      return undefined;
    }
    managedClaudeSnapshot = claudeSnapshot;
  }
  const snapshot = snapshotDirectory(dir);
  if (!snapshot) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }
  if (
    managedClaudeSnapshot &&
    (!unchangedDirectory(managedClaudeSnapshot) ||
      !samePath(snapshot.realPath, join(managedClaudeSnapshot.realPath, managedChild!)))
  ) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }

  // Scan through the canonical path so registry spelling and record order can
  // never affect source paths, references, or serialized output.
  const canonicalSnapshot = snapshotDirectory(snapshot.realPath);
  if (
    !canonicalSnapshot ||
    !samePath(canonicalSnapshot.realPath, snapshot.realPath) ||
    !sameDirectory(canonicalSnapshot.stat, snapshot.stat)
  ) {
    reportProfileRootSkip(profile, "untrusted-profile-root", onSkip, dir);
    return undefined;
  }
  const profileIdentity = profile.identity ?? snapshot.realPath;
  if (!isWellFormedUtf16(profileIdentity)) {
    onSkip?.({ path: snapshot.realPath, reason: "invalid-profile-identity" });
    return undefined;
  }
  return {
    ownerProfile: profile.name,
    profileIdentity,
    dir: canonicalSnapshot.path,
    profilePath: snapshot.realPath,
    snapshot: canonicalSnapshot,
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
  if (
    options.profile &&
    !entry.representations.some((representation) => representation.ownerProfile === options.profile)
  ) {
    return false;
  }
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

function encodeCatalogParts(parts: readonly string[]): string | undefined {
  if (!parts.every(isWellFormedUtf16)) return undefined;
  return parts.map((part) => encodeURIComponent(part)).join(":");
}

function canonicalCatalogRef(
  profilePath: string,
  encodedProject: string,
  uuid: string,
  sourcePath: string,
): string | undefined {
  const encoded = encodeCatalogParts([profilePath, encodedProject, uuid, sourcePath]);
  return encoded === undefined ? undefined : `claude-session:v2:${encoded}`;
}

/** Exact reference algorithm landed in PR #22. */
function legacyCatalogRef(
  profileIdentity: string,
  profilePath: string,
  encodedProject: string,
  uuid: string,
  sourcePath: string,
): string | undefined {
  const encoded = encodeCatalogParts([
    profileIdentity,
    profilePath,
    encodedProject,
    uuid,
    sourcePath,
  ]);
  return encoded === undefined ? undefined : `claude-session:v1:${encoded}`;
}

function compareVerifiedProfiles(a: VerifiedProfileRoot, b: VerifiedProfileRoot): number {
  return (
    compareText(a.ownerProfile, b.ownerProfile) ||
    compareText(a.profileIdentity, b.profileIdentity) ||
    compareText(a.profilePath, b.profilePath)
  );
}

/** Group every deterministic account representation by one canonical storage root. */
function verifiedStorageRoots(
  profiles: readonly Profile[],
  managedRoot: string,
  defaultRoot: string,
  onSkip?: ClaudeSessionCatalogOptions["onSkip"],
): VerifiedStorageRoot[] {
  const orderedProfiles = [...profiles].sort(
    (a, b) =>
      compareText(a.tool, b.tool) ||
      compareText(a.name, b.name) ||
      compareText(a.dir, b.dir) ||
      compareText(a.identity ?? "", b.identity ?? "") ||
      compareText(a.createdAt, b.createdAt),
  );
  const roots = new Map<string, VerifiedStorageRoot>();
  const representationRefs = new Map<string, Set<string>>();

  for (const profile of orderedProfiles) {
    const verified = verifyProfileRoot(profile, managedRoot, defaultRoot, onSkip);
    if (!verified) continue;
    const representationRef = encodeCatalogParts([
      verified.ownerProfile,
      verified.profileIdentity,
      verified.profilePath,
    ]);
    if (!representationRef) {
      onSkip?.({ path: verified.profilePath, reason: "invalid-source-identity" });
      continue;
    }

    const rootKey = comparablePath(verified.profilePath);
    const existing = roots.get(rootKey);
    if (!existing) {
      roots.set(rootKey, {
        dir: verified.dir,
        profilePath: verified.profilePath,
        snapshot: verified.snapshot,
        representations: [verified],
      });
      representationRefs.set(rootKey, new Set([representationRef]));
      continue;
    }

    const refs = representationRefs.get(rootKey)!;
    if (!refs.has(representationRef)) {
      refs.add(representationRef);
      existing.representations.push(verified);
    }
  }

  return [...roots.values()]
    .map((root) => ({
      ...root,
      representations: root.representations.sort(compareVerifiedProfiles),
    }))
    .sort((a, b) => compareText(a.profilePath, b.profilePath));
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
  const storageRoots = verifiedStorageRoots(
    profiles,
    managedRoot,
    defaultRoot,
    options.onSkip,
  );

  for (const verified of storageRoots) {
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
        const reference = canonicalCatalogRef(
          verified.profilePath,
          encodedProject,
          uuid,
          sourcePath,
        );
        if (!reference) {
          options.onSkip?.({ path: candidatePath, reason: "invalid-source-identity" });
          continue;
        }
        const representations: ClaudeSessionProfileRepresentation[] = [];
        let invalidRepresentation = false;
        for (const represented of verified.representations) {
          const alias = legacyCatalogRef(
            represented.profileIdentity,
            verified.profilePath,
            encodedProject,
            uuid,
            sourcePath,
          );
          if (!alias) {
            invalidRepresentation = true;
            break;
          }
          representations.push({
            ownerProfile: represented.ownerProfile,
            profileIdentity: represented.profileIdentity,
            profilePath: verified.profilePath,
            catalogRefAlias: alias,
          });
        }
        if (invalidRepresentation || representations.length === 0) {
          options.onSkip?.({ path: candidatePath, reason: "invalid-source-identity" });
          continue;
        }
        const primary = representations[0]!;
        const catalogRefAliases = [
          ...new Set(representations.map((representation) => representation.catalogRefAlias)),
        ].sort(compareText);
        const entry: ClaudeSessionCatalogEntry = {
          identity: {
            ownerProfile: primary.ownerProfile,
            profileIdentity: primary.profileIdentity,
            profilePath: verified.profilePath,
            encodedProject,
            projectIdentity,
            uuid,
            sourcePath,
          },
          storageIdentity: {
            profilePath: verified.profilePath,
            encodedProject,
            uuid,
            sourcePath,
          },
          catalogRef: reference,
          catalogRefAliases,
          representations,
          ownerProfile: primary.ownerProfile,
          profileIdentity: primary.profileIdentity,
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
      compareText(a.catalogRef, b.catalogRef) ||
      compareText(a.sourcePath, b.sourcePath),
  );
}
