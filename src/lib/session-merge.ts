import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  type Stats,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { AccountsError, type Profile, type ToolDef } from "../types.js";
import { loadStore, profilesDir } from "../storage.js";
import { getTool } from "./tools.js";
import { writeFileAtomic } from "./safe-path.js";
import { ensureSharedCapabilities, sharedHomeFor } from "./shared-capabilities.js";
import { withApplyLock } from "./apply-lock.js";

/**
 * Sessions are the one capability that cannot simply be linked.
 *
 * `ensureSharedCapabilities` refuses to replace a real directory a profile owns
 * — that guard is what stops a link from swallowing real data — and every
 * profile that predates session sharing already owns a real, populated
 * `projects/` and `history.jsonl`. Declaring them as shared entries therefore
 * does nothing at all while still reporting success. The contents have to be
 * unioned into the shared home first; only then is the profile's path free to
 * become a link.
 *
 * The union is made with `link(2)`, not by copying:
 *
 *  - it is atomic and reads no bytes, so a transcript that is being appended to
 *    right now cannot be captured half-written — the shared directory gets the
 *    same inode and therefore the whole file, including everything written after
 *    the merge;
 *  - a re-run is a no-op by construction: the second attempt fails `EEXIST`, and
 *    an inode comparison distinguishes "already merged" from a real collision;
 *  - it preserves mtimes, which the tool's own 30-day cleanup depends on — a
 *    copy that reset them would make the whole corpus look fresh and stop it
 *    ever being pruned;
 *  - and it costs no disk, so the migration is seconds rather than gigabytes.
 *
 * A copy is the fallback for a source on another filesystem, and it is the only
 * path that has to reason about torn reads.
 *
 * Nothing is ever deleted. A source file is only read; a profile's own tree is
 * renamed aside before its path becomes a link, and the link is verified to
 * resolve to a non-empty corpus before the migration of that profile is allowed
 * to stand.
 */

/** A file whose mtime is younger than this may still be growing. */
export const DEFAULT_ACTIVE_WINDOW_MS = 60_000;

/** Guards against a symlink loop or a pathological tree; real depth is ~6. */
const MAX_WALK_DEPTH = 32;

/** Retained originals are kept indefinitely; hardlinks make them cost nothing. */
const RETAINED_DIR = ".accounts-session-migration";

export type SessionLinkState =
  /** The swap failed and the original could NOT be put back. */
  | "restore-failed"
  /** Newly pointed at the shared home; the original is under `retainedAt`. */
  | "linked"
  /** Already resolved to the shared home before this run. */
  | "already-linked"
  /** `--dry-run`: nothing was written. */
  | "dry-run"
  /** Linking was not requested. */
  | "not-requested"
  /** The dir is not in the registry, so nothing would maintain the link. */
  | "skipped-unregistered"
  /** Merge left something unaccounted for; linking would risk hiding it. */
  | "skipped-unverified"
  /** The swap failed and the original was put back. */
  | "rolled-back"
  | "error";

export interface SessionMergeSourceReport {
  profile: string;
  dir: string;
  /** Whether Accounts knows about this dir; only registered dirs are linked. */
  registered: boolean;
  /** Recursive transcript (`*.jsonl`) count under the profile's own tree. */
  transcriptsBefore: number;
  transcriptsAfter: number;
  /** Files the shared home did not have, now present. */
  merged: number;
  /** How many of those were regular `.jsonl` transcripts (what the floor counts). */
  mergedTranscripts: number;
  /** How many of those were placed with `link(2)`. */
  hardlinked: number;
  /** How many had to be copied byte-for-byte (a source on another filesystem). */
  copied: number;
  /** Files already present as the very same inode — nothing to do. */
  alreadyMerged: number;
  /** Files already present with identical bytes but a different inode. */
  identical: number;
  /** Shared copies replaced by a proven strict superset of themselves. */
  extended: number;
  /** Files whose bytes the shared copy already fully contains. */
  contained: number;
  /** Different bytes, neither containing the other; both copies are kept. */
  divergent: number;
  /** Shared-home paths written for divergent files, for the operator to inspect. */
  divergentPaths: string[];
  /** Files left for a later run because they were moving under the read. */
  deferredActive: number;
  /** Files that disappeared between being listed and being placed. */
  vanished: number;
  /** Files neither merged nor deliberately deferred — blocks linking. */
  unaccounted: number;
  historyRecords: number;
  linkState: SessionLinkState;
  /** Where the profile's original tree was moved before it became a link. */
  retainedAt?: string;
  errors: string[];
}

export interface SessionMergeHistoryReport {
  target: string;
  recordsBefore: number;
  recordsAfter: number;
  /** Lines kept verbatim because they did not parse as JSON. */
  unparsedPreserved: number;
  /** True when the merged file is in ascending timestamp order. */
  ascending: boolean;
  /** False when the shared file exists but could not be read — never rewritten. */
  readable: boolean;
}

export interface SessionMergeReport {
  tool: string;
  dryRun: boolean;
  /** Counts are bounds, not exact: a dry run places nothing (see `dryRun`). */
  approximate: boolean;
  sharedHome: string;
  sharedTranscriptsBefore: number;
  sharedTranscriptsAfter: number;
  totalTranscriptsBefore: number;
  totalTranscriptsAfter: number;
  sources: SessionMergeSourceReport[];
  history: SessionMergeHistoryReport;
  verification: { assertion: string; passed: boolean; detail?: string };
  errors: string[];
}

export interface SessionMergeOptions {
  toolId?: string;
  /** Merge only this source, by registry name or directory basename. */
  profile?: string;
  dryRun?: boolean;
  /** Replace migrated profile entries with links. Default true. */
  link?: boolean;
  activeWindowMs?: number;
  /** Test seam for the "still being written" window. */
  now?: number;
  /**
   * Extra read-only trees to merge in, such as a backup taken before the
   * migration. Transcripts deleted from the live tree since the backup exist
   * only there, so without this the merge cannot restore them. Never linked,
   * never written to.
   */
  from?: readonly string[];
  /**
   * Profiles considered registered, and therefore eligible to be linked.
   *
   * Defaults to the on-box registry file, but this machine can be pointed at a
   * self-hosted registry, in which case the on-box file is empty and every
   * profile would be treated as unregistered — silently linking nothing. The
   * caller resolves the store it actually uses and passes it in.
   */
  profiles?: readonly Profile[];
  /** Test seam: fires before an existing shared file is replaced. */
  onBeforeSwap?: () => void;
  /** Test seam: fires after every source has been merged, before verification. */
  onAfterMerge?: () => void;
  /** Test seam: fires after verification, before the link loop. */
  onBeforeLink?: () => void;
  /** Test seam: fires after the link loop, before the post-link census. */
  onAfterLink?: () => void;
  /** Test seam: fires when a failed swap starts restoring the original. */
  onRollback?: () => void;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function errorCode(err: unknown): string {
  return err && typeof err === "object" && "code" in err ? String((err as { code?: unknown }).code) : "";
}

function lstatIfExists(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function realpathIfExists(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    return undefined;
  }
}

function sha256(contents: Uint8Array): string {
  return createHash("sha256").update(contents).digest("hex");
}

/**
 * A path ending in a separator is the shape that makes `rm -rf`, `find -delete`
 * and `rsync --delete` traverse a symlink instead of removing it — the measured
 * way one careless argument wipes the shared corpus for every profile. Nothing
 * here needs a trailing separator, so it is refused rather than normalised.
 */
export function assertNoTrailingSeparator(path: string, label: string): void {
  if (path.length > 1 && (path.endsWith("/") || path.endsWith(sep))) {
    throw new AccountsError(`${label} must not end with a path separator: ${path}`);
  }
}

// --- walking ----------------------------------------------------------------

interface WalkedFile {
  rel: string;
  stat: Stats;
  /**
   * Claude Code creates symlinks INSIDE the session tree for forked and resumed
   * subagent transcripts. Discarding them made every profile that had one
   * permanently ineligible for linking, so they are carried through the merge
   * and reproduced in the shared corpus.
   */
  kind: "file" | "symlink";
}

/**
 * Every regular file under `root` at any depth, keyed by its path relative to
 * `root`. Only a minority of transcripts sit at the top level — subagent and
 * workflow transcripts are nested several directories deeper — and the relative
 * path is the only safe key: `journal.jsonl` alone occurs at hundreds of
 * distinct paths, so keying on a file name would collapse unrelated files.
 *
 * Symlinked entries are reported rather than followed: a session tree is data,
 * and following a link out of it would merge something nobody put there.
 */
function walkFiles(root: string, onSkip: (rel: string, reason: string) => void): WalkedFile[] {
  const files: WalkedFile[] = [];
  const visit = (dir: string, rel: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) {
      onSkip(rel, "directory nesting exceeds the walk depth limit");
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      onSkip(rel, `could not list directory (${message(err)})`);
      return;
    }
    for (const entry of entries) {
      const childRel = rel ? join(rel, entry.name) : entry.name;
      const child = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        const stat = lstatIfExists(child);
        if (!stat) {
          onSkip(childRel, "disappeared while listing");
          continue;
        }
        files.push({ rel: childRel, stat, kind: "symlink" });
        continue;
      }
      if (entry.isDirectory()) {
        visit(child, childRel, depth + 1);
        continue;
      }
      if (!entry.isFile()) {
        onSkip(childRel, "not a regular file");
        continue;
      }
      const stat = lstatIfExists(child);
      if (!stat) {
        onSkip(childRel, "disappeared while listing");
        continue;
      }
      files.push({ rel: childRel, stat, kind: "file" });
    }
  };
  if (existsSync(root)) visit(root, "", 0);
  return files.sort((a, b) => a.rel.localeCompare(b.rel));
}

/**
 * Recursive, because transcripts are nested. A top-level `readdir` of
 * `projects/` counts encoded-cwd directories, so every transcript inside them
 * could be lost without the number moving.
 */
export function countTranscripts(root: string): number {
  // Regular files only: a symlink inside the tree is another name for a
  // transcript that is already counted, so counting it would inflate the floor
  // that is meant to catch loss.
  return walkFiles(root, () => {}).filter((file) => file.kind === "file" && file.rel.endsWith(".jsonl")).length;
}

// --- placing one file -------------------------------------------------------

type FileOutcome =
  | "merged"
  | "alreadyMerged"
  | "identical"
  | "extended"
  | "contained"
  | "divergent"
  | "deferred"
  | "vanished"
  | "unaccounted";

interface FileResult {
  outcome: FileOutcome;
  hardlinked?: boolean;
  copied?: boolean;
  divergentPath?: string;
  error?: string;
}

/** True when `prefix` is a strict byte prefix of `whole`. */
export function isStrictPrefix(prefix: Uint8Array, whole: Uint8Array): boolean {
  if (prefix.byteLength >= whole.byteLength) return false;
  return Buffer.from(whole.buffer, whole.byteOffset, prefix.byteLength).equals(Buffer.from(prefix));
}

function sanitizeForFilename(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned.length > 0 ? cleaned.slice(0, 48) : "profile";
}

/**
 * Where a same-path-but-different file is kept. Derived only from the owning
 * source and the content hash, so a re-run recomputes the same path and finds
 * its own previous copy instead of making another one.
 */
export function divergentCopyPath(targetPath: string, profile: string, contentHash: string): string {
  const name = basename(targetPath);
  const ext = extname(name);
  const stem = ext ? name.slice(0, -ext.length) : name;
  const suffix = `.from-${sanitizeForFilename(profile)}.${contentHash.slice(0, 12)}${ext}`;
  // POSIX caps a single name at 255 bytes; keep the discriminating suffix and
  // trim the stem, which is the part already duplicated by the target.
  const room = Math.max(1, 255 - Buffer.byteLength(suffix));
  return join(dirname(targetPath), `${stem.slice(0, room)}${suffix}`);
}

function sameInode(a: Stats | undefined, b: Stats | undefined): boolean {
  return a !== undefined && b !== undefined && a.dev === b.dev && a.ino === b.ino;
}

/**
 * Read a file only if it is not moving under us, and never accept a JSONL body
 * that does not end in a newline: that is exactly what a copy of a file being
 * appended to produces, and Claude Code's next append concatenates onto the
 * partial line, corrupting the record silently. The hardlink path never gets
 * here — this is the fallback's problem alone.
 */
function readStable(
  path: string,
  stat: Stats,
  opts: { requireCompleteLine: boolean },
): { contents: Uint8Array } | { outcome: "deferred" | "vanished" } {
  let contents: Uint8Array;
  try {
    contents = readFileSync(path);
  } catch {
    return { outcome: existsSync(path) ? "deferred" : "vanished" };
  }
  const after = lstatIfExists(path);
  // Gone between the listing and the read. It cannot be merged, and calling it
  // "deferred" would promise a later run that will never find it.
  if (!after) return { outcome: "vanished" };
  if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) return { outcome: "deferred" };
  if (contents.byteLength !== stat.size) return { outcome: "deferred" };
  if (opts.requireCompleteLine && contents.byteLength > 0 && contents[contents.byteLength - 1] !== 0x0a) {
    return { outcome: "deferred" };
  }
  return { contents };
}

interface MergeFileContext {
  sourceRoot: string;
  targetRoot: string;
  profile: string;
  dryRun: boolean;
  cutoff: number;
  /** Test seam: fires immediately before an existing shared file is replaced. */
  onBeforeSwap?: () => void;
}

type PlaceResult = { placed: "hardlink" | "copy" } | { outcome: "deferred" | "vanished" } | { error: string };

/**
 * Put `source` at `destination` without reading it if at all possible. The
 * hardlink is atomic and shares the inode, so a file still being appended to
 * arrives whole rather than as a prefix of itself.
 */
function placeFile(ctx: MergeFileContext, file: WalkedFile, sourcePath: string, destination: string): PlaceResult {
  if (ctx.dryRun) return { placed: "hardlink" };
  try {
    mkdirSync(dirname(destination), { recursive: true });
  } catch (err) {
    return { error: message(err) };
  }
  try {
    linkSync(sourcePath, destination);
    return { placed: "hardlink" };
  } catch (err) {
    const code = errorCode(err);
    if (code === "ENOENT") return { outcome: "vanished" };
    // Only a cross-device, cross-mount or link-count limit justifies a copy;
    // anything else is a real failure and must not be papered over.
    if (code !== "EXDEV" && code !== "EPERM" && code !== "EMLINK" && code !== "EOPNOTSUPP") {
      return { error: message(err) };
    }
  }
  const read = readStable(sourcePath, file.stat, { requireCompleteLine: destination.endsWith(".jsonl") });
  if ("outcome" in read) return { outcome: read.outcome };
  try {
    writeFileAtomic(destination, read.contents, {
      mode: (file.stat.mode & 0o777) || 0o600,
      mustStayUnder: ctx.targetRoot,
    });
    // Preserve mtime: the tool prunes sessions older than 30 days, so a copy
    // that reset it would make the whole corpus look fresh and never prune.
    utimesSync(destination, file.stat.atime, file.stat.mtime);
    return { placed: "copy" };
  } catch (err) {
    return { error: message(err) };
  }
}

function outcomeFor(result: PlaceResult, outcome: FileOutcome, rel: string): FileResult {
  if ("error" in result) return { outcome: "unaccounted", error: `${rel}: ${result.error}` };
  if ("outcome" in result) return { outcome: result.outcome };
  return { outcome, hardlinked: result.placed === "hardlink", copied: result.placed === "copy" };
}

/** True when `candidate` is `root` itself or sits underneath it. */
function isInside(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * Reproduce a symlink that Claude Code created inside the session tree.
 *
 * The link is only reproduced when it points back into the same tree, and it is
 * rewritten relative to its own directory so the shared corpus stays portable —
 * an absolute path into one profile's directory would break the moment another
 * profile read it. A link out of the tree is refused: following it would merge
 * something nobody put in the corpus, and silently dropping it would leave the
 * profile permanently unlinkable with no explanation.
 */
function mergeSymlink(ctx: MergeFileContext, file: WalkedFile, sourcePath: string, targetPath: string): FileResult {
  let raw: string;
  try {
    raw = readlinkSync(sourcePath);
  } catch (err) {
    return { outcome: "unaccounted", error: `${file.rel}: could not read the symbolic link (${message(err)})` };
  }
  const absolute = resolve(dirname(sourcePath), raw);
  // In-tree by path, or in-tree by resolution: a retained tree's links still
  // name the profile's own `projects/`, which by then IS the shared corpus.
  let inTree: string | undefined;
  if (isInside(absolute, ctx.sourceRoot)) {
    inTree = relative(ctx.sourceRoot, absolute);
  } else {
    const realRoot = realpathIfExists(ctx.targetRoot);
    const realAbsolute = realpathIfExists(absolute);
    if (realRoot && realAbsolute && isInside(realAbsolute, realRoot)) inTree = relative(realRoot, realAbsolute);
  }
  if (inTree === undefined) {
    return {
      outcome: "unaccounted",
      error:
        `${file.rel}: symbolic link points outside the session tree (${raw}); ` +
        "it is not reproduced in the shared corpus — move or remove it, then merge again",
    };
  }
  const desired = relative(dirname(targetPath), join(ctx.targetRoot, inTree));
  const existing = lstatIfExists(targetPath);
  if (existing) {
    if (!existing.isSymbolicLink()) {
      return { outcome: "unaccounted", error: `${file.rel}: a regular entry occupies the path this link needs` };
    }
    let current: string;
    try {
      current = readlinkSync(targetPath);
    } catch (err) {
      return { outcome: "unaccounted", error: `${file.rel}: could not read the shared link (${message(err)})` };
    }
    if (current === desired) return { outcome: "alreadyMerged" };
    return { outcome: "unaccounted", error: `${file.rel}: shared link points at ${current}, not ${desired}` };
  }
  if (ctx.dryRun) return { outcome: "merged" };
  try {
    mkdirSync(dirname(targetPath), { recursive: true });
    symlinkSync(desired, targetPath);
    return { outcome: "merged" };
  } catch (err) {
    return { outcome: "unaccounted", error: `${file.rel}: could not reproduce the symbolic link (${message(err)})` };
  }
}

function mergeFile(ctx: MergeFileContext, file: WalkedFile): FileResult {
  const sourcePath = join(ctx.sourceRoot, file.rel);
  const targetPath = join(ctx.targetRoot, file.rel);
  if (file.kind === "symlink") return mergeSymlink(ctx, file, sourcePath, targetPath);
  const targetStat = lstatIfExists(targetPath);

  if (targetStat?.isSymbolicLink()) {
    return { outcome: "unaccounted", error: `${file.rel}: target path is a symbolic link` };
  }
  if (targetStat && !targetStat.isFile()) {
    return { outcome: "unaccounted", error: `${file.rel}: target path exists and is not a regular file` };
  }

  if (!targetStat) {
    return outcomeFor(placeFile(ctx, file, sourcePath, targetPath), "merged", file.rel);
  }

  // The cheap answer first, and the one that makes a re-run free: the same
  // inode means this exact file was merged by an earlier run.
  if (sameInode(file.stat, targetStat)) return { outcome: "alreadyMerged" };

  const read = readStable(sourcePath, file.stat, { requireCompleteLine: false });
  if ("outcome" in read) return { outcome: read.outcome };
  const contents = read.contents;

  let existing: Uint8Array;
  try {
    existing = readFileSync(targetPath);
  } catch (err) {
    return { outcome: "unaccounted", error: `${file.rel}: could not read the shared copy (${message(err)})` };
  }
  if (existing.byteLength === contents.byteLength && sha256(existing) === sha256(contents)) {
    return { outcome: "identical" };
  }

  // Transcripts are append-only, so the usual difference between two copies of
  // one session is that one has more of it. That is only ever acted on when the
  // containment is proved byte for byte on these exact two files — never
  // assumed from their lengths or from the shape of the data.
  if (isStrictPrefix(contents, existing)) return { outcome: "contained" };
  if (isStrictPrefix(existing, contents)) {
    // Replacing the shared copy with a proven strict superset of itself cannot
    // lose a byte — but only while the bytes the proof was taken from are still
    // the bytes on disk.
    if (targetStat.mtimeMs > ctx.cutoff) return { outcome: "deferred" };
    const current = lstatIfExists(targetPath);
    if (!current || current.size !== targetStat.size || current.mtimeMs !== targetStat.mtimeMs) {
      return { outcome: "deferred" };
    }
    return outcomeFor(replaceAtomically(ctx, file, sourcePath, targetPath, existing), "extended", file.rel);
  }

  // Neither contains the other: two genuinely forked histories at one path.
  // Both are real, neither is authoritative, and the shared copy is never
  // overwritten — so the other one is kept beside it under a name derived from
  // its own content.
  const divergentPath = divergentCopyPath(targetPath, ctx.profile, sha256(contents));
  const divergentStat = lstatIfExists(divergentPath);
  if (divergentStat) {
    if (!divergentStat.isFile()) {
      return { outcome: "unaccounted", error: `${file.rel}: divergent copy path is not a regular file` };
    }
    if (sameInode(file.stat, divergentStat)) return { outcome: "divergent", divergentPath };
    try {
      if (
        divergentStat.size === contents.byteLength &&
        sha256(readFileSync(divergentPath)) === sha256(contents)
      ) {
        return { outcome: "divergent", divergentPath };
      }
    } catch {
      // fall through and place it again
    }
    return { outcome: "unaccounted", error: `${file.rel}: divergent copy path is taken by different content` };
  }
  const result = outcomeFor(placeFile(ctx, file, sourcePath, divergentPath), "divergent", file.rel);
  return result.outcome === "divergent" ? { ...result, divergentPath } : result;
}

/**
 * Replace an existing entry with the source, atomically. A temporary hardlink
 * renamed over the target swaps the directory entry in one step, so a reader
 * sees the old file or the new one and never a gap — and any other name that
 * pointed at the old inode keeps it.
 */
/** Read exactly the first `length` bytes of a path, or fewer if it is shorter. */
function readPrefixBytes(path: string, length: number): Uint8Array | undefined {
  if (length === 0) return new Uint8Array(0);
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const buffer = Buffer.alloc(length);
    const read = readSync(fd, buffer, 0, length, 0);
    return buffer.subarray(0, read);
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Replace an existing entry with the source, atomically, and only after
 * re-proving on the exact inode about to be published that it still begins with
 * the bytes the shared copy holds.
 *
 * Re-stating the source's stat is not enough. The prefix was proved on bytes
 * read from one inode; `mv`, `cp`, an editor, `rsync` (temp-plus-rename by
 * default) or a restore puts a DIFFERENT inode at that path, and linking that
 * one into place publishes content nothing ever proved to contain the shared
 * copy — silently replacing a whole transcript with an unrelated file while
 * reporting `extended`. An append is safe precisely because it keeps the inode
 * and only adds, which is what this re-proof accepts and a stat comparison
 * would reject.
 */
function replaceAtomically(
  ctx: MergeFileContext,
  file: WalkedFile,
  sourcePath: string,
  targetPath: string,
  provenPrefix: Uint8Array,
): PlaceResult {
  if (ctx.dryRun) return { placed: "hardlink" };
  ctx.onBeforeSwap?.();
  const temp = `${targetPath}.${process.pid}.${randomUUID()}.tmp`;
  try {
    linkSync(sourcePath, temp);
  } catch (err) {
    const code = errorCode(err);
    if (code === "ENOENT") return { outcome: "vanished" };
    if (code !== "EXDEV" && code !== "EPERM" && code !== "EMLINK" && code !== "EOPNOTSUPP") {
      return { error: message(err) };
    }
    return placeFileByCopyOver(ctx, file, sourcePath, targetPath, provenPrefix);
  }
  const actual = readPrefixBytes(temp, provenPrefix.byteLength);
  if (!actual || actual.byteLength !== provenPrefix.byteLength || !Buffer.from(actual).equals(Buffer.from(provenPrefix))) {
    rmSync(temp, { force: true });
    return { outcome: "deferred" };
  }
  try {
    renameSync(temp, targetPath);
    return { placed: "hardlink" };
  } catch (err) {
    rmSync(temp, { force: true });
    return { error: message(err) };
  }
}

function placeFileByCopyOver(
  ctx: MergeFileContext,
  file: WalkedFile,
  sourcePath: string,
  targetPath: string,
  provenPrefix?: Uint8Array,
): PlaceResult {
  const read = readStable(sourcePath, file.stat, { requireCompleteLine: targetPath.endsWith(".jsonl") });
  if ("outcome" in read) return { outcome: read.outcome };
  if (provenPrefix) {
    // Same re-proof as the hardlink path: these are freshly read bytes, and
    // they must still contain what the shared copy holds.
    const head = read.contents.subarray(0, provenPrefix.byteLength);
    if (head.byteLength !== provenPrefix.byteLength || !Buffer.from(head).equals(Buffer.from(provenPrefix))) {
      return { outcome: "deferred" };
    }
  }
  try {
    writeFileAtomic(targetPath, read.contents, {
      mode: (file.stat.mode & 0o777) || 0o600,
      mustStayUnder: ctx.targetRoot,
    });
    utimesSync(targetPath, file.stat.atime, file.stat.mtime);
    return { placed: "copy" };
  } catch (err) {
    return { error: message(err) };
  }
}

// --- history ----------------------------------------------------------------

/** Deterministic key for a record, so equal records collapse and others do not. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function timestampOf(value: unknown): number {
  if (!value || typeof value !== "object") return Number.POSITIVE_INFINITY;
  const raw = (value as Record<string, unknown>).timestamp;
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string") {
    const parsed = Date.parse(raw);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return Number.POSITIVE_INFINITY;
}

interface HistoryRecord {
  line: string;
  timestamp: number;
  order: number;
}

type HistoryRead = { state: "ok"; lines: string[] } | { state: "unreadable"; reason: string };

/**
 * "Absent" and "unreadable" must never give the same answer. Swallowing a read
 * error into an empty list makes the merge believe the file held nothing, write
 * a document built from the other sources over it, and — because the same
 * failed read also supplies `recordsBefore` — pass a "records never decreased"
 * check that could not have failed. One transient EACCES or EMFILE during a
 * fourteen-thousand-file run would destroy the whole prompt history.
 */
function readHistory(path: string): HistoryRead {
  if (!existsSync(path)) return { state: "ok", lines: [] };
  try {
    return { state: "ok", lines: readFileSync(path, "utf8").split("\n").filter((line) => line.trim().length > 0) };
  } catch (err) {
    return { state: "unreadable", reason: message(err) };
  }
}

/**
 * Union of every source's records, deduped and sorted ascending by timestamp —
 * the order the file is already in and the one the tool navigates by, so a
 * plain concatenation would break it.
 *
 * Records are deduped on their whole content rather than on
 * `(timestamp, sessionId, display)`: the triple is unique across the measured
 * corpus, so the two agree today, and whole-content keying is the one that
 * cannot silently drop a record that differs only in a field outside the
 * triple. A line that does not parse is not evidence of nothing — it is kept
 * verbatim, keyed by its own text, and sorted to the end where it cannot
 * displace a real record.
 */
export function unionHistory(sources: string[][]): { lines: string[]; unparsed: number } {
  const seen = new Map<string, HistoryRecord>();
  let order = 0;
  let unparsed = 0;
  for (const lines of sources) {
    for (const line of lines) {
      let key: string;
      let timestamp: number;
      try {
        const parsed: unknown = JSON.parse(line);
        key = canonicalize(parsed);
        timestamp = timestampOf(parsed);
      } catch {
        key = `raw:${line}`;
        timestamp = Number.POSITIVE_INFINITY;
        if (!seen.has(key)) unparsed += 1;
      }
      if (seen.has(key)) continue;
      seen.set(key, { line, timestamp, order: order++ });
    }
  }
  const records = [...seen.values()].sort((a, b) =>
    a.timestamp === b.timestamp ? a.order - b.order : a.timestamp - b.timestamp,
  );
  return { lines: records.map((record) => record.line), unparsed };
}

function isAscending(lines: readonly string[]): boolean {
  let previous = Number.NEGATIVE_INFINITY;
  for (const line of lines) {
    let timestamp: number;
    try {
      timestamp = timestampOf(JSON.parse(line));
    } catch {
      timestamp = Number.POSITIVE_INFINITY;
    }
    if (timestamp < previous) return false;
    previous = timestamp;
  }
  return true;
}

// --- sources ----------------------------------------------------------------

export interface MergeSource {
  profile: string;
  dir: string;
  registered: boolean;
}

/**
 * Every profile directory on the machine, not just the registered ones: a dir
 * Accounts has forgotten still holds real transcripts — measured, thousands of
 * them — and "no session gets lost" has to cover them. Only registered dirs are
 * ever linked, because only registered dirs are visited by the launch-time
 * repair that keeps a link pointing at the right place.
 */
export function discoverSessionSources(tool: ToolDef, profiles: readonly Profile[]): MergeSource[] {
  const byRealPath = new Map<string, MergeSource>();
  const add = (source: MergeSource): void => {
    const key = realpathIfExists(source.dir) ?? resolve(source.dir);
    const existing = byRealPath.get(key);
    if (existing) {
      if (source.registered) existing.registered = true;
      return;
    }
    byRealPath.set(key, source);
  };

  for (const profile of profiles) {
    if (profile.tool !== tool.id) continue;
    if (!existsSync(profile.dir)) continue;
    add({ profile: profile.name, dir: resolve(profile.dir), registered: true });
  }

  const root = join(profilesDir(), tool.id);
  let entries: string[] = [];
  try {
    entries = readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
      .map((entry) => entry.name);
  } catch {
    entries = [];
  }
  for (const name of entries) add({ profile: name, dir: join(root, name), registered: false });

  return [...byRealPath.values()].sort((a, b) => a.profile.localeCompare(b.profile));
}

/** How deep under a `--from` root a profile-shaped directory is looked for. */
const MAX_EXTRA_SOURCE_DEPTH = 3;

/**
 * Find the profile-shaped directories under an arbitrary root, so the operator
 * can point `--from` at a whole backup rather than at each directory inside it.
 * A directory qualifies once it holds the tool's session entries; the search
 * does not descend into one, so a transcript tree is never mistaken for a
 * profile.
 */
export function discoverExtraSources(root: string, tool: ToolDef): MergeSource[] {
  const sessions = tool.sessions;
  if (!sessions) return [];
  const found: MergeSource[] = [];
  const visit = (dir: string, rel: string, depth: number): void => {
    if (existsSync(join(dir, sessions.transcripts)) || existsSync(join(dir, sessions.history))) {
      found.push({ profile: rel === "" ? basename(dir) : rel, dir, registered: false });
      return;
    }
    if (depth >= MAX_EXTRA_SOURCE_DEPTH) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      visit(join(dir, entry.name), rel ? `${rel}-${entry.name}` : entry.name, depth + 1);
    }
  };
  if (existsSync(root)) visit(resolve(root), "", 0);
  return found.sort((a, b) => a.profile.localeCompare(b.profile));
}

// --- linking ----------------------------------------------------------------

interface EntryLinkPlan {
  entry: string;
  alreadyLinked: boolean;
  nothingToDo: boolean;
}

function planEntryLink(profileDir: string, sharedHome: string, entry: string): EntryLinkPlan {
  const target = join(profileDir, entry);
  const source = join(sharedHome, entry);
  const stat = lstatIfExists(target);
  if (stat?.isSymbolicLink()) {
    const realTarget = realpathIfExists(target);
    const realSource = realpathIfExists(source);
    if (realTarget && realSource && realTarget === realSource) {
      return { entry, alreadyLinked: true, nothingToDo: false };
    }
  }
  if (!stat && !existsSync(source)) return { entry, alreadyLinked: false, nothingToDo: true };
  return { entry, alreadyLinked: false, nothingToDo: false };
}

/**
 * The link resolves to the shared entry AND that entry still holds the corpus.
 * "Not empty" is not the test: one surviving file passes it while the rest of
 * the corpus is gone, which is precisely the state this is meant to refuse.
 */
function linkIsGood(profileDir: string, sharedHome: string, entry: string, minimumTranscripts: number): boolean {
  const target = join(profileDir, entry);
  const source = join(sharedHome, entry);
  if (!lstatIfExists(target)?.isSymbolicLink()) return false;
  const realTarget = realpathIfExists(target);
  const realSource = realpathIfExists(source);
  if (!realTarget || !realSource || realTarget !== realSource) return false;
  let stat: Stats;
  try {
    stat = statSync(realTarget);
  } catch {
    return false;
  }
  // A link that resolves to an empty corpus is the failure this check exists for.
  if (stat.isDirectory()) return countTranscripts(realTarget) >= minimumTranscripts;
  return stat.size > 0;
}

/**
 * Free the profile's path and point it at the shared home, one entry at a time
 * and reversibly.
 *
 * The original is renamed aside, never removed. If the swap fails at any point
 * the rename is undone and the profile is left exactly as it was: the failure
 * mode this avoids is a profile left with no `projects/` at all, because the
 * tool then recreates it as a real directory, which `shareEntry` will correctly
 * refuse to replace and `doctor` reports only as a warning — a profile silently
 * de-shared forever.
 */
function linkSource(
  source: MergeSource,
  tool: ToolDef,
  sharedHome: string,
  stamp: string,
  opts: { cutoff: number; minimumTranscripts: number; onRollback?: () => void },
): { state: SessionLinkState; retainedAt?: string; errors: string[]; residueMerged?: number } {
  const sessions = tool.sessions!;
  const errors: string[] = [];
  const entries = [sessions.transcripts, sessions.history];
  const plans = entries.map((entry) => planEntryLink(source.dir, sharedHome, entry));
  const movable = plans.filter((plan) => !plan.alreadyLinked && !plan.nothingToDo);
  if (movable.length === 0) return { state: "already-linked", errors };

  const retainedAt = join(source.dir, RETAINED_DIR, stamp);
  const moved: { entry: string; from: string; to: string }[] = [];
  /**
   * Put everything back. Returns false if it could not, which must be reported
   * rather than swallowed: a live writer can recreate `projects/` inside the
   * swap window, and skipping the restore in silence leaves the real tree
   * stranded under the retained directory while the run says "rolled back".
   * "Rolled back" has to mean "left exactly as it was".
   */
  const rollback = (): boolean => {
    let restored = true;
    for (const item of moved) {
      try {
        const link = lstatIfExists(item.from);
        if (link?.isSymbolicLink()) unlinkSync(item.from);
        // The window a live writer actually races: the link is gone and the
        // original has not been renamed back yet.
        opts.onRollback?.();
        if (existsSync(item.from)) {
          restored = false;
          errors.push(
            `${item.entry}: could not restore the original — something else now occupies ${item.from}; ` +
              `the original is still at ${item.to} and must be moved back by hand`,
          );
          continue;
        }
        renameSync(item.to, item.from);
      } catch (err) {
        restored = false;
        errors.push(`${item.entry}: could not restore the original after a failed swap (${message(err)})`);
      }
    }
    return restored;
  };

  for (const plan of movable) {
    const from = join(source.dir, plan.entry);
    if (!lstatIfExists(from)) continue;
    const to = join(retainedAt, plan.entry);
    try {
      mkdirSync(retainedAt, { recursive: true });
      renameSync(from, to);
      moved.push({ entry: plan.entry, from, to });
    } catch (err) {
      errors.push(`${plan.entry}: could not retain the original (${message(err)})`);
      return { state: rollback() ? "rolled-back" : "restore-failed", errors };
    }
  }

  const result = ensureSharedCapabilities(source.dir, tool);
  errors.push(...result.errors);

  const failed = entries.filter((entry) => {
    const plan = plans.find((candidate) => candidate.entry === entry)!;
    if (plan.alreadyLinked) return false;
    if (plan.nothingToDo && !moved.some((item) => item.entry === entry)) return false;
    return !linkIsGood(source.dir, sharedHome, entry, opts.minimumTranscripts);
  });
  if (failed.length > 0) {
    errors.push(`${failed.join(", ")}: link did not resolve to the expected shared corpus`);
    return { state: rollback() ? "rolled-back" : "restore-failed", errors };
  }

  // Anything written to the profile's own tree between the walk and this rename
  // is now sitting under the retained directory, reachable from no profile at
  // all — and a clean re-run cannot find it, because the source is a link by
  // then. Merge the retained tree before declaring the swap good.
  let residueMerged = 0;
  if (moved.some((item) => item.entry === sessions.transcripts)) {
    const residue = mergeOneSource(
      { profile: `${source.profile}:retained`, dir: retainedAt, registered: false },
      tool,
      sharedHome,
      { dryRun: false, cutoff: opts.cutoff },
    );
    residueMerged = residue.report.merged;
    const stranded =
      residue.report.deferredActive + residue.report.vanished + residue.report.unaccounted + residue.report.errors.length;
    if (stranded > 0) {
      errors.push(
        `${sessions.transcripts}: ${stranded} entrie(s) written during the run could not be merged from ${retainedAt}`,
        ...residue.report.errors,
      );
      return { state: rollback() ? "rolled-back" : "restore-failed", errors, residueMerged };
    }
  }

  const newlyLinked = entries.filter(
    (entry) => result.linked.includes(entry) || result.repaired.includes(entry),
  );
  if (moved.length === 0 && newlyLinked.length === 0) return { state: "already-linked", errors, residueMerged };
  return { state: "linked", ...(moved.length > 0 ? { retainedAt } : {}), errors, residueMerged };
}

// --- entry point ------------------------------------------------------------

/**
 * Serialized against the other mutating Accounts operations. Two merges
 * interleaving in the rename window is exactly the condition that leaves a
 * profile with a recreated `projects/` and an unrestorable original.
 */
export function mergeClaudeSessions(options: SessionMergeOptions = {}): SessionMergeReport {
  return withApplyLock(() => runMerge(options));
}

function runMerge(options: SessionMergeOptions): SessionMergeReport {
  const tool = getTool(options.toolId ?? "claude");
  if (!tool.sessions) {
    throw new AccountsError(`tool "${tool.id}" does not declare where it stores sessions`);
  }
  const sharedHome = sharedHomeFor(tool);
  if (!existsSync(sharedHome)) throw new AccountsError(`shared home does not exist: ${sharedHome}`);
  const dryRun = options.dryRun ?? false;
  const link = options.link ?? true;
  const now = options.now ?? Date.now();
  const cutoff = now - (options.activeWindowMs ?? DEFAULT_ACTIVE_WINDOW_MS);

  const sharedRoot = join(sharedHome, tool.sessions.transcripts);
  const sharedHistoryPath = join(sharedHome, tool.sessions.history);

  const profiles = options.profiles ?? loadStore().profiles;
  let sources = discoverSessionSources(tool, profiles);
  for (const root of options.from ?? []) {
    assertNoTrailingSeparator(root, "--from");
    const extra = discoverExtraSources(root, tool);
    if (extra.length === 0) throw new AccountsError(`no ${tool.id} session directory found under ${root}`);
    // Prefixed so a backup's `account003` can never be confused with the live
    // `account003`, in the report or in a divergent copy's filename.
    sources = [...sources, ...extra.map((extraSource) => ({ ...extraSource, profile: `from:${extraSource.profile}` }))];
  }
  // Never treat the shared home as one of its own sources.
  const sharedReal = realpathIfExists(sharedHome) ?? resolve(sharedHome);
  sources = sources.filter((candidate) => (realpathIfExists(candidate.dir) ?? resolve(candidate.dir)) !== sharedReal);
  if (options.profile) {
    sources = sources.filter((candidate) => candidate.profile === options.profile);
    if (sources.length === 0) throw new AccountsError(`no ${tool.id} session source named "${options.profile}"`);
  }

  const report: SessionMergeReport = {
    tool: tool.id,
    dryRun,
    // A dry run places nothing, so each source is evaluated against a shared
    // tree that never received the earlier sources: two profiles holding the
    // same new path both count as `merged` where a real run would record one
    // merge and one collision. Merge counts are an upper bound and collision
    // counts a lower bound, and the report says so rather than implying
    // precision it cannot have.
    approximate: dryRun,
    sharedHome,
    sharedTranscriptsBefore: countTranscripts(sharedRoot),
    sharedTranscriptsAfter: 0,
    totalTranscriptsBefore: 0,
    totalTranscriptsAfter: 0,
    sources: [],
    history: {
      target: sharedHistoryPath,
      recordsBefore: 0,
      recordsAfter: 0,
      unparsedPreserved: 0,
      ascending: true,
      readable: true,
    },
    verification: { assertion: "", passed: false },
    errors: [],
  };

  const sharedHistory = readHistory(sharedHistoryPath);
  if (sharedHistory.state === "unreadable") {
    report.history.readable = false;
    report.errors.push(
      `${tool.sessions.history}: could not be read (${sharedHistory.reason}); ` +
        "refusing to rewrite it, because a document built from the other sources would replace whatever it still holds",
    );
  }
  const sharedHistoryBefore = sharedHistory.state === "ok" ? sharedHistory.lines : [];
  report.history.recordsBefore = sharedHistoryBefore.length;

  const historySources: string[][] = [sharedHistoryBefore];
  for (const source of sources) {
    const merged = mergeOneSource(source, tool, sharedHome, {
      dryRun,
      cutoff,
      ...(options.onBeforeSwap ? { onBeforeSwap: options.onBeforeSwap } : {}),
    });
    report.sources.push(merged.report);
    historySources.push(merged.historyLines);
  }
  options.onAfterMerge?.();

  const union = unionHistory(historySources);
  report.history.recordsAfter = union.lines.length;
  report.history.unparsedPreserved = union.unparsed;
  report.history.ascending = isAscending(union.lines);
  // Ordering matters as much as membership: the tool navigates history by its
  // ascending timestamps, so a same-length but out-of-order file still has to be
  // rewritten. Comparing the whole document keeps the re-run a no-op.
  const historyChanged = union.lines.join("\n") !== sharedHistoryBefore.join("\n");
  if (!dryRun && report.history.readable && historyChanged) {
    try {
      writeFileAtomic(sharedHistoryPath, union.lines.join("\n") + "\n", {
        mode: 0o600,
        mustStayUnder: sharedHome,
      });
    } catch (err) {
      report.errors.push(`${tool.sessions.history}: could not write the merged history (${message(err)})`);
    }
  }

  report.sharedTranscriptsAfter = countTranscripts(sharedRoot);
  report.totalTranscriptsBefore =
    report.sharedTranscriptsBefore + report.sources.reduce((sum, source) => sum + source.transcriptsBefore, 0);
  report.totalTranscriptsAfter =
    report.sharedTranscriptsAfter + report.sources.reduce((sum, source) => sum + source.transcriptsAfter, 0);

  // The floor is counted on the SHARED side only. Adding the sources back in
  // double-counts every hardlink — the same inode under two names — which gave
  // the check about a hundred per cent of slack: it could only fire once more
  // than half the corpus was gone. What has to hold is that the shared tree
  // grew by exactly the transcripts this run placed into it.
  // A dry run places nothing by definition, so holding it to a growth floor
  // would fail every time and report a loss that never happened.
  const expectedGrowth = dryRun ? 0 : report.sources.reduce((sum, source) => sum + source.mergedTranscripts, 0);
  const expectedShared = report.sharedTranscriptsBefore + expectedGrowth;
  const sharedHeld = report.sharedTranscriptsAfter >= expectedShared;
  const historyHeld = report.history.readable && report.history.recordsAfter >= report.history.recordsBefore;
  const passed = sharedHeld && historyHeld && report.history.ascending;
  const assertion =
    "the shared transcript count must be at least its count before the merge plus the transcripts this run placed, " +
    "the shared history must be readable and never lose records, and the merged history must be in ascending order";
  const detailFor = (extra?: string): string =>
    `shared ${report.sharedTranscriptsBefore} -> ${report.sharedTranscriptsAfter}, expected at least ${expectedShared} ` +
    `(${expectedGrowth} transcripts placed); history ${report.history.recordsBefore} -> ${report.history.recordsAfter}, ` +
    `readable=${report.history.readable}, ascending=${report.history.ascending}${extra ? `; ${extra}` : ""}`;
  report.verification = { assertion, passed, ...(passed ? {} : { detail: detailFor() }) };

  const stamp = new Date(now).toISOString().replace(/[:.]/g, "-");
  options.onBeforeLink?.();
  for (const source of report.sources) {
    if (dryRun) {
      source.linkState = "dry-run";
      continue;
    }
    if (!link) {
      source.linkState = "not-requested";
      continue;
    }
    if (!source.registered) {
      source.linkState = "skipped-unregistered";
      continue;
    }
    // A profile is only safe to link once everything under it is demonstrably
    // in the shared home. Anything deferred, vanished or unaccounted for would
    // otherwise end up behind the link with no signal that it was left behind.
    if (
      !report.verification.passed ||
      source.errors.length > 0 ||
      source.deferredActive > 0 ||
      source.vanished > 0 ||
      source.unaccounted > 0
    ) {
      source.linkState = "skipped-unverified";
      continue;
    }
    const descriptor = sources.find((candidate) => candidate.dir === source.dir)!;
    const linked = linkSource(descriptor, tool, sharedHome, stamp, {
      cutoff,
      minimumTranscripts: report.sharedTranscriptsAfter,
      ...(options.onRollback ? { onRollback: options.onRollback } : {}),
    });
    source.linkState = linked.state;
    if (linked.retainedAt) source.retainedAt = linked.retainedAt;
    if (linked.residueMerged) source.merged += linked.residueMerged;
    source.errors.push(...linked.errors);
  }
  options.onAfterLink?.();

  // The census above was taken BEFORE the destructive step, so on its own it
  // says nothing about what the link loop did. Re-count afterwards, or the only
  // part of the run that can destroy anything is the part nothing checks.
  if (!dryRun && link) {
    const afterLink = countTranscripts(sharedRoot);
    report.sharedTranscriptsAfter = afterLink;
    if (afterLink < expectedShared) {
      report.verification = {
        assertion,
        passed: false,
        detail: detailFor(`shared transcripts fell to ${afterLink} after linking`),
      };
    }
  }

  return report;
}

function mergeOneSource(
  source: MergeSource,
  tool: ToolDef,
  sharedHome: string,
  options: { dryRun: boolean; cutoff: number; onBeforeSwap?: () => void },
): { report: SessionMergeSourceReport; historyLines: string[] } {
  const sessions = tool.sessions!;
  const sourceRoot = join(source.dir, sessions.transcripts);
  const targetRoot = join(sharedHome, sessions.transcripts);
  const report: SessionMergeSourceReport = {
    profile: source.profile,
    dir: source.dir,
    registered: source.registered,
    transcriptsBefore: 0,
    transcriptsAfter: 0,
    merged: 0,
    mergedTranscripts: 0,
    hardlinked: 0,
    copied: 0,
    alreadyMerged: 0,
    identical: 0,
    extended: 0,
    contained: 0,
    divergent: 0,
    divergentPaths: [],
    deferredActive: 0,
    vanished: 0,
    unaccounted: 0,
    historyRecords: 0,
    linkState: "not-requested",
    errors: [],
  };

  const transcriptPlan = planEntryLink(source.dir, sharedHome, sessions.transcripts);
  const historyPlan = planEntryLink(source.dir, sharedHome, sessions.history);

  if (!transcriptPlan.alreadyLinked) {
    report.transcriptsBefore = countTranscripts(sourceRoot);
    const files = walkFiles(sourceRoot, (rel, reason) => {
      report.unaccounted += 1;
      report.errors.push(`${rel}: ${reason}`);
    });
    const ctx: MergeFileContext = {
      sourceRoot,
      targetRoot,
      profile: source.profile,
      dryRun: options.dryRun,
      cutoff: options.cutoff,
      ...(options.onBeforeSwap ? { onBeforeSwap: options.onBeforeSwap } : {}),
    };
    for (const file of files) {
      const result = mergeFile(ctx, file);
      if (result.error) report.errors.push(result.error);
      if (result.hardlinked) report.hardlinked += 1;
      if (result.copied) report.copied += 1;
      switch (result.outcome) {
        case "merged":
          report.merged += 1;
          if (file.kind === "file" && file.rel.endsWith(".jsonl")) report.mergedTranscripts += 1;
          break;
        case "alreadyMerged":
          report.alreadyMerged += 1;
          break;
        case "identical":
          report.identical += 1;
          break;
        case "extended":
          report.extended += 1;
          break;
        case "contained":
          report.contained += 1;
          break;
        case "divergent":
          report.divergent += 1;
          if (result.divergentPath) report.divergentPaths.push(result.divergentPath);
          break;
        case "deferred":
          report.deferredActive += 1;
          break;
        case "vanished":
          report.vanished += 1;
          report.errors.push(`${file.rel}: disappeared between being listed and being merged`);
          break;
        case "unaccounted":
          report.unaccounted += 1;
          break;
      }
    }
    report.transcriptsAfter = countTranscripts(sourceRoot);
  }

  let historyLines: string[] = [];
  if (!historyPlan.alreadyLinked) {
    const read = readHistory(join(source.dir, sessions.history));
    if (read.state === "unreadable") {
      // Not "this profile has no history". Merging on would silently drop it,
      // and linking would then hide the file behind a link to the shared one.
      report.errors.push(`${sessions.history}: could not be read (${read.reason})`);
    } else {
      historyLines = read.lines;
    }
  }
  report.historyRecords = historyLines.length;
  return { report, historyLines };
}
