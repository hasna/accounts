import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmdirSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { sharedClaudeSessionsDir } from "../storage.js";

/**
 * The shared Claude session registry (owner directive 2026-08-08).
 *
 * Claude Code discovers cross-session peers ONLY through
 * `$CLAUDE_CONFIG_DIR/sessions/<pid>.json`; the message transport underneath
 * (`/tmp/cc-socks/<pid>.sock`, 0600, same uid) is already machine-wide. With
 * per-profile `sessions/` directories, sessions running under different
 * account profiles cannot see each other even though they could talk —
 * measured on station01: copying one profile's `<pid>.json` into another
 * profile's `sessions/` made ListAgents show the peer and a native
 * SendMessage delivered cross-profile, and the exact `<pid>.json` filename is
 * required (a renamed copy is silently ignored).
 *
 * So this module makes every Claude profile's `sessions/` directory a SYMLINK
 * to one machine-level directory (`sharedClaudeSessionsDir()`), following the
 * same shape as the 0.2.38 single-inode credential broker: one real home,
 * per-profile pointers, an idempotent migration, and a doctor drift check
 * (the Claude binary owns `sessions/` and an update may recreate it as a real
 * directory, silently unsharing the machine).
 *
 * Why this is safe:
 * - Entries are pid-keyed, so concurrent writers can never collide at any N.
 * - Claude's stale-entry reaping is by pid-liveness, which is machine-scoped,
 *   so one profile's binary reaping another profile's dead entry is correct.
 * - Migration moves entries by rename(2) and then swaps the directory for a
 *   symlink, so a live session's registry path keeps resolving throughout —
 *   its next heartbeat simply lands in the shared directory.
 * - No credential or auth artifact is read or written here. Authentication
 *   stays the ONLY per-profile artifact (owner directive 2026-08-06); the one
 *   path this module touches is `<configDir>/sessions`.
 *
 * What deliberately did NOT change: per-dir liveness semantics. Guards that
 * ask "which live sessions are bound to THIS config dir" (switch guards, auth
 * heal, occupancy) go through `listDirLiveSessions`, which attributes shared
 * entries back to their owning config dir — see `claude-layout.ts`.
 *
 * MACHINE BOUNDARY: the shared directory must never leave the machine — pids
 * and `/tmp` socket paths are meaningless off-box. See
 * `sharedClaudeSessionsDir()` in `storage.ts`.
 */

export type SessionsDirKind =
  /** No `sessions` path at all (a profile that has never run a session). */
  | "missing"
  /** A symlink resolving to the machine-shared registry — the target state. */
  | "shared-link"
  /** A symlink resolving somewhere else. */
  | "foreign-link"
  /** A real per-profile directory — the pre-migration (or de-migrated) state. */
  | "real-dir"
  /** Something else entirely (a regular file, an unreadable link). */
  | "unexpected";

export interface SessionsDirState {
  kind: SessionsDirKind;
  /** The profile's `sessions` path (not resolved). */
  path: string;
  /** For links: the resolved target. */
  target?: string;
}

export interface EnsureSessionsResult {
  outcome:
    /** Nothing existed; the symlink was created. */
    | "linked"
    /** Already the shared link; nothing to do. */
    | "already-linked"
    /** A real directory was drained into the shared dir and replaced by the link. */
    | "migrated"
    /** A foreign symlink was replaced by the shared link. */
    | "repointed"
    /** Refused without mutating anything; `reason` says why. */
    | "blocked"
    /** The config dir itself does not exist. */
    | "no-config-dir";
  changed: boolean;
  /** Registry filenames moved into the shared dir. */
  moved: string[];
  /** Filenames that existed on both sides; the newest copy was kept. */
  deduped: string[];
  reason?: string;
}

/**
 * The migration races Claude itself: a live session can write a heartbeat (or
 * recreate the directory) between any two steps. Every step is individually
 * safe, so the loop just re-reads and retries a bounded number of times.
 */
const ENSURE_ATTEMPTS = 5;

/** Registry entries are `<pid>.json`, nothing else. */
const REGISTRY_ENTRY_RE = /^\d+\.json$/;

function canonicalPath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

function samePath(left: string, right: string): boolean {
  return canonicalPath(left) === canonicalPath(right);
}

/** Classify a config dir's `sessions` path without following anything unsafe. */
export function inspectSessionsDir(configDir: string): SessionsDirState {
  const path = join(configDir, "sessions");
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return { kind: "missing", path };
  }
  if (st.isSymbolicLink()) {
    let target: string;
    try {
      target = resolve(dirname(path), readlinkSync(path));
    } catch {
      return { kind: "unexpected", path };
    }
    if (samePath(target, sharedClaudeSessionsDir())) return { kind: "shared-link", path, target };
    return { kind: "foreign-link", path, target };
  }
  if (st.isDirectory()) return { kind: "real-dir", path };
  return { kind: "unexpected", path };
}

/**
 * Move one registry entry into the shared dir. Prefers rename(2) — an inode
 * move, atomic on one filesystem — and falls back to copy+rename+unlink when
 * the profile dir sits on another filesystem (custom `--dir` profiles). When
 * both sides carry the same `<pid>.json`, the newest copy wins: registry
 * files are heartbeat-rewritten wholesale, so mtime orders them truthfully.
 */
function migrateEntry(
  sourceDir: string,
  sharedDir: string,
  name: string,
  moved: string[],
  deduped: string[],
): void {
  const src = join(sourceDir, name);
  const dest = join(sharedDir, name);
  const destStat = (() => {
    try {
      return statSync(dest);
    } catch {
      return undefined;
    }
  })();
  if (destStat) {
    const srcStat = statSync(src);
    if (srcStat.ino === destStat.ino && srcStat.dev === destStat.dev) {
      // Already the same inode (a hand-made hardlink bridge) — drop the extra name.
      unlinkSync(src);
      deduped.push(name);
      return;
    }
    if (srcStat.mtimeMs <= destStat.mtimeMs) {
      unlinkSync(src);
      deduped.push(name);
      return;
    }
    deduped.push(name);
  }
  try {
    renameSync(src, dest);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && (error as { code?: string }).code === "EXDEV")) {
      throw error;
    }
    const tmp = join(sharedDir, `.${name}.migrating-${process.pid}`);
    copyFileSync(src, tmp);
    const srcStat = statSync(src);
    utimesSync(tmp, srcStat.atime, srcStat.mtime);
    renameSync(tmp, dest);
    unlinkSync(src);
  }
  moved.push(name);
}

/**
 * Idempotently converge one Claude config dir onto the shared session
 * registry. Never throws and never deletes registry data: unexpected content
 * blocks the migration (reported, not removed), and dedupe keeps the newest
 * copy of an entry. Safe to run with live sessions attached.
 */
export function ensureSharedClaudeSessions(configDir: string): EnsureSessionsResult {
  const done = (
    outcome: EnsureSessionsResult["outcome"],
    changed: boolean,
    moved: string[],
    deduped: string[],
    reason?: string,
  ): EnsureSessionsResult => ({ outcome, changed, moved, deduped, ...(reason ? { reason } : {}) });

  const moved: string[] = [];
  const deduped: string[] = [];
  try {
    const dir = resolve(configDir);
    if (!existsSync(dir)) {
      return done("no-config-dir", false, moved, deduped, `config dir does not exist: ${dir}`);
    }
    const shared = sharedClaudeSessionsDir();
    const sessionsPath = join(dir, "sessions");
    // Refuse the one self-referential foot-gun outright: running this against
    // a "config dir" whose sessions path IS the shared registry would make the
    // dedupe below delete entries from themselves. Canonicalize the PARENT and
    // keep the leaf literal — canonicalizing the leaf would follow the very
    // link this function creates and misread every linked dir as the registry.
    if (join(canonicalPath(dir), "sessions") === canonicalPath(shared)) {
      return done("blocked", false, moved, deduped, "sessions path is the shared registry itself");
    }
    mkdirSync(shared, { recursive: true, mode: 0o700 });

    let migratedRealDir = false;
    let repointedForeign = false;
    let createdLink = false;
    let lastReason: string | undefined;

    for (let attempt = 0; attempt < ENSURE_ATTEMPTS; attempt++) {
      const state = inspectSessionsDir(dir);

      if (state.kind === "shared-link") {
        const outcome = migratedRealDir
          ? "migrated"
          : repointedForeign
            ? "repointed"
            : createdLink
              ? "linked"
              : "already-linked";
        return done(outcome, outcome !== "already-linked", moved, deduped);
      }

      if (state.kind === "unexpected") {
        return done("blocked", false, moved, deduped, `sessions path is neither a directory nor a symlink: ${state.path}`);
      }

      if (state.kind === "missing") {
        try {
          symlinkSync(shared, sessionsPath);
          createdLink = true;
        } catch {
          // Lost a race with a session start (or a parallel ensure) — re-inspect.
        }
        continue;
      }

      if (state.kind === "foreign-link") {
        try {
          unlinkSync(sessionsPath);
          repointedForeign = true;
        } catch {
          // Re-inspect; a parallel ensure may already have replaced it.
        }
        continue;
      }

      // real-dir: drain registry entries, then swap the dir for the link.
      let entries;
      try {
        entries = readdirSync(sessionsPath, { withFileTypes: true });
      } catch {
        continue;
      }
      const unexpected = entries.filter(
        (entry) => !(entry.isFile() && !entry.isSymbolicLink() && REGISTRY_ENTRY_RE.test(entry.name)),
      );
      if (unexpected.length > 0) {
        // Possibly a transient mid-write artifact — retry, then refuse without
        // deleting anything. A blocked dir is reported by doctor, not razed.
        lastReason =
          `sessions dir holds unexpected content (${unexpected.map((entry) => entry.name).slice(0, 5).join(", ")}); ` +
          "not migrating";
        continue;
      }
      try {
        for (const entry of entries) {
          migrateEntry(sessionsPath, shared, entry.name, moved, deduped);
        }
        rmdirSync(sessionsPath);
        migratedRealDir = true;
      } catch {
        // A writer landed a new entry mid-drain (ENOTEMPTY) or a file vanished —
        // the next attempt re-reads the directory.
      }
    }
    return done("blocked", moved.length > 0, moved, deduped, lastReason ?? "sessions dir kept changing; re-run to converge");
  } catch (error) {
    return done("blocked", moved.length > 0, moved, deduped, error instanceof Error ? error.message : String(error));
  }
}

export { sharedClaudeSessionsDir } from "../storage.js";
