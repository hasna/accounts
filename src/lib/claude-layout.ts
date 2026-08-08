import { existsSync, lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { ToolDef } from "../types.js";
import { sharedClaudeSessionsDir } from "../storage.js";

export const CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials";
export const ACCOUNTS_AUTH_DIR = ".accounts-auth";
export const OAUTH_SNAPSHOT = "oauth-account.json";
export const CREDENTIALS_SNAPSHOT = "credentials.json";
export const KEYCHAIN_SNAPSHOT = "keychain.json";
export const SWITCHED_ACCOUNT_MARKER = "switched-account.json";
export const UNREADABLE_CREDENTIALS_DIR = "unreadable-credentials";
export const DIR_CREDENTIALS_FILE = ".credentials.json";

/**
 * A config dir's LIVE credential file.
 *
 * Named for what it holds rather than for the profile that owns the directory:
 * after an in-place switch this file carries the CURRENT OCCUPANT's credential,
 * not the dir's own. Reading it as "the profile's credential" is the single
 * most repeated mistake on this code, so the helper says `dir`, not `profile`.
 */
export function dirCredentialsFile(configDir: string): string {
  return join(configDir, DIR_CREDENTIALS_FILE);
}

/** Root directory for live Claude auth files (home or ACCOUNTS_TEST_LIVE_DIR). */
export function liveClaudeBase(): string {
  const testBase = process.env.ACCOUNTS_TEST_LIVE_DIR;
  return testBase && testBase.trim() ? testBase : homedir();
}

/** Live Claude Code paths (default install, no CLAUDE_CONFIG_DIR). */
export function liveClaudePaths(): { configDir: string; homeJson: string; credentialsFile: string } {
  const base = liveClaudeBase();
  const configDir = join(base, ".claude");
  return {
    configDir,
    homeJson: join(base, ".claude.json"),
    credentialsFile: join(configDir, ".credentials.json"),
  };
}

function fileMtimeMs(path: string): number {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * Account JSON paths for a profile config dir (handles parent ~/.claude.json
 * layout), FRESHEST FIRST for the default dir.
 *
 * THE ORDER IS THE FIX (bug 04a350a9, task 9b006e93). The live default keeps
 * its account record in two places — the inner `~/.claude/.claude.json` and
 * the home `~/.claude.json` — and readers over these paths (`dirAccountUuid`,
 * `findOAuthSource`) take the FIRST record they can parse. With the inner
 * file pinned first, a stale inner record shadowed a fresh home one: measured
 * on station01, an Aug-3 inner uuid (643e2376) shadowing a same-day home uuid
 * (11aabd84), so the credential broker attributed and harvested the live
 * default under the wrong account. The freshest file speaks for the dir;
 * missing files rank last, and ties keep the historical inner-first order.
 * Writers are unaffected: `mergeOAuthInto` writes EVERY listed path, so both
 * records converge on the next write regardless of order.
 *
 * The default-dir check also matches the LIVE claude config dir (which honors
 * ACCOUNTS_TEST_LIVE_DIR) rather than only `tool.defaultDir`, which is frozen
 * to the process's homedir at module load and therefore invisible to tests.
 */
export function profileAccountJsonPaths(profileDir: string, tool: ToolDef): string[] {
  if (!tool.accountFile) return [];
  const isDefaultDir =
    profileDir === tool.defaultDir ||
    (tool.id === "claude" && resolve(profileDir) === resolve(liveClaudePaths().configDir));
  const paths = [join(profileDir, tool.accountFile)];
  if (isDefaultDir) {
    paths.push(join(dirname(profileDir), tool.accountFile));
    paths.sort((a, b) => fileMtimeMs(b) - fileMtimeMs(a));
  }
  return paths;
}

export function profileAuthDir(profileDir: string): string {
  return join(profileDir, ACCOUNTS_AUTH_DIR);
}

export function profileOAuthSnapshot(profileDir: string): string {
  return join(profileAuthDir(profileDir), OAUTH_SNAPSHOT);
}

export function profileCredentialsSnapshot(profileDir: string): string {
  return join(profileAuthDir(profileDir), CREDENTIALS_SNAPSHOT);
}

export function profileKeychainSnapshot(profileDir: string): string {
  return join(profileAuthDir(profileDir), KEYCHAIN_SNAPSHOT);
}

/** Copies of unrecognised live credential payloads preserved before recovery. */
export function profileUnreadableCredentialsDir(profileDir: string): string {
  return join(profileAuthDir(profileDir), UNREADABLE_CREDENTIALS_DIR);
}

/**
 * Marker recording that a config dir's LIVE auth files currently carry another
 * profile's account (written by in-place `switch-account`, cleared when the
 * dir's own account is restored or a fresh login lands).
 */
export function profileSwitchedAccountMarker(profileDir: string): string {
  return join(profileAuthDir(profileDir), SWITCHED_ACCOUNT_MARKER);
}

export interface DirSessionInfo {
  pid: number;
  alive: boolean;
  /**
   * Present only for entries read from the SHARED machine registry:
   * `own` means the entry was positively attributed to this config dir,
   * `unknown` means it could not be attributed and is included so that every
   * caller errs toward caution (a guard that over-counts refuses; one that
   * under-counts destroys a live session's identity).
   */
  attribution?: "own" | "unknown";
}

export interface ListDirSessionsOptions {
  /** Injectable for tests: the liveness probe (defaults to `kill(pid, 0)`). */
  isAlive?: (pid: number) => boolean;
  /**
   * Injectable for tests: resolve a process's CLAUDE_CONFIG_DIR. Returns the
   * value when set, `null` when the process is readable and the variable is
   * unset (a default-dir session), `undefined` when unreadable. The default
   * reader uses `/proc/<pid>/environ` and returns `undefined` off Linux.
   */
  readEnvironConfigDir?: (pid: number) => string | null | undefined;
}

/**
 * Reproduce Claude's lossy project-directory encoding (`/a.b`, `/a-b`, `/a_b`
 * all encode to `-a-b`). Exported so there is exactly one definition.
 */
export function claudeProjectKey(cwd: string): string {
  return cwd.replace(/[^A-Za-z0-9]/g, "-");
}

function canonicalDirPath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

/** True when a config dir's `sessions` is the machine-shared registry link. */
function sessionsDirIsShared(sessionsDir: string): boolean {
  try {
    if (!lstatSync(sessionsDir).isSymbolicLink()) return false;
    const target = resolve(dirname(sessionsDir), readlinkSync(sessionsDir));
    return canonicalDirPath(target) === canonicalDirPath(sharedClaudeSessionsDir());
  } catch {
    return false;
  }
}

/**
 * Default attribution source: `/proc/<pid>/environ`, same-uid readable on
 * Linux. `null` means the variable is genuinely unset (a default-dir session);
 * `undefined` means the environment could not be read at all (dead process,
 * foreign uid, non-Linux platform).
 */
function readProcEnvironConfigDir(pid: number): string | null | undefined {
  if (process.platform !== "linux") return undefined;
  let raw: Buffer;
  try {
    raw = readFileSync(`/proc/${pid}/environ`);
  } catch {
    return undefined;
  }
  if (raw.length === 0) return undefined; // zombie: environ exists but is empty
  for (const chunk of raw.toString("utf8").split("\0")) {
    if (chunk.startsWith("CLAUDE_CONFIG_DIR=")) {
      const value = chunk.slice("CLAUDE_CONFIG_DIR=".length);
      return value || null;
    }
  }
  return null;
}

/**
 * Attribute one SHARED-registry entry to a config dir.
 *
 * Order of evidence: the process's own CLAUDE_CONFIG_DIR (definitive), then
 * the transcript the entry names (`<configDir>/projects/<encoded-cwd>/
 * <sessionId>.jsonl` — transcripts stay per-profile, so presence here is
 * ownership). An entry that resists both stays `unknown` when alive (included,
 * so guards err toward caution) and is dropped when dead (a dead entry carries
 * no guard weight and will be reaped).
 */
function attributeSharedEntry(
  configDir: string,
  pid: number,
  alive: boolean,
  record: { sessionId?: unknown; cwd?: unknown },
  options: ListDirSessionsOptions,
): "own" | "unknown" | "excluded" {
  const reader = options.readEnvironConfigDir ?? readProcEnvironConfigDir;
  const environDir = reader(pid);
  if (typeof environDir === "string") {
    return canonicalDirPath(environDir) === canonicalDirPath(configDir) ? "own" : "excluded";
  }
  if (environDir === null) {
    return canonicalDirPath(liveClaudePaths().configDir) === canonicalDirPath(configDir)
      ? "own"
      : "excluded";
  }
  if (typeof record.sessionId === "string" && typeof record.cwd === "string" && record.cwd) {
    const transcript = join(
      configDir,
      "projects",
      claudeProjectKey(record.cwd),
      `${record.sessionId.toLowerCase()}.jsonl`,
    );
    if (existsSync(transcript)) return "own";
  }
  return alive ? "unknown" : "excluded";
}

/**
 * Live sessions bound to a config dir, from the tool's `sessions/<pid>.json`
 * heartbeat files. Every one of them flips identity together on an in-place
 * switch — the dir is shared state, not per-session state.
 *
 * When the dir's `sessions/` is the machine-shared registry link (see
 * `lib/claude-session-registry.ts`), the raw listing is machine-wide, so
 * entries are attributed back to this config dir first — otherwise every
 * switch guard, auth heal, and occupancy count would see every profile as
 * busy whenever anything runs anywhere on the box.
 */
export function listDirLiveSessions(
  configDir: string,
  options: ListDirSessionsOptions = {},
): DirSessionInfo[] {
  const sessionsDir = join(configDir, "sessions");
  if (!existsSync(sessionsDir)) return [];
  const aliveProbe = options.isAlive ?? processAlive;
  const shared = sessionsDirIsShared(sessionsDir);
  const sessions: DirSessionInfo[] = [];
  for (const entry of readdirSync(sessionsDir)) {
    if (!entry.endsWith(".json")) continue;
    let pid = Number.parseInt(entry.slice(0, -".json".length), 10);
    let record: { pid?: unknown; sessionId?: unknown; cwd?: unknown } = {};
    try {
      record = JSON.parse(readFileSync(join(sessionsDir, entry), "utf8")) as typeof record;
      if (typeof record.pid === "number" && Number.isInteger(record.pid)) pid = record.pid;
    } catch {
      // Fall back to the pid encoded in the filename.
    }
    if (!Number.isInteger(pid) || pid <= 0) continue;
    const alive = aliveProbe(pid);
    if (!shared) {
      sessions.push({ pid, alive });
      continue;
    }
    const attribution = attributeSharedEntry(configDir, pid, alive, record, options);
    if (attribution === "excluded") continue;
    sessions.push({ pid, alive, attribution });
  }
  return sessions.sort((a, b) => a.pid - b.pid);
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the process exists but belongs to someone else.
    return error instanceof Error && "code" in error && (error as { code?: string }).code === "EPERM";
  }
}
