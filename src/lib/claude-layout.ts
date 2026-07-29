import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ToolDef } from "../types.js";

export const CLAUDE_KEYCHAIN_SERVICE = "Claude Code-credentials";
export const ACCOUNTS_AUTH_DIR = ".accounts-auth";
export const OAUTH_SNAPSHOT = "oauth-account.json";
export const CREDENTIALS_SNAPSHOT = "credentials.json";
export const KEYCHAIN_SNAPSHOT = "keychain.json";
export const SWITCHED_ACCOUNT_MARKER = "switched-account.json";
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

/** Account JSON paths for a profile config dir (handles parent ~/.claude.json layout). */
export function profileAccountJsonPaths(profileDir: string, tool: ToolDef): string[] {
  if (!tool.accountFile) return [];
  const paths = [join(profileDir, tool.accountFile)];
  if (profileDir === tool.defaultDir) paths.push(join(dirname(profileDir), tool.accountFile));
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
}

/**
 * Live sessions bound to a config dir, from the tool's `sessions/<pid>.json`
 * heartbeat files. Every one of them flips identity together on an in-place
 * switch — the dir is shared state, not per-session state.
 */
export function listDirLiveSessions(configDir: string): DirSessionInfo[] {
  const sessionsDir = join(configDir, "sessions");
  if (!existsSync(sessionsDir)) return [];
  const sessions: DirSessionInfo[] = [];
  for (const entry of readdirSync(sessionsDir)) {
    if (!entry.endsWith(".json")) continue;
    let pid = Number.parseInt(entry.slice(0, -".json".length), 10);
    try {
      const parsed = JSON.parse(readFileSync(join(sessionsDir, entry), "utf8")) as { pid?: unknown };
      if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid)) pid = parsed.pid;
    } catch {
      // Fall back to the pid encoded in the filename.
    }
    if (!Number.isInteger(pid) || pid <= 0) continue;
    sessions.push({ pid, alive: processAlive(pid) });
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
