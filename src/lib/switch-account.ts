import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile } from "./apply.js";
import { withApplyLock } from "./apply-lock.js";
import {
  claudeProfileAuthHealth,
  clearSwitchedAccountMarker,
  dirCredentialShouldUpdateProfile,
  dirOAuthEmail,
  ensureProfileAuthSnapshot,
  liveOAuthEmail,
  profileOAuthEmail,
  readSwitchedAccountMarker,
  restoreClaudeAuthIntoDir,
  snapshotDirAuthToProfile,
  writeSwitchedAccountMarker,
} from "./claude-auth.js";
import { liveClaudePaths } from "./claude-layout.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { getTool } from "./tools.js";

export type SessionDirKind = "live-default" | "profile-dir" | "external";

export interface SwitchAccountOptions {
  /** Tool id; in-place switching is Claude-only today. */
  tool?: string;
  /** Explicit session config dir (overrides the tool env var). */
  dir?: string;
  /** Environment to read the tool's config-dir variable from (tests inject). */
  env?: NodeJS.ProcessEnv;
  /** Proceed even when several live sessions share the config dir. */
  yes?: boolean;
}

export interface DirSessionInfo {
  pid: number;
  alive: boolean;
}

export interface SwitchAccountResult {
  profile: Profile;
  tool: ToolDef;
  configDir: string;
  dirKind: SessionDirKind;
  alreadyActive: boolean;
  previousEmail?: string;
  /** Profile that received a snapshot of the dir's outgoing credentials. */
  snapshotBackProfile?: string;
  liveSessions: number;
  warnings: string[];
  /** The whole point: the running session adopts the new account on its next request. */
  restartRequired: false;
  message: string;
}

/** Session config dir precedence: explicit --dir, then the tool env var, then the live default. */
export function resolveSessionConfigDir(
  tool: ToolDef,
  opts: { dir?: string; env?: NodeJS.ProcessEnv } = {},
): string {
  const env = opts.env ?? process.env;
  const fromOption = opts.dir?.trim();
  if (fromOption) return resolve(fromOption);
  const fromEnv = env[tool.envVar]?.trim();
  if (fromEnv) return resolve(fromEnv);
  if (tool.id === "claude") return liveClaudePaths().configDir;
  return tool.defaultDir;
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

function singleMatch<T>(items: T[]): T | undefined {
  return items.length === 1 ? items[0] : undefined;
}

/**
 * The profile whose account currently lives in the dir: the switch marker when
 * it still agrees with the dir's email, then the dir's own registry profile,
 * then a unique email match. `undefined` plus a warning otherwise.
 */
function detectDirOwner(
  dir: string,
  dirEmail: string | undefined,
  profiles: Profile[],
  tool: ToolDef,
  warnings: string[],
): Profile | undefined {
  if (!dirEmail) {
    warnings.push(`config dir carries no OAuth account; nothing to snapshot back`);
    return undefined;
  }
  const marker = readSwitchedAccountMarker(dir);
  if (marker) {
    const markerProfile = profiles.find((p) => p.name === marker.profile);
    if (markerProfile && (marker.email === dirEmail || profileOAuthEmail(markerProfile.dir, tool) === dirEmail)) {
      return markerProfile;
    }
  }
  const resolvedDir = resolve(dir);
  const dirProfile = profiles.find((p) => resolve(p.dir) === resolvedDir);
  if (dirProfile && !marker && profileOAuthEmail(dirProfile.dir, tool) === dirEmail) return dirProfile;

  const byEmail = profiles.filter((p) => profileOAuthEmail(p.dir, tool) === dirEmail || p.email === dirEmail);
  const unique = singleMatch(byEmail);
  if (unique) return unique;
  warnings.push(
    byEmail.length === 0
      ? `no profile owns ${dirEmail}; outgoing credentials were not snapshotted`
      : `multiple profiles share ${dirEmail}; outgoing credentials were not snapshotted`,
  );
  return undefined;
}

/**
 * Switch the account of the CURRENT session in place: swap the target profile's
 * credentials + `oauthAccount` into the session's config dir. Proven on Claude
 * Code 2.1.220 — a running session re-reads `.credentials.json` from disk at
 * request time, so the next message runs as the new account with no restart and
 * the conversation intact.
 */
export async function switchAccount(
  name: string,
  opts: SwitchAccountOptions = {},
  store: AccountsStore = resolveStore(),
): Promise<SwitchAccountResult> {
  const profile = await store.getProfile(name, opts.tool);
  const tool = getTool(profile.tool);
  if (tool.id !== "claude") {
    throw new AccountsError(
      `in-place account switching is only supported for Claude Code (profile "${profile.name}" is for ${tool.label}). Use \`accounts switch ${profile.name}\` instead.`,
    );
  }

  // Fail loudly on dead auth BEFORE touching anything: a switch to an expired
  // profile would strand the running session mid-conversation.
  ensureProfileAuthSnapshot(profile.dir, tool);
  const health = claudeProfileAuthHealth(profile.dir, tool, { restoreView: true });
  if (!health.valid) {
    const detail = health.reasons.length ? health.reasons.join("; ") : `status ${health.status}`;
    throw new AccountsError(
      `profile "${profile.name}" cannot take over this session — ${detail}` +
        (health.credentialExpiresAt ? ` (expired ${health.credentialExpiresAt})` : "") +
        `. Re-authenticate with \`accounts login ${profile.name}\` first.`,
    );
  }

  const configDir = resolveSessionConfigDir(tool, opts);
  const liveDefault = liveClaudePaths().configDir;
  const profiles = await store.listProfiles(tool.id);
  const resolvedConfigDir = resolve(configDir);
  const dirKind: SessionDirKind =
    resolvedConfigDir === resolve(liveDefault)
      ? "live-default"
      : profiles.some((p) => resolve(p.dir) === resolvedConfigDir)
        ? "profile-dir"
        : "external";

  const warnings: string[] = [];
  const sessions = listDirLiveSessions(configDir);
  const liveSessions = sessions.filter((s) => s.alive).length;
  if (liveSessions > 1 && !opts.yes) {
    throw new AccountsError(
      `${liveSessions} live sessions share ${configDir} and ALL of them would switch to "${profile.name}" together. Re-run with --yes to proceed.`,
    );
  }
  if (liveSessions > 1) {
    warnings.push(`${liveSessions} live sessions share this config dir; all of them switch together`);
  }

  const previousEmail =
    dirKind === "live-default" ? liveOAuthEmail() : dirOAuthEmail(configDir, tool);
  const targetEmail = profileOAuthEmail(profile.dir, tool) ?? profile.email;

  if (dirKind === "live-default") {
    // The live default paths already have first-class switch semantics (owner
    // snapshot, applied pointer, apply lock) — reuse them wholesale.
    await applyProfile(profile.name, tool.id, store);
    return {
      profile: await store.getProfile(profile.name, tool.id),
      tool,
      configDir,
      dirKind,
      alreadyActive: false,
      ...(previousEmail ? { previousEmail } : {}),
      liveSessions,
      warnings,
      restartRequired: false,
      message: `${profile.name} now owns the live Claude auth — running sessions on the default config pick it up on their next message`,
    };
  }

  const marker = readSwitchedAccountMarker(configDir);
  const dirIsTargetsOwn = resolve(profile.dir) === resolvedConfigDir;
  if (previousEmail && targetEmail && previousEmail === targetEmail && (!marker || marker.profile === profile.name)) {
    return {
      profile,
      tool,
      configDir,
      dirKind,
      alreadyActive: true,
      previousEmail,
      liveSessions,
      warnings,
      restartRequired: false,
      message: `${profile.name} (${targetEmail}) already owns this session's config dir — nothing to switch`,
    };
  }

  let snapshotBackProfile: string | undefined;
  withApplyLock(() => {
    const owner = detectDirOwner(configDir, previousEmail, profiles, tool, warnings);
    if (owner) {
      if (resolve(owner.dir) === resolvedConfigDir) {
        // The dir IS the owner's profile dir: the standard snapshot refresh
        // captures any tokens the session rotated in place.
        ensureProfileAuthSnapshot(owner.dir, tool);
        snapshotBackProfile = owner.name;
      } else if (dirCredentialShouldUpdateProfile(configDir, owner.dir)) {
        snapshotDirAuthToProfile(configDir, tool, owner.dir);
        snapshotBackProfile = owner.name;
      } else {
        warnings.push(`${owner.name} already holds a better credential than this dir; snapshot-back skipped`);
      }
    }

    restoreClaudeAuthIntoDir(profile.dir, tool, configDir, profile.name);

    if (dirIsTargetsOwn) clearSwitchedAccountMarker(configDir);
    else {
      writeSwitchedAccountMarker(configDir, {
        profile: profile.name,
        ...(targetEmail ? { email: targetEmail } : {}),
      });
    }
  });

  await store.useProfile(profile.name, tool.id);

  return {
    profile: await store.getProfile(profile.name, tool.id),
    tool,
    configDir,
    dirKind,
    alreadyActive: false,
    ...(previousEmail ? { previousEmail } : {}),
    ...(snapshotBackProfile ? { snapshotBackProfile } : {}),
    liveSessions,
    warnings,
    restartRequired: false,
    message: `${profile.name}${targetEmail ? ` (${targetEmail})` : ""} takes over this session on its next message — no restart needed`,
  };
}
