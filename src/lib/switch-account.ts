import { resolve } from "node:path";
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
import { listDirLiveSessions, liveClaudeBase, liveClaudePaths, type DirSessionInfo } from "./claude-layout.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { getTool } from "./tools.js";

export { listDirLiveSessions } from "./claude-layout.js";
export type { DirSessionInfo } from "./claude-layout.js";

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

type LockedOutcome =
  | { alreadyActive: true; previousEmail?: string }
  | { alreadyActive: false; previousEmail?: string; snapshotBackProfile?: string };

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

  const warnings: string[] = [];

  // Fail loudly on UNUSABLE auth before touching anything: a switch onto a dead
  // profile would strand the running session mid-conversation.
  //
  // "Expired" alone is not unusable, and treating it as such deadlocked the CLI
  // against itself. Observed 2026-07-29: `accounts login account004` refused
  // because that profile's dir carried another account after an in-place switch
  // and pointed the operator at `accounts switch-account`; `accounts
  // switch-account account004 --dir ...` refused because the profile's own
  // credential snapshot had an aged-out access token and pointed back at
  // `accounts login`. Neither command has a `--force`, so five profiles had no
  // CLI route out at all — each command deferring to the other.
  //
  // The refusal was also wrong on the facts. The snapshot it read
  // (`.accounts-auth/credentials.json`, plus its central copy under
  // ~/.hasna/accounts/auth/<uuid>/) carried a REAL refresh token valid for
  // another three to four weeks; only the 8-hour access token had aged out, and
  // Claude Code renews those in place. Measured across all 23 registered Claude
  // profiles: every profile whose live dir file had been emptied still had its
  // own refresh token intact in the snapshot or central store — six of six.
  //
  // A credential with no refresh token is still refused: that one really is
  // dead, and re-authenticating is the only answer. The two verdicts are
  // different and must stay different.
  ensureProfileAuthSnapshot(profile.dir, tool);
  const health = claudeProfileAuthHealth(profile.dir, tool, { restoreView: true });
  if (!health.valid && !health.renewable) {
    const detail = health.reasons.length ? health.reasons.join("; ") : `status ${health.status}`;
    throw new AccountsError(
      `profile "${profile.name}" cannot take over this session — ${detail}` +
        (health.credentialExpiresAt ? ` (expired ${health.credentialExpiresAt})` : "") +
        `. Re-authenticate with \`accounts login ${profile.name}\` first.`,
    );
  }
  if (!health.valid) {
    warnings.push(
      `"${profile.name}" has an aged-out access token${health.credentialExpiresAt ? ` (expired ${health.credentialExpiresAt})` : ""}` +
        `; its refresh token is intact, so the tool renews it on the next request`,
    );
  }

  const configDir = resolveSessionConfigDir(tool, opts);
  const resolvedConfigDir = resolve(configDir);
  if (resolvedConfigDir === resolve(liveClaudeBase())) {
    throw new AccountsError(
      `${configDir} is a home/base directory, not a Claude config dir — pass the config dir itself (e.g. ~/.claude) or omit --dir`,
    );
  }

  const liveDefault = liveClaudePaths().configDir;
  const profiles = await store.listProfiles(tool.id);
  const dirKind: SessionDirKind =
    resolvedConfigDir === resolve(liveDefault)
      ? "live-default"
      : profiles.some((p) => resolve(p.dir) === resolvedConfigDir)
        ? "profile-dir"
        : "external";

  const sessions = listDirLiveSessions(configDir);
  const liveSessions = sessions.filter((s: DirSessionInfo) => s.alive).length;
  if (liveSessions > 1 && !opts.yes) {
    throw new AccountsError(
      `${liveSessions} live sessions share ${configDir} and ALL of them would switch to "${profile.name}" together. Re-run with --yes to proceed.`,
    );
  }
  if (liveSessions > 1) {
    warnings.push(`${liveSessions} live sessions share this config dir; all of them switch together`);
  }

  const targetEmail = profileOAuthEmail(profile.dir, tool) ?? profile.email;

  if (dirKind === "live-default") {
    // The live default paths already have first-class switch semantics (owner
    // snapshot, applied pointer, apply lock) — reuse them wholesale.
    const previousEmail = liveOAuthEmail();
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

  const dirIsTargetsOwn = resolve(profile.dir) === resolvedConfigDir;

  // All owner-detection inputs (dir email, marker, alreadyActive) are read
  // INSIDE the lock so a concurrent switch cannot make this one snapshot the
  // wrong account into the wrong profile.
  const outcome: LockedOutcome = withApplyLock(() => {
    const previousEmail = dirOAuthEmail(configDir, tool);
    const marker = readSwitchedAccountMarker(configDir);
    if (
      previousEmail &&
      targetEmail &&
      previousEmail === targetEmail &&
      (!marker || marker.profile === profile.name)
    ) {
      return { alreadyActive: true as const, previousEmail };
    }

    let snapshotBackProfile: string | undefined;
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

    // Marker BEFORE mutation: if the restore fails midway, the fail state is a
    // disagreeing (stale) marker — which later flows detect and clear — never
    // an unmarked dir whose foreign files would be snapshotted into the wrong
    // profile's store.
    if (!dirIsTargetsOwn) {
      writeSwitchedAccountMarker(configDir, {
        profile: profile.name,
        ...(targetEmail ? { email: targetEmail } : {}),
      });
    }
    try {
      restoreClaudeAuthIntoDir(profile.dir, tool, configDir, profile.name);
    } catch (error) {
      // When the account file still carries the old email nothing was mutated;
      // drop the marker so the dir is exactly as before the attempt.
      if (!dirIsTargetsOwn && dirOAuthEmail(configDir, tool) === previousEmail) {
        clearSwitchedAccountMarker(configDir);
      }
      throw error;
    }
    if (dirIsTargetsOwn) clearSwitchedAccountMarker(configDir);

    return {
      alreadyActive: false as const,
      ...(previousEmail ? { previousEmail } : {}),
      ...(snapshotBackProfile ? { snapshotBackProfile } : {}),
    };
  });

  if (outcome.alreadyActive) {
    return {
      profile,
      tool,
      configDir,
      dirKind,
      alreadyActive: true,
      ...(outcome.previousEmail ? { previousEmail: outcome.previousEmail } : {}),
      liveSessions,
      warnings,
      restartRequired: false,
      message: `${profile.name} (${targetEmail}) already owns this session's config dir — nothing to switch`,
    };
  }

  // The on-disk switch already happened; a registry hiccup must not be
  // reported as a failed switch.
  try {
    await store.useProfile(profile.name, tool.id);
  } catch (error) {
    warnings.push(`active-profile pointer not updated: ${error instanceof Error ? error.message : String(error)}`);
  }

  let refreshed: Profile = profile;
  try {
    refreshed = await store.getProfile(profile.name, tool.id);
  } catch {
    // Registry read-back is cosmetic; the on-disk switch is done.
  }

  return {
    profile: refreshed,
    tool,
    configDir,
    dirKind,
    alreadyActive: false,
    ...(outcome.previousEmail ? { previousEmail: outcome.previousEmail } : {}),
    ...(outcome.snapshotBackProfile ? { snapshotBackProfile: outcome.snapshotBackProfile } : {}),
    liveSessions,
    warnings,
    restartRequired: false,
    message: `${profile.name}${targetEmail ? ` (${targetEmail})` : ""} takes over this session on its next message — no restart needed`,
  };
}
