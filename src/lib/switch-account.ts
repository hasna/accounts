import { existsSync } from "node:fs";
import { resolve } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile } from "./apply.js";
import { withApplyLock } from "./apply-lock.js";
import {
  applyProfileOAuthIdentityToDir,
  claudeProfileAuthHealth,
  clearSwitchedAccountMarker,
  dirCredentialShouldUpdateProfile,
  dirOAuthEmail,
  ensureProfileAuthSnapshot,
  liveOAuthEmail,
  parkOrphanDirAuth,
  profileOAuthEmail,
  readSwitchedAccountMarker,
  restoreClaudeAuthIntoDir,
  snapshotDirAuthToProfile,
  writeSwitchedAccountMarker,
} from "./claude-auth.js";
import { listDirLiveSessions, liveClaudeBase, liveClaudePaths, type DirSessionInfo } from "./claude-layout.js";
import { credentialHealth, isAccountUuid, profileAccountUuid } from "./auth-store.js";
import { convergeIdentityCredential } from "./credential-broker.js";
import { dirAccountUuid } from "./identity-index.js";
import {
  centralCredentialsPath,
  inspectDirCredential,
  migrateDirToLink,
  repointDir,
} from "./symlink-broker.js";
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
  /**
   * Write credentials into a dir that is NEITHER this machine's live config dir
   * NOR a registered profile dir. Off by default — see the guard in
   * {@link switchAccount} for why. An explicit, human-driven override only:
   * `accounts usage-hook` must never set it.
   */
  allowUnregisteredDir?: boolean;
  /**
   * Target the live default config dir DELIBERATELY when neither --dir nor the
   * tool's env var chose it. Without this, a switch whose dir resolution FELL
   * THROUGH to the live default is refused while live profile-dir sessions
   * exist on the box — see the wrong-dir guard in {@link switchAccount}.
   */
  liveDefault?: boolean;
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

/** Which rung of the precedence chain picked the session config dir. */
export type SessionConfigDirSource = "option" | "env" | "default";

/**
 * Session config dir precedence — explicit --dir, then the tool env var, then
 * the live default — WITH the rung that decided it. The source matters
 * because "the operator named this dir" and "nothing named a dir so the
 * machine default caught it" demand different levels of caution from callers
 * that write credentials (see the wrong-dir guard in {@link switchAccount}).
 */
export function resolveSessionConfigDirWithSource(
  tool: ToolDef,
  opts: { dir?: string; env?: NodeJS.ProcessEnv } = {},
): { dir: string; source: SessionConfigDirSource } {
  const env = opts.env ?? process.env;
  const fromOption = opts.dir?.trim();
  if (fromOption) return { dir: resolve(fromOption), source: "option" };
  const fromEnv = env[tool.envVar]?.trim();
  if (fromEnv) return { dir: resolve(fromEnv), source: "env" };
  if (tool.id === "claude") return { dir: liveClaudePaths().configDir, source: "default" };
  return { dir: tool.defaultDir, source: "default" };
}

/** Session config dir precedence: explicit --dir, then the tool env var, then the live default. */
export function resolveSessionConfigDir(
  tool: ToolDef,
  opts: { dir?: string; env?: NodeJS.ProcessEnv } = {},
): string {
  return resolveSessionConfigDirWithSource(tool, opts).dir;
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

  const { dir: configDir, source: dirSource } = resolveSessionConfigDirWithSource(tool, opts);
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

  // THE DESTINATION IS CHECKED BEFORE THE SOURCE IS TOUCHED.
  //
  // This function's whole job is to copy a live OAuth credential into a
  // directory, and until this guard existed that directory was whatever the
  // caller named. `accounts usage-hook --dir <path>` therefore doubled as a
  // credential-exfiltration primitive: plant a `.claude.json` carrying any
  // `oauthAccount.accountUuid` plus a usage-cache entry for that uuid at 95%,
  // and the hook would rank the OTHER accounts, pick the healthiest, and write
  // its real access and refresh tokens into the caller's directory at mode
  // 0600. No confirmation, no allowlist, and the flag reads like a diagnostic.
  //
  // The write path did carry a guard —
  // `assertSafeWritePath(targetCredentials, { mustStayUnder: targetDir })` in
  // restoreClaudeAuthIntoDir — but `targetDir` IS the caller's argument, so it
  // only proved the file landed inside the directory the caller chose. A
  // boundary check against an attacker-supplied boundary is vacuous by
  // construction; the allowlist has to come from somewhere the caller does not
  // control, which here means the profile registry plus this machine's live
  // config dir.
  //
  // Measured before shipping this: every one of the 26 live `CLAUDE_CONFIG_DIR`
  // values on this fleet is a registered managed profile dir, and the live
  // default is registered too — so the allowlist refuses nothing that is
  // actually in use.
  if (dirKind === "external" && !opts.allowUnregisteredDir) {
    throw new AccountsError(
      `refusing to write ${tool.label} credentials into ${configDir}: it is not a registered profile dir ` +
        `and it is not this machine's live config dir. Register it first ` +
        `(\`accounts add <name> --dir ${configDir}\`), or pass --allow-unregistered-dir to override deliberately.`,
    );
  }

  // WRONG-DIR SWITCH GUARD (bug 04a350a9, task c48e92b7). Profile wiring on
  // this fleet lives only inside `accounts launch` process subtrees: a plain
  // tmux pane shell carries no CLAUDE_CONFIG_DIR, so a switch typed at a pane
  // prompt FALLS THROUGH to the live default and silently rewrites it — while
  // the profile-dir sessions the operator is actually looking at never read
  // that dir (measured: 20 of 31 live claudes on station01 ran under profile
  // dirs). When the fallthrough lands on the live default AND live profile-dir
  // sessions exist on this box, name the targeted dir and refuse unless
  // --live-default says the default was meant. An explicit --dir or a set env
  // var is a deliberate target and is never guarded.
  if (dirKind === "live-default" && dirSource === "default" && !opts.liveDefault) {
    const busyProfiles = profiles.filter(
      (p) => resolve(p.dir) !== resolvedConfigDir && listDirLiveSessions(p.dir).some((s) => s.alive),
    );
    if (busyProfiles.length > 0) {
      throw new AccountsError(
        `this switch would target the LIVE DEFAULT config dir ${configDir} — no --dir was given and ` +
          `${tool.envVar} is not set in this shell, so the fallthrough landed on the machine default. ` +
          `${busyProfiles.length} registered profile dir(s) currently have live ${tool.label} session(s) ` +
          `(${busyProfiles.map((p) => p.name).join(", ")}) and those sessions never read ${configDir}, so this ` +
          `switch would rewrite the default silently while changing nothing you are looking at. ` +
          `Pass --live-default to target ${configDir} deliberately, or --dir <config-dir> for the session you mean.`,
      );
    }
  }

  const warnings: string[] = [];

  // === SINGLE-INODE BROKER: ATOMIC SYMLINK REPOINT (owner directive 2026-08-06) ===
  //
  // The target-state switch: point the session's `.credentials.json` at the
  // incoming account's ONE central file by an atomic `rename` of a symlink,
  // preserving the outgoing account's in-place refresh onto its own central
  // file first. Zero credential bytes are copied and no central file is
  // unlinked, so a switch can never destroy a login (design §4, task 46679f8b).
  //
  // ROLLOUT IS PER-DIR AND SAFE BY DEFAULT. A dir already ON the model — its
  // `.credentials.json` is a symlink into the central store — MUST repoint,
  // because the legacy copy path refuses to write through a symlink. A dir that
  // is still a regular file keeps the legacy copy behaviour UNCHANGED until it
  // is deliberately converted with `accounts migrate-links` (design GATE 1/2:
  // symlinks are created on production dirs deliberately, not implicitly on
  // every switch). `HASNA_ACCOUNTS_SYMLINK_BROKER=1` opts a box in to
  // migrate-on-switch for regular dirs too. So installing this release changes
  // nothing on a box whose dirs are all regular files; the model activates a
  // dir at a time, on migration.
  const targetUuid = profileAccountUuid(profile.dir, tool);
  const targetHasCentral =
    !!targetUuid && isAccountUuid(targetUuid) && existsSync(centralCredentialsPath(targetUuid));
  if (dirKind !== "live-default") {
    const dirInfo = inspectDirCredential(configDir);
    const dirIsMigrated = dirInfo.kind === "link-central";
    const brokerOptIn = process.env.HASNA_ACCOUNTS_SYMLINK_BROKER === "1";
    if (dirIsMigrated || brokerOptIn) {
      // A migrated dir can ONLY be switched by repoint; if the target has no
      // central file, say so plainly rather than letting the copy-path
      // fall-through raise a confusing "refusing to write through symlink".
      if (dirIsMigrated && !targetHasCentral) {
        throw new AccountsError(
          `profile "${profile.name}" has no central credential to link this session to. ` +
            `Re-authenticate with \`accounts login ${profile.name}\` first.`,
        );
      }
      if (targetHasCentral) {
        const outUuid =
          dirInfo.kind === "link-central"
            ? dirInfo.uuid
            : dirInfo.kind === "regular"
              ? dirAccountUuid(configDir, tool)
              : undefined;
        // The outgoing credential must be preservable: an already-linked dir, a
        // Claude refresh fork of a known account, or an empty dir. An opt-in on
        // a regular dir whose account cannot be resolved falls through to the
        // legacy path, which PARKS it rather than risk losing a login.
        const outgoingPreservable =
          dirInfo.kind === "link-central" ||
          dirInfo.kind === "missing" ||
          (dirInfo.kind === "regular" && Boolean(outUuid));
        if (outgoingPreservable) {
          return await switchAccountViaRepoint(profile, tool, {
            configDir,
            dirKind,
            targetUuid: targetUuid!,
            outUuid,
            warnings,
            opts,
            store,
          });
        }
      }
    }
  }

  // BROKER CONVERGENCE BEFORE ANYTHING READS THE PROFILE'S CREDENTIAL. When
  // the target account is also live in another dir, this profile's parked copy
  // can be a SUPERSEDED PREDECESSOR of the account's current credential —
  // switching that stale copy in is precisely how the two-copies rotation race
  // used to start. Convergence pulls the newest rotation across every store
  // (central, snapshots, live dirs) under the account's cross-process lock, so
  // the health check below and `restoreClaudeAuthIntoDir` both act on the
  // credential of record. Best-effort: an unreadable sibling dir degrades to
  // the pre-broker behaviour, and the switch itself still proceeds.
  try {
    const targetUuid = profileAccountUuid(profile.dir, tool);
    if (targetUuid && isAccountUuid(targetUuid)) {
      convergeIdentityCredential(targetUuid, { tool, extraDirs: [configDir] });
    }
  } catch (error) {
    warnings.push(
      `credential convergence skipped: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Fail loudly on UNUSABLE auth before touching anything: a switch onto a dead
  // profile would strand the running session mid-conversation.
  //
  // "Expired" alone is not unusable, and treating it as such deadlocked the CLI
  // against itself — see the commit that introduced `renewable`. Claude Code
  // mints 8-hour access tokens and renews them in place, so on a fleet that
  // idles overnight most profiles read `expired` while holding a refresh token
  // good for weeks. A credential with no refresh token is still refused: that
  // one really is dead, and re-authenticating is the only answer.
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
      `"${profile.name}" has an aged-out access token${health.credentialExpiresAt ? ` (expired ${health.credentialExpiresAt})` : ""}; ` +
        `its refresh token is intact, so the tool renews it on the next request`,
    );
  }
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
    } else {
      // NO RESOLVABLE OWNER — PARK, NEVER DESTROY (bug 04a350a9, task
      // 61148ec0). `restoreClaudeAuthIntoDir` below overwrites the dir's live
      // credential wholesale, and a rotated-in refresh token exists nowhere
      // else, so warning-and-overwriting destroyed the outgoing login. Park
      // the bytes in a timestamped orphan snapshot instead; if parking THROWS,
      // the switch aborts here — before the marker write and the restore —
      // leaving the dir exactly as it was. Orphan snapshots are an interim
      // crash-net until the zero-copies invariant design (task aaf4c98f)
      // supersedes them.
      const parked = parkOrphanDirAuth(configDir, tool);
      if (parked) {
        warnings.push(
          `no profile could be identified as this dir's owner, so its outgoing credential was parked in ${parked} — ` +
            `recover it with \`accounts add\` + \`accounts login\`, or by restoring that file deliberately`,
        );
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

interface RepointContext {
  configDir: string;
  dirKind: SessionDirKind;
  targetUuid: string;
  outUuid?: string;
  warnings: string[];
  opts: SwitchAccountOptions;
  store: AccountsStore;
}

/**
 * The single-inode broker switch: preserve the outgoing account's in-place
 * refresh onto its central file, then atomically repoint the dir's
 * `.credentials.json` symlink at the incoming account's central file, and merge
 * the incoming identity into the dir's account file. Zero credential bytes are
 * copied and no central file is unlinked, so the switch cannot destroy a login
 * (design §4). Health is gated on the credential OF RECORD — the central file —
 * so a husked incoming account is refused before anything is touched.
 */
async function switchAccountViaRepoint(
  profile: Profile,
  tool: ToolDef,
  ctx: RepointContext,
): Promise<SwitchAccountResult> {
  const { configDir, dirKind, targetUuid, outUuid, warnings, opts, store } = ctx;

  const central = credentialHealth(centralCredentialsPath(targetUuid));
  if (!central.exists || central.refreshTokenLength === 0) {
    throw new AccountsError(
      `profile "${profile.name}" cannot take over this session — its central credential is missing or has no refresh token. ` +
        `Re-authenticate with \`accounts login ${profile.name}\` first.`,
    );
  }
  if (central.expiresAt <= Date.now()) {
    warnings.push(
      `"${profile.name}" has an aged-out access token; its refresh token is intact, so the tool renews it on the next request`,
    );
  }

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
  const previousEmail = dirOAuthEmail(configDir, tool);

  // Switching to the account the dir already carries: normalise onto the link
  // model (adopt any refresh fork, relink) and report a no-op.
  if (outUuid && outUuid.toLowerCase() === targetUuid.toLowerCase()) {
    withApplyLock(() => {
      migrateDirToLink(configDir, targetUuid);
      clearSwitchedAccountMarker(configDir);
    });
    return {
      profile,
      tool,
      configDir,
      dirKind,
      alreadyActive: true,
      ...(previousEmail ? { previousEmail } : {}),
      liveSessions,
      warnings,
      restartRequired: false,
      message: `${profile.name}${targetEmail ? ` (${targetEmail})` : ""} already owns this session's config dir — nothing to switch`,
    };
  }

  withApplyLock(() => {
    const result = repointDir(configDir, {
      ...(outUuid ? { fromUuid: outUuid } : {}),
      toUuid: targetUuid,
    });
    if (result.quarantined) {
      warnings.push(`outgoing credential preserved in ${result.quarantined}`);
    }
    // Per-key oauthAccount merge: the dir's account file names the incoming
    // account; every other key survives, and no credential bytes are written.
    applyProfileOAuthIdentityToDir(profile.dir, tool, configDir);
    // Occupancy is the symlink itself now (readlink), so a legacy
    // switched-account marker is vestigial and, left stale, mislabels the dir
    // (bug 1eadc484). Clear it.
    clearSwitchedAccountMarker(configDir);
  });

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
    ...(previousEmail ? { previousEmail } : {}),
    liveSessions,
    warnings,
    restartRequired: false,
    message: `${profile.name}${targetEmail ? ` (${targetEmail})` : ""} takes over this session on its next message — no restart needed`,
  };
}
