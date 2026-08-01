import { randomUUID } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  CLAUDE_KEYCHAIN_SERVICE,
  listDirLiveSessions,
  liveClaudeBase,
  liveClaudePaths,
  profileAccountJsonPaths,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileKeychainSnapshot,
  profileOAuthSnapshot,
  profileSwitchedAccountMarker,
  profileUnreadableCredentialsDir,
  OAUTH_SNAPSHOT,
  dirCredentialsFile,
} from "./claude-layout.js";
import {
  describeCredentialState,
  isRestorableState,
  parkedCredentialVerdict,
  profileCredentialLayers,
  type ProfileCredentialLayers,
} from "./credential-state.js";
import {
  assertAllowedKeychainCredential,
  keychainSupported,
  readClaudeKeychain,
  type KeychainCredential,
  writeClaudeKeychain,
} from "./keychain.js";
import { assertSafeWritePath, writeFileAtomic } from "./safe-path.js";
import {
  betterCredential,
  centralCredentialsPathForProfile,
  centralOAuthRecordForProfile,
  credentialHealth,
  dirLiveIdentityIsForeign,
  dirLiveIdentityRelation,
  type CredentialHealthPresent,
  type SyncResult,
  syncProfileSnapshotToCentral,
} from "./auth-store.js";
import {
  accountGuestOccupantDoorsElsewhere,
  accountLiveDoorsElsewhere,
  buildIdentityIndex,
  type AccountIdentity,
} from "./identity-index.js";
import { listProfiles } from "./profiles.js";
import { accountsHome } from "../storage.js";

type JsonRecord = Record<string, unknown>;

export const CLAUDE_API_AUTH_ENV_KEYS = [
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "CLAUDE_CODE_API_KEY_HELPER",
  "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
] as const;

function readJsonFile(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as JsonRecord;
  } catch {
    return undefined;
  }
}

function writeJsonFile(path: string, data: JsonRecord, stayUnder?: string): void {
  // Atomic write: these files (account json, credentials, markers) are read
  // concurrently by running tools, and `writeFileSync`'s mode never tightens a
  // pre-existing file — writeFileAtomic chmods explicitly after the rename.
  writeFileAtomic(path, JSON.stringify(data, null, 2) + "\n", {
    mode: 0o600,
    ...(stayUnder ? { mustStayUnder: stayUnder } : {}),
  });
}

function readOAuthFromPaths(paths: string[]): JsonRecord | undefined {
  return findOAuthSource(paths)?.oauth;
}

function readOAuthSnapshot(profileDir: string): JsonRecord | undefined {
  const snap = readJsonFile(profileOAuthSnapshot(profileDir));
  const oauth = snap?.oauthAccount;
  return oauth && typeof oauth === "object" ? (oauth as JsonRecord) : undefined;
}

function profileCredentialFile(profileDir: string): string {
  return dirCredentialsFile(profileDir);
}

export interface SwitchedAccountMarker {
  profile: string;
  email?: string;
  switchedAt?: string;
}

/**
 * When present, the dir's live `.credentials.json`/`oauthAccount` belong to the
 * named OTHER profile (an in-place session switch), so snapshot refreshes from
 * those files would contaminate the dir's own profile and must be skipped.
 */
export function readSwitchedAccountMarker(dir: string): SwitchedAccountMarker | undefined {
  const raw = readJsonFile(profileSwitchedAccountMarker(dir));
  if (!raw || typeof raw.profile !== "string" || !raw.profile) return undefined;
  return {
    profile: raw.profile,
    ...(typeof raw.email === "string" && raw.email ? { email: raw.email } : {}),
    ...(typeof raw.switchedAt === "string" && raw.switchedAt ? { switchedAt: raw.switchedAt } : {}),
  };
}

export function writeSwitchedAccountMarker(dir: string, marker: SwitchedAccountMarker): void {
  const path = profileSwitchedAccountMarker(dir);
  assertSafeWritePath(path, { mustStayUnder: dir });
  mkdirSync(profileAuthDir(dir), { recursive: true });
  writeJsonFile(path, { ...marker, switchedAt: marker.switchedAt ?? new Date().toISOString() }, dir);
}

export function clearSwitchedAccountMarker(dir: string): void {
  const path = profileSwitchedAccountMarker(dir);
  if (existsSync(path)) unlinkSync(path);
}

/**
 * Is this profile dir currently CARRYING another account?
 *
 * The single occupancy question for READ paths — health reporting, and the
 * keychain secret a launch installs. Both used to ask it as "is a switch marker
 * present", and that was wrong in both directions.
 *
 * TOO NARROW: an in-session `/login` writes no marker at all. Measured on this
 * fleet 2026-07-29 — `.../profiles/claude/account006` carried `anya@ideawin.com`
 * with no marker and no parked identity of its own, and every marker-keyed
 * guard read straight past it.
 *
 * TOO BROAD: a marker left behind after the dir came back to its own account is
 * stale. `ensureProfileAuthSnapshot` and `healSwitchedProfileDir` already treat
 * a marker contradicted by the dir's live account as stale and delete it; a
 * read path that still believed it would report a healthy profile off its
 * parked copy while ignoring a perfectly good live credential.
 *
 * THE RULE. Identity decides when identity is legible: `foreign` is occupied,
 * `own` is not, and the marker does not get a vote either way. When identity is
 * NOT legible — no parked snapshot, or an unreadable live account file — there
 * is nothing to compare, so the marker is the only evidence there is and it
 * fails CLOSED. That keeps this predicate a superset of the marker-only rule it
 * replaces in every case except the one where identity positively disproves the
 * marker.
 *
 * `own-unknown` deliberately does NOT count as occupied on its own. A dir that
 * has never been snapshotted has no identity to be foreign TO; its live files
 * are the only truth it has. Treating first capture as occupation would report
 * every freshly imported profile as carrying someone else's account.
 */
export function profileDirCarriesForeignAccount(profileDir: string, tool?: ToolDef): boolean {
  const relation = dirLiveIdentityRelation(profileDir, tool);
  if (relation === "foreign") return true;
  if (relation === "own") return false;
  return existsSync(profileSwitchedAccountMarker(profileDir));
}

function profileHasOAuthAccount(profileDir: string, tool: ToolDef): boolean {
  return !!readOAuthSnapshot(profileDir) || !!readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool));
}

function profileHasCredentialPayload(profileDir: string): boolean {
  return (
    existsSync(profileCredentialFile(profileDir)) ||
    existsSync(profileCredentialsSnapshot(profileDir)) ||
    centralCredentialsPathForProfile(profileDir) !== undefined
  );
}

export function assertRestorableProfileAuth(profileDir: string, tool: ToolDef, profileName?: string): void {
  const label = profileName ?? "NAME";
  if (!profileHasOAuthAccount(profileDir, tool)) {
    throw new AccountsError(
      `profile "${label}" has no auth to apply — run \`accounts login ${label}\` then \`accounts detect ${label}\` first`,
    );
  }
  if (!profileHasCredentialPayload(profileDir)) {
    throw new AccountsError(
      `profile "${label}" has no Claude credentials to apply — run \`accounts login ${label}\` and complete /login first`,
    );
  }
}

function findOAuthSource(paths: string[]): { path: string; oauth: JsonRecord } | undefined {
  for (const p of paths) {
    const data = readJsonFile(p);
    const oauth = data?.oauthAccount;
    if (oauth && typeof oauth === "object") return { path: p, oauth: oauth as JsonRecord };
  }
  return undefined;
}

/** True when the snapshot is missing or strictly older than its source file. */
/**
 * Would copying `sourcePath` over `snapshotPath` destroy credential material?
 *
 * THE HOLE THIS CLOSES: the snapshot refresh above was ordered by MTIME alone,
 * and the newest write is not always a credential. When two config dirs hold one
 * account, the second one to refresh gets its token rotated out from under it
 * and Claude Code blanks its `.credentials.json` in place — a newer file
 * containing nothing. The mtime rule then copied that blank over the profile's
 * parked credential, which for a profile whose dir had already lost its live
 * copy was the ONLY remaining copy under that directory. Measured on this fleet:
 * one profile (account031) had already lost both its live file and its snapshot
 * this way, surviving only because the central store refused the same downgrade.
 *
 * The central store never had this hole — `syncCredentialsFile` in auth-store.ts
 * replaces central only with a strict `betterCredential` winner. This restores
 * the symmetry the comment above already claims: the two layers rank credentials
 * identically. `betterCredential` orders on refresh-token presence, then
 * usability, then mtime, so it subsumes the staleness rule rather than
 * contradicting it — a genuinely rotated token still wins, and a blank never
 * does.
 */
function wouldDowngradeSnapshot(sourcePath: string, snapshotPath: string): boolean {
  const source = credentialHealth(sourcePath);
  const snapshot = credentialHealth(snapshotPath);
  if (!snapshot.exists || !source.exists) return false;
  return betterCredential(source, snapshot) !== source;
}

function snapshotIsStale(sourcePath: string, snapshotPath: string): boolean {
  if (!existsSync(snapshotPath)) return true;
  try {
    return statSync(sourcePath).mtimeMs > statSync(snapshotPath).mtimeMs;
  } catch {
    return false;
  }
}

// credentialHealth/betterCredential live in auth-store.ts (the lower layer)
// so the central store and these read paths rank credentials identically.

/**
 * Best restorable credential snapshot for a profile: the per-profile copy vs
 * the central identity-keyed copy, `betterCredential` winner. Not "central
 * first" — during the 0.2.15/0.2.16 window an old binary may have rotated a
 * fresher token into the per-profile copy, and restoring a stale central one
 * would log the account out. `stayUnder` is the containment root for source
 * symlink checks on the winning path.
 */
function bestRestorableCredentialPath(
  profileDir: string,
  tool?: ToolDef,
): { path: string; stayUnder: string } | undefined {
  const candidates: { path: string; stayUnder: string }[] = [
    { path: profileCredentialsSnapshot(profileDir), stayUnder: profileDir },
  ];
  const central = centralCredentialsPathForProfile(profileDir, tool);
  if (central) candidates.push({ path: central, stayUnder: accountsHome() });
  const existing = candidates
    .filter((c) => existsSync(c.path) && !lstatSync(c.path).isSymbolicLink())
    .map((c) => ({ ...c, health: credentialHealth(c.path) }))
    .filter((c): c is typeof c & { health: CredentialHealthPresent } => c.health.exists);
  if (existing.length === 0) return undefined;
  const best = existing.reduce((a, b) => (betterCredential(a.health, b.health) === a.health ? a : b));
  return { path: best.path, stayUnder: best.stayUnder };
}

export function liveCredentialShouldUpdateProfile(profileDir: string): boolean {
  return sourceCredentialShouldUpdateProfile(liveClaudePaths().credentialsFile, profileDir);
}

/** True when `sourceCredentialsFile` holds a better credential than the profile already has. */
export function dirCredentialShouldUpdateProfile(sourceDir: string, profileDir: string): boolean {
  return sourceCredentialShouldUpdateProfile(profileCredentialFile(sourceDir), profileDir);
}

function sourceCredentialShouldUpdateProfile(sourceCredentialsFile: string, profileDir: string): boolean {
  const source = credentialHealth(sourceCredentialsFile);
  if (!source.exists) return false;

  const profileRoot = credentialHealth(profileCredentialFile(profileDir));
  const profileSnapshot = credentialHealth(profileCredentialsSnapshot(profileDir));
  const centralPath = centralCredentialsPathForProfile(profileDir);
  const profileCentral = centralPath ? credentialHealth(centralPath) : ({ exists: false } as const);
  const profileCreds = [profileRoot, profileSnapshot, profileCentral].filter(
    (c): c is Exclude<typeof c, { exists: false }> => c.exists,
  );
  if (profileCreds.length === 0) return true;

  const bestProfileCred = profileCreds.reduce((best, candidate) => betterCredential(best, candidate));
  return betterCredential(source, bestProfileCred) === source;
}

function mergeOAuthInto(
  paths: string[],
  oauth: JsonRecord | undefined,
  allowDelete: boolean,
  stayUnder?: string,
): void {
  const primary = paths[0];
  if (!primary) return;
  const data = readJsonFile(primary) ?? {};
  if (oauth) {
    data.oauthAccount = oauth;
    writeJsonFile(primary, data, stayUnder);
  } else if (allowDelete) {
    delete data.oauthAccount;
    writeJsonFile(primary, data, stayUnder);
  }
  if (paths[1] && paths[1] !== primary) {
    const parent = readJsonFile(paths[1]) ?? {};
    if (oauth) {
      parent.oauthAccount = oauth;
      writeJsonFile(paths[1], parent, stayUnder);
    } else if (allowDelete) {
      delete parent.oauthAccount;
      writeJsonFile(paths[1], parent, stayUnder);
    }
  }
}

function sanitizeSettingsFile(configDir: string, stayUnder: string): boolean {
  const settingsPath = join(configDir, "settings.json");
  const settings = readJsonFile(settingsPath);
  if (!settings) return false;

  let changed = false;
  if ("apiKeyHelper" in settings) {
    delete settings.apiKeyHelper;
    changed = true;
  }

  const env = settings.env;
  if (env && typeof env === "object" && !Array.isArray(env)) {
    const envRecord = env as JsonRecord;
    for (const key of CLAUDE_API_AUTH_ENV_KEYS) {
      if (key in envRecord) {
        delete envRecord[key];
        changed = true;
      }
    }
  }

  if (changed) writeJsonFile(settingsPath, settings, stayUnder);
  return changed;
}

export function sanitizeClaudeProfileApiSettings(profileDir: string, tool: ToolDef): boolean {
  if (tool.id !== "claude") return false;
  return sanitizeSettingsFile(profileDir, profileDir);
}

export function sanitizeClaudeOAuthProfileSettings(profileDir: string, tool: ToolDef): boolean {
  if (tool.id !== "claude") return false;
  if (!readOAuthSnapshot(profileDir) && !readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))) {
    return false;
  }
  return sanitizeClaudeProfileApiSettings(profileDir, tool);
}

export function sanitizeLiveClaudeOAuthSettings(): boolean {
  return sanitizeSettingsFile(liveClaudePaths().configDir, liveClaudeBase());
}

/** Email address of the account currently authenticated on the live Claude paths. */
export function liveOAuthEmail(): string | undefined {
  const live = liveClaudePaths();
  const oauth = readOAuthFromPaths([live.homeJson]);
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

/** Snapshot live Claude auth into a profile directory (used when switching away on apply). */
export function snapshotLiveAuthToProfile(profileDir: string, _tool: ToolDef): void {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  const live = liveClaudePaths();
  const oauth = readOAuthFromPaths([live.homeJson]);
  if (oauth) writeJsonFile(profileOAuthSnapshot(profileDir), { oauthAccount: oauth }, profileDir);

  if (existsSync(live.credentialsFile)) {
    const dest = profileCredentialsSnapshot(profileDir);
    assertSafeWritePath(dest, { mustStayUnder: profileDir });
    copyFileSync(live.credentialsFile, dest);

    if (keychainSupported()) {
      const kc = readClaudeKeychain();
      if (kc) writeJsonFile(profileKeychainSnapshot(profileDir), kc as unknown as JsonRecord, profileDir);
    }
  }

  syncProfileSnapshotToCentral(profileDir, _tool);
}

/** @deprecated Use snapshotLiveAuthToProfile */
export function snapshotClaudeAuthToProfile(profileDir: string, tool: ToolDef): void {
  snapshotLiveAuthToProfile(profileDir, tool);
}

/**
 * Snapshot the auth currently living in an arbitrary session config dir into a
 * profile's snapshot store (the in-place switch counterpart of
 * `snapshotLiveAuthToProfile`, for sessions not on the live default paths).
 */
export function snapshotDirAuthToProfile(sourceDir: string, tool: ToolDef, profileDir: string): void {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  const oauth = readOAuthFromPaths([join(sourceDir, tool.accountFile ?? ".claude.json")]);
  if (oauth) writeJsonFile(profileOAuthSnapshot(profileDir), { oauthAccount: oauth }, profileDir);

  const sourceCredentials = join(sourceDir, ".credentials.json");
  if (existsSync(sourceCredentials)) {
    const dest = profileCredentialsSnapshot(profileDir);
    assertSafeWritePath(dest, { mustStayUnder: profileDir });
    copyFileSync(sourceCredentials, dest);
  }

  syncProfileSnapshotToCentral(profileDir, tool);
}

/**
 * Put a dir's OWN parked identity back into its live account file, touching no
 * credential at all. Returns false when the dir has no parked identity to
 * restore.
 *
 * WHY THIS IS SEPARATE FROM `restoreClaudeAuthIntoDir`: that function restores
 * identity AND credential together, and begins by calling
 * `ensureProfileAuthSnapshot`, which re-reads the LIVE account file. On a dir
 * whose live files carry a foreign account, calling it first is the wrong
 * order — the live guest identity is newer than the park, so the refresh
 * overwrites the dir's own parked identity with the guest's, and every
 * downstream identity gate then compares the guest against itself and passes.
 *
 * Callers reconciling an occupied dir must restore the identity FIRST with
 * this, so the dir's live and own identities agree again, and only then hand
 * the credential question to the guarded `recoverParkedCredential`.
 */
export function restoreOwnIdentityIntoLiveFiles(profileDir: string, tool: ToolDef): boolean {
  const own = readOAuthSnapshot(profileDir);
  if (!own) return false;
  mergeOAuthInto(profileAccountJsonPaths(profileDir, tool), own, false, profileDir);
  return true;
}

/**
 * Restore a profile's auth into an arbitrary session config dir: the write half
 * of an in-place account switch. Merges `oauthAccount` into the dir's account
 * file (preserving unrelated session state) and installs the profile's
 * credential snapshot as the dir's live `.credentials.json`. A running Claude
 * session bound to the dir picks the new identity up on its next API request.
 */
export function restoreClaudeAuthIntoDir(
  profileDir: string,
  tool: ToolDef,
  targetDir: string,
  profileName?: string,
): void {
  ensureProfileAuthSnapshot(profileDir, tool);
  assertRestorableProfileAuth(profileDir, tool, profileName);

  const oauth =
    readOAuthSnapshot(profileDir) ??
    centralOAuthRecordForProfile(profileDir, tool) ??
    (readSwitchedAccountMarker(profileDir)
      ? undefined
      : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));
  if (!oauth) throw new AccountsError("profile has no OAuth account data to apply");

  const credSnap = bestRestorableCredentialPath(profileDir, tool);
  if (!credSnap) {
    throw new AccountsError(
      `profile "${profileName ?? "NAME"}" has no restorable Claude credential snapshot`,
    );
  }

  mkdirSync(targetDir, { recursive: true });

  // Validate EVERY write path before mutating anything: a refused credential
  // write (e.g. a symlinked target) must not leave the dir with a new
  // oauthAccount over the old credentials.
  const accountFile = join(targetDir, tool.accountFile ?? ".claude.json");
  const targetCredentials = join(targetDir, ".credentials.json");
  assertSafeWritePath(accountFile, { mustStayUnder: targetDir });
  assertSafeWritePath(targetCredentials, { mustStayUnder: targetDir });
  const credentialBytes = readFileSync(credSnap.path);

  sanitizeSettingsFile(targetDir, targetDir);
  mergeOAuthInto([accountFile], oauth, false, targetDir);
  // Atomic: the running session reads this file on every request.
  writeFileAtomic(targetCredentials, credentialBytes, { mode: 0o600, mustStayUnder: targetDir });
}

/**
 * If a profile's own dir was switched to another account (agreeing marker) and
 * no live session is using it, restore the profile's own auth so a fresh launch
 * runs as the profile it claims to be. Throws when live sessions still run on
 * the dir — yanking their identity out from under them is never right.
 */
export function healSwitchedProfileDir(profileDir: string, tool: ToolDef, profileName?: string): boolean {
  if (tool.id !== "claude") return false;
  const marker = readSwitchedAccountMarker(profileDir);
  if (!marker) return false;

  const liveEmailNow = readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))?.emailAddress;
  if (typeof liveEmailNow === "string" && liveEmailNow && marker.email && marker.email !== liveEmailNow) {
    // Stale marker (a later login changed the dir); normal flows own it again.
    clearSwitchedAccountMarker(profileDir);
    return false;
  }

  const live = listDirLiveSessions(profileDir).filter((s) => s.alive).length;
  if (live > 0) {
    throw new AccountsError(
      `profile "${profileName ?? "NAME"}" cannot launch: its config dir currently carries the account of "${marker.profile}" (in-place switch) with ${live} live session(s) attached. Switch the running session back first — accounts switch-account ${profileName ?? "NAME"} --dir ${profileDir}`,
    );
  }

  restoreClaudeAuthIntoDir(profileDir, tool, profileDir, profileName);
  clearSwitchedAccountMarker(profileDir);
  return true;
}

/** Reasons a restore is refused. Every one of them means nothing was written. */
export type ParkedRecoveryRefusal =
  | "no-parked-credential"
  | "identity-would-change"
  | "identity-unknown"
  /**
   * This same account's credential is currently live in a DIFFERENT directory.
   * Deliberately NOT folded into `identity-would-change`: that one is about the
   * dir showing somebody else's account, this one is about the account already
   * running somewhere else, and the operator's next move differs. Conflating
   * them sends them to `accounts switch-account`, which is the wrong tool here.
   */
  | "account-live-elsewhere"
  /**
   * The set of other config dirs could not be read, so a second live copy
   * cannot be ruled out. Fail CLOSED — the cost of a needless refusal is an
   * operator running the command again with a profile argument; the cost of a
   * needless restore is a revoked refresh token on an account with headroom.
   */
  | "cross-directory-unknown";

export type ParkedRecoveryOutcome =
  | "recovered"
  | "live-credential-usable"
  | "failed"
  | "not-applicable"
  | ParkedRecoveryRefusal;

/** What the planner decides, before anything is written. */
export type ParkedRecoveryPlanOutcome =
  | "would-recover"
  | "live-credential-usable"
  | "not-applicable"
  | ParkedRecoveryRefusal;

/**
 * Discriminated so the acting case cannot be constructed without the facts the
 * executor needs — the layers it is acting on and which parked layer wins. An
 * optional field there would put a `?? "absent"` in the executor's message and
 * make a missing plan detail look like a real credential state.
 */
export type ParkedRecoveryPlan =
  | {
      outcome: "would-recover";
      /** Operator-facing explanation, safe to print. */
      detail: string;
      layers: ProfileCredentialLayers;
      /** Parked layers that would serve the restore, best first. */
      restorableLayers: Array<"snapshot" | "central">;
    }
  | {
      outcome: Exclude<ParkedRecoveryPlanOutcome, "would-recover">;
      detail: string;
      layers?: ProfileCredentialLayers;
      /**
       * `account-live-elsewhere` ONLY: NO other dir that currently presents this
       * account is a guest — every one of them also owns it. Computed over the
       * UNFILTERED occupant-door set, which is the set the credential broker
       * actually writes to; see {@link accountGuestOccupantDoorsElsewhere} for
       * why the credential-state-filtered set is the wrong domain for a
       * write-safety gate.
       *
       * This does NOT soften the refusal — restoring a parked PREDECESSOR
       * credential stays refused either way, because the hazard it guards
       * (two DIFFERENT tokens, one revoked on the next rotation) is identical
       * for legitimate doors. It is published for callers deciding whether a
       * CONVERGENCE — which makes every copy hold the SAME token rather than a
       * second one — is safe here, and that question does turn on whether a
       * guest dir would be written through.
       */
      noGuestOccupantDoorsElsewhere?: boolean;
    };

export interface ParkedRecoveryResult {
  outcome: ParkedRecoveryOutcome;
  /** Operator-facing explanation, safe to print. */
  detail: string;
  layers?: ProfileCredentialLayers;
  /** See the identically named field on {@link ParkedRecoveryPlan}. */
  noGuestOccupantDoorsElsewhere?: boolean;
}

/** A config dir this machine knows about, from whichever registry the caller uses. */
export interface KnownProfileDir {
  name?: string;
  dir: string;
}

export interface ParkedRecoveryOptions {
  /**
   * Every profile dir to consider when asking "is this account live somewhere
   * else". Callers that already hold the profile list (the CLI, which may be
   * talking to a remote registry) should pass it: it avoids rebuilding the
   * identity index once per profile, and it is the only correct list when the
   * registry is not the local file. Omitted, the planner reads the LOCAL
   * registry itself — the launch path is synchronous and has no list to give.
   */
  profiles?: ReadonlyArray<KnownProfileDir>;
}

/**
 * How an outcome should be surfaced. Callers render from this rather than from
 * their own list of outcome strings, so a newly added outcome cannot be
 * silently invisible in the CLI — which for a refusal that blocks a destructive
 * run would read to the operator as "nothing to repair".
 */
export type ParkedRecoveryDisposition = "acted" | "blocked" | "quiet";

export function parkedRecoveryDisposition(
  outcome: ParkedRecoveryOutcome | ParkedRecoveryPlanOutcome,
): ParkedRecoveryDisposition {
  switch (outcome) {
    case "recovered":
    case "would-recover":
      return "acted";
    case "live-credential-usable":
    case "not-applicable":
      return "quiet";
    default:
      return "blocked";
  }
}

/**
 * Put a profile's own PARKED credential back into its dir when the dir's live
 * copy has been rotated away.
 *
 * THE GAP THIS FILLS: `healSwitchedProfileDir` above answers a narrower
 * question — "was this dir switched away, and can it be switched back" — and
 * returns false on its second line when there is no switch marker. A dir whose
 * own credential was rotated out from under it in place never had a marker, so
 * no CLI path reached it at all. Measured 2026-07-29: four of the six affected
 * profiles on this machine had no marker, and each was sitting on a parked
 * refresh token valid for another three to four weeks that nothing would use.
 * The operator's only remaining route was an interactive browser re-login.
 *
 * WHY LIVE SESSIONS DO NOT BLOCK THIS, WHERE THEY DO BLOCK `healSwitchedProfileDir`:
 * that function evicts a WORKING identity, so live sessions are a reason to
 * refuse. Here the live slot holds no working credential by definition — that is
 * the precondition. Restoring takes nothing away from the attached sessions; it
 * gives back the credential they lost. Five of the six affected dirs had live
 * sessions, so refusing on liveness would have made the recovery reach almost
 * nothing.
 *
 * WHAT IT WILL NOT DO: change which ACCOUNT the dir presents. When the dir
 * currently carries another account (an in-place switch) the parked credential
 * belongs to a different identity, and restoring it would swap the identity
 * under attached sessions. That is the eviction case, and it stays a deliberate
 * operator action (`accounts switch-account`), not something a launch does
 * silently.
 *
 * WHAT IT ALSO WILL NOT DO (defect bb267228): restore a park while that same
 * account is already live in ANOTHER directory. See `accountLiveDoorsElsewhere`.
 *
 * Nothing is deleted: the parked snapshot and the central store are read-only
 * here, and the only file overwritten is a live slot already proven to hold no
 * credential material.
 *
 * THIS FUNCTION DECIDES; IT DOES NOT WRITE. `recoverParkedCredential` is the
 * thin executor over it, and `--dry-run` calls this directly. One decision
 * function is the whole point: the previous split had the preview compute
 * `parkedCredentialVerdict` (pure content ranking, no identity gates at all)
 * while the real run applied the gates, so the preview promised recoveries the
 * command then refused. Do not reintroduce a second decision path.
 */
export function planParkedRecovery(
  profileDir: string,
  tool: ToolDef,
  profileName?: string,
  opts: ParkedRecoveryOptions = {},
): ParkedRecoveryPlan {
  if (tool.id !== "claude") {
    return { outcome: "not-applicable", detail: `parked-credential recovery is Claude-only, not ${tool.id}` };
  }

  const layers = profileCredentialLayers(profileDir, tool);
  if (isRestorableState(layers.live.state)) {
    return {
      outcome: "live-credential-usable",
      detail: `the dir's credential is ${describeCredentialState(layers.live.state)}; nothing to recover`,
      layers,
    };
  }

  const verdict = parkedCredentialVerdict(layers);
  if (!verdict.parkedRestorable) {
    return {
      outcome: "no-parked-credential",
      detail:
        `the dir's credential is ${describeCredentialState(layers.live.state)} and no parked copy can serve it ` +
        `(snapshot: ${describeCredentialState(layers.snapshot.state)}` +
        `${layers.central ? `, central store: ${describeCredentialState(layers.central.state)}` : ""}). ` +
        `Re-authentication is required: \`accounts login ${profileName ?? "NAME"}\`.`,
      layers,
    };
  }

  // Identity gate. The parked copy is the profile's OWN account; if the dir is
  // presenting someone else's, restoring changes who the dir is.
  //
  // The profile's own identity must be KNOWN, not merely not-contradicted.
  // `profileHasOAuthAccount` is satisfied by the LIVE `.claude.json`, which
  // after an in-place switch is the guest's, and `restoreClaudeAuthIntoDir`
  // falls back to that same live record when no snapshot exists. A profile
  // holding a parked credential but no parked IDENTITY would therefore have had
  // the guest's `oauthAccount` written next to this profile's credential —
  // pairing one account's identity with another account's token, which is the
  // precise failure the identity-index layering exists to prevent. Unknown
  // identity is a refusal, not a free pass.
  const own = readOAuthSnapshot(profileDir) ?? centralOAuthRecordForProfile(profileDir, tool);
  const ownUuid = typeof own?.accountUuid === "string" ? own.accountUuid.toLowerCase() : undefined;
  const liveUuidRaw = readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))?.accountUuid;
  const liveUuid = typeof liveUuidRaw === "string" ? liveUuidRaw.toLowerCase() : undefined;
  if (!ownUuid) {
    return {
      outcome: "identity-unknown",
      detail:
        `the dir's credential is ${describeCredentialState(layers.live.state)} and a parked copy exists, but this ` +
        `profile has no OAuth account snapshot of its own, so the parked credential cannot be attributed to an ` +
        `account. Restoring it would pair whatever identity the dir currently shows with this credential. ` +
        `Run \`accounts detect ${profileName ?? "NAME"}\` or re-authenticate.`,
      layers,
    };
  }
  if (liveUuid && ownUuid !== liveUuid) {
    const attached = listDirLiveSessions(profileDir).filter((s) => s.alive).length;
    return {
      outcome: "identity-would-change",
      detail:
        `the dir currently carries a different account after an in-place switch, and its credential is ` +
        `${describeCredentialState(layers.live.state)}. Restoring "${profileName ?? "this profile"}"'s own parked ` +
        `credential would change which account the dir presents` +
        `${attached > 0 ? `, with ${attached} live session(s) attached` : ""}, so it is left to an explicit ` +
        `\`accounts switch-account\`.`,
      layers,
    };
  }

  // CROSS-DIRECTORY GATE (defect bb267228). Everything above reasons about THIS
  // directory only, and the destructive case does not live in this directory:
  // the parked copy can be a SUPERSEDED PREDECESSOR of an account whose current
  // credential is alive in another dir. Restoring it puts two live copies of one
  // account on disk, and the next refresh revokes the loser server-side.
  //
  // Ordered AFTER the two identity checks on purpose: those are narrower
  // statements about this dir, they were here first, and reordering would change
  // which refusal an operator sees for a dir that is both switched away AND
  // duplicated. This gate is the last thing standing between the plan and a
  // write.
  const cross = crossDirectoryView(opts, tool);
  if (!cross.known) {
    return {
      outcome: "cross-directory-unknown",
      detail:
        `a parked copy is restorable, but the set of other config dirs could not be read (${cross.reason}), so ` +
        `whether this account is already live in another directory cannot be established. Restoring blind risks a ` +
        `second live copy, whose next token refresh revokes the first — refusing instead. Re-run once the profile ` +
        `registry is readable.`,
      layers,
    };
  }
  const liveElsewhere = accountLiveDoorsElsewhere(cross.index, ownUuid, profileDir);
  if (liveElsewhere.length > 0) {
    const where = liveElsewhere
      .map((door) => `${door.profileName ? `"${door.profileName}" (${door.dir})` : door.dir}`)
      .join(", ");
    return {
      outcome: "account-live-elsewhere",
      // Default-deny, and computed over the UNFILTERED occupant set rather
      // than `liveElsewhere`: the broker writes to every occupant door
      // regardless of its credential state, so a gate reading only the
      // restorable ones is blind to a guest dir holding a husk. Consumed only
      // by callers weighing a CONVERGENCE; the refusal itself is unconditional.
      noGuestOccupantDoorsElsewhere:
        accountGuestOccupantDoorsElsewhere(cross.index, ownUuid, profileDir).length === 0,
      detail:
        `this profile's parked credential belongs to an account that is ALREADY live in another config dir ` +
        `(${where}), so the parked copy is a superseded predecessor rather than the account's current credential. ` +
        `Restoring it would put two live copies of one account on disk, and the next token refresh revokes ` +
        `whichever loses the race. Nothing was written. Re-authenticate this profile ` +
        `(\`accounts login ${profileName ?? "NAME"}\`) if it needs its own account.`,
      layers,
    };
  }

  return {
    outcome: "would-recover",
    detail:
      `would restore this profile's own parked credential from the ${verdict.restorableLayers[0]} ` +
      `(the dir's copy is ${describeCredentialState(layers.live.state)})`,
    layers,
    restorableLayers: verdict.restorableLayers,
  };
}

/**
 * Resolve the cross-directory view, fail-closed.
 *
 * The launch path (`profileEnv`) is synchronous and holds no profile list, so
 * the planner reads the LOCAL registry itself when the caller supplies none.
 * `loadStore` is a single small JSON read and `buildIdentityIndex` reads a
 * handful of small files per profile — both already happen on this path via
 * `ensureSharedCapabilities` and the snapshot layers, so this is not a new class
 * of work. Any failure to read is `known: false`, never an exception and never
 * a free pass.
 */
function crossDirectoryView(
  opts: ParkedRecoveryOptions,
  tool: ToolDef,
): { known: true; index: AccountIdentity[] } | { known: false; reason: string } {
  try {
    // Every profile of every tool, not just this tool's: a Claude account can
    // be sitting live in a dir registered under another tool, and that copy
    // rotates tokens just the same. Dirs with no Claude files contribute
    // nothing, so the wider list only ever adds true positives.
    const profiles = opts.profiles ?? listProfiles();
    return { known: true, index: buildIdentityIndex(profiles, tool) };
  } catch (error) {
    return { known: false, reason: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Preserve an unrecognised live payload before recovery replaces the live slot.
 *
 * An unreadable file may be the first evidence of a credential-schema change or
 * a foreign writer, so it is not equivalent to a parsed, provably spent
 * `rotated-away` payload. Each incident gets its own byte-exact, mode-0600 copy.
 */
function preserveUnreadableLiveCredential(profileDir: string): string {
  const live = dirCredentialsFile(profileDir);
  assertSafeWritePath(live, { mustStayUnder: profileDir });
  const archiveDir = profileUnreadableCredentialsDir(profileDir);
  const timestamp = new Date().toISOString().replaceAll(":", "-");
  const archive = join(archiveDir, `${timestamp}-${randomUUID()}.bin`);
  const bytes = readFileSync(live);
  writeFileAtomic(archive, bytes, { mode: 0o600, mustStayUnder: profileDir });
  return archive;
}

export function recoverParkedCredential(
  profileDir: string,
  tool: ToolDef,
  profileName?: string,
  opts: ParkedRecoveryOptions = {},
): ParkedRecoveryResult {
  const plan = planParkedRecovery(profileDir, tool, profileName, opts);
  if (plan.outcome !== "would-recover") {
    // Every refusal outcome is identical between plan and execution BECAUSE the
    // decision was made in one place. That identity is what `--dry-run` relies
    // on; duplicating the gates into the preview is what let them drift.
    return {
      outcome: plan.outcome,
      detail: plan.detail,
      ...(plan.layers ? { layers: plan.layers } : {}),
      ...(plan.noGuestOccupantDoorsElsewhere !== undefined
        ? { noGuestOccupantDoorsElsewhere: plan.noGuestOccupantDoorsElsewhere }
        : {}),
    };
  }

  // NEVER THROWS. This runs inside `profileEnv`, which every launch surface goes
  // through, so a profile with incomplete auth must not take the launch down
  // with it — recovery is an improvement on the way past, not a precondition.
  // `restoreClaudeAuthIntoDir` throws for a profile with no OAuth account data,
  // and that profile still deserves to launch and reach its own error.
  let preservedUnreadable: string | undefined;
  try {
    if (plan.layers.live.state === "unreadable") {
      preservedUnreadable = preserveUnreadableLiveCredential(profileDir);
    }
    restoreClaudeAuthIntoDir(profileDir, tool, profileDir, profileName);
  } catch (error) {
    return {
      outcome: "failed",
      detail:
        `could not restore the parked credential: ${error instanceof Error ? error.message : String(error)}` +
        (preservedUnreadable ? `; preserved the unreadable prior live file at ${preservedUnreadable}` : ""),
      layers: plan.layers,
    };
  }
  // The dir now presents its own account again, so any marker is stale.
  if (readSwitchedAccountMarker(profileDir)) clearSwitchedAccountMarker(profileDir);
  return {
    outcome: "recovered",
    detail:
      `restored this profile's own parked credential from the ${plan.restorableLayers[0]} ` +
      `(the dir's copy was ${describeCredentialState(plan.layers.live.state)})` +
      (preservedUnreadable ? `; preserved the unreadable prior live file at ${preservedUnreadable}` : ""),
    layers: plan.layers,
  };
}

/**
 * Build auth snapshots from files already present in the profile config dir.
 * Snapshots are refreshed per-file whenever the source in the profile dir is
 * newer than the existing snapshot — a running tool rotates its OAuth tokens
 * in place, and restoring a login-time snapshot over rotated tokens logs the
 * account out (rotated-out refresh tokens are revoked server-side).
 */
export function ensureProfileAuthSnapshot(
  profileDir: string,
  tool: ToolDef,
  opts: { overwrite?: boolean } = {},
): SyncResult {
  const authDir = profileAuthDir(profileDir);
  assertSafeWritePath(join(authDir, OAUTH_SNAPSHOT), { mustStayUnder: profileDir });
  mkdirSync(authDir, { recursive: true });

  // A fresh login (overwrite) makes the dir's files the profile's truth again;
  // otherwise a switched-away dir holds ANOTHER profile's live auth, and
  // refreshing snapshots from it would overwrite this profile's real tokens.
  // A marker contradicted by the dir's live email is stale (e.g. an in-session
  // /login landed after the switch) — the dir's files are the truth again, so
  // the marker is dropped and the normal refresh resumes.
  if (opts.overwrite) clearSwitchedAccountMarker(profileDir);
  else {
    const marker = readSwitchedAccountMarker(profileDir);
    if (marker) {
      const liveEmailNow = readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool))?.emailAddress;
      const stale =
        typeof liveEmailNow === "string" && liveEmailNow && marker.email && marker.email !== liveEmailNow;
      if (stale) clearSwitchedAccountMarker(profileDir);
      else {
        sanitizeClaudeOAuthProfileSettings(profileDir, tool);
        // The dir's live files belong to another account, but the profile's
        // own snapshot is owner-true — still mirror it centrally.
        return syncProfileSnapshotToCentral(profileDir, tool);
      }
    }
  }

  // IDENTITY GATE (defect 0e7069a9), the symmetric counterpart to the one
  // `recoverParkedCredential` applies on the restore path. An in-session
  // `/login` to another account writes NO switch marker, so the marker branch
  // above never fires; both credentials are then healthy, `betterCredential` is
  // identity-blind, and the guest's newer file wins on mtime and replaces this
  // profile's parked copy. Ranking cannot separate two healthy credentials —
  // only identity can.
  //
  // READ ORDER IS LOAD-BEARING: this must be evaluated BEFORE the oauth
  // snapshot refresh below, because that refresh is precisely what overwrites
  // the profile's own identity with the guest's. Reading it afterwards would
  // compare the guest against itself and always pass.
  //
  // BOTH writes are gated, not just the credential one. Gating the credential
  // alone would still let the parked identity become the guest's, making `own`
  // equal `live` on the next call — a one-invocation delay, not a fix.
  //
  // `overwrite` is the deliberate rebinding path (`finalizeLogin`): it means
  // the dir's files are this profile's truth again, so it crosses the gate.
  const liveIdentityIsForeign = !opts.overwrite && dirLiveIdentityIsForeign(profileDir, tool);

  const oauthSource = findOAuthSource(profileAccountJsonPaths(profileDir, tool));
  const oauthSnap = profileOAuthSnapshot(profileDir);
  if (oauthSource && !liveIdentityIsForeign && (opts.overwrite || snapshotIsStale(oauthSource.path, oauthSnap))) {
    writeJsonFile(oauthSnap, { oauthAccount: oauthSource.oauth }, profileDir);
  }

  const credFile = profileCredentialFile(profileDir);
  const credSnap = profileCredentialsSnapshot(profileDir);
  if (
    existsSync(credFile) &&
    !liveIdentityIsForeign &&
    (opts.overwrite || snapshotIsStale(credFile, credSnap)) &&
    !wouldDowngradeSnapshot(credFile, credSnap)
  ) {
    assertSafeWritePath(credSnap, { mustStayUnder: profileDir });
    copyFileSync(credFile, credSnap);
  }

  sanitizeClaudeOAuthProfileSettings(profileDir, tool);
  // Write-new half of the compat window: every per-profile snapshot write is
  // mirrored into the central identity-keyed store.
  return syncProfileSnapshotToCentral(profileDir, tool);
}

export function profileHasAuth(profileDir: string, tool: ToolDef): boolean {
  return profileHasOAuthAccount(profileDir, tool) && profileHasCredentialPayload(profileDir);
}

export type ClaudeProfileAuthStatus = "ok" | "missing" | "expired" | "invalid" | "unknown";

export interface ClaudeProfileAuthHealth {
  status: ClaudeProfileAuthStatus;
  /** Usable as is: an unexpired credential carrying a refresh token. */
  valid: boolean;
  /**
   * Not valid, but recoverable: the access token aged out while the refresh
   * token is intact. Kept separate from `valid` so each caller picks its own
   * bar — `doctor` should still call this unhealthy and prompt a re-login,
   * while a session switch can accept it rather than refuse the only route out.
   */
  renewable: boolean;
  oauthAccountPresent: boolean;
  credentialPayloadPresent: boolean;
  credentialPayloadValid: boolean;
  credentialPayloadExpired: boolean;
  credentialExpiresAt?: string;
  keychainSnapshotPresent: boolean;
  snapshotPresent: boolean;
  /**
   * The dir's live files carry a DIFFERENT account than this profile's parked
   * identity, so every field above was computed from the profile's own parked
   * copy and the dir cannot launch as this profile until it is reconciled.
   * See {@link profileDirCarriesForeignAccount}.
   */
  dirOccupiedByAnotherAccount: boolean;
  reasons: string[];
}

interface CredentialPayloadReadiness {
  exists: boolean;
  parseableOauth: boolean;
  refreshTokenPresent: boolean;
  expired: boolean;
  expiresAt?: string;
  valid: boolean;
}

function credentialPayloadReadiness(path: string): CredentialPayloadReadiness {
  if (!existsSync(path)) {
    return {
      exists: false,
      parseableOauth: false,
      refreshTokenPresent: false,
      expired: false,
      valid: false,
    };
  }

  const health = credentialHealth(path);
  const raw = readJsonFile(path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") {
    return {
      exists: true,
      parseableOauth: false,
      refreshTokenPresent: false,
      expired: false,
      valid: false,
    };
  }

  const expiresAtMs = health.exists ? health.expiresAt : 0;
  const expired = expiresAtMs > 0 && expiresAtMs <= Date.now();
  const refreshTokenPresent = health.exists && health.refreshTokenLength > 0;
  const valid = refreshTokenPresent && expiresAtMs > Date.now();
  return {
    exists: true,
    parseableOauth: true,
    refreshTokenPresent,
    expired,
    ...(expiresAtMs > 0 ? { expiresAt: new Date(expiresAtMs).toISOString() } : {}),
    valid,
  };
}

/**
 * The profile's own account email: snapshot first (owner-true even when the
 * dir's live files were switched to another account), then the account file
 * unless a switch marker says those files belong to someone else.
 */
export function profileOAuthEmail(profileDir: string, tool: ToolDef): string | undefined {
  const snapshot = readOAuthSnapshot(profileDir);
  const oauth =
    snapshot ??
    (readSwitchedAccountMarker(profileDir) ? undefined : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

/** OAuth account email carried by a config dir's live account file, if any. */
export function dirOAuthEmail(dir: string, tool: ToolDef): string | undefined {
  const oauth = readOAuthFromPaths([join(dir, tool.accountFile ?? ".claude.json")]);
  const email = oauth?.emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

export function claudeProfileAuthHealth(
  profileDir: string,
  tool: ToolDef,
  opts: { restoreView?: boolean } = {},
): ClaudeProfileAuthHealth {
  if (tool.id !== "claude") {
    return {
      status: "unknown",
      valid: false,
      renewable: false,
      oauthAccountPresent: false,
      credentialPayloadPresent: false,
      credentialPayloadValid: false,
      credentialPayloadExpired: false,
      keychainSnapshotPresent: false,
      snapshotPresent: false,
      // Occupancy is a Claude in-place-switch concept; for other tools the
      // honest answer is "not applicable", and `false` is how that reads here.
      dirOccupiedByAnotherAccount: false,
      reasons: [`auth validation is only available for Claude profiles, not ${tool.id}`],
    };
  }

  const oauthAccountPresent = profileHasOAuthAccount(profileDir, tool);
  const centralCredentialPath = centralCredentialsPathForProfile(profileDir, tool);

  // WHOSE CREDENTIAL IS THE DIR'S LIVE ONE? When the dir carries another
  // account, `<dir>/.credentials.json` is the OCCUPANT's token and says nothing
  // about this profile. Reading it here reported the guest's health as the
  // host's: measured 2026-07-29, three occupied dirs (account003, account004,
  // account030) returned `ok`/valid from a foreign unexpired token while their
  // own parked copies were merely renewable — and `accounts launch account004`
  // returned rc=1 at the same moment. Readiness said healthy; launch refused.
  //
  // This exclusion used to be conditional on `opts.restoreView`, which is why
  // the default view — the one `getAccountsReadiness` uses — never applied it.
  // The distinction was never real: "is this profile healthy" and "can this
  // profile's auth be restored" have the same answer once the occupant's
  // credential is out of the comparison, because it was never this profile's
  // credential to begin with. `restoreView` is kept as an additional OR term so
  // no caller ever gets a LESS conservative answer than before.
  const dirOccupiedByAnotherAccount = profileDirCarriesForeignAccount(profileDir, tool);
  const excludeLiveCredential =
    dirOccupiedByAnotherAccount || Boolean(opts.restoreView && readSwitchedAccountMarker(profileDir));
  const credentialPaths = excludeLiveCredential
    ? [profileCredentialsSnapshot(profileDir), ...(centralCredentialPath ? [centralCredentialPath] : [])]
    : [
        profileCredentialFile(profileDir),
        profileCredentialsSnapshot(profileDir),
        ...(centralCredentialPath ? [centralCredentialPath] : []),
      ];
  const credentials = credentialPaths.map((path) => credentialPayloadReadiness(path));
  const existingCredentials = credentials.filter((credential) => credential.exists);
  // A file that exists but carries no OAuth payload — `{}` is the shape this
  // fleet produced — holds no credential. Counting it as "present" made the
  // profile unreadable rather than unauthenticated: expiry could not be
  // determined, so the verdict came back `unknown` instead of `missing`, and a
  // pool manager reading "no verdict" neither quarantined it nor asked anyone
  // to log in. Presence is about the payload, not the inode.
  const credentialPayloadPresent = existingCredentials.some((credential) => credential.parseableOauth);
  const validCredential = existingCredentials.find((credential) => credential.valid);
  const expiredCredential = existingCredentials.find((credential) => credential.expired);
  // Not usable as is, but still holding a refresh token: the tool renews this on
  // use. Deliberately NOT gated on `expired`, because a payload with no recorded
  // expiry is also unusable-as-is and also renewable — gating on the timestamp
  // classified those as an unknown dead end and took live accounts out of every
  // pool that reads this.
  const renewableCredential = existingCredentials.find(
    (credential) => credential.refreshTokenPresent && !credential.valid,
  );
  const parseableInvalidCredential = existingCredentials.find(
    (credential) => credential.parseableOauth && !credential.refreshTokenPresent,
  );
  const keychainSnapshotPresent = existsSync(profileKeychainSnapshot(profileDir));
  const snapshotPresent = hasAuthSnapshot(profileDir);

  // Reasons name the STATE and the LAYER, because "credential payload is
  // expired" was reported for every one of these and sent three separate
  // investigations to study token lifetimes when the answer was custody. An
  // operator needs to know whether to wait (the tool renews it), restore
  // (a parked copy survives) or re-authenticate (nothing survives) — and those
  // are three different actions behind one old message.
  const layers = profileCredentialLayers(profileDir, tool);
  const verdict = parkedCredentialVerdict(layers);
  const reasons: string[] = [];
  if (dirOccupiedByAnotherAccount) {
    // Said FIRST and said even when the verdict is otherwise clean: without it
    // an operator reads a renewable profile and concludes it can launch, which
    // is the contradiction that started this. Everything below describes this
    // profile's OWN parked credential, so the sentence has to establish that.
    reasons.push(
      "this dir's live files currently carry another account (in-place switch, or an in-session login); " +
        "the credential state below is this profile's OWN parked copy, not the occupant's",
    );
  }
  if (!oauthAccountPresent) reasons.push("OAuth account snapshot is missing");
  if (!credentialPayloadPresent) reasons.push("credential payload is missing");
  if (!validCredential) {
    // `layers.live` is the OCCUPANT's file on an occupied dir, so its state is
    // not a fact about this profile and must not be narrated as one.
    if (!dirOccupiedByAnotherAccount && layers.live.state === "rotated-away") {
      reasons.push(
        verdict.parkedRestorable
          ? `this dir's credential was ${describeCredentialState("rotated-away")}, and a restorable copy is ` +
            `parked in the ${verdict.restorableLayers.join(" and ")} — recoverable without re-authenticating`
          : `this dir's credential was ${describeCredentialState("rotated-away")} and no parked copy survives`,
      );
    }
    if (expiredCredential && renewableCredential) {
      reasons.push("access token aged out; the refresh token is intact and the tool renews it on use");
    } else if (expiredCredential) {
      reasons.push("credential payload is expired");
    }
    if (parseableInvalidCredential && (dirOccupiedByAnotherAccount || layers.live.state !== "rotated-away")) {
      reasons.push("credential payload has no refresh token");
    }
  }
  if (credentialPayloadPresent && !validCredential && !expiredCredential && !parseableInvalidCredential) {
    reasons.push("credential payload expiry is unknown");
  }

  let status: ClaudeProfileAuthStatus = "ok";
  if (!oauthAccountPresent || !credentialPayloadPresent) status = "missing";
  else if (!validCredential && expiredCredential) status = "expired";
  else if (!validCredential && parseableInvalidCredential) status = "invalid";
  else if (!validCredential) status = "unknown";

  return {
    status,
    valid: status === "ok",
    renewable: status !== "ok" && oauthAccountPresent && Boolean(renewableCredential),
    oauthAccountPresent,
    credentialPayloadPresent,
    credentialPayloadValid: Boolean(validCredential),
    credentialPayloadExpired: !validCredential && Boolean(expiredCredential),
    ...(validCredential?.expiresAt ?? expiredCredential?.expiresAt
      ? { credentialExpiresAt: validCredential?.expiresAt ?? expiredCredential?.expiresAt }
      : {}),
    keychainSnapshotPresent,
    snapshotPresent,
    dirOccupiedByAnotherAccount,
    reasons,
  };
}

function profileCredentialSource(path: string):
  | { secret: string; health: { exists: true; expiresAt: number; refreshTokenLength: number; mtimeMs: number } }
  | undefined {
  if (!existsSync(path) || lstatSync(path).isSymbolicLink()) return undefined;
  const secret = readFileSync(path, "utf8").trim();
  if (!secret) return undefined;
  const health = credentialHealth(path);
  return health.exists ? { secret, health } : undefined;
}

function profileFileCredentialSecret(profileDir: string): string | undefined {
  // An occupied dir's root credential belongs to another account; only the
  // snapshot (and the central copy of the profile's own account, whose binding
  // resolves through that snapshot) still holds this profile's own tokens.
  //
  // THIS IS A READ WITH A WRITE CONSEQUENCE, which is why it is in scope here
  // alongside the reporting fix: the value returned is what
  // `prepareClaudeProfileKeychain` installs into the machine keychain AS THIS
  // PROFILE. Asking the marker-only question let an in-session `/login` — which
  // writes no marker — put the guest's secret into the host's keychain slot,
  // crossing one account's credential into another's identity. The identity
  // test catches the unmarked case; the marker still decides when identity is
  // illegible.
  const central = centralCredentialsPathForProfile(profileDir);
  const paths = profileDirCarriesForeignAccount(profileDir)
    ? [profileCredentialsSnapshot(profileDir), ...(central ? [central] : [])]
    : [profileCredentialsSnapshot(profileDir), profileCredentialFile(profileDir), ...(central ? [central] : [])];
  const sources = paths
    .map((path) => profileCredentialSource(path))
    .filter((source): source is NonNullable<typeof source> => !!source);
  if (sources.length === 0) return undefined;
  return sources.reduce((best, candidate) =>
    betterCredential(candidate.health, best.health) === candidate.health ? candidate : best,
  ).secret;
}

function profileKeychainSnapshotAccount(profileDir: string): string | undefined {
  const kcRaw = readJsonFile(profileKeychainSnapshot(profileDir));
  if (!kcRaw || typeof kcRaw.account !== "string") return undefined;
  try {
    assertAllowedKeychainCredential({
      service: CLAUDE_KEYCHAIN_SERVICE,
      account: kcRaw.account,
      secret: "metadata-only",
    });
    return kcRaw.account;
  } catch {
    return undefined;
  }
}

function assertKeychainSnapshotAllowed(profileDir: string): KeychainCredential | undefined {
  const kcRaw = readJsonFile(profileKeychainSnapshot(profileDir));
  if (!kcRaw || typeof kcRaw.secret !== "string" || typeof kcRaw.account !== "string") return undefined;
  const cred = {
    service: typeof kcRaw.service === "string" ? kcRaw.service : CLAUDE_KEYCHAIN_SERVICE,
    account: kcRaw.account,
    secret: kcRaw.secret,
  };
  assertAllowedKeychainCredential(cred);
  return {
    service: CLAUDE_KEYCHAIN_SERVICE,
    account: cred.account,
    secret: cred.secret,
  };
}

export function claudeKeychainCredentialFromProfile(
  profileDir: string,
  profileName?: string,
): KeychainCredential | undefined {
  const fileSecret = profileFileCredentialSecret(profileDir);
  if (!fileSecret) return assertKeychainSnapshotAllowed(profileDir);
  const cred = {
    service: CLAUDE_KEYCHAIN_SERVICE,
    account: profileKeychainSnapshotAccount(profileDir) ?? profileName ?? "claude",
    secret: fileSecret,
  };
  assertAllowedKeychainCredential(cred);
  return cred;
}

export function prepareClaudeProfileKeychain(profileDir: string, tool: ToolDef, profileName?: string): boolean {
  if (tool.id !== "claude" || !keychainSupported()) return false;
  try {
    ensureProfileAuthSnapshot(profileDir, tool);
    const cred = claudeKeychainCredentialFromProfile(profileDir, profileName);
    if (!cred) return false;
    writeClaudeKeychain(cred);
    return true;
  } catch {
    return false;
  }
}

/** Restore profile auth snapshots onto live Claude paths. */
export function restoreClaudeAuthFromProfile(
  profileDir: string,
  tool: ToolDef,
  profileName?: string,
): void {
  ensureProfileAuthSnapshot(profileDir, tool);
  assertRestorableProfileAuth(profileDir, tool, profileName);

  const live = liveClaudePaths();
  const liveRoot = liveClaudeBase();
  mkdirSync(live.configDir, { recursive: true });

  const oauth =
    readOAuthSnapshot(profileDir) ??
    centralOAuthRecordForProfile(profileDir, tool) ??
    (readSwitchedAccountMarker(profileDir)
      ? undefined
      : readOAuthFromPaths(profileAccountJsonPaths(profileDir, tool)));

  if (!oauth) {
    throw new AccountsError("profile has no OAuth account data to apply");
  }

  sanitizeClaudeOAuthProfileSettings(profileDir, tool);
  sanitizeLiveClaudeOAuthSettings();

  assertSafeWritePath(live.homeJson, { mustStayUnder: liveRoot });
  mergeOAuthInto([live.homeJson], oauth, false, liveRoot);

  const credSnap = bestRestorableCredentialPath(profileDir, tool);
  if (credSnap) {
    assertSafeWritePath(live.credentialsFile, { mustStayUnder: liveRoot });
    assertSafeWritePath(credSnap.path, { mustStayUnder: credSnap.stayUnder });
    copyFileSync(credSnap.path, live.credentialsFile);
    writeFileSync(live.credentialsFile, readFileSync(live.credentialsFile), { mode: 0o600 });
  } else if (existsSync(live.credentialsFile)) {
    if (!lstatSync(live.credentialsFile).isSymbolicLink()) unlinkSync(live.credentialsFile);
  }

  prepareClaudeProfileKeychain(profileDir, tool, profileName);
}

export function hasAuthSnapshot(profileDir: string): boolean {
  return (
    existsSync(profileOAuthSnapshot(profileDir)) ||
    existsSync(profileCredentialsSnapshot(profileDir)) ||
    existsSync(profileKeychainSnapshot(profileDir))
  );
}
