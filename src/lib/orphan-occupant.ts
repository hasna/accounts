import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  buildIdentityIndex,
  isUsableIdentity,
  type AccountIdentity,
  type AccountStatus,
} from "./identity-index.js";
import { isAccountUuid, syncProfileSnapshotToCentral } from "./auth-store.js";
import {
  dirCredentialsFile,
  listDirLiveSessions,
  profileAccountJsonPaths,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
} from "./claude-layout.js";
import {
  classifyCredentialFile,
  isRestorableState,
  parkedCredentialVerdict,
  profileCredentialLayers,
} from "./credential-state.js";
import { recoverParkedCredential, restoreOwnIdentityIntoLiveFiles } from "./claude-auth.js";
import { assertSafeWritePath } from "./safe-path.js";

/**
 * ORPHAN OCCUPANTS — accounts this machine holds credentials for but has no
 * name for.
 *
 * A profile dir is a DOOR, an account is the THING (see identity-index.ts).
 * A dir's `own-identity` door is its PARKED `.accounts-auth/oauth-account.json`;
 * its `current-occupant` door is whoever's account sits in the LIVE
 * `.claude.json`. An in-session `/login` to a second account inside a profile's
 * dir writes no switch marker and never parks anything, so the second account
 * acquires an occupant door and never an own-identity one.
 *
 * MEASURED CONSEQUENCE: such an account reports `status: ok` with `profiles: []`
 * — on this fleet the single healthiest account was in exactly that state. It
 * cannot be switched to, because switching goes through a PROFILE and applying
 * the host profile would apply the HOST's credential, landing on a different
 * account than the one chosen. And its credential exists in exactly one place,
 * a dir another profile claims to own.
 *
 * Adoption is the reconciliation: give the account its own profile, MOVE its
 * credential there, and hand the host dir back to the account it belongs to.
 */

export interface OrphanOccupantDoor {
  dir: string;
  profileName?: string;
}

export interface OrphanOccupant {
  accountUuid: string;
  email?: string;
  status: AccountStatus;
  /** Dirs whose LIVE files currently run as this account. */
  occupies: OrphanOccupantDoor[];
  /** Live sessions attached across every occupied dir. */
  liveSessions: number;
  /** Usable now, or after the tool renews an aged-out access token. */
  usable: boolean;
}

function occupantDoors(identity: AccountIdentity): OrphanOccupantDoor[] {
  return identity.doors
    .filter((d) => d.role === "current-occupant")
    .map((d) => ({ dir: d.dir, ...(d.profileName ? { profileName: d.profileName } : {}) }))
    .sort((a, b) => a.dir.localeCompare(b.dir));
}

function hasOwnIdentityDoor(identity: AccountIdentity): boolean {
  return identity.doors.some((d) => d.role === "own-identity");
}

function liveSessionCount(dirs: ReadonlyArray<string>): number {
  let total = 0;
  for (const dir of dirs) {
    try {
      total += listDirLiveSessions(dir).filter((s) => s.alive).length;
    } catch {
      // A dir we cannot inspect is not evidence of a session. It is also not
      // evidence of none, which is why every mutating path below re-reads this
      // and refuses on any count above zero rather than on a cached figure.
    }
  }
  return total;
}

/**
 * Every account that occupies at least one profile dir and is named by none.
 *
 * Accounts with an own-identity door are excluded even when they ALSO occupy
 * someone else's dir: they already have a name, and the fix for a stray
 * occupancy is `accounts repair-auth`, not a second profile.
 */
export function findOrphanOccupants(
  profiles: ReadonlyArray<{ name?: string; dir: string }>,
  tool: ToolDef,
): OrphanOccupant[] {
  return buildIdentityIndex(profiles, tool)
    .filter((identity) => !hasOwnIdentityDoor(identity))
    .map((identity) => ({ identity, occupies: occupantDoors(identity) }))
    .filter(({ occupies }) => occupies.length > 0)
    .map(({ identity, occupies }) => ({
      accountUuid: identity.accountUuid,
      ...(identity.email ? { email: identity.email } : {}),
      status: identity.status,
      occupies,
      liveSessions: liveSessionCount(occupies.map((o) => o.dir)),
      usable: isUsableIdentity(identity),
    }));
}

export type AdoptRefusal =
  | "not-applicable"
  | "unknown-account"
  | "ambiguous-selector"
  | "already-named"
  | "malformed-uuid"
  | "multiple-occupants"
  | "no-live-credential"
  | "sessions-live"
  | "host-would-be-stranded"
  | "name-taken";

export type HostRestore = "restored" | "host-needs-login";

export interface AdoptPlan {
  accountUuid: string;
  email?: string;
  profileName: string;
  /** The dir the credential is moved OUT of. */
  fromDir: string;
  fromProfile?: string;
  hostRestore: HostRestore;
}

export type AdoptResult =
  | { outcome: "adopted"; plan: AdoptPlan; profile: Profile; hostRestore: HostRestore; detail: string }
  | { outcome: "would-adopt"; plan: AdoptPlan; detail: string }
  | { outcome: "refused"; refusal: AdoptRefusal; detail: string };

export interface AdoptOptions {
  /** accountUuid or email of the occupant to adopt. */
  account: string;
  /** Name for the new profile. */
  name: string;
  tool?: string;
  dryRun?: boolean;
  /**
   * Proceed even though the host dir has no parked credential of its own and
   * will therefore need `accounts login` afterwards.
   */
  allowHostRelogin?: boolean;
}

function refuse(refusal: AdoptRefusal, detail: string): AdoptResult {
  return { outcome: "refused", refusal, detail };
}

function matches(identity: AccountIdentity, selector: string): boolean {
  const needle = selector.trim().toLowerCase();
  if (identity.accountUuid.toLowerCase() === needle) return true;
  return (identity.email ?? "").toLowerCase() === needle && needle.length > 0;
}

/** The occupant's identity record as written in the host dir's live account file. */
function liveIdentityRecord(dir: string, tool: ToolDef): Record<string, unknown> | undefined {
  for (const path of profileAccountJsonPaths(dir, tool)) {
    if (!existsSync(path)) continue;
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
      const oauth = parsed.oauthAccount;
      if (oauth && typeof oauth === "object") return oauth as Record<string, unknown>;
    } catch {
      continue;
    }
  }
  return undefined;
}

/**
 * Move a credential file. `renameSync` is preferred BECAUSE it is atomic: it
 * never leaves two copies of one credential in existence, not even for the
 * instant a copy-then-delete would. Refresh-token rotation between two copies
 * is the one confirmed credential-destroying path on this fleet, so the
 * cross-device fallback is the exception, taken only when rename cannot work.
 */
function moveCredential(from: string, to: string, stayUnder: string): void {
  assertSafeWritePath(to, { mustStayUnder: stayUnder });
  mkdirSync(dirname(to), { recursive: true });
  try {
    renameSync(from, to);
    return;
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code !== "EXDEV") throw error;
  }
  copyFileSync(from, to);
  rmSync(from, { force: true });
}

/**
 * Give an orphan-occupant account a profile of its own.
 *
 * ORDER IS LOAD-BEARING. Every guard runs before the first byte is written, so
 * a refusal never leaves a half-adopted state; and the host dir's identity is
 * restored BEFORE its credential, because `recoverParkedCredential` refuses a
 * dir whose live identity contradicts its parked one — which, until the
 * identity is put back, is exactly what this dir is.
 */
export async function adoptOrphanOccupant(
  opts: AdoptOptions,
  store: AccountsStore = resolveStore(),
): Promise<AdoptResult> {
  const toolId = opts.tool ?? "claude";
  // No fallback to the local builtin: if the active registry cannot resolve
  // the tool, adopting against a guessed definition would read the wrong
  // account file. Let the error surface.
  const tool = await store.resolveTool(toolId);
  if (tool.id !== "claude") {
    return refuse("not-applicable", `adoption reads Claude's auth layout and does not apply to ${tool.id}`);
  }

  const profiles = await store.listProfiles(toolId);
  if (profiles.some((p) => p.name === opts.name)) {
    // Checked here rather than left to `addProfile` so the refusal happens
    // before anything moves: a name clash discovered mid-adoption would have
    // to be unwound, and unwinding a credential move is the risk this avoids.
    return refuse("name-taken", `a ${toolId} profile named "${opts.name}" already exists`);
  }

  const index = buildIdentityIndex(
    profiles.map((p) => ({ name: p.name, dir: p.dir })),
    tool,
  );
  const found = index.filter((identity) => matches(identity, opts.account));
  if (found.length === 0) {
    return refuse("unknown-account", `no account on this machine matches "${opts.account}"`);
  }
  if (found.length > 1) {
    return refuse(
      "ambiguous-selector",
      `"${opts.account}" matches ${found.length} accounts (${found.map((f) => f.accountUuid).join(", ")}) — ` +
        "select by accountUuid",
    );
  }

  const identity = found[0]!;
  if (hasOwnIdentityDoor(identity)) {
    const named = [
      ...new Set(identity.doors.filter((d) => d.role === "own-identity" && d.profileName).map((d) => d.profileName!)),
    ].sort();
    // A second profile for one account means two dirs claiming to own one
    // credential, which refresh-token rotation resolves by destroying a copy.
    return refuse(
      "already-named",
      `account ${identity.email ?? identity.accountUuid} already has a profile of its own ` +
        `(${named.join(", ") || "an unnamed dir"}); it is not an orphan occupant`,
    );
  }

  const occupies = occupantDoors(identity);
  if (occupies.length === 0) {
    return refuse(
      "unknown-account",
      `account ${identity.accountUuid} occupies no profile dir on this machine, so there is nothing to adopt`,
    );
  }
  if (!isAccountUuid(identity.accountUuid)) {
    // The central store is keyed by uuid and its path helpers throw on
    // malformed values. Reporting a corrupt account is fine; adopting one is
    // not, and a throw here would read as a crash rather than a verdict.
    return refuse(
      "malformed-uuid",
      `account uuid "${identity.accountUuid}" is not well formed and cannot key the central auth store; ` +
        "the dir's .claude.json is corrupt",
    );
  }
  if (occupies.length > 1) {
    return refuse(
      "multiple-occupants",
      `account ${identity.email ?? identity.accountUuid} occupies ${occupies.length} dirs ` +
        `(${occupies.map((o) => o.profileName ?? o.dir).join(", ")}) — moving its credential out of one would ` +
        "leave the others presenting an account they no longer hold; reconcile them first",
    );
  }

  const host = occupies[0]!;
  const hostCredential = dirCredentialsFile(host.dir);
  const liveState = classifyCredentialFile(hostCredential);
  if (!isRestorableState(liveState.state)) {
    return refuse(
      "no-live-credential",
      `the dir ${host.profileName ?? host.dir} runs as this account but its credential is ${liveState.state}; ` +
        "adopting would create a profile with nothing in it",
    );
  }

  const live = liveSessionCount([host.dir]);
  if (live > 0) {
    // The same rule healSwitchedProfileDir and the usage hook's contention
    // check already apply. A refusal costs one deferred adoption and says so;
    // moving a credential out from under a running session costs the session
    // and possibly the credential.
    return refuse(
      "sessions-live",
      `${live} live session(s) are attached to ${host.profileName ?? host.dir} and are running as this account; ` +
        "adoption moves its credential out of that dir, so it waits until they exit",
    );
  }

  const hostLayers = profileCredentialLayers(host.dir, tool);
  const hostCanRecover =
    existsSync(profileOAuthSnapshot(host.dir)) && parkedCredentialVerdict(hostLayers).parkedRestorable;
  if (!hostCanRecover && !opts.allowHostRelogin) {
    return refuse(
      "host-would-be-stranded",
      `${host.profileName ?? host.dir} has no parked credential of its own, so moving this account's credential ` +
        "out would leave that profile with none. Re-authenticate it first (`accounts login " +
        `${host.profileName ?? "NAME"}\`), or accept the cost with --allow-host-relogin`,
    );
  }

  const oauthRecord = liveIdentityRecord(host.dir, tool);
  if (!oauthRecord) {
    return refuse(
      "unknown-account",
      `the dir ${host.profileName ?? host.dir} no longer carries a readable oauthAccount record`,
    );
  }

  const plan: AdoptPlan = {
    accountUuid: identity.accountUuid,
    ...(identity.email ? { email: identity.email } : {}),
    profileName: opts.name,
    fromDir: host.dir,
    ...(host.profileName ? { fromProfile: host.profileName } : {}),
    hostRestore: hostCanRecover ? "restored" : "host-needs-login",
  };

  if (opts.dryRun) {
    return {
      outcome: "would-adopt",
      plan,
      detail:
        `would move ${identity.email ?? identity.accountUuid}'s credential from ` +
        `${host.profileName ?? host.dir} into a new profile "${opts.name}"`,
    };
  }

  const profile = await store.addProfile({
    name: opts.name,
    tool: toolId,
    ...(identity.email ? { email: identity.email } : {}),
  });

  const adoptedCredential = profileCredentialsSnapshot(profile.dir);
  let moved = false;
  try {
    mkdirSync(profileAuthDir(profile.dir), { recursive: true });
    const snapshotPath = profileOAuthSnapshot(profile.dir);
    assertSafeWritePath(snapshotPath, { mustStayUnder: profile.dir });
    // Park the identity FIRST: it is what turns this dir into an own-identity
    // door, and it must be in place before the credential lands beside it so
    // the pair is never a credential with no account attached to it.
    writeFileSync(snapshotPath, JSON.stringify({ oauthAccount: oauthRecord }, null, 2) + "\n", { mode: 0o600 });

    moveCredential(hostCredential, adoptedCredential, profile.dir);
    moved = true;

    syncProfileSnapshotToCentral(profile.dir, tool);
  } catch (error) {
    // Unwind in reverse. The credential goes back FIRST — a registry row we
    // failed to delete is an annoyance, a credential left in neither dir is a
    // dead account.
    if (moved && existsSync(adoptedCredential)) {
      try {
        moveCredential(adoptedCredential, hostCredential, host.dir);
      } catch {
        throw new AccountsError(
          `adoption failed AND the credential could not be moved back; it is at ${adoptedCredential}`,
        );
      }
    }
    await store.removeProfile(opts.name, { tool: toolId }).catch(() => undefined);
    throw error;
  }

  // Hand the host dir back to the account that owns it. Identity first (see
  // restoreOwnIdentityIntoLiveFiles), then the guarded credential restore.
  let hostRestore: HostRestore = "host-needs-login";
  if (hostCanRecover && restoreOwnIdentityIntoLiveFiles(host.dir, tool)) {
    const recovery = recoverParkedCredential(host.dir, tool, host.profileName);
    if (recovery.outcome === "recovered") hostRestore = "restored";
  }

  return {
    outcome: "adopted",
    plan: { ...plan, hostRestore },
    profile,
    hostRestore,
    detail:
      `moved ${identity.email ?? identity.accountUuid}'s credential out of ` +
      `${host.profileName ?? host.dir} into profile "${opts.name}"` +
      (hostRestore === "restored"
        ? `; ${host.profileName ?? "the host dir"} is back on its own account`
        : `; ${host.profileName ?? "the host dir"} now needs \`accounts login\``),
  };
}
