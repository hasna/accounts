import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";
import {
  CREDENTIALS_SNAPSHOT,
  OAUTH_SNAPSHOT,
  dirCredentialsFile,
  profileAccountJsonPaths,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
} from "./claude-layout.js";
import { centralAuthRoot, isAccountUuid, profileAccountUuid } from "./auth-store.js";
import { classifyCredentialFile, isRestorableState, type CredentialState } from "./credential-state.js";
import { canonicalConfigDir, sameConfigDir } from "./safe-path.js";

/**
 * UUID-keyed account enumeration. Directories are DOORS; accounts are the
 * THING: several profile dirs routinely hold the same OAuth account (imports,
 * in-place switches), so anything that reasons about quota, selection, or
 * "switch to a fresh account" must be keyed on `oauthAccount.accountUuid` —
 * a directory-keyed selector can "switch" between two doors of the same
 * exhausted account and report success while nothing changed.
 *
 * All reads go through this module so the auth-store migration (per-profile
 * `.accounts-auth/` → central `~/.hasna/accounts/auth/<accountUuid>/`, task
 * 7840d1da) changes ONE implementation, not call sites: the central home is
 * read first, per-profile stores remain as fallback for the compat window.
 */

export type AccountDoorRole = "own-identity" | "current-occupant";

export interface AccountDoor {
  dir: string;
  role: AccountDoorRole;
  profileName?: string;
  email?: string;
  /**
   * `own-identity` doors only: the uuid of the account whose credential is
   * CURRENTLY in the dir's live files, when that is somebody else. Absent when
   * the dir runs as its owner, and absent when the dir has no live occupant at
   * all — "parked and idle" is not the same fact as "squatted".
   *
   * Occupancy is recorded per DOOR, never as a scalar on the account, because
   * an account with two doors can be displaced from one and serving from the
   * other; a single flag would have to be wrong about one of them.
   */
  occupiedBy?: string;
}

export type CredentialSource = "central" | "profile-snapshot" | "dir-live";

export interface AccountCredentialRef {
  /** File holding the claudeAiOauth payload; the token itself is read lazily. */
  path: string;
  source: CredentialSource;
  expiresAt: number;
  hasAccessToken: boolean;
  hasRefreshToken: boolean;
  /** Usable AS IS: an unexpired access token. */
  valid: boolean;
  /**
   * Usable AFTER the tool renews it: a refresh token is present, so an aged-out
   * access token is a stale artefact rather than a dead account.
   *
   * Measured on this fleet 2026-07-29: Claude Code mints 8-hour access tokens
   * and renews them IN PLACE. One profile dir was observed holding
   * `expiresAt = 05:43:02Z` at 05:23Z and `expiresAt = 13:38:04Z` at 05:38Z —
   * same file, same account, a fresh 8-hour token written over the old one
   * without any operator action. An access token past its expiry therefore says
   * nothing about whether the account works; only the refresh token does.
   *
   * `renewable` never OUTRANKS `valid` anywhere it is consumed: it widens the
   * usable set, it does not reorder it.
   */
  renewable: boolean;
}

/**
 * A credential-LIVENESS verdict, and nothing else.
 *
 *   ok             an unexpired access token; usable right now
 *   needs-refresh  access token aged out, refresh token intact — the tool
 *                  renews it on the next request; nothing for an operator to do
 *   expired        no usable access token AND no refresh token: genuinely dead,
 *                  re-authentication is the fix
 *   no-credentials no credential file pairs with this uuid in any store
 *
 * `needs-refresh` exists because its absence was a measured incident. On
 * 2026-07-29 six of twelve accounts on this fleet reported `expired` from
 * `accounts usage`; every one of them held a refresh token and was alive, and
 * the owner acted on the report. Access tokens live 8 hours and a fleet that
 * idles overnight has most of its parked copies past expiry at any moment, so
 * "the access token aged out" is the NORMAL state of a healthy parked account —
 * spelling it with the same word as "dead" makes the common case indistinguishable
 * from the emergency. `credential-state.ts` already drew this exact line for the
 * per-file view (`needs-refresh` vs `unusable`); this is the account-level view
 * of it, and the two now agree.
 *
 * `expired` only ever NARROWS as a result: an account that reads `expired` after
 * this change would have read `expired` before it, so the word became more true
 * and never appears anywhere new.
 *
 * Occupancy is deliberately NOT a member of this union. Whether another account
 * currently squats a dir is orthogonal to whether this account's credential is
 * alive — all four combinations occur — so it is reported on `AccountDoor`
 * instead. Folding it in here would re-create the same defect from the other
 * side, hiding liveness behind occupancy.
 */
export type AccountStatus = "ok" | "needs-refresh" | "expired" | "no-credentials";

/**
 * Operator-facing gloss for a status, safe to print (never a token value).
 *
 * Lives here rather than in the CLI for the same reason
 * `describeCredentialState` lives in `credential-state.ts`: the words are the
 * part that was wrong, so they belong somewhere a test can read them without
 * spawning a process. A status word with no gloss is what sent an operator to
 * re-authenticate a live account.
 *
 * The switch is exhaustive over `AccountStatus` with no `default`, so adding a
 * member to the union fails the typecheck here instead of silently printing a
 * bare identifier.
 */
export function describeAccountStatus(status: AccountStatus): string {
  switch (status) {
    case "ok":
      return "usable now";
    case "needs-refresh":
      return "access token aged out, refresh token intact — the tool renews it on use";
    case "expired":
      return "no refresh token — re-authentication required";
    case "no-credentials":
      return "no credential file in any store";
  }
}

/**
 * The liveness verdict for a credential that cannot serve a session AS IS.
 *
 * Shared by `buildIdentityIndex` and by the usage collector's mid-flight
 * downgrade so there is exactly ONE place that decides whether "no usable access
 * token" means `needs-refresh` or `expired`. It was two places, and the second
 * one said `expired` unconditionally — the same conflation, one layer up, in a
 * branch no public-API test can reach (it needs the credential file to be
 * rewritten between the index scan and the token read, which is what a
 * concurrent refresh or park actually does). Making it a call to a tested
 * function is how that branch gets correctness it cannot get from a test.
 */
export function statusWithoutValidAccessToken(credential?: AccountCredentialRef): AccountStatus {
  if (!credential) return "no-credentials";
  return credential.renewable ? "needs-refresh" : "expired";
}

/** True when the status is one an operator has to act on. */
export function statusNeedsOperator(status: AccountStatus): boolean {
  return status === "expired" || status === "no-credentials";
}

export interface AccountIdentity {
  accountUuid: string;
  email?: string;
  doors: AccountDoor[];
  /** Best credential across every store that pairs with this uuid. */
  credential?: AccountCredentialRef;
  status: AccountStatus;
}

// Central store paths are owned by auth-store.ts (which also validates uuids
// on the write side); this module only re-exports them for its callers.
export { centralAuthDir, centralAuthRoot } from "./auth-store.js";

type JsonRecord = Record<string, unknown>;

function readJson(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as JsonRecord) : undefined;
  } catch {
    return undefined;
  }
}

interface OAuthIdentity {
  accountUuid: string;
  email?: string;
}

function oauthIdentityFrom(record: JsonRecord | undefined): OAuthIdentity | undefined {
  const oauth = record?.oauthAccount;
  if (!oauth || typeof oauth !== "object") return undefined;
  const { accountUuid, emailAddress } = oauth as JsonRecord;
  if (typeof accountUuid !== "string" || !accountUuid) return undefined;
  return {
    // Lowercase well-formed uuids so case-variant spellings of one account
    // dedupe into a single identity; malformed values pass through as-is —
    // they are still shown to diagnostics, but must never reach the central
    // path helpers (which throw): guard with isAccountUuid first.
    accountUuid: isAccountUuid(accountUuid) ? accountUuid.toLowerCase() : accountUuid,
    ...(typeof emailAddress === "string" && emailAddress ? { email: emailAddress } : {}),
  };
}

function credentialRef(path: string, source: CredentialSource): AccountCredentialRef | undefined {
  const raw = readJson(path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return undefined;
  const record = oauth as JsonRecord;
  const hasAccessToken = typeof record.accessToken === "string" && record.accessToken.length > 0;
  const hasRefreshToken = typeof record.refreshToken === "string" && record.refreshToken.length > 0;
  const expiresAtRaw = record.expiresAt;
  const expiresAt =
    typeof expiresAtRaw === "number"
      ? expiresAtRaw
      : typeof expiresAtRaw === "string"
        ? Date.parse(expiresAtRaw)
        : 0;
  const normalizedExpiry = Number.isFinite(expiresAt) ? expiresAt : 0;
  return {
    path,
    source,
    expiresAt: normalizedExpiry,
    hasAccessToken,
    hasRefreshToken,
    valid: hasAccessToken && normalizedExpiry > Date.now(),
    renewable: hasRefreshToken,
  };
}

/**
 * Can this account take a session over — now, or after the tool renews it?
 *
 * An aged-out access token is not a verdict of unusable: on a fleet that idles
 * overnight it is the majority state (access tokens live 8 hours). Excluding
 * those shrinks the switch pool exactly when unattended sessions need it, so the
 * pool is "valid OR renewable" and ranking — not filtering — keeps valid
 * credentials first.
 *
 * A credential with no refresh token is still unusable. That distinction is the
 * whole point: `needs-refresh` and `expired` are different verdicts.
 */
export function isUsableIdentity(identity: AccountIdentity): boolean {
  // Status-led on purpose, so this is a strict SUPERSET of the rule it
  // replaces (`status === "ok"`): everything that was usable stays usable, and
  // the aged-out-but-refreshable case is added. A widening fix must not be able
  // to narrow anything by accident.
  if (identity.status === "ok") return true;
  if (identity.status === "needs-refresh") return true;
  // Retained deliberately. `buildIdentityIndex` can no longer produce
  // `expired` together with a renewable credential — that pair is now spelled
  // `needs-refresh` — but identities are also constructed by callers and tests
  // that have not been re-spelled, and dropping this leg would NARROW the usable
  // set for them. Keeping it makes the change a superset of both the old rule
  // and the new one, which is the invariant stated above.
  return identity.status === "expired" && identity.credential?.renewable === true;
}

const SOURCE_RANK: Record<CredentialSource, number> = { central: 3, "profile-snapshot": 2, "dir-live": 1 };

/**
 * Valid beats invalid; later expiry beats earlier; central store breaks ties.
 *
 * Deliberately DIFFERENT from auth-store's `betterCredential`: this ranking
 * answers "which credential can a caller USE right now" (selection), while
 * `betterCredential` answers "which bytes must SURVIVE a sync/restore"
 * (refresh-token presence and write recency first, because restoring a
 * rotated-out refresh token logs the account out). Do not unify them.
 */
function betterCredentialRef(a: AccountCredentialRef, b: AccountCredentialRef): AccountCredentialRef {
  if (a.valid !== b.valid) return a.valid ? a : b;
  if (a.expiresAt !== b.expiresAt) return a.expiresAt > b.expiresAt ? a : b;
  if (a.hasRefreshToken !== b.hasRefreshToken) return a.hasRefreshToken ? a : b;
  return SOURCE_RANK[a.source] >= SOURCE_RANK[b.source] ? a : b;
}

interface MutableIdentity {
  accountUuid: string;
  email?: string;
  doors: AccountDoor[];
  credential?: AccountCredentialRef;
}

function record(
  byUuid: Map<string, MutableIdentity>,
  identity: OAuthIdentity,
  door: AccountDoor | undefined,
  credential: AccountCredentialRef | undefined,
): void {
  let entry = byUuid.get(identity.accountUuid);
  if (!entry) {
    entry = { accountUuid: identity.accountUuid, doors: [] };
    byUuid.set(identity.accountUuid, entry);
  }
  if (!entry.email && identity.email) entry.email = identity.email;
  if (door && !entry.doors.some((d) => d.dir === door.dir && d.role === door.role)) {
    entry.doors.push(door);
  }
  if (credential) {
    entry.credential = entry.credential ? betterCredentialRef(entry.credential, credential) : credential;
  }
}

/**
 * Enumerate every account we know about, deduplicated by accountUuid.
 *
 * Identity/credential pairing is per LAYER — each layer pairs an identity file
 * with the credential file written alongside it, so a dir whose live files were
 * switched to another account can never attribute the guest's token to the
 * dir's own uuid:
 *  - central:   auth/<uuid>/oauth-account.json + auth/<uuid>/credentials.json
 *  - snapshot:  .accounts-auth/oauth-account.json + .accounts-auth/credentials.json
 *  - dir-live:  .claude.json#oauthAccount + .credentials.json
 */
export function buildIdentityIndex(
  profiles: ReadonlyArray<{ name?: string; dir: string }>,
  tool: ToolDef,
): AccountIdentity[] {
  const byUuid = new Map<string, MutableIdentity>();

  // Central home first: the post-migration source of truth, and the only
  // place that knows accounts with no profile door at all.
  const centralRoot = centralAuthRoot();
  if (existsSync(centralRoot)) {
    for (const entry of readdirSync(centralRoot)) {
      // Strict-uuid parity with listCentralAccounts: a planted non-uuid dir
      // must not become an identity (and must never reach path helpers that
      // throw on malformed uuids).
      if (!isAccountUuid(entry)) continue;
      const dir = join(centralRoot, entry);
      try {
        if (!statSync(dir).isDirectory()) continue;
      } catch {
        continue;
      }
      const identity = oauthIdentityFrom(readJson(join(dir, OAUTH_SNAPSHOT)));
      // The store writes lowercased dir names; tolerate case-variant payloads.
      if (!identity || identity.accountUuid !== entry.toLowerCase()) continue;
      record(byUuid, identity, undefined, credentialRef(join(dir, CREDENTIALS_SNAPSHOT), "central"));
    }
  }

  for (const profile of profiles) {
    const { dir } = profile;
    if (!existsSync(dir)) continue;

    // Layer A — whoever's account currently occupies the dir's live files.
    // Read BEFORE layer B so the owner's door can record that it is displaced;
    // both layers are read from the same profile layout in one pass, so this is
    // a reordering rather than a second profile scan.
    let occupant: OAuthIdentity | undefined;
    for (const path of profileAccountJsonPaths(dir, tool)) {
      occupant = oauthIdentityFrom(readJson(path));
      if (occupant) break;
    }

    // Layer B — the dir's OWN identity (survives in-place switches away).
    //
    // A newly registered profile can legitimately have only live auth: no
    // legacy per-profile snapshot and no central mirror yet. In that first-
    // capture state the live identity is also the profile binding, so expose an
    // own-identity door for selectors to switch through. `profileAccountUuid`
    // owns the binding rule and fails closed when a switch marker exists, so a
    // switched guest is never promoted from current occupant to profile owner.
    const snapshotOwn = oauthIdentityFrom(readJson(profileOAuthSnapshot(dir)));
    const own =
      snapshotOwn ??
      (occupant && profileAccountUuid(dir, tool) === occupant.accountUuid ? occupant : undefined);
    if (own) {
      // Squatted only when someone else is actually in the dir. No occupant is
      // "parked and idle", and the owner occupying its own dir is the normal
      // case — neither is displacement.
      const displacedBy =
        occupant && occupant.accountUuid !== own.accountUuid ? occupant.accountUuid : undefined;
      record(
        byUuid,
        own,
        {
          dir,
          role: "own-identity",
          ...(profile.name ? { profileName: profile.name } : {}),
          ...(own.email ? { email: own.email } : {}),
          ...(displacedBy ? { occupiedBy: displacedBy } : {}),
        },
        snapshotOwn
          ? credentialRef(profileCredentialsSnapshot(dir), "profile-snapshot")
          : credentialRef(dirCredentialsFile(dir), "dir-live"),
      );
    }

    if (occupant) {
      record(
        byUuid,
        occupant,
        {
          dir,
          role: "current-occupant",
          ...(profile.name ? { profileName: profile.name } : {}),
          ...(occupant.email ? { email: occupant.email } : {}),
        },
        credentialRef(join(dir, ".credentials.json"), "dir-live"),
      );
    }
  }

  return [...byUuid.values()]
    .map((entry) => ({
      accountUuid: entry.accountUuid,
      ...(entry.email ? { email: entry.email } : {}),
      doors: entry.doors,
      ...(entry.credential ? { credential: entry.credential } : {}),
      // Three bits, three words. `valid` (usable now) and `renewable` (usable
      // after the tool refreshes it) are both already computed per credential;
      // before this, only the first reached the status and every renewable
      // parked copy was labelled dead. See AccountStatus.
      status: entry.credential
        ? entry.credential.valid
          ? "ok"
          : statusWithoutValidAccessToken(entry.credential)
        : "no-credentials",
    }))
    .sort((a, b) => a.accountUuid.localeCompare(b.accountUuid));
}

export interface LiveAccountDoor {
  dir: string;
  profileName?: string;
  /** State of that dir's live `.credentials.json` — never a token value. */
  state: CredentialState;
}

/**
 * Other directories whose LIVE slot is currently serving `accountUuid`.
 *
 * WHY THIS EXISTS: restoring a parked credential into a dir while another dir
 * already runs the same account puts TWO live copies of one credential on disk,
 * and the next refresh rotates the token — revoking whichever copy loses the
 * race, server-side and irreversibly. That is the confirmed destructive hazard
 * in this area, and no gate asked about it: `recoverParkedCredential`'s identity
 * check only compared the dir's own live identity against the profile's own, so
 * a profile holding a SUPERSEDED PREDECESSOR of an account that is alive
 * elsewhere passed straight through. Measured 2026-07-29: three profiles on this
 * fleet were in exactly that shape, and `repair-auth` with no profile argument
 * attempts every profile, so a single blanket run would have taken out all
 * three working copies.
 *
 * LIVENESS, NOT DOOR EXISTENCE. A door whose live credential is itself a husk
 * holds nothing that a rotation could revoke, and refusing on those would strand
 * an account with no working copy anywhere — the exact recovery this feature was
 * built for. So the filter is `isRestorableState`, not "a door exists".
 *
 * Directory identity is `sameConfigDir`, the same canonicalisation profile
 * creation uses. Comparing raw strings would let a symlinked alias of one
 * directory read as two, and read a dir as being in conflict with itself.
 */
export function accountLiveDoorsElsewhere(
  index: ReadonlyArray<AccountIdentity>,
  accountUuid: string,
  excludeDir: string,
): LiveAccountDoor[] {
  const wanted = accountUuid.toLowerCase();
  // Match case-insensitively: `buildIdentityIndex` lowercases well-formed uuids
  // but passes malformed ones through verbatim, and a malformed uuid must not
  // silently fall out of the gate.
  const identity = index.find((entry) => entry.accountUuid.toLowerCase() === wanted);
  if (!identity) return [];

  const seen = new Set<string>();
  const live: LiveAccountDoor[] = [];
  for (const door of identity.doors) {
    // Only the CURRENT OCCUPANT of a dir can be rotated by that dir's tool. A
    // dir that merely has the account parked in `.accounts-auth/` is not
    // running it and takes part in no rotation race.
    if (door.role !== "current-occupant") continue;
    if (sameConfigDir(door.dir, excludeDir)) continue;
    // Dedupe on the CANONICAL path, matching the exclusion above: two registry
    // entries spelling one directory differently are one door, not two.
    const canonical = canonicalConfigDir(door.dir);
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    const state = classifyCredentialFile(dirCredentialsFile(door.dir)).state;
    if (!isRestorableState(state)) continue;
    live.push({
      dir: door.dir,
      ...(door.profileName ? { profileName: door.profileName } : {}),
      state,
    });
  }
  return live;
}

/**
 * Other dirs currently PRESENTING this account that do not OWN it — guests
 * carrying it after an in-place switch, or dirs whose own binding is unreadable.
 *
 * DELIBERATELY UNFILTERED BY CREDENTIAL STATE, unlike `accountLiveDoorsElsewhere`
 * above, and that difference is the entire point of this function existing
 * separately rather than being a flag on that one.
 *
 * The two answer different questions over different domains:
 *
 *   - `accountLiveDoorsElsewhere` asks "could a token rotation revoke a WORKING
 *     copy somewhere else", so it rightly drops doors holding nothing
 *     restorable — a husk cannot be revoked.
 *   - this asks "would a write REACH a dir that another account owns", and the
 *     broker's `enumerateCopies` adds a `dir-live` write target for EVERY
 *     `current-occupant` door with no state filter whatsoever
 *     (`credential-broker.ts`, the `dirLiveCopy` branch). A guest dir whose own
 *     credential happens to be a husk is therefore still a write target.
 *
 * A gate built on the FILTERED set is blind to exactly those dirs while the
 * write set still contains them — measured: a guest dir holding a husk was
 * written through while the gate reported no guests present. The gate and the
 * write set must range over the same doors, so this one ranges over all of them.
 *
 * Ownership is decided the same way the index builds roles: a dir OWNS this
 * account when it also carries an `own-identity` door for it. A dir with no
 * such door is not this account's — fail closed and report it as a guest.
 */
export function accountGuestOccupantDoorsElsewhere(
  index: ReadonlyArray<AccountIdentity>,
  accountUuid: string,
  excludeDir: string,
): string[] {
  const wanted = accountUuid.toLowerCase();
  const identity = index.find((entry) => entry.accountUuid.toLowerCase() === wanted);
  if (!identity) return [];

  const seen = new Set<string>();
  const guests: string[] = [];
  for (const door of identity.doors) {
    if (door.role !== "current-occupant") continue;
    if (sameConfigDir(door.dir, excludeDir)) continue;
    const canonical = canonicalConfigDir(door.dir);
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    const owns = identity.doors.some(
      (other) => other.role === "own-identity" && sameConfigDir(other.dir, door.dir),
    );
    if (!owns) guests.push(door.dir);
  }
  return guests;
}

/**
 * The accountUuid currently occupying a config dir's live account file.
 *
 * ITERATES EVERY CANDIDATE PATH, exactly as `buildIdentityIndex`'s layer A
 * does (see the `occupant` loop above) — same order, same first-match-wins
 * precedence. It must, because `profileAccountJsonPaths` returns a SECOND path
 * — the PARENT `.claude.json` — precisely when the dir is `tool.defaultDir`,
 * which is the standard Claude layout (claude-layout.ts:48).
 *
 * Reading only `paths[0]` made this function DISAGREE WITH THE ENUMERATOR on
 * the default dir: the index still raised a door for it, while the predicate
 * reported "no account here". While the predicate only gated WRITES that was
 * latent — the dir merely could not receive. Once it also gates SOURCES, the
 * disagreement means the live default dir cannot DONATE either, and
 * convergence for a single-account default layout silently degrades to "no
 * restorable credential copy". With a stale sibling present it is worse than a
 * no-op: the stale copy is crowned and written to central with a FRESH mtime,
 * and since `betterCredential` tie-breaks on mtime it then durably outranks
 * the genuinely fresher live credential.
 */
export function dirAccountUuid(dir: string, tool: ToolDef): string | undefined {
  for (const path of profileAccountJsonPaths(dir, tool)) {
    const identity = oauthIdentityFrom(readJson(path));
    if (identity) return identity.accountUuid;
  }
  return undefined;
}

/**
 * The account's current access token, or undefined when none is valid. Read
 * lazily from the winning credential file so index building never holds
 * secrets in memory longer than a caller needs.
 */
export function accessTokenForAccount(identity: AccountIdentity): string | undefined {
  if (!identity.credential?.valid) return undefined;
  const raw = readJson(identity.credential.path);
  const oauth = raw?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return undefined;
  const token = (oauth as JsonRecord).accessToken;
  return typeof token === "string" && token ? token : undefined;
}
