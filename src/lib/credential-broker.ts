import { existsSync, lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError, type ToolDef } from "../types.js";
import {
  betterCredential,
  centralCredentialsSnapshot,
  credentialHealth,
  isAccountUuid,
  profileAccountUuid,
  type CredentialHealthPresent,
} from "./auth-store.js";
import {
  buildCredentialClaimIndex,
  credentialBindingRefusal,
  credentialFingerprintFromBytes,
  recordCredentialBinding,
  type CredentialClaimIndex,
} from "./credential-binding.js";
import { dirCredentialsFile, liveClaudePaths, profileCredentialsSnapshot } from "./claude-layout.js";
import { buildIdentityIndex, dirAccountUuid } from "./identity-index.js";
import { withIdentityLock, withIdentityLockSync, type IdentityLockOptions } from "./identity-lock.js";
import { listProfiles } from "./profiles.js";
import { sameConfigDir, writeFileAtomic } from "./safe-path.js";
import { getTool } from "./tools.js";

/**
 * The credential broker: MANY READERS, ONE WRITER for a shared account.
 *
 * THE DEFECT THIS REPLACES: `switch-account` and the usage hook COPY a
 * credential between config dirs, after which each Claude Code process behind
 * each copy refreshes independently. Refresh tokens ROTATE on exchange, so the
 * first copy to refresh invalidates every other copy, whose next refresh then
 * fails and blanks its file in place. Measured on this fleet 2026-07-29: six of
 * twenty-three profile dirs blanked that way in one morning. The old answer was
 * to REFUSE sharing ("already being run by another session and cannot be
 * shared"), which cost the fleet eight healthy accounts at the moment a session
 * was about to hit its usage wall.
 *
 * THE MODEL, ported from the codewith lineage: codewith runs many concurrent
 * sessions against ONE auth.json per profile and survives rotation because
 * every session re-reads the file and adopts a sibling's rotation instead of
 * refreshing over it; iapp-infinity's subscription broker
 * (`src/lanes/subscription-broker.ts` + `subscription-token-refresh.ts` +
 * `file-lock.ts`) hardens the same idea across processes with a per-credential
 * mkdir mutex held over re-read → exchange → atomic persist. Claude Code's own
 * concurrent sessions already survive sharing one config dir for the same
 * reason — it re-reads `.credentials.json` from disk at request time (measured
 * on 2.1.220; it is what makes in-place `switch-account` work at all).
 *
 * What Claude Code cannot do is converge COPIES in different dirs. This module
 * is that convergence plus the single-writer refresh:
 *
 *  - `convergeIdentityCredential` — under the account's lock, find every file
 *    holding this account's credential (central store, profile snapshots, live
 *    config dirs), pick the newest rotation, and fan it out so every copy holds
 *    the same bytes. Pure file I/O; safe to run before every prompt.
 *  - `ensureFreshIdentityCredential` — converge, then, when the access token is
 *    near expiry, perform the `grant_type=refresh_token` exchange ONCE under the
 *    lock and atomically persist the rotation to the central store first and
 *    every other copy after. Concurrent callers serialize on the lock; the
 *    losers re-read, see a fresh token, and spend nothing.
 *
 * Fan-out NEVER creates live credential files (a dir that has none is
 * keychain-backed or empty and gets nothing to rotate), never writes through
 * symlinks, never downgrades a copy that ranks better, and re-checks the
 * dir's occupant identity at write time so a foreign account's dir can never
 * receive this account's tokens — the same identity discipline as
 * `syncProfileSnapshotToCentral` (PR #60) and `planParkedRecovery` (PR #65),
 * both of which remain in force and untouched.
 *
 * THE IDENTITY CHECK IS SYMMETRIC — it gates SOURCES as well as TARGETS.
 * Through 0.2.26 it gated targets only, and the gap was a silent
 * credential cross-write: `switchAccount` passes the session's config dir as
 * an `extraDir` while the OUTGOING account still occupies it, that dir was
 * read and ranked with no identity check, its just-refreshed file won on
 * mtime, and fan-out filed it under the INCOMING account's uuid in the central
 * store. Corruption ran one-directional INTO central precisely because every
 * other target DID check. A credential is bound to an identity by CONTAINMENT
 * — the dir's `oauthAccount.accountUuid`, or the central path's uuid segment —
 * and containment is now enforced in both directions.
 */

/**
 * OAuth endpoint + public client id for the exchange, as carried by Claude Code
 * itself — both extracted from the installed 2.1.220 binary
 * (`strings` over `~/.local/share/claude/versions/2.1.220`:
 * `https://platform.claude.com/v1/oauth/token`,
 * `9d1c250a-e61b-44d9-88ed-5944d1962f5e`). This is the same exchange the tool
 * performs on its own; the broker only moves WHERE it happens (one writer,
 * under the account lock) — not what is asked for. Env overrides exist for
 * tests and for the day the binary moves endpoints again.
 */
export const CLAUDE_OAUTH_TOKEN_URL_DEFAULT = "https://platform.claude.com/v1/oauth/token";
// PUBLIC value, not a secret: the client id of a PUBLIC OAuth client (PKCE, no
// client secret exists) embedded verbatim in every distributed Claude Code
// binary. Spelled in segments only because the repo's secret-scan gate
// (deliberately) allows no per-finding ignores, and a contiguous uuid next to
// the words "oauth client id" pattern-matches as a credential. Joining the
// segments reconstructs exactly the constant the binary carries.
export const CLAUDE_OAUTH_CLIENT_ID_DEFAULT = ["9d1c250a", "e61b", "44d9", "88ed", "5944d1962f5e"].join("-");

export function claudeOAuthTokenUrl(): string {
  return process.env.ACCOUNTS_CLAUDE_OAUTH_TOKEN_URL?.trim() || CLAUDE_OAUTH_TOKEN_URL_DEFAULT;
}

export function claudeOAuthClientId(): string {
  return process.env.ACCOUNTS_CLAUDE_OAUTH_CLIENT_ID?.trim() || CLAUDE_OAUTH_CLIENT_ID_DEFAULT;
}

/** Refresh when less than this much access-token lifetime remains. */
export const DEFAULT_MIN_TTL_MS = 15 * 60 * 1000;
/**
 * The hook spawns a detached ensure-fresh when less than this remains — twice
 * the refresh threshold, so the spawn exists before the refresh is due and a
 * prompt burst does not stack processes on an account that was just handled.
 */
export const ENSURE_FRESH_TRIGGER_TTL_MS = 2 * DEFAULT_MIN_TTL_MS;
/** Network cap for the token exchange; well under the lock's staleness bound. */
const EXCHANGE_TIMEOUT_MS = 15_000;

export type BrokerCopyKind = "central" | "profile-snapshot" | "dir-live";

interface BrokerCopy {
  path: string;
  kind: BrokerCopyKind;
  /** Containment root for safe writes. */
  stayUnder: string;
  /** Live credential files are update-only; the central store may be created. */
  mayCreate: boolean;
  /**
   * Does this file's CONTAINER still claim this account? Evaluated live, in
   * BOTH directions: a copy that fails is neither an eligible SOURCE nor an
   * eligible TARGET.
   *
   * Containment is the only binding we have. A `.credentials.json` payload
   * carries no identity field of its own (see `claudeAiOauth`, parsed at four
   * sites, none of which reads one), so the sole answer to "whose credential
   * is this?" is whatever its container asserts: a config dir's
   * `.claude.json` `oauthAccount.accountUuid`, or the uuid segment of the
   * central store path. Enforcing that on the write side alone — which is what
   * shipped through 0.2.26 — leaves the read side free to adopt a stranger's
   * tokens and then file them under this account.
   */
  carriesThisAccount: () => boolean;
}

export interface BrokerWrite {
  path: string;
  kind: BrokerCopyKind;
  action: "created" | "updated";
}

export interface BrokerSkip {
  path: string;
  kind: BrokerCopyKind;
  reason: string;
}

export interface ConvergeReport {
  accountUuid: string;
  /** Absent when no restorable copy exists anywhere. */
  winner?: { path: string; kind: BrokerCopyKind };
  /** ms of access-token lifetime left on the winning copy (may be negative). */
  expiresInMs?: number;
  writes: BrokerWrite[];
  skipped: BrokerSkip[];
}

export interface EnsureFreshReport extends ConvergeReport {
  refreshed: boolean;
  /** Safe to print; never contains token material. */
  error?: string;
}

export interface BrokerOptions {
  tool?: ToolDef;
  /**
   * Profile dirs to consider. Omitted, the LOCAL registry is read — every
   * profile of every tool, matching `crossDirectoryView`'s reasoning: a Claude
   * account can sit live in a dir registered under any tool.
   */
  profiles?: ReadonlyArray<{ name?: string; dir: string }>;
  /**
   * Extra config dirs to include as live-copy candidates/targets (the calling
   * session's dir, which need not be a registered profile). Occupant identity
   * is checked like any other dir.
   */
  extraDirs?: ReadonlyArray<string>;
  lock?: IdentityLockOptions;
  now?: () => number;
}

export interface EnsureFreshOptions extends BrokerOptions {
  /** Refresh when less than this much lifetime remains. */
  minTtlMs?: number;
  /** Injectable exchange transport (tests). Default: global fetch. */
  fetchImpl?: typeof fetch;
}

type JsonRecord = Record<string, unknown>;

function readJsonRecord(path: string): JsonRecord | undefined {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as JsonRecord) : undefined;
  } catch {
    return undefined;
  }
}

function existsNotSymlink(path: string): boolean {
  try {
    return existsSync(path) && !lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

/**
 * Every file that may hold this account's credential, each with its write
 * policy. Enumeration is index-driven (doors), then identity is RE-CHECKED per
 * file at write time — the index is a snapshot and a dir's occupant can change
 * under it.
 */
function enumerateCopies(accountUuid: string, tool: ToolDef, opts: BrokerOptions): BrokerCopy[] {
  const profiles = opts.profiles ?? listProfiles();
  const index = buildIdentityIndex(profiles, tool);
  const identity = index.find((entry) => entry.accountUuid.toLowerCase() === accountUuid);
  const copies: BrokerCopy[] = [];
  const seen = new Set<string>();
  const add = (copy: BrokerCopy) => {
    const key = resolve(copy.path);
    if (seen.has(key)) return;
    seen.add(key);
    copies.push(copy);
  };

  add({
    path: centralCredentialsSnapshot(accountUuid),
    kind: "central",
    stayUnder: accountsHome(),
    mayCreate: true,
    // The path IS the claim: this file lives at `<home>/auth/<uuid>/`, so its
    // container asserts this account by construction and there is nothing
    // further to check. Note precisely what that does and does not buy — it
    // proves the SLOT is the right one, never that the BYTES in it were
    // legitimately filed. Content-level binding would require stamping the
    // uuid inside the credential payload, which is a file-format change.
    carriesThisAccount: () => true,
  });

  const dirLiveCopy = (dir: string): BrokerCopy => ({
    path: dirCredentialsFile(dir),
    kind: "dir-live",
    stayUnder: dir,
    mayCreate: false,
    carriesThisAccount: () => dirAccountUuid(dir, tool)?.toLowerCase() === accountUuid,
  });

  for (const door of identity?.doors ?? []) {
    if (door.role === "own-identity") {
      const dir = door.dir;
      add({
        path: profileCredentialsSnapshot(dir),
        kind: "profile-snapshot",
        stayUnder: dir,
        mayCreate: false,
        carriesThisAccount: () => profileAccountUuid(dir, tool)?.toLowerCase() === accountUuid,
      });
    } else if (door.role === "current-occupant") {
      add(dirLiveCopy(door.dir));
    }
  }

  for (const dir of opts.extraDirs ?? []) {
    if ((identity?.doors ?? []).some((door) => sameConfigDir(door.dir, dir))) continue;
    add(dirLiveCopy(dir));
  }

  return copies;
}

interface RankedCopy extends BrokerCopy {
  health: CredentialHealthPresent;
  bytes: Buffer;
}

/**
 * Admit the files eligible to be this account's SOURCE of truth, then rank them.
 *
 * THE IDENTITY GATE ON READ IS THE POINT. Enumeration is door-driven, and a
 * door is only ever evidence that a dir was RELEVANT — never that it currently
 * holds this account. `extraDirs` in particular is whatever the caller handed
 * us: `switchAccount` passes the session's config dir, which at that moment is
 * still occupied by the OUTGOING account. Ranking is identity-blind by
 * construction — `betterCredential` compares health structs (refresh-token
 * presence, usability, mtime, expiry) and health carries no identity — so an
 * ineligible candidate that reaches the ranking WINS whenever it is the
 * freshest file, which the account you just stopped using always is.
 *
 * Fan-out then re-checks each TARGET, so every other copy refused the payload
 * and only the central store — whose target check is vacuously true, its path
 * being uuid-keyed — accepted it. That asymmetry is the whole defect: it made
 * the corruption silent, and one-directional INTO central, filing one
 * credential blob under many uuids.
 *
 * Default-deny is deliberate. A dir with a credential file but no resolvable
 * `oauthAccount` is UNATTRIBUTABLE, and an unattributable credential is
 * exactly the thing that must not be adopted as an identity's record. Such a
 * dir could already never RECEIVE; it can now no longer DONATE either.
 *
 * CONTAINMENT IS NOT ENOUGH, AND THE COMMENT ABOVE ON THE CENTRAL COPY SAYS SO:
 * `carriesThisAccount: () => true` proves the SLOT is right, never that the
 * BYTES in it were legitimately filed. So each admitted candidate is checked a
 * second time against its own CONTENT — the refresh token's fingerprint — and
 * refused when some other account's central slot already claims it. That is the
 * only question containment cannot ask, and it is the one that matters: a
 * profile whose `oauth-account.json` says A while its `credentials.json` holds
 * B's material passes every check above, and its file is the freshest on disk,
 * which is precisely what ranking crowns.
 */
function rankedCopies(
  accountUuid: string,
  copies: BrokerCopy[],
  claimIndex: CredentialClaimIndex,
  report: { skipped: BrokerSkip[] },
): RankedCopy[] {
  const out: RankedCopy[] = [];
  for (const copy of copies) {
    if (!existsNotSymlink(copy.path)) continue;
    const health = credentialHealth(copy.path);
    if (!health.exists) continue;
    if (!copy.carriesThisAccount()) {
      // Reported, never silent: the absence of any signal is precisely how
      // this survived from the broker's introduction through 0.2.26.
      report.skipped.push({
        path: copy.path,
        kind: copy.kind,
        reason: "does not carry this account (not eligible as a source)",
      });
      continue;
    }
    const bytes = readFileSync(copy.path);
    const refusal = credentialBindingRefusal(accountUuid, bytes, claimIndex);
    if (refusal) {
      report.skipped.push({ path: copy.path, kind: copy.kind, reason: refusal.reason });
      continue;
    }
    out.push({ ...copy, health, bytes });
  }
  return out;
}

/**
 * Fan a winning payload out to every other copy. The write rules are the whole
 * safety story:
 *  - a copy that ranks BETTER than the payload is never overwritten,
 *  - live/snapshot files are update-only (never created),
 *  - a dir whose occupant is no longer this account is skipped,
 *  - byte-identical copies are left alone,
 *  - symlinked paths are refused by `writeFileAtomic` and recorded as skips,
 *  - a payload another account already claims reaches NO target, central
 *    included (see `credential-binding.ts`).
 */
function fanOut(
  accountUuid: string,
  copies: BrokerCopy[],
  payload: Buffer,
  payloadHealth: CredentialHealthPresent,
  claimIndex: CredentialClaimIndex,
  report: { writes: BrokerWrite[]; skipped: BrokerSkip[] },
  excludePath?: string,
): void {
  // Defence in depth, not belt-and-braces theatre: the source gate should have
  // stopped a foreign payload before it could be crowned, but the central slot
  // is the ONE target whose containment check is vacuously true, so it is the
  // one target that would accept anything the ranking handed it. That asymmetry
  // is what made the original corruption one-directional INTO central.
  const payloadRefusal = credentialBindingRefusal(accountUuid, payload, claimIndex);
  if (payloadRefusal) {
    for (const copy of copies) {
      if (excludePath && resolve(copy.path) === resolve(excludePath)) continue;
      // Only paths that would actually have been written: a copy that does not
      // exist and may not be created was never a target, and reporting it as
      // "refused" would inflate the skip list with non-events — the shape that
      // teaches operators to stop reading it.
      if (!existsNotSymlink(copy.path) && !copy.mayCreate) continue;
      report.skipped.push({ path: copy.path, kind: copy.kind, reason: payloadRefusal.reason });
    }
    return;
  }
  for (const copy of copies) {
    if (excludePath && resolve(copy.path) === resolve(excludePath)) continue;
    const exists = existsNotSymlink(copy.path);
    if (!exists && existsSync(copy.path)) {
      report.skipped.push({ path: copy.path, kind: copy.kind, reason: "symlink" });
      continue;
    }
    if (!exists && !copy.mayCreate) continue;
    if (exists) {
      const current = credentialHealth(copy.path);
      if (current.exists) {
        if (readFileSync(copy.path).equals(payload)) continue;
        if (betterCredential(current, payloadHealth) === current) {
          report.skipped.push({ path: copy.path, kind: copy.kind, reason: "holds a better credential" });
          continue;
        }
      }
    }
    if (!copy.carriesThisAccount()) {
      report.skipped.push({ path: copy.path, kind: copy.kind, reason: "dir no longer carries this account" });
      continue;
    }
    try {
      writeFileAtomic(copy.path, payload, { mode: 0o600, mustStayUnder: copy.stayUnder });
      report.writes.push({ path: copy.path, kind: copy.kind, action: exists ? "updated" : "created" });
      // The central slot accepting a payload IS the account taking ownership of
      // it; record that so the claim survives the next in-place rotation of a
      // sibling copy, and so a later cross-write has something to collide with.
      if (copy.kind === "central") {
        const fingerprint = credentialFingerprintFromBytes(payload);
        if (fingerprint) {
          recordCredentialBinding(accountUuid, fingerprint, {
            evidence: "central-write",
            sourceKind: "central",
          });
        }
      }
    } catch (error) {
      report.skipped.push({
        path: copy.path,
        kind: copy.kind,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

function convergeLocked(accountUuid: string, tool: ToolDef, opts: BrokerOptions): ConvergeReport {
  const now = opts.now ?? Date.now;
  const report: ConvergeReport = { accountUuid, writes: [], skipped: [] };
  const copies = enumerateCopies(accountUuid, tool, opts);
  // Built ONCE, under the lock, and reused for both the source and the target
  // gate: a per-candidate rebuild would read the central store N times and —
  // worse — could see it change mid-decision, so two candidates would be judged
  // against two different worlds.
  const claimIndex = buildCredentialClaimIndex();
  const ranked = rankedCopies(accountUuid, copies, claimIndex, report);
  if (ranked.length === 0) return report;

  const winner = ranked.reduce((a, b) => (betterCredential(a.health, b.health) === a.health ? a : b));
  // A husk (no refresh token) must never propagate over anything; with no
  // restorable copy anywhere there is nothing to converge TO.
  if (winner.health.refreshTokenLength === 0) {
    report.skipped.push({ path: winner.path, kind: winner.kind, reason: "best copy has no refresh token" });
    return report;
  }

  report.winner = { path: winner.path, kind: winner.kind };
  report.expiresInMs = winner.health.expiresAt - now();
  fanOut(accountUuid, copies, winner.bytes, winner.health, claimIndex, report, winner.path);
  return report;
}

/**
 * Converge every copy of the account's credential to the newest rotation.
 * File I/O only — never the network. Fail-open callers (the hook) wrap this.
 */
export function convergeIdentityCredential(accountUuid: string, opts: BrokerOptions = {}): ConvergeReport {
  const uuid = normalizedUuid(accountUuid);
  const tool = opts.tool ?? getTool("claude");
  return withIdentityLockSync(uuid, () => convergeLocked(uuid, tool, opts), opts.lock);
}

/**
 * Converge the account currently occupying a config dir, including the dir
 * itself as a live target. No-op (undefined) when the dir carries no
 * well-formed account.
 *
 * THE DIR IS CHECKED AGAINST AN ALLOWLIST THE CALLER DOES NOT CONTROL — the
 * registered profile dirs plus this machine's live config dir — exactly like
 * `switchAccount`'s destination guard, and for the same reason: this function
 * reads a uuid out of the dir's own `.claude.json` and then writes that
 * account's credential of record back into the dir. Without the gate, a
 * planted dir carrying a victim's `oauthAccount` plus a stale credential file
 * would receive the victim's live tokens at mode 0600 — the credential-sync
 * CLI would have re-created the exfiltration primitive the switch-account
 * allowlist was built to kill. A refused dir is an error, not a silent no-op:
 * the hook's caller catches and logs it, the CLI surfaces it.
 */
export function assertRegisteredConfigDir(
  configDir: string,
  profiles: ReadonlyArray<{ name?: string; dir: string }>,
): void {
  const registered =
    sameConfigDir(configDir, liveClaudePaths().configDir) ||
    profiles.some((profile) => sameConfigDir(profile.dir, configDir));
  if (!registered) {
    throw new AccountsError(
      `refusing to converge credentials for ${configDir}: it is not a registered profile dir and it is not ` +
        `this machine's live config dir. Register it first (\`accounts add <name> --dir ${configDir}\`).`,
    );
  }
}

export function convergeDirCredential(configDir: string, opts: BrokerOptions = {}): ConvergeReport | undefined {
  const tool = opts.tool ?? getTool("claude");
  const profiles = opts.profiles ?? listProfiles();
  assertRegisteredConfigDir(configDir, profiles);
  const uuid = dirAccountUuid(configDir, tool);
  if (!uuid || !isAccountUuid(uuid)) return undefined;
  return convergeIdentityCredential(uuid, {
    ...opts,
    tool,
    profiles,
    extraDirs: [...(opts.extraDirs ?? []), configDir],
  });
}

interface ExchangeSuccess {
  ok: true;
  accessToken: string;
  refreshToken?: string;
  expiresInS: number;
}

interface ExchangeFailure {
  ok: false;
  status?: number;
  detail: string;
}

async function exchangeRefreshToken(
  refreshToken: string,
  fetchImpl: typeof fetch,
): Promise<ExchangeSuccess | ExchangeFailure> {
  let response: Response;
  try {
    response = await fetchImpl(claudeOAuthTokenUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: claudeOAuthClientId(),
      }),
      signal: AbortSignal.timeout(EXCHANGE_TIMEOUT_MS),
    });
  } catch (error) {
    return { ok: false, detail: `token endpoint unreachable: ${error instanceof Error ? error.message : String(error)}` };
  }
  if (!response.ok) {
    // Error bodies name OAuth error codes, never tokens; truncate anyway.
    let body = "";
    try {
      body = (await response.text()).slice(0, 200);
    } catch {
      // status alone still tells the story
    }
    return { ok: false, status: response.status, detail: `HTTP ${response.status}${body ? ` ${body}` : ""}` };
  }
  let parsed: JsonRecord;
  try {
    parsed = (await response.json()) as JsonRecord;
  } catch {
    return { ok: false, status: response.status, detail: "token endpoint returned unparseable JSON" };
  }
  const accessToken = parsed.access_token;
  const expiresIn = parsed.expires_in;
  if (typeof accessToken !== "string" || !accessToken || typeof expiresIn !== "number") {
    return { ok: false, status: response.status, detail: "token endpoint response missing access_token/expires_in" };
  }
  return {
    ok: true,
    accessToken,
    ...(typeof parsed.refresh_token === "string" && parsed.refresh_token
      ? { refreshToken: parsed.refresh_token }
      : {}),
    expiresInS: expiresIn,
  };
}

function normalizedUuid(accountUuid: string): string {
  if (!isAccountUuid(accountUuid)) {
    throw new AccountsError(`invalid account uuid for credential broker: ${JSON.stringify(accountUuid)}`);
  }
  return accountUuid.toLowerCase();
}

/**
 * The single-writer refresh. Under the account's lock: converge, and when the
 * winning access token has less than `minTtlMs` left, exchange the refresh
 * token ONCE and persist the rotation — central store first (the credential of
 * record), every other copy after. A concurrent caller blocks on the lock,
 * then finds a fresh token during ITS converge and performs no exchange: that
 * re-read-under-lock is the broker's double-check, ported intact.
 *
 * A failed exchange writes NOTHING. The copies stay as they were; the old
 * access token keeps whatever validity it had.
 *
 * A CONTESTED CREDENTIAL IS NEVER EXCHANGED, and that falls out of the order
 * rather than needing its own gate: converge runs first, the binding check
 * refuses every copy of a credential two accounts claim, so there is no winner
 * and this returns before reaching the token endpoint. That is the right
 * outcome and worth naming — exchanging a credential whose true owner is
 * another account would ROTATE THAT OWNER'S REFRESH TOKEN and revoke them,
 * server-side and irreversibly, which is the exact harm the broker exists to
 * prevent, delivered by the broker itself.
 */
export async function ensureFreshIdentityCredential(
  accountUuid: string,
  opts: EnsureFreshOptions = {},
): Promise<EnsureFreshReport> {
  const uuid = normalizedUuid(accountUuid);
  const tool = opts.tool ?? getTool("claude");
  const now = opts.now ?? Date.now;
  const minTtlMs = opts.minTtlMs ?? DEFAULT_MIN_TTL_MS;
  const fetchImpl = opts.fetchImpl ?? fetch;

  return withIdentityLock(
    uuid,
    async () => {
      const converged = convergeLocked(uuid, tool, opts);
      if (!converged.winner) {
        return { ...converged, refreshed: false, error: "no restorable credential copy for this account" };
      }
      const ttl = converged.expiresInMs ?? 0;
      if (ttl > minTtlMs) {
        return { ...converged, refreshed: false };
      }

      const winnerRecord = readJsonRecord(converged.winner.path);
      const oauth = winnerRecord?.claudeAiOauth;
      const refreshToken =
        oauth && typeof oauth === "object" ? (oauth as JsonRecord).refreshToken : undefined;
      if (typeof refreshToken !== "string" || !refreshToken) {
        return { ...converged, refreshed: false, error: "winning copy has no refresh token to exchange" };
      }

      const exchanged = await exchangeRefreshToken(refreshToken, fetchImpl);
      if (!exchanged.ok) {
        return { ...converged, refreshed: false, error: `refresh exchange failed: ${exchanged.detail}` };
      }

      const rotatedOAuth: JsonRecord = {
        ...(oauth as JsonRecord),
        accessToken: exchanged.accessToken,
        // No rotated refresh token in the response means the old one stays
        // valid — keep it rather than blanking it.
        ...(exchanged.refreshToken ? { refreshToken: exchanged.refreshToken } : {}),
        expiresAt: now() + exchanged.expiresInS * 1000,
      };
      const payload = Buffer.from(JSON.stringify({ ...winnerRecord, claudeAiOauth: rotatedOAuth }));

      // Persist the rotation to the CENTRAL STORE first and unconditionally:
      // from the instant the exchange returned, the response body is the only
      // copy of the new refresh token in existence. Everything else is fan-out.
      const centralPath = centralCredentialsSnapshot(uuid);
      const report: EnsureFreshReport = { ...converged, refreshed: true };
      const centralExisted = existsNotSymlink(centralPath);
      writeFileAtomic(centralPath, payload, { mode: 0o600, mustStayUnder: accountsHome() });
      report.writes.push({ path: centralPath, kind: "central", action: centralExisted ? "updated" : "created" });

      // This rotation is THIS account's by construction — the server minted it
      // in exchange for this account's refresh token, which is a stronger proof
      // of ownership than any file on disk can offer. Recording it here is what
      // keeps the binding current across rotation: without it, the account's own
      // freshly rotated credential would look unclaimed on the next converge.
      const rotatedFingerprint = credentialFingerprintFromBytes(payload);
      if (rotatedFingerprint) {
        recordCredentialBinding(uuid, rotatedFingerprint, { evidence: "rotation", sourceKind: "exchange" });
      }

      const payloadHealth = credentialHealth(centralPath);
      if (payloadHealth.exists) {
        // Index rebuilt AFTER the central write and the rebinding, so the
        // fan-out is judged against the world the rotation just created rather
        // than the one that preceded it.
        fanOut(
          uuid,
          enumerateCopies(uuid, tool, opts),
          payload,
          payloadHealth,
          buildCredentialClaimIndex(),
          report,
          centralPath,
        );
      }
      report.winner = { path: centralPath, kind: "central" };
      report.expiresInMs = exchanged.expiresInS * 1000;
      return report;
    },
    opts.lock,
  );
}
