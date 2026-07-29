import { existsSync, readFileSync, statSync } from "node:fs";
import type { ToolDef } from "../types.js";
import {
  dirCredentialsFile,
  listDirLiveSessions,
  profileCredentialsSnapshot,
  profileSwitchedAccountMarker,
} from "./claude-layout.js";
// From auth-store (the lower layer), NOT claude-auth: claude-auth consumes this
// module for its reasons text, so importing back would close a cycle.
import {
  centralCredentialsPathForProfile,
  dirLiveIdentityToken,
  profileParkedIdentityToken,
} from "./auth-store.js";

/**
 * What a credential file actually IS, as distinct from how old it is.
 *
 * WHY THIS EXISTS: `credential payload is expired` was reported for every one of
 * these states, and it sent three separate investigations to study token
 * lifetimes when the real answer was custody. Two of them were mine. The states
 * below are the ones that need different actions from an operator, so they need
 * different words:
 *
 *   usable         nothing to do
 *   needs-refresh  nothing to do — the tool renews it on the next request
 *   rotated-away   another copy of this SAME account refreshed and the server
 *                  rotated the token out from under this one; this file is not
 *                  a credential any more, and re-login is NOT the fix if a
 *                  parked copy survives
 *   unusable       genuinely dead; re-login IS the fix
 *   unreadable     not a credential payload at all
 *   absent         no file
 *
 * `rotated-away` is a described FINGERPRINT, not a claimed cause: the payload
 * structure is intact while both the refresh token and the expiry are gone.
 * Measured on this fleet 2026-07-29 — six profile dirs in exactly that shape,
 * each written seconds to minutes after a sibling dir holding the same account
 * refreshed successfully. Claude Code writes it; `accounts` never does. A
 * partially-written file would fail the JSON parse and land in `unreadable`
 * instead, and a logged-out account keeps its expiry, so the shape is specific
 * even though the cause is inferred.
 */
export type CredentialState =
  | "usable"
  | "needs-refresh"
  | "rotated-away"
  | "unusable"
  | "unreadable"
  | "absent";

export interface CredentialFileState {
  path: string;
  state: CredentialState;
  /** Only for states that carry one; never a token value. */
  expiresAt?: string;
  mtime?: string;
}

/** True when the file can serve a session now or after the tool renews it. */
export function isRestorableState(state: CredentialState): boolean {
  return state === "usable" || state === "needs-refresh";
}

/**
 * Classify one credential file.
 *
 * Deliberately reads the payload itself rather than going through
 * `credentialHealth`, which collapses "not a claudeAiOauth object" and "a
 * claudeAiOauth object with everything blanked" into the same
 * `{ expiresAt: 0, refreshTokenLength: 0 }` — and telling those two apart is the
 * whole point here.
 *
 * Refresh-token presence is decided on the VALUE, never the key name:
 * `refreshTokenExpiresAt` survives in a rotated-away payload and contains the
 * substring `refresh`, so a name-matching check reports a token that is not
 * there. That exact mistake produced a wrong diagnosis on this defect.
 */
export function classifyCredentialFile(path: string, now: Date = new Date()): CredentialFileState {
  if (!existsSync(path)) return { path, state: "absent" };

  let mtime: string | undefined;
  try {
    mtime = new Date(statSync(path).mtimeMs).toISOString();
  } catch {
    // Stat is decoration; a classification must not fail on it.
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return { path, state: "unreadable", ...(mtime ? { mtime } : {}) };
  }
  const oauth = (parsed as { claudeAiOauth?: unknown } | null)?.claudeAiOauth;
  if (!oauth || typeof oauth !== "object") {
    return { path, state: "unreadable", ...(mtime ? { mtime } : {}) };
  }

  const record = oauth as Record<string, unknown>;
  const refreshToken = record.refreshToken;
  const hasRefreshToken = typeof refreshToken === "string" && refreshToken.length > 0;

  const rawExpiry = record.expiresAt;
  const expiresAtMs =
    typeof rawExpiry === "number" ? rawExpiry : typeof rawExpiry === "string" ? Date.parse(rawExpiry) : 0;
  const expiry = Number.isFinite(expiresAtMs) ? expiresAtMs : 0;
  const expiresAt = expiry > 0 ? new Date(expiry).toISOString() : undefined;
  const decorate = { ...(expiresAt ? { expiresAt } : {}), ...(mtime ? { mtime } : {}) };

  if (!hasRefreshToken) {
    // Structure intact, both secrets gone: the rotation fingerprint. Keeping it
    // separate from `unusable` is what stops an operator being told to
    // re-authenticate when a parked copy would restore the account for free.
    if (expiry === 0) return { path, state: "rotated-away", ...decorate };
    return { path, state: "unusable", ...decorate };
  }

  if (expiry > now.getTime()) return { path, state: "usable", ...decorate };
  return { path, state: "needs-refresh", ...decorate };
}

/**
 * WHO the dir currently belongs to, as opposed to how healthy its credential is.
 *
 * WHY THIS EXISTS (defect 6a58cdb8): every "is there anything to do" decision in
 * this package was made from credential CONTENT alone. An occupied dir — one
 * whose live files present an account that is not the profile's own — carries a
 * perfectly healthy credential, so `parkedCredentialVerdict` computed
 * `recoverable = false` and `recoverParkedCredential` returned
 * `live-credential-usable` from its first branch, above the identity gate. The
 * `identity-would-change` outcome was therefore unreachable whenever the
 * occupant's credential worked, and occupation by a LIVE foreign account mapped
 * to no action and no report anywhere. Measured on this fleet 2026-07-29: seven
 * dirs in exactly that state, none of them ever coming back.
 *
 * Content ranking cannot separate two healthy credentials belonging to
 * different accounts — only identity can. So identity is a first-class layer
 * here, not an afterthought below a health check.
 */
export interface ProfileDirOccupancy {
  /** The profile's own parked identity. Snapshot only — never the live files. */
  ownUuid?: string;
  /** The identity the dir's live files present right now. */
  liveUuid?: string;
  /**
   * The dir presents an account that is provably not the profile's own.
   * Requires own to be KNOWN: an unproven claim is not an occupation, because
   * acting on it would pair whatever the dir shows with this profile's tokens.
   */
  occupied: boolean;
  /**
   * `switch-account` recorded this occupation, so `healSwitchedProfileDir` owns
   * undoing it (with its own liveness refusal). Reconciliation deliberately
   * leaves marked dirs alone rather than duplicating that decision.
   */
  marked: boolean;
  /** Sessions attached to the dir right now — the occupant's, when occupied. */
  liveSessions: number;
}

export interface ProfileCredentialLayers {
  /** `<dir>/.credentials.json` — whoever's account currently occupies the dir. */
  live: CredentialFileState;
  /** `<dir>/.accounts-auth/credentials.json` — the profile's OWN parked copy. */
  snapshot: CredentialFileState;
  /** `~/.hasna/accounts/auth/<uuid>/credentials.json` — the central parked copy. */
  central?: CredentialFileState;
  /**
   * Optional so the many call sites that build a layer literal in tests keep
   * compiling; `profileCredentialLayers` always populates it.
   */
  occupancy?: ProfileDirOccupancy;
}

/**
 * Which account a dir currently belongs to versus which one the profile is.
 *
 * `own` is resolved from the parked snapshot ONLY. `profileAccountUuid` falls
 * back to the dir's live account file when no snapshot exists, which is correct
 * for binding a fresh profile and fatal here: on an occupied dir that fallback
 * returns the OCCUPANT's uuid, making own === live and hiding the occupation
 * from the one check that exists to find it.
 */
export function profileDirOccupancy(profileDir: string, tool?: ToolDef): ProfileDirOccupancy {
  const ownUuid = profileParkedIdentityToken(profileDir);
  const liveUuid = dirLiveIdentityToken(profileDir, tool);
  return {
    ...(ownUuid ? { ownUuid } : {}),
    ...(liveUuid ? { liveUuid } : {}),
    // Both must be known. Unknown own is "cannot prove", not "is foreign".
    occupied: Boolean(ownUuid && liveUuid && ownUuid !== liveUuid),
    marked: existsSync(profileSwitchedAccountMarker(profileDir)),
    liveSessions: listDirLiveSessions(profileDir).filter((s) => s.alive).length,
  };
}

/**
 * Every layer that could hold this profile's credential.
 *
 * The layers are NOT interchangeable and conflating them is the single most
 * repeated error on this defect: after an in-place switch the LIVE file holds
 * the current occupant's credential, not the profile's own. Three separate
 * diagnoses were wrong because they read the live file and reported it as the
 * profile's.
 */
export function profileCredentialLayers(
  profileDir: string,
  tool: ToolDef,
  now: Date = new Date(),
): ProfileCredentialLayers {
  const centralPath = centralCredentialsPathForProfile(profileDir, tool);
  return {
    live: classifyCredentialFile(dirCredentialsFile(profileDir), now),
    snapshot: classifyCredentialFile(profileCredentialsSnapshot(profileDir), now),
    ...(centralPath ? { central: classifyCredentialFile(centralPath, now) } : {}),
    occupancy: profileDirOccupancy(profileDir, tool),
  };
}

export interface ParkedCredentialVerdict {
  /** The dir's own live slot cannot serve a session. */
  liveUnusable: boolean;
  /** A parked copy of the profile's OWN credential could serve one. */
  parkedRestorable: boolean;
  /** Which parked layer is restorable, best first. */
  restorableLayers: Array<"snapshot" | "central">;
  /**
   * The dir presents a foreign account with no `switch-account` marker, so
   * nothing in the package owns undoing it. Independent of credential health:
   * the occupant's credential is normally perfectly good, which is exactly why
   * a content-only verdict never saw this.
   */
  occupiedUnmarked: boolean;
  /** Sessions attached right now; non-zero means reconciling would evict them. */
  occupantSessions: number;
  /**
   * True when a restore would turn an unusable dir into a working one, OR when
   * it would return an idle occupied dir to its own account.
   *
   * Both legs require `parkedRestorable`. Reconciling an occupied dir whose
   * owner has nothing restorable would replace a WORKING credential with a dead
   * one — strictly worse than the occupation it fixes.
   */
  recoverable: boolean;
}

/**
 * Is there parked credential material this dir is not using?
 *
 * This is the question no CLI path asked. `healSwitchedProfileDir` answers a
 * narrower one — "was this dir switched away and can it be switched back" — and
 * returns false immediately when there is no switch marker, so a dir whose own
 * credential was rotated away in place is invisible to it. Measured: four of the
 * six affected profiles have no marker.
 */
export function parkedCredentialVerdict(layers: ProfileCredentialLayers): ParkedCredentialVerdict {
  const liveUnusable = !isRestorableState(layers.live.state);
  const restorableLayers: Array<"snapshot" | "central"> = [];
  if (isRestorableState(layers.snapshot.state)) restorableLayers.push("snapshot");
  if (layers.central && isRestorableState(layers.central.state)) restorableLayers.push("central");
  const parkedRestorable = restorableLayers.length > 0;
  const occupancy = layers.occupancy;
  const occupiedUnmarked = Boolean(occupancy?.occupied && !occupancy.marked);
  const occupantSessions = occupancy?.liveSessions ?? 0;
  return {
    liveUnusable,
    parkedRestorable,
    restorableLayers,
    occupiedUnmarked,
    occupantSessions,
    recoverable: parkedRestorable && (liveUnusable || (occupiedUnmarked && occupantSessions === 0)),
  };
}

/** Operator-facing description of a layer, safe to print. */
export function describeCredentialState(state: CredentialState): string {
  switch (state) {
    case "usable":
      return "usable";
    case "needs-refresh":
      return "access token aged out, refresh token intact (the tool renews it on use)";
    case "rotated-away":
      return "rotated away by another copy of the same account (payload blanked: no refresh token, no expiry)";
    case "unusable":
      return "no refresh token — re-authentication required";
    case "unreadable":
      return "not a readable credential payload";
    case "absent":
      return "no file";
  }
}
