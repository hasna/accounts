import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import {
  centralAuthDir,
  centralAuthRoot,
  centralCredentialsSnapshot,
  centralOAuthSnapshot,
  isAccountUuid,
} from "./auth-store.js";
import { writeFileAtomic } from "./safe-path.js";

/**
 * CREDENTIAL → ACCOUNT IDENTITY BINDING.
 *
 * THE DEFECT (todos bc32e38c, measured on station01): the central store held
 * 18 accounts with 18 distinct emails but only 8 distinct credentials — ONE
 * credential filed under EIGHT different account uuids. Eight identities cannot
 * share one OAuth credential, so at most one of those bindings was true; the
 * other seven accounts had lost their credential while every health surface
 * stayed green.
 *
 * WHY THE EXISTING GATES CANNOT SEE IT. Until now the only binding a credential
 * had was CONTAINMENT — "whose credential is this?" answered by the directory
 * the file sits in. `credential-broker.ts` says so in its own words, and PR #97
 * (which made containment symmetric, gating sources as well as targets) named
 * the residue precisely: the central copy's check is
 * `carriesThisAccount: () => true`, which "proves the SLOT is the right one,
 * never that the BYTES in it were legitimately filed."
 *
 * A container's claim is worth exactly as much as the last thing that wrote the
 * container — and the two files making that claim, `oauth-account.json` and
 * `credentials.json`, are written by SEPARATE code paths (`syncOAuthFile` and
 * `syncCredentialsFile`; the broker writes only the second). When they
 * disagree, every containment gate passes, ranking is identity-blind by
 * construction, and the freshest file wins. Reproduced through the public API
 * in 112ms against 0.2.26 + PR #97: profile A's snapshot holding B's credential
 * was crowned A's winner, written to `auth/<A>/credentials.json`, fanned out to
 * A's live dir, with `skipped: []`.
 *
 * WHAT BINDS A CREDENTIAL TO AN ACCOUNT HERE: the REFRESH TOKEN, by digest.
 * Not the whole file — two copies of one credential are routinely spelled
 * differently on disk (`syncCredentialsFile` copies raw bytes, the broker
 * writes compact `JSON.stringify`, and Claude Code rewrites the access token in
 * place every eight hours), so a whole-file digest reports two spellings of one
 * credential as two credentials and misses exactly the duplication that matters.
 * The refresh token is also the harm: two files holding the SAME refresh token
 * is the mutual-revocation hazard the broker exists to prevent, because the
 * first exchange rotates it and revokes every other copy server-side.
 *
 * NO TOKEN VALUE IS EMITTED. The token is read into memory, hashed, and
 * discarded; only `sha256:<hex>` leaves this module, the record is written
 * 0600, and the CLI prints a truncated prefix. A digest of a high-entropy
 * secret is an identifier, not the secret.
 *
 * WHERE THE CLAIM LIVES. `auth/<uuid>/credential-binding.json`, beside the
 * credential it describes — deliberately NOT a separate ledger. A ledger is a
 * second lifecycle that drifts from the store it describes, needs its own
 * pruning, and survives `auth sweep` moving an account to `auth-trash`. A
 * sidecar inherits all of that for free.
 *
 * FAIL-OPEN ON UNKNOWN, BY DESIGN, AND IT IS NOT THE SAME POSTURE AS
 * CONTAINMENT. Containment default-DENIES (an unattributable dir may neither
 * donate nor receive) because a dir either claims an account or does not.
 * Content binding cannot: a credential that has never been filed anywhere has
 * no claimant, and refusing that would stop any account ever acquiring its
 * first binding. So this layer refuses only on POSITIVE PROOF that some other
 * account already claims these bytes. The two layers are complementary, and
 * neither is weakened by the other.
 *
 * WHAT THIS DOES NOT BUY. A claim is evidenced by the central store's CURRENT
 * contents plus one predecessor, so once the true owner has rotated twice, an
 * old credential of theirs is no longer claimed and could be filed elsewhere.
 * That is a stale credential rather than a live one, and `betterCredential`
 * already ranks it last — stated here rather than glossed, because a binding
 * trusted past its reach is how the next leak happens.
 */

export const CREDENTIAL_BINDING_FILE = "credential-binding.json";
export const CREDENTIAL_BINDING_SCHEMA = "accounts.credential-binding.v1";

/**
 * The rule that produced a fingerprint, emitted in every record and every
 * report. Same discipline as `buildProfileRegistry`'s `method`: when the rule
 * changes, existing records say which rule made them instead of silently
 * comparing across two definitions.
 */
export const CREDENTIAL_BINDING_METHOD = "sha256-refresh-token/v1";

export type CredentialBindingEvidence = "central-write" | "rotation" | "migrated";
export type CredentialBindingSourceKind = "central" | "profile-snapshot" | "dir-live" | "exchange";

export interface CredentialBinding {
  schema: typeof CREDENTIAL_BINDING_SCHEMA;
  method: typeof CREDENTIAL_BINDING_METHOD;
  accountUuid: string;
  fingerprint: string;
  boundAt: string;
  evidence: CredentialBindingEvidence;
  sourceKind: CredentialBindingSourceKind;
  /** The fingerprint this one replaced. One level deep — see `recordCredentialBinding`. */
  supersedes?: string;
}

type JsonRecord = Record<string, unknown>;

function readJsonFile(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as JsonRecord) : undefined;
  } catch {
    return undefined;
  }
}

// --- fingerprinting -----------------------------------------------------------

/**
 * Digest of a refresh token. The token reaches this function and nothing else:
 * it is never returned, logged, compared as a string outside here, or written.
 */
function digest(refreshToken: string): string {
  return `sha256:${createHash("sha256").update(refreshToken, "utf8").digest("hex")}`;
}

/**
 * The account-bearing fingerprint of a credential payload, or `undefined` when
 * the payload carries no refresh token.
 *
 * `undefined` is a real answer, not a failure: a husk (blanked by a failed
 * rotation, or the empty-token materialization of defect b29f5b6c) binds
 * nothing and claims nothing. The broker already refuses to propagate husks;
 * this agrees with it rather than inventing a second rule.
 */
export function credentialFingerprintFromBytes(bytes: Buffer | string): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(typeof bytes === "string" ? bytes : bytes.toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) return undefined;
  const oauth = (parsed as JsonRecord).claudeAiOauth;
  if (!oauth || typeof oauth !== "object") return undefined;
  const refreshToken = (oauth as JsonRecord).refreshToken;
  if (typeof refreshToken !== "string" || refreshToken.length === 0) return undefined;
  return digest(refreshToken);
}

/** As above, read from a file. A missing or unreadable file fingerprints to `undefined`. */
export function credentialFingerprintFromFile(path: string): string | undefined {
  try {
    if (!existsSync(path)) return undefined;
    return credentialFingerprintFromBytes(readFileSync(path));
  } catch {
    return undefined;
  }
}

// --- the binding record -------------------------------------------------------

export function credentialBindingPath(accountUuid: string): string {
  return join(centralAuthDir(accountUuid), CREDENTIAL_BINDING_FILE);
}

export function readCredentialBinding(accountUuid: string): CredentialBinding | undefined {
  if (!isAccountUuid(accountUuid)) return undefined;
  const raw = readJsonFile(credentialBindingPath(accountUuid));
  if (!raw) return undefined;
  const { accountUuid: uuid, fingerprint, boundAt } = raw;
  if (typeof uuid !== "string" || typeof fingerprint !== "string" || typeof boundAt !== "string") {
    return undefined;
  }
  // A record whose method is not the one this build computes describes
  // fingerprints this build cannot reproduce; treating it as a claim would
  // compare across two definitions. Absent is the honest reading.
  if (raw.method !== CREDENTIAL_BINDING_METHOD) return undefined;
  return {
    schema: CREDENTIAL_BINDING_SCHEMA,
    method: CREDENTIAL_BINDING_METHOD,
    accountUuid: uuid.toLowerCase(),
    fingerprint,
    boundAt,
    evidence: (typeof raw.evidence === "string" ? raw.evidence : "central-write") as CredentialBindingEvidence,
    sourceKind: (typeof raw.sourceKind === "string"
      ? raw.sourceKind
      : "central") as CredentialBindingSourceKind,
    ...(typeof raw.supersedes === "string" ? { supersedes: raw.supersedes } : {}),
  };
}

/**
 * Bind a fingerprint to an account. Idempotent: re-binding the fingerprint an
 * account already holds rewrites nothing, so a converge that changes no bytes
 * also changes no record.
 *
 * `supersedes` is ONE level deep on purpose. It exists to cover the interval
 * between the true owner rotating its credential and the next converge seeing
 * it — without that window a legitimate rotation briefly looks like an
 * unclaimed credential. Keeping more would turn a fixed-size record into an
 * unbounded history of every token an account ever held, which is both a
 * growing file of secret-derived material and a widening window in which a
 * long-superseded credential still counts as claimed.
 */
export function recordCredentialBinding(
  accountUuid: string,
  fingerprint: string,
  opts: { evidence: CredentialBindingEvidence; sourceKind: CredentialBindingSourceKind },
): void {
  if (!isAccountUuid(accountUuid)) return;
  const uuid = accountUuid.toLowerCase();
  const previous = readCredentialBinding(uuid);
  if (previous?.fingerprint === fingerprint) return;
  const record: CredentialBinding = {
    schema: CREDENTIAL_BINDING_SCHEMA,
    method: CREDENTIAL_BINDING_METHOD,
    accountUuid: uuid,
    fingerprint,
    boundAt: new Date().toISOString(),
    evidence: opts.evidence,
    sourceKind: opts.sourceKind,
    ...(previous?.fingerprint ? { supersedes: previous.fingerprint } : {}),
  };
  writeFileAtomic(credentialBindingPath(uuid), JSON.stringify(record, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

/**
 * Every fingerprint this account currently claims: what its central slot holds
 * right now, plus the record's fingerprint and its one predecessor.
 *
 * The store's CURRENT CONTENTS are a claim in their own right, not merely the
 * record — so an estate that predates this feature, with no record files at
 * all, is protected from the first write onward instead of needing a migration
 * to become safe.
 */
export function bindingClaimsForAccount(accountUuid: string): Set<string> {
  const claims = new Set<string>();
  if (!isAccountUuid(accountUuid)) return claims;
  const live = credentialFingerprintFromFile(centralCredentialsSnapshot(accountUuid));
  if (live) claims.add(live);
  const record = readCredentialBinding(accountUuid);
  if (record) {
    claims.add(record.fingerprint);
    if (record.supersedes) claims.add(record.supersedes);
  }
  return claims;
}

// --- the claim index ----------------------------------------------------------

/** fingerprint → the account uuids that claim it. Built from the central store. */
export type CredentialClaimIndex = Map<string, string[]>;

function centralAccountUuids(): string[] {
  const root = centralAuthRoot();
  let entries: string[];
  try {
    if (!existsSync(root) || !statSync(root).isDirectory()) return [];
    entries = readdirSync(root);
  } catch {
    return [];
  }
  const uuids: string[] = [];
  for (const entry of entries) {
    // Strict-uuid parity with `listCentralAccounts` and `buildIdentityIndex`: a
    // planted non-uuid directory must never become an account, and must never
    // reach the central path helpers, which throw on malformed input.
    if (!isAccountUuid(entry)) continue;
    try {
      if (!statSync(join(root, entry)).isDirectory()) continue;
    } catch {
      continue;
    }
    uuids.push(entry.toLowerCase());
  }
  return uuids.sort();
}

export function buildCredentialClaimIndex(): CredentialClaimIndex {
  const index: CredentialClaimIndex = new Map();
  for (const uuid of centralAccountUuids()) {
    for (const fingerprint of bindingClaimsForAccount(uuid)) {
      const holders = index.get(fingerprint);
      if (holders) {
        if (!holders.includes(uuid)) holders.push(uuid);
      } else {
        index.set(fingerprint, [uuid]);
      }
    }
  }
  return index;
}

/** Account uuids currently claiming a fingerprint. */
export function credentialClaimants(fingerprint: string, index?: CredentialClaimIndex): string[] {
  return [...((index ?? buildCredentialClaimIndex()).get(fingerprint) ?? [])];
}

// --- the decision -------------------------------------------------------------

/**
 *   bind        nobody claims these bytes — this account may take them
 *   bound       this account already claims them; the write is a no-op or a re-file
 *   cross-write another account claims them — REFUSE
 *   unbindable  the payload carries no refresh token, so it claims nothing
 *
 * Claimed by this account AND another is still `cross-write`: one of the two
 * bindings is false and nothing here can tell which, so the correct action is
 * to stop adding copies rather than to pick a winner. That is the same
 * "unknown is not unreferenced" posture `sweepCentralAuth` already takes.
 */
export type CredentialWriteVerdict = "bind" | "bound" | "cross-write" | "unbindable";

export function classifyCredentialWrite(input: {
  accountUuid: string;
  fingerprint: string | undefined;
  claimants: ReadonlyArray<string>;
}): CredentialWriteVerdict {
  if (!input.fingerprint) return "unbindable";
  const self = input.accountUuid.toLowerCase();
  const others = input.claimants.filter((uuid) => uuid.toLowerCase() !== self);
  if (others.length > 0) return "cross-write";
  return input.claimants.length > 0 ? "bound" : "bind";
}

export interface CredentialBindingRefusal {
  reason: string;
  claimedBy: string[];
  fingerprint: string;
}

/**
 * The gate. `undefined` means "no proven conflict — proceed"; a refusal means
 * these bytes are already another account's credential of record.
 *
 * Used on BOTH sides for the same reason PR #97 made containment symmetric: a
 * credential that may not be WRITTEN under this account may equally not be
 * ADOPTED as this account's source of truth, and gating only one direction is
 * what made the original corruption silent and one-directional.
 */
export function credentialBindingRefusal(
  accountUuid: string,
  bytes: Buffer | string,
  index?: CredentialClaimIndex,
): CredentialBindingRefusal | undefined {
  const fingerprint = credentialFingerprintFromBytes(bytes);
  if (!fingerprint) return undefined;
  const claimants = credentialClaimants(fingerprint, index);
  if (classifyCredentialWrite({ accountUuid, fingerprint, claimants }) !== "cross-write") return undefined;
  const claimedBy = claimants.filter((uuid) => uuid.toLowerCase() !== accountUuid.toLowerCase()).sort();
  return {
    fingerprint,
    claimedBy,
    reason:
      `credential is bound to another account (${claimedBy.join(", ")}); ` +
      `one OAuth credential cannot belong to two identities [${CREDENTIAL_BINDING_METHOD}]`,
  };
}

/** As above, reading the payload from a file. */
export function credentialBindingRefusalForFile(
  accountUuid: string,
  path: string,
  index?: CredentialClaimIndex,
): CredentialBindingRefusal | undefined {
  try {
    if (!existsSync(path)) return undefined;
    return credentialBindingRefusal(accountUuid, readFileSync(path), index);
  } catch {
    return undefined;
  }
}

// --- reporting ----------------------------------------------------------------

export interface CredentialBindingRow {
  accountUuid: string;
  email?: string;
  /** Fingerprint of what the central slot holds right now. */
  fingerprint?: string;
  /** The recorded binding, when one has been written. */
  recorded?: { fingerprint: string; boundAt: string; evidence: string; sourceKind: string; supersedes?: string };
  /** True when the slot's contents differ from the recorded binding. */
  drifted: boolean;
}

export interface CredentialBindingConflict {
  fingerprint: string;
  accountUuids: string[];
  emails: string[];
}

function centralEmail(accountUuid: string): string | undefined {
  const oauth = readJsonFile(centralOAuthSnapshot(accountUuid))?.oauthAccount;
  if (!oauth || typeof oauth !== "object") return undefined;
  const email = (oauth as JsonRecord).emailAddress;
  return typeof email === "string" && email ? email : undefined;
}

export function listCredentialBindings(): CredentialBindingRow[] {
  return centralAccountUuids().map((accountUuid) => {
    const fingerprint = credentialFingerprintFromFile(centralCredentialsSnapshot(accountUuid));
    const record = readCredentialBinding(accountUuid);
    const email = centralEmail(accountUuid);
    return {
      accountUuid,
      ...(email ? { email } : {}),
      ...(fingerprint ? { fingerprint } : {}),
      ...(record
        ? {
            recorded: {
              fingerprint: record.fingerprint,
              boundAt: record.boundAt,
              evidence: record.evidence,
              sourceKind: record.sourceKind,
              ...(record.supersedes ? { supersedes: record.supersedes } : {}),
            },
          }
        : {}),
      // Drift is only meaningful when both sides exist. An account with a slot
      // and no record predates this feature; an account with a record and an
      // empty slot has been blanked, which `auth status` already reports.
      drifted: Boolean(fingerprint && record && record.fingerprint !== fingerprint),
    };
  });
}

/**
 * Credentials claimed by more than one account. Every one of these is provably
 * wrong: at most one of the claims can be true, and the accounts on the losing
 * side have no credential of their own left. Re-authenticating them is the only
 * repair — this reports, it never chooses.
 */
export function credentialBindingConflicts(): CredentialBindingConflict[] {
  const conflicts: CredentialBindingConflict[] = [];
  for (const [fingerprint, accountUuids] of buildCredentialClaimIndex()) {
    if (accountUuids.length < 2) continue;
    const sorted = [...accountUuids].sort();
    conflicts.push({
      fingerprint,
      accountUuids: sorted,
      emails: sorted.map((uuid) => centralEmail(uuid)).filter((e): e is string => Boolean(e)),
    });
  }
  return conflicts.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}
