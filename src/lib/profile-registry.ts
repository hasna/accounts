import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";
import {
  centralAuthRoot,
  centralCredentialsSnapshot,
  centralOAuthSnapshot,
  isAccountUuid,
} from "./auth-store.js";
import {
  dirCredentialsFile,
  profileAccountJsonPaths,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
  profileSwitchedAccountMarker,
} from "./claude-layout.js";

/**
 * THE BRIDGE BETWEEN THE THREE THINGS A PROFILE ACTUALLY IS.
 *
 * A profile is a NAME, a DIRECTORY, and a CREDENTIAL, and this codebase stores
 * those three in three different places that nothing reconciles:
 *
 *   name -> dir        the accounts store (registry row)
 *   dir  -> identity   `.claude.json` oauthAccount (LIVE, current occupant)
 *                      `.accounts-auth/oauth-account.json` (PARKED, own identity)
 *   dir  -> credential `.credentials.json` (live) and
 *                      `.accounts-auth/credentials.json` (parked)
 *   uuid -> credential `~/.hasna/accounts/auth/<uuid>/` (central store)
 *
 * `switch-account` copies a credential INTO whatever directory the session is
 * using, so after one in-place switch a directory named `accountNNN` routinely
 * holds a different account's credential while still answering to its own name.
 * That is why one `switch-account` invocation can print three different account
 * names — the target identity, the directory it landed in, and a third profile
 * guessed as the directory's previous owner — and why nothing on the machine
 * can tell you which of the three is the account that will actually serve the
 * next request.
 *
 * This module is READ-ONLY and computes that reconciliation. It mutates
 * nothing, moves nothing, and deletes nothing: the directories it reads are the
 * only surviving copy of several credentials, and a "tidy-up" here is
 * unrecoverable.
 *
 * IT COMPUTES, IT DOES NOT RECORD. Two careful operators hand-censusing the
 * same 28 directories within one hour produced different groupings, because
 * each applied a slightly different rule for what counts as an empty file. A
 * registry that stores a grouping inherits whichever mistake its author made; a
 * registry that derives one from a rule stated in code is corrected by
 * re-running it. So the rule lives in {@link classifyCredentialPresence} and
 * {@link CREDENTIAL_GROUPING_METHOD}, and every group carries the method that
 * produced it.
 *
 * NO CREDENTIAL VALUE IS EVER READ INTO A RETURNED FIELD. Grouping uses a
 * digest of the file's bytes; the token itself is never parsed out, never
 * logged, and never returned.
 */

/** Files this small are placeholders (`{}`), not credentials. */
export const EMPTY_CREDENTIAL_MAX_BYTES = 4;

/**
 * Stated so consumers can tell whether two registries were built the same way,
 * and so a future change to the rule is visible in the output rather than
 * silently reshaping every group.
 */
export const CREDENTIAL_GROUPING_METHOD =
  `md5 of credential file bytes; files of <=${EMPTY_CREDENTIAL_MAX_BYTES} bytes are classified empty and excluded from grouping`;

/**
 * The verification that would turn the inference below into a fact, recorded
 * because nobody can run it by reading files: exhaust one member of a group,
 * then immediately probe a sibling that has run no work. A sibling that is
 * already rate-limited shares the upstream account.
 */
export const CREDENTIAL_IDENTITY_VERIFICATION_PATH =
  "exhaust one member, then immediately probe a sibling that has run no work; a sibling limited without working shares the upstream account";

/**
 * Three states, because they need three different actions and collapsing them
 * is where both hand-censuses diverged. `empty` is a real, common state here:
 * a `{}` placeholder is not a missing file and not a credential.
 */
export type CredentialPresence = "absent" | "empty" | "present";

export interface CredentialFacts {
  path: string;
  presence: CredentialPresence;
  bytes: number;
  /** Digest of the file's bytes. Present only when `presence` is `present`. */
  fingerprint?: string;
  mtime?: string;
}

export interface IdentityFacts {
  accountUuid?: string;
  email?: string;
}

export interface SwitchMarker {
  profile: string;
  email?: string;
  switchedAt?: string;
}

/**
 * What the directory's own identity and its current occupant say about each
 * other. `occupied` versus `displaced` is the load-bearing pair: both mean
 * somebody else's account is in the live files, but `displaced` was recorded by
 * `switch-account` and is therefore explained and reversible, while `occupied`
 * happened without a marker — an in-session `/login`, or a write this tool
 * cannot account for.
 */
export type BindingVerdict =
  | "consistent"
  | "displaced"
  | "occupied"
  | "unbound"
  | "vacant";

export interface RegistryEntry {
  profileName?: string;
  tool: string;
  dir: string;
  /** Parked `.accounts-auth/oauth-account.json` — survives in-place switches. */
  own: IdentityFacts;
  /** Live `.claude.json` oauthAccount — whoever is in the dir right now. */
  occupant: IdentityFacts;
  marker?: SwitchMarker;
  liveCredential: CredentialFacts;
  parkedCredential: CredentialFacts;
  binding: BindingVerdict;
}

export interface CentralEntry {
  accountUuid: string;
  email?: string;
  credential: CredentialFacts;
}

export interface GroupMember {
  /** Where the copy lives: a profile dir layer, or the central store. */
  layer: "live" | "parked" | "central";
  dir?: string;
  profileName?: string;
  accountUuid?: string;
  email?: string;
}

/**
 * Why one credential appears in several places. Identical bytes have three
 * causes with three different remedies, and reporting only the grouping loses
 * the remedy — which is how three symptoms of one exhausted account were
 * diagnosed as three separate bugs in one hour.
 */
export type GroupCause = "aliasing" | "displacement" | "contamination" | "indeterminate";

export interface GroupInference {
  cause: GroupCause;
  why: string;
  confidence: "high" | "medium" | "low";
  method: string;
  /**
   * Always null: no code path here can confirm upstream account identity.
   * Present as a field so a later measurement fills it in rather than
   * rewriting the shape.
   */
  verified: null;
  verificationPath: string;
}

export interface CredentialGroup {
  fingerprint: string;
  members: GroupMember[];
  distinctAccountUuids: string[];
  distinctEmails: string[];
  inference: GroupInference;
}

export interface ProfileRegistry {
  generatedAt: string;
  method: string;
  entries: RegistryEntry[];
  central: CentralEntry[];
  /** Every fingerprint held in more than one place, live/parked/central. */
  groups: CredentialGroup[];
  /**
   * Groups whose members declare more than one account identity. One credential
   * cannot belong to two accounts, so at most one declaration in each of these
   * is true — and this tool cannot say which.
   */
  contradictions: CredentialGroup[];
}

function readJson(path: string): Record<string, unknown> | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Classify a credential file WITHOUT parsing the payload.
 *
 * Deliberately byte-level: the point is to compare copies, and a structural
 * read would both invite a token into a variable and make the digest depend on
 * how the payload happened to be serialised.
 */
export function classifyCredentialPresence(path: string): CredentialFacts {
  if (!existsSync(path)) return { path, presence: "absent", bytes: 0 };
  let bytes = 0;
  let mtime: string | undefined;
  try {
    const stat = statSync(path);
    bytes = stat.size;
    mtime = new Date(stat.mtimeMs).toISOString();
  } catch {
    return { path, presence: "absent", bytes: 0 };
  }
  if (bytes <= EMPTY_CREDENTIAL_MAX_BYTES) {
    return { path, presence: "empty", bytes, ...(mtime ? { mtime } : {}) };
  }
  let fingerprint: string;
  try {
    fingerprint = createHash("md5").update(readFileSync(path)).digest("hex");
  } catch {
    return { path, presence: "absent", bytes, ...(mtime ? { mtime } : {}) };
  }
  return { path, presence: "present", bytes, fingerprint, ...(mtime ? { mtime } : {}) };
}

function identityFrom(record: Record<string, unknown> | undefined): IdentityFacts {
  const oauth = record?.oauthAccount;
  const source = (oauth && typeof oauth === "object" ? oauth : record) as
    | Record<string, unknown>
    | undefined;
  if (!source) return {};
  const uuid = source.accountUuid;
  const email = source.emailAddress ?? source.email;
  return {
    ...(typeof uuid === "string" && uuid
      ? { accountUuid: isAccountUuid(uuid) ? uuid.toLowerCase() : uuid }
      : {}),
    ...(typeof email === "string" && email ? { email } : {}),
  };
}

function readMarker(dir: string): SwitchMarker | undefined {
  const record = readJson(profileSwitchedAccountMarker(dir));
  const profile = record?.profile;
  if (typeof profile !== "string" || !profile) return undefined;
  const email = record?.email;
  const switchedAt = record?.switchedAt;
  return {
    profile,
    ...(typeof email === "string" && email ? { email } : {}),
    ...(typeof switchedAt === "string" && switchedAt ? { switchedAt } : {}),
  };
}

function verdictFor(
  own: IdentityFacts,
  occupant: IdentityFacts,
  marker: SwitchMarker | undefined,
  live: CredentialFacts,
): BindingVerdict {
  if (!own.accountUuid && !occupant.accountUuid) {
    return live.presence === "present" ? "unbound" : "vacant";
  }
  if (!own.accountUuid) return "unbound";
  if (!occupant.accountUuid) return "vacant";
  if (own.accountUuid === occupant.accountUuid) return "consistent";
  return marker ? "displaced" : "occupied";
}

/** Read one profile directory into its three-layer facts. */
export function readRegistryEntry(
  profile: { name?: string; dir: string },
  tool: ToolDef,
): RegistryEntry {
  const { dir } = profile;
  let occupant: IdentityFacts = {};
  for (const path of profileAccountJsonPaths(dir, tool)) {
    const found = identityFrom(readJson(path));
    if (found.accountUuid) {
      occupant = found;
      break;
    }
  }
  const own = identityFrom(readJson(profileOAuthSnapshot(dir)));
  const marker = readMarker(dir);
  const liveCredential = classifyCredentialPresence(dirCredentialsFile(dir));
  const parkedCredential = classifyCredentialPresence(profileCredentialsSnapshot(dir));
  return {
    ...(profile.name ? { profileName: profile.name } : {}),
    tool: tool.id,
    dir,
    own,
    occupant,
    ...(marker ? { marker } : {}),
    liveCredential,
    parkedCredential,
    binding: verdictFor(own, occupant, marker, liveCredential),
  };
}

function readCentralEntries(): CentralEntry[] {
  const root = centralAuthRoot();
  if (!existsSync(root)) return [];
  const entries: CentralEntry[] = [];
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return [];
  }
  for (const name of names) {
    if (!isAccountUuid(name)) continue;
    try {
      if (!statSync(join(root, name)).isDirectory()) continue;
    } catch {
      continue;
    }
    const uuid = name.toLowerCase();
    const identity = identityFrom(readJson(centralOAuthSnapshot(uuid)));
    entries.push({
      accountUuid: uuid,
      ...(identity.email ? { email: identity.email } : {}),
      credential: classifyCredentialPresence(centralCredentialsSnapshot(uuid)),
    });
  }
  return entries.sort((a, b) => a.accountUuid.localeCompare(b.accountUuid));
}

/**
 * Why one credential appears in several places.
 *
 * The order of these tests is the whole argument. DISPLACEMENT IS CHECKED
 * FIRST AND ON EVIDENCE, because it is the only cause the filesystem can prove:
 * `switch-account` writes a marker when it puts one profile's credential into
 * another profile's directory, and that marker plus a parked own-identity says
 * outright "this copy is a visitor". Only copies that displacement does NOT
 * explain can be read as a claim on the credential — and it is disagreement
 * among *those* that means contamination.
 *
 * Getting this order wrong inverts the meaning: counting a displaced visitor as
 * a competing claim turns a normal, reversible switch into a false corruption
 * report, and counting a cross-write as aliasing hides real data loss behind a
 * tidy group.
 */
function inferCause(
  members: GroupMember[],
  byDir: Map<string, RegistryEntry>,
): GroupInference {
  const base = {
    method: CREDENTIAL_GROUPING_METHOD,
    verified: null as null,
    verificationPath: CREDENTIAL_IDENTITY_VERIFICATION_PATH,
  };

  // A live copy in a directory carrying a switch marker is a VISITOR and makes
  // no claim on the credential.
  //
  // Keyed on the marker itself rather than on the derived `displaced` verdict,
  // because a switch that failed partway leaves the guest's credential in the
  // live files while `.claude.json` still names the host — which reads as
  // `consistent` and would put the HOST's identity forward as a claimant on the
  // GUEST's credential, manufacturing a contradiction out of a normal switch.
  // `switch-account` clears the marker when a dir is restored to its own
  // account, so a marker that is still present means a visitor is still in.
  const displacedMembers = members.filter((m) => {
    if (m.layer !== "live" || !m.dir) return false;
    return byDir.get(m.dir)?.marker !== undefined;
  });

  const claimants = members.filter((m) => !displacedMembers.includes(m));
  const claimUuids = [...new Set(claimants.map((m) => m.accountUuid).filter((v): v is string => !!v))].sort();
  const claimEmails = [...new Set(claimants.map((m) => m.email).filter((v): v is string => !!v))].sort();

  if (claimUuids.length > 1) {
    return {
      ...base,
      cause: "contamination",
      confidence: "high",
      why:
        `${claimUuids.length} different accounts` +
        (claimEmails.length > 1 ? ` (${claimEmails.join(", ")})` : "") +
        ` claim this one credential in copies that displacement does not explain. One credential cannot belong to several accounts, so all but at most one of these bindings is a cross-write, and those accounts have lost their own credential — deleting any copy here destroys evidence, not a duplicate.`,
    };
  }

  if (displacedMembers.length > 0) {
    return {
      ...base,
      cause: "displacement",
      confidence: "high",
      why:
        `${displacedMembers.length} of these copies are visitors: a recorded switch put this credential into a directory whose own identity is a different account, whose credential is still parked in .accounts-auth/. Those profiles are distinct accounts, not copies, and restoring them is reversible.`,
    };
  }

  if (claimUuids.length === 1) {
    return {
      ...base,
      cause: "aliasing",
      confidence: "medium",
      why:
        "every copy that displacement does not explain declares the same account, so these directories look like additional doors onto one account rather than separate accounts — strong evidence, but identical bytes are not confirmation of upstream identity",
    };
  }

  return {
    ...base,
    cause: "indeterminate",
    confidence: "low",
    why: "no copy carries an account identity, so the evidence on disk does not separate aliasing from a cross-write",
  };
}

function groupFrom(
  fingerprint: string,
  members: GroupMember[],
  byDir: Map<string, RegistryEntry>,
): CredentialGroup {
  const distinctAccountUuids = [...new Set(members.map((m) => m.accountUuid).filter((v): v is string => !!v))].sort();
  const distinctEmails = [...new Set(members.map((m) => m.email).filter((v): v is string => !!v))].sort();
  return {
    fingerprint,
    members,
    distinctAccountUuids,
    distinctEmails,
    inference: inferCause(members, byDir),
  };
}

/**
 * Build the whole picture: every profile's three layers, the central store, and
 * the credential groups across all of them.
 *
 * `profiles` comes from the accounts store, so a directory nobody registered is
 * absent by construction — that is the registry row's job, and inventing
 * entries for unregistered directories here would give two sources of truth for
 * which profiles exist.
 */
export function buildProfileRegistry(
  profiles: ReadonlyArray<{ name?: string; dir: string }>,
  tool: ToolDef,
): ProfileRegistry {
  const entries = profiles.map((profile) => readRegistryEntry(profile, tool));
  const central = readCentralEntries();

  const byFingerprint = new Map<string, GroupMember[]>();
  const add = (facts: CredentialFacts, member: Omit<GroupMember, "layer"> & { layer: GroupMember["layer"] }) => {
    if (facts.presence !== "present" || !facts.fingerprint) return;
    const list = byFingerprint.get(facts.fingerprint) ?? [];
    list.push(member);
    byFingerprint.set(facts.fingerprint, list);
  };

  for (const entry of entries) {
    add(entry.liveCredential, {
      layer: "live",
      dir: entry.dir,
      ...(entry.profileName ? { profileName: entry.profileName } : {}),
      ...(entry.occupant.accountUuid ? { accountUuid: entry.occupant.accountUuid } : {}),
      ...(entry.occupant.email ? { email: entry.occupant.email } : {}),
    });
    add(entry.parkedCredential, {
      layer: "parked",
      dir: entry.dir,
      ...(entry.profileName ? { profileName: entry.profileName } : {}),
      ...(entry.own.accountUuid ? { accountUuid: entry.own.accountUuid } : {}),
      ...(entry.own.email ? { email: entry.own.email } : {}),
    });
  }
  for (const entry of central) {
    add(entry.credential, {
      layer: "central",
      accountUuid: entry.accountUuid,
      ...(entry.email ? { email: entry.email } : {}),
    });
  }

  const byDir = new Map(entries.map((entry) => [entry.dir, entry]));
  const groups = [...byFingerprint.entries()]
    .filter(([, members]) => members.length > 1)
    .map(([fingerprint, members]) => groupFrom(fingerprint, members, byDir))
    .sort((a, b) => b.members.length - a.members.length || a.fingerprint.localeCompare(b.fingerprint));

  return {
    generatedAt: new Date().toISOString(),
    method: CREDENTIAL_GROUPING_METHOD,
    entries,
    central,
    groups,
    // Contamination only. A displaced visitor also puts two identities on one
    // fingerprint, and reporting that as a contradiction would drown the real
    // ones in normal switch traffic.
    contradictions: groups.filter((g) => g.inference.cause === "contamination"),
  };
}

/**
 * The lookup a switch-target selector needs: the credential a profile would
 * actually present, keyed so that two names backed by one credential collapse.
 *
 * Selecting by profile NAME is what makes an exhausted account look like
 * several candidates — a name-walk lands on a sibling backed by the same
 * credential and fails identically and instantly. Cooldown and reset state
 * belong on this key, never on the profile name.
 */
export function credentialKeyForEntry(entry: RegistryEntry): string | undefined {
  if (entry.liveCredential.presence === "present") return entry.liveCredential.fingerprint;
  if (entry.parkedCredential.presence === "present") return entry.parkedCredential.fingerprint;
  return undefined;
}

/** Profile names grouped by the credential they would actually present. */
export function profilesByCredential(registry: ProfileRegistry): Map<string, string[]> {
  const byKey = new Map<string, string[]>();
  for (const entry of registry.entries) {
    const key = credentialKeyForEntry(entry);
    if (!key || !entry.profileName) continue;
    const list = byKey.get(key) ?? [];
    list.push(entry.profileName);
    byKey.set(key, list);
  }
  return byKey;
}
