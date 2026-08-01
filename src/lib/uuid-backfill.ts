// Backfill each profile's `accountUuid` from evidence, and refuse to guess.
//
// THE THREE JOINS THAT LOOK RIGHT AND ARE FORBIDDEN.
//
//   by NAME       — the profile named `account005` and the central entry whose
//                   email is `account005@…` are not related. Names collide
//                   across providers (23 records do) and are what this series
//                   exists to disambiguate; joining on one would launder the
//                   ambiguity into a uuid binding that then looks authoritative.
//
//   by CREDENTIAL — the census measured 9 distinct credentials across 18
//                   accounts. Identical bytes in two places is the SIGNATURE OF
//                   CONTAMINATION, not a join key: at most one of the two
//                   claims is true and this code cannot say which. Joining on a
//                   fingerprint would bind both profiles to one account and
//                   erase the evidence that they disagreed.
//
//   by OCCUPANT   — `.claude.json` names whoever is in the directory RIGHT NOW.
//                   `switch-account` copies a credential into whatever dir the
//                   session is using, so a dir routinely holds a foreign
//                   identity while still answering to its own name. Reading the
//                   occupant binds the profile to the visitor.
//
// The only admissible source is the dir's PARKED own identity —
// `.accounts-auth/oauth-account.json`, which `switch-account` preserves
// precisely so the dir's own account survives a visit — and it is admitted only
// after being confirmed present in the central store. A parked uuid the central
// store does not know is REPORTED, never applied: it is a finding, not a fact.
//
// Nothing here writes. It plans, and `--apply` is the caller's decision.

import { isAccountUuid } from "./auth-store.js";
import type { ProfileRegistry, RegistryEntry } from "./profile-registry.js";

export type BackfillOutcome =
  /** Parked identity resolved and confirmed centrally; safe to write. */
  | "backfilled"
  /** Already bound to exactly this uuid; writing would be a no-op. */
  | "already-set"
  /** Bound to a DIFFERENT uuid than the parked identity. Never overwritten. */
  | "conflict"
  /** No parked identity to read. Stays null and earns a health finding. */
  | "unresolved"
  /** Parked identity present but unknown to the central store. Not applied. */
  | "unverified";

export interface BackfillPlanEntry {
  profileName?: string;
  provider: string;
  dir: string;
  /** Set only for `backfilled` — the uuid a caller may write. */
  accountUuid?: string;
  /** The uuid already recorded on the profile, when there is one. */
  existingAccountUuid?: string;
  outcome: BackfillOutcome;
  reason: string;
}

export interface BackfillSummary {
  backfilled: number;
  alreadySet: number;
  conflict: number;
  unresolved: number;
  unverified: number;
}

/**
 * Plan the backfill for every entry in `registry`.
 *
 * `existing` maps profile name -> the accountUuid already on its record, so a
 * value that disagrees with the evidence surfaces as `conflict` rather than
 * being silently replaced. A conflict is a real finding: it means the record
 * and the directory disagree about which account this profile is.
 */
export function planAccountUuidBackfill(
  registry: ProfileRegistry,
  existing: ReadonlyMap<string, string> = new Map(),
): BackfillPlanEntry[] {
  const centralUuids = new Set(registry.central.map((entry) => entry.accountUuid.toLowerCase()));
  const plan = registry.entries.map((entry) => planOne(entry, centralUuids, existing));
  return resolveDuplicateClaims(plan, existing);
}

/**
 * CRITICAL, task 2b15400e. `planOne` decides each row in isolation, so it
 * cannot see that two different profiles both independently resolved the SAME
 * parked identity — two directories can each genuinely carry the same
 * `.accounts-auth/oauth-account.json` uuid (a stale copy, a botched restore, a
 * shared parent dir), and per-row planning reads both as clean, confirmed,
 * `backfilled` rows. Measured live on 2026-08-01: one uuid proposed for
 * account001/account002/account088, a second for account032/account039, and
 * `summary.conflict` read 0 throughout — the exact guard this series exists to
 * provide, reporting clean while the condition it guards against is present.
 *
 * `backfilled` is documented as "confirmed, safe to write"
 * (docs/name-invariant.md). A uuid claimed by more than one profile is not
 * safe to write for ANY of them: at most one binding can be correct and
 * nothing here can say which — the identical epistemic problem the per-row
 * `conflict` outcome already refuses to guess through for a single profile
 * whose existing record disagrees with its parked identity. This is that same
 * refusal, applied across rows instead of within one: reuse `conflict` rather
 * than invent a second outcome, so `applyAccountUuidBackfill` (which already
 * writes only `backfilled` rows) requires no change to stop applying these.
 *
 * Deliberately NOT a whole-plan abort: an unrelated, unambiguous row elsewhere
 * in the same plan is untouched and still backfills. Refusing the entire run
 * over one duplicate would also block every unrelated, already-confirmed
 * profile in it, which is the same reasoning docs/name-invariant.md gives for
 * why the merged-universe check WARNS instead of refusing outright while real
 * data is dirty. The narrower, per-row refusal already closes the actual
 * hazard: `--apply` will never write a uuid this function cannot say is
 * uniquely claimed.
 *
 * CYCLE 1 REMEDIATION (independent review, Seneca). The first pass at this
 * only compared freshly PROPOSED (`backfilled`) rows against each other. It
 * missed the same defect reached a different way: a uuid already RECORDED on
 * one profile (an `already-set` row — the store's existing binding, which
 * `planOne` only ever reaches by confirming it agrees with that profile's own
 * parked identity) is a real, standing claim regardless of what this plan
 * proposes elsewhere. A different profile whose OWN parked identity
 * independently resolves to that same uuid still looked `backfilled`, because
 * its row-level check only ever compares against ITS OWN existing entry (which
 * is empty), never another profile's. `existing` is therefore seeded into the
 * same claimant map as every freshly proposed uuid: an `already-set` profile
 * never itself reaches `backfilled` (`planOne` returns `already-set` or
 * `conflict` whenever `existing` has an entry for it), so seeding cannot cause
 * a row to collide with itself — only a genuinely different profile's proposal
 * against an already-recorded uuid. This is reachable through the tool's own
 * dry-run -> apply -> re-run workflow: the moment any profile has been
 * backfilled once, this gap is live for every subsequent invocation, which is
 * exactly the state the fleet is in after `--apply` first runs.
 */
function resolveDuplicateClaims(
  plan: BackfillPlanEntry[],
  existing: ReadonlyMap<string, string>,
): BackfillPlanEntry[] {
  interface Claimant {
    label: string;
    kind: "existing" | "proposed";
    row?: BackfillPlanEntry;
  }

  const claimants = new Map<string, Claimant[]>();

  // Seed with what the store ALREADY records. Real regardless of what this
  // plan proposes elsewhere, and never redundant with a `backfilled` row for
  // the SAME profile: `planOne` only reaches `backfilled` when `existing` has
  // no entry for that profile name.
  for (const [name, uuid] of existing) {
    const lower = uuid.toLowerCase();
    const list = claimants.get(lower) ?? [];
    list.push({ label: name, kind: "existing" });
    claimants.set(lower, list);
  }

  // Add every freshly proposed backfill.
  for (const row of plan) {
    if (row.outcome !== "backfilled" || !row.accountUuid) continue;
    const list = claimants.get(row.accountUuid) ?? [];
    list.push({ label: row.profileName ?? "(unregistered)", kind: "proposed", row });
    claimants.set(row.accountUuid, list);
  }

  const disputed = new Map([...claimants.entries()].filter(([, rows]) => rows.length > 1));
  if (disputed.size === 0) return plan;

  return plan.map((row) => {
    const uuid = row.accountUuid;
    if (row.outcome !== "backfilled" || !uuid || !disputed.has(uuid)) return row;
    // Excluded by object identity, not by label — labels are not unique
    // (multiple unregistered dirs all read "(unregistered)").
    const siblings = disputed
      .get(uuid)!
      .filter((claimant) => claimant.row !== row)
      .map((claimant) =>
        claimant.kind === "existing" ? `already recorded on ${claimant.label}` : `also proposed for ${claimant.label}`,
      );
    const { accountUuid: _drop, ...withoutUuid } = row;
    return {
      ...withoutUuid,
      outcome: "conflict",
      reason:
        `${uuid} is ${siblings.join("; ")}; refusing to apply — ` +
        "a uuid claimed by more than one profile means at most one binding is correct and this cannot say which",
    };
  });
}

function planOne(
  entry: RegistryEntry,
  centralUuids: ReadonlySet<string>,
  existing: ReadonlyMap<string, string>,
): BackfillPlanEntry {
  const base = {
    ...(entry.profileName ? { profileName: entry.profileName } : {}),
    provider: entry.tool,
    dir: entry.dir,
  };
  const current = entry.profileName ? existing.get(entry.profileName) : undefined;
  const withCurrent = current ? { ...base, existingAccountUuid: current } : base;

  // ONLY the parked own identity. Never entry.occupant, never a fingerprint.
  const parked = entry.own.accountUuid;
  if (!parked) {
    return {
      ...withCurrent,
      outcome: "unresolved",
      reason:
        "no parked identity at .accounts-auth/oauth-account.json; the profile's own account " +
        "cannot be established from this directory without guessing",
    };
  }
  if (!isAccountUuid(parked)) {
    return {
      ...withCurrent,
      outcome: "unverified",
      reason: "parked identity is not a well-formed account uuid",
    };
  }

  const uuid = parked.toLowerCase();
  if (!centralUuids.has(uuid)) {
    return {
      ...withCurrent,
      outcome: "unverified",
      reason: `parked identity ${uuid} has no entry in the central auth store; reported, not applied`,
    };
  }

  if (current) {
    if (current.toLowerCase() === uuid) {
      return { ...withCurrent, outcome: "already-set", reason: "record already bound to the parked identity" };
    }
    return {
      ...withCurrent,
      outcome: "conflict",
      reason:
        `record is bound to ${current.toLowerCase()} but the directory's parked identity is ${uuid}; ` +
        "refusing to overwrite — one of the two bindings is wrong and this cannot say which",
    };
  }

  return {
    ...withCurrent,
    accountUuid: uuid,
    outcome: "backfilled",
    reason: "parked identity confirmed in the central auth store",
  };
}

/** The narrow slice of the store the apply step needs. */
export interface BackfillApplyTarget {
  updateProfile(name: string, opts: { tool?: string; accountUuid?: string }): Promise<unknown>;
}

/**
 * Write the `backfilled` rows of `plan`, and nothing else.
 *
 * The provider is passed on every update ON PURPOSE. Name alone is ambiguous
 * for exactly the records this exists to repair: a colliding name resolves to
 * "exists for multiple tools" and the update throws, so a name-only apply fails
 * on its own target population while succeeding on every record that did not
 * need it. That is the failure this function was extracted to make testable.
 */
export async function applyAccountUuidBackfill(
  store: BackfillApplyTarget,
  plan: readonly BackfillPlanEntry[],
): Promise<string[]> {
  const applied: string[] = [];
  for (const row of plan) {
    if (row.outcome !== "backfilled" || !row.profileName || !row.accountUuid) continue;
    await store.updateProfile(row.profileName, { tool: row.provider, accountUuid: row.accountUuid });
    applied.push(row.profileName);
  }
  return applied;
}

export function summarizeBackfill(plan: readonly BackfillPlanEntry[]): BackfillSummary {
  const summary: BackfillSummary = {
    backfilled: 0,
    alreadySet: 0,
    conflict: 0,
    unresolved: 0,
    unverified: 0,
  };
  for (const row of plan) {
    if (row.outcome === "backfilled") summary.backfilled += 1;
    else if (row.outcome === "already-set") summary.alreadySet += 1;
    else if (row.outcome === "conflict") summary.conflict += 1;
    else if (row.outcome === "unresolved") summary.unresolved += 1;
    else summary.unverified += 1;
  }
  return summary;
}
