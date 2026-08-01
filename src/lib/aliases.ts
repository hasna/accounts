// R-P1-4 (2026-07-31-accounts-debloat-design.md): "a rename is recorded, not
// just performed". A renamed record gains `aliases: [<old-name>]` and
// `nativeName: <tool-native/on-disk name>` (schema: src/types.ts). This module
// is the read-path lookup both transports share: given the full profile set
// and a queried name, which OTHER profiles record that name as a former name
// of themselves.
//
// Deliberately NOT a store method: it operates on an already-loaded profile
// list (LocalStore already holds one; ApiStore's `listProfiles()` fetches
// one), so no new HTTP route or repo query is needed for this — see the PR
// description for why that is the intended scope.

import type { Profile } from "../types.js";

/**
 * Profiles whose `aliases` history includes `name` — i.e. `name` used to be
 * their registry name before a rename.
 */
export function findAliasHolders(profiles: readonly Profile[], name: string): Profile[] {
  return profiles.filter((p) => (p.aliases ?? []).includes(name));
}

/**
 * The disambiguation line `accounts show <old-name>` prints per alias holder.
 * Exact wording from the design doc's worked example:
 * "alias note: 'account005' is also the former/native name of
 * account005-codewith (codewith)".
 */
export function formatAliasNote(queriedName: string, holder: Profile): string {
  return `alias note: '${queriedName}' is also the former/native name of ${holder.name} (${holder.tool})`;
}
