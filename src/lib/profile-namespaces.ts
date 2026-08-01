// Enumerate every profile directory on this machine, across every provider
// namespace — and say plainly which store is authoritative.
//
// AUTHORITY, because getting this backwards builds an enumerator that cannot
// see its own fixtures. The PRIMARY universe is the store's records (the server
// `accounts` table via the cloud transport, or accounts.json in local mode) —
// that is what `accounts list` returns and what the acceptance gate reads. Two
// of the named regression fixtures, `account01` and `account024`, have NO local
// directory and NO accounts.json row on station01: they exist only as server
// rows. A disk-first enumerator would report them absent and pass.
//
// Disk is therefore SUPPLEMENTARY: it finds directories no store row describes
// (opencode and browserplan dirs are unregistered today), which is drift worth
// reporting, not a competing source of truth.
//
// Two layouts, both real:
//   managed — `<accountsHome>/profiles/<provider>/<name>`
//   native  — `<tool.defaultDir>/<tool.nativeProfilesDir>/<name>`, for tools
//             that own their profile mechanism (codewith's `auth_profiles`,
//             which holds 22 of the merged view's records)
//
// The native root comes from the tool definition, never from a mapping kept
// here — see `nativeProfilesDir` in src/types.ts for why.

import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { profileProvider } from "../types.js";
import { profilesDir } from "../storage.js";
import type { NameBinding } from "./name-invariant.js";

export type ProfileDirLayout = "managed" | "native";

export interface DiscoveredProfileDir {
  provider: string;
  /** The directory's own name, which may differ from any registry row's name. */
  name: string;
  dir: string;
  layout: ProfileDirLayout;
}

/** Where a tool keeps its own profile dirs, if it has such a place. */
export function nativeProfilesRoot(tool: ToolDef): string | undefined {
  if (!tool.nativeProfilesDir) return undefined;
  return join(tool.defaultDir, tool.nativeProfilesDir);
}

function childDirectories(root: string): string[] {
  if (!existsSync(root)) return [];
  let names: string[];
  try {
    names = readdirSync(root);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const name of names) {
    if (name.startsWith(".")) continue;
    try {
      if (statSync(join(root, name)).isDirectory()) out.push(name);
    } catch {
      // A dir that vanished or is unreadable is not a profile we can describe.
    }
  }
  return out.sort();
}

/**
 * Every profile directory discoverable on disk, for every provider in `tools`.
 *
 * Read-only and non-throwing: an unreadable root yields no rows rather than
 * aborting the sweep, because this feeds a reconcile report whose whole job is
 * to run on a machine that is already inconsistent.
 */
export function enumerateProfileDirs(tools: readonly ToolDef[]): DiscoveredProfileDir[] {
  const found: DiscoveredProfileDir[] = [];
  const managedRoot = profilesDir();
  for (const tool of tools) {
    for (const name of childDirectories(join(managedRoot, tool.id))) {
      found.push({ provider: tool.id, name, dir: join(managedRoot, tool.id, name), layout: "managed" });
    }
    const native = nativeProfilesRoot(tool);
    if (!native) continue;
    for (const name of childDirectories(native)) {
      found.push({ provider: tool.id, name, dir: join(native, name), layout: "native" });
    }
  }
  return found;
}

/**
 * The merged (name, provider) universe the invariant is evaluated against.
 *
 * Store records first and they win: a store row carries the email the violation
 * message needs, and a directory of the same name under the same provider is
 * the same binding seen twice, not a second one. Disk-only rows are appended so
 * an unregistered directory still participates in the check.
 */
export function mergedNameUniverse(
  records: readonly Profile[],
  discovered: readonly DiscoveredProfileDir[] = [],
): NameBinding[] {
  const universe: NameBinding[] = [];
  const seen = new Set<string>();
  for (const record of records) {
    const provider = profileProvider(record);
    const key = `${record.name} ${provider}`;
    if (seen.has(key)) continue;
    seen.add(key);
    universe.push({
      name: record.name,
      provider,
      ...(record.email ? { email: record.email } : {}),
      source: "store",
    });
  }
  for (const dir of discovered) {
    const key = `${dir.name} ${dir.provider}`;
    if (seen.has(key)) continue;
    seen.add(key);
    universe.push({ name: dir.name, provider: dir.provider, source: `disk:${dir.layout}` });
  }
  return universe;
}
