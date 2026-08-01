// The set of (name, provider) bindings that already existed when PR-1 landed.
//
// WHY IT EXISTS. Ten names are held by more than one provider today, and six of
// the colliding records are codewith accounts the loops runtime routes to. The
// b29f5b6c materialization fix is forcing those accounts to re-login RIGHT NOW.
// An invariant that treats a re-login as a new binding would block exactly the
// repair the rest of this series depends on — so existing pairs are recorded
// once, at install, and never counted as violations.
//
// It is deliberately a SNAPSHOT and not a rule: it is written from the same
// enumerator the invariant reads, so a pair that exists only on another machine
// is in the manifest and its re-login is not over-blocked. PR-2's migration
// renames the colliders and DELETES this file; after that there is no
// grandfathering and the invariant is total. A manifest that outlives the
// migration is itself the defect, which is why {@link isGrandfatherManifestStale}
// exists and the reconcile report prints its age.

import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { accountsHome } from "../storage.js";
import { writeFileAtomic } from "./safe-path.js";
import type { NameBinding } from "./name-invariant.js";

export const GRANDFATHER_MANIFEST_FILE = "grandfather-manifest.json";

export function grandfatherManifestPath(): string {
  return join(accountsHome(), GRANDFATHER_MANIFEST_FILE);
}

const manifestSchema = z.object({
  version: z.literal(1),
  createdAt: z.string(),
  /** Which enumerator produced it, so two manifests can be told apart. */
  source: z.string(),
  pairs: z
    .array(
      z.object({
        name: z.string().min(1),
        provider: z.string().min(1),
        email: z.string().optional(),
      }),
    )
    .default([]),
});

export type GrandfatherManifest = z.infer<typeof manifestSchema>;

/**
 * Read the manifest, or undefined when there is none.
 *
 * A malformed manifest reads as ABSENT rather than throwing. The manifest only
 * ever widens what is allowed, so losing it fails toward warning more, never
 * toward allowing more — and a corrupt file must not brick every registry read
 * during the very window this exists to keep working.
 */
export function readGrandfatherManifest(): GrandfatherManifest | undefined {
  const path = grandfatherManifestPath();
  if (!existsSync(path)) return undefined;
  try {
    const parsed = manifestSchema.safeParse(JSON.parse(readFileSync(path, "utf8")));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** The grandfathered pairs, or an empty list when there is no manifest. */
export function grandfatheredPairs(): NameBinding[] {
  const manifest = readGrandfatherManifest();
  if (!manifest) return [];
  return manifest.pairs.map((pair) => ({
    name: pair.name,
    provider: pair.provider,
    ...(pair.email ? { email: pair.email } : {}),
    source: "grandfathered",
  }));
}

export function writeGrandfatherManifest(
  pairs: readonly NameBinding[],
  source: string,
): GrandfatherManifest {
  const seen = new Set<string>();
  const deduped: GrandfatherManifest["pairs"] = [];
  for (const pair of pairs) {
    const key = `${pair.name} ${pair.provider}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push({
      name: pair.name,
      provider: pair.provider,
      ...(pair.email ? { email: pair.email } : {}),
    });
  }
  deduped.sort((a, b) => a.name.localeCompare(b.name) || a.provider.localeCompare(b.provider));
  const manifest: GrandfatherManifest = {
    version: 1,
    createdAt: new Date().toISOString(),
    source,
    pairs: deduped,
  };
  writeFileAtomic(grandfatherManifestPath(), JSON.stringify(manifest, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
  return manifest;
}

/** PR-2 calls this after the rename migration; the invariant is total after it. */
export function removeGrandfatherManifest(): boolean {
  const path = grandfatherManifestPath();
  if (!existsSync(path)) return false;
  rmSync(path, { force: true });
  return true;
}
