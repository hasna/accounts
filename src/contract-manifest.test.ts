// Manifest-honesty regression tests.
//
// `hasna.contract.json` exists so fleet tooling can trust it WITHOUT reading the
// source. That only holds if every claim in it is true of the code. The
// dual-engine `storage_capabilities` conformance gate requires class "service"
// repos to declare both sqlite and postgres and admits no waiver for this class
// (waivers are restricted to class "cli-with-store", and are additionally
// refused for a repo shipping <name>-serve or declaring the cloud placement).
// The declaration is therefore forced. What must NOT happen is the manifest
// growing further fabricated detail on top of it — in particular a sqlitePath
// pointing at a file this package never creates.

import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SQLITE_DRIVER_PATTERN = /\b(?:bun:sqlite|better-sqlite3|node:sqlite)\b/;

interface Manifest {
  description?: string;
  storage?: {
    engines?: string[];
    sqlitePath?: string;
  };
  metadata?: {
    storageNotes?: Record<string, string>;
  };
}

function readManifest(): Manifest {
  return JSON.parse(
    readFileSync(join(import.meta.dir, "../hasna.contract.json"), "utf8"),
  ) as Manifest;
}

/**
 * Shipped TypeScript sources under `dir`. Test files are excluded: the claim
 * under test is about the code this package ships, and a test that plants a
 * driver import as a control would otherwise match itself.
 */
function shippedSources(dir: string, found: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      shippedSources(path, found);
      continue;
    }
    if (!entry.endsWith(".ts")) continue;
    if (entry.endsWith(".test.ts") || entry.endsWith(".integration.ts")) continue;
    found.push(path);
  }
  return found;
}

function sourcesImportingSqlite(dir: string): string[] {
  return shippedSources(dir).filter((path) => SQLITE_DRIVER_PATTERN.test(readFileSync(path, "utf8")));
}

describe("hasna.contract.json storage claims", () => {
  test("the sqlite scan finds a planted driver import in a real source tree", () => {
    // Positive control for the absence assertion below. Planting the defect on
    // disk exercises the directory walk, the extension filter and the pattern
    // together — a regex-only control would not prove the walk reaches files.
    const root = mkdtempSync(join(tmpdir(), "accounts-sqlite-control-"));
    try {
      mkdirSync(join(root, "nested"), { recursive: true });
      writeFileSync(join(root, "clean.ts"), 'import { readFileSync } from "node:fs";\n');
      expect(sourcesImportingSqlite(root)).toEqual([]);

      const planted = join(root, "nested", "planted.ts");
      writeFileSync(planted, 'import { Database } from "bun:sqlite";\n');
      expect(sourcesImportingSqlite(root)).toEqual([planted]);

      // The exclusion must not swallow a real driver: a planted *test* file is
      // ignored by design, which is why the control above uses a shipped file.
      writeFileSync(join(root, "planted.test.ts"), 'import { Database } from "bun:sqlite";\n');
      expect(sourcesImportingSqlite(root)).toEqual([planted]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("no sqlitePath is declared, because no .db file is ever created", () => {
    // The previous manifest pointed sqlitePath at the real JSON registry, which
    // was mislabelled but at least existed. Declaring a .db path instead points
    // fleet tooling at a file that will never appear. sqlitePath is optional for
    // class "service", so the honest declaration is no declaration.
    const manifest = readManifest();
    expect(manifest.storage?.sqlitePath).toBeUndefined();

    expect(shippedSources(import.meta.dir).length).toBeGreaterThan(50);
    expect(sourcesImportingSqlite(import.meta.dir)).toEqual([]);
  });

  test("the gate-mandated sqlite engine declaration carries a note explaining it", () => {
    // If `storage.engines` must claim sqlite to pass conformance, the manifest
    // has to say so in the manifest itself — otherwise the next reader takes the
    // declaration at face value, which is precisely what it must not do.
    const manifest = readManifest();
    if (!manifest.storage?.engines?.includes("sqlite")) return;
    expect(manifest.metadata?.storageNotes?.sqlite ?? "").toContain("no SQLite driver");
  });

  test("the description names the real single-box store", () => {
    const manifest = readManifest();
    expect(manifest.description).toContain("accounts.json");
  });
});
