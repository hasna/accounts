// The merged universe, the grandfather manifest, and the WARN-mode load check.
//
// The design's first review cycle was rejected because the gate and the
// enumerator read different stores. These tests pin the enumeration's shape and
// — critically — assert the load-time check WARNS rather than throws, with a
// positive control proving it can detect a collision at all.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Profile, ToolDef } from "./types.js";
import {
  enumerateProfileDirs,
  mergedNameUniverse,
  nativeProfilesRoot,
} from "./lib/profile-namespaces.js";
import {
  grandfatherManifestPath,
  grandfatheredPairs,
  readGrandfatherManifest,
  removeGrandfatherManifest,
  writeGrandfatherManifest,
} from "./lib/grandfather-manifest.js";
import { loadStore, resetCollisionReportState, INVARIANT_QUIET_ENV } from "./storage.js";
import { getTool } from "./lib/tools.js";

let home: string;
let prevHome: string | undefined;
let prevQuiet: string | undefined;

beforeEach(() => {
  prevHome = process.env.ACCOUNTS_HOME;
  prevQuiet = process.env[INVARIANT_QUIET_ENV];
  delete process.env[INVARIANT_QUIET_ENV];
  home = mkdtempSync(join(tmpdir(), "accounts-universe-"));
  process.env.ACCOUNTS_HOME = home;
  resetCollisionReportState();
});

afterEach(() => {
  if (prevHome === undefined) delete process.env.ACCOUNTS_HOME;
  else process.env.ACCOUNTS_HOME = prevHome;
  if (prevQuiet === undefined) delete process.env[INVARIANT_QUIET_ENV];
  else process.env[INVARIANT_QUIET_ENV] = prevQuiet;
  rmSync(home, { recursive: true, force: true });
  resetCollisionReportState();
});

function profile(name: string, tool: string, extra: Partial<Profile> = {}): Profile {
  return {
    name,
    tool,
    dir: join(home, "profiles", tool, name),
    createdAt: new Date(0).toISOString(),
    ...extra,
  } as Profile;
}

/** Capture everything written to stderr while `fn` runs. */
function captureStderr(fn: () => void): string {
  const original = process.stderr.write.bind(process.stderr);
  let captured = "";
  (process.stderr as unknown as { write: unknown }).write = ((chunk: unknown) => {
    captured += String(chunk);
    return true;
  }) as unknown as typeof process.stderr.write;
  try {
    fn();
  } finally {
    (process.stderr as unknown as { write: unknown }).write = original;
  }
  return captured;
}

function writeStoreFile(profiles: Profile[]): void {
  mkdirSync(home, { recursive: true });
  writeFileSync(
    join(home, "accounts.json"),
    JSON.stringify({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles, tools: [] }),
  );
}

describe("tool-native profile roots come from the tool definition", () => {
  test("codewith declares auth_profiles; claude declares none", () => {
    // The mapping lives in the ToolDef (src/lib/builtin-tools.ts), not in the
    // enumerator — so a tool that grows its own profiles root is picked up by
    // declaring it, not by editing the sweep.
    expect(nativeProfilesRoot(getTool("codewith"))).toMatch(/\.codewith\/auth_profiles$/);
    expect(nativeProfilesRoot(getTool("claude"))).toBeUndefined();
  });
});

describe("enumerateProfileDirs", () => {
  function fakeTool(id: string, defaultDir: string, nativeProfilesDir?: string): ToolDef {
    return {
      id,
      label: id,
      envVar: "FAKE_HOME",
      defaultDir,
      bin: id,
      ...(nativeProfilesDir ? { nativeProfilesDir } : {}),
    } as ToolDef;
  }

  test("finds managed dirs under <accountsHome>/profiles/<provider>/", () => {
    mkdirSync(join(home, "profiles", "claude", "acct-a"), { recursive: true });
    mkdirSync(join(home, "profiles", "claude", "acct-b"), { recursive: true });
    const found = enumerateProfileDirs([fakeTool("claude", join(home, "toolhome-claude"))]);
    expect(found.map((f) => f.name).sort()).toEqual(["acct-a", "acct-b"]);
    expect(new Set(found.map((f) => f.layout))).toEqual(new Set(["managed"]));
  });

  test("finds NATIVE dirs under the tool's own profiles root", () => {
    // The unregistered-namespace case the design calls out: these dirs hold real
    // bindings and no registry row describes them.
    const toolHome = join(home, "toolhome-codewith");
    mkdirSync(join(toolHome, "auth_profiles", "native-one"), { recursive: true });
    const found = enumerateProfileDirs([fakeTool("codewith", toolHome, "auth_profiles")]);
    expect(found).toEqual([
      {
        provider: "codewith",
        name: "native-one",
        dir: join(toolHome, "auth_profiles", "native-one"),
        layout: "native",
      },
    ]);
  });

  test("a missing or unreadable root yields no rows instead of throwing", () => {
    expect(enumerateProfileDirs([fakeTool("ghost", join(home, "nope"), "auth_profiles")])).toEqual([]);
  });
});

describe("mergedNameUniverse", () => {
  test("store records are primary and carry the email a violation message needs", () => {
    const universe = mergedNameUniverse([profile("acct", "claude", { email: "a@example.com" })], []);
    expect(universe).toEqual([{ name: "acct", provider: "claude", email: "a@example.com", source: "store" }]);
  });

  test("a disk dir duplicating a store record is the same binding, not a second one", () => {
    const universe = mergedNameUniverse(
      [profile("acct", "claude", { email: "a@example.com" })],
      [{ provider: "claude", name: "acct", dir: "/x", layout: "managed" }],
    );
    expect(universe.length).toBe(1);
    expect(universe[0]!.source).toBe("store");
  });

  test("a disk-only dir still participates in the universe", () => {
    const universe = mergedNameUniverse(
      [profile("acct", "claude")],
      [{ provider: "codewith", name: "acct", dir: "/x", layout: "native" }],
    );
    expect(universe.length).toBe(2);
    expect(universe.find((b) => b.provider === "codewith")!.source).toBe("disk:native");
  });
});

describe("grandfather manifest", () => {
  test("round-trips and dedupes pairs", () => {
    writeGrandfatherManifest(
      [
        { name: "acct", provider: "claude", email: "a@example.com" },
        { name: "acct", provider: "claude" },
        { name: "acct", provider: "codewith" },
      ],
      "test",
    );
    const manifest = readGrandfatherManifest()!;
    expect(manifest.pairs.length).toBe(2);
    expect(grandfatheredPairs().map((p) => p.provider).sort()).toEqual(["claude", "codewith"]);
  });

  test("absent manifest grandfathers nothing", () => {
    expect(readGrandfatherManifest()).toBeUndefined();
    expect(grandfatheredPairs()).toEqual([]);
  });

  test("a malformed manifest reads as ABSENT — it may only widen, never brick a read", () => {
    mkdirSync(home, { recursive: true });
    writeFileSync(grandfatherManifestPath(), "{ not json");
    expect(readGrandfatherManifest()).toBeUndefined();
    expect(grandfatheredPairs()).toEqual([]);
  });

  test("removal is idempotent (PR-2 deletes it after the rename migration)", () => {
    writeGrandfatherManifest([{ name: "acct", provider: "claude" }], "test");
    expect(removeGrandfatherManifest()).toBe(true);
    expect(removeGrandfatherManifest()).toBe(false);
  });
});

describe("load-time duplicate-name check ships in WARN mode", () => {
  test("a cross-provider duplicate WARNS and loadStore still returns the store", () => {
    writeStoreFile([profile("shared", "claude", { email: "c@example.com" }), profile("shared", "codewith")]);
    let store: ReturnType<typeof loadStore> | undefined;
    const stderr = captureStderr(() => {
      store = loadStore();
    });
    // Warned...
    expect(stderr).toContain("name-invariant warning");
    expect(stderr).toContain("shared");
    expect(stderr).toContain("claude");
    expect(stderr).toContain("codewith");
    // ...and did NOT refuse. Both records are still readable, which is the
    // whole point: a hard check here would brick every command on today's data.
    expect(store!.profiles.length).toBe(2);
  });

  test("the warning is emitted once per collision signature, not once per call", () => {
    writeStoreFile([profile("shared", "claude"), profile("shared", "codewith")]);
    const first = captureStderr(() => {
      loadStore();
    });
    const second = captureStderr(() => {
      loadStore();
      loadStore();
    });
    expect(first).toContain("name-invariant warning");
    expect(second).toBe("");
  });

  test("POSITIVE CONTROL: a clean store produces no warning", () => {
    // Without this, "no warning" in a later run cannot be told apart from a
    // check that never fires.
    writeStoreFile([profile("alpha", "claude"), profile("beta", "codewith")]);
    expect(captureStderr(() => loadStore())).toBe("");
  });

  test("the warning is suppressible for scripted consumers", () => {
    writeStoreFile([profile("shared", "claude"), profile("shared", "codewith")]);
    process.env[INVARIANT_QUIET_ENV] = "1";
    expect(captureStderr(() => loadStore())).toBe("");
  });
});
