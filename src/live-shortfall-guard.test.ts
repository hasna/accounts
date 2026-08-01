/**
 * The shortfall guard has to be ARMED by something other than the thing it
 * checks, and it has to say so when it is not.
 *
 * PR #90 added a guard that rejects a render carrying fewer instruction sources
 * than required. Review then found it inert in production: no caller passed
 * `requiredSourceIds`, so the live fallback derived the required set from the
 * SAME export it was validating. That comparison cannot fail. A stale export
 * declaring 3 sources renders 3, `missingSources` is empty, verdict `applied` —
 * which is exactly the state `claude/account005` sat in for weeks while every
 * surface reported it healthy.
 *
 * The failure class is "expected value derived from the thing under test", and
 * it appeared INSIDE a fix written to address that class. So two things are
 * fixed here, and the second matters as much as the first:
 *
 *  1. an INDEPENDENT required set is resolvable at the call site, from
 *     configuration rather than from the export;
 *  2. when no independent set is configured the guard reports itself UNARMED,
 *     instead of silently degrading to the self-comparison and passing.
 *
 * A guard that cannot tell "I checked and it was fine" from "I could not check"
 * is the same defect as the outage it was written to prevent.
 */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runConfigsPrelaunch } from "./lib/configs-prelaunch.js";
import { resolveRequiredInstructionSourceIds } from "./lib/configs-prelaunch.js";
import { addProfile } from "./lib/profiles.js";
import { getTool } from "./lib/tools.js";
import type { Profile } from "./types.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-live-guard-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
  delete process.env.HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
  delete process.env.HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES;
});

/** The canonical rule set a governed Claude home is expected to carry. */
const CANONICAL = [
  "hasna-agent-operating-rules",
  "hasna-global-coding-agent-non-overridable-rules",
  "global-credential-exposure-hygiene",
];

function writeIdentityExport(name: string, ids: string[]): string {
  const path = join(home, `${name}.configs.json`);
  writeFileSync(
    path,
    JSON.stringify({
      contract: "hasna.identities.configs-instructions/v1",
      sources: ids.map((id) => ({ id, layer: "global", content: `content for ${id}` })),
    }) + "\n",
  );
  return path;
}

function manifestWriter(profile: Profile, sourceIds: string[]) {
  return () => {
    const path = join(profile.dir, ".hasna", "session-render-manifest.json");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        schema: "hasna.configs.session-render/v1",
        tool: "claude",
        profile: profile.name,
        targetHome: profile.dir,
        generatedAt: new Date().toISOString(),
        sources: sourceIds.map((id) => ({ id, layer: "global" })),
        files: [],
      }) + "\n",
    );
    return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
  };
}

test("THE ACCOUNT005 CASE: a stale export short of the canonical set is rejected once the guard is armed", () => {
  // The export itself is the stale artefact: it declares only one of the three
  // rules a governed home must carry. The renderer faithfully produces exactly
  // what it was handed, so a guard comparing the render against the export sees
  // nothing wrong. Only an INDEPENDENT expectation catches this.
  const profile = addProfile({ name: "stale", tool: "claude" });
  const staleExport = writeIdentityExport("stale", ["hasna-agent-operating-rules"]);

  expect(() =>
    runConfigsPrelaunch(profile, getTool("claude"), {
      identityExports: [staleExport],
      requiredSourceIds: CANONICAL,
      runner: manifestWriter(profile, ["hasna-agent-operating-rules"]),
    }),
  ).toThrow(/missing 2 of 3 required instruction sources/i);
});

test("the same stale export PASSES when the guard is left to derive its expectation from that export", () => {
  // Not a bug being asserted as correct — this pins the inert behaviour so the
  // difference between armed and unarmed is visible and cannot regress silently.
  const profile = addProfile({ name: "stale-unarmed", tool: "claude" });
  const staleExport = writeIdentityExport("stale-unarmed", ["hasna-agent-operating-rules"]);

  const result = runConfigsPrelaunch(profile, getTool("claude"), {
    identityExports: [staleExport],
    runner: manifestWriter(profile, ["hasna-agent-operating-rules"]),
  });

  expect(result.result).toBe("applied");
  // ...but it must NOT claim the render was verified against anything.
  expect(result.prelaunch.lastRun?.shortfallGuard).toBe("unarmed");
});

test("an armed guard records that it actually checked, so silence is not read as coverage", () => {
  const profile = addProfile({ name: "armed", tool: "claude" });
  const full = writeIdentityExport("armed", CANONICAL);

  const result = runConfigsPrelaunch(profile, getTool("claude"), {
    identityExports: [full],
    requiredSourceIds: CANONICAL,
    runner: manifestWriter(profile, CANONICAL),
  });

  expect(result.result).toBe("applied");
  expect(result.prelaunch.lastRun?.shortfallGuard).toBe("armed");
});

test("the required set is resolvable from configuration, not only from a caller literal", () => {
  process.env.HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES = CANONICAL.join(",");

  expect(resolveRequiredInstructionSourceIds({ env: process.env })).toEqual(CANONICAL);
});

test("an explicit caller list beats the environment, and whitespace/empties are ignored", () => {
  process.env.HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES = " a , , b ,";

  expect(resolveRequiredInstructionSourceIds({ env: process.env })).toEqual(["a", "b"]);
  expect(resolveRequiredInstructionSourceIds({ env: process.env, explicit: ["c"] })).toEqual(["c"]);
});

test("no configuration means no required set — reported as absent, never invented", () => {
  expect(resolveRequiredInstructionSourceIds({ env: {} })).toEqual([]);
});

test("configuration arms the guard end to end, without the caller passing a literal", () => {
  process.env.HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES = CANONICAL.join(",");
  const profile = addProfile({ name: "env-armed", tool: "claude" });
  const staleExport = writeIdentityExport("env-armed", ["hasna-agent-operating-rules"]);

  expect(() =>
    runConfigsPrelaunch(profile, getTool("claude"), {
      identityExports: [staleExport],
      requiredSourceIds: resolveRequiredInstructionSourceIds({ env: process.env }),
      runner: manifestWriter(profile, ["hasna-agent-operating-rules"]),
    }),
  ).toThrow(/missing 2 of 3 required instruction sources/i);
});
