/**
 * A launch into a home that carries NO operating rules must be refused,
 * whether or not a render was attempted.
 *
 * WHY THIS TEST EXISTS
 * On station01 (2026-08-07) `claude/account095` was ACTIVE and APPLIED, had been
 * running since 14:49Z under `accounts launch ... --permissions dangerous`, and
 * its config dir contained no rules file, no `.hasna/instructions`, and no render
 * manifest. `accounts doctor` gave it a tick identical to a healthy profile. An
 * agent in that session ran with no credential hygiene, no worktree rule and no
 * operating rules, and had no way to know they existed. Todos `OPE15-00059`.
 *
 * THE MECHANISM, and it is the reason a test at this level is the right one.
 * Every instruction guard in this module lives INSIDE the render path:
 *
 *   - the empty-source guard      (`mode === "apply" && identityExports.length === 0`)
 *   - the incumbent floor         (`resolveIncumbentFloor`)
 *   - the post-render shortfall   (`missingSources`)
 *
 * `--skip-configs` does not weaken those guards. It returns before the code that
 * contains them, so all three are unreachable in one flag.
 *
 * AND THE DEFAULT PATH DOES NOT COVER THIS EITHER, which is the half that is easy
 * to get wrong. `--allow-empty-instructions` documents itself as "fails closed
 * otherwise", and it does — it fails closed on RENDERING an empty home OVER an
 * existing one. `empty-instruction-render.test.ts` path 2 pins that behaviour
 * deliberately: zero sources means skip the render, keep the home, let the launch
 * proceed. That is correct when the home has rules to keep. When the home is
 * ALREADY empty there is nothing to keep, and the same branch walks an ungoverned
 * launch straight through.
 *
 * So the check here is deliberately NOT part of the render. It reads the home's
 * STATE, costs a directory probe, and asks one question the render path cannot:
 * "this launch will not render, so the home as it stands is what the agent gets —
 * is that home governed?"
 *
 * WHAT MUST NOT REGRESS, pinned below as much as the defect itself:
 *  - a stale-but-present home still launches (path 2 of the render test),
 *  - `--allow-empty-instructions` still launches an empty home on purpose,
 *  - a tool with no configs session support is unaffected.
 */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  assertGovernedInstructionHome,
  assessInstructionHome,
  runConfigsPrelaunch,
} from "./lib/configs-prelaunch.js";
import { addProfile } from "./lib/profiles.js";
import { getTool } from "./lib/tools.js";
import type { Profile } from "./types.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-ungoverned-launch-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});

/** A home that has been rendered: per-source files plus the manifest that names them. */
function renderInstructionHome(profile: Profile, tool: string, ids = ["hasna-agent-operating-rules"]) {
  const dir = join(profile.dir, ".hasna", "instructions");
  mkdirSync(dir, { recursive: true });
  ids.forEach((id, i) => {
    writeFileSync(join(dir, `${String(i + 1).padStart(2, "0")}-${id}.md`), `# ${id}\n`);
  });
  const manifestPath = join(profile.dir, ".hasna", "session-render-manifest.json");
  mkdirSync(dirname(manifestPath), { recursive: true });
  writeFileSync(
    manifestPath,
    JSON.stringify({
      schema: "hasna.configs.session-render/v1",
      tool,
      profile: profile.name,
      targetHome: profile.dir,
      generatedAt: new Date().toISOString(),
      sources: ids.map((id) => ({ id, layer: "global" })),
      files: [],
      warnings: [],
    }) + "\n",
  );
}

/** A runner that must never be reached; reaching it means a render was attempted. */
function forbiddenRunner() {
  return () => {
    throw new Error("the renderer must not run on this path");
  };
}

// ---------------------------------------------------------------------------
// THE DEFECT: --skip-configs walks an ungoverned home straight into a launch.
// ---------------------------------------------------------------------------

test("a launch into a home with no operating rules is refused", () => {
  // Exactly account095: an empty config dir, reached by a launch that skipped
  // the render. The prelaunch itself is happy — that is the defect.
  const profile = addProfile({ name: "account095like", tool: "claude" });

  const prelaunch = runConfigsPrelaunch(profile, getTool("claude"), {
    mode: "skip",
    skipReason: "--skip-configs",
    runner: forbiddenRunner(),
  });
  expect(prelaunch.skipped).toBe(true);

  // ...and the launch boundary is what stops it.
  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).toThrow(/no operating rules/i);
});

test("the refusal names the profile and the way out, so an operator is never wedged", () => {
  const profile = addProfile({ name: "account095like", tool: "claude" });

  let message = "";
  try {
    assertGovernedInstructionHome(profile, getTool("claude"));
  } catch (err) {
    message = err instanceof Error ? err.message : String(err);
  }

  expect(message).toContain("claude/account095like");
  expect(message).toContain("--allow-empty-instructions");
});

test("the guard reads the home's STATE, so --skip-configs keeps its point", () => {
  // A render is never attempted: this is a directory probe. The whole reason
  // --skip-configs exists is to avoid re-rendering a known-good home, and a
  // check that had to render in order to answer would take that away.
  const profile = addProfile({ name: "probe-only", tool: "claude" });
  renderInstructionHome(profile, "claude");

  const assessment = assessInstructionHome(profile);

  expect(assessment.state).toBe("governed");
  expect(assessment.instructionFileCount).toBe(1);
  expect(assessment.manifestExists).toBe(true);
});

// ---------------------------------------------------------------------------
// THE SECOND HOLE, on the path that was believed to fail closed already.
// ---------------------------------------------------------------------------

test("the DEFAULT apply path is not covered either, and is refused too", () => {
  // No --skip-configs anywhere. The empty-source guard fires, keeps the home and
  // returns `skipped` — correct when the home HAS rules, and exactly wrong when
  // it does not. `--allow-empty-instructions` says it "fails closed otherwise",
  // and it does: closed against WRITING an empty home over a full one, not
  // against LAUNCHING one that is already empty.
  const profile = addProfile({ name: "starved-and-empty", tool: "claude" });

  const prelaunch = runConfigsPrelaunch(profile, getTool("claude"), {
    runner: () => ({ status: 0, stdout: Buffer.from(""), stderr: Buffer.from("") }),
  });
  expect(prelaunch.result).toBe("skipped");

  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).toThrow(/no operating rules/i);
});

// ---------------------------------------------------------------------------
// WHAT MUST NOT REGRESS.
// ---------------------------------------------------------------------------

test("--skip-configs into a home that already carries rules still launches", () => {
  // The whole point of the flag: the home is known good, a render is wasteful.
  const profile = addProfile({ name: "governed", tool: "claude" });
  renderInstructionHome(profile, "claude");

  const result = runConfigsPrelaunch(profile, getTool("claude"), {
    mode: "skip",
    skipReason: "--skip-configs",
    runner: forbiddenRunner(),
  });

  expect(result.skipped).toBe(true);
  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).not.toThrow();
});

test("--allow-empty-instructions still launches an empty home on purpose", () => {
  // The single documented override. Its help text already promises exactly this
  // ("render a home with no operating rules on purpose (fails closed otherwise)").
  const profile = addProfile({ name: "deliberately-empty", tool: "claude" });

  expect(() =>
    assertGovernedInstructionHome(profile, getTool("claude"), { allowEmptySources: true }),
  ).not.toThrow();
});

test("a stale-but-present home with only an index file still launches", () => {
  // `empty-instruction-render.test.ts` path 2, restated as a guard assertion.
  // That test writes a bare `CLAUDE.md` and nothing else, and pins it as a home
  // that must survive. A predicate reading only `.hasna/instructions` plus the
  // manifest calls it empty and turns a preserved home into a dead launch —
  // which is the 0.2.9 breakage, and worse than the defect this file fixes.
  // Measured: that exact predicate broke 7 of this repo's own tests.
  const profile = addProfile({ name: "stale-index-only", tool: "claude" });
  writeFileSync(join(profile.dir, "CLAUDE.md"), "# claude session instructions\n\nPR-first landing.\n");

  const assessment = assessInstructionHome(profile);

  expect(assessment.state).toBe("governed");
  expect(assessment.instructionFileCount).toBe(0);
  expect(assessment.manifestExists).toBe(false);
  expect(assessment.indexFileCount).toBe(1);
  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).not.toThrow();
});

test("a tool with no configs session support is unaffected", () => {
  // Nothing renders instructions for it, so an empty home is its normal state
  // and refusing would break every launch of it. `gemini` is a real tool here
  // and is deliberately absent from CONFIGS_SESSION_TOOL_IDS.
  const profile = addProfile({ name: "other", tool: "gemini" });

  expect(() => assertGovernedInstructionHome(profile, getTool("gemini"))).not.toThrow();
});

test("a freshly rendered home passes the guard", () => {
  // The first-render path must stay open: a brand-new profile is empty until the
  // render fills it, and this guard runs after that render, never before it.
  const profile = addProfile({ name: "fresh", tool: "claude" });
  const ids = ["hasna-agent-operating-rules"];
  const exportPath = join(home, "fresh.configs.json");
  writeFileSync(
    exportPath,
    JSON.stringify({
      contract: "hasna.identities.configs-instructions/v1",
      sources: ids.map((id) => ({ id, layer: "global", content: `content for ${id}` })),
    }) + "\n",
  );

  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).toThrow(/no operating rules/i);

  const result = runConfigsPrelaunch(profile, getTool("claude"), {
    identityExports: [exportPath],
    runner: () => {
      renderInstructionHome(profile, "claude", ids);
      return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
    },
  });

  expect(result.result).toBe("applied");
  expect(() => assertGovernedInstructionHome(profile, getTool("claude"))).not.toThrow();
});
