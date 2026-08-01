/**
 * A rules-free agent home must never be reported as a healthy prelaunch.
 *
 * WHY THIS TEST EXISTS
 * On station01 (2026-07-30) twenty-six profile homes carried a four-line
 * CLAUDE.md / CODEWITH.md with ZERO operating rules: no safety text, no review
 * policy, nothing. An agent launched on one of them ran ungoverned. Every
 * surface called this fine — the render manifest said `sources: []` with a
 * warning, and accounts recorded `result: applied, statusCode: 0`, which
 * `accounts health` then reported as `configs: ok`.
 *
 * The cause was here: `configsPrelaunchCommand` added `--allow-empty-sources`
 * automatically whenever a profile had no identity export, which is the normal
 * state of every `accountNNN` profile on this fleet. The renderer already fails
 * closed on an empty source set; accounts opted out of that protection on every
 * call and then graded the result as a pass.
 *
 * Failing closed is the point. Operators who genuinely want an empty home ask
 * for one (`allowEmptySources`), and callers that must launch regardless still
 * have `allowFailure` / `--skip-configs` — but the empty render is recorded as
 * a failure instead of disappearing into a green check.
 */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { configsPrelaunchCommand, runConfigsPrelaunch } from "./lib/configs-prelaunch.js";
import { addProfile } from "./lib/profiles.js";
import { getTool } from "./lib/tools.js";
import type { Profile } from "./types.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-empty-render-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});


/** A minimal valid instruction export, so a test can exercise the WITH-sources path. */
function writeIdentityExport(name: string, ids: string[] = ["hasna-agent-operating-rules"]): string {
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

/** Stand in for the renderer, writing the manifest accounts inspects afterwards. */
function manifestWriter(profile: Profile, tool: string, sourceIds: string[]) {
  return () => {
    const path = join(profile.dir, ".hasna", "session-render-manifest.json");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        schema: "hasna.configs.session-render/v1",
        tool,
        profile: profile.name,
        targetHome: profile.dir,
        generatedAt: new Date().toISOString(),
        sources: sourceIds.map((id) => ({ id, layer: "global" })),
        files: [],
        warnings: sourceIds.length === 0 ? ["No instruction sources were provided."] : [],
      }) + "\n",
    );
    return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
  };
}

test("an identity-less profile does not silently opt out of the renderer's empty-source guard", () => {
  const profile = addProfile({ name: "starved", tool: "claude" });

  const command = configsPrelaunchCommand(profile, getTool("claude"));

  expect(command).not.toContain("--identity-export");
  // The renderer's own guard must stay armed. Passing this flag on every
  // identity-less call is what produced twenty-six rules-free agent homes.
  expect(command).not.toContain("--allow-empty-sources");
});

test("an explicitly requested empty render still passes the flag", () => {
  const profile = addProfile({ name: "deliberate", tool: "claude" });

  const command = configsPrelaunchCommand(profile, getTool("claude"), { allowEmptySources: true });

  expect(command).toContain("--allow-empty-sources");
});

test("a profile with instruction sources never asks for an empty render", () => {
  const profile = addProfile({ name: "sourced", tool: "claude" });

  const command = configsPrelaunchCommand(profile, getTool("claude"), {
    identityExports: ["/tmp/some-identity.json"],
  });

  expect(command).toContain("--identity-export");
  expect(command).not.toContain("--allow-empty-sources");
});

// The three paths a prelaunch can take. All three are pinned, because the
// failure this file exists for was fixed twice in opposite directions before:
// rendering an empty home (agents run ungoverned) and refusing to render
// (every pooled launch aborts, which is the 0.2.9 breakage).

test("path 1 — sources resolve, so the home is rendered", () => {
  const profile = addProfile({ name: "governed", tool: "claude" });
  const tool = getTool("claude");

  const result = runConfigsPrelaunch(profile, tool, {
    identityExports: [writeIdentityExport("governed")],
    runner: manifestWriter(profile, "claude", ["hasna-agent-operating-rules"]),
  });

  expect(result.skipped).toBe(false);
  expect(result.result).toBe("applied");
  expect(result.prelaunch.status).toBe("ok");
});

test("path 2 — zero sources: skip, leave the home untouched, let the launch proceed", () => {
  const profile = addProfile({ name: "starved", tool: "claude" });
  const tool = getTool("claude");
  // A home that already carries rules from an earlier render. Stale-but-present
  // must survive: it is strictly better than the empty home that replaced it.
  const indexPath = join(profile.dir, "CLAUDE.md");
  writeFileSync(indexPath, "# claude session instructions\n\nPR-first landing is the default.\n");
  const before = readFileSync(indexPath, "utf8");

  let rendererCalls = 0;
  const result = runConfigsPrelaunch(profile, tool, {
    runner: () => {
      rendererCalls += 1;
      return { status: 0, stdout: Buffer.from(""), stderr: Buffer.from("") };
    },
  });

  // Never invoked, so it cannot have written an empty home.
  expect(rendererCalls).toBe(0);
  expect(readFileSync(indexPath, "utf8")).toBe(before);
  // Skipped, not applied: `accounts health` must not read this as governed.
  expect(result.skipped).toBe(true);
  expect(result.result).toBe("skipped");
  expect(result.prelaunch.status).not.toBe("ok");
  // Loud: the reason names the profile and the way out.
  expect(result.reason).toMatch(/no instruction sources resolved/i);
  expect(result.reason).toContain("accounts set starved --tool claude --identity");
});

test("path 2 does not throw, because a bare `accounts launch` would abort on it", () => {
  const profile = addProfile({ name: "starved", tool: "claude" });
  const tool = getTool("claude");

  // No allowFailure: this is exactly how `accounts launch accountNNN --tool
  // claude --permissions dangerous` calls it, ~15 concurrent on the fleet.
  expect(() =>
    runConfigsPrelaunch(profile, tool, {
      runner: () => ({ status: 0, stdout: Buffer.from(""), stderr: Buffer.from("") }),
    }),
  ).not.toThrow();
});

test("path 3 — a genuine render failure is still surfaced, not swallowed", () => {
  const profile = addProfile({ name: "broken", tool: "claude" });
  const tool = getTool("claude");

  expect(() =>
    runConfigsPrelaunch(profile, tool, {
      identityExports: [writeIdentityExport("broken")],
      runner: () => ({ status: 1, stdout: Buffer.from(""), stderr: Buffer.from("renderer exploded") }),
    }),
  ).toThrow(/configs prelaunch apply failed/i);
});

test("an explicit empty render is still allowed to write one", () => {
  const profile = addProfile({ name: "deliberate", tool: "claude" });
  const tool = getTool("claude");

  const result = runConfigsPrelaunch(profile, tool, {
    allowEmptySources: true,
    runner: manifestWriter(profile, "claude", []),
  });

  expect(result.skipped).toBe(false);
  expect(result.result).toBe("applied");
});

test("path 4 — a PARTIAL render is rejected, because a shortfall reads exactly like success", () => {
  // The quiet half of this defect, and the one that survived weeks rather than
  // hours. `claude/account005` rendered 3 of 10 sources — missing the core
  // operating rules and the credential-hygiene rule — while the command exited
  // 0, the manifest parsed, drift said `ok` and accounts recorded `applied`.
  // A guard that only rejects ZERO waves that through as a governed home.
  const profile = addProfile({ name: "partial", tool: "claude" });
  const tool = getTool("claude");
  const exportPath = writeIdentityExport("partial", [
    "hasna-agent-operating-rules",
    "global-credential-exposure-hygiene",
    "hasna-global-coding-agent-system-prompt",
  ]);

  expect(() =>
    runConfigsPrelaunch(profile, tool, {
      identityExports: [exportPath],
      // The renderer emits only one of the three it was handed.
      runner: manifestWriter(profile, "claude", ["hasna-global-coding-agent-system-prompt"]),
    }),
  ).toThrow(/missing 2 of 3 required instruction sources/i);
});

test("the shortfall message names what is actually missing, so nobody has to diff a manifest", () => {
  const profile = addProfile({ name: "partial", tool: "claude" });
  const tool = getTool("claude");
  const exportPath = writeIdentityExport("partial", [
    "hasna-agent-operating-rules",
    "global-credential-exposure-hygiene",
  ]);

  const result = runConfigsPrelaunch(profile, tool, {
    allowFailure: true,
    identityExports: [exportPath],
    runner: manifestWriter(profile, "claude", ["global-credential-exposure-hygiene"]),
  });

  expect(result.result).toBe("bypassed");
  expect(result.reason).toContain("hasna-agent-operating-rules");
  expect(result.prelaunch.status).not.toBe("ok");
});

test("a caller can demand specific rules regardless of what the export happens to carry", () => {
  const profile = addProfile({ name: "underspecified", tool: "claude" });
  const tool = getTool("claude");
  const exportPath = writeIdentityExport("underspecified", ["some-unrelated-rule"]);

  expect(() =>
    runConfigsPrelaunch(profile, tool, {
      identityExports: [exportPath],
      requiredSourceIds: ["hasna-agent-operating-rules"],
      runner: manifestWriter(profile, "claude", ["some-unrelated-rule"]),
    }),
  ).toThrow(/missing 1 of 1 required instruction sources/i);
});

test("a complete render passes the shortfall guard", () => {
  const profile = addProfile({ name: "complete", tool: "claude" });
  const tool = getTool("claude");
  const ids = ["hasna-agent-operating-rules", "global-credential-exposure-hygiene"];
  const exportPath = writeIdentityExport("complete", ids);

  const result = runConfigsPrelaunch(profile, tool, {
    identityExports: [exportPath],
    runner: manifestWriter(profile, "claude", ids),
  });

  expect(result.result).toBe("applied");
  expect(result.prelaunch.status).toBe("ok");
});
