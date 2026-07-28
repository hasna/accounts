import { describe, expect, test } from "bun:test";
import { AccountsError } from "../types.js";
import fixture from "../../test/fixtures/production-profile-dirs.json";
import {
  assertRegistrableProfileDir,
  builtinToolHomeRoots,
  classifyProfileDir,
  classifyToolHomeDir,
  defaultProfileDirPolicy,
  resolveProfileDirPolicy,
} from "./profile-dir-policy.js";

describe("classifyProfileDir", () => {
  test("accepts the managed profiles root", () => {
    expect(
      classifyProfileDir("/home/hasna/.hasna/accounts/profiles/claude/account003"),
    ).toEqual({ ok: true });
  });

  test("accepts other tool homes on either home root", () => {
    for (const dir of [
      "/home/hasna/.codewith/auth_profiles/account009",
      "/home/hasna/.claude",
      "/home/hasna/.config/opencode",
      "/Users/hasna/.hasna/accounts/profiles/codex-app/account001",
      "/Users/andreihasna/.codewith/auth_profiles/account020",
    ]) {
      expect(classifyProfileDir(dir)).toEqual({ ok: true });
    }
  });

  test("rejects /tmp — the leak that polluted the production registry", () => {
    const result = classifyProfileDir("/tmp/accounts-login-cli-1ITud2/profiles/claude/acct");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("ephemeral-root");
  });

  test("rejects every ephemeral root, not just /tmp", () => {
    for (const dir of [
      "/tmp/x/prof",
      "/var/tmp/prof",
      "/private/tmp/prof",
      "/private/var/folders/ab/cd/prof",
      "/var/folders/ab/cd/prof",
      "/dev/shm/prof",
      "/run/user/1000/prof",
    ]) {
      const result = classifyProfileDir(dir);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason.code).toBe("ephemeral-root");
    }
  });

  test("rejects an agent scratchpad under /tmp even when deeply nested", () => {
    const result = classifyProfileDir(
      "/tmp/claude-1000/-home-hasna--hasna-projects/abc/scratchpad/accounts-home/profiles/claude/swa-demo-a",
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("ephemeral-root");
  });

  test("rejects a non-dot directory under home (not a tool home)", () => {
    const result = classifyProfileDir("/home/hasna/scratch/prof");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("outside-profile-roots");
  });

  // Regression: CI redirects tmpdir() into the checkout under
  // node_modules/.cache, producing a path that IS under a home root but whose
  // first segment is `work`. This is correctly refused — the point of recording
  // it is that such a path must never be judged by a CLIENT, because the client
  // may legitimately be writing to a test double rather than to production.
  test("rejects a CI checkout path under a home root", () => {
    const result = classifyProfileDir(
      "/home/runner/work/accounts/accounts/node_modules/.cache/accounts-tests/worker-b2VcWH/case-300/tmp/accounts-store-tools-LFBsC5/profiles/acme/work",
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("outside-profile-roots");
  });

  test("rejects a bare home directory", () => {
    const result = classifyProfileDir("/home/hasna");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("not-home-anchored");
  });

  test("rejects paths outside any home root", () => {
    for (const dir of ["/opt/prof", "/srv/accounts/prof", "/root/.claude"]) {
      const result = classifyProfileDir(dir);
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason.code).toBe("not-home-anchored");
    }
  });

  test("rejects relative paths", () => {
    const result = classifyProfileDir("relative/path");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("not-absolute");
  });

  test("rejects traversal that escapes a tool home after normalisation", () => {
    const result = classifyProfileDir("/home/hasna/.claude/../../../tmp/prof");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("ephemeral-root");
  });

  test("normalises traversal that stays inside a tool home", () => {
    expect(classifyProfileDir("/home/hasna/.claude/x/../y")).toEqual({ ok: true });
  });

  test("rejects control characters", () => {
    const result = classifyProfileDir(`/home/hasna/.claude/a${String.fromCodePoint(0)}b`);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("invalid-characters");
  });

  test("rejects newlines", () => {
    const result = classifyProfileDir("/home/hasna/.claude/a\nb");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("invalid-characters");
  });
});

describe("assertRegistrableProfileDir", () => {
  test("throws AccountsError naming the offending path", () => {
    expect(() => assertRegistrableProfileDir("/tmp/prof")).toThrow(AccountsError);
    expect(() => assertRegistrableProfileDir("/tmp/prof")).toThrow(/\/tmp\/prof/);
  });

  test("the message tells the operator how to widen the policy", () => {
    expect(() => assertRegistrableProfileDir("/opt/prof")).toThrow(
      /HASNA_ACCOUNTS_PROFILE_DIR_ROOTS/,
    );
  });

  test("passes a legitimate managed dir through silently", () => {
    expect(() =>
      assertRegistrableProfileDir("/home/hasna/.hasna/accounts/profiles/claude/account003"),
    ).not.toThrow();
  });
});

describe("resolveProfileDirPolicy", () => {
  test("defaults are used when no override is set", () => {
    expect(resolveProfileDirPolicy({})).toEqual(defaultProfileDirPolicy);
  });

  test("home roots can be widened by env for unusual machine layouts", () => {
    const policy = resolveProfileDirPolicy({
      HASNA_ACCOUNTS_PROFILE_DIR_ROOTS: "/home:/Users:/export/home",
    });
    expect(policy.homeRoots).toContain("/export/home");
    expect(classifyProfileDir("/export/home/hasna/.claude", policy)).toEqual({ ok: true });
  });

  test("a widened home root still cannot re-admit an ephemeral path", () => {
    const policy = resolveProfileDirPolicy({ HASNA_ACCOUNTS_PROFILE_DIR_ROOTS: "/tmp" });
    const result = classifyProfileDir("/tmp/hasna/.claude", policy);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("ephemeral-root");
  });

  test("blank and duplicate entries in the override are ignored", () => {
    const policy = resolveProfileDirPolicy({
      HASNA_ACCOUNTS_PROFILE_DIR_ROOTS: " /home : : /home :/Users ",
    });
    expect(policy.homeRoots).toEqual(["/home", "/Users"]);
  });

  test("a relative override entry is refused rather than silently ignored", () => {
    expect(() =>
      resolveProfileDirPolicy({ HASNA_ACCOUNTS_PROFILE_DIR_ROOTS: "home" }),
    ).toThrow(AccountsError);
  });
});

describe("agent worktrees, scratchpads and caches are refused (F1)", () => {
  // These are the paths the earlier dot-directory rule admitted. They matter
  // more than /tmp did: the global rules REQUIRE agents to work in
  // $HOME/.hasna/repos/worktrees/<repo>/<name>, and the real leak lever is an
  // ACCOUNTS_HOME override feeding profilesDir() — so an agent pointing
  // ACCOUNTS_HOME at its own worktree reproduces the original leak one level in.
  const refused = [
    "/home/hasna/.hasna/repos/worktrees/open-accounts/e68bc8c7-registry-cleanup",
    "/home/hasna/.hasna/repos/worktrees/open-accounts/x/profiles/claude/acct",
    "/home/hasna/.hasna/projects/workspaces/wks_abc/scratchpad/accounts-home/profiles/claude/a",
    "/home/hasna/.hasna/projects/workspaces/wks_abc/h2/prof-claude",
    "/home/hasna/.cache/accounts-tests/worker-a/case-1/profiles/claude/acct",
    "/home/hasna/.hasna/accounts",
    "/home/hasna/.hasna",
    "/home/hasna/.hasna/emails",
  ];
  for (const dir of refused) {
    test(`refuses ${dir}`, () => {
      const result = classifyProfileDir(dir);
      expect({ dir, ok: result.ok }).toEqual({ dir, ok: false });
      if (result.ok) throw new Error("unreachable");
      expect(result.reason.code).toBe("outside-profile-roots");
    });
  }

  test("but the managed profiles root beside them is still admitted", () => {
    expect(classifyProfileDir("/home/hasna/.hasna/accounts/profiles/claude/account003")).toEqual({
      ok: true,
    });
  });
});

describe("profile roots are derived from the tool table, not enumerated", () => {
  test("every built-in tool home is a profile root", () => {
    const roots = defaultProfileDirPolicy.profileRoots;
    for (const rel of builtinToolHomeRoots()) {
      expect({ rel, present: roots.includes(rel) }).toEqual({ rel, present: true });
    }
  });

  test("the managed profiles root is included", () => {
    expect(defaultProfileDirPolicy.profileRoots).toContain(".hasna/accounts/profiles");
  });

  test("a tool home nested two segments deep works (.config/opencode)", () => {
    expect(classifyProfileDir("/home/hasna/.config/opencode")).toEqual({ ok: true });
    // ...but .config itself is not a blanket root
    const result = classifyProfileDir("/home/hasna/.config/something-unknown");
    expect(result.ok).toBe(false);
  });

  test("a tool home admits nested profile dirs (.codewith/auth_profiles)", () => {
    expect(classifyProfileDir("/home/hasna/.codewith/auth_profiles/account009")).toEqual({
      ok: true,
    });
  });
});

describe("classifyToolHomeDir (F2 — POST /v1/tools defaultDir)", () => {
  test("refuses the ephemeral paths that were previously accepted", () => {
    for (const dir of ["/tmp/evil", "/dev/shm/x", "/var/folders/ab/cd/x"]) {
      const result = classifyToolHomeDir(dir);
      expect({ dir, ok: result.ok }).toEqual({ dir, ok: false });
      if (result.ok) throw new Error("unreachable");
      expect(result.reason.code).toBe("ephemeral-root");
    }
  });

  test("refuses a bare relative string", () => {
    const result = classifyToolHomeDir("relative");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason.code).toBe("not-absolute");
  });

  test("admits a NEW tool home the built-in table does not know", () => {
    // Custom tools exist to add config dirs without a code change, so tool
    // homes deliberately do NOT get the profile-root allowlist.
    expect(classifyToolHomeDir("/home/hasna/.config/aicopilot")).toEqual({ ok: true });
    expect(classifyToolHomeDir("/home/hasna/.some-new-agent")).toEqual({ ok: true });
  });

  test("a path refused as a PROFILE dir can still be a valid tool home", () => {
    const asProfile = classifyProfileDir("/home/hasna/.config/aicopilot");
    const asToolHome = classifyToolHomeDir("/home/hasna/.config/aicopilot");
    expect(asProfile.ok).toBe(false);
    expect(asToolHome.ok).toBe(true);
  });

  test("non-string input is rejected, not thrown", () => {
    expect(() => classifyToolHomeDir(42 as unknown as string)).not.toThrow();
    const result = classifyToolHomeDir(42 as unknown as string);
    expect(result.ok).toBe(false);
  });
});

describe("real-registry corpus", () => {
  // The 71-row production registry replayed through the policy. Previously this
  // lived only in a throwaway script, so the strongest evidence for the rule was
  // not a test and could not catch a regression. It is a committed fixture now:
  // widen the rule and a leaked path starts passing; narrow it and a real row
  // starts failing. Either way this fails.
  const corpus = fixture as { capturedAt: string; dirs: { dir: string; expect: string }[] };

  test("the fixture is the real thing, not a sample", () => {
    const allow = corpus.dirs.filter((d) => d.expect === "allow").length;
    const refuse = corpus.dirs.filter((d) => d.expect === "refuse").length;
    expect({ allow, refuse, total: corpus.dirs.length }).toEqual({
      allow: 48,
      refuse: 16,
      total: 64,
    });
  });

  test("every dir the live registry legitimately held is admitted", () => {
    const wrong = corpus.dirs
      .filter((d) => d.expect === "allow")
      .filter((d) => !classifyProfileDir(d.dir).ok)
      .map((d) => d.dir);
    expect(wrong).toEqual([]);
  });

  test("every leaked dir is refused", () => {
    const wrong = corpus.dirs
      .filter((d) => d.expect === "refuse")
      .filter((d) => classifyProfileDir(d.dir).ok)
      .map((d) => d.dir);
    expect(wrong).toEqual([]);
  });

  test("all six macOS rows are admitted (the corpus is not Linux-only)", () => {
    const mac = corpus.dirs.filter((d) => d.dir.startsWith("/Users/"));
    expect(mac.length).toBe(6);
    expect(mac.filter((d) => !classifyProfileDir(d.dir).ok).map((d) => d.dir)).toEqual([]);
  });
});
