import { describe, expect, test } from "bun:test";
import { AccountsError } from "../types.js";
import {
  assertRegistrableProfileDir,
  classifyProfileDir,
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

describe("real-registry corpus", () => {
  // Positive control: the policy must separate the 53 legitimate rows observed in
  // the production registry from the 16 /tmp rows that leaked into it. A check
  // that cannot produce both outcomes on real input is not evidence.
  const legitimate = [
    "/home/hasna/.hasna/accounts/profiles/claude/account003",
    "/home/hasna/.hasna/accounts/profiles/codewith/account015",
    "/home/hasna/.hasna/accounts/profiles/cursor/account024",
    "/home/hasna/.codewith/auth_profiles/account009",
    "/home/hasna/.claude",
    "/home/hasna/.codewith",
    "/Users/hasna/.hasna/accounts/profiles/codex-app/account002",
    "/Users/andreihasna/.hasna/accounts/profiles/claude/account027",
  ];
  const leaked = [
    "/tmp/accounts-login-cli-1ITud2/profiles/claude/acct",
    "/tmp/accounts-test-dJ98ge/profiles/claude/copied",
    "/tmp/import-src-ADyjrn",
    "/tmp/tmp.qJnMsgXfli/profiles/codex/acct",
    "/tmp/accounts-permissions-cli-wGAboW/profiles/codex/codexer",
    "/tmp/accounts-review-state-shape-gva3Gg/profiles/review-state-shape/review",
    "/tmp/claude-1000/-home-hasna/abc/scratchpad/h2/prof-broken",
  ];

  test("every legitimate dir is admitted", () => {
    for (const dir of legitimate) {
      expect({ dir, ...classifyProfileDir(dir) }).toEqual({ dir, ok: true });
    }
  });

  test("every leaked dir is refused", () => {
    for (const dir of leaked) {
      const result = classifyProfileDir(dir);
      expect({ dir, ok: result.ok }).toEqual({ dir, ok: false });
    }
  });
});
