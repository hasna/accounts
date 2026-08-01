// Regression tests for the one-name-one-provider invariant (PR-1, task ad756590).
//
// PR-1 ships the invariant in WARN mode ONLY. That is the property most at risk
// of being silently lost, so it is asserted in both directions: warn mode must
// NOT throw, and the SAME input in hard mode MUST throw. Without that positive
// control "it did not throw" is indistinguishable from "the check never ran".

import { describe, expect, test } from "bun:test";
import {
  NAME_INVARIANT_MODE,
  assertNameFree,
  evaluateNameFree,
  type NameBinding,
} from "./lib/name-invariant.js";
import { profileSchema, profileProvider } from "./types.js";

const UNIVERSE: NameBinding[] = [
  { name: "account005", provider: "claude", email: "andrei.hasna@gmail.com", source: "server" },
  { name: "account024", provider: "claude", source: "server" },
  { name: "solo", provider: "codewith", email: "solo@example.com", source: "server" },
];

describe("evaluateNameFree", () => {
  test("a name held by ANOTHER provider is a violation naming that provider and its email", () => {
    const verdict = evaluateNameFree("account005", "codewith", UNIVERSE);
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error("unreachable");
    expect(verdict.code).toBe("cross-provider-name-collision");
    expect(verdict.existing.provider).toBe("claude");
    expect(verdict.existing.email).toBe("andrei.hasna@gmail.com");
    // The design requires the message to name the existing provider AND email.
    expect(verdict.message).toContain("claude");
    expect(verdict.message).toContain("andrei.hasna@gmail.com");
    expect(verdict.message).toContain("account005");
  });

  test("a violation on a record with no email still names the provider", () => {
    const verdict = evaluateNameFree("account024", "cursor", UNIVERSE);
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error("unreachable");
    expect(verdict.existing.provider).toBe("claude");
    expect(verdict.message).toContain("claude");
    expect(verdict.message).not.toContain("undefined");
  });

  test("an unused name is free", () => {
    expect(evaluateNameFree("brand-new", "claude", UNIVERSE).ok).toBe(true);
  });

  test("re-binding the SAME name to the SAME provider is idempotent, not a violation", () => {
    expect(evaluateNameFree("account005", "claude", UNIVERSE).ok).toBe(true);
  });

  test("a grandfathered (name, provider) pair is not a violation", () => {
    const grandfathered: NameBinding[] = [{ name: "account005", provider: "codewith" }];
    expect(evaluateNameFree("account005", "codewith", UNIVERSE, grandfathered).ok).toBe(true);
    // ...and grandfathering one pair must not grandfather a DIFFERENT provider.
    expect(evaluateNameFree("account005", "cursor", UNIVERSE, grandfathered).ok).toBe(false);
  });
});

describe("assertNameFree ships in WARN mode", () => {
  test("PR-1 mode constant is warn (PR-2 flips this single constant)", () => {
    expect(NAME_INVARIANT_MODE).toBe("warn");
  });

  test("warn mode reports the violation and does NOT throw", () => {
    const warnings: string[] = [];
    const verdict = assertNameFree("account005", "codewith", UNIVERSE, {
      mode: "warn",
      warn: (m) => warnings.push(m),
    });
    expect(verdict.ok).toBe(false);
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toContain("account005");
    expect(warnings[0]).toContain("claude");
  });

  test("POSITIVE CONTROL: the same input in hard mode throws", () => {
    // Without this, the warn-mode assertion above cannot distinguish "warned
    // instead of throwing" from "the check is inert".
    expect(() =>
      assertNameFree("account005", "codewith", UNIVERSE, { mode: "hard", warn: () => {} }),
    ).toThrow(/account005/);
  });

  test("a clean binding emits no warning in either mode", () => {
    const warnings: string[] = [];
    expect(assertNameFree("brand-new", "claude", UNIVERSE, { mode: "warn", warn: (m) => warnings.push(m) }).ok).toBe(true);
    expect(() => assertNameFree("brand-new", "claude", UNIVERSE, { mode: "hard" })).not.toThrow();
    expect(warnings.length).toBe(0);
  });
});

describe("profile schema: provider read-alias and accountUuid", () => {
  const base = { name: "acct", tool: "claude", dir: "/tmp/acct", createdAt: new Date(0).toISOString() };

  test("provider is optional and tool alone still parses", () => {
    const parsed = profileSchema.parse(base);
    expect(parsed.tool).toBe("claude");
    expect(profileProvider(parsed)).toBe("claude");
  });

  test("provider is accepted and read back through profileProvider", () => {
    const parsed = profileSchema.parse({ ...base, provider: "claude" });
    expect(parsed.provider).toBe("claude");
    expect(profileProvider(parsed)).toBe("claude");
  });

  test("provider that disagrees with tool is rejected, not silently preferred", () => {
    expect(() => profileSchema.parse({ ...base, provider: "codewith" })).toThrow();
  });

  test("accountUuid must be a uuid", () => {
    const uuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    expect(profileSchema.parse({ ...base, accountUuid: uuid }).accountUuid).toBe(uuid);
    expect(() => profileSchema.parse({ ...base, accountUuid: "not-a-uuid" })).toThrow();
  });
});
