import { expect, test } from "bun:test";
import { AccountsError, getTool, mergeToolArgs } from "./index.js";

const canonicalClaudePermissionModes = [
  ["bypass", "bypassPermissions"],
  ["auto", "auto"],
  ["accept-edits", "acceptEdits"],
  ["dont-ask", "dontAsk"],
  ["plan", "plan"],
] as const;

const invalidClaudePermissionModes = [
  ["bypass", "bypass"],
  ["bypass", "bypass-permissions"],
  ["accept-edits", "accept-edits"],
  ["dont-ask", "dont-ask"],
  ["plan", "PLAN"],
  ["plan", " plan"],
  ["plan", "plan "],
] as const;

test("public mergeToolArgs rejects conflicting Claude permission modes", () => {
  const claude = getTool("claude");

  for (const [permissions, args] of [
    ["plan", ["--permission-mode", "bypassPermissions"]],
    ["plan", ["--permission-mode=bypassPermissions"]],
    ["bypass", ["--permission-mode", "plan"]],
    ["bypass", ["--permission-mode=plan"]],
  ] as const) {
    expect(() => mergeToolArgs(claude, [...args], { permissions })).toThrow(AccountsError);
  }
});

test("public mergeToolArgs requires exact canonical Claude native permission modes", () => {
  const claude = getTool("claude");

  for (const [permissions, nativeMode] of invalidClaudePermissionModes) {
    for (const args of [
      ["--permission-mode", nativeMode],
      [`--permission-mode=${nativeMode}`],
    ]) {
      expect(() => mergeToolArgs(claude, [...args])).toThrow(/exact canonical/);
      expect(() => mergeToolArgs(claude, [...args], { permissions })).toThrow(/exact canonical/);
    }
  }
});

for (const [label, args, error] of [
  [
    "dangerous alias plus native mode",
    ["--dangerously-skip-permissions", "--permission-mode", "plan"],
    "--permission-mode cannot be combined with another permission source",
  ],
  [
    "two native modes",
    ["--permission-mode=plan", "--permission-mode=bypassPermissions"],
    "--permissions may be supplied only once",
  ],
  [
    "raw preset plus native mode",
    ["--permissions=dangerous", "--permission-mode", "plan"],
    "--permission-mode cannot be combined with another permission source",
  ],
] as const) {
  test(`public mergeToolArgs rejects ${label}`, () => {
    expect(() => mergeToolArgs(getTool("claude"), [...args])).toThrow(error);
  });
}

test("public mergeToolArgs preserves coherent Claude permission sources", () => {
  const claude = getTool("claude");

  for (const args of [
    ["--dangerously-skip-permissions"],
    ["--permission-mode", "plan"],
    ["--permission-mode=plan"],
    ["--permissions=dangerous"],
  ]) {
    expect(mergeToolArgs(claude, args)).toEqual(args);
  }
  for (const [permissions, nativeMode] of canonicalClaudePermissionModes) {
    for (const args of [
      ["--permission-mode", nativeMode],
      [`--permission-mode=${nativeMode}`],
    ]) {
      expect(mergeToolArgs(claude, [...args])).toEqual(args);
      expect(mergeToolArgs(claude, [...args], { permissions })).toEqual(args);
    }
  }
});

test("public mergeToolArgs rejects unknown Claude native permission modes", () => {
  const claude = getTool("claude");

  for (const nativeMode of ["futureMode", "allow-dangerous"]) {
    for (const args of [
      ["--permission-mode", nativeMode],
      [`--permission-mode=${nativeMode}`],
    ]) {
      expect(() => mergeToolArgs(claude, [...args])).toThrow(/exact canonical/);
      expect(() => mergeToolArgs(claude, [...args], { permissions: "plan" })).toThrow(
        /exact canonical/,
      );
    }
  }
});

test("public mergeToolArgs leaves Claude-style permission args unchanged for other tools", () => {
  const args = [
    "--dangerously-skip-permissions",
    "--permission-mode",
    "plan",
    "--permissions=dangerous",
  ];

  expect(mergeToolArgs(getTool("codex"), args)).toEqual(args);
});
