import { describe, expect, test } from "bun:test";
import { planClaudeLaunch, redactArgv, redactText } from "./lib/claude-launch.js";
import { readBackgroundSupervisorPayload } from "./lib/supervisor.js";
import { getTool, mergeToolArgs } from "./lib/tools.js";
import { AccountsError } from "./types.js";

const claude = getTool("claude");

test("headless convenience produces deterministic foreground argv", () => {
  const plan = planClaudeLaunch(claude, ["Reply exactly OK."], { headless: true });
  expect(plan).toEqual({
    mode: "headless",
    args: ["-p", "Reply exactly OK."],
    nonInteractive: true,
  });
  expect(mergeToolArgs(claude, plan.args, { permissions: "dangerous" })).toEqual([
    "--dangerously-skip-permissions",
    "-p",
    "Reply exactly OK.",
  ]);
});

test("background convenience captures a deterministic session id and name", () => {
  const plan = planClaudeLaunch(
    claude,
    ["Work the assigned task."],
    { background: true, name: "ui-worker" },
    { sessionId: () => "11111111-1111-4111-8111-111111111111" },
  );
  expect(plan).toEqual({
    mode: "background",
    args: ["--session-id", "11111111-1111-4111-8111-111111111111", "Work the assigned task."],
    name: "ui-worker",
    sessionId: "11111111-1111-4111-8111-111111111111",
    nonInteractive: true,
  });
});

test("background preserves one explicit raw session id and raw name", () => {
  const args = ["--session-id=22222222-2222-4222-8222-222222222222", "--name", "raw-worker", "Work"];
  const plan = planClaudeLaunch(claude, args, { bg: true });
  expect(plan.args).toEqual(args);
  expect(plan.sessionId).toBe("22222222-2222-4222-8222-222222222222");
  expect(plan.name).toBe("raw-worker");
});

test("raw-only passthrough remains exact and is classified without rewriting", () => {
  const print = ["--print", "--output-format", "json", "Prompt"];
  const background = ["--bg", "--name", "native", "Prompt"];
  expect(planClaudeLaunch(claude, print).args).toEqual(print);
  expect(planClaudeLaunch(claude, print).mode).toBe("headless");
  expect(planClaudeLaunch(claude, background).args).toEqual(background);
  expect(planClaudeLaunch(claude, background).mode).toBe("raw-background");
});

describe("mixed Claude mode conflicts", () => {
  const cases: Array<[string, string[], Parameters<typeof planClaudeLaunch>[2]]> = [
    ["headless plus convenience background", [], { headless: true, background: true }],
    ["headless plus convenience bg alias", [], { headless: true, bg: true }],
    ["headless plus raw background", ["--bg", "Prompt"], { headless: true }],
    ["headless plus raw long background", ["--background", "Prompt"], { headless: true }],
    ["headless plus raw print", ["-p", "Prompt"], { headless: true }],
    ["headless plus raw long print", ["--print", "Prompt"], { headless: true }],
    ["headless plus continue", ["--continue"], { headless: true }],
    ["headless plus resume", ["--resume", "session"], { headless: true }],
    ["headless plus fork", ["--fork-session"], { headless: true }],
    ["headless plus IDE", ["--ide"], { headless: true }],
    ["headless plus raw name", ["--name", "worker"], { headless: true }],
    ["background plus raw print", ["--print", "Prompt"], { background: true }],
    ["background plus short print", ["-p", "Prompt"], { background: true }],
    ["background plus raw bg", ["--bg", "Prompt"], { background: true }],
    ["background plus raw long background", ["--background", "Prompt"], { background: true }],
    ["background plus continue", ["-c"], { background: true }],
    ["background plus resume", ["-r", "session"], { background: true }],
    ["background plus fork", ["--fork-session"], { background: true }],
    ["background plus IDE", ["--ide"], { background: true }],
    ["both convenience background aliases", [], { background: true, bg: true }],
    ["name without background", [], { name: "worker" }],
  ];

  for (const [label, args, options] of cases) {
    test(label, () => {
      expect(() => planClaudeLaunch(claude, args, options)).toThrow(AccountsError);
    });
  }
});

test("duplicate and conflicting name or session options fail", () => {
  expect(() => planClaudeLaunch(claude, ["--name", "one"], { background: true, name: "two" })).toThrow(
    /both as an accounts option and a raw passthrough/,
  );
  expect(() => planClaudeLaunch(claude, ["--name", "one", "--name=two"], { background: true })).toThrow(
    /may be supplied only once/,
  );
  expect(() =>
    planClaudeLaunch(claude, ["--session-id", "one", "--session-id=two"], { background: true }),
  ).toThrow(/may be supplied only once/);
  expect(() => planClaudeLaunch(claude, ["--session-id"], { background: true })).toThrow(/requires a value/);
  expect(() => planClaudeLaunch(claude, [], { background: true, name: "   " })).toThrow(/non-empty/);
});

test("Claude convenience options reject unsupported tools before argv changes", () => {
  for (const options of [{ headless: true }, { background: true }, { bg: true }, { name: "worker" }]) {
    expect(() => planClaudeLaunch(getTool("codex"), ["Prompt"], options)).toThrow(/only with --tool claude/);
  }
});

test("background supervisor payload accepts only complete typed values", () => {
  const payload = JSON.stringify({
    profile: "acct",
    tool: "claude",
    args: ["--session-id", "worker", "Prompt"],
    cwd: "/tmp/project",
    name: "worker",
    sessionId: "worker",
  });
  expect(readBackgroundSupervisorPayload(payload)).toMatchObject({ profile: "acct", tool: "claude", name: "worker" });
  expect(() => readBackgroundSupervisorPayload("{\"profile\":true}")).toThrow(AccountsError);
});

test("command and error redaction removes common credentials", () => {
  const secret = "sk-ant-abcdefghijklmnopqrstuvwxyz";
  expect(redactArgv(["claude", "--api-key", secret, "--token=ghp_abcdefghijklmnopqrstuvwxyz", secret])).toEqual([
    "claude",
    "--api-key",
    "[REDACTED]",
    "--token=[REDACTED]",
    "[REDACTED]",
  ]);
  expect(redactText(`spawn failed with ${secret}`)).toBe("spawn failed with [REDACTED]");
});
