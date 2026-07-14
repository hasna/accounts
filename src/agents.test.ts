import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, listProfiles } from "./lib/profiles.js";
import {
  extractJsonArray,
  isToolSessionCommand,
  listAgentsAcrossProfiles,
  type AgentsRunner,
} from "./lib/agents.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-agents-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

test("extractJsonArray parses a clean JSON array", () => {
  expect(extractJsonArray('[{"pid":1}]')).toEqual([{ pid: 1 }]);
});

test("extractJsonArray strips pty and ANSI noise around the array", () => {
  const raw = '[?25l\r\n[\r\n  {"pid": 42, "name": "a [b] c"},\r\n  {"kind": "background"}\r\n]\r\n[?25h';
  expect(extractJsonArray(raw)).toEqual([{ pid: 42, name: "a [b] c" }, { kind: "background" }]);
});

test("extractJsonArray handles brackets inside strings and escapes", () => {
  const raw = 'noise [ {"name": "x\\"]y", "cwd": "/a[b"} ] trailing';
  expect(extractJsonArray(raw)).toEqual([{ name: 'x"]y', cwd: "/a[b" }]);
});

test("extractJsonArray returns undefined when no array present", () => {
  expect(extractJsonArray("error: something broke")).toBeUndefined();
});

test("listAgentsAcrossProfiles aggregates agents per claude profile", () => {
  addProfile({ name: "acct1", tool: "claude", email: "one@example.com" });
  addProfile({ name: "acct2", tool: "claude", email: "two@example.com" });
  addProfile({ name: "codexer", tool: "codex", email: "codex@example.com" });

  const runner: AgentsRunner = (profile) => {
    if (profile.name === "acct1") {
      return { ok: true, raw: '[{"kind":"background","sessionId":"s1","state":"working"}]' };
    }
    return { ok: true, raw: "[]" };
  };

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner,
    processScanner: () => [],
    defaultDir: join(home, "no-default-dir"),
  });
  expect(results.map((r) => r.profile)).toEqual(["acct1", "acct2"]);
  expect(results[0]?.email).toBe("one@example.com");
  expect(results[0]?.agents).toEqual([{ kind: "background", sessionId: "s1", state: "working" }]);
  expect(results[1]?.agents).toEqual([]);
});

test("listAgentsAcrossProfiles records per-profile errors without failing the run", () => {
  addProfile({ name: "good", tool: "claude", email: "good@example.com" });
  addProfile({ name: "bad", tool: "claude", email: "bad@example.com" });

  const runner: AgentsRunner = (profile) =>
    profile.name === "bad"
      ? { ok: false, raw: "", error: "claude binary not found" }
      : { ok: true, raw: '[{"kind":"interactive","sessionId":"s2"}]' };

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, processScanner: () => [] });
  const bad = results.find((r) => r.profile === "bad");
  const good = results.find((r) => r.profile === "good");
  expect(bad?.error).toContain("not found");
  expect(bad?.agents).toEqual([]);
  expect(good?.agents).toHaveLength(1);
});

test("listAgentsAcrossProfiles filters to a single profile and background kind", () => {
  addProfile({ name: "acct1", tool: "claude", email: "one@example.com" });
  addProfile({ name: "acct2", tool: "claude", email: "two@example.com" });

  const runner: AgentsRunner = () => ({
    ok: true,
    raw: '[{"kind":"background","sessionId":"b1"},{"kind":"interactive","sessionId":"i1"}]',
  });

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, profile: "acct1", backgroundOnly: true });
  expect(results).toHaveLength(1);
  expect(results[0]?.profile).toBe("acct1");
  expect(results[0]?.agents).toEqual([{ kind: "background", sessionId: "b1" }]);
});

test("listAgentsAcrossProfiles treats unparseable output as an error", () => {
  addProfile({ name: "acct1", tool: "claude", email: "one@example.com" });
  const runner: AgentsRunner = () => ({ ok: true, raw: "garbage with no json" });

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, processScanner: () => [] });
  expect(results[0]?.error).toBeDefined();
  expect(results[0]?.agents).toEqual([]);
});

test("accounts agents --help registers the command", () => {
  const result = spawnSync(process.execPath, ["run", "src/cli.ts", "agents", "--help"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home },
  });
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("--json");
  expect(result.stdout).toContain("--background");
});

// --- default-dir and untracked-process coverage (headless loops were invisible) ---

test("listAgentsAcrossProfiles queries the tool default dir as a synthetic (default) profile", () => {
  addProfile({ name: "acct1", tool: "claude", email: "one@example.com" });
  const defaultDir = join(home, "fake-claude-default");
  mkdirSync(defaultDir, { recursive: true });

  const seen: string[] = [];
  const runner: AgentsRunner = (profile) => {
    seen.push(profile.name);
    return profile.name === "(default)"
      ? { ok: true, raw: '[{"kind":"interactive","pid":77,"sessionId":"headless"}]' }
      : { ok: true, raw: "[]" };
  };

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, defaultDir, processScanner: () => [] });
  expect(seen).toContain("(default)");
  const def = results.find((r) => r.profile === "(default)");
  expect(def?.dir).toBe(defaultDir);
  expect(def?.agents).toEqual([{ kind: "interactive", pid: 77, sessionId: "headless" }]);
});

test("default dir is not duplicated when a registered profile already uses it", () => {
  const defaultDir = join(home, "fake-claude-default2");
  mkdirSync(defaultDir, { recursive: true });
  addProfile({ name: "main", tool: "claude", dir: defaultDir });

  const runner: AgentsRunner = () => ({ ok: true, raw: "[]" });
  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, defaultDir, processScanner: () => [] });
  expect(results.map((r) => r.profile)).toEqual(["main"]);
});

test("default dir is skipped when it does not exist", () => {
  addProfile({ name: "acct1", tool: "claude" });
  const runner: AgentsRunner = () => ({ ok: true, raw: "[]" });
  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, defaultDir: join(home, "missing-dir"), processScanner: () => [] });
  expect(results.map((r) => r.profile)).toEqual(["acct1"]);
});

test("processes no daemon reports appear as (untracked)", () => {
  addProfile({ name: "acct1", tool: "claude" });
  const runner: AgentsRunner = () => ({
    ok: true,
    raw: '[{"kind":"background","pid":10,"sessionId":"s1"}]',
  });
  const processScanner = () => [
    { pid: 10, ppid: 14, command: "claude tracked-directly" },
    { pid: 11, ppid: 10, command: "claude child-of-reported" },
    { pid: 14, ppid: 1, command: "node /usr/bin/claude wrapper-parent-of-reported" },
    { pid: 12, ppid: 1, command: "claude --resume deadbeef --allow-dangerously-skip-permissions", configDir: "/home/u/.claude" },
  ];

  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(), runner, processScanner });
  const untracked = results.find((r) => r.profile === "(untracked)");
  expect(untracked).toBeDefined();
  expect(untracked?.agents).toEqual([
    {
      kind: "process",
      pid: 12,
      command: "claude --resume deadbeef --allow-dangerously-skip-permissions",
      configDir: "/home/u/.claude",
    },
  ]);
});

test("(untracked) section is omitted when everything is accounted for or a profile filter is set", () => {
  addProfile({ name: "acct1", tool: "claude" });
  const runner: AgentsRunner = () => ({ ok: true, raw: '[{"kind":"background","pid":10}]' });
  const allTracked = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner,
    processScanner: () => [{ pid: 10, ppid: 1, command: "claude" }],
  });
  expect(allTracked.some((r) => r.profile === "(untracked)")).toBe(false);

  const filtered = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner,
    profile: "acct1",
    processScanner: () => [{ pid: 99, ppid: 1, command: "claude orphan" }],
  });
  expect(filtered.some((r) => r.profile === "(untracked)")).toBe(false);
});

test("isToolSessionCommand matches real session processes and rejects helpers", () => {
  const cases: Array<[string, boolean]> = [
    ["claude", true],
    ["/home/u/.local/bin/claude --resume abc --allow-dangerously-skip-permissions", true],
    ["node /home/u/.local/bin/claude --dangerously-skip-permissions", true],
    ["/home/u/.local/share/claude/versions/2.1.170 --session-id abc", true],
    ["/home/u/.local/share/claude/versions/2.1.170 --bg-pty-host /tmp/x.sock 79 74", false],
    ["/home/u/.local/share/claude/versions/2.1.170 --bg-spare /tmp/y.sock", false],
    ["/home/u/.local/bin/claude daemon run --origin transient", false],
    ["claude agents --json", false],
    ["node /home/u/.local/bin/accounts login acct1 --tool claude", false],
    ["/bin/bash -c source /home/u/profiles/claude/acct1/shell-snapshots/snap.sh", false],
    ["script -qefc claude agents --json /dev/null", false],
  ];
  for (const [command, expected] of cases) {
    expect(isToolSessionCommand(command, "claude")).toBe(expected);
  }
});

test("backgroundOnly does not leak interactive sessions into (untracked)", () => {
  addProfile({ name: "acct1", tool: "claude" });
  const runner: AgentsRunner = () => ({
    ok: true,
    raw: '[{"kind":"interactive","pid":20},{"kind":"background","pid":21}]',
  });
  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner,
    backgroundOnly: true,
    processScanner: () => [
      { pid: 20, ppid: 1, command: "claude" },
      { pid: 21, ppid: 1, command: "claude" },
    ],
  });
  expect(results.some((r) => r.profile === "(untracked)")).toBe(false);
});
