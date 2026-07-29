import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, listProfiles } from "./lib/profiles.js";
import {
  extractJsonArray,
  isToolSessionCommand,
  listAgentsAcrossProfiles,
  projectAgentEntries,
  runClaudeAgentsJson,
  scanToolProcesses,
  type AgentsRunner,
  type ProcessInfo,
} from "./lib/agents.js";
import { addCustomTool } from "./lib/tools.js";

let home: string;
let pathBeforeTest: string | undefined;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-agents-test-"));
  pathBeforeTest = process.env.PATH;
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  if (pathBeforeTest === undefined) delete process.env.PATH;
  else process.env.PATH = pathBeforeTest;
});

interface TrustedInterpreterPaths {
  node: string;
  nodejs: string;
  bun: string;
}

function trustInterpreters(): TrustedInterpreterPaths {
  const binDir = join(home, "trusted-interpreters");
  mkdirSync(binDir, { recursive: true });
  for (const name of ["node", "nodejs", "bun"]) {
    const executable = join(binDir, name);
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
  }

  process.env.PATH = `${binDir}:${process.env.PATH ?? ""}`;
  return {
    node: join(binDir, "node"),
    nodejs: join(binDir, "nodejs"),
    bun: join(binDir, "bun"),
  };
}

function wrapperProcessIdentity(
  command: string,
  trusted: TrustedInterpreterPaths,
): string | undefined {
  const first = command.match(/^(?:"([^"]+)"|'([^']+)'|(\S+))/);
  const observed = first?.[1] ?? first?.[2] ?? first?.[3];
  const name = observed?.replaceAll("\\", "/").split("/").pop();
  return name === "node" || name === "nodejs" || name === "bun"
    ? trusted[name]
    : undefined;
}

const classifyWithProcessIdentity = isToolSessionCommand as (
  command: string,
  bin: string,
  toolId?: string,
  processExecutable?: string,
  requireKernelAttribution?: boolean,
) => boolean;

test("extractJsonArray parses a clean JSON array", () => {
  expect(extractJsonArray('[{"kind":"background","pid":1}]')).toEqual([
    { kind: "background", pid: 1 },
  ]);
});

test("extractJsonArray strips pty and ANSI noise around the array", () => {
  const raw = '[?25l\r\n[\r\n  {"pid": 42, "name": "a [b] c"},\r\n  {"kind": "background"}\r\n]\r\n[?25h';
  expect(extractJsonArray(raw)).toEqual([{ pid: 42, name: "a [b] c" }, { kind: "background" }]);
});

test("extractJsonArray ignores bracketed ANSI OSC payloads before agent data", () => {
  const raw = '\u001b]0;status [1]\u0007\r\n[{"pid":42,"kind":"background"}]\r\n';
  expect(extractJsonArray(raw)).toEqual([{ pid: 42, kind: "background" }]);
});

test("extractJsonArray recovers agent data after an unterminated OSC line", () => {
  const raw = '\u001b]0;broken [1]\n[{"pid":42,"kind":"background"}]\n';
  expect(extractJsonArray(raw)).toEqual([{ pid: 42, kind: "background" }]);
});

test("extractJsonArray recovers agent data after an unterminated CSI line", () => {
  for (const control of ["\u001b[31", "\u009b31"]) {
    const raw = `${control}\n[{"pid":42,"kind":"background"}]\n`;
    expect(extractJsonArray(raw), JSON.stringify(control)).toEqual([
      { pid: 42, kind: "background" },
    ]);
  }
});

test("extractJsonArray resumes after CAN or SUB cancels a terminal control", () => {
  for (const cancel of ["\u0018", "\u001a"]) {
    expect(
      extractJsonArray(`\u001b[31${cancel}[{"pid":42,"kind":"background"}]`),
      `CSI ${cancel.charCodeAt(0)}`,
    ).toEqual([{ pid: 42, kind: "background" }]);
    expect(
      extractJsonArray(`\u001b]0;broken${cancel}[{"pid":42,"kind":"background"}]`),
      `OSC ${cancel.charCodeAt(0)}`,
    ).toEqual([{ pid: 42, kind: "background" }]);
  }
});

test("extractJsonArray keeps BEL-delimited bracket data inside DCS-family controls", () => {
  const controls = ["\u001bP", "\u001bX", "\u001b^", "\u001b_", "\u0090", "\u0098", "\u009e", "\u009f"];
  for (const control of controls) {
    const terminator = control.startsWith("\u001b") ? "\u001b\\" : "\u009c";
    const raw =
      `${control}ignored\u0007[{"pid":1,"kind":"background"}]${terminator}\n` +
      '[{"pid":42,"kind":"background"}]\n';
    expect(extractJsonArray(raw), JSON.stringify(control)).toEqual([
      { pid: 42, kind: "background" },
    ]);
  }
});

test("extractJsonArray handles brackets inside strings and escapes", () => {
  const raw =
    'noise [ {"kind":"background","name": "x\\"]y", "cwd": "/a[b"} ] trailing';
  expect(extractJsonArray(raw)).toEqual([
    { kind: "background", name: 'x"]y', cwd: "/a[b" },
  ]);
});

test("extractJsonArray returns undefined when no array present", () => {
  expect(extractJsonArray("error: something broke")).toBeUndefined();
});

test("extractJsonArray recovers a bounded inner candidate from malformed wrapper noise", () => {
  expect(
    extractJsonArray('noise [broken wrapper [{"pid":7,"kind":"background"}] tail'),
  ).toEqual([{ pid: 7, kind: "background" }]);
});

test("extractJsonArray skips non-record arrays before agent data", () => {
  expect(
    extractJsonArray('progress [1]\n[{"pid":7,"kind":"background"}]'),
  ).toEqual([{ pid: 7, kind: "background" }]);
});

test("extractJsonArray prefers later agent records over an empty noise array", () => {
  expect(
    extractJsonArray('progress []\n[{"pid":7,"kind":"background"}]'),
  ).toEqual([{ pid: 7, kind: "background" }]);
  expect(extractJsonArray("[]")).toEqual([]);
});

test("extractJsonArray skips unrelated record arrays before agent data", () => {
  expect(
    extractJsonArray(
      '[{"diagnostic":"warming"}]\n[{"kind":"background","pid":42}]',
    ),
  ).toEqual([{ kind: "background", pid: 42 }]);
});

test("extractJsonArray recovers after an unterminated string in malformed wrapper noise", () => {
  expect(
    extractJsonArray('noise [broken "unterminated [{"pid":7,"kind":"background"}] tail'),
  ).toEqual([{ pid: 7, kind: "background" }]);
});

test("extractJsonArray reserves a rolling candidate slot for later agent data", () => {
  const agents = '[{"pid":7,"kind":"background"}]';
  expect(extractJsonArray(`${"[".repeat(32)}broken ${agents}`)).toEqual([
    { pid: 7, kind: "background" },
  ]);
});

test("extractJsonArray preserves a valid root across more than 32 nested arrays", () => {
  let nested: unknown = "leaf";
  for (let depth = 0; depth < 40; depth++) nested = [nested];
  const payload = [{ pid: 7, kind: "background", nested }];
  expect(extractJsonArray(JSON.stringify(payload))).toEqual(payload);
});

test("extractJsonArray enforces its candidate limit in UTF-8 bytes", () => {
  const oversized = `[{"kind":"background","name":"${"😀".repeat(300_000)}"}]`;
  expect(oversized.length).toBeLessThan(1024 * 1024);
  expect(Buffer.byteLength(oversized, "utf8")).toBeGreaterThan(1024 * 1024);
  expect(extractJsonArray(oversized) === undefined).toBe(true);
});

test("extractJsonArray fails closed on nested fallbacks inside bounded-out roots", () => {
  const nestedAgent = '[{"kind":"background","pid":999}]';
  const oversized =
    `[{"kind":"background","padding":"${"x".repeat(1_100_000)}",` +
    `"nested":${nestedAgent}}]`;
  expect(Buffer.byteLength(oversized, "utf8")).toBeGreaterThan(1024 * 1024);
  expect(extractJsonArray(oversized)).toBeUndefined();
  expect(
    extractJsonArray(`${oversized}\n[{"kind":"background","pid":42}]`),
  ).toEqual([{ kind: "background", pid: 42 }]);

  const mismatchedCloser =
    `[${"x".repeat(1_100_000)}}${nestedAgent}]`;
  expect(extractJsonArray(mismatchedCloser)).toBeUndefined();
  expect(
    extractJsonArray(
      `${mismatchedCloser}\n[{"kind":"interactive","pid":43}]`,
    ),
  ).toEqual([{ kind: "interactive", pid: 43 }]);

  const overflowedQuarantine =
    `[${"x".repeat(1_100_000)}${"[".repeat(65_537)}` +
    `${"]".repeat(65_537)}]\n[{"kind":"interactive","pid":44}]`;
  expect(extractJsonArray(overflowedQuarantine)).toBeUndefined();

  const tooDeep =
    `[{"kind":"background","nested":${"[".repeat(32_769)}` +
    `${nestedAgent}${"]".repeat(32_769)}}]`;
  expect(extractJsonArray(tooDeep)).toBeUndefined();
});

test("extractJsonArray counts object and mixed containers before parsing", () => {
  const nestedAgent = '[{"kind":"background","pid":999}]';
  const deepObject =
    `[{"kind":"background","nested":${'{"nested":'.repeat(32_769)}` +
    `${nestedAgent}${"}".repeat(32_769)}}]`;
  expect(extractJsonArray(deepObject)).toBeUndefined();
  expect(
    extractJsonArray(`${deepObject}\n[{"kind":"background","pid":42}]`),
  ).toEqual([{ kind: "background", pid: 42 }]);

  const mixed =
    `[{"kind":"background","nested":${'{"nested":['.repeat(16_385)}` +
    `${nestedAgent}${"]}".repeat(16_385)}}]`;
  expect(extractJsonArray(mixed)).toBeUndefined();
  expect(
    extractJsonArray(`${mixed}\n[{"kind":"interactive","pid":43}]`),
  ).toEqual([{ kind: "interactive", pid: 43 }]);
});

test("extractJsonArray stays linear on dense malformed bracket noise", () => {
  const input = "[".repeat(40_000);
  const startedAt = performance.now();
  expect(extractJsonArray(input)).toBeUndefined();
  const elapsedMs = performance.now() - startedAt;

  expect(elapsedMs).toBeLessThan(500);
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

test.skipIf(process.platform !== "linux")("agents probe quotes custom executable names before the script shell", () => {
  const executable = join(home, "safe-agent-probe");
  const injectionMarker = join(home, "injected");
  writeFileSync(executable, "#!/bin/sh\nprintf '[]\\n'\n");
  chmodSync(executable, 0o755);
  addCustomTool({
    id: "probe-tool",
    label: "Probe Tool",
    envVar: "PROBE_HOME",
    defaultDir: join(home, "probe-default"),
    bin: `${executable}; touch ${injectionMarker}; #`,
  });
  const profile = addProfile({ name: "probe", tool: "probe-tool" });

  const result = runClaudeAgentsJson(profile);

  expect(result.ok).toBe(false);
  expect(existsSync(injectionMarker)).toBe(false);
});

test.skipIf(process.platform === "win32")("agents probe errors recover credentials after unmatched quotes", () => {
  const executable = join(home, "failing-agent-probe");
  const secret = "agent-probe-unmatched-secret";
  writeFileSync(
    executable,
    [
      "#!/bin/sh",
      `printf '%s\\n' 'provider "unterminated －－ --client-key=${secret} --trace keep-agent-probe' >&2`,
      "exit 2",
      "",
    ].join("\n"),
  );
  chmodSync(executable, 0o755);
  addCustomTool({
    id: "failing-probe-tool",
    label: "Failing Probe Tool",
    envVar: "FAILING_PROBE_HOME",
    defaultDir: join(home, "failing-probe-default"),
    bin: executable,
  });
  const profile = addProfile({ name: "failing-probe", tool: "failing-probe-tool" });

  const result = runClaudeAgentsJson(profile);

  expect(result.ok).toBe(false);
  expect(result.error).not.toContain(secret);
  expect(result.error).toContain("[REDACTED]");
  expect(result.error).toContain("keep-agent-probe");
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
  const trustedBinDir = join(home, "session-bin");
  const trustedClaude = join(trustedBinDir, "claude");
  mkdirSync(trustedBinDir, { recursive: true });
  for (const executable of [
    trustedClaude,
    join(trustedBinDir, "node"),
    join(trustedBinDir, "nodejs"),
    join(trustedBinDir, "bun"),
  ]) {
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
  }
  const previousPath = process.env.PATH;
  process.env.PATH = `${trustedBinDir}:${previousPath ?? ""}`;
  const trustedInterpreters: TrustedInterpreterPaths = {
    node: join(trustedBinDir, "node"),
    nodejs: join(trustedBinDir, "nodejs"),
    bun: join(trustedBinDir, "bun"),
  };
  const versionedClaude = join(
    homedir(),
    ".local",
    "share",
    "claude",
    "versions",
    "2.1.170",
  );
  const cases: Array<[string, boolean]> = [
    ["claude", true],
    [`${trustedClaude} --resume abc --allow-dangerously-skip-permissions`, true],
    [`node ${trustedClaude} --dangerously-skip-permissions`, true],
    [`${versionedClaude} --session-id abc`, true],
    ["/tmp/evil/claude/versions/2.1.170 --session-id abc", false],
    ["/tmp/not-claude/claude/versions/helper --session-id abc", false],
    [`${versionedClaude} --bg-pty-host /tmp/x.sock 79 74`, false],
    [`${versionedClaude} --bg-spare /tmp/y.sock`, false],
    [`${trustedClaude} daemon run --origin transient`, false],
    [`${trustedClaude} --debug daemon run --origin transient`, true],
    ["claude agents --json", false],
    ["claude auth", false],
    ["claude auto-mode", false],
    ["claude doctor", false],
    ["claude gateway", false],
    ["claude install latest", false],
    ["claude mcp serve", false],
    ["claude plugin list", false],
    ["claude project", false],
    ["claude setup-token", false],
    ["claude ultrareview", false],
    ["claude update", false],
    ["claude upgrade", false],
    ["claude --debug=api gateway", false],
    ["claude --help", false],
    ["claude --version", false],
    ["claude --config /tmp agents --json", false],
    ["claude --debug-file /dev/null agents --json", false],
    ["claude --debug-file /dev/null daemon run", true],
    ["claude --debug api daemon run", true],
    ["claude --debug gateway", true],
    ["claude --resume gateway", true],
    ["claude --from-pr gateway", true],
    ["claude --remote-control gateway", true],
    ["claude --worktree gateway", true],
    ["claude --add-dir /tmp gateway", true],
    ["claude --allowedTools Bash gateway", true],
    ["claude --allowed-tools Bash gateway", true],
    ["claude --betas beta-a gateway", true],
    ["claude --disallowedTools Write gateway", true],
    ["claude --disallowed-tools Write gateway", true],
    ["claude --file file_abc:a.txt gateway", true],
    ["claude --mcp-config config.json gateway", true],
    ["claude --tools Bash gateway", true],
    ["claude --add-dir --verbose gateway", true],
    ["claude --add-dir --debug=api gateway", true],
    ["claude --allowedTools --verbose gateway", true],
    ["claude --allowed-tools --verbose gateway", true],
    ["claude --betas --verbose gateway", true],
    ["claude --disallowedTools --verbose gateway", true],
    ["claude --disallowed-tools --verbose gateway", true],
    ["claude --file --verbose gateway", true],
    ["claude --mcp-config --verbose gateway", true],
    ["claude --tools --verbose gateway", true],
    ["claude --add-dir /tmp --verbose gateway", false],
    ["claude --add-dir=/tmp gateway", false],
    ["claude --add-dir", false],
    ["claude -r abc agents --json", false],
    ["claude --effort high agents --json", false],
    ['claude --json-schema "{}" agents --json', false],
    ["claude --max-budget-usd 1 agents --json", false],
    ["claude -p explain--bg-pty-host-behavior", true],
    ["claude --bg-sparely user-data", true],
    ["claude -- --bg-spare", true],
    ["claude -- gateway", true],
    ["claude --system-prompt --bg-spare --resume abc", true],
    ["claude --debug --bg-spare /tmp/y.sock", false],
    ["node /home/u/.local/bin/accounts login acct1 --tool claude", false],
    ["/bin/bash -c source /home/u/profiles/claude/acct1/shell-snapshots/snap.sh", false],
    ["script -qefc claude agents --json /dev/null", false],
  ];
  try {
    for (const [command, expected] of cases) {
      expect(
        isToolSessionCommand(
          command,
          "claude",
          "claude",
          wrapperProcessIdentity(command, trustedInterpreters),
        ),
        command,
      ).toBe(expected);
    }
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test("bare configured executables trust only the bare token, PATH target, and native version root", () => {
  const directoryBin = join(home, "directory-bin");
  const directoryNamedClaude = join(directoryBin, "claude");
  const binDir = join(home, "trusted-bin");
  const resolvedClaude = join(binDir, "claude");
  mkdirSync(directoryNamedClaude, { recursive: true });
  mkdirSync(binDir, { recursive: true });
  writeFileSync(resolvedClaude, "#!/bin/sh\nexit 0\n");
  chmodSync(resolvedClaude, 0o755);
  const previousPath = process.env.PATH;
  process.env.PATH = `${directoryBin}:${binDir}:${previousPath ?? ""}`;

  try {
    const versionedClaude = join(
      homedir(),
      ".local",
      "share",
      "claude",
      "versions",
      "2.1.220",
    );
    const prereleaseClaude = join(
      homedir(),
      ".local",
      "share",
      "claude",
      "versions",
      "2.1.220-beta.1+build.7",
    );
    for (const command of [
      "claude --session-id abc",
      `${resolvedClaude} --session-id abc`,
      `${versionedClaude} --session-id abc`,
      `${prereleaseClaude} --session-id abc`,
    ]) {
      expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(true);
    }
    for (const command of [
      `${directoryNamedClaude} --session-id abc`,
      "/tmp/evil/claude --session-id abc",
      "node /tmp/evil/claude --session-id abc",
      "bun /tmp/evil/claude --session-id abc",
      join(homedir(), ".local", "share", "claude", "versions", "2.1"),
      join(homedir(), ".local", "share", "claude", "versions", "02.1.3"),
      join(homedir(), ".local", "share", "claude", "versions", "2.01.3"),
      join(homedir(), ".local", "share", "claude", "versions", "2.1.03"),
      join(homedir(), ".local", "share", "claude", "versions", "2.1.3-01"),
      join(homedir(), ".local", "share", "claude", "versions", "2.1.3-.."),
      join(
        homedir(),
        ".local",
        "share",
        "claude",
        "versions",
        "2.1.3-alpha..1",
      ),
    ]) {
      expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(false);
    }
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test("interpreter wrappers require PATH-trusted interpreter and child identities", () => {
  const binDir = join(home, "wrapper-bin");
  const trustedNode = join(binDir, "node");
  const trustedBun = join(binDir, "bun");
  const trustedChild = join(binDir, "custom-agent");
  const evilDir = join(home, "evil-wrapper-bin");
  const evilNode = join(evilDir, "node");
  const evilBun = join(evilDir, "bun");
  const evilChild = join(evilDir, "custom-agent");
  mkdirSync(binDir, { recursive: true });
  mkdirSync(evilDir, { recursive: true });
  for (const executable of [
    trustedNode,
    trustedBun,
    trustedChild,
    evilNode,
    evilBun,
    evilChild,
  ]) {
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
  }

  const previousPath = process.env.PATH;
  process.env.PATH = `${binDir}:${evilDir}`;
  const trustedInterpreters: TrustedInterpreterPaths = {
    node: trustedNode,
    nodejs: join(binDir, "nodejs"),
    bun: trustedBun,
  };
  try {
    for (const command of [
      `${trustedNode} ${trustedChild} --resume abc`,
      `${trustedBun} ${trustedChild} --resume abc`,
      `node ${trustedChild} --resume abc`,
      `bun ${trustedChild} --resume abc`,
    ]) {
      expect(
        isToolSessionCommand(
          command,
          "custom-agent",
          "custom-agent",
          wrapperProcessIdentity(command, trustedInterpreters),
        ),
        command,
      ).toBe(true);
    }

    for (const command of [
      `${evilNode} ${trustedChild} --resume abc`,
      `${evilBun} ${trustedChild} --resume abc`,
      `${trustedNode} ${evilChild} --resume abc`,
      `${trustedBun} ${evilChild} --resume abc`,
      "node custom-agent --resume abc",
      "bun custom-agent --resume abc",
      "node missing-agent --resume abc",
      "bun missing-agent --resume abc",
    ]) {
      expect(
        isToolSessionCommand(
          command,
          "custom-agent",
          "custom-agent",
          wrapperProcessIdentity(command, trustedInterpreters),
        ),
        command,
      ).toBe(false);
    }

    rmSync(trustedNode);
    expect(
      isToolSessionCommand(
        `${trustedNode} ${trustedChild} --resume abc`,
        "custom-agent",
        "custom-agent",
        trustedNode,
      ),
    ).toBe(false);
    expect(
      isToolSessionCommand(
        `${evilNode} ${trustedChild} --resume abc`,
        "custom-agent",
        "custom-agent",
        evilNode,
      ),
    ).toBe(true);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test("interpreter wrappers fail closed without a verified process executable identity", () => {
  const binDir = join(home, "identity-wrapper-bin");
  const trustedNode = join(binDir, "node");
  const trustedChild = join(binDir, "custom-agent");
  const untrustedNode = join(home, "untrusted-node");
  mkdirSync(binDir, { recursive: true });
  for (const executable of [trustedNode, trustedChild, untrustedNode]) {
    writeFileSync(executable, "#!/bin/sh\nexit 0\n");
    chmodSync(executable, 0o755);
  }

  const previousPath = process.env.PATH;
  process.env.PATH = binDir;
  try {
    const command = `node ${trustedChild} --resume abc`;
    expect(
      classifyWithProcessIdentity(command, trustedChild, "custom-agent"),
    ).toBe(false);
    expect(
      classifyWithProcessIdentity(
        command,
        trustedChild,
        "custom-agent",
        trustedNode,
      ),
    ).toBe(true);
    expect(
      classifyWithProcessIdentity(
        command,
        trustedChild,
        "custom-agent",
        untrustedNode,
      ),
    ).toBe(false);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test.skipIf(process.platform !== "linux")(
  "process attribution verifies direct PID executables and fails closed on wrapper argv",
  async () => {
    const binDir = join(home, "pid-identity-bin");
    const trustedNode = join(binDir, "node");
    const trustedChild = join(binDir, "pid-identity-agent");
    const titleForger = join(binDir, "title-forger.mjs");
    const nodeExecutable = [
      process.env.NODE,
      join(homedir(), ".hermes", "node", "bin", "node"),
      "/usr/bin/node",
      "/bin/node",
    ].find((candidate): candidate is string =>
      typeof candidate === "string" && existsSync(candidate)
    );
    if (!nodeExecutable) return;
    mkdirSync(binDir, { recursive: true });
    symlinkSync(nodeExecutable!, trustedNode);
    symlinkSync("/bin/sleep", trustedChild);
    writeFileSync(
      titleForger,
      [
        "process.title = process.argv[2];",
        "setInterval(() => {}, 1_000);",
        "",
      ].join("\n"),
    );
    process.env.PATH = `${binDir}:${process.env.PATH ?? ""}`;

    const genuine = spawn(
      trustedChild,
      ["30"],
      {
        stdio: "ignore",
      },
    );
    const forged = spawn(
      "/bin/sleep",
      ["30"],
      {
        argv0: `node ${trustedChild} --resume forged`,
        stdio: "ignore",
      },
    );
    const forgedTrustedInterpreter = spawn(
      trustedNode,
      [
        titleForger,
        `node ${trustedChild} --resume forged-trusted-interpreter`,
      ],
      {
        argv0: "node",
        stdio: "ignore",
      },
    );
    await Promise.all([
      new Promise<void>((resolve, reject) => {
        genuine.once("spawn", resolve);
        genuine.once("error", reject);
      }),
      new Promise<void>((resolve, reject) => {
        forged.once("spawn", resolve);
        forged.once("error", reject);
      }),
      new Promise<void>((resolve, reject) => {
        forgedTrustedInterpreter.once("spawn", resolve);
        forgedTrustedInterpreter.once("error", reject);
      }),
    ]);

    try {
      let forgedTitleObserved = false;
      let genuineCommand = "";
      let forgedCommand = "";
      let forgedTrustedCommand = "";
      const deadline = Date.now() + 2_000;
      do {
        genuineCommand = spawnSync(
          "ps",
          ["-p", String(genuine.pid), "-o", "args="],
          { encoding: "utf8" },
        ).stdout.trim();
        forgedCommand = spawnSync(
          "ps",
          ["-p", String(forged.pid), "-o", "args="],
          { encoding: "utf8" },
        ).stdout.trim();
        forgedTrustedCommand = spawnSync(
          "ps",
          ["-p", String(forgedTrustedInterpreter.pid), "-o", "args="],
          { encoding: "utf8" },
        ).stdout.trim();
        forgedTitleObserved ||= forgedTrustedCommand.startsWith(
          `node ${trustedChild} --resume forged-trusted-interpreter`,
        );
        if (
          forgedTitleObserved &&
          genuineCommand &&
          forgedCommand
        ) {
          break;
        }
        await Bun.sleep(10);
      } while (Date.now() < deadline);
      expect(forgedTitleObserved).toBe(true);
      expect(
        classifyWithProcessIdentity(
          genuineCommand,
          trustedChild,
          "pid-identity-agent",
          readlinkSync(`/proc/${genuine.pid}/exe`),
          true,
        ),
      ).toBe(true);
      expect(
        classifyWithProcessIdentity(
          forgedCommand,
          trustedChild,
          "pid-identity-agent",
          readlinkSync(`/proc/${forged.pid}/exe`),
          true,
        ),
      ).toBe(false);
      expect(
        classifyWithProcessIdentity(
          forgedTrustedCommand,
          trustedChild,
          "pid-identity-agent",
          readlinkSync(`/proc/${forgedTrustedInterpreter.pid}/exe`),
          true,
        ),
      ).toBe(false);
    } finally {
      genuine.kill("SIGKILL");
      forged.kill("SIGKILL");
      forgedTrustedInterpreter.kill("SIGKILL");
      await Promise.all([
        new Promise<void>((resolve) => genuine.once("close", () => resolve())),
        new Promise<void>((resolve) => forged.once("close", () => resolve())),
        new Promise<void>((resolve) =>
          forgedTrustedInterpreter.once("close", () => resolve())
        ),
      ]);
    }
  },
);

test("tool identity, not executable basename, selects Claude and wrapper grammar", () => {
  expect(isToolSessionCommand("claude daemon", "claude", "custom-claude")).toBe(true);
  expect(isToolSessionCommand("claude --help", "claude", "custom-claude")).toBe(true);
  expect(isToolSessionCommand("claude daemon", "claude", "claude")).toBe(false);

  expect(isToolSessionCommand("node --future-option value", "node", "custom-node")).toBe(true);
  expect(isToolSessionCommand("bun --future-option value", "bun", "custom-bun")).toBe(true);

  const codexAppBin = "/Applications/Codex.app/Contents/MacOS/Codex";
  expect(
    isToolSessionCommand(
      `${codexAppBin} --user-data-dir=/safe`,
      codexAppBin,
      "codex-app",
    ),
  ).toBe(true);
});

test("Claude 2.1.220 control grammar excludes exact non-session commands and daemon positions", () => {
  for (const command of [
    "remote",
    "sync",
    "bridge",
    "logs",
    "attach",
    "stop",
    "kill",
    "respawn",
    "rm",
  ]) {
    expect(
      isToolSessionCommand(`claude ${command}`, "claude", "claude"),
      command,
    ).toBe(false);
  }

  for (const command of [
    "claude daemon run",
    "claude --dangerously-skip-permissions daemon run",
    "claude --allow-dangerously-skip-permissions daemon run",
    "claude logs --bg",
    "claude daemon --bg",
    "claude --dangerously-skip-permissions daemon --background",
  ]) {
    expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(false);
  }
  for (const command of [
    "claude --debug-file /dev/null daemon run",
    "claude --permission-mode bypassPermissions daemon run",
    "claude --debug remote",
    "claude --debug sync",
    "claude --debug bridge",
    "claude --debug logs",
    "claude logs-extra",
    "claude prompt daemon run",
  ]) {
    expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(true);
  }

  for (const command of [
    "claude --bg",
    "claude --background",
    "claude -- --bg",
    "claude --bg --help",
    "claude -- --background --version",
  ]) {
    expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(false);
  }
  for (const command of [
    "claude --backgrounded",
    "claude --bg=worker",
    "claude prompt-with---background-suffix",
  ]) {
    expect(isToolSessionCommand(command, "claude", "claude"), command).toBe(true);
  }
  expect(
    isToolSessionCommand("claude --bg-spare /tmp/spare.sock", "claude", "claude"),
  ).toBe(false);
});

test("isToolSessionCommand enforces every required scalar tool option arity", () => {
  const requiredValueOptions = [
    "--config",
    "--config-dir",
    "--debug-file",
    "--effort",
    "--thinking",
    "--thinking-display",
    "--max-thinking-tokens",
    "--task-budget",
    "--permission-prompt-tool",
    "--settings",
    "--managed-settings",
    "--model",
    "--permission-mode",
    "--session-id",
    "--resume-session-at",
    "--name",
    "-n",
    "--output-format",
    "--input-format",
    "--system-prompt",
    "--system-prompt-file",
    "--append-system-prompt",
    "--append-system-prompt-file",
    "--append-subagent-system-prompt",
    "--plan-mode-instructions",
    "--fallback-model",
    "--json-schema",
    "--max-budget-usd",
    "--agent",
    "--agents",
    "--agent-id",
    "--agent-name",
    "--agent-type",
    "--agent-color",
    "--team-name",
    "--parent-session-id",
    "--teammate-mode",
    "--plugin-dir",
    "--plugin-dir-no-mcp",
    "--plugin-url",
    "--prefill",
    "--prefill-b64",
    "--deep-link-repo",
    "--deep-link-last-fetch",
    "--deep-link-cwd-b64",
    "--advisor",
    "--sdk-url",
    "--workload",
    "--remote-control-session-name-prefix",
    "--setting-sources",
    "--max-turns",
    "--budget-usd",
  ];

  for (const option of requiredValueOptions) {
    expect(isToolSessionCommand(`claude ${option}`, "claude"), `${option} missing`).toBe(false);
    expect(isToolSessionCommand(`claude ${option} value`, "claude"), `${option} separate`).toBe(
      true,
    );
    expect(
      isToolSessionCommand(`claude ${option} value --bg-spare`, "claude"),
      `${option} separate boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude ${option}=value --bg-spare`, "claude"),
      `${option} attached boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude ${option} --bg-spare`, "claude"),
      `${option} dash-leading value`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude hello ${option}`, "claude"),
      `${option} post-positional missing`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option} value`, "claude"),
      `${option} post-positional separate`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude hello ${option}=value --bg-spare`, "claude"),
      `${option} post-positional attached boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option} --bg-spare`, "claude"),
      `${option} post-positional dash-leading value`,
    ).toBe(true);
  }
});

test("isToolSessionCommand consumes every optional tool option value when present", () => {
  const optionalValueOptions = [
    "-d",
    "--debug",
    "--from-pr",
    "--prompt-suggestions",
    "--remote-control",
    "--teleport",
    "--cloud",
    "--remote",
    "--rc",
    "-r",
    "--resume",
    "-w",
    "--worktree",
  ];

  for (const option of optionalValueOptions) {
    expect(isToolSessionCommand(`claude ${option}`, "claude"), `${option} omitted`).toBe(true);
    expect(
      isToolSessionCommand(`claude ${option} gateway`, "claude"),
      `${option} separate named like subcommand`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude ${option}=value --bg-spare`, "claude"),
      `${option} attached boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option}`, "claude"),
      `${option} post-positional omitted`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude hello ${option} gateway`, "claude"),
      `${option} post-positional separate named like subcommand`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude hello ${option}=value --bg-spare`, "claude"),
      `${option} post-positional attached boundary`,
    ).toBe(false);
  }
});

test("isToolSessionCommand enforces every mandatory-first variadic tool option arity", () => {
  const variadicValueOptions = [
    "--add-dir",
    "--allowedTools",
    "--allowed-tools",
    "--betas",
    "--channels",
    "--dangerously-load-development-channels",
    "--disallowedTools",
    "--disallowed-tools",
    "--file",
    "--mcp-config",
    "--tools",
  ];

  for (const option of variadicValueOptions) {
    expect(isToolSessionCommand(`claude ${option}`, "claude"), `${option} missing`).toBe(false);
    expect(isToolSessionCommand(`claude ${option} value`, "claude"), `${option} one value`).toBe(
      true,
    );
    expect(
      isToolSessionCommand(`claude ${option} first second`, "claude"),
      `${option} multiple values`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude ${option} --bg-spare`, "claude"),
      `${option} mandatory dash-leading first value`,
    ).toBe(true);
    expect(
      isToolSessionCommand(`claude ${option} first --bg-spare`, "claude"),
      `${option} helper boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude ${option}=first --bg-spare`, "claude"),
      `${option} attached boundary`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option}`, "claude"),
      `${option} post-positional missing`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option} first second --bg-spare`, "claude"),
      `${option} post-positional helper boundary`,
    ).toBe(false);
  }
});

test("isToolSessionCommand validates global options after a positional until end-of-options", () => {
  expect(isToolSessionCommand("claude hello --tools", "claude")).toBe(false);
  expect(isToolSessionCommand("claude hello --add-dir", "claude")).toBe(false);
  expect(isToolSessionCommand("claude hello --debug", "claude")).toBe(true);
  expect(isToolSessionCommand("claude hello -- --help", "claude")).toBe(true);
  expect(isToolSessionCommand("claude hello -- --model", "claude")).toBe(true);
});

test("isToolSessionCommand excludes every terminal and helper option spelling", () => {
  const terminalOptions = [
    "-h",
    "--help",
    "-v",
    "-V",
    "--version",
    "--update",
    "--upgrade",
    "--init-only",
    "--rewind-files",
    "--handle-uri",
  ];
  const helperOptions = [
    "--bg-pty-host",
    "--bg-spare",
    "--chrome-native-host",
    "--claude-in-chrome-mcp",
    "--computer-use-mcp",
    "--daemon-worker",
    "--preload",
  ];

  for (const option of [...terminalOptions, ...helperOptions]) {
    expect(isToolSessionCommand(`claude ${option}`, "claude"), `${option} leading`).toBe(false);
    expect(
      isToolSessionCommand(`claude hello ${option}`, "claude"),
      `${option} post-positional`,
    ).toBe(false);
    expect(
      isToolSessionCommand(`claude -- ${option}`, "claude"),
      `${option} after end-of-options`,
    ).toBe(true);
  }
});

test("isToolSessionCommand excludes Claude pre-parser and positional exit modes", () => {
  for (const command of [
    "claude remote-control",
    "claude rc",
    "claude --handle-uri cc://test",
    "claude --handle-uri=cc://test",
    "claude -- --handle-uri cc://test",
    "claude hello --handle-uri cc://test",
    "claude --init-only",
    "claude hello --init-only",
    "claude --rewind-files abc",
    "claude hello --rewind-files abc",
  ]) {
    expect(isToolSessionCommand(command, "claude"), command).toBe(false);
  }
  for (const command of [
    "claude -- --handle-uri",
    "claude -- --handle-uri=cc://test",
    "claude hello -- --handle-uri",
    "claude hello -- --handle-uri=cc://test",
    'claude -- --handle-uri ""',
    'claude hello -- --handle-uri ""',
    'claude -- --handle-uri "" --handle-uri cc://test',
  ]) {
    expect(isToolSessionCommand(command, "claude"), command).toBe(true);
  }
  expect(
    isToolSessionCommand(
      "claude -- --handle-uri=cc://first --handle-uri cc://test",
      "claude",
    ),
  ).toBe(false);
});

test("isToolSessionCommand matches absolute tool bins and interpreter wrappers", () => {
  const trustedInterpreters = trustInterpreters();
  const customBin = "/opt/acme/bin/custom-agent";
  for (const command of [
    `${customBin} --resume abc`,
    `node ${customBin} --resume abc`,
    `bun ${customBin} --resume abc`,
    `node --no-warnings ${customBin} --resume abc`,
    `node --trace-warnings ${customBin} --resume abc`,
    `node --experimental-loader /dev/null ${customBin} --resume abc`,
    `node --require=/dev/null ${customBin} --resume abc`,
    `node -C custom ${customBin} --resume abc`,
    `node --conditions=custom ${customBin} --resume abc`,
    `node --env-file-if-exists /tmp/nope ${customBin} --resume abc`,
    `node --debug-port 9230 ${customBin} --resume abc`,
    `node --inspect ${customBin} --resume abc`,
    `node --inspect=9230 ${customBin} --resume abc`,
    `nodejs ${customBin} --resume abc`,
    `bun --preload /dev/null ${customBin} --resume abc`,
    `bun -r./src/lib/tools.ts ${customBin} --resume abc`,
    `bun --cwd /tmp ${customBin} --resume abc`,
    `bun -c=/dev/null ${customBin} --resume abc`,
    `bun --cpu-prof-name p.cpuprofile ${customBin} --resume abc`,
    `${customBin} --preload`,
    `${customBin} --daemon-worker`,
    `${customBin} --update`,
    `${customBin} --handle-uri cc://test`,
    `${customBin} --init-only`,
    `${customBin} --rewind-files abc`,
    `${customBin} remote-control`,
    `${customBin} rc`,
    `node ${customBin} --preload`,
    `bun ${customBin} --daemon-worker`,
  ]) {
    expect(
      isToolSessionCommand(
        command,
        customBin,
        "custom-agent",
        wrapperProcessIdentity(command, trustedInterpreters),
      ),
      command,
    ).toBe(true);
  }
  for (const command of [
    "/tmp/other/custom-agent --resume abc",
    "node /tmp/other/custom-agent --resume abc",
    "bun /tmp/other/custom-agent --resume abc",
    `node --require ${customBin} /tmp/other-entrypoint.js`,
    `node --inspect /dev/null ${customBin}`,
    `node --inspect-brk /dev/null ${customBin}`,
    `node --inspect-wait /dev/null ${customBin}`,
    `node -e "setTimeout(() => {}, 10)" ${customBin}`,
    `node --eval="" ${customBin}`,
    `bun -e "setTimeout(() => {}, 10)" ${customBin}`,
    `bun --eval="" ${customBin}`,
    `node --run=no-such-script ${customBin}`,
    `node --future-option=value ${customBin}`,
    `node -r./mod.cjs ${customBin}`,
    `node -r=./mod.cjs ${customBin}`,
    `node -C/tmp ${customBin}`,
    `node -C=custom ${customBin}`,
    `node -random ${customBin}`,
    `node --cwd /tmp ${customBin}`,
    `node --smol ${customBin}`,
    `node --preload /dev/null ${customBin}`,
    `node --input-type module ${customBin}`,
    `node --experimental-sea-config /dev/null ${customBin}`,
    `node --build-snapshot-config /dev/null ${customBin}`,
    `bun -C custom ${customBin}`,
    `bun --experimental-loader /dev/null ${customBin}`,
    `bun --filter no-match ${customBin}`,
    `bun --workspaces ${customBin}`,
    `bun --parallel ${customBin}`,
    `bun --sequential ${customBin}`,
    `bun --shell bun ${customBin}`,
    "node --env-file-if-exists /dev/null /tmp/other-entrypoint.js",
    "bun --cpu-prof-name /dev/null /tmp/other-entrypoint.js",
  ]) {
    expect(
      isToolSessionCommand(
        command,
        customBin,
        "custom-agent",
        wrapperProcessIdentity(command, trustedInterpreters),
      ),
      command,
    ).toBe(false);
  }
  expect(
    isToolSessionCommand(
      "node --env-file-if-exists /dev/null /tmp/other-entrypoint.js",
      "/dev/null",
      "dev-null",
      trustedInterpreters.node,
    ),
  ).toBe(false);
  expect(
    isToolSessionCommand(
      "bun --cpu-prof-name /dev/null /tmp/other-entrypoint.js",
      "/dev/null",
      "dev-null",
      trustedInterpreters.bun,
    ),
  ).toBe(false);
  expect(isToolSessionCommand("custom-agent --resume abc", customBin)).toBe(false);
  expect(isToolSessionCommand("node custom-agent --resume abc", customBin)).toBe(false);

  const codexAppBin = "/Applications/Codex.app/Contents/MacOS/Codex";
  for (const command of [
    `${codexAppBin} --user-data-dir=/safe`,
    `${codexAppBin} --preload`,
    `${codexAppBin} --daemon-worker`,
    `${codexAppBin} --update`,
    `${codexAppBin} --handle-uri codex://test`,
    `${codexAppBin} --init-only`,
    `${codexAppBin} --rewind-files abc`,
    `${codexAppBin} remote-control`,
    `${codexAppBin} rc`,
  ]) {
    expect(isToolSessionCommand(command, codexAppBin), command).toBe(true);
  }

  const spacedBin = "/Applications/Custom Agent.app/Contents/MacOS/custom-agent";
  for (const command of [
    `${spacedBin} --resume abc`,
    `"${spacedBin}" --resume abc`,
    `node ${spacedBin} --resume abc`,
    `bun "${spacedBin}" --resume abc`,
  ]) {
    expect(
      isToolSessionCommand(
        command,
        spacedBin,
        "custom-agent",
        wrapperProcessIdentity(command, trustedInterpreters),
      ),
      command,
    ).toBe(true);
  }
});

test("Node 22.22.3 and Bun 1.3.14 wrapper option schemas are explicit and fail closed", () => {
  const trustedInterpreters = trustInterpreters();
  const customBin = "/opt/acme/bin/custom-agent";
  // This classifier is a trust boundary, not a byte-for-byte runtime parser:
  // Bun 1.3.14 tolerates some empty `--name=` forms, but required-value schema
  // entries still fail closed here because no meaningful wrapper value was
  // proven. Optional attached-value entries such as `--inspect=` remain valid.
  const accepted = [
    `node --allow-child-process ${customBin}`,
    `node --allow-fs-read=/tmp ${customBin}`,
    `node --allow-fs-read /tmp ${customBin}`,
    `node --experimental-permission ${customBin}`,
    `node --use-env-proxy ${customBin}`,
    `node --max-old-space-size=2048 ${customBin}`,
    `node --max-semi-space-size=64 ${customBin}`,
    `node --stack-trace-limit=100 ${customBin}`,
    `node --inspect= ${customBin}`,
    `bun --main-fields module ${customBin}`,
    `bun --main-fields=module ${customBin}`,
    `bun --extension-order .tsx,.ts ${customBin}`,
    `bun --tsconfig-override tsconfig.json ${customBin}`,
    `bun --define DEBUG=true ${customBin}`,
    `bun -dDEBUG=true ${customBin}`,
    `bun --drop console ${customBin}`,
    `bun --feature shell ${customBin}`,
    `bun --loader ts ${customBin}`,
    `bun -lts ${customBin}`,
    `bun --jsx-factory h ${customBin}`,
    `bun --jsx-fragment Fragment ${customBin}`,
    `bun --jsx-import-source preact ${customBin}`,
    `bun --jsx-runtime automatic ${customBin}`,
    `bun --no-macros ${customBin}`,
    `bun --jsx-side-effects ${customBin}`,
    `bun --ignore-dce-annotations ${customBin}`,
    `bun --conditions custom ${customBin}`,
    `bun --conditions=custom ${customBin}`,
    `bun --inspect= ${customBin}`,
    `bun run ${customBin}`,
    `bun --silent run ${customBin}`,
    `bun --cwd /tmp run ${customBin}`,
    `bun --cwd=/tmp run ${customBin}`,
    `bun --smol run ${customBin}`,
    `bun run --silent ${customBin}`,
    `bun run --cwd /tmp ${customBin}`,
    `bun run --main-fields module ${customBin}`,
    `bun run --filter workspace-a ${customBin}`,
    `bun run --filter=workspace-a ${customBin}`,
    `bun run -Fworkspace-a ${customBin}`,
    `bun run --shell=bun ${customBin}`,
    `bun run --workspaces ${customBin}`,
    `bun run --parallel ${customBin}`,
    `bun run --sequential ${customBin}`,
    `bun run -- ${customBin}`,
  ];
  const rejected = [
    `node --conditions= ${customBin}`,
    `node '--conditions=' ${customBin}`,
    `node --title= ${customBin}`,
    `node --allow-fs-read= ${customBin}`,
    `node --allow-fs-read --future-separated value ${customBin}`,
    `node --max-old-space-size 2048 ${customBin}`,
    `node --max-semi-space-size 64 ${customBin}`,
    `node --stack-trace-limit 100 ${customBin}`,
    "node --max-old-space-size",
    "node --max-semi-space-size",
    "node --stack-trace-limit",
    `node --future-separated value ${customBin}`,
    `bun --conditions= ${customBin}`,
    `bun --title= ${customBin}`,
    `bun --cwd= run ${customBin}`,
    `bun --main-fields= ${customBin}`,
    `bun run --filter= ${customBin}`,
    `bun --future-separated value ${customBin}`,
    `bun --future-separated value run ${customBin}`,
    `bun --eval console.log(1) run ${customBin}`,
    `bun run run ${customBin}`,
    `bun run --future-separated value ${customBin}`,
    `bun run --eval console.log(1) ${customBin}`,
  ];

  for (const command of accepted) {
    expect(
      isToolSessionCommand(
        command,
        customBin,
        "custom-agent",
        wrapperProcessIdentity(command, trustedInterpreters),
      ),
      command,
    ).toBe(true);
  }
  for (const command of rejected) {
    expect(
      isToolSessionCommand(
        command,
        customBin,
        "custom-agent",
        wrapperProcessIdentity(command, trustedInterpreters),
      ),
      command,
    ).toBe(false);
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

test("process scanning is bound to the requested tool id", () => {
  addProfile({ name: "codexer", tool: "codex" });
  let observedTool: unknown;
  const processScanner = function () {
    observedTool = arguments[0];
    return [];
  };

  listAgentsAcrossProfiles({
    profiles: listProfiles(),
    tool: "codex",
    runner: () => ({ ok: true, raw: "[]" }),
    processScanner,
  });

  expect(observedTool).toBe("codex");
});

test("malformed provider PIDs cannot suppress real untracked processes", () => {
  addProfile({ name: "acct1", tool: "claude" });
  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner: () => ({
      ok: true,
      raw: JSON.stringify([
        { kind: "unknown", pid: 321, state: "working" },
        { kind: "background", pid: -1, state: "working" },
        { kind: "interactive", pid: Number.MAX_SAFE_INTEGER + 1, state: "working" },
      ]),
    }),
    processScanner: () => [
      { pid: -2, ppid: 1, command: "claude invalid-negative-pid" },
      {
        pid: Number.MAX_SAFE_INTEGER + 1,
        ppid: 1,
        command: "claude invalid-unsafe-pid",
      },
      { pid: 654, ppid: -1, command: "claude invalid-negative-ppid" },
      {
        pid: 321,
        ppid: 1,
        command: "claude --resume real-untracked",
      },
    ],
  });

  expect(results[0]?.agents).toEqual([]);
  expect(results.find((result) => result.profile === "(untracked)")?.agents).toEqual([
    {
      kind: "process",
      pid: 321,
      command: "claude --resume real-untracked",
    },
  ]);
});

test("provider agent projection is getter-free, proxy-safe, cycle-safe, and recursively redacted", () => {
  let getterCount = 0;
  let proxyTrapCount = 0;
  const nested = Object.create(null) as Record<string, unknown>;
  Object.defineProperties(nested, {
    state: { value: "working", enumerable: true },
    message: {
      value: "provider --api-key nested-message-secret --trace keep-agent-message",
      enumerable: true,
    },
    token: { value: "nested-token-secret", enumerable: true },
    getter: {
      get() {
        getterCount++;
        return "agent-getter-secret";
      },
      enumerable: true,
    },
  });
  nested.cycle = nested;
  const proxy = new Proxy(
    { message: "proxy-agent-secret" },
    {
      ownKeys(target) {
        proxyTrapCount++;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        proxyTrapCount++;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      getPrototypeOf(target) {
        proxyTrapCount++;
        return Reflect.getPrototypeOf(target);
      },
    },
  );
  const entry = Object.create(null) as Record<string, unknown>;
  Object.defineProperties(entry, {
    kind: { value: "background", enumerable: true },
    pid: { value: 42, enumerable: true },
    sessionId: { value: "session-safe", enumerable: true },
    nested: { value: nested, enumerable: true },
    list: {
      value: [
        "provider --client-key array-agent-secret --mode keep-agent-array",
        proxy,
      ],
      enumerable: true,
    },
    throwing: {
      get() {
        getterCount++;
        throw new Error("agent-throwing-getter-secret");
      },
      enumerable: true,
    },
  });

  const projected = projectAgentEntries([entry, proxy, null, "raw-agent-secret"]);
  const serialized = JSON.stringify(projected);

  expect(getterCount).toBe(0);
  expect(proxyTrapCount).toBe(0);
  expect(projected).toHaveLength(1);
  expect(projected[0]?.kind).toBe("background");
  expect(projected[0]?.pid).toBe(42);
  expect(serialized).not.toContain("nested-message-secret");
  expect(serialized).not.toContain("nested-token-secret");
  expect(serialized).not.toContain("array-agent-secret");
  expect(serialized).not.toContain("proxy-agent-secret");
  expect(serialized).not.toContain("agent-getter-secret");
  expect(serialized).not.toContain("agent-throwing-getter-secret");
  expect(serialized).toContain("keep-agent-message");
  expect(serialized).toContain("keep-agent-array");
});

test("provider agent projection bounds deeply nested records without recursion", () => {
  const root: Record<string, unknown> = {
    kind: "background",
    pid: 42,
    state: "working",
  };
  let cursor = root;
  for (let depth = 0; depth < 22_000; depth++) {
    const next = Object.create(null) as Record<string, unknown>;
    cursor.nested = next;
    cursor = next;
  }
  cursor.message =
    "provider --api-key unreachable-deep-secret --trace keep-deep-agent";

  let projected: ReturnType<typeof projectAgentEntries> | undefined;
  expect(() => {
    projected = projectAgentEntries([root]);
  }).not.toThrow();

  const serialized = JSON.stringify(projected);
  expect(serialized).toContain("[TRUNCATED]");
  expect(serialized).not.toContain("unreachable-deep-secret");
});

test("agents library projections redact provider payloads and untracked process command lines", () => {
  addProfile({ name: "acct1", tool: "claude" });
  let processGetterCount = 0;
  let processProxyTrapCount = 0;
  const providerProjectKey = ["sk", "proj", "provider-positional-token"].join("-");
  const providerMetadataKey = "credential=provider-metadata-key-secret-a";
  const providerMetadataCollisionKey = "credential=provider-metadata-key-secret-b";
  const providerAuthorizationCredentialParts = [
    "eyJhbGciOi" + "Provider12345",
    "eyJzdWIiOi" + "Provider67890",
    "sig" + "ProviderABCDE",
  ];
  const providerAuthorizationKey = `Authorization Bearer ${providerAuthorizationCredentialParts.join(".")}`;
  const runner: AgentsRunner = () => ({
    ok: true,
    raw: JSON.stringify([
      {
        kind: "background",
        pid: 10,
        sessionId: "session-safe",
        argv: [
          "claude",
          "--",
          "wrapper=(--client-key=provider-positional-attached-secret)",
          "outer=(env=--api-key)",
          "",
          "provider-positional-wrapper-split-secret",
          "keep-provider-positional-wrapper-split",
          "url=urn:authorization:public",
          "keep-provider-positional-urn",
          "wrap/Authorization:Bearer",
          "provider-positional-bearer-secret",
          providerProjectKey,
          "https://operator:provider-authority-secret@example.test/callback",
          "keep-provider-positional-control",
        ],
        metadata: {
          token: "provider-token-secret",
          message: "provider --api-key provider-message-secret --trace keep-provider-message",
          [providerMetadataKey]: "provider-metadata-value-secret-a",
          [providerMetadataCollisionKey]: "provider-metadata-value-secret-b",
          [providerAuthorizationKey]: "provider-metadata-bearer-value-secret",
        },
      },
    ]),
  });
  const safeProcess = Object.create(null) as Record<string, unknown>;
  Object.defineProperties(safeProcess, {
    pid: { value: 99, enumerable: true },
    ppid: { value: 1, enumerable: true },
    command: {
      value:
        "claude --resume safe-session -- " +
        "env=--client-key=process-command-secret " +
        "wrapper:--api-key=process-command-wrapper-secret " +
        "outer=(env=--master-key) \"\" process-command-wrapper-split-secret " +
        "keep-process-wrapper-split url=https://example.test/authorization:public " +
        "keep-process-url " +
        "url=https://operator:process-authority-secret@example.test/callback " +
        "keep-process-authority " +
        "keep-before-process-command-auth " +
        "env=Authorization:Bearer process-command-bearer-secret " +
        "keep-process-command",
      enumerable: true,
    },
    configDir: { value: "/profiles/safe", enumerable: true },
    getter: {
      get() {
        processGetterCount++;
        return "process-getter-secret";
      },
      enumerable: true,
    },
    toString: {
      value: () => {
        processGetterCount++;
        return "process-coercion-secret";
      },
      enumerable: true,
    },
  });
  const unsafeProcess = new Proxy(
    {
      pid: 100,
      ppid: 1,
      command: "claude --api-key process-proxy-secret",
    },
    {
      ownKeys(target) {
        processProxyTrapCount++;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, key) {
        processProxyTrapCount++;
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      getPrototypeOf(target) {
        processProxyTrapCount++;
        return Reflect.getPrototypeOf(target);
      },
    },
  );
  const results = listAgentsAcrossProfiles({
    profiles: listProfiles(),
    runner,
    processScanner: () => [safeProcess, unsafeProcess] as unknown as ProcessInfo[],
  });
  const serialized = JSON.stringify(results);

  expect(processGetterCount).toBe(0);
  expect(processProxyTrapCount).toBe(0);
  expect(serialized).not.toContain("provider-token-secret");
  expect(serialized).not.toContain("provider-message-secret");
  expect(serialized).not.toContain("provider-positional-attached-secret");
  expect(serialized).not.toContain("provider-positional-wrapper-split-secret");
  expect(serialized).not.toContain("provider-positional-bearer-secret");
  expect(serialized).not.toContain(providerProjectKey);
  expect(serialized).not.toContain("provider-authority-secret");
  expect(serialized).not.toContain("process-command-secret");
  expect(serialized).not.toContain("process-command-wrapper-secret");
  expect(serialized).not.toContain("process-command-wrapper-split-secret");
  expect(serialized).not.toContain("process-authority-secret");
  expect(serialized).not.toContain("process-command-bearer-secret");
  expect(serialized).not.toContain("process-getter-secret");
  expect(serialized).not.toContain("process-coercion-secret");
  expect(serialized).not.toContain("process-proxy-secret");
  expect(serialized).not.toContain("provider-metadata-key-secret-a");
  expect(serialized).not.toContain("provider-metadata-key-secret-b");
  expect(serialized).not.toContain("provider-metadata-value-secret-a");
  expect(serialized).not.toContain("provider-metadata-value-secret-b");
  for (const credentialPart of providerAuthorizationCredentialParts) {
    expect(serialized).not.toContain(credentialPart);
  }
  expect(serialized).not.toContain("provider-metadata-bearer-value-secret");
  expect(serialized).toContain("credential=[REDACTED]");
  expect(serialized).toContain("credential=[REDACTED]#2");
  expect(serialized).toContain("keep-provider-message");
  expect(serialized).toContain("keep-provider-positional-wrapper-split");
  expect(serialized).toContain("url=urn:authorization:public");
  expect(serialized).toContain("keep-provider-positional-urn");
  expect(serialized).toContain("https://[REDACTED]@example.test/callback");
  expect(serialized).not.toContain("keep-provider-positional-control");
  expect(serialized).toContain("keep-process-wrapper-split");
  expect(serialized).toContain("url=https://example.test/authorization:public");
  expect(serialized).toContain("keep-process-url");
  expect(serialized).toContain("keep-process-authority");
  expect(serialized).toContain("keep-before-process-command-auth");
  expect(serialized).not.toContain("keep-process-command");
  expect(results[0]?.agents[0]).toMatchObject({
    kind: "background",
    pid: 10,
    sessionId: "session-safe",
  });
  expect(results.find((result) => result.profile === "(untracked)")?.agents[0]).toMatchObject({
    kind: "process",
    pid: 99,
    configDir: "/profiles/safe",
  });
});

test.skipIf(process.platform === "win32")("accounts agents JSON and human output use projected provider records", () => {
  const executable = join(home, "projected-agent-provider");
  const agentMetadataKey = "credential=agent-json-metadata-key-secret-a";
  const agentMetadataCollisionKey = "credential=agent-json-metadata-key-secret-b";
  const agentAuthorizationCredentialParts = [
    "eyJhbGciOi" + "AgentJson12345",
    "eyJzdWIiOi" + "AgentJson67890",
    "sig" + "AgentJsonABCDE",
  ];
  const agentAuthorizationKey = `Authorization Bearer ${agentAuthorizationCredentialParts.join(".")}`;
  const payload = JSON.stringify([
    {
      kind: "background",
      pid: 77,
      sessionId: "session-safe",
      state: { phase: "working" },
      name: "provider --api-key agent-human-name-secret --trace keep-agent-human-name",
      cwd: "/safe --client-key=agent-human-cwd-secret --mode keep-agent-human-cwd",
      token: "agent-json-token-secret",
      metadata: {
        message:
          "provider --credentials agent-json-message-secret --debug keep-agent-json-message",
        [agentMetadataKey]: "agent-json-metadata-value-secret-a",
        [agentMetadataCollisionKey]: "agent-json-metadata-value-secret-b",
        [agentAuthorizationKey]: "agent-json-metadata-bearer-value-secret",
      },
    },
  ]);
  writeFileSync(
    executable,
    `#!/bin/sh\nprintf '%s\\n' '${payload.replaceAll("'", "'\\''")}'\n`,
  );
  chmodSync(executable, 0o755);
  addCustomTool({
    id: "projected-agent-provider",
    label: "Projected Agent Provider",
    envVar: "PROJECTED_AGENT_HOME",
    defaultDir: join(home, "projected-agent-default"),
    bin: executable,
  });
  addProfile({ name: "projected", tool: "projected-agent-provider" });
  const run = (json: boolean) =>
    spawnSync(
      process.execPath,
      [
        "run",
        "src/cli.ts",
        "agents",
        "--tool",
        "projected-agent-provider",
        ...(json ? ["--json"] : []),
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          ACCOUNTS_HOME: home,
          NO_COLOR: "1",
        },
      },
    );
  const jsonResult = run(true);
  const humanResult = run(false);

  for (const result of [jsonResult, humanResult]) {
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).not.toContain("agent-human-name-secret");
    expect(result.stdout).not.toContain("agent-human-cwd-secret");
    expect(result.stdout).not.toContain("agent-json-token-secret");
    expect(result.stdout).not.toContain("agent-json-message-secret");
    expect(result.stdout).not.toContain("agent-json-metadata-key-secret-a");
    expect(result.stdout).not.toContain("agent-json-metadata-key-secret-b");
    expect(result.stdout).not.toContain("agent-json-metadata-value-secret-a");
    expect(result.stdout).not.toContain("agent-json-metadata-value-secret-b");
    for (const credentialPart of agentAuthorizationCredentialParts) {
      expect(result.stdout).not.toContain(credentialPart);
    }
    expect(result.stdout).not.toContain("agent-json-metadata-bearer-value-secret");
    expect(result.stdout).toContain("[REDACTED]");
  }
  expect(jsonResult.stdout).toContain("credential=[REDACTED]");
  expect(jsonResult.stdout).toContain("credential=[REDACTED]#2");
  expect(humanResult.stdout).toContain("keep-agent-human-name");
  expect(humanResult.stdout).toContain("keep-agent-human-cwd");
  expect(jsonResult.stdout).toContain("keep-agent-json-message");
});

test.skipIf(process.platform === "win32")("accounts agents bounds deeply nested provider JSON in both output modes", () => {
  const executable = join(home, "deep-agent-provider");
  writeFileSync(
    executable,
    [
      "#!/usr/bin/env bun",
      "const depth = 22_000;",
      "const payload = '[{\"kind\":\"background\",\"pid\":88,\"state\":\"working\",\"metadata\":' + '{\"nested\":'.repeat(depth) + '\"leaf\"' + '}'.repeat(depth) + '}]';",
      "process.stdout.write(payload);",
      "",
    ].join("\n"),
  );
  chmodSync(executable, 0o755);
  addCustomTool({
    id: "deep-agent-provider",
    label: "Deep Agent Provider",
    envVar: "DEEP_AGENT_HOME",
    defaultDir: join(home, "deep-agent-default"),
    bin: executable,
  });
  addProfile({ name: "deep", tool: "deep-agent-provider" });

  const run = (json: boolean) =>
    spawnSync(
      process.execPath,
      [
        "run",
        "src/cli.ts",
        "agents",
        "--tool",
        "deep-agent-provider",
        ...(json ? ["--json"] : []),
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          ACCOUNTS_HOME: home,
          NO_COLOR: "1",
        },
      },
    );

  const jsonResult = run(true);
  const humanResult = run(false);
  for (const result of [jsonResult, humanResult]) {
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).not.toContain("Maximum call stack size exceeded");
  }
  expect(jsonResult.stdout).toContain("[TRUNCATED]");
  expect(humanResult.stdout).toContain("working");
});
