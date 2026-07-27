import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, listProfiles } from "./lib/profiles.js";
import {
  extractJsonArray,
  isToolSessionCommand,
  listAgentsAcrossProfiles,
  projectAgentEntries,
  runClaudeAgentsJson,
  type AgentsRunner,
  type ProcessInfo,
} from "./lib/agents.js";
import { addCustomTool } from "./lib/tools.js";

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

test("extractJsonArray recovers a bounded inner candidate from malformed wrapper noise", () => {
  expect(
    extractJsonArray('noise [broken wrapper [{"pid":7,"kind":"background"}] tail'),
  ).toEqual([{ pid: 7, kind: "background" }]);
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

test("isToolSessionCommand matches absolute tool bins and interpreter wrappers", () => {
  const customBin = "/opt/acme/bin/custom-agent";
  for (const command of [
    `${customBin} --resume abc`,
    `node ${customBin} --resume abc`,
    `bun ${customBin} --resume abc`,
  ]) {
    expect(isToolSessionCommand(command, customBin), command).toBe(true);
  }

  const codexAppBin = "/Applications/Codex.app/Contents/MacOS/Codex";
  expect(isToolSessionCommand(`${codexAppBin} --user-data-dir=/safe`, codexAppBin)).toBe(true);
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
  const runner: AgentsRunner = () => ({
    ok: true,
    raw: JSON.stringify([
      {
        kind: "background",
        pid: 10,
        sessionId: "session-safe",
        metadata: {
          token: "provider-token-secret",
          message: "provider --api-key provider-message-secret --trace keep-provider-message",
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
        "claude --resume safe-session --client-key process-command-secret --trace keep-process-command",
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
  expect(serialized).not.toContain("process-command-secret");
  expect(serialized).not.toContain("process-getter-secret");
  expect(serialized).not.toContain("process-coercion-secret");
  expect(serialized).not.toContain("process-proxy-secret");
  expect(serialized).toContain("keep-provider-message");
  expect(serialized).toContain("keep-process-command");
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
    expect(result.stdout).toContain("[REDACTED]");
  }
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
