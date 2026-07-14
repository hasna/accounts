import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repo = process.cwd();
const cli = join(repo, "src", "cli.ts");
let home: string;
let binDir: string;
let launchCwd: string;
let logPath: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-claude-cli-"));
  binDir = mkdtempSync(join(tmpdir(), "accounts-claude-bin-"));
  launchCwd = mkdtempSync(join(tmpdir(), "accounts-claude-cwd-"));
  logPath = join(home, "fake-claude.jsonl");
  writeFakeClaude();
});

afterEach(() => {
  runCli(["supervisor", "stop", "claude"]);
  rmSync(home, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
  rmSync(launchCwd, { recursive: true, force: true });
});

function runCli(args: string[], options: { cwd?: string; env?: Record<string, string> } = {}) {
  return spawnSync(process.execPath, ["run", cli, ...args], {
    cwd: options.cwd ?? repo,
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_ENV: "test",
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
      HASNA_ACCOUNTS_API_URL: "",
      HASNA_ACCOUNTS_API_KEY: "",
      FAKE_CLAUDE_LOG: logPath,
      PATH: `${binDir}:${process.env.PATH ?? ""}`,
      ...options.env,
    },
  });
}

function writeFakeClaude() {
  const path = join(binDir, "claude");
  writeFileSync(
    path,
    [
      "#!/usr/bin/env bun",
      'import { appendFileSync } from "node:fs";',
      "appendFileSync(process.env.FAKE_CLAUDE_LOG, JSON.stringify({",
      "  args: process.argv.slice(2),",
      "  cwd: process.cwd(),",
      "  configDir: process.env.CLAUDE_CONFIG_DIR,",
      "  active: process.env.ACCOUNTS_ACTIVE,",
      "  supervisor: process.env.ACCOUNTS_SUPERVISOR,",
      '}) + "\\n");',
      'console.log("fake-claude-stdout");',
      'console.error("fake-claude-stderr");',
      "const delay = Number(process.env.FAKE_CLAUDE_SLEEP_MS ?? 0);",
      "if (delay > 0) await Bun.sleep(delay);",
      "process.exit(Number(process.env.FAKE_CLAUDE_EXIT ?? 0));",
    ].join("\n"),
  );
  chmodSync(path, 0o755);
}

function entries(): Array<{
  args: string[];
  cwd: string;
  configDir: string;
  active?: string;
  supervisor?: string;
}> {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function storeCurrent(): Record<string, string> {
  return JSON.parse(readFileSync(join(home, "accounts.json"), "utf8")).current ?? {};
}

async function waitFor<T>(read: () => T | undefined, timeoutMs = 4_000): Promise<T> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = read();
    if (value !== undefined) return value;
    await Bun.sleep(25);
  }
  throw new Error("timed out waiting for fake Claude");
}

test("foreground headless launch preserves argv, cwd, stdout, stderr, and exit status", () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const result = runCli(
    [
      "launch",
      "acct",
      "--tool",
      "claude",
      "--skip-configs",
      "--headless",
      "--permissions",
      "dangerous",
      "--",
      "Prompt with spaces",
      "--literal",
    ],
    { cwd: launchCwd, env: { FAKE_CLAUDE_EXIT: "23" } },
  );

  expect(result.status).toBe(23);
  expect(result.stdout).toContain("fake-claude-stdout");
  expect(result.stderr).toContain("fake-claude-stderr");
  expect(entries()[0]).toMatchObject({
    args: ["--dangerously-skip-permissions", "-p", "Prompt with spaces", "--literal"],
    cwd: launchCwd,
  });
  expect(entries()[0]?.active).toBeUndefined();
  expect(storeCurrent()).toEqual({});
});

test("delimiter passthrough stays raw and noninteractive raw modes do not select a profile", () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const result = runCli(["launch", "acct", "--tool", "claude", "--skip-configs", "--", "--print", "Raw prompt"]);
  expect(result.status).toBe(0);
  expect(entries()[0]?.args).toEqual(["--print", "Raw prompt"]);
  expect(storeCurrent()).toEqual({});
});

test("conflicts and unsupported tools fail before profile mutation or process launch", () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const conflict = runCli([
    "launch",
    "acct",
    "--tool",
    "claude",
    "--skip-configs",
    "--headless",
    "--",
    "--continue",
  ]);
  expect(conflict.status).toBe(1);
  expect(conflict.stderr).toContain("cannot be combined");
  expect(entries()).toEqual([]);
  expect(storeCurrent()).toEqual({});

  expect(runCli(["add", "other", "--tool", "codex"]).status).toBe(0);
  const unsupported = runCli(["launch", "other", "--tool", "codex", "--skip-configs", "--headless", "Prompt"]);
  expect(unsupported.status).toBe(1);
  expect(unsupported.stderr).toContain("only with --tool claude");
  expect(entries()).toEqual([]);
});

test("launch preview redacts secret-shaped args", () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const secret = "sk-ant-abcdefghijklmnopqrstuvwxyz";
  const result = runCli([
    "launch",
    "acct",
    "--tool",
    "claude",
    "--skip-configs",
    "--headless",
    "--",
    "--api-key",
    secret,
    "Prompt",
  ]);
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("--api-key [REDACTED]");
  expect(result.stdout).not.toContain(secret);
  expect(result.stderr).not.toContain(secret);
});

test("foreground headless run preserves argv, cwd, stdout, and exit status without selecting a profile", () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const result = runCli(
    ["run", "claude", "--profile", "acct", "--skip-configs", "--headless", "--", "Run prompt"],
    { cwd: launchCwd, env: { FAKE_CLAUDE_EXIT: "19" } },
  );

  expect(result.status).toBe(19);
  expect(result.stdout).toContain("fake-claude-stdout");
  expect(result.stderr).toContain("fake-claude-stderr");
  expect(entries()[0]).toMatchObject({
    args: ["-p", "Run prompt"],
    cwd: launchCwd,
    supervisor: "1",
  });
  expect(entries()[0]?.active).toBeUndefined();
  expect(storeCurrent()).toEqual({});
});

test("fake Claude background smoke captures session metadata and supports status and stop", async () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const started = runCli(
    [
      "launch",
      "acct",
      "--tool",
      "claude",
      "--skip-configs",
      "--background",
      "--name",
      "worker-one",
      "--json",
      "--",
      "Background prompt",
    ],
    { cwd: launchCwd, env: { FAKE_CLAUDE_SLEEP_MS: "10000" } },
  );
  expect(started.status).toBe(0);
  const state = JSON.parse(started.stdout) as {
    mode: string;
    name: string;
    sessionId: string;
    cwd: string;
    status: string;
    command: string[];
  };
  expect(state).toMatchObject({
    mode: "background",
    name: "worker-one",
    cwd: launchCwd,
    status: "running",
  });
  expect(state.sessionId).toMatch(/^[0-9a-f-]{36}$/);
  expect(state.command).toEqual(["claude", "--session-id", state.sessionId, "Background prompt"]);

  const launched = await waitFor(() => entries()[0]);
  expect(launched).toMatchObject({
    args: ["--session-id", state.sessionId, "Background prompt"],
    cwd: launchCwd,
    supervisor: "1",
  });
  expect(launched.active).toBeUndefined();
  expect(storeCurrent()).toEqual({});

  const status = runCli(["supervisor", "status", "claude", "--json"]);
  expect(status.status).toBe(0);
  expect(JSON.parse(status.stdout)[0]).toMatchObject({
    mode: "background",
    name: "worker-one",
    sessionId: state.sessionId,
    cwd: launchCwd,
    status: "running",
  });

  const stop = runCli(["supervisor", "stop", "claude"]);
  expect(stop.status).toBe(0);
  await waitFor(() => {
    const result = runCli(["supervisor", "status", "claude", "--json"]);
    const current = JSON.parse(result.stdout)[0] as { status?: string } | undefined;
    return current?.status === "exited" ? current : undefined;
  });
  const clear = runCli(["supervisor", "stop", "claude"]);
  expect(clear.status).toBe(0);
  expect(clear.stdout).toContain("cleared completed");
});

test("background run preserves the name and records a completed child exit code", async () => {
  expect(runCli(["add", "acct", "--tool", "claude"]).status).toBe(0);
  const started = runCli(
    [
      "run",
      "claude",
      "--profile",
      "acct",
      "--skip-configs",
      "--bg",
      "--name",
      "run-worker",
      "--json",
      "--",
      "Run in background",
    ],
    { cwd: launchCwd, env: { FAKE_CLAUDE_EXIT: "17" } },
  );
  expect(started.status).toBe(0);
  const state = JSON.parse(started.stdout) as { sessionId: string; name: string };
  expect(state.name).toBe("run-worker");

  const completed = await waitFor(() => {
    const result = runCli(["supervisor", "status", "claude", "--json"]);
    const current = JSON.parse(result.stdout)[0] as { status?: string; exitCode?: number; sessionId?: string } | undefined;
    return current?.status === "exited" ? current : undefined;
  });
  expect(completed).toMatchObject({ exitCode: 17, sessionId: state.sessionId });
  expect(entries()[0]).toMatchObject({
    args: ["--session-id", state.sessionId, "Run in background"],
    cwd: launchCwd,
    supervisor: "1",
  });
  expect(entries()[0]?.active).toBeUndefined();
  expect(storeCurrent()).toEqual({});

  const clear = runCli(["supervisor", "stop", "claude"]);
  expect(clear.status).toBe(0);
  expect(clear.stdout).toContain("cleared completed");
});
