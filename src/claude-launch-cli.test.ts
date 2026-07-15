import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import {
  planClaudeLaunch,
  prepareWindowsBatchCommand,
  redactArgv,
  redactText,
} from "./lib/claude-launch.js";
import { getTool } from "./lib/tools.js";
import { AccountsError } from "./types.js";

const repo = process.cwd();
const cli = join(repo, "src", "cli.ts");
const claude = getTool("claude");
let home: string;
let binDir: string;
let launchCwd: string;
let claudeLog: string;
let securityLog: string;
let keychainState: string;
let keychainLock: string;
let securityBin: string;

beforeAll(() => {
  binDir = mkdtempSync(join(tmpdir(), "accounts-claude-bin-"));
  securityBin = writeExecutable("security", fakeSecuritySource());
  writeExecutable("claude", fakeClaudeSource());
});

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-claude-cli-"));
  launchCwd = mkdtempSync(join(tmpdir(), "accounts-claude-cwd-"));
  claudeLog = join(home, "fake-claude.jsonl");
  securityLog = join(home, "fake-security.jsonl");
  keychainState = join(home, "fake-keychain.json");
  keychainLock = join(home, "keychain.lock");
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(launchCwd, { recursive: true, force: true });
});

afterAll(() => {
  rmSync(binDir, { recursive: true, force: true });
});

function writeExecutable(name: string, source: string): string {
  const script = join(binDir, `fake-${name}.ts`);
  writeFileSync(script, source);
  if (process.platform === "win32") {
    const executable = join(binDir, `${name}.exe`);
    const built = spawnSync(process.execPath, ["build", "--compile", script, "--outfile", executable], {
      encoding: "utf8",
    });
    if (built.status !== 0) throw new Error(`failed to compile fake ${name}: ${built.stderr}`);
    return executable;
  }
  const wrapper = join(binDir, name);
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" run "${script}" "$@"\n`);
  chmodSync(wrapper, 0o755);
  return wrapper;
}

function fakeClaudeSource(): string {
  return `
import { appendFileSync, existsSync, readFileSync } from "node:fs";
const args = process.argv.slice(2);
const background = args.includes("--bg");
if (process.env.FAKE_REQUIRE_BG === "1" && !background) {
  console.error("native --bg required");
  process.exit(64);
}
if (background && (args.includes("-p") || args.includes("--print"))) {
  console.error("background and print conflict");
  process.exit(64);
}
const nameIndex = args.findIndex((value) => value === "--name" || value === "-n");
if (process.env.FAKE_REQUIRE_NAME === "1" && (nameIndex < 0 || !args[nameIndex + 1])) {
  console.error("native --name required");
  process.exit(64);
}
if (process.env.FAKE_CRASH === "1") process.exit(Number(process.env.FAKE_EXIT ?? 17));
let keychainAccount;
if (process.env.FAKE_KEYCHAIN_STATE && existsSync(process.env.FAKE_KEYCHAIN_STATE)) {
  keychainAccount = JSON.parse(readFileSync(process.env.FAKE_KEYCHAIN_STATE, "utf8")).account;
}
appendFileSync(process.env.FAKE_CLAUDE_LOG, JSON.stringify({
  args,
  cwd: process.cwd(),
  configDir: process.env.CLAUDE_CONFIG_DIR,
  active: process.env.ACCOUNTS_ACTIVE,
  supervisor: process.env.ACCOUNTS_SUPERVISOR,
  keychainAccount,
}) + "\\n");
if (process.env.FAKE_STDOUT !== "0") console.log("fake-claude-stdout");
if (process.env.FAKE_STDERR !== "0") console.error("fake-claude-stderr");
if (process.env.FAKE_IGNORE_TERM === "1") process.on("SIGTERM", () => {});
const delay = Number(process.env.FAKE_SLEEP_MS ?? 0);
if (delay > 0) await Bun.sleep(delay);
process.exit(Number(process.env.FAKE_EXIT ?? 0));
`;
}

function fakeSecuritySource(): string {
  return `
import { appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const command = args[0];
const statePath = process.env.FAKE_KEYCHAIN_STATE;
const logPath = process.env.FAKE_SECURITY_LOG;
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : undefined;
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
};
if (command === "find-generic-password") {
  if (process.env.FAKE_SECURITY_FIND_ERROR === "1") process.exit(1);
  if (!state) process.exit(44);
  appendFileSync(logPath, JSON.stringify({ operation: "find", account: state.account }) + "\\n");
  if (args.includes("-w")) process.stdout.write(state.secret + "\\n");
  else process.stdout.write('"acct"<blob>="' + state.account + '"\\n');
  process.exit(0);
}
if (command === "delete-generic-password") {
  if (process.env.FAKE_SECURITY_DELETE_ERROR === "1") process.exit(1);
  appendFileSync(logPath, JSON.stringify({ operation: "delete", account: valueAfter("-a") }) + "\\n");
  if (!state) process.exit(44);
  rmSync(statePath, { force: true });
  process.exit(0);
}
if (command === "add-generic-password") {
  const account = valueAfter("-a");
  const secret = valueAfter("-w");
  if (!account || !secret) process.exit(64);
  appendFileSync(logPath, JSON.stringify({ operation: "add", account }) + "\\n");
  const delay = Number(process.env.FAKE_SECURITY_ADD_SLEEP_MS ?? 0);
  if (delay > 0) await Bun.sleep(delay);
  writeFileSync(statePath, JSON.stringify({ account, secret }), { mode: 0o600 });
  process.exit(0);
}
process.exit(64);
`;
}

function baseEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "test",
    ACCOUNTS_HOME: home,
    HASNA_ACCOUNTS_STORAGE_MODE: "local",
    HASNA_ACCOUNTS_API_URL: "",
    HASNA_ACCOUNTS_API_KEY: "",
    FAKE_CLAUDE_LOG: claudeLog,
    FAKE_SECURITY_LOG: securityLog,
    FAKE_KEYCHAIN_STATE: keychainState,
    ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH: keychainLock,
    ...extra,
  };
  const inheritedPath = Object.entries(process.env)
    .find(([key]) => key.toLowerCase() === "path")?.[1] ?? "";
  const requestedPath = extra.PATH ?? `${binDir}${delimiter}${inheritedPath}`;
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === "path") delete env[key];
  }
  env[process.platform === "win32" ? "Path" : "PATH"] = requestedPath;
  return env;
}

function runCli(args: string[], options: { cwd?: string; env?: Record<string, string> } = {}) {
  return spawnSync(process.execPath, ["run", cli, ...args], {
    cwd: options.cwd ?? repo,
    encoding: "utf8",
    env: baseEnv(options.env),
  });
}

function windowsNodeExecutable(): string {
  const located = spawnSync("where.exe", ["node"], { encoding: "utf8" });
  const executable = located.stdout.split(/\r?\n/).find(Boolean);
  if (located.status !== 0 || !executable) {
    throw new Error(`failed to locate node.exe: ${located.stderr}`);
  }
  return executable;
}

function runBuiltNodeCli(args: string[], options: { cwd?: string; env?: Record<string, string> } = {}) {
  return spawnSync(windowsNodeExecutable(), [join(repo, "dist", "cli.js"), ...args], {
    cwd: options.cwd ?? repo,
    encoding: "utf8",
    env: baseEnv(options.env),
  });
}

function expectStatus(
  result: ReturnType<typeof runCli>,
  expected: number,
): void {
  if (result.status !== expected) {
    throw new Error(
      `expected status ${expected}, received ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
}

function spawnCli(args: string[], env: Record<string, string> = {}): ChildProcess {
  return spawn(process.execPath, ["run", cli, ...args], {
    cwd: launchCwd,
    env: baseEnv(env),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function collect(child: ChildProcess): Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk) => { stdout += chunk; });
  child.stderr?.on("data", (chunk) => { stderr += chunk; });
  return await new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function entries<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as T);
}

function claudeEntries(): Array<{
  args: string[];
  cwd: string;
  configDir: string;
  active?: string;
  supervisor?: string;
  keychainAccount?: string;
}> {
  return entries(claudeLog);
}

function storeCurrent(): Record<string, string> {
  if (!existsSync(join(home, "accounts.json"))) return {};
  return JSON.parse(readFileSync(join(home, "accounts.json"), "utf8")).current ?? {};
}

function profileDir(name: string): string {
  return join(home, "profiles", "claude", name);
}

function addProfile(name: string, credential?: string): void {
  expect(runCli(["add", name, "--tool", "claude"]).status).toBe(0);
  if (credential) writeFileSync(join(profileDir(name), ".credentials.json"), credential, { mode: 0o600 });
}

function setKeychain(account: string, secret: string): void {
  writeFileSync(keychainState, JSON.stringify({ account, secret }), { mode: 0o600 });
}

function readKeychain(): { account: string; secret: string } | undefined {
  return existsSync(keychainState) ? JSON.parse(readFileSync(keychainState, "utf8")) : undefined;
}

async function waitFor(read: () => boolean, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (read()) return;
    await Bun.sleep(20);
  }
  throw new Error("timed out waiting for fake process");
}

describe("Claude launch planning", () => {
  const valid: Array<{
    label: string;
    args: string[];
    options?: Parameters<typeof planClaudeLaunch>[2];
    mode: "interactive" | "headless" | "background";
    expected: string[];
  }> = [
    { label: "interactive passthrough", args: ["Prompt"], mode: "interactive", expected: ["Prompt"] },
    { label: "headless convenience", args: ["Prompt"], options: { headless: true }, mode: "headless", expected: ["-p", "Prompt"] },
    { label: "raw print", args: ["--print", "--output-format", "json", "Prompt"], mode: "headless", expected: ["--print", "--output-format", "json", "Prompt"] },
    { label: "print continue is native", args: ["-p", "-c", "Prompt"], mode: "headless", expected: ["-p", "-c", "Prompt"] },
    { label: "background convenience", args: ["Prompt"], options: { bg: true, name: "worker" }, mode: "background", expected: ["--bg", "--name", "worker", "Prompt"] },
    { label: "raw bg plus convenience name", args: ["--bg", "Prompt"], options: { name: "worker" }, mode: "background", expected: ["--bg", "--name", "worker", "Prompt"] },
    { label: "background convenience plus raw name", args: ["-n", "worker", "Prompt"], options: { background: true }, mode: "background", expected: ["--bg", "-n", "worker", "Prompt"] },
    { label: "raw background alias", args: ["--background", "Prompt"], mode: "background", expected: ["--background", "Prompt"] },
    { label: "explicit UUID remains exact", args: ["--session-id", "11111111-1111-4111-8111-111111111111", "Prompt"], mode: "interactive", expected: ["--session-id", "11111111-1111-4111-8111-111111111111", "Prompt"] },
  ];
  for (const row of valid) {
    test(row.label, () => {
      expect(planClaudeLaunch(claude, row.args, row.options)).toEqual({
        mode: row.mode,
        args: row.expected,
        nonInteractive: row.mode !== "interactive",
      });
    });
  }

  const invalid: Array<[string, string[], Parameters<typeof planClaudeLaunch>[2]]> = [
    ["convenience modes conflict", [], { headless: true, background: true }],
    ["convenience aliases duplicate", [], { background: true, bg: true }],
    ["raw bg and print conflict", ["--bg", "-p"], {}],
    ["raw background aliases duplicate", ["--bg", "--background"], {}],
    ["raw print aliases duplicate", ["-p", "--print"], {}],
    ["headless duplicates raw print", ["-p"], { headless: true }],
    ["headless conflicts raw bg", ["--bg"], { headless: true }],
    ["background conflicts raw print", ["-p"], { background: true }],
    ["background duplicates raw bg", ["--bg"], { background: true }],
    ["name sources duplicate", ["--name", "one"], { background: true, name: "two" }],
    ["raw names duplicate", ["--name", "one", "-ntwo"], {}],
    ["name lacks background", [], { name: "worker" }],
    ["missing raw name", ["--name", "--bg"], {}],
    ["session IDs duplicate", ["--session-id", "11111111-1111-4111-8111-111111111111", "--session-id=22222222-2222-4222-8222-222222222222"], {}],
    ["session ID invalid", ["--session-id", "not-a-uuid"], {}],
    ["boolean flag has value", ["--bg=yes"], {}],
  ];
  for (const [label, args, options] of invalid) {
    test(label, () => expect(() => planClaudeLaunch(claude, args, options)).toThrow(AccountsError));
  }

  for (const [label, name] of [
    ["empty", ""],
    ["leading whitespace", " worker"],
    ["trailing whitespace", "worker "],
    ["control", "work\ner"],
    ["format", "work\u200ber"],
    ["too long", "x".repeat(129)],
  ]) {
    test(`invalid name: ${label}`, () => {
      expect(() => planClaudeLaunch(claude, ["--bg"], { name })).toThrow(AccountsError);
    });
  }

  test("non-Claude convenience options reject without rewriting argv", () => {
    expect(planClaudeLaunch(getTool("codex"), ["Prompt"])).toEqual({
      mode: "interactive",
      args: ["Prompt"],
      nonInteractive: false,
    });
    expect(() => planClaudeLaunch(getTool("codex"), ["Prompt"], { headless: true })).toThrow(/only with --tool claude/);
  });
});

test("Windows batch commands escape shell metacharacters before serialization", () => {
  const command = prepareWindowsBatchCommand(
    "C:\\Tools & Stuff\\claude.cmd",
    ["plain", "space value", "x&whoami", "%PATH%", "caret^value", "quote\"value"],
    "C:\\Windows\\System32\\cmd.exe",
  );

  expect(command.command).toBe("C:\\Windows\\System32\\cmd.exe");
  expect(command.args.slice(0, 3)).toEqual(["/d", "/s", "/c"]);
  expect(command.args).toHaveLength(4);
  expect(command.windowsVerbatimArguments).toBe(true);
  expect(command.args[3]).not.toContain("x&whoami");
  expect(command.args[3]).not.toContain("%PATH%");
  expect(command.args[3]).not.toContain("C:\\Tools & Stuff\\claude.cmd");
  expect(() => prepareWindowsBatchCommand("claude.cmd", ["line\nbreak"], "cmd.exe"))
    .toThrow("Windows batch arguments cannot contain line breaks");
});

test("built Node CLI executes a real Windows cmd shim with exact argv", () => {
  if (process.platform !== "win32") return;
  addProfile("acct");
  const batchBin = mkdtempSync(join(tmpdir(), "accounts claude & cmd-"));
  const batchLog = join(home, "fake-cmd-claude.jsonl");
  const injectionMarker = join(home, "cmd-injection-marker");
  const script = join(batchBin, "fake-claude.mjs");
  const shim = join(batchBin, "claude.cmd");
  const hostileArgs = [
    "",
    "Prompt with spaces",
    `literal&echo injected>${injectionMarker}`,
    "%PATH%",
    "caret^value",
    "bang!value",
    "quote\"value",
    "trailing\\",
  ];

  try {
    writeFileSync(script, `
import { appendFileSync } from "node:fs";
appendFileSync(process.env.FAKE_CLAUDE_LOG, JSON.stringify({
  args: process.argv.slice(2),
  cwd: process.cwd(),
  relayEnv: process.env.CMD_RELAY_ENV,
}) + "\\n");
process.stdout.write("fake-cmd-stdout\\n");
process.stderr.write("fake-cmd-stderr\\n");
process.exit(29);
`);
    writeFileSync(shim, `@echo off\r\n"${windowsNodeExecutable()}" "${script}" %*\r\n`);
    const inheritedPath = Object.entries(process.env)
      .find(([key]) => key.toLowerCase() === "path")?.[1] ?? "";
    const result = runBuiltNodeCli(
      [
        "launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--",
        ...hostileArgs,
      ],
      {
        cwd: launchCwd,
        env: {
          PATH: `${batchBin}${delimiter}${inheritedPath}`,
          PATHEXT: ".CMD;.EXE",
          FAKE_CLAUDE_LOG: batchLog,
          CMD_RELAY_ENV: "preserved",
        },
      },
    );

    expectStatus(result, 29);
    expect(result.stdout).toBe("fake-cmd-stdout\n");
    expect(result.stderr).toContain("fake-cmd-stderr");
    expect(entries<{ args: string[]; cwd: string; relayEnv: string }>(batchLog)).toEqual([
      { args: ["-p", ...hostileArgs], cwd: launchCwd, relayEnv: "preserved" },
    ]);

    const rejected = runBuiltNodeCli(
      [
        "launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--",
        `line\r\necho injected>${injectionMarker}`,
      ],
      {
        cwd: launchCwd,
        env: {
          PATH: `${batchBin}${delimiter}${inheritedPath}`,
          PATHEXT: ".CMD;.EXE",
          FAKE_CLAUDE_LOG: batchLog,
        },
      },
    );
    expectStatus(rejected, 1);
    expect(rejected.stderr).toContain("Windows batch arguments cannot contain line breaks");
    expect(entries(batchLog)).toHaveLength(1);
    expect(existsSync(injectionMarker)).toBe(false);
  } finally {
    rmSync(batchBin, { recursive: true, force: true });
  }
});

test("headless launch keeps Claude stdout clean and returns its exit code", () => {
  addProfile("acct");
  const result = runCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--permissions", "dangerous", "--", "Prompt with spaces"],
    { cwd: launchCwd, env: { FAKE_EXIT: "23", ACCOUNTS_ACTIVE: "inherited" } },
  );
  expectStatus(result, 23);
  expect(result.stdout).toBe("fake-claude-stdout\n");
  expect(result.stderr).toContain("fake-claude-stderr");
  expect(result.stderr).toContain("claude --dangerously-skip-permissions -p Prompt with spaces");
  expect(claudeEntries()[0]).toMatchObject({
    args: ["--dangerously-skip-permissions", "-p", "Prompt with spaces"],
    cwd: launchCwd,
  });
  expect(claudeEntries()[0]?.active).toBeUndefined();
  expect(claudeEntries()[0]?.supervisor).toBeUndefined();
  expect(storeCurrent()).toEqual({});
});

test("background convenience relays exact native bg and name argv", () => {
  addProfile("acct");
  const result = runCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--background", "--name", "worker-one", "--", "Background prompt"],
    { cwd: launchCwd, env: { FAKE_REQUIRE_BG: "1", FAKE_REQUIRE_NAME: "1" } },
  );
  expectStatus(result, 0);
  expect(result.stdout).toBe("fake-claude-stdout\n");
  expect(claudeEntries()[0]).toMatchObject({
    args: ["--bg", "--name", "worker-one", "Background prompt"],
    cwd: launchCwd,
  });
  expect(storeCurrent()).toEqual({});
});

test("run headless and background bypass the Accounts supervisor", () => {
  addProfile("acct");
  const headless = runCli(["run", "claude", "--profile", "acct", "--skip-configs", "--headless", "--", "Run prompt"]);
  const background = runCli([
    "run", "claude", "--profile", "acct", "--skip-configs", "--bg", "--name", "run-worker", "--", "Run background",
  ], { env: { FAKE_REQUIRE_BG: "1", FAKE_REQUIRE_NAME: "1" } });
  expectStatus(headless, 0);
  expectStatus(background, 0);
  expect(claudeEntries().map((entry) => entry.args)).toEqual([
    ["-p", "Run prompt"],
    ["--bg", "--name", "run-worker", "Run background"],
  ]);
  expect(claudeEntries().every((entry) => entry.supervisor === undefined)).toBe(true);
  expect(storeCurrent()).toEqual({});
});

test("conflicts fail before prelaunch, keychain access, profile selection, or Claude", () => {
  addProfile("acct", "profile-credential-value");
  setKeychain("prior", "prior-credential-value");
  const result = runCli(
    ["launch", "acct", "--tool", "claude", "--headless", "--", "--bg", "Prompt"],
    {
      env: {
        ACCOUNTS_TEST_KEYCHAIN: "1",
        ACCOUNTS_TEST_SECURITY_BIN: securityBin,
      },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("cannot be combined");
  expect(claudeEntries()).toEqual([]);
  expect(entries(securityLog)).toEqual([]);
  expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
  expect(storeCurrent()).toEqual({});
});

test("only print mode accepts raw output-format json; Accounts has no json mode", () => {
  addProfile("acct");
  const supported = runCli([
    "launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "--output-format", "json", "Prompt",
  ]);
  expectStatus(supported, 0);
  expect(claudeEntries()[0]?.args).toEqual(["-p", "--output-format", "json", "Prompt"]);
  const unsupported = runCli(["launch", "acct", "--tool", "claude", "--skip-configs", "--json"]);
  expect(unsupported.status).toBe(1);
  expect(unsupported.stderr).toContain("unknown option");
});

test("diagnostic redaction stays on stderr", () => {
  addProfile("acct");
  const secret = "sk-ant-abcdefghijklmnopqrstuvwxyz";
  const result = runCli([
    "launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "--api-key", secret, "Prompt",
  ]);
  expectStatus(result, 0);
  expect(result.stdout).toBe("fake-claude-stdout\n");
  expect(result.stderr).toContain("--api-key [REDACTED]");
  expect(result.stderr).not.toContain(secret);
  expect(redactArgv(["claude", "--api-key", secret, `--token=${secret}`])).toEqual([
    "claude", "--api-key", "[REDACTED]", "--token=[REDACTED]",
  ]);
  expect(redactText(`failed ${secret}`)).toBe("failed [REDACTED]");
});

test("immediate crash and missing executable are returned as nonzero diagnostics", () => {
  addProfile("acct");
  const crash = runCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--bg", "--name", "crash-worker"],
    { env: { FAKE_CRASH: "1", FAKE_EXIT: "17", FAKE_REQUIRE_BG: "1", FAKE_REQUIRE_NAME: "1" } },
  );
  expect(crash.status).toBe(17);

  writeFileSync(join(profileDir("acct"), ".credentials.json"), "profile-credential-value", { mode: 0o600 });
  setKeychain("prior", "prior-credential-value");
  const emptyPath = mkdtempSync(join(tmpdir(), "accounts-missing-bin-"));
  try {
    const missing = runCli(
      ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
      {
        env: {
          PATH: emptyPath,
          ACCOUNTS_TEST_KEYCHAIN: "1",
          ACCOUNTS_TEST_SECURITY_BIN: securityBin,
        },
      },
    );
    expect(missing.status).toBe(1);
    expect(missing.stdout).toBe("");
    expect(missing.stderr).toContain("failed to launch claude");
    expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
    expect(existsSync(keychainLock)).toBe(false);
  } finally {
    rmSync(emptyPath, { recursive: true, force: true });
  }
});

test("two concurrent profiles serialize keychain use and restore inherited state", async () => {
  addProfile("alpha", "credential-alpha-value");
  addProfile("beta", "credential-beta-value");
  setKeychain("prior", "credential-prior-value");
  const env = {
    ACCOUNTS_TEST_KEYCHAIN: "1",
    ACCOUNTS_TEST_SECURITY_BIN: securityBin,
    FAKE_REQUIRE_BG: "1",
    FAKE_REQUIRE_NAME: "1",
    FAKE_SLEEP_MS: "150",
  };
  const alpha = collect(spawnCli([
    "launch", "alpha", "--tool", "claude", "--skip-configs", "--bg", "--name", "alpha-worker",
  ], env));
  const beta = collect(spawnCli([
    "launch", "beta", "--tool", "claude", "--skip-configs", "--bg", "--name", "beta-worker",
  ], env));
  const results = await Promise.all([alpha, beta]);
  expect(results.map((result) => result.code)).toEqual([0, 0]);

  const observed = new Map(claudeEntries().map((entry) => [entry.args[2], entry.keychainAccount]));
  expect(observed.get("alpha-worker")).toBe("alpha");
  expect(observed.get("beta-worker")).toBe("beta");
  expect(readKeychain()).toEqual({ account: "prior", secret: "credential-prior-value" });
  expect(existsSync(keychainLock)).toBe(false);
  const securityText = existsSync(securityLog) ? readFileSync(securityLog, "utf8") : "";
  expect(securityText).not.toContain("credential-alpha-value");
  expect(securityText).not.toContain("credential-beta-value");
  expect(securityText).not.toContain("credential-prior-value");
});

test("keychain lock timeout does not launch or alter inherited credentials", () => {
  addProfile("acct", "profile-credential-value");
  setKeychain("prior", "prior-credential-value");
  writeFileSync(keychainLock, `${process.pid}:held`, { mode: 0o600 });
  const result = runCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
    {
      env: {
        ACCOUNTS_TEST_KEYCHAIN: "1",
        ACCOUNTS_TEST_SECURITY_BIN: securityBin,
        ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS: "75",
      },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("timed out waiting for the Claude keychain lock");
  expect(claudeEntries()).toEqual([]);
  expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
});

test("keychain capture failure aborts before credential mutation or launch", () => {
  addProfile("acct", "profile-credential-value");
  setKeychain("prior", "prior-credential-value");
  const result = runCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
    {
      env: {
        ACCOUNTS_TEST_KEYCHAIN: "1",
        ACCOUNTS_TEST_SECURITY_BIN: securityBin,
        FAKE_SECURITY_FIND_ERROR: "1",
      },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("keychain read failed before Claude launch");
  expect(claudeEntries()).toEqual([]);
  expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
  expect(existsSync(keychainLock)).toBe(false);
});

test("SIGTERM is forwarded, returns nonzero, and restores the prior keychain", async () => {
  if (process.platform === "win32") return;
  addProfile("acct", "profile-credential-value");
  setKeychain("prior", "prior-credential-value");
  const child = spawnCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
    {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: securityBin,
      ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS: "100",
      FAKE_IGNORE_TERM: "1",
      FAKE_SLEEP_MS: "10000",
    },
  );
  const result = collect(child);
  await waitFor(() => claudeEntries().length === 1);
  child.kill("SIGTERM");
  const completed = await result;
  expect(completed.code).toBe(143);
  expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
  expect(existsSync(keychainLock)).toBe(false);
});

test("SIGTERM during keychain mutation still restores the prior credential", async () => {
  if (process.platform === "win32") return;
  addProfile("acct", "profile-credential-value");
  setKeychain("prior", "prior-credential-value");
  const child = spawnCli(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
    {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: securityBin,
      ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS: "100",
      FAKE_SECURITY_ADD_SLEEP_MS: "250",
      FAKE_IGNORE_TERM: "1",
      FAKE_SLEEP_MS: "10000",
    },
  );
  const result = collect(child);
  await waitFor(() => entries(securityLog).some((entry) => entry.operation === "add" && entry.account === "acct"));
  child.kill("SIGTERM");
  const completed = await result;
  expect(completed.code).toBe(143);
  expect(readKeychain()).toEqual({ account: "prior", secret: "prior-credential-value" });
  expect(existsSync(keychainLock)).toBe(false);
});
