import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;
let binDir: string;
let logPath: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-login-cli-"));
  binDir = mkdtempSync(join(tmpdir(), "accounts-login-bin-"));
  logPath = join(home, "fake-login.log");
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
});

interface RunOptions {
  input?: string;
  env?: Record<string, string | undefined>;
  path?: string;
}

function cliEnv(opts: RunOptions = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_ENV: "test",
    HOME: home,
    ACCOUNTS_HOME: home,
    HASNA_ACCOUNTS_STORAGE_MODE: "local",
    HASNA_ACCOUNTS_API_URL: "",
    HASNA_ACCOUNTS_API_KEY: "",
    FAKE_LOGIN_LOG: logPath,
    PATH: opts.path ?? `${binDir}:${process.env.PATH ?? ""}`,
    ...opts.env,
  };
}

function runCliWith(args: string[], opts: RunOptions = {}) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    input: opts.input,
    env: cliEnv(opts),
  });
}

function spawnCliWith(args: string[], opts: RunOptions = {}): ChildProcess {
  return spawn(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    env: cliEnv(opts),
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

async function waitFor(read: () => boolean, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (read()) return;
    await Bun.sleep(20);
  }
  throw new Error("timed out waiting for fake login process");
}

function runCli(...args: string[]) {
  return runCliWith(args);
}

function writeFakeTool(binName: string, envVar: string, toolName = binName, exitCode = 0) {
  const fakeBin = join(binDir, binName);
  writeFileSync(
    fakeBin,
    [
      "#!/bin/sh",
      `home="\${${envVar}:-}"`,
      `printf '{"tool":"${toolName}","args":"%s","home":"%s"}\\n' "$*" "$home" >> "$FAKE_LOGIN_LOG"`,
      `exit ${exitCode}`,
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);
}

function writeSignalledFakeTool(binName: string, envVar: string, toolName = binName) {
  const fakeBin = join(binDir, binName);
  writeFileSync(
    fakeBin,
    [
      "#!/bin/sh",
      `home="\${${envVar}:-}"`,
      `printf '{"tool":"${toolName}","args":"%s","home":"%s"}\\n' "$*" "$home" >> "$FAKE_LOGIN_LOG"`,
      "kill -TERM $$",
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);
}

function writeFinalizationSignalTool(binName: string, envVar: string, toolName = binName) {
  const fakeBin = join(binDir, binName);
  writeFileSync(
    fakeBin,
    [
      "#!/bin/sh",
      `home="\${${envVar}:-}"`,
      `printf '{"tool":"${toolName}","args":"%s","home":"%s"}\\n' "$*" "$home" >> "$FAKE_LOGIN_LOG"`,
      'printf completed > "$FAKE_LOGIN_COMPLETED"',
      "exit 0",
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);
}

function writeBlockingFakeTool(binName: string, envVar: string, toolName = binName) {
  const script = join(binDir, `${binName}-blocking.ts`);
  const fakeBin = join(binDir, binName);
  writeFileSync(
    script,
    `
import { appendFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_LOGIN_LOG, JSON.stringify({
  tool: ${JSON.stringify(toolName)},
  args: args.join(" "),
  home: process.env[${JSON.stringify(envVar)}] ?? "",
}) + "\\n");
if (args.length === 0) {
  writeFileSync(process.env.FAKE_LOGIN_READY, "ready");
  const handleSignal = (signal, code) => {
    if (process.env.FAKE_LOGIN_SIGNAL_LOG) appendFileSync(process.env.FAKE_LOGIN_SIGNAL_LOG, signal + "\\n");
    if (process.env.FAKE_LOGIN_IGNORE_SIGNALS !== "1") process.exit(code);
  };
  process.on("SIGINT", () => handleSignal("SIGINT", 130));
  process.on("SIGTERM", () => handleSignal("SIGTERM", 143));
  await new Promise(() => {});
}
process.exit(0);
`,
  );
  writeFileSync(fakeBin, `#!/bin/sh\nexec "${process.execPath}" run "${script}" "$@"\n`);
  chmodSync(fakeBin, 0o755);
}

function writeFakeConfigs() {
  const fakeBin = join(binDir, "configs");
  writeFileSync(
    fakeBin,
    [
      "#!/bin/sh",
      'printf \'%s\\n\' "$*" >> "$FAKE_CONFIGS_LOG"',
      'mode="${2:-}"',
      'tool=""',
      'profile=""',
      'target=""',
      'while [ "$#" -gt 0 ]; do',
      '  case "$1" in',
      '    --tool) shift; tool="${1:-}" ;;',
      '    --profile) shift; profile="${1:-}" ;;',
      '    --target-home) shift; target="${1:-}" ;;',
      '  esac',
      '  shift || true',
      'done',
      'if [ "$mode" = "apply" ] && [ -n "$target" ]; then',
      '  mkdir -p "$target/.hasna"',
      '  printf \'{"schema":"hasna.configs.session-render/v1","tool":"%s","profile":"%s","targetHome":"%s","generatedAt":"2026-07-01T00:00:00.000Z","sources":[{"id":"global-codewith"}],"files":[]}\\n\' "$tool" "$profile" "$target" > "$target/.hasna/session-render-manifest.json"',
      'fi',
      "exit 0",
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);
}

function writeFakeSecurity() {
  const fakeSecurity = join(binDir, "fake-security");
  writeFileSync(
    fakeSecurity,
    [
      "#!/usr/bin/env bash",
      `printf '%s\\n' "$*" >> "$FAKE_SECURITY_LOG"`,
      `if [ "\${1:-}" = "delete-generic-password" ]; then exit 1; fi`,
      `if [ "\${1:-}" = "add-generic-password" ]; then`,
      `  account=""`,
      `  secret=""`,
      `  while [ "$#" -gt 0 ]; do`,
      `    case "$1" in`,
      `      -a) shift; account="\${1:-}" ;;`,
      `      -w) shift; secret="\${1:-}" ;;`,
      `    esac`,
      `    shift || true`,
      `  done`,
      `  printf 'account=%s\\n' "$account" >> "$FAKE_SECURITY_PAYLOAD"`,
      `  printf 'secret=%s\\n' "$secret" >> "$FAKE_SECURITY_PAYLOAD"`,
      `  exit 0`,
      `fi`,
      `exit 0`,
    ].join("\n"),
  );
  chmodSync(fakeSecurity, 0o755);
  return fakeSecurity;
}

function writeStatefulFakeSecurity() {
  const script = join(binDir, "stateful-security.ts");
  const fakeSecurity = join(binDir, "stateful-security");
  writeFileSync(
    script,
    `
import { appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
const command = args[0];
const statePath = process.env.FAKE_KEYCHAIN_STATE;
const logPath = process.env.FAKE_SECURITY_LOG;
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : undefined;
if (
  process.env.FAKE_LOGIN_COMPLETED &&
  existsSync(process.env.FAKE_LOGIN_COMPLETED) &&
  process.env.FAKE_FINALIZE_SIGNAL_SENT &&
  !existsSync(process.env.FAKE_FINALIZE_SIGNAL_SENT)
) {
  writeFileSync(process.env.FAKE_FINALIZE_SIGNAL_SENT, "sent");
  process.kill(process.ppid, "SIGINT");
}
const delay = Number(process.env.FAKE_SECURITY_DELAY_MS ?? 0);
if (delay > 0) await Bun.sleep(delay);
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
};
if (command === "find-generic-password") {
  if (!state) process.exit(44);
  appendFileSync(logPath, JSON.stringify({ operation: "find", account: state.account }) + "\\n");
  if (args.includes("-w")) process.stdout.write(state.secret + "\\n");
  else process.stdout.write('"acct"<blob>="' + state.account + '"\\n');
  process.exit(0);
}
if (command === "delete-generic-password") {
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
  writeFileSync(statePath, JSON.stringify({ account, secret }), { mode: 0o600 });
  process.exit(0);
}
process.exit(64);
`,
  );
  writeFileSync(fakeSecurity, `#!/bin/sh\nexec "${process.execPath}" run "${script}" "$@"\n`);
  chmodSync(fakeSecurity, 0o755);
  return fakeSecurity;
}

function writeClaudeAuth(profileDir: string, email: string) {
  writeFileSync(join(profileDir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }));
  writeFileSync(
    join(profileDir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        accessToken: `${email}-access-token`,
        refreshToken: `${email}-refresh-token`,
        expiresAt: Date.now() + 60_000,
      },
    }),
  );
}

function addFakeLoginTool(id = "fake-login", label = "Fake Login", envVar = "FAKE_LOGIN_HOME", bin = "fake-login-tool") {
  expect(
    runCli(
      "tools",
      "add",
      id,
      "--label",
      label,
      "--env-var",
      envVar,
      "--bin",
      bin,
      "--login-arg",
      "auth",
      "login",
    ).status,
  ).toBe(0);
}

function readLogEntries() {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { tool: string; args: string; home: string });
}

function readStore() {
  return JSON.parse(readFileSync(join(home, "accounts.json"), "utf8")) as {
    current?: Record<string, string>;
    applied?: Record<string, string>;
    toolLocks?: Record<string, string>;
    profiles?: Array<{ name: string; tool: string; dir: string; email?: string }>;
  };
}

function setupClaudeLogin(exit: "success" | "nonzero" | "signal") {
  if (exit === "signal") writeSignalledFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  else writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", exit === "nonzero" ? 23 : 0);
  const fakeSecurity = writeStatefulFakeSecurity();
  const securityLog = join(home, "stateful-security.log");
  const keychainState = join(home, "stateful-keychain.json");
  const keychainLock = join(home, "keychain.lock");
  expect(runCli("add", "prior", "--tool", "claude").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  expect(runCli("use", "prior", "--tool", "claude").status).toBe(0);
  const profile = readStore().profiles?.find((entry) => entry.name === "acct" && entry.tool === "claude");
  expect(profile).toBeTruthy();
  writeClaudeAuth(profile!.dir, "acct@example.com");
  writeFileSync(keychainState, JSON.stringify({ account: "prior", secret: "prior-secret" }), { mode: 0o600 });
  return {
    env: {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: fakeSecurity,
      FAKE_SECURITY_LOG: securityLog,
      FAKE_KEYCHAIN_STATE: keychainState,
      ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH: keychainLock,
    },
    keychainState,
    keychainLock,
    securityLog,
  };
}

function expectNoProfileState(name: string, tool: string) {
  expect(existsSync(join(home, "profiles", tool, name))).toBe(false);
  if (!existsSync(join(home, "accounts.json"))) return;
  const store = readStore();
  expect(store.profiles?.some((profile) => profile.name === name && profile.tool === tool)).toBe(false);
  expect(store.toolLocks?.[name]).toBeUndefined();
}

test("login forwards documented and native-compatible Claude dangerous permissions", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);

  const documented = runCli("login", "acct", "--tool", "claude", "--permissions", "dangerous");
  const compatible = runCli("login", "acct", "--tool", "claude", "--dangerously-skip-permissions");

  expect(documented.status).toBe(23);
  expect(compatible.status).toBe(23);
  expect(readLogEntries().map((entry) => entry.args)).toEqual([
    "--dangerously-skip-permissions",
    "--dangerously-skip-permissions",
  ]);
});

test("login rejects unsupported and duplicate permission inputs before launching the tool", () => {
  writeFakeTool("opencode", "OPENCODE_CONFIG_DIR", "opencode");
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  expect(runCli("add", "open", "--tool", "opencode").status).toBe(0);
  expect(runCli("add", "claude", "--tool", "claude").status).toBe(0);

  const unsupported = runCli("login", "open", "--tool", "opencode", "--permissions", "dangerous");
  const duplicate = runCli(
    "login",
    "claude",
    "--tool",
    "claude",
    "--permissions",
    "dangerous",
    "--dangerously-skip-permissions",
  );

  expect(unsupported.status).toBe(1);
  expect(unsupported.stderr).toContain('tool "opencode" does not support permissions "dangerous"');
  expect(duplicate.status).toBe(1);
  expect(duplicate.stderr).toContain("cannot be combined");
  expect(readLogEntries()).toEqual([]);
});

for (const duplicate of [
  {
    label: "same-value repeated --permissions",
    args: ["--permissions", "dangerous", "--permissions=dangerous"],
  },
  {
    label: "conflicting repeated --permissions",
    args: ["--permissions", "none", "--permissions", "dangerous"],
  },
]) {
  test(`login rejects ${duplicate.label} before profile, keychain, or spawn mutation`, () => {
    const fixture = setupClaudeLogin("nonzero");
    const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");
    const keychainBefore = readFileSync(fixture.keychainState, "utf8");

    const result = runCliWith(["login", "acct", "--tool", "claude", ...duplicate.args], {
      env: fixture.env,
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--permissions may be supplied only once");
    expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
    expect(readFileSync(fixture.keychainState, "utf8")).toBe(keychainBefore);
    expect(existsSync(fixture.securityLog)).toBe(false);
    expect(readLogEntries()).toEqual([]);
  });
}

test("nonzero Claude login restores the prior active profile and keychain without finalizing", () => {
  const fixture = setupClaudeLogin("nonzero");
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");

  const result = runCliWith(["login", "acct", "--tool", "claude", "--permissions", "dangerous"], {
    env: fixture.env,
  });

  expect(result.status).toBe(23);
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(readStore().current?.claude).toBe("prior");
  expect(readStore().applied?.claude).toBeUndefined();
  expect(readStore().toolLocks?.acct).toBeUndefined();
  expect(readStore().profiles?.find((profile) => profile.name === "acct")?.email).toBeUndefined();
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(readLogEntries()).toHaveLength(1);
});

test("signalled Claude login returns nonzero and restores active profile and keychain without finalizing", () => {
  const fixture = setupClaudeLogin("signal");
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");

  const result = runCliWith(["login", "acct", "--tool", "claude"], { env: fixture.env });

  expect(result.status).toBe(143);
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(readStore().current?.claude).toBe("prior");
  expect(readStore().applied?.claude).toBeUndefined();
  expect(readStore().toolLocks?.acct).toBeUndefined();
  expect(readStore().profiles?.find((profile) => profile.name === "acct")?.email).toBeUndefined();
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(readLogEntries()).toHaveLength(1);
});

test("repeated parent SIGINT rolls back while holding the shared Claude keychain lease", async () => {
  const fixture = setupClaudeLogin("success");
  const ready = join(home, "blocking-login.ready");
  const signalLog = join(home, "blocking-login.signals");
  writeBlockingFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");
  const child = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      FAKE_LOGIN_READY: ready,
      FAKE_LOGIN_SIGNAL_LOG: signalLog,
      FAKE_LOGIN_IGNORE_SIGNALS: "1",
      ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS: "100",
    },
  });
  const resultPromise = collect(child);

  await waitFor(() => existsSync(ready));
  expect(existsSync(fixture.keychainLock)).toBe(true);
  const securityBeforeBlockedLaunch = readFileSync(fixture.securityLog, "utf8");
  const blockedLaunch = runCliWith(
    ["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "Prompt"],
    {
      env: {
        ...fixture.env,
        ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS: "75",
      },
    },
  );
  expect(blockedLaunch.status).toBe(1);
  expect(blockedLaunch.stderr).toContain("timed out waiting for the Claude keychain lock");
  expect(readFileSync(fixture.securityLog, "utf8")).toBe(securityBeforeBlockedLaunch);
  expect(readLogEntries()).toHaveLength(1);

  child.kill("SIGINT");
  await waitFor(() => existsSync(signalLog));
  child.kill("SIGINT");
  const result = await resultPromise;
  expect(result.code).toBe(130);
  expect(result.signal).toBeNull();
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(existsSync(fixture.keychainLock)).toBe(false);
  expect(readFileSync(signalLog, "utf8")).toContain("SIGINT");
});

test("SIGINT during finalization restores live auth, applied state, profile metadata, and keychain", () => {
  const fixture = setupClaudeLogin("success");
  const liveBase = join(home, "live-claude");
  const liveConfig = join(liveBase, ".claude");
  const loginCompleted = join(home, "login-completed");
  const signalSent = join(home, "finalization-signal.sent");
  mkdirSync(liveConfig, { recursive: true });
  const liveHomeJson = join(liveBase, ".claude.json");
  const liveCredentials = join(liveConfig, ".credentials.json");
  const liveSettings = join(liveConfig, "settings.json");
  writeFileSync(liveHomeJson, '{"oauthAccount":{"emailAddress":"prior@example.com"}}\n', { mode: 0o600 });
  writeFileSync(liveCredentials, '{"claudeAiOauth":{"refreshToken":"prior-live"}}\n', { mode: 0o600 });
  writeFileSync(liveSettings, '{"apiKeyHelper":"keep-me","theme":"dark"}\n', { mode: 0o600 });
  const store = readStore();
  store.applied = { ...(store.applied ?? {}), claude: "prior" };
  writeFileSync(join(home, "accounts.json"), JSON.stringify({ version: 1, tools: [], ...store }, null, 2) + "\n");
  const storeBefore = readStore();
  writeFinalizationSignalTool("claude", "CLAUDE_CONFIG_DIR", "claude");

  const result = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LIVE_DIR: liveBase,
      FAKE_SECURITY_DELAY_MS: "40",
      FAKE_LOGIN_COMPLETED: loginCompleted,
      FAKE_FINALIZE_SIGNAL_SENT: signalSent,
    },
  });

  expect(result.status).toBe(130);
  expect(existsSync(signalSent)).toBe(true);
  expect(result.stdout).not.toContain("live/default Claude Code account");
  expect(readStore()).toEqual(storeBefore);
  expect(readFileSync(liveHomeJson, "utf8")).toBe('{"oauthAccount":{"emailAddress":"prior@example.com"}}\n');
  expect(readFileSync(liveCredentials, "utf8")).toBe('{"claudeAiOauth":{"refreshToken":"prior-live"}}\n');
  expect(readFileSync(liveSettings, "utf8")).toBe('{"apiKeyHelper":"keep-me","theme":"dark"}\n');
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(existsSync(fixture.keychainLock)).toBe(false);
});

test("zero exit without completed auth rolls back failed finalization", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  const fakeSecurity = writeStatefulFakeSecurity();
  const securityLog = join(home, "finalize-security.log");
  const keychainState = join(home, "finalize-keychain.json");
  const keychainLock = join(home, "finalize-keychain.lock");
  writeFileSync(keychainState, JSON.stringify({ account: "prior", secret: "prior-secret" }), { mode: 0o600 });

  const result = runCliWith(["login", "unfinished", "--tool", "claude"], {
    env: {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: fakeSecurity,
      FAKE_SECURITY_LOG: securityLog,
      FAKE_KEYCHAIN_STATE: keychainState,
      ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH: keychainLock,
    },
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain('profile "unfinished" has no auth to apply');
  expectNoProfileState("unfinished", "claude");
  expect(JSON.parse(readFileSync(keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(existsSync(keychainLock)).toBe(false);
  expect(readLogEntries()).toHaveLength(1);
});

test("failed Claude login restores an initially empty keychain", () => {
  const fixture = setupClaudeLogin("nonzero");
  rmSync(fixture.keychainState, { force: true });

  const result = runCliWith(["login", "acct", "--tool", "claude"], { env: fixture.env });

  expect(result.status).toBe(23);
  expect(existsSync(fixture.keychainState)).toBe(false);
  expect(readStore().current?.claude).toBe("prior");
});

test("failed login restores a pre-existing tool lock for the same profile name", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  expect(runCli("add", "shared", "--tool", "codex").status).toBe(0);
  expect(runCli("add", "shared", "--tool", "claude").status).toBe(0);
  expect(runCli("use", "shared", "--tool", "codex").status).toBe(0);
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");

  const result = runCli("login", "shared", "--tool", "claude");

  expect(result.status).toBe(23);
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(readStore().toolLocks?.shared).toBe("codex");
  expect(readStore().current?.codex).toBe("shared");
  expect(readStore().current?.claude).toBeUndefined();
});

test("failed new login removes its profile but preserves a pre-existing managed directory", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  const profileDir = join(home, "profiles", "claude", "preexisting-dir");
  const sentinel = join(profileDir, "keep.txt");
  mkdirSync(profileDir, { recursive: true });
  writeFileSync(sentinel, "keep");

  const result = runCli("login", "preexisting-dir", "--tool", "claude");

  expect(result.status).toBe(23);
  expect(readStore().profiles?.some((profile) => profile.name === "preexisting-dir" && profile.tool === "claude")).toBe(false);
  expect(readStore().toolLocks?.["preexisting-dir"]).toBeUndefined();
  expect(readFileSync(sentinel, "utf8")).toBe("keep");
});

test("successful Claude login still finalizes, applies, and keeps the profile keychain", () => {
  const fixture = setupClaudeLogin("success");

  const result = runCliWith(["login", "acct", "--tool", "claude", "--permissions", "dangerous"], {
    env: fixture.env,
  });

  expect(result.status).toBe(0);
  expect(result.stdout).toContain("acct is now the live/default Claude Code account");
  expect(readStore().current?.claude).toBe("acct");
  expect(readStore().applied?.claude).toBe("acct");
  expect(readStore().profiles?.find((profile) => profile.name === "acct")?.email).toBe("acct@example.com");
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8")).account).toBe("acct");
  expect(readLogEntries().map((entry) => entry.args)).toEqual(["--dangerously-skip-permissions"]);
});

test("duplicate permissions for a nonexistent login do not create profile state", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");

  const result = runCli(
    "login",
    "new-duplicate",
    "--tool",
    "claude",
    "--permissions",
    "dangerous",
    "--dangerously-skip-permissions",
  );

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("cannot be combined");
  expectNoProfileState("new-duplicate", "claude");
  expect(readLogEntries()).toEqual([]);
});

test("unsupported permissions for an interactively selected new login do not create profile state", () => {
  writeFakeTool("opencode", "OPENCODE_CONFIG_DIR", "opencode");

  const result = runCliWith(["login", "new-unsupported", "--permissions", "dangerous"], {
    input: "opencode\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain('tool "opencode" does not support permissions "dangerous"');
  expectNoProfileState("new-unsupported", "opencode");
  expect(readLogEntries()).toEqual([]);
});

test("valid permissions survive interactive tool selection for a new login", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);

  const result = runCliWith(["login", "new-valid", "--permissions", "dangerous"], {
    input: "claude\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(23);
  expect(readLogEntries().map((entry) => entry.args)).toEqual(["--dangerously-skip-permissions"]);
  expectNoProfileState("new-valid", "claude");
});

test("launch syncs Claude profile credentials into keychain before spawning", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  const fakeSecurity = writeFakeSecurity();
  const securityLog = join(home, "fake-security.log");
  const securityPayload = join(home, "fake-security-payload.log");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const profile = readStore().profiles?.find((entry) => entry.name === "acct" && entry.tool === "claude");
  expect(profile).toBeTruthy();
  writeClaudeAuth(profile!.dir, "acct@example.com");

  const result = runCliWith(["launch", "acct", "--tool", "claude", "--skip-configs", "--", "--version"], {
    env: {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: fakeSecurity,
      FAKE_SECURITY_LOG: securityLog,
      FAKE_SECURITY_PAYLOAD: securityPayload,
    },
  });

  expect(result.status).toBe(0);
  expect(readLogEntries()[0]?.tool).toBe("claude");
  const keychainLog = readFileSync(securityLog, "utf8");
  const keychainPayload = readFileSync(securityPayload, "utf8");
  expect(keychainLog).toContain("add-generic-password");
  expect(keychainPayload).toContain("account=acct");
  expect(keychainPayload).toContain("acct@example.com-access-token");
});

test("launch runs configs apply by default before spawning", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  writeFakeConfigs();
  const configsLog = join(home, "fake-configs.log");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const profile = readStore().profiles?.find((entry) => entry.name === "acct" && entry.tool === "claude");
  expect(profile).toBeTruthy();

  const result = runCliWith(["launch", "acct", "--tool", "claude", "--", "--version"], {
    env: { FAKE_CONFIGS_LOG: configsLog },
  });

  expect(result.status).toBe(0);
  const configsCall = readFileSync(configsLog, "utf8");
  expect(configsCall).toContain("session apply --tool claude --profile acct");
  expect(configsCall).toContain(`--target-home ${profile!.dir}`);
  expect(readLogEntries()[0]?.tool).toBe("claude");
});

test("switch --launch runs configs apply by default before spawning", () => {
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude");
  writeFakeConfigs();
  const configsLog = join(home, "fake-configs.log");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const profile = readStore().profiles?.find((entry) => entry.name === "acct" && entry.tool === "claude");
  expect(profile).toBeTruthy();

  const result = runCliWith(["switch", "acct", "--tool", "claude", "--mode", "active", "--launch", "--", "--version"], {
    env: { FAKE_CONFIGS_LOG: configsLog },
  });

  expect(result.status).toBe(0);
  const configsCall = readFileSync(configsLog, "utf8");
  expect(configsCall).toContain("session apply --tool claude --profile acct");
  expect(configsCall).toContain(`--target-home ${profile!.dir}`);
  expect(readLogEntries()[0]?.tool).toBe("claude");
});

test("env syncs Claude profile credentials into keychain before printing exports", () => {
  const fakeSecurity = writeFakeSecurity();
  const securityLog = join(home, "fake-security.log");
  const securityPayload = join(home, "fake-security-payload.log");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const profile = readStore().profiles?.find((entry) => entry.name === "acct" && entry.tool === "claude");
  expect(profile).toBeTruthy();
  writeClaudeAuth(profile!.dir, "acct@example.com");

  const result = runCliWith(["env", "acct", "--tool", "claude"], {
    env: {
      ACCOUNTS_TEST_KEYCHAIN: "1",
      ACCOUNTS_TEST_SECURITY_BIN: fakeSecurity,
      FAKE_SECURITY_LOG: securityLog,
      FAKE_SECURITY_PAYLOAD: securityPayload,
    },
  });

  expect(result.status).toBe(0);
  expect(result.stdout).toContain("export CLAUDE_CONFIG_DIR=");
  const keychainLog = readFileSync(securityLog, "utf8");
  const keychainPayload = readFileSync(securityPayload, "utf8");
  expect(keychainLog).toContain("add-generic-password");
  expect(keychainPayload).toContain("account=acct");
  expect(keychainPayload).toContain("acct@example.com-access-token");
});

test("login infers and locks the tool for an existing unambiguous profile", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);

  const result = runCli("login", "acct");

  expect(result.status).toBe(0);
  const entries = readLogEntries();
  expect(entries).toHaveLength(1);
  expect(entries[0]?.args).toBe("auth login");
  expect(entries[0]?.home).toContain("fake-login/acct");
  expect(readStore().toolLocks?.acct).toBe("fake-login");
});

test("login requires an explicit choice for shared profile names when non-interactive and unlocked", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  writeFakeTool("fake-variant-tool", "FAKE_VARIANT_HOME", "fake-variant");
  addFakeLoginTool("fake-login", "Fake Login", "FAKE_LOGIN_HOME", "fake-login-tool");
  addFakeLoginTool("fake-variant", "Fake Variant", "FAKE_VARIANT_HOME", "fake-variant-tool");
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "fake-variant").status).toBe(0);

  const result = runCli("login", "acct");

  expect(result.status).toBe(1);
  expect(result.stderr).toContain('profile "acct" is not locked to a tool');
  expect(result.stderr).toContain("accounts login acct --tool fake-login");
  expect(result.stderr).toContain("accounts login acct --tool fake-variant");
  expect(readLogEntries()).toHaveLength(0);
});

test("login chooser creates a new account with a custom registered tool variant and persists the lock", () => {
  writeFakeTool("fake-variant-tool", "FAKE_VARIANT_HOME", "fake-variant");
  addFakeLoginTool("fake-variant", "Fake Variant", "FAKE_VARIANT_HOME", "fake-variant-tool");

  const result = runCliWith(["login", "acct"], {
    input: "fake-variant\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
  });

  expect(result.status).toBe(0);
  expect(result.stderr).toContain('Choose a tool for profile "acct"');
  expect(result.stderr).toContain("Fake Variant (fake-variant) - available");
  const entries = readLogEntries();
  expect(entries).toHaveLength(1);
  expect(entries[0]?.tool).toBe("fake-variant");
  expect(entries[0]?.args).toBe("auth login");
  expect(entries[0]?.home).toContain("fake-variant/acct");
  expect(readStore().toolLocks?.acct).toBe("fake-variant");

  const show = runCli("show", "acct");
  expect(show.status).toBe(0);
  expect(show.stdout).toContain("tool:       fake-variant");
});

test("login chooser marks unavailable tools and prefers installed tools", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();

  const result = runCliWith(["login", "acct"], {
    input: "q\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("1. Fake Login (fake-login) - available");
  expect(result.stderr).toContain("Cursor Agent (cursor) - requires install");
  expect(readLogEntries()).toHaveLength(0);
});

test("non-interactive login for a new account does not prompt or create partial state", () => {
  const result = runCliWith(["login", "acct"], { path: binDir });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain('profile "acct" is not locked to a tool');
  expect(readLogEntries()).toHaveLength(0);
  expect(existsSync(join(home, "accounts.json"))).toBe(false);
});

test("explicit cursor login with missing Cursor install fails with accounts-level guidance", () => {
  writeFakeTool("cursor-agent", "CURSOR_CONFIG_DIR", "cursor");

  const result = runCliWith(["login", "acct", "--tool", "cursor"], { path: binDir });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Cursor Agent is selected for profile "acct"');
  expect(result.stderr).toContain("Cursor IDE installation was not found");
  expect(result.stderr).toContain("https://cursor.com/download");
  expect(result.stderr).toContain("Profile dir if kept selected:");
  expect(result.stderr).not.toContain("No Cursor IDE installation found");
  expect(existsSync(join(home, "accounts.json"))).toBe(false);
});

test("missing explicit cursor install can choose another installed tool and re-lock", () => {
  writeFakeTool("cursor-agent", "CURSOR_CONFIG_DIR", "cursor");
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();

  const result = runCliWith(["login", "acct", "--tool", "cursor"], {
    input: "1\nfake-login\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(0);
  expect(result.stderr).toContain("Choose another tool");
  const entries = readLogEntries();
  expect(entries).toHaveLength(1);
  expect(entries[0]?.tool).toBe("fake-login");
  expect(readStore().toolLocks?.acct).toBe("fake-login");
});

test("missing explicit cursor install can keep cursor selected without launching it", () => {
  writeFakeTool("cursor-agent", "CURSOR_CONFIG_DIR", "cursor");

  const result = runCliWith(["login", "acct", "--tool", "cursor"], {
    input: "2\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("Selected tool kept: cursor");
  expect(readLogEntries()).toHaveLength(0);
  const store = readStore();
  expect(store.toolLocks?.acct).toBe("cursor");
  expect(store.profiles?.some((profile) => profile.name === "acct" && profile.tool === "cursor")).toBe(true);
});

test("cancelling an inferred missing existing profile does not write a tool lock", () => {
  expect(
    runCli(
      "tools",
      "add",
      "missing-review",
      "--label",
      "Missing Review",
      "--env-var",
      "MISSING_REVIEW_HOME",
      "--bin",
      "missing-review-bin",
    ).status,
  ).toBe(0);
  expect(runCli("add", "acct", "--tool", "missing-review").status).toBe(0);

  const result = runCliWith(["login", "acct"], {
    input: "3\n",
    env: { ACCOUNTS_FORCE_INTERACTIVE: "1" },
    path: binDir,
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("Cancel without changes");
  expect(readStore().toolLocks?.acct).toBeUndefined();
});
