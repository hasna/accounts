import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { deserialize, serialize } from "node:v8";

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

function recoveryHookFile(
  directory: string,
  role: string,
  stage: string,
  suffix: "ready" | "release",
  journalId = "batch",
): string {
  return join(directory, `${role}.${stage}.${journalId}.${suffix}`);
}

function releaseRecoveryHook(
  directory: string,
  role: string,
  stage: string,
  journalId = "batch",
): void {
  writeFileSync(recoveryHookFile(directory, role, stage, "release", journalId), "release");
}

async function waitForRecoveryHook(
  directory: string,
  role: string,
  stage: string,
  journalId = "batch",
): Promise<void> {
  await waitFor(
    () => existsSync(recoveryHookFile(directory, role, stage, "ready", journalId)),
    12_000,
  );
}

function recoveryJournalIds(): string[] {
  const directory = join(home, "login-finalization-journals");
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith(".bin"))
    .map((name) => name.slice(0, -4))
    .sort();
}

function recoveryLeaseIds(): string[] {
  const directory = join(home, "login-finalization-journals");
  if (!existsSync(directory)) return [];
  return readdirSync(directory)
    .filter((name) => name.endsWith(".lease"))
    .map((name) => name.slice(0, -6))
    .sort();
}

function readRecoveryLease(id: string): {
  profileDir: string;
  profileLockToken: string;
} {
  return deserialize(
    readFileSync(join(home, "login-finalization-journals", `${id}.lease`)),
  );
}

function recoveryProfileLockPath(profileDir: string): string {
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  const identity = createHash("sha256")
    .update(resolve(profileDir))
    .digest("hex")
    .slice(0, 32);
  return join(
    process.platform === "win32" ? tmpdir() : "/tmp",
    `accounts-claude-login-${uid}-${identity}.lock`,
  );
}

function readRecoveryJournal(id: string): {
  ownerPid: number;
  finalizationState: {
    writes: {
      keychainLockToken?: string;
      applyLockToken?: string;
    };
  };
} {
  return deserialize(
    readFileSync(join(home, "login-finalization-journals", `${id}.bin`)),
  );
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

function writeRawAuthMutatingFailureTool(
  binName: string,
  envVar: string,
  exit: "nonzero" | "signal",
) {
  const fakeBin = join(binDir, binName);
  writeFileSync(
    fakeBin,
    [
      "#!/bin/sh",
      `profile_dir="\${${envVar}:-}"`,
      'printf \'{"oauthAccount":{"emailAddress":"partial@example.com"},"concurrentPreference":"keep"}\\n\' > "$profile_dir/.claude.json"',
      'printf \'{"claudeAiOauth":{"refreshToken":"partial-refresh"},"concurrentPreference":"keep"}\\n\' > "$profile_dir/.credentials.json"',
      exit === "signal" ? "kill -TERM $$" : "exit 23",
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);
}

function writeBlockingRawAuthMutatingFailureTool(
  binName: string,
  envVar: string,
  exit: "nonzero" | "signal",
) {
  const script = join(binDir, `${binName}-auth-race.ts`);
  const fakeBin = join(binDir, binName);
  writeFileSync(
    script,
    `
import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const profileDir = process.env[${JSON.stringify(envVar)}];
if (!profileDir) throw new Error("missing profile directory");
const loginId = process.env.FAKE_LOGIN_ID;
if (process.env.FAKE_LOGIN_EVENTS && loginId) appendFileSync(process.env.FAKE_LOGIN_EVENTS, loginId + ":start\\n");
if (process.env.FAKE_LOGIN_MUTATE) {
  writeFileSync(process.env.FAKE_LOGIN_STARTED, "started");
  while (!existsSync(process.env.FAKE_LOGIN_MUTATE)) await Bun.sleep(10);
}
writeFileSync(
  join(profileDir, ".claude.json"),
  JSON.stringify({ oauthAccount: { emailAddress: loginId ? loginId + "@example.com" : "rotated@example.com" }, laterProcessPreference: "keep" }) + "\\n",
  { mode: 0o600 },
);
writeFileSync(
  join(profileDir, ".credentials.json"),
  JSON.stringify({
    claudeAiOauth: {
      accessToken: loginId ? loginId + "-access-token" : "rotated-access-token",
      refreshToken: loginId ? loginId + "-refresh-token" : "rotated-refresh-token",
      expiresAt: Date.now() + 60_000,
    },
    laterProcessPreference: "keep",
  }) + "\\n",
  { mode: 0o600 },
);
writeFileSync(process.env.FAKE_LOGIN_READY, "ready");
while (!existsSync(process.env.FAKE_LOGIN_RELEASE)) await Bun.sleep(10);
if (process.env.FAKE_LOGIN_EVENTS && loginId) appendFileSync(process.env.FAKE_LOGIN_EVENTS, loginId + ":exit\\n");
if (process.env.FAKE_LOGIN_EXIT === "success") process.exit(0);
${exit === "signal" ? 'process.kill(process.pid, "SIGTERM");' : "process.exit(23);"}
await new Promise(() => {});
`,
  );
  writeFileSync(fakeBin, `#!/bin/sh\nexec "${process.execPath}" run "${script}" "$@"\n`);
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
      'if [ "${FAKE_LOGIN_MUTATE_LIVE:-}" = "1" ]; then',
      '  mkdir -p "$ACCOUNTS_TEST_LIVE_DIR/.claude"',
      '  printf \'{"oauthAccount":{"emailAddress":"child@example.com"}}\\n\' > "$ACCOUNTS_TEST_LIVE_DIR/.claude.json"',
      '  printf \'{"claudeAiOauth":{"refreshToken":"child-live"}}\\n\' > "$ACCOUNTS_TEST_LIVE_DIR/.claude/.credentials.json"',
      '  printf \'{"theme":"child"}\\n\' > "$ACCOUNTS_TEST_LIVE_DIR/.claude/settings.json"',
      "fi",
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
  if (
    process.env.FAKE_SECURITY_FAIL_ADD_CONTAINS &&
    secret.includes(process.env.FAKE_SECURITY_FAIL_ADD_CONTAINS)
  ) process.exit(23);
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
    currentRevisions?: Record<string, string>;
    applied?: Record<string, string>;
    appliedRevisions?: Record<string, string>;
    profileAuthRevisions?: Record<string, string>;
    profileAuthCommitRevisions?: Record<string, string>;
    profileAuthIncarnations?: Record<string, string>;
    toolLocks?: Record<string, string>;
    toolLockRevisions?: Record<string, string>;
    loginOperations?: Record<string, unknown>;
    profiles?: Array<{ name: string; tool: string; dir: string; createdAt: string; email?: string }>;
  };
}

function expectOnlyStableAuthTrackingAdded(beforeText: string, profileKey: string): void {
  const before = JSON.parse(beforeText) as ReturnType<typeof readStore>;
  const after = readStore();
  expect({
    ...after,
    profileAuthRevisions: before.profileAuthRevisions,
    profileAuthCommitRevisions: before.profileAuthCommitRevisions,
    profileAuthIncarnations: before.profileAuthIncarnations,
  }).toEqual(before);
  expect(after.profileAuthRevisions?.[profileKey]).toMatch(/^[0-9a-f-]{36}$/i);
  expect(after.profileAuthCommitRevisions?.[profileKey]).toMatch(/^[0-9a-f-]{36}$/i);
  expect(after.profileAuthIncarnations?.[profileKey]).toMatch(/^[0-9a-f]{64}$/i);
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
  {
    label: "repeated direct Claude compatibility flags",
    args: ["--dangerously-skip-permissions", "--dangerously-skip-permissions"],
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
  expectOnlyStableAuthTrackingAdded(storeBefore, "claude/acct");
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
  expectOnlyStableAuthTrackingAdded(storeBefore, "claude/acct");
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

for (const failure of [
  { label: "failed", exit: "nonzero" as const, status: 23 },
  { label: "signalled", exit: "signal" as const, status: 143 },
]) {
  test(`${failure.label} existing-profile login restores raw auth while preserving unrelated fields`, () => {
    const fixture = setupClaudeLogin(failure.exit);
    writeRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", failure.exit);
    const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
    if (!target) throw new Error("missing existing Claude profile fixture");
    writeFileSync(
      join(target.dir, ".claude.json"),
      '{"oauthAccount":{"emailAddress":"before@example.com"},"stablePreference":"before"}\n',
      { mode: 0o600 },
    );
    writeFileSync(
      join(target.dir, ".credentials.json"),
      '{"claudeAiOauth":{"refreshToken":"before-refresh"}}\n',
      { mode: 0o600 },
    );

    const result = runCliWith(["login", "acct", "--tool", "claude"], { env: fixture.env });

    expect(result.status).toBe(failure.status);
    expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toEqual({
      oauthAccount: { emailAddress: "before@example.com" },
      stablePreference: "before",
      concurrentPreference: "keep",
    });
    expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toEqual({
      claudeAiOauth: { refreshToken: "before-refresh" },
      concurrentPreference: "keep",
    });
  });
}

for (const failure of [
  { label: "nonzero", exit: "nonzero" as const, status: 23 },
  { label: "signalled", exit: "signal" as const, status: 143 },
]) {
  test(`${failure.label} login does not restore stale auth over a later same-profile apply`, async () => {
    const ready = join(home, `${failure.label}-auth-race.ready`);
    const release = join(home, `${failure.label}-auth-race.release`);
    writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", failure.exit);
    expect(runCli("add", "prior", "--tool", "claude").status).toBe(0);
    expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
    expect(runCli("use", "prior", "--tool", "claude").status).toBe(0);
    const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
    if (!target) throw new Error("missing existing Claude profile fixture");
    writeFileSync(
      join(target.dir, ".claude.json"),
      '{"oauthAccount":{"emailAddress":"before@example.com"},"stablePreference":"before"}\n',
      { mode: 0o600 },
    );
    writeFileSync(
      join(target.dir, ".credentials.json"),
      '{"claudeAiOauth":{"refreshToken":"before-refresh"}}\n',
      { mode: 0o600 },
    );

    const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
      env: {
        FAKE_LOGIN_READY: ready,
        FAKE_LOGIN_RELEASE: release,
      },
    });
    const loginResult = collect(login);
    await waitFor(() => existsSync(ready));

    const apply = runCli("apply", "acct", "--tool", "claude");
    expect(apply.status).toBe(0);
    expect(readStore().current?.claude).toBe("acct");
    expect(readStore().applied?.claude).toBe("acct");
    const laterHome = readFileSync(join(target.dir, ".claude.json"), "utf8");
    const laterCredentials = readFileSync(join(target.dir, ".credentials.json"), "utf8");
    const laterStore = readStore();

    writeFileSync(release, "release");
    const result = await loginResult;

    expect(result.code).toBe(failure.status);
    expect(result.signal).toBeNull();
    expect(readStore().current?.claude).toBe("acct");
    expect(readStore().applied?.claude).toBe("acct");
    expect(readStore().currentRevisions?.claude).toBe(laterStore.currentRevisions?.claude);
    expect(readStore().appliedRevisions?.claude).toBe(laterStore.appliedRevisions?.claude);
    expect(readStore().toolLocks?.acct).toBe("claude");
    expect(readStore().toolLockRevisions?.acct).toBe(laterStore.toolLockRevisions?.acct);
    expect(readStore().profileAuthRevisions?.["claude/acct"]).toBe(
      laterStore.profileAuthRevisions?.["claude/acct"],
    );
    expect(readStore().profileAuthCommitRevisions?.["claude/acct"]).toBe(
      laterStore.profileAuthCommitRevisions?.["claude/acct"],
    );
    expect(readStore().profileAuthIncarnations?.["claude/acct"]).toBe(
      laterStore.profileAuthIncarnations?.["claude/acct"],
    );
    expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toEqual(JSON.parse(laterHome));
    expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toEqual(JSON.parse(laterCredentials));
    expect(JSON.parse(laterHome)).toEqual({
      oauthAccount: { emailAddress: "rotated@example.com" },
      laterProcessPreference: "keep",
    });
    expect(JSON.parse(laterCredentials)).toMatchObject({
      claudeAiOauth: {
        accessToken: "rotated-access-token",
        refreshToken: "rotated-refresh-token",
      },
      laterProcessPreference: "keep",
    });
  });
}

for (const failure of [
  { label: "nonzero", exit: "nonzero" as const, status: 23 },
  { label: "signalled", exit: "signal" as const, status: 143 },
]) {
  test(`${failure.label} login restores auth owned by an apply that completed before the child mutation`, async () => {
    const started = join(home, `${failure.label}-pre-mutation.started`);
    const mutate = join(home, `${failure.label}-pre-mutation.mutate`);
    const ready = join(home, `${failure.label}-pre-mutation.ready`);
    const release = join(home, `${failure.label}-pre-mutation.release`);
    writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", failure.exit);
    expect(runCli("add", "prior", "--tool", "claude").status).toBe(0);
    expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
    expect(runCli("use", "prior", "--tool", "claude").status).toBe(0);
    const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
    if (!target) throw new Error("missing existing Claude profile fixture");
    writeFileSync(
      join(target.dir, ".claude.json"),
      '{"oauthAccount":{"emailAddress":"apply-owned@example.com"},"stablePreference":"before"}\n',
      { mode: 0o600 },
    );
    writeFileSync(
      join(target.dir, ".credentials.json"),
      '{"claudeAiOauth":{"refreshToken":"apply-owned-refresh"}}\n',
      { mode: 0o600 },
    );

    const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
      env: {
        FAKE_LOGIN_STARTED: started,
        FAKE_LOGIN_MUTATE: mutate,
        FAKE_LOGIN_READY: ready,
        FAKE_LOGIN_RELEASE: release,
      },
    });
    const loginResult = collect(login);
    await waitFor(() => existsSync(started));

    const apply = runCli("apply", "acct", "--tool", "claude");
    expect(apply.status).toBe(0);
    writeFileSync(mutate, "mutate");
    await waitFor(() => existsSync(ready));
    writeFileSync(release, "release");
    const result = await loginResult;

    expect(result.code).toBe(failure.status);
    expect(result.signal).toBeNull();
    expect(readStore().current?.claude).toBe("acct");
    expect(readStore().applied?.claude).toBe("acct");
    expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toEqual({
      oauthAccount: { emailAddress: "apply-owned@example.com" },
      stablePreference: "before",
      laterProcessPreference: "keep",
    });
    expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toEqual({
      claudeAiOauth: { refreshToken: "apply-owned-refresh" },
      laterProcessPreference: "keep",
    });
  });
}

test("failed login does not restore stale auth after the profile is removed and recreated", async () => {
  const ready = join(home, "recreated-auth.ready");
  const release = join(home, "recreated-auth.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing original Claude profile fixture");
  writeClaudeAuth(original.dir, "before@example.com");

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_READY: ready,
      FAKE_LOGIN_RELEASE: release,
    },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(ready));

  expect(runCli("remove", "acct", "--tool", "claude").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const recreated = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!recreated) throw new Error("missing recreated Claude profile fixture");
  writeFileSync(
    join(recreated.dir, ".claude.json"),
    '{"oauthAccount":{"emailAddress":"recreated@example.com"},"recreatedPreference":"keep"}\n',
    { mode: 0o600 },
  );
  writeFileSync(
    join(recreated.dir, ".credentials.json"),
    '{"claudeAiOauth":{"refreshToken":"recreated-refresh"},"recreatedPreference":"keep"}\n',
    { mode: 0o600 },
  );

  writeFileSync(release, "release");
  const result = await loginResult;

  expect(result.code).toBe(23);
  expect(JSON.parse(readFileSync(join(recreated.dir, ".claude.json"), "utf8"))).toEqual({
    oauthAccount: { emailAddress: "recreated@example.com" },
    recreatedPreference: "keep",
  });
  expect(JSON.parse(readFileSync(join(recreated.dir, ".credentials.json"), "utf8"))).toEqual({
    claudeAiOauth: { refreshToken: "recreated-refresh" },
    recreatedPreference: "keep",
  });
});

test("same-timestamp profile reincarnation fails closed without restoring old auth", async () => {
  const ready = join(home, "same-timestamp-recreated-auth.ready");
  const release = join(home, "same-timestamp-recreated-auth.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing original same-timestamp profile fixture");
  writeClaudeAuth(original.dir, "before@example.com");

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: { FAKE_LOGIN_READY: ready, FAKE_LOGIN_RELEASE: release },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(ready));

  expect(runCli("remove", "acct", "--tool", "claude").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const registry = readStore();
  const recreated = registry.profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!recreated) throw new Error("missing recreated same-timestamp profile fixture");
  // Force the strongest possible incarnation-digest collision: same tool,
  // managed directory, and timestamp. The independent auth identity must
  // still prevent the old login from owning this new profile.
  recreated.createdAt = original.createdAt;
  writeFileSync(join(home, "accounts.json"), JSON.stringify(registry, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(
    join(recreated.dir, ".claude.json"),
    '{"oauthAccount":{"emailAddress":"recreated@example.com"},"recreatedPreference":"keep"}\n',
    { mode: 0o600 },
  );
  writeFileSync(
    join(recreated.dir, ".credentials.json"),
    '{"claudeAiOauth":{"refreshToken":"recreated-refresh"},"recreatedPreference":"keep"}\n',
    { mode: 0o600 },
  );

  writeFileSync(release, "release");
  const result = await loginResult;

  expect(result.code).toBe(1);
  expect(result.stderr).toMatch(/missing Claude profile auth identity/);
  expect(JSON.parse(readFileSync(join(recreated.dir, ".claude.json"), "utf8"))).toEqual({
    oauthAccount: { emailAddress: "recreated@example.com" },
    recreatedPreference: "keep",
  });
  expect(JSON.parse(readFileSync(join(recreated.dir, ".credentials.json"), "utf8"))).toEqual({
    claudeAiOauth: { refreshToken: "recreated-refresh" },
    recreatedPreference: "keep",
  });
});

test("overlapping failed logins keep their shared committed auth baseline", async () => {
  const readyA = join(home, "overlap-a.ready");
  const releaseA = join(home, "overlap-a.release");
  const readyB = join(home, "overlap-b.ready");
  const releaseB = join(home, "overlap-b.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!target) throw new Error("missing overlapping login profile fixture");
  writeFileSync(
    join(target.dir, ".claude.json"),
    '{"oauthAccount":{"emailAddress":"baseline@example.com"},"stablePreference":"before"}\n',
    { mode: 0o600 },
  );
  writeFileSync(
    join(target.dir, ".credentials.json"),
    '{"claudeAiOauth":{"refreshToken":"baseline-refresh"}}\n',
    { mode: 0o600 },
  );

  const loginA = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: { FAKE_LOGIN_READY: readyA, FAKE_LOGIN_RELEASE: releaseA },
  });
  const resultA = collect(loginA);
  await waitFor(() => existsSync(readyA));
  const loginB = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: { FAKE_LOGIN_READY: readyB, FAKE_LOGIN_RELEASE: releaseB },
  });
  const resultB = collect(loginB);
  await Bun.sleep(200);
  expect(existsSync(readyB)).toBe(false);

  writeFileSync(releaseA, "release");
  expect((await resultA).code).toBe(23);
  await waitFor(() => existsSync(readyB));
  // The second child is still live and may write again after A rolls back.
  writeFileSync(
    join(target.dir, ".claude.json"),
    '{"oauthAccount":{"emailAddress":"second-child@example.com"},"overlapPreference":"keep"}\n',
    { mode: 0o600 },
  );
  writeFileSync(
    join(target.dir, ".credentials.json"),
    '{"claudeAiOauth":{"refreshToken":"second-child-refresh"},"overlapPreference":"keep"}\n',
    { mode: 0o600 },
  );
  writeFileSync(releaseB, "release");
  expect((await resultB).code).toBe(23);

  expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toEqual({
    oauthAccount: { emailAddress: "baseline@example.com" },
    stablePreference: "before",
    overlapPreference: "keep",
  });
  expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toEqual({
    claudeAiOauth: { refreshToken: "baseline-refresh" },
    overlapPreference: "keep",
  });
  expect(readStore().profileAuthRevisions?.["claude/acct"]).toBeTruthy();
  expect(readStore().profileAuthCommitRevisions?.["claude/acct"]).toBeTruthy();
  expect(readStore().profileAuthIncarnations?.["claude/acct"]).toBeTruthy();
});

test("same-profile login children are serialized without blocking a later apply", async () => {
  const readyA = join(home, "serialized-a.ready");
  const releaseA = join(home, "serialized-a.release");
  const readyB = join(home, "serialized-b.ready");
  const releaseB = join(home, "serialized-b.release");
  const events = join(home, "serialized-login-events");
  const tmpA = join(home, "tmp-a");
  const tmpB = join(home, "tmp-b");
  mkdirSync(tmpA, { recursive: true });
  mkdirSync(tmpB, { recursive: true });
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);

  const loginA = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_ID: "a",
      FAKE_LOGIN_EVENTS: events,
      FAKE_LOGIN_READY: readyA,
      FAKE_LOGIN_RELEASE: releaseA,
      TMPDIR: tmpA,
    },
  });
  const resultA = collect(loginA);
  await waitFor(() => existsSync(readyA));
  const loginB = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_ID: "b",
      FAKE_LOGIN_EXIT: "success",
      FAKE_LOGIN_EVENTS: events,
      FAKE_LOGIN_READY: readyB,
      FAKE_LOGIN_RELEASE: releaseB,
      TMPDIR: tmpB,
    },
  });
  const resultB = collect(loginB);
  await Bun.sleep(800);
  expect(existsSync(readyB)).toBe(false);
  writeFileSync(releaseA, "release");
  expect((await resultA).code).toBe(23);
  await waitFor(() => existsSync(readyB));
  writeFileSync(releaseB, "release");
  expect((await resultB).code).toBe(0);

  const order = readFileSync(events, "utf8").trim().split("\n");
  expect(order.indexOf("a:exit")).toBeLessThan(order.indexOf("b:start"));
  const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!target) throw new Error("missing serialized login profile fixture");
  expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toMatchObject({
    oauthAccount: { emailAddress: "b@example.com" },
  });
  expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toMatchObject({
    claudeAiOauth: { accessToken: "b-access-token", refreshToken: "b-refresh-token" },
  });
});

test("a login waiting on the profile lease never crosses a remove and recreate", async () => {
  const readyA = join(home, "recreate-lease-a.ready");
  const releaseA = join(home, "recreate-lease-a.release");
  const readyB = join(home, "recreate-lease-b.ready");
  const releaseB = join(home, "recreate-lease-b.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);

  const loginA = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_ID: "a",
      FAKE_LOGIN_READY: readyA,
      FAKE_LOGIN_RELEASE: releaseA,
    },
  });
  const resultA = collect(loginA);
  await waitFor(() => existsSync(readyA));

  const loginB = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_ID: "b",
      FAKE_LOGIN_READY: readyB,
      FAKE_LOGIN_RELEASE: releaseB,
    },
  });
  const resultB = collect(loginB);
  await Bun.sleep(300);
  expect(existsSync(readyB)).toBe(false);

  expect(runCli("remove", "acct", "--tool", "claude").status).toBe(0);
  await Bun.sleep(20);
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  writeFileSync(releaseA, "release");
  expect((await resultA).code).toBe(23);

  await waitFor(() => existsSync(readyB) || loginB.exitCode !== null);
  if (existsSync(readyB)) writeFileSync(releaseB, "release");
  const failed = await resultB;
  expect(failed.code).toBe(1);
  expect(failed.stderr).toMatch(/profile changed before Claude auth capture/);
  expect(existsSync(readyB)).toBe(false);
});

test("SIGTERM rollback waits beyond the old five-second apply window", async () => {
  const ready = join(home, "long-apply-wait.ready");
  const release = join(home, "long-apply-wait.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const target = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!target) throw new Error("missing long apply wait profile fixture");
  writeClaudeAuth(target.dir, "before-long-apply@example.com");

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: { FAKE_LOGIN_READY: ready, FAKE_LOGIN_RELEASE: release },
  });
  const resultPromise = collect(login);
  await waitFor(() => existsSync(ready));
  const applyLock = join(home, ".apply.lock");
  writeFileSync(applyLock, "99999\n", { mode: 0o600 });
  const releaseLock = setTimeout(() => rmSync(applyLock, { force: true }), 5_200);
  login.kill("SIGTERM");
  const result = await resultPromise;
  clearTimeout(releaseLock);
  rmSync(applyLock, { force: true });

  expect(result.code).toBe(143);
  expect(result.stderr).not.toMatch(/timed out waiting for the accounts apply lock/);
  expect(JSON.parse(readFileSync(join(target.dir, ".claude.json"), "utf8"))).toMatchObject({
    oauthAccount: { emailAddress: "before-long-apply@example.com" },
    laterProcessPreference: "keep",
  });
  expect(JSON.parse(readFileSync(join(target.dir, ".credentials.json"), "utf8"))).toMatchObject({
    claudeAiOauth: { refreshToken: "before-long-apply@example.com-refresh-token" },
    laterProcessPreference: "keep",
  });
}, 8_000);

test("failed login follows a concurrent profile rename without restoring a stale identity", async () => {
  const ready = join(home, "renamed-auth.ready");
  const release = join(home, "renamed-auth.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing original Claude profile fixture");
  writeFileSync(
    join(original.dir, ".claude.json"),
    '{"oauthAccount":{"emailAddress":"before-rename@example.com"},"stablePreference":"before"}\n',
    { mode: 0o600 },
  );
  writeFileSync(
    join(original.dir, ".credentials.json"),
    '{"claudeAiOauth":{"refreshToken":"before-rename-refresh"}}\n',
    { mode: 0o600 },
  );

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      FAKE_LOGIN_READY: ready,
      FAKE_LOGIN_RELEASE: release,
    },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(ready));

  expect(runCli("rename", "acct", "renamed", "--tool", "claude").status).toBe(0);
  writeFileSync(release, "release");
  const result = await loginResult;
  const renamed = readStore().profiles?.find((profile) => profile.name === "renamed" && profile.tool === "claude");
  if (!renamed) throw new Error("missing renamed Claude profile fixture");

  expect(result.code).toBe(23);
  expect(JSON.parse(readFileSync(join(renamed.dir, ".claude.json"), "utf8"))).toEqual({
    oauthAccount: { emailAddress: "before-rename@example.com" },
    stablePreference: "before",
    laterProcessPreference: "keep",
  });
  expect(JSON.parse(readFileSync(join(renamed.dir, ".credentials.json"), "utf8"))).toEqual({
    claudeAiOauth: { refreshToken: "before-rename-refresh" },
    laterProcessPreference: "keep",
  });
});

test("rename between login lookup and auth publication preserves a later apply", async () => {
  const captureReady = join(home, "rename-gap.capture-ready");
  const childReady = join(home, "rename-gap.child-ready");
  const release = join(home, "rename-gap.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing rename-gap profile fixture");
  writeClaudeAuth(original.dir, "before-gap@example.com");

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ACCOUNTS_TEST_LOGIN_CAPTURE_READY: captureReady,
      ACCOUNTS_TEST_LOGIN_CAPTURE_DELAY_MS: "500",
      FAKE_LOGIN_READY: childReady,
      FAKE_LOGIN_RELEASE: release,
    },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(captureReady));
  expect(runCli("rename", "acct", "renamed", "--tool", "claude").status).toBe(0);
  await waitFor(() => existsSync(childReady));

  const apply = runCli("apply", "renamed", "--tool", "claude");
  expect(apply.status).toBe(0);
  const renamed = readStore().profiles?.find((profile) => profile.name === "renamed" && profile.tool === "claude");
  if (!renamed) throw new Error("missing renamed gap profile fixture");
  const laterHome = readFileSync(join(renamed.dir, ".claude.json"), "utf8");
  const laterCredentials = readFileSync(join(renamed.dir, ".credentials.json"), "utf8");
  writeFileSync(release, "release");
  expect((await loginResult).code).toBe(23);

  expect(readStore().current?.claude).toBe("renamed");
  expect(readStore().applied?.claude).toBe("renamed");
  expect(JSON.parse(readFileSync(join(renamed.dir, ".claude.json"), "utf8"))).toEqual(JSON.parse(laterHome));
  expect(JSON.parse(readFileSync(join(renamed.dir, ".credentials.json"), "utf8"))).toEqual(
    JSON.parse(laterCredentials),
  );
  expect(readStore().profileAuthRevisions?.["claude/acct"]).toBeUndefined();
  expect(readStore().profileAuthCommitRevisions?.["claude/acct"]).toBeUndefined();
  expect(readStore().profileAuthIncarnations?.["claude/acct"]).toBeUndefined();
  expect(readStore().profileAuthRevisions?.["claude/renamed"]).toBeTruthy();
  expect(readStore().profileAuthCommitRevisions?.["claude/renamed"]).toBeTruthy();
  expect(readStore().profileAuthIncarnations?.["claude/renamed"]).toBeTruthy();
});

test("stale login lookup never moves pre-existing auth ownership back across rename", async () => {
  const captureReady = join(home, "rename-existing.capture-ready");
  writeRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing pre-existing rename profile fixture");
  writeClaudeAuth(original.dir, "before-existing-rename@example.com");
  expect(runCli("apply", "acct", "--tool", "claude").status).toBe(0);

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ACCOUNTS_TEST_LOGIN_CAPTURE_READY: captureReady,
      ACCOUNTS_TEST_LOGIN_CAPTURE_DELAY_MS: "500",
    },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(captureReady));
  expect(runCli("rename", "acct", "renamed", "--tool", "claude").status).toBe(0);
  const failed = await loginResult;
  expect(failed.code).toBe(23);

  const machine = readStore();
  expect(machine.current?.claude).toBe("renamed");
  expect(machine.applied?.claude).toBe("renamed");
  expect(machine.profileAuthRevisions?.["claude/acct"]).toBeUndefined();
  expect(machine.profileAuthCommitRevisions?.["claude/acct"]).toBeUndefined();
  expect(machine.profileAuthIncarnations?.["claude/acct"]).toBeUndefined();
  expect(machine.profileAuthRevisions?.["claude/renamed"]).toBeTruthy();
  expect(machine.profileAuthCommitRevisions?.["claude/renamed"]).toBeTruthy();
  expect(machine.profileAuthIncarnations?.["claude/renamed"]).toBeTruthy();
  expect(JSON.parse(readFileSync(join(original.dir, ".claude.json"), "utf8"))).toMatchObject({
    oauthAccount: { emailAddress: "before-existing-rename@example.com" },
  });
});

test("removing a renamed profile cleans stale pre-rename auth ownership before name reuse", async () => {
  const captureReady = join(home, "rename-remove.capture-ready");
  writeRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const original = readStore().profiles?.find((profile) => profile.name === "acct" && profile.tool === "claude");
  if (!original) throw new Error("missing rename/remove profile fixture");
  writeClaudeAuth(original.dir, "before-remove@example.com");

  const login = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ACCOUNTS_TEST_LOGIN_CAPTURE_READY: captureReady,
      ACCOUNTS_TEST_LOGIN_CAPTURE_DELAY_MS: "500",
    },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(captureReady));
  expect(runCli("rename", "acct", "renamed", "--tool", "claude").status).toBe(0);
  expect((await loginResult).code).toBe(23);
  expect(readStore().profileAuthRevisions?.["claude/acct"]).toBeTruthy();

  expect(runCli("remove", "renamed", "--tool", "claude").status).toBe(0);
  expect(readStore().profileAuthRevisions).toEqual({});
  expect(readStore().profileAuthCommitRevisions).toEqual({});
  expect(readStore().profileAuthIncarnations).toEqual({});
  expect(runCli("add", "acct", "--tool", "claude").status).toBe(0);
  const reused = runCli("login", "acct", "--tool", "claude");
  expect(reused.status).toBe(23);
  expect(reused.stderr).not.toContain("profile changed before Claude auth capture");
});

test("post-child SIGTERM rolls back finalization without Claude keychain support", async () => {
  const completed = join(home, "non-keychain-login-completed");
  writeFinalizationSignalTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "prior", "--tool", "fake-login").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);
  expect(runCli("use", "prior", "--tool", "fake-login").status).toBe(0);
  const storeBefore = readStore();
  const child = spawnCliWith(["login", "acct", "--tool", "fake-login"], {
    env: {
      FAKE_LOGIN_COMPLETED: completed,
      ACCOUNTS_TEST_LOGIN_FINALIZE_DELAY_MS: "500",
    },
  });
  const resultPromise = collect(child);

  await waitFor(() => existsSync(completed));
  child.kill("SIGTERM");
  const result = await resultPromise;

  expect(result.code).toBe(143);
  expect(result.signal).toBeNull();
  expect(readStore()).toEqual(storeBefore);
  expect(readLogEntries()).toHaveLength(1);
});

test("post-child SIGHUP rolls back finalization and exits with the shell convention", async () => {
  const completed = join(home, "non-keychain-sighup-completed");
  writeFinalizationSignalTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "prior", "--tool", "fake-login").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);
  expect(runCli("use", "prior", "--tool", "fake-login").status).toBe(0);
  const storeBefore = readStore();
  const child = spawnCliWith(["login", "acct", "--tool", "fake-login"], {
    env: {
      FAKE_LOGIN_COMPLETED: completed,
      ACCOUNTS_TEST_LOGIN_FINALIZE_DELAY_MS: "500",
    },
  });
  const resultPromise = collect(child);

  await waitFor(() => existsSync(completed));
  child.kill("SIGHUP");
  const result = await resultPromise;

  expect(result.code).toBe(129);
  expect(result.signal).toBeNull();
  expect(readStore()).toEqual(storeBefore);
});

const HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS = 30_000;

for (const crashPoint of ["pre-save", "post-apply", "post-finalize"] as const) {
  test(`restart rolls back a hard-dead Claude finalization at ${crashPoint}`, () => {
    const fixture = setupClaudeLogin("success");
    const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
      env: {
        ...fixture.env,
        ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: crashPoint,
      },
    });
    expect(crashed.signal).toBe("SIGKILL");

    writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
    const recovered = runCliWith(["login", "acct", "--tool", "claude"], {
      env: fixture.env,
    });
    expect(recovered.stderr).toBe("");
    expect(recovered.status).toBe(23);
    const store = readStore();
    expect(store.current?.claude).toBe("prior");
    expect(store.applied?.claude).toBeUndefined();
    expect(store.loginOperations).toEqual({});
    expect(store.profiles?.find((profile) => profile.name === "acct")?.email).toBeUndefined();
    expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
      account: "prior",
      secret: "prior-secret",
    });
    const identity = store.profileAuthRevisions?.["claude/acct"];
    const commit = store.profileAuthCommitRevisions?.["claude/acct"];
    expect(identity).toBeTruthy();
    expect(commit).toBeTruthy();
    expect(readdirSync(join(home, ".auth-commits", identity!)).sort())
      .toEqual([`${commit}.json`]);
    const journalDir = join(home, "login-finalization-journals");
    expect(existsSync(journalDir) ? readdirSync(journalDir) : []).toEqual([]);
  }, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);
}

test("recovery releases the keychain lease before clearing its last durable journal", () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  expect(recoveryJournalIds()).toHaveLength(1);

  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  const cleanupCrashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_RECOVERY_HARD_CRASH_STAGE: "after-journal-clear",
    },
  });

  expect(cleanupCrashed.signal).toBe("SIGKILL");
  expect(recoveryJournalIds()).toEqual([]);
  expect(existsSync(fixture.keychainLock)).toBe(false);
  const [leaseId] = recoveryLeaseIds();
  expect(leaseId).toBeTruthy();
  const intent = readRecoveryLease(leaseId!);
  expect(
    readFileSync(recoveryProfileLockPath(intent.profileDir), "utf8"),
  ).toBe(intent.profileLockToken);

  const restarted = runCliWith(["login", "acct", "--tool", "claude"], {
    env: fixture.env,
  });
  expect(restarted.status).toBe(23);
  expect(restarted.stderr).toBe("");
  expect(existsSync(fixture.keychainLock)).toBe(false);
  expect(recoveryLeaseIds()).toEqual([]);
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("recovery retains its journal when exact keychain lease removal does not complete", async () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  const [journalId] = recoveryJournalIds();
  expect(journalId).toBeTruthy();

  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  const hookDirectory = join(home, "recovery-hooks-release-failure");
  const recovery = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_RECOVERY_HOOK_DIR: hookDirectory,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "recovery",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES: "before-keychain-release",
      ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS: "75",
    },
  });
  const result = collect(recovery);
  await waitForRecoveryHook(
    hookDirectory,
    "recovery",
    "before-keychain-release",
    journalId,
  );

  const exactToken = readFileSync(fixture.keychainLock, "utf8");
  renameSync(fixture.keychainLock, `${fixture.keychainLock}.displaced`);
  writeFileSync(fixture.keychainLock, exactToken, { mode: 0o600 });
  releaseRecoveryHook(
    hookDirectory,
    "recovery",
    "before-keychain-release",
    journalId,
  );

  const failed = await result;
  expect(failed.code).toBe(1);
  expect(recoveryJournalIds()).toEqual([journalId]);
  expect(existsSync(fixture.keychainLock)).toBe(true);

  const restarted = runCliWith(["login", "acct", "--tool", "claude"], {
    env: fixture.env,
  });
  expect(restarted.status).toBe(23);
  expect(restarted.stderr).toBe("");
  expect(recoveryJournalIds()).toEqual([]);
  expect(existsSync(fixture.keychainLock)).toBe(false);
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("concurrent recovery publishes lock ownership only after its exclusive profile claim", async () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  const [journalId] = recoveryJournalIds();
  expect(journalId).toBeTruthy();
  const [leaseId] = recoveryLeaseIds();
  expect(leaseId).toBeTruthy();
  const abandonedProfileIntent = readRecoveryLease(leaseId!);
  const abandonedProfileLock = recoveryProfileLockPath(
    abandonedProfileIntent.profileDir,
  );
  const abandonedJournal = readRecoveryJournal(journalId!);
  const abandonedKeychainLock = readFileSync(fixture.keychainLock, "utf8");
  expect(readFileSync(abandonedProfileLock, "utf8"))
    .toBe(abandonedProfileIntent.profileLockToken);
  expect(abandonedJournal.finalizationState.writes.keychainLockToken).toBeTruthy();
  expect(abandonedJournal.finalizationState.writes.applyLockToken).toBeTruthy();

  // This test coordinates two contenders for the dead journal. Resolve the
  // original crashed login's separate profile-lease intent first so the
  // contenders cannot race in the startup intent prepass before both reach the
  // journal-recovery barrier. Keep the journal, its keychain/apply ownership
  // tokens, and its live keychain lease abandoned so the tested recovery
  // ownership path remains unchanged.
  rmSync(abandonedProfileLock);
  rmSync(
    join(home, "login-finalization-journals", `${leaseId}.lease`),
  );
  expect(recoveryLeaseIds()).toEqual([]);
  expect(recoveryJournalIds()).toEqual([journalId]);
  expect(readRecoveryJournal(journalId!)).toEqual(abandonedJournal);
  expect(readFileSync(fixture.keychainLock, "utf8")).toBe(abandonedKeychainLock);

  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  const hookDirectory = join(home, "recovery-hooks-ownership");
  const commonEnv = {
    ...fixture.env,
    ACCOUNTS_TEST_LOGIN_RECOVERY_HOOK_DIR: hookDirectory,
    ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
      "after-read,before-profile-claim",
  };
  const recoveryA = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "a",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
        "after-read,before-profile-claim,after-keychain-claim",
    },
  });
  const resultA = collect(recoveryA);
  const recoveryB = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "b",
    },
  });
  const resultB = collect(recoveryB);

  await waitForRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "after-read");
  releaseRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "b", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  await waitForRecoveryHook(hookDirectory, "a", "after-keychain-claim", journalId);
  releaseRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);

  recoveryA.kill("SIGKILL");
  const killedA = await resultA;
  const failedB = await resultB;
  const durable = readRecoveryJournal(journalId);
  const restarted = runCliWith(["login", "acct", "--tool", "claude"], {
    env: fixture.env,
  });

  expect(killedA.signal).toBe("SIGKILL");
  expect(failedB.code).toBe(1);
  expect(durable.ownerPid).toBe(recoveryA.pid);
  expect(durable.finalizationState.writes.keychainLockToken)
    .toMatch(new RegExp(`^${recoveryA.pid}:`));
  expect(restarted.status).toBe(23);
  expect(restarted.stderr).toBe("");
  expect(recoveryJournalIds()).toEqual([]);
  expect(existsSync(fixture.keychainLock)).toBe(false);
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("a recovery waiter re-reads a cleared journal instead of replaying stale state", async () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  const [journalId] = recoveryJournalIds();
  expect(journalId).toBeTruthy();
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  const hookDirectory = join(home, "recovery-hooks-reread");
  const commonEnv = {
    ...fixture.env,
    ACCOUNTS_TEST_LOGIN_RECOVERY_HOOK_DIR: hookDirectory,
    ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
      "after-read,before-profile-claim",
  };
  const recoveryA = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "a",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
        "after-read,before-profile-claim,before-replay",
    },
  });
  const resultA = collect(recoveryA);
  const recoveryB = spawnCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "b",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
        "after-read,before-profile-claim,after-profile-claim",
    },
  });
  const resultB = collect(recoveryB);

  await waitForRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "after-read");
  releaseRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "b", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  await waitForRecoveryHook(hookDirectory, "a", "before-replay", journalId);
  releaseRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "a", "before-replay", journalId);
  await waitForRecoveryHook(hookDirectory, "b", "after-profile-claim", journalId);

  writeFileSync(
    fixture.keychainState,
    JSON.stringify({ account: "successor", secret: "successor-secret" }),
    { mode: 0o600 },
  );
  releaseRecoveryHook(hookDirectory, "b", "after-profile-claim", journalId);
  const [completedA, completedB] = await Promise.all([resultA, resultB]);

  expect(completedA.stderr).toBe("");
  expect(completedB.stderr).toBe("");
  expect(completedA.code).toBe(23);
  expect(completedB.code).toBe(23);
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "successor",
    secret: "successor-secret",
  });
  expect(recoveryJournalIds()).toEqual([]);
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("independent dead recovery journals still proceed under separate claims", () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  const [firstId] = recoveryJournalIds();
  expect(firstId).toBeTruthy();
  const secondId = randomUUID();
  const duplicate = deserialize(
    readFileSync(
      join(home, "login-finalization-journals", `${firstId}.bin`),
    ),
  ) as { id: string };
  duplicate.id = secondId;
  writeFileSync(
    join(home, "login-finalization-journals", `${secondId}.bin`),
    serialize(duplicate),
    { mode: 0o600 },
  );
  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);

  const recovered = runCliWith(["login", "acct", "--tool", "claude"], {
    env: fixture.env,
  });

  expect(recovered.status).toBe(23);
  expect(recovered.stderr).toBe("");
  expect(recoveryJournalIds()).toEqual([]);
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("non-Claude recovery waiters also skip a winner-cleared journal", async () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "prior", "--tool", "fake-login").status).toBe(0);
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);
  expect(runCli("use", "prior", "--tool", "fake-login").status).toBe(0);
  const crashed = runCliWith(["login", "acct", "--tool", "fake-login"], {
    env: {
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");
  const [journalId] = recoveryJournalIds();
  expect(journalId).toBeTruthy();
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login", 23);
  const hookDirectory = join(home, "recovery-hooks-non-claude");
  const commonEnv = {
    ACCOUNTS_TEST_LOGIN_RECOVERY_HOOK_DIR: hookDirectory,
    ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
      "after-read,before-profile-claim",
  };
  const recoveryA = spawnCliWith(["login", "acct", "--tool", "fake-login"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "a",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
        "after-read,before-profile-claim,before-replay",
    },
  });
  const resultA = collect(recoveryA);
  const recoveryB = spawnCliWith(["login", "acct", "--tool", "fake-login"], {
    env: {
      ...commonEnv,
      ACCOUNTS_TEST_LOGIN_RECOVERY_ROLE: "b",
      ACCOUNTS_TEST_LOGIN_RECOVERY_PAUSE_STAGES:
        "after-read,before-profile-claim,after-profile-claim",
    },
  });
  const resultB = collect(recoveryB);

  await waitForRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "after-read");
  releaseRecoveryHook(hookDirectory, "a", "after-read");
  await waitForRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "b", "after-read");
  await waitForRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "a", "before-profile-claim", journalId);
  await waitForRecoveryHook(hookDirectory, "a", "before-replay", journalId);
  releaseRecoveryHook(hookDirectory, "b", "before-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "a", "before-replay", journalId);
  await waitForRecoveryHook(hookDirectory, "b", "after-profile-claim", journalId);
  releaseRecoveryHook(hookDirectory, "b", "after-profile-claim", journalId);
  const [completedA, completedB] = await Promise.all([resultA, resultB]);

  expect(completedA.stderr).toBe("");
  expect(completedA.code).toBe(23);
  expect([1, 23]).toContain(completedB.code);
  if (completedB.code === 1) {
    expect(completedB.stderr).toContain(
      'login preparation is still in progress for profile "acct" and tool "fake-login"',
    );
  } else {
    expect(completedB.stderr).toBe("");
  }
  expect(
    existsSync(
      recoveryHookFile(
        hookDirectory,
        "b",
        "before-replay",
        "ready",
        journalId,
      ),
    ),
  ).toBe(false);
  expect(recoveryJournalIds()).toEqual([]);
  expect(readStore().current?.["fake-login"]).toBe("prior");
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("committed hard-death replay finishes immutable auth retention before clearing its journal", () => {
  const fixture = setupClaudeLogin("success");
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-commit-marker",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");

  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  expect(runCliWith(["login", "acct", "--tool", "claude"], { env: fixture.env }).status)
    .toBe(23);
  const store = readStore();
  expect(store.current?.claude).toBe("acct");
  expect(store.applied?.claude).toBe("acct");
  expect(store.loginOperations).toEqual({});
  const identity = store.profileAuthRevisions?.["claude/acct"];
  const commit = store.profileAuthCommitRevisions?.["claude/acct"];
  expect(readdirSync(join(home, ".auth-commits", identity!)).sort())
    .toEqual([`${commit}.json`]);
  expect(readdirSync(join(home, "login-finalization-journals"))).toEqual([]);
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

test("hard-death recovery preserves an initially absent Claude keychain", () => {
  const fixture = setupClaudeLogin("success");
  rmSync(fixture.keychainState, { force: true });
  const crashed = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LOGIN_HARD_CRASH_POINT: "post-finalize",
    },
  });
  expect(crashed.signal).toBe("SIGKILL");

  writeFakeTool("claude", "CLAUDE_CONFIG_DIR", "claude", 23);
  expect(runCliWith(["login", "acct", "--tool", "claude"], { env: fixture.env }).status)
    .toBe(23);
  expect(existsSync(fixture.keychainState)).toBe(false);
  expect(readStore().current?.claude).toBe("prior");
  expect(readStore().applied?.claude).toBeUndefined();
}, HARD_DEATH_RECOVERY_TEST_TIMEOUT_MS);

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
  expectOnlyStableAuthTrackingAdded(storeBefore, "claude/acct");
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(existsSync(fixture.keychainLock)).toBe(false);
  expect(readFileSync(signalLog, "utf8")).toContain("SIGINT");
});

test("ordinary apply waits for the shared Claude keychain lease before mutating", () => {
  const fixture = setupClaudeLogin("success");
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");
  const keychainBefore = readFileSync(fixture.keychainState, "utf8");
  writeFileSync(fixture.keychainLock, `${process.pid}:held-by-test`, { mode: 0o600 });

  const result = runCliWith(["apply", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS: "75",
    },
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("timed out waiting for the Claude keychain lock");
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(readFileSync(fixture.keychainState, "utf8")).toBe(keychainBefore);
});

test("ordinary apply rolls back live, registry, and keychain state when the keychain write fails", () => {
  const fixture = setupClaudeLogin("success");
  const profiles = readStore().profiles ?? [];
  const prior = profiles.find((profile) => profile.name === "prior" && profile.tool === "claude");
  if (!prior) throw new Error("missing prior Claude profile fixture");
  writeClaudeAuth(prior.dir, "prior@example.com");
  expect(runCliWith(["apply", "prior", "--tool", "claude"], { env: fixture.env }).status).toBe(0);
  const liveHomeJson = join(home, ".claude.json");
  const liveCredentials = join(home, ".claude", ".credentials.json");
  const storeBefore = readFileSync(join(home, "accounts.json"), "utf8");
  const keychainBefore = readFileSync(fixture.keychainState, "utf8");
  const liveHomeBefore = readFileSync(liveHomeJson, "utf8");
  const liveCredentialsBefore = readFileSync(liveCredentials, "utf8");

  const result = runCliWith(["apply", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      FAKE_SECURITY_FAIL_ADD_CONTAINS: "acct@example.com-access-token",
    },
  });

  expect(result.status).toBe(1);
  expect(result.stderr).toContain("keychain write failed");
  expect(readFileSync(join(home, "accounts.json"), "utf8")).toBe(storeBefore);
  expect(readFileSync(fixture.keychainState, "utf8")).toBe(keychainBefore);
  expect(readFileSync(liveHomeJson, "utf8")).toBe(liveHomeBefore);
  expect(readFileSync(liveCredentials, "utf8")).toBe(liveCredentialsBefore);
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
  store.appliedRevisions = { ...(store.appliedRevisions ?? {}), claude: "prior-generation" };
  writeFileSync(join(home, "accounts.json"), JSON.stringify({ version: 1, tools: [], ...store }, null, 2) + "\n");
  const storeBefore = readStore();
  const priorProfileDir = store.profiles?.find((profile) => profile.name === "prior")?.dir;
  const targetProfileDir = store.profiles?.find((profile) => profile.name === "acct")?.dir;
  if (!priorProfileDir || !targetProfileDir) throw new Error("missing login rollback profile fixtures");
  const trackedProfileSnapshots = [
    join(priorProfileDir, ".accounts-auth", "oauth-account.json"),
    join(priorProfileDir, ".accounts-auth", "credentials.json"),
    join(priorProfileDir, ".accounts-auth", "keychain.json"),
    join(targetProfileDir, ".accounts-auth", "oauth-account.json"),
    join(targetProfileDir, ".accounts-auth", "credentials.json"),
    join(targetProfileDir, ".accounts-auth", "keychain.json"),
  ];
  expect(trackedProfileSnapshots.every((path) => !existsSync(path))).toBe(true);
  writeFinalizationSignalTool("claude", "CLAUDE_CONFIG_DIR", "claude");

  const result = runCliWith(["login", "acct", "--tool", "claude"], {
    env: {
      ...fixture.env,
      ACCOUNTS_TEST_LIVE_DIR: liveBase,
      FAKE_SECURITY_DELAY_MS: "40",
      FAKE_LOGIN_MUTATE_LIVE: "1",
      FAKE_LOGIN_COMPLETED: loginCompleted,
      FAKE_FINALIZE_SIGNAL_SENT: signalSent,
    },
  });

  expect(result.status).toBe(130);
  expect(existsSync(signalSent)).toBe(true);
  expect(result.stdout).not.toContain("live/default Claude Code account");
  const restoredStore = readStore();
  expect({
    ...restoredStore,
    currentRevisions: storeBefore.currentRevisions,
    appliedRevisions: storeBefore.appliedRevisions,
    profileAuthRevisions: storeBefore.profileAuthRevisions,
    profileAuthCommitRevisions: storeBefore.profileAuthCommitRevisions,
    profileAuthIncarnations: storeBefore.profileAuthIncarnations,
  }).toEqual(storeBefore);
  expect(restoredStore.currentRevisions.claude).not.toBe(storeBefore.currentRevisions.claude);
  expect(restoredStore.appliedRevisions.claude).not.toBe(storeBefore.appliedRevisions.claude);
  expect(readFileSync(liveHomeJson, "utf8")).toBe('{"oauthAccount":{"emailAddress":"prior@example.com"}}\n');
  expect(readFileSync(liveCredentials, "utf8")).toBe('{"claudeAiOauth":{"refreshToken":"prior-live"}}\n');
  expect(readFileSync(liveSettings, "utf8")).toBe('{"apiKeyHelper":"keep-me","theme":"dark"}\n');
  expect(JSON.parse(readFileSync(fixture.keychainState, "utf8"))).toEqual({
    account: "prior",
    secret: "prior-secret",
  });
  expect(trackedProfileSnapshots.every((path) => !existsSync(path))).toBe(true);
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
  const before = JSON.parse(storeBefore) as ReturnType<typeof readStore>;
  const after = readStore();
  expect({
    ...after,
    profileAuthRevisions: before.profileAuthRevisions,
    profileAuthCommitRevisions: before.profileAuthCommitRevisions,
    profileAuthIncarnations: before.profileAuthIncarnations,
  }).toEqual(before);
  expect(after.toolLocks?.shared).toBe("codex");
  expect(after.toolLockRevisions?.shared).toBe(before.toolLockRevisions?.shared);
  expect(after.current?.codex).toBe("shared");
  expect(after.current?.claude).toBeUndefined();
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

test("failed new login preserves a profile adopted by a later update and use", async () => {
  const ready = join(home, "adopted-created.ready");
  const release = join(home, "adopted-created.release");
  writeBlockingRawAuthMutatingFailureTool("claude", "CLAUDE_CONFIG_DIR", "nonzero");

  const login = spawnCliWith(["login", "adopted", "--tool", "claude"], {
    env: { FAKE_LOGIN_READY: ready, FAKE_LOGIN_RELEASE: release },
  });
  const loginResult = collect(login);
  await waitFor(() => existsSync(ready));

  expect(runCli("set", "adopted", "--tool", "claude", "--description", "adopted elsewhere").status).toBe(0);
  expect(runCli("use", "adopted", "--tool", "claude").status).toBe(0);
  const adopted = readStore();
  const adoptedRevision = adopted.currentRevisions?.claude;
  const adoptedToolLockRevision = adopted.toolLockRevisions?.adopted;

  writeFileSync(release, "release");
  expect((await loginResult).code).toBe(23);

  const after = readStore();
  expect(after.profiles?.find((profile) => profile.name === "adopted" && profile.tool === "claude")?.description)
    .toBe("adopted elsewhere");
  expect(after.current?.claude).toBe("adopted");
  expect(after.currentRevisions?.claude).toBe(adoptedRevision);
  expect(after.toolLocks?.adopted).toBe("claude");
  expect(after.toolLockRevisions?.adopted).toBe(adoptedToolLockRevision);
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
