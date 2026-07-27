import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

function runCliWith(args: string[], opts: RunOptions = {}) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    input: opts.input,
    env: {
      ...process.env,
      NODE_ENV: "test",
      ACCOUNTS_HOME: home,
      FAKE_LOGIN_LOG: logPath,
      PATH: opts.path ?? `${binDir}:${process.env.PATH ?? ""}`,
      ...opts.env,
    },
  });
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
      'request_debug=""',
      '[ "${BUN_CONFIG_VERBOSE_FETCH+x}" = x ] && request_debug="${request_debug}BUN_CONFIG_VERBOSE_FETCH,"',
      '[ "${NODE_DEBUG+x}" = x ] && request_debug="${request_debug}NODE_DEBUG,"',
      '[ "${NODE_DEBUG_NATIVE+x}" = x ] && request_debug="${request_debug}NODE_DEBUG_NATIVE,"',
      `printf '{"tool":"${toolName}","args":"%s","home":"%s","requestDebug":"%s","path":"%s","httpsProxy":"%s","tlsCert":"%s","bedrock":"%s","vertex":"%s","awsProfile":"%s","googleCredentials":"%s"}\\n' "$*" "$home" "$request_debug" "$PATH" "\${HTTPS_PROXY:-}" "\${NODE_EXTRA_CA_CERTS:-}" "\${CLAUDE_CODE_USE_BEDROCK:-}" "\${CLAUDE_CODE_USE_VERTEX:-}" "\${AWS_PROFILE:-}" "\${GOOGLE_APPLICATION_CREDENTIALS:-}" >> "$FAKE_LOGIN_LOG"`,
      'if [ -n "${BUN_CONFIG_VERBOSE_FETCH:-}${NODE_DEBUG:-}${NODE_DEBUG_NATIVE:-}" ] && [ -n "${FAKE_DEBUG_CREDENTIAL:-}" ]; then',
      '  printf "Authorization: Bearer %s\\n" "$FAKE_DEBUG_CREDENTIAL"',
      '  printf "x-api-key=%s\\n" "$FAKE_DEBUG_CREDENTIAL" >&2',
      "fi",
      `exit ${exitCode}`,
    ].join("\n"),
  );
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
  const result = runCli(
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
  );
  expect(result.status, result.stderr).toBe(0);
}

function readLogEntries() {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as {
      tool: string;
      args: string;
      home: string;
      requestDebug: string;
      path: string;
      httpsProxy: string;
      tlsCert: string;
      bedrock: string;
      vertex: string;
      awsProfile: string;
      googleCredentials: string;
    });
}

const handoffEnvironment = {
  BUN_CONFIG_VERBOSE_FETCH: "1",
  NODE_DEBUG: "http,http2",
  NODE_DEBUG_NATIVE: "http",
  HTTPS_PROXY: "http://proxy.example.test:8443",
  NODE_EXTRA_CA_CERTS: "/profiles/work/ca.pem",
  CLAUDE_CODE_USE_BEDROCK: "1",
  CLAUDE_CODE_USE_VERTEX: "1",
  AWS_PROFILE: "work",
  GOOGLE_APPLICATION_CREDENTIALS: "/profiles/work/google.json",
};

function expectSafeProviderObservation() {
  const observation = readLogEntries().at(-1);
  expect(observation).toBeTruthy();
  expect(observation?.requestDebug).toBe("");
  expect(observation).toMatchObject({
    httpsProxy: handoffEnvironment.HTTPS_PROXY,
    tlsCert: handoffEnvironment.NODE_EXTRA_CA_CERTS,
    bedrock: handoffEnvironment.CLAUDE_CODE_USE_BEDROCK,
    vertex: handoffEnvironment.CLAUDE_CODE_USE_VERTEX,
    awsProfile: handoffEnvironment.AWS_PROFILE,
    googleCredentials: handoffEnvironment.GOOGLE_APPLICATION_CREDENTIALS,
  });
  expect(observation?.path).toContain(binDir);
}

function executeGeneratedHandoff(lines: string) {
  return spawnSync(
    "/bin/sh",
    ["-c", `${lines}\nfake-login-tool observe`],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        ...handoffEnvironment,
        FAKE_LOGIN_LOG: logPath,
        PATH: `${binDir}:${process.env.PATH ?? ""}`,
      },
    },
  );
}

function executeHandoffCommand(commandLine: string) {
  return spawnSync(
    "/bin/sh",
    ["-c", commandLine],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        ...handoffEnvironment,
        FAKE_LOGIN_LOG: logPath,
        PATH: `${binDir}:${process.env.PATH ?? ""}`,
      },
    },
  );
}

function readStore() {
  return JSON.parse(readFileSync(join(home, "accounts.json"), "utf8")) as {
    toolLocks?: Record<string, string>;
    profiles?: Array<{ name: string; tool: string; dir: string }>;
  };
}

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

test("login and switch launch suppress inherited request-debug output", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);
  const dummyCredential = "dummy-login-request-credential";
  const env = {
    BUN_CONFIG_VERBOSE_FETCH: "1",
    NODE_DEBUG: "http,http2",
    NODE_DEBUG_NATIVE: "http",
    FAKE_DEBUG_CREDENTIAL: dummyCredential,
  };

  const login = runCliWith(["login", "acct"], { env });
  expect(login.status).toBe(0);
  expect(login.stdout).not.toContain(dummyCredential);
  expect(login.stderr).not.toContain(dummyCredential);

  const launchedSwitch = runCliWith(
    ["switch", "acct", "--tool", "fake-login", "--mode", "active", "--launch"],
    { env },
  );
  expect(launchedSwitch.status).toBe(0);
  expect(launchedSwitch.stdout).not.toContain(dummyCredential);
  expect(launchedSwitch.stderr).not.toContain(dummyCredential);
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

test("generated env and pick --env handoffs unset request debugging before provider execution", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);

  const generated = runCliWith(["env", "acct", "--tool", "fake-login"], {
    env: handoffEnvironment,
  });
  expect(generated.status).toBe(0);
  const generatedLines = generated.stdout
    .split("\n")
    .filter((line) => line.startsWith("unset ") || line.startsWith("export "))
    .join("\n");
  expect(generatedLines).toContain("unset BUN_CONFIG_VERBOSE_FETCH NODE_DEBUG NODE_DEBUG_NATIVE");
  expect(executeGeneratedHandoff(generatedLines).status).toBe(0);
  expectSafeProviderObservation();

  rmSync(logPath, { force: true });
  const picked = runCliWith(["pick", "--tool", "fake-login", "--env"], {
    input: "1\n",
    env: handoffEnvironment,
  });
  expect(picked.status).toBe(0);
  const pickedLines = picked.stdout
    .split("\n")
    .filter((line) => line.startsWith("unset ") || line.startsWith("export "))
    .join("\n");
  expect(pickedLines).toContain("unset BUN_CONFIG_VERBOSE_FETCH NODE_DEBUG NODE_DEBUG_NATIVE");
  expect(executeGeneratedHandoff(pickedLines).status).toBe(0);
  expectSafeProviderObservation();
});

test("env, pick --env, and switch preserve hostile profile and extra env bytes", () => {
  const toolBin = join(binDir, "-hostile-handoff-tool");
  const markerDollar = join(home, "cli-dollar-marker");
  const markerBacktick = join(home, "cli-backtick-marker");
  const hostileDir =
    `${home}/-leading "double" 'single'\nline\\backslash $DOLLAR ` +
    `$(touch cli-dollar-marker) \`touch cli-backtick-marker\``;
  const extraTemplate =
    `-extra "double" 'single'\nline\\backslash $DOLLAR ` +
    `$(touch cli-dollar-marker) \`touch cli-backtick-marker\`::{profileDir}`;
  const expectedExtra = extraTemplate.replaceAll("{profileDir}", hostileDir);
  writeFileSync(
    toolBin,
    [
      "#!/bin/sh",
      `printf '%s\\n---EXTRA---\\n%s' "$HOSTILE_HOME" "$EXTRA_VALUE" > "$OBSERVATION_PATH"`,
    ].join("\n"),
  );
  chmodSync(toolBin, 0o755);
  addFakeLoginTool("hostile-handoff", "Hostile Handoff", "HOSTILE_HOME", "-hostile-handoff-tool");
  expect(runCli("add", "acct", "--tool", "hostile-handoff").status).toBe(0);

  const storePath = join(home, "accounts.json");
  const store = JSON.parse(readFileSync(storePath, "utf8")) as {
    profiles: Array<{ name: string; tool: string; dir: string }>;
    tools: Array<{ id: string; extraEnv?: Record<string, string> }>;
  };
  store.profiles.find((entry) => entry.name === "acct" && entry.tool === "hostile-handoff")!.dir = hostileDir;
  store.tools.find((entry) => entry.id === "hostile-handoff")!.extraEnv = { EXTRA_VALUE: extraTemplate };
  writeFileSync(storePath, JSON.stringify(store));

  const extractExports = (stdout: string): string => {
    const start = stdout.indexOf("unset BUN_CONFIG_VERBOSE_FETCH");
    expect(start).toBeGreaterThanOrEqual(0);
    return stdout.slice(start).trimEnd();
  };
  const evaluateExports = (script: string, observation: string) =>
    spawnSync("/bin/sh", ["-s"], {
      cwd: home,
      encoding: "utf8",
      input: `${script}\nprintf '%s\\n---EXTRA---\\n%s' "$HOSTILE_HOME" "$EXTRA_VALUE" > "$OBSERVATION_PATH"`,
      env: {
        ...process.env,
        DOLLAR: "expanded-by-shell",
        OBSERVATION_PATH: observation,
      },
    });

  const generated = runCliWith(["env", "acct", "--tool", "hostile-handoff"]);
  expect(generated.status, generated.stderr).toBe(0);
  const envObservation = join(home, "env-observation");
  const evaluatedEnv = evaluateExports(extractExports(generated.stdout), envObservation);
  expect(evaluatedEnv.status, evaluatedEnv.stderr).toBe(0);
  expect(readFileSync(envObservation, "utf8")).toBe(`${hostileDir}\n---EXTRA---\n${expectedExtra}`);

  const picked = runCliWith(["pick", "--tool", "hostile-handoff", "--env"], { input: "1\n" });
  expect(picked.status, picked.stderr).toBe(0);
  const pickObservation = join(home, "pick-observation");
  const evaluatedPick = evaluateExports(extractExports(picked.stdout), pickObservation);
  expect(evaluatedPick.status, evaluatedPick.stderr).toBe(0);
  expect(readFileSync(pickObservation, "utf8")).toBe(`${hostileDir}\n---EXTRA---\n${expectedExtra}`);

  const switched = runCliWith(["switch", "acct", "--tool", "hostile-handoff", "--mode", "active"]);
  expect(switched.status, switched.stderr).toBe(0);
  const commandStart = switched.stdout.indexOf("restart command: ");
  const commandEnd = switched.stdout.indexOf("\n  Exit the current agent session", commandStart);
  expect(commandStart).toBeGreaterThanOrEqual(0);
  expect(commandEnd).toBeGreaterThan(commandStart);
  const commandLine = switched.stdout.slice(commandStart + "restart command: ".length, commandEnd);
  const switchObservation = join(home, "switch-observation");
  const evaluatedSwitch = spawnSync("/bin/sh", ["-s"], {
    cwd: home,
    encoding: "utf8",
    input: [
      "HOSTILE_HOME=parent-value",
      commandLine,
      'printf %s "$HOSTILE_HOME"',
    ].join("\n"),
    env: {
      ...process.env,
      DOLLAR: "expanded-by-shell",
      OBSERVATION_PATH: switchObservation,
      PATH: `${binDir}:${process.env.PATH ?? ""}`,
    },
  });
  expect(evaluatedSwitch.status, evaluatedSwitch.stderr).toBe(0);
  expect(evaluatedSwitch.stdout).toBe("parent-value");
  expect(readFileSync(switchObservation, "utf8")).toBe(`${hostileDir}\n---EXTRA---\n${expectedExtra}`);
  expect(existsSync(markerDollar)).toBe(false);
  expect(existsSync(markerBacktick)).toBe(false);
});

test("non-launch switch handoff command unsets request debugging before provider execution", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);

  const switched = runCliWith(
    ["switch", "acct", "--tool", "fake-login", "--mode", "active"],
    { env: handoffEnvironment },
  );
  expect(switched.status).toBe(0);
  const commandLine = switched.stdout.match(/restart command: (.+)/)?.[1];
  expect(commandLine).toContain("env -u BUN_CONFIG_VERBOSE_FETCH -u NODE_DEBUG -u NODE_DEBUG_NATIVE");
  expect(executeHandoffCommand(commandLine ?? "").status).toBe(0);
  expectSafeProviderObservation();
});

test("switch human, JSON, and launch output use the safe DTO while launch keeps raw args transient", () => {
  const labelSecret = "caller-controlled-tool-label-secret";
  writeFakeTool("safe-output-tool", "SAFE_OUTPUT_HOME", "safe-output");
  addFakeLoginTool("safe-output", labelSecret, "SAFE_OUTPUT_HOME", "safe-output-tool");
  expect(runCli("add", "acct", "--tool", "safe-output").status).toBe(0);

  const envSecret = "switch-extra-env-secret";
  const argvSecret = "switch-api-arg-secret";
  const storePath = join(home, "accounts.json");
  const store = JSON.parse(readFileSync(storePath, "utf8")) as {
    tools: Array<{ id: string; extraEnv?: Record<string, string> }>;
  };
  store.tools.find((tool) => tool.id === "safe-output")!.extraEnv = {
    SERVICE_API_KEY: envSecret,
  };
  writeFileSync(storePath, JSON.stringify(store));

  const human = runCliWith([
    "switch",
    "acct",
    "--tool",
    "safe-output",
    "--mode",
    "active",
    "--",
    "--api-key",
    argvSecret,
  ]);
  expect(human.status, human.stderr).toBe(0);
  expect(`${human.stdout}${human.stderr}`).not.toContain(argvSecret);
  expect(`${human.stdout}${human.stderr}`).not.toContain(envSecret);
  expect(`${human.stdout}${human.stderr}`).not.toContain(labelSecret);
  expect(human.stdout).toContain("--api-key");
  expect(human.stdout).toContain("[REDACTED]");

  const json = runCliWith([
    "switch",
    "acct",
    "--tool",
    "safe-output",
    "--mode",
    "active",
    "--json",
    "--",
    "--api-key",
    argvSecret,
  ]);
  expect(json.status, json.stderr).toBe(0);
  expect(`${json.stdout}${json.stderr}`).not.toContain(argvSecret);
  expect(`${json.stdout}${json.stderr}`).not.toContain(envSecret);
  expect(`${json.stdout}${json.stderr}`).not.toContain(labelSecret);
  const output = JSON.parse(json.stdout) as Record<string, unknown>;
  expect(output["schema"]).toBe("hasna.accounts.switch-output/v1");
  expect(output).not.toHaveProperty("env");
  expect(output).not.toHaveProperty("exports");
  expect(output["tool"]).toEqual({ id: "safe-output", label: "Custom tool" });
  expect(output["profile"]).toEqual({ name: "acct", tool: "safe-output" });

  rmSync(logPath, { force: true });
  const launched = runCliWith([
    "switch",
    "acct",
    "--tool",
    "safe-output",
    "--mode",
    "active",
    "--launch",
    "--",
    "--api-key",
    argvSecret,
  ]);
  expect(launched.status, launched.stderr).toBe(0);
  expect(`${launched.stdout}${launched.stderr}`).not.toContain(argvSecret);
  expect(`${launched.stdout}${launched.stderr}`).not.toContain(envSecret);
  expect(`${launched.stdout}${launched.stderr}`).not.toContain(labelSecret);
  expect(readLogEntries().at(-1)?.args).toContain(`--api-key ${argvSecret}`);
});

test("switch surfaces redact normalized, clustered, and Unicode credential arguments", () => {
  writeFakeTool("argv-grammar-tool", "ARGV_GRAMMAR_HOME", "argv-grammar");
  addFakeLoginTool(
    "argv-grammar",
    "Argv Grammar",
    "ARGV_GRAMMAR_HOME",
    "argv-grammar-tool",
  );
  expect(runCli("add", "acct", "--tool", "argv-grammar").status).toBe(0);

  const secrets = Array.from(
    { length: 15 },
    (_, index) => `actual-switch-credential-${index}`,
  );
  const credentialArgs = [
    "--secret-key",
    secrets[0]!,
    `--service-account-key=${secrets[1]}`,
    `--auth-header:${secrets[2]}`,
    "--service-auth",
    secrets[3]!,
    "--bearer",
    secrets[4]!,
    "--credentials",
    secrets[5]!,
    "-vk",
    secrets[6]!,
    "-vvk",
    secrets[7]!,
    "－ｋ",
    secrets[8]!,
    "−k",
    secrets[9]!,
    `-vk${secrets[10]}`,
    "--encryption-key",
    secrets[11]!,
    `--master-key=${secrets[12]}`,
    `--client-key:${secrets[13]}`,
    "--aws-access-key-id",
    secrets[14]!,
  ];

  for (const surfaceArgs of [
    [],
    ["--json"],
  ]) {
    const result = runCliWith([
      "switch",
      "acct",
      "--tool",
      "argv-grammar",
      "--mode",
      "active",
      ...surfaceArgs,
      "--",
      ...credentialArgs,
    ]);
    expect(result.status, result.stderr).toBe(0);
    for (const secret of secrets) {
      expect(`${result.stdout}${result.stderr}`).not.toContain(secret);
    }
    expect(result.stdout).toContain("[REDACTED]");
  }

  rmSync(logPath, { force: true });
  const launched = runCliWith([
    "switch",
    "acct",
    "--tool",
    "argv-grammar",
    "--mode",
    "active",
    "--launch",
    "--",
    ...credentialArgs,
  ]);
  expect(launched.status, launched.stderr).toBe(0);
  for (const secret of secrets) {
    expect(`${launched.stdout}${launched.stderr}`).not.toContain(secret);
    expect(readLogEntries().at(-1)?.args).toContain(secret);
  }
});

test("accounts shell removes request debugging while preserving same-binding environment", () => {
  writeFakeTool("fake-login-tool", "FAKE_LOGIN_HOME", "fake-login");
  addFakeLoginTool();
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);

  const shell = runCliWith(["shell", "acct", "--tool", "fake-login"], {
    env: {
      ...handoffEnvironment,
      SHELL: join(binDir, "fake-login-tool"),
    },
  });

  expect(shell.status).toBe(0);
  expect(shell.stdout).toContain("env -u BUN_CONFIG_VERBOSE_FETCH -u NODE_DEBUG -u NODE_DEBUG_NATIVE");
  expectSafeProviderObservation();
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
