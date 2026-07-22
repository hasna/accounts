import { expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { delimiter, join } from "node:path";

const nestedProbe = process.env.ACCOUNTS_TEST_NESTED_PROBE === "1";

const inheritedToolHomeKeys = [
  "CLAUDE_CONFIG_DIR",
  "CODEX_HOME",
  "CODEWITH_HOME",
  "TAKUMI_CONFIG_DIR",
  "GEMINI_CONFIG_DIR",
  "OPENCODE_CONFIG_DIR",
  "CURSOR_CONFIG_DIR",
  "PI_CODING_AGENT_HOME",
  "HERMES_HOME",
  "KIMI_CODE_HOME",
  "TELEGRAM_STATE_DIR",
] as const;

const inheritedDirectoryKeys = [
  "HOME",
  "USERPROFILE",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "ProgramFiles",
  "ProgramFiles(x86)",
  "ProgramW6432",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
] as const;

const toolExecutables = [
  "claude",
  "codex",
  "codewith",
  "cursor-agent",
  "gemini",
  "grok",
  "hermes",
  "kimi",
  "opencode",
  "pi",
  "takumi",
] as const;

function writeMarkerExecutable(path: string, marker: string): string {
  const executablePath = platform() === "win32" ? `${path}.cmd` : path;
  const source = platform() === "win32"
    ? `@echo off\r\ntype nul > ${JSON.stringify(marker)}\r\nexit /b 87\r\n`
    : `#!/bin/sh\n: > ${JSON.stringify(marker)}\nexit 87\n`;
  writeFileSync(executablePath, source, { mode: 0o700 });
  return executablePath;
}

test("bare Bun tests make zero inherited network, database, keychain, or tool side effects", async () => {
  if (nestedProbe) {
    expect(process.env.ACCOUNTS_TEST_NESTED_PROBE).toBe("1");
    return;
  }

  const sentinelRoot = mkdtempSync(join(tmpdir(), "accounts-inherited-sentinel-"));
  const sentinelBin = join(sentinelRoot, "bin");
  const keychainMarker = join(sentinelRoot, "keychain-called");
  const toolMarker = join(sentinelRoot, "tool-called");
  const shellMarker = join(sentinelRoot, "shell-called");
  let httpRequests = 0;
  let postgresConnections = 0;

  mkdirSync(sentinelBin, { recursive: true });
  const inheritedSecurity = writeMarkerExecutable(join(sentinelBin, "security"), keychainMarker);
  const inheritedShell = writeMarkerExecutable(join(sentinelBin, "shell"), shellMarker);
  for (const executable of toolExecutables) {
    writeMarkerExecutable(join(sentinelBin, executable), toolMarker);
  }

  const apiServer = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      httpRequests += 1;
      return Response.json({ accounts: [] });
    },
  });
  const postgresServer = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open(socket) {
        postgresConnections += 1;
        socket.end();
      },
      data() {},
      error() {},
    },
  });

  const apiUrl = `http://127.0.0.1:${apiServer.port}`;
  const postgresUrl =
    `postgresql://sentinel:sentinel@127.0.0.1:${postgresServer.port}/accounts?connect_timeout=1`;
  const inheritedEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ACCOUNTS_TEST_NESTED_PROBE: "1",
    ACCOUNTS_TEST_BOOTSTRAP_PROBE: "1",
    ACCOUNTS_TEST_EXPECTED_SENTINEL_ROOT: sentinelRoot,
    HASNA_ACCOUNTS_API_URL: apiUrl,
    HASNA_ACCOUNTS_API_KEY: "sentinel-hasna-key",
    ACCOUNTS_API_URL: apiUrl,
    ACCOUNTS_API_KEY: "sentinel-fallback-key",
    APP_API_URL: apiUrl,
    APP_API_KEY: "sentinel-app-key",
    HASNA_ACCOUNTS_TEST_DATABASE_URL: postgresUrl,
    HASNA_ACCOUNTS_DATABASE_URL: postgresUrl,
    ACCOUNTS_DATABASE_URL: postgresUrl,
    ACCOUNTS_REQUIRE_POSTGRES: "1",
    PGHOST: "127.0.0.1",
    PGPORT: String(postgresServer.port),
    PGDATABASE: "sentinel",
    PGUSER: "sentinel",
    PGPASSWORD: "sentinel",
    PGSSLROOTCERT: join(sentinelRoot, "pg-root.pem"),
    NODE_EXTRA_CA_CERTS: join(sentinelRoot, "node-extra-ca.pem"),
    HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
    ACCOUNTS_STORAGE_MODE: "self_hosted",
    HASNA_ACCOUNTS_MODE: "cloud",
    HASNA_ACCOUNTS_RUNTIME_ROLE: "sentinel-runtime-role",
    HASNA_ACCOUNTS_API_SIGNING_KEY: "sentinel-signing-key",
    HASNA_API_SIGNING_KEY: "sentinel-shared-signing-key",
    HOST: "127.0.0.1",
    PORT: "1",
    ACCOUNTS_SERVE_PORT: "1",
    ACCOUNTS_HOME: sentinelRoot,
    HASNA_ACCOUNTS_HOME: sentinelRoot,
    ACCOUNTS_STORE_PATH: join(sentinelRoot, "accounts.json"),
    HASNA_ACCOUNTS_MACHINE_ID: "sentinel-machine",
    ACCOUNTS_MACHINE_ID: "sentinel-machine",
    HASNA_ACCOUNTS_S3_BUCKET: "sentinel-bucket",
    ACCOUNTS_S3_BUCKET: "sentinel-bucket",
    ACCOUNTS_ACTIVE: "sentinel-profile",
    ACCOUNTS_SUPERVISOR: "1",
    ACCOUNTS_FORCE_INTERACTIVE: "1",
    ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS: "1",
    ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS: "1",
    ACCOUNTS_TEST_KEYCHAIN: "1",
    ACCOUNTS_TEST_SECURITY_BIN: inheritedSecurity,
    ACCOUNTS_TEST_LIVE_DIR: join(sentinelRoot, "live-home"),
    ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH: join(sentinelRoot, "keychain.lock"),
    CLAUDE_CODE_API_KEY_HELPER: join(sentinelRoot, "credential-helper"),
    CLAUDE_CODE_API_KEY_HELPER_TTL_MS: "60000",
    ANTHROPIC_API_KEY: "sentinel-anthropic-key",
    ANTHROPIC_AUTH_TOKEN: "sentinel-anthropic-token",
    ANTHROPIC_BASE_URL: apiUrl,
    CLAUDE_CODE_USE_BEDROCK: "1",
    CLAUDE_CODE_USE_VERTEX: "1",
    SHELL: inheritedShell,
    COMSPEC: inheritedShell,
    PATH: `${sentinelBin}${delimiter}${process.env.PATH ?? ""}`,
  };
  for (const key of inheritedToolHomeKeys) inheritedEnv[key] = join(sentinelRoot, key.toLowerCase());
  for (const key of inheritedDirectoryKeys) inheritedEnv[key] = join(sentinelRoot, key.toLowerCase());

  try {
    const child = Bun.spawn({
      cmd: [process.execPath, "test"],
      cwd: process.cwd(),
      env: inheritedEnv,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);

    expect(exitCode, `${stdout}\n${stderr}`).toBe(0);
    expect(httpRequests).toBe(0);
    expect(postgresConnections).toBe(0);
    expect(existsSync(keychainMarker)).toBe(false);
    expect(existsSync(toolMarker)).toBe(false);
    expect(existsSync(shellMarker)).toBe(false);
    expect(existsSync(join(sentinelRoot, "accounts.json"))).toBe(false);
    expect(existsSync(join(sentinelRoot, "keychain.lock"))).toBe(false);
  } finally {
    apiServer.stop(true);
    postgresServer.stop(true);
    rmSync(sentinelRoot, { recursive: true, force: true });
  }
}, 120_000);

test("PostgreSQL variables survive only the exact integration target plus explicit opt-in", async () => {
  if (nestedProbe) {
    expect(process.env.ACCOUNTS_TEST_NESTED_PROBE).toBe("1");
    return;
  }

  let postgresConnections = 0;
  const postgresServer = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open(socket) {
        postgresConnections += 1;
        socket.end();
      },
      data() {},
      error() {},
    },
  });
  const sentinelUrl =
    `postgresql://sentinel:sentinel@127.0.0.1:${postgresServer.port}/accounts?connect_timeout=1`;

  try {
    const explicitChild = Bun.spawn({
      cmd: [process.execPath, "run", "./test/run-postgres.ts"],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_TEST_POSTGRES_PROBE: "1",
        ACCOUNTS_TEST_EXPECTED_POSTGRES_URL: sentinelUrl,
        ACCOUNTS_REQUIRE_POSTGRES: "1",
        HASNA_ACCOUNTS_TEST_DATABASE_URL: sentinelUrl,
        HASNA_ACCOUNTS_DATABASE_URL: sentinelUrl,
        ACCOUNTS_DATABASE_URL: sentinelUrl,
        PGHOST: "127.0.0.1",
        PGPORT: String(postgresServer.port),
        PGSSLROOTCERT: "/sentinel/pg-root.pem",
        NODE_EXTRA_CA_CERTS: "/sentinel/node-extra-ca.pem",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [explicitExit, explicitStdout, explicitStderr] = await Promise.all([
      explicitChild.exited,
      new Response(explicitChild.stdout).text(),
      new Response(explicitChild.stderr).text(),
    ]);
    expect(explicitExit, `${explicitStdout}\n${explicitStderr}`).toBe(0);
    expect(postgresConnections).toBe(0);

    const closedChild = Bun.spawn({
      cmd: [process.execPath, "test", "./src/server/postgres.integration.ts"],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_TEST_POSTGRES_CLOSED_PROBE: "1",
        ACCOUNTS_REQUIRE_POSTGRES: "1",
        HASNA_ACCOUNTS_TEST_DATABASE_URL: sentinelUrl,
        HASNA_ACCOUNTS_DATABASE_URL: sentinelUrl,
        ACCOUNTS_DATABASE_URL: sentinelUrl,
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [closedExit, closedStdout, closedStderr] = await Promise.all([
      closedChild.exited,
      new Response(closedChild.stdout).text(),
      new Response(closedChild.stderr).text(),
    ]);
    expect(closedExit, `${closedStdout}\n${closedStderr}`).toBe(0);
    expect(postgresConnections).toBe(0);

    const optionValueChild = Bun.spawn({
      cmd: [
        process.execPath,
        "test",
        "--preload",
        "./src/server/postgres.integration.ts",
        "./test/environment-isolation.test.ts",
      ],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_REQUIRE_POSTGRES: "1",
        ACCOUNTS_POSTGRES_TEST_TARGET: "1",
        HASNA_ACCOUNTS_TEST_DATABASE_URL: sentinelUrl,
      },
      stdout: "ignore",
      stderr: "ignore",
    });
    expect(await optionValueChild.exited).not.toBe(0);
    expect(postgresConnections).toBe(0);
  } finally {
    postgresServer.stop(true);
  }
}, 30_000);
