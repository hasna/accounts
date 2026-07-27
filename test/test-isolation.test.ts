import { expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { platform, tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import { controlledTestsRoot, executableFilename } from "./support/isolation-paths.js";

const nestedProbe = process.env.ACCOUNTS_TEST_NESTED_PROBE === "1";

// The side-effect probe re-runs the entire suite in a child process, so a fixed
// budget silently turns into a flake as soon as the suite grows. Scale it with
// the number of spec files the child will execute, and let a slow machine raise
// it explicitly with ACCOUNTS_TEST_NESTED_PROBE_TIMEOUT_MS.
const NESTED_PROBE_BUDGET_PER_TEST_FILE_MS = 15_000;
const NESTED_PROBE_MINIMUM_BUDGET_MS = 180_000;

function countTestFiles(root: string): number {
  let total = 0;
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    if (entry.isDirectory()) {
      total += countTestFiles(join(root, entry.name));
    } else if (entry.name.endsWith(".test.ts")) {
      total += 1;
    }
  }
  return total;
}

function nestedProbeBudgetMs(): number {
  const requested = Number(process.env.ACCOUNTS_TEST_NESTED_PROBE_TIMEOUT_MS);
  if (Number.isFinite(requested) && requested > 0) return requested;
  return Math.max(
    NESTED_PROBE_MINIMUM_BUDGET_MS,
    countTestFiles(process.cwd()) * NESTED_PROBE_BUDGET_PER_TEST_FILE_MS,
  );
}

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

function compileMarkerExecutable(root: string): string {
  const sourcePath = join(root, "marker-executable.ts");
  const outputPath = join(root, executableFilename("marker-executable"));
  writeFileSync(sourcePath, [
    'import { writeFileSync } from "node:fs";',
    'import { basename, dirname, join } from "node:path";',
    "const executable = process.execPath;",
    "const markerRoot = dirname(dirname(executable));",
    'writeFileSync(join(markerRoot, `${basename(executable)}.called`), "called\\n");',
    "process.exit(87);",
  ].join("\n"));
  const build = Bun.spawnSync({
    cmd: [process.execPath, "build", "--compile", sourcePath, "--outfile", outputPath],
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  if (build.exitCode !== 0) {
    throw new Error(`failed to compile marker executable (exit ${build.exitCode})`);
  }
  return outputPath;
}

function installMarkerExecutable(source: string, binDirectory: string, name: string): {
  executable: string;
  marker: string;
} {
  const executable = join(binDirectory, executableFilename(name));
  try {
    linkSync(source, executable);
  } catch {
    copyFileSync(source, executable);
  }
  if (platform() !== "win32") chmodSync(executable, 0o700);
  return {
    executable,
    marker: join(dirname(binDirectory), `${basename(executable)}.called`),
  };
}

function postgresLaunchResidue(launchId: string): string[] {
  const root = controlledTestsRoot(process.cwd());
  if (!existsSync(root)) return [];
  return readdirSync(root).filter((entry) => entry.startsWith(`postgres-launch-${launchId}-`));
}

test("bare Bun tests make zero inherited network, database, keychain, or tool side effects", async () => {
  if (nestedProbe) {
    expect(process.env.ACCOUNTS_TEST_NESTED_PROBE).toBe("1");
    return;
  }

  const sentinelRoot = mkdtempSync(join(tmpdir(), "accounts-inherited-sentinel-"));
  const sentinelBin = join(sentinelRoot, "bin");
  let httpRequests = 0;
  let postgresConnections = 0;

  mkdirSync(sentinelBin, { recursive: true });
  const markerExecutable = compileMarkerExecutable(sentinelRoot);
  const installedMarkers = [
    installMarkerExecutable(markerExecutable, sentinelBin, "security"),
    installMarkerExecutable(markerExecutable, sentinelBin, "shell"),
  ];
  for (const executable of toolExecutables) {
    installedMarkers.push(installMarkerExecutable(markerExecutable, sentinelBin, executable));
  }
  const inheritedSecurity = installedMarkers[0]!.executable;
  const inheritedShell = installedMarkers[1]!.executable;

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
    ACCOUNTS_TEST_ROOT_PARENT: sentinelRoot,
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
    ANTHROPIC_AWS_API_KEY: "sentinel-anthropic-aws-key",
    ANTHROPIC_FEDERATION_RULE_ID: "sentinel-federation-rule",
    ANTHROPIC_FOUNDRY_API_KEY: "sentinel-foundry-key",
    ANTHROPIC_FOUNDRY_AUTH_TOKEN: "sentinel-foundry-token",
    ANTHROPIC_ORGANIZATION_ID: "sentinel-organization",
    AWS_BEARER_TOKEN_BEDROCK: "sentinel-bedrock-token",
    CLOUDSDK_AUTH_ACCESS_TOKEN: "sentinel-cloudsdk-token",
    CLAUDE_CODE_HFI_BEARER_TOKEN: "sentinel-hfi-token",
    CLAUDE_CODE_HOST_CREDS_FILE: join(sentinelRoot, "host-creds"),
    CLAUDE_CODE_OAUTH_TOKEN: "sentinel-oauth-token",
    CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR: "9",
    CLAUDE_CODE_SESSION_ACCESS_TOKEN: "sentinel-session-token",
    CLAUDE_CODE_USE_BEDROCK: "1",
    CLAUDE_CODE_USE_VERTEX: "1",
    CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR: "10",
    CLAUDE_SESSION_INGRESS_TOKEN_FILE: join(sentinelRoot, "ingress-token"),
    CLAUDE_TRUSTED_DEVICE_TOKEN: "sentinel-device-token",
    SHELL: inheritedShell,
    COMSPEC: inheritedShell,
    TMPDIR: sentinelRoot,
    TMP: sentinelRoot,
    TEMP: sentinelRoot,
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
    for (const { marker } of installedMarkers) expect(existsSync(marker)).toBe(false);
    expect(existsSync(join(sentinelRoot, "accounts.json"))).toBe(false);
    expect(existsSync(join(sentinelRoot, "keychain.lock"))).toBe(false);
  } finally {
    apiServer.stop(true);
    postgresServer.stop(true);
    rmSync(sentinelRoot, { recursive: true, force: true });
  }
}, nestedProbeBudgetMs());

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
  const successLaunchId = randomUUID();

  try {
    const explicitChild = Bun.spawn({
      cmd: [process.execPath, "run", "./test/run-postgres.ts"],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_TEST_POSTGRES_PROBE: "1",
        ACCOUNTS_TEST_EXPECTED_POSTGRES_URL: sentinelUrl,
        ACCOUNTS_TEST_LAUNCH_ID: successLaunchId,
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
    expect(postgresLaunchResidue(successLaunchId)).toEqual([]);

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

test("PostgreSQL launcher kills its child and purges its root when signalled", async () => {
  if (nestedProbe) {
    expect(process.env.ACCOUNTS_TEST_NESTED_PROBE).toBe("1");
    return;
  }

  const launchId = randomUUID();
  const child = Bun.spawn({
    cmd: [process.execPath, "run", "./test/run-postgres.ts"],
    cwd: process.cwd(),
    env: {
      ...process.env,
      ACCOUNTS_TEST_LAUNCH_ID: launchId,
      ACCOUNTS_TEST_POSTGRES_HANG_PROBE: "1",
    },
    stdout: "ignore",
    stderr: "ignore",
  });

  try {
    const deadline = Date.now() + 20_000;
    while (postgresLaunchResidue(launchId).length === 0) {
      if (Date.now() > deadline) throw new Error("launcher never created its controlled root");
      await Bun.sleep(50);
    }
    // Let the child integration run start under the launcher before signalling.
    await Bun.sleep(500);

    child.kill("SIGTERM");
    const exitCode = await child.exited;

    expect(exitCode).not.toBe(0);
    expect(postgresLaunchResidue(launchId)).toEqual([]);
  } finally {
    child.kill("SIGKILL");
  }
}, 30_000);

test("PostgreSQL launcher removes its unique root after a deliberate bail", async () => {
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
  const launchId = randomUUID();

  try {
    const child = Bun.spawn({
      cmd: [process.execPath, "run", "./test/run-postgres.ts", "--bail=1"],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_TEST_POSTGRES_PROBE: "1",
        ACCOUNTS_TEST_EXPECTED_POSTGRES_URL: `${sentinelUrl}-expected-mismatch`,
        ACCOUNTS_TEST_LAUNCH_ID: launchId,
        ACCOUNTS_REQUIRE_POSTGRES: "1",
        HASNA_ACCOUNTS_TEST_DATABASE_URL: sentinelUrl,
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);

    expect(exitCode, `${stdout}\n${stderr}`).not.toBe(0);
    expect(postgresConnections).toBe(0);
    expect(postgresLaunchResidue(launchId)).toEqual([]);
  } finally {
    postgresServer.stop(true);
  }
}, 30_000);
