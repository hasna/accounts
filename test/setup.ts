import { afterAll, beforeEach } from "bun:test";
import { copyFileSync, linkSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import {
  executableFilename,
  resolveControlledTestParent,
} from "./support/isolation-paths.js";

const postgresIntegrationFile = resolve(process.cwd(), "src/server/postgres.integration.ts");
const normalizedPostgresIntegrationFile = normalizePath(postgresIntegrationFile);
const explicitPostgresTarget = process.argv.length === 2
  && isAbsolute(process.argv[1]!)
  && normalizePath(process.argv[1]!) === normalizedPostgresIntegrationFile;
const postgresOptIn = process.env.ACCOUNTS_REQUIRE_POSTGRES === "1"
  && process.env.ACCOUNTS_POSTGRES_TEST_TARGET === "1"
  && explicitPostgresTarget;
const postgresTestDatabaseUrl = postgresOptIn
  ? process.env.HASNA_ACCOUNTS_TEST_DATABASE_URL
  : undefined;

// Never let inherited temp variables or an OS fallback select the test root.
// The postgres launcher may provide a unique child only under this controlled,
// ignored worktree-local directory so it can clean the entire launch in finally.
const testRootParent = resolveControlledTestParent(
  process.cwd(),
  postgresOptIn ? process.env.ACCOUNTS_TEST_ROOT_PARENT : undefined,
);
mkdirSync(testRootParent, { recursive: true });
const workerRoot = mkdtempSync(join(testRootParent, "worker-"));
const safeBin = join(workerRoot, "safe-bin");
let testIndex = 0;
let cleaned = false;
process.once("exit", cleanupWorkerRoot);

mkdirSync(safeBin, { recursive: true });
const blockedProcessSource = join(workerRoot, "blocked-process.ts");
const blockedProcessExecutable = join(workerRoot, executableFilename("blocked-process"));
writeFileSync(blockedProcessSource, "process.exit(86);\n");
const compilerEnvironment: Record<string, string> = {
  HOME: workerRoot,
  USERPROFILE: workerRoot,
  TMPDIR: workerRoot,
  TMP: workerRoot,
  TEMP: workerRoot,
};
for (const key of ["SystemRoot", "WINDIR"] as const) {
  if (process.env[key]) compilerEnvironment[key] = process.env[key]!;
}
const blockedProcessBuild = Bun.spawnSync({
  cmd: [
    process.execPath,
    "build",
    "--compile",
    blockedProcessSource,
    "--outfile",
    blockedProcessExecutable,
  ],
  cwd: process.cwd(),
  env: compilerEnvironment,
  stdout: "pipe",
  stderr: "pipe",
});
if (blockedProcessBuild.exitCode !== 0) {
  throw new Error(`failed to compile isolated process blocker (exit ${blockedProcessBuild.exitCode})`);
}

function linkOrCopy(source: string, target: string): void {
  try {
    linkSync(source, target);
  } catch {
    copyFileSync(source, target);
  }
}

for (const executable of [
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
]) {
  linkOrCopy(blockedProcessExecutable, join(safeBin, executableFilename(executable)));
}

const safeBunExecutable = join(safeBin, executableFilename("bun"));
linkOrCopy(process.execPath, safeBunExecutable);

const remoteConfigurationKeys = [
  "HASNA_ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_URL",
  "ACCOUNTS_API_KEY",
  "APP_API_URL",
  "APP_API_KEY",
  "HASNA_ACCOUNTS_DATABASE_URL",
  "ACCOUNTS_DATABASE_URL",
  "HASNA_ACCOUNTS_S3_BUCKET",
  "HASNA_ACCOUNTS_S3_PREFIX",
  "HASNA_ACCOUNTS_AWS_REGION",
  "HASNA_ACCOUNTS_S3_ENDPOINT",
  "HASNA_ACCOUNTS_S3_FORCE_PATH_STYLE",
  "ACCOUNTS_S3_BUCKET",
  "ACCOUNTS_S3_PREFIX",
  "ACCOUNTS_AWS_REGION",
  "ACCOUNTS_S3_ENDPOINT",
  "ACCOUNTS_S3_FORCE_PATH_STYLE",
] as const;

const serverConfigurationKeys = [
  "HASNA_ACCOUNTS_RUNTIME_ROLE",
  "HASNA_ACCOUNTS_API_SIGNING_KEY",
  "HASNA_API_SIGNING_KEY",
  "HOST",
  "PORT",
  "ACCOUNTS_SERVE_PORT",
] as const;

const postgresConfigurationKeys = [
  "HASNA_ACCOUNTS_TEST_DATABASE_URL",
  "ACCOUNTS_REQUIRE_POSTGRES",
  "PGHOST",
  "PGHOSTADDR",
  "PGPORT",
  "PGDATABASE",
  "PGUSER",
  "PGPASSWORD",
  "PGPASSFILE",
  "PGSERVICE",
  "PGSERVICEFILE",
  "PGOPTIONS",
  "PGAPPNAME",
  "PGSSLMODE",
  "PGSSLROOTCERT",
  "PGSSLCERT",
  "PGSSLKEY",
  "PGSSLCRL",
  "PGSSLCRLDIR",
  "PGCHANNELBINDING",
  "NODE_EXTRA_CA_CERTS",
] as const;

const inheritedProcessHookKeys = [
  "ACCOUNTS_ACTIVE",
  "ACCOUNTS_SUPERVISOR",
  "ACCOUNTS_FORCE_INTERACTIVE",
  "ACCOUNTS_TEST_SECURITY_BIN",
  "ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS",
  "ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS",
  "ACCOUNTS_POSTGRES_TEST_TARGET",
  "ACCOUNTS_TEST_ROOT_PARENT",
  "ACCOUNTS_TEST_LAUNCH_ID",
  "CMD_RELAY_ENV",
  "CLAUDE_CODE_API_KEY_HELPER",
  "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "ANTHROPIC_AWS_API_KEY",
  "ANTHROPIC_FEDERATION_RULE_ID",
  "ANTHROPIC_FOUNDRY_API_KEY",
  "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
  "ANTHROPIC_ORGANIZATION_ID",
  "AWS_BEARER_TOKEN_BEDROCK",
  "CLOUDSDK_AUTH_ACCESS_TOKEN",
  "CLAUDE_CODE_HFI_BEARER_TOKEN",
  "CLAUDE_CODE_HOST_CREDS_FILE",
  "CLAUDE_CODE_OAUTH_TOKEN",
  "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
  "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
  "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
  "CLAUDE_TRUSTED_DEVICE_TOKEN",
] as const;

const isolatedDirectoryKeys = [
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

function normalizePath(path: string): string {
  const absolute = resolve(path);
  return platform() === "win32" ? absolute.toLowerCase() : absolute;
}

function resetTestEnvironment(): void {
  const testRoot = join(workerRoot, `case-${testIndex++}`);
  const accountsHome = join(testRoot, "accounts-home");
  const liveHome = join(testRoot, "live-home");
  const isolatedHomes = join(testRoot, "isolated-homes");
  const isolatedTemp = join(testRoot, "tmp");

  for (const path of [accountsHome, liveHome, isolatedHomes, isolatedTemp]) {
    mkdirSync(path, { recursive: true });
  }

  for (const key of remoteConfigurationKeys) delete process.env[key];
  for (const key of serverConfigurationKeys) delete process.env[key];
  for (const key of postgresConfigurationKeys) delete process.env[key];
  for (const key of inheritedProcessHookKeys) delete process.env[key];
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("FAKE_")) delete process.env[key];
    if (key.toLowerCase() === "path") delete process.env[key];
  }

  process.env.NODE_ENV = "test";
  process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
  process.env.ACCOUNTS_STORAGE_MODE = "local";
  process.env.HASNA_ACCOUNTS_MODE = "local";
  process.env.HASNA_ACCOUNTS_MACHINE_ID = "accounts-test-worker";
  process.env.ACCOUNTS_MACHINE_ID = "accounts-test-worker";

  process.env.ACCOUNTS_HOME = accountsHome;
  process.env.HASNA_ACCOUNTS_HOME = accountsHome;
  delete process.env.ACCOUNTS_STORE_PATH;

  for (const key of isolatedDirectoryKeys) {
    process.env[key] = join(isolatedHomes, key.toLowerCase());
  }
  delete process.env.HOMEDRIVE;
  delete process.env.HOMEPATH;
  process.env.TMPDIR = isolatedTemp;
  process.env.TMP = isolatedTemp;
  process.env.TEMP = isolatedTemp;

  const pathDirectories = [safeBin];
  if (platform() === "win32") {
    const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
    if (systemRoot) pathDirectories.push(join(systemRoot, "System32"));
    delete process.env.COMSPEC;
    process.env.PATHEXT = ".COM;.EXE;.BAT;.CMD";
  } else {
    pathDirectories.push("/usr/bin", "/bin");
    process.env.SHELL = "/bin/sh";
    delete process.env.PATHEXT;
    delete process.env.COMSPEC;
  }
  process.env.PATH = [...new Set(pathDirectories)].join(delimiter);

  process.env.ACCOUNTS_TEST_KEYCHAIN = platform() === "darwin" ? "1" : "0";
  if (platform() === "darwin") process.env.ACCOUNTS_TEST_SECURITY_BIN = blockedProcessExecutable;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveHome;
  process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH = join(testRoot, "keychain.lock");

  if (postgresOptIn) {
    process.env.ACCOUNTS_REQUIRE_POSTGRES = "1";
    if (postgresTestDatabaseUrl) {
      process.env.HASNA_ACCOUNTS_TEST_DATABASE_URL = postgresTestDatabaseUrl;
    }
  }
}

function cleanupWorkerRoot(): void {
  if (cleaned) return;
  rmSync(workerRoot, {
    recursive: true,
    force: true,
    maxRetries: 3,
    retryDelay: 25,
  });
  cleaned = true;
}

// Run once before application test modules load, then again before each test so
// per-file cleanup cannot expose a later test to inherited machine state.
resetTestEnvironment();
beforeEach(resetTestEnvironment);
afterAll(cleanupWorkerRoot);
