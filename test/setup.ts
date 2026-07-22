import { afterAll, beforeEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

const workerRoot = mkdtempSync(join(tmpdir(), "accounts-bun-test-"));
const fakeSecurityExecutable = join(workerRoot, "security-not-found");
const postgresOptIn = process.env.ACCOUNTS_REQUIRE_POSTGRES === "1";
let testIndex = 0;

writeFileSync(fakeSecurityExecutable, "#!/bin/sh\nexit 44\n", { mode: 0o700 });

const remoteConfigurationKeys = [
  "HASNA_ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_URL",
  "ACCOUNTS_API_KEY",
  "APP_API_URL",
  "APP_API_KEY",
  "HASNA_ACCOUNTS_DATABASE_URL",
  "ACCOUNTS_DATABASE_URL",
] as const;

const postgresConfigurationKeys = [
  "HASNA_ACCOUNTS_TEST_DATABASE_URL",
] as const;

const inheritedProcessHookKeys = [
  "ACCOUNTS_ACTIVE",
  "ACCOUNTS_SUPERVISOR",
  "ACCOUNTS_TEST_SECURITY_BIN",
  "ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS",
  "CLAUDE_CODE_API_KEY_HELPER",
  "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
  "ANTHROPIC_API_KEY",
  "ANTHROPIC_AUTH_TOKEN",
  "ANTHROPIC_BASE_URL",
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
] as const;

const toolHomeKeys = [
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

function resetTestEnvironment(): void {
  const testRoot = join(workerRoot, `case-${testIndex++}`);
  const accountsHome = join(testRoot, "accounts-home");
  const liveHome = join(testRoot, "live-home");
  const toolHomes = join(testRoot, "tool-homes");

  mkdirSync(accountsHome, { recursive: true });
  mkdirSync(liveHome, { recursive: true });
  mkdirSync(toolHomes, { recursive: true });

  for (const key of remoteConfigurationKeys) delete process.env[key];
  for (const key of inheritedProcessHookKeys) delete process.env[key];
  if (!postgresOptIn) {
    for (const key of postgresConfigurationKeys) delete process.env[key];
    delete process.env.ACCOUNTS_REQUIRE_POSTGRES;
  }

  process.env.NODE_ENV = "test";
  process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
  process.env.ACCOUNTS_STORAGE_MODE = "local";
  process.env.HASNA_ACCOUNTS_MODE = "local";

  process.env.ACCOUNTS_HOME = accountsHome;
  process.env.HASNA_ACCOUNTS_HOME = accountsHome;
  delete process.env.ACCOUNTS_STORE_PATH;

  process.env.ACCOUNTS_TEST_KEYCHAIN = platform() === "darwin" ? "1" : "0";
  if (platform() === "darwin") process.env.ACCOUNTS_TEST_SECURITY_BIN = fakeSecurityExecutable;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveHome;
  process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH = join(testRoot, "keychain.lock");

  for (const key of toolHomeKeys) {
    process.env[key] = join(toolHomes, key.toLowerCase());
  }
}

// Run once before application test modules load, then again before each test so
// per-file cleanup cannot expose a later test to inherited machine state.
resetTestEnvironment();
beforeEach(resetTestEnvironment);

afterAll(() => {
  rmSync(workerRoot, { recursive: true, force: true });
});
