import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { platform } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { accountsHome, storePath } from "../src/storage.js";
import { liveClaudeBase } from "../src/lib/claude-layout.js";
import { keychainSupported, readClaudeKeychain, securityExecutable } from "../src/lib/keychain.js";
import { resolveStore } from "../src/lib/store.js";

test("test preload replaces inherited machine and cloud state before app resolution", async () => {
  const sentinelRoot = process.env.ACCOUNTS_TEST_EXPECTED_SENTINEL_ROOT;
  if (sentinelRoot) expect(process.env.ACCOUNTS_TEST_BOOTSTRAP_PROBE).toBe("1");

  for (const key of [
    "HASNA_ACCOUNTS_API_URL",
    "HASNA_ACCOUNTS_API_KEY",
    "ACCOUNTS_API_URL",
    "ACCOUNTS_API_KEY",
    "APP_API_URL",
    "APP_API_KEY",
    "HASNA_ACCOUNTS_TEST_DATABASE_URL",
    "HASNA_ACCOUNTS_DATABASE_URL",
    "ACCOUNTS_DATABASE_URL",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGSSLROOTCERT",
    "NODE_EXTRA_CA_CERTS",
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
  ]) {
    expect(process.env[key]).toBeUndefined();
  }
  expect(process.env.ACCOUNTS_REQUIRE_POSTGRES).toBeUndefined();
  for (const key of [
    "HASNA_ACCOUNTS_RUNTIME_ROLE",
    "HASNA_ACCOUNTS_API_SIGNING_KEY",
    "HASNA_API_SIGNING_KEY",
    "HOST",
    "PORT",
    "ACCOUNTS_SERVE_PORT",
    "ACCOUNTS_ACTIVE",
    "ACCOUNTS_SUPERVISOR",
    "ACCOUNTS_FORCE_INTERACTIVE",
    "ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS",
    "ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS",
    "ACCOUNTS_POSTGRES_TEST_TARGET",
    "CMD_RELAY_ENV",
    "COMSPEC",
  ]) {
    expect(process.env[key]).toBeUndefined();
  }
  for (const key of [
    "HASNA_ACCOUNTS_STORAGE_MODE",
    "ACCOUNTS_STORAGE_MODE",
    "HASNA_ACCOUNTS_MODE",
  ]) {
    expect(process.env[key]).toBe("local");
  }

  expect(accountsHome()).toBe(process.env.ACCOUNTS_HOME!);
  expect(process.env.HASNA_ACCOUNTS_HOME).toBe(accountsHome());
  expect(process.env.ACCOUNTS_STORE_PATH).toBeUndefined();
  expect(storePath()).toBe(join(accountsHome(), "accounts.json"));
  if (sentinelRoot) {
    expect(accountsHome().startsWith(sentinelRoot)).toBe(false);
  }
  const testRoot = dirname(accountsHome());

  if (platform() === "darwin") {
    expect(keychainSupported()).toBe(true);
    if (sentinelRoot) {
      expect(process.env.ACCOUNTS_TEST_SECURITY_BIN!.startsWith(sentinelRoot)).toBe(false);
    }
    expect(securityExecutable()).toBe(process.env.ACCOUNTS_TEST_SECURITY_BIN!);
    expect(readClaudeKeychain()).toBeUndefined();
  } else {
    expect(keychainSupported()).toBe(false);
    expect(process.env.ACCOUNTS_TEST_SECURITY_BIN).toBeUndefined();
  }
  if (sentinelRoot) expect(process.env.ACCOUNTS_TEST_LIVE_DIR!.startsWith(sentinelRoot)).toBe(false);
  expect(liveClaudeBase()).toBe(process.env.ACCOUNTS_TEST_LIVE_DIR!);
  if (sentinelRoot) {
    expect(process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH!.startsWith(sentinelRoot)).toBe(false);
  }
  for (const key of [
    "CLAUDE_CODE_API_KEY_HELPER",
    "CLAUDE_CODE_API_KEY_HELPER_TTL_MS",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
  ]) {
    expect(process.env[key]).toBeUndefined();
  }

  for (const key of [
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
    "TMPDIR",
    "TMP",
    "TEMP",
  ]) {
    const value = process.env[key]!;
    if (sentinelRoot) expect(value.startsWith(sentinelRoot)).toBe(false);
    const fromTestRoot = relative(testRoot, value);
    expect(fromTestRoot.startsWith("..") || isAbsolute(fromTestRoot)).toBe(false);
  }
  expect(process.env.HOMEDRIVE).toBeUndefined();
  expect(process.env.HOMEPATH).toBeUndefined();
  expect(process.env.HASNA_ACCOUNTS_MACHINE_ID).toBe("accounts-test-worker");
  expect(process.env.ACCOUNTS_MACHINE_ID).toBe("accounts-test-worker");
  if (sentinelRoot) expect(process.env.PATH!.includes(sentinelRoot)).toBe(false);
  if (platform() !== "win32") {
    expect(process.env.PATHEXT).toBeUndefined();
    expect(process.env.SHELL).toBe("/bin/sh");
  }

  const store = resolveStore();
  expect(store.transport).toBe("local");
  const profile = await store.addProfile({ name: "bootstrap-probe", tool: "claude" });
  expect(profile.dir.startsWith(accountsHome())).toBe(true);
  expect(existsSync(storePath())).toBe(true);
});
