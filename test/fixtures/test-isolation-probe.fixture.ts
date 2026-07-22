import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { accountsHome, storePath } from "../../src/storage.js";
import { liveClaudeBase } from "../../src/lib/claude-layout.js";
import { keychainSupported, readClaudeKeychain, securityExecutable } from "../../src/lib/keychain.js";
import { resolveStore } from "../../src/lib/store.js";

test("test preload replaces inherited machine and cloud state before app resolution", async () => {
  expect(process.env.ACCOUNTS_TEST_BOOTSTRAP_PROBE).toBe("1");
  const sentinelRoot = process.env.ACCOUNTS_TEST_EXPECTED_SENTINEL_ROOT;
  expect(sentinelRoot).toBeTruthy();

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
  ]) {
    expect(process.env[key]).toBeUndefined();
  }
  expect(process.env.ACCOUNTS_REQUIRE_POSTGRES).toBeUndefined();
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
  expect(accountsHome().startsWith(sentinelRoot!)).toBe(false);
  expect(dirname(accountsHome()).startsWith(dirname(sentinelRoot!))).toBe(true);

  if (platform() === "darwin") {
    expect(keychainSupported()).toBe(true);
    expect(process.env.ACCOUNTS_TEST_SECURITY_BIN!.startsWith(sentinelRoot!)).toBe(false);
    expect(securityExecutable()).toBe(process.env.ACCOUNTS_TEST_SECURITY_BIN!);
    expect(readClaudeKeychain()).toBeUndefined();
  } else {
    expect(keychainSupported()).toBe(false);
    expect(process.env.ACCOUNTS_TEST_SECURITY_BIN).toBeUndefined();
  }
  expect(process.env.ACCOUNTS_TEST_LIVE_DIR!.startsWith(sentinelRoot!)).toBe(false);
  expect(liveClaudeBase()).toBe(process.env.ACCOUNTS_TEST_LIVE_DIR!);
  expect(process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH!.startsWith(sentinelRoot!)).toBe(false);
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
  ]) {
    expect(process.env[key]!.startsWith(sentinelRoot!)).toBe(false);
  }

  const store = resolveStore();
  expect(store.transport).toBe("local");
  const profile = await store.addProfile({ name: "bootstrap-probe", tool: "claude" });
  expect(profile.dir.startsWith(accountsHome())).toBe(true);
  expect(existsSync(storePath())).toBe(true);
});
