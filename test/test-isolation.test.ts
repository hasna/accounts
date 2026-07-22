import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

test("bare Bun tests fail closed when cloud and live-machine variables are inherited", () => {
  const sentinelRoot = mkdtempSync(join(tmpdir(), "accounts-inherited-sentinel-"));
  const inheritedEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ACCOUNTS_TEST_BOOTSTRAP_PROBE: "1",
    ACCOUNTS_TEST_EXPECTED_SENTINEL_ROOT: sentinelRoot,
    HASNA_ACCOUNTS_API_URL: "http://127.0.0.1:1",
    HASNA_ACCOUNTS_API_KEY: "sentinel-hasna-key",
    ACCOUNTS_API_URL: "http://127.0.0.1:1",
    ACCOUNTS_API_KEY: "sentinel-fallback-key",
    APP_API_URL: "http://127.0.0.1:1",
    APP_API_KEY: "sentinel-app-key",
    HASNA_ACCOUNTS_TEST_DATABASE_URL: "postgresql://sentinel.invalid/accounts",
    HASNA_ACCOUNTS_DATABASE_URL: "postgresql://sentinel.invalid/accounts",
    ACCOUNTS_DATABASE_URL: "postgresql://sentinel.invalid/accounts",
    ACCOUNTS_REQUIRE_POSTGRES: "0",
    HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
    ACCOUNTS_STORAGE_MODE: "self_hosted",
    HASNA_ACCOUNTS_MODE: "cloud",
    ACCOUNTS_HOME: sentinelRoot,
    HASNA_ACCOUNTS_HOME: sentinelRoot,
    ACCOUNTS_STORE_PATH: join(sentinelRoot, "accounts.json"),
    ACCOUNTS_TEST_KEYCHAIN: "1",
    ACCOUNTS_TEST_SECURITY_BIN: join(sentinelRoot, "real-security-hook"),
    ACCOUNTS_TEST_LIVE_DIR: join(sentinelRoot, "live-home"),
    ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH: join(sentinelRoot, "keychain.lock"),
    CLAUDE_CODE_API_KEY_HELPER: join(sentinelRoot, "credential-helper"),
    CLAUDE_CODE_API_KEY_HELPER_TTL_MS: "60000",
    ANTHROPIC_API_KEY: "sentinel-anthropic-key",
    ANTHROPIC_AUTH_TOKEN: "sentinel-anthropic-token",
    ANTHROPIC_BASE_URL: "http://127.0.0.1:1",
    CLAUDE_CODE_USE_BEDROCK: "1",
    CLAUDE_CODE_USE_VERTEX: "1",
  };
  for (const key of inheritedToolHomeKeys) inheritedEnv[key] = join(sentinelRoot, key.toLowerCase());

  try {
    const child = Bun.spawnSync({
      cmd: [
        process.execPath,
        "test",
        "./test/fixtures/test-isolation-probe.fixture.ts",
        "--max-concurrency",
        "1",
      ],
      cwd: process.cwd(),
      env: inheritedEnv,
      stdout: "pipe",
      stderr: "pipe",
    });

    expect(child.exitCode, `${child.stdout.toString()}\n${child.stderr.toString()}`).toBe(0);
    expect(existsSync(join(sentinelRoot, "accounts.json"))).toBe(false);
    expect(existsSync(join(sentinelRoot, "keychain.lock"))).toBe(false);
  } finally {
    rmSync(sentinelRoot, { recursive: true, force: true });
  }
});

test("explicit PostgreSQL integration opt-in keeps the isolated test URL", () => {
  const sentinelUrl = "postgresql://sentinel.invalid/accounts";
  const child = Bun.spawnSync({
    cmd: [
      process.execPath,
      "test",
      "./test/fixtures/postgres-opt-in.fixture.ts",
      "--max-concurrency",
      "1",
    ],
    cwd: process.cwd(),
    env: {
      ...process.env,
      ACCOUNTS_TEST_POSTGRES_PROBE: "1",
      ACCOUNTS_TEST_EXPECTED_POSTGRES_URL: sentinelUrl,
      ACCOUNTS_REQUIRE_POSTGRES: "1",
      HASNA_ACCOUNTS_TEST_DATABASE_URL: sentinelUrl,
      HASNA_ACCOUNTS_DATABASE_URL: sentinelUrl,
      ACCOUNTS_DATABASE_URL: sentinelUrl,
    },
    stdout: "pipe",
    stderr: "pipe",
  });

  expect(child.exitCode, `${child.stdout.toString()}\n${child.stderr.toString()}`).toBe(0);
});
