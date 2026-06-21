import { test, expect, beforeEach, afterEach } from "bun:test";
import { execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync, chmodSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertSafeWritePath } from "./lib/safe-path.js";
import { assertAllowedKeychainCredential, keychainWriteFailureMessage, writeClaudeKeychain } from "./lib/keychain.js";
import { CLAUDE_KEYCHAIN_SERVICE } from "./lib/claude-layout.js";
import { saveStore, loadStore } from "./storage.js";
import { shellQuotePath, hookScript } from "./lib/hook.js";
import { withApplyLock } from "./lib/apply-lock.js";
import { AccountsError } from "./types.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-sec-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});

test("assertSafeWritePath refuses symlink target file", () => {
  const base = mkdtempSync(join(tmpdir(), "symlink-base-"));
  const target = join(base, "real.txt");
  const link = join(base, "link.txt");
  writeFileSync(target, "ok");
  symlinkSync(target, link);
  expect(() => assertSafeWritePath(link)).toThrow(AccountsError);
  rmSync(base, { recursive: true, force: true });
});

test("assertSafeWritePath refuses symlink directory under profile", () => {
  const profile = join(home, "profiles", "claude", "work");
  const authDir = join(profile, ".accounts-auth");
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  mkdirSync(profile, { recursive: true });
  symlinkSync(outside, authDir);
  expect(() =>
    assertSafeWritePath(join(authDir, "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
  rmSync(outside, { recursive: true, force: true });
});

test("assertSafeWritePath refuses writes outside mustStayUnder", () => {
  const profile = join(home, "profiles", "claude", "work");
  mkdirSync(profile, { recursive: true });
  const outside = join(home, "escape.json");
  expect(() => assertSafeWritePath(outside, { mustStayUnder: profile })).toThrow(AccountsError);
});

test("keychain allowlist rejects unexpected service", () => {
  expect(() =>
    assertAllowedKeychainCredential({
      service: "Other App",
      account: "claude",
      secret: "x",
    }),
  ).toThrow(AccountsError);
  expect(() =>
    assertAllowedKeychainCredential({
      service: CLAUDE_KEYCHAIN_SERVICE,
      account: 'x"; evil',
      secret: "token",
    }),
  ).toThrow(AccountsError);
});

test("writeClaudeKeychain rejects non-allowlisted service", () => {
  expect(() =>
    writeClaudeKeychain({
      service: "malicious-service",
      account: "claude",
      secret: "secret",
    }),
  ).toThrow(AccountsError);
});

test("keychain write failure messages do not include command arguments", () => {
  const message = keychainWriteFailureMessage({
    message: "Command failed: security add-generic-password -w secret-token",
    stderr: Buffer.from("security: SecKeychainItemCreateFromContent: User interaction is not allowed.\n"),
  });
  expect(message).toBe("security: SecKeychainItemCreateFromContent: User interaction is not allowed.");
  expect(message).not.toContain("secret-token");
});

test.skipIf(!existsSync("/var/folders"))("saveStore works when ACCOUNTS_HOME is under /var/folders temp", () => {
  const varHome = execSync("mktemp -d", { encoding: "utf8" }).trim();
  expect(varHome.startsWith("/var/folders/")).toBe(true);
  process.env.ACCOUNTS_HOME = varHome;
  delete process.env.ACCOUNTS_STORE_PATH;
  saveStore({ version: 1, current: {}, applied: {}, profiles: [], tools: [] });
  expect(existsSync(join(varHome, "accounts.json"))).toBe(true);
  rmSync(varHome, { recursive: true, force: true });
});

test("saveStore refuses writing through symlinked store path", () => {
  const realDir = join(home, "real");
  const linkPath = join(home, "accounts.json");
  mkdirSync(realDir, { recursive: true });
  writeFileSync(join(realDir, "accounts.json"), "{}");
  symlinkSync(join(realDir, "accounts.json"), linkPath);
  process.env.ACCOUNTS_STORE_PATH = linkPath;
  expect(() => saveStore(loadStore())).toThrow(AccountsError);
});

test("saveStore tightens permissions on an existing store file", () => {
  const path = join(home, "accounts.json");
  writeFileSync(path, JSON.stringify({ version: 1, profiles: [] }));
  chmodSync(path, 0o644);

  saveStore({ version: 1, current: {}, applied: {}, profiles: [], tools: [] });

  expect(statSync(path).mode & 0o777).toBe(0o600);
});

test("saveStore normalizes existing store permissions before writing", () => {
  const path = join(home, "accounts.json");
  writeFileSync(path, JSON.stringify({ version: 1, profiles: [] }));
  chmodSync(path, 0o400);

  saveStore({
    version: 1,
    current: { claude: "work" },
    applied: {},
    profiles: [{ name: "work", tool: "claude", dir: join(home, "profiles", "work"), createdAt: "2026-01-01T00:00:00.000Z" }],
    tools: [],
  });

  expect(loadStore().current.claude).toBe("work");
  expect(statSync(path).mode & 0o777).toBe(0o600);
});

test("ACCOUNTS_HOME with newline is rejected on save", () => {
  process.env.ACCOUNTS_HOME = "/tmp/bad\n/home";
  expect(() => saveStore(loadStore())).toThrow(AccountsError);
});

test("shellQuotePath escapes single quotes in hook path", () => {
  const quoted = shellQuotePath("/tmp/it's/hook.sh");
  expect(quoted).toBe("'/tmp/it'\\''s/hook.sh'");
  process.env.ACCOUNTS_HOME = "/tmp/it's";
  expect(hookScript()).toContain("'/tmp/it'\\''s/claude-hook.sh'");
});

test("withApplyLock creates mode 600 lock file", () => {
  withApplyLock(() => {
    const lock = join(home, ".apply.lock");
    expect(existsSync(lock)).toBe(true);
    expect(statSync(lock).mode & 0o777).toBe(0o600);
  });
  expect(existsSync(join(home, ".apply.lock"))).toBe(false);
});

test("withApplyLock rejects concurrent apply", () => {
  const lock = join(home, ".apply.lock");
  writeFileSync(lock, "99999\n");
  chmodSync(lock, 0o600);
  expect(() => withApplyLock(() => undefined)).toThrow(AccountsError);
});
