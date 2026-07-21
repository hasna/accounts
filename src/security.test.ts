import { test, expect, beforeEach, afterEach } from "bun:test";
import { execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync, chmodSync, statSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import { assertSafeWritePath } from "./lib/safe-path.js";
import {
  assertAllowedKeychainCredential,
  keychainWriteFailureMessage,
  readClaudeKeychain,
  securityExecutable,
  writeClaudeKeychain,
} from "./lib/keychain.js";
import { CLAUDE_KEYCHAIN_SERVICE } from "./lib/claude-layout.js";
import { saveStore, loadStore } from "./storage.js";
import { shellQuotePath, hookScript } from "./lib/hook.js";
import { withApplyLock, withApplyLockWait } from "./lib/apply-lock.js";
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

test("assertSafeWritePath refuses symlinked mustStayUnder root", () => {
  const profiles = join(home, "profiles", "claude");
  const profile = join(profiles, "work");
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  mkdirSync(profiles, { recursive: true });
  symlinkSync(outside, profile);
  expect(() =>
    assertSafeWritePath(join(profile, ".accounts-auth", "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
  rmSync(outside, { recursive: true, force: true });
});

test("assertSafeWritePath refuses dangling symlink mustStayUnder root", () => {
  const profiles = join(home, "profiles", "claude");
  const profile = join(profiles, "work");
  mkdirSync(profiles, { recursive: true });
  symlinkSync(join(home, "missing-target"), profile);
  expect(() =>
    assertSafeWritePath(join(profile, ".accounts-auth", "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
});

test("assertSafeWritePath refuses symlink ancestors before creating mustStayUnder root", () => {
  const profiles = join(home, "profiles");
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  const toolDir = join(profiles, "claude");
  const profile = join(toolDir, "work");
  mkdirSync(profiles, { recursive: true });
  symlinkSync(outside, toolDir);

  expect(() =>
    assertSafeWritePath(join(profile, ".accounts-auth", "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
  expect(existsSync(join(outside, "work"))).toBe(false);
  rmSync(outside, { recursive: true, force: true });
});

test("assertSafeWritePath refuses existing symlink ancestors under mustStayUnder root", () => {
  const profiles = join(home, "profiles");
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  const toolDir = join(profiles, "claude");
  const profile = join(toolDir, "work");
  mkdirSync(profiles, { recursive: true });
  mkdirSync(join(outside, "work"), { recursive: true });
  symlinkSync(outside, toolDir);

  expect(() =>
    assertSafeWritePath(join(profile, "created", "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
  expect(existsSync(join(outside, "work", "created"))).toBe(false);
  rmSync(outside, { recursive: true, force: true });
});

test("assertSafeWritePath refuses symlink directories before creating nested parents", () => {
  const profile = join(home, "profiles", "claude", "work");
  const outside = mkdtempSync(join(tmpdir(), "outside-"));
  const link = join(profile, "link");
  mkdirSync(profile, { recursive: true });
  symlinkSync(outside, link);

  expect(() =>
    assertSafeWritePath(join(link, "nested", "oauth-account.json"), { mustStayUnder: profile }),
  ).toThrow(AccountsError);
  expect(existsSync(join(outside, "nested"))).toBe(false);
  rmSync(outside, { recursive: true, force: true });
});

test("assertSafeWritePath allows descendant names that start with two dots", () => {
  const profile = join(home, "profiles", "claude", "work");
  const target = join(profile, "..legit", "oauth-account.json");
  mkdirSync(profile, { recursive: true });

  expect(assertSafeWritePath(target, { mustStayUnder: profile })).toBe(join(profile, "..legit"));
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

test.skipIf(platform() !== "darwin")("keychain commands use the macOS security executable", () => {
  expect(securityExecutable()).toBe("/usr/bin/security");
});

test("test security executable override is gated by NODE_ENV=test", () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalTestKeychain = process.env.ACCOUNTS_TEST_KEYCHAIN;
  const originalSecurityBin = process.env.ACCOUNTS_TEST_SECURITY_BIN;
  try {
    delete process.env.NODE_ENV;
    process.env.ACCOUNTS_TEST_KEYCHAIN = "1";
    process.env.ACCOUNTS_TEST_SECURITY_BIN = "/tmp/fake-security";

    expect(securityExecutable()).toBe("/usr/bin/security");

    process.env.NODE_ENV = "test";
    expect(securityExecutable()).toBe("/tmp/fake-security");
  } finally {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (originalTestKeychain === undefined) delete process.env.ACCOUNTS_TEST_KEYCHAIN;
    else process.env.ACCOUNTS_TEST_KEYCHAIN = originalTestKeychain;
    if (originalSecurityBin === undefined) delete process.env.ACCOUNTS_TEST_SECURITY_BIN;
    else process.env.ACCOUNTS_TEST_SECURITY_BIN = originalSecurityBin;
  }
});

test.skipIf(platform() !== "darwin")("keychain reads use macOS security when PATH is shadowed", () => {
  const fakeBinDir = mkdtempSync(join(tmpdir(), "fake-security-bin-"));
  const fakeSecurity = join(fakeBinDir, "security");
  const fakeLog = join(fakeBinDir, "called.log");
  writeFileSync(
    fakeSecurity,
    ["#!/usr/bin/env bash", `printf 'shadowed security called\\n' >> ${JSON.stringify(fakeLog)}`, "exit 1"].join("\n"),
  );
  chmodSync(fakeSecurity, 0o755);

  const originalPath = process.env.PATH;
  process.env.PATH = `${fakeBinDir}:${originalPath ?? ""}`;
  let fakeCalled = false;
  try {
    readClaudeKeychain();
    fakeCalled = existsSync(fakeLog);
  } finally {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    rmSync(fakeBinDir, { recursive: true, force: true });
  }

  expect(fakeCalled).toBe(false);
});

test.skipIf(!existsSync("/var/folders"))("saveStore works when ACCOUNTS_HOME is under /var/folders temp", () => {
  const varHome = execSync("mktemp -d", { encoding: "utf8" }).trim();
  expect(varHome.startsWith("/var/folders/")).toBe(true);
  process.env.ACCOUNTS_HOME = varHome;
  delete process.env.ACCOUNTS_STORE_PATH;
  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });
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

  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });

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
    toolLocks: {},
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

test("withApplyLockWait serializes rollback behind an in-flight apply", async () => {
  const lock = join(home, ".apply.lock");
  writeFileSync(lock, "99999\n", { mode: 0o600 });
  setTimeout(() => rmSync(lock, { force: true }), 30);
  expect(await withApplyLockWait(() => "restored", { timeoutMs: 500, pollMs: 5 })).toBe("restored");
  expect(existsSync(lock)).toBe(false);
});
