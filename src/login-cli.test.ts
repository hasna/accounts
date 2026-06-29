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
      `printf '{"tool":"${toolName}","args":"%s","home":"%s"}\\n' "$*" "$home" >> "$FAKE_LOGIN_LOG"`,
      `exit ${exitCode}`,
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
  expect(
    runCli(
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
    ).status,
  ).toBe(0);
}

function readLogEntries() {
  if (!existsSync(logPath)) return [];
  return readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { tool: string; args: string; home: string });
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

  const result = runCliWith(["launch", "acct", "--tool", "claude", "--", "--version"], {
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
