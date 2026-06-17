import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      FAKE_LOGIN_LOG: logPath,
      PATH: `${binDir}:${process.env.PATH ?? ""}`,
    },
  });
}

test("login infers the tool for an existing profile", () => {
  const fakeBin = join(binDir, "fake-login-tool");
  writeFileSync(
    fakeBin,
    [
      "#!/usr/bin/env node",
      "const fs = require('node:fs');",
      "fs.appendFileSync(process.env.FAKE_LOGIN_LOG, JSON.stringify({",
      "  args: process.argv.slice(2),",
      "  home: process.env.FAKE_LOGIN_HOME,",
      "}) + '\\n');",
    ].join("\n"),
  );
  chmodSync(fakeBin, 0o755);

  expect(
    runCli(
      "tools",
      "add",
      "fake-login",
      "--label",
      "Fake Login",
      "--env-var",
      "FAKE_LOGIN_HOME",
      "--bin",
      "fake-login-tool",
      "--login-arg",
      "auth",
      "login",
    ).status,
  ).toBe(0);
  expect(runCli("add", "acct", "--tool", "fake-login").status).toBe(0);

  const result = runCli("login", "acct");

  expect(result.status).toBe(0);
  const entries = readFileSync(logPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as { args: string[]; home: string });
  expect(entries).toHaveLength(1);
  expect(entries[0]?.args).toEqual(["auth", "login"]);
  expect(entries[0]?.home).toContain("fake-login/acct");
});

