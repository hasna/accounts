import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, useProfile } from "./lib/profiles.js";
import { getAccountsReadiness } from "./lib/readiness.js";
import { loadStore, saveStore } from "./storage.js";

let home: string;
let binDir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-readiness-"));
  binDir = mkdtempSync(join(tmpdir(), "accounts-readiness-bin-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});

function readinessEnv(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    PATH: `${binDir}:${process.env.PATH ?? ""}`,
    HASNA_ACCOUNTS_S3_BUCKET: "accounts-readiness-test",
    ...extra,
  };
}

function runHealthCli(args: string[] = [], extraEnv: Record<string, string | undefined> = {}) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", "health", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: readinessEnv(extraEnv),
  });
}

function writeFakeBin(name: string): void {
  const path = join(binDir, name);
  writeFileSync(path, ["#!/bin/sh", "exit 0"].join("\n"));
  chmodSync(path, 0o755);
}

function writeClaudeAuth(profileDir: string, email: string, expiresAt: number, token: string): void {
  writeFileSync(join(profileDir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }) + "\n");
  writeFileSync(
    join(profileDir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        accessToken: `${token}-access`,
        refreshToken: `${token}-refresh`,
        expiresAt,
      },
    }) + "\n",
  );
}

function markApplied(tool: string, name: string): void {
  const store = loadStore();
  store.applied[tool] = name;
  saveStore(store);
}

test("empty store returns an unavailable readiness contract", () => {
  const readiness = getAccountsReadiness({ env: readinessEnv() });

  expect(readiness.schema).toBe("hasna.accounts.readiness/v1");
  expect(readiness.ok).toBe(false);
  expect(readiness.status).toBe("unavailable");
  expect(readiness.checks.find((item) => item.id === "profiles")?.status).toBe("unavailable");
  expect(readiness.nextActions.join("\n")).toContain("accounts add <name>");
});

test("fake Claude profile reports sanitized login, provider, storage, and supervisor readiness", () => {
  writeFakeBin("claude");
  const profile = addProfile({ name: "work", tool: "claude", email: "work@example.test" });
  writeClaudeAuth(profile.dir, "work@example.test", Date.now() + 60_000, "secret-readiness-token");
  useProfile("work", "claude");
  markApplied("claude", "work");

  const readiness = getAccountsReadiness({ env: readinessEnv() });
  const profileReadiness = readiness.profiles.find((entry) => entry.name === "work");
  const provider = readiness.providers.find((entry) => entry.id === "claude");
  const json = JSON.stringify(readiness);

  expect(profileReadiness?.login.status).toBe("ok");
  expect(profileReadiness?.login.authStatus).toBe("ok");
  expect(profileReadiness?.login.oauthAccountPresent).toBe(true);
  expect(profileReadiness?.login.credentialPayloadPresent).toBe(true);
  expect(provider?.available).toBe(true);
  expect(provider?.status).toBe("ok");
  expect(readiness.storage.status).toBe("ok");
  expect(readiness.supervisors.find((entry) => entry.tool === "claude")?.status).toBe("missing");
  expect(json).not.toContain("secret-readiness-token");
  expect(json).not.toContain("refreshToken");
  expect(json).not.toContain("accessToken");
});

test("valid Claude credential wins over an older expired snapshot", () => {
  writeFakeBin("claude");
  const profile = addProfile({ name: "mixed", tool: "claude", email: "mixed@example.test" });
  writeClaudeAuth(profile.dir, "mixed@example.test", Date.now() + 60_000, "valid-secret-token");
  mkdirSync(join(profile.dir, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(profile.dir, ".accounts-auth", "credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        accessToken: "expired-secret-access",
        refreshToken: "expired-secret-refresh",
        expiresAt: Date.now() - 60_000,
      },
    }) + "\n",
  );

  const readiness = getAccountsReadiness({ env: readinessEnv() });
  const profileReadiness = readiness.profiles.find((entry) => entry.name === "mixed");
  const json = JSON.stringify(readiness);

  expect(profileReadiness?.login.status).toBe("ok");
  expect(profileReadiness?.login.authStatus).toBe("ok");
  expect(profileReadiness?.login.credentialPayloadValid).toBe(true);
  expect(profileReadiness?.login.credentialPayloadExpired).toBe(false);
  expect(json).not.toContain("valid-secret-token");
  expect(json).not.toContain("expired-secret");
});

test("expired Claude credential is unavailable without leaking credential contents", () => {
  writeFakeBin("claude");
  const profile = addProfile({ name: "expired", tool: "claude", email: "expired@example.test" });
  writeClaudeAuth(profile.dir, "expired@example.test", Date.now() - 60_000, "super-secret-refresh-token");

  const readiness = getAccountsReadiness({ env: readinessEnv() });
  const profileReadiness = readiness.profiles.find((entry) => entry.name === "expired");
  const json = JSON.stringify(readiness);

  expect(profileReadiness?.status).toBe("unavailable");
  expect(profileReadiness?.login.authStatus).toBe("expired");
  expect(profileReadiness?.login.credentialPayloadExpired).toBe(true);
  expect(profileReadiness?.nextActions.join("\n")).toContain("accounts login expired --tool claude");
  expect(json).not.toContain("super-secret-refresh-token");
  expect(json).not.toContain("refreshToken");
  expect(json).not.toContain("accessToken");
});

test("health CLI emits JSON and text readiness without leaking fixture secrets", () => {
  writeFakeBin("claude");
  const profile = addProfile({ name: "expired", tool: "claude", email: "expired@example.test" });
  writeClaudeAuth(profile.dir, "expired@example.test", Date.now() - 60_000, "cli-secret-token");

  const jsonResult = runHealthCli(["--json"]);
  expect(jsonResult.status).toBe(1);
  const payload = JSON.parse(jsonResult.stdout) as ReturnType<typeof getAccountsReadiness>;
  expect(payload.status).toBe("unavailable");
  expect(payload.profiles[0]?.login.authStatus).toBe("expired");
  expect(jsonResult.stdout).not.toContain("cli-secret-token");
  expect(jsonResult.stderr).not.toContain("cli-secret-token");

  const textResult = runHealthCli();
  expect(textResult.status).toBe(1);
  expect(textResult.stdout).toContain("Profile availability");
  expect(textResult.stdout).not.toContain("cli-secret-token");
  expect(textResult.stderr).not.toContain("cli-secret-token");
});
