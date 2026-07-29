import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AccountsStore } from "./lib/store.js";
import { collectAccountsUsage } from "./lib/usage-report.js";

let home: string;
let root: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-usage-home-"));
  root = mkdtempSync(join(tmpdir(), "accounts-usage-report-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

function expiredCredentials(): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: "expired-test-token",
      refreshToken: "test-refresh-token",
      expiresAt: Date.now() - 60_000,
    },
  });
}

function writeIdentity(path: string, accountUuid: string, email: string): void {
  writeFileSync(path, JSON.stringify({ oauthAccount: { accountUuid, emailAddress: email } }));
}

test("a squatted profile reports its unavailable owner as occupied, not expired", async () => {
  const dir = join(root, "owner-profile");
  const snapshot = join(dir, ".accounts-auth");
  mkdirSync(snapshot, { recursive: true });

  writeIdentity(join(snapshot, "oauth-account.json"), "uuid-owner", "owner@example.com");
  writeFileSync(join(snapshot, "credentials.json"), expiredCredentials());
  writeIdentity(join(dir, ".claude.json"), "uuid-guest", "guest@example.com");
  writeFileSync(join(dir, ".credentials.json"), expiredCredentials());

  const store = {
    listProfiles: async () => [{ name: "owner", tool: "claude", dir, createdAt: new Date().toISOString() }],
  } as AccountsStore;
  const entries = await collectAccountsUsage({}, store);

  expect(entries.find((entry) => entry.accountUuid === "uuid-owner")).toMatchObject({
    status: "occupied",
    profiles: ["owner"],
    occupies: [],
  });
  expect(entries.find((entry) => entry.accountUuid === "uuid-guest")).toMatchObject({
    status: "expired",
    profiles: [],
    occupies: ["owner"],
  });
});
