import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home },
  });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-auth-cli-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const UUID = "33333333-cccc-4ccc-8ccc-333333333333";

function writeIdentity(dir: string, uuid: string, email: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }));
  writeFileSync(
    join(dir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: { accessToken: `${email}-access`, refreshToken: `${email}-refresh`, expiresAt: Date.now() + 60_000 },
    }),
  );
}

test("auth migrate populates the central store and auth status reports it", () => {
  const dir = join(home, "external-profile");
  writeIdentity(dir, UUID, "cli@example.com");
  const add = runCli("add", "cliprof", "--dir", dir, "--email", "cli@example.com");
  expect(add.status).toBe(0);

  const migrate = runCli("auth", "migrate", "--json");
  expect(migrate.status).toBe(0);
  const rows = JSON.parse(migrate.stdout) as Array<Record<string, unknown>>;
  const row = rows.find((r) => r.profile === "cliprof");
  expect(row?.synced).toBe(true);
  expect(row?.uuid).toBe(UUID);
  expect(existsSync(join(home, "auth", UUID, "credentials.json"))).toBe(true);
  expect(existsSync(join(home, "auth", UUID, "oauth-account.json"))).toBe(true);

  const status = runCli("auth", "status", "--json");
  expect(status.status).toBe(0);
  const accounts = JSON.parse(status.stdout) as Array<{
    accountUuid: string;
    email?: string;
    central: boolean;
    doors: Array<{ role: string; profileName?: string }>;
  }>;
  const account = accounts.find((a) => a.accountUuid === UUID);
  expect(account?.central).toBe(true);
  expect(account?.email).toBe("cli@example.com");
  expect(account?.doors.some((d) => d.role === "own-identity" && d.profileName === "cliprof")).toBe(true);
});

test("auth sweep dry-runs by default and only --delete trashes orphans", () => {
  // Central entry with no profile referencing it.
  const orphanDir = join(home, "auth", UUID);
  mkdirSync(orphanDir, { recursive: true });
  writeFileSync(join(orphanDir, "oauth-account.json"), JSON.stringify({ oauthAccount: { accountUuid: UUID } }));
  writeFileSync(join(orphanDir, "credentials.json"), JSON.stringify({ claudeAiOauth: {} }));

  const dry = runCli("auth", "sweep", "--json");
  expect(dry.status).toBe(0);
  const dryResult = JSON.parse(dry.stdout) as { deleted: boolean; orphans: Array<{ uuid: string }> };
  expect(dryResult.deleted).toBe(false);
  expect(dryResult.orphans.map((o) => o.uuid)).toEqual([UUID]);
  expect(existsSync(orphanDir)).toBe(true);

  const del = runCli("auth", "sweep", "--json", "--delete");
  expect(del.status).toBe(0);
  const delResult = JSON.parse(del.stdout) as { deleted: boolean; orphans: Array<{ uuid: string; trashedTo?: string }> };
  expect(delResult.deleted).toBe(true);
  expect(existsSync(orphanDir)).toBe(false);
  expect(existsSync(join(delResult.orphans[0]!.trashedTo!, "credentials.json"))).toBe(true);
});
