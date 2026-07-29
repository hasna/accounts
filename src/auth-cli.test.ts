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

async function runCliAsync(env: NodeJS.ProcessEnv, ...args: string[]) {
  const child = Bun.spawn({
    cmd: [process.execPath, "run", "src/cli.ts", ...args],
    cwd: process.cwd(),
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
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

function writeParkedIdentity(dir: string, uuid: string, email: string): void {
  const authDir = join(dir, ".accounts-auth");
  mkdirSync(authDir, { recursive: true });
  writeFileSync(
    join(authDir, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }),
  );
  writeFileSync(
    join(authDir, "credentials.json"),
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

test("auth migrate reads every profile from the active API registry, not the local registry", async () => {
  const localDir = join(home, "local-only");
  writeIdentity(localDir, "44444444-dddd-4ddd-8ddd-444444444444", "local@example.com");
  expect(runCli("add", "local-only", "--dir", localDir).status).toBe(0);

  const remoteProfiles = [
    {
      name: "remote-one",
      tool: "claude",
      dir: join(home, "remote-one"),
      uuid: "55555555-eeee-4eee-8eee-555555555555",
      email: "remote-one@example.com",
    },
    {
      name: "remote-two",
      tool: "claude",
      dir: join(home, "remote-two"),
      uuid: "66666666-ffff-4fff-8fff-666666666666",
      email: "remote-two@example.com",
    },
  ];
  for (const profile of remoteProfiles) writeParkedIdentity(profile.dir, profile.uuid, profile.email);

  const requestedUrls: string[] = [];
  const api = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requestedUrls.push(request.url);
      return Response.json({
        accounts: remoteProfiles.map(({ uuid: _uuid, email, ...profile }) => ({
          ...profile,
          email,
          createdAt: "2026-01-01T00:00:00.000Z",
        })),
      });
    },
  });

  try {
    const migrate = await runCliAsync(
      {
        ...process.env,
        ACCOUNTS_HOME: home,
        HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: `http://127.0.0.1:${api.port}`,
        HASNA_ACCOUNTS_API_KEY: "hasna_accounts_testkey_0000",
      },
      "auth",
      "migrate",
      "--json",
    );
    expect(migrate.status, migrate.stderr).toBe(0);
    const rows = JSON.parse(migrate.stdout) as Array<{ profile: string; synced?: boolean }>;
    expect(rows.map((row) => row.profile)).toEqual(["remote-one", "remote-two"]);
    expect(rows.every((row) => row.synced)).toBe(true);
    expect(requestedUrls.some((url) => new URL(url).pathname === "/v1/accounts")).toBe(true);
    for (const profile of remoteProfiles) {
      expect(existsSync(join(home, "auth", profile.uuid, "credentials.json"))).toBe(true);
      expect(existsSync(join(home, "auth", profile.uuid, "oauth-account.json"))).toBe(true);
    }
  } finally {
    api.stop(true);
  }
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

test("auth status survives a profile with a malformed accountUuid and still lists healthy accounts", () => {
  // Vector 1: malformed uuid in the profile SNAPSHOT.
  const bad = join(home, "bad-profile");
  mkdirSync(join(bad, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(bad, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "not-a-uuid", emailAddress: "bad@example.com" } }),
  );
  expect(runCli("add", "badprof", "--dir", bad, "--email", "bad@example.com").status).toBe(0);

  // Vector 2: malformed uuid in the dir's LIVE .claude.json (Claude's own file).
  const worse = join(home, "worse-profile");
  mkdirSync(worse, { recursive: true });
  writeFileSync(
    join(worse, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "corrupted-value", emailAddress: "worse@example.com" } }),
  );
  expect(runCli("add", "worseprof", "--dir", worse, "--email", "worse@example.com").status).toBe(0);

  const good = join(home, "good-profile");
  writeIdentity(good, UUID, "good@example.com");
  expect(runCli("add", "goodprof", "--dir", good, "--email", "good@example.com").status).toBe(0);
  expect(runCli("auth", "migrate", "--json").status).toBe(0);

  const status = runCli("auth", "status", "--json");
  expect(status.status).toBe(0);
  const rows = JSON.parse(status.stdout) as Array<{ accountUuid: string; central: boolean }>;
  expect(rows.some((r) => r.accountUuid === UUID && r.central)).toBe(true);
  // Malformed identities are shown (not hidden, not fatal) and never claim central.
  const malformed = rows.filter((r) => r.accountUuid === "not-a-uuid" || r.accountUuid === "corrupted-value");
  expect(malformed.length).toBe(2);
  expect(malformed.every((r) => r.central === false)).toBe(true);
});
