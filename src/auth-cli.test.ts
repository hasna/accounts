import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

// --- credential → account binding (todos bc32e38c) ----------------------------

const UUID_OTHER = "44444444-dddd-4ddd-8ddd-444444444444";

/** Write a central entry directly: identity file plus credential file. */
function seedCentral(uuid: string, email: string, refreshToken: string): void {
  const dir = join(home, "auth", uuid);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }),
  );
  writeFileSync(
    join(dir, "credentials.json"),
    JSON.stringify({
      claudeAiOauth: { accessToken: `${email}-access`, refreshToken, expiresAt: Date.now() + 60_000 },
    }),
  );
}

test("auth bindings reports a clean estate and exits 0", () => {
  seedCentral(UUID, "one@example.com", "one-refresh");
  seedCentral(UUID_OTHER, "two@example.com", "two-refresh");

  const json = runCli("auth", "bindings", "--json");
  expect(json.status).toBe(0);
  const payload = JSON.parse(json.stdout) as {
    method: string;
    bindings: Array<{ accountUuid: string; fingerprint?: string }>;
    conflicts: unknown[];
  };
  expect(payload.method).toBe("sha256-refresh-token/v1");
  expect(payload.bindings.map((b) => b.accountUuid).sort()).toEqual([UUID, UUID_OTHER].sort());
  expect(payload.conflicts).toEqual([]);
  // Two distinct accounts, two distinct fingerprints — the property the
  // conflict check rests on, asserted rather than assumed.
  expect(new Set(payload.bindings.map((b) => b.fingerprint)).size).toBe(2);
  // Never a token value, in any encoding this command could emit.
  expect(json.stdout).not.toContain("one-refresh");
  expect(json.stdout).not.toContain("two-refresh");
});

test("auth bindings flags one credential claimed by two accounts and exits 1", () => {
  seedCentral(UUID, "one@example.com", "shared-refresh");
  seedCentral(UUID_OTHER, "two@example.com", "shared-refresh");

  const json = runCli("auth", "bindings", "--json");
  // Non-zero on a corrupt estate: a scripted caller must not be able to read
  // "the command ran" as "the estate is fine".
  expect(json.status).toBe(1);
  const payload = JSON.parse(json.stdout) as {
    conflicts: Array<{ accountUuids: string[]; emails: string[] }>;
  };
  expect(payload.conflicts.length).toBe(1);
  expect(payload.conflicts[0]!.accountUuids.sort()).toEqual([UUID, UUID_OTHER].sort());
  expect(json.stdout).not.toContain("shared-refresh");

  const human = runCli("auth", "bindings");
  expect(human.status).toBe(1);
  expect(human.stdout).toContain("claimed by 2");
  expect(human.stdout).not.toContain("shared-refresh");
});

test("auth migrate REFUSES to file a credential another account already claims, and exits 1", () => {
  // The other account legitimately owns `shared-refresh`: it is that account's
  // credential of record in its own central slot.
  seedCentral(UUID_OTHER, "two@example.com", "shared-refresh");

  // This profile's identity files all say UUID; only its credential bytes are
  // the other account's. Every containment gate passes.
  const dir = join(home, "contaminated-profile");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID, emailAddress: "one@example.com" } }),
  );
  writeFileSync(
    join(dir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: { accessToken: "x-access", refreshToken: "shared-refresh", expiresAt: Date.now() + 60_000 },
    }),
  );
  expect(runCli("add", "oneprof", "--dir", dir, "--email", "one@example.com").status).toBe(0);

  const migrate = runCli("auth", "migrate", "--json");
  expect(migrate.status).toBe(1);
  const rows = JSON.parse(migrate.stdout) as Array<Record<string, unknown>>;
  const row = rows.find((r) => r.profile === "oneprof");
  expect(row?.credentials).toBe("refused");
  expect(String(row?.credentialsReason)).toContain("bound to another account");
  // Nothing was filed under this account.
  expect(existsSync(join(home, "auth", UUID, "credentials.json"))).toBe(false);
  // And the account that does own the credential is untouched.
  expect(
    JSON.parse(readFileSync(join(home, "auth", UUID_OTHER, "credentials.json"), "utf8")).claudeAiOauth
      .refreshToken,
  ).toBe("shared-refresh");
});
