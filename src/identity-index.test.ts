import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  accessTokenForAccount,
  buildIdentityIndex,
  centralAuthDir,
} from "./lib/identity-index.js";
import { getTool } from "./lib/tools.js";

let home: string;
let root: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-idx-home-"));
  root = mkdtempSync(join(tmpdir(), "accounts-idx-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

interface DirFixture {
  uuid: string;
  email: string;
  expiresInMs?: number;
  accessToken?: string;
}

function writeLive(dir: string, f: DirFixture): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: f.uuid, emailAddress: f.email } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credentialJson(f));
}

function writeSnapshot(dir: string, f: DirFixture): void {
  const auth = join(dir, ".accounts-auth");
  mkdirSync(auth, { recursive: true });
  writeFileSync(
    join(auth, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: f.uuid, emailAddress: f.email } }),
  );
  writeFileSync(join(auth, "credentials.json"), credentialJson(f));
}

function credentialJson(f: DirFixture): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: f.accessToken ?? `${f.email}-access`,
      refreshToken: `${f.email}-refresh`,
      expiresAt: Date.now() + (f.expiresInMs ?? 60_000),
    },
  });
}

function makeDir(name: string): string {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

test("two dirs holding the same accountUuid collapse into ONE identity with two doors", () => {
  const a = makeDir("account-a");
  const b = makeDir("account-b");
  writeLive(a, { uuid: "uuid-shared", email: "one@example.com" });
  writeSnapshot(a, { uuid: "uuid-shared", email: "one@example.com" });
  writeLive(b, { uuid: "uuid-shared", email: "one@example.com" });
  writeSnapshot(b, { uuid: "uuid-shared", email: "one@example.com" });

  const index = buildIdentityIndex(
    [
      { name: "a", dir: a },
      { name: "b", dir: b },
    ],
    tool(),
  );
  expect(index).toHaveLength(1);
  const identity = index[0]!;
  expect(identity.accountUuid).toBe("uuid-shared");
  expect(identity.email).toBe("one@example.com");
  expect(new Set(identity.doors.map((d) => d.dir))).toEqual(new Set([a, b]));
  expect(identity.status).toBe("ok");
});

test("a switched dir maps its LIVE occupant and its OWN snapshot to different identities", () => {
  // account003-style: dir's own identity is "owner@", but the live files hold
  // "guest@" after an in-place switch. The guest's token must never be
  // attributed to the owner's uuid.
  const dir = makeDir("switched");
  writeLive(dir, { uuid: "uuid-guest", email: "guest@example.com", accessToken: "guest-token" });
  writeSnapshot(dir, { uuid: "uuid-owner", email: "owner@example.com", accessToken: "owner-token" });

  const index = buildIdentityIndex([{ name: "switched", dir }], tool());
  expect(index.map((i) => i.accountUuid).sort()).toEqual(["uuid-guest", "uuid-owner"]);

  const guest = index.find((i) => i.accountUuid === "uuid-guest")!;
  const owner = index.find((i) => i.accountUuid === "uuid-owner")!;
  expect(accessTokenForAccount(guest)).toBe("guest-token");
  expect(accessTokenForAccount(owner)).toBe("owner-token");
  expect(guest.doors.some((d) => d.role === "current-occupant")).toBe(true);
  expect(owner.doors.some((d) => d.role === "own-identity")).toBe(true);
});

test("an aged-out access token with a refresh token reports needs-refresh, not a crash and not expired", () => {
  // This assertion used to read `expired`, and the word was wrong: the fixture
  // has always carried a refresh token, so the account is alive and the tool
  // renews it on next use. Reporting it as `expired` is the defect — six live
  // accounts read as dead from it on 2026-07-29 — so the expectation is
  // corrected here rather than preserved. `expired` keeps a test of its own
  // below, with a fixture that is actually dead.
  const dir = makeDir("aged-out");
  writeLive(dir, { uuid: "uuid-exp", email: "tired@example.com", expiresInMs: -60_000 });
  writeSnapshot(dir, { uuid: "uuid-exp", email: "tired@example.com", expiresInMs: -60_000 });

  const index = buildIdentityIndex([{ name: "aged-out", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.credential?.renewable).toBe(true);
  expect(index[0]!.status).toBe("needs-refresh");
  // Unchanged: no VALID access token, so nothing is handed out.
  expect(accessTokenForAccount(index[0]!)).toBeUndefined();
});

test("an account with no refresh token reports expired — the word now means genuinely dead", () => {
  const dir = makeDir("dead");
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(dir, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "uuid-dead", emailAddress: "dead@example.com" } }),
  );
  writeFileSync(
    join(dir, ".accounts-auth", "credentials.json"),
    // No refreshToken key at all: re-authentication is the only fix.
    JSON.stringify({
      claudeAiOauth: { accessToken: "SYNTHETIC-dead-access", expiresAt: Date.now() - 60_000 },
    }),
  );

  const index = buildIdentityIndex([{ name: "dead", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.credential?.renewable).toBe(false);
  expect(index[0]!.status).toBe("expired");
  expect(accessTokenForAccount(index[0]!)).toBeUndefined();
});

test("identity files without credentials report no-credentials; dirs with neither are skipped", () => {
  const noCreds = makeDir("no-creds");
  mkdirSync(join(noCreds, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(noCreds, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "uuid-nc", emailAddress: "nc@example.com" } }),
  );
  const emptyDir = makeDir("empty");
  writeFileSync(join(emptyDir, ".claude.json"), JSON.stringify({}));

  const index = buildIdentityIndex(
    [
      { name: "no-creds", dir: noCreds },
      { name: "empty", dir: emptyDir },
      { name: "missing", dir: join(root, "does-not-exist") },
    ],
    tool(),
  );
  expect(index).toHaveLength(1);
  expect(index[0]!.accountUuid).toBe("uuid-nc");
  expect(index[0]!.status).toBe("no-credentials");
});

test("the central auth home is read FIRST and enumerates accounts with no profile door", () => {
  // Future layout from the .accounts-auth migration (task 7840d1da):
  // ~/.hasna/accounts/auth/<accountUuid>/{oauth-account.json,credentials.json}.
  const central = centralAuthDir("cccccccc-1111-4111-8111-cccccccc1111");
  expect(central).toBe(join(home, "auth", "cccccccc-1111-4111-8111-cccccccc1111"));
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "cccccccc-1111-4111-8111-cccccccc1111", emailAddress: "central@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "cccccccc-1111-4111-8111-cccccccc1111", email: "central@example.com", accessToken: "central-token" }),
  );

  const index = buildIdentityIndex([], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.accountUuid).toBe("cccccccc-1111-4111-8111-cccccccc1111");
  expect(index[0]!.status).toBe("ok");
  expect(index[0]!.credential?.source).toBe("central");
  expect(accessTokenForAccount(index[0]!)).toBe("central-token");
});

test("when central and profile stores both know an account, the central credential wins ties", () => {
  const dir = makeDir("dup");
  writeLive(dir, { uuid: "dddddddd-2222-4222-8222-dddddddd2222", email: "dup@example.com", accessToken: "profile-token" });
  writeSnapshot(dir, { uuid: "dddddddd-2222-4222-8222-dddddddd2222", email: "dup@example.com", accessToken: "profile-token" });

  const central = centralAuthDir("dddddddd-2222-4222-8222-dddddddd2222");
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "dddddddd-2222-4222-8222-dddddddd2222", emailAddress: "dup@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "dddddddd-2222-4222-8222-dddddddd2222", email: "dup@example.com", accessToken: "central-token" }),
  );

  const index = buildIdentityIndex([{ name: "dup", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.credential?.source).toBe("central");
  // Doors from the profile layer are still attached to the identity.
  expect(index[0]!.doors.some((d) => d.dir === dir)).toBe(true);
});

test("a fresher profile credential beats a stale central one — validity outranks location", () => {
  const dir = makeDir("fresh");
  writeLive(dir, { uuid: "ffffffff-3333-4333-8333-ffffffff3333", email: "fresh@example.com", accessToken: "profile-token" });
  writeSnapshot(dir, { uuid: "ffffffff-3333-4333-8333-ffffffff3333", email: "fresh@example.com", accessToken: "profile-token" });

  const central = centralAuthDir("ffffffff-3333-4333-8333-ffffffff3333");
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "ffffffff-3333-4333-8333-ffffffff3333", emailAddress: "fresh@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "ffffffff-3333-4333-8333-ffffffff3333", email: "fresh@example.com", accessToken: "stale-token", expiresInMs: -60_000 }),
  );

  const index = buildIdentityIndex([{ name: "fresh", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.status).toBe("ok");
  expect(accessTokenForAccount(index[0]!)).toBe("profile-token");
});

test("case-variant payload uuids collapse into ONE identity (central uppercase vs snapshot lowercase)", () => {
  const UP = "ABCDABCD-1234-4ABC-8ABC-ABCDABCD1234";
  const low = UP.toLowerCase();

  const central = centralAuthDir(low);
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UP, emailAddress: "case@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: UP, email: "case@example.com", accessToken: "central-token" }),
  );

  const dir = makeDir("case");
  writeSnapshot(dir, { uuid: low, email: "case@example.com", accessToken: "profile-token" });

  const index = buildIdentityIndex([{ name: "case", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.accountUuid).toBe(low);
});

test("central scan skips non-UUID directory names (parity with listCentralAccounts)", () => {
  const evil = join(home, "auth", "not-a-uuid");
  mkdirSync(evil, { recursive: true });
  writeFileSync(
    join(evil, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "not-a-uuid", emailAddress: "evil@example.com" } }),
  );
  writeFileSync(join(evil, "credentials.json"), credentialJson({ uuid: "not-a-uuid", email: "evil@example.com" }));

  const index = buildIdentityIndex([], tool());
  expect(index).toHaveLength(0);
});
