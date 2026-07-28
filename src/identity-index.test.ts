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

test("an account whose only credential is expired reports status expired, not a crash", () => {
  const dir = makeDir("expired");
  writeLive(dir, { uuid: "uuid-exp", email: "tired@example.com", expiresInMs: -60_000 });
  writeSnapshot(dir, { uuid: "uuid-exp", email: "tired@example.com", expiresInMs: -60_000 });

  const index = buildIdentityIndex([{ name: "expired", dir }], tool());
  expect(index).toHaveLength(1);
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
  const central = centralAuthDir("uuid-central");
  expect(central).toBe(join(home, "auth", "uuid-central"));
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "uuid-central", emailAddress: "central@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "uuid-central", email: "central@example.com", accessToken: "central-token" }),
  );

  const index = buildIdentityIndex([], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.accountUuid).toBe("uuid-central");
  expect(index[0]!.status).toBe("ok");
  expect(index[0]!.credential?.source).toBe("central");
  expect(accessTokenForAccount(index[0]!)).toBe("central-token");
});

test("when central and profile stores both know an account, the central credential wins ties", () => {
  const dir = makeDir("dup");
  writeLive(dir, { uuid: "uuid-dup", email: "dup@example.com", accessToken: "profile-token" });
  writeSnapshot(dir, { uuid: "uuid-dup", email: "dup@example.com", accessToken: "profile-token" });

  const central = centralAuthDir("uuid-dup");
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "uuid-dup", emailAddress: "dup@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "uuid-dup", email: "dup@example.com", accessToken: "central-token" }),
  );

  const index = buildIdentityIndex([{ name: "dup", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.credential?.source).toBe("central");
  // Doors from the profile layer are still attached to the identity.
  expect(index[0]!.doors.some((d) => d.dir === dir)).toBe(true);
});

test("a fresher profile credential beats a stale central one — validity outranks location", () => {
  const dir = makeDir("fresh");
  writeLive(dir, { uuid: "uuid-fresh", email: "fresh@example.com", accessToken: "profile-token" });
  writeSnapshot(dir, { uuid: "uuid-fresh", email: "fresh@example.com", accessToken: "profile-token" });

  const central = centralAuthDir("uuid-fresh");
  mkdirSync(central, { recursive: true });
  writeFileSync(
    join(central, "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "uuid-fresh", emailAddress: "fresh@example.com" } }),
  );
  writeFileSync(
    join(central, "credentials.json"),
    credentialJson({ uuid: "uuid-fresh", email: "fresh@example.com", accessToken: "stale-token", expiresInMs: -60_000 }),
  );

  const index = buildIdentityIndex([{ name: "fresh", dir }], tool());
  expect(index).toHaveLength(1);
  expect(index[0]!.status).toBe("ok");
  expect(accessTokenForAccount(index[0]!)).toBe("profile-token");
});
