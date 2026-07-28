import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, removeProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot, restoreClaudeAuthIntoDir } from "./lib/claude-auth.js";
import { profileCredentialsSnapshot, profileOAuthSnapshot } from "./lib/claude-layout.js";
import {
  centralAuthDir,
  centralCredentialsSnapshot,
  centralOAuthSnapshot,
  listCentralAccounts,
  listKnownAccounts,
  profileAccountUuid,
  sweepCentralAuth,
  syncProfileSnapshotToCentral,
} from "./lib/auth-store.js";
import { importProfile } from "./lib/import-profile.js";
import { getTool } from "./lib/tools.js";
import { AccountsError } from "./types.js";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-authstore-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-authstore-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

interface IdentityFixture {
  uuid: string;
  email: string;
  expiresInMs?: number;
  refreshToken?: string | null;
}

function credentialJson(fixture: IdentityFixture): string {
  const { email, expiresInMs = 60_000, refreshToken = `${email}-refresh` } = fixture;
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${email}-access`,
      ...(refreshToken === null ? {} : { refreshToken }),
      expiresAt: Date.now() + expiresInMs,
    },
  });
}

function writeIdentity(dir: string, fixture: IdentityFixture): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: fixture.uuid, emailAddress: fixture.email } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credentialJson(fixture));
}

function makeProfile(name: string, fixture: IdentityFixture): string {
  const dir = mkdtempSync(join(tmpdir(), `authstore-${name}-`));
  writeIdentity(dir, fixture);
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

function centralAccessToken(uuid: string): string {
  const data = readJson(centralCredentialsSnapshot(uuid)) as { claudeAiOauth?: { accessToken?: string } };
  return data.claudeAiOauth?.accessToken ?? "";
}

/** Backdate a file so mtime-based freshness comparisons see it as old. */
function backdate(path: string, secondsAgo: number): void {
  const t = new Date(Date.now() - secondsAgo * 1000);
  utimesSync(path, t, t);
}

const UUID_A = "11111111-aaaa-4aaa-8aaa-111111111111";
const UUID_B = "22222222-bbbb-4bbb-8bbb-222222222222";

// --- layout ------------------------------------------------------------------

test("central store paths live under ACCOUNTS_HOME/auth keyed by account uuid", () => {
  expect(centralAuthDir(UUID_A)).toBe(join(home, "auth", UUID_A));
  expect(centralOAuthSnapshot(UUID_A)).toBe(join(home, "auth", UUID_A, "oauth-account.json"));
  expect(centralCredentialsSnapshot(UUID_A)).toBe(join(home, "auth", UUID_A, "credentials.json"));
});

test("central store rejects uuids that are not safe path segments", () => {
  for (const bad of ["../evil", "a/b", "", " ", "x".repeat(80), "..", "uuid\0"]) {
    expect(() => centralAuthDir(bad)).toThrow(AccountsError);
  }
});

// --- binding resolution ------------------------------------------------------

test("profileAccountUuid resolves from the per-profile oauth snapshot", () => {
  const dir = makeProfile("bind", { uuid: UUID_A, email: "a@example.com" });
  expect(profileAccountUuid(dir, tool())).toBe(UUID_A);
});

test("profileAccountUuid falls back to the dir account file when no snapshot exists", () => {
  const dir = mkdtempSync(join(tmpdir(), "authstore-bindfile-"));
  writeIdentity(dir, { uuid: UUID_B, email: "b@example.com" });
  expect(profileAccountUuid(dir, tool())).toBe(UUID_B);
});

// --- sync / migration --------------------------------------------------------

test("ensureProfileAuthSnapshot mirrors the snapshot into the central store", () => {
  const dir = makeProfile("mirror", { uuid: UUID_A, email: "a@example.com" });
  expect(existsSync(centralCredentialsSnapshot(UUID_A))).toBe(true);
  expect(existsSync(centralOAuthSnapshot(UUID_A))).toBe(true);
  // byte-identical to the per-profile snapshot it mirrors
  expect(readFileSync(centralCredentialsSnapshot(UUID_A), "utf8")).toBe(
    readFileSync(profileCredentialsSnapshot(dir), "utf8"),
  );
  // per-profile snapshot still present (compat window for 0.2.15 binaries)
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(true);
  expect(existsSync(profileOAuthSnapshot(dir))).toBe(true);
});

test("sync never downgrades central: an expired no-refresh candidate loses to a valid central", () => {
  makeProfile("good", { uuid: UUID_A, email: "good@example.com" });
  const goodToken = centralAccessToken(UUID_A);

  // Second profile, same account uuid, but a strictly worse credential.
  const worse = mkdtempSync(join(tmpdir(), "authstore-worse-"));
  writeIdentity(worse, { uuid: UUID_A, email: "good@example.com", refreshToken: null, expiresInMs: -60_000 });
  addProfile({ name: "worse", dir: worse });
  ensureProfileAuthSnapshot(worse, tool());

  expect(centralAccessToken(UUID_A)).toBe(goodToken);
  // loser's own per-profile snapshot is untouched, not deleted
  expect(existsSync(profileCredentialsSnapshot(worse))).toBe(true);
});

test("sync upgrades central when the candidate credential is better", () => {
  const stale = mkdtempSync(join(tmpdir(), "authstore-stale-"));
  writeIdentity(stale, { uuid: UUID_A, email: "acct@example.com", refreshToken: null, expiresInMs: -60_000 });
  addProfile({ name: "stale", dir: stale });
  ensureProfileAuthSnapshot(stale, tool());
  expect(centralAccessToken(UUID_A)).toBe("acct@example.com-access");

  const fresh = makeProfile("fresh", { uuid: UUID_A, email: "fresh@example.com" });
  expect(centralAccessToken(UUID_A)).toBe("fresh@example.com-access");
  expect(existsSync(profileCredentialsSnapshot(fresh))).toBe(true);
});

test("duplicate-pair merge: newer valid refresh token wins, loser snapshot preserved in place", () => {
  const older = mkdtempSync(join(tmpdir(), "authstore-old-"));
  writeIdentity(older, { uuid: UUID_A, email: "dup@example.com", expiresInMs: 5_000 });
  addProfile({ name: "older", dir: older });
  ensureProfileAuthSnapshot(older, tool());
  backdate(profileCredentialsSnapshot(older), 3600);

  const newer = mkdtempSync(join(tmpdir(), "authstore-new-"));
  writeIdentity(newer, { uuid: UUID_A, email: "dup2@example.com", expiresInMs: 120_000 });
  addProfile({ name: "newer", dir: newer });
  ensureProfileAuthSnapshot(newer, tool());

  expect(centralAccessToken(UUID_A)).toBe("dup2@example.com-access");
  expect(existsSync(profileCredentialsSnapshot(older))).toBe(true);
  expect(existsSync(profileCredentialsSnapshot(newer))).toBe(true);
});

test("syncProfileSnapshotToCentral reports what it did", () => {
  const dir = mkdtempSync(join(tmpdir(), "authstore-report-"));
  writeIdentity(dir, { uuid: UUID_A, email: "r@example.com" });
  addProfile({ name: "report", dir });
  ensureProfileAuthSnapshot(dir, tool());

  // Re-running against an identical snapshot must be a no-op, not a rewrite.
  const again = syncProfileSnapshotToCentral(dir, tool());
  expect(again.synced).toBe(true);
  expect(again.uuid).toBe(UUID_A);
  expect(again.credentials).toBe("kept");

  const unbound = mkdtempSync(join(tmpdir(), "authstore-unbound-"));
  mkdirSync(unbound, { recursive: true });
  const none = syncProfileSnapshotToCentral(unbound, tool());
  expect(none.synced).toBe(false);
});

// --- read-both fallback (the survival scenario) ------------------------------

test("restore works from central alone after the per-profile snapshot is lost", () => {
  const dir = makeProfile("survivor", { uuid: UUID_A, email: "s@example.com" });

  // Simulate dir rebuild: identity file remains, credentials + snapshot gone.
  rmSync(join(dir, ".accounts-auth"), { recursive: true, force: true });
  rmSync(join(dir, ".credentials.json"), { force: true });
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(false);

  const target = mkdtempSync(join(tmpdir(), "authstore-target-"));
  restoreClaudeAuthIntoDir(dir, tool(), target, "survivor");
  const restored = readJson(join(target, ".credentials.json")) as { claudeAiOauth?: { accessToken?: string } };
  expect(restored.claudeAiOauth?.accessToken).toBe("s@example.com-access");
});

test("read prefers the better credential when per-profile and central diverge (old-binary window)", () => {
  const dir = makeProfile("window", { uuid: UUID_A, email: "w@example.com" });

  // A 0.2.15 binary rotates the per-profile snapshot AFTER central was written.
  writeFileSync(
    profileCredentialsSnapshot(dir),
    credentialJson({ uuid: UUID_A, email: "rotated@example.com", expiresInMs: 600_000 }),
  );
  backdate(centralCredentialsSnapshot(UUID_A), 3600);

  const target = mkdtempSync(join(tmpdir(), "authstore-target2-"));
  restoreClaudeAuthIntoDir(dir, tool(), target, "window");
  const restored = readJson(join(target, ".credentials.json")) as { claudeAiOauth?: { accessToken?: string } };
  expect(restored.claudeAiOauth?.accessToken).toBe("rotated@example.com-access");
});

// --- mtime tier of betterCredential (the compat-window ordering) -------------
// These two must fail against an expiry-ordered implementation: mtime recency
// outranks expiresAt for usable credentials in BOTH directions.

test("sync: a fresher-mtime candidate with SHORTER expiry replaces an older central with longer expiry", () => {
  const dir = makeProfile("mtimesync", { uuid: UUID_A, email: "long@example.com", expiresInMs: 600_000 });
  backdate(centralCredentialsSnapshot(UUID_A), 7200);
  backdate(join(dir, ".credentials.json"), 3600);

  writeFileSync(
    profileCredentialsSnapshot(dir),
    credentialJson({ uuid: UUID_A, email: "short@example.com", expiresInMs: 120_000 }),
  );
  const result = syncProfileSnapshotToCentral(dir, tool());
  expect(result.credentials).toBe("updated");
  expect(centralAccessToken(UUID_A)).toBe("short@example.com-access");
});

test("restore: a fresher-mtime central with SHORTER expiry beats an older per-profile snapshot with longer expiry", () => {
  const dir = makeProfile("mtimerestore", { uuid: UUID_A, email: "profile@example.com", expiresInMs: 600_000 });
  // Age everything the profile holds; then plant a fresher central rotation.
  backdate(join(dir, ".credentials.json"), 7200);
  backdate(profileCredentialsSnapshot(dir), 7200);
  writeFileSync(
    centralCredentialsSnapshot(UUID_A),
    credentialJson({ uuid: UUID_A, email: "central@example.com", expiresInMs: 120_000 }),
  );

  const target = mkdtempSync(join(tmpdir(), "authstore-mtime-target-"));
  restoreClaudeAuthIntoDir(dir, tool(), target, "mtimerestore");
  const restored = readJson(join(target, ".credentials.json")) as { claudeAiOauth?: { accessToken?: string } };
  expect(restored.claudeAiOauth?.accessToken).toBe("central@example.com-access");
});

// --- switch markers must not contaminate the central store -------------------

function switchAwayDir(dir: string, marker: unknown): void {
  // The dir's LIVE files now carry a foreign account's fresher identity.
  writeFileSync(join(dir, ".accounts-auth", "switched-account.json"), JSON.stringify(marker));
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_B, emailAddress: "foreign@example.com" } }),
  );
  writeFileSync(
    join(dir, ".credentials.json"),
    credentialJson({ uuid: UUID_B, email: "foreign@example.com", expiresInMs: 900_000 }),
  );
}

test("a validly-marked switched-away dir never leaks foreign live tokens into central", () => {
  const dir = makeProfile("marked", { uuid: UUID_A, email: "owner@example.com" });
  const ownToken = centralAccessToken(UUID_A);
  switchAwayDir(dir, { profile: "other", email: "foreign@example.com" });

  const result = syncProfileSnapshotToCentral(dir, tool());
  expect(result.uuid).toBe(UUID_A);
  expect(centralAccessToken(UUID_A)).toBe(ownToken);
  expect(existsSync(centralAuthDir(UUID_B))).toBe(false);
});

test("a CORRUPT marker fails closed: still no foreign contamination of central", () => {
  const dir = makeProfile("corruptmarked", { uuid: UUID_A, email: "owner2@example.com" });
  const ownToken = centralAccessToken(UUID_A);
  switchAwayDir(dir, { profile: 42 });

  const result = syncProfileSnapshotToCentral(dir, tool());
  expect(result.uuid).toBe(UUID_A);
  expect(centralAccessToken(UUID_A)).toBe(ownToken);
  expect(existsSync(centralAuthDir(UUID_B))).toBe(false);
});

// --- literal {} payloads (exist on two live profiles) ------------------------

test("a literal {} credentials payload never beats a real credential and is upgraded by one", () => {
  const empty = mkdtempSync(join(tmpdir(), "authstore-empty-"));
  mkdirSync(join(empty, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(empty, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "empty@example.com" } }),
  );
  writeFileSync(join(empty, ".accounts-auth", "credentials.json"), "{}");
  addProfile({ name: "empty", dir: empty });

  // {} arrives first: stored as-is (identity preserved, no fake credential invented).
  let result = syncProfileSnapshotToCentral(empty, tool());
  expect(result.credentials).toBe("created");
  expect(readFileSync(centralCredentialsSnapshot(UUID_A), "utf8")).toBe("{}");

  // A real credential upgrades the {} central copy.
  makeProfile("real", { uuid: UUID_A, email: "real@example.com" });
  expect(centralAccessToken(UUID_A)).toBe("real@example.com-access");

  // Re-syncing the {} profile never downgrades central back.
  result = syncProfileSnapshotToCentral(empty, tool());
  expect(result.credentials).toBe("kept");
  expect(centralAccessToken(UUID_A)).toBe("real@example.com-access");
});

// --- purge policy ------------------------------------------------------------

test("removeProfile --purge deletes the managed dir but never the central entry", async () => {
  // Managed dir (under profilesDir) so purge actually deletes it.
  const src = mkdtempSync(join(tmpdir(), "authstore-purgesrc-"));
  writeIdentity(src, { uuid: UUID_A, email: "p@example.com" });
  const profile = await importProfile({ name: "purgeme", dir: src, copy: true });
  expect(existsSync(centralCredentialsSnapshot(UUID_A))).toBe(true);

  const result = removeProfile("purgeme", { purge: true });
  expect(result.purged).toBe(true);
  expect(existsSync(profile.dir)).toBe(false);
  expect(existsSync(centralCredentialsSnapshot(UUID_A))).toBe(true);
});

// --- orphan sweep ------------------------------------------------------------

test("sweep lists orphaned central entries and only --delete moves them to trash", () => {
  makeProfile("kept", { uuid: UUID_A, email: "kept@example.com" });

  // Orphan: central entry with no profile bound to it.
  mkdirSync(centralAuthDir(UUID_B), { recursive: true });
  writeFileSync(centralCredentialsSnapshot(UUID_B), credentialJson({ uuid: UUID_B, email: "orphan@example.com" }));
  writeFileSync(
    centralOAuthSnapshot(UUID_B),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_B, emailAddress: "orphan@example.com" } }),
  );

  const dryRun = sweepCentralAuth();
  expect(dryRun.orphans.map((o) => o.uuid)).toEqual([UUID_B]);
  expect(dryRun.deleted).toBe(false);
  expect(dryRun.unresolved).toEqual([]);
  expect(existsSync(centralAuthDir(UUID_B))).toBe(true);

  const swept = sweepCentralAuth({ delete: true });
  expect(swept.deleted).toBe(true);
  expect(swept.orphans.map((o) => o.uuid)).toEqual([UUID_B]);
  expect(existsSync(centralAuthDir(UUID_B))).toBe(false);
  // never destroyed outright: bytes moved to a trash dir under the accounts home
  const trashed = swept.orphans[0]?.trashedTo;
  expect(trashed).toBeTruthy();
  expect(trashed!.startsWith(join(home, "auth-trash"))).toBe(true);
  expect(existsSync(join(trashed!, "credentials.json"))).toBe(true);
  // referenced entry untouched
  expect(existsSync(centralCredentialsSnapshot(UUID_A))).toBe(true);
});

test("sweep refuses --delete while any registered profile's binding is unresolvable", () => {
  makeProfile("resolved", { uuid: UUID_A, email: "resolved@example.com" });

  // Registered profile whose dir vanished: its central entry must survive.
  const gone = mkdtempSync(join(tmpdir(), "authstore-gone-"));
  writeIdentity(gone, { uuid: UUID_B, email: "gone@example.com" });
  addProfile({ name: "gone", dir: gone });
  ensureProfileAuthSnapshot(gone, tool());
  expect(existsSync(centralCredentialsSnapshot(UUID_B))).toBe(true);
  rmSync(gone, { recursive: true, force: true });

  const dry = sweepCentralAuth();
  expect(dry.unresolved.map((u) => u.profile)).toEqual(["gone"]);
  // Unknown is not unreferenced: delete is blocked entirely.
  expect(() => sweepCentralAuth({ delete: true })).toThrow(AccountsError);
  expect(existsSync(centralCredentialsSnapshot(UUID_B))).toBe(true);
  expect(existsSync(centralCredentialsSnapshot(UUID_A))).toBe(true);
});

test("sweep refuses outright in api storage mode", () => {
  process.env.HASNA_ACCOUNTS_STORAGE_MODE = "cloud";
  process.env.HASNA_ACCOUNTS_API_URL = "https://accounts.example.com";
  process.env.HASNA_ACCOUNTS_API_KEY = "test-placeholder";
  try {
    expect(() => sweepCentralAuth()).toThrow(/local storage mode/);
  } finally {
    process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
    delete process.env.HASNA_ACCOUNTS_API_URL;
    delete process.env.HASNA_ACCOUNTS_API_KEY;
  }
});

// --- import ------------------------------------------------------------------

test("import --copy registers an unknown account in the central store", async () => {
  const src = mkdtempSync(join(tmpdir(), "authstore-import-"));
  writeIdentity(src, { uuid: UUID_B, email: "imported@example.com" });
  expect(existsSync(centralAuthDir(UUID_B))).toBe(false);

  await importProfile({ name: "imported", dir: src, copy: true });
  expect(existsSync(centralCredentialsSnapshot(UUID_B))).toBe(true);
  expect(centralAccessToken(UUID_B)).toBe("imported@example.com-access");
});

// --- enumeration accessor ----------------------------------------------------

test("listCentralAccounts and listKnownAccounts enumerate identities central-then-fallback", () => {
  makeProfile("enum1", { uuid: UUID_A, email: "one@example.com" });

  // Profile with a snapshot but (artificially) no central entry: fallback source.
  const dir = mkdtempSync(join(tmpdir(), "authstore-enum2-"));
  writeIdentity(dir, { uuid: UUID_B, email: "two@example.com" });
  addProfile({ name: "enum2", dir });
  ensureProfileAuthSnapshot(dir, tool());
  rmSync(centralAuthDir(UUID_B), { recursive: true, force: true });

  const central = listCentralAccounts();
  expect(central.map((a) => a.uuid)).toEqual([UUID_A]);
  expect(central[0]?.email).toBe("one@example.com");

  const known = listKnownAccounts();
  const byUuid = new Map(known.map((a) => [a.uuid, a]));
  expect(byUuid.size).toBe(2);
  expect(byUuid.get(UUID_A)?.central).toBe(true);
  expect(byUuid.get(UUID_A)?.profiles).toEqual(["enum1"]);
  expect(byUuid.get(UUID_B)?.central).toBe(false);
  expect(byUuid.get(UUID_B)?.profiles).toEqual(["enum2"]);
  expect(byUuid.get(UUID_B)?.email).toBe("two@example.com");
});
