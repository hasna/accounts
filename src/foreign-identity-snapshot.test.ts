import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { profileCredentialsSnapshot, profileOAuthSnapshot } from "./lib/claude-layout.js";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { getTool } from "./lib/tools.js";

/**
 * Regression cover for defect 0e7069a9: a healthy FOREIGN credential overwrites
 * a profile's own parked copy when no switch marker exists.
 *
 * REPRODUCED, not modelled: an in-session `/login` to a different account
 * writes NO switch marker, so the marker branch in `ensureProfileAuthSnapshot`
 * never fires. What the tests below plant is exactly what Claude Code leaves on
 * disk in that case — a rewritten `.claude.json` carrying the guest's
 * `oauthAccount` and a rewritten `.credentials.json` carrying the guest's
 * token, both freshly written and therefore newer than the host profile's
 * parked copies.
 *
 * WHY RANKING CANNOT CATCH IT: `betterCredential` orders on refresh-token
 * presence, then usability, then mtime. Both credentials here are healthy, so
 * the first two tiers tie and mtime decides — and the guest's file is always
 * the newer one. Ranking can separate healthy from degraded; it cannot separate
 * two healthy credentials belonging to different accounts. Only identity can.
 * Every fixture below therefore gives BOTH accounts a valid, unexpired,
 * refresh-token-bearing credential; a fixture that degraded either one would
 * pass for the wrong reason.
 */

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-foreign-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-foreign-live-"));
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

/** A healthy credential: refresh token present, comfortably unexpired. */
function credentialJson(label: string, expiresInMs = 600_000): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + expiresInMs,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

function emailIdentityJson(label: string): string {
  return JSON.stringify({ oauthAccount: { emailAddress: `${label}@example.com` } });
}

/** Backdate a file so mtime-based freshness comparisons see it as old. */
function backdate(path: string, secondsAgo: number): void {
  const t = new Date(Date.now() - secondsAgo * 1000);
  utimesSync(path, t, t);
}

/**
 * A profile dir holding the host account, with its own identity and credential
 * already parked in `.accounts-auth/` and the central store.
 */
function makeHostProfile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `foreign-${name}-`));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/** A legacy/sparse profile whose OAuth record identifies the owner by email. */
function makeEmailOnlyHostProfile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `foreign-${name}-`));
  writeFileSync(join(dir, ".claude.json"), emailIdentityJson("host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/**
 * The on-disk residue of an in-session `/login` to another account: the dir's
 * live identity AND live credential both become the guest's, both newer than
 * everything the host profile has parked, and NO switch marker is written.
 */
function inSessionLoginTo(dir: string, uuid: string, label: string): void {
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(profileOAuthSnapshot(dir), 3600);
  const central = centralCredentialsSnapshot(UUID_HOST);
  if (existsSync(central)) backdate(central, 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, label));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
  expect(
    existsSync(join(dir, ".accounts-auth", "switched-account.json")),
    "fixture must reproduce the NO-MARKER path — a marker would exercise a branch that is already guarded",
  ).toBe(false);
}

function inSessionLoginWithoutUuidTo(dir: string, label: string): void {
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(profileOAuthSnapshot(dir), 3600);
  writeFileSync(join(dir, ".claude.json"), emailIdentityJson(label));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
}

// --- the parked copy must survive a foreign in-session login -----------------

test("an in-session login to another account does not replace the profile's parked credential", () => {
  const dir = makeHostProfile("hostcred");
  const parked = readFileSync(profileCredentialsSnapshot(dir));
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  ensureProfileAuthSnapshot(dir, tool());

  // Byte-equality, not existsSync: the failure mode is the file being REPLACED
  // with the guest's credential, and a replaced file still exists.
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

test("an in-session login to another account does not overwrite the profile's parked identity", () => {
  const dir = makeHostProfile("hostident");
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  ensureProfileAuthSnapshot(dir, tool());

  // The parked identity is what makes the credential attributable, and what the
  // guard reads on the NEXT call. Losing it turns the guard into a one-call
  // delay: `own` would become the guest's, match `live`, and the credential
  // would be destroyed on the following invocation.
  const parkedIdentity = JSON.parse(readFileSync(profileOAuthSnapshot(dir), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(parkedIdentity.oauthAccount?.accountUuid).toBe(UUID_HOST);
});

test("an in-session login to another account does not overwrite the profile's CENTRAL credential", () => {
  const dir = makeHostProfile("hostcentral");
  const central = readFileSync(centralCredentialsSnapshot(UUID_HOST));
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  ensureProfileAuthSnapshot(dir, tool());

  // The central store is keyed by the HOST's uuid, so mirroring the guest's
  // live credential into it destroys the last copy of the host's material.
  // Guarding only the per-profile snapshot would move the loss, not stop it.
  expect(readFileSync(centralCredentialsSnapshot(UUID_HOST))).toEqual(central);
});

test("repeated calls do not erode the parked credential (the guard holds, it does not merely delay)", () => {
  const dir = makeHostProfile("hostrepeat");
  const parked = readFileSync(profileCredentialsSnapshot(dir));
  const central = readFileSync(centralCredentialsSnapshot(UUID_HOST));
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  for (let i = 0; i < 3; i++) ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
  expect(readFileSync(centralCredentialsSnapshot(UUID_HOST))).toEqual(central);
});

test("an email-only profile rejects a foreign email-only identity and credential", () => {
  const dir = makeEmailOnlyHostProfile("emailonly");
  const parkedCredential = readFileSync(profileCredentialsSnapshot(dir));
  const parkedIdentity = readFileSync(profileOAuthSnapshot(dir));
  inSessionLoginWithoutUuidTo(dir, "guest");

  for (let i = 0; i < 3; i++) ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parkedCredential);
  expect(readFileSync(profileOAuthSnapshot(dir))).toEqual(parkedIdentity);
});

test("an email-only profile rejects a foreign live identity that has a uuid", () => {
  const dir = makeEmailOnlyHostProfile("parkedemailonly");
  const parkedCredential = readFileSync(profileCredentialsSnapshot(dir));
  const parkedIdentity = readFileSync(profileOAuthSnapshot(dir));
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parkedCredential);
  expect(readFileSync(profileOAuthSnapshot(dir))).toEqual(parkedIdentity);
});

test("a uuid-bound profile rejects a foreign live identity that has only email", () => {
  const dir = makeHostProfile("liveemailonly");
  const parkedCredential = readFileSync(profileCredentialsSnapshot(dir));
  const parkedIdentity = readFileSync(profileOAuthSnapshot(dir));
  const central = readFileSync(centralCredentialsSnapshot(UUID_HOST));
  inSessionLoginWithoutUuidTo(dir, "guest");

  ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parkedCredential);
  expect(readFileSync(profileOAuthSnapshot(dir))).toEqual(parkedIdentity);
  expect(readFileSync(centralCredentialsSnapshot(UUID_HOST))).toEqual(central);
});

// --- positive controls: the guard must not freeze the legitimate paths -------
// Each of these must survive the fix. A mutant that satisfies the tests above
// by refusing every snapshot refresh has to break at least one of them.

test("POSITIVE CONTROL: the same account rotating its token still refreshes the parked credential", () => {
  const dir = makeHostProfile("samerotate");
  const before = readFileSync(profileCredentialsSnapshot(dir));
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(centralCredentialsSnapshot(UUID_HOST), 3600);
  // Same identity, newly rotated token — exactly what a running tool writes.
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-rotated"));

  ensureProfileAuthSnapshot(dir, tool());

  const after = readFileSync(profileCredentialsSnapshot(dir));
  expect(after).not.toEqual(before);
  expect(JSON.parse(after.toString()).claudeAiOauth.accessToken).toBe("host-rotated-access");
});

test("POSITIVE CONTROL: a profile with no parked identity still captures its first snapshot", () => {
  const dir = mkdtempSync(join(tmpdir(), "foreign-firstcapture-"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "firstcapture", dir });
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(false);

  ensureProfileAuthSnapshot(dir, tool());

  // Unknown own identity is the FIRST-CAPTURE case, not a conflict: there is no
  // parked claim to defend, and refusing here would stop a profile ever
  // acquiring one. This is the deliberate asymmetry with
  // `recoverParkedCredential`, where unknown own identity IS a refusal.
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(true);
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-access",
  );
});

test("POSITIVE CONTROL: a fresh login (overwrite) still rebinds the dir to the new account", () => {
  const dir = makeHostProfile("relogin");
  inSessionLoginTo(dir, UUID_GUEST, "guest");

  // `finalizeLogin` is the one caller that passes overwrite — it means "the
  // dir's files are this profile's truth again", so it must cross the gate.
  ensureProfileAuthSnapshot(dir, tool(), { overwrite: true });

  const parkedIdentity = JSON.parse(readFileSync(profileOAuthSnapshot(dir), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(parkedIdentity.oauthAccount?.accountUuid).toBe(UUID_GUEST);
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "guest-access",
  );
});

// --- adjacent identity cases ------------------------------------------------

test("a case-variant uuid is the SAME account, so the refresh still happens", () => {
  const dir = makeHostProfile("casevariant");
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(centralCredentialsSnapshot(UUID_HOST), 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST.toUpperCase(), "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-rotated"));

  ensureProfileAuthSnapshot(dir, tool());

  // Comparing case-sensitively would read a case-variant as a foreign account
  // and strand a genuinely rotated token — the failure the compat window exists
  // to avoid.
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-rotated-access",
  );
});

test("an empty live uuid falls back to the matching email, so the refresh still happens", () => {
  const dir = makeHostProfile("liveunknown");
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(centralCredentialsSnapshot(UUID_HOST), 3600);
  // Empty-string uuid carries no UUID identity, but the matching email still
  // proves this is the host account rather than a foreign login.
  writeFileSync(join(dir, ".claude.json"), identityJson("", "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-rotated"));

  ensureProfileAuthSnapshot(dir, tool());

  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-rotated-access",
  );
});

test("an email-only profile accepts the same account when the live record gains a uuid", () => {
  const dir = makeEmailOnlyHostProfile("emailuuid");
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(profileOAuthSnapshot(dir), 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-rotated"));

  ensureProfileAuthSnapshot(dir, tool());

  const parkedIdentity = JSON.parse(readFileSync(profileOAuthSnapshot(dir), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(parkedIdentity.oauthAccount?.accountUuid).toBe(UUID_HOST);
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-rotated-access",
  );
});

test("a malformed-but-DIFFERENT live uuid is still a conflict", () => {
  const dir = mkdtempSync(join(tmpdir(), "foreign-malformed-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  // Both sides malformed, so neither passes the strict UUID filter that binding
  // resolution uses. Conflict detection must still notice they DIFFER — a
  // guard that treats "not a well-formed uuid" as "no identity" would wave the
  // destroying write straight through.
  writeFileSync(join(dir, ".accounts-auth", "oauth-account.json"), identityJson("host-account", "host"));
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("host"));
  writeFileSync(join(dir, ".claude.json"), identityJson("guest-account", "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  addProfile({ name: "malformed", dir });
  const parked = readFileSync(profileCredentialsSnapshot(dir));
  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(profileOAuthSnapshot(dir), 3600);

  ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});
