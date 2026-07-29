/**
 * ADVERSARIAL VERIFICATION of the merged fix for 0e7069a9 (PR #60, 4918133).
 *
 * The gate `dirLiveIdentityIsForeign` requires `own` to be KNOWN, where `own` is the parked
 * OAUTH snapshot. The PR documents "unknown own = first capture, nothing to defend".
 *
 * That reasoning holds when NOTHING is parked. This asks whether the two can come apart: a
 * profile that has a parked CREDENTIAL but no parked IDENTITY. There, `own` is unknown while
 * something valuable IS parked, so the gate opens over a credential that has a claim to defend.
 */
import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { profileCredentialsSnapshot, profileOAuthSnapshot } from "./lib/claude-layout.js";
import { getTool } from "./lib/tools.js";

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "verify-residual-"));
  liveBase = mkdtempSync(join(tmpdir(), "verify-residual-live-"));
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

function credentialJson(label: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + 600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}
function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}
function backdate(path: string, secondsAgo: number): void {
  const t = new Date(Date.now() - secondsAgo * 1000);
  utimesSync(path, t, t);
}

test("RESIDUAL: a parked credential with NO parked identity is replaced by a foreign live credential", () => {
  const dir = mkdtempSync(join(tmpdir(), "residual-noident-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  // Parked credential present, parked identity ABSENT. Nothing in the layout couples them:
  // ensureProfileAuthSnapshot writes the oauth snapshot only when an oauth SOURCE exists, so
  // a dir first snapshotted while .claude.json was missing lands in exactly this state.
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "noident", dir });
  expect(existsSync(profileOAuthSnapshot(dir))).toBe(false);
  const parked = readFileSync(profileCredentialsSnapshot(dir));

  // Now an in-session /login to another account: guest identity + guest credential, both new.
  backdate(profileCredentialsSnapshot(dir), 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));

  ensureProfileAuthSnapshot(dir, tool());

  // If the merged guard covers this, the parked bytes are unchanged. Assert the token
  // identity explicitly too: a byte diff over timestamps is ambiguous about WHICH credential
  // now occupies the file, and "which" is the whole question.
  const afterToken = JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken;
  const parkedToken = JSON.parse(parked.toString()).claudeAiOauth.accessToken;
  expect(parkedToken).toBe("host-access");
  expect(afterToken).toBe("host-access");
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

test("CONTROL: with a parked identity present, the same sequence is refused (the fix works)", () => {
  const dir = mkdtempSync(join(tmpdir(), "residual-ctrl-"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "ctrl", dir });
  ensureProfileAuthSnapshot(dir, tool());
  const parked = readFileSync(profileCredentialsSnapshot(dir));

  backdate(profileCredentialsSnapshot(dir), 3600);
  backdate(profileOAuthSnapshot(dir), 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));

  ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

test("REACHABILITY: that state is produced by the shipped API, not planted by hand", () => {
  // A hand-built fixture proves nothing if the state cannot occur. This reaches it only
  // through ensureProfileAuthSnapshot: a dir holding a credential but no .claude.json — which
  // is what a login-in-progress, an imported dir, or a tool that has not yet written its
  // account file looks like. The oauth snapshot is written only when an oauth SOURCE exists,
  // so the credential gets parked and the identity does not.
  const dir = mkdtempSync(join(tmpdir(), "residual-reach-"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "reach", dir });

  ensureProfileAuthSnapshot(dir, tool());

  // The credential IS parked here and the identity is NOT — that asymmetry stays, because
  // switchAccount's snapshot-back, `apply`, and profileEnv's self-heal all legitimately park
  // credentials in dirs carrying no identity snapshot. An earlier revision of this fix
  // refused to park until an identity existed, and CI measured the cost: ~14 existing tests
  // broke with ENOENT on the parked file. So the state is allowed to exist and is DEFENDED
  // instead.
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(true);
  expect(existsSync(profileOAuthSnapshot(dir))).toBe(false);
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-access",
  );

  // ...and from here the write that used to destroy it is refused, on the strength of the
  // credential fingerprint alone, with no identity to compare.
  backdate(profileCredentialsSnapshot(dir), 3600);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));

  ensureProfileAuthSnapshot(dir, tool());

  const afterToken = JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken;
  expect(afterToken).toBe("host-access");
});

// --- positive controls: the fix must not freeze any legitimate path ----------
// A guard that simply refused every snapshot refresh would satisfy the three
// tests above. These are what such a mutant has to break.

test("POSITIVE CONTROL: the same account rotating its token still refreshes the parked credential", () => {
  const dir = mkdtempSync(join(tmpdir(), "unattr-rotate-"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "rotate", dir });
  ensureProfileAuthSnapshot(dir, tool());

  backdate(profileCredentialsSnapshot(dir), 3600);
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-rotated"));

  ensureProfileAuthSnapshot(dir, tool());

  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-rotated-access",
  );
});

test("POSITIVE CONTROL: a first capture WITH an identity present still parks both", () => {
  const dir = mkdtempSync(join(tmpdir(), "unattr-first-"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "first", dir });
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(false);

  ensureProfileAuthSnapshot(dir, tool());

  expect(existsSync(profileOAuthSnapshot(dir))).toBe(true);
  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(true);
});

test("POSITIVE CONTROL: a first capture with NO identity still parks the credential", () => {
  // The regression this guards: refusing to park an unattributed credential breaks
  // switchAccount's snapshot-back, `apply`, and profileEnv's self-heal, which park
  // credentials in dirs with no identity snapshot. Measured on CI as ~14 ENOENT failures.
  const dir = mkdtempSync(join(tmpdir(), "unattr-first-noident-"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name: "firstnoident", dir });

  ensureProfileAuthSnapshot(dir, tool());

  expect(existsSync(profileCredentialsSnapshot(dir))).toBe(true);
  expect(existsSync(profileOAuthSnapshot(dir))).toBe(false);
});

test("POSITIVE CONTROL: a legacy unattributed park still accepts the SAME credential's identity", () => {
  // The dir holds exactly what we parked, so a newly appeared account file plausibly
  // describes it. Refusing here would strand such a dir permanently — it could never
  // acquire the identity that would let it be defended or restored.
  const dir = mkdtempSync(join(tmpdir(), "unattr-legacy-same-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  const same = credentialJson("host");
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), same);
  writeFileSync(join(dir, ".credentials.json"), same);   // byte-identical: SAME credential
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  addProfile({ name: "legacysame", dir });

  ensureProfileAuthSnapshot(dir, tool());

  const parkedIdentity = JSON.parse(readFileSync(profileOAuthSnapshot(dir), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(parkedIdentity.oauthAccount?.accountUuid).toBe(UUID_HOST);
});

test("POSITIVE CONTROL: `accounts login` (overwrite) still rebinds a legacy unattributed dir", () => {
  const dir = mkdtempSync(join(tmpdir(), "unattr-overwrite-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("host"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  addProfile({ name: "legacyoverwrite", dir });
  // Backdate the parked copy so it is unambiguously the older, no-fresher credential.
  // Without this the two fixtures can land in the same millisecond, `wouldDowngradeSnapshot`
  // ties on both mtime and expiry, and `betterCredential` keeps the snapshot — the test then
  // fails on fixture timing rather than on the behaviour it is asking about.
  backdate(profileCredentialsSnapshot(dir), 3600);

  // finalizeLogin's path: "the dir's files are this profile's truth again".
  ensureProfileAuthSnapshot(dir, tool(), { overwrite: true });

  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "guest-access",
  );
});

test("a tool with no identity concept is unaffected: no live identity cannot prove a conflict", () => {
  // Live identity unknown AND own unknown, with a parked credential present. There is no
  // second account in the picture, so refusing would break a legitimate refresh for a
  // profile that simply has no account file to read.
  const dir = mkdtempSync(join(tmpdir(), "unattr-noident-tool-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  const same = credentialJson("host");
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), same);
  writeFileSync(join(dir, ".credentials.json"), same);
  addProfile({ name: "noidenttool", dir });

  ensureProfileAuthSnapshot(dir, tool());

  // Same credential either way — the point is that nothing throws and nothing is destroyed.
  expect(JSON.parse(readFileSync(profileCredentialsSnapshot(dir), "utf8")).claudeAiOauth.accessToken).toBe(
    "host-access",
  );
});


