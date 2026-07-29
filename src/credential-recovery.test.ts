import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  ensureProfileAuthSnapshot,
  healSwitchedProfileDir,
  recoverParkedCredential,
  writeSwitchedAccountMarker,
} from "./lib/claude-auth.js";
import { profileCredentialsSnapshot } from "./lib/claude-layout.js";
import {
  classifyCredentialFile,
  parkedCredentialVerdict,
  profileCredentialLayers,
} from "./lib/credential-state.js";
import { getTool } from "./lib/tools.js";

/**
 * Regressions for 5d4f2bf0 — two config dirs holding one account destroy each
 * other's credential through refresh-token rotation, and nothing recovers the
 * survivor.
 *
 * Token values below are literal placeholders. Nothing here reaches a network.
 */

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-recov-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-recov-live-"));
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

const UUID_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

function credentialJson(opts: { label: string; expiresInMs?: number; refreshToken?: string | null }): string {
  const { label, expiresInMs = 60_000, refreshToken = `${label}-refresh` } = opts;
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      ...(refreshToken === null ? {} : { refreshToken }),
      expiresAt: Date.now() + expiresInMs,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

/**
 * Exactly what Claude Code leaves behind when a refresh fails because another
 * copy of the same account rotated the token: payload structure intact, both
 * secrets gone, expiry zeroed, `refreshTokenExpiresAt` still sitting there.
 */
function rotatedAwayJson(): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: "",
      refreshToken: "",
      expiresAt: 0,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
      scopes: ["user:inference"],
      subscriptionType: "max",
    },
  });
}

function makeProfile(name: string, uuid: string, label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `recov-${name}-`));
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credentialJson({ label }));
  addProfile({ name, dir });
  // Parks the profile's own credential in .accounts-auth/ and the central store.
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

function dirCredential(dir: string): { accessToken?: string; refreshToken?: string } {
  const raw = JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")) as {
    claudeAiOauth?: { accessToken?: string; refreshToken?: string };
  };
  return raw.claudeAiOauth ?? {};
}

// --- classification ---------------------------------------------------------

test("the rotation fingerprint is its own state, not `expired` and not `unusable`", () => {
  const dir = mkdtempSync(join(tmpdir(), "recov-classify-"));
  const rotated = join(dir, "rotated.json");
  const dead = join(dir, "dead.json");
  const aged = join(dir, "aged.json");
  const good = join(dir, "good.json");
  const junk = join(dir, "junk.json");

  writeFileSync(rotated, rotatedAwayJson());
  // A genuinely dead credential keeps its expiry — that is what separates it.
  writeFileSync(dead, credentialJson({ label: "dead", expiresInMs: -60_000, refreshToken: null }));
  writeFileSync(aged, credentialJson({ label: "aged", expiresInMs: -60_000 }));
  writeFileSync(good, credentialJson({ label: "good" }));
  writeFileSync(junk, "{ not json");

  // Four distinct verdicts from four inputs: the check can tell them apart, so
  // asserting any one of them means something.
  expect(classifyCredentialFile(rotated).state).toBe("rotated-away");
  expect(classifyCredentialFile(dead).state).toBe("unusable");
  expect(classifyCredentialFile(aged).state).toBe("needs-refresh");
  expect(classifyCredentialFile(good).state).toBe("usable");
  expect(classifyCredentialFile(junk).state).toBe("unreadable");
  expect(classifyCredentialFile(join(dir, "nope.json")).state).toBe("absent");
  rmSync(dir, { recursive: true, force: true });
});

test("refresh-token presence is decided on the VALUE, not the key name", () => {
  // `refreshTokenExpiresAt` contains the substring `refresh` and survives in a
  // rotated-away payload. A name-matching check reports a token that is gone —
  // the exact mistake that produced a wrong diagnosis on this defect.
  const dir = mkdtempSync(join(tmpdir(), "recov-keyname-"));
  const path = join(dir, "c.json");
  writeFileSync(
    path,
    JSON.stringify({ claudeAiOauth: { accessToken: "", expiresAt: 0, refreshTokenExpiresAt: Date.now() + 1000 } }),
  );
  expect(readFileSync(path, "utf8")).toContain("refreshToken");
  expect(classifyCredentialFile(path).state).toBe("rotated-away");
  rmSync(dir, { recursive: true, force: true });
});

// --- the parked copy must survive a rotated-away live file ------------------

test("a rotated-away live file must NOT overwrite the parked snapshot", () => {
  // The second destruction path, and the more dangerous one: rotation blanks the
  // live file, then the next launch/env/switch propagates the blank downward
  // because the snapshot refresh was ordered by mtime alone. For a dir that had
  // already lost its live copy the snapshot was the last copy under that
  // directory. One profile on this fleet was measured having already lost both.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const parked = readFileSync(profileCredentialsSnapshot(dir));
  expect(classifyCredentialFile(profileCredentialsSnapshot(dir)).state).toBe("usable");

  // Claude Code blanks the live file, and it is now the NEWEST write.
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  const snapMtimeBefore = statSync(profileCredentialsSnapshot(dir)).mtimeMs;
  utimesSync(join(dir, ".credentials.json"), new Date(), new Date(snapMtimeBefore + 60_000));

  ensureProfileAuthSnapshot(dir, tool());

  // Byte-for-byte: the parked credential is untouched.
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
  expect(classifyCredentialFile(profileCredentialsSnapshot(dir)).state).toBe("usable");
});

test("a truncated non-empty refresh token must NOT overwrite the parked snapshot", () => {
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const parked = readFileSync(profileCredentialsSnapshot(dir));

  // Both credentials remain "usable" to the general ranking rule, so the
  // newer one-character token would otherwise win on mtime.
  writeFileSync(join(dir, ".credentials.json"), credentialJson({ label: "truncated", refreshToken: "x" }));
  const snapMtimeBefore = statSync(profileCredentialsSnapshot(dir)).mtimeMs;
  utimesSync(join(dir, ".credentials.json"), new Date(), new Date(snapMtimeBefore + 60_000));

  ensureProfileAuthSnapshot(dir, tool());

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

test("POSITIVE CONTROL: a genuinely rotated NEWER credential still replaces the snapshot", () => {
  // Without this, the test above is satisfied by never refreshing snapshots at
  // all — which would reintroduce the bug the mtime rule exists to prevent:
  // restoring a login-time snapshot over tokens the running tool rotated in
  // place logs the account out.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const before = readFileSync(profileCredentialsSnapshot(dir), "utf8");

  // A modest length change is plausible across rotations and must not be
  // mistaken for the large regression guarded above.
  writeFileSync(
    join(dir, ".credentials.json"),
    credentialJson({ label: "rotated-fresh", refreshToken: "new-refresh" }),
  );
  const snapMtime = statSync(profileCredentialsSnapshot(dir)).mtimeMs;
  utimesSync(join(dir, ".credentials.json"), new Date(), new Date(snapMtime + 60_000));

  ensureProfileAuthSnapshot(dir, tool());

  const after = readFileSync(profileCredentialsSnapshot(dir), "utf8");
  expect(after).not.toBe(before);
  expect(JSON.parse(after).claudeAiOauth.accessToken).toBe("rotated-fresh-access");
});

test("POSITIVE CONTROL: a fresh login (overwrite) still replaces the parked snapshot", () => {
  // The downgrade guard applies to `overwrite: true` as well, so it could in
  // principle block a re-login from parking its new credential — which would
  // silently strand a re-authenticated profile on its old token. betterCredential
  // ranks refresh-token presence, then usability, then mtime, so a real login
  // always wins; this proves it rather than assuming it.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const before = readFileSync(profileCredentialsSnapshot(dir), "utf8");

  writeFileSync(join(dir, ".credentials.json"), credentialJson({ label: "after-login" }));
  ensureProfileAuthSnapshot(dir, tool(), { overwrite: true });

  const after = readFileSync(profileCredentialsSnapshot(dir), "utf8");
  expect(after).not.toBe(before);
  expect(JSON.parse(after).claudeAiOauth.accessToken).toBe("after-login-access");
});

test("a login that somehow wrote a BLANK still cannot destroy the parked copy", () => {
  // The other side of the same knob: `overwrite` must not be a bypass for the
  // downgrade guard, or re-login becomes a way to lose the last good copy.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const parked = readFileSync(profileCredentialsSnapshot(dir));

  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  ensureProfileAuthSnapshot(dir, tool(), { overwrite: true });

  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

// --- the gap: nothing recovered a marker-less rotated-away dir ---------------

test("healSwitchedProfileDir does NOT reach a rotated-away dir with no marker", () => {
  // This is the shape four of the six affected profiles were in. It passes
  // before and after the fix — it documents the gap that `recoverParkedCredential`
  // exists to fill, and guards against anyone "fixing" it by loosening the
  // marker check inside healSwitchedProfileDir, which would start evicting
  // live guests.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  expect(healSwitchedProfileDir(dir, tool(), "alpha")).toBe(false);
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("rotated-away");
});

test("recoverParkedCredential restores the parked credential into a rotated-away dir", () => {
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const snapshotBefore = readFileSync(profileCredentialsSnapshot(dir));
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  const layersBefore = profileCredentialLayers(dir, tool());
  expect(layersBefore.live.state).toBe("rotated-away");
  expect(parkedCredentialVerdict(layersBefore).recoverable).toBe(true);

  const result = recoverParkedCredential(dir, tool(), "alpha");

  expect(result.outcome).toBe("recovered");
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("usable");
  expect(dirCredential(dir).accessToken).toBe("alpha-access");

  // ARCHIVE-NEVER-DELETE: the parked copy is the only source of this material
  // and must survive the restore byte-for-byte.
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(snapshotBefore);
});

test("recovery works even with live sessions attached — there is no identity to yank", () => {
  // Five of the six affected dirs had live sessions. Refusing on liveness (as
  // healSwitchedProfileDir does, correctly, for the eviction case) would have
  // made this recovery reach almost nothing. Here the attached sessions hold a
  // credential that is already dead.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));

  const result = recoverParkedCredential(dir, tool(), "alpha");

  expect(result.outcome).toBe("recovered");
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("usable");
});

test("recovery REFUSES when it would change which account the dir presents", () => {
  // The dir carries a guest after an in-place switch and the guest's credential
  // is the one that got rotated away. Restoring this profile's own credential
  // would swap the identity under whoever is attached, so it stays a deliberate
  // `accounts switch-account`, not a side effect of launching.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_B, emailAddress: "beta@example.com" } }),
  );
  writeSwitchedAccountMarker(dir, { profile: "beta", email: "beta@example.com" });
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  const result = recoverParkedCredential(dir, tool(), "alpha");

  expect(result.outcome).toBe("identity-would-change");
  // Nothing was written: the dir is exactly as it was.
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("rotated-away");
});

test("recovery leaves a healthy dir alone", () => {
  // The destructive mistake this guards against: clobbering a working live
  // credential with an older parked one.
  const dir = makeProfile("alpha", UUID_A, "alpha");
  const before = readFileSync(join(dir, ".credentials.json"), "utf8");

  const result = recoverParkedCredential(dir, tool(), "alpha");

  expect(result.outcome).toBe("live-credential-usable");
  expect(readFileSync(join(dir, ".credentials.json"), "utf8")).toBe(before);
});

test("recovery REFUSES when the profile has a parked credential but no parked IDENTITY", () => {
  // Found by adversarial self-review, not by the brief. `profileHasOAuthAccount`
  // is satisfied by the LIVE .claude.json — the guest's after an in-place switch —
  // and restoreClaudeAuthIntoDir falls back to that same record when no snapshot
  // exists. Without this gate the dir would end up carrying the GUEST's
  // oauthAccount next to THIS profile's credential: one account's identity
  // paired with another account's token.
  const dir = mkdtempSync(join(tmpdir(), "recov-noident-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  // A restorable parked credential, but no parked identity for it.
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson({ label: "parked" }));
  // The dir currently shows a DIFFERENT account, and its credential is blanked.
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_B, emailAddress: "guest@example.com" } }),
  );
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  addProfile({ name: "noident", dir });

  const result = recoverParkedCredential(dir, tool(), "noident");

  expect(result.outcome).toBe("identity-unknown");
  // Nothing written: the guest identity was NOT paired with the parked credential.
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("rotated-away");
  const stillGuest = JSON.parse(readFileSync(join(dir, ".claude.json"), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(stillGuest.oauthAccount?.accountUuid).toBe(UUID_B);
  rmSync(dir, { recursive: true, force: true });
});

test("recovery never throws on the launch path, whatever shape the dir is in", () => {
  // profileEnv runs this on EVERY launch, so a malformed or half-built profile
  // must not take the launch down with it — it still has to reach its own error.
  // The guarantee is "returns an outcome, never throws", so it is asserted
  // across the broken shapes rather than for one of them.
  const known = new Set([
    "recovered",
    "live-credential-usable",
    "no-parked-credential",
    "identity-would-change",
    "identity-unknown",
    "failed",
    "not-applicable",
  ]);

  const shapes: Array<[string, (dir: string) => void]> = [
    ["parked credential, no parked identity", (dir) => {
      mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
      writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson({ label: "orphan" }));
      writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
    }],
    ["nothing at all", () => {}],
    ["unreadable everything", (dir) => {
      mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
      writeFileSync(join(dir, ".claude.json"), "{ not json");
      writeFileSync(join(dir, ".credentials.json"), "{ not json");
      writeFileSync(join(dir, ".accounts-auth", "credentials.json"), "{ not json");
    }],
    ["identity present, credential unreadable", (dir) => {
      mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
      writeFileSync(
        join(dir, ".accounts-auth", "oauth-account.json"),
        JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
      );
      writeFileSync(join(dir, ".accounts-auth", "credentials.json"), "{ not json");
      writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
    }],
  ];

  for (const [label, build] of shapes) {
    const dir = mkdtempSync(join(tmpdir(), "recov-shape-"));
    build(dir);
    let outcome: string | undefined;
    expect(() => {
      outcome = recoverParkedCredential(dir, tool(), "shaky").outcome;
    }, label).not.toThrow();
    expect(known.has(outcome ?? ""), `${label} -> ${outcome}`).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recovery says re-authentication is required only when nothing is parked", () => {
  const dir = mkdtempSync(join(tmpdir(), "recov-dead-"));
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "alpha@example.com" } }),
  );
  writeFileSync(
    join(dir, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "alpha@example.com" } }),
  );
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), rotatedAwayJson());
  addProfile({ name: "dead", dir });

  const result = recoverParkedCredential(dir, tool(), "dead");

  expect(result.outcome).toBe("no-parked-credential");
  expect(result.detail).toMatch(/accounts login/);
  rmSync(dir, { recursive: true, force: true });
});
