import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  claudeKeychainCredentialFromProfile,
  claudeProfileAuthHealth,
  ensureProfileAuthSnapshot,
  writeSwitchedAccountMarker,
} from "./lib/claude-auth.js";
import { getTool } from "./lib/tools.js";

/**
 * Regression cover for the READ/REPORT half of the profile-dir occupation
 * defect. PR #60 closed the WRITE half (a foreign credential replacing a
 * profile's parked copy). Nothing stopped the read paths from doing the mirror
 * of that: reading the OCCUPANT's live credential and attributing it to the
 * host profile.
 *
 * MEASURED ON THIS FLEET 2026-07-29, not modelled. Three profile dirs
 * (account003, account004, account030) each carried another account's live
 * credential in a `usable` state while their own parked copy was merely
 * `needs-refresh`. `claudeProfileAuthHealth(dir, tool)` returned
 * `status: "ok", valid: true` for all three — the guest's health, reported as
 * the host's — while `accounts launch account004` returned rc=1
 * ("its config dir currently carries the account of account010"). Readiness
 * said healthy; launch refused. That contradiction is how a scheduler hands
 * work to a profile that cannot run it.
 *
 * TWO SEPARATE HOLES, and a fixture has to be able to produce both:
 *
 *   1. The default (non-`restoreView`) health view put the dir's live
 *      `.credentials.json` FIRST in its candidate list with no occupancy test
 *      at all. A marked, switched-away dir was reported off the guest's token.
 *
 *   2. Every occupancy test that did exist keyed on the switch MARKER. An
 *      in-session `/login` writes no marker, so an unmarked-but-occupied dir
 *      was invisible to the `restoreView` guard too — and to
 *      `profileFileCredentialSecret`, which feeds the host's keychain entry.
 *
 * WHY THE FIXTURES LOOK THE WAY THEY DO: the guest credential is always
 * strictly HEALTHIER than the host's parked copy (unexpired vs aged-out), and
 * the host's parked copy always holds a refresh token. Any other arrangement
 * would let the assertions pass for the wrong reason — if the host's own copy
 * were the healthier one, ranking alone would pick it and the tests would go
 * green against the unfixed code. Reversing that (the `betterCredential`
 * positive control below) is what proves these tests can actually fail.
 */

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

let home: string;
let liveBase: string;
const dirs: string[] = [];
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-occupied-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-occupied-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

/** Obviously-synthetic credential material. Never a real token shape. */
function credentialJson(label: string, opts: { expiredAccessToken?: boolean; refreshToken?: boolean } = {}): string {
  const hasRefresh = opts.refreshToken !== false;
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `SYNTHETIC-${label}-access`,
      ...(hasRefresh ? { refreshToken: `SYNTHETIC-${label}-refresh` } : {}),
      expiresAt: opts.expiredAccessToken ? Date.now() - 600_000 : Date.now() + 600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

function touchNow(path: string): void {
  const t = new Date();
  utimesSync(path, t, t);
}

/**
 * A registered profile whose OWN identity and credential are parked, and whose
 * parked credential is aged out but renewable — the overnight state most of
 * this fleet sits in, and the one where a guest's fresher token wins any
 * health-blind comparison.
 */
function makeHostProfile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `occupied-${name}-`));
  dirs.push(dir);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host", { expiredAccessToken: true }));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/**
 * The residue of an in-session `/login` to another account: live identity and
 * live credential both become the guest's, both freshly written, and NO switch
 * marker exists.
 */
function occupyUnmarked(dir: string): void {
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  touchNow(join(dir, ".claude.json"));
  touchNow(join(dir, ".credentials.json"));
}

/** The residue of a deliberate `accounts switch-account --dir <host dir>`. */
function occupyMarked(dir: string): void {
  occupyUnmarked(dir);
  writeSwitchedAccountMarker(dir, { profile: "guest-profile", email: "guest@example.com" });
}

// --- the defect ------------------------------------------------------------

test("a MARKED occupied dir does not report the occupant's credential as the profile's own", () => {
  const dir = makeHostProfile("host-marked");
  occupyMarked(dir);

  const health = claudeProfileAuthHealth(dir, tool());

  // Pre-fix this was status "ok" / valid true, read straight off the guest's
  // unexpired token. The honest answer is the host's own parked copy: aged out
  // but holding a refresh token, so renewable.
  expect(health.valid).toBe(false);
  expect(health.status).toBe("expired");
  expect(health.renewable).toBe(true);
});

test("an UNMARKED occupied dir (in-session /login) does not report the occupant's credential either", () => {
  const dir = makeHostProfile("host-unmarked");
  occupyUnmarked(dir);

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.valid).toBe(false);
  expect(health.status).toBe("expired");
  expect(health.renewable).toBe(true);
});

test("both views answer for the HOST on an unmarked occupied dir, not merely agree", () => {
  // Agreement alone is not evidence and this test used to prove nothing:
  // pre-fix BOTH views read the guest's credential, so they agreed on the wrong
  // answer and the assertion passed. What has to be asserted is the value they
  // agree ON — the host's parked copy, aged out and renewable.
  const dir = makeHostProfile("host-views");
  occupyUnmarked(dir);

  const plain = claudeProfileAuthHealth(dir, tool());
  const restore = claudeProfileAuthHealth(dir, tool(), { restoreView: true });

  for (const health of [plain, restore]) {
    expect(health.status).toBe("expired");
    expect(health.valid).toBe(false);
    expect(health.renewable).toBe(true);
    expect(health.dirOccupiedByAnotherAccount).toBe(true);
  }
});

test("a MARKED dir whose live account is provably its OWN is not occupied (stale marker)", () => {
  // The other direction of the marker-only rule. `ensureProfileAuthSnapshot`
  // and `healSwitchedProfileDir` both already delete a marker contradicted by
  // the dir's live account; a read path that still believed it would ignore a
  // perfectly good live credential and report the profile as expired. Identity
  // decides when identity is legible.
  const dir = makeHostProfile("host-stale-marker");
  writeSwitchedAccountMarker(dir, { profile: "guest-profile", email: "guest@example.com" });
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-fresh"));
  touchNow(join(dir, ".credentials.json"));

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(false);
  expect(health.valid).toBe(true);
});

test("a marker still decides when the dir's live identity is illegible (fail closed)", () => {
  // No readable live identity means nothing to compare, so the marker is the
  // only evidence there is. Dropping to "not occupied" here would reinstate the
  // original defect for any dir whose `.claude.json` Claude Code has mangled.
  const dir = makeHostProfile("host-illegible");
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "who@example.com" } }));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  touchNow(join(dir, ".credentials.json"));
  writeSwitchedAccountMarker(dir, { profile: "guest-profile", email: "guest@example.com" });

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(true);
  expect(health.valid).toBe(false);
  expect(health.renewable).toBe(true);
});

test("an occupied dir says so, naming the state rather than only the expiry", () => {
  const dir = makeHostProfile("host-reason");
  occupyUnmarked(dir);

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(true);
  expect(health.reasons.join(" | ")).toContain("another account");
});

test("the keychain entry for an unmarked occupied dir is not the occupant's secret", () => {
  // `prepareClaudeProfileKeychain` writes this into the machine keychain as the
  // host profile's credential. Handing it the guest's token crosses one
  // account's secret into another's slot — a read defect with a write
  // consequence, and the reason this path is in scope.
  const dir = makeHostProfile("host-keychain");
  occupyUnmarked(dir);

  const cred = claudeKeychainCredentialFromProfile(dir, "host-keychain");

  expect(cred).toBeDefined();
  expect(cred!.secret).not.toContain("guest");
  expect(cred!.secret).toContain("host");
});

// --- positive controls: each of these must FAIL if the guard over-reaches ---

test("POSITIVE CONTROL: an unoccupied dir still reports off its own live credential", () => {
  // If the guard fired unconditionally, this profile — whose live credential is
  // its own and healthy — would be reported expired. It must not be.
  const dir = makeHostProfile("host-clean");
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-fresh"));
  touchNow(join(dir, ".credentials.json"));

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.valid).toBe(true);
  expect(health.status).toBe("ok");
  expect(health.dirOccupiedByAnotherAccount).toBe(false);
});

test("POSITIVE CONTROL: a dir with no parked identity of its own is not treated as occupied", () => {
  // First-capture: a dir that has never been snapshotted has no claim to
  // defend, and its live files ARE its truth. Refusing here would report every
  // freshly imported profile as occupied.
  const dir = mkdtempSync(join(tmpdir(), "occupied-fresh-"));
  dirs.push(dir);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  addProfile({ name: "host-nosnapshot", dir });

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(false);
  expect(health.valid).toBe(true);
});

test("POSITIVE CONTROL: case-variant spellings of one uuid are the SAME account, not an occupation", () => {
  const dir = makeHostProfile("host-case");
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST.toUpperCase(), "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host-fresh"));
  touchNow(join(dir, ".credentials.json"));

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(false);
  expect(health.valid).toBe(true);
});

test("POSITIVE CONTROL: the fixture can produce the failure — ranking alone picks the guest", () => {
  // The discriminating-input check. If the host's parked copy were the
  // healthier of the two, every assertion above would pass against UNFIXED
  // code, because `betterCredential` would already prefer the host. This
  // asserts the opposite arrangement actually holds: with the guard removed
  // from the equation (an unoccupied dir carrying the guest's fresher token),
  // the health read follows the guest. That is the behaviour the occupied-dir
  // tests must separate themselves from.
  const dir = makeHostProfile("host-control");
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  touchNow(join(dir, ".credentials.json"));
  // Same identity, so no occupation — only the credential differs.

  const health = claudeProfileAuthHealth(dir, tool());

  expect(health.dirOccupiedByAnotherAccount).toBe(false);
  expect(health.valid).toBe(true);
  expect(health.status).toBe("ok");
});

// --- the INTERSECTION of two independently-reviewed changes ----------------
//
// `dirOccupiedByAnotherAccount` (#63) and `renewable` (#90) were written
// against each other's absence: #63's tests exercise occupancy against the old
// status logic, #90's exercise renewability against the old occupancy logic.
// Both suites passing proves each half in isolation and says NOTHING about the
// state where both hold at once — which is not a corner case but the ordinary
// overnight condition of this fleet: a dir someone `/login`-ed into, whose host
// profile's own parked credential has merely aged out.
//
// It is also the exact pairing that produces a contradiction if either half is
// dropped in a merge. Report it `unavailable` and a scheduler benches a profile
// that only needs its dir reconciled; report it `ok` and a scheduler hands work
// to a profile whose dir carries someone else's account and whose launch will
// refuse. The composed answer has to say BOTH things at once, and lead with the
// action that actually fixes it.

test("COMPOSED: an occupied dir whose own credential is renewable reports both facts, not one", async () => {
  const { getAccountsReadiness } = await import("./lib/readiness.js");
  const dir = makeHostProfile("composed");
  occupyUnmarked(dir);

  const readiness = await getAccountsReadiness({
    env: { ...process.env, HASNA_ACCOUNTS_S3_BUCKET: "accounts-composed-test" },
  });
  const row = readiness.profiles.find((entry) => entry.name === "composed");
  expect(row).toBeDefined();

  // Usable once reconciled, so not `unavailable` — the half #90 restored.
  expect(row?.login.status).toBe("degraded");
  expect(row?.login.renewable).toBe(true);
  // And occupied, so not silently `ok` either — the half #63 added.
  expect(row?.login.dirOccupiedByAnotherAccount).toBe(true);

  // Order is load-bearing: re-authenticating does not fix an occupied dir, so
  // reconcile has to be the first action an operator reads.
  const actions = row?.nextActions ?? [];
  const reconcileAt = actions.findIndex((action) => action.includes("switch-account"));
  const loginAt = actions.findIndex((action) => action.includes("accounts login"));
  expect(reconcileAt).toBeGreaterThanOrEqual(0);
  expect(loginAt).toBeGreaterThanOrEqual(0);
  expect(reconcileAt).toBeLessThan(loginAt);

  // The reason names the occupation, so the credential lines below it are not
  // read as facts about the occupant.
  expect(row?.login.reasons.join("\n")).toContain("currently carry another account");
});

test("COMPOSED POSITIVE CONTROL: the same profile unoccupied is renewable and NOT flagged occupied", async () => {
  const { getAccountsReadiness } = await import("./lib/readiness.js");
  makeHostProfile("composed-control");

  const readiness = await getAccountsReadiness({
    env: { ...process.env, HASNA_ACCOUNTS_S3_BUCKET: "accounts-composed-test" },
  });
  const row = readiness.profiles.find((entry) => entry.name === "composed-control");

  expect(row?.login.renewable).toBe(true);
  expect(row?.login.status).toBe("degraded");
  expect(row?.login.dirOccupiedByAnotherAccount).toBe(false);
  expect((row?.nextActions ?? []).some((action) => action.includes("switch-account"))).toBe(false);
});
