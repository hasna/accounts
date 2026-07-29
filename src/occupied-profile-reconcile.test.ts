import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  ensureProfileAuthSnapshot,
  planParkedRecovery,
  recoverParkedCredential,
  writeSwitchedAccountMarker,
} from "./lib/claude-auth.js";
import { profileCredentialsSnapshot, profileOAuthSnapshot } from "./lib/claude-layout.js";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { profileCredentialLayers, profileDirOccupancy } from "./lib/credential-state.js";
import { getTool } from "./lib/tools.js";

/**
 * Regressions for 6a58cdb8 — a profile dir OCCUPIED by another account is never
 * reconciled back to its own parked credential, and nothing reports it.
 *
 * THE MEASURED MECHANISM (origin/main 9d04bd0): every "is there anything to do"
 * decision is made from credential CONTENT HEALTH, never from IDENTITY.
 *
 *   - `parkedCredentialVerdict` computes `recoverable = liveUnusable &&
 *     parkedRestorable`, and an occupant's credential is healthy, so
 *     `liveUnusable` is false;
 *   - `recoverParkedCredential` returns `live-credential-usable` on its FIRST
 *     branch, above both the `parkedRestorable` check and the identity gate, so
 *     the `identity-would-change` outcome is unreachable whenever the occupant's
 *     credential works. It can only ever fire for a dir held by a DEAD foreign
 *     credential;
 *   - `healSwitchedProfileDir` — the only code that ever undoes occupation —
 *     returns false on its third line when there is no switch marker, and an
 *     in-session `/login` writes no marker (defect 0e7069a9, PR #60).
 *
 * So (own uuid != live uuid) maps to no action and no report anywhere, and the
 * seven occupied dirs measured on this fleet stay occupied indefinitely.
 *
 * FIXTURE DISCIPLINE: every fixture below gives BOTH accounts a healthy,
 * unexpired, refresh-token-bearing credential. A fixture that degraded the
 * occupant's credential would be detected by the pre-existing content-health
 * path and would prove nothing about identity. Token values are literal
 * placeholders; nothing here reaches a network.
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
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

/** Healthy: refresh token present, comfortably unexpired. */
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

/** The rotation fingerprint: structure intact, both secrets gone, expiry zeroed. */
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

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

/** A registered profile holding the host account, with its own auth parked. */
function makeHostProfile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `occupied-${name}-`));
  dirs.push(dir);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/**
 * The on-disk residue of an in-session `/login` to another account: live
 * identity AND live credential both become the guest's, and NO switch marker is
 * written. This is the shape the fleet is actually in.
 */
function occupyMarkerless(dir: string, uuid = UUID_GUEST, label = "guest"): void {
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, label));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
  expect(
    existsSync(join(dir, ".accounts-auth", "switched-account.json")),
    "fixture must reproduce the NO-MARKER path — a marker routes to healSwitchedProfileDir instead",
  ).toBe(false);
}

/** Attach a live session to the dir, using this process's own (definitely alive) pid. */
function attachLiveSession(dir: string): void {
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
}

function liveOauth(dir: string): { accountUuid?: string } {
  const raw = JSON.parse(readFileSync(join(dir, ".claude.json"), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  return raw.oauthAccount ?? {};
}

function liveCredential(dir: string): { accessToken?: string; refreshToken?: string } {
  const raw = JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")) as {
    claudeAiOauth?: { accessToken?: string; refreshToken?: string };
  };
  return raw.claudeAiOauth ?? {};
}

// --- detection ---------------------------------------------------------------

test("occupancy is detected from identity, not from how healthy the live credential is", () => {
  // The discriminating input: the occupant's credential is perfectly healthy.
  // Content ranking cannot separate two healthy credentials — only identity can.
  const dir = makeHostProfile("detect");
  const before = profileDirOccupancy(dir, tool());
  expect(before.occupied).toBe(false);

  occupyMarkerless(dir);

  const after = profileDirOccupancy(dir, tool());
  expect(after.occupied).toBe(true);
  expect(after.marked).toBe(false);
  expect(after.ownUuid).toBe(UUID_HOST);
  expect(after.liveUuid).toBe(UUID_GUEST);
  // Both behaviours are reachable from this check: it said false a moment ago.
});

test("the layer view carries occupancy, so every consumer can see it", () => {
  const dir = makeHostProfile("layers");
  occupyMarkerless(dir);

  const layers = profileCredentialLayers(dir, tool());
  // The live slot is HEALTHY. That is the whole point: the old content-only
  // verdict reads this and concludes there is nothing to do.
  expect(layers.live.state).toBe("usable");
  expect(layers.occupancy?.occupied).toBe(true);
});

// --- the fix: reconciliation --------------------------------------------------

test("an idle dir occupied by another account is reconciled back to its own account", () => {
  const dir = makeHostProfile("idle");
  const parkedCredential = readFileSync(profileCredentialsSnapshot(dir));
  const parkedIdentity = readFileSync(profileOAuthSnapshot(dir));
  occupyMarkerless(dir);

  const result = recoverParkedCredential(dir, tool(), "idle");

  expect(result.outcome).toBe("reconciled");
  // The dir presents its OWN account again, with its OWN credential.
  expect(liveOauth(dir).accountUuid).toBe(UUID_HOST);
  expect(liveCredential(dir).accessToken).toBe("host-access");
  // ARCHIVE-NEVER-DELETE: the park is the source and must survive byte-for-byte.
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parkedCredential);
  expect(readFileSync(profileOAuthSnapshot(dir))).toEqual(parkedIdentity);
});

test("reconciliation parks the OCCUPANT's credential before overwriting it", () => {
  // The invariant that makes this safe to do at all: credentials are parked,
  // never destroyed. Overwriting the live slot without parking the occupant
  // first would destroy the guest's only copy in this dir.
  const dir = makeHostProfile("park");
  occupyMarkerless(dir);
  const guestBytes = readFileSync(join(dir, ".credentials.json"));
  expect(existsSync(centralCredentialsSnapshot(UUID_GUEST))).toBe(false);

  const result = recoverParkedCredential(dir, tool(), "park");

  expect(result.outcome).toBe("reconciled");
  // Byte-equality against what was live: the guest's material survives intact,
  // under the GUEST's uuid — not smuggled into the host's central entry.
  expect(readFileSync(centralCredentialsSnapshot(UUID_GUEST))).toEqual(guestBytes);
  expect(readFileSync(centralCredentialsSnapshot(UUID_HOST))).not.toEqual(guestBytes);
});

test("reconciliation needs no switch marker — that is the case nothing owned", () => {
  const dir = makeHostProfile("nomarker");
  occupyMarkerless(dir);
  expect(existsSync(join(dir, ".accounts-auth", "switched-account.json"))).toBe(false);

  expect(recoverParkedCredential(dir, tool(), "nomarker").outcome).toBe("reconciled");
});

// --- the live-session case ----------------------------------------------------

test("reconciliation REFUSES to evict an occupant that has live sessions attached", () => {
  // account004 on this fleet: occupied, with one live session belonging to the
  // occupant. Swapping the credential under a session that is actively
  // refreshing it races the refresh — the one confirmed destructive path.
  const dir = makeHostProfile("busy");
  occupyMarkerless(dir);
  attachLiveSession(dir);
  const guestCredential = readFileSync(join(dir, ".credentials.json"));

  const result = recoverParkedCredential(dir, tool(), "busy");

  expect(result.outcome).toBe("occupied-by-another-account");
  // Nothing written: the dir is exactly as it was.
  expect(liveOauth(dir).accountUuid).toBe(UUID_GUEST);
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(guestCredential);
  // The refusal is actionable, not just a status word.
  expect(result.detail).toContain("1 live session");
  expect(result.detail).toContain("switch-account");
});

// --- planted failures the guard must refuse -----------------------------------

test("PLANTED: reconciliation refuses when the profile's own park cannot serve", () => {
  // Deliberate failure: an occupied dir whose owner has NO usable parked copy.
  // A reconciliation that acted on occupancy alone would blank a working guest
  // credential and leave a dead one — strictly worse than the occupation.
  const dir = makeHostProfile("noparked");
  writeFileSync(profileCredentialsSnapshot(dir), rotatedAwayJson());
  writeFileSync(centralCredentialsSnapshot(UUID_HOST), rotatedAwayJson());
  occupyMarkerless(dir);
  const guestCredential = readFileSync(join(dir, ".credentials.json"));

  const result = recoverParkedCredential(dir, tool(), "noparked");

  expect(result.outcome).toBe("no-parked-credential");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(guestCredential);
  expect(liveOauth(dir).accountUuid).toBe(UUID_GUEST);
});

test("PLANTED: an occupant whose credential cannot be parked is not overwritten", () => {
  // Found by adversarial self-review of this change, not by the brief.
  // Occupancy detection tolerates a malformed uuid on purpose — a garbled
  // identity still contradicts the parked one — but the central store keys on a
  // well-formed uuid because it becomes a path segment. Reconciling here would
  // destroy the only copy of a HEALTHY credential, trading this defect for a
  // worse one on exactly the inputs least likely to be well-formed.
  const dir = makeHostProfile("unparkable");
  writeFileSync(join(dir, ".claude.json"), identityJson("not-a-uuid", "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  const guestCredential = readFileSync(join(dir, ".credentials.json"));

  // The discriminating pair: still detected as occupation...
  expect(profileDirOccupancy(dir, tool()).occupied).toBe(true);
  // ...but refused rather than acted on.
  const result = recoverParkedCredential(dir, tool(), "unparkable");
  expect(result.outcome).toBe("occupied-by-another-account");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(guestCredential);
  expect(result.detail).toContain("not well-formed");
});

test("a malformed-uuid occupant whose credential is DEAD is reconciled — nothing to lose", () => {
  // The other side of the branch above, so it is a real condition and not an
  // unconditional refusal: when there is no working credential to preserve, the
  // unparkable occupant is no reason to leave the profile stranded.
  const dir = makeHostProfile("unparkable-dead");
  writeFileSync(join(dir, ".claude.json"), identityJson("not-a-uuid", "guest"));
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  expect(recoverParkedCredential(dir, tool(), "unparkable-dead").outcome).toBe("reconciled");
  expect(liveCredential(dir).accessToken).toBe("host-access");
});

test("PLANTED: a MARKED occupation is still left to healSwitchedProfileDir", () => {
  // `switch-account` records its own occupations and owns undoing them, with a
  // liveness refusal of its own. Reconciling marked dirs here would duplicate
  // that decision in two places and let them disagree.
  const dir = makeHostProfile("marked");
  occupyMarkerless(dir);
  writeSwitchedAccountMarker(dir, { profile: "guest", email: "guest@example.com" });
  const guestCredential = readFileSync(join(dir, ".credentials.json"));

  const result = recoverParkedCredential(dir, tool(), "marked");

  expect(result.outcome).not.toBe("reconciled");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(guestCredential);
});

test("PLANTED: an occupation this profile cannot prove is not its own is refused", () => {
  // No parked identity => `own` is unknown => not provably occupied. Acting
  // would pair whatever the dir currently shows with this profile's credential.
  const dir = mkdtempSync(join(tmpdir(), "occupied-unknown-"));
  dirs.push(dir);
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("parked"));
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  addProfile({ name: "unknownident", dir });

  expect(profileDirOccupancy(dir, tool()).occupied).toBe(false);
  const result = recoverParkedCredential(dir, tool(), "unknownident");
  expect(result.outcome).not.toBe("reconciled");
  expect(liveOauth(dir).accountUuid).toBe(UUID_GUEST);
});

// --- positive controls: the guard must NOT fire on its own account ------------

test("POSITIVE CONTROL: a healthy dir running its OWN account is left untouched", () => {
  // If this ever fails, the guard has degenerated into "always reconcile" and
  // every assertion above is worthless.
  const dir = makeHostProfile("own");
  const before = readFileSync(join(dir, ".credentials.json"));

  const result = recoverParkedCredential(dir, tool(), "own");

  expect(result.outcome).toBe("live-credential-usable");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(before);
});

test("POSITIVE CONTROL: a case-variant spelling of the same uuid is not occupation", () => {
  const dir = makeHostProfile("case");
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST.toUpperCase(), "host"));

  expect(profileDirOccupancy(dir, tool()).occupied).toBe(false);
  expect(recoverParkedCredential(dir, tool(), "case").outcome).toBe("live-credential-usable");
});

test("POSITIVE CONTROL: a rotated-away dir on its own account still RECOVERS, not reconciles", () => {
  // The pre-existing recovery must keep working; occupancy must not have
  // swallowed it.
  const dir = makeHostProfile("rotated");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  const result = recoverParkedCredential(dir, tool(), "rotated");

  expect(result.outcome).toBe("recovered");
  expect(liveCredential(dir).accessToken).toBe("host-access");
});

// --- dry-run must not be able to disagree with the real run -------------------

test("the dry-run plan and the acting call agree, because they are one decision", () => {
  // `repair-auth --dry-run` re-derived its verdict from `verdict.recoverable`
  // instead of asking the same function, which is why it reported
  // `nothing-to-do / live credential is usable` for an occupied dir.
  const dir = makeHostProfile("plan");
  occupyMarkerless(dir);

  const plan = planParkedRecovery(dir, tool(), "plan");
  expect(plan.action).toBe("reconcile");
  expect(plan.outcome).toBe("reconciled");
  // Planning writes nothing.
  expect(liveOauth(dir).accountUuid).toBe(UUID_GUEST);

  expect(recoverParkedCredential(dir, tool(), "plan").outcome).toBe(plan.outcome);
});

test("the plan reports the blocked occupied case as an action of none", () => {
  const dir = makeHostProfile("planbusy");
  occupyMarkerless(dir);
  attachLiveSession(dir);

  const plan = planParkedRecovery(dir, tool(), "planbusy");
  expect(plan.action).toBe("none");
  expect(plan.outcome).toBe("occupied-by-another-account");
});

// --- the operator surface -----------------------------------------------------

test("`repair-auth --dry-run --json` reports an occupied dir instead of nothing-to-do", () => {
  // The surface an operator actually reaches. The library decision is covered
  // above; this proves the verb reports it rather than filtering it out, which
  // is the half of the defect that let seven dirs stay occupied unnoticed.
  const dir = makeHostProfile("cliocc");
  occupyMarkerless(dir);

  const run = spawnSync(process.execPath, ["run", "src/cli.ts", "repair-auth", "cliocc", "--dry-run", "--json"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, NODE_ENV: "test", ACCOUNTS_HOME: home, ACCOUNTS_TEST_LIVE_DIR: liveBase },
  });

  expect(run.status).toBe(0);
  const parsed = JSON.parse(run.stdout) as {
    dryRun: boolean;
    profiles: Array<{ profile: string; outcome: string; occupiedByAnotherAccount?: boolean }>;
  };
  const row = parsed.profiles.find((p) => p.profile === "cliocc");
  expect(row?.outcome).toBe("would-reconcile");
  expect(row?.occupiedByAnotherAccount).toBe(true);
  // --dry-run wrote nothing.
  expect(liveOauth(dir).accountUuid).toBe(UUID_GUEST);
});
