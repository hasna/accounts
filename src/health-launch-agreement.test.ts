/**
 * `accounts health` must never report `ok` for a profile `accounts launch` will
 * refuse.
 *
 * MEASURED ON STATION01, 2026-07-30, against main with #63 already landed. Six
 * profile dirs carried a switched-account marker from an in-place switch.
 * `accounts health` reported `status: "ok"` for five of them. `accounts launch
 * account031` returned:
 *
 *   profile "account031" cannot launch: its config dir currently carries the
 *   account of "account029" (in-place switch) with 1 live session(s) attached
 *
 * #63 added `dirOccupiedByAnotherAccount` and a reconcile next-action, and both
 * were emitted correctly — `occupied=True` on all six. What it did not do was
 * let occupancy affect `status`. So the flag said occupied and the verdict said
 * `ok` in the same payload, and anything reading the verdict — a scheduler, a
 * pool manager, a human skimming — is told the profile is fine.
 *
 * That is the contradiction #63's own comment warns about, still live one field
 * away from the fix. It was reported to me as "accounts cannot launch two
 * profiles concurrently"; concurrency turned out to be a red herring (two
 * concurrent launches on unmarked profiles both exit 0). The actual mechanism is
 * that auto-switched profiles silently stop being launchable while every
 * inspection surface still calls them healthy.
 *
 * THE INVARIANT, and it is the only acceptance test that means anything here:
 * a refusable profile is not `ok`.
 */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  claudeProfileAuthHealth,
  ensureProfileAuthSnapshot,
  healSwitchedProfileDir,
  writeSwitchedAccountMarker,
} from "./lib/claude-auth.js";
import { addProfile } from "./lib/profiles.js";
import { getAccountsReadiness } from "./lib/readiness.js";
import { getTool } from "./lib/tools.js";

let home: string;
let liveBase: string;
const dirs: string[] = [];

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-agreement-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-agreement-live-"));
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

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

/** Obviously-synthetic material. Never a real token shape. */
function credentialJson(label: string, expired = false): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `SYNTHETIC-${label}-access`,
      refreshToken: `SYNTHETIC-${label}-refresh`,
      expiresAt: expired ? Date.now() - 600_000 : Date.now() + 600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

/** A profile whose own identity and credential are parked and healthy. */
function makeProfile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `agreement-${name}-`));
  dirs.push(dir);
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_HOST, "host"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("host"));
  addProfile({ name, dir, email: "host@example.com" });
  ensureProfileAuthSnapshot(dir, getTool("claude"));
  return dir;
}

/** The residue of `accounts switch-account <guest> --dir <this profile's dir>`. */
function switchDirToGuest(dir: string, guestProfile: string): void {
  writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
  writeFileSync(join(dir, ".credentials.json"), credentialJson("guest"));
  writeSwitchedAccountMarker(dir, { profile: guestProfile, email: "guest@example.com" });
}

async function readinessFor(name: string) {
  const readiness = await getAccountsReadiness({
    env: { ...process.env, HASNA_ACCOUNTS_S3_BUCKET: "accounts-agreement-test" },
  });
  return readiness.profiles.find((entry) => entry.name === name);
}

test("THE INVARIANT: a profile whose dir carries another account is never reported ok", async () => {
  const dir = makeProfile("host");
  switchDirToGuest(dir, "guest-profile");

  // The detector fires — this is what #63 already gets right.
  expect(claudeProfileAuthHealth(dir, getTool("claude")).dirOccupiedByAnotherAccount).toBe(true);

  const row = await readinessFor("host");
  // ...and the verdict must follow it. `ok` here is the exact payload that told
  // a scheduler five unlaunchable profiles were fine.
  expect(row?.login.dirOccupiedByAnotherAccount).toBe(true);
  expect(row?.login.status).not.toBe("ok");
  expect(row?.status).not.toBe("ok");
});

test("health and launch agree: whatever launch refuses, health does not call ok", async () => {
  const dir = makeProfile("host");
  switchDirToGuest(dir, "guest-profile");

  // `healSwitchedProfileDir` is the guard the launch path runs. With no live
  // session it heals rather than refusing, so assert on the state it leaves.
  const healed = healSwitchedProfileDir(dir, getTool("claude"), "host");
  expect(healed).toBe(true);

  // After healing, the dir is the profile's own again and health may say ok —
  // that is agreement, not a downgrade. The invariant is about the window
  // BEFORE reconciliation, which the first test pins.
  const row = await readinessFor("host");
  expect(row?.login.dirOccupiedByAnotherAccount).toBe(false);
});

test("POSITIVE CONTROL: an unoccupied profile is still ok, so the check is not just failing everything", async () => {
  makeProfile("clean");

  const row = await readinessFor("clean");

  expect(row?.login.dirOccupiedByAnotherAccount).toBe(false);
  expect(row?.login.status).toBe("ok");
});

test("the reconcile action is offered, and it is the FIRST thing an operator reads", async () => {
  const dir = makeProfile("host");
  switchDirToGuest(dir, "guest-profile");

  // Asserted on login.nextActions, which is where #63 places the ordering
  // guarantee. The profile-level list prepends dir/email/configs actions, so
  // index 0 there would be testing a different thing and would pass or fail for
  // reasons unrelated to occupancy.
  const row = await readinessFor("host");
  const loginActions = row?.login.nextActions ?? [];
  const reconcileAt = loginActions.findIndex((action) => action.includes("switch-account"));
  const loginAt = loginActions.findIndex((action) => action.includes("accounts login"));

  expect(reconcileAt).toBe(0);
  expect(loginAt).toBeGreaterThan(reconcileAt);
  // And the profile-level list still surfaces it somewhere.
  expect((row?.nextActions ?? []).some((action) => action.includes("switch-account"))).toBe(true);
});

test("`accounts show` displays the reason a launch would be refused", async () => {
  // The CLI refused `accounts launch account031` naming account029, while
  // `accounts show account031 --json` displayed the right dir, the right email
  // and no mention of account029 anywhere. An operator cannot diagnose a
  // refusal from a command that will not show them the state causing it.
  const { spawnSync } = await import("node:child_process");
  const dir = makeProfile("shown");
  switchDirToGuest(dir, "guest-profile");

  const result = spawnSync(process.execPath, ["run", "src/cli.ts", "show", "shown", "--tool", "claude", "--json"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HASNA_TEST_GUARD_HELD: "1" },
  });

  expect(result.status).toBe(0);
  const payload = JSON.parse(result.stdout) as { switchedAway?: { profile?: string } };
  expect(payload.switchedAway?.profile).toBe("guest-profile");
  // Named in the raw output too, so a human reading it without --json sees it.
  const text = spawnSync(process.execPath, ["run", "src/cli.ts", "show", "shown", "--tool", "claude"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HASNA_TEST_GUARD_HELD: "1" },
  });
  expect(text.stdout).toContain("guest-profile");
  expect(text.stdout).toContain("cannot launch until it is reconciled");
});

test("POSITIVE CONTROL: an unswitched profile shows no switchedAway noise", async () => {
  const { spawnSync } = await import("node:child_process");
  makeProfile("quiet");

  const result = spawnSync(process.execPath, ["run", "src/cli.ts", "show", "quiet", "--tool", "claude", "--json"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, HASNA_TEST_GUARD_HELD: "1" },
  });

  const payload = JSON.parse(result.stdout) as { switchedAway?: unknown };
  expect(payload.switchedAway).toBeUndefined();
});
