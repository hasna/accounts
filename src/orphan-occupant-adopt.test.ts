import { test, expect } from "bun:test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { listProfiles } from "./lib/profiles.js";
import { loadStore, profilesDir, saveStore } from "./storage.js";
import { getTool } from "./lib/tools.js";
import { resolveStore } from "./lib/store.js";
import { collectAccountsUsage } from "./lib/usage-report.js";
import { adoptOrphanOccupant, findOrphanOccupants } from "./lib/orphan-occupant.js";
import {
  dirCredentialsFile,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
} from "./lib/claude-layout.js";
import { centralCredentialsSnapshot, centralOAuthSnapshot } from "./lib/auth-store.js";

/**
 * An account that exists only as the current occupant of another profile's dir
 * has no profile naming it, so nothing can route work to it deliberately.
 * `accounts auth adopt` is the verb that gives it one.
 *
 * WHAT MAKES THESE TESTS EVIDENCE: every guard below is exercised by a defect
 * planted ON PURPOSE (a foreign account that already has a profile, a live
 * session on the dir, a host with nothing parked to fall back on), and each
 * refusal is paired with a byte-equality assertion that the credential material
 * was NOT touched. A guard that refuses everything is caught by the adoption
 * tests; an adoption that refuses nothing is caught by the guard tests.
 */

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const UUID_SPARE = "cccccccc-3333-4333-8333-cccccccccccc";
const MALFORMED_UUID = "not-a-uuid-at-all";

const tool = () => getTool("claude");

/** Obviously synthetic. No real credential material appears in this file. */
function credentialJson(label: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + 3_600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 3_600_000,
    },
  });
}

function identityJson(uuid: string, email: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } });
}

function park(dir: string, uuid: string, email: string, label: string): void {
  mkdirSync(profileAuthDir(dir), { recursive: true });
  writeFileSync(profileOAuthSnapshot(dir), identityJson(uuid, email));
  writeFileSync(profileCredentialsSnapshot(dir), credentialJson(label));
}

function parkIdentityOnly(dir: string, uuid: string, email: string): void {
  mkdirSync(profileAuthDir(dir), { recursive: true });
  writeFileSync(profileOAuthSnapshot(dir), identityJson(uuid, email));
}

function occupy(dir: string, uuid: string, email: string, label: string): void {
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, email));
  writeFileSync(dirCredentialsFile(dir), credentialJson(label));
}

/**
 * Register a FIXTURE profile straight into the registry — the pre-existing
 * dirs an adoption acts on, not the thing under test. `addProfile` spends
 * ~1.1s seeding shared capabilities, and paying that for setup pushed these
 * past bun's 5s default under load. The profile adoption CREATES still goes
 * through the real `store.addProfile`, so that path stays covered.
 */
function profileDir(name: string): string {
  const dir = join(profilesDir(), "claude", name);
  mkdirSync(dir, { recursive: true });
  const store = loadStore();
  store.profiles.push({ name, tool: "claude", dir, createdAt: new Date().toISOString() });
  saveStore(store);
  return dir;
}

/** A pid file the liveness probe reads as a running session. */
function attachLiveSession(dir: string): void {
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
}

/** account006 owns HOST but currently runs GUEST — the in-session `/login` residue. */
function occupiedHost(name = "account006"): string {
  const dir = profileDir(name);
  park(dir, UUID_HOST, "host@example.com", "host");
  occupy(dir, UUID_GUEST, "guest@example.com", "guest");
  return dir;
}

// --- detection ---------------------------------------------------------------

test("an account known only as an occupant is found; ones with a profile of their own are not", () => {
  occupiedHost();
  const spare = profileDir("spare");
  park(spare, UUID_SPARE, "spare@example.com", "spare");
  occupy(spare, UUID_SPARE, "spare@example.com", "spare");

  const orphans = findOrphanOccupants(listProfiles("claude"), tool());

  // HOST has an own-identity door; SPARE owns and occupies its own dir. Only
  // the guest is nameless — a detector that returned all three would be
  // indistinguishable from one that returned none of them usefully.
  expect(orphans.map((o) => o.accountUuid)).toEqual([UUID_GUEST]);
  expect(orphans[0]!.email).toBe("guest@example.com");
  expect(orphans[0]!.occupies).toEqual([{ dir: expect.any(String), profileName: "account006" }]);
  expect(orphans[0]!.liveSessions).toBe(0);
  expect(orphans[0]!.usable).toBe(true);
});

// --- the fix -----------------------------------------------------------------

test("adopting an orphan occupant gives the account a profile that names it", async () => {
  const host = occupiedHost();
  const guestBytes = readFileSync(dirCredentialsFile(host));
  const hostParked = readFileSync(profileCredentialsSnapshot(host));

  const result = await adoptOrphanOccupant({ account: "guest@example.com", name: "anya" }, resolveStore());

  expect(result.outcome).toBe("adopted");
  if (result.outcome !== "adopted") throw new Error("unreachable");

  // 1. The account is now reachable BY NAME through the same reporting path
  //    that showed the symptom.
  const entries = await collectAccountsUsage({ tool: "claude" }, resolveStore());
  const guest = entries.find((e) => e.accountUuid === UUID_GUEST)!;
  expect(guest.profiles).toEqual(["anya"]);
  expect(guest.occupies).toEqual([]);

  // 2. The credential MOVED — it is parked under the new profile and mirrored
  //    centrally under the guest's OWN uuid, and byte-equal to what it was.
  const adoptedDir = listProfiles("claude").find((p) => p.name === "anya")!.dir;
  expect(readFileSync(profileCredentialsSnapshot(adoptedDir))).toEqual(guestBytes);
  expect(readFileSync(centralCredentialsSnapshot(UUID_GUEST))).toEqual(guestBytes);
  expect(existsSync(centralOAuthSnapshot(UUID_GUEST))).toBe(true);

  // 3. The host dir is its own account again, on its own parked credential.
  //    Byte-inequality against the guest is the assertion that matters: a
  //    host still holding the guest's token would look "fine" to existsSync.
  expect(readFileSync(dirCredentialsFile(host))).toEqual(hostParked);
  expect(readFileSync(dirCredentialsFile(host))).not.toEqual(guestBytes);
  const hostLive = JSON.parse(readFileSync(join(host, ".claude.json"), "utf8")) as {
    oauthAccount?: { accountUuid?: string };
  };
  expect(hostLive.oauthAccount?.accountUuid).toBe(UUID_HOST);

  // 4. Nothing left a second copy behind for refresh-token rotation to destroy.
  expect(readFileSync(profileCredentialsSnapshot(host))).toEqual(hostParked);
  expect(findOrphanOccupants(listProfiles("claude"), tool())).toEqual([]);
});

test("adopting by accountUuid works as well as by email", async () => {
  occupiedHost();
  const result = await adoptOrphanOccupant({ account: UUID_GUEST.toUpperCase(), name: "anya" }, resolveStore());
  expect(result.outcome).toBe("adopted");
  expect(listProfiles("claude").map((p) => p.name).sort()).toEqual(["account006", "anya"]);
});

test("POSITIVE CONTROL: --dry-run reports the plan and changes nothing", async () => {
  const host = occupiedHost();
  const before = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant(
    { account: "guest@example.com", name: "anya", dryRun: true },
    resolveStore(),
  );

  expect(result.outcome).toBe("would-adopt");
  expect(readFileSync(dirCredentialsFile(host))).toEqual(before);
  expect(listProfiles("claude").map((p) => p.name)).toEqual(["account006"]);
});

// --- planted failures: each guard must be shown REFUSING one ------------------

test("PLANTED: refuses to create a second profile for an account that already has one", async () => {
  // The foreign-overwrite shape, on the naming path: an account with a profile
  // of its own must never acquire a second one, or two dirs end up claiming to
  // own one credential and rotation resolves the tie by destroying a copy.
  occupiedHost();
  const owned = profileDir("guestowned");
  park(owned, UUID_GUEST, "guest@example.com", "guest");
  occupy(owned, UUID_GUEST, "guest@example.com", "guest");
  const ownedParked = readFileSync(profileCredentialsSnapshot(owned));

  const result = await adoptOrphanOccupant({ account: UUID_GUEST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("already-named");
  expect(result.detail).toContain("guestowned");
  expect(listProfiles("claude").map((p) => p.name).sort()).toEqual(["account006", "guestowned"]);
  expect(readFileSync(profileCredentialsSnapshot(owned))).toEqual(ownedParked);
});

test("PLANTED: refuses while a live session is attached to the occupied dir", async () => {
  const host = occupiedHost();
  attachLiveSession(host);
  const before = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant({ account: UUID_GUEST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("sessions-live");
  // Yanking a credential out from under a running session is the one thing
  // this must never do; the file is still exactly where the session left it.
  expect(readFileSync(dirCredentialsFile(host))).toEqual(before);
  expect(listProfiles("claude").map((p) => p.name)).toEqual(["account006"]);
});

test("PLANTED: refuses when the move would strand the host with no credential", async () => {
  const host = profileDir("account006");
  parkIdentityOnly(host, UUID_HOST, "host@example.com"); // identity parked, credential NOT
  occupy(host, UUID_GUEST, "guest@example.com", "guest");
  const before = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant({ account: UUID_GUEST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("host-would-be-stranded");
  expect(readFileSync(dirCredentialsFile(host))).toEqual(before);
});

test("POSITIVE CONTROL: --allow-host-relogin adopts anyway and says the host must re-login", async () => {
  // The stranding refusal must be an operator's choice, not a dead end — a
  // guard nobody can clear would make the healthiest account permanently
  // unreachable, which is the defect it is meant to fix.
  const host = profileDir("account006");
  parkIdentityOnly(host, UUID_HOST, "host@example.com");
  occupy(host, UUID_GUEST, "guest@example.com", "guest");
  const guestBytes = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant(
    { account: UUID_GUEST, name: "anya", allowHostRelogin: true },
    resolveStore(),
  );

  expect(result.outcome).toBe("adopted");
  if (result.outcome !== "adopted") throw new Error("unreachable");
  expect(result.hostRestore).toBe("host-needs-login");
  const adoptedDir = listProfiles("claude").find((p) => p.name === "anya")!.dir;
  expect(readFileSync(profileCredentialsSnapshot(adoptedDir))).toEqual(guestBytes);
});

test("PLANTED: refuses an account whose uuid cannot key the central store", async () => {
  const host = profileDir("account006");
  park(host, UUID_HOST, "host@example.com", "host");
  occupy(host, MALFORMED_UUID, "corrupt@example.com", "corrupt");
  const before = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant({ account: MALFORMED_UUID, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("malformed-uuid");
  expect(readFileSync(dirCredentialsFile(host))).toEqual(before);
});

test("PLANTED: refuses when two dirs hold the account, rather than picking one", async () => {
  const first = occupiedHost("account006");
  const second = occupiedHost("account007");
  const firstBytes = readFileSync(dirCredentialsFile(first));
  const secondBytes = readFileSync(dirCredentialsFile(second));

  const result = await adoptOrphanOccupant({ account: UUID_GUEST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("multiple-occupants");
  expect(result.detail).toContain("account006");
  expect(result.detail).toContain("account007");
  // Moving from one and leaving the other would leave two dirs presenting one
  // account — the two-live-copies state that rotation resolves destructively.
  expect(readFileSync(dirCredentialsFile(first))).toEqual(firstBytes);
  expect(readFileSync(dirCredentialsFile(second))).toEqual(secondBytes);
});

test("PLANTED: refuses when the target profile name is already taken, before moving anything", async () => {
  const host = occupiedHost();
  profileDir("anya");
  const before = readFileSync(dirCredentialsFile(host));

  const result = await adoptOrphanOccupant({ account: UUID_GUEST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("name-taken");
  expect(readFileSync(dirCredentialsFile(host))).toEqual(before);
});

test("PLANTED: refuses an account that is not an occupant of anything", async () => {
  const spare = profileDir("spare");
  park(spare, UUID_SPARE, "spare@example.com", "spare");
  occupy(spare, UUID_SPARE, "spare@example.com", "spare");

  const result = await adoptOrphanOccupant({ account: UUID_HOST, name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("unknown-account");
});

test("PLANTED: refuses an ambiguous selector rather than guessing", async () => {
  const a = profileDir("account006");
  park(a, UUID_HOST, "host@example.com", "host");
  occupy(a, UUID_GUEST, "shared@example.com", "guest");
  const b = profileDir("account007");
  park(b, UUID_SPARE, "spare@example.com", "spare");
  occupy(b, "dddddddd-4444-4444-8444-dddddddddddd", "shared@example.com", "other");

  const result = await adoptOrphanOccupant({ account: "shared@example.com", name: "anya" }, resolveStore());

  expect(result.outcome).toBe("refused");
  if (result.outcome !== "refused") throw new Error("unreachable");
  expect(result.refusal).toBe("ambiguous-selector");
});
