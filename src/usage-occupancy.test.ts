import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildIdentityIndex,
  describeAccountStatus,
  isUsableIdentity,
  statusNeedsOperator,
  statusWithoutValidAccessToken,
  type AccountStatus,
} from "./lib/identity-index.js";
import { collectAccountsUsage, usageDoorSummary, type AccountUsageEntry } from "./lib/usage-report.js";
import type { AccountsStore } from "./lib/store.js";
import { getTool } from "./lib/tools.js";

/**
 * A profile dir that another account currently occupies must not be reported as
 * a dead account.
 *
 * Measured on this fleet 2026-07-29: five profile dirs (account003, account004,
 * account028, account029, account030) were squatted by another account, and
 * `accounts usage --json` reported `status: "expired"` for all five owners while
 * every one of them held a parked credential WITH a refresh token — the state
 * `credential-state.ts` calls `needs-refresh` and documents as "nothing to do".
 * Six of twelve accounts read as dead for this reason and the owner acted on it.
 *
 * Two independent facts were collapsed onto the one word `expired`:
 *   liveness  — renewable (alive) vs no refresh token (genuinely dead)
 *   occupancy — this account's own door is currently running as someone else
 *
 * They are orthogonal: an occupied dir can own a live credential or a dead one,
 * and an unoccupied dir can own either too. Encoding occupancy INTO `status`
 * would re-create the defect from the other side, so occupancy is reported on
 * its own axis and `status` stays a pure credential-liveness verdict.
 */

let home: string;
let root: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-occ-home-"));
  root = mkdtempSync(join(tmpdir(), "accounts-occ-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

interface CredFixture {
  uuid: string;
  email: string;
  /** Negative for an aged-out access token. */
  expiresInMs?: number;
  /** false builds the genuinely-dead payload: no refresh token at all. */
  refreshToken?: boolean;
}

// Synthetic, obviously-fake token material. Never a real credential value.
function credentialJson(f: CredFixture): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `SYNTHETIC-access-${f.uuid}`,
      ...(f.refreshToken === false ? {} : { refreshToken: `SYNTHETIC-refresh-${f.uuid}` }),
      expiresAt: Date.now() + (f.expiresInMs ?? 60_000),
    },
  });
}

function identityJson(f: CredFixture): string {
  return JSON.stringify({ oauthAccount: { accountUuid: f.uuid, emailAddress: f.email } });
}

/** The account whose credential currently occupies the dir's live files. */
function writeLive(dir: string, f: CredFixture): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), identityJson(f));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(f));
}

/** The dir's OWN identity and its parked copy — what a switch leaves behind. */
function writeSnapshot(dir: string, f: CredFixture): void {
  const auth = join(dir, ".accounts-auth");
  mkdirSync(auth, { recursive: true });
  writeFileSync(join(auth, "oauth-account.json"), identityJson(f));
  writeFileSync(join(auth, "credentials.json"), credentialJson(f));
}

function makeDir(name: string): string {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

const HOST = { uuid: "11111111-1111-4111-8111-111111111111", email: "host@example.test" };
const GUEST = { uuid: "22222222-2222-4222-8222-222222222222", email: "guest@example.test" };

/**
 * The exact shape measured on the fleet: the dir's own account is parked with an
 * aged-out access token but an intact refresh token, while a DIFFERENT account's
 * live, valid credential occupies the dir.
 */
function squattedProfile(name: string, opts: { ownerRenewable?: boolean } = {}): string {
  const dir = makeDir(name);
  writeSnapshot(dir, {
    ...HOST,
    expiresInMs: -8 * 60 * 60 * 1000,
    ...(opts.ownerRenewable === false ? { refreshToken: false } : {}),
  });
  writeLive(dir, { ...GUEST, expiresInMs: 60 * 60 * 1000 });
  return dir;
}

function stubStore(profiles: Array<{ name: string; dir: string }>): AccountsStore {
  return {
    transport: "local",
    listProfiles: async () => profiles as never,
  } as unknown as AccountsStore;
}

/**
 * A COUNTING stub, not a throwing one: `fetchAccountUsage` catches everything a
 * fetch impl throws and turns it into a `network` error, so a stub that threw
 * would be swallowed and "the endpoint was never queried" would be unprovable.
 * The count is the evidence.
 */
function countingFetch(): { impl: typeof fetch; calls: () => number } {
  let calls = 0;
  const impl = (async () => {
    calls += 1;
    return new Response("upstream unavailable", { status: 503 });
  }) as unknown as typeof fetch;
  return { impl, calls: () => calls };
}

test("a squatted profile's owner is reported needs-refresh, not expired", () => {
  const dir = squattedProfile("account004");

  const index = buildIdentityIndex([{ name: "account004", dir }], tool());
  const owner = index.find((i) => i.accountUuid === HOST.uuid)!;

  // The credential really is the owner's own parked copy, not the squatter's —
  // if this ever reads the guest's file the rest of the test proves nothing.
  expect(owner.credential?.source).toBe("profile-snapshot");
  expect(owner.credential?.renewable).toBe(true);
  expect(owner.credential?.valid).toBe(false);

  expect(owner.status).toBe("needs-refresh");
  expect(isUsableIdentity(owner)).toBe(true);
});

test("POSITIVE CONTROL: a squatted profile whose own credential is genuinely dead still reports expired", () => {
  // Same occupancy, same aged-out expiry — the ONLY difference is the absent
  // refresh token. Without this the fix could be "relabel everything
  // needs-refresh" and every other assertion here would still pass.
  const dir = squattedProfile("account004-dead", { ownerRenewable: false });

  const index = buildIdentityIndex([{ name: "account004-dead", dir }], tool());
  const owner = index.find((i) => i.accountUuid === HOST.uuid)!;

  expect(owner.credential?.renewable).toBe(false);
  expect(owner.status).toBe("expired");
  expect(isUsableIdentity(owner)).toBe(false);
});

test("the owner's own-identity door records WHICH account occupies it", () => {
  const dir = squattedProfile("account029");

  const index = buildIdentityIndex([{ name: "account029", dir }], tool());
  const owner = index.find((i) => i.accountUuid === HOST.uuid)!;
  const door = owner.doors.find((d) => d.role === "own-identity")!;

  expect(door.occupiedBy).toBe(GUEST.uuid);
});

test("POSITIVE CONTROL: an unoccupied profile's own door carries no occupiedBy", () => {
  // The dir's live files hold its OWN account. If `occupiedBy` were set
  // unconditionally the squatted-door test above would pass for the wrong reason.
  const dir = makeDir("account031");
  writeSnapshot(dir, { ...HOST, expiresInMs: -8 * 60 * 60 * 1000 });
  writeLive(dir, { ...HOST, expiresInMs: 60 * 60 * 1000 });

  const index = buildIdentityIndex([{ name: "account031", dir }], tool());
  const owner = index.find((i) => i.accountUuid === HOST.uuid)!;
  const door = owner.doors.find((d) => d.role === "own-identity")!;

  expect(door.occupiedBy).toBeUndefined();
});

test("POSITIVE CONTROL: an idle profile with no live occupant at all is not reported as occupied", () => {
  // No `.claude.json` occupant: the dir is parked, not squatted. Treating
  // "nobody is here" as occupancy would make the field meaningless.
  const dir = makeDir("account030-idle");
  writeSnapshot(dir, { ...HOST, expiresInMs: -8 * 60 * 60 * 1000 });

  const index = buildIdentityIndex([{ name: "account030-idle", dir }], tool());
  const owner = index.find((i) => i.accountUuid === HOST.uuid)!;

  expect(owner.doors.find((d) => d.role === "own-identity")!.occupiedBy).toBeUndefined();
  expect(owner.status).toBe("needs-refresh");
});

test("usage reports the squatted owner as needs-refresh and names the profile it is displaced from", async () => {
  const dir = squattedProfile("account003");
  const fetchStub = countingFetch();

  const entries = await collectAccountsUsage(
    { tool: "claude", maxAgeMs: 0, fetchImpl: fetchStub.impl },
    stubStore([{ name: "account003", dir }]),
  );
  const owner = entries.find((e) => e.accountUuid === HOST.uuid)!;
  const guest = entries.find((e) => e.accountUuid === GUEST.uuid)!;

  // Exactly one query: the guest, whose access token is valid. The owner's aged
  // -out token cannot authenticate the endpoint, so widening its STATUS must not
  // widen what gets queried.
  expect(fetchStub.calls()).toBe(1);
  expect(owner.source).toBe("none");

  // The defect verbatim: this read "expired" while the same output reported the
  // dir as occupied by the guest.
  expect(owner.status).toBe("needs-refresh");
  expect(owner.profiles).toEqual(["account003"]);
  expect(owner.displacedFrom).toEqual(["account003"]);

  // The other half of the same output, unchanged.
  expect(guest.occupies).toEqual(["account003"]);
  expect(guest.displacedFrom).toEqual([]);
});

test("POSITIVE CONTROL: usage still reports a genuinely dead squatted owner as expired", async () => {
  const dir = squattedProfile("account003-dead", { ownerRenewable: false });

  const entries = await collectAccountsUsage(
    { tool: "claude", maxAgeMs: 0, fetchImpl: countingFetch().impl },
    stubStore([{ name: "account003-dead", dir }]),
  );
  const owner = entries.find((e) => e.accountUuid === HOST.uuid)!;

  expect(owner.status).toBe("expired");
  // Occupancy is reported either way: it is a separate fact from liveness, and
  // an operator needs both to know whether re-login or a restore is the fix.
  expect(owner.displacedFrom).toEqual(["account003-dead"]);
});

test("an account displaced from one door and healthy in another reports both", async () => {
  // Occupancy is per-door. A scalar `occupied` on the account would have to pick
  // one of these and would be wrong for the other.
  const squatted = squattedProfile("door-taken");
  const free = makeDir("door-free");
  writeSnapshot(free, { ...HOST, expiresInMs: 60 * 60 * 1000 });
  writeLive(free, { ...HOST, expiresInMs: 60 * 60 * 1000 });

  const entries = await collectAccountsUsage(
    { tool: "claude", maxAgeMs: 0, fetchImpl: countingFetch().impl },
    stubStore([
      { name: "door-taken", dir: squatted },
      { name: "door-free", dir: free },
    ]),
  );
  const owner = entries.find((e) => e.accountUuid === HOST.uuid)!;

  expect(owner.profiles).toEqual(["door-free", "door-taken"]);
  expect(owner.displacedFrom).toEqual(["door-taken"]);
  // A valid credential in the free door still wins the ranking, so the account
  // is `ok` overall — displacement does not demote a working account.
  expect(owner.status).toBe("ok");
});

// ---------------------------------------------------------------------------
// The operator-facing wording. This is the layer that actually misled a human,
// so it is asserted directly rather than left to a CLI smoke test.
// ---------------------------------------------------------------------------

test("every status carries a gloss, and only the actionable ones are flagged for a human", () => {
  const all: AccountStatus[] = ["ok", "needs-refresh", "expired", "no-credentials"];

  for (const status of all) {
    const gloss = describeAccountStatus(status);
    // A bare identifier with no explanation is the thing that misread as "dead".
    expect(gloss.length).toBeGreaterThan(0);
    expect(gloss).not.toBe(status);
  }

  // needs-refresh must NOT summon an operator: that is the whole correction.
  expect(statusNeedsOperator("needs-refresh")).toBe(false);
  expect(statusNeedsOperator("ok")).toBe(false);
  expect(statusNeedsOperator("expired")).toBe(true);
  expect(statusNeedsOperator("no-credentials")).toBe(true);

  // The two words an operator acts on differently must not read the same.
  expect(describeAccountStatus("needs-refresh")).toContain("renews it on use");
  expect(describeAccountStatus("expired")).toContain("re-authentication required");
  expect(describeAccountStatus("needs-refresh")).not.toBe(describeAccountStatus("expired"));
});

test("the door line names displacement, not just ownership", () => {
  const squatted: AccountUsageEntry = {
    accountUuid: HOST.uuid,
    status: "needs-refresh",
    profiles: ["account004"],
    occupies: [],
    displacedFrom: ["account004"],
    source: "none",
  };
  expect(usageDoorSummary(squatted)).toEqual(["profiles: account004", "displaced from: account004"]);

  const squatter: AccountUsageEntry = {
    accountUuid: GUEST.uuid,
    status: "ok",
    profiles: ["account010"],
    occupies: ["account004", "account010"],
    displacedFrom: [],
    source: "cache",
  };
  // POSITIVE CONTROL: an account that is displaced from nothing must not gain
  // the phrase. Printing it unconditionally would make it meaningless.
  expect(usageDoorSummary(squatter)).toEqual([
    "profiles: account010",
    "running in: account004, account010",
  ]);
  expect(usageDoorSummary(squatter).join(" ")).not.toContain("displaced");
});

test("the shared no-usable-access-token verdict is the ONE place that word is chosen", () => {
  // Directly covers the usage collector's mid-flight downgrade, whose branch is
  // only reachable when another process rewrites the credential file between the
  // index scan and the token read. It cannot be driven through the public API, so
  // it is made correct by calling this instead of re-deciding inline.
  const ref = (renewable: boolean) => ({
    path: "/dev/null",
    source: "central" as const,
    expiresAt: 0,
    hasAccessToken: true,
    hasRefreshToken: renewable,
    valid: false,
    renewable,
  });

  expect(statusWithoutValidAccessToken(ref(true))).toBe("needs-refresh");
  expect(statusWithoutValidAccessToken(ref(false))).toBe("expired");
  expect(statusWithoutValidAccessToken(undefined)).toBe("no-credentials");
});
