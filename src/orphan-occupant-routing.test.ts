import { test, expect } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadStore, profilesDir, saveStore } from "./storage.js";
import { getTool } from "./lib/tools.js";
import { resolveStore } from "./lib/store.js";
import { collectAccountsUsage, pickHealthiestAccount } from "./lib/usage-report.js";
import {
  dirCredentialsFile,
  profileAuthDir,
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
} from "./lib/claude-layout.js";

/**
 * An account known to this machine ONLY as the current occupant of another
 * profile's dir has no profile naming it, and the healthiest-account selector
 * gives up on it at rank 1 instead of falling through to a reachable runner-up.
 *
 * MEASURED SYMPTOM this covers: `anya@ideawin.com` reports `status: ok` with
 * the highest headroom in the fleet and `profiles: []`, present only as an
 * occupant of `account006`'s dir.
 *
 * WHY THE FIXTURE CAN PRODUCE THE FAILURE: the occupant is given a genuinely
 * healthy credential and the BEST headroom of the pool, so it wins the ranking
 * outright. A fixture where the occupant ranked second could not distinguish
 * "walks past a doorless winner" from "never had to" — the two behaviours these
 * tests separate are (a) give up at rank 1, and (b) walk the ranking.
 */

const UUID_HOST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_GUEST = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const UUID_SPARE = "cccccccc-3333-4333-8333-cccccccccccc";

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

/** The dir's OWN parked identity + credential — what makes an own-identity door. */
function park(dir: string, uuid: string, email: string, label: string): void {
  mkdirSync(profileAuthDir(dir), { recursive: true });
  writeFileSync(profileOAuthSnapshot(dir), identityJson(uuid, email));
  writeFileSync(profileCredentialsSnapshot(dir), credentialJson(label));
}

/** The dir's LIVE files — whoever currently occupies it. */
function occupy(dir: string, uuid: string, email: string, label: string): void {
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, email));
  writeFileSync(dirCredentialsFile(dir), credentialJson(label));
}

/**
 * Register a profile straight into the registry.
 *
 * `addProfile` is deliberately NOT used here: it spends ~1.1s per call seeding
 * shared capabilities, which pushed these tests past bun's 5s default under
 * parallel load and produced a timeout that looked like an assertion failure.
 * Nothing below is a test OF profile creation — these exercise door reasoning
 * and candidate selection, which read only `{name, dir}`. The adopt tests,
 * which DO cover profile creation, call the real `store.addProfile`.
 */
function profileDir(name: string): string {
  const dir = join(profilesDir(), "claude", name);
  mkdirSync(dir, { recursive: true });
  const store = loadStore();
  store.profiles.push({ name, tool: "claude", dir, createdAt: new Date().toISOString() });
  saveStore(store);
  return dir;
}

/** `percentUsed` per access token; anything else is rejected like a bad token. */
function usageFetch(percentUsedByToken: Record<string, number>): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const token = String(headers.Authorization ?? "").replace(/^Bearer /, "");
    const used = percentUsedByToken[token];
    if (used === undefined) return new Response("nope", { status: 401 });
    const resets = new Date(Date.now() + 3_600_000).toISOString();
    return new Response(
      JSON.stringify({
        limits: [
          { kind: "session", group: "session", percent: used, resets_at: resets },
          { kind: "weekly_all", group: "weekly", percent: used, resets_at: resets },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

/**
 * account006: own identity HOST, live files GUEST (the in-session `/login`
 * residue). spare: a plain, wholly self-consistent profile.
 */
function fleetWithOrphanOccupant(): { occupied: string; spare: string } {
  const occupied = profileDir("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");

  const spare = profileDir("spare");
  park(spare, UUID_SPARE, "spare@example.com", "spare");
  occupy(spare, UUID_SPARE, "spare@example.com", "spare");

  return { occupied, spare };
}

// --- characterization: the reported symptom, so a change to it is visible ----

test("an account present only as an occupant reports healthy with NO profile naming it", async () => {
  fleetWithOrphanOccupant();

  const entries = await collectAccountsUsage(
    { tool: "claude", refresh: true, fetchImpl: usageFetch({ "guest-access": 3, "host-access": 40, "spare-access": 45 }) },
    resolveStore(),
  );

  const guest = entries.find((e) => e.accountUuid === UUID_GUEST)!;
  expect(guest.status).toBe("ok");
  expect(guest.usage?.headroom).toBe(97);
  // The defect, stated as an assertion: healthiest in the fleet, nameless.
  expect(guest.profiles).toEqual([]);
  expect(guest.occupies).toEqual(["account006"]);
});

// --- the routing defect ------------------------------------------------------

test("the healthiest account having no profile door does not veto the whole selection", async () => {
  fleetWithOrphanOccupant();

  const picked = await pickHealthiestAccount(
    {
      tool: "claude",
      refresh: true,
      minHeadroom: 20,
      currentUuid: UUID_HOST,
      fetchImpl: usageFetch({ "guest-access": 3, "host-access": 10, "spare-access": 45 }),
    },
    resolveStore(),
  );

  // Rank 1 is the doorless occupant; rank 2 is reachable. Giving up at rank 1
  // strands every session on an exhausted account while a usable runner-up
  // sits one place down — the hazard `SelectionResult.ranked` is documented to
  // exist for, and which usage-hook.ts already handles.
  expect(picked.selection.ranked.map((r) => r.accountUuid)).toEqual([UUID_GUEST, UUID_SPARE]);
  expect(picked.profileName).toBe("spare");
  expect(picked.candidate?.accountUuid).toBe(UUID_SPARE);
  expect(picked.doorless).toBe(1);
  // Diagnostic fidelity: the true healthiest is still reported as such.
  expect(picked.selection.candidate?.accountUuid).toBe(UUID_GUEST);
});

test("POSITIVE CONTROL: a healthiest account that DOES have a door is still chosen", async () => {
  fleetWithOrphanOccupant();
  // Give the guest a profile of its own — now rank 1 is reachable.
  const owned = profileDir("guestowned");
  park(owned, UUID_GUEST, "guest@example.com", "guest");
  occupy(owned, UUID_GUEST, "guest@example.com", "guest");

  const picked = await pickHealthiestAccount(
    {
      tool: "claude",
      refresh: true,
      minHeadroom: 20,
      currentUuid: UUID_HOST,
      fetchImpl: usageFetch({ "guest-access": 3, "host-access": 10, "spare-access": 45 }),
    },
    resolveStore(),
  );

  // A fix that satisfies the test above by always skipping rank 1 dies here.
  expect(picked.candidate?.accountUuid).toBe(UUID_GUEST);
  expect(picked.profileName).toBe("guestowned");
  expect(picked.doorless).toBe(0);
});

test("POSITIVE CONTROL: when NO ranked candidate has a door, none is invented", async () => {
  const occupied = profileDir("account006");
  park(occupied, UUID_HOST, "host@example.com", "host");
  occupy(occupied, UUID_GUEST, "guest@example.com", "guest");

  const picked = await pickHealthiestAccount(
    {
      tool: "claude",
      refresh: true,
      minHeadroom: 20,
      currentUuid: UUID_HOST,
      fetchImpl: usageFetch({ "guest-access": 3, "host-access": 10 }),
    },
    resolveStore(),
  );

  expect(picked.selection.ranked).toHaveLength(1);
  expect(picked.candidate).toBeUndefined();
  expect(picked.profileName).toBeUndefined();
  // The count is what lets the caller say "1 account has headroom but no
  // profile owns it" instead of the false "no eligible account was found".
  expect(picked.doorless).toBe(1);
});
