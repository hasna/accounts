// Regression tests for the accountUuid backfill (PR-1, task ad756590).
//
// The design forbids two joins outright: NEVER by name, NEVER by credential
// hash. Both prohibitions are asserted with fixtures that would produce a
// DIFFERENT answer if the forbidden join were used — a test that merely checks
// the happy path cannot tell a correct join from a forbidden one that happens
// to agree.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildProfileRegistry } from "./lib/profile-registry.js";
import { applyAccountUuidBackfill, planAccountUuidBackfill } from "./lib/uuid-backfill.js";
import { getTool } from "./lib/tools.js";

const OWN_UUID = "11111111-1111-4111-8111-111111111111";
const OCCUPANT_UUID = "22222222-2222-4222-8222-222222222222";
const SECOND_UUID = "33333333-3333-4333-8333-333333333333";
const UNKNOWN_UUID = "99999999-9999-4999-8999-999999999999";

let home: string;
let prevHome: string | undefined;

/** A credential-shaped payload. No real token: bytes only matter for grouping. */
const CREDENTIAL = JSON.stringify({ claudeAiOauth: { accessToken: "x".repeat(64) } });

function writeJson(path: string, value: unknown): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify(value));
}

/** A profile dir with a PARKED own identity and, optionally, a live occupant. */
function makeProfileDir(
  name: string,
  opts: { own?: string; ownEmail?: string; occupant?: string; credential?: string } = {},
): { name: string; dir: string } {
  const dir = join(home, "profiles", "claude", name);
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  if (opts.own) {
    writeJson(join(dir, ".accounts-auth", "oauth-account.json"), {
      oauthAccount: { accountUuid: opts.own, emailAddress: opts.ownEmail ?? `${name}@example.com` },
    });
  }
  if (opts.occupant) {
    writeJson(join(dir, ".claude.json"), {
      oauthAccount: { accountUuid: opts.occupant, emailAddress: "occupant@example.com" },
    });
  }
  if (opts.credential) writeFileSync(join(dir, ".credentials.json"), opts.credential);
  return { name, dir };
}

/** An entry in the central store at `<accountsHome>/auth/<uuid>/`. */
function makeCentral(uuid: string, email: string): void {
  const dir = join(home, "auth", uuid);
  mkdirSync(dir, { recursive: true });
  writeJson(join(dir, "oauth-account.json"), { oauthAccount: { accountUuid: uuid, emailAddress: email } });
  writeFileSync(join(dir, "credentials.json"), CREDENTIAL);
}

function planFor(profiles: { name: string; dir: string }[], existing: Map<string, string> = new Map()) {
  const tool = getTool("claude");
  const registry = buildProfileRegistry(profiles, tool);
  return planAccountUuidBackfill(registry, existing);
}

beforeEach(() => {
  prevHome = process.env.ACCOUNTS_HOME;
  home = mkdtempSync(join(tmpdir(), "accounts-backfill-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  if (prevHome === undefined) delete process.env.ACCOUNTS_HOME;
  else process.env.ACCOUNTS_HOME = prevHome;
  rmSync(home, { recursive: true, force: true });
});

describe("planAccountUuidBackfill", () => {
  test("backfills from the PARKED own identity when it is present in the central store", () => {
    makeCentral(OWN_UUID, "own@example.com");
    const plan = planFor([makeProfileDir("acct-a", { own: OWN_UUID })]);
    expect(plan.length).toBe(1);
    expect(plan[0]!.outcome).toBe("backfilled");
    expect(plan[0]!.accountUuid).toBe(OWN_UUID);
  });

  test("NEVER binds the occupant: a displaced dir backfills its OWN uuid, not the one in the live files", () => {
    // This is the discriminating fixture. `own` and `occupant` differ, and both
    // exist centrally, so a backfill that read the live `.claude.json` would
    // return OCCUPANT_UUID and still look like a success.
    makeCentral(OWN_UUID, "own@example.com");
    makeCentral(OCCUPANT_UUID, "occupant@example.com");
    const plan = planFor([makeProfileDir("acct-b", { own: OWN_UUID, occupant: OCCUPANT_UUID })]);
    expect(plan[0]!.accountUuid).toBe(OWN_UUID);
    expect(plan[0]!.accountUuid).not.toBe(OCCUPANT_UUID);
    expect(plan[0]!.outcome).toBe("backfilled");
  });

  test("NEVER joins by credential hash: two dirs sharing identical credential bytes keep distinct uuids", () => {
    // Identical bytes are the exact condition the census flagged as
    // contamination. A hash join would collapse these two onto one uuid.
    makeCentral(OWN_UUID, "own@example.com");
    makeCentral(SECOND_UUID, "second@example.com");
    const plan = planFor([
      makeProfileDir("acct-c", { own: OWN_UUID, credential: CREDENTIAL }),
      makeProfileDir("acct-d", { own: SECOND_UUID, credential: CREDENTIAL }),
    ]);
    const byName = new Map(plan.map((p) => [p.profileName, p.accountUuid]));
    expect(byName.get("acct-c")).toBe(OWN_UUID);
    expect(byName.get("acct-d")).toBe(SECOND_UUID);
  });

  test("NEVER joins by name: a dir with no parked identity stays unresolved even when a central entry exists", () => {
    makeCentral(OWN_UUID, "acct-e@example.com");
    const plan = planFor([makeProfileDir("acct-e", {})]);
    expect(plan[0]!.outcome).toBe("unresolved");
    expect(plan[0]!.accountUuid).toBeUndefined();
    expect(plan[0]!.reason).toMatch(/no parked/i);
  });

  test("a parked uuid absent from the central store is reported unverified, never applied", () => {
    const plan = planFor([makeProfileDir("acct-f", { own: UNKNOWN_UUID })]);
    expect(plan[0]!.outcome).toBe("unverified");
    expect(plan[0]!.accountUuid).toBeUndefined();
  });

  test("an existing accountUuid that disagrees with the parked identity is a conflict, never overwritten", () => {
    makeCentral(OWN_UUID, "own@example.com");
    makeCentral(SECOND_UUID, "second@example.com");
    const plan = planFor([makeProfileDir("acct-g", { own: OWN_UUID })], new Map([["acct-g", SECOND_UUID]]));
    expect(plan[0]!.outcome).toBe("conflict");
    expect(plan[0]!.accountUuid).toBeUndefined();
  });

  test("an already-correct accountUuid is a no-op, not a rewrite", () => {
    makeCentral(OWN_UUID, "own@example.com");
    const plan = planFor([makeProfileDir("acct-h", { own: OWN_UUID })], new Map([["acct-h", OWN_UUID]]));
    expect(plan[0]!.outcome).toBe("already-set");
  });

  test("POSITIVE CONTROL: the plan is not vacuously empty — every fixture produces exactly one row", () => {
    makeCentral(OWN_UUID, "own@example.com");
    const plan = planFor([
      makeProfileDir("acct-i", { own: OWN_UUID }),
      makeProfileDir("acct-j", {}),
    ]);
    expect(plan.length).toBe(2);
    expect(new Set(plan.map((p) => p.outcome))).toEqual(new Set(["backfilled", "unresolved"]));
  });
});

describe("applyAccountUuidBackfill", () => {
  test("passes the PROVIDER on every update, so a colliding name is still applyable", async () => {
    // Regression: an apply keyed on name alone throws `exists for multiple
    // tools` for exactly the colliding records this backfill exists to repair
    // — it would succeed on every record that did not need it and fail on the
    // target population. Measured against the real CLI before the fix.
    makeCentral(OWN_UUID, "own@example.com");
    const plan = planFor([makeProfileDir("collider", { own: OWN_UUID })]);
    const calls: Array<{ name: string; opts: { tool?: string; accountUuid?: string } }> = [];
    const store = {
      async updateProfile(name: string, opts: { tool?: string; accountUuid?: string }) {
        if (opts.tool === undefined) {
          throw new Error(`profile "${name}" exists for multiple tools (claude, codewith); pass --tool`);
        }
        calls.push({ name, opts });
        return {};
      },
    };
    const applied = await applyAccountUuidBackfill(store, plan);
    expect(applied).toEqual(["collider"]);
    expect(calls[0]!.opts.tool).toBe("claude");
    expect(calls[0]!.opts.accountUuid).toBe(OWN_UUID);
  });

  test("writes ONLY backfilled rows — conflict, unverified and unresolved are never applied", async () => {
    makeCentral(OWN_UUID, "own@example.com");
    makeCentral(SECOND_UUID, "second@example.com");
    const plan = planFor(
      [
        makeProfileDir("ok", { own: OWN_UUID }),
        makeProfileDir("conflicted", { own: OWN_UUID }),
        makeProfileDir("unknown", { own: UNKNOWN_UUID }),
        makeProfileDir("bare", {}),
      ],
      new Map([["conflicted", SECOND_UUID]]),
    );
    const touched: string[] = [];
    const applied = await applyAccountUuidBackfill(
      {
        async updateProfile(name: string) {
          touched.push(name);
          return {};
        },
      },
      plan,
    );
    expect(applied).toEqual(["ok"]);
    expect(touched).toEqual(["ok"]);
  });
});

describe("plan shape", () => {
  test("every plan row carries the provider the apply step needs", () => {
    makeCentral(OWN_UUID, "own@example.com");
    const plan = planFor([makeProfileDir("acct-k", { own: OWN_UUID }), makeProfileDir("acct-l", {})]);
    expect(plan.every((row) => row.provider === "claude")).toBe(true);
  });
});
