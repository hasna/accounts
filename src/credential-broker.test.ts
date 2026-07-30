import { test, expect } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  convergeDirCredential,
  convergeIdentityCredential,
  ensureFreshIdentityCredential,
} from "./lib/credential-broker.js";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { profileCredentialsSnapshot } from "./lib/claude-layout.js";
import { getTool } from "./lib/tools.js";

/**
 * The credential broker: many readers, one writer, no independent copies.
 *
 * What is REPRODUCED and what is MODELLED (same discipline as
 * credential-contention.test.ts): the multi-dir custody of one account, the
 * fan-out, the lock, and the persist paths are all real files through the real
 * code. The OAuth server is MODELLED by `rotationProvider`, which enforces the
 * real server's one rule — a refresh token is single-use; exchanging a
 * superseded one is `invalid_grant` — so any surviving two-writer path in the
 * broker shows up here as a recorded invalid grant, exactly the failure the
 * fleet measured on 2026-07-29.
 */

const UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER_UUID = "99999999-8888-4777-8666-555555555555";
const tool = getTool("claude");

interface Cred {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function credBytes(cred: Cred): string {
  return JSON.stringify({ claudeAiOauth: { ...cred, scopes: ["user:inference"] } });
}

function makeDir(home: string, label: string, uuid: string, cred: Cred, opts: { mtime?: Date } = {}): string {
  const dir = join(home, "profiles", label);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } }));
  writeFileSync(join(dir, ".credentials.json"), credBytes(cred));
  if (opts.mtime) utimesSync(join(dir, ".credentials.json"), opts.mtime, opts.mtime);
  return dir;
}

function readCred(path: string): Cred {
  return (JSON.parse(readFileSync(path, "utf8")) as { claudeAiOauth: Cred }).claudeAiOauth;
}

function setupHome(): { home: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "accounts-broker-"));
  const previous = process.env.ACCOUNTS_HOME;
  process.env.ACCOUNTS_HOME = home;
  return {
    home,
    cleanup: () => {
      if (previous === undefined) delete process.env.ACCOUNTS_HOME;
      else process.env.ACCOUNTS_HOME = previous;
      rmSync(home, { recursive: true, force: true });
    },
  };
}

function withHome(fn: (home: string) => void): void {
  const { home, cleanup } = setupHome();
  try {
    fn(home);
  } finally {
    cleanup();
  }
}

/** Async variant: teardown only after `fn`'s promise settles. */
async function withHomeAsync(fn: (home: string) => Promise<void>): Promise<void> {
  const { home, cleanup } = setupHome();
  try {
    await fn(home);
  } finally {
    cleanup();
  }
}

/**
 * A model of the provider's rotation semantics: exactly one refresh token is
 * current; exchanging it rotates; exchanging anything else is an invalid
 * grant, recorded. Any invalid grant observed in a test is a second writer.
 */
function rotationProvider(initialRefresh: string) {
  const state = {
    current: initialRefresh,
    seq: 1,
    calls: 0,
    invalidGrants: [] as string[],
  };
  const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
    state.calls += 1;
    const body = JSON.parse(String(init?.body)) as { refresh_token: string; grant_type: string; client_id: string };
    expect(body.grant_type).toBe("refresh_token");
    if (body.refresh_token !== state.current) {
      state.invalidGrants.push(body.refresh_token);
      return new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 });
    }
    state.seq += 1;
    state.current = `rt-${state.seq}`;
    return new Response(
      JSON.stringify({ access_token: `at-${state.seq}`, refresh_token: state.current, expires_in: 28_800 }),
      { status: 200 },
    );
  }) as typeof fetch;
  return { fetchImpl, state };
}

const HOUR = 60 * 60 * 1000;

// --- convergence ------------------------------------------------------------

test("converge: every copy of one account ends holding the newest rotation", () => {
  withHome((home) => {
    const old = new Date(Date.now() - 2 * HOUR);
    const stale: Cred = { accessToken: "at-stale", refreshToken: "rt-stale", expiresAt: Date.now() - HOUR };
    const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
    const dirA = makeDir(home, "acct-a", UUID, fresh);
    const dirB = makeDir(home, "acct-b", UUID, stale, { mtime: old });
    ensureProfileAuthSnapshot(dirB, tool);
    // B's snapshot captured the stale copy; age it too.
    utimesSync(profileCredentialsSnapshot(dirB), old, old);

    const profiles = [
      { name: "a", dir: dirA },
      { name: "b", dir: dirB },
    ];
    const report = convergeIdentityCredential(UUID, { tool, profiles });

    expect(report.winner?.path).toBe(join(dirA, ".credentials.json"));
    // The superseded copy, the parked snapshot, and the central store all now
    // hold the SAME bytes as the winner: there is no independent copy left to
    // race the next refresh.
    const winnerBytes = readFileSync(join(dirA, ".credentials.json"), "utf8");
    expect(readFileSync(join(dirB, ".credentials.json"), "utf8")).toBe(winnerBytes);
    expect(readFileSync(profileCredentialsSnapshot(dirB), "utf8")).toBe(winnerBytes);
    expect(readFileSync(centralCredentialsSnapshot(UUID), "utf8")).toBe(winnerBytes);
    expect(readCred(join(dirB, ".credentials.json")).refreshToken).toBe("rt-fresh");
  });
});

test("converge repairs a rotated-away husk from the surviving copy", () => {
  withHome((home) => {
    const survivor: Cred = { accessToken: "at-live", refreshToken: "rt-live", expiresAt: Date.now() + 6 * HOUR };
    const dirA = makeDir(home, "acct-a", UUID, survivor);
    // The measured blanked-in-place shape.
    const dirB = makeDir(home, "acct-b", UUID, { accessToken: "", refreshToken: "", expiresAt: 0 });

    const report = convergeIdentityCredential(UUID, {
      tool,
      profiles: [
        { name: "a", dir: dirA },
        { name: "b", dir: dirB },
      ],
    });

    expect(report.winner?.path).toBe(join(dirA, ".credentials.json"));
    expect(readCred(join(dirB, ".credentials.json")).refreshToken).toBe("rt-live");
  });
});

test("converge NEVER propagates a husk: with no restorable copy anywhere, nothing is written", () => {
  withHome((home) => {
    const dirA = makeDir(home, "acct-a", UUID, { accessToken: "", refreshToken: "", expiresAt: 0 });
    const before = readFileSync(join(dirA, ".credentials.json"), "utf8");

    const report = convergeIdentityCredential(UUID, { tool, profiles: [{ name: "a", dir: dirA }] });

    expect(report.winner).toBeUndefined();
    expect(report.writes).toEqual([]);
    expect(readFileSync(join(dirA, ".credentials.json"), "utf8")).toBe(before);
  });
});

test("converge never writes this account's tokens into a dir occupied by ANOTHER account", () => {
  withHome((home) => {
    const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
    const dirA = makeDir(home, "acct-a", UUID, fresh);
    // Dir C's OWN identity is UUID (parked snapshot), but a different account
    // occupies its live files — the in-place-switch shape #60 protects.
    const foreign: Cred = { accessToken: "at-foreign", refreshToken: "rt-foreign", expiresAt: Date.now() + 7 * HOUR };
    const old = new Date(Date.now() - 2 * HOUR);
    const dirC = makeDir(home, "acct-c", UUID, { accessToken: "at-old", refreshToken: "rt-old", expiresAt: Date.now() - HOUR }, { mtime: old });
    ensureProfileAuthSnapshot(dirC, tool);
    utimesSync(profileCredentialsSnapshot(dirC), old, old);
    // The in-place switch: live files now carry the OTHER account.
    writeFileSync(join(dirC, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: OTHER_UUID, emailAddress: "other@example.com" } }));
    writeFileSync(join(dirC, ".credentials.json"), credBytes(foreign));

    convergeIdentityCredential(UUID, {
      tool,
      profiles: [
        { name: "a", dir: dirA },
        { name: "c", dir: dirC },
      ],
    });

    // The guest's live credential is untouched; the host's parked snapshot
    // converged to the host account's newest copy.
    expect(readCred(join(dirC, ".credentials.json")).refreshToken).toBe("rt-foreign");
    expect(readCred(profileCredentialsSnapshot(dirC)).refreshToken).toBe("rt-fresh");
  });
});

/**
 * THE CROSS-WRITE. `switch-account` calls
 * `convergeIdentityCredential(targetUuid, { extraDirs: [configDir] })`, where
 * `configDir` is the dir the OUTGOING account is still sitting in. That dir
 * enters `enumerateCopies` as a `dir-live` candidate, and — before the read
 * gate — was READ and RANKED with no identity check at all. The outgoing
 * account has just been in use, so its file is the newest on disk and the
 * mtime-ordered, identity-blind ranking crowns it. Fan-out then wrote it into
 * `central/<INCOMING uuid>/.credentials.json`, whose write gate is the
 * hardcoded `() => true`.
 *
 * One-directional by construction: every OTHER write target re-checks its
 * dir's occupant, so the poison could only ever flow INTO central. Measured
 * store state on this fleet: 18 uuid entries, 18 distinct identity files, but
 * only 8 distinct credential blobs — one blob filed under eight uuids.
 */
test("CROSS-WRITE GATE: an extraDir occupied by ANOTHER account is not an eligible source", () => {
  withHome((home) => {
    const old = new Date(Date.now() - 2 * HOUR);
    // The INCOMING account — the switch target. Its own copy is older, which
    // is the ordinary case: the session has not been using it.
    const incoming: Cred = { accessToken: "at-incoming", refreshToken: "rt-incoming", expiresAt: Date.now() + 6 * HOUR };
    const targetDir = makeDir(home, "incoming", UUID, incoming, { mtime: old });

    // The OUTGOING account, still occupying the session's config dir. It was
    // refreshed moments ago, so it is the NEWEST credential file on disk —
    // precisely what an identity-blind mtime ranking selects.
    const outgoing: Cred = { accessToken: "at-outgoing", refreshToken: "rt-outgoing", expiresAt: Date.now() + 7 * HOUR };
    const sessionDir = makeDir(home, "outgoing", OTHER_UUID, outgoing);

    // Exactly switchAccount's call shape.
    const report = convergeIdentityCredential(UUID, {
      tool,
      profiles: [
        { name: "incoming", dir: targetDir },
        { name: "outgoing", dir: sessionDir },
      ],
      extraDirs: [sessionDir],
    });

    // THE LOAD-BEARING ASSERTION: the incoming account's credential of record
    // is its OWN credential, never the outgoing account's. This is the exact
    // byte-level claim behind "18 uuids, 8 credential blobs".
    expect(readCred(centralCredentialsSnapshot(UUID)).refreshToken).toBe("rt-incoming");

    // The outgoing account's file must never be crowned for the incoming uuid.
    expect(report.winner?.path).not.toBe(join(sessionDir, ".credentials.json"));
    expect(report.winner?.path).toBe(join(targetDir, ".credentials.json"));

    // And the outgoing account keeps its own material, untouched.
    expect(readCred(join(sessionDir, ".credentials.json")).refreshToken).toBe("rt-outgoing");

    // The refusal is REPORTED, not silent — the absence of any signal is how
    // this survived to 0.2.26.
    expect(
      report.skipped.some((s) => s.path === join(sessionDir, ".credentials.json") && /does not carry this account/.test(s.reason)),
    ).toBe(true);
  });
});

test("CROSS-WRITE GATE, positive control: the SAME extraDir, carrying the target account, is used", () => {
  withHome((home) => {
    const old = new Date(Date.now() - 2 * HOUR);
    // Same shape as above, except the session dir carries the TARGET account.
    // If the gate were over-broad this would go dead and convergence would
    // stop doing its job.
    const parked: Cred = { accessToken: "at-parked", refreshToken: "rt-parked", expiresAt: Date.now() + 6 * HOUR };
    const targetDir = makeDir(home, "incoming", UUID, parked, { mtime: old });
    const live: Cred = { accessToken: "at-live", refreshToken: "rt-live", expiresAt: Date.now() + 7 * HOUR };
    const sessionDir = makeDir(home, "session", UUID, live);

    const report = convergeIdentityCredential(UUID, {
      tool,
      profiles: [{ name: "incoming", dir: targetDir }],
      extraDirs: [sessionDir],
    });

    expect(report.winner?.path).toBe(join(sessionDir, ".credentials.json"));
    expect(readCred(centralCredentialsSnapshot(UUID)).refreshToken).toBe("rt-live");
    expect(readCred(join(targetDir, ".credentials.json")).refreshToken).toBe("rt-live");
  });
});

/**
 * THE DEFAULT-DIR LAYOUT. Claude Code's real default config dir keeps its
 * `oauthAccount` in the PARENT `~/.claude.json`, not inside `~/.claude/`.
 * `profileAccountJsonPaths` models that by returning a SECOND path — and only
 * when `profileDir === tool.defaultDir` (claude-layout.ts:48).
 *
 * `buildIdentityIndex` loops every one of those paths, so the dir is still
 * enumerated as a door. Any identity predicate that reads `paths[0]` alone
 * therefore DISAGREES WITH THE ENUMERATOR on exactly the standard layout.
 *
 * Every fixture in this file until now put `.claude.json` INSIDE the profile
 * dir (see `makeDir`), so the second path was never exercised — which is how a
 * fully green suite could miss this.
 */
function makeDefaultDir(home: string, uuid: string, cred: Cred, opts: { mtime?: Date } = {}): { dir: string; tool: typeof tool } {
  const fakeHome = join(home, "userhome");
  const dir = join(fakeHome, ".claude");
  mkdirSync(dir, { recursive: true });
  // Identity lives in the PARENT only — the real default layout.
  writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: "live@example.com" } }));
  writeFileSync(join(dir, ".credentials.json"), credBytes(cred));
  if (opts.mtime) utimesSync(join(dir, ".credentials.json"), opts.mtime, opts.mtime);
  return { dir, tool: { ...tool, defaultDir: dir } };
}

test("DEFAULT-DIR SOURCE: the live default config dir donates for its own account", () => {
  withHome((home) => {
    const live: Cred = { accessToken: "at-live", refreshToken: "rt-live", expiresAt: Date.now() + 7 * HOUR };
    const { dir, tool: defaultTool } = makeDefaultDir(home, UUID, live);

    const report = convergeIdentityCredential(UUID, {
      tool: defaultTool,
      profiles: [{ name: "live", dir }],
    });

    // The account's ONLY credential is in this dir. Refusing it as a source
    // makes convergence a no-op that reports "no restorable credential copy".
    expect(report.winner?.path).toBe(join(dir, ".credentials.json"));
    expect(readCred(centralCredentialsSnapshot(UUID)).refreshToken).toBe("rt-live");
  });
});

test("DEFAULT-DIR SOURCE: a STALE sibling never outranks the live default dir", () => {
  withHome((home) => {
    // Worse than a no-op. If the default dir cannot donate, the only remaining
    // candidate is the stale sibling — which is then crowned AND written to
    // central with a FRESH mtime. `betterCredential` tie-breaks on mtime, so
    // the stale copy would durably outrank the genuinely fresher live one.
    const live: Cred = { accessToken: "at-live", refreshToken: "rt-live", expiresAt: Date.now() + 7 * HOUR };
    const { dir, tool: defaultTool } = makeDefaultDir(home, UUID, live);
    const old = new Date(Date.now() - 2 * HOUR);
    const staleDir = makeDir(home, "stale-sibling", UUID, { accessToken: "at-stale", refreshToken: "rt-stale", expiresAt: Date.now() - HOUR }, { mtime: old });

    const report = convergeIdentityCredential(UUID, {
      tool: defaultTool,
      profiles: [
        { name: "live", dir },
        { name: "stale", dir: staleDir },
      ],
    });

    expect(report.winner?.path).toBe(join(dir, ".credentials.json"));
    expect(readCred(centralCredentialsSnapshot(UUID)).refreshToken).toBe("rt-live");
    // The stale sibling converged UP to the live rotation, not the reverse.
    expect(readCred(join(staleDir, ".credentials.json")).refreshToken).toBe("rt-live");
  });
});

test("EXFILTRATION GATE: converging an UNREGISTERED dir is refused outright", () => {
  withHome((home) => {
    const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
    const victimDir = makeDir(home, "victim", UUID, fresh);
    // Attacker plants a dir OUTSIDE the registry carrying the victim's
    // identity plus a stale credential file — the shape that would have made
    // fan-out deliver the victim's live tokens to a path the attacker chose.
    const attackerDir = makeDir(home, "attacker-unregistered", UUID, {
      accessToken: "at-old",
      refreshToken: "rt-old",
      expiresAt: Date.now() - HOUR,
    });
    const before = readFileSync(join(attackerDir, ".credentials.json"), "utf8");

    expect(() =>
      convergeDirCredential(attackerDir, { tool, profiles: [{ name: "victim", dir: victimDir }] }),
    ).toThrow(/not a registered profile dir/);
    // Nothing moved: the planted file is exactly as planted.
    expect(readFileSync(join(attackerDir, ".credentials.json"), "utf8")).toBe(before);
  });
});

test("POSITIVE CONTROL for the gate: the same dir, registered, converges", () => {
  withHome((home) => {
    const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
    const victimDir = makeDir(home, "victim", UUID, fresh);
    const old = new Date(Date.now() - 2 * HOUR);
    const siblingDir = makeDir(home, "sibling", UUID, {
      accessToken: "at-old",
      refreshToken: "rt-old",
      expiresAt: Date.now() - HOUR,
    }, { mtime: old });

    const report = convergeDirCredential(siblingDir, {
      tool,
      profiles: [
        { name: "victim", dir: victimDir },
        { name: "sibling", dir: siblingDir },
      ],
    });

    expect(report?.winner?.path).toBe(join(victimDir, ".credentials.json"));
    expect(readCred(join(siblingDir, ".credentials.json")).refreshToken).toBe("rt-fresh");
  });
});

// --- the single-writer refresh ----------------------------------------------

test("ensure-fresh: a fresh token is left alone — no network call at all", async () => {
  await withHomeAsync(async (home) => {
    const fresh: Cred = { accessToken: "at-fresh", refreshToken: "rt-fresh", expiresAt: Date.now() + 7 * HOUR };
    const dirA = makeDir(home, "acct-a", UUID, fresh);
    const provider = rotationProvider("rt-fresh");

    const report = await ensureFreshIdentityCredential(UUID, {
      tool,
      profiles: [{ name: "a", dir: dirA }],
      fetchImpl: provider.fetchImpl,
    });

    expect(report.refreshed).toBe(false);
    expect(provider.state.calls).toBe(0);
  });
});

test("ensure-fresh: a near-expiry token is exchanged once and the rotation lands in EVERY copy", async () => {
  await withHomeAsync(async (home) => {
    const nearExpiry: Cred = { accessToken: "at-1", refreshToken: "rt-1", expiresAt: Date.now() + 60_000 };
    const dirA = makeDir(home, "acct-a", UUID, nearExpiry);
    const dirB = makeDir(home, "acct-b", UUID, nearExpiry);
    ensureProfileAuthSnapshot(dirA, tool);
    const provider = rotationProvider("rt-1");

    const report = await ensureFreshIdentityCredential(UUID, {
      tool,
      profiles: [
        { name: "a", dir: dirA },
        { name: "b", dir: dirB },
      ],
      fetchImpl: provider.fetchImpl,
    });

    expect(report.refreshed).toBe(true);
    expect(provider.state.calls).toBe(1);
    expect(provider.state.invalidGrants).toEqual([]);
    const central = readFileSync(centralCredentialsSnapshot(UUID), "utf8");
    expect(readFileSync(join(dirA, ".credentials.json"), "utf8")).toBe(central);
    expect(readFileSync(join(dirB, ".credentials.json"), "utf8")).toBe(central);
    expect(readFileSync(profileCredentialsSnapshot(dirA), "utf8")).toBe(central);
    const rotated = readCred(centralCredentialsSnapshot(UUID));
    expect(rotated.refreshToken).toBe("rt-2");
    expect(rotated.accessToken).toBe("at-2");
    expect(rotated.expiresAt).toBeGreaterThan(Date.now() + 7 * HOUR);
    // Non-token fields of the payload survive the rotation.
    const raw = JSON.parse(central) as { claudeAiOauth: { scopes?: string[] } };
    expect(raw.claudeAiOauth.scopes).toEqual(["user:inference"]);
  });
});

test("ensure-fresh: a failed exchange writes NOTHING", async () => {
  await withHomeAsync(async (home) => {
    const nearExpiry: Cred = { accessToken: "at-1", refreshToken: "rt-1", expiresAt: Date.now() + 60_000 };
    const dirA = makeDir(home, "acct-a", UUID, nearExpiry);
    const before = readFileSync(join(dirA, ".credentials.json"), "utf8");
    // Provider whose current token is something else: our exchange 400s.
    const provider = rotationProvider("rt-elsewhere");

    const report = await ensureFreshIdentityCredential(UUID, {
      tool,
      profiles: [{ name: "a", dir: dirA }],
      fetchImpl: provider.fetchImpl,
    });

    expect(report.refreshed).toBe(false);
    expect(report.error ?? "").toMatch(/refresh exchange failed/);
    expect(readFileSync(join(dirA, ".credentials.json"), "utf8")).toBe(before);
  });
});

test("TWO CONCURRENT WRITERS COLLAPSE TO ONE: racing ensure-fresh calls produce one exchange, zero invalid grants", async () => {
  await withHomeAsync(async (home) => {
    const nearExpiry: Cred = { accessToken: "at-1", refreshToken: "rt-1", expiresAt: Date.now() + 60_000 };
    const dirA = makeDir(home, "acct-a", UUID, nearExpiry);
    const dirB = makeDir(home, "acct-b", UUID, nearExpiry);
    const provider = rotationProvider("rt-1");
    const opts = {
      tool,
      profiles: [
        { name: "a", dir: dirA },
        { name: "b", dir: dirB },
      ],
      fetchImpl: provider.fetchImpl,
    };

    // Both "sessions" hit the refresh boundary at the same moment.
    const [first, second] = await Promise.all([
      ensureFreshIdentityCredential(UUID, opts),
      ensureFreshIdentityCredential(UUID, opts),
    ]);

    // Exactly one performed the exchange; the other adopted its result under
    // the lock. The provider never saw a superseded token.
    expect(provider.state.calls).toBe(1);
    expect(provider.state.invalidGrants).toEqual([]);
    expect([first.refreshed, second.refreshed].sort()).toEqual([false, true]);
    expect(readCred(join(dirA, ".credentials.json")).refreshToken).toBe("rt-2");
    expect(readCred(join(dirB, ".credentials.json")).refreshToken).toBe("rt-2");
  });
});

// --- the acceptance control -------------------------------------------------

test("ACCEPTANCE: two sessions share one account across refresh boundaries — both keep working, the stored refresh token stays valid", async () => {
  await withHomeAsync(async (home) => {
    // Two config dirs, one account: the exact state the old hook refused to
    // create ("cannot be shared — a second copy would get its token rotated
    // away").
    const initial: Cred = { accessToken: "at-1", refreshToken: "rt-1", expiresAt: Date.now() + 60_000 };
    const dirA = makeDir(home, "acct-a", UUID, initial);
    const dirB = makeDir(home, "acct-b", UUID, initial);
    ensureProfileAuthSnapshot(dirA, tool);
    ensureProfileAuthSnapshot(dirB, tool);
    const provider = rotationProvider("rt-1");
    const profiles = [
      { name: "a", dir: dirA },
      { name: "b", dir: dirB },
    ];
    const opts = { tool, profiles, fetchImpl: provider.fetchImpl };
    const credentialOf = (dir: string) => readCred(join(dir, ".credentials.json"));

    // FIRST REFRESH BOUNDARY: session A's broker pass renews the shared token.
    const first = await ensureFreshIdentityCredential(UUID, opts);
    expect(first.refreshed).toBe(true);
    expect(credentialOf(dirA).refreshToken).toBe("rt-2");
    expect(credentialOf(dirB).refreshToken).toBe("rt-2");

    // MID-FLIGHT TOOL-SIDE ROTATION: Claude Code in session B refreshes on its
    // own (its right — the broker does not own the tool) and writes ONLY its
    // own dir, exactly as the real binary does.
    const toolSide = await provider.fetchImpl("mock://token", {
      method: "POST",
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: "rt-2", client_id: "test" }),
    });
    expect(toolSide.status).toBe(200);
    const rotated = (await toolSide.json()) as { access_token: string; refresh_token: string; expires_in: number };
    writeFileSync(
      join(dirB, ".credentials.json"),
      credBytes({ accessToken: rotated.access_token, refreshToken: rotated.refresh_token, expiresAt: Date.now() + 8 * HOUR }),
    );
    expect(provider.state.current).toBe("rt-3");

    // Session A's next prompt: the hook's converge pass ADOPTS B's rotation
    // instead of racing it — A never exchanges rt-2 (which would now be an
    // invalid grant).
    const converged = convergeIdentityCredential(UUID, { tool, profiles });
    expect(converged.winner?.path).toBe(join(dirB, ".credentials.json"));
    expect(credentialOf(dirA).refreshToken).toBe("rt-3");

    // SECOND REFRESH BOUNDARY, from the OTHER side: still one writer.
    const second = await ensureFreshIdentityCredential(UUID, { ...opts, minTtlMs: 9 * HOUR });
    expect(second.refreshed).toBe(true);

    // Both sessions still work: every copy holds the provider's CURRENT
    // refresh token, the provider saw zero invalid grants across two broker
    // refreshes and one tool-side rotation, and there is no independent copy
    // left anywhere — the sharper claim: nothing left to race.
    expect(provider.state.invalidGrants).toEqual([]);
    expect(provider.state.current).toBe("rt-4");
    const central = readFileSync(centralCredentialsSnapshot(UUID), "utf8");
    expect(readFileSync(join(dirA, ".credentials.json"), "utf8")).toBe(central);
    expect(readFileSync(join(dirB, ".credentials.json"), "utf8")).toBe(central);
    expect(readCred(join(dirA, ".credentials.json")).refreshToken).toBe("rt-4");

    // And the stored refresh token is VALID: a further exchange with exactly
    // what is on disk succeeds.
    const final = await ensureFreshIdentityCredential(UUID, { ...opts, minTtlMs: 9 * HOUR });
    expect(final.refreshed).toBe(true);
    expect(provider.state.invalidGrants).toEqual([]);
  });
});
