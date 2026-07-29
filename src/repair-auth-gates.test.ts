import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  ensureProfileAuthSnapshot,
  planParkedRecovery,
  recoverParkedCredential,
  writeSwitchedAccountMarker,
  type ParkedRecoveryOutcome,
  type ParkedRecoveryPlanOutcome,
} from "./lib/claude-auth.js";
import { profileEnv } from "./lib/env.js";
import { profileCredentialsSnapshot } from "./lib/claude-layout.js";
import { classifyCredentialFile } from "./lib/credential-state.js";
import { getTool } from "./lib/tools.js";

/**
 * Regressions for bb267228 — two defects in the parked-credential repair path.
 *
 * DEFECT 1: the identity gate in `recoverParkedCredential` only refuses when the
 * dir's LIVE identity differs from the profile's own. It never asks whether THIS
 * SAME account's credential is already live in a DIFFERENT directory. Measured
 * on this fleet: three profiles hold parked credentials that are superseded
 * PREDECESSORS of accounts whose current credential lives in another, squatted
 * dir. `accounts repair-auth` with no profile argument attempts every profile,
 * so one blanket run would have restored all three — putting two live copies of
 * each account on disk. Refresh-token rotation then revokes the loser
 * server-side, which is the confirmed destructive hazard this whole area exists
 * to prevent.
 *
 * DEFECT 2: `--dry-run` computed `parkedCredentialVerdict` (pure content
 * ranking) and never applied the identity gates at all, so it reported
 * `would-recover` for profiles the real run refuses. A preview that disagrees
 * with the operation it previews is worse than no preview, because plans get
 * built on it.
 *
 * FIXTURE DISCIPLINE: every credential planted below that is meant to be alive
 * is genuinely healthy — refresh token present, comfortably unexpired. A fixture
 * that degraded one side would pass for the wrong reason, since ranking already
 * separates healthy from degraded and only identity/liveness can separate two
 * healthy credentials. Token values are literal placeholders; nothing here
 * reaches a network.
 */

let home: string;
let liveBase: string;
const scratch: string[] = [];
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-gates-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-gates-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  while (scratch.length > 0) rmSync(scratch.pop()!, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

const UUID_X = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_Y = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const UUID_Z = "cccccccc-3333-4333-8333-cccccccccccc";

function scratchDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  scratch.push(dir);
  return dir;
}

/** A healthy credential: refresh token present, comfortably unexpired. */
function credentialJson(label: string, expiresInMs = 600_000): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + expiresInMs,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
      scopes: ["user:inference"],
      subscriptionType: "max",
    },
  });
}

/**
 * The husk Claude Code leaves when a refresh fails because another copy of the
 * same account rotated the token first: payload intact, both secrets emptied,
 * expiry zeroed. This is the `account031` shape.
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

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

/**
 * A registered profile whose own identity and credential are parked in
 * `.accounts-auth/` and mirrored centrally — the normal, healthy starting state.
 */
function makeProfile(name: string, uuid: string, label: string): string {
  const dir = scratchDir(`gates-${name}`);
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, label));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/** Pretend a session is attached to the dir (matches `listDirLiveSessions`). */
function attachLiveSession(dir: string): void {
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
}

// ---------------------------------------------------------------------------
// DEFECT 1 — a park must not be restored while the SAME account is live elsewhere
// ---------------------------------------------------------------------------

/**
 * The measured shape. Profile `predecessor` parked account X's OLD credential.
 * Account X's CURRENT credential is live in profile `squatted`'s dir, whose own
 * identity is a different account entirely (an in-place switch). Both
 * credentials are healthy.
 */
function twoCopiesOfOneAccount(): { predecessor: string; squatted: string } {
  const predecessor = makeProfile("predecessor", UUID_X, "x-old");
  // Its live copy lost the rotation race and was blanked in place.
  writeFileSync(join(predecessor, ".credentials.json"), rotatedAwayJson());

  // A different profile's dir now carries account X's CURRENT credential.
  const squatted = makeProfile("squatted", UUID_Y, "y");
  writeFileSync(join(squatted, ".claude.json"), identityJson(UUID_X, "x-new"));
  writeFileSync(join(squatted, ".credentials.json"), credentialJson("x-new"));
  return { predecessor, squatted };
}

test("recovery REFUSES when this account's credential is already live in another dir", () => {
  const { predecessor, squatted } = twoCopiesOfOneAccount();

  // The situation is real, not assumed: the park here is restorable and the
  // other dir genuinely holds a usable credential for the SAME account.
  expect(classifyCredentialFile(profileCredentialsSnapshot(predecessor)).state).toBe("usable");
  expect(classifyCredentialFile(join(squatted, ".credentials.json")).state).toBe("usable");

  const result = recoverParkedCredential(predecessor, tool(), "predecessor");

  expect(result.outcome).toBe("account-live-elsewhere");
  // A DISTINCT outcome, not a reuse of the neighbouring refusal: the operator
  // has to be able to tell "the dir shows someone else" from "this account is
  // already running somewhere else".
  expect(result.outcome).not.toBe("identity-would-change");
  // The detail has to name the other directory, or the operator cannot act.
  expect(result.detail).toContain(squatted);
});

test("the refusal writes nothing — neither dir is touched", () => {
  const { predecessor, squatted } = twoCopiesOfOneAccount();
  const parkedBefore = readFileSync(profileCredentialsSnapshot(predecessor));
  const liveElsewhereBefore = readFileSync(join(squatted, ".credentials.json"));
  const huskBefore = readFileSync(join(predecessor, ".credentials.json"));

  recoverParkedCredential(predecessor, tool(), "predecessor");

  expect(readFileSync(join(predecessor, ".credentials.json"))).toEqual(huskBefore);
  expect(readFileSync(profileCredentialsSnapshot(predecessor))).toEqual(parkedBefore);
  expect(readFileSync(join(squatted, ".credentials.json"))).toEqual(liveElsewhereBefore);
});

test("the launch path refuses it too — a blanket launch cannot create the second copy", () => {
  // `profileEnv` runs recovery on EVERY launch, so a gate that only exists on
  // the CLI path would still let a dozen agents starting up do the damage.
  const { predecessor, squatted } = twoCopiesOfOneAccount();
  const liveElsewhereBefore = readFileSync(join(squatted, ".credentials.json"));

  expect(() => profileEnv({ name: "predecessor", tool: "claude", dir: predecessor }, tool())).not.toThrow();

  expect(classifyCredentialFile(join(predecessor, ".credentials.json")).state).toBe("rotated-away");
  expect(readFileSync(join(squatted, ".credentials.json"))).toEqual(liveElsewhereBefore);
});

test("two doors of ONE account: the second is refused, so exactly one live copy survives", () => {
  // Not a squat — two profiles legitimately importing the same account, which
  // is the documented duplicate-door case. The hazard is identical.
  const first = makeProfile("doorone", UUID_X, "x-current");
  const second = makeProfile("doortwo", UUID_X, "x-old");
  writeFileSync(join(second, ".credentials.json"), rotatedAwayJson());

  expect(recoverParkedCredential(second, tool(), "doortwo").outcome).toBe("account-live-elsewhere");
  expect(classifyCredentialFile(join(first, ".credentials.json")).state).toBe("usable");
});

// --- discrimination: the gate reads LIVENESS, not the mere existence of a door

test("a dead copy of the same account elsewhere does NOT block recovery", () => {
  // Both dirs lost their credential. There is no working copy to revoke, so
  // refusing here would strand the account for no benefit. This separates
  // "another door exists" (never a reason to refuse) from "another door is
  // holding a usable credential" (always a reason to refuse).
  const mine = makeProfile("deadmine", UUID_X, "x-parked");
  writeFileSync(join(mine, ".credentials.json"), rotatedAwayJson());

  const other = makeProfile("deadother", UUID_Y, "y");
  writeFileSync(join(other, ".claude.json"), identityJson(UUID_X, "x-dead"));
  writeFileSync(join(other, ".credentials.json"), rotatedAwayJson());

  const result = recoverParkedCredential(mine, tool(), "deadmine");

  expect(result.outcome).toBe("recovered");
  expect(classifyCredentialFile(join(mine, ".credentials.json")).state).toBe("usable");
});

test("the same account merely PARKED in another dir does not block recovery", () => {
  // The other dir holds account X only in its `.accounts-auth/` park; its live
  // slot belongs to a different account. Restoring here yields exactly one LIVE
  // copy of X, which is the safe state. (Should the other dir later try to
  // restore its own park, this same gate will refuse it — the system converges
  // on one live copy either way.)
  const mine = makeProfile("parkedmine", UUID_X, "x-parked");
  writeFileSync(join(mine, ".credentials.json"), rotatedAwayJson());

  const other = makeProfile("parkedother", UUID_X, "x-also-parked");
  writeFileSync(join(other, ".claude.json"), identityJson(UUID_Z, "z"));
  writeFileSync(join(other, ".credentials.json"), credentialJson("z"));

  expect(recoverParkedCredential(mine, tool(), "parkedmine").outcome).toBe("recovered");
});

// --- POSITIVE CONTROLS: the gate must not be satisfiable by refusing everything

test("POSITIVE CONTROL: the account031 shape (husk in its own dir) still recovers", () => {
  // accessToken and refreshToken both empty strings, park matches the dir's own
  // account, that account live nowhere else. This is the case the whole feature
  // exists to serve; a gate that blocks it is a regression, not a fix.
  const dir = makeProfile("husk", UUID_Z, "z");
  const parked = readFileSync(profileCredentialsSnapshot(dir));
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  attachLiveSession(dir);

  const result = recoverParkedCredential(dir, tool(), "husk");

  expect(result.outcome).toBe("recovered");
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("usable");
  // Archive-never-delete: the park survives the restore byte for byte.
  expect(readFileSync(profileCredentialsSnapshot(dir))).toEqual(parked);
});

test("POSITIVE CONTROL: a park that IS the account's current credential still recovers", () => {
  // No husk at all — the dir simply has no live credential file. Nothing else
  // holds this account, so the park is the current credential and restoring it
  // is the correct, non-destructive action.
  const dir = makeProfile("absentlive", UUID_Z, "z");
  rmSync(join(dir, ".credentials.json"));
  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("absent");

  const result = recoverParkedCredential(dir, tool(), "absentlive");

  expect(result.outcome).toBe("recovered");
  expect(JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")).claudeAiOauth.accessToken).toBe("z-access");
});

test("an unreadable profile registry FAILS CLOSED rather than restoring blind", () => {
  // The launch path has no profile list of its own, so it reads the registry.
  // If that read fails, whether the account is live elsewhere is unknown — and
  // an unknown must not be spent as a "no". The cost of a wrong refusal is
  // re-running the command; the cost of a wrong restore is a revoked refresh
  // token on an account that still had headroom.
  const dir = makeProfile("failclosed", UUID_Z, "z");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  const husk = readFileSync(join(dir, ".credentials.json"));
  // Resolve the tool def BEFORE corrupting the store: `getTool` reads the store
  // too (for custom tools), so corrupting first would throw there and the
  // branch under test — the planner's profile-list read — would never run.
  const toolDef = tool();
  writeFileSync(join(home, "accounts.json"), "{ not valid json");

  const result = recoverParkedCredential(dir, toolDef, "failclosed");

  expect(result.outcome).toBe("cross-directory-unknown");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(husk);
  // And it still must not throw on the launch path.
  expect(() => profileEnv({ name: "failclosed", tool: "claude", dir }, toolDef)).not.toThrow();
  // Still nothing written after the launch-path call either.
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(husk);
});

test("a caller that supplies the profile list is not affected by an unreadable registry", () => {
  // The CLI holds its own list (possibly from a remote registry), so it must
  // not be dragged into the fail-closed branch by the local store's state.
  // Without this, fixing the launch path would break the repair command.
  const dir = makeProfile("suppliedlist", UUID_Z, "z");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  const toolDef = tool();
  writeFileSync(join(home, "accounts.json"), "{ not valid json");

  const result = recoverParkedCredential(dir, toolDef, "suppliedlist", {
    profiles: [{ name: "suppliedlist", dir }],
  });

  expect(result.outcome).toBe("recovered");
});

test("POSITIVE CONTROL: the launch path still recovers the account031 shape", () => {
  const dir = makeProfile("huskenv", UUID_Z, "z");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

  profileEnv({ name: "huskenv", tool: "claude", dir }, tool());

  expect(classifyCredentialFile(join(dir, ".credentials.json")).state).toBe("usable");
});

// ---------------------------------------------------------------------------
// DEFECT 2 — the plan and the execution must reach the same verdict
// ---------------------------------------------------------------------------

/** What the executor is expected to return for a given plan outcome. */
function executedOutcomeFor(plan: ParkedRecoveryPlanOutcome): ParkedRecoveryOutcome {
  return plan === "would-recover" ? "recovered" : plan;
}

interface Shape {
  label: string;
  expected: ParkedRecoveryPlanOutcome;
  build: () => string;
}

/**
 * Each matrix row gets its OWN account uuid. Sharing one would make two rows
 * two doors of a single account, and the `account-live-elsewhere` gate would
 * then fire on rows that are meant to exercise something else — the matrix
 * would be measuring its own fixture instead of the code.
 */
const SHAPE_UUID = {
  healthy: "d0000000-0001-4001-8001-000000000001",
  recoverable: "d0000000-0002-4002-8002-000000000002",
  nothingParked: "d0000000-0003-4003-8003-000000000003",
  switchedAway: "d0000000-0004-4004-8004-000000000004",
} as const;

/**
 * Every outcome the planner can produce, each from a distinct fixture. The
 * matrix is the discriminating input: a planner that always returned one value
 * would fail on six of the seven rows, so agreement on any single row is only
 * meaningful because disagreement is reachable on the others.
 */
function shapes(): Shape[] {
  return [
    {
      label: "healthy live credential",
      expected: "live-credential-usable",
      build: () => makeProfile("healthy", SHAPE_UUID.healthy, "healthy"),
    },
    {
      label: "husk over a restorable park",
      expected: "would-recover",
      build: () => {
        const dir = makeProfile("recoverable", SHAPE_UUID.recoverable, "recoverable");
        writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
        return dir;
      },
    },
    {
      label: "husk with nothing parked",
      expected: "no-parked-credential",
      build: () => {
        const dir = makeProfile("nothingparked", SHAPE_UUID.nothingParked, "nothingparked");
        writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
        writeFileSync(profileCredentialsSnapshot(dir), rotatedAwayJson());
        writeFileSync(join(home, "auth", SHAPE_UUID.nothingParked, "credentials.json"), rotatedAwayJson());
        return dir;
      },
    },
    {
      label: "the account028 shape: switched-away dir with live sessions attached",
      expected: "identity-would-change",
      build: () => {
        const dir = makeProfile("switchedaway", SHAPE_UUID.switchedAway, "switchedaway");
        writeFileSync(join(dir, ".claude.json"), identityJson(UUID_Y, "guest"));
        writeSwitchedAccountMarker(dir, { profile: "guest", email: "guest@example.com" });
        writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
        attachLiveSession(dir);
        return dir;
      },
    },
    {
      label: "parked credential with no parked identity",
      expected: "identity-unknown",
      build: () => {
        const dir = scratchDir("gates-noident");
        mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
        writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("orphan"));
        writeFileSync(join(dir, ".claude.json"), identityJson(UUID_Y, "guest"));
        writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
        addProfile({ name: "noident", dir });
        return dir;
      },
    },
    {
      label: "this account is live in another dir",
      expected: "account-live-elsewhere",
      build: () => twoCopiesOfOneAccount().predecessor,
    },
    {
      label: "a non-Claude tool",
      expected: "not-applicable",
      build: () => scratchDir("gates-notclaude"),
    },
  ];
}

const MATRIX_TIMEOUT_MS = 60_000;

test("the planner can reach every outcome — the agreement matrix is discriminating", () => {
  const seen = new Set<ParkedRecoveryPlanOutcome>();
  for (const shape of shapes()) {
    const dir = shape.build();
    const toolDef = shape.expected === "not-applicable" ? getTool("codex") : tool();
    const plan = planParkedRecovery(dir, toolDef, "probe");
    expect(plan.outcome, shape.label).toBe(shape.expected);
    seen.add(plan.outcome);
  }
  expect(seen.size).toBe(shapes().length);
}, MATRIX_TIMEOUT_MS);

test("dry-run and the real run reach the SAME verdict for every shape", () => {
  // The defect: the dry-run branch computed `parkedCredentialVerdict` and never
  // applied any identity gate, so it said `would-recover` for shapes the real
  // run refuses. Asserted as equality across the whole matrix, not eyeballed.
  for (const shape of shapes()) {
    const dir = shape.build();
    const toolDef = shape.expected === "not-applicable" ? getTool("codex") : tool();

    const planned = planParkedRecovery(dir, toolDef, "probe").outcome;
    const executed = recoverParkedCredential(dir, toolDef, "probe").outcome;

    expect(executed, shape.label).toBe(executedOutcomeFor(planned));
  }
}, MATRIX_TIMEOUT_MS);

test("the plan is pure — planning the account031 shape writes nothing", () => {
  const dir = makeProfile("planpure", UUID_Z, "z");
  writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
  const before = readFileSync(join(dir, ".credentials.json"));

  const plan = planParkedRecovery(dir, tool(), "planpure");

  expect(plan.outcome).toBe("would-recover");
  expect(readFileSync(join(dir, ".credentials.json"))).toEqual(before);
});

test("planning never throws, whatever shape the dir is in", () => {
  // Same guarantee `recoverParkedCredential` already carries: the planner is on
  // the launch path via the executor, so a half-built profile must not take a
  // launch down with it.
  const broken: Array<[string, (dir: string) => void]> = [
    ["nothing at all", () => {}],
    ["unreadable everything", (dir) => {
      mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
      writeFileSync(join(dir, ".claude.json"), "{ not json");
      writeFileSync(join(dir, ".credentials.json"), "{ not json");
      writeFileSync(join(dir, ".accounts-auth", "credentials.json"), "{ not json");
    }],
    ["malformed uuid on both sides", (dir) => {
      mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
      writeFileSync(join(dir, ".accounts-auth", "oauth-account.json"), identityJson("not-a-uuid", "host"));
      writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credentialJson("host"));
      writeFileSync(join(dir, ".claude.json"), identityJson("not-a-uuid", "host"));
      writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
    }],
  ];

  for (const [label, build] of broken) {
    const dir = scratchDir("gates-broken");
    build(dir);
    expect(() => planParkedRecovery(dir, tool(), "shaky"), label).not.toThrow();
  }
});
