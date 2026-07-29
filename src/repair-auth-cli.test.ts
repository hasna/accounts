import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * CLI-level regressions for bb267228.
 *
 * The dry-run defect lives in `cli.ts`, not in the library: the `--dry-run`
 * branch computed `parkedCredentialVerdict` (pure content ranking) while the
 * real branch called `recoverParkedCredential` (which applies identity gates).
 * A library-only test cannot see that divergence, so these drive the actual
 * command and compare the two runs' JSON.
 *
 * Everything lives under a throwaway ACCOUNTS_HOME. No live profile directory is
 * read or written, and `repair-auth` is never run against the real registry.
 *
 * Each test spawns the CLI several times, so the per-test timeout is raised
 * well past bun's 5s default — on a loaded machine these legitimately take
 * ~10s, and a timeout there would look like a product failure.
 */

const CLI_TIMEOUT_MS = 60_000;

let home: string;
const scratch: string[] = [];

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ACCOUNTS_TEST_LIVE_DIR: join(home, "live") },
  });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-repair-cli-"));
  mkdirSync(join(home, "live"), { recursive: true });
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  while (scratch.length > 0) rmSync(scratch.pop()!, { recursive: true, force: true });
});

const UUID_OWN = "e0000000-1111-4111-8111-000000000011";
const UUID_GUEST = "e0000000-2222-4222-8222-000000000022";
const UUID_SHARED = "e0000000-3333-4333-8333-000000000033";
const UUID_OTHER = "e0000000-4444-4444-8444-000000000044";

/** Healthy: refresh token present, comfortably unexpired. Placeholder values. */
function credentialJson(label: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${label}-access`,
      refreshToken: `${label}-refresh`,
      expiresAt: Date.now() + 600_000,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

/** The husk a lost rotation race leaves behind. */
function rotatedAwayJson(): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: "",
      refreshToken: "",
      expiresAt: 0,
      refreshTokenExpiresAt: Date.now() + 30 * 24 * 60 * 60_000,
    },
  });
}

function identityJson(uuid: string, label: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: `${label}@example.com` } });
}

function scratchDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  scratch.push(dir);
  return dir;
}

/** Register a profile with the CLI so the run sees exactly what an operator would. */
function addProfileDir(name: string, uuid: string, label: string): string {
  const dir = scratchDir(`repaircli-${name}`);
  writeFileSync(join(dir, ".claude.json"), identityJson(uuid, label));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(label));
  const add = runCli("add", name, "--dir", dir);
  expect(add.status, add.stderr).toBe(0);
  return dir;
}

/** Park every profile's own identity + credential, the way a real profile has them. */
function parkAll(): void {
  const migrate = runCli("auth", "migrate", "--json");
  expect(migrate.status, migrate.stderr).toBe(0);
}

interface Row {
  profile: string;
  outcome: string;
  detail: string;
}

function repairRows(...extra: string[]): Row[] {
  const run = runCli("repair-auth", "--json", ...extra);
  expect(run.status, run.stderr).toBe(0);
  return (JSON.parse(run.stdout) as { profiles: Row[] }).profiles;
}

function rowFor(rows: Row[], profile: string): Row {
  const row = rows.find((r) => r.profile === profile);
  if (!row) throw new Error(`no repair-auth row for ${profile}: ${JSON.stringify(rows)}`);
  return row;
}

/**
 * Profile `predecessor` parked account SHARED's old credential; account SHARED's
 * current credential is live in `squatted`'s dir. Both healthy.
 */
function twoCopiesOfOneAccount(): { predecessor: string; squatted: string } {
  const predecessor = addProfileDir("predecessor", UUID_SHARED, "shared-old");
  const squatted = addProfileDir("squatted", UUID_OTHER, "other");
  parkAll();
  writeFileSync(join(predecessor, ".credentials.json"), rotatedAwayJson());
  writeFileSync(join(squatted, ".claude.json"), identityJson(UUID_SHARED, "shared-new"));
  writeFileSync(join(squatted, ".credentials.json"), credentialJson("shared-new"));
  return { predecessor, squatted };
}

test(
  "--dry-run and the real run agree on a switched-away dir with live sessions",
  () => {
    // The measured account028 shape. Before the fix the dry-run said
    // `would-recover` here while the real run refused with
    // `identity-would-change ... with 1 live session(s) attached`.
    const dir = addProfileDir("switched", UUID_OWN, "own");
    parkAll();
    writeFileSync(join(dir, ".claude.json"), identityJson(UUID_GUEST, "guest"));
    writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());
    mkdirSync(join(dir, "sessions"), { recursive: true });
    writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));

    const dry = rowFor(repairRows("--dry-run"), "switched");
    const real = rowFor(repairRows(), "switched");

    // Asserted as equality, not eyeballed.
    expect(dry.outcome).toBe(real.outcome);
    expect(dry.outcome).toBe("identity-would-change");
    expect(dry.detail).toContain("live session(s) attached");
  },
  CLI_TIMEOUT_MS,
);

test(
  "--dry-run and the real run agree when the account is live in another dir",
  () => {
    const { squatted } = twoCopiesOfOneAccount();
    const liveElsewhereBefore = readFileSync(join(squatted, ".credentials.json"));

    const dry = rowFor(repairRows("--dry-run"), "predecessor");
    const real = rowFor(repairRows(), "predecessor");

    expect(dry.outcome).toBe(real.outcome);
    expect(dry.outcome).toBe("account-live-elsewhere");
    // A blanket `repair-auth` with no profile argument attempted this and would
    // have created the second live copy. Nothing moved.
    expect(readFileSync(join(squatted, ".credentials.json"))).toEqual(liveElsewhereBefore);
  },
  CLI_TIMEOUT_MS,
);

test(
  "a single-profile run still sees the OTHER dirs — the gate is not narrowed away",
  () => {
    // `repair-auth predecessor` repairs one profile, but the question "is this
    // account live elsewhere" is about every OTHER dir. If the command passed
    // only its filtered list to the gate, the gate could never fire — a check
    // that cannot fail. This is the positive control for that wiring.
    twoCopiesOfOneAccount();

    const rows = repairRows("predecessor");

    expect(rows.length).toBe(1);
    expect(rowFor(rows, "predecessor").outcome).toBe("account-live-elsewhere");
  },
  CLI_TIMEOUT_MS,
);

test(
  "POSITIVE CONTROL: the account031 shape still recovers on the CLI path",
  () => {
    // Required control for the fail-closed design: if the cross-directory gate
    // were unsatisfiable, or if the CLI stopped supplying its profile list, this
    // legitimate recovery would silently stop working.
    const dir = addProfileDir("husk", UUID_OWN, "own");
    parkAll();
    writeFileSync(join(dir, ".credentials.json"), rotatedAwayJson());

    const dry = rowFor(repairRows("--dry-run"), "husk");
    expect(dry.outcome).toBe("would-recover");
    // The preview must not have written anything.
    expect(JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")).claudeAiOauth.accessToken).toBe("");

    const real = rowFor(repairRows(), "husk");
    expect(real.outcome).toBe("recovered");
    expect(JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")).claudeAiOauth.accessToken).toBe(
      "own-access",
    );
  },
  CLI_TIMEOUT_MS,
);

test(
  "a refusal is reported to the operator, not filtered out of the human output",
  () => {
    // `account-live-elsewhere` is the outcome that stops a destructive blanket
    // run. If the text renderer drops it the operator sees "nothing to repair"
    // and goes looking for another way to force it.
    twoCopiesOfOneAccount();

    const run = runCli("repair-auth", "--dry-run");
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toContain("account-live-elsewhere");
    expect(run.stdout).toContain("predecessor");
  },
  CLI_TIMEOUT_MS,
);
