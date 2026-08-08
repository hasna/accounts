import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let root: string;
let home: string;
let sharedHome: string;

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      ACCOUNTS_SHARED_HOME_CLAUDE: sharedHome,
      ACCOUNTS_TEST_LIVE_DIR: join(root, "livehome"),
    },
  });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "accounts-migrate-sessions-"));
  home = join(root, "accounts");
  sharedHome = join(root, "shared-claude");
  mkdirSync(join(root, "livehome"), { recursive: true });
  // A capability corpus so `add`/`doctor` capability checks stay green.
  mkdirSync(join(sharedHome, "skills", "alpha"), { recursive: true });
  writeFileSync(join(sharedHome, "skills", "alpha", "SKILL.md"), "---\nname: alpha\n---\nbody\n");
  mkdirSync(join(sharedHome, "agents"), { recursive: true });
  writeFileSync(join(sharedHome, "agents", "reviewer.md"), "---\nname: reviewer\n---\nbody\n");
  writeFileSync(join(root, "livehome", ".claude.json"), JSON.stringify({ mcpServers: { todos: { command: "todos-mcp" } } }));
  mkdirSync(home, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const sharedSessions = () => join(home, "shared", "claude-sessions");

test("add provisions a new claude profile with sessions linked to the shared dir from birth", () => {
  const add = runCli("add", "born-linked", "--email", "born@example.com");
  expect(add.status).toBe(0);

  const link = join(home, "profiles", "claude", "born-linked", "sessions");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  expect(realpathSync(link)).toBe(realpathSync(sharedSessions()));
});

test("migrate-sessions --dir migrates a real dir and is idempotent", () => {
  const dir = join(root, "cfg");
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", "4242.json"), JSON.stringify({ pid: 4242 }));

  const first = runCli("migrate-sessions", "--dir", dir, "--json");
  expect(first.status).toBe(0);
  const parsed = JSON.parse(first.stdout) as {
    schema: string;
    sharedDir: string;
    results: Array<{ outcome: string; moved?: string[] }>;
  };
  expect(parsed.schema).toBe("hasna.accounts.migrate-sessions/v1");
  expect(parsed.results[0]?.outcome).toBe("migrated");
  expect(parsed.results[0]?.moved).toEqual(["4242.json"]);
  expect(lstatSync(join(dir, "sessions")).isSymbolicLink()).toBe(true);
  expect(readdirSync(sharedSessions())).toEqual(["4242.json"]);

  const second = runCli("migrate-sessions", "--dir", dir, "--json");
  expect(second.status).toBe(0);
  const parsedSecond = JSON.parse(second.stdout) as { results: Array<{ outcome: string }> };
  expect(parsedSecond.results[0]?.outcome).toBe("already-linked");
});

test("migrate-sessions --json exits non-zero while preserving a blocked structured result", () => {
  const dir = join(root, "blocked-json");
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", "notes.txt"), "unexpected registry content\n");

  const result = runCli("migrate-sessions", "--dir", dir, "--json");

  expect(result.status).toBe(1);
  expect(result.stderr).toBe("");
  const parsed = JSON.parse(result.stdout) as {
    schema: string;
    results: Array<{ dir: string; outcome: string; reason?: string }>;
  };
  expect(parsed.schema).toBe("hasna.accounts.migrate-sessions/v1");
  expect(parsed.results).toHaveLength(1);
  expect(parsed.results[0]?.dir).toBe(dir);
  expect(parsed.results[0]?.outcome).toBe("blocked");
  expect(parsed.results[0]?.reason).toContain("unexpected content");
  expect(lstatSync(join(dir, "sessions")).isDirectory()).toBe(true);
  expect(lstatSync(join(dir, "sessions")).isSymbolicLink()).toBe(false);
  expect(readdirSync(join(dir, "sessions"))).toEqual(["notes.txt"]);
});

test("migrate-sessions --all covers every registered claude profile", () => {
  expect(runCli("add", "mig-one", "--email", "one@example.com").status).toBe(0);
  expect(runCli("add", "mig-two", "--email", "two@example.com").status).toBe(0);
  // Simulate a Claude update recreating one profile's sessions as a real dir.
  const dirOne = join(home, "profiles", "claude", "mig-one");
  rmSync(join(dirOne, "sessions"), { force: true });
  mkdirSync(join(dirOne, "sessions"));
  writeFileSync(join(dirOne, "sessions", "777.json"), JSON.stringify({ pid: 777 }));

  const result = runCli("migrate-sessions", "--all", "--json");
  expect(result.status).toBe(0);
  const parsed = JSON.parse(result.stdout) as { results: Array<{ dir: string; outcome: string }> };
  const one = parsed.results.find((row) => row.dir === dirOne);
  expect(one?.outcome).toBe("migrated");
  expect(realpathSync(join(dirOne, "sessions"))).toBe(realpathSync(sharedSessions()));
  expect(readdirSync(sharedSessions())).toContain("777.json");
});

test("doctor flags a profile whose sessions link was replaced by a real dir, and --apply repairs it", () => {
  expect(runCli("add", "drifted", "--email", "drift@example.com").status).toBe(0);
  const dir = join(home, "profiles", "claude", "drifted");
  expect(runCli("doctor").status).toBe(0);

  // A Claude update owns `sessions/` and may recreate it as a real dir.
  rmSync(join(dir, "sessions"), { force: true });
  mkdirSync(join(dir, "sessions"));
  writeFileSync(join(dir, "sessions", "888.json"), JSON.stringify({ pid: 888 }));

  const broken = runCli("doctor");
  expect(broken.status).toBe(1);
  expect(broken.stdout).toContain("sessions registry");

  const repaired = runCli("doctor", "--apply");
  expect(repaired.status).toBe(0);
  expect(repaired.stdout).toContain("relinked");
  expect(realpathSync(join(dir, "sessions"))).toBe(realpathSync(sharedSessions()));
  expect(readdirSync(sharedSessions())).toContain("888.json");

  expect(runCli("doctor").status).toBe(0);
});

test("doctor flags a sessions link pointing somewhere other than the shared dir", () => {
  expect(runCli("add", "foreign", "--email", "foreign@example.com").status).toBe(0);
  const dir = join(home, "profiles", "claude", "foreign");
  rmSync(join(dir, "sessions"), { force: true });
  mkdirSync(join(root, "elsewhere"), { recursive: true });
  symlinkSync(join(root, "elsewhere"), join(dir, "sessions"));

  const broken = runCli("doctor");
  expect(broken.status).toBe(1);
  expect(broken.stdout).toContain("sessions registry");

  const repaired = runCli("doctor", "--apply");
  expect(repaired.status).toBe(0);
  expect(realpathSync(join(dir, "sessions"))).toBe(realpathSync(sharedSessions()));
});
