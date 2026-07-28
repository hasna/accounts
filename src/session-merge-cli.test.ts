import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;
let sharedHome: string;

const PROJECT = "-home-hasna-workspace-alpha";
const SESSION = "00000000-0000-4000-8000-0000000000aa";

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ACCOUNTS_SHARED_HOME_CLAUDE: sharedHome },
  });
}

function profileDir(name: string): string {
  return join(home, "profiles", "claude", name);
}

/** A profile as it exists before session sharing: real `projects/`, real history. */
function seedLegacyProfile(name: string, session: string): void {
  const dir = profileDir(name);
  mkdirSync(join(dir, "projects", PROJECT), { recursive: true });
  writeFileSync(join(dir, "projects", PROJECT, `${session}.jsonl`), `{"sessionId":"${session}"}\n`);
  writeFileSync(
    join(dir, "history.jsonl"),
    `${JSON.stringify({ display: name, project: "/home/hasna", sessionId: session, timestamp: 1000 })}\n`,
  );
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-merge-cli-"));
  sharedHome = join(home, "shared-claude");
  mkdirSync(join(sharedHome, "skills"), { recursive: true });
  mkdirSync(join(sharedHome, "agents"), { recursive: true });
  mkdirSync(join(sharedHome, "projects"), { recursive: true });
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

test("`accounts sessions` still lists by default", () => {
  const result = runCli("sessions");
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("no Claude sessions found.");

  const explicit = runCli("sessions", "list");
  expect(explicit.status).toBe(0);
  expect(explicit.stdout).toBe(result.stdout);
});

test("`sessions merge --dry-run` reports counts and writes nothing", () => {
  expect(runCli("add", "alpha", "--email", "alpha@example.com").status).toBe(0);
  rmSync(join(profileDir("alpha"), "projects"), { force: true });
  seedLegacyProfile("alpha", SESSION);

  const dry = runCli("sessions", "merge", "--dry-run");
  expect(dry.status).toBe(0);
  expect(dry.stdout).toContain("dry run");
  expect(dry.stdout).toContain("alpha");
  expect(lstatSync(join(sharedHome, "projects", PROJECT), { throwIfNoEntry: false })).toBeUndefined();
});

test("`sessions merge` unions an unregistered profile's sessions and never links it", () => {
  // Thousands of transcripts on the real machine live in directories the
  // registry has forgotten; enumeration is from the filesystem for that reason.
  seedLegacyProfile("account088", SESSION);

  const merged = runCli("sessions", "merge", "--link", "--json");
  expect(merged.status).toBe(0);
  const report = JSON.parse(merged.stdout) as {
    sources: { profile: string; registered: boolean; merged: number; linkState: string }[];
    verification: { passed: boolean };
  };
  const source = report.sources.find((entry) => entry.profile === "account088")!;
  expect(source.registered).toBe(false);
  expect(source.merged).toBe(1);
  expect(source.linkState).toBe("skipped-unregistered");
  expect(report.verification.passed).toBe(true);

  const target = join(sharedHome, "projects", PROJECT, `${SESSION}.jsonl`);
  expect(statSync(target).ino).toBe(statSync(join(profileDir("account088"), "projects", PROJECT, `${SESSION}.jsonl`)).ino);
  expect(lstatSync(join(profileDir("account088"), "projects")).isSymbolicLink()).toBe(false);
});

test("`sessions merge --link` migrates a registered profile and retains its original", () => {
  expect(runCli("add", "alpha", "--email", "alpha@example.com").status).toBe(0);
  rmSync(join(profileDir("alpha"), "projects"), { force: true });
  rmSync(join(profileDir("alpha"), "history.jsonl"), { force: true });
  seedLegacyProfile("alpha", SESSION);

  const merged = runCli("sessions", "merge", "--link");
  expect(merged.status).toBe(0);
  expect(merged.stdout).toContain("originals retained");

  expect(lstatSync(join(profileDir("alpha"), "projects")).isSymbolicLink()).toBe(true);
  expect(lstatSync(join(profileDir("alpha"), "history.jsonl")).isSymbolicLink()).toBe(true);
  expect(readFileSync(join(profileDir("alpha"), "projects", PROJECT, `${SESSION}.jsonl`), "utf8")).toContain(SESSION);

  // A second run is a no-op that still exits 0.
  const again = runCli("sessions", "merge", "--link");
  expect(again.status).toBe(0);
  expect(again.stdout).toContain("already-linked");
});

test("a session written under one profile is readable through another", () => {
  // The whole point: resume work started elsewhere.
  for (const name of ["alpha", "beta"]) {
    expect(runCli("add", name, "--email", `${name}@example.com`).status).toBe(0);
    rmSync(join(profileDir(name), "projects"), { force: true });
    rmSync(join(profileDir(name), "history.jsonl"), { force: true });
  }
  seedLegacyProfile("alpha", SESSION);
  seedLegacyProfile("beta", "00000000-0000-4000-8000-0000000000bb");

  expect(runCli("sessions", "merge", "--link").status).toBe(0);

  // Each profile now reaches both sessions through its own config dir.
  for (const name of ["alpha", "beta"]) {
    expect(readFileSync(join(profileDir(name), "projects", PROJECT, `${SESSION}.jsonl`), "utf8")).toContain(SESSION);
    expect(
      readFileSync(join(profileDir(name), "projects", PROJECT, "00000000-0000-4000-8000-0000000000bb.jsonl"), "utf8"),
    ).toContain("0000000000bb");
    expect(readFileSync(join(profileDir(name), "history.jsonl"), "utf8")).toContain("alpha");
    expect(readFileSync(join(profileDir(name), "history.jsonl"), "utf8")).toContain("beta");
  }
});
