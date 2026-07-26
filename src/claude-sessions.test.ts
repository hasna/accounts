import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Profile } from "./types.js";
import {
  CLAUDE_SESSION_METADATA_MAX_BYTES,
  listClaudeSessions,
} from "./lib/claude-sessions.js";

const UUID_A = "11111111-1111-4111-8111-111111111111";
const UUID_B = "22222222-2222-4222-8222-222222222222";
const UUID_C = "33333333-3333-4333-8333-333333333333";
const UUID_D = "44444444-4444-7444-8444-444444444444";

let root: string;
let accountsHome: string;
let profilesRoot: string;
let fakeHome: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "accounts-claude-sessions-"));
  accountsHome = join(root, "accounts");
  profilesRoot = join(accountsHome, "profiles");
  fakeHome = join(root, "home");
  mkdirSync(profilesRoot, { recursive: true });
  mkdirSync(fakeHome, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function profile(name: string, dir = join(profilesRoot, "claude", name)): Profile {
  return {
    name,
    tool: "claude",
    dir,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function sessionPath(profileDir: string, encodedProject: string, uuid: string): string {
  const projectDir = join(profileDir, "projects", encodedProject);
  mkdirSync(projectDir, { recursive: true });
  return join(projectDir, `${uuid}.jsonl`);
}

function writeSession(
  profileDir: string,
  encodedProject: string,
  uuid: string,
  cwd: string,
  secret = "PROMPT_MUST_NOT_ESCAPE",
): string {
  const path = sessionPath(profileDir, encodedProject, uuid);
  writeFileSync(
    path,
    `${JSON.stringify({
      type: "user",
      sessionId: uuid,
      cwd,
      message: { role: "user", content: secret },
    })}\n`,
  );
  return path;
}

describe("Claude session catalog discovery", () => {
  test("preserves owner + project + UUID identity across managed profiles and represented main", () => {
    const work = profile("work");
    const personal = profile("personal");
    const main = profile("main", join(fakeHome, ".claude"));
    const repoOne = join(root, "repos", "one");
    const repoTwo = join(root, "repos", "two");
    const repoMain = join(root, "repos", "main");
    mkdirSync(repoOne, { recursive: true });
    mkdirSync(repoTwo, { recursive: true });
    mkdirSync(repoMain, { recursive: true });

    const workSource = writeSession(work.dir, "-repos-one", UUID_A, repoOne);
    writeSession(personal.dir, "-repos-two", UUID_A, repoTwo);
    writeSession(main.dir, "-repos-main", UUID_B, repoMain);

    const sessions = listClaudeSessions([personal, main, work], {
      profilesRoot,
      defaultDir: main.dir,
    });

    expect(sessions).toHaveLength(3);
    expect(sessions.map((entry) => [entry.ownerProfile, entry.encodedProject, entry.uuid])).toEqual([
      ["main", "-repos-main", UUID_B],
      ["personal", "-repos-two", UUID_A],
      ["work", "-repos-one", UUID_A],
    ]);
    expect(sessions.find((entry) => entry.ownerProfile === "work")).toMatchObject({
      projectIdentity: repoOne,
      cwd: repoOne,
      sourcePath: workSource,
    });
    expect(new Set(sessions.map((entry) => JSON.stringify(entry.identity))).size).toBe(3);
  });

  test("excludes stale foreign, missing, non-Claude, and unrepresented default directories", () => {
    const valid = profile("valid");
    const foreign = profile("foreign", join(root, "tmp", "claude-profile"));
    const macStale = profile("mac-stale", "/Users/other/.claude-profile");
    const missing = profile("missing");
    const defaultDir = join(fakeHome, ".claude");
    const codex = { ...profile("codex"), tool: "codex" };

    writeSession(valid.dir, "-repo-valid", UUID_A, join(root, "repo-valid"));
    writeSession(foreign.dir, "-repo-foreign", UUID_B, join(root, "repo-foreign"));
    writeSession(defaultDir, "-repo-main", UUID_C, join(root, "repo-main"));

    const sessions = listClaudeSessions([valid, foreign, macStale, missing, codex], {
      profilesRoot,
      defaultDir,
    });

    expect(sessions.map((entry) => entry.ownerProfile)).toEqual(["valid"]);
  });

  test("does not follow profile, project, or session symlinks and only accepts root UUID JSONL files", () => {
    const valid = profile("valid");
    const linkedProfile = profile("linked");
    const outside = join(root, "outside");
    const outsideProject = join(outside, "project");
    mkdirSync(outsideProject, { recursive: true });
    writeFileSync(join(outsideProject, `${UUID_A}.jsonl`), `${JSON.stringify({ cwd: "/outside" })}\n`);

    mkdirSync(join(profilesRoot, "claude"), { recursive: true });
    symlinkSync(outside, linkedProfile.dir, "dir");

    const projectsDir = join(valid.dir, "projects");
    mkdirSync(projectsDir, { recursive: true });
    symlinkSync(outsideProject, join(projectsDir, "-linked-project"), "dir");

    const realProject = join(projectsDir, "-real-project");
    mkdirSync(realProject, { recursive: true });
    symlinkSync(join(outsideProject, `${UUID_A}.jsonl`), join(realProject, `${UUID_B}.jsonl`), "file");
    writeFileSync(join(realProject, "not-a-session.jsonl"), "{}\n");
    mkdirSync(join(realProject, "nested"), { recursive: true });
    writeFileSync(join(realProject, "nested", `${UUID_C}.jsonl`), "{}\n");
    writeFileSync(join(realProject, `${UUID_D}.jsonl`), `${JSON.stringify({ cwd: "/real" })}\n`);

    const sessions = listClaudeSessions([linkedProfile, valid], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });

    expect(sessions.map((entry) => entry.uuid)).toEqual([UUID_D]);
  });

  test("tolerates malformed transcripts and bounds top-level metadata parsing", () => {
    const work = profile("work");
    const recovered = sessionPath(work.dir, "-repo-recovered", UUID_A);
    const recoveredCwd = join(root, "repo-recovered");
    writeFileSync(
      recovered,
      `not-json\n${JSON.stringify({
        type: "system",
        cwd: recoveredCwd,
        message: { cwd: "/nested-must-not-win", content: "PROMPT_MUST_NOT_ESCAPE" },
      })}\n`,
    );

    const malformed = sessionPath(work.dir, "-repo-malformed", UUID_B);
    writeFileSync(malformed, "{\"cwd\":");

    const bounded = sessionPath(work.dir, "-repo-bounded", UUID_C);
    writeFileSync(
      bounded,
      `${"x".repeat(CLAUDE_SESSION_METADATA_MAX_BYTES)}\n${JSON.stringify({ cwd: "/too-late" })}\n`,
    );

    const sessions = listClaudeSessions([work], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });

    expect(sessions.find((entry) => entry.uuid === UUID_A)).toMatchObject({
      cwd: recoveredCwd,
      projectIdentity: recoveredCwd,
    });
    expect(sessions.find((entry) => entry.uuid === UUID_B)).toMatchObject({
      projectIdentity: "encoded:-repo-malformed",
    });
    expect(sessions.find((entry) => entry.uuid === UUID_C)).toMatchObject({
      projectIdentity: "encoded:-repo-bounded",
    });
  });
});

describe("accounts sessions CLI", () => {
  function writeStore(profiles: Profile[]): void {
    mkdirSync(accountsHome, { recursive: true });
    writeFileSync(
      join(accountsHome, "accounts.json"),
      JSON.stringify({
        version: 1,
        current: {},
        applied: {},
        toolLocks: {},
        tools: [],
        profiles,
      }),
    );
  }

  function runCli(...args: string[]) {
    return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_ENV: "test",
        HOME: fakeHome,
        ACCOUNTS_HOME: accountsHome,
        NO_COLOR: "1",
      },
    });
  }

  test("renders a concise table by default and structured filtered JSON for both command forms", () => {
    const work = profile("work");
    const personal = profile("personal");
    const projectOne = join(root, "repo-one");
    const projectTwo = join(root, "repo-two");
    writeSession(work.dir, "-repo-one", UUID_A, projectOne, "FIRST_SECRET_PROMPT");
    writeSession(personal.dir, "-repo-two", UUID_A, projectTwo, "SECOND_SECRET_PROMPT");
    writeStore([personal, work]);

    const table = runCli("sessions");
    expect(table.status).toBe(0);
    expect(table.stdout).toContain("OWNER");
    expect(table.stdout).toContain("PROJECT");
    expect(table.stdout).toContain("UUID");
    expect(table.stdout).toContain("personal");
    expect(table.stdout).toContain("work");
    expect(table.stdout).not.toContain("SECRET_PROMPT");

    const json = runCli(
      "sessions",
      "list",
      "--profile",
      "work",
      "--project",
      projectOne,
      "--uuid",
      UUID_A,
      "--json",
    );
    expect(json.status).toBe(0);
    const parsed = JSON.parse(json.stdout) as Array<Record<string, unknown>>;
    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toMatchObject({
      ownerProfile: "work",
      encodedProject: "-repo-one",
      projectIdentity: projectOne,
      uuid: UUID_A,
    });
    expect(parsed[0]?.identity).toEqual({
      ownerProfile: "work",
      projectIdentity: projectOne,
      uuid: UUID_A,
    });
    expect(json.stdout).not.toContain("FIRST_SECRET_PROMPT");

    const duplicateUuid = runCli("sessions", "--uuid", UUID_A, "--json");
    expect(duplicateUuid.status).toBe(0);
    expect(
      (JSON.parse(duplicateUuid.stdout) as Array<{ ownerProfile: string }>).map((entry) => entry.ownerProfile),
    ).toEqual(["personal", "work"]);

    const directJson = runCli("sessions", "--profile", "personal", "--json");
    expect(directJson.status).toBe(0);
    expect(JSON.parse(directJson.stdout)).toHaveLength(1);
  });
});
