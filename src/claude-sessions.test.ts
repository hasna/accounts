import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
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
import { formatClaudeSessionTable } from "./lib/claude-sessions-cli.js";

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

function canonicalPath(path: string): string {
  return realpathSync.native(path);
}

function writeSession(
  profileDir: string,
  encodedProject: string,
  uuid: string,
  cwd: string,
  secret = "PROMPT_MUST_NOT_ESCAPE",
  sessionId = uuid,
): string {
  const path = sessionPath(profileDir, encodedProject, uuid);
  writeFileSync(
    path,
    `${JSON.stringify({
      type: "user",
      sessionId,
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
      sourcePath: canonicalPath(workSource),
      sessionIdCheck: "bounded-match",
      identity: {
        ownerProfile: "work",
        profileIdentity: canonicalPath(work.dir),
        profilePath: canonicalPath(work.dir),
        encodedProject: "-repos-one",
        projectIdentity: repoOne,
        uuid: UUID_A,
        sourcePath: canonicalPath(workSource),
      },
    });
    expect(new Set(sessions.map((entry) => JSON.stringify(entry.identity))).size).toBe(3);
    expect(new Set(sessions.map((entry) => entry.catalogRef)).size).toBe(3);
  });

  test("uses source paths in canonical refs and reports bounded sessionId mismatches", () => {
    const managed = { ...profile("same"), identity: "identity://managed-same" };
    const representedDefault = {
      ...profile("same", join(fakeHome, ".claude")),
      identity: "identity://default-same",
    };
    const sharedCwd = join(root, "repos", "same");
    mkdirSync(sharedCwd, { recursive: true });

    const managedSource = writeSession(managed.dir, "-same-project", UUID_A, sharedCwd, "SECRET_ONE", UUID_B);
    const defaultSource = writeSession(representedDefault.dir, "-same-project", UUID_A, sharedCwd);

    const sessions = listClaudeSessions([managed, representedDefault], {
      profilesRoot,
      defaultDir: representedDefault.dir,
    });

    expect(sessions).toHaveLength(2);
    expect(new Set(sessions.map((entry) => entry.catalogRef)).size).toBe(2);
    const managedEntry = sessions.find(
      (entry) => entry.sourcePath === canonicalPath(managedSource),
    )!;
    expect(managedEntry.catalogRef).toContain(encodeURIComponent(managed.identity));
    expect(managedEntry.catalogRef).toContain(encodeURIComponent(canonicalPath(managed.dir)));
    expect(managedEntry.catalogRef).toContain(encodeURIComponent("-same-project"));
    expect(managedEntry.catalogRef).toContain(UUID_A);
    expect(managedEntry.catalogRef).toContain(encodeURIComponent(canonicalPath(managedSource)));
    expect(sessions.map((entry) => entry.identity.sourcePath).sort()).toEqual(
      [canonicalPath(defaultSource), canonicalPath(managedSource)].sort(),
    );
    expect(managedEntry.sessionIdCheck).toBe("bounded-mismatch");
    expect(
      sessions.find((entry) => entry.sourcePath === canonicalPath(defaultSource))?.sessionIdCheck,
    ).toBe("bounded-match");
    expect(JSON.stringify(sessions)).not.toContain("SECRET_ONE");
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

  test("rejects multiply-linked session files and leaves transcript content unchanged", () => {
    const valid = profile("valid");
    const original = writeSession(valid.dir, "-hardlinks", UUID_A, "/hardlink");
    const linked = sessionPath(valid.dir, "-hardlinks", UUID_B);
    linkSync(original, linked);
    const retained = writeSession(valid.dir, "-hardlinks", UUID_C, "/retained");
    const before = readFileSync(retained);

    const sessions = listClaudeSessions([valid], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });

    expect(sessions.map((entry) => entry.uuid)).toEqual([UUID_C]);
    expect(readFileSync(retained)).toEqual(before);
  });

  test("normalizes profile-root comparison case on Windows", () => {
    const work = profile("work");
    writeSession(work.dir, "-case", UUID_A, join(root, "repo-case"));
    const caseVariant = { ...work, dir: work.dir.toUpperCase() };

    const sessions = listClaudeSessions([caseVariant], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });

    expect(sessions).toHaveLength(process.platform === "win32" ? 1 : 0);
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

  function runCliEntrypoint(entrypointArgs: string[], ...args: string[]) {
    return spawnSync(process.execPath, [...entrypointArgs, ...args], {
      cwd: process.cwd(),
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      env: {
        ...process.env,
        NODE_ENV: "test",
        HOME: fakeHome,
        ACCOUNTS_HOME: accountsHome,
        NO_COLOR: "1",
      },
    });
  }

  function runCli(...args: string[]) {
    return runCliEntrypoint(["run", "src/cli.ts"], ...args);
  }

  function parseCatalog(result: ReturnType<typeof runCli>): Array<Record<string, unknown>> {
    if (result.status !== 0) {
      throw new Error(`session CLI exited ${String(result.status)}: ${result.stderr.slice(0, 500)}`);
    }
    try {
      const value = JSON.parse(result.stdout) as unknown;
      if (!Array.isArray(value)) throw new Error("catalog JSON was not an array");
      return value as Array<Record<string, unknown>>;
    } catch (error) {
      throw new Error(
        `session CLI emitted invalid JSON (${result.stdout.length} bytes): ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
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
      profileIdentity: canonicalPath(work.dir),
      profilePath: canonicalPath(work.dir),
      encodedProject: "-repo-one",
      projectIdentity: projectOne,
      uuid: UUID_A,
      sourcePath: canonicalPath(sessionPath(work.dir, "-repo-one", UUID_A)),
    });
    expect(parsed[0]?.catalogRef).toMatch(/^claude-session:v1:/);
    expect(parsed[0]?.sessionIdCheck).toBe("bounded-match");
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

  test("flushes valid JSON for at least 2,000 sessions from source and built Bun entrypoints", () => {
    const work = profile("bulk");
    const count = 2_000;
    for (let index = 0; index < count; index++) {
      const uuid = `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
      writeSession(work.dir, "-bulk", uuid, join(root, "repo-bulk"));
    }
    writeStore([work]);

    const source = runCliEntrypoint(["run", "src/cli.ts"], "sessions", "--json");
    expect(source.status).toBe(0);
    expect(parseCatalog(source)).toHaveLength(count);

    const buildDir = join(root, "built");
    const build = spawnSync(
      process.execPath,
      [
        "build",
        "src/cli.ts",
        "--outdir",
        buildDir,
        "--target",
        "node",
        "--external",
        "@hasna/contracts",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
      },
    );
    expect(build.status).toBe(0);
    const built = runCliEntrypoint([join(buildDir, "cli.js")], "sessions", "--json");
    expect(built.status).toBe(0);
    expect(parseCatalog(built)).toHaveLength(count);
  }, 30_000);

  test("escapes Unicode controls and truncates tables without splitting code points", () => {
    const entry = {
      identity: {
        ownerProfile: "safe",
        profileIdentity: "identity://safe",
        profilePath: "/profiles/safe",
        encodedProject: "-project",
        projectIdentity: "/project",
        uuid: UUID_A,
        sourcePath: `/profiles/safe/projects/-project/${UUID_A}.jsonl`,
      },
      catalogRef: "claude-session:v1:test",
      ownerProfile: `\u202e\u2066safe`,
      profileIdentity: "identity://safe",
      profilePath: "/profiles/safe",
      encodedProject: `${"漢".repeat(22)}😀`,
      projectIdentity: "/project",
      uuid: UUID_A,
      sourcePath: `/profiles/safe/projects/-project/${UUID_A}.jsonl`,
      sessionIdCheck: "not-observed" as const,
      sizeBytes: 1,
      updatedAt: "2026-01-01T00:00:00.000Z",
    };

    const table = formatClaudeSessionTable([entry]);
    expect(table).toContain("\\u202e");
    expect(table).toContain("\\u2066");
    expect(table).not.toContain("\u202e");
    expect(table).not.toContain("\u2066");
    expect(table).toContain(`${"漢".repeat(19)}…`);
    expect(
      Array.from(table).some((character) => {
        const codePoint = character.codePointAt(0)!;
        return codePoint >= 0xd800 && codePoint <= 0xdfff;
      }),
    ).toBe(false);
  });
});
