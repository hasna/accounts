import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import type { Profile } from "./types.js";
import {
  CLAUDE_SESSION_METADATA_MAX_BYTES,
  listClaudeSessions,
  matchesClaudeSessionReference,
  resolveClaudeSessionReference,
  type ClaudeSessionCatalogEntry,
  type ClaudeSessionScanSkip,
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

function bulkUuid(index: number): string {
  return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function bulkCatalogEntry(index: number): ClaudeSessionCatalogEntry {
  const uuid = bulkUuid(index);
  const sourcePath = `/profiles/bulk/projects/-bulk/${uuid}.jsonl`;
  const catalogRefAlias = `claude-session:v1:${index}`;
  return {
    identity: {
      ownerProfile: "bulk",
      profileIdentity: "/profiles/bulk",
      profilePath: "/profiles/bulk",
      encodedProject: "-bulk",
      projectIdentity: "/repo-bulk",
      uuid,
      sourcePath,
    },
    storageIdentity: {
      profilePath: "/profiles/bulk",
      encodedProject: "-bulk",
      uuid,
      sourcePath,
    },
    catalogRef: `claude-session:v2:${index}`,
    catalogRefAliases: [catalogRefAlias],
    representations: [
      {
        ownerProfile: "bulk",
        profileIdentity: "/profiles/bulk",
        profilePath: "/profiles/bulk",
        catalogRefAlias,
      },
    ],
    ownerProfile: "bulk",
    profileIdentity: "/profiles/bulk",
    profilePath: "/profiles/bulk",
    encodedProject: "-bulk",
    projectIdentity: "/repo-bulk",
    cwd: "/repo-bulk",
    uuid,
    sourcePath,
    sessionIdCheck: "bounded-match",
    sizeBytes: index,
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}

function encodedCatalogRef(version: 1 | 2, parts: readonly string[]): string {
  return `claude-session:v${version}:${parts.map((part) => encodeURIComponent(part)).join(":")}`;
}

/** The published binary runs on node, which `bun test` is not. */
function resolveNodeBinary(): string | undefined {
  const probe = spawnSync("node", ["--version"], { encoding: "utf8" });
  return probe.status === 0 ? "node" : undefined;
}

async function waitFor(condition: () => boolean, label: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
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
    expect(managedEntry.catalogRef).toBe(
      encodedCatalogRef(2, [
        canonicalPath(managed.dir),
        "-same-project",
        UUID_A,
        canonicalPath(managedSource),
      ]),
    );
    expect(managedEntry.catalogRefAliases).toEqual([
      encodedCatalogRef(1, [
        managed.identity,
        canonicalPath(managed.dir),
        "-same-project",
        UUID_A,
        canonicalPath(managedSource),
      ]),
    ]);
    expect(managedEntry.storageIdentity).toEqual({
      profilePath: canonicalPath(managed.dir),
      encodedProject: "-same-project",
      uuid: UUID_A,
      sourcePath: canonicalPath(managedSource),
    });
    expect(sessions.map((entry) => entry.identity.sourcePath).sort()).toEqual(
      [canonicalPath(defaultSource), canonicalPath(managedSource)].sort(),
    );
    expect(managedEntry.sessionIdCheck).toBe("bounded-mismatch");
    expect(
      sessions.find((entry) => entry.sourcePath === canonicalPath(defaultSource))?.sessionIdCheck,
    ).toBe("bounded-match");
    expect(JSON.stringify(sessions)).not.toContain("SECRET_ONE");
  });

  test("deduplicates and deterministically represents profiles that share one default root", () => {
    const sharedDir = join(fakeHome, ".claude");
    const primary = { ...profile("primary", sharedDir), identity: "identity://primary" };
    const secondary = { ...profile("secondary", sharedDir), identity: "identity://secondary" };
    const source = writeSession(
      sharedDir,
      "-shared-default",
      UUID_A,
      join(root, "repo-shared"),
    );

    const first = listClaudeSessions([primary, secondary], {
      profilesRoot,
      defaultDir: sharedDir,
    });
    const reordered = listClaudeSessions([secondary, primary], {
      profilesRoot,
      defaultDir: sharedDir,
    });

    expect(first).toEqual(reordered);
    expect(first).toHaveLength(1);
    expect(first[0]?.ownerProfile).toBe("primary");
    expect(first[0]?.representations).toEqual([
      {
        ownerProfile: "primary",
        profileIdentity: "identity://primary",
        profilePath: canonicalPath(sharedDir),
        catalogRefAlias: encodedCatalogRef(1, [
          "identity://primary",
          canonicalPath(sharedDir),
          "-shared-default",
          UUID_A,
          canonicalPath(source),
        ]),
      },
      {
        ownerProfile: "secondary",
        profileIdentity: "identity://secondary",
        profilePath: canonicalPath(sharedDir),
        catalogRefAlias: encodedCatalogRef(1, [
          "identity://secondary",
          canonicalPath(sharedDir),
          "-shared-default",
          UUID_A,
          canonicalPath(source),
        ]),
      },
    ]);
    expect(first[0]?.catalogRefAliases).toEqual(
      first[0]!.representations.map((representation) => representation.catalogRefAlias).sort(),
    );
    expect(first[0]?.catalogRef).toBe(
      encodedCatalogRef(2, [
        canonicalPath(sharedDir),
        "-shared-default",
        UUID_A,
        canonicalPath(source),
      ]),
    );

    const filtered = listClaudeSessions([secondary, primary], {
      profilesRoot,
      defaultDir: sharedDir,
      profile: "secondary",
    });
    expect(filtered).toEqual(first);
  });

  test("deduplicates exact duplicate profile source records", () => {
    const representedDefault = {
      ...profile("main", join(fakeHome, ".claude")),
      identity: "identity://represented-default",
    };
    writeSession(
      representedDefault.dir,
      "-represented-default",
      UUID_A,
      join(root, "repo-default"),
    );

    const sessions = listClaudeSessions(
      [representedDefault, { ...representedDefault }],
      {
        profilesRoot,
        defaultDir: representedDefault.dir,
      },
    );

    expect(sessions).toHaveLength(1);
    expect(sessions[0]?.ownerProfile).toBe("main");
  });

  test("keeps the canonical ref stable when mutable profile identity metadata changes", () => {
    const managed = profile("managed");
    writeSession(managed.dir, "-identity-change", UUID_A, join(root, "repo-identity"));

    const before = listClaudeSessions(
      [{ ...managed, identity: "identity://before" }],
      {
        profilesRoot,
        defaultDir: join(fakeHome, ".claude"),
      },
    )[0]!;
    const after = listClaudeSessions(
      [{ ...managed, identity: "identity://after" }],
      {
        profilesRoot,
        defaultDir: join(fakeHome, ".claude"),
      },
    )[0]!;

    expect(after.catalogRef).toBe(before.catalogRef);
    expect(after.storageIdentity).toEqual(before.storageIdentity);
    expect(after.catalogRefAliases).not.toEqual(before.catalogRefAliases);
  });

  test("resolves canonical and landed v1 aliases while bare UUIDs stay storage-ambiguous", () => {
    const sharedDir = join(fakeHome, ".claude");
    const primary = { ...profile("primary", sharedDir), identity: "identity://primary" };
    const secondary = { ...profile("secondary", sharedDir), identity: "identity://secondary" };
    const distinct = profile("distinct");
    writeSession(sharedDir, "-shared", UUID_A, join(root, "repo-shared"));
    writeSession(distinct.dir, "-distinct", UUID_A, join(root, "repo-distinct"));

    const entries = listClaudeSessions([secondary, distinct, primary], {
      profilesRoot,
      defaultDir: sharedDir,
    });
    expect(entries).toHaveLength(2);
    const shared = entries.find((entry) => entry.profilePath === canonicalPath(sharedDir))!;
    expect(shared.catalogRefAliases).toHaveLength(2);
    expect(resolveClaudeSessionReference(entries, shared.catalogRef)).toBe(shared);
    for (const alias of shared.catalogRefAliases) {
      expect(matchesClaudeSessionReference(shared, alias)).toBe(true);
      expect(resolveClaudeSessionReference(entries, alias)).toBe(shared);
    }
    expect(() =>
      resolveClaudeSessionReference(entries, "claude-session:v1:unknown-development-ref"),
    ).toThrow("invalid or stale Claude session catalogRef");
    expect(() => resolveClaudeSessionReference(entries, UUID_A)).toThrow(
      "Claude session UUID is ambiguous",
    );

    const sameStorageOnly = entries.filter((entry) => entry === shared);
    expect(resolveClaudeSessionReference(sameStorageOnly, UUID_A)).toBe(shared);
  });

  test("uses canonical storage identity as the total sort tie-breaker", () => {
    const firstRoot = join(profilesRoot, "claude", "storage-a");
    const secondRoot = join(profilesRoot, "claude", "storage-b");
    const firstProfile = { ...profile("same-owner", firstRoot), identity: "identity://z" };
    const secondProfile = { ...profile("same-owner", secondRoot), identity: "identity://a" };
    const sharedCwd = join(root, "same-project");
    writeSession(firstRoot, "-same", UUID_A, sharedCwd);
    writeSession(secondRoot, "-same", UUID_A, sharedCwd);

    const forward = listClaudeSessions([firstProfile, secondProfile], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });
    const reversed = listClaudeSessions([secondProfile, firstProfile], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
    });

    expect(forward).toEqual(reversed);
    expect(forward).toHaveLength(2);
    expect(forward.map((entry) => entry.catalogRef)).toEqual(
      [...forward.map((entry) => entry.catalogRef)].sort(),
    );
    expect(() => resolveClaudeSessionReference(forward, UUID_A)).toThrow(
      "Claude session UUID is ambiguous",
    );
  });

  test("skips one malformed profile identity without aborting the catalog or exposing it", () => {
    const valid = profile("valid");
    const malformed = {
      ...profile("malformed"),
      identity: "SENSITIVE_IDENTITY_PREFIX\uD800",
    };
    writeSession(valid.dir, "-valid", UUID_A, join(root, "repo-valid"));
    writeSession(malformed.dir, "-malformed", UUID_B, join(root, "repo-malformed"));
    const skipped: ClaudeSessionScanSkip[] = [];

    const sessions = listClaudeSessions([malformed, valid], {
      profilesRoot,
      defaultDir: join(fakeHome, ".claude"),
      onSkip: (skip) => {
        skipped.push(skip);
      },
    });

    expect(sessions.map((entry) => entry.ownerProfile)).toEqual(["valid"]);
    expect(skipped).toEqual([
      {
        path: canonicalPath(malformed.dir),
        reason: "invalid-profile-identity",
      },
    ]);
    expect(JSON.stringify({ sessions, skipped })).not.toContain("SENSITIVE_IDENTITY_PREFIX");
  });

  test("reports and rejects malicious, stale, nested, traversal, and symlink stored roots", () => {
    const foreign = profile("foreign", join(root, "foreign"));
    const nested = profile("nested", join(profilesRoot, "claude", "parent", "nested"));
    const traversalTarget = join(profilesRoot, "claude", "traversal-target");
    const traversal = profile(
      "traversal",
      `${join(profilesRoot, "claude", "temporary")}${sep}..${sep}traversal-target`,
    );
    const linked = profile("linked", join(profilesRoot, "claude", "linked"));
    const missing = profile("missing", join(profilesRoot, "claude", "missing"));
    const outside = join(root, "outside");

    writeSession(foreign.dir, "-foreign", UUID_A, join(root, "repo-foreign"));
    writeSession(nested.dir, "-nested", UUID_B, join(root, "repo-nested"));
    writeSession(traversalTarget, "-traversal", UUID_C, join(root, "repo-traversal"));
    writeSession(outside, "-linked", UUID_D, join(root, "repo-linked"));
    mkdirSync(join(profilesRoot, "claude"), { recursive: true });
    symlinkSync(outside, linked.dir, "dir");

    const skipped: ClaudeSessionScanSkip[] = [];
    const sessions = listClaudeSessions(
      [linked, traversal, nested, missing, foreign],
      {
        profilesRoot,
        defaultDir: join(fakeHome, ".claude"),
        onSkip: (skip) => {
          skipped.push(skip);
        },
      },
    );

    expect(sessions).toEqual([]);
    expect(skipped.map((skip) => skip.reason)).toEqual([
      "untrusted-profile-root",
      "untrusted-profile-root",
      "missing-profile-root",
      "untrusted-profile-root",
      "untrusted-profile-root",
    ]);
    expect(JSON.stringify(skipped)).not.toContain("PROMPT_MUST_NOT_ESCAPE");
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

  test("stays complete while project directories and sessions are written underneath it", async () => {
    const work = profile("churn");
    const projectCount = 24;
    const sessionsPerProject = 10;
    const expected = projectCount * sessionsPerProject;
    for (let project = 0; project < projectCount; project++) {
      for (let session = 0; session < sessionsPerProject; session++) {
        writeSession(
          work.dir,
          `-repo-${project}`,
          bulkUuid(project * sessionsPerProject + session),
          join(root, `repo-${project}`),
        );
      }
    }
    const livePath = writeSession(work.dir, "-live", UUID_A, join(root, "repo-live"));

    const projectsDir = join(work.dir, "projects");
    const readyPath = join(root, "churn-ready");
    const stopPath = join(root, "churn-stop");
    const counterPath = join(root, "churn-count");
    // The churn process appends one byte per pass; sampling the size never
    // races with a rewrite, and 0 simply means "no reading this time".
    const churnCount = (): number => {
      try {
        return statSync(counterPath).size;
      } catch {
        return 0;
      }
    };

    const churn = spawn(
      process.execPath,
      [
        "run",
        join("test", "support", "claude-session-churn.ts"),
        projectsDir,
        join(projectsDir, "-repo-0"),
        livePath,
        readyPath,
        stopPath,
        counterPath,
      ],
      { cwd: process.cwd(), env: process.env, stdio: ["ignore", "ignore", "ignore"] },
    );
    // Subscribe before the scans so an early exit cannot be missed in `finally`.
    const churnClosed = once(churn, "close");
    churn.on("error", () => {});

    try {
      await waitFor(() => existsSync(readyPath), "the churn process to start");
      const churnedBeforeScans = churnCount();
      let churnedDuringScans = churnedBeforeScans;
      for (let scan = 0; scan < 25; scan++) {
        const skipped: ClaudeSessionScanSkip[] = [];
        const sessions = listClaudeSessions([work], {
          profilesRoot,
          defaultDir: join(fakeHome, ".claude"),
          onSkip: (skip) => {
            skipped.push(skip);
          },
        });
        // Settled sessions are never in the churn path, so every scan must see
        // all of them: a TOCTOU guard failure may not silently truncate.
        expect(sessions.filter((entry) => entry.encodedProject !== "-live")).toHaveLength(expected);
        // The session being appended to may legitimately lose the race, but it
        // has to be reported rather than silently omitted.
        expect(
          sessions.some((entry) => entry.encodedProject === "-live") ||
            skipped.some((skip) => skip.path === livePath),
        ).toBe(true);
        churnedDuringScans = Math.max(churnedDuringScans, churnCount());
      }
      // Proves the scans really did overlap a mutating tree.
      expect(churnedDuringScans).toBeGreaterThan(churnedBeforeScans);
    } finally {
      writeFileSync(stopPath, "");
      churn.kill();
      await churnClosed;
    }
  }, 60_000);

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "reports project directories it cannot observe instead of dropping them",
    () => {
      const work = profile("locked");
      writeSession(work.dir, "-visible", UUID_A, join(root, "repo-visible"));
      writeSession(work.dir, "-locked", UUID_B, join(root, "repo-locked"));
      const lockedDir = join(work.dir, "projects", "-locked");
      const skipped: ClaudeSessionScanSkip[] = [];

      chmodSync(lockedDir, 0o000);
      try {
        const sessions = listClaudeSessions([work], {
          profilesRoot,
          defaultDir: join(fakeHome, ".claude"),
          onSkip: (skip) => {
            skipped.push(skip);
          },
        });

        expect(sessions.map((entry) => entry.uuid)).toEqual([UUID_A]);
        expect(skipped).toEqual([{ path: lockedDir, reason: "unstable-directory" }]);
      } finally {
        chmodSync(lockedDir, 0o700);
      }
    },
  );
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

  function cliEnv(): NodeJS.ProcessEnv {
    return {
      ...process.env,
      NODE_ENV: "test",
      HOME: fakeHome,
      USERPROFILE: fakeHome,
      ACCOUNTS_HOME: accountsHome,
      NO_COLOR: "1",
    };
  }

  function runCliEntrypoint(entrypointArgs: string[], ...args: string[]) {
    return spawnSync(process.execPath, [...entrypointArgs, ...args], {
      cwd: process.cwd(),
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      env: cliEnv(),
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
    expect(parsed[0]?.catalogRef).toMatch(/^claude-session:v2:/);
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

  test("keeps managed and default-root sessions stable through real accounts rename commands", () => {
    const managed = profile("managed-old");
    const representedDefault = profile("default-old", join(fakeHome, ".claude"));
    const managedSource = writeSession(
      managed.dir,
      "-managed",
      UUID_A,
      join(root, "repo-managed"),
    );
    const defaultSource = writeSession(
      representedDefault.dir,
      "-default",
      UUID_B,
      join(root, "repo-default"),
    );
    writeStore([managed, representedDefault]);

    const beforeResult = runCli("sessions", "--json");
    expect(beforeResult.status).toBe(0);
    expect(beforeResult.stderr).toBe("");
    const before = parseCatalog(beforeResult);

    const managedRename = runCli(
      "rename",
      "managed-old",
      "managed-new",
      "--tool",
      "claude",
    );
    const defaultRename = runCli(
      "rename",
      "default-old",
      "default-new",
      "--tool",
      "claude",
    );
    expect(managedRename.status).toBe(0);
    expect(defaultRename.status).toBe(0);

    const afterResult = runCli("sessions", "--json");
    expect(afterResult.status).toBe(0);
    expect(afterResult.stderr).toBe("");
    const after = parseCatalog(afterResult);
    const beforeBySource = new Map(before.map((entry) => [entry.sourcePath, entry]));
    const afterBySource = new Map(after.map((entry) => [entry.sourcePath, entry]));

    for (const [source, renamedOwner] of [
      [canonicalPath(managedSource), "managed-new"],
      [canonicalPath(defaultSource), "default-new"],
    ] as const) {
      expect(afterBySource.get(source)?.catalogRef).toBe(beforeBySource.get(source)?.catalogRef);
      expect(afterBySource.get(source)?.catalogRefAliases).toEqual(
        beforeBySource.get(source)?.catalogRefAliases,
      );
      expect(afterBySource.get(source)?.ownerProfile).toBe(renamedOwner);
      expect(
        (
          afterBySource.get(source)?.representations as
            | Array<{ ownerProfile: string }>
            | undefined
        )?.map((representation) => representation.ownerProfile),
      ).toEqual([renamedOwner]);
    }

    const stored = JSON.parse(readFileSync(join(accountsHome, "accounts.json"), "utf8")) as {
      profiles: Profile[];
    };
    expect(stored.profiles.find((entry) => entry.name === "managed-new")?.dir).toBe(managed.dir);
    expect(stored.profiles.find((entry) => entry.name === "default-new")?.dir).toBe(
      representedDefault.dir,
    );
  });

  test("rejects invalid UUID filter syntax while a valid no-match remains successful", () => {
    writeStore([]);

    const invalid = runCli("sessions", "--uuid", "not-a-uuid", "--json");
    expect(invalid.status).not.toBe(0);
    expect(invalid.stdout).toBe("");
    expect(invalid.stderr).toContain("--uuid must be a valid UUID");

    const noMatch = runCli("sessions", "--uuid", UUID_D, "--json");
    expect(noMatch.status).toBe(0);
    expect(JSON.parse(noMatch.stdout)).toEqual([]);
    expect(noMatch.stderr).toBe("");
  });

  test("isolates malformed UTF-16 identity from a real CLI catalog pass", () => {
    const valid = profile("valid");
    const malformed = {
      ...profile("malformed"),
      identity: "CLI_IDENTITY_MUST_NOT_ESCAPE\uD800",
    };
    writeSession(valid.dir, "-valid", UUID_A, join(root, "repo-valid"));
    writeSession(malformed.dir, "-malformed", UUID_B, join(root, "repo-malformed"));
    writeStore([malformed, valid]);

    const result = runCli("sessions", "--json");
    expect(result.status).toBe(0);
    expect(parseCatalog(result).map((entry) => entry.ownerProfile)).toEqual(["valid"]);
    expect(result.stderr).toContain("invalid-profile-identity");
    expect(result.stdout).not.toContain("CLI_IDENTITY_MUST_NOT_ESCAPE");
    expect(result.stderr).not.toContain("CLI_IDENTITY_MUST_NOT_ESCAPE");
    expect(result.stderr).not.toContain("URIError");
  });

  test("warns instead of silently omitting rejected registered Claude roots", () => {
    const nested = profile(
      "nested",
      join(profilesRoot, "claude", "unexpected-parent", "nested"),
    );
    const missing = profile("missing");
    writeSession(nested.dir, "-nested", UUID_A, join(root, "repo-nested"));
    writeStore([nested, missing]);

    const result = runCli("sessions", "--json");
    expect(result.status).toBe(0);
    expect(parseCatalog(result)).toEqual([]);
    expect(result.stderr).toContain("warning: 2 source root/path(s)");
    expect(result.stderr).toContain("missing-profile-root");
    expect(result.stderr).toContain("untrusted-profile-root");
    expect(result.stderr).not.toContain("PROMPT_MUST_NOT_ESCAPE");
  });

  test("shows bounded metadata integrity states in the human table", () => {
    const match = bulkCatalogEntry(1);
    const mismatch = {
      ...bulkCatalogEntry(2),
      sessionIdCheck: "bounded-mismatch" as const,
    };
    const notObserved = {
      ...bulkCatalogEntry(3),
      sessionIdCheck: "not-observed" as const,
    };

    const table = formatClaudeSessionTable([match, mismatch, notObserved]);
    expect(table).toContain("ID CHECK");
    expect(table).toContain("bounded-match");
    expect(table).toContain("BOUNDED-MISMATCH");
    expect(table).toContain("NOT-OBSERVED");
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

  // Default table mode, on the engine the published binary actually runs. Both
  // entrypoints above are driven by `process.execPath`, which under `bun test`
  // is Bun — and Bun's call arity ceiling is several times node's, so a catalog
  // that Bun formats happily is one node can abort on. The harness refuses to
  // run unless the row count still overflows a spread on the engine under test.
  const nodeBinary = resolveNodeBinary();
  test.skipIf(nodeBinary === undefined)(
    "formats a catalog past node's call arity ceiling instead of aborting the table",
    () => {
      const rows = 200_000;
      const buildDir = join(root, "table-scale");
      const build = spawnSync(
        process.execPath,
        [
          "build",
          "./test/support/claude-session-table-scale.ts",
          "--outdir",
          buildDir,
          "--target",
          "node",
        ],
        { cwd: process.cwd(), encoding: "utf8" },
      );
      expect(build.status).toBe(0);

      const formatted = spawnSync(
        nodeBinary!,
        [join(buildDir, "claude-session-table-scale.js"), String(rows)],
        { cwd: process.cwd(), encoding: "utf8" },
      );
      expect(formatted.stderr).not.toContain("RangeError");
      expect(formatted.status).toBe(0);
      // Header, rule, then every row: the catalog is formatted, not truncated.
      expect(formatted.stdout.trim()).toBe(String(rows + 2));
    },
    60_000,
  );

  // The same invariant stated so it holds on every engine, including one whose
  // ceiling is too high to reach with a catalog a test can afford to build.
  test("measures column widths without one call argument per catalog row", () => {
    const entries = Array.from({ length: 5_000 }, (_, index) => bulkCatalogEntry(index));
    const nativeMax = Math.max;
    let widestCall = 0;
    Math.max = ((...values: number[]) => {
      widestCall = nativeMax(widestCall, values.length);
      return nativeMax(...values);
    }) as typeof Math.max;
    let table: string;
    try {
      table = formatClaudeSessionTable(entries);
    } finally {
      Math.max = nativeMax;
    }

    expect(table.split("\n")).toHaveLength(entries.length + 2);
    expect(widestCall).toBeLessThanOrEqual(4);
  });

  // POSIX pipe semantics: a reader that quits early is the case the guard is
  // for, and the crash it prevents was only ever reachable there.
  test.skipIf(process.platform === "win32")(
    "exits cleanly when the reader closes the pipe before the catalog is flushed",
    async () => {
      const work = profile("piped");
      for (let index = 0; index < 400; index++) {
        writeSession(work.dir, "-piped", bulkUuid(index), join(root, "repo-piped"));
      }
      writeStore([work]);

      const child = spawn(process.execPath, ["run", "src/cli.ts", "sessions", "--json"], {
        cwd: process.cwd(),
        env: cliEnv(),
      });
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.stdout.on("error", () => {});
      child.stdout.destroy();

      const [code] = (await once(child, "close")) as [number | null, string | null];
      expect(stderr).toBe("");
      expect(code).toBe(0);
    },
    30_000,
  );

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "warns on stderr about paths that could not be observed",
    () => {
      const work = profile("locked");
      writeSession(work.dir, "-visible", UUID_A, join(root, "repo-visible"));
      writeSession(work.dir, "-locked", UUID_B, join(root, "repo-locked"));
      const lockedDir = join(work.dir, "projects", "-locked");
      writeStore([work]);

      chmodSync(lockedDir, 0o000);
      try {
        const json = runCli("sessions", "--json");
        expect(json.status).toBe(0);
        expect(parseCatalog(json).map((entry) => entry.uuid)).toEqual([UUID_A]);
        expect(json.stderr).toContain("warning:");
        expect(json.stderr).toContain("unstable-directory");
        expect(json.stderr).toContain(lockedDir);
      } finally {
        chmodSync(lockedDir, 0o700);
      }
    },
  );

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
      storageIdentity: {
        profilePath: "/profiles/safe",
        encodedProject: "-project",
        uuid: UUID_A,
        sourcePath: `/profiles/safe/projects/-project/${UUID_A}.jsonl`,
      },
      catalogRef: "claude-session:v2:test",
      catalogRefAliases: ["claude-session:v1:test"],
      representations: [
        {
          ownerProfile: `\u202e\u2066safe`,
          profileIdentity: "identity://safe",
          profilePath: "/profiles/safe",
          catalogRefAlias: "claude-session:v1:test",
        },
      ],
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
