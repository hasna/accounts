import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ensureSharedClaudeSessions,
  inspectSessionsDir,
  sharedClaudeSessionsDir,
} from "./lib/claude-session-registry.js";
import { listDirLiveSessions } from "./lib/claude-layout.js";

let root: string;
let accountsHome: string;
let previousAccountsHome: string | undefined;
let previousLiveDir: string | undefined;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "accounts-session-registry-"));
  accountsHome = join(root, "accounts");
  mkdirSync(accountsHome, { recursive: true });
  previousAccountsHome = process.env.ACCOUNTS_HOME;
  previousLiveDir = process.env.ACCOUNTS_TEST_LIVE_DIR;
  process.env.ACCOUNTS_HOME = accountsHome;
  process.env.ACCOUNTS_TEST_LIVE_DIR = join(root, "livehome");
  mkdirSync(join(root, "livehome"), { recursive: true });
});

afterEach(() => {
  if (previousAccountsHome === undefined) delete process.env.ACCOUNTS_HOME;
  else process.env.ACCOUNTS_HOME = previousAccountsHome;
  if (previousLiveDir === undefined) delete process.env.ACCOUNTS_TEST_LIVE_DIR;
  else process.env.ACCOUNTS_TEST_LIVE_DIR = previousLiveDir;
  rmSync(root, { recursive: true, force: true });
});

function makeProfileDir(name: string): string {
  const dir = join(accountsHome, "profiles", "claude", name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function sessionEntry(pid: number, extra: Record<string, unknown> = {}): string {
  return `${JSON.stringify({
    pid,
    sessionId: "00000000-0000-4000-8000-00000000000" + (pid % 10),
    name: `agent-${pid}`,
    messagingSocketPath: `/tmp/cc-socks/${pid}.sock`,
    peerProtocol: 1,
    kind: "interactive",
    status: "idle",
    ...extra,
  })}\n`;
}

describe("ensureSharedClaudeSessions", () => {
  test("links a profile with no sessions dir, and is idempotent", () => {
    const dir = makeProfileDir("account001");

    const first = ensureSharedClaudeSessions(dir);
    expect(first.outcome).toBe("linked");
    expect(first.changed).toBe(true);

    const link = join(dir, "sessions");
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(realpathSync(link)).toBe(realpathSync(sharedClaudeSessionsDir()));

    const second = ensureSharedClaudeSessions(dir);
    expect(second.outcome).toBe("already-linked");
    expect(second.changed).toBe(false);
  });

  test("migrates an existing real sessions dir into the shared dir by rename", () => {
    const dir = makeProfileDir("account002");
    const sessions = join(dir, "sessions");
    mkdirSync(sessions, { recursive: true });
    writeFileSync(join(sessions, "111.json"), sessionEntry(111));
    writeFileSync(join(sessions, "222.json"), sessionEntry(222));

    const result = ensureSharedClaudeSessions(dir);
    expect(result.outcome).toBe("migrated");
    expect(result.changed).toBe(true);
    expect(result.moved.sort()).toEqual(["111.json", "222.json"]);

    const shared = sharedClaudeSessionsDir();
    expect(readdirSync(shared).sort()).toEqual(["111.json", "222.json"]);
    expect(lstatSync(join(dir, "sessions")).isSymbolicLink()).toBe(true);
    // The entries stay readable through the profile path.
    expect(JSON.parse(readFileSync(join(dir, "sessions", "111.json"), "utf8")).pid).toBe(111);

    // Idempotent: a second run changes nothing.
    const second = ensureSharedClaudeSessions(dir);
    expect(second.outcome).toBe("already-linked");
    expect(second.changed).toBe(false);
    expect(second.moved).toEqual([]);
  });

  test("dedupes a pid present in both places by keeping the newest copy", () => {
    const dir = makeProfileDir("account003");
    const sessions = join(dir, "sessions");
    const shared = sharedClaudeSessionsDir();
    mkdirSync(sessions, { recursive: true });
    mkdirSync(shared, { recursive: true });

    // Profile copy of 555 is NEWER than the shared copy — profile wins.
    writeFileSync(join(shared, "555.json"), sessionEntry(555, { status: "stale-copy" }));
    utimesSync(join(shared, "555.json"), new Date("2026-01-01"), new Date("2026-01-01"));
    writeFileSync(join(sessions, "555.json"), sessionEntry(555, { status: "fresh-copy" }));

    // Profile copy of 666 is OLDER than the shared copy — shared wins.
    writeFileSync(join(sessions, "666.json"), sessionEntry(666, { status: "stale-copy" }));
    utimesSync(join(sessions, "666.json"), new Date("2026-01-01"), new Date("2026-01-01"));
    writeFileSync(join(shared, "666.json"), sessionEntry(666, { status: "fresh-copy" }));

    const result = ensureSharedClaudeSessions(dir);
    expect(result.outcome).toBe("migrated");
    const kept555 = JSON.parse(readFileSync(join(shared, "555.json"), "utf8")) as { status: string };
    const kept666 = JSON.parse(readFileSync(join(shared, "666.json"), "utf8")) as { status: string };
    expect(kept555.status).toBe("fresh-copy");
    expect(kept666.status).toBe("fresh-copy");
    expect(lstatSync(join(dir, "sessions")).isSymbolicLink()).toBe(true);
  });

  test("repoints a foreign symlink at the shared dir", () => {
    const dir = makeProfileDir("account004");
    const elsewhere = join(root, "elsewhere");
    mkdirSync(elsewhere, { recursive: true });
    symlinkSync(elsewhere, join(dir, "sessions"));

    const result = ensureSharedClaudeSessions(dir);
    expect(result.outcome).toBe("repointed");
    expect(result.changed).toBe(true);
    expect(realpathSync(join(dir, "sessions"))).toBe(realpathSync(sharedClaudeSessionsDir()));
    // The foreign target is left exactly as it was.
    expect(existsSync(elsewhere)).toBe(true);
  });

  test("refuses to migrate a sessions dir holding unexpected content, deleting nothing", () => {
    const dir = makeProfileDir("account005");
    const sessions = join(dir, "sessions");
    mkdirSync(join(sessions, "unexpected-subdir"), { recursive: true });
    writeFileSync(join(sessions, "123.json"), sessionEntry(123));
    writeFileSync(join(sessions, "notes.txt"), "not a registry entry\n");

    const result = ensureSharedClaudeSessions(dir);
    expect(result.outcome).toBe("blocked");
    expect(result.changed).toBe(false);
    expect(result.reason).toContain("unexpected");
    // Nothing moved, nothing deleted, dir still real.
    expect(lstatSync(sessions).isDirectory()).toBe(true);
    expect(lstatSync(sessions).isSymbolicLink()).toBe(false);
    expect(readdirSync(sessions).sort()).toEqual(["123.json", "notes.txt", "unexpected-subdir"]);
  });

  test("never touches auth artifacts (switching/link state survives byte-for-byte)", () => {
    const dir = makeProfileDir("account006");
    const authDir = join(dir, ".accounts-auth");
    mkdirSync(authDir, { recursive: true });
    writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" } }));
    writeFileSync(join(authDir, "credentials.json"), '{"claudeAiOauth":{"refreshToken":"KEEP"}}\n');
    // The live credential is a symlink into the central store, per the
    // single-inode broker — ensure must not rewrite, retarget, or replace it.
    const central = join(accountsHome, "auth", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    mkdirSync(central, { recursive: true });
    writeFileSync(join(central, "credentials.json"), '{"claudeAiOauth":{"refreshToken":"KEEP"}}\n');
    symlinkSync(join(central, "credentials.json"), join(dir, ".credentials.json"));

    const before = {
      credLink: readlinkSync(join(dir, ".credentials.json")),
      claudeJson: readFileSync(join(dir, ".claude.json"), "utf8"),
      snapshot: readFileSync(join(authDir, "credentials.json"), "utf8"),
      central: readFileSync(join(central, "credentials.json"), "utf8"),
    };
    const result = ensureSharedClaudeSessions(dir);
    expect(result.changed).toBe(true);
    expect(readlinkSync(join(dir, ".credentials.json"))).toBe(before.credLink);
    expect(readFileSync(join(dir, ".claude.json"), "utf8")).toBe(before.claudeJson);
    expect(readFileSync(join(authDir, "credentials.json"), "utf8")).toBe(before.snapshot);
    expect(readFileSync(join(central, "credentials.json"), "utf8")).toBe(before.central);
  });

  test("inspectSessionsDir classifies every state", () => {
    const dir = makeProfileDir("account007");
    expect(inspectSessionsDir(dir).kind).toBe("missing");

    mkdirSync(join(dir, "sessions"));
    expect(inspectSessionsDir(dir).kind).toBe("real-dir");

    rmSync(join(dir, "sessions"), { recursive: true });
    symlinkSync(join(root, "elsewhere-2"), join(dir, "sessions"));
    expect(inspectSessionsDir(dir).kind).toBe("foreign-link");

    rmSync(join(dir, "sessions"));
    mkdirSync(sharedClaudeSessionsDir(), { recursive: true });
    symlinkSync(sharedClaudeSessionsDir(), join(dir, "sessions"));
    expect(inspectSessionsDir(dir).kind).toBe("shared-link");
  });
});

describe("listDirLiveSessions attribution over the shared registry", () => {
  test("a real per-profile sessions dir keeps its historical meaning: every entry is the dir's own", () => {
    const dir = makeProfileDir("legacy01");
    const sessions = join(dir, "sessions");
    mkdirSync(sessions, { recursive: true });
    writeFileSync(join(sessions, "101.json"), sessionEntry(101));
    writeFileSync(join(sessions, "102.json"), sessionEntry(102));

    const listed = listDirLiveSessions(dir, {
      isAlive: (pid) => pid === 101,
      readEnvironConfigDir: () => {
        throw new Error("attribution must not run for a per-profile real dir");
      },
    });
    expect(listed.map((s) => s.pid)).toEqual([101, 102]);
    expect(listed.find((s) => s.pid === 101)?.alive).toBe(true);
    expect(listed.find((s) => s.pid === 102)?.alive).toBe(false);
  });

  test("a shared sessions dir attributes entries per config dir", () => {
    const dirA = makeProfileDir("attribA");
    const dirB = makeProfileDir("attribB");
    const defaultDir = join(root, "livehome", ".claude");
    mkdirSync(defaultDir, { recursive: true });
    for (const dir of [dirA, dirB, defaultDir]) {
      expect(ensureSharedClaudeSessions(dir).changed).toBe(true);
    }
    const shared = sharedClaudeSessionsDir();
    writeFileSync(join(shared, "201.json"), sessionEntry(201)); // environ -> dirA
    writeFileSync(join(shared, "202.json"), sessionEntry(202)); // environ -> dirB
    writeFileSync(join(shared, "203.json"), sessionEntry(203)); // environ unreadable, alive -> unknown
    writeFileSync(join(shared, "204.json"), sessionEntry(204)); // environ has no CLAUDE_CONFIG_DIR -> default dir
    writeFileSync(join(shared, "205.json"), sessionEntry(205)); // dead + unattributable -> dropped

    const environ: Record<number, string | null | undefined> = {
      201: dirA,
      202: dirB,
      203: undefined,
      204: null,
      205: undefined,
    };
    const opts = {
      isAlive: (pid: number) => pid !== 205,
      readEnvironConfigDir: (pid: number) => environ[pid],
    };

    const inA = listDirLiveSessions(dirA, opts);
    expect(inA.map((s) => s.pid)).toEqual([201, 203]);
    expect(inA.find((s) => s.pid === 201)?.attribution).toBe("own");
    expect(inA.find((s) => s.pid === 203)?.attribution).toBe("unknown");

    const inB = listDirLiveSessions(dirB, opts);
    expect(inB.map((s) => s.pid)).toEqual([202, 203]);

    const inDefault = listDirLiveSessions(defaultDir, opts);
    expect(inDefault.map((s) => s.pid)).toEqual([203, 204]);
    expect(inDefault.find((s) => s.pid === 204)?.attribution).toBe("own");
  });

  test("a dead unreadable-environ entry is attributed through its transcript", () => {
    const dirA = makeProfileDir("transcriptA");
    const dirB = makeProfileDir("transcriptB");
    for (const dir of [dirA, dirB]) ensureSharedClaudeSessions(dir);
    const shared = sharedClaudeSessionsDir();

    const sessionId = "99999999-9999-4999-8999-999999999999";
    const cwd = join(root, "work", "proj.one");
    writeFileSync(join(shared, "301.json"), sessionEntry(301, { sessionId, cwd }));
    // dirA holds the transcript for that session; dirB does not.
    const encoded = cwd.replace(/[^A-Za-z0-9]/g, "-");
    mkdirSync(join(dirA, "projects", encoded), { recursive: true });
    writeFileSync(join(dirA, "projects", encoded, `${sessionId}.jsonl`), `{"sessionId":"${sessionId}"}\n`);

    const opts = { isAlive: () => false, readEnvironConfigDir: () => undefined };
    expect(listDirLiveSessions(dirA, opts).map((s) => s.pid)).toEqual([301]);
    expect(listDirLiveSessions(dirB, opts).map((s) => s.pid)).toEqual([]);
  });
});
