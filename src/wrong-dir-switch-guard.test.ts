// Regression tests for bug 04a350a9 (task c48e92b7): the wrong-dir switch.
//
// `resolveSessionConfigDir` falls through --dir -> CLAUDE_CONFIG_DIR -> the
// live default (~/.claude). A switch typed at a tmux pane prompt runs in a
// shell that carries no CLAUDE_CONFIG_DIR (profile wiring lives only inside
// `accounts launch` process subtrees), so the switch silently rewrote the
// live default while every profile-dir session on the box — the sessions the
// operator was actually looking at — never read it. Measured on station01:
// 20 of 31 live claude processes ran under profile dirs.
//
// The guard: when the FALLTHROUGH lands on the live default AND live
// profile-dir sessions exist on the box, name the targeted dir and refuse
// unless --live-default is passed. An explicit --dir or a set CLAUDE_CONFIG_DIR
// is a deliberate target and is never guarded.
import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { switchAccount } from "./lib/switch-account.js";
import { loadStore } from "./storage.js";
import { getTool } from "./lib/tools.js";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-wdg-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-wdg-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

// Synthetic sentinel tokens only — shaped so no secret scanner pattern matches.
function credentialJson(email: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${email}-access-sentinel`,
      refreshToken: `${email}-refresh-sentinel`,
      expiresAt: Date.now() + 60_000,
    },
  });
}

function writeIdentity(dir: string, email: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(email));
}

function makeProfile(name: string, email: string): string {
  const dir = mkdtempSync(join(tmpdir(), `wdg-${name}-`));
  writeIdentity(dir, email);
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

/** A profile dir with a LIVE session attached (this test process's own pid). */
function makeBusyProfile(name: string, email: string): string {
  const dir = makeProfile(name, email);
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
  return dir;
}

function seedLiveDefault(email: string): { credFile: string; bytes: Buffer } {
  const liveConfigDir = join(liveBase, ".claude");
  mkdirSync(liveConfigDir, { recursive: true });
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }));
  const credFile = join(liveConfigDir, ".credentials.json");
  writeFileSync(credFile, credentialJson(email));
  return { credFile, bytes: readFileSync(credFile) };
}

test("fallthrough onto the live default refuses while profile-dir sessions are live, naming the target dir", async () => {
  makeProfile("alpha", "alpha@example.com");
  makeBusyProfile("busy", "busy@example.com");
  const live = seedLiveDefault("victim@example.com");
  const liveConfigDir = join(liveBase, ".claude");

  // No --dir, no CLAUDE_CONFIG_DIR: the unwired-pane shape.
  await expect(switchAccount("alpha", { env: {} })).rejects.toThrow(liveConfigDir);
  await expect(switchAccount("alpha", { env: {} })).rejects.toThrow(/--live-default/);

  // The refusal must have mutated nothing.
  expect(readFileSync(live.credFile).equals(live.bytes)).toBe(true);
  const liveJson = JSON.parse(readFileSync(join(liveBase, ".claude.json"), "utf8")) as {
    oauthAccount?: { emailAddress?: string };
  };
  expect(liveJson.oauthAccount?.emailAddress).toBe("victim@example.com");
});

test("--live-default overrides the guard deliberately", async () => {
  makeProfile("alpha", "alpha@example.com");
  makeBusyProfile("busy", "busy@example.com");
  seedLiveDefault("victim@example.com");

  const result = await switchAccount("alpha", { env: {}, liveDefault: true });

  expect(result.dirKind).toBe("live-default");
  expect(loadStore().applied.claude).toBe("alpha");
});

test("a set CLAUDE_CONFIG_DIR pointing at the live default is explicit and never guarded", async () => {
  makeProfile("alpha", "alpha@example.com");
  makeBusyProfile("busy", "busy@example.com");
  seedLiveDefault("victim@example.com");

  const result = await switchAccount("alpha", { env: { CLAUDE_CONFIG_DIR: join(liveBase, ".claude") } });

  expect(result.dirKind).toBe("live-default");
  expect(loadStore().applied.claude).toBe("alpha");
});

test("an explicit --dir at the live default is unchanged and never guarded", async () => {
  makeProfile("alpha", "alpha@example.com");
  makeBusyProfile("busy", "busy@example.com");
  seedLiveDefault("victim@example.com");

  const result = await switchAccount("alpha", { dir: join(liveBase, ".claude"), env: {} });

  expect(result.dirKind).toBe("live-default");
  expect(loadStore().applied.claude).toBe("alpha");
});

test("fallthrough with NO live profile-dir sessions proceeds without the flag (existing behavior kept)", async () => {
  makeProfile("alpha", "alpha@example.com");
  makeProfile("idle", "idle@example.com");
  seedLiveDefault("victim@example.com");

  const result = await switchAccount("alpha", { env: {} });

  expect(result.dirKind).toBe("live-default");
  expect(loadStore().applied.claude).toBe("alpha");
});
