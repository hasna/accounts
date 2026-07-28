import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import {
  profileCredentialsSnapshot,
  profileOAuthSnapshot,
  profileSwitchedAccountMarker,
} from "./lib/claude-layout.js";
import {
  listDirLiveSessions,
  resolveSessionConfigDir,
  switchAccount,
} from "./lib/switch-account.js";
import { loadStore } from "./storage.js";
import { getTool } from "./lib/tools.js";
import { AccountsError } from "./types.js";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-swa-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-swa-live-"));
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

interface CredentialFixture {
  email: string;
  expiresInMs?: number;
  refreshToken?: string | null;
}

function credentialJson(fixture: CredentialFixture): string {
  const { email, expiresInMs = 60_000, refreshToken = `${email}-refresh` } = fixture;
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${email}-access`,
      ...(refreshToken === null ? {} : { refreshToken }),
      expiresAt: Date.now() + expiresInMs,
    },
  });
}

function writeIdentity(dir: string, fixture: CredentialFixture): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: fixture.email } }));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(fixture));
}

function makeProfile(name: string, fixture: CredentialFixture): string {
  const dir = mkdtempSync(join(tmpdir(), `swa-${name}-`));
  writeIdentity(dir, fixture);
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

function dirEmail(dir: string): string {
  const data = readJson(join(dir, ".claude.json")) as { oauthAccount?: { emailAddress?: string } };
  return data.oauthAccount?.emailAddress ?? "";
}

function dirAccessToken(dir: string): string {
  const data = readJson(join(dir, ".credentials.json")) as { claudeAiOauth?: { accessToken?: string } };
  return data.claudeAiOauth?.accessToken ?? "";
}

// --- resolveSessionConfigDir -------------------------------------------------

test("resolveSessionConfigDir prefers explicit dir over env and live default", () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-dir-"));
  const resolved = resolveSessionConfigDir(tool(), {
    dir,
    env: { CLAUDE_CONFIG_DIR: "/nope/from-env" },
  });
  expect(resolved).toBe(dir);
  rmSync(dir, { recursive: true, force: true });
});

test("resolveSessionConfigDir reads the tool env var when no dir is given", () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-envdir-"));
  const resolved = resolveSessionConfigDir(tool(), { env: { CLAUDE_CONFIG_DIR: dir } });
  expect(resolved).toBe(dir);
  rmSync(dir, { recursive: true, force: true });
});

test("resolveSessionConfigDir falls back to the live default config dir", () => {
  const resolved = resolveSessionConfigDir(tool(), { env: {} });
  expect(resolved).toBe(join(liveBase, ".claude"));
});

// --- listDirLiveSessions -----------------------------------------------------

test("listDirLiveSessions reports live and dead pid files", () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-sess-"));
  mkdirSync(join(dir, "sessions"), { recursive: true });
  let deadPid = 4_100_000;
  while (true) {
    try {
      process.kill(deadPid, 0);
      deadPid -= 7;
    } catch {
      break;
    }
  }
  writeFileSync(join(dir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
  writeFileSync(join(dir, "sessions", `${deadPid}.json`), JSON.stringify({ pid: deadPid }));
  const sessions = listDirLiveSessions(dir);
  expect(sessions.find((s) => s.pid === process.pid)?.alive).toBe(true);
  expect(sessions.find((s) => s.pid === deadPid)?.alive).toBe(false);
  rmSync(dir, { recursive: true, force: true });
});

test("listDirLiveSessions returns empty for a dir without session files", () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-nosess-"));
  expect(listDirLiveSessions(dir)).toEqual([]);
  rmSync(dir, { recursive: true, force: true });
});

// --- validation --------------------------------------------------------------

test("switchAccount rejects an unknown profile", async () => {
  await expect(switchAccount("ghost", { env: {} })).rejects.toThrow(AccountsError);
});

test("switchAccount rejects a profile with expired credentials, loudly", async () => {
  makeProfile("dead", { email: "dead@example.com", expiresInMs: -60_000 });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-session-"));
  writeIdentity(sessionDir, { email: "live@example.com" });
  await expect(switchAccount("dead", { dir: sessionDir, env: {} })).rejects.toThrow(/expired/);
  // The session dir must be untouched by a failed switch.
  expect(dirEmail(sessionDir)).toBe("live@example.com");
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount rejects a profile with no credentials", async () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-nocred-"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "x@example.com" } }));
  addProfile({ name: "nocred", dir });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-session2-"));
  writeIdentity(sessionDir, { email: "live@example.com" });
  await expect(switchAccount("nocred", { dir: sessionDir, env: {} })).rejects.toThrow(AccountsError);
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount rejects non-claude tools", async () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-codex-"));
  mkdirSync(dir, { recursive: true });
  addProfile({ name: "cdx", dir, tool: "codex" });
  await expect(switchAccount("cdx", { tool: "codex", env: {} })).rejects.toThrow(/Claude Code/);
});

// --- session-dir switching ---------------------------------------------------

test("switchAccount swaps credentials and oauthAccount into the session dir", async () => {
  makeProfile("alpha", { email: "alpha@example.com" });
  const betaDir = makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-live-session-"));
  writeIdentity(sessionDir, { email: "alpha@example.com" });
  // Unrelated session state must survive the switch.
  const claudeJson = readJson(join(sessionDir, ".claude.json"));
  claudeJson.projects = { "/tmp/somewhere": { history: ["hello"] } };
  writeFileSync(join(sessionDir, ".claude.json"), JSON.stringify(claudeJson));

  const result = await switchAccount("beta", { dir: sessionDir, env: {} });

  expect(result.restartRequired).toBe(false);
  expect(result.alreadyActive).toBe(false);
  expect(result.configDir).toBe(sessionDir);
  expect(result.previousEmail).toBe("alpha@example.com");
  expect(dirEmail(sessionDir)).toBe("beta@example.com");
  expect(dirAccessToken(sessionDir)).toBe("beta@example.com-access");
  const preserved = readJson(join(sessionDir, ".claude.json")) as { projects?: Record<string, unknown> };
  expect(preserved.projects).toEqual({ "/tmp/somewhere": { history: ["hello"] } });
  // Marker records whose account now lives in this dir.
  const marker = readJson(profileSwitchedAccountMarker(sessionDir)) as { profile?: string; email?: string };
  expect(marker.profile).toBe("beta");
  expect(marker.email).toBe("beta@example.com");
  // The registry's active profile follows the switch.
  expect(loadStore().current.claude).toBe("beta");
  expect(betaDir.length).toBeGreaterThan(0);
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount snapshots rotated credentials back to the owning profile", async () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-rotated-"));
  // The running session rotated alpha's tokens in place: the session dir holds
  // a NEWER credential than alpha's profile snapshot.
  writeIdentity(sessionDir, { email: "alpha@example.com" });
  writeFileSync(
    join(sessionDir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        accessToken: "alpha@example.com-ROTATED",
        refreshToken: "alpha@example.com-refresh-ROTATED",
        expiresAt: Date.now() + 120_000,
      },
    }),
  );

  const result = await switchAccount("beta", { dir: sessionDir, env: {} });

  expect(result.snapshotBackProfile).toBe("alpha");
  const snap = readJson(profileCredentialsSnapshot(alphaDir)) as { claudeAiOauth?: { accessToken?: string } };
  expect(snap.claudeAiOauth?.accessToken).toBe("alpha@example.com-ROTATED");
  const oauthSnap = readJson(profileOAuthSnapshot(alphaDir)) as { oauthAccount?: { emailAddress?: string } };
  expect(oauthSnap.oauthAccount?.emailAddress).toBe("alpha@example.com");
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount round-trips a profile's own dir via the marker", async () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  makeProfile("beta", { email: "beta@example.com" });

  // Session runs directly on alpha's profile dir (the `accounts launch` case).
  const toBeta = await switchAccount("beta", { dir: alphaDir, env: {} });
  expect(toBeta.dirKind).toBe("profile-dir");
  expect(dirEmail(alphaDir)).toBe("beta@example.com");
  expect(existsSync(profileSwitchedAccountMarker(alphaDir))).toBe(true);
  // Alpha's snapshot must still hold alpha's credentials, not beta's.
  const alphaSnap = readJson(profileCredentialsSnapshot(alphaDir)) as { claudeAiOauth?: { accessToken?: string } };
  expect(alphaSnap.claudeAiOauth?.accessToken).toBe("alpha@example.com-access");

  // While switched, snapshot refresh must NOT contaminate alpha's snapshot.
  ensureProfileAuthSnapshot(alphaDir, tool());
  const alphaSnapAfter = readJson(profileCredentialsSnapshot(alphaDir)) as { claudeAiOauth?: { accessToken?: string } };
  expect(alphaSnapAfter.claudeAiOauth?.accessToken).toBe("alpha@example.com-access");

  // Switching back to alpha restores its own auth and clears the marker.
  const back = await switchAccount("alpha", { dir: alphaDir, env: {} });
  expect(back.alreadyActive).toBe(false);
  expect(dirEmail(alphaDir)).toBe("alpha@example.com");
  expect(dirAccessToken(alphaDir)).toBe("alpha@example.com-access");
  expect(existsSync(profileSwitchedAccountMarker(alphaDir))).toBe(false);
});

test("switchAccount is a guarded no-op when the target already owns the dir", async () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  const result = await switchAccount("alpha", { dir: alphaDir, env: {} });
  expect(result.alreadyActive).toBe(true);
  expect(dirEmail(alphaDir)).toBe("alpha@example.com");
});

test("switchAccount warns instead of snapshotting when the dir owner is ambiguous", async () => {
  makeProfile("dup1", { email: "shared@example.com" });
  makeProfile("dup2", { email: "shared@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-dup-"));
  writeIdentity(sessionDir, { email: "shared@example.com" });

  const result = await switchAccount("beta", { dir: sessionDir, env: {} });

  expect(result.snapshotBackProfile).toBeUndefined();
  expect(result.warnings.some((w) => w.includes("shared@example.com"))).toBe(true);
  expect(dirEmail(sessionDir)).toBe("beta@example.com");
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount routes the live default dir through apply semantics", async () => {
  makeProfile("alpha", { email: "alpha@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "alpha@example.com" } }));
  mkdirSync(join(liveBase, ".claude"), { recursive: true });
  writeFileSync(join(liveBase, ".claude", ".credentials.json"), credentialJson({ email: "alpha@example.com" }));

  const result = await switchAccount("beta", { env: {} });

  expect(result.dirKind).toBe("live-default");
  expect(result.restartRequired).toBe(false);
  expect(loadStore().applied.claude).toBe("beta");
  const liveCred = readJson(join(liveBase, ".claude", ".credentials.json")) as {
    claudeAiOauth?: { accessToken?: string };
  };
  expect(liveCred.claudeAiOauth?.accessToken).toBe("beta@example.com-access");
});

test("switchAccount refuses multiple live sessions without --yes", async () => {
  makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-many-"));
  writeIdentity(sessionDir, { email: "solo@example.com" });
  mkdirSync(join(sessionDir, "sessions"), { recursive: true });
  writeFileSync(join(sessionDir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));
  const helper = Bun.spawn(["sleep", "30"]);
  try {
    writeFileSync(join(sessionDir, "sessions", `${helper.pid}.json`), JSON.stringify({ pid: helper.pid }));
    await expect(switchAccount("beta", { dir: sessionDir, env: {} })).rejects.toThrow(/live session/);
    expect(dirEmail(sessionDir)).toBe("solo@example.com");

    const result = await switchAccount("beta", { dir: sessionDir, env: {}, yes: true });
    expect(result.liveSessions).toBe(2);
    expect(dirEmail(sessionDir)).toBe("beta@example.com");
  } finally {
    helper.kill();
    rmSync(sessionDir, { recursive: true, force: true });
  }
});
