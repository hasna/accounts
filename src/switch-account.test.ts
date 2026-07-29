import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, updateProfile } from "./lib/profiles.js";
import {
  ensureProfileAuthSnapshot,
  restoreClaudeAuthIntoDir,
  writeSwitchedAccountMarker,
} from "./lib/claude-auth.js";
import { profileEnv } from "./lib/env.js";
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

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env },
  });
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

test("switch-account CLI projects JSON and human output through the public switch DTO", () => {
  const targetDir = makeProfile("safe-target", { email: "target-secret@example.com" });
  updateProfile("safe-target", {
    cardLast4: "4242",
    metadata: { private: "profile-metadata-secret" },
  });

  const jsonDir = mkdtempSync(join(tmpdir(), "swa-json-secret-"));
  writeIdentity(jsonDir, { email: "previous-json-secret@example.com" });
  const json = runCli(
    "switch-account",
    "safe-target",
    "--dir",
    jsonDir,
    "--allow-unregistered-dir",
    "--json",
  );

  expect(json.status).toBe(0);
  expect(JSON.parse(json.stdout)).toEqual({
    schema: "hasna.accounts.switch-output/v1",
    profile: { name: "safe-target", tool: "claude" },
    tool: { id: "claude", label: "Claude Code" },
    applied: false,
    active: true,
    command: [],
    commandLine: "",
    restartRequired: false,
    message: "safe-target is now the active Claude Code profile",
  });
  for (const secret of [
    "target-secret@example.com",
    "previous-json-secret@example.com",
    "4242",
    "profile-metadata-secret",
    targetDir,
    jsonDir,
  ]) {
    expect(json.stdout).not.toContain(secret);
  }

  const humanDir = mkdtempSync(join(tmpdir(), "swa-human-secret-"));
  writeIdentity(humanDir, { email: "previous-human-secret@example.com" });
  const human = runCli(
    "switch-account",
    "safe-target",
    "--dir",
    humanDir,
    "--allow-unregistered-dir",
  );

  expect(human.status).toBe(0);
  expect(human.stdout).toContain("safe-target is now the active Claude Code profile");
  expect(human.stdout).toContain("verify: the session's next reply runs as the new account");
  for (const secret of [
    "target-secret@example.com",
    "previous-human-secret@example.com",
    "4242",
    "profile-metadata-secret",
    targetDir,
    humanDir,
  ]) {
    expect(human.stdout).not.toContain(secret);
  }

  rmSync(jsonDir, { recursive: true, force: true });
  rmSync(humanDir, { recursive: true, force: true });
  rmSync(targetDir, { recursive: true, force: true });
});

// --- 63e642c1: aged-out access token vs genuinely dead credential ------------
//
// These two tests are a matched pair and must stay one. The first proves the
// refusal still fires for a credential that cannot be recovered; the second
// proves it no longer fires for one that only needs a token refresh. Either
// alone is compatible with a broken fix — the first alone with the deadlock
// that locked five profiles out, the second alone with never checking expiry.

test("switchAccount rejects a profile whose credential has NO refresh token, loudly", async () => {
  makeProfile("dead", { email: "dead@example.com", expiresInMs: -60_000, refreshToken: null });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-session-"));
  writeIdentity(sessionDir, { email: "live@example.com" });
  await expect(
    switchAccount("dead", { dir: sessionDir, env: {}, allowUnregisteredDir: true }),
  ).rejects.toThrow(/expired/);
  // The session dir must be untouched by a failed switch.
  expect(dirEmail(sessionDir)).toBe("live@example.com");
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount accepts an aged-out access token when the refresh token is intact", async () => {
  // The shape that deadlocked the CLI: `login` refuses because the dir carries
  // another account and points at `switch-account`; `switch-account` refused
  // because the access token had aged out and pointed back at `login`. The
  // credential was never dead — its refresh token had weeks left.
  makeProfile("aged", { email: "aged@example.com", expiresInMs: -60_000 });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-aged-session-"));
  writeIdentity(sessionDir, { email: "live@example.com" });

  const result = await switchAccount("aged", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

  // The switch really happened — the dir now carries the target's account and
  // its credential bytes, not just an absence of an exception.
  expect(result.alreadyActive).toBe(false);
  expect(dirEmail(sessionDir)).toBe("aged@example.com");
  expect(dirAccessToken(sessionDir)).toBe("aged@example.com-access");
  // ...and it says so, rather than pretending the credential was healthy.
  expect(result.warnings.join(" ")).toMatch(/aged-out access token/);
  rmSync(sessionDir, { recursive: true, force: true });
});

test("switchAccount rejects a profile with no credentials", async () => {
  const dir = mkdtempSync(join(tmpdir(), "swa-nocred-"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "x@example.com" } }));
  addProfile({ name: "nocred", dir });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-session2-"));
  writeIdentity(sessionDir, { email: "live@example.com" });
  await expect(
    switchAccount("nocred", { dir: sessionDir, env: {}, allowUnregisteredDir: true }),
  ).rejects.toThrow(AccountsError);
  rmSync(sessionDir, { recursive: true, force: true });
});

// --- 9a069a85: the destination is an allowlist, not the caller's argument ----

test("switchAccount refuses to write credentials into an unregistered dir", async () => {
  // The reviewer's exploit shape: a directory holding only a planted
  // `.claude.json`, never registered with `accounts add`. Before the guard,
  // `accounts usage-hook --dir <that path>` would rank the OTHER accounts, pick
  // the healthiest, and write its real access and refresh tokens here.
  makeProfile("healthy", { email: "healthy@example.com" });
  const planted = mkdtempSync(join(tmpdir(), "swa-planted-"));
  writeFileSync(
    join(planted, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "planted-uuid-0000", emailAddress: "stranger@example.com" } }),
  );

  await expect(switchAccount("healthy", { dir: planted, env: {} })).rejects.toThrow(
    /not a registered profile dir/,
  );
  // The absence claim that matters: no credential material landed.
  expect(existsSync(join(planted, ".credentials.json"))).toBe(false);
  rmSync(planted, { recursive: true, force: true });
});

test("POSITIVE CONTROL: the same call with the override DOES write the credential", async () => {
  // Without this, the test above proves nothing — an assertion that no file
  // appeared is worthless unless the identical input can make one appear.
  makeProfile("healthy", { email: "healthy@example.com" });
  const planted = mkdtempSync(join(tmpdir(), "swa-planted-ctrl-"));
  writeFileSync(
    join(planted, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: "planted-uuid-0000", emailAddress: "stranger@example.com" } }),
  );

  const result = await switchAccount("healthy", { dir: planted, env: {}, allowUnregisteredDir: true });

  expect(result.dirKind).toBe("external");
  expect(existsSync(join(planted, ".credentials.json"))).toBe(true);
  expect(dirAccessToken(planted)).toBe("healthy@example.com-access");
  rmSync(planted, { recursive: true, force: true });
});

test("a registered profile dir needs no override — the allowlist refuses nothing in use", async () => {
  // Every live CLAUDE_CONFIG_DIR on this fleet is a registered managed profile
  // dir, so this is the shape production actually runs in.
  makeProfile("alpha", { email: "alpha@example.com" });
  const betaDir = makeProfile("beta", { email: "beta@example.com" });

  const result = await switchAccount("alpha", { dir: betaDir, env: {} });

  expect(result.dirKind).toBe("profile-dir");
  expect(dirEmail(betaDir)).toBe("alpha@example.com");
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

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

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
  // Beta's own profile dir must be untouched by handing its auth to a session.
  expect(dirAccessToken(betaDir)).toBe("beta@example.com-access");
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

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

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

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

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
    await expect(
      switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true }),
    ).rejects.toThrow(/live session/);
    expect(dirEmail(sessionDir)).toBe("solo@example.com");

    const result = await switchAccount("beta", {
      dir: sessionDir,
      env: {},
      yes: true,
      allowUnregisteredDir: true,
    });
    expect(result.liveSessions).toBe(2);
    expect(dirEmail(sessionDir)).toBe("beta@example.com");
  } finally {
    helper.kill();
    rmSync(sessionDir, { recursive: true, force: true });
  }
});

// --- review fixes (PR #39 adversarial pass) ---------------------------------

test("owner detection prefers an agreeing marker over ambiguous email matches", async () => {
  makeProfile("dup1", { email: "shared@example.com" });
  const dup2Dir = makeProfile("dup2", { email: "shared@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-marker-owner-"));
  writeIdentity(sessionDir, { email: "shared@example.com" });
  // A previous in-place switch recorded that dup2's account lives here; the
  // email alone is ambiguous (dup1/dup2), the marker is not.
  writeSwitchedAccountMarker(sessionDir, { profile: "dup2", email: "shared@example.com" });

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

  expect(result.snapshotBackProfile).toBe("dup2");
  const snap = readJson(profileCredentialsSnapshot(dup2Dir)) as { claudeAiOauth?: { accessToken?: string } };
  expect(snap.claudeAiOauth?.accessToken).toBe("shared@example.com-access");
  rmSync(sessionDir, { recursive: true, force: true });
});

test("a marker contradicted by the dir's live email is stale and is cleared", () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  // Simulate: dir switched to beta, then the user ran /login back to alpha
  // in-session — dir files are alpha's again (and fresher than the snapshot),
  // but the marker still claims beta.
  writeFileSync(
    join(alphaDir, ".credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        accessToken: "alpha@example.com-FRESH-LOGIN",
        refreshToken: "alpha@example.com-refresh-FRESH",
        expiresAt: Date.now() + 300_000,
      },
    }),
  );
  const future = new Date(Date.now() + 15_000);
  utimesSync(join(alphaDir, ".credentials.json"), future, future);
  writeSwitchedAccountMarker(alphaDir, { profile: "beta", email: "beta@example.com" });

  ensureProfileAuthSnapshot(alphaDir, tool());

  expect(existsSync(profileSwitchedAccountMarker(alphaDir))).toBe(false);
  const snap = readJson(profileCredentialsSnapshot(alphaDir)) as { claudeAiOauth?: { accessToken?: string } };
  expect(snap.claudeAiOauth?.accessToken).toBe("alpha@example.com-FRESH-LOGIN");
});

test("profileEnv self-heals a switched-away profile dir with no live sessions", async () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  await switchAccount("beta", { dir: alphaDir, env: {} });
  expect(dirEmail(alphaDir)).toBe("beta@example.com");

  const { getProfile } = await import("./lib/profiles.js");
  profileEnv(getProfile("alpha", "claude"), tool());

  // Launching alpha must run ALPHA's account again, not beta's leftovers.
  expect(dirEmail(alphaDir)).toBe("alpha@example.com");
  expect(dirAccessToken(alphaDir)).toBe("alpha@example.com-access");
  expect(existsSync(profileSwitchedAccountMarker(alphaDir))).toBe(false);
});

test("profileEnv refuses to heal while a live session still runs on the dir", async () => {
  const alphaDir = makeProfile("alpha", { email: "alpha@example.com" });
  makeProfile("beta", { email: "beta@example.com" });
  await switchAccount("beta", { dir: alphaDir, env: {} });
  mkdirSync(join(alphaDir, "sessions"), { recursive: true });
  writeFileSync(join(alphaDir, "sessions", `${process.pid}.json`), JSON.stringify({ pid: process.pid }));

  const { getProfile } = await import("./lib/profiles.js");
  expect(() => profileEnv(getProfile("alpha", "claude"), tool())).toThrow(/live session/);
  // The running session's identity must not be yanked out from under it.
  expect(dirEmail(alphaDir)).toBe("beta@example.com");
});

test("restoreClaudeAuthIntoDir validates every write path before mutating anything", () => {
  const betaDir = makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-symlink-"));
  writeIdentity(sessionDir, { email: "alpha@example.com" });
  const outside = mkdtempSync(join(tmpdir(), "swa-outside-"));
  writeFileSync(join(outside, "creds.json"), "{}");
  rmSync(join(sessionDir, ".credentials.json"));
  symlinkSync(join(outside, "creds.json"), join(sessionDir, ".credentials.json"));

  expect(() => restoreClaudeAuthIntoDir(betaDir, tool(), sessionDir, "beta")).toThrow(AccountsError);
  // The account file must be untouched when the credential write is refused.
  expect(dirEmail(sessionDir)).toBe("alpha@example.com");
  rmSync(sessionDir, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

test("switchAccount refuses a home/base directory as the config dir", async () => {
  makeProfile("beta", { email: "beta@example.com" });
  await expect(switchAccount("beta", { dir: liveBase, env: {} })).rejects.toThrow(/config dir/);
});

test("a failed switch leaves no agreeing marker behind (fail-safe ordering)", async () => {
  makeProfile("beta", { email: "beta@example.com" });
  const sessionDir = mkdtempSync(join(tmpdir(), "swa-failsafe-"));
  writeIdentity(sessionDir, { email: "alpha-solo@example.com" });
  const outside = mkdtempSync(join(tmpdir(), "swa-out2-"));
  writeFileSync(join(outside, "creds.json"), "{}");
  rmSync(join(sessionDir, ".credentials.json"));
  symlinkSync(join(outside, "creds.json"), join(sessionDir, ".credentials.json"));

  await expect(
    switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true }),
  ).rejects.toThrow(AccountsError);
  // The dir keeps its old identity, so any marker left behind must NOT agree
  // with the dir email — otherwise later snapshot refreshes would freeze or
  // mis-attribute the dir's real credentials.
  const marker = existsSync(profileSwitchedAccountMarker(sessionDir))
    ? (readJson(profileSwitchedAccountMarker(sessionDir)) as { email?: string })
    : undefined;
  expect(marker?.email === dirEmail(sessionDir)).toBe(false);
  rmSync(sessionDir, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});
