import { test, expect, beforeEach, afterEach } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, useProfile, renameProfile, removeProfile, currentProfile } from "./lib/profiles.js";
import { applyProfile, appliedProfile } from "./lib/apply.js";
import { importProfile, ensureProfileForLogin } from "./lib/import-profile.js";
import { finalizeLogin } from "./lib/login.js";
import {
  ensureProfileAuthSnapshot,
  hasAuthSnapshot,
  profileHasAuth,
} from "./lib/claude-auth.js";
import { liveClaudePaths, profileOAuthSnapshot } from "./lib/claude-layout.js";
import { installHook, hookPath, hookScript, isSafeProfileName } from "./lib/hook.js";
import { resolvePickMode } from "./lib/pick.js";
import { switchProfile } from "./lib/switch.js";
import { loadStore } from "./storage.js";
import { getTool } from "./lib/tools.js";
import { AccountsError } from "./types.js";

let home: string;
let liveBase: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-test-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-live-"));
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

function writeOAuth(dir: string, email: string) {
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }));
}

test("import snapshots oauth from profile dir not live", () => {
  const importDir = mkdtempSync(join(tmpdir(), "import-src-"));
  writeOAuth(importDir, "import@example.com");
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "live@wrong.com" } }));

  const p = importProfile({ name: "imp", dir: importDir, email: "import@example.com" });
  const snap = JSON.parse(readFileSync(profileOAuthSnapshot(p.dir), "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(snap.oauthAccount.emailAddress).toBe("import@example.com");
  rmSync(importDir, { recursive: true, force: true });
});

test("apply rejects profile without auth", () => {
  const emptyDir = mkdtempSync(join(tmpdir(), "empty-"));
  mkdirSync(emptyDir, { recursive: true });
  addProfile({ name: "empty", dir: emptyDir });
  expect(() => applyProfile("empty")).toThrow(AccountsError);
  rmSync(emptyDir, { recursive: true, force: true });
});

test("apply does not wipe live oauth when profile empty", () => {
  const emptyDir = mkdtempSync(join(tmpdir(), "empty2-"));
  mkdirSync(emptyDir, { recursive: true });
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "keep@example.com" } }));
  addProfile({ name: "empty2", dir: emptyDir });
  expect(() => applyProfile("empty2")).toThrow(AccountsError);
  const live = JSON.parse(readFileSync(join(liveBase, ".claude.json"), "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(live.oauthAccount.emailAddress).toBe("keep@example.com");
  rmSync(emptyDir, { recursive: true, force: true });
});

test("apply snapshots live oauth to previous profile when switching", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-snap-"));
  const personalDir = mkdtempSync(join(tmpdir(), "personal-snap-"));
  writeOAuth(workDir, "work@example.com");
  writeOAuth(personalDir, "personal@example.com");
  addProfile({ name: "work", dir: workDir });
  addProfile({ name: "personal", dir: personalDir });
  const tool = getTool("claude");
  ensureProfileAuthSnapshot(workDir, tool);
  ensureProfileAuthSnapshot(personalDir, tool);
  applyProfile("work");
  applyProfile("personal");
  const snap = JSON.parse(readFileSync(profileOAuthSnapshot(workDir), "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(snap.oauthAccount.emailAddress).toBe("work@example.com");
  const live = JSON.parse(readFileSync(join(liveBase, ".claude.json"), "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(live.oauthAccount.emailAddress).toBe("personal@example.com");
  rmSync(workDir, { recursive: true, force: true });
  rmSync(personalDir, { recursive: true, force: true });
});

test("apply sets applied and active pointers", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-ptr-"));
  writeOAuth(workDir, "work@example.com");
  addProfile({ name: "work", dir: workDir });
  ensureProfileAuthSnapshot(workDir, getTool("claude"));
  const { previous } = applyProfile("work");
  expect(previous).toBeUndefined();
  expect(appliedProfile("claude")?.name).toBe("work");
  expect(currentProfile("claude")?.name).toBe("work");
  rmSync(workDir, { recursive: true, force: true });
});

test("import --copy creates managed dir with auth snapshot", () => {
  const importDir = mkdtempSync(join(tmpdir(), "import-copy-"));
  writeOAuth(importDir, "copy@example.com");
  const p = importProfile({ name: "copied", dir: importDir, copy: true });
  expect(p.dir.startsWith(home)).toBe(true);
  expect(hasAuthSnapshot(p.dir)).toBe(true);
  expect(profileHasAuth(p.dir, getTool("claude"))).toBe(true);
  rmSync(importDir, { recursive: true, force: true });
});

test("ensureProfileForLogin creates profile when missing", () => {
  const p = ensureProfileForLogin("newlogin");
  expect(p.name).toBe("newlogin");
  expect(p.tool).toBe("claude");
  expect(existsSync(p.dir)).toBe(true);
  expect(ensureProfileForLogin("newlogin").dir).toBe(p.dir);
});

test("applyProfile writes oauth to live paths", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-"));
  writeOAuth(workDir, "work@example.com");
  addProfile({ name: "work", dir: workDir });
  ensureProfileAuthSnapshot(workDir, getTool("claude"));
  applyProfile("work");
  const live = liveClaudePaths();
  const liveJson = JSON.parse(readFileSync(live.homeJson, "utf8")) as { oauthAccount: { emailAddress: string } };
  expect(liveJson.oauthAccount.emailAddress).toBe("work@example.com");
  rmSync(workDir, { recursive: true, force: true });
});

test("finalizeLogin snapshots and applies a Claude login automatically", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-login-"));
  addProfile({ name: "work", dir: workDir });
  writeOAuth(workDir, "work@example.com");

  const result = finalizeLogin("work", "claude");

  expect(result.applied).toBe(true);
  expect(appliedProfile("claude")?.name).toBe("work");
  expect(currentProfile("claude")?.name).toBe("work");
  const live = JSON.parse(readFileSync(liveClaudePaths().homeJson, "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(live.oauthAccount.emailAddress).toBe("work@example.com");
  rmSync(workDir, { recursive: true, force: true });
});

test("finalizeLogin refreshes a stale auth snapshot from the profile dir", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-login-refresh-"));
  writeOAuth(workDir, "old@example.com");
  addProfile({ name: "work", dir: workDir });
  ensureProfileAuthSnapshot(workDir, getTool("claude"));
  writeOAuth(workDir, "new@example.com");

  finalizeLogin("work", "claude");

  const snap = JSON.parse(readFileSync(profileOAuthSnapshot(workDir), "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(snap.oauthAccount.emailAddress).toBe("new@example.com");
  const live = JSON.parse(readFileSync(liveClaudePaths().homeJson, "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(live.oauthAccount.emailAddress).toBe("new@example.com");
  rmSync(workDir, { recursive: true, force: true });
});

test("rename and remove keep applied pointer coherent", () => {
  const workDir = mkdtempSync(join(tmpdir(), "work-"));
  writeOAuth(workDir, "work@example.com");
  addProfile({ name: "work", dir: workDir });
  ensureProfileAuthSnapshot(workDir, getTool("claude"));
  applyProfile("work");
  renameProfile("work", "job");
  expect(appliedProfile("claude")?.name).toBe("job");
  removeProfile("job");
  expect(appliedProfile("claude")).toBeUndefined();
  rmSync(workDir, { recursive: true, force: true });
});

test("duplicate config dir rejected", () => {
  const dir = mkdtempSync(join(tmpdir(), "dup-"));
  addProfile({ name: "a", dir });
  expect(() => addProfile({ name: "b", dir })).toThrow(AccountsError);
  rmSync(dir, { recursive: true, force: true });
});

test("store rejects tampered profile names on load", () => {
  addProfile({ name: "ok" });
  const storePath = join(home, "accounts.json");
  const raw = JSON.parse(readFileSync(storePath, "utf8")) as { profiles: { name: string }[] };
  raw.profiles[0]!.name = 'bad"; touch /tmp/pwned "';
  writeFileSync(storePath, JSON.stringify(raw));
  expect(() => loadStore()).toThrow(AccountsError);
});

test("isSafeProfileName rejects injection patterns", () => {
  expect(isSafeProfileName("work")).toBe(true);
  expect(isSafeProfileName('x"; evil')).toBe(false);
});

test("hook install writes script with name validation", () => {
  const { path, created } = installHook();
  expect(created).toBe(true);
  expect(path).toBe(hookPath());
  expect(hookScript()).toContain("accounts apply");
  expect(hookScript()).toContain("=~ ^[a-z0-9][a-z0-9-]*$");
});

test("resolvePickMode maps Commander --no-act to none", () => {
  expect(resolvePickMode({ act: false })).toBe("none");
  expect(resolvePickMode({ env: true })).toBe("env");
  expect(resolvePickMode({})).toBe("apply");
});

test("switchProfile applies Claude and returns a continue handoff command", () => {
  const dir = mkdtempSync(join(tmpdir(), "switch-claude-"));
  writeOAuth(dir, "switch@example.com");
  addProfile({ name: "switcher", dir });
  ensureProfileAuthSnapshot(dir, getTool("claude"));

  const result = switchProfile("switcher", { tool: "claude", resume: true });

  expect(result.applied).toBe(true);
  expect(result.restartRequired).toBe(true);
  expect(result.command).toEqual(["claude", "--continue"]);
  expect(result.commandLine).toContain("CLAUDE_CONFIG_DIR=");
  expect(appliedProfile("claude")?.name).toBe("switcher");
  const live = JSON.parse(readFileSync(liveClaudePaths().homeJson, "utf8")) as {
    oauthAccount: { emailAddress: string };
  };
  expect(live.oauthAccount.emailAddress).toBe("switch@example.com");
  rmSync(dir, { recursive: true, force: true });
});

test("switchProfile marks Codex active and returns resume command without applying live auth", () => {
  const p = addProfile({ name: "codexer", tool: "codex" });

  const result = switchProfile("codexer", { tool: "codex", resume: true });

  expect(result.applied).toBe(false);
  expect(result.command).toEqual(["codex", "resume", "--last"]);
  expect(result.env.CODEX_HOME).toBe(p.dir);
  expect(currentProfile("codex")?.name).toBe("codexer");
  expect(appliedProfile("codex")).toBeUndefined();
});
