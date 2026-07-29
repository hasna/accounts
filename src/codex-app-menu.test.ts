import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, currentProfile, useProfile } from "./lib/profiles.js";
import { saveStore } from "./storage.js";
import type { AccountsStore } from "./lib/store.js";
import {
  codexAppMenuState,
  codexAppMenuSwiftSource,
  switchCodexAppFromMenu,
  type CodexAppProcessRunner,
} from "./lib/codex-app-menu.js";

let home: string;
let previousStorageMode: string | undefined;

function apiProfile() {
  return {
    name: "desktop",
    tool: "codex-app",
    email: "desktop@example.com",
    dir: join(home, "remote-profile-dir"),
    createdAt: "2026-07-27T00:00:00.000Z",
  };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-menu-test-"));
  previousStorageMode = process.env.HASNA_ACCOUNTS_STORAGE_MODE;
  process.env.ACCOUNTS_HOME = home;
  process.env.HASNA_ACCOUNTS_STORAGE_MODE = "local";
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  if (previousStorageMode === undefined) delete process.env.HASNA_ACCOUNTS_STORAGE_MODE;
  else process.env.HASNA_ACCOUNTS_STORAGE_MODE = previousStorageMode;
});

test("codex app menu state lists profiles with active marker", async () => {
  addProfile({ name: "personal", tool: "codex-app", email: "personal@example.com" });
  addProfile({ name: "work", tool: "codex-app", displayName: "Work" });
  addProfile({ name: "cli", tool: "codex" });
  useProfile("work", "codex-app");

  const state = await codexAppMenuState();

  expect(state.tool.id).toBe("codex-app");
  expect(state.activeProfileName).toBe("work");
  expect(state.profiles.map((profile) => profile.name)).toEqual(["personal", "work"]);
  expect(state.profiles.find((profile) => profile.name === "work")?.active).toBe(true);
  expect(state.profiles.find((profile) => profile.name === "personal")?.active).toBe(false);
});

test("codex app menu state preserves applied marker for API-only profiles", async () => {
  const profile = apiProfile();
  saveStore({
    version: 1,
    current: {},
    applied: { "codex-app": "desktop" },
    toolLocks: {},
    profiles: [],
    tools: [],
  });
  const apiStore = {
    transport: "api",
    currentProfile: async () => profile,
    listProfiles: async () => [profile],
  } as AccountsStore;

  const state = await codexAppMenuState(apiStore);

  expect(state.activeProfileName).toBe("desktop");
  expect(state.appliedProfileName).toBe("desktop");
  expect(state.profiles).toHaveLength(1);
  expect(state.profiles[0]?.active).toBe(true);
  expect(state.profiles[0]?.applied).toBe(true);
});

test("codex app menu switch can update active profile without launching", async () => {
  addProfile({ name: "desktop", tool: "codex-app" });

  const result = await switchCodexAppFromMenu("desktop", { quit: false, launch: false });

  expect(result.quitAttempted).toBe(false);
  expect(result.launchStarted).toBe(false);
  expect(result.switch.profile.name).toBe("desktop");
  expect(result.launchCommand[0]).toBe("/Applications/Codex.app/Contents/MacOS/Codex");
  expect(currentProfile("codex-app")?.name).toBe("desktop");
});

test("codex app menu switch relaunches with isolated profile environment", async () => {
  const profile = addProfile({ name: "desktop", tool: "codex-app" });
  const calls: Array<{ command: string; args: string[]; env?: Record<string, string> }> = [];
  const runner: CodexAppProcessRunner = {
    spawnSync(command, args) {
      calls.push({ command, args });
      return { status: 0 };
    },
    spawn(command, args, opts) {
      calls.push({ command, args, env: opts?.env as Record<string, string> | undefined });
      return { unref() {} };
    },
  };

  const result = await switchCodexAppFromMenu("desktop", { quit: true, runner, relaunchDelayMs: 0 });

  expect(result.quitAttempted).toBe(true);
  expect(result.launchStarted).toBe(true);
  expect(calls.at(-1)?.command).toBe("/Applications/Codex.app/Contents/MacOS/Codex");
  expect(calls.at(-1)?.args).toEqual([`--user-data-dir=${join(profile.dir, "electron-user-data")}`]);
  expect(calls.at(-1)?.env?.CODEX_HOME).toBe(profile.dir);
});

test("swift source calls the codex app menu JSON commands", () => {
  const source = codexAppMenuSwiftSource("/opt/accounts");

  expect(source).toContain('let accountsCommand = "/opt/accounts"');
  expect(source).toContain('"codex-app", "menu-state", "--json"');
  expect(source).toContain('"codex-app", "menu-switch", name, "--json"');
});
