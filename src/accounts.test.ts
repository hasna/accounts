import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  addProfile,
  listProfiles,
  getProfile,
  findProfile,
  useProfile,
  currentProfile,
  renameProfile,
  updateProfile,
  removeProfile,
  redetectEmail,
} from "./lib/profiles.js";
import { loadStore, saveStore } from "./storage.js";
import { detectEmail } from "./lib/detect.js";
import {
  getTool,
  listTools,
  addCustomTool,
  removeCustomTool,
  isBuiltinTool,
  mergeToolArgs,
  normalizePermissionPreset,
  permissionArgsFor,
} from "./lib/tools.js";
import { formatExportLines, profileEnv } from "./lib/env.js";
import { AccountsError } from "./types.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

test("add creates a profile with a managed config dir", () => {
  const p = addProfile({ name: "work", email: "work@example.com" });
  expect(p.name).toBe("work");
  expect(p.tool).toBe("claude");
  expect(p.email).toBe("work@example.com");
  expect(existsSync(p.dir)).toBe(true);
  expect(p.dir.startsWith(home)).toBe(true);
});

test("add rejects duplicate names", () => {
  addProfile({ name: "work" });
  expect(() => addProfile({ name: "work" })).toThrow(AccountsError);
});

test("add rejects invalid names", () => {
  expect(() => addProfile({ name: "Work Space!" })).toThrow(AccountsError);
});

test("add rejects unknown tool", () => {
  expect(() => addProfile({ name: "x", tool: "nope" })).toThrow(AccountsError);
});

test("list and find", () => {
  addProfile({ name: "work" });
  addProfile({ name: "personal", tool: "codex" });
  expect(listProfiles().length).toBe(2);
  expect(listProfiles("codex").map((p) => p.name)).toEqual(["personal"]);
  expect(findProfile("work")?.name).toBe("work");
  expect(findProfile("ghost")).toBeUndefined();
});

test("built-in tools cover major coding agents", () => {
  const ids = listTools().map((t) => t.id);
  expect(ids).toContain("claude");
  expect(ids).toContain("codex");
  expect(ids).toContain("codex-app");
  expect(ids).toContain("takumi");
  expect(ids).toContain("gemini");
  expect(ids).toContain("opencode");
  expect(ids).toContain("cursor");
  expect(ids).toContain("pi");
  expect(ids).toContain("hermes");
  expect(ids).toContain("kimi");
  expect(ids).toContain("grok");
});

test("built-in tools expose tool-specific permission presets", () => {
  expect(permissionArgsFor(getTool("claude"), "dangerous")).toEqual(["--dangerously-skip-permissions"]);
  expect(permissionArgsFor(getTool("takumi"), "dangerously-skip-permissions")).toEqual(["--dangerously-skip-permissions"]);
  expect(permissionArgsFor(getTool("codex"), "dangerous")).toEqual(["--dangerously-bypass-approvals-and-sandbox"]);
  expect(permissionArgsFor(getTool("gemini"), "yolo")).toEqual(["--yolo"]);
  expect(permissionArgsFor(getTool("hermes"), "danger")).toEqual(["--yolo"]);
  expect(permissionArgsFor(getTool("kimi"), "auto")).toEqual(["--auto"]);
  expect(normalizePermissionPreset("bypassPermissions")).toBe("bypass");
});

test("mergeToolArgs prepends permission args without duplicating explicit flags", () => {
  const claude = getTool("claude");
  expect(mergeToolArgs(claude, ["--continue"], { permissions: "dangerous" })).toEqual([
    "--dangerously-skip-permissions",
    "--continue",
  ]);
  expect(mergeToolArgs(claude, ["--dangerously-skip-permissions"], { permissions: "dangerous" })).toEqual([
    "--dangerously-skip-permissions",
  ]);
  expect(mergeToolArgs(getTool("codex"), ["resume", "--last"], { permissions: "dangerous" })).toEqual([
    "--dangerously-bypass-approvals-and-sandbox",
    "resume",
    "--last",
  ]);
});

test("mergeToolArgs prepends templated launch args", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  expect(mergeToolArgs(getTool("codex-app"), [], { profile: p })).toEqual([
    `--user-data-dir=${join(p.dir, "electron-user-data")}`,
  ]);
});

test("unsupported permission preset fails clearly", () => {
  expect(() => permissionArgsFor(getTool("opencode"), "dangerous")).toThrow(AccountsError);
  expect(permissionArgsFor(getTool("opencode"), "none")).toEqual([]);
});

test("same profile name is allowed across tools and ambiguous without tool", () => {
  addProfile({ name: "work", tool: "claude" });
  addProfile({ name: "work", tool: "codex" });
  expect(() => getProfile("work")).toThrow(AccountsError);
  expect(getProfile("work", "codex").tool).toBe("codex");
  useProfile("work", "codex");
  expect(currentProfile("codex")?.name).toBe("work");
  expect(currentProfile("codex")?.tool).toBe("codex");
  expect(currentProfile("claude")).toBeUndefined();
});

test("profileEnv renders extra per-tool environment templates", () => {
  const p = addProfile({ name: "ops", tool: "opencode" });
  const env = profileEnv(p, getTool("opencode"));
  expect(env.OPENCODE_CONFIG_DIR).toBe(p.dir);
  expect(env.XDG_CONFIG_HOME).toBe(join(p.dir, "xdg-config"));
  expect(env.XDG_DATA_HOME).toBe(join(p.dir, "xdg-data"));
  expect(formatExportLines(env)).toContain("export OPENCODE_CONFIG_DIR=");
});

test("claude profile env isolates Telegram channel state", () => {
  const p = addProfile({ name: "telegram", tool: "claude" });
  const env = profileEnv(p, getTool("claude"));
  expect(env.CLAUDE_CONFIG_DIR).toBe(p.dir);
  expect(env.TELEGRAM_STATE_DIR).toBe(join(p.dir, "channels", "telegram"));
  expect(formatExportLines(env)).toContain("export TELEGRAM_STATE_DIR=");
});

test("codex app profile env isolates CODEX_HOME and file credentials", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  const env = profileEnv(p, getTool("codex-app"));
  expect(env.CODEX_HOME).toBe(p.dir);
  expect(readFileSync(join(p.dir, "config.toml"), "utf8")).toContain('cli_auth_credentials_store = "file"');
});

test("getProfile throws for missing", () => {
  expect(() => getProfile("ghost")).toThrow(AccountsError);
});

test("use sets the active profile per tool and bumps lastUsedAt", () => {
  addProfile({ name: "work" });
  addProfile({ name: "play", tool: "codex" });
  useProfile("work");
  expect(currentProfile("claude")?.name).toBe("work");
  expect(currentProfile("codex")).toBeUndefined();
  expect(getProfile("work").lastUsedAt).toBeDefined();
  useProfile("play");
  expect(currentProfile("codex")?.name).toBe("play");
});

test("rename updates the current pointer too", () => {
  addProfile({ name: "work" });
  useProfile("work");
  renameProfile("work", "job");
  expect(findProfile("work")).toBeUndefined();
  expect(currentProfile("claude")?.name).toBe("job");
});

test("rename rejects collisions", () => {
  addProfile({ name: "a" });
  addProfile({ name: "b" });
  expect(() => renameProfile("a", "b")).toThrow(AccountsError);
});

test("update sets email and description", () => {
  addProfile({ name: "work" });
  const p = updateProfile("work", { email: "new@example.com", description: "main" });
  expect(p.email).toBe("new@example.com");
  expect(p.description).toBe("main");
});

test("remove clears the current pointer", () => {
  addProfile({ name: "work" });
  useProfile("work");
  const { profile } = removeProfile("work");
  expect(profile.name).toBe("work");
  expect(currentProfile("claude")).toBeUndefined();
  expect(findProfile("work")).toBeUndefined();
});

test("remove --purge deletes a managed dir", () => {
  const p = addProfile({ name: "work" });
  expect(existsSync(p.dir)).toBe(true);
  const res = removeProfile("work", true);
  expect(res.purged).toBe(true);
  expect(existsSync(p.dir)).toBe(false);
});

test("remove --purge refuses to delete an unmanaged dir", () => {
  const external = mkdtempSync(join(tmpdir(), "ext-"));
  addProfile({ name: "ext", dir: external });
  const res = removeProfile("ext", true);
  expect(res.purged).toBe(false);
  expect(res.purgeNote).toBeDefined();
  expect(existsSync(external)).toBe(true);
  rmSync(external, { recursive: true, force: true });
});

test("detectEmail reads claude oauthAccount.emailAddress", () => {
  const dir = mkdtempSync(join(tmpdir(), "claudedir-"));
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "auto@example.com" } }));
  const email = detectEmail(dir, getTool("claude"));
  expect(email).toBe("auto@example.com");
  rmSync(dir, { recursive: true, force: true });
});

test("detectEmail falls back to the parent dir for the default config dir", () => {
  // Simulate the default Claude layout: ~/.claude/ (dir) + ~/.claude.json (home).
  const fakeHome = mkdtempSync(join(tmpdir(), "home-"));
  const defaultDir = join(fakeHome, ".claude");
  mkdirSync(defaultDir, { recursive: true });
  writeFileSync(join(fakeHome, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "parent@example.com" } }));
  const tool = {
    id: "claude",
    label: "Claude Code",
    envVar: "CLAUDE_CONFIG_DIR",
    defaultDir,
    bin: "claude",
    accountFile: ".claude.json",
    emailPath: ["oauthAccount", "emailAddress"],
  };
  expect(detectEmail(defaultDir, tool)).toBe("parent@example.com");
  rmSync(fakeHome, { recursive: true, force: true });
});

test("detectEmail returns undefined when absent", () => {
  const dir = mkdtempSync(join(tmpdir(), "claudedir-"));
  expect(detectEmail(dir, getTool("claude"))).toBeUndefined();
  rmSync(dir, { recursive: true, force: true });
});

test("add auto-detects email from an imported config dir", () => {
  const dir = mkdtempSync(join(tmpdir(), "imported-"));
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "detected@example.com" } }));
  const p = addProfile({ name: "imported", dir });
  expect(p.email).toBe("detected@example.com");
  rmSync(dir, { recursive: true, force: true });
});

test("redetect updates the email", () => {
  const dir = mkdtempSync(join(tmpdir(), "redetect-"));
  const p = addProfile({ name: "rd", dir });
  expect(p.email).toBeUndefined();
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "later@example.com" } }));
  expect(redetectEmail("rd").email).toBe("later@example.com");
  rmSync(dir, { recursive: true, force: true });
});

test("store persists across loads", () => {
  addProfile({ name: "work", email: "w@example.com" });
  useProfile("work");
  const store = loadStore();
  expect(store.profiles.length).toBe(1);
  expect(store.current.claude).toBe("work");
});

test("custom tools: register, use for a profile, and list", () => {
  addCustomTool({
    id: "windsurf",
    label: "Windsurf",
    envVar: "WINDSURF_HOME",
    defaultDir: "/tmp/.windsurf",
    bin: "windsurf",
    permissionArgs: { dangerous: ["--yolo"] },
  });
  expect(listTools().some((t) => t.id === "windsurf")).toBe(true);
  expect(isBuiltinTool("windsurf")).toBe(false);
  expect(getTool("windsurf").label).toBe("Windsurf");
  expect(permissionArgsFor(getTool("windsurf"), "dangerous")).toEqual(["--yolo"]);
  const p = addProfile({ name: "design", tool: "windsurf", email: "d@example.com" });
  expect(p.tool).toBe("windsurf");
});

test("custom tools: cannot redefine a built-in", () => {
  expect(() =>
    addCustomTool({ id: "claude", label: "X", envVar: "X_DIR", defaultDir: "/tmp/x", bin: "x" }),
  ).toThrow(AccountsError);
});

test("custom tools: invalid envVar is rejected", () => {
  expect(() =>
    addCustomTool({ id: "foo", label: "Foo", envVar: "bad-var", defaultDir: "/tmp/foo", bin: "foo" }),
  ).toThrow(AccountsError);
});

test("custom tools: cannot remove while in use, can after", () => {
  addCustomTool({ id: "windsurf", label: "Windsurf", envVar: "WINDSURF_HOME", defaultDir: "/tmp/.windsurf", bin: "windsurf" });
  addProfile({ name: "design", tool: "windsurf" });
  expect(() => removeCustomTool("windsurf")).toThrow(AccountsError);
  removeProfile("design");
  removeCustomTool("windsurf");
  expect(listTools().some((t) => t.id === "windsurf")).toBe(false);
});

test("custom tools: removing a built-in throws", () => {
  expect(() => removeCustomTool("claude")).toThrow(AccountsError);
});

test("remove clears applied pointer", () => {
  addProfile({ name: "work", email: "w@example.com" });
  useProfile("work");
  const store = loadStore();
  store.applied = { claude: "work" };
  saveStore(store);
  removeProfile("work");
  expect(loadStore().applied.claude).toBeUndefined();
});

test("rename updates applied pointer", () => {
  addProfile({ name: "work" });
  const store = loadStore();
  store.applied = { claude: "work" };
  saveStore(store);
  renameProfile("work", "job");
  expect(loadStore().applied.claude).toBe("job");
});

test("loadStore prunes stale current and applied pointers", () => {
  addProfile({ name: "work" });
  addProfile({ name: "codexprof", tool: "codex" });
  const store = loadStore();
  store.current = { claude: "ghost", codex: "codexprof" };
  store.applied = { claude: "ghost" };
  saveStore(store);
  const reloaded = loadStore();
  expect(reloaded.current.claude).toBeUndefined();
  expect(reloaded.applied.claude).toBeUndefined();
  expect(reloaded.current.codex).toBe("codexprof");
});

test("explicit dir is honored and created", () => {
  const dir = join(home, "custom", "spot");
  mkdirSync(join(home, "custom"), { recursive: true });
  const p = addProfile({ name: "c", dir });
  expect(p.dir).toBe(dir);
  expect(existsSync(dir)).toBe(true);
});
