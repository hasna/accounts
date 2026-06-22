import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
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

test("codex app profile env forces existing root credentials store to file", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  writeFileSync(
    join(p.dir, "config.toml"),
    ['# existing Codex config', 'cli_auth_credentials_store = "keychain"', 'model = "gpt-5"', ""].join("\n"),
  );

  profileEnv(p, getTool("codex-app"));

  expect(readFileSync(join(p.dir, "config.toml"), "utf8")).toBe(
    ['# existing Codex config', 'cli_auth_credentials_store = "file"', 'model = "gpt-5"', ""].join("\n"),
  );
});

test("codex app profile env does not duplicate an existing root file credentials store", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  const comments = Array.from({ length: 12 }, (_, index) => `# imported config line ${index + 1}`);
  writeFileSync(
    join(p.dir, "config.toml"),
    [
      ...comments,
      'cli_auth_credentials_store = "file"',
      'model = "gpt-5"',
      'cli_auth_credentials_store = "file"',
      "",
      "[profiles.default]",
      'model = "gpt-5"',
      "",
    ].join("\n"),
  );

  profileEnv(p, getTool("codex-app"));

  const config = readFileSync(join(p.dir, "config.toml"), "utf8");
  const rootConfig = config.split("[profiles.default]")[0]!;
  expect(rootConfig.match(/^cli_auth_credentials_store\s*=/gm)).toEqual(['cli_auth_credentials_store =']);
  expect(config).toBe(
    [...comments, 'cli_auth_credentials_store = "file"', 'model = "gpt-5"', "", "[profiles.default]", 'model = "gpt-5"', ""].join(
      "\n",
    ),
  );
});

test("codex app profile env inserts a root credentials store before tables", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  writeFileSync(
    join(p.dir, "config.toml"),
    ['[profiles.default]', 'cli_auth_credentials_store = "keychain"', 'model = "gpt-5"', ""].join("\n"),
  );

  profileEnv(p, getTool("codex-app"));

  expect(readFileSync(join(p.dir, "config.toml"), "utf8")).toBe(
    [
      'cli_auth_credentials_store = "file"',
      "",
      "[profiles.default]",
      'cli_auth_credentials_store = "keychain"',
      'model = "gpt-5"',
      "",
    ].join("\n"),
  );
});

test("codex app profile env inserts a root credentials store before array tables", () => {
  const p = addProfile({ name: "desktop", tool: "codex-app" });
  writeFileSync(join(p.dir, "config.toml"), ['[[mcp_servers]]', 'command = "node"', ""].join("\n"));

  profileEnv(p, getTool("codex-app"));

  expect(readFileSync(join(p.dir, "config.toml"), "utf8")).toBe(
    ['cli_auth_credentials_store = "file"', "", "[[mcp_servers]]", 'command = "node"', ""].join("\n"),
  );
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

test("update rejects a config dir already used by another profile", () => {
  const first = addProfile({ name: "first" });
  const second = addProfile({ name: "second" });

  expect(() => updateProfile("second", { dir: first.dir })).toThrow(AccountsError);
  expect(getProfile("second").dir).toBe(second.dir);
  expect(() => updateProfile("second", { dir: `${first.dir}/` })).toThrow(AccountsError);
  expect(getProfile("second").dir).toBe(second.dir);
});

test("update rejects a config dir already stored with legacy path spelling", () => {
  const dir = join(home, "legacy-dir");
  const secondDir = join(home, "second-dir");
  saveStore({
    version: 1,
    current: {},
    applied: {},
    profiles: [
      { name: "first", tool: "claude", dir: `${dir}/`, createdAt: "2026-06-21T00:00:00.000Z" },
      { name: "second", tool: "claude", dir: secondDir, createdAt: "2026-06-21T00:00:00.000Z" },
    ],
    tools: [],
  });

  expect(() => updateProfile("second", { dir })).toThrow(AccountsError);
  expect(getProfile("second").dir).toBe(secondDir);
});

test("add and update reject symlink aliases for an existing config dir", () => {
  const first = addProfile({ name: "first" });
  const second = addProfile({ name: "second" });
  const link = join(home, "link-to-first");
  symlinkSync(first.dir, link, "dir");

  expect(() => addProfile({ name: "alias", dir: link })).toThrow(AccountsError);
  expect(() => updateProfile("second", { dir: link })).toThrow(AccountsError);
  expect(getProfile("second").dir).toBe(second.dir);
});

test("add and update preserve account metadata and identity links", () => {
  const p = addProfile({
    name: "work",
    email: "work@example.com",
    displayName: "Work Owner",
    identity: "agent:work-owner",
    cardLast4: "4242",
    metadata: { machine: "spark02", priority: 3, primary: true, note: null },
  });
  expect(p.displayName).toBe("Work Owner");
  expect(p.identity).toBe("agent:work-owner");
  expect(p.cardLast4).toBe("4242");
  expect(p.metadata).toEqual({ machine: "spark02", priority: 3, primary: true, note: null });

  const updated = updateProfile("work", {
    displayName: "Updated Owner",
    identity: "identity_abc123",
    metadata: { machine: "spark01", cardIssuer: "visa" },
  });
  expect(updated.displayName).toBe("Updated Owner");
  expect(updated.identity).toBe("identity_abc123");
  expect(updated.cardLast4).toBe("4242");
  expect(updated.metadata).toEqual({ machine: "spark01", priority: 3, primary: true, note: null, cardIssuer: "visa" });
});

test("card last4 must be exactly four digits", () => {
  expect(() => addProfile({ name: "bad", cardLast4: "123" })).toThrow(AccountsError);
  addProfile({ name: "work" });
  expect(() => updateProfile("work", { cardLast4: "12ab" })).toThrow(AccountsError);
});

test("display name and identity must not be empty", () => {
  expect(() => addProfile({ name: "bad", displayName: "" })).toThrow(AccountsError);
  addProfile({ name: "work" });
  expect(() => updateProfile("work", { displayName: "" })).toThrow(AccountsError);
  expect(() => updateProfile("work", { identity: " " })).toThrow(AccountsError);
  expect(loadStore().profiles[0]?.name).toBe("work");
});

test("metadata values and keys are validated", () => {
  expect(() => addProfile({ name: "bad", metadata: { "bad key": "value" } })).toThrow(AccountsError);
  expect(() => addProfile({ name: "proto", metadata: { ["__proto__"]: "value" } })).toThrow(AccountsError);
  expect(() => addProfile({ name: "ctor", metadata: { constructor: "value" } })).toThrow(AccountsError);
  expect(() => addProfile({ name: "nan", metadata: { score: Number.NaN } })).toThrow(AccountsError);
  expect(() => addProfile({ name: "inf", metadata: { score: Number.POSITIVE_INFINITY } })).toThrow(AccountsError);
  expect(() => addProfile({ name: "array", metadata: ["value"] as never })).toThrow(AccountsError);
  expect(() => addProfile({ name: "custom", metadata: Object.create({ inherited: "value" }) as never })).toThrow(AccountsError);
});

test("saveStore validates raw profile metadata and ownership fields", () => {
  const storeWith = (profile: Record<string, unknown>) =>
    ({
      version: 1,
      current: {},
      applied: {},
      profiles: [{ name: "work", tool: "claude", dir: join(home, "work"), createdAt: "2026-06-21T00:00:00.000Z", ...profile }],
      tools: [],
    }) as never;

  expect(() => saveStore(storeWith({ name: "BAD NAME" }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ displayName: " " }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ identity: "\t" }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ metadata: { score: Number.POSITIVE_INFINITY } }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ metadata: { "bad key": "value" } }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ metadata: { constructor: "value" } }))).toThrow(AccountsError);
  expect(() => saveStore(storeWith({ metadata: JSON.parse('{"__proto__":"value"}') }))).toThrow(AccountsError);
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

test("remove --purge refuses managed-dir prefix siblings", () => {
  const sibling = join(home, "profiles-evil");
  addProfile({ name: "sibling", dir: sibling });
  const res = removeProfile("sibling", true);
  expect(res.purged).toBe(false);
  expect(res.purgeNote).toBeDefined();
  expect(existsSync(sibling)).toBe(true);
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
