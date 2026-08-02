import { test, expect, beforeEach, afterEach } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, purgeProfileDir, removeProfile } from "./lib/profiles.js";
import { addCustomTool, getTool } from "./lib/tools.js";
import { profileEnv } from "./lib/env.js";
import { switchProfile } from "./lib/switch.js";
import { importProfile } from "./lib/import-profile.js";
import { assertSafeWritePath } from "./lib/safe-path.js";
import { AccountsError } from "./types.js";
import {
  ensureSharedCapabilities,
  resetCapabilityBaseline,
  sharedCapabilityHealth,
  assertProfileGuarded,
  sharedConfigsFor,
  sharedHomeFor,
} from "./lib/shared-capabilities.js";

let home: string;
let sharedHome: string;

/** Two skills + one agent + one MCP server: enough to tell "shared" from "empty". */
function seedSharedCorpus(root: string): void {
  for (const name of ["alpha", "beta"]) {
    mkdirSync(join(root, "skills", name), { recursive: true });
    writeFileSync(join(root, "skills", name, "SKILL.md"), `---\nname: ${name}\ndescription: ${name}\n---\nbody\n`);
  }
  mkdirSync(join(root, "agents"), { recursive: true });
  writeFileSync(join(root, "agents", "reviewer.md"), "---\nname: reviewer\n---\nbody\n");
}

/** The predicate both purge tests share, so the positive control exercises the real detector. */
function corpusIntact(root: string): boolean {
  return (
    existsSync(join(root, "skills", "alpha", "SKILL.md")) && existsSync(join(root, "skills", "beta", "SKILL.md"))
  );
}

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-shared-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;

  sharedHome = join(home, "shared-claude");
  mkdirSync(sharedHome, { recursive: true });
  seedSharedCorpus(sharedHome);
  // `../.claude.json` relative to the shared home — the user-scope MCP file Claude
  // Code actually reads (measured on 2.1.220; settings.json/mcp.json are not read).
  writeFileSync(
    join(home, ".claude.json"),
    JSON.stringify({ numStartups: 3, mcpServers: { todos: { command: "todos-mcp" }, notes: { command: "notes-mcp" } } }, null, 2),
  );
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_SHARED_HOME_CLAUDE;
});

test("sharedHomeFor prefers the machine-local override over the tool default dir", () => {
  expect(sharedHomeFor(getTool("claude"))).toBe(sharedHome);
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = "";
  expect(sharedHomeFor(getTool("claude"))).toBe(getTool("claude").defaultDir);
});

test("addProfile materializes shared skills and agents at creation", () => {
  const p = addProfile({ name: "fresh" });
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
  expect(realpathSync(join(p.dir, "agents"))).toBe(realpathSync(join(sharedHome, "agents")));
  expect(lstatSync(join(p.dir, "skills")).isSymbolicLink()).toBe(true);
});

test("profileEnv repairs a profile created before shared capabilities existed", () => {
  // Simulate the 23 profiles already on disk: created while no shared home was known.
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "legacy" });
  expect(existsSync(join(p.dir, "skills"))).toBe(false);
  expect(existsSync(join(p.dir, "agents"))).toBe(false);

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const env = profileEnv(p, getTool("claude"));
  expect(env.CLAUDE_CONFIG_DIR).toBe(p.dir);
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
  expect(realpathSync(join(p.dir, "agents"))).toBe(realpathSync(join(sharedHome, "agents")));
});

test("ensureSharedCapabilities is idempotent", () => {
  const p = addProfile({ name: "twice" });
  const first = ensureSharedCapabilities(p.dir, getTool("claude"));
  const second = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(first.linked).toEqual([]);
  expect(first.kept).toEqual(["skills", "agents"]);
  expect(second.kept).toEqual(["skills", "agents"]);
  expect(second.errors).toEqual([]);
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
});

test("ensureSharedCapabilities never clobbers a real directory the profile already owns", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "owns" });
  mkdirSync(join(p.dir, "skills", "private"), { recursive: true });
  writeFileSync(join(p.dir, "skills", "private", "SKILL.md"), "local only\n");

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(lstatSync(join(p.dir, "skills")).isSymbolicLink()).toBe(false);
  expect(readFileSync(join(p.dir, "skills", "private", "SKILL.md"), "utf8")).toBe("local only\n");
  expect(result.skipped.map((s) => s.entry)).toContain("skills");
  // agents had nothing local, so it still gets shared
  expect(realpathSync(join(p.dir, "agents"))).toBe(realpathSync(join(sharedHome, "agents")));
});

test("ensureSharedCapabilities repairs a dangling link", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "dangling" });
  symlinkSync(join(home, "gone", "skills"), join(p.dir, "skills"));
  expect(existsSync(join(p.dir, "skills"))).toBe(false);
  expect(lstatSync(join(p.dir, "skills")).isSymbolicLink()).toBe(true);

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(result.repaired).toContain("skills");
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
});

test("ensureSharedCapabilities repairs a link pointing at the wrong corpus", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "wrong" });
  const otherCorpus = join(home, "other-claude");
  seedSharedCorpus(otherCorpus);
  symlinkSync(join(otherCorpus, "skills"), join(p.dir, "skills"));

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(result.repaired).toContain("skills");
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
});

test("a missing shared home leaves no dangling links and does not throw", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "nohome" });
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(result.errors).toEqual([]);
  expect(existsSync(join(p.dir, "skills"))).toBe(false);
  expect(lstatSync(p.dir).isDirectory()).toBe(true);
  // lstat must also report nothing at all — not even a broken link
  expect(() => lstatSync(join(p.dir, "skills"))).toThrow();
});

test("a profile whose dir IS the shared home is left alone", () => {
  const p = addProfile({ name: "self", dir: sharedHome });
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(result.linked).toEqual([]);
  expect(result.repaired).toEqual([]);
  expect(lstatSync(join(sharedHome, "skills")).isSymbolicLink()).toBe(false);
});

test("tools that declare no shared entries are untouched", () => {
  const p = addProfile({ name: "codexprofile", tool: "codex" });
  profileEnv(p, getTool("codex"));
  expect(existsSync(join(p.dir, "skills"))).toBe(false);
  expect(existsSync(join(p.dir, "agents"))).toBe(false);
});

test("shared MCP servers are seeded into the profile account file, not settings.json", () => {
  const p = addProfile({ name: "mcp" });
  const accountFile = join(p.dir, ".claude.json");
  const data = readJson(accountFile);
  expect(Object.keys(data.mcpServers as Record<string, unknown>).sort()).toEqual(["notes", "todos"]);
  // settings.json is not the file Claude Code reads user-scope MCP servers from.
  expect(existsSync(join(p.dir, "settings.json"))).toBe(false);
});

test("MCP seeding merges without clobbering profile-local state", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "merge" });
  writeFileSync(
    join(p.dir, ".claude.json"),
    JSON.stringify(
      {
        oauthAccount: { emailAddress: "merge@example.com" },
        mcpServers: { todos: { command: "profile-specific-todos" }, extra: { command: "extra-mcp" } },
      },
      null,
      2,
    ),
  );

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  ensureSharedCapabilities(p.dir, getTool("claude"));
  const data = readJson(join(p.dir, ".claude.json"));
  expect((data.oauthAccount as Record<string, string>).emailAddress).toBe("merge@example.com");
  const servers = data.mcpServers as Record<string, { command: string }>;
  expect(servers.todos!.command).toBe("profile-specific-todos");
  expect(servers.notes!.command).toBe("notes-mcp");
  expect(servers.extra!.command).toBe("extra-mcp");
});

test("MCP seeding does not rewrite the account file when nothing changes", () => {
  const p = addProfile({ name: "stable" });
  const accountFile = join(p.dir, ".claude.json");
  const before = readFileSync(accountFile, "utf8");
  const beforeMtime = lstatSync(accountFile).mtimeMs;
  ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(readFileSync(accountFile, "utf8")).toBe(before);
  expect(lstatSync(accountFile).mtimeMs).toBe(beforeMtime);
});

test("linked capability dirs do not break the profile's own safe writes", () => {
  const p = addProfile({ name: "safewrite" });
  expect(lstatSync(join(p.dir, "skills")).isSymbolicLink()).toBe(true);
  expect(() => assertSafeWritePath(join(p.dir, "settings.json"), { mustStayUnder: p.dir })).not.toThrow();
  expect(() => assertSafeWritePath(join(p.dir, ".claude.json"), { mustStayUnder: p.dir })).not.toThrow();
  expect(() =>
    assertSafeWritePath(join(p.dir, ".accounts-auth", "oauth-account.json"), { mustStayUnder: p.dir }),
  ).not.toThrow();
});

test("purge removes the profile without touching the shared corpus", () => {
  const p = addProfile({ name: "purgeme" });
  expect(realpathSync(join(p.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
  expect(corpusIntact(sharedHome)).toBe(true);

  const result = removeProfile("purgeme", { purge: true });
  expect(result.purged).toBe(true);
  expect(existsSync(p.dir)).toBe(false);
  expect(corpusIntact(sharedHome)).toBe(true);
});

test("positive control: corpusIntact does detect a purge that really deletes a corpus", () => {
  // Plant the defect deliberately — a corpus reachable by real path under the
  // purged tree is exactly what a dereferencing copy/link would produce.
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "control" });
  const insideCorpus = join(p.dir, "inside-corpus");
  seedSharedCorpus(insideCorpus);
  expect(corpusIntact(insideCorpus)).toBe(true);

  removeProfile("control", { purge: true });
  expect(corpusIntact(insideCorpus)).toBe(false);
});

test("import --copy keeps shared capabilities shared instead of duplicating the corpus", async () => {
  const source = addProfile({ name: "origin" });
  expect(lstatSync(join(source.dir, "skills")).isSymbolicLink()).toBe(true);

  const copied = await importProfile({ name: "copied", tool: "claude", dir: source.dir, copy: true });
  expect(lstatSync(join(copied.dir, "skills")).isSymbolicLink()).toBe(true);
  expect(realpathSync(join(copied.dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
});

test("health reports a correctly shared profile as clean", () => {
  const p = addProfile({ name: "healthy" });
  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.supported).toBe(true);
  expect(health.problems).toEqual([]);
  // The capability corpora this fixture seeds. Session entries are reported too
  // and are "unavailable" here, because this shared home has no session tree —
  // they are covered by the session merge tests.
  expect(health.entries.filter((e) => ["skills", "agents"].includes(e.entry)).map((e) => e.status)).toEqual([
    "shared",
    "shared",
  ]);
  expect(health.config[0]!.status).toBe("shared");
});

test("health fails a dangling link instead of silently passing", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "brokenlink" });
  symlinkSync(join(home, "gone", "skills"), join(p.dir, "skills"));

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.entries.find((e) => e.entry === "skills")!.status).toBe("missing");
  expect(health.problems.join(" ")).toContain("skills");
});

test("health fails the profiles this hotfix is for: no skills, no agents, no MCP servers", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "empty" });
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.entries.find((e) => e.entry === "skills")!.status).toBe("missing");
  expect(health.entries.find((e) => e.entry === "agents")!.status).toBe("missing");
  expect(health.config[0]!.status).toBe("missing");
  expect(health.problems.length).toBe(3);
});

test("health treats a profile-owned real directory as a warning, not a failure", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "localdir" });
  mkdirSync(join(p.dir, "skills"), { recursive: true });
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  ensureSharedCapabilities(p.dir, getTool("claude"));
  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.entries.find((e) => e.entry === "skills")!.status).toBe("local");
  expect(health.problems.join(" ")).not.toContain("skills");
  expect(health.warnings.join(" ")).toContain("skills");
});

test("health is inert for tools that declare no shared capabilities", () => {
  const p = addProfile({ name: "codexhealth", tool: "codex" });
  const health = sharedCapabilityHealth(p.dir, getTool("codex"));
  expect(health.supported).toBe(false);
  expect(health.problems).toEqual([]);
});

// ---------------------------------------------------------------------------
// Regression tests for the defects found in adversarial review of PR #34.
// ---------------------------------------------------------------------------

test("a corrupt profile account file is never replaced by the merge", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "corrupt" });
  const accountFile = join(p.dir, ".claude.json");
  // Exactly what an interrupted write leaves behind: a truncated prefix of a
  // healthy file, still carrying the identity keys.
  const truncated = JSON.stringify({
    oauthAccount: { emailAddress: "corrupt@example.com" },
    userID: "user-1",
    machineID: "machine-1",
    numStartups: 42,
  }).slice(0, 60);
  writeFileSync(accountFile, truncated);

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));

  expect(readFileSync(accountFile, "utf8")).toBe(truncated);
  expect(result.seededKeys).toEqual([]);
  expect(result.errors.join(" ")).toContain(".claude.json");
  expect(result.errors.join(" ")).toMatch(/could not be read|invalid JSON/i);
});

test("an account file whose top level is not an object aborts the merge", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "notobject" });
  const accountFile = join(p.dir, ".claude.json");
  writeFileSync(accountFile, "[1,2,3]");

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(readFileSync(accountFile, "utf8")).toBe("[1,2,3]");
  expect(result.seededKeys).toEqual([]);
  expect(result.errors.length).toBeGreaterThan(0);
});

test("health diagnoses a corrupt account file as unreadable, not as empty", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "corrupthealth" });
  writeFileSync(join(p.dir, ".claude.json"), "{not json");

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.config[0]!.status).toBe("unreadable");
  expect(health.problems.join(" ")).toMatch(/could not be read/i);
  expect(health.problems.join(" ")).not.toMatch(/is empty/i);
});

test("the account-file merge is atomic and tightens the file mode", () => {
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "atomic" });
  const accountFile = join(p.dir, ".claude.json");
  writeFileSync(accountFile, JSON.stringify({ oauthAccount: { emailAddress: "a@example.com" } }), { mode: 0o644 });
  const before = statSync(accountFile);
  expect(before.mode & 0o777).toBe(0o644);

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  const result = ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(result.seededKeys).toEqual(["mcpServers"]);

  const after = statSync(accountFile);
  expect(after.mode & 0o777).toBe(0o600);
  // A rename-based write replaces the inode; an in-place truncate+write keeps it.
  if (process.platform !== "win32") expect(after.ino).not.toBe(before.ino);
  expect(readdirSync(p.dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  const data = readJson(accountFile);
  expect((data.oauthAccount as Record<string, string>).emailAddress).toBe("a@example.com");
});

test("rendered config sources win over the account file for the same server", () => {
  // The account file is what Claude Code reads at runtime, but on a real machine
  // it can be the *unrendered* copy — carrying {{PLACEHOLDER}} commands.
  writeFileSync(
    join(sharedHome, "settings.json"),
    JSON.stringify({ mcpServers: { todos: { command: "/real/bin/todos" }, onlysettings: { command: "/real/bin/x" } } }),
  );
  const p = addProfile({ name: "rendered" });
  const servers = readJson(join(p.dir, ".claude.json")).mcpServers as Record<string, { command: string }>;
  expect(servers.todos!.command).toBe("/real/bin/todos");
  // members are unioned across sources, so nothing the operator configured is dropped
  expect(servers.onlysettings!.command).toBe("/real/bin/x");
  expect(servers.notes!.command).toBe("notes-mcp");
});

test("servers with unrendered placeholders are never merged into a profile", () => {
  writeFileSync(
    join(home, ".claude.json"),
    JSON.stringify({ mcpServers: { broken: { command: "{{BUN_BIN_DIR}}/thing" }, good: { command: "/bin/good" } } }),
  );
  const p = addProfile({ name: "placeholder" });
  const servers = readJson(join(p.dir, ".claude.json")).mcpServers as Record<string, unknown>;
  expect(Object.keys(servers)).toEqual(["good"]);
});

test("excluded members are never shared into a profile", () => {
  writeFileSync(
    join(home, ".claude.json"),
    JSON.stringify({ mcpServers: { secrets: { command: "/bin/secrets" }, todos: { command: "/bin/todos" } } }),
  );
  const p = addProfile({ name: "excluded" });
  const servers = readJson(join(p.dir, ".claude.json")).mcpServers as Record<string, unknown>;
  expect(Object.keys(servers)).toEqual(["todos"]);
  const accountSpec = sharedConfigsFor(getTool("claude")).find((c) => c.target === ".claude.json");
  expect(accountSpec!.exclude).toContain("secrets");
});

test("switchProfile materializes shared capabilities even when it applies live auth", async () => {
  const liveBase = join(home, "live");
  mkdirSync(liveBase, { recursive: true });
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  try {
    process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
    const dir = join(home, "switch-profile");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "switch@example.com" } }));
    writeFileSync(
      join(dir, ".credentials.json"),
      JSON.stringify({ claudeAiOauth: { accessToken: "a", refreshToken: "r", expiresAt: Date.now() + 60_000 } }),
    );
    addProfile({ name: "switcher", dir });
    expect(existsSync(join(dir, "skills"))).toBe(false);

    process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
    const result = await switchProfile("switcher", { tool: "claude" });
    // Applied mode reads the live home, so that session is fine — the defect is
    // that the profile dir stayed broken for every later isolated launch.
    expect(result.applied).toBe(true);
    expect(result.env.CLAUDE_CONFIG_DIR).toBeUndefined();
    expect(realpathSync(join(dir, "skills"))).toBe(realpathSync(join(sharedHome, "skills")));
    expect(realpathSync(join(dir, "agents"))).toBe(realpathSync(join(sharedHome, "agents")));
  } finally {
    delete process.env.ACCOUNTS_TEST_LIVE_DIR;
  }
});

test("health detects a corpus emptied through the link instead of reporting it shared", () => {
  const p = addProfile({ name: "wiped" });
  expect(sharedCapabilityHealth(p.dir, getTool("claude")).problems).toEqual([]);

  // Destruction through the write-through link: the pointer is still correct.
  rmSync(join(sharedHome, "skills", "alpha"), { recursive: true, force: true });
  rmSync(join(sharedHome, "skills", "beta"), { recursive: true, force: true });

  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  expect(health.entries.find((e) => e.entry === "skills")!.status).toBe("shared");
  expect(health.problems.join(" ")).toMatch(/shrunk/i);
  expect(health.problems.join(" ")).toContain("skills");
});

test("a growing corpus raises the floor, and only an explicit reset lowers it", () => {
  const p = addProfile({ name: "growing" });
  mkdirSync(join(sharedHome, "skills", "gamma"), { recursive: true });
  writeFileSync(join(sharedHome, "skills", "gamma", "SKILL.md"), "---\nname: gamma\n---\n");

  ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(sharedCapabilityHealth(p.dir, getTool("claude")).problems).toEqual([]);

  rmSync(join(sharedHome, "skills", "gamma"), { recursive: true, force: true });
  expect(sharedCapabilityHealth(p.dir, getTool("claude")).problems.join(" ")).toMatch(/shrunk/i);
  // A launch must not quietly ratify the loss.
  ensureSharedCapabilities(p.dir, getTool("claude"));
  expect(sharedCapabilityHealth(p.dir, getTool("claude")).problems.join(" ")).toMatch(/shrunk/i);

  resetCapabilityBaseline(getTool("claude"));
  expect(sharedCapabilityHealth(p.dir, getTool("claude")).problems).toEqual([]);
});

test("tool definitions may not share credential artifacts", () => {
  const base = { label: "x", envVar: "X_HOME", defaultDir: "/tmp/x", bin: "x" };
  for (const entry of [".credentials.json", "credentials.json", ".accounts-auth", "auth.json", "keychain.json"]) {
    expect(() => addCustomTool({ ...base, id: "cred-entry", sharedEntries: [entry] })).toThrow(AccountsError);
  }
  expect(() =>
    addCustomTool({
      ...base,
      id: "cred-target",
      sharedConfig: { target: "auth.json", sources: ["settings.json"], keys: ["mcpServers"] },
    }),
  ).toThrow(AccountsError);
  expect(() =>
    addCustomTool({
      ...base,
      id: "cred-key",
      sharedConfig: { target: "config.json", sources: ["settings.json"], keys: ["oauthAccount"] },
    }),
  ).toThrow(AccountsError);
});

test("tool definitions may not contain NUL bytes in shared paths", () => {
  const base = { label: "x", envVar: "X_HOME", defaultDir: "/tmp/x", bin: "x" };
  expect(() => addCustomTool({ ...base, id: "nul-entry", sharedEntries: ["skills\u0000evil"] })).toThrow(AccountsError);
  expect(() =>
    addCustomTool({
      ...base,
      id: "nul-source",
      sharedConfig: { target: "config.json", sources: ["set\u0000tings.json"], keys: ["mcpServers"] },
    }),
  ).toThrow(AccountsError);
});

// --- hooks reach the profile's own settings.json (70d05ea6 / 189da2d6) -------
//
// Claude Code loads hooks from $CLAUDE_CONFIG_DIR/settings.json, and `accounts`
// sets CLAUDE_CONFIG_DIR to the profile dir. Before this test existed, the only
// key the creation path propagated was `mcpServers`, and it wrote it to
// `.claude.json` — so a hook configured on the machine could not reach a new
// profile by any route, and every profile minted after a guard sweep was born
// unguarded while looking completely normal (measured 2026-07-31: guard coverage
// brought to 30/30, next profile created minutes later was 0/2).

/** Shape Claude Code actually reads: event -> matcher groups -> command hooks. */
function seedSharedHooks(root: string, command: string): void {
  writeFileSync(
    join(root, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command, timeout: 10 }] }],
      },
    }),
  );
}

test("a profile is BORN with the machine's hooks in its own settings.json", () => {
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");

  const p = addProfile({ name: "guarded-at-birth" });

  const settingsPath = join(p.dir, "settings.json");
  expect(existsSync(settingsPath)).toBe(true);
  const hooks = readJson(settingsPath).hooks as Record<string, unknown[]>;
  expect(JSON.stringify(hooks)).toContain("/opt/guards/env-dump-guard.sh");
  expect(hooks.PreToolUse).toHaveLength(1);
});

test("seeding hooks does not disturb the profile's own settings or the mcp merge", () => {
  seedSharedHooks(sharedHome, "/opt/guards/layout-guard.sh");
  const p = addProfile({ name: "coexist" });

  // The account file merge is unchanged: mcpServers still lands in .claude.json.
  const servers = readJson(join(p.dir, ".claude.json")).mcpServers as Record<string, unknown>;
  expect(Object.keys(servers).sort()).toEqual(["notes", "todos"]);
  // ...and hooks did NOT leak into the account file.
  expect(readJson(join(p.dir, ".claude.json")).hooks).toBeUndefined();

  // A key the profile owns survives a re-run that seeds nothing new.
  const settingsPath = join(p.dir, "settings.json");
  const settings = readJson(settingsPath);
  writeFileSync(settingsPath, JSON.stringify({ ...settings, theme: "dark" }));
  ensureSharedCapabilities(p.dir, getTool("claude"));
  const after = readJson(settingsPath);
  expect(after.theme).toBe("dark");
  expect(JSON.stringify(after.hooks)).toContain("/opt/guards/layout-guard.sh");
});

test("a profile's own hook event wins, and unseen events are still seeded", () => {
  writeFileSync(
    join(sharedHome, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/shared/pre.sh" }] }],
        SessionStart: [{ hooks: [{ type: "command", command: "/shared/start.sh" }] }],
      },
    }),
  );
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "own-hooks" });
  writeFileSync(
    join(p.dir, "settings.json"),
    JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/profile/pre.sh" }] }] } }),
  );

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  ensureSharedCapabilities(p.dir, getTool("claude"));

  const hooks = readJson(join(p.dir, "settings.json")).hooks as Record<string, unknown>;
  // union by member name, profile always wins — the documented merge semantics
  expect(JSON.stringify(hooks.PreToolUse)).toContain("/profile/pre.sh");
  expect(JSON.stringify(hooks.PreToolUse)).not.toContain("/shared/pre.sh");
  expect(JSON.stringify(hooks.SessionStart)).toContain("/shared/start.sh");
});

test("sharedCapabilityHealth reports an unguarded profile as a problem", () => {
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "unhealthy" });
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  const health = sharedCapabilityHealth(p.dir, getTool("claude"));
  const hooksRow = health.config.find((c) => c.key === "hooks");
  expect(hooksRow).toBeDefined();
  expect(hooksRow!.status).toBe("missing");
  expect(hooksRow!.target).toBe(join(p.dir, "settings.json"));
});

// --- the startup assertion (70d05ea6 step 5) --------------------------------
//
// Seeding fixes the creation path; this is what stops the fix decaying again.
// Both directions are asserted, because an assertion that cannot refuse is
// decoration and one that cannot pass bricks every launch on the machine.

test("profileEnv REFUSES a profile missing required shared config", () => {
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "bare" });
  expect(existsSync(join(p.dir, "settings.json"))).toBe(false);

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  // Make the seed that profileEnv attempts fail, so the profile is still bare
  // when the assertion runs — the real-world case is an unwritable dir.
  writeFileSync(join(p.dir, "settings.json"), "{ not json");

  expect(() => profileEnv(p, getTool("claude"))).toThrow(AccountsError);
  expect(() => profileEnv(p, getTool("claude"))).toThrow(/refusing to launch/);
});

test("the refusal names its own override, and the override works", () => {
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");
  const p = addProfile({ name: "override" });
  writeFileSync(join(p.dir, "settings.json"), "{ not json");

  let message = "";
  try {
    profileEnv(p, getTool("claude"));
  } catch (err) {
    message = (err as Error).message;
  }
  expect(message).toContain("ACCOUNTS_ALLOW_UNGUARDED_PROFILE");

  process.env.ACCOUNTS_ALLOW_UNGUARDED_PROFILE = "1";
  try {
    expect(profileEnv(p, getTool("claude")).CLAUDE_CONFIG_DIR).toBe(p.dir);
  } finally {
    delete process.env.ACCOUNTS_ALLOW_UNGUARDED_PROFILE;
  }
});

test("the assertion PASSES for a normally created profile, and on a machine with no hooks", () => {
  // (a) machine declares hooks -> profile is seeded -> launch proceeds.
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");
  const guarded = addProfile({ name: "normal" });
  expect(profileEnv(guarded, getTool("claude")).CLAUDE_CONFIG_DIR).toBe(guarded.dir);

  // (b) machine declares NO hooks -> nothing to enforce -> launch proceeds.
  // Without this the check would refuse every launch on every machine that does
  // not use hooks, which is the same defect pointed the other way.
  rmSync(join(sharedHome, "settings.json"), { force: true });
  const plain = addProfile({ name: "no-hooks-machine" });
  expect(profileEnv(plain, getTool("claude")).CLAUDE_CONFIG_DIR).toBe(plain.dir);
});

// --- P1 from adversarial review (Seneca, PR #105): partial coverage ---------
//
// specHealth compared member COUNTS, so any one hook event made a profile pass.
// Measured live on station01 during that review: the shared home declared
// PreToolUse AND SessionStart, and 30 of 30 profiles held only PreToolUse — all
// 30 would have reported "shared" and launched. The comparison has to be over
// the declared member NAMES.

test("a profile holding only SOME of the machine's hook events is NOT healthy", () => {
  writeFileSync(
    join(sharedHome, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/shared/pre.sh" }] }],
        SessionStart: [{ hooks: [{ type: "command", command: "/shared/start.sh" }] }],
      },
    }),
  );
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "partial" });
  writeFileSync(
    join(p.dir, "settings.json"),
    JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/own/pre.sh" }] }] } }),
  );
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  const row = sharedCapabilityHealth(p.dir, getTool("claude")).config.find((c) => c.key === "hooks");
  expect(row!.status).toBe("missing");
  expect(row!.reason).toContain("SessionStart");
  // ...and the launch assertion must act on it, not just report it.
  expect(() => assertProfileGuarded(p.dir, getTool("claude"))).toThrow(/refusing to launch/);
});

test("a hook event present but EMPTY counts as absent, not as covered", () => {
  seedSharedHooks(sharedHome, "/opt/guards/env-dump-guard.sh");
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "hollow" });
  // The permanently-unguarded shape: union-by-member never fills an existing
  // member, so this profile would never be seeded AND never be refused.
  writeFileSync(join(p.dir, "settings.json"), JSON.stringify({ hooks: { PreToolUse: [] } }));
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  expect(readFileSync(join(p.dir, "settings.json"), "utf8")).not.toContain("env-dump-guard");
  const row = sharedCapabilityHealth(p.dir, getTool("claude")).config.find((c) => c.key === "hooks");
  expect(row!.status).toBe("missing");
  expect(() => assertProfileGuarded(p.dir, getTool("claude"))).toThrow(/refusing to launch/);
});

test("a profile with every declared event, under its own commands, stays healthy", () => {
  // The passing state, so the stricter check is not one that can only refuse.
  writeFileSync(
    join(sharedHome, "settings.json"),
    JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/shared/pre.sh" }] }],
        SessionStart: [{ hooks: [{ type: "command", command: "/shared/start.sh" }] }],
      },
    }),
  );
  const p = addProfile({ name: "complete" });
  const row = sharedCapabilityHealth(p.dir, getTool("claude")).config.find((c) => c.key === "hooks");
  expect(row!.status).toBe("shared");
  expect(() => assertProfileGuarded(p.dir, getTool("claude"))).not.toThrow();
});

// --- P1 from adversarial review: the purge deleted a path it was HANDED -----
//
// `isManagedProfileDir` is lexical, so a symlink under the profiles root
// satisfied it while pointing anywhere. On the hosted path `profile.dir` comes
// from an API response, which made the delete target remote-controlled. The
// reviewer walked past the guard and deleted a different live profile's dir,
// `.credentials.json` and all.

test("purge REFUSES a symlink under the profiles root that points elsewhere", () => {
  const victim = join(home, "precious");
  mkdirSync(victim, { recursive: true });
  writeFileSync(join(victim, ".credentials.json"), JSON.stringify({ token: "PLACEHOLDER" }));

  const real = addProfile({ name: "decoy" });
  const evilName = "evil";
  const evilDir = join(home, "profiles", "claude", evilName);
  symlinkSync(victim, evilDir);

  // Positive control: the victim is genuinely there before the attempt, so a
  // later `true` is an observation rather than a check that cannot fail.
  expect(existsSync(join(victim, ".credentials.json"))).toBe(true);

  const result = purgeProfileDir({ ...real, name: evilName, dir: evilDir });
  expect(result.purged).toBe(false);
  expect(result.purgeNote).toContain("not the managed dir");
  expect(existsSync(join(victim, ".credentials.json"))).toBe(true);
});

test("purge REFUSES a dir that is managed but belongs to a different profile", () => {
  const mine = addProfile({ name: "mine" });
  const theirs = addProfile({ name: "theirs" });
  writeFileSync(join(theirs.dir, ".credentials.json"), JSON.stringify({ token: "PLACEHOLDER" }));
  expect(existsSync(join(theirs.dir, ".credentials.json"))).toBe(true);

  // The hosted store hands us a row whose `dir` disagrees with its own name.
  const result = purgeProfileDir({ ...mine, dir: theirs.dir });
  expect(result.purged).toBe(false);
  expect(existsSync(join(theirs.dir, ".credentials.json"))).toBe(true);
});

test("purge still deletes the profile's OWN managed dir", () => {
  // The passing state — a guard that refuses everything is not a fix.
  const p = addProfile({ name: "genuine" });
  expect(existsSync(p.dir)).toBe(true);
  const result = purgeProfileDir(p);
  expect(result.purged).toBe(true);
  expect(result.purgeNote).toBeUndefined();
  expect(existsSync(p.dir)).toBe(false);
});

// --- P1 from re-review (Seneca @ 9b56b82): the DERIVATION took untrusted input
//
// Deriving join(profilesDir(), tool, name) removed the trust from `dir` and
// silently moved it to `name`, which is just as remote-supplied: HostedStore
// returns the server's body and cloud-accounts' toProfile is a plain field copy
// that never applies profileSchema. A response naming "../claude/victim"
// normalises back inside the managed root, so both containment checks agree and
// the delete lands on a different profile's dir.

test("purge REFUSES a profile identity that is not a slug", () => {
  const victim = addProfile({ name: "victimprofile" });
  writeFileSync(join(victim.dir, ".credentials.json"), JSON.stringify({ token: "PLACEHOLDER" }));
  const decoy = addProfile({ name: "throwaway" });
  // Positive control: the victim is genuinely present before the attempt.
  expect(existsSync(join(victim.dir, ".credentials.json"))).toBe(true);

  // Exactly the reviewer's RR-B3b: a traversing `name` whose join() normalises
  // back inside the root, paired with the matching `dir` so both checks agree.
  const result = purgeProfileDir({ ...decoy, name: "../claude/victimprofile", dir: victim.dir });

  expect(result.purged).toBe(false);
  expect(result.purgeNote).toContain("not a valid profile identity");
  expect(existsSync(join(victim.dir, ".credentials.json"))).toBe(true);
  expect(existsSync(victim.dir)).toBe(true);
});

test("purge REFUSES a tool id that is not a slug", () => {
  const victim = addProfile({ name: "othervictim" });
  expect(existsSync(victim.dir)).toBe(true);
  const result = purgeProfileDir({ ...victim, tool: "../claude" });
  expect(result.purged).toBe(false);
  expect(result.purgeNote).toContain("not a valid profile identity");
  expect(existsSync(victim.dir)).toBe(true);
});

test("a valid identity still purges — the identity check refuses only bad input", () => {
  // The passing state, so the new gate is not one that refuses everything.
  const p = addProfile({ name: "legitimate" });
  expect(existsSync(p.dir)).toBe(true);
  const result = purgeProfileDir(p);
  expect(result.purged).toBe(true);
  expect(result.purgeNote).toBeUndefined();
  expect(existsSync(p.dir)).toBe(false);
});

// --- the status line reaches the profile's own settings.json (4f2e0bd2) ------
//
// Claude Code reads `statusLine` from $CLAUDE_CONFIG_DIR/settings.json, exactly
// like `hooks`, and `accounts` points CLAUDE_CONFIG_DIR at the profile dir. A
// status line configured on the machine therefore reaches the machine's shared
// home and nothing else: every profile minted after a one-time seeding sweep is
// born without it and silently shows no status line (measured 2026-08-02 on
// station01: 22 of 33 claude profiles carried the key, and the 11 that did not
// were the contiguous newest block — account033..account041 plus `anya`, which
// is what a snapshot sweep followed by continued minting looks like).
//
// The key is seeded, never authored here: no command string, path, or binary
// name appears in this package. What lands in a profile is whatever the
// machine's own settings.json declares, so this stays a mechanism and the fleet
// supplies the policy — the same split the `hooks` spec above already makes.

/** Shape Claude Code actually reads: a command-type status line row. */
function seedSharedStatusLine(root: string, command: string): void {
  const existing = existsSync(join(root, "settings.json")) ? readJson(join(root, "settings.json")) : {};
  writeFileSync(
    join(root, "settings.json"),
    JSON.stringify({ ...existing, statusLine: { type: "command", command, padding: 0 } }),
  );
}

test("a profile is BORN with the machine's statusLine in its own settings.json", () => {
  seedSharedStatusLine(sharedHome, "statusline render");

  const p = addProfile({ name: "statusline-at-birth" });

  const settingsPath = join(p.dir, "settings.json");
  expect(existsSync(settingsPath)).toBe(true);
  const statusLine = readJson(settingsPath).statusLine as Record<string, unknown>;
  expect(statusLine).toEqual({ type: "command", command: "statusline render", padding: 0 });
});

test("a profile created before the statusLine spec is repaired through the same code path", () => {
  // The 10 profiles already on disk: minted while the machine declared no
  // status line, then repaired by the ensure pass that runs on env/launch/switch.
  const p = addProfile({ name: "statusline-legacy" });
  const settingsPath = join(p.dir, "settings.json");
  const born = existsSync(settingsPath) ? readJson(settingsPath).statusLine : undefined;
  expect(born).toBeUndefined();

  seedSharedStatusLine(sharedHome, "statusline render");
  ensureSharedCapabilities(p.dir, getTool("claude"));

  expect(readJson(join(p.dir, "settings.json")).statusLine).toEqual({
    type: "command",
    command: "statusline render",
    padding: 0,
  });
});

test("a profile's own statusLine member wins, and unseen members are still seeded", () => {
  seedSharedStatusLine(sharedHome, "/shared/statusline render");
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "own-statusline" });
  writeFileSync(
    join(p.dir, "settings.json"),
    JSON.stringify({ statusLine: { type: "command", command: "/profile/mine.sh" } }),
  );

  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
  ensureSharedCapabilities(p.dir, getTool("claude"));

  const statusLine = readJson(join(p.dir, "settings.json")).statusLine as Record<string, unknown>;
  // union by member name, profile always wins — the documented merge semantics
  expect(statusLine.command).toBe("/profile/mine.sh");
  expect(statusLine.padding).toBe(0);
});

test("a machine that declares NO statusLine seeds none, and still launches", () => {
  // The negative control. Without it this spec could be satisfied by a rule that
  // writes a statusLine unconditionally, which would author policy in code and
  // put a broken command into every profile on a machine that wants none.
  const p = addProfile({ name: "no-statusline-machine" });

  const settingsPath = join(p.dir, "settings.json");
  // Nothing to seed from either spec, so the file is not created at all; if some
  // other rule does create it, it must still carry no statusLine.
  const statusLine = existsSync(settingsPath) ? readJson(settingsPath).statusLine : undefined;
  expect(statusLine).toBeUndefined();
  // statusLine is deliberately NOT `required`: an absent status line is visible
  // on screen, unlike an absent guard hook, so it must never refuse a launch.
  expect(() => assertProfileGuarded(p.dir, getTool("claude"))).not.toThrow();
});

test("a machine that declares a statusLine still never refuses a launch for a profile missing it", () => {
  seedSharedStatusLine(sharedHome, "statusline render");
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = join(home, "does-not-exist");
  const p = addProfile({ name: "statusline-unseeded" });
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;

  const row = sharedCapabilityHealth(p.dir, getTool("claude")).config.find((c) => c.key === "statusLine");
  expect(row).toBeDefined();
  expect(row!.status).toBe("missing");
  expect(row!.target).toBe(join(p.dir, "settings.json"));
  // reported by doctor, never fatal
  expect(() => assertProfileGuarded(p.dir, getTool("claude"))).not.toThrow();
});
