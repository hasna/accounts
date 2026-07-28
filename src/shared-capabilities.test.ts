import { test, expect, beforeEach, afterEach } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, removeProfile } from "./lib/profiles.js";
import { getTool } from "./lib/tools.js";
import { profileEnv } from "./lib/env.js";
import { importProfile } from "./lib/import-profile.js";
import { assertSafeWritePath } from "./lib/safe-path.js";
import {
  ensureSharedCapabilities,
  sharedCapabilityHealth,
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
  expect(health.entries.map((e) => e.status)).toEqual(["shared", "shared"]);
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
