import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
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
import { loadStore } from "./storage.js";
import { detectEmail } from "./lib/detect.js";
import { getTool, listTools, addCustomTool, removeCustomTool, isBuiltinTool } from "./lib/tools.js";
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
  addCustomTool({ id: "cursor", label: "Cursor", envVar: "CURSOR_CONFIG_DIR", defaultDir: "/tmp/.cursor", bin: "cursor" });
  expect(listTools().some((t) => t.id === "cursor")).toBe(true);
  expect(isBuiltinTool("cursor")).toBe(false);
  expect(getTool("cursor").label).toBe("Cursor");
  const p = addProfile({ name: "design", tool: "cursor", email: "d@example.com" });
  expect(p.tool).toBe("cursor");
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
  addCustomTool({ id: "cursor", label: "Cursor", envVar: "CURSOR_CONFIG_DIR", defaultDir: "/tmp/.cursor", bin: "cursor" });
  addProfile({ name: "design", tool: "cursor" });
  expect(() => removeCustomTool("cursor")).toThrow(AccountsError);
  removeProfile("design");
  removeCustomTool("cursor");
  expect(listTools().some((t) => t.id === "cursor")).toBe(false);
});

test("custom tools: removing a built-in throws", () => {
  expect(() => removeCustomTool("claude")).toThrow(AccountsError);
});

test("explicit dir is honored and created", () => {
  const dir = join(home, "custom", "spot");
  mkdirSync(join(home, "custom"), { recursive: true });
  const p = addProfile({ name: "c", dir });
  expect(p.dir).toBe(dir);
  expect(existsSync(dir)).toBe(true);
});
