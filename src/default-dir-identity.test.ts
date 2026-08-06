// Regression tests for bug 04a350a9 (task 9b006e93): live-default identity
// attribution.
//
// The live default keeps its account record in TWO places: the inner
// `~/.claude/.claude.json` and the home `~/.claude.json`. Claude Code writes
// the home file; the inner file can go stale — and 0.2.32's
// `profileAccountJsonPaths` listed the inner file FIRST while `dirAccountUuid`
// returned the first hit, so a stale inner uuid shadowed the fresh home uuid.
// Measured on station01: inner uuid 643e2376 (Aug 3) shadowing home uuid
// 11aabd84 (fresh), so the broker attributed and harvested the live default
// under the wrong account. The freshest identity must win.
import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirAccountUuid } from "./lib/identity-index.js";
import { liveClaudePaths, profileAccountJsonPaths } from "./lib/claude-layout.js";
import { getTool } from "./lib/tools.js";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

const STALE_UUID = "643e2376-0000-4000-8000-00000000000a";
const FRESH_UUID = "11aabd84-0000-4000-8000-00000000000b";

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-ddi-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-ddi-live-"));
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

function writeAccountJson(path: string, accountUuid: string, ageMs = 0): void {
  writeFileSync(path, JSON.stringify({ oauthAccount: { accountUuid, emailAddress: `${accountUuid.slice(0, 8)}@example.com` } }));
  if (ageMs > 0) {
    const then = (Date.now() - ageMs) / 1000;
    utimesSync(path, then, then);
  }
}

test("dirAccountUuid on the live default: a fresh home ~/.claude.json beats a stale inner one", () => {
  const liveConfigDir = liveClaudePaths().configDir;
  mkdirSync(liveConfigDir, { recursive: true });
  // The measured shape: inner file three days stale, home file fresh.
  writeAccountJson(join(liveConfigDir, ".claude.json"), STALE_UUID, 3 * 86_400_000);
  writeAccountJson(join(liveBase, ".claude.json"), FRESH_UUID);

  expect(dirAccountUuid(liveConfigDir, tool())).toBe(FRESH_UUID);
});

test("CONTROL: when the inner file is the fresher one, IT wins — freshest, not home-always", () => {
  const liveConfigDir = liveClaudePaths().configDir;
  mkdirSync(liveConfigDir, { recursive: true });
  writeAccountJson(join(liveConfigDir, ".claude.json"), FRESH_UUID);
  writeAccountJson(join(liveBase, ".claude.json"), STALE_UUID, 3 * 86_400_000);

  expect(dirAccountUuid(liveConfigDir, tool())).toBe(FRESH_UUID);
});

test("the live default still resolves from the inner file alone when no home file exists", () => {
  const liveConfigDir = liveClaudePaths().configDir;
  mkdirSync(liveConfigDir, { recursive: true });
  writeAccountJson(join(liveConfigDir, ".claude.json"), STALE_UUID, 3 * 86_400_000);

  expect(dirAccountUuid(liveConfigDir, tool())).toBe(STALE_UUID);
});

test("profileAccountJsonPaths orders the live default's two account files freshest first", () => {
  const liveConfigDir = liveClaudePaths().configDir;
  mkdirSync(liveConfigDir, { recursive: true });
  writeAccountJson(join(liveConfigDir, ".claude.json"), STALE_UUID, 3 * 86_400_000);
  writeAccountJson(join(liveBase, ".claude.json"), FRESH_UUID);

  const paths = profileAccountJsonPaths(liveConfigDir, tool());
  expect(paths.length).toBe(2);
  expect(paths[0]).toBe(join(liveBase, ".claude.json"));
  expect(paths[1]).toBe(join(liveConfigDir, ".claude.json"));
});

test("an ordinary profile dir keeps its single account path — no parent file involved", () => {
  const profileDir = mkdtempSync(join(tmpdir(), "ddi-profile-"));
  writeAccountJson(join(profileDir, ".claude.json"), FRESH_UUID);
  // A sibling file in the parent must never be read for a non-default dir.
  writeAccountJson(join(profileDir, "..", ".claude.json"), STALE_UUID);

  const paths = profileAccountJsonPaths(profileDir, tool());
  expect(paths).toEqual([join(profileDir, ".claude.json")]);
  expect(dirAccountUuid(profileDir, tool())).toBe(FRESH_UUID);
  rmSync(profileDir, { recursive: true, force: true });
});
