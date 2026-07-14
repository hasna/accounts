// Regression: `accounts list` must not crash when the registry holds a profile
// whose tool is unknown on this machine. This reproduces the self-hosted failure
// where the shared cloud store held profiles for tools (aicopilot, browserplan)
// not present in the client's local tool set: rendering the per-profile configs
// prelaunch summary called getTool(), which threw and aborted the ENTIRE listing.
import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-list-unknown-tool-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function writeStore(): void {
  const store = {
    version: 1,
    current: {},
    applied: {},
    toolLocks: {},
    tools: [],
    profiles: [
      { name: "known", tool: "claude", dir: join(home, "known"), createdAt: "2026-01-01T00:00:00.000Z" },
      // Tools NOT in the built-in set and not registered locally — the exact
      // shape the shared cloud store returned in the field failure.
      { name: "co", tool: "aicopilot", dir: join(home, "co"), createdAt: "2026-01-01T00:00:00.000Z" },
      { name: "bp", tool: "browserplan", dir: join(home, "bp"), createdAt: "2026-01-01T00:00:00.000Z" },
    ],
  };
  writeFileSync(join(home, "accounts.json"), JSON.stringify(store));
}

function runList(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", "list", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, NODE_ENV: "test", ACCOUNTS_HOME: home },
  });
}

test("list does not crash on a profile with an unknown tool (human output)", () => {
  writeStore();
  const res = runList();
  expect(res.status).toBe(0);
  expect(res.stderr).not.toMatch(/unknown tool/);
  // Every profile is listed, including the unknown-tool ones.
  expect(res.stdout).toContain("known");
  expect(res.stdout).toContain("co");
  expect(res.stdout).toContain("bp");
});

test("list --json does not crash on a profile with an unknown tool", () => {
  writeStore();
  const res = runList("--json");
  expect(res.status).toBe(0);
  const parsed = JSON.parse(res.stdout) as { name: string; tool: string; prelaunch: { supported: boolean; status: string } }[];
  expect(parsed).toHaveLength(3);
  const unknown = parsed.find((p) => p.tool === "aicopilot");
  expect(unknown).toBeDefined();
  // The unknown tool degrades to an unsupported prelaunch summary, not a crash.
  expect(unknown!.prelaunch.supported).toBe(false);
  expect(unknown!.prelaunch.status).toBe("unsupported");
});
