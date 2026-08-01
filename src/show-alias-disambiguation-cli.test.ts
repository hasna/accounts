// R-P1-4 (2026-07-31-accounts-debloat-design.md), the live-harm reproduction
// this task closes: a migration renamed 13 records (e.g. `account005` @
// codewith -> `account005-codewith`) and looking one up by its old name
// silently answered "no such thing" for something that exists.
//
// "accounts show <name> and list read aliases: show account005 returns the
// claude profile AND prints a disambiguation line ('alias note: ...')
// ... show account005-codewith shows nativeName: account005."
import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-alias-disambiguation-"));
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
      { name: "account005", tool: "claude", dir: join(home, "claude005"), createdAt: "2026-01-01T00:00:00.000Z" },
      {
        name: "account005-codewith",
        tool: "codewith",
        dir: join(home, "cw005"),
        createdAt: "2026-01-01T00:00:00.000Z",
        nativeName: "account005",
        aliases: ["account005"],
      },
    ],
  };
  writeFileSync(join(home, "accounts.json"), JSON.stringify(store));
}

function runShow(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", "show", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, NODE_ENV: "test", ACCOUNTS_HOME: home },
  });
}

test("show <old-name> resolves the exact-name profile AND prints the alias disambiguation line", () => {
  writeStore();
  const res = runShow("account005");
  expect(res.status).toBe(0);
  // Still resolves to the claude profile — the exact-name match is unchanged.
  expect(res.stdout).toContain("account005");
  expect(res.stdout).toContain("claude");
  // And now names the other record that used to answer to this name too.
  expect(res.stdout).toContain(
    "alias note: 'account005' is also the former/native name of account005-codewith (codewith)",
  );
});

test("show <old-name> --json carries structured alias notes", () => {
  writeStore();
  const res = runShow("account005", "--json");
  expect(res.status).toBe(0);
  const details = JSON.parse(res.stdout);
  expect(details.name).toBe("account005");
  expect(details.tool).toBe("claude");
  expect(details.aliasNotes).toEqual([{ name: "account005-codewith", tool: "codewith" }]);
});

test("show <new-name> shows its nativeName and aliases", () => {
  writeStore();
  const res = runShow("account005-codewith", "--json");
  expect(res.status).toBe(0);
  const details = JSON.parse(res.stdout);
  expect(details.nativeName).toBe("account005");
  expect(details.aliases).toEqual(["account005"]);
});

test("show <new-name> (human output) prints the nativeName line", () => {
  writeStore();
  const res = runShow("account005-codewith");
  expect(res.status).toBe(0);
  expect(res.stdout).toMatch(/nativeName:\s+account005/);
});

test("show a profile with no aliases pointing at it prints no disambiguation line", () => {
  writeStore();
  const res = runShow("account005-codewith");
  expect(res.status).toBe(0);
  expect(res.stdout).not.toContain("alias note:");
});
