// R-P1-4 write path: the CLI's supported way to record an alias/nativeName on
// an existing profile, via `accounts set`. Deliberately NOT wired into
// `accounts rename` — see the PR description for why (auto-aliasing every
// future rename is a separate, bigger decision this task does not make).
import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-set-alias-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function run(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, NODE_ENV: "test", ACCOUNTS_HOME: home },
  });
}

test("accounts set --native-name and --alias record the fields; show --json reflects them", () => {
  expect(run("add", "account005-codewith", "--tool", "codewith").status).toBe(0);
  expect(run("set", "account005-codewith", "--tool", "codewith", "--native-name", "account005", "--alias", "account005").status).toBe(0);

  const shown = run("show", "account005-codewith", "--tool", "codewith", "--json");
  expect(shown.status).toBe(0);
  const details = JSON.parse(shown.stdout);
  expect(details.nativeName).toBe("account005");
  expect(details.aliases).toEqual(["account005"]);
});

test("rename does NOT auto-populate aliases/nativeName (explicit write path only)", () => {
  expect(run("add", "old-name", "--tool", "codewith").status).toBe(0);
  expect(run("rename", "old-name", "new-name", "--tool", "codewith").status).toBe(0);

  const shown = run("show", "new-name", "--tool", "codewith", "--json");
  expect(shown.status).toBe(0);
  const details = JSON.parse(shown.stdout);
  expect(details.nativeName).toBeUndefined();
  expect(details.aliases).toBeUndefined();
});
