import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-permissions-cli-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home },
  });
}

test("switch CLI accepts --permissions and returns tool-specific command args", () => {
  const add = runCli("add", "codexer", "--tool", "codex");
  expect(add.status).toBe(0);

  const result = runCli("switch", "codexer", "--tool", "codex", "--resume", "--permissions", "dangerous", "--json");
  expect(result.status).toBe(0);

  const parsed = JSON.parse(result.stdout) as { command: string[]; permissions?: string };
  expect(parsed.permissions).toBe("dangerous");
  expect(parsed.command).toEqual(["codex", "--dangerously-bypass-approvals-and-sandbox", "resume", "--last"]);
});

