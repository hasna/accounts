import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;
let sharedHome: string;
let missingHome: string;

function runCli(sharedHomeForRun: string, ...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ACCOUNTS_SHARED_HOME_CLAUDE: sharedHomeForRun },
  });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-doctor-cli-"));
  sharedHome = join(home, "shared-claude");
  missingHome = join(home, "no-shared-home");
  mkdirSync(join(sharedHome, "skills", "alpha"), { recursive: true });
  writeFileSync(join(sharedHome, "skills", "alpha", "SKILL.md"), "---\nname: alpha\n---\nbody\n");
  mkdirSync(join(sharedHome, "agents"), { recursive: true });
  writeFileSync(join(sharedHome, "agents", "reviewer.md"), "---\nname: reviewer\n---\nbody\n");
  writeFileSync(join(home, ".claude.json"), JSON.stringify({ mcpServers: { todos: { command: "todos-mcp" } } }));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

test("doctor fails a profile that carries none of the machine's capabilities", () => {
  // Created while no shared home was known — the state all 23 existing profiles are in.
  const add = runCli(missingHome, "add", "capless", "--email", "capless@example.com");
  expect(add.status).toBe(0);

  const before = runCli(sharedHome, "doctor");
  expect(before.status).toBe(1);
  expect(before.stdout).toContain("skills is not shared");
  expect(before.stdout).toContain("agents is not shared");
  expect(before.stdout).toContain("mcpServers is empty");

  // `accounts env` runs profileEnv, which materializes the shared capabilities.
  const env = runCli(sharedHome, "env", "capless");
  expect(env.status).toBe(0);

  const after = runCli(sharedHome, "doctor");
  expect(after.status).toBe(0);
  expect(after.stdout).toContain("healthy.");
});

test("doctor passes a profile created with the shared home available", () => {
  const add = runCli(sharedHome, "add", "capable", "--email", "capable@example.com");
  expect(add.status).toBe(0);

  const result = runCli(sharedHome, "doctor");
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("healthy.");
});

test("doctor names non-portable extraEnv keys in already-stored custom tools", () => {
  writeFileSync(
    join(home, "accounts.json"),
    JSON.stringify({
      version: 1,
      current: {},
      applied: {},
      toolLocks: {},
      profiles: [],
      tools: [
        {
          id: "legacy-tool",
          label: "Legacy Tool",
          envVar: "LEGACY_HOME",
          extraEnv: { "BAD-NAME": "value" },
          defaultDir: join(home, "legacy-tool"),
          bin: "legacy-tool",
        },
      ],
    }),
  );

  const list = runCli(sharedHome, "tools", "list");
  expect(list.status).toBe(0);
  expect(list.stdout).toContain("legacy-tool");

  const result = runCli(sharedHome, "doctor");
  expect(result.status).toBe(1);
  expect(result.stdout).toContain('stored custom tool "legacy-tool" has non-portable extraEnv key "BAD-NAME"');
  expect(result.stdout).toContain("^[A-Za-z_][A-Za-z0-9_]*$");

  const repair = runCli(
    sharedHome,
    "tools",
    "add",
    "legacy-tool",
    "--label",
    "Legacy Tool",
    "--env-var",
    "LEGACY_HOME",
    "--bin",
    "legacy-tool",
    "--default-dir",
    join(home, "legacy-tool"),
    "--extra-env",
    "GOOD_NAME=value",
  );
  expect(repair.status).toBe(0);
  expect(runCli(sharedHome, "doctor").status).toBe(0);
});
