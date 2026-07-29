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

test("doctor loudly warns that an accounts.json profile registry is stale in api mode", async () => {
  const localStorePath = join(home, "accounts.json");
  writeFileSync(
    localStorePath,
    JSON.stringify({
      version: 1,
      current: {},
      applied: {},
      toolLocks: {},
      profiles: [
        {
          name: "stale-local",
          tool: "claude",
          email: "stale@example.test",
          dir: join(home, "profiles", "claude", "stale-local"),
          createdAt: "2026-07-07T00:00:00.000Z",
        },
      ],
      tools: [],
    }),
  );
  const apiServer = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const pathname = new URL(request.url).pathname;
      if (pathname === "/v1/accounts") return Response.json({ accounts: [] });
      if (pathname === "/v1/current") return Response.json({ current: [] });
      return Response.json({ error: "not found" }, { status: 404 });
    },
  });

  try {
    const apiUrl = `http://127.0.0.1:${apiServer.port}`;
    const child = Bun.spawn({
      cmd: [process.execPath, "run", "src/cli.ts", "doctor"],
      cwd: process.cwd(),
      env: {
        ...process.env,
        ACCOUNTS_HOME: home,
        ACCOUNTS_STORE_PATH: localStorePath,
        HASNA_ACCOUNTS_STORAGE_MODE: "cloud",
        ACCOUNTS_STORAGE_MODE: "cloud",
        HASNA_ACCOUNTS_MODE: "cloud",
        HASNA_ACCOUNTS_API_URL: apiUrl,
        ACCOUNTS_API_URL: apiUrl,
        HASNA_ACCOUNTS_API_KEY: "doctor-test-key",
        ACCOUNTS_API_KEY: "doctor-test-key",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);

    expect(exitCode).toBe(0);
    expect(stdout).toContain("store: API registry");
    expect(stdout).toContain(`machine state: ${localStorePath}`);
    expect(stderr).toContain("WARNING: LOCAL PROFILE DATA IS NOT AUTHORITATIVE IN API MODE");
    expect(stderr).toContain(`${localStorePath} exists, but profiles are read from the API registry.`);
    expect(stderr).toContain("Its profile records may be stale.");
  } finally {
    apiServer.stop(true);
  }
});
