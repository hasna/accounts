import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile, currentProfile, useProfile } from "./lib/profiles.js";
import { addCustomTool, getTool } from "./lib/tools.js";
import {
  resolveSupervisorLaunch,
  runSupervisedTool,
  sendSupervisorRequest,
  supervisorSocketPath,
} from "./lib/supervisor.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-supervisor-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor<T>(read: () => T | undefined, timeoutMs = 2500): Promise<T> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = read();
    if (value !== undefined) return value;
    await sleep(25);
  }
  throw new Error("timed out waiting for condition");
}

function readLog(path: string): Array<{ active: string; home: string; args: string[] }> {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as { active: string; home: string; args: string[] });
}

test("resolveSupervisorLaunch treats a known target as a tool and uses the active profile", () => {
  addProfile({ name: "one", tool: "codex" });
  useProfile("one", "codex");

  const plan = resolveSupervisorLaunch("codex");

  expect(plan.targetKind).toBe("tool");
  expect(plan.tool.id).toBe("codex");
  expect(plan.profile.name).toBe("one");
});

test("runSupervisedTool restarts a child under the requested profile", async () => {
  const logPath = join(home, "fake-agent.log");
  const scriptPath = join(home, "fake-agent.mjs");
  writeFileSync(
    scriptPath,
    [
      'import { appendFileSync } from "node:fs";',
      "appendFileSync(process.env.FAKE_LOG, JSON.stringify({",
      "  active: process.env.ACCOUNTS_ACTIVE,",
      "  home: process.env.FAKE_HOME,",
      "  args: process.argv.slice(2),",
      '}) + "\\n");',
      'process.on("SIGTERM", () => process.exit(0));',
      "setInterval(() => undefined, 1000);",
    ].join("\n"),
  );

  addCustomTool({
    id: "fakeagent",
    label: "Fake Agent",
    envVar: "FAKE_HOME",
    defaultDir: join(home, "fake-default"),
    bin: process.execPath,
    resumeArgs: [scriptPath, "--resume"],
    permissionArgs: { dangerous: ["--no-warnings"] },
  });
  const one = addProfile({ name: "one", tool: "fakeagent" });
  const two = addProfile({ name: "two", tool: "fakeagent" });
  const tool = getTool("fakeagent");

  const previousFakeLog = process.env.FAKE_LOG;
  process.env.FAKE_LOG = logPath;
  const running = runSupervisedTool(one, tool, [scriptPath, "--start"], {
    stdio: "ignore",
    restartDelayMs: 25,
  });

  try {
    await waitFor(() => (existsSync(supervisorSocketPath("fakeagent")) ? true : undefined));
    await waitFor(() => (readLog(logPath).some((entry) => entry.active === "one") ? true : undefined));

    const response = await sendSupervisorRequest("fakeagent", {
      type: "switch_profile",
      name: "two",
      resume: true,
      permissions: "dangerous",
    });

    expect(response?.ok).toBe(true);
    expect(response && "queued" in response ? response.result.command : []).toEqual([
      process.execPath,
      "--no-warnings",
      scriptPath,
      "--resume",
    ]);

    await waitFor(() => {
      const hit = readLog(logPath).find((entry) => entry.active === "two");
      return hit;
    });

    const entries = readLog(logPath);
    const second = entries.find((entry) => entry.active === "two");
    expect(second?.home).toBe(two.dir);
    expect(second?.args).toEqual(["--resume"]);
    expect(currentProfile("fakeagent")?.name).toBe("two");

    await sendSupervisorRequest("fakeagent", { type: "stop" });
    expect(await running).toBe(0);
  } finally {
    process.env.FAKE_LOG = previousFakeLog;
    await sendSupervisorRequest("fakeagent", { type: "stop" }, { allowMissing: true }).catch(() => undefined);
  }
});
