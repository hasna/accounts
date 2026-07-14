import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

function writeManifest(profile: { name: string; dir: string }, tool = "codewith") {
  mkdirSync(join(profile.dir, ".hasna"), { recursive: true });
  writeFileSync(
    join(profile.dir, ".hasna", "session-render-manifest.json"),
    JSON.stringify(
      {
        schema: "hasna.configs.session-render/v1",
        tool,
        profile: profile.name,
        targetHome: profile.dir,
        generatedAt: "2026-07-01T00:00:00.000Z",
        sources: [{ id: "global-codewith" }],
        files: [],
      },
      null,
      2,
    ) + "\n",
  );
}

async function listen(server: Server, socketPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", resolve);
    server.listen(socketPath);
  });
}

test("resolveSupervisorLaunch treats a known target as a tool and uses the active profile", async () => {
  addProfile({ name: "one", tool: "codex" });
  useProfile("one", "codex");

  const plan = await resolveSupervisorLaunch("codex");

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

test("supervisor switch preflights configs before queueing or stopping the current child", async () => {
  const logPath = join(home, "codewith-agent.log");
  const scriptPath = join(home, "codewith-agent.mjs");
  writeFileSync(
    scriptPath,
    [
      'import { appendFileSync } from "node:fs";',
      "appendFileSync(process.env.FAKE_LOG, JSON.stringify({",
      "  active: process.env.ACCOUNTS_ACTIVE,",
      "  home: process.env.CODEWITH_HOME,",
      "  args: process.argv.slice(2),",
      '}) + "\\n");',
      'process.on("SIGTERM", () => process.exit(0));',
      "setInterval(() => undefined, 1000);",
    ].join("\n"),
  );

  const one = addProfile({ name: "one", tool: "codewith" });
  const two = addProfile({ name: "two", tool: "codewith" });
  const bad = addProfile({ name: "bad", tool: "codewith" });
  const tool = { ...getTool("codewith"), bin: process.execPath, resumeArgs: [scriptPath] };
  const calls: string[][] = [];

  const previousFakeLog = process.env.FAKE_LOG;
  process.env.FAKE_LOG = logPath;
  const running = runSupervisedTool(one, tool, [scriptPath], {
    stdio: "ignore",
    restartDelayMs: 25,
    configsPrelaunch: {
      mode: "apply",
      runner: (bin, args) => {
        calls.push([bin, ...args]);
        if (args.includes("two")) return { status: 2, stdout: Buffer.from(""), stderr: Buffer.from("bad config") };
        if (args.includes("bad")) writeManifest(bad);
        else writeManifest(one);
        return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
      },
    },
  });

  try {
    await waitFor(() => (existsSync(supervisorSocketPath("codewith")) ? true : undefined));
    await waitFor(() => (readLog(logPath).some((entry) => entry.active === "one") ? true : undefined));

    const failed = await sendSupervisorRequest("codewith", {
      type: "switch_profile",
      name: "two",
      resume: false,
      args: [scriptPath],
    });

    expect(failed?.ok).toBe(false);
    expect(failed && !failed.ok ? failed.error : "").toContain("configs prelaunch apply failed");
    await sleep(75);
    expect(readLog(logPath).some((entry) => entry.active === "two")).toBe(false);
    expect(currentProfile("codewith")?.name).toBe("one");

    const callCountBeforeSkip = calls.length;
    const skipped = await sendSupervisorRequest("codewith", {
      type: "switch_profile",
      name: "two",
      resume: false,
      args: [scriptPath],
      configsPrelaunch: { mode: "skip" },
    });
    expect(skipped?.ok).toBe(true);
    await waitFor(() => readLog(logPath).find((entry) => entry.active === "two"));
    expect(calls.length).toBe(callCountBeforeSkip);
    expect(currentProfile("codewith")?.name).toBe("two");
    const statusAfterSkip = await sendSupervisorRequest("codewith", { type: "status" });
    expect(statusAfterSkip?.ok && "state" in statusAfterSkip ? statusAfterSkip.state.prelaunch?.status : "").toBe("skipped");
    expect(statusAfterSkip?.ok && "state" in statusAfterSkip ? statusAfterSkip.state.prelaunch?.lastRun?.reason : "").toBe("configs prelaunch skipped");

    const allowed = await sendSupervisorRequest("codewith", {
      type: "switch_profile",
      name: "bad",
      resume: false,
      args: [scriptPath],
      configsPrelaunch: { mode: "apply", allowFailure: true },
    });
    expect(allowed?.ok).toBe(true);
    await waitFor(() => readLog(logPath).find((entry) => entry.active === "bad"));
    expect(currentProfile("codewith")?.name).toBe(bad.name);
    expect(readLog(logPath).find((entry) => entry.active === "bad")?.home).toBe(bad.dir);
    expect(two.dir).toContain("two");
    const statusAfterAllowed = await sendSupervisorRequest("codewith", { type: "status" });
    expect(statusAfterAllowed?.ok && "state" in statusAfterAllowed ? statusAfterAllowed.state.prelaunch?.lastRun?.allowFailure : false).toBe(true);

    await sendSupervisorRequest("codewith", { type: "stop" });
    expect(await running).toBe(0);
  } finally {
    process.env.FAKE_LOG = previousFakeLog;
    await sendSupervisorRequest("codewith", { type: "stop" }, { allowMissing: true }).catch(() => undefined);
  }
});

test("switch --supervisor sends configs prelaunch flags to the supervisor", async () => {
  addProfile({ name: "two", tool: "codewith" });

  let request: unknown;
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      request = JSON.parse(chunk.trim());
      socket.end(
        JSON.stringify({
          ok: true,
          queued: true,
          result: { profile: { name: "two" }, command: ["codewith"], commandLine: "codewith" },
          state: { version: 1, tool: "codewith", profile: "one", pid: process.pid, socketPath: supervisorSocketPath("codewith"), command: ["codewith"], startedAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
          restartDelayMs: 1,
        }) + "\n",
      );
    });
  });

  try {
    rmSync(supervisorSocketPath("codewith"), { force: true });
    mkdirSync(dirname(supervisorSocketPath("codewith")), { recursive: true });
    await listen(server, supervisorSocketPath("codewith"));
    const proc = Bun.spawn({
      cmd: [
        process.execPath,
        "run",
        "src/cli.ts",
        "switch",
        "two",
        "--tool",
        "codewith",
        "--supervisor",
        "--configs",
        "apply",
        "--allow-configs-failure",
        "--configs-bin",
        "configs-dev",
        "--identity-export",
        "/tmp/account-agent.json",
        "--json",
      ],
      env: { ...process.env, ACCOUNTS_HOME: home },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      proc.exited,
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);

    expect({ exitCode, stdout, stderr }).toMatchObject({ exitCode: 0 });
    expect(request).toMatchObject({
      type: "switch_profile",
      name: "two",
      tool: "codewith",
      configsPrelaunch: {
        mode: "apply",
        allowFailure: true,
        configsBin: "configs-dev",
        identityExports: ["/tmp/account-agent.json"],
      },
    });
  } finally {
    server.close();
    rmSync(supervisorSocketPath("codewith"), { force: true });
  }
});
