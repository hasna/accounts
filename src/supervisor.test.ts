import { afterEach, beforeEach, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { addProfile, currentProfile, useProfile } from "./lib/profiles.js";
import { addCustomTool, getTool } from "./lib/tools.js";
import {
  listSupervisorStates,
  readSupervisorState,
  resolveSupervisorLaunch,
  runSupervisedTool,
  sendSupervisorRequest,
  supervisorSocketPath,
  supervisorStatePath,
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

function readLog(path: string): Array<{
  active: string;
  home: string;
  args: string[];
  requestDebug?: string[];
  path?: string;
}> {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as {
      active: string;
      home: string;
      args: string[];
      requestDebug?: string[];
      path?: string;
    });
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

test("accounts run/supervisor prelaunch passes --allow-empty-sources for identity-less profiles", async () => {
  // Regression for the live-bridge dead-letter: `accounts run codewith -p accountNNN`
  // (supervisor path) must render an explicit EMPTY session for a profile with no
  // identity/instruction sources instead of failing closed with
  // "Session render has no instruction sources".
  const scriptPath = join(home, "codewith-exec-once.mjs");
  writeFileSync(scriptPath, "process.exit(0);\n");

  const identityless = addProfile({ name: "account006", tool: "codewith" });
  const tool = { ...getTool("codewith"), bin: process.execPath };
  const calls: string[][] = [];

  const exitCode = await runSupervisedTool(identityless, tool, [scriptPath], {
    stdio: "ignore",
    restartDelayMs: 25,
    configsPrelaunch: {
      mode: "apply",
      runner: (bin, args) => {
        calls.push([bin, ...args]);
        // configs writes a valid sourceCount:0 manifest for an explicit empty render.
        mkdirSync(join(identityless.dir, ".hasna"), { recursive: true });
        writeFileSync(
          join(identityless.dir, ".hasna", "session-render-manifest.json"),
          JSON.stringify({
            schema: "hasna.configs.session-render/v1",
            tool: "codewith",
            profile: identityless.name,
            targetHome: identityless.dir,
            generatedAt: "2026-07-01T00:00:00.000Z",
            sources: [],
            files: [],
          }, null, 2) + "\n",
        );
        return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
      },
    },
  });

  expect(exitCode).toBe(0);
  const apply = calls.find((call) => call[1] === "session" && call[2] === "apply");
  expect(apply).toBeDefined();
  expect(apply).toContain("--allow-empty-sources");
  expect(apply).not.toContain("--identity-export");
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
      '  requestDebug: ["BUN_CONFIG_VERBOSE_FETCH", "NODE_DEBUG", "NODE_DEBUG_NATIVE"].filter((name) => process.env[name]),',
      "  path: process.env.PATH,",
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
  const previousRequestDebug = {
    BUN_CONFIG_VERBOSE_FETCH: process.env.BUN_CONFIG_VERBOSE_FETCH,
    NODE_DEBUG: process.env.NODE_DEBUG,
    NODE_DEBUG_NATIVE: process.env.NODE_DEBUG_NATIVE,
  };
  const inheritedPath = process.env.PATH;
  process.env.FAKE_LOG = logPath;
  process.env.BUN_CONFIG_VERBOSE_FETCH = "1";
  process.env.NODE_DEBUG = "http,http2";
  process.env.NODE_DEBUG_NATIVE = "http";
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
    expect(entries.every((entry) => entry.requestDebug?.length === 0)).toBe(true);
    expect(entries.every((entry) => entry.path === inheritedPath)).toBe(true);
    expect(currentProfile("fakeagent")?.name).toBe("two");

    await sendSupervisorRequest("fakeagent", { type: "stop" });
    expect(await running).toBe(0);
  } finally {
    process.env.FAKE_LOG = previousFakeLog;
    for (const [name, value] of Object.entries(previousRequestDebug)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await sendSupervisorRequest("fakeagent", { type: "stop" }, { allowMissing: true }).catch(() => undefined);
  }
});

test("supervisor keeps raw credential arguments transient while persistence and status stay redacted", async () => {
  const logPath = join(home, "credential-argv.log");
  const scriptPath = join(home, "credential-argv.mjs");
  writeFileSync(
    scriptPath,
    [
      'import { appendFileSync } from "node:fs";',
      'appendFileSync(process.env.FAKE_LOG, JSON.stringify({ args: process.argv.slice(2) }) + "\\n");',
      'process.on("SIGTERM", () => process.exit(0));',
      "setInterval(() => undefined, 1000);",
    ].join("\n"),
  );

  addCustomTool({
    id: "credentialagent",
    label: "Credential Agent",
    envVar: "FAKE_HOME",
    defaultDir: join(home, "credential-default"),
    bin: process.execPath,
    resumeArgs: [scriptPath, "--resume"],
  });
  const one = addProfile({ name: "one", tool: "credentialagent" });
  const two = addProfile({ name: "two", tool: "credentialagent" });
  const tool = getTool("credentialagent");
  const initialSecret = "supervisor-initial-api-secret";
  const switchedSecret = "supervisor-switched-consumer-secret";
  const previousFakeLog = process.env.FAKE_LOG;
  process.env.FAKE_LOG = logPath;
  const running = runSupervisedTool(
    one,
    tool,
    [scriptPath, "--api-key", initialSecret],
    { stdio: "ignore", restartDelayMs: 25 },
  );

  try {
    await waitFor(() => (existsSync(supervisorSocketPath("credentialagent")) ? true : undefined));
    await waitFor(() => {
      const entry = readLog(logPath).find((item) => item.args.includes(initialSecret));
      return entry;
    });

    const persistedInitial = readFileSync(supervisorStatePath("credentialagent"), "utf8");
    expect(persistedInitial).not.toContain(initialSecret);
    expect(persistedInitial).toContain("[REDACTED]");
    expect(JSON.stringify(readSupervisorState("credentialagent"))).not.toContain(initialSecret);
    expect(JSON.stringify(listSupervisorStates())).not.toContain(initialSecret);

    const liveInitial = await sendSupervisorRequest("credentialagent", { type: "status" });
    expect(JSON.stringify(liveInitial)).not.toContain(initialSecret);
    expect(JSON.stringify(liveInitial)).toContain("[REDACTED]");
    const initialStatusCli = Bun.spawn({
      cmd: [process.execPath, "run", "src/cli.ts", "supervisor", "status", "credentialagent", "--json"],
      env: { ...process.env, ACCOUNTS_HOME: home },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [initialStatusExit, initialStatusStdout, initialStatusStderr] = await Promise.all([
      initialStatusCli.exited,
      new Response(initialStatusCli.stdout).text(),
      new Response(initialStatusCli.stderr).text(),
    ]);
    expect(initialStatusExit, initialStatusStderr).toBe(0);
    expect(initialStatusStdout).not.toContain(initialSecret);
    expect(initialStatusStdout).toContain("[REDACTED]");

    const switched = await sendSupervisorRequest("credentialagent", {
      type: "switch_profile",
      name: two.name,
      resume: false,
      args: [scriptPath, `--consumerSecret=${switchedSecret}`],
    });
    expect(JSON.stringify(switched)).not.toContain(switchedSecret);
    expect(JSON.stringify(switched)).toContain("[REDACTED]");

    await waitFor(() => {
      const entry = readLog(logPath).find((item) => item.args.includes(`--consumerSecret=${switchedSecret}`));
      return entry;
    });
    const persistedSwitched = readFileSync(supervisorStatePath("credentialagent"), "utf8");
    expect(persistedSwitched).not.toContain(switchedSecret);
    expect(persistedSwitched).toContain("--consumerSecret=[REDACTED]");
    const liveSwitched = await sendSupervisorRequest("credentialagent", { type: "status" });
    expect(JSON.stringify(liveSwitched)).not.toContain(switchedSecret);
    const switchedStatusCli = Bun.spawn({
      cmd: [process.execPath, "run", "src/cli.ts", "supervisor", "status", "credentialagent"],
      env: { ...process.env, ACCOUNTS_HOME: home, NO_COLOR: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [switchedStatusExit, switchedStatusStdout, switchedStatusStderr] = await Promise.all([
      switchedStatusCli.exited,
      new Response(switchedStatusCli.stdout).text(),
      new Response(switchedStatusCli.stderr).text(),
    ]);
    expect(switchedStatusExit, switchedStatusStderr).toBe(0);
    expect(switchedStatusStdout).not.toContain(switchedSecret);
    expect(switchedStatusStdout).toContain("--consumerSecret=[REDACTED]");

    await sendSupervisorRequest("credentialagent", { type: "stop" });
    expect(await running).toBe(0);
  } finally {
    process.env.FAKE_LOG = previousFakeLog;
    await sendSupervisorRequest("credentialagent", { type: "stop" }, { allowMissing: true }).catch(() => undefined);
  }
});

test("legacy supervisor state is redacted defensively when read", () => {
  mkdirSync(dirname(supervisorStatePath("codewith")), { recursive: true });
  writeFileSync(
    supervisorStatePath("codewith"),
    JSON.stringify({
      version: 1,
      tool: "codewith",
      profile: "one",
      pid: 123,
      socketPath: supervisorSocketPath("codewith"),
      command: ["codewith", "--webhookCredential", "legacy-supervisor-secret"],
      args: ["--passphrase", "legacy-unknown-args-secret"],
      lastError: "oauth.key=legacy-last-error-secret",
      custom: { "session key": "legacy-custom-secret" },
      startedAt: "2026-07-27T00:00:00.000Z",
      updatedAt: "2026-07-27T00:00:00.000Z",
    }),
  );

  const state = readSupervisorState("codewith");
  expect(state?.command).toEqual(["codewith", "--webhookCredential", "[REDACTED]"]);
  expect(state).not.toHaveProperty("args");
  expect(state).not.toHaveProperty("lastError");
  expect(state).not.toHaveProperty("custom");
  for (const secret of [
    "legacy-supervisor-secret",
    "legacy-unknown-args-secret",
    "legacy-last-error-secret",
    "legacy-custom-secret",
  ]) {
    expect(JSON.stringify(state)).not.toContain(secret);
  }
});

test("supervisor public switch response is a strict safe DTO and filesystem is owner-only", async () => {
  const logPath = join(home, "safe-dto.log");
  const scriptPath = join(home, "safe-dto.mjs");
  writeFileSync(
    scriptPath,
    [
      'import { appendFileSync } from "node:fs";',
      'appendFileSync(process.env.FAKE_LOG, JSON.stringify({ args: process.argv.slice(2), secret: process.env.SERVICE_API_KEY }) + "\\n");',
      'process.on("SIGTERM", () => process.exit(0));',
      "setInterval(() => undefined, 1000);",
    ].join("\n"),
  );

  const envSecret = "supervisor-extra-env-secret";
  const argSecret = "supervisor-short-arg-secret";
  addCustomTool({
    id: "safedto",
    label: "Safe DTO",
    envVar: "SAFE_DTO_HOME",
    extraEnv: { SERVICE_API_KEY: envSecret },
    defaultDir: join(home, "safe-dto-default"),
    bin: process.execPath,
    resumeArgs: [scriptPath],
  });
  const one = addProfile({ name: "one", tool: "safedto" });
  const two = addProfile({ name: "two", tool: "safedto" });
  const previousFakeLog = process.env.FAKE_LOG;
  process.env.FAKE_LOG = logPath;
  if (process.platform !== "win32") {
    mkdirSync(dirname(supervisorSocketPath("safedto")), { recursive: true, mode: 0o777 });
    chmodSync(dirname(supervisorSocketPath("safedto")), 0o777);
  }
  const running = runSupervisedTool(one, getTool("safedto"), [scriptPath], {
    stdio: "ignore",
    restartDelayMs: 25,
  });

  try {
    await waitFor(() => (existsSync(supervisorSocketPath("safedto")) ? true : undefined));
    if (process.platform !== "win32") {
      expect(statSync(dirname(supervisorSocketPath("safedto"))).mode & 0o777).toBe(0o700);
      expect(statSync(supervisorSocketPath("safedto")).mode & 0o777).toBe(0o600);
      await waitFor(() => (existsSync(supervisorStatePath("safedto")) ? true : undefined));
      expect(statSync(supervisorStatePath("safedto")).mode & 0o777).toBe(0o600);
    }

    const response = await sendSupervisorRequest("safedto", {
      type: "switch_profile",
      name: two.name,
      resume: false,
      args: [scriptPath, "-k", argSecret],
    });
    const publicJson = JSON.stringify(response);
    expect(publicJson).not.toContain(argSecret);
    expect(publicJson).not.toContain(envSecret);
    const publicResult = response?.ok && "queued" in response ? response.result : undefined;
    expect(publicResult).toEqual({
      schema: "hasna.accounts.switch-output/v1",
      profile: { name: "two", tool: "safedto" },
      tool: { id: "safedto", label: "Safe DTO" },
      applied: false,
      active: true,
      command: [process.execPath, scriptPath, "-k", "[REDACTED]"],
      commandLine: publicResult?.commandLine,
      restartRequired: false,
      message: "two is now the active Safe DTO profile",
    });
    expect(publicResult?.commandLine).toContain("'-k' '[REDACTED]'");
    expect(response?.ok && "queued" in response ? response.result : undefined).not.toHaveProperty("env");
    expect(response?.ok && "queued" in response ? response.result : undefined).not.toHaveProperty("exports");
    await waitFor(() => readLog(logPath).find((entry) => entry.args.includes(argSecret)));

    await sendSupervisorRequest("safedto", { type: "stop" });
    expect(await running).toBe(0);
  } finally {
    process.env.FAKE_LOG = previousFakeLog;
    await sendSupervisorRequest("safedto", { type: "stop" }, { allowMissing: true }).catch(() => undefined);
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

  const responseSecret = "malicious-response-extra-env-secret";
  let request: unknown;
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      request = JSON.parse(chunk.trim());
      socket.end(
        JSON.stringify({
          ok: true,
          queued: true,
          result: {
            schema: "hasna.accounts.switch-output/v1",
            profile: { name: "two", tool: "codewith" },
            tool: { id: "codewith", label: "Codewith" },
            applied: false,
            active: true,
            command: ["codewith"],
            commandLine: "codewith",
            restartRequired: true,
            message: "two is now the active Codewith profile",
            env: { SERVICE_API_KEY: responseSecret },
            exports: `export SERVICE_API_KEY=${responseSecret}`,
          },
          state: {
            version: 1,
            tool: "codewith",
            profile: "one",
            pid: process.pid,
            socketPath: supervisorSocketPath("codewith"),
            command: ["codewith"],
            args: ["--api-key", responseSecret],
            lastError: `oauth.key=${responseSecret}`,
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          restartDelayMs: 1,
          extra: { passphrase: responseSecret },
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
    expect(`${stdout}${stderr}`).not.toContain(responseSecret);
    const publicResponse = JSON.parse(stdout) as {
      result: Record<string, unknown>;
      state: Record<string, unknown>;
    };
    expect(publicResponse.result).not.toHaveProperty("env");
    expect(publicResponse.result).not.toHaveProperty("exports");
    expect(publicResponse.state).not.toHaveProperty("args");
    expect(publicResponse.state).not.toHaveProperty("lastError");
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
