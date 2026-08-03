import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeUsageCache } from "./lib/auto-switch.js";
import { BUILTIN_TOOLS } from "./lib/builtin-tools.js";
import { writeSwitchedAccountMarker } from "./lib/claude-auth.js";
import {
  scanToolProcessesWithAvailability,
  type ProcessInfo,
} from "./lib/agents.js";
import { resolveStore } from "./lib/store.js";
import { parseUsageResponse } from "./lib/usage.js";
import { collectProfilesUsage } from "./lib/usage-report.js";
import { saveStore } from "./storage.js";
import type { Profile, Store, ToolDef } from "./types.js";

const ACCOUNT_UUID = "11111111-1111-4111-8111-111111111111";
const CREATED_AT = "2026-08-01T08:00:00.000Z";
const SELECTED_AT = "2026-08-02T09:00:00.000Z";
const SWITCHED_AT = "2026-08-03T10:00:00.000Z";
const FIXTURE_SECRET = "synthetic-usage-profile-private-material";
const PROCESS_SECRET = "synthetic-process-private-material";

const CUSTOM_TOOL: ToolDef = {
  id: "new-agent",
  label: "New Agent",
  envVar: "NEW_AGENT_HOME",
  defaultDir: "/unused/new-agent",
  bin: "new-agent",
};

const PROFILE_TOOLS = [
  "claude",
  "codex",
  "codex-app",
  "codewith",
  "cursor",
  "opencode",
  CUSTOM_TOOL.id,
] as const;

let home: string;
let root: string;
let binDir: string;
let profiles: Profile[];

function tool(id: string): ToolDef {
  if (id === CUSTOM_TOOL.id) return CUSTOM_TOOL;
  const found = BUILTIN_TOOLS.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`missing built-in fixture tool ${id}`);
  return found;
}

function fixtureEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ACCOUNTS_HOME: home,
    PATH: `${binDir}:${process.env.PATH ?? ""}`,
    HASNA_ACCOUNTS_INVARIANT_QUIET: "1",
  };
}

function writeFakeBin(name: string): void {
  const path = join(binDir, name);
  writeFileSync(path, "#!/bin/sh\nexit 0\n");
  chmodSync(path, 0o755);
}

function writeClaudeAuth(profile: Profile): void {
  const accessKey = "access" + "Token";
  const refreshKey = "refresh" + "Token";
  const identity = JSON.stringify({
    oauthAccount: { accountUuid: ACCOUNT_UUID, emailAddress: profile.email },
  }) + "\n";
  const credentials = JSON.stringify({
    claudeAiOauth: {
      [accessKey]: `${FIXTURE_SECRET}-access`,
      [refreshKey]: `${FIXTURE_SECRET}-refresh`,
      expiresAt: Date.now() + 60 * 60 * 1000,
    },
  }) + "\n";
  writeFileSync(
    join(profile.dir, ".claude.json"),
    identity,
  );
  writeFileSync(join(profile.dir, ".credentials.json"), credentials);
}

function parkClaudeAuth(profile: Profile): void {
  const accessKey = "access" + "Token";
  const refreshKey = "refresh" + "Token";
  const authDir = join(profile.dir, ".accounts-auth");
  mkdirSync(authDir, { recursive: true });
  writeFileSync(
    join(authDir, "oauth-account.json"),
    JSON.stringify({
      oauthAccount: { accountUuid: ACCOUNT_UUID, emailAddress: profile.email },
    }) + "\n",
  );
  writeFileSync(
    join(authDir, "credentials.json"),
    JSON.stringify({
      claudeAiOauth: {
        [accessKey]: `${FIXTURE_SECRET}-parked-access`,
        [refreshKey]: `${FIXTURE_SECRET}-parked-refresh`,
        expiresAt: Date.now() + 60 * 60 * 1000,
      },
    }) + "\n",
  );
}

function usageShape(sessionPercent: number, weeklyPercent?: number): Record<string, unknown> {
  return {
    limits: [
      {
        kind: "session",
        group: "session",
        percent: sessionPercent,
        resets_at: null,
        scope: null,
        is_active: false,
      },
      ...(weeklyPercent === undefined
        ? []
        : [
            {
              kind: "weekly_all",
              group: "weekly",
              percent: weeklyPercent,
              resets_at: null,
              scope: null,
              is_active: false,
            },
          ]),
    ],
  };
}

function cacheUsage(sessionPercent: number, weeklyPercent?: number): void {
  const fetchedAt = new Date().toISOString();
  const usage = parseUsageResponse(usageShape(sessionPercent, weeklyPercent));
  writeUsageCache({ accountUuid: ACCOUNT_UUID, fetchedAt, usage });
}

function countingFetch(body = usageShape(25, 40)): { impl: typeof fetch; calls: () => number } {
  let count = 0;
  const impl = (async () => {
    count += 1;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { impl, calls: () => count };
}

function runUsageCli(args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", "usage", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: fixtureEnv(),
  });
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-usage-profiles-home-"));
  root = mkdtempSync(join(tmpdir(), "accounts-usage-profiles-root-"));
  binDir = mkdtempSync(join(tmpdir(), "accounts-usage-profiles-bin-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;

  for (const name of ["claude", "codex", "codewith", "cursor-agent", "opencode", "new-agent"]) {
    writeFakeBin(name);
  }

  profiles = PROFILE_TOOLS.map((toolId, index) => {
    const dir = join(root, `${toolId}-profile`);
    mkdirSync(dir, { recursive: true });
    return {
      name: `${toolId}-profile`,
      tool: toolId,
      email: `${toolId}@example.test`,
      dir,
      createdAt: CREATED_AT,
      lastUsedAt: index === 0 ? SELECTED_AT : CREATED_AT,
    };
  });
  writeClaudeAuth(profiles[0]!);

  const store: Store = {
    version: 1,
    current: { claude: "claude-profile", codewith: "codewith-profile" },
    applied: { claude: "claude-profile" },
    toolLocks: {},
    profiles,
    tools: [CUSTOM_TOOL],
  };
  saveStore(store);
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  rmSync(binDir, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});

test("default profile usage covers every registered tool, stays cache-only, and exposes safe selection signals", async () => {
  const fetched = countingFetch();
  const scanner = (toolId: string): ProcessInfo[] => {
    if (toolId === "claude") {
      return [{
        pid: 101,
        ppid: 1,
        command: `claude --credential ${PROCESS_SECRET}`,
        configDir: profiles[0]!.dir,
      }];
    }
    if (toolId === "codewith") {
      return [{ pid: 102, ppid: 1, command: `codewith --credential ${PROCESS_SECRET}` }];
    }
    return [];
  };

  const report = await collectProfilesUsage(
    { env: fixtureEnv(), fetchImpl: fetched.impl, processScanner: scanner },
    resolveStore(fixtureEnv()),
  );
  const byTool = new Map(report.profiles.map((profile) => [profile.tool, profile]));

  expect(report.schema).toBe("hasna.accounts.usage-profiles/v1");
  expect(report.profiles.map((profile) => profile.tool).sort()).toEqual([...PROFILE_TOOLS].sort());
  expect(byTool.has(CUSTOM_TOOL.id)).toBe(true);
  expect(fetched.calls()).toBe(0);

  expect(byTool.get("claude")?.usage).toEqual({
    kind: "readiness-proxy",
    status: "degraded",
    reason: "no-cached-rate-limit-data",
  });
  expect(byTool.get("opencode")?.usage).toMatchObject({
    kind: "readiness-proxy",
    reason: "provider-rate-limit-unavailable",
  });

  expect(byTool.get("claude")?.occupancy).toMatchObject({
    status: "occupied",
    processCount: 1,
    unattributedProcessCount: 0,
  });
  expect(byTool.get("codex")?.occupancy.status).toBe("vacant");
  expect(byTool.get("codewith")?.occupancy).toMatchObject({
    status: "unknown",
    processCount: 0,
    unattributedProcessCount: 1,
  });

  expect(byTool.get("claude")?.active).toBe(true);
  expect(byTool.get("claude")?.applied).toBe(true);
  expect(byTool.get("codewith")?.active).toBe(true);
  expect(byTool.get("codewith")?.applied).toBe(false);
  expect(byTool.get("claude")?.launchable.status).toBe("yes");
  expect(byTool.get("opencode")?.launchable).toEqual({
    status: "unknown",
    reason: "auth-not-locally-verifiable",
  });
  expect(byTool.get("codex-app")?.launchable).toEqual({
    status: "no",
    reason: "provider-unavailable",
  });

  expect(report.accounts).toHaveLength(1);
  expect(report.accounts[0]).toMatchObject({
    accountUuid: ACCOUNT_UUID,
    profiles: ["claude-profile"],
    source: "none",
  });

  const profileJson = JSON.stringify(report.profiles);
  for (const forbidden of [
    FIXTURE_SECRET,
    PROCESS_SECRET,
    root,
    profiles[0]!.dir,
    "access" + "Token",
    "refresh" + "Token",
    "authorization",
    "apiKey",
  ]) {
    expect(profileJson).not.toContain(forbidden);
  }
});

test("unavailable process coverage stays unknown instead of reporting every profile vacant", async () => {
  const report = await collectProfilesUsage(
    {
      env: fixtureEnv(),
      processScanner: () => ({ available: false, processes: [] }),
    },
    resolveStore(fixtureEnv()),
  );

  expect(report.profiles.every((profile) => profile.occupancy.status === "unknown")).toBe(true);
  expect(report.profiles.every((profile) => profile.occupancy.scanAvailable === false)).toBe(true);
});

test("the default scanner declares platforms without Linux process attribution unavailable", () => {
  expect(scanToolProcessesWithAvailability("claude", "darwin")).toEqual({
    available: false,
    processes: [],
  });
  expect(scanToolProcessesWithAvailability("claude", "win32")).toEqual({
    available: false,
    processes: [],
  });
});

test("tool filtering returns only that registered profile and scans only that tool", async () => {
  const scanned: string[] = [];
  const report = await collectProfilesUsage(
    {
      tool: "codex",
      env: fixtureEnv(),
      processScanner: (toolId) => {
        scanned.push(toolId);
        return [];
      },
    },
    resolveStore(fixtureEnv()),
  );

  expect(report.profiles.map((profile) => `${profile.tool}/${profile.name}`)).toEqual([
    "codex/codex-profile",
  ]);
  expect(report.accounts).toEqual([]);
  expect(scanned).toEqual(["codex"]);

  const cli = runUsageCli(["--tool", "codex", "--json"]);
  expect(cli.status).toBe(0);
  const cliJson = JSON.parse(cli.stdout) as {
    tool: string;
    profiles: Array<{ tool: string; name: string }>;
    accounts: unknown[];
  };
  expect(cliJson.tool).toBe("codex");
  expect(cliJson.profiles).toEqual([
    expect.objectContaining({ tool: "codex", name: "codex-profile" }),
  ]);
  expect(cliJson.accounts).toEqual([]);
});

test("cached Claude usage reports both measured axes, prefers a newer in-place switch, and never invents a missing axis", async () => {
  cacheUsage(30, 55);
  parkClaudeAuth(profiles[0]!);
  writeSwitchedAccountMarker(profiles[0]!.dir, {
    profile: "visitor-profile",
    switchedAt: SWITCHED_AT,
  });

  const both = await collectProfilesUsage(
    { env: fixtureEnv(), processScanner: () => [] },
    resolveStore(fixtureEnv()),
  );
  const claude = both.profiles.find((profile) => profile.tool === "claude")!;
  const codex = both.profiles.find((profile) => profile.tool === "codex")!;

  expect(claude.usage).toMatchObject({
    kind: "rate-limit",
    source: "cache",
    sessionHeadroom: 70,
    weeklyHeadroom: 45,
  });
  expect(claude.lastSwitchAt).toBe(SWITCHED_AT);
  expect(claude.lastSwitchSource).toBe("in-place-switch");
  expect(codex.lastSwitchAt).toBe(CREATED_AT);
  expect(codex.lastSwitchSource).toBe("profile-selection");

  cacheUsage(20);
  const oneAxis = await collectProfilesUsage(
    { env: fixtureEnv(), processScanner: () => [] },
    resolveStore(fixtureEnv()),
  );
  expect(oneAxis.profiles.find((profile) => profile.tool === "claude")?.usage).toMatchObject({
    kind: "rate-limit",
    sessionHeadroom: 80,
    weeklyHeadroom: null,
  });
});

test("refresh is the explicit provider-fetch gate and still fetches once per distinct Claude account", async () => {
  const fetched = countingFetch(usageShape(25, 40));
  const report = await collectProfilesUsage(
    { refresh: true, env: fixtureEnv(), fetchImpl: fetched.impl, processScanner: () => [] },
    resolveStore(fixtureEnv()),
  );

  expect(fetched.calls()).toBe(1);
  expect(report.profiles.find((profile) => profile.tool === "claude")?.usage).toMatchObject({
    kind: "rate-limit",
    source: "fetch",
    sessionHeadroom: 75,
    weeklyHeadroom: 60,
  });
});

test("usage CLI emits versioned backwards-compatible JSON and safe cross-tool human output", () => {
  cacheUsage(35, 50);

  const jsonRun = runUsageCli(["--json"]);
  expect(jsonRun.status).toBe(0);
  expect(jsonRun.stderr).toBe("");
  const output = JSON.parse(jsonRun.stdout) as Record<string, unknown>;
  expect(output.schema).toBe("hasna.accounts.usage-profiles/v1");
  expect(Array.isArray(output.profiles)).toBe(true);
  expect((output.profiles as unknown[]).length).toBe(PROFILE_TOOLS.length);
  expect(Array.isArray(output.accounts)).toBe(true);
  expect((output.accounts as Array<Record<string, unknown>>)[0]?.accountUuid).toBe(ACCOUNT_UUID);

  const humanRun = runUsageCli([]);
  expect(humanRun.status).toBe(0);
  expect(humanRun.stderr).toBe("");
  expect(humanRun.stdout).toContain("claude/claude-profile");
  expect(humanRun.stdout).toContain(`${CUSTOM_TOOL.id}/${CUSTOM_TOOL.id}-profile`);
  expect(humanRun.stdout).toContain("usage unknown; readiness");
  expect(humanRun.stdout).toContain("launchable");

  for (const rendered of [jsonRun.stdout, humanRun.stdout]) {
    for (const forbidden of [
      FIXTURE_SECRET,
      PROCESS_SECRET,
      root,
      profiles[0]!.dir,
      "access" + "Token",
      "refresh" + "Token",
      "authorization",
      "apiKey",
    ]) {
      expect(rendered).not.toContain(forbidden);
    }
  }
});
