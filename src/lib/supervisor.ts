import { spawn, type ChildProcess, type StdioOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { basename, join } from "node:path";
import { accountsHome, loadAppliedMap } from "../storage.js";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { prepareClaudeProfileKeychain } from "./claude-auth.js";
import { profileEnv, providerLaunchEnv } from "./env.js";
import { redactArgv, redactPublicValue, redactText } from "./redaction.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  publicSwitchResult,
  switchProfile,
  type PublicSwitchResult,
  type SwitchMode,
  type SwitchResult,
} from "./switch.js";
import { getTool } from "./tools.js";
import { configsSessionToolFor, runConfigsPrelaunch, type ConfigsPrelaunchOptions, type ConfigsPrelaunchResult } from "./configs-prelaunch.js";
import { getConfigsPrelaunchSummary, type ConfigsPrelaunchSummary } from "./configs-prelaunch-status.js";

export interface SupervisorState {
  version: 1;
  tool: string;
  profile: string;
  pid: number;
  childPid?: number;
  socketPath: string;
  command: string[];
  startedAt: string;
  updatedAt: string;
  prelaunch?: ConfigsPrelaunchSummary;
}

export type SupervisorRequest =
  | { type: "status" }
  | {
      type: "switch_profile";
      name: string;
      tool?: string;
      mode?: SwitchMode;
      resume?: boolean;
      args?: string[];
      permissions?: string;
      configsPrelaunch?: ConfigsPrelaunchOptions;
    }
  | { type: "stop" };

export type SupervisorResponse =
  | { ok: true; state: SupervisorState }
  | { ok: true; queued: true; result: PublicSwitchResult; state: SupervisorState; restartDelayMs: number }
  | { ok: true; stopping: true; state: SupervisorState }
  | { ok: false; error: string };

export interface SupervisorLaunchPlan {
  profile: Profile;
  tool: ToolDef;
  targetKind: "tool" | "profile";
}

export interface RunSupervisorOptions {
  stdio?: StdioOptions;
  restartDelayMs?: number;
  log?: (message: string) => void;
  configsPrelaunch?: ConfigsPrelaunchOptions;
}

export interface SupervisorClientOptions {
  timeoutMs?: number;
  allowMissing?: boolean;
}

const STATE_SUFFIX = ".json";

export function supervisorDir(): string {
  return join(accountsHome(), "supervisors");
}

export function supervisorStatePath(toolId: string): string {
  return join(supervisorDir(), `${toolId}${STATE_SUFFIX}`);
}

export function supervisorSocketPath(toolId: string): string {
  if (process.platform === "win32") {
    const hash = createHash("sha1").update(accountsHome()).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\hasna-accounts-${hash}-${toolId}`;
  }
  return join(supervisorDir(), `${toolId}.sock`);
}

function nowIso(): string {
  return new Date().toISOString();
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function projectState(value: unknown): SupervisorState | undefined {
  const data = objectValue(value);
  if (!data) return undefined;
  if (
    data["version"] !== 1 ||
    typeof data["tool"] !== "string" ||
    typeof data["profile"] !== "string" ||
    typeof data["pid"] !== "number" ||
    typeof data["socketPath"] !== "string" ||
    !Array.isArray(data["command"]) ||
    !data["command"].every((entry) => typeof entry === "string")
  ) {
    return undefined;
  }
  const state: SupervisorState = {
    version: 1,
    tool: redactText(data["tool"]),
    profile: redactText(data["profile"]),
    pid: data["pid"],
    ...(typeof data["childPid"] === "number" ? { childPid: data["childPid"] } : {}),
    socketPath: redactText(data["socketPath"]),
    command: redactArgv(data["command"] as string[]),
    startedAt: typeof data["startedAt"] === "string" ? redactText(data["startedAt"]) : "",
    updatedAt: typeof data["updatedAt"] === "string" ? redactText(data["updatedAt"]) : "",
  };
  if (data["prelaunch"] && typeof data["prelaunch"] === "object") {
    state.prelaunch = redactPublicValue(data["prelaunch"]) as ConfigsPrelaunchSummary;
  }
  return state;
}

function parseState(raw: string): SupervisorState | undefined {
  return projectState(JSON.parse(raw));
}

function projectSwitchResult(value: unknown): PublicSwitchResult | undefined {
  const data = objectValue(value);
  const profile = objectValue(data?.["profile"]);
  const tool = objectValue(data?.["tool"]);
  if (
    data?.["schema"] !== "hasna.accounts.switch-output/v1" ||
    typeof profile?.["name"] !== "string" ||
    typeof profile["tool"] !== "string" ||
    typeof tool?.["id"] !== "string" ||
    typeof tool["label"] !== "string" ||
    typeof data["applied"] !== "boolean" ||
    typeof data["active"] !== "boolean" ||
    !Array.isArray(data["command"]) ||
    !data["command"].every((entry) => typeof entry === "string") ||
    typeof data["commandLine"] !== "string" ||
    typeof data["restartRequired"] !== "boolean" ||
    typeof data["message"] !== "string"
  ) {
    return undefined;
  }
  return {
    schema: "hasna.accounts.switch-output/v1",
    profile: {
      name: redactText(profile["name"]),
      tool: redactText(profile["tool"]),
    },
    tool: {
      id: redactText(tool["id"]),
      label: redactText(tool["label"]),
    },
    applied: data["applied"],
    active: data["active"],
    command: redactArgv(data["command"] as string[]),
    commandLine: redactText(data["commandLine"]),
    ...(typeof data["permissions"] === "string"
      ? { permissions: redactText(data["permissions"]) }
      : {}),
    restartRequired: data["restartRequired"],
    message: redactText(data["message"]),
  };
}

function projectResponse(value: unknown): SupervisorResponse {
  const data = objectValue(value);
  if (!data || typeof data["ok"] !== "boolean") {
    throw new AccountsError("accounts supervisor returned an invalid response");
  }
  if (data["ok"] === false) {
    if (typeof data["error"] !== "string") {
      throw new AccountsError("accounts supervisor returned an invalid error response");
    }
    return { ok: false, error: redactText(data["error"]) };
  }

  const state = projectState(data["state"]);
  if (!state) throw new AccountsError("accounts supervisor returned an invalid state");
  if (data["queued"] === true) {
    const result = projectSwitchResult(data["result"]);
    if (!result || typeof data["restartDelayMs"] !== "number") {
      throw new AccountsError("accounts supervisor returned an invalid switch response");
    }
    return {
      ok: true,
      queued: true,
      result,
      state,
      restartDelayMs: data["restartDelayMs"],
    };
  }
  if (data["stopping"] === true) return { ok: true, stopping: true, state };
  return { ok: true, state };
}

export function readSupervisorState(toolId: string): SupervisorState | undefined {
  const path = supervisorStatePath(toolId);
  if (!existsSync(path)) return undefined;
  try {
    return parseState(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

export function listSupervisorStates(): SupervisorState[] {
  const dir = supervisorDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(STATE_SUFFIX))
    .map((name) => basename(name, STATE_SUFFIX))
    .map((toolId) => readSupervisorState(toolId))
    .filter((state): state is SupervisorState => state !== undefined);
}

function writeSupervisorState(state: SupervisorState): void {
  mkdirSync(supervisorDir(), { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") chmodSync(supervisorDir(), 0o700);
  writeFileSync(
    supervisorStatePath(state.tool),
    JSON.stringify({ ...state, command: redactArgv(state.command) }, null, 2) + "\n",
    { mode: 0o600 },
  );
  if (process.platform !== "win32") chmodSync(supervisorStatePath(state.tool), 0o600);
}

function removeSupervisorFiles(toolId: string): void {
  rmSync(supervisorStatePath(toolId), { force: true });
  if (process.platform !== "win32") rmSync(supervisorSocketPath(toolId), { force: true });
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function knownTool(id: string, store: AccountsStore): Promise<ToolDef | undefined> {
  try {
    return await store.resolveTool(id);
  } catch (error) {
    if (error instanceof AccountsError && /unknown tool/.test(error.message)) return undefined;
    throw error;
  }
}

/**
 * The machine-local `applied` pointer records which profile's auth is currently
 * live on this box (see apply.ts). The pointer's *name* is genuinely local, but
 * its full record is resolved through the Store — so in api mode we read the
 * cloud registry instead of local profile metadata.
 */
async function resolveAppliedProfile(toolId: string, store: AccountsStore): Promise<Profile | undefined> {
  const name = loadAppliedMap()[toolId];
  if (!name) return undefined;
  return store.findProfile(name, toolId);
}

export async function resolveSupervisorLaunch(
  target: string,
  opts: { profile?: string; tool?: string } = {},
  store: AccountsStore = resolveStore(),
): Promise<SupervisorLaunchPlan> {
  const targetTool = await knownTool(target, store);

  if (opts.profile) {
    const profile = await store.getProfile(opts.profile, opts.tool ?? targetTool?.id);
    if (targetTool && profile.tool !== targetTool.id) {
      throw new AccountsError(`profile "${profile.name}" belongs to ${profile.tool}, not ${targetTool.id}`);
    }
    return { profile, tool: getTool(profile.tool), targetKind: targetTool ? "tool" : "profile" };
  }

  if (targetTool && !opts.tool) {
    const profile = (await store.currentProfile(targetTool.id)) ?? (await resolveAppliedProfile(targetTool.id, store));
    if (!profile) {
      throw new AccountsError(
        `no active ${targetTool.label} profile. Run \`accounts use <name> --tool ${targetTool.id}\` or pass --profile.`,
      );
    }
    return { profile, tool: targetTool, targetKind: "tool" };
  }

  const profile = await store.getProfile(target, opts.tool);
  return { profile, tool: getTool(profile.tool), targetKind: "profile" };
}

function exitCode(code: number | null, signal: NodeJS.Signals | null): number {
  if (code !== null) return code;
  if (signal === "SIGINT") return 130;
  if (signal === "SIGTERM") return 143;
  return signal ? 1 : 0;
}

function killChildProcess(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // Fall back to the direct child if the process group no longer exists.
    }
  }
  child.kill(signal);
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function listen(server: Server, socketPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off("listening", onListening);
      reject(err);
    };
    const onListening = () => {
      server.off("error", onError);
      if (process.platform !== "win32") chmodSync(socketPath, 0o600);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    if (process.platform === "win32") {
      server.listen(socketPath);
      return;
    }
    const previousUmask = process.umask(0o177);
    try {
      server.listen(socketPath);
    } finally {
      process.umask(previousUmask);
    }
  });
}

export async function sendSupervisorRequest(
  toolId: string,
  request: SupervisorRequest,
  opts: SupervisorClientOptions = {},
): Promise<SupervisorResponse | undefined> {
  const timeoutMs = opts.timeoutMs ?? 1500;
  const socketPath = supervisorSocketPath(toolId);

  return await new Promise<SupervisorResponse | undefined>((resolve, reject) => {
    const socket = createConnection(socketPath);
    let buffer = "";
    let settled = false;

    const finish = (value: SupervisorResponse | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    };

    const fail = (err: Error & { code?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (opts.allowMissing && (err.code === "ENOENT" || err.code === "ECONNREFUSED")) {
        resolve(undefined);
      } else {
        reject(new AccountsError(`could not contact accounts supervisor for ${toolId}: ${err.message}`));
      }
    };

    const timer = setTimeout(() => {
      fail(Object.assign(new Error(`timed out after ${timeoutMs}ms`), { code: "ETIMEDOUT" }));
    }, timeoutMs);

    socket.setEncoding("utf8");
    socket.once("connect", () => {
      socket.write(JSON.stringify(request) + "\n");
    });
    socket.once("error", fail);
    socket.on("data", (chunk) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      try {
        finish(projectResponse(JSON.parse(buffer.slice(0, newline))));
      } catch (err) {
        fail(err as Error);
      }
    });
    socket.once("end", () => {
      if (!settled) fail(new Error("connection closed without a response"));
    });
  });
}

export async function runSupervisedTool(
  initialProfile: Profile,
  tool: ToolDef,
  initialArgs: string[] = [],
  opts: RunSupervisorOptions = {},
): Promise<number> {
  const socketPath = supervisorSocketPath(tool.id);
  const existing = readSupervisorState(tool.id);
  if (existing && processAlive(existing.pid)) {
    throw new AccountsError(`an accounts supervisor for ${tool.label} is already running (pid ${existing.pid})`);
  }
  removeSupervisorFiles(tool.id);
  mkdirSync(supervisorDir(), { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") chmodSync(supervisorDir(), 0o700);

  const startedAt = nowIso();
  const restartDelayMs = opts.restartDelayMs ?? 350;
  const log = opts.log ?? (() => undefined);
  const store = resolveStore();
  const server = createServer();
  let profile = initialProfile;
  let childArgs = initialArgs;
  let child: ChildProcess | undefined;
  let stopping = false;
  let restarting = false;
  let settled = false;

  const state = (): SupervisorState => ({
    version: 1,
    tool: tool.id,
    profile: profile.name,
    pid: process.pid,
    ...(child?.pid ? { childPid: child.pid } : {}),
    socketPath,
    command: redactArgv([tool.bin, ...childArgs]),
    startedAt,
    updatedAt: nowIso(),
    prelaunch: getConfigsPrelaunchSummary(profile, tool, configsSessionToolFor(tool)),
  });

  const persist = () => writeSupervisorState(state());

  const stopChild = async (): Promise<void> => {
    const target = child;
    if (!target || target.exitCode !== null) return;
    await new Promise<void>((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(killTimer);
        resolve();
      };
      const killTimer = setTimeout(() => {
        try {
          killChildProcess(target, "SIGKILL");
        } catch {
          finish();
        }
      }, 2500);
      target.once("exit", finish);
      try {
        killChildProcess(target, "SIGTERM");
      } catch {
        finish();
      }
    });
  };

  const cleanup = () => {
    server.close();
    removeSupervisorFiles(tool.id);
    process.off("SIGINT", onSigint);
    process.off("SIGTERM", onSigterm);
  };

  let resolveRun: (code: number) => void;
  const done = new Promise<number>((resolve) => {
    resolveRun = resolve;
  });

  const finishRun = (code: number) => {
    if (settled) return;
    settled = true;
    cleanup();
    resolveRun(code);
  };

  const configsOptionsFor = (request?: { configsPrelaunch?: ConfigsPrelaunchOptions }): ConfigsPrelaunchOptions | undefined => ({
    ...(opts.configsPrelaunch ?? {}),
    ...(request?.configsPrelaunch ?? {}),
  });

  const logConfigsResult = (configs: ConfigsPrelaunchResult, nextProfile: Profile, configOpts?: ConfigsPrelaunchOptions): void => {
    const mode = configOpts?.mode ?? "apply";
    if (configs.result === "applied" || configs.result === "planned") {
      log(`accounts supervisor: configs ${mode} ${configs.result} for ${tool.id}/${nextProfile.name}`);
      return;
    }
    if (configs.result === "skipped") {
      log(`accounts supervisor: configs skipped for ${tool.id}/${nextProfile.name}: ${configs.reason ?? "skip requested"}`);
      return;
    }
    if (configs.result === "bypassed") {
      log(`accounts supervisor: configs bypassed for ${tool.id}/${nextProfile.name}: ${configs.reason ?? "allow-failure"}`);
    }
  };

  const startChild = async (nextProfile: Profile, nextArgs: string[], preflightedConfigs?: ConfigsPrelaunchResult): Promise<void> => {
    const configOpts = configsOptionsFor();
    const configs = preflightedConfigs ?? runConfigsPrelaunch(nextProfile, tool, configOpts);
    logConfigsResult(configs, nextProfile, configOpts);
    profile = nextProfile;
    childArgs = nextArgs;
    // Mark this profile as the tool's active selection through the Store so the
    // shared registry (cloud in api mode) is the single source of truth — never
    // a local-only write that would diverge from the cloud "current".
    await store.useProfile(profile.name, tool.id);
    const env = profileEnv(profile, tool);
    log(`accounts supervisor: starting ${tool.bin} for ${profile.name}`);
    prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
    const proc = spawn(tool.bin, childArgs, {
      stdio: opts.stdio ?? "inherit",
      env: providerLaunchEnv(process.env, env, {
        ACCOUNTS_SUPERVISOR: "1",
        ACCOUNTS_ACTIVE: profile.name,
      }),
      detached: process.platform !== "win32",
    });
    child = proc;
    persist();

    proc.once("error", (err) => {
      log(`accounts supervisor: failed to start ${tool.bin}: ${redactText(err.message)}`);
      if (!restarting && !stopping) finishRun(1);
    });

    proc.once("exit", (code, signal) => {
      if (child === proc) child = undefined;
      persist();
      if (restarting || stopping) return;
      finishRun(exitCode(code, signal));
    });
  };

  const restartWith = async (result: SwitchResult, preflightedConfigs: ConfigsPrelaunchResult): Promise<void> => {
    restarting = true;
    try {
      await wait(restartDelayMs);
      await stopChild();
      await startChild(result.profile, result.command.slice(1), preflightedConfigs);
    } finally {
      restarting = false;
    }
  };

  const shutdown = async (code: number): Promise<void> => {
    if (stopping) return;
    stopping = true;
    await stopChild();
    finishRun(code);
  };

  const handleRequest = async (request: SupervisorRequest): Promise<SupervisorResponse> => {
    if (request.type === "status") return { ok: true, state: state() };
    if (request.type === "stop") {
      setTimeout(() => void shutdown(0), 25);
      return { ok: true, stopping: true, state: state() };
    }
    if (request.type !== "switch_profile") return { ok: false, error: "unknown supervisor request" };
    if (request.tool && request.tool !== tool.id) {
      return { ok: false, error: `this supervisor runs ${tool.id}, not ${request.tool}` };
    }
    try {
      const store = resolveStore();
      const nextProfile = await store.getProfile(request.name, tool.id);
      const configOpts = configsOptionsFor(request);
      const preflightedConfigs = runConfigsPrelaunch(nextProfile, tool, configOpts);
      const result = await switchProfile(request.name, {
        tool: tool.id,
        mode: request.mode ?? "auto",
        resume: request.resume ?? true,
        args: request.args ?? [],
        permissions: request.permissions,
      }, store);
      log(`accounts supervisor: switching ${tool.id} to ${result.profile.name}`);
      setTimeout(() => void restartWith(result, preflightedConfigs), 0);
      return { ok: true, queued: true, result: publicSwitchResult(result), state: state(), restartDelayMs };
    } catch (err) {
      return { ok: false, error: redactText(err instanceof Error ? err.message : String(err)) };
    }
  };

  server.on("connection", (socket: Socket) => {
    socket.setEncoding("utf8");
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      void (async () => {
        let response: SupervisorResponse;
        try {
          response = await handleRequest(JSON.parse(line) as SupervisorRequest);
        } catch (err) {
          response = { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
        socket.end(JSON.stringify(response) + "\n");
      })();
    });
  });

  const onSigint = () => void shutdown(130);
  const onSigterm = () => void shutdown(143);
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigterm);

  await listen(server, socketPath);
  await startChild(profile, childArgs);
  return await done;
}
