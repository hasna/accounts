import { spawn, type ChildProcess, type StdioOptions } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { basename, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { accountsHome, loadAppliedMap } from "../storage.js";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { prepareClaudeProfileKeychain } from "./claude-auth.js";
import { profileEnv, providerLaunchEnv } from "./env.js";
import { redactArgv, redactText } from "./redaction.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  publicSwitchResult,
  publicSwitchMessage,
  publicToolLabel,
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
let stateWriteSequence = 0;

interface SupervisorBoundary {
  home: string;
  dir: string;
  realHome: string;
  realDir: string;
  homeIdentity: string;
  dirIdentity: string;
}

function lstatIfExists(path: string) {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function isAllowedSystemDirectorySymlink(path: string): boolean {
  if (path !== "/var" && path !== "/tmp") return false;
  try {
    return realpathSync.native(path) === `/private${path}`;
  } catch {
    return false;
  }
}

function pathIdentity(path: string): string {
  const stat = statSync(path);
  return `${stat.dev}:${stat.ino}`;
}

function statIdentity(stat: ReturnType<typeof fstatSync>): string {
  return `${stat.dev}:${stat.ino}`;
}

function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (
    rel !== ".." &&
    !rel.startsWith(`..${sep}`) &&
    !isAbsolute(rel)
  );
}

function prepareSupervisorBoundary(
  create: boolean,
  expected?: SupervisorBoundary,
): SupervisorBoundary | undefined {
  const home = resolve(accountsHome());
  const dir = join(home, "supervisors");
  const root = parse(dir).root;
  const segments = relative(root, dir).split(sep).filter(Boolean);
  let cursor = root;

  for (const segment of segments) {
    cursor = join(cursor, segment);
    let stat = lstatIfExists(cursor);
    if (!stat) {
      if (!create) return undefined;
      mkdirSync(cursor, { mode: 0o700 });
      stat = lstatSync(cursor);
    }
    if (stat.isSymbolicLink()) {
      const isBoundaryComponent = cursor === home || cursor === dir;
      if (isBoundaryComponent || !isAllowedSystemDirectorySymlink(cursor)) {
        throw new AccountsError(
          `refusing unsafe supervisor symlink boundary: ${cursor}`,
        );
      }
      continue;
    }
    if (!stat.isDirectory()) {
      throw new AccountsError(
        `refusing non-directory supervisor boundary: ${cursor}`,
      );
    }
  }

  const realHome = realpathSync.native(home);
  const realDir = realpathSync.native(dir);
  if (!isInside(realDir, realHome)) {
    throw new AccountsError(
      `refusing supervisor directory outside ACCOUNTS_HOME: ${dir}`,
    );
  }
  const boundary: SupervisorBoundary = {
    home,
    dir,
    realHome,
    realDir,
    homeIdentity: pathIdentity(realHome),
    dirIdentity: pathIdentity(realDir),
  };
  if (
    expected &&
    (
      boundary.home !== expected.home ||
      boundary.dir !== expected.dir ||
      boundary.realHome !== expected.realHome ||
      boundary.realDir !== expected.realDir ||
      boundary.homeIdentity !== expected.homeIdentity ||
      boundary.dirIdentity !== expected.dirIdentity
    )
  ) {
    throw new AccountsError("supervisor filesystem boundary changed during operation");
  }
  return boundary;
}

function ensureSupervisorBoundary(): SupervisorBoundary {
  const boundary = prepareSupervisorBoundary(true)!;
  if (process.platform !== "win32") {
    const descriptor = openSync(
      boundary.realDir,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      if (statIdentity(fstatSync(descriptor)) !== boundary.dirIdentity) {
        throw new AccountsError("supervisor directory changed before chmod");
      }
      fchmodSync(descriptor, 0o700);
    } finally {
      closeSync(descriptor);
    }
    prepareSupervisorBoundary(false, boundary);
  }
  return boundary;
}

function requireStableBoundary(boundary: SupervisorBoundary): SupervisorBoundary {
  return prepareSupervisorBoundary(false, boundary)!;
}

function assertToolId(toolId: string): void {
  if (!PUBLIC_ID_PATTERN.test(toolId)) {
    throw new AccountsError(`invalid supervisor tool id: ${redactText(toolId)}`);
  }
}

function statePathAt(boundary: SupervisorBoundary, toolId: string): string {
  assertToolId(toolId);
  return join(boundary.dir, `${toolId}${STATE_SUFFIX}`);
}

function socketPathAt(boundary: SupervisorBoundary, toolId: string): string {
  assertToolId(toolId);
  return join(boundary.dir, `${toolId}.sock`);
}

function assertStateLeaf(path: string): void {
  const stat = lstatIfExists(path);
  if (!stat) return;
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new AccountsError(`refusing unsafe supervisor state path: ${path}`);
  }
}

function assertSocketLeaf(path: string): void {
  const stat = lstatIfExists(path);
  if (!stat) return;
  if (stat.isSymbolicLink() || !stat.isSocket()) {
    throw new AccountsError(`refusing non-socket supervisor control path: ${path}`);
  }
}

export function supervisorDir(): string {
  return join(resolve(accountsHome()), "supervisors");
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

const PUBLIC_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PRELAUNCH_DRIFT = new Set([
  "ok",
  "missing",
  "invalid",
  "mismatch",
  "stale",
  "unsupported",
]);
const PRELAUNCH_STATUS = new Set([
  ...PRELAUNCH_DRIFT,
  "planned",
  "skipped",
  "failed",
  "bypassed",
]);
const PRELAUNCH_RESULT = new Set([
  "applied",
  "planned",
  "skipped",
  "failed",
  "bypassed",
]);
const PRELAUNCH_MODE = new Set(["plan", "apply", "skip"]);

function boundedPublicString(
  value: unknown,
  maxLength: number,
): string | undefined {
  return typeof value === "string"
    ? redactText(value.slice(0, maxLength))
    : undefined;
}

function boundedPublicStrings(
  value: unknown,
  maxItems: number,
  maxLength: number,
): string[] | undefined {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    return undefined;
  }
  return value
    .slice(0, maxItems)
    .map((entry) => redactText(entry.slice(0, maxLength)));
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function projectPrelaunchManifest(
  value: unknown,
): ConfigsPrelaunchSummary["manifest"] | undefined {
  const data = objectValue(value);
  const path = boundedPublicString(data?.["path"], 4096);
  const sourceIds = boundedPublicStrings(data?.["sourceIds"], 20, 128);
  const sourceCount = finiteNumber(data?.["sourceCount"]);
  const drift = data?.["drift"];
  const reasons = boundedPublicStrings(data?.["reasons"], 6, 220);
  if (
    !data ||
    path === undefined ||
    typeof data["exists"] !== "boolean" ||
    sourceIds === undefined ||
    sourceCount === undefined ||
    typeof data["sourceIdsTruncated"] !== "boolean" ||
    typeof drift !== "string" ||
    !PRELAUNCH_DRIFT.has(drift) ||
    reasons === undefined
  ) {
    return undefined;
  }
  const fileCount = finiteNumber(data["fileCount"]);
  return {
    path,
    exists: data["exists"],
    ...(boundedPublicString(data["hash"], 128) !== undefined
      ? { hash: boundedPublicString(data["hash"], 128) }
      : {}),
    ...(boundedPublicString(data["schema"], 128) !== undefined
      ? { schema: boundedPublicString(data["schema"], 128) }
      : {}),
    ...(boundedPublicString(data["tool"], 128) !== undefined
      ? { tool: boundedPublicString(data["tool"], 128) }
      : {}),
    ...(boundedPublicString(data["profile"], 128) !== undefined
      ? { profile: boundedPublicString(data["profile"], 128) }
      : {}),
    ...(boundedPublicString(data["targetHome"], 4096) !== undefined
      ? { targetHome: boundedPublicString(data["targetHome"], 4096) }
      : {}),
    ...(boundedPublicString(data["generatedAt"], 128) !== undefined
      ? { generatedAt: boundedPublicString(data["generatedAt"], 128) }
      : {}),
    sourceIds,
    sourceCount,
    sourceIdsTruncated: data["sourceIdsTruncated"],
    ...(fileCount !== undefined ? { fileCount } : {}),
    drift: drift as ConfigsPrelaunchSummary["manifest"]["drift"],
    reasons,
  };
}

function projectPrelaunchAudit(
  value: unknown,
): NonNullable<ConfigsPrelaunchSummary["lastRun"]> | undefined {
  const data = objectValue(value);
  const manifest = objectValue(data?.["manifest"]);
  const mode = data?.["mode"];
  const result = data?.["result"];
  const drift = manifest?.["drift"];
  const sourceIds = boundedPublicStrings(manifest?.["sourceIds"], 20, 128);
  const sourceCount = finiteNumber(manifest?.["sourceCount"]);
  const identityExportCount = finiteNumber(data?.["identityExportCount"]);
  if (
    !data ||
    data["schema"] !== "hasna.accounts.configs-prelaunch/v1" ||
    typeof mode !== "string" ||
    !PRELAUNCH_MODE.has(mode) ||
    typeof result !== "string" ||
    !PRELAUNCH_RESULT.has(result) ||
    typeof data["allowFailure"] !== "boolean" ||
    identityExportCount === undefined ||
    boundedPublicString(data["tool"], 128) === undefined ||
    boundedPublicString(data["profile"], 128) === undefined ||
    boundedPublicString(data["updatedAt"], 128) === undefined ||
    !manifest ||
    boundedPublicString(manifest["path"], 4096) === undefined ||
    typeof drift !== "string" ||
    !PRELAUNCH_DRIFT.has(drift) ||
    sourceCount === undefined ||
    sourceIds === undefined ||
    typeof manifest["sourceIdsTruncated"] !== "boolean"
  ) {
    return undefined;
  }
  const statusCode =
    data["statusCode"] === null ? null : finiteNumber(data["statusCode"]);
  if (data["statusCode"] !== undefined && statusCode === undefined) return undefined;
  return {
    schema: "hasna.accounts.configs-prelaunch/v1",
    tool: boundedPublicString(data["tool"], 128)!,
    profile: boundedPublicString(data["profile"], 128)!,
    mode: mode as NonNullable<ConfigsPrelaunchSummary["lastRun"]>["mode"],
    result: result as NonNullable<ConfigsPrelaunchSummary["lastRun"]>["result"],
    allowFailure: data["allowFailure"],
    ...(boundedPublicString(data["reason"], 220) !== undefined
      ? { reason: boundedPublicString(data["reason"], 220) }
      : {}),
    ...(data["statusCode"] !== undefined ? { statusCode } : {}),
    identityExportCount,
    updatedAt: boundedPublicString(data["updatedAt"], 128)!,
    manifest: {
      path: boundedPublicString(manifest["path"], 4096)!,
      ...(boundedPublicString(manifest["hash"], 128) !== undefined
        ? { hash: boundedPublicString(manifest["hash"], 128) }
        : {}),
      ...(boundedPublicString(manifest["generatedAt"], 128) !== undefined
        ? { generatedAt: boundedPublicString(manifest["generatedAt"], 128) }
        : {}),
      drift: drift as NonNullable<ConfigsPrelaunchSummary["lastRun"]>["manifest"]["drift"],
      sourceCount,
      sourceIds,
      sourceIdsTruncated: manifest["sourceIdsTruncated"],
    },
  };
}

function projectPrelaunch(
  value: unknown,
): ConfigsPrelaunchSummary | undefined {
  const data = objectValue(value);
  const status = data?.["status"];
  const reasons = boundedPublicStrings(data?.["reasons"], 6, 220);
  const manifest = projectPrelaunchManifest(data?.["manifest"]);
  if (
    !data ||
    typeof data["supported"] !== "boolean" ||
    typeof data["required"] !== "boolean" ||
    typeof status !== "string" ||
    !PRELAUNCH_STATUS.has(status) ||
    reasons === undefined ||
    !manifest
  ) {
    return undefined;
  }
  const lastRun =
    data["lastRun"] === undefined
      ? undefined
      : projectPrelaunchAudit(data["lastRun"]);
  if (data["lastRun"] !== undefined && !lastRun) return undefined;
  return {
    supported: data["supported"],
    required: data["required"],
    status: status as ConfigsPrelaunchSummary["status"],
    reasons,
    manifest,
    ...(lastRun ? { lastRun } : {}),
  };
}

function projectState(value: unknown): SupervisorState | undefined {
  const data = objectValue(value);
  if (!data) return undefined;
  if (
    data["version"] !== 1 ||
    typeof data["tool"] !== "string" ||
    !PUBLIC_ID_PATTERN.test(data["tool"]) ||
    typeof data["profile"] !== "string" ||
    !PUBLIC_ID_PATTERN.test(data["profile"]) ||
    typeof data["pid"] !== "number" ||
    !Number.isInteger(data["pid"]) ||
    data["pid"] < 0 ||
    typeof data["socketPath"] !== "string" ||
    !Array.isArray(data["command"]) ||
    !data["command"].every((entry) => typeof entry === "string")
  ) {
    return undefined;
  }
  const childPid =
    typeof data["childPid"] === "number" &&
    Number.isInteger(data["childPid"]) &&
    data["childPid"] >= 0
      ? data["childPid"]
      : undefined;
  const publicTimestamp = (timestamp: unknown): string => {
    if (
      typeof timestamp !== "string" ||
      timestamp.length > 64 ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(timestamp)
    ) {
      return "";
    }
    return timestamp;
  };
  const state: SupervisorState = {
    version: 1,
    tool: redactText(data["tool"]),
    profile: redactText(data["profile"]),
    pid: data["pid"],
    ...(childPid !== undefined ? { childPid } : {}),
    socketPath: supervisorSocketPath(data["tool"]),
    command: redactArgv(data["command"] as string[]),
    startedAt: publicTimestamp(data["startedAt"]),
    updatedAt: publicTimestamp(data["updatedAt"]),
  };
  if (data["prelaunch"] !== undefined) {
    const prelaunch = projectPrelaunch(data["prelaunch"]);
    if (prelaunch) state.prelaunch = prelaunch;
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
    !PUBLIC_ID_PATTERN.test(profile["name"]) ||
    typeof profile["tool"] !== "string" ||
    !PUBLIC_ID_PATTERN.test(profile["tool"]) ||
    typeof tool?.["id"] !== "string" ||
    !PUBLIC_ID_PATTERN.test(tool["id"]) ||
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
  const toolLabel = publicToolLabel(tool["id"]);
  return {
    schema: "hasna.accounts.switch-output/v1",
    profile: {
      name: redactText(profile["name"]),
      tool: redactText(profile["tool"]),
    },
    tool: {
      id: redactText(tool["id"]),
      label: toolLabel,
    },
    applied: data["applied"],
    active: data["active"],
    command: redactArgv(data["command"] as string[]),
    commandLine: redactText(data["commandLine"]),
    ...(typeof data["permissions"] === "string"
      ? { permissions: redactText(data["permissions"]) }
      : {}),
    restartRequired: data["restartRequired"],
    message: publicSwitchMessage(profile["name"], toolLabel, data["applied"]),
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

function readSupervisorStateAt(
  boundary: SupervisorBoundary,
  toolId: string,
): SupervisorState | undefined {
  requireStableBoundary(boundary);
  const path = statePathAt(boundary, toolId);
  if (!existsSync(path)) return undefined;
  assertStateLeaf(path);
  try {
    const raw = readFileSync(path, "utf8");
    requireStableBoundary(boundary);
    return parseState(raw);
  } catch {
    return undefined;
  }
}

export function readSupervisorState(toolId: string): SupervisorState | undefined {
  const boundary = prepareSupervisorBoundary(false);
  return boundary ? readSupervisorStateAt(boundary, toolId) : undefined;
}

export function listSupervisorStates(): SupervisorState[] {
  const boundary = prepareSupervisorBoundary(false);
  if (!boundary) return [];
  requireStableBoundary(boundary);
  return readdirSync(boundary.dir)
    .filter((name) => name.endsWith(STATE_SUFFIX))
    .map((name) => basename(name, STATE_SUFFIX))
    .filter((toolId) => PUBLIC_ID_PATTERN.test(toolId))
    .map((toolId) => readSupervisorStateAt(boundary, toolId))
    .filter((state): state is SupervisorState => state !== undefined);
}

function writeSupervisorState(
  state: SupervisorState,
  expected?: SupervisorBoundary,
): void {
  const boundary = expected
    ? requireStableBoundary(expected)
    : ensureSupervisorBoundary();
  const path = statePathAt(boundary, state.tool);
  assertStateLeaf(path);
  const contents =
    JSON.stringify({ ...state, command: redactArgv(state.command) }, null, 2) +
    "\n";

  if (process.platform === "win32") {
    requireStableBoundary(boundary);
    writeFileSync(path, contents, { mode: 0o600 });
    return;
  }

  const tempPath = `${path}.${process.pid}.${++stateWriteSequence}.tmp`;
  if (lstatIfExists(tempPath)) {
    throw new AccountsError(`refusing occupied supervisor state temp path: ${tempPath}`);
  }
  let descriptor: number | undefined;
  try {
    requireStableBoundary(boundary);
    descriptor = openSync(
      tempPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, contents);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    requireStableBoundary(boundary);
    assertStateLeaf(path);
    renameSync(tempPath, path);
    requireStableBoundary(boundary);
    assertStateLeaf(path);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      requireStableBoundary(boundary);
      const tempStat = lstatIfExists(tempPath);
      if (tempStat?.isFile()) rmSync(tempPath);
    } catch {
      // Never follow or clean through a boundary that changed under us.
    }
    throw error;
  }
}

function removeSupervisorFiles(
  toolId: string,
  expected?: SupervisorBoundary,
): void {
  const boundary = expected
    ? requireStableBoundary(expected)
    : prepareSupervisorBoundary(false);
  if (!boundary) return;
  const statePath = statePathAt(boundary, toolId);
  assertStateLeaf(statePath);
  const stateExists = Boolean(lstatIfExists(statePath));
  let socketPath: string | undefined;
  let socketExists = false;
  if (process.platform !== "win32") {
    socketPath = socketPathAt(boundary, toolId);
    assertSocketLeaf(socketPath);
    socketExists = Boolean(lstatIfExists(socketPath));
  }
  requireStableBoundary(boundary);
  assertStateLeaf(statePath);
  if (socketPath) assertSocketLeaf(socketPath);
  if (stateExists) rmSync(statePath);
  if (socketPath && socketExists) {
    requireStableBoundary(boundary);
    assertSocketLeaf(socketPath);
    rmSync(socketPath);
  }
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
        `no active ${publicToolLabel(targetTool.id)} profile. Run \`accounts use <name> --tool ${targetTool.id}\` or pass --profile.`,
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

async function listen(
  server: Server,
  socketPath: string,
  boundary?: SupervisorBoundary,
): Promise<void> {
  if (boundary) {
    requireStableBoundary(boundary);
    assertSocketLeaf(socketPath);
    if (lstatIfExists(socketPath)) {
      throw new AccountsError(
        `refusing occupied supervisor control path: ${socketPath}`,
      );
    }
  }
  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off("listening", onListening);
      reject(err);
    };
    const onListening = () => {
      server.off("error", onError);
      try {
        if (process.platform !== "win32") {
          if (boundary) requireStableBoundary(boundary);
          const socketStat = lstatIfExists(socketPath);
          if (!socketStat?.isSocket()) {
            reject(
              new AccountsError(
                `supervisor control path is not a socket: ${socketPath}`,
              ),
            );
            return;
          }
          chmodSync(socketPath, 0o600);
          if (boundary) requireStableBoundary(boundary);
        }
        resolve();
      } catch (error) {
        reject(error as Error);
      }
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
  let socketPath = supervisorSocketPath(toolId);
  if (process.platform !== "win32") {
    const boundary = prepareSupervisorBoundary(false);
    if (!boundary) {
      if (opts.allowMissing) return undefined;
      throw new AccountsError(`could not contact accounts supervisor for ${toolId}: control directory is missing`);
    }
    requireStableBoundary(boundary);
    socketPath = socketPathAt(boundary, toolId);
    const socketStat = lstatIfExists(socketPath);
    if (!socketStat) {
      if (opts.allowMissing) return undefined;
      throw new AccountsError(`could not contact accounts supervisor for ${toolId}: control socket is missing`);
    }
    assertSocketLeaf(socketPath);
    requireStableBoundary(boundary);
  }

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
  const boundary = ensureSupervisorBoundary();
  const socketPath =
    process.platform === "win32"
      ? supervisorSocketPath(tool.id)
      : socketPathAt(boundary, tool.id);
  const existing = readSupervisorStateAt(boundary, tool.id);
  if (existing && processAlive(existing.pid)) {
    throw new AccountsError(`an accounts supervisor for ${publicToolLabel(tool.id)} is already running (pid ${existing.pid})`);
  }
  removeSupervisorFiles(tool.id, boundary);

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

  const persist = () => writeSupervisorState(state(), boundary);

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
    if (server.listening) server.close();
    try {
      removeSupervisorFiles(tool.id, boundary);
    } catch (error) {
      log(
        `accounts supervisor: refused unsafe cleanup: ${redactText(
          error instanceof Error ? error.message : String(error),
        )}`,
      );
    }
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
    requireStableBoundary(boundary);
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
    requireStableBoundary(boundary);
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
      try {
        persist();
      } catch (error) {
        log(
          `accounts supervisor: refused unsafe state write: ${redactText(
            error instanceof Error ? error.message : String(error),
          )}`,
        );
      }
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
    try {
      requireStableBoundary(boundary);
    } catch (error) {
      return {
        ok: false,
        error: redactText(error instanceof Error ? error.message : String(error)),
      };
    }
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
      setTimeout(() => {
        void restartWith(result, preflightedConfigs).catch((error) => {
          log(
            `accounts supervisor: restart failed: ${redactText(
              error instanceof Error ? error.message : String(error),
            )}`,
          );
          void shutdown(1);
        });
      }, 0);
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
          response = {
            ok: false,
            error: redactText(err instanceof Error ? err.message : String(err)),
          };
        }
        socket.end(JSON.stringify(response) + "\n");
      })();
    });
  });

  const onSigint = () => void shutdown(130);
  const onSigterm = () => void shutdown(143);
  process.once("SIGINT", onSigint);
  process.once("SIGTERM", onSigterm);

  try {
    await listen(server, socketPath, process.platform === "win32" ? undefined : boundary);
    await startChild(profile, childArgs);
    return await done;
  } catch (error) {
    stopping = true;
    await stopChild();
    cleanup();
    throw error;
  }
}
