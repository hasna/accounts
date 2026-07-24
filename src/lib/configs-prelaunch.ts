import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  assessConfigsManifest,
  getConfigsPrelaunchSummary,
  recordConfigsPrelaunchAudit,
  type ConfigsPrelaunchAuditResult,
  type ConfigsPrelaunchSummary,
} from "./configs-prelaunch-status.js";

export type ConfigsPrelaunchMode = "plan" | "apply" | "skip";
export type ConfigsRunner = (command: string, args: string[]) => Pick<SpawnSyncReturns<Buffer>, "status" | "error" | "stdout" | "stderr">;

export interface ConfigsPrelaunchOptions {
  mode?: ConfigsPrelaunchMode;
  allowFailure?: boolean;
  configsBin?: string;
  identitiesBin?: string;
  sessionId?: string;
  identityExports?: string[];
  includeProfileIdentity?: boolean;
  skipReason?: string;
  runner?: ConfigsRunner;
}

export interface ConfigsPrelaunchResult {
  skipped: boolean;
  mode: ConfigsPrelaunchMode;
  result: ConfigsPrelaunchAuditResult;
  reason?: string;
  command: string[];
  status?: number | null;
  identityExports?: string[];
  allowFailure: boolean;
  prelaunch: ConfigsPrelaunchSummary;
}

const CONFIGS_SESSION_TOOL_IDS = new Set(["claude", "codex", "cursor", "opencode", "codewith"]);

export function configsSessionToolFor(tool: ToolDef): string | undefined {
  if (tool.id === "codex-app") return "codex";
  return CONFIGS_SESSION_TOOL_IDS.has(tool.id) ? tool.id : undefined;
}

export function configsPrelaunchCommand(
  profile: Profile,
  tool: ToolDef,
  opts: ConfigsPrelaunchOptions = {},
): string[] {
  const mode = opts.mode ?? "apply";
  const configsTool = configsSessionToolFor(tool);
  if (mode === "skip" || !configsTool) return [];
  const identityExports = opts.identityExports ?? [];
  return [
    opts.configsBin ?? "configs",
    "session",
    mode,
    "--tool",
    configsTool,
    "--profile",
    profile.name,
    "--target-home",
    profile.dir,
    "--session-id",
    opts.sessionId ?? `accounts:${tool.id}:${profile.name}`,
    ...identityExports.flatMap((path) => ["--identity-export", path]),
    // No instruction sources: tell configs this is an explicit empty render so it
    // produces a valid sourceCount:0 manifest instead of failing closed.
    ...(identityExports.length === 0 ? ["--allow-empty-sources"] : []),
  ];
}

function expandPath(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return isAbsolute(path) ? path : resolve(path);
}

function looksLikePath(value: string): boolean {
  return value === "~" || value.startsWith("~/") || value.startsWith("./") || value.startsWith("../") || value.includes("/");
}

function slug(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || "identity";
}

function profileIdentityExportPath(profile: Profile): string {
  return join(profile.dir, ".hasna", "accounts", "identity-exports", `${slug(profile.identity ?? profile.name)}.configs.json`);
}

interface ResolvedIdentityExports {
  paths: string[];
  bypassReason?: string;
}

function resolveIdentityExports(profile: Profile, tool: ToolDef, opts: ConfigsPrelaunchOptions, runner: ConfigsRunner): ResolvedIdentityExports {
  const exports = [...(opts.identityExports ?? []).map(expandPath)];
  const identity = profile.identity?.trim();
  if (!identity || opts.includeProfileIdentity === false) return { paths: exports };

  const identityPath = expandPath(identity);
  if (existsSync(identityPath)) return { paths: [...exports, identityPath] };
  if (looksLikePath(identity)) {
    const reason = `profile identity export file not found`;
    if (opts.allowFailure) return { paths: exports, bypassReason: reason };
    throw new AccountsError(`${reason} for ${tool.id}/${profile.name}: ${identityPath}`);
  }

  const exportPath = profileIdentityExportPath(profile);
  mkdirSync(dirname(exportPath), { recursive: true });
  const result = runner(opts.identitiesBin ?? "identities", [
    "instructions",
    "export",
    exportPath,
    "--identity",
    identity,
    "--format",
    "configs",
    "--json",
  ]);
  const failed = !!result.error || (result.status ?? 1) !== 0;
  if (failed && !opts.allowFailure) {
    const detail = result.error ? `: ${result.error.message}` : outputSummary(result);
    throw new AccountsError(`identity instruction export failed for ${tool.id}/${profile.name}${detail}`);
  }
  if (failed) return { paths: exports, bypassReason: "identity instruction export failed" };
  return { paths: [...exports, exportPath] };
}

function defaultRunner(command: string, args: string[]) {
  return spawnSync(command, args, {
    encoding: "buffer",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function outputSummary(result: Pick<SpawnSyncReturns<Buffer>, "stdout" | "stderr">): string {
  const combined = `${result.stderr?.toString("utf8") ?? ""}${result.stdout?.toString("utf8") ?? ""}`.trim();
  return combined ? `: ${combined.split("\n").slice(0, 3).join(" ")}` : "";
}

export function runConfigsPrelaunch(
  profile: Profile,
  tool: ToolDef,
  opts: ConfigsPrelaunchOptions = {},
): ConfigsPrelaunchResult {
  const mode = opts.mode ?? "apply";
  const configsTool = configsSessionToolFor(tool);
  const allowFailure = opts.allowFailure ?? false;
  if (mode === "skip") {
    const reason = opts.skipReason ?? "configs prelaunch skipped";
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "skipped",
      allowFailure,
      reason,
    });
    return { skipped: true, mode, result: "skipped", reason, command: [], allowFailure, prelaunch };
  }
  if (!configsTool) {
    const reason = `unsupported tool ${tool.id}`;
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "skipped",
      allowFailure,
      reason,
    });
    return { skipped: true, mode, result: "skipped", reason, command: [], allowFailure, prelaunch };
  }

  const runner = opts.runner ?? defaultRunner;
  let resolved: ResolvedIdentityExports;
  try {
    resolved = resolveIdentityExports(profile, tool, opts, runner);
  } catch (err) {
    const reason = err instanceof Error ? err.message : "identity instruction export failed";
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: allowFailure ? "bypassed" : "failed",
      allowFailure,
      reason,
    });
    if (!allowFailure) throw err;
    return {
      skipped: false,
      mode,
      result: "bypassed",
      reason,
      command: [],
      identityExports: [],
      allowFailure,
      prelaunch,
    };
  }
  const identityExports = resolved.paths;
  const command = configsPrelaunchCommand(profile, tool, { ...opts, identityExports });
  const [bin, ...args] = command;
  const result = runner(bin!, args);
  const failed = !!result.error || (result.status ?? 1) !== 0;
  const identityBypass = resolved.bypassReason ? `${resolved.bypassReason}; --allow-configs-failure` : undefined;
  if (failed && !opts.allowFailure) {
    const detail = result.error ? `: ${result.error.message}` : outputSummary(result);
    recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "failed",
      allowFailure,
      reason: `configs prelaunch ${mode} failed`,
      statusCode: result.status,
      identityExportCount: identityExports.length,
    });
    throw new AccountsError(`configs prelaunch ${mode} failed for ${tool.id}/${profile.name}${detail}`);
  }
  if (failed && opts.allowFailure) {
    const reason = `configs prelaunch ${mode} failed; --allow-configs-failure`;
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "bypassed",
      allowFailure,
      reason,
      statusCode: result.status,
      identityExportCount: identityExports.length,
    });
    return {
      skipped: false,
      mode,
      result: "bypassed",
      reason,
      command,
      status: result.status,
      identityExports,
      allowFailure,
      prelaunch,
    };
  }

  if (mode === "apply") {
    const manifest = assessConfigsManifest(profile, tool, configsTool);
    if (manifest.drift !== "ok") {
      const reason = `session render manifest ${manifest.drift}: ${manifest.reasons.join("; ") || "not fresh"}`;
      const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
        mode,
        result: allowFailure ? "bypassed" : "failed",
        allowFailure,
        reason: allowFailure ? `${reason}; --allow-configs-failure` : reason,
        statusCode: result.status,
        identityExportCount: identityExports.length,
      });
      if (!allowFailure) throw new AccountsError(`configs prelaunch ${mode} failed for ${tool.id}/${profile.name}: ${reason}`);
      return {
        skipped: false,
        mode,
        result: "bypassed",
        reason,
        command,
        status: result.status,
        identityExports,
        allowFailure,
        prelaunch,
      };
    }
  }

  const auditResult: ConfigsPrelaunchAuditResult = identityBypass ? "bypassed" : mode === "plan" ? "planned" : "applied";
  const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
    mode,
    result: auditResult,
    allowFailure,
    reason: identityBypass,
    statusCode: result.status,
    identityExportCount: identityExports.length,
  });
  return {
    skipped: false,
    mode,
    result: auditResult,
    reason: identityBypass,
    command,
    status: result.status,
    identityExports,
    allowFailure,
    prelaunch: identityBypass ? prelaunch : getConfigsPrelaunchSummary(profile, tool, configsTool),
  };
}
