import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { controlledProbeEnv } from "./env.js";
import { redactText } from "./redaction.js";
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
  /**
   * Render a home with NO instruction rules on purpose.
   *
   * Off by default, and it must stay that way. This used to be inferred from
   * "the profile has no identity export", which is the normal state of every
   * pooled `accountNNN` profile — so the renderer's empty-source guard was
   * disarmed on essentially every call, and twenty-six agent homes ended up
   * carrying no operating rules at all while every surface reported `ok`.
   */
  allowEmptySources?: boolean;
  /**
   * Instruction source ids the rendered home MUST end up carrying.
   *
   * Zero sources is the loud failure; a SHORTFALL is the quiet one, and the
   * quiet one ran undetected for weeks. `claude/account005` rendered 3 of 10
   * sources — missing the core operating rules and the credential-hygiene rule
   * — and every surface called it healthy, because the render ran, exited 0 and
   * produced a well-formed manifest. Counting is not enough: a home carrying
   * three arbitrary rules is not a governed home, so the caller states which
   * ids have to be there and the render is rejected if any are absent.
   *
   * Left empty, the check falls back to "render everything that was supplied",
   * which still catches a renderer silently dropping sources.
   */
  requiredSourceIds?: string[];
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
    // Only when the caller explicitly asked for an empty home. Having no
    // instruction sources is a fault to report, not a reason to suppress the
    // renderer's guard against rendering nothing.
    ...(opts.allowEmptySources === true ? ["--allow-empty-sources"] : []),
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
    const detail = result.error ? `: ${redactText(result.error.message)}` : outputSummary(result);
    throw new AccountsError(`identity instruction export failed for ${tool.id}/${profile.name}${detail}`);
  }
  if (failed) return { paths: exports, bypassReason: "identity instruction export failed" };
  return { paths: [...exports, exportPath] };
}

/**
 * Instruction source ids an export declares.
 *
 * Best-effort by design: an unreadable or unexpected export yields no required
 * ids rather than throwing, because this feeds a SAFETY check and a check that
 * crashes on a malformed input is a check that gets removed. A malformed export
 * still fails the render itself, where the error belongs.
 */
function readIdentityExportSourceIds(path: string): string[] {
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as { sources?: Array<{ id?: unknown }> };
    if (!Array.isArray(raw?.sources)) return [];
    return raw.sources.map((source) => source?.id).filter((id): id is string => typeof id === "string" && id.length > 0);
  } catch {
    return [];
  }
}

function defaultRunner(command: string, args: string[]) {
  return spawnSync(command, args, {
    encoding: "buffer",
    stdio: ["ignore", "pipe", "pipe"],
    env: controlledProbeEnv(),
  });
}

function capturedOutputRecords(
  result: Pick<SpawnSyncReturns<Buffer>, "stdout" | "stderr">,
): string[] {
  const stderr = result.stderr?.toString("utf8") ?? "";
  const stdout = result.stdout?.toString("utf8") ?? "";
  return [stderr, stdout].filter(Boolean);
}

function outputSummary(result: Pick<SpawnSyncReturns<Buffer>, "stdout" | "stderr">): string {
  const bounded: string[] = [];
  let remainingLines = 3;
  for (const record of capturedOutputRecords(result)) {
    if (remainingLines === 0) break;
    const trimmed = record.trim();
    if (!trimmed) continue;
    const lines = trimmed.split(/\r\n|\r|\n/).slice(0, remainingLines);
    if (lines.length === 0) continue;
    bounded.push(lines.join("\n"));
    remainingLines -= lines.length;
  }
  if (bounded.length === 0) return "";
  return `: ${bounded
    .map((record) => redactText(record).replace(/\r\n|\r|\n/g, " "))
    .join(" ")}`;
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

  // Nothing to render FROM. Skip the render entirely and leave whatever the home
  // already has in place.
  //
  // The three wrong answers, all of which were shipped at some point:
  //  - render it empty anyway (what happened until now): the home is stripped to
  //    a stub and the agent launches with no operating rules, graded `applied`.
  //  - let the renderer refuse and propagate that: `configs session apply`
  //    exits 1 and this function throws by default, so bare
  //    `accounts launch accountNNN` aborts. Every pooled profile is
  //    identity-less, so that fails every launch on the fleet.
  //  - swallow it: the estate looks healthy while nothing is governed.
  //
  // A stale-but-present instruction home beats an empty one and beats a dead
  // launch, so this skips loudly and lets the launch continue.
  if (mode === "apply" && identityExports.length === 0 && opts.allowEmptySources !== true) {
    // Keep WHY there is nothing to render. "The identity export failed" and
    // "no identity was ever configured" need different actions from an operator,
    // and collapsing them into one message sent earlier investigations the wrong
    // way.
    const reason =
      (resolved.bypassReason ? `${resolved.bypassReason}; ` : "") +
      `no instruction sources resolved for ${tool.id}/${profile.name}; ` +
      `kept the existing instruction home instead of rendering an empty one. ` +
      `Set an identity export (accounts set ${profile.name} --tool ${tool.id} --identity <path>) ` +
      `or pass --allow-empty-instructions to render an empty home on purpose.`;
    process.stderr.write(`accounts: ${reason}\n`);
    // `bypassed` when something failed on the way here, `skipped` when there was
    // simply nothing configured. Neither is `ok`, so no surface reads the
    // profile as governed.
    const outcome: ConfigsPrelaunchAuditResult = resolved.bypassReason ? "bypassed" : "skipped";
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: outcome,
      allowFailure,
      reason,
      identityExportCount: 0,
    });
    return {
      skipped: true,
      mode,
      result: outcome,
      reason,
      command: [],
      identityExports: [],
      allowFailure,
      prelaunch,
    };
  }

  // What this render is REQUIRED to end up carrying. An explicit list from the
  // caller wins; otherwise every source the supplied exports declare, so a
  // renderer that quietly drops one is still caught.
  const requiredSourceIds = opts.requiredSourceIds ?? identityExports.flatMap(readIdentityExportSourceIds);

  const command = configsPrelaunchCommand(profile, tool, { ...opts, identityExports });
  const [bin, ...args] = command;
  const result = runner(bin!, args);
  const failed = !!result.error || (result.status ?? 1) !== 0;
  const identityBypass = resolved.bypassReason ? `${resolved.bypassReason}; --allow-configs-failure` : undefined;
  if (failed && !opts.allowFailure) {
    const detail = result.error ? `: ${redactText(result.error.message)}` : outputSummary(result);
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
    // A render that wrote a well-formed home containing NO rules is the failure
    // that hid the longest, because every other signal reads clean: the command
    // exits 0, the manifest parses, nothing drifted. The home is simply empty of
    // instructions, and an agent launched into it runs with no operating rules.
    // Grading that as `applied` is what let it persist across twenty-six
    // profiles unnoticed, so it is checked here rather than inferred elsewhere.
    const emptyRender = opts.allowEmptySources !== true && manifest.drift === "ok" && manifest.sourceCount === 0;
    // The SHORTFALL check. A render that dropped some of what it was given is
    // the failure mode that survived undetected longest, precisely because it
    // looks identical to success everywhere else. Only trustworthy when the
    // manifest listed its ids in full; a truncated list cannot prove absence.
    const missingSources =
      manifest.drift === "ok" && !manifest.sourceIdsTruncated
        ? requiredSourceIds.filter((id) => !manifest.sourceIds.includes(id))
        : [];
    if (manifest.drift !== "ok" || emptyRender || missingSources.length > 0) {
      const reason = emptyRender
        ? `session render produced no instruction sources for ${tool.id}/${profile.name}; the home would carry no operating rules`
        : missingSources.length > 0
          ? `session render for ${tool.id}/${profile.name} is missing ${missingSources.length} of ` +
            `${requiredSourceIds.length} required instruction sources ` +
            `(${missingSources.slice(0, 5).join(", ")}${missingSources.length > 5 ? ", …" : ""}); ` +
            `the home would run without them`
          : `session render manifest ${manifest.drift}: ${manifest.reasons.join("; ") || "not fresh"}`;
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
