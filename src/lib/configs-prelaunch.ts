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
  readConfigsPrelaunchAudit,
  readManifestSourceIds,
  recordConfigsPrelaunchAudit,
  type ConfigsPrelaunchAuditResult,
  type ConfigsPrelaunchSummary,
  type ConfigsShortfallGuardState,
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
  /**
   * Let this render REMOVE instruction sources the home already carries.
   *
   * Off by default. A prelaunch render is the wrong place to retire a rule: it
   * fires on an ordinary `accounts launch`, from whatever export happens to be
   * on disk, and `configs session apply` deletes the unmatched managed files
   * outright ("stale managed file removed"). Measured 2026-08-01 on station01,
   * that is how a governed home went from 19 sources to 12 at rc=0, recorded as
   * `applied`, with no surface reporting a loss.
   *
   * Retiring a rule is a deliberate act performed by the canonical render, which
   * resets the floor for every home. This flag exists so that act is expressible
   * here too, not so it can happen by accident.
   */
  allowSourceReduction?: boolean;
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

/**
 * Environment key carrying the canonical instruction sources a governed home
 * must end up with. Comma-separated ids.
 *
 * Configuration rather than a constant in this file on purpose: accounts does
 * not own the rule set and must not encode it. It only needs to be told, by
 * something that is NOT the artefact under test, what to expect.
 */
export const REQUIRED_INSTRUCTION_SOURCES_ENV = "HASNA_ACCOUNTS_REQUIRED_INSTRUCTION_SOURCES";

/**
 * The instruction sources a render must produce, from a source INDEPENDENT of
 * the render being checked.
 *
 * This independence is the whole point. The guard shipped inert because its
 * expected value was derived from the same export it was validating, which
 * cannot fail: a stale export declaring three rules renders three, and the
 * comparison passes while the home is missing seven. Returns an empty list when
 * nothing is configured, and callers must treat that as "cannot check" rather
 * than "checked and fine".
 */
export function resolveRequiredInstructionSourceIds(
  opts: { env?: NodeJS.ProcessEnv; explicit?: string[] } = {},
): string[] {
  if (opts.explicit && opts.explicit.length > 0) return [...opts.explicit];
  const raw = (opts.env ?? process.env)[REQUIRED_INSTRUCTION_SOURCES_ENV];
  if (!raw) return [];
  return raw
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
}

/**
 * Where the preservation floor came from, or why there is none.
 *
 * `manifest`  read from the home's own session render manifest — the normal case.
 * `audit`     the manifest is gone or corrupt, so the floor came from the
 *             prelaunch audit accounts wrote on the previous run.
 * `fresh`     nothing on disk claims this home has ever carried sources. The
 *             only state in which rendering into an unprotected home is correct.
 * `waived`    the operator authorised a reduction; no floor applies.
 * `destroyed` something says this home HAS carried sources and nothing can say
 *             which. Not the same as `fresh`, and the whole point of this type.
 */
type IncumbentFloor =
  | { ids: string[]; origin: "manifest" | "audit" | "fresh" | "waived" }
  | { ids: never[]; origin: "destroyed"; detail: string };

/**
 * The set of instruction sources this home must not lose, read from the most
 * trustworthy record still standing.
 *
 * Two records exist and accounts writes the second one itself: every prelaunch
 * run stores the manifest's source ids into `.hasna/accounts/prelaunch-status.json`.
 * That file is independent of the manifest and of the export, so consulting it
 * turns "the floor file was deleted" from a silent disarm into an ordinary
 * drop-check — which is what probe B on todos `8776dba9` demonstrated was
 * missing.
 *
 * New audits carry an uncapped `preservationFloor` separately from the bounded
 * manifest summary. Older audits have only the capped summary, so their fallback
 * remains partial until one successful render refreshes the durable floor.
 */
function resolveIncumbentFloor(profile: Profile, tool: ToolDef): IncumbentFloor {
  const read = readManifestSourceIds(profile);
  if (read.state === "ok") return { ids: read.ids, origin: "manifest" };

  const audit = readConfigsPrelaunchAudit(profile, tool);
  const recorded = audit?.preservationFloor ?? audit?.manifest;
  if (recorded && recorded.sourceIds.length > 0) return { ids: [...recorded.sourceIds], origin: "audit" };

  const manifestDetail =
    read.state === "unreadable"
      ? "the session render manifest exists but could not be parsed"
      : "the session render manifest is absent";

  // The audit remembers a non-empty set but cannot name it, so a comparison is
  // impossible while the home is known to have something to lose.
  if (recorded && recorded.sourceCount > 0) {
    return {
      ids: [],
      origin: "destroyed",
      detail: `${manifestDetail}, and the prelaunch audit records ${recorded.sourceCount} previous sources without usable ids`,
    };
  }

  // A corrupt manifest with nothing corroborating it is still a destroyed input,
  // not an empty one: a home that has never been rendered has NO manifest, so a
  // manifest that exists and cannot be read is an anomaly either way.
  if (read.state === "unreadable") return { ids: [], origin: "destroyed", detail: manifestDetail };

  return { ids: [], origin: "fresh" };
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

  // What this render is REQUIRED to end up carrying, and — just as important —
  // whether that expectation is INDEPENDENT of the thing being checked.
  //
  //   armed   an expectation supplied from outside: a caller literal, or the
  //           configured canonical set. This can actually fail.
  //   unarmed nothing configured, so the only available expectation is the
  //           export itself. That comparison catches a renderer DROPPING a
  //           source it was handed, and cannot catch an export that was already
  //           short — which is the case that ran for weeks. Recorded by name so
  //           its silence is never read as coverage.
  const independentRequiredSourceIds = resolveRequiredInstructionSourceIds({ explicit: opts.requiredSourceIds });

  // What the home ALREADY carries, read before anything is written.
  //
  // This is the floor that was missing. The configured expectation above is the
  // stronger check but nobody sets it, so in practice the guard fell back to the
  // export's own ids and compared the render against the artefact that produced
  // it — a comparison that cannot fail. The prior manifest is independent of the
  // export by construction, costs one file read, and needs no rule list, so it
  // arms on every home that has ever been rendered instead of on the homes
  // someone remembered to configure.
  // Not consulted at all once the operator has authorised a reduction: the floor
  // and the permission to go below it cannot both apply, and leaving it in place
  // made the post-render check reject the very reduction that was just allowed.
  const floorApplies = mode === "apply" && opts.allowSourceReduction !== true;
  const incumbent = floorApplies ? resolveIncumbentFloor(profile, tool) : { ids: [], origin: "waived" as const };
  const incumbentSourceIds = incumbent.ids;

  // FAIL CLOSED WHEN THE FLOOR ITSELF IS DESTROYED.
  //
  // todos `8776dba9`. The floor above is read from one file, and until this
  // branch existed an unreadable file produced an empty list that was
  // indistinguishable from a home with nothing to protect — so deleting or
  // corrupting `.hasna/session-render-manifest.json` re-armed the exact failure
  // this module was written to stop. Measured on station01 2026-08-01 against
  // 0.2.31: one corrupt file, guard passes, render issues, 19 sources become 12,
  // every gate green. `resolveIncumbentFloor` first falls back to the prelaunch
  // audit, which is a second, independently written record of the same set; this
  // branch is what happens when BOTH are gone.
  //
  // Refusing costs a launch that keeps its rules. Proceeding costs the rules.
  // `--allow-instruction-reduction` remains the way to say the loss is intended,
  // and it bypasses this whole block, so an operator is never wedged.
  if (incumbent.origin === "destroyed") {
    const reason =
      `the instruction floor for ${tool.id}/${profile.name} cannot be read: ` +
      `${incumbent.detail}. Refusing to render, because a render that cannot see ` +
      `what the home already carries cannot be shown not to remove it. ` +
      `Re-run the canonical render to rebuild the manifest, ` +
      `or pass --allow-instruction-reduction to render anyway.`;
    process.stderr.write(`accounts: ${reason}\n`);
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "skipped",
      allowFailure,
      reason,
      identityExportCount: identityExports.length,
      shortfallGuard: "unarmed",
    });
    return {
      skipped: true,
      mode,
      result: "skipped",
      reason,
      command: [],
      status: undefined,
      identityExports,
      allowFailure,
      prelaunch,
    };
  }

  const shortfallGuard: ConfigsShortfallGuardState =
    independentRequiredSourceIds.length > 0 ? "armed" : incumbentSourceIds.length > 0 ? "incumbent" : "unarmed";
  const suppliedSourceIds = identityExports.flatMap(readIdentityExportSourceIds);
  const requiredSourceIds =
    shortfallGuard === "armed"
      ? independentRequiredSourceIds
      : // Union, not either/or: the incumbent set catches an export that is
        // already short, and the supplied set catches the renderer dropping
        // something it WAS handed. Neither subsumes the other.
        [...new Set([...incumbentSourceIds, ...suppliedSourceIds])];

  // REFUSE BEFORE WRITING, not after.
  //
  // The post-render check below already rejects a shortfall, but by then the
  // home is corrupted — the render has run and configs has deleted the files.
  // Failing closed at that point buys both the damage and a dead launch. If the
  // inputs to this render cannot possibly produce what the home already has,
  // the render is simply not worth running: the home keeps its rules and the
  // launch proceeds. Loud, non-destructive, and no outage.
  const wouldDropSourceIds =
    mode === "apply" && opts.allowSourceReduction !== true && identityExports.length > 0
      ? incumbentSourceIds.filter((id) => !suppliedSourceIds.includes(id))
      : [];
  if (wouldDropSourceIds.length > 0) {
    const shown = wouldDropSourceIds.slice(0, 5).join(", ");
    const reason =
      `session render inputs for ${tool.id}/${profile.name} declare ${suppliedSourceIds.length} instruction ` +
      `sources but the home already carries ${incumbentSourceIds.length}; rendering would remove ` +
      `${wouldDropSourceIds.length} of them (${shown}${wouldDropSourceIds.length > 5 ? ", …" : ""}). ` +
      `Kept the existing instruction home and skipped the render. ` +
      `Refresh the identity export, re-run the canonical render, ` +
      `or pass --allow-instruction-reduction to remove them on purpose.`;
    process.stderr.write(`accounts: ${reason}\n`);
    const prelaunch = recordConfigsPrelaunchAudit(profile, tool, configsTool, {
      mode,
      result: "skipped",
      allowFailure,
      reason,
      identityExportCount: identityExports.length,
      shortfallGuard,
      // The full list, structured. `reason` is prose and is capped at
      // MAX_REASON_LENGTH; an eight-id refusal measured 220 characters and named
      // two of them before cutting off mid-list, so the audit would have been
      // least informative exactly where most was being removed.
      droppedSourceIds: wouldDropSourceIds,
    });
    return {
      skipped: true,
      mode,
      result: "skipped",
      reason,
      command: [],
      status: undefined,
      identityExports,
      allowFailure,
      prelaunch,
    };
  }

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
      shortfallGuard,
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
      shortfallGuard,
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
    // Compare against the UNCAPPED id list. `manifest.sourceIds` is truncated at
    // MAX_SOURCE_IDS for the audit record, and reading the check off it meant the
    // guard stopped checking — reporting nothing missing — as soon as a home
    // carried more sources than the display cap. The canonical set is 19 against
    // a cap of 20, so that cliff was one rule away.
    // `.ids` alone is safe HERE only because the branch below is gated on
    // `manifest.drift === "ok"`, which independently proves the manifest just
    // written is present and parseable. A `missing`/`unreadable` read cannot
    // reach the comparison.
    const renderedSourceIds = readManifestSourceIds(profile).ids;
    const missingSources =
      manifest.drift === "ok" ? requiredSourceIds.filter((id) => !renderedSourceIds.includes(id)) : [];
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
        shortfallGuard,
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
    shortfallGuard,
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
