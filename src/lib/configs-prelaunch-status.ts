import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { Profile, ToolDef } from "../types.js";

export type ConfigsManifestDrift = "ok" | "missing" | "invalid" | "mismatch" | "stale" | "unsupported";
export type ConfigsPrelaunchAuditResult = "applied" | "planned" | "skipped" | "failed" | "bypassed";
export type ConfigsPrelaunchStatus = ConfigsManifestDrift | "planned" | "skipped" | "failed" | "bypassed";

export interface ConfigsPrelaunchSourcesSummary {
  count: number;
  ids: string[];
  truncated: boolean;
}

export interface ConfigsPrelaunchManifestStatus {
  path: string;
  exists: boolean;
  hash?: string;
  schema?: string;
  tool?: string;
  profile?: string;
  targetHome?: string;
  generatedAt?: string;
  sourceIds: string[];
  sourceCount: number;
  sourceIdsTruncated: boolean;
  fileCount?: number;
  drift: ConfigsManifestDrift;
  reasons: string[];
}

/**
 * Whether the shortfall check had an expectation INDEPENDENT of the render it
 * was checking.
 *
 * `unarmed` is not a soft pass. It means the only available expectation was the
 * export itself, so the check could catch a renderer dropping a source but not
 * an export that was already short — the case that ran undetected for weeks.
 * Recorded explicitly so a surface can distinguish "checked and fine" from
 * "could not check", which is the distinction the whole incident turned on.
 */
export type ConfigsShortfallGuardState = "armed" | "unarmed";

export interface ConfigsPrelaunchAudit {
  schema: "hasna.accounts.configs-prelaunch/v1";
  tool: string;
  profile: string;
  mode: "plan" | "apply" | "skip";
  result: ConfigsPrelaunchAuditResult;
  allowFailure: boolean;
  reason?: string;
  statusCode?: number | null;
  identityExportCount: number;
  shortfallGuard?: ConfigsShortfallGuardState;
  updatedAt: string;
  manifest: {
    path: string;
    hash?: string;
    generatedAt?: string;
    drift: ConfigsManifestDrift;
    sourceCount: number;
    sourceIds: string[];
    sourceIdsTruncated: boolean;
  };
}

export interface ConfigsPrelaunchSummary {
  supported: boolean;
  required: boolean;
  status: ConfigsPrelaunchStatus;
  reasons: string[];
  manifest: ConfigsPrelaunchManifestStatus;
  lastRun?: ConfigsPrelaunchAudit;
}

export interface RecordConfigsPrelaunchAuditInput {
  mode: "plan" | "apply" | "skip";
  result: ConfigsPrelaunchAuditResult;
  allowFailure?: boolean;
  reason?: string;
  statusCode?: number | null;
  identityExportCount?: number;
  shortfallGuard?: ConfigsShortfallGuardState;
}

const STATUS_SCHEMA = "hasna.accounts.configs-prelaunch/v1" as const;
const MANIFEST_SCHEMA = "hasna.configs.session-render/v1";
const MAX_SOURCE_IDS = 20;
const MAX_REASONS = 6;
const MAX_REASON_LENGTH = 220;

export function configsManifestPath(profile: Profile): string {
  return join(profile.dir, ".hasna", "session-render-manifest.json");
}

export function configsPrelaunchAuditPath(profile: Profile): string {
  return join(profile.dir, ".hasna", "accounts", "prelaunch-status.json");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function boundedReasons(reasons: string[]): string[] {
  return reasons
    .filter(Boolean)
    .slice(0, MAX_REASONS)
    .map((reason) => reason.slice(0, MAX_REASON_LENGTH));
}

function sourceSummary(sources: unknown): ConfigsPrelaunchSourcesSummary {
  if (!Array.isArray(sources)) return { count: 0, ids: [], truncated: false };
  const ids = sources.flatMap((source) => {
    const id = stringValue(asRecord(source)?.["id"]);
    return id ? [id] : [];
  });
  return {
    count: sources.length,
    ids: ids.slice(0, MAX_SOURCE_IDS),
    truncated: ids.length > MAX_SOURCE_IDS,
  };
}

function safeRelativeTarget(targetHome: string, relativePath: string): string | undefined {
  if (!relativePath || isAbsolute(relativePath) || relativePath.includes("\0")) return undefined;
  const target = resolve(targetHome, ...relativePath.split("/"));
  const rel = relative(resolve(targetHome), target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return undefined;
  return target;
}

function checkManifestFiles(manifest: Record<string, unknown>, targetHome: string): { drift: ConfigsManifestDrift; reasons: string[]; fileCount?: number } {
  const files = manifest["files"];
  if (!Array.isArray(files)) return { drift: "invalid", reasons: ["manifest files field is missing or invalid"] };

  const reasons: string[] = [];
  for (const file of files) {
    const record = asRecord(file);
    const relativePath = stringValue(record?.["relativePath"]);
    const expectedSha = stringValue(record?.["sha256"]);
    if (!relativePath || !expectedSha) {
      reasons.push("manifest file entry is missing relativePath or sha256");
      continue;
    }
    const target = safeRelativeTarget(targetHome, relativePath);
    if (!target) {
      reasons.push(`manifest file escapes target home: ${relativePath}`);
      continue;
    }
    if (!existsSync(target)) {
      reasons.push(`managed file missing: ${relativePath}`);
      continue;
    }
    const actualSha = sha256(readFileSync(target, "utf8"));
    if (actualSha !== expectedSha) reasons.push(`managed file drifted: ${relativePath}`);
  }

  return {
    drift: reasons.length > 0 ? "stale" : "ok",
    reasons,
    fileCount: files.length,
  };
}

export function assessConfigsManifest(profile: Profile, tool: ToolDef, configsTool?: string): ConfigsPrelaunchManifestStatus {
  const path = configsManifestPath(profile);
  if (!configsTool) {
    return {
      path,
      exists: existsSync(path),
      sourceIds: [],
      sourceCount: 0,
      sourceIdsTruncated: false,
      drift: "unsupported",
      reasons: [`unsupported tool ${tool.id}`],
    };
  }
  if (!existsSync(path)) {
    return {
      path,
      exists: false,
      sourceIds: [],
      sourceCount: 0,
      sourceIdsTruncated: false,
      drift: "missing",
      reasons: ["session render manifest is missing"],
    };
  }

  const raw = readFileSync(path, "utf8");
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = asRecord(JSON.parse(raw));
  } catch {
    parsed = undefined;
  }
  if (!parsed) {
    return {
      path,
      exists: true,
      hash: sha256(raw),
      sourceIds: [],
      sourceCount: 0,
      sourceIdsTruncated: false,
      drift: "invalid",
      reasons: ["session render manifest is not valid JSON"],
    };
  }

  const sources = sourceSummary(parsed["sources"]);
  const schema = stringValue(parsed["schema"]);
  const manifestTool = stringValue(parsed["tool"]);
  const manifestProfile = stringValue(parsed["profile"]);
  const targetHome = stringValue(parsed["targetHome"]);
  const generatedAt = stringValue(parsed["generatedAt"]);
  const mismatchReasons = [
    schema !== MANIFEST_SCHEMA ? `manifest schema mismatch: ${schema ?? "missing"}` : "",
    manifestTool !== configsTool ? `manifest tool mismatch: ${manifestTool ?? "missing"}` : "",
    manifestProfile !== profile.name ? `manifest profile mismatch: ${manifestProfile ?? "missing"}` : "",
    targetHome !== profile.dir ? "manifest targetHome mismatch" : "",
  ].filter(Boolean);

  let drift: ConfigsManifestDrift = mismatchReasons.length > 0 ? "mismatch" : "ok";
  const fileCheck = targetHome ? checkManifestFiles(parsed, targetHome) : { drift: "invalid" as const, reasons: ["manifest targetHome is missing"] };
  const reasons = [...mismatchReasons, ...fileCheck.reasons];
  if (fileCheck.drift === "invalid") drift = "invalid";
  else if (drift === "ok" && fileCheck.drift === "stale") drift = "stale";

  return {
    path,
    exists: true,
    hash: sha256(raw),
    schema,
    tool: manifestTool,
    profile: manifestProfile,
    targetHome,
    generatedAt,
    sourceIds: sources.ids,
    sourceCount: sources.count,
    sourceIdsTruncated: sources.truncated,
    fileCount: fileCheck.fileCount,
    drift,
    reasons: boundedReasons(reasons),
  };
}

export function readConfigsPrelaunchAudit(profile: Profile, tool?: ToolDef): ConfigsPrelaunchAudit | undefined {
  const path = configsPrelaunchAuditPath(profile);
  if (!existsSync(path)) return undefined;
  try {
    const parsed = asRecord(JSON.parse(readFileSync(path, "utf8")));
    if (!parsed || parsed["schema"] !== STATUS_SCHEMA) return undefined;
    if (parsed["profile"] !== profile.name) return undefined;
    if (tool && parsed["tool"] !== tool.id) return undefined;
    return parsed as unknown as ConfigsPrelaunchAudit;
  } catch {
    return undefined;
  }
}

function statusFrom(lastRun: ConfigsPrelaunchAudit | undefined, manifest: ConfigsPrelaunchManifestStatus): ConfigsPrelaunchStatus {
  if (manifest.drift === "unsupported") return "unsupported";
  if (lastRun?.result === "skipped") return "skipped";
  if (lastRun?.result === "bypassed") return "bypassed";
  if (lastRun?.result === "failed") return "failed";
  if (lastRun?.result === "planned") return "planned";
  return manifest.drift;
}

export function getConfigsPrelaunchSummary(profile: Profile, tool: ToolDef, configsTool?: string): ConfigsPrelaunchSummary {
  const manifest = assessConfigsManifest(profile, tool, configsTool);
  const lastRun = readConfigsPrelaunchAudit(profile, tool);
  const status = statusFrom(lastRun, manifest);
  const reasons = boundedReasons([
    ...(lastRun?.reason ? [lastRun.reason] : []),
    ...manifest.reasons,
  ]);
  return {
    supported: Boolean(configsTool),
    required: Boolean(configsTool),
    status,
    reasons,
    manifest,
    ...(lastRun ? { lastRun } : {}),
  };
}

export function recordConfigsPrelaunchAudit(
  profile: Profile,
  tool: ToolDef,
  configsTool: string | undefined,
  input: RecordConfigsPrelaunchAuditInput,
): ConfigsPrelaunchSummary {
  const manifest = assessConfigsManifest(profile, tool, configsTool);
  const audit: ConfigsPrelaunchAudit = {
    schema: STATUS_SCHEMA,
    tool: tool.id,
    profile: profile.name,
    mode: input.mode,
    result: input.result,
    allowFailure: input.allowFailure ?? false,
    ...(input.reason ? { reason: input.reason.slice(0, MAX_REASON_LENGTH) } : {}),
    ...(input.statusCode !== undefined ? { statusCode: input.statusCode } : {}),
    identityExportCount: input.identityExportCount ?? 0,
    ...(input.shortfallGuard ? { shortfallGuard: input.shortfallGuard } : {}),
    updatedAt: new Date().toISOString(),
    manifest: {
      path: manifest.path,
      ...(manifest.hash ? { hash: manifest.hash } : {}),
      ...(manifest.generatedAt ? { generatedAt: manifest.generatedAt } : {}),
      drift: manifest.drift,
      sourceCount: manifest.sourceCount,
      sourceIds: manifest.sourceIds,
      sourceIdsTruncated: manifest.sourceIdsTruncated,
    },
  };
  const path = configsPrelaunchAuditPath(profile);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(audit, null, 2) + "\n", { mode: 0o600 });
  return getConfigsPrelaunchSummary(profile, tool, configsTool);
}
