import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { platform } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { ToolDef } from "../types.js";
import { assertSafeWritePath } from "./safe-path.js";

/**
 * Capabilities (skills, subagents, MCP servers) belong to the person using the
 * machine; credentials belong to the account. A profile is an isolated config
 * dir, so without this module a profile starts with an empty capability set —
 * the tool is pointed at a directory that has none of the user's work in it.
 *
 * Entries listed in `ToolDef.sharedEntries` are symlinked to the tool's shared
 * home, so there is exactly one corpus and an edit made from any profile is an
 * edit to that corpus. Keys listed in `ToolDef.sharedConfig` are merged instead,
 * because the file that holds them is rewritten in place by the tool (and by
 * `sanitizeSettingsFile`), and `assertSafeWritePath` refuses to write through a
 * symlink.
 */

export type SharedEntryStatus =
  /** Profile entry resolves to the shared home's entry. */
  | "shared"
  /** Nothing at the profile path, or a link that resolves to nothing. */
  | "missing"
  /** A link that resolves somewhere other than the shared corpus. */
  | "diverged"
  /** A real directory/file the profile owns; never replaced. */
  | "local"
  /** The shared home has no such entry, so there is nothing to share. */
  | "unavailable";

export interface SharedCapabilitiesResult {
  supported: boolean;
  sharedHome?: string;
  /** Entries linked for the first time. */
  linked: string[];
  /** Entries whose link was dangling or pointed elsewhere and was re-pointed. */
  repaired: string[];
  /** Entries that already resolved to the shared corpus. */
  kept: string[];
  skipped: { entry: string; reason: string }[];
  /** Config keys whose members were merged into the profile's file. */
  seededKeys: string[];
  errors: string[];
}

export interface SharedCapabilityEntryHealth {
  entry: string;
  status: SharedEntryStatus;
  target: string;
  source: string;
}

export interface SharedCapabilityConfigHealth {
  key: string;
  status: "shared" | "missing" | "unavailable";
  target: string;
  /** Member count available in the shared home. */
  shared: number;
  /** Member count present in the profile. */
  profile: number;
}

export interface SharedCapabilityHealth {
  supported: boolean;
  sharedHome: string;
  sharedHomeExists: boolean;
  entries: SharedCapabilityEntryHealth[];
  config: SharedCapabilityConfigHealth[];
  problems: string[];
  warnings: string[];
}

type JsonRecord = Record<string, unknown>;

function envSuffix(toolId: string): string {
  return toolId.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
}

/**
 * The machine-local root the tool reads when no profile is active — its default
 * config dir, overridable per tool with `ACCOUNTS_SHARED_HOME_<TOOL_ID>`.
 *
 * This is deliberately machine-local configuration and never a registry field:
 * profile directories are machine-local (see `importProfile`), so a path stored
 * in a shared registry would be wrong on every other machine.
 */
export function sharedHomeFor(tool: ToolDef): string {
  const override = process.env[`ACCOUNTS_SHARED_HOME_${envSuffix(tool.id)}`];
  const value = override && override.trim() ? override.trim() : tool.defaultDir;
  return resolve(value);
}

export function toolSharesCapabilities(tool: ToolDef): boolean {
  return (tool.sharedEntries?.length ?? 0) > 0 || tool.sharedConfig !== undefined;
}

function lstatIfExists(path: string) {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function realpathIfExists(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    return undefined;
  }
}

function samePath(a: string, b: string): boolean {
  const realA = realpathIfExists(a) ?? resolve(a);
  const realB = realpathIfExists(b) ?? resolve(b);
  return realA === realB;
}

function isPlainObject(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readJsonFile(path: string): JsonRecord | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    return isPlainObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Resolve a shared-home-relative config source, refusing anything that escapes
 * the tool's home root (`dirname(sharedHome)`) — the schema allows one leading
 * `..` so a tool can read its sibling account file, and nothing further.
 */
function resolveSharedSource(sharedHome: string, rel: string): string | undefined {
  const abs = resolve(sharedHome, rel);
  const boundary = dirname(sharedHome);
  const relToBoundary = relative(boundary, abs);
  if (relToBoundary === "" || relToBoundary.startsWith("..") || isAbsolute(relToBoundary)) return undefined;
  return abs;
}

/** Windows needs an explicit type; junctions work for directories without elevation. */
function linkTypeFor(source: string): "junction" | "file" | undefined {
  if (platform() !== "win32") return undefined;
  try {
    return statSync(source).isDirectory() ? "junction" : "file";
  } catch {
    return undefined;
  }
}

interface SharedContext {
  sharedHome: string;
  profileDir: string;
}

function resolveContext(profileDir: string, tool: ToolDef): SharedContext | { skip: string } {
  const sharedHome = sharedHomeFor(tool);
  if (!existsSync(profileDir)) return { skip: `profile dir does not exist: ${profileDir}` };
  if (!existsSync(sharedHome)) return { skip: `shared home does not exist: ${sharedHome}` };
  if (samePath(sharedHome, profileDir)) return { skip: "profile dir is the shared home" };
  return { sharedHome, profileDir: resolve(profileDir) };
}

function shareEntry(ctx: SharedContext, entry: string, result: SharedCapabilitiesResult): void {
  const source = join(ctx.sharedHome, entry);
  const target = join(ctx.profileDir, entry);
  if (!existsSync(source)) {
    result.skipped.push({ entry, reason: "shared home has no such entry" });
    return;
  }

  const existing = lstatIfExists(target);
  if (existing && !existing.isSymbolicLink()) {
    result.skipped.push({ entry, reason: "profile owns a real entry at this path" });
    return;
  }
  if (existing) {
    if (samePath(target, source) && realpathIfExists(target)) {
      result.kept.push(entry);
      return;
    }
    try {
      unlinkSync(target);
    } catch (err) {
      result.errors.push(`${entry}: could not replace stale link (${message(err)})`);
      return;
    }
    try {
      symlinkSync(source, target, linkTypeFor(source));
      result.repaired.push(entry);
    } catch (err) {
      result.errors.push(`${entry}: could not re-link (${message(err)})`);
    }
    return;
  }

  try {
    symlinkSync(source, target, linkTypeFor(source));
    result.linked.push(entry);
  } catch (err) {
    result.errors.push(`${entry}: could not link (${message(err)})`);
  }
}

/** First source that supplies a non-empty object for a key wins. */
function readSharedConfig(sharedHome: string, tool: ToolDef): Record<string, JsonRecord> {
  const config = tool.sharedConfig;
  const found: Record<string, JsonRecord> = {};
  if (!config) return found;
  for (const rel of config.sources) {
    const path = resolveSharedSource(sharedHome, rel);
    if (!path) continue;
    const data = readJsonFile(path);
    if (!data) continue;
    for (const key of config.keys) {
      if (found[key]) continue;
      const value = data[key];
      if (isPlainObject(value) && Object.keys(value).length > 0) found[key] = value;
    }
  }
  return found;
}

function mergeSharedConfig(ctx: SharedContext, tool: ToolDef, result: SharedCapabilitiesResult): void {
  const config = tool.sharedConfig;
  if (!config) return;
  const shared = readSharedConfig(ctx.sharedHome, tool);
  if (Object.keys(shared).length === 0) return;

  const targetPath = join(ctx.profileDir, config.target);
  const current = readJsonFile(targetPath) ?? {};
  const next: JsonRecord = { ...current };
  const seeded: string[] = [];

  for (const key of config.keys) {
    const sharedValue = shared[key];
    if (!sharedValue) continue;
    const existing = isPlainObject(current[key]) ? (current[key] as JsonRecord) : undefined;
    // Union by member name, profile always wins — so a profile keeps its own
    // overrides and additions while still gaining anything new in the shared set.
    const additions = Object.entries(sharedValue).filter(([member]) => !existing || !(member in existing));
    if (additions.length === 0) continue;
    next[key] = { ...(existing ?? {}), ...Object.fromEntries(additions) };
    seeded.push(key);
  }

  if (seeded.length === 0) return;
  try {
    assertSafeWritePath(targetPath, { mustStayUnder: ctx.profileDir });
    writeFileSync(targetPath, JSON.stringify(next, null, 2) + "\n", { mode: 0o600 });
    result.seededKeys.push(...seeded);
  } catch (err) {
    result.errors.push(`${config.target}: could not merge shared config (${message(err)})`);
  }
}

/**
 * Point a profile at the machine's shared capability corpus. Idempotent: a
 * correct link is left alone, a dangling or misdirected link is re-pointed, and
 * a real directory the profile owns is never replaced. Best-effort by design —
 * it runs on every launch, so a filesystem that refuses a link must not stop the
 * tool from starting. `accounts doctor` reports what is actually on disk.
 */
export function ensureSharedCapabilities(profileDir: string, tool: ToolDef): SharedCapabilitiesResult {
  const result: SharedCapabilitiesResult = {
    supported: toolSharesCapabilities(tool),
    linked: [],
    repaired: [],
    kept: [],
    skipped: [],
    seededKeys: [],
    errors: [],
  };
  if (!result.supported) return result;

  const ctx = resolveContext(profileDir, tool);
  if ("skip" in ctx) {
    result.skipped.push({ entry: "*", reason: ctx.skip });
    return result;
  }

  result.sharedHome = ctx.sharedHome;
  for (const entry of tool.sharedEntries ?? []) shareEntry(ctx, entry, result);
  mergeSharedConfig(ctx, tool, result);
  return result;
}

function entryHealth(sharedHome: string, profileDir: string, entry: string): SharedCapabilityEntryHealth {
  const source = join(sharedHome, entry);
  const target = join(profileDir, entry);
  const base = { entry, target, source };
  if (!existsSync(source)) return { ...base, status: "unavailable" };

  const link = lstatIfExists(target);
  if (!link) return { ...base, status: "missing" };
  if (!link.isSymbolicLink()) return { ...base, status: "local" };

  // realpath, never lstat/existsSync alone: a dangling link must fail, and only
  // realpath equality proves the profile reads the same corpus.
  const realTarget = realpathIfExists(target);
  if (!realTarget) return { ...base, status: "missing" };
  const realSource = realpathIfExists(source);
  return { ...base, status: realSource && realTarget === realSource ? "shared" : "diverged" };
}

function configHealth(sharedHome: string, profileDir: string, tool: ToolDef): SharedCapabilityConfigHealth[] {
  const config = tool.sharedConfig;
  if (!config) return [];
  const shared = readSharedConfig(sharedHome, tool);
  const targetPath = join(profileDir, config.target);
  const current = readJsonFile(targetPath) ?? {};
  return config.keys.map((key) => {
    const sharedCount = Object.keys(shared[key] ?? {}).length;
    const value = current[key];
    const profileCount = isPlainObject(value) ? Object.keys(value).length : 0;
    const status = sharedCount === 0 ? "unavailable" : profileCount === 0 ? "missing" : "shared";
    return { key, status, target: targetPath, shared: sharedCount, profile: profileCount };
  });
}

/**
 * Read-only capability report for `accounts doctor`. Absence and dangling links
 * are problems; a real directory the profile owns is a warning, because it is a
 * deliberate local override rather than a defect.
 */
export function sharedCapabilityHealth(profileDir: string, tool: ToolDef): SharedCapabilityHealth {
  const sharedHome = sharedHomeFor(tool);
  const health: SharedCapabilityHealth = {
    supported: toolSharesCapabilities(tool),
    sharedHome,
    sharedHomeExists: existsSync(sharedHome),
    entries: [],
    config: [],
    problems: [],
    warnings: [],
  };
  if (!health.supported) return health;
  if (!health.sharedHomeExists || samePath(sharedHome, profileDir)) {
    health.entries = (tool.sharedEntries ?? []).map((entry) => ({
      entry,
      status: "unavailable" as const,
      target: join(profileDir, entry),
      source: join(sharedHome, entry),
    }));
    return health;
  }

  health.entries = (tool.sharedEntries ?? []).map((entry) => entryHealth(sharedHome, profileDir, entry));
  health.config = configHealth(sharedHome, profileDir, tool);

  for (const entry of health.entries) {
    if (entry.status === "missing") health.problems.push(`${entry.entry} is not shared (expected a link to ${entry.source})`);
    else if (entry.status === "diverged") health.problems.push(`${entry.entry} links to ${realpathIfExists(entry.target)}, not ${entry.source}`);
    else if (entry.status === "local") health.warnings.push(`${entry.entry} is a profile-local copy, not the shared corpus`);
  }
  for (const key of health.config) {
    if (key.status === "missing") health.problems.push(`${key.key} is empty in ${key.target} (${key.shared} available in the shared home)`);
  }
  return health;
}
