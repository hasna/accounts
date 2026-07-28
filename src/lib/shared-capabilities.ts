import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  symlinkSync,
  unlinkSync,
} from "node:fs";
import { platform } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { ToolDef } from "../types.js";
import { accountsHome } from "../storage.js";
import { writeFileAtomic } from "./safe-path.js";

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
  /** `unreadable` means the profile's file exists but does not parse — never merge into it. */
  status: "shared" | "missing" | "unavailable" | "unreadable";
  target: string;
  /** Member count available in the shared home. */
  shared: number;
  /** Member count present in the profile. */
  profile: number;
  reason?: string;
}

/**
 * A shared corpus is write-through, so a profile can destroy it for every other
 * profile. Comparing realpaths only proves the pointer is right — it says
 * nothing about whether the corpus still has anything in it. The floor is the
 * high-water mark recorded when the link was made or last confirmed.
 */
export interface SharedCapabilityFloor {
  entries: number;
  digest: string;
  recordedAt: string;
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

/**
 * Every profile-relative entry linked to the shared home: the declared
 * capability corpora plus the tool's session entries. Session entries are
 * derived from `ToolDef.sessions` rather than restated in `sharedEntries` so
 * the two can never disagree about which paths a merge is expected to free.
 */
export function sharedEntriesFor(tool: ToolDef): string[] {
  const sessions = tool.sessions ? [tool.sessions.transcripts, tool.sessions.history] : [];
  return [...new Set([...(tool.sharedEntries ?? []), ...sessions])];
}

export function toolSharesCapabilities(tool: ToolDef): boolean {
  return sharedEntriesFor(tool).length > 0 || tool.sharedConfig !== undefined;
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

/**
 * "Absent" and "unreadable" must never collapse into the same answer. Treating
 * an unparseable file as `{}` and writing a merge result over it destroys
 * whatever the file still held — for `.claude.json` that is the account's
 * identity.
 */
type JsonDocument =
  | { state: "absent" }
  | { state: "unreadable"; reason: string }
  | { state: "object"; value: JsonRecord };

function readJsonDocument(path: string): JsonDocument {
  if (!existsSync(path)) return { state: "absent" };
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    return { state: "unreadable", reason: message(err) };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (err) {
    return { state: "unreadable", reason: `invalid JSON (${message(err)})` };
  }
  if (!isPlainObject(parsed)) return { state: "unreadable", reason: "top-level value is not a JSON object" };
  return { state: "object", value: parsed };
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

/** An unsubstituted `{{TEMPLATE}}` marker anywhere in a member's definition. */
function hasUnrenderedPlaceholder(value: unknown): boolean {
  return /\{\{[^}]*\}\}/.test(JSON.stringify(value) ?? "");
}

/**
 * Members are unioned across every source and the first definition of a member
 * name wins, so the tool can list rendered files ahead of raw ones without
 * losing anything only the raw file declares. A member whose definition still
 * carries an unsubstituted placeholder is dropped: shipping it would put a
 * server into every profile that cannot start.
 */
function readSharedConfig(sharedHome: string, tool: ToolDef): Record<string, JsonRecord> {
  const config = tool.sharedConfig;
  const found: Record<string, JsonRecord> = {};
  if (!config) return found;
  const excluded = new Set(config.exclude ?? []);
  for (const rel of config.sources) {
    const path = resolveSharedSource(sharedHome, rel);
    if (!path) continue;
    const doc = readJsonDocument(path);
    if (doc.state !== "object") continue;
    for (const key of config.keys) {
      const value = doc.value[key];
      if (!isPlainObject(value)) continue;
      const target = (found[key] ??= {});
      for (const [member, definition] of Object.entries(value)) {
        if (member in target || excluded.has(member)) continue;
        if (hasUnrenderedPlaceholder(definition)) continue;
        target[member] = definition;
      }
    }
  }
  for (const key of Object.keys(found)) {
    if (Object.keys(found[key]!).length === 0) delete found[key];
  }
  return found;
}

function mergeSharedConfig(ctx: SharedContext, tool: ToolDef, result: SharedCapabilitiesResult): void {
  const config = tool.sharedConfig;
  if (!config) return;
  const shared = readSharedConfig(ctx.sharedHome, tool);
  if (Object.keys(shared).length === 0) return;

  const targetPath = join(ctx.profileDir, config.target);
  const doc = readJsonDocument(targetPath);
  if (doc.state === "unreadable") {
    // The file exists and holds bytes we cannot interpret. Merging would mean
    // writing a document built from `{}` over the profile's identity.
    result.errors.push(
      `${config.target}: could not be read (${doc.reason}); refusing to merge shared config over it`,
    );
    return;
  }
  const current = doc.state === "object" ? doc.value : {};
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
    writeFileAtomic(targetPath, JSON.stringify(next, null, 2) + "\n", {
      mode: 0o600,
      mustStayUnder: ctx.profileDir,
    });
    result.seededKeys.push(...seeded);
  } catch (err) {
    result.errors.push(`${config.target}: could not merge shared config (${message(err)})`);
  }
}

// --- corpus floor -----------------------------------------------------------

const CORPUS_BASELINE_FILE = "capability-baseline.json";

interface CorpusBaselineFile {
  version: 1;
  corpora: Record<string, SharedCapabilityFloor>;
}

function baselinePath(): string {
  return join(accountsHome(), CORPUS_BASELINE_FILE);
}

function readBaselines(): CorpusBaselineFile {
  const doc = readJsonDocument(baselinePath());
  if (doc.state !== "object") return { version: 1, corpora: {} };
  const corpora = isPlainObject(doc.value.corpora) ? (doc.value.corpora as Record<string, SharedCapabilityFloor>) : {};
  return { version: 1, corpora };
}

function writeBaselines(file: CorpusBaselineFile): void {
  writeFileAtomic(baselinePath(), JSON.stringify(file, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
}

/** Every file under `path`, relative to it. Bounded so a link loop cannot hang. */
function listFilesRecursively(path: string, rel = "", depth = 0): string[] | undefined {
  if (depth > 32) return [];
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return undefined;
  }
  const found: string[] = [];
  for (const entry of entries) {
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      found.push(...(listFilesRecursively(join(path, entry.name), childRel, depth + 1) ?? []));
    } else {
      found.push(childRel);
    }
  }
  return found;
}

/**
 * Census of a shared corpus: entry count plus a digest of the sorted names.
 *
 * Flat corpora (skills, subagents) are counted at the top level, where one
 * directory is one skill. A session tree must be counted RECURSIVELY: its top
 * level is one directory per project, so every transcript inside them could be
 * deleted without the top-level count moving at all — the floor would be blind
 * to exactly the loss it exists to catch.
 */
function measureCorpus(path: string, recursive: boolean): SharedCapabilityFloor | undefined {
  let names: string[] | undefined;
  if (recursive) {
    names = listFilesRecursively(path);
  } else {
    try {
      names = readdirSync(path);
    } catch {
      names = undefined;
    }
  }
  if (!names) return undefined;
  names = [...names].sort();
  return {
    entries: names.length,
    digest: createHash("sha256").update(names.join("\n")).digest("hex").slice(0, 16),
    recordedAt: new Date().toISOString(),
  };
}

/** Session trees nest; capability corpora do not. */
function corpusIsRecursive(tool: ToolDef, entry: string): boolean {
  return tool.sessions?.transcripts === entry;
}

function corpusKey(source: string): string {
  return realpathIfExists(source) ?? resolve(source);
}

/**
 * Raise the floor to the current census, never lower it. Growth is normal;
 * shrinkage is the event this exists to catch, so it takes an explicit
 * `resetCapabilityBaseline` to accept it.
 */
function recordCorpusFloor(source: string, recursive: boolean): void {
  const current = measureCorpus(source, recursive);
  if (!current) return;
  const key = corpusKey(source);
  try {
    const file = readBaselines();
    const previous = file.corpora[key];
    if (previous && previous.entries >= current.entries) return;
    file.corpora[key] = current;
    writeBaselines(file);
  } catch {
    // The floor is a tripwire, not a prerequisite: never break a launch over it.
  }
}

function corpusFloor(source: string): SharedCapabilityFloor | undefined {
  return readBaselines().corpora[corpusKey(source)];
}

/** Forget the recorded floors for a tool's shared entries and re-record them. */
export function resetCapabilityBaseline(tool: ToolDef): void {
  const sharedHome = sharedHomeFor(tool);
  const file = readBaselines();
  for (const entry of sharedEntriesFor(tool)) {
    const source = join(sharedHome, entry);
    const current = measureCorpus(source, corpusIsRecursive(tool, entry));
    if (current) file.corpora[corpusKey(source)] = current;
    else delete file.corpora[corpusKey(source)];
  }
  writeBaselines(file);
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
  for (const entry of sharedEntriesFor(tool)) {
    shareEntry(ctx, entry, result);
    if (result.linked.includes(entry) || result.repaired.includes(entry) || result.kept.includes(entry)) {
      recordCorpusFloor(join(ctx.sharedHome, entry), corpusIsRecursive(tool, entry));
    }
  }
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
  const doc = readJsonDocument(targetPath);
  return config.keys.map((key) => {
    const sharedCount = Object.keys(shared[key] ?? {}).length;
    if (doc.state === "unreadable") {
      // Reporting this as "empty" would be the wrong diagnosis and would invite
      // the very repair that must not run against an unparseable file.
      return { key, status: "unreadable" as const, target: targetPath, shared: sharedCount, profile: 0, reason: doc.reason };
    }
    const value = doc.state === "object" ? doc.value[key] : undefined;
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
    health.entries = sharedEntriesFor(tool).map((entry) => ({
      entry,
      status: "unavailable" as const,
      target: join(profileDir, entry),
      source: join(sharedHome, entry),
    }));
    return health;
  }

  health.entries = sharedEntriesFor(tool).map((entry) => entryHealth(sharedHome, profileDir, entry));
  health.config = configHealth(sharedHome, profileDir, tool);

  for (const entry of health.entries) {
    if (entry.status === "missing") health.problems.push(`${entry.entry} is not shared (expected a link to ${entry.source})`);
    else if (entry.status === "diverged") health.problems.push(`${entry.entry} links to ${realpathIfExists(entry.target)}, not ${entry.source}`);
    else if (entry.status === "local") health.warnings.push(`${entry.entry} is a profile-local copy, not the shared corpus`);
    if (entry.status !== "shared") continue;
    // The link being correct says nothing about the corpus still having
    // anything in it — a delete through the link leaves the pointer intact.
    const floor = corpusFloor(entry.source);
    const current = measureCorpus(entry.source, corpusIsRecursive(tool, entry.entry));
    if (floor && current && current.entries < floor.entries) {
      health.problems.push(
        `${entry.entry} corpus has shrunk: ${current.entries} entries in ${entry.source}, was ${floor.entries} ` +
          `(if the removal was intended, re-baseline with \`accounts doctor --accept-capability-baseline\`)`,
      );
    }
  }
  for (const key of health.config) {
    if (key.status === "unreadable") {
      health.problems.push(`${key.target} could not be read (${key.reason}); shared config is not merged into it`);
    } else if (key.status === "missing") {
      health.problems.push(`${key.key} is empty in ${key.target} (${key.shared} available in the shared home)`);
    }
  }
  return health;
}
