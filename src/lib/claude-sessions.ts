import {
  closeSync,
  constants,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  type Dirent,
  type Stats,
} from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import type { Profile } from "../types.js";
import { profilesDir } from "../storage.js";
import { getTool } from "./tools.js";

export const CLAUDE_SESSION_METADATA_MAX_BYTES = 64 * 1024;
export const CLAUDE_SESSION_METADATA_MAX_LINES = 32;

const UUID_JSONL = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/i;

export interface ClaudeSessionIdentity {
  ownerProfile: string;
  projectIdentity: string;
  uuid: string;
}

export interface ClaudeSessionCatalogEntry {
  identity: ClaudeSessionIdentity;
  ownerProfile: string;
  encodedProject: string;
  projectIdentity: string;
  cwd?: string;
  uuid: string;
  sourcePath: string;
  sizeBytes: number;
  updatedAt: string;
}

export interface ClaudeSessionCatalogOptions {
  /** Accounts-managed profiles root. Overridable for isolated tests. */
  profilesRoot?: string;
  /** Claude's live/default config dir. Overridable for isolated tests. */
  defaultDir?: string;
  profile?: string;
  project?: string;
  uuid?: string;
  metadataMaxBytes?: number;
  metadataMaxLines?: number;
}

interface VerifiedProfileRoot {
  ownerProfile: string;
  dir: string;
}

function safeResolve(path: string): string | undefined {
  if (!path || !isAbsolute(path) || path.includes("\0") || /[\r\n]/.test(path)) return undefined;
  try {
    return resolve(path);
  } catch {
    return undefined;
  }
}

function lstatNoThrow(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function realDirectory(path: string): boolean {
  const stat = lstatNoThrow(path);
  return Boolean(stat?.isDirectory() && !stat.isSymbolicLink());
}

function readDirectory(path: string): Dirent[] {
  if (!realDirectory(path)) return [];
  try {
    return readdirSync(path, { withFileTypes: true });
  } catch {
    return [];
  }
}

/**
 * Accept only profile roots represented by Accounts on this machine:
 * the exact managed `profiles/claude/<owner>` path, or Claude's exact default
 * dir when a registry profile explicitly points at it. Cloud-stale `/Users`,
 * `/tmp`, and other foreign paths therefore never become discovery roots.
 */
function verifyProfileRoot(
  profile: Profile,
  managedRoot: string,
  defaultRoot: string,
): VerifiedProfileRoot | undefined {
  if (profile.tool !== "claude") return undefined;
  const dir = safeResolve(profile.dir);
  if (!dir) return undefined;
  const expectedManaged = resolve(managedRoot, "claude", profile.name);
  if (dir !== expectedManaged && dir !== defaultRoot) return undefined;
  if (dir === expectedManaged && (!realDirectory(managedRoot) || !realDirectory(resolve(managedRoot, "claude")))) {
    return undefined;
  }
  if (!realDirectory(dir)) return undefined;
  return { ownerProfile: profile.name, dir };
}

function scanJsonStringEnd(value: string, start: number): number {
  if (value[start] !== '"') return -1;
  let escaped = false;
  for (let i = start + 1; i < value.length; i++) {
    const char = value[i]!;
    if (escaped) {
      escaped = false;
    } else if (char === "\\") {
      escaped = true;
    } else if (char === '"') {
      return i + 1;
    }
  }
  return -1;
}

function skipWhitespace(value: string, start: number): number {
  let i = start;
  while (i < value.length && /\s/.test(value[i]!)) i++;
  return i;
}

/** Skip one JSON value without decoding transcript-owned nested content. */
function skipJsonValue(value: string, start: number): number {
  const first = value[start];
  if (!first) return -1;
  if (first === '"') return scanJsonStringEnd(value, start);
  if (first !== "{" && first !== "[") {
    let i = start;
    while (i < value.length && value[i] !== "," && value[i] !== "}") i++;
    return i;
  }

  const stack: string[] = [first];
  for (let i = start + 1; i < value.length; i++) {
    const char = value[i]!;
    if (char === '"') {
      const end = scanJsonStringEnd(value, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (char === "{" || char === "[") {
      stack.push(char);
      continue;
    }
    if (char === "}" || char === "]") {
      const expected = char === "}" ? "{" : "[";
      if (stack.pop() !== expected) return -1;
      if (stack.length === 0) return i + 1;
    }
  }
  return -1;
}

/**
 * Extract one top-level string field while skipping every other value.
 * Only the requested JSON string token is decoded; prompts/messages are never
 * parsed into application objects or returned by the catalog.
 */
function topLevelString(line: string, wantedKey: string): string | undefined {
  let i = skipWhitespace(line, 0);
  if (line[i] !== "{") return undefined;
  i++;

  while (i < line.length) {
    i = skipWhitespace(line, i);
    if (line[i] === "}") return undefined;
    const keyEnd = scanJsonStringEnd(line, i);
    if (keyEnd < 0) return undefined;

    let key: unknown;
    try {
      key = JSON.parse(line.slice(i, keyEnd));
    } catch {
      return undefined;
    }

    i = skipWhitespace(line, keyEnd);
    if (line[i] !== ":") return undefined;
    i = skipWhitespace(line, i + 1);
    const valueStart = i;
    const valueEnd = skipJsonValue(line, valueStart);
    if (valueEnd < 0) return undefined;

    if (key === wantedKey && line[valueStart] === '"') {
      try {
        const decoded = JSON.parse(line.slice(valueStart, valueEnd)) as unknown;
        return typeof decoded === "string" ? decoded : undefined;
      } catch {
        return undefined;
      }
    }

    i = skipWhitespace(line, valueEnd);
    if (line[i] === ",") {
      i++;
      continue;
    }
    if (line[i] === "}") return undefined;
    return undefined;
  }
  return undefined;
}

function canonicalCwd(value: string): string | undefined {
  const resolved = safeResolve(value);
  if (!resolved) return undefined;
  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function readBoundedCwd(
  path: string,
  sizeBytes: number,
  maxBytes: number,
  maxLines: number,
): string | undefined {
  if (sizeBytes <= 0 || maxBytes <= 0 || maxLines <= 0) return undefined;
  const readLength = Math.min(sizeBytes, maxBytes);
  const buffer = Buffer.allocUnsafe(readLength);
  let fd: number | undefined;
  let bytesRead = 0;
  try {
    const noFollow = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;
    fd = openSync(path, constants.O_RDONLY | noFollow);
    bytesRead = readSync(fd, buffer, 0, readLength, 0);
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }

  const text = buffer.subarray(0, bytesRead).toString("utf8");
  const lines = text.split("\n");
  if (sizeBytes > maxBytes && !text.endsWith("\n")) lines.pop();

  for (const rawLine of lines.slice(0, maxLines)) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const cwd = topLevelString(line, "cwd");
    if (cwd !== undefined) return canonicalCwd(cwd);
  }
  return undefined;
}

function matchesFilters(entry: ClaudeSessionCatalogEntry, options: ClaudeSessionCatalogOptions): boolean {
  if (options.profile && entry.ownerProfile !== options.profile) return false;
  if (options.uuid && entry.uuid !== options.uuid.toLowerCase()) return false;
  const projectFilter = options.project ? (canonicalCwd(options.project) ?? options.project) : undefined;
  if (
    projectFilter &&
    entry.projectIdentity !== projectFilter &&
    entry.encodedProject !== projectFilter &&
    entry.cwd !== projectFilter
  ) {
    return false;
  }
  return true;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Discover root Claude JSONL sessions under Accounts-owned local profiles.
 * This function is strictly read-only and never follows session-store symlinks.
 */
export function listClaudeSessions(
  profiles: readonly Profile[],
  options: ClaudeSessionCatalogOptions = {},
): ClaudeSessionCatalogEntry[] {
  const managedRoot = resolve(options.profilesRoot ?? profilesDir());
  const defaultRoot = resolve(options.defaultDir ?? getTool("claude").defaultDir);
  const maxBytes = options.metadataMaxBytes ?? CLAUDE_SESSION_METADATA_MAX_BYTES;
  const maxLines = options.metadataMaxLines ?? CLAUDE_SESSION_METADATA_MAX_LINES;
  const results: ClaudeSessionCatalogEntry[] = [];

  for (const profile of profiles) {
    const verified = verifyProfileRoot(profile, managedRoot, defaultRoot);
    if (!verified) continue;
    const projectsPath = join(verified.dir, "projects");

    for (const projectDirent of readDirectory(projectsPath)) {
      if (!projectDirent.isDirectory() || projectDirent.isSymbolicLink()) continue;
      const encodedProject = projectDirent.name;
      const projectPath = join(projectsPath, encodedProject);
      if (!realDirectory(projectPath)) continue;

      for (const sessionDirent of readDirectory(projectPath)) {
        if (!sessionDirent.isFile() || sessionDirent.isSymbolicLink()) continue;
        const match = sessionDirent.name.match(UUID_JSONL);
        if (!match) continue;

        const sourcePath = join(projectPath, sessionDirent.name);
        const stat = lstatNoThrow(sourcePath);
        if (!stat?.isFile() || stat.isSymbolicLink()) continue;
        const uuid = match[1]!.toLowerCase();
        const cwd = readBoundedCwd(sourcePath, stat.size, maxBytes, maxLines);
        const projectIdentity = cwd ?? `encoded:${encodedProject}`;
        const entry: ClaudeSessionCatalogEntry = {
          identity: {
            ownerProfile: verified.ownerProfile,
            projectIdentity,
            uuid,
          },
          ownerProfile: verified.ownerProfile,
          encodedProject,
          projectIdentity,
          ...(cwd ? { cwd } : {}),
          uuid,
          sourcePath,
          sizeBytes: stat.size,
          updatedAt: new Date(stat.mtimeMs).toISOString(),
        };
        if (matchesFilters(entry, options)) results.push(entry);
      }
    }
  }

  return results.sort(
    (a, b) =>
      compareText(a.ownerProfile, b.ownerProfile) ||
      compareText(a.projectIdentity, b.projectIdentity) ||
      compareText(a.uuid, b.uuid) ||
      compareText(a.sourcePath, b.sourcePath),
  );
}
