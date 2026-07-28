import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { AccountsError } from "../types.js";

function lstatIfExists(path: string) {
  try {
    return lstatSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    return undefined;
  }
}

function throwIfSymlink(path: string, label: string): void {
  if (lstatIfExists(path)?.isSymbolicLink()) {
    throw new AccountsError(`${label}: ${path}`);
  }
}

function isAllowedSystemDirectorySymlink(path: string): boolean {
  if (path !== "/var" && path !== "/tmp") return false;
  try {
    return realpathSync(path) === `/private${path}`;
  } catch {
    return false;
  }
}

function assertDirectory(path: string, label: string, opts?: { allowSystemSymlink?: boolean }): void {
  const stat = lstatIfExists(path);
  if (!stat) {
    throw new AccountsError(`refusing to write under missing directory: ${path}`);
  }
  if (stat.isSymbolicLink()) {
    if (opts?.allowSystemSymlink && isAllowedSystemDirectorySymlink(path)) return;
    throw new AccountsError(`${label}: ${path}`);
  }
  if (!stat.isDirectory()) {
    throw new AccountsError(`refusing to write under non-directory path: ${path}`);
  }
}

function assertInsideBase(absPath: string, base: string, originalPath: string): string {
  const rel = relative(base, absPath);
  if (rel === "") return rel;
  if (rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) {
    throw new AccountsError(`refusing to write outside profile directory: ${originalPath}`);
  }
  return rel;
}

function assertExistingDirectoryComponentsSafe(path: string, label: string): void {
  const root = parse(path).root;
  const rel = relative(root, path);
  const segments = rel ? rel.split(sep).filter(Boolean) : [];
  let cursor = root;

  assertDirectory(cursor, label, { allowSystemSymlink: true });
  for (const segment of segments) {
    cursor = join(cursor, segment);
    if (!lstatIfExists(cursor)) return;
    assertDirectory(cursor, label, { allowSystemSymlink: true });
  }
}

function ensureBoundaryRootSafe(base: string): void {
  const missing: string[] = [];
  let cursor = base;

  while (!lstatIfExists(cursor)) {
    missing.unshift(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }

  assertDirectory(cursor, "refusing to use symlink base directory");
  for (const dir of missing) {
    if (lstatIfExists(dir)) {
      assertDirectory(dir, "refusing to use symlink base directory");
    } else {
      mkdirSync(dir);
      assertDirectory(dir, "refusing to use symlink base directory");
    }
  }
  assertDirectory(base, "refusing to use symlink base directory");
}

function ensureDirectoryChainSafe(parent: string, startAt?: string): void {
  const root = startAt ?? parse(parent).root;
  const rel = relative(root, parent);
  const segments = rel ? rel.split(sep).filter(Boolean) : [];
  let cursor = root;

  if (startAt) assertDirectory(startAt, "refusing to write under symlink directory");

  for (const segment of segments) {
    cursor = join(cursor, segment);
    if (lstatIfExists(cursor)) {
      assertDirectory(cursor, "refusing to write under symlink directory");
    } else {
      mkdirSync(cursor);
      assertDirectory(cursor, "refusing to write under symlink directory");
    }
  }
}

/** Refuse writes through symlinks; optionally confine to a base directory. */
export function assertSafeWritePath(filePath: string, opts?: { mustStayUnder?: string }): string {
  const absFile = resolve(filePath);
  const parent = dirname(absFile);
  const base = opts?.mustStayUnder ? resolve(opts.mustStayUnder) : undefined;

  if (base) {
    assertInsideBase(absFile, base, filePath);
    assertExistingDirectoryComponentsSafe(base, "refusing to use symlink base directory");
    ensureBoundaryRootSafe(base);
    ensureDirectoryChainSafe(parent, base);
  } else {
    ensureDirectoryChainSafe(parent);
  }

  throwIfSymlink(absFile, "refusing to write through symlink");
  const resolved = realpathSync(existsSync(absFile) ? absFile : parent);
  if (base) {
    const realBase = realpathSync(base);
    if (resolved !== realBase && !resolved.startsWith(realBase + sep)) {
      throw new AccountsError(`refusing to write outside profile directory: ${filePath}`);
    }
  }
  return resolved;
}

/**
 * Write a file so an interrupted or short write can never be observed: the
 * content lands in a fresh temp file, is fsynced, and is moved into place with
 * a single rename. Anything that reads the target sees either the old bytes or
 * the new ones, never a truncated prefix.
 *
 * `mode` is applied explicitly after the rename because `writeFileSync`'s mode
 * only takes effect when it creates the file — it will not tighten an existing
 * one.
 */
export function writeFileAtomic(
  path: string,
  contents: string,
  opts: { mode: number; mustStayUnder?: string },
): void {
  const guard = opts.mustStayUnder ? { mustStayUnder: opts.mustStayUnder } : undefined;
  assertSafeWritePath(path, guard);
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  assertSafeWritePath(temp, guard);
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", opts.mode);
    writeFileSync(fd, contents, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    chmodSync(path, opts.mode);
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}
