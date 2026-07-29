import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { AccountsError } from "../types.js";

export const RUNTIME_PROVENANCE_SCHEMA = "hasna.accounts.runtime-provenance/v1" as const;
export const EXPECTED_HEAD_ENV = "HASNA_ACCOUNTS_EXPECTED_HEAD";

const FULL_GIT_HEAD = /^[0-9a-f]{40}$/;

export interface RuntimeProvenance {
  schema: typeof RUNTIME_PROVENANCE_SCHEMA;
  package: { name: "@hasna/accounts"; version: string; root: string };
  command: { entrypoint: string; executable: string };
  source: { head: string; kind: "build-manifest" | "git-worktree" };
  verifiable: true;
}

export interface PublicRuntimeProvenance {
  schema: typeof RUNTIME_PROVENANCE_SCHEMA;
  package: { name: "@hasna/accounts"; version: string };
  source: { head: string; kind: "build-manifest" | "git-worktree" };
  verifiable: true;
}

interface BuildManifest {
  schema: typeof RUNTIME_PROVENANCE_SCHEMA;
  package: { name: "@hasna/accounts"; version: string };
  source: { head: string };
}

export interface RuntimeProvenanceOptions {
  env?: NodeJS.ProcessEnv;
  entrypoint?: string;
  executable?: string;
  cwd?: string;
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new AccountsError(`could not read runtime provenance at ${path}: ${(err as Error).message}`);
  }
}

function packageAt(path: string): { name?: string; version?: string } | undefined {
  if (!existsSync(path)) return undefined;
  const value = readJson(path);
  return value && typeof value === "object" ? value as { name?: string; version?: string } : undefined;
}

function candidateRoots(entrypoint: string, cwd: string): string[] {
  const roots = new Set<string>();
  let cursor = dirname(entrypoint);
  for (let i = 0; i < 5; i += 1) {
    roots.add(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  roots.add(cwd);
  try {
    const moduleDir = dirname(fileURLToPath(import.meta.url));
    roots.add(moduleDir);
    roots.add(join(moduleDir, ".."));
    roots.add(join(moduleDir, "..", ".."));
  } catch {
    // The entrypoint and cwd candidates are sufficient in unusual loaders.
  }
  roots.add("/app");
  return [...roots].map((root) => resolve(root));
}

function findPackageRoot(roots: readonly string[]): { root: string; version: string } {
  for (const root of roots) {
    const pkg = packageAt(join(root, "package.json"));
    if (pkg?.name === "@hasna/accounts" && typeof pkg.version === "string" && pkg.version.length > 0) {
      return { root, version: pkg.version };
    }
  }
  throw new AccountsError(
    "cannot verify command provenance: package.json for @hasna/accounts was not found beside the active binary",
  );
}

function parseManifest(value: unknown, path: string): BuildManifest {
  if (!value || typeof value !== "object") {
    throw new AccountsError(`invalid runtime provenance manifest at ${path}`);
  }
  const manifest = value as Partial<BuildManifest>;
  const head = manifest.source?.head;
  if (
    manifest.schema !== RUNTIME_PROVENANCE_SCHEMA ||
    manifest.package?.name !== "@hasna/accounts" ||
    typeof manifest.package.version !== "string" ||
    typeof head !== "string" ||
    !FULL_GIT_HEAD.test(head)
  ) {
    throw new AccountsError(`invalid runtime provenance manifest at ${path}`);
  }
  return manifest as BuildManifest;
}

function gitHead(root: string): string | undefined {
  const result = spawnSync("git", ["-C", root, "rev-parse", "--verify", "HEAD"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const head = result.status === 0 ? result.stdout.trim().toLowerCase() : "";
  return FULL_GIT_HEAD.test(head) ? head : undefined;
}

function manifestCandidates(root: string, entrypoint: string, env: NodeJS.ProcessEnv): string[] {
  const candidates = new Set<string>();
  if (env.HASNA_ACCOUNTS_PROVENANCE_PATH?.trim()) {
    candidates.add(resolve(env.HASNA_ACCOUNTS_PROVENANCE_PATH.trim()));
  }
  candidates.add(join(dirname(entrypoint), "runtime-provenance.json"));
  candidates.add(join(dirname(entrypoint), "..", "runtime-provenance.json"));
  candidates.add(join(root, "dist", "runtime-provenance.json"));
  return [...candidates];
}

function pathWithin(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

export function runtimeProvenance(options: RuntimeProvenanceOptions = {}): RuntimeProvenance {
  const env = options.env ?? process.env;
  const cwd = resolve(options.cwd ?? process.cwd());
  const entrypoint = resolve(options.entrypoint ?? process.argv[1] ?? fileURLToPath(import.meta.url));
  const executable = resolve(options.executable ?? process.execPath);
  const roots = candidateRoots(entrypoint, cwd);
  const pkg = findPackageRoot(roots);

  let head: string | undefined;
  let kind: RuntimeProvenance["source"]["kind"] = "git-worktree";
  for (const candidate of manifestCandidates(pkg.root, entrypoint, env)) {
    if (!existsSync(candidate)) continue;
    const manifest = parseManifest(readJson(candidate), candidate);
    if (manifest.package.version !== pkg.version) {
      throw new AccountsError(
        `cannot reconcile package provenance: manifest version ${manifest.package.version} does not match package.json ${pkg.version}`,
      );
    }
    head = manifest.source.head;
    kind = "build-manifest";
    break;
  }
  head ??= gitHead(pkg.root);
  if (!head) {
    throw new AccountsError(
      "cannot verify command provenance: no exact Git HEAD or dist/runtime-provenance.json is available",
    );
  }

  let canonicalEntry = entrypoint;
  let canonicalRoot = pkg.root;
  try {
    if (existsSync(entrypoint)) canonicalEntry = realpathSync(entrypoint);
    if (existsSync(pkg.root)) canonicalRoot = realpathSync(pkg.root);
  } catch {
    // The resolved paths still provide a conservative containment check.
  }
  if (!pathWithin(canonicalEntry, canonicalRoot)) {
    throw new AccountsError(
      `cannot reconcile command provenance: active entrypoint ${canonicalEntry} is outside package ${canonicalRoot}`,
    );
  }

  const expected = env[EXPECTED_HEAD_ENV]?.trim().toLowerCase();
  if (expected) {
    if (!FULL_GIT_HEAD.test(expected)) {
      throw new AccountsError(`${EXPECTED_HEAD_ENV} must be a full 40-character lowercase Git commit`);
    }
    if (expected !== head) {
      throw new AccountsError(
        `command provenance mismatch: expected HEAD ${expected}, active @hasna/accounts HEAD is ${head}`,
      );
    }
  }

  return {
    schema: RUNTIME_PROVENANCE_SCHEMA,
    package: { name: "@hasna/accounts", version: pkg.version, root: canonicalRoot },
    command: { entrypoint: canonicalEntry, executable },
    source: { head, kind },
    verifiable: true,
  };
}

export function publicRuntimeProvenance(value: RuntimeProvenance): PublicRuntimeProvenance {
  return {
    schema: value.schema,
    package: { name: value.package.name, version: value.package.version },
    source: value.source,
    verifiable: true,
  };
}

export function packageVersion(): string {
  return runtimeProvenance().package.version;
}
