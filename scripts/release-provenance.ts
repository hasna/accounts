#!/usr/bin/env bun

import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import { spawnSync, type SpawnSyncOptionsWithStringEncoding } from "node:child_process";
import { gunzipSync } from "node:zlib";
import type { Bundle as SigstoreBundle } from "@sigstore/bundle";
import { compare, prerelease, valid } from "semver";

export const RELEASE_WORKFLOW = ".github/workflows/release.yml";
export const PUBLISH_PREDICATE =
  "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";
export const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
export const RELEASE_NODE_VERSION = "24.18.0";
export const RELEASE_NPM_VERSION = "11.16.0";
export const RELEASE_BUN_VERSION = "1.3.14";
export const MAX_JSON_BYTES = 8 * 1024 * 1024;
export const MAX_TARBALL_BYTES = 32 * 1024 * 1024;
export const MAX_ARCHIVE_ENTRIES = 512;
export const MAX_ARCHIVE_ENTRY_BYTES = 16 * 1024 * 1024;
export const MAX_ARCHIVE_UNPACKED_BYTES = 64 * 1024 * 1024;
export const FETCH_TIMEOUT_MS = 15_000;
export const COMMAND_TIMEOUT_MS = 180_000;

const REGISTRY = "https://registry.npmjs.org";
const GITHUB_API = "https://api.github.com";
const GITHUB_API_VERSION = "2026-03-10";
const RELEASE_TAG_PATTERN = "refs/tags/npm/accounts/v*";
const RELEASE_ENVIRONMENT = "npm-release";
const RELEASE_ENVIRONMENT_TAG_PATTERN = "npm/accounts/v*";
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_TAR_STREAM_BYTES =
  MAX_ARCHIVE_UNPACKED_BYTES + MAX_ARCHIVE_ENTRIES * 1024 + 1024 * 1024;
const SIGSTORE_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

interface SigstoreVerifyOptions {
  certificateIdentityURI: string;
  certificateIssuer: string;
  ctLogThreshold?: number;
  tlogThreshold?: number;
}

interface Manifest {
  name: string;
  version: string;
  repository: string | { url: string };
  publishConfig?: { registry?: string; access?: string; tag?: string };
}

export interface PackResult {
  name: string;
  version: string;
  filename: string;
  shasum: string;
  integrity: string;
  size: number;
  files: Array<{ path: string; size: number; mode: number }>;
}

interface PackedArtifact {
  result: PackResult;
  bytes: Buffer;
}

interface StagedPackSource {
  root: string;
  preview: PackResult;
}

export interface ReleaseCandidate {
  schema: "hasna.accounts.release-candidate/v3";
  name: string;
  version: string;
  tag: string;
  commit: string;
  repository: string;
  workflow: typeof RELEASE_WORKFLOW;
  integrity: string;
  shasum: string;
  filename: string;
  size: number;
  fileCount: number;
  unpackedBytes: number;
  artifactPath: string;
  stagingTag: string;
  intendedTag: string;
}

export interface GitEvidence {
  head: string;
  tagObjectType?: string;
  tagCommit?: string;
  mainContainsCommit: boolean;
  status: string;
}

export type RegistryPhase = "staged" | "promoted";
type RecordValue = Record<string, unknown>;

export interface ArchiveSummary {
  fileCount: number;
  unpackedBytes: number;
  files: Array<{ path: string; size: number }>;
}

interface ParsedArchive {
  summary: ArchiveSummary;
  packageManifest?: Buffer;
}

type SigstoreVerifier = (
  bundle: SigstoreBundle,
  options?: SigstoreVerifyOptions,
) => Promise<void>;

interface ToolchainVersions {
  node: string;
  npm: string;
  bun: string;
}

interface RunOptions {
  inherit?: boolean;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  input?: string;
}

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function record(value: unknown, label: string): RecordValue {
  check(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as RecordValue;
}

function text(value: unknown, label: string): string {
  check(typeof value === "string" && value.length > 0, `${label} must be a non-empty string`);
  return value;
}

function integer(value: unknown, label: string): number {
  check(Number.isInteger(value) && (value as number) >= 0, `${label} must be a non-negative integer`);
  return value as number;
}

function runResult(
  executable: string,
  args: string[],
  cwd: string,
  options: RunOptions = {},
) {
  const spawnOptions: SpawnSyncOptionsWithStringEncoding = {
    cwd,
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    timeout: options.timeoutMs ?? COMMAND_TIMEOUT_MS,
    stdio: options.inherit ? "inherit" : "pipe",
    env: {
      ...process.env,
      ...options.env,
      NO_UPDATE_NOTIFIER: "1",
      NPM_CONFIG_AUDIT: "false",
      NPM_CONFIG_FUND: "false",
    },
    input: options.input,
  };
  return spawnSync(executable, args, spawnOptions);
}

function run(
  executable: string,
  args: string[],
  cwd: string,
  options: RunOptions = {},
): string {
  const result = runResult(executable, args, cwd, options);
  check(!result.error, `could not run ${executable}: ${result.error?.message}`);
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  check(
    result.status === 0,
    `${executable} ${args.join(" ")} failed with exit ${result.status}${detail ? `:\n${detail}` : ""}`,
  );
  return result.stdout ?? "";
}

function loadManifest(root: string): Manifest {
  const value = record(JSON.parse(readFileSync(join(root, "package.json"), "utf8")), "package.json");
  const repository = value.repository;
  check(
    typeof repository === "string" ||
      (repository && typeof repository === "object" && !Array.isArray(repository) &&
        typeof (repository as RecordValue).url === "string"),
    "package.json repository must contain a URL",
  );
  return {
    name: text(value.name, "package name"),
    version: text(value.version, "package version"),
    repository: repository as Manifest["repository"],
    publishConfig: value.publishConfig as Manifest["publishConfig"],
  };
}

export function repositorySlug(manifest: Manifest): string {
  const url = typeof manifest.repository === "string" ? manifest.repository : manifest.repository.url;
  const match = url.match(
    /^(?:git\+)?(?:https:\/\/github\.com\/|git@github\.com:)([^/]+\/[^/#]+?)(?:\.git)?$/,
  );
  check(match?.[1], `repository is not canonical GitHub metadata: ${url}`);
  return match[1];
}

export function releaseTag(manifest: Pick<Manifest, "name" | "version">): string {
  const slug = manifest.name.split("/").at(-1);
  check(slug?.match(/^[a-z0-9][a-z0-9._-]*$/), `invalid package name: ${manifest.name}`);
  check(
    manifest.version.match(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/),
    `invalid package version: ${manifest.version}`,
  );
  return `npm/${slug}/v${manifest.version}`;
}

function assertDistTag(value: string, label: string): string {
  check(
    value.match(/^[a-z][a-z0-9._-]{0,127}$/) && !value.match(/^v?\d+(?:\.\d+){1,2}(?:[-+].*)?$/),
    `${label} is not a safe npm dist-tag: ${value}`,
  );
  return value;
}

export function stagingDistTag(version: string): string {
  return assertDistTag(`release-candidate-${version.toLowerCase().replace(/[^a-z0-9._-]/g, "-")}`, "staging tag");
}

function intendedDistTag(manifest: Manifest): string {
  const tag = assertDistTag(manifest.publishConfig?.tag ?? "latest", "intended tag");
  check(tag === "latest", "Accounts releases must promote only the latest dist-tag");
  return tag;
}

export function packagePurl(name: string, version: string): string {
  if (!name.startsWith("@")) return `pkg:npm/${name}@${version}`;
  const [scope, packageName, extra] = name.split("/");
  check(scope && packageName && !extra, `invalid scoped package name: ${name}`);
  return `pkg:npm/${encodeURIComponent(scope)}/${packageName}@${version}`;
}

function parsePack(stdout: string): PackResult {
  const start = stdout.indexOf("[");
  check(start !== -1, "npm pack did not produce JSON");
  const values = JSON.parse(stdout.slice(start)) as unknown;
  check(Array.isArray(values) && values.length === 1, "npm pack must describe one package");
  const value = record(values[0], "npm pack result");
  check(Array.isArray(value.files) && value.files.length > 0, "npm pack reported no files");
  return {
    name: text(value.name, "pack name"),
    version: text(value.version, "pack version"),
    filename: text(value.filename, "pack filename"),
    shasum: text(value.shasum, "pack shasum"),
    integrity: text(value.integrity, "pack integrity"),
    size: integer(value.size, "pack size"),
    files: value.files.map((entry, index) => {
      const file = record(entry, `pack file ${index}`);
      return {
        path: text(file.path, `pack file ${index} path`),
        size: integer(file.size, `pack file ${index} size`),
        mode: integer(file.mode, `pack file ${index} mode`),
      };
    }),
  };
}

function tarText(header: Buffer, offset: number, length: number, label: string): string {
  const field = header.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  const value = field.subarray(0, nul === -1 ? field.length : nul).toString("utf8");
  check(!value.match(/[\u0000-\u001f\u007f]/), `${label} contains control characters`);
  return value;
}

function tarOctal(header: Buffer, offset: number, length: number, label: string): number {
  const raw = header.subarray(offset, offset + length).toString("ascii").replace(/\0.*$/, "").trim();
  check(raw.match(/^[0-7]+$/), `${label} is not canonical octal`);
  const value = Number.parseInt(raw, 8);
  check(Number.isSafeInteger(value) && value >= 0, `${label} exceeds safe integer range`);
  return value;
}

function assertTarChecksum(header: Buffer): void {
  const expected = tarOctal(header, 148, 8, "archive header checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index++) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index]!;
  }
  check(actual === expected, "archive header checksum disagrees");
}

function archivePath(header: Buffer): string {
  const name = tarText(header, 0, 100, "archive entry name");
  const prefix = tarText(header, 345, 155, "archive entry prefix");
  const path = prefix ? `${prefix}/${name}` : name;
  check(
    path.startsWith("package/") &&
      !path.startsWith("/") &&
      !path.includes("\\") &&
      !path.match(/(?:^|\/)\.{1,2}(?:\/|$)/) &&
      posix.normalize(path) === path,
    `unsafe archive path: ${path || "<empty>"}`,
  );
  return path.slice("package/".length);
}

function parseArchive(bytes: Uint8Array): ParsedArchive {
  let tar: Buffer;
  try {
    tar = gunzipSync(Buffer.from(bytes), { maxOutputLength: MAX_TAR_STREAM_BYTES });
  } catch (error) {
    throw new Error(
      `archive gzip stream is invalid or exceeds ${MAX_TAR_STREAM_BYTES} bytes: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  check(tar.length % 512 === 0, "archive tar stream is not block aligned");
  const files: ArchiveSummary["files"] = [];
  let packageManifest: Buffer | undefined;
  const seen = new Set<string>();
  let unpackedBytes = 0;
  let entries = 0;
  let offset = 0;
  let endBlocks = 0;
  while (offset < tar.length) {
    const header = tar.subarray(offset, offset + 512);
    check(header.length === 512, "archive header is truncated");
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      endBlocks++;
      if (endBlocks === 2) {
        check(
          tar.subarray(offset).every((byte) => byte === 0),
          "archive contains data after its terminal blocks",
        );
        break;
      }
      continue;
    }
    check(endBlocks === 0, "archive contains a single zero block before data");
    assertTarChecksum(header);
    check(
      tarText(header, 257, 6, "archive format") === "ustar",
      "archive must use the ustar format",
    );
    entries++;
    check(entries <= MAX_ARCHIVE_ENTRIES, `archive entry count exceeds ${MAX_ARCHIVE_ENTRIES}`);
    const type = String.fromCharCode(header[156] ?? 0);
    check(
      type === "\0" || type === "0" || type === "5",
      `unsupported archive entry type ${JSON.stringify(type)}`,
    );
    const path = archivePath(header);
    check(!seen.has(path), `archive contains duplicate path: ${path}`);
    seen.add(path);
    const size = tarOctal(header, 124, 12, "archive entry size");
    if (type === "5") {
      check(size === 0, "archive directory entry must be empty");
      continue;
    }
    check(
      size <= MAX_ARCHIVE_ENTRY_BYTES,
      `archive individual entry exceeds ${MAX_ARCHIVE_ENTRY_BYTES} bytes`,
    );
    unpackedBytes += size;
    check(
      unpackedBytes <= MAX_ARCHIVE_UNPACKED_BYTES,
      `archive total unpacked bytes exceed ${MAX_ARCHIVE_UNPACKED_BYTES}`,
    );
    const padded = Math.ceil(size / 512) * 512;
    check(offset + padded <= tar.length, `archive entry ${path} is truncated`);
    if (path === "package.json") {
      packageManifest = Buffer.from(tar.subarray(offset, offset + size));
    }
    offset += padded;
    files.push({ path, size });
  }
  check(endBlocks === 2, "archive is missing two terminal zero blocks");
  check(files.length > 0, "archive contains no regular files");
  return {
    summary: { fileCount: files.length, unpackedBytes, files },
    packageManifest,
  };
}

export function verifyArchive(bytes: Uint8Array): ArchiveSummary {
  return parseArchive(bytes).summary;
}

function exactCommit(value: string, label: string): string {
  check(value.match(/^[0-9a-f]{40}$/), `${label} must be an exact 40-character lowercase git SHA`);
  return value;
}

function verifyPackedManifest(
  archive: ParsedArchive,
  expected: Pick<ReleaseCandidate, "name" | "version" | "commit">,
): void {
  const bytes = archive.packageManifest;
  check(bytes, "packed archive is missing package.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8")) as unknown;
  } catch (error) {
    throw new Error(
      `packed package.json is invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const manifest = record(parsed, "packed package.json");
  check(
    manifest.name === expected.name && manifest.version === expected.version,
    "packed package.json identity disagrees with the release candidate",
  );
  check(
    manifest.gitHead === exactCommit(expected.commit, "expected gitHead"),
    "packed package.json gitHead disagrees with the release commit",
  );
}

function verifyArtifactBytes(
  pack: PackResult,
  bytes: Buffer,
  expectedCommit: string,
): void {
  check(bytes.length === pack.size, "npm pack size does not match the tarball bytes");
  check(bytes.length <= MAX_TARBALL_BYTES, `tarball exceeds ${MAX_TARBALL_BYTES} bytes`);
  check(
    createHash("sha1").update(bytes).digest("hex") === pack.shasum &&
      `sha512-${createHash("sha512").update(bytes).digest("base64")}` === pack.integrity,
    "npm pack metadata does not match the tarball bytes",
  );
  const archive = parseArchive(bytes);
  const summary = archive.summary;
  const expectedFiles = pack.files
    .map(({ path, size }) => ({ path, size }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const archiveFiles = [...summary.files].sort((left, right) => left.path.localeCompare(right.path));
  check(
    JSON.stringify(archiveFiles) === JSON.stringify(expectedFiles),
    "archive entries disagree with npm pack metadata",
  );
  verifyPackedManifest(archive, {
    name: pack.name,
    version: pack.version,
    commit: expectedCommit,
  });
}

export function assertDeterministicPacks(
  first: PackResult,
  second: PackResult,
  firstBytes?: Uint8Array,
  secondBytes?: Uint8Array,
): void {
  check(
    JSON.stringify(first) === JSON.stringify(second),
    "two clean build-and-pack runs produced different artifacts; refusing release",
  );
  if (firstBytes || secondBytes) {
    check(firstBytes && secondBytes, "both packed byte streams are required");
    check(
      Buffer.from(firstBytes).equals(Buffer.from(secondBytes)),
      "two clean build-and-pack runs produced different tarball bytes; refusing release",
    );
  }
}

function safePackPath(root: string, path: string): {
  source: string;
  relativePath: string;
} {
  check(
    !isAbsolute(path) &&
      !path.includes("\\") &&
      !path.match(/(?:^|\/)\.{1,2}(?:\/|$)/) &&
      posix.normalize(path) === path,
    `npm pack returned an unsafe file path: ${path}`,
  );
  const source = resolve(root, ...path.split("/"));
  const relativePath = relative(root, source);
  check(
    relativePath && relativePath !== ".." && !relativePath.startsWith(`..${sep}`),
    `npm pack file escapes the package root: ${path}`,
  );
  return { source, relativePath };
}

function stagePackSource(root: string, expectedCommit: string): StagedPackSource {
  const preview = parsePack(run("npm", [
    "pack", "--ignore-scripts", "--json", "--dry-run",
  ], root));
  const staged = mkdtempSync(join(tmpdir(), "accounts-pack-source-"));
  for (const file of preview.files) {
    const { source, relativePath } = safePackPath(root, file.path);
    const stat = lstatSync(source);
    check(
      stat.isFile() && !stat.isSymbolicLink(),
      `npm pack source must be a regular non-symlink file: ${file.path}`,
    );
    const destination = join(staged, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(source, destination);
    chmodSync(destination, file.mode);
  }
  const manifestPath = join(staged, "package.json");
  const manifest = record(
    JSON.parse(readFileSync(manifestPath, "utf8")),
    "staged package.json",
  );
  check(
    manifest.gitHead === undefined,
    "source package.json must not contain generated gitHead metadata",
  );
  manifest.gitHead = exactCommit(expectedCommit, "release commit");
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    flag: "w",
    mode: 0o644,
  });
  return { root: staged, preview };
}

function verifyStagedPackFileSet(preview: PackResult, packed: PackResult): void {
  check(
    preview.name === packed.name && preview.version === packed.version,
    "staged pack identity changed after gitHead injection",
  );
  const fileShape = (pack: PackResult) =>
    pack.files
      .map(({ path, size, mode }) => ({
        path,
        size: path === "package.json" ? "<generated-gitHead>" : size,
        mode,
      }))
      .sort((left, right) => left.path.localeCompare(right.path));
  check(
    JSON.stringify(fileShape(preview)) === JSON.stringify(fileShape(packed)),
    "staged pack file set changed after gitHead injection",
  );
}

function buildAndPack(root: string, expectedCommit: string): PackedArtifact {
  run("bun", ["run", "build"], root, { inherit: true, timeoutMs: 300_000 });
  const staged = stagePackSource(root, expectedCommit);
  const destination = mkdtempSync(join(tmpdir(), "accounts-pack-"));
  try {
    const pack = parsePack(run("npm", [
      "pack", "--ignore-scripts", "--json", "--pack-destination", destination,
    ], staged.root));
    verifyStagedPackFileSet(staged.preview, pack);
    check(basename(pack.filename) === pack.filename, "npm pack returned an unsafe filename");
    const bytes = readFileSync(join(destination, pack.filename));
    verifyArtifactBytes(pack, bytes, expectedCommit);
    return { result: pack, bytes };
  } finally {
    rmSync(staged.root, { recursive: true, force: true });
    rmSync(destination, { recursive: true, force: true });
  }
}

export function verifyDeterministicPack(
  root: string,
  artifactPath?: string,
  expectedCommit = run("git", ["rev-parse", "HEAD"], root).trim(),
): PackResult {
  exactCommit(expectedCommit, "release commit");
  const first = buildAndPack(root, expectedCommit);
  const second = buildAndPack(root, expectedCommit);
  assertDeterministicPacks(first.result, second.result, first.bytes, second.bytes);
  if (artifactPath) {
    const output = resolve(artifactPath);
    writeFileSync(output, second.bytes, { flag: "wx", mode: 0o600 });
  }
  console.log(
    `verified deterministic package ${second.result.name}@${second.result.version}: ` +
      `${second.result.files.length} files, ${second.result.size} bytes, ${second.result.integrity}`,
  );
  return second.result;
}

function workflowIdentity(
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
): { repository: string; tag: string; sha: string } {
  const repository = repositorySlug(manifest);
  const tag = releaseTag(manifest);
  const expected: Record<string, string> = {
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: `refs/tags/${tag}`,
    GITHUB_REF_TYPE: "tag",
    GITHUB_REF_NAME: tag,
    GITHUB_REF_PROTECTED: "true",
    GITHUB_REPOSITORY: repository,
    GITHUB_WORKFLOW_REF: `${repository}/${RELEASE_WORKFLOW}@refs/tags/${tag}`,
  };
  for (const [name, value] of Object.entries(expected)) {
    check(env[name] === value, `${name} must be ${value}; received ${env[name] ?? "<unset>"}`);
  }
  const sha = text(env.GITHUB_SHA, "GITHUB_SHA");
  check(sha.match(/^[0-9a-f]{40}$/), "GITHUB_SHA must be a full commit SHA");
  check(
    env.NPM_DIST_TAG_TOKEN_CONFIGURED === "true",
    "NPM_DIST_TAG_TOKEN is not configured in the protected release environment",
  );
  check(
    env.RELEASE_GITHUB_ADMIN_TOKEN_CONFIGURED === "true",
    "RELEASE_GITHUB_ADMIN_TOKEN is not configured in the protected release environment",
  );
  check(manifest.publishConfig?.registry === REGISTRY, `publish registry must be ${REGISTRY}`);
  check(manifest.publishConfig?.access === "public", "publish access must be public");
  return { repository, tag, sha };
}

function assertExactToolchain(versions: ToolchainVersions): void {
  check(versions.node.trim() === `v${RELEASE_NODE_VERSION}`, `Node ${RELEASE_NODE_VERSION} is required`);
  check(versions.npm.trim() === RELEASE_NPM_VERSION, `npm ${RELEASE_NPM_VERSION} is required`);
  check(versions.bun.trim() === RELEASE_BUN_VERSION, `Bun ${RELEASE_BUN_VERSION} is required`);
}

export function assertTrustedPublishEnvironment(
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
  versions: ToolchainVersions,
): void {
  workflowIdentity(manifest, env);
  assertExactToolchain(versions);
  check(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, "GitHub OIDC is missing");
  const credentialKeys = Object.entries(env)
    .filter(([name, value]) =>
      Boolean(value) &&
      /^(?:NODE_AUTH_TOKEN|NPM_TOKEN|NPM_CONFIG_.*(?:AUTH|TOKEN))/i.test(name)
    )
    .map(([name]) => name);
  check(
    credentialKeys.length === 0,
    "long-lived npm publish tokens are forbidden during trusted publication",
  );
}

function assertPromotionEnvironment(
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
  versions: ToolchainVersions,
): void {
  workflowIdentity(manifest, env);
  assertExactToolchain(versions);
  check(env.NODE_AUTH_TOKEN, "the scoped npm dist-tag promotion token is missing");
  const credentialKeys = Object.entries(env)
    .filter(([name, value]) =>
      Boolean(value) &&
      /^(?:NODE_AUTH_TOKEN|NPM_TOKEN|NPM_CONFIG_.*(?:AUTH|TOKEN))/i.test(name)
    )
    .map(([name]) => name);
  check(
    credentialKeys.length === 1 && credentialKeys[0] === "NODE_AUTH_TOKEN",
    "unexpected npm credential source",
  );
}

function currentToolchain(root: string): ToolchainVersions {
  return {
    node: run("node", ["--version"], root).trim(),
    npm: run("npm", ["--version"], root).trim(),
    bun: run("bun", ["--version"], root).trim(),
  };
}

export function assertGitEvidence(
  manifest: Manifest,
  sha: string,
  evidence: GitEvidence,
): void {
  const tag = releaseTag(manifest);
  check(evidence.head === sha, "HEAD does not match GITHUB_SHA");
  check(evidence.tagObjectType !== undefined, `${tag} is missing`);
  check(evidence.tagObjectType === "tag", `${tag} is not annotated`);
  check(evidence.tagCommit === sha, `${tag} does not resolve to HEAD`);
  check(evidence.mainContainsCommit, `${sha} is not contained in origin/main`);
  check(!evidence.status.trim(), "release checkout is dirty");
}

function optionalGit(root: string, args: string[]): string | undefined {
  const result = runResult("git", args, root);
  if (result.error || result.status !== 0) return undefined;
  return result.stdout?.trim();
}

function assertGitContext(root: string, manifest: Manifest, env: NodeJS.ProcessEnv): void {
  const sha = text(env.GITHUB_SHA, "GITHUB_SHA");
  const tag = releaseTag(manifest);
  const mainResult = runResult("git", ["merge-base", "--is-ancestor", sha, "origin/main"], root);
  assertGitEvidence(manifest, sha, {
    head: run("git", ["rev-parse", "HEAD"], root).trim(),
    tagObjectType: optionalGit(root, ["cat-file", "-t", `refs/tags/${tag}`]),
    tagCommit: optionalGit(root, ["rev-parse", `${tag}^{commit}`]),
    mainContainsCommit: !mainResult.error && mainResult.status === 0,
    status: run("git", ["status", "--porcelain", "--untracked-files=all"], root),
  });
}

function refConditionIncludesReleaseTag(value: unknown): boolean {
  const conditions = record(value, "ruleset conditions");
  const refName = record(conditions.ref_name, "ruleset ref_name condition");
  check(Array.isArray(refName.include), "ruleset ref includes must be an array");
  check(Array.isArray(refName.exclude), "ruleset ref excludes must be an array");
  return refName.include.length === 1 &&
    refName.include[0] === RELEASE_TAG_PATTERN &&
    refName.exclude.length === 0;
}

export function verifyReleaseRulesets(input: unknown): { id: number; name: string } {
  check(Array.isArray(input), "GitHub rulesets response must be an array");
  for (const entry of input) {
    const ruleset = record(entry, "GitHub ruleset");
    if (
      ruleset.target !== "tag" ||
      ruleset.enforcement !== "active" ||
      !refConditionIncludesReleaseTag(ruleset.conditions)
    ) continue;
    check(Array.isArray(ruleset.rules), "ruleset rules must be an array");
    const types = ruleset.rules.map((rule, index) =>
      text(record(rule, `ruleset rule ${index}`).type, `ruleset rule ${index} type`)
    );
    check(
      types.length === 3 &&
        new Set(types).size === 3 &&
        ["creation", "update", "deletion"].every((type) => types.includes(type)),
      "release tag rules must be exactly creation, update, and deletion",
    );
    check(
      ruleset.bypass_actors !== undefined,
      "release tag ruleset bypass actors are unavailable; administration-read authority is required",
    );
    check(Array.isArray(ruleset.bypass_actors), "ruleset bypass actors must be an array");
    check(
      ruleset.bypass_actors.length === 1,
      "release tag ruleset must have exactly one organization-admin always bypass",
    );
    const actor = record(ruleset.bypass_actors[0], "ruleset bypass actor");
    check(
      actor.actor_id === null &&
        actor.actor_type === "OrganizationAdmin" &&
        actor.bypass_mode === "always",
      "release tag ruleset must have exactly one organization-admin always bypass",
    );
    return {
      id: integer(ruleset.id, "ruleset id"),
      name: text(ruleset.name, "ruleset name"),
    };
  }
  throw new Error(
    `no active tag ruleset protects only ${RELEASE_TAG_PATTERN} with creation, update, and deletion restrictions`,
  );
}

export function verifyReleaseEnvironment(
  environmentInput: unknown,
  policiesInput: unknown,
  actorPermissionInput: unknown,
  administrationIdentityInput: unknown,
  administrationPermissionInput: unknown,
): void {
  const environment = record(environmentInput, "GitHub release environment");
  const actorPermission = record(actorPermissionInput, "GitHub release actor permission");
  const actor = record(actorPermission.user, "GitHub release actor");
  const administrationIdentity = record(
    administrationIdentityInput,
    "GitHub administration credential identity",
  );
  const administrationPermission = record(
    administrationPermissionInput,
    "GitHub administration credential permission",
  );
  const administrationUser = record(
    administrationPermission.user,
    "GitHub administration credential permission user",
  );
  check(actorPermission.permission === "admin", "release actor must have repository admin permission");
  check(
    administrationPermission.permission === "admin",
    "administration credential needs repository admin read authority",
  );
  check(
    administrationIdentity.id === actor.id &&
      administrationIdentity.login === actor.login &&
      administrationUser.id === actor.id &&
      administrationUser.login === actor.login,
    "administration credential must belong to the release actor",
  );
  check(environment.name === RELEASE_ENVIRONMENT, `release environment must be ${RELEASE_ENVIRONMENT}`);
  check(Array.isArray(environment.protection_rules), "release environment protection rules must be an array");
  const rules = environment.protection_rules.map((entry, index) =>
    record(entry, `environment protection rule ${index}`)
  );
  const reviewers = rules.find((rule) => rule.type === "required_reviewers");
  check(reviewers, "release environment must require reviewers");
  check(
    reviewers.prevent_self_review === false,
    "sole-maintainer release environment must allow the authorized reviewer to self-review",
  );
  check(
    Array.isArray(reviewers.reviewers) && reviewers.reviewers.length === 1,
    "release environment must have exactly one accountable reviewer",
  );
  const reviewer = record(reviewers.reviewers[0], "release environment reviewer");
  const reviewerIdentity = record(reviewer.reviewer, "release environment reviewer identity");
  check(reviewer.type === "User", "release environment reviewer must be the authorized user");
  check(
    reviewerIdentity.id === actor.id && reviewerIdentity.login === actor.login,
    "release environment reviewer must exactly match the live release actor",
  );
  check(rules.some((rule) => rule.type === "branch_policy"), "release environment needs a tag policy");
  const deployment = record(environment.deployment_branch_policy, "deployment branch policy");
  check(
    deployment.protected_branches === false && deployment.custom_branch_policies === true,
    "release environment must use custom deployment policies only",
  );
  const policies = record(policiesInput, "deployment tag policies");
  check(Array.isArray(policies.branch_policies), "deployment tag policies must be an array");
  check(
    policies.branch_policies.length === 1,
    "release environment must have exactly one deployment tag policy",
  );
  check(
    record(policies.branch_policies[0], "deployment tag policy").name ===
        RELEASE_ENVIRONMENT_TAG_PATTERN &&
      record(policies.branch_policies[0], "deployment tag policy").type === "tag",
    `release environment must use the exact ${RELEASE_ENVIRONMENT_TAG_PATTERN} tag policy`,
  );
}

export async function readLimited(response: Response, maxBytes: number): Promise<Buffer> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    check(Number.isSafeInteger(length) && length >= 0, "response has an invalid content-length");
    check(length <= maxBytes, `response exceeds ${maxBytes} bytes`);
  }
  check(response.body, "response has no body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    total += next.value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`response exceeds ${maxBytes} bytes`);
    }
    chunks.push(next.value);
  }
  return Buffer.concat(chunks, total);
}

async function fetchLimited(
  url: URL,
  maxBytes: number,
  headers: Record<string, string> = {},
): Promise<Buffer> {
  const response = await fetch(url, {
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  check(response.ok, `GET ${url.origin}${url.pathname} returned ${response.status}`);
  return readLimited(response, maxBytes);
}

async function fetchJson(
  url: URL,
  maxBytes = MAX_JSON_BYTES,
  headers: Record<string, string> = {},
): Promise<unknown> {
  const bytes = await fetchLimited(url, maxBytes, { accept: "application/json", ...headers });
  return JSON.parse(bytes.toString("utf8")) as unknown;
}

function githubUrl(path: string): URL {
  const url = new URL(path, GITHUB_API);
  check(url.origin === GITHUB_API, "unsafe GitHub API URL");
  return url;
}

async function assertLiveReleaseControls(
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const repository = repositorySlug(manifest);
  check(env.GITHUB_REPOSITORY === repository, "ruleset repository disagrees with package metadata");
  const token = text(env.GITHUB_TOKEN, "GITHUB_TOKEN");
  const administrationToken = text(
    env.RELEASE_GITHUB_ADMIN_TOKEN,
    "RELEASE_GITHUB_ADMIN_TOKEN",
  );
  const headers = {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "x-github-api-version": GITHUB_API_VERSION,
  };
  const administrationHeaders = {
    ...headers,
    authorization: `Bearer ${administrationToken}`,
  };
  const actorName = encodeURIComponent(text(env.GITHUB_ACTOR, "GITHUB_ACTOR"));
  const [
    summaries,
    environment,
    policies,
    actorPermission,
    administrationIdentity,
  ] = await Promise.all([
    fetchJson(
      githubUrl(`/repos/${repository}/rulesets?includes_parents=true&targets=tag&per_page=100`),
      MAX_JSON_BYTES,
      administrationHeaders,
    ),
    fetchJson(
      githubUrl(`/repos/${repository}/environments/${RELEASE_ENVIRONMENT}`),
      MAX_JSON_BYTES,
      headers,
    ),
    fetchJson(
      githubUrl(
        `/repos/${repository}/environments/${RELEASE_ENVIRONMENT}/deployment-branch-policies?per_page=100`,
      ),
      MAX_JSON_BYTES,
      headers,
    ),
    fetchJson(
      githubUrl(`/repos/${repository}/collaborators/${actorName}/permission`),
      MAX_JSON_BYTES,
      headers,
    ),
    fetchJson(githubUrl("/user"), MAX_JSON_BYTES, administrationHeaders),
  ]);
  check(Array.isArray(summaries), "GitHub rulesets response must be an array");
  const details = await Promise.all(summaries.map(async (entry, index) => {
    const summary = record(entry, `ruleset summary ${index}`);
    const id = integer(summary.id, `ruleset summary ${index} id`);
    return fetchJson(
      githubUrl(`/repos/${repository}/rulesets/${id}`),
      MAX_JSON_BYTES,
      administrationHeaders,
    );
  }));
  const administration = record(administrationIdentity, "GitHub administration credential identity");
  const administrationName = encodeURIComponent(
    text(administration.login, "GitHub administration credential login"),
  );
  const administrationPermission = await fetchJson(
    githubUrl(`/repos/${repository}/collaborators/${administrationName}/permission`),
    MAX_JSON_BYTES,
    administrationHeaders,
  );
  const ruleset = verifyReleaseRulesets(details);
  verifyReleaseEnvironment(
    environment,
    policies,
    actorPermission,
    administrationIdentity,
    administrationPermission,
  );
  console.log(`verified active release tag ruleset ${ruleset.name} (${ruleset.id})`);
  console.log(`verified protected ${RELEASE_ENVIRONMENT} environment and tag policy`);
}

function candidateFrom(
  manifest: Manifest,
  pack: PackResult,
  commit: string,
  artifactPath: string,
): ReleaseCandidate {
  check(pack.name === manifest.name && pack.version === manifest.version, "pack metadata disagrees with package.json");
  const unpackedBytes = pack.files.reduce((sum, file) => sum + file.size, 0);
  check(
    Number.isSafeInteger(unpackedBytes) && unpackedBytes <= MAX_ARCHIVE_UNPACKED_BYTES,
    "pack unpacked size exceeds the release limit",
  );
  return {
    schema: "hasna.accounts.release-candidate/v3",
    name: manifest.name,
    version: manifest.version,
    tag: releaseTag(manifest),
    commit,
    repository: repositorySlug(manifest),
    workflow: RELEASE_WORKFLOW,
    integrity: pack.integrity,
    shasum: pack.shasum,
    filename: pack.filename,
    size: pack.size,
    fileCount: pack.files.length,
    unpackedBytes,
    artifactPath,
    stagingTag: stagingDistTag(manifest.version),
    intendedTag: intendedDistTag(manifest),
  };
}

function loadCandidate(path: string): ReleaseCandidate {
  const value = record(JSON.parse(readFileSync(path, "utf8")), "release candidate");
  check(value.schema === "hasna.accounts.release-candidate/v3", "unsupported candidate schema");
  const artifactPath = text(value.artifactPath, "candidate artifact path");
  check(isAbsolute(artifactPath), "candidate artifact path must be absolute");
  const result: ReleaseCandidate = {
    schema: "hasna.accounts.release-candidate/v3",
    name: text(value.name, "candidate name"),
    version: text(value.version, "candidate version"),
    tag: text(value.tag, "candidate tag"),
    commit: text(value.commit, "candidate commit"),
    repository: text(value.repository, "candidate repository"),
    workflow: RELEASE_WORKFLOW,
    integrity: text(value.integrity, "candidate integrity"),
    shasum: text(value.shasum, "candidate shasum"),
    filename: text(value.filename, "candidate filename"),
    size: integer(value.size, "candidate size"),
    fileCount: integer(value.fileCount, "candidate file count"),
    unpackedBytes: integer(value.unpackedBytes, "candidate unpacked bytes"),
    artifactPath,
    stagingTag: assertDistTag(text(value.stagingTag, "candidate staging tag"), "candidate staging tag"),
    intendedTag: assertDistTag(text(value.intendedTag, "candidate intended tag"), "candidate intended tag"),
  };
  check(result.commit.match(/^[0-9a-f]{40}$/), "candidate commit must be a full SHA");
  check(
    result.size > 0 &&
      result.fileCount > 0 &&
      result.fileCount <= MAX_ARCHIVE_ENTRIES &&
      result.unpackedBytes > 0 &&
      result.unpackedBytes <= MAX_ARCHIVE_UNPACKED_BYTES,
    "candidate artifact metadata must be nonempty and within archive limits",
  );
  return result;
}

function assertCandidateContext(
  value: ReleaseCandidate,
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
): void {
  const expected = {
    name: manifest.name,
    version: manifest.version,
    tag: releaseTag(manifest),
    commit: text(env.GITHUB_SHA, "GITHUB_SHA"),
    repository: repositorySlug(manifest),
    workflow: RELEASE_WORKFLOW,
    stagingTag: stagingDistTag(manifest.version),
    intendedTag: intendedDistTag(manifest),
  };
  for (const [key, expectedValue] of Object.entries(expected)) {
    check(value[key as keyof ReleaseCandidate] === expectedValue, `candidate ${key} disagrees with release context`);
  }
}

function verifyCandidateArtifact(value: ReleaseCandidate): Buffer {
  const stat = lstatSync(value.artifactPath);
  check(stat.isFile() && !stat.isSymbolicLink(), "candidate artifact must be a regular non-symlink file");
  check(stat.size === value.size, "candidate artifact size changed after verification");
  check(stat.size <= MAX_TARBALL_BYTES, `candidate artifact exceeds ${MAX_TARBALL_BYTES} bytes`);
  const bytes = readFileSync(value.artifactPath);
  check(
    createHash("sha1").update(bytes).digest("hex") === value.shasum &&
      `sha512-${createHash("sha512").update(bytes).digest("base64")}` === value.integrity,
    "candidate artifact bytes changed after verification",
  );
  const archive = parseArchive(bytes);
  check(
    archive.summary.fileCount === value.fileCount,
    "candidate archive file count changed after verification",
  );
  check(
    archive.summary.unpackedBytes === value.unpackedBytes,
    "candidate archive unpacked bytes changed after verification",
  );
  verifyPackedManifest(archive, value);
  return bytes;
}

function packageUrl(name: string, version = ""): URL {
  return new URL(`${REGISTRY}/${encodeURIComponent(name)}${version ? `/${encodeURIComponent(version)}` : ""}`);
}

async function ensureUnpublished(value: ReleaseCandidate): Promise<void> {
  const response = await fetch(packageUrl(value.name, value.version), {
    redirect: "error",
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  check(response.status === 404, response.ok
    ? `${value.name}@${value.version} already exists; versions are immutable`
    : `registry preflight returned ${response.status}`);
  console.log(`${value.name}@${value.version} is not published`);
}

function safeRegistryUrl(value: unknown, label: string, prefix: string): URL {
  const url = new URL(text(value, label));
  check(
    url.origin === REGISTRY &&
      url.pathname.startsWith(prefix) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash,
    `unsafe ${label}`,
  );
  return url;
}

export function verifyRegistryMetadata(
  value: ReleaseCandidate,
  input: unknown,
): { tarballUrl: URL } {
  const metadata = record(input, "registry metadata");
  check(metadata.name === value.name && metadata.version === value.version, "registry package identity disagrees");
  check(metadata.gitHead === value.commit, "registry gitHead disagrees");
  const dist = record(metadata.dist, "registry dist");
  check(dist.integrity === value.integrity && dist.shasum === value.shasum, "registry integrity disagrees");
  check(
    integer(dist.fileCount, "registry fileCount") === value.fileCount,
    "registry fileCount disagrees",
  );
  check(
    integer(dist.unpackedSize, "registry unpackedSize") === value.unpackedBytes,
    "registry unpackedSize disagrees",
  );
  const attestations = record(dist.attestations, "registry attestations");
  check(
    record(attestations.provenance, "registry provenance").predicateType === PROVENANCE_PREDICATE,
    "registry does not advertise SLSA v1 provenance",
  );
  const attestationsUrl = safeRegistryUrl(
    attestations.url,
    "attestations URL",
    "/-/npm/v1/attestations/",
  );
  check(
    decodeURIComponent(attestationsUrl.pathname) ===
      `/-/npm/v1/attestations/${value.name}@${value.version}`,
    "registry attestations URL disagrees with the package identity",
  );
  return {
    tarballUrl: safeRegistryUrl(
      dist.tarball,
      "tarball URL",
      `/${value.name}/-/`,
    ),
  };
}

function decodeBase64(value: unknown, label: string): Buffer {
  const encoded = text(value, label);
  check(encoded.length % 4 === 0 && encoded.match(/^[A-Za-z0-9+/]+={0,2}$/), `${label} is not strict base64`);
  const bytes = Buffer.from(encoded, "base64");
  check(bytes.toString("base64") === encoded, `${label} is not canonical base64`);
  check(bytes.length <= MAX_JSON_BYTES, `${label} exceeds ${MAX_JSON_BYTES} decoded bytes`);
  return bytes;
}

function integrityHex(integrity: string): string {
  const match = integrity.match(/^sha512-([A-Za-z0-9+/]+={0,2})$/);
  check(match?.[1], "candidate integrity is not sha512");
  return decodeBase64(match[1], "candidate integrity").toString("hex");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function expectedSigstoreIdentity(
  value: Pick<ReleaseCandidate, "repository" | "workflow" | "tag">,
): Pick<SigstoreVerifyOptions, "certificateIdentityURI" | "certificateIssuer"> {
  const identity =
    `https://github.com/${value.repository}/${value.workflow}@refs/tags/${value.tag}`;
  return {
    certificateIdentityURI: `^${escapeRegex(identity)}$`,
    certificateIssuer: SIGSTORE_OIDC_ISSUER,
  };
}

async function verifySigstoreWithPinnedNode(
  bundle: SigstoreBundle,
  options?: SigstoreVerifyOptions,
): Promise<void> {
  const root = resolve(process.cwd());
  run("node", [join(root, "scripts", "verify-sigstore.mjs")], root, {
    timeoutMs: 60_000,
    input: JSON.stringify({ bundle, options }),
  });
}

export async function verifySigstoreBundle(
  value: ReleaseCandidate,
  input: unknown,
  verifier: SigstoreVerifier = verifySigstoreWithPinnedNode,
): Promise<void> {
  const bundle = record(input, "Sigstore provenance bundle");
  check(
    bundle.mediaType === "application/vnd.dev.sigstore.bundle.v0.3+json",
    "provenance must use a Sigstore v0.3 bundle",
  );
  const material = record(bundle.verificationMaterial, "Sigstore verification material");
  check(material.certificate, "Sigstore provenance bundle must contain a Fulcio certificate");
  await verifier(bundle as unknown as SigstoreBundle, {
    ...expectedSigstoreIdentity(value),
    ctLogThreshold: 1,
    tlogThreshold: 1,
  });
}

export async function verifyProvenanceBundleCryptographically(
  value: ReleaseCandidate,
  input: unknown,
  verifier: SigstoreVerifier = verifySigstoreWithPinnedNode,
): Promise<void> {
  check(Array.isArray(input), "npm audit did not return attestation bundles");
  const provenance = input.filter((entry) =>
    record(entry, "cryptographically verified attestation").predicateType ===
      PROVENANCE_PREDICATE
  );
  check(provenance.length === 1, "exactly one SLSA provenance bundle is required");
  await verifySigstoreBundle(
    value,
    record(provenance[0], "SLSA provenance attestation").bundle,
    verifier,
  );
}

function positiveIntegerStringOrNumber(value: unknown, label: string): bigint {
  const encoded = typeof value === "number" ? String(value) : value;
  check(
    typeof encoded === "string" && encoded.match(/^[1-9]\d*$/),
    `${label} must be a positive integer`,
  );
  return BigInt(encoded);
}

function auditedStatement(item: unknown, value: ReleaseCandidate): RecordValue {
  const attestation = record(item, "cryptographically verified attestation");
  const predicateType = text(attestation.predicateType, "predicate type");
  const bundle = record(attestation.bundle, "Sigstore bundle");
  const envelope = record(bundle.dsseEnvelope, "DSSE envelope");
  check(Array.isArray(envelope.signatures) && envelope.signatures.length > 0, "unsigned DSSE bundle is forbidden");
  const material = record(bundle.verificationMaterial, "Sigstore verification material");
  check(
    Array.isArray(material.tlogEntries) && material.tlogEntries.length === 1,
    "exactly one Sigstore transparency-log entry is required",
  );
  const tlog = record(material.tlogEntries[0], "Sigstore transparency-log entry");
  positiveIntegerStringOrNumber(tlog.logIndex, "Sigstore logIndex");
  positiveIntegerStringOrNumber(tlog.integratedTime, "Sigstore integratedTime");
  const decoded = record(
    JSON.parse(decodeBase64(envelope.payload, "DSSE payload").toString("utf8")),
    "in-toto statement",
  );
  check(decoded.predicateType === predicateType, "attestation predicate types disagree");
  const subjects = decoded.subject;
  check(Array.isArray(subjects) && subjects.length === 1, "attestation must have one subject");
  const subject = record(subjects[0], "attestation subject");
  check(
    subject.name === packagePurl(value.name, value.version) &&
      record(subject.digest, "subject digest").sha512 === integrityHex(value.integrity),
    "attestation subject disagrees with the package digest",
  );
  return decoded;
}

export function verifyAttestations(value: ReleaseCandidate, input: unknown): void {
  check(Array.isArray(input), "npm audit did not return cryptographically verified attestation bundles");
  const statements = input.map((entry) => auditedStatement(entry, value));
  const publish = statements.filter((entry) => entry.predicateType === PUBLISH_PREDICATE);
  const provenance = statements.filter((entry) => entry.predicateType === PROVENANCE_PREDICATE);
  check(
    publish.length === 1 && provenance.length === 1,
    "exactly one npm publish and one SLSA provenance attestation are required",
  );
  const published = record(publish[0]!.predicate, "publish predicate");
  check(
    published.name === value.name && published.version === value.version && published.registry === REGISTRY,
    "publish attestation disagrees",
  );
  const build = record(
    record(provenance[0]!.predicate, "provenance predicate").buildDefinition,
    "build definition",
  );
  const workflow = record(
    record(record(build.externalParameters, "external parameters").workflow, "workflow"),
    "workflow",
  );
  check(
    workflow.repository === `https://github.com/${value.repository}` &&
      workflow.path === value.workflow && workflow.ref === `refs/tags/${value.tag}`,
    "provenance workflow, repository, or tag disagrees",
  );
  check(
    Array.isArray(build.resolvedDependencies) && build.resolvedDependencies.some((entry) => {
      const dependency = entry && typeof entry === "object" && !Array.isArray(entry) ? entry as RecordValue : {};
      const digest = dependency.digest && typeof dependency.digest === "object" &&
        !Array.isArray(dependency.digest) ? dependency.digest as RecordValue : {};
      return digest.gitCommit === value.commit;
    }),
    "provenance does not bind the release commit",
  );
}

export function verifyDownloadedTarball(value: ReleaseCandidate, bytes: Uint8Array): void {
  const buffer = Buffer.from(bytes);
  check(buffer.length === value.size, "downloaded registry tarball size differs from the reviewed pack");
  check(buffer.length <= MAX_TARBALL_BYTES, `downloaded tarball exceeds ${MAX_TARBALL_BYTES} bytes`);
  check(
    createHash("sha1").update(buffer).digest("hex") === value.shasum &&
      `sha512-${createHash("sha512").update(buffer).digest("base64")}` === value.integrity,
    "downloaded registry tarball differs from the reviewed pack",
  );
  const archive = parseArchive(buffer);
  check(archive.summary.fileCount === value.fileCount, "downloaded archive file count differs");
  check(
    archive.summary.unpackedBytes === value.unpackedBytes,
    "downloaded archive unpacked bytes differ",
  );
  verifyPackedManifest(archive, value);
}

export function verifyDistTags(
  value: ReleaseCandidate,
  input: unknown,
  phase: RegistryPhase,
): void {
  const tags = record(record(input, "registry package metadata")["dist-tags"], "registry dist-tags");
  check(tags[value.stagingTag] === value.version, `${value.stagingTag} does not point to ${value.version}`);
  if (phase === "staged") {
    check(
      tags[value.intendedTag] !== value.version,
      `${value.intendedTag} was promoted before registry verification completed`,
    );
  } else {
    check(
      tags[value.intendedTag] === value.version,
      `${value.intendedTag} does not agree with ${value.stagingTag}`,
    );
  }
}

export function assertPromotionVersion(
  candidateVersion: string,
  currentLatest: string | undefined,
): "advance" | "idempotent" {
  check(valid(candidateVersion) !== null, `candidate ${candidateVersion} is not valid SemVer`);
  check(
    prerelease(candidateVersion) === null,
    `refusing prerelease ${candidateVersion} promotion to latest`,
  );
  if (currentLatest === undefined) return "advance";
  check(
    valid(currentLatest) !== null,
    `registry latest ${currentLatest} is not valid SemVer`,
  );
  if (candidateVersion === currentLatest) return "idempotent";
  const precedence = compare(candidateVersion, currentLatest);
  check(
    precedence !== 0,
    `${candidateVersion} does not advance semantic precedence over registry latest ${currentLatest}`,
  );
  check(
    precedence > 0,
    `refusing stale or downgrade promotion of ${candidateVersion} over registry latest ${currentLatest}`,
  );
  return "advance";
}

export function assertPromotionSnapshotUnchanged(
  expectedLatest: string | undefined,
  immediateLatest: string | undefined,
): void {
  check(
    expectedLatest === immediateLatest,
    "registry latest changed immediately before promotion; expected " +
      `${expectedLatest ?? "<absent>"}, received ${immediateLatest ?? "<absent>"}`,
  );
}

export function assertFinalPromotionVersion(
  candidateVersion: string,
  currentLatest: string | undefined,
): void {
  check(
    assertPromotionVersion(candidateVersion, currentLatest) === "idempotent",
    `registry latest changed during promotion; expected ${candidateVersion}, received ` +
      `${currentLatest ?? "<absent>"}`,
  );
}

function latestDistTag(input: unknown): string | undefined {
  const tags = record(record(input, "registry package metadata")["dist-tags"], "registry dist-tags");
  const latest = tags.latest;
  check(latest === undefined || typeof latest === "string", "registry latest must be a string");
  return latest;
}

export function extractVerifiedAttestations(
  value: ReleaseCandidate,
  input: unknown,
): unknown[] {
  const audit = record(input, "npm audit signatures result");
  check(Array.isArray(audit.invalid) && audit.invalid.length === 0, "npm reported invalid signatures");
  check(Array.isArray(audit.missing) && audit.missing.length === 0, "npm reported missing signatures");
  check(Array.isArray(audit.verified), "npm audit signatures did not report verified packages");
  const expectedLocation = `node_modules/${value.name}`;
  const verified = audit.verified
    .map((entry, index) => record(entry, `npm verified entry ${index}`))
    .find((entry) =>
      entry.name === value.name &&
      entry.version === value.version &&
      entry.location === expectedLocation
    );
  check(verified, `npm did not cryptographically verify ${value.name}@${value.version}`);
  check(
    Array.isArray(verified.attestationBundles) && verified.attestationBundles.length > 0,
    "npm did not return the verified attestation bundles",
  );
  return verified.attestationBundles;
}

export function assertExactCliVersion(value: ReleaseCandidate, stdout: string): void {
  check(stdout.trim() === value.version, `accounts --version returned ${stdout.trim() || "<empty>"}`);
}

function verifyExactInstallAndAttestations(value: ReleaseCandidate): unknown[] {
  const root = mkdtempSync(join(tmpdir(), "accounts-consumer-"));
  try {
    writeFileSync(join(root, "package.json"), `${JSON.stringify({ private: true })}\n`, { mode: 0o600 });
    run("npm", [
      "install", "--ignore-scripts", "--audit=false", "--fund=false", "--save-exact",
      `${value.name}@${value.version}`,
    ], root, { timeoutMs: 300_000 });
    const packageRoot = join(root, "node_modules", ...value.name.split("/"));
    const installed = record(
      JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")),
      "installed package",
    );
    check(installed.name === value.name && installed.version === value.version, "exact install resolved another version");
    const cliPath = join(packageRoot, "dist", "cli.js");
    const cliStat = lstatSync(cliPath);
    check(cliStat.isFile() && !cliStat.isSymbolicLink(), "installed Accounts CLI is not a regular file");
    assertExactCliVersion(value, run("node", [cliPath, "--version"], root));
    const audit = JSON.parse(run("npm", [
      "audit", "signatures", "--json", "--include-attestations",
    ], root, { timeoutMs: 300_000 })) as unknown;
    return extractVerifiedAttestations(value, audit);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export function parseRetryOptions(attemptsInput: string, delayInput: string): {
  attempts: number;
  delayMs: number;
} {
  const attempts = Number(attemptsInput);
  const delayMs = Number(delayInput);
  check(Number.isInteger(attempts) && attempts > 0 && attempts <= 6, "attempts must be between 1 and 6");
  check(Number.isInteger(delayMs) && delayMs >= 0 && delayMs <= 10_000, "delay must be between 0 and 10000 ms");
  check((attempts - 1) * delayMs <= 60_000, "retry delay budget exceeds 60 seconds");
  return { attempts, delayMs };
}

async function verifyRegistryRelease(
  value: ReleaseCandidate,
  phase: RegistryPhase,
  attempts: number,
  delayMs: number,
): Promise<void> {
  let failure: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const versionMetadata = await fetchJson(packageUrl(value.name, value.version));
      const urls = verifyRegistryMetadata(value, versionMetadata);
      const packageMetadata = await fetchJson(packageUrl(value.name));
      verifyDistTags(value, packageMetadata, phase);
      if (phase === "promoted") {
        assertFinalPromotionVersion(value.version, latestDistTag(packageMetadata));
      }
      verifyDownloadedTarball(value, await fetchLimited(urls.tarballUrl, MAX_TARBALL_BYTES));
      const auditedBundles = verifyExactInstallAndAttestations(value);
      await verifyProvenanceBundleCryptographically(value, auditedBundles);
      verifyAttestations(value, auditedBundles);
      console.log(
        `verified ${value.name}@${value.version}: registry bytes, gitHead, ` +
          `cryptographic attestations, provenance semantics, ${value.stagingTag}, exact install, and CLI agree`,
      );
      return;
    } catch (error) {
      failure = error;
      if (attempt < attempts) await Bun.sleep(delayMs);
    }
  }
  throw failure;
}

async function promoteDistTag(
  root: string,
  manifest: Manifest,
  value: ReleaseCandidate,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  assertPromotionEnvironment(manifest, env, currentToolchain(root));
  assertGitContext(root, manifest, env);
  assertCandidateContext(value, manifest, env);
  verifyCandidateArtifact(value);
  const before = await fetchJson(packageUrl(value.name));
  const observedLatest = latestDistTag(before);
  const promotion = assertPromotionVersion(value.version, observedLatest);
  if (promotion === "advance") {
    verifyDistTags(value, before, "staged");
    const immediatelyBeforeMutation = await fetchJson(packageUrl(value.name));
    verifyDistTags(value, immediatelyBeforeMutation, "staged");
    assertPromotionSnapshotUnchanged(
      observedLatest,
      latestDistTag(immediatelyBeforeMutation),
    );
    run("npm", [
      "dist-tag", "add", `${value.name}@${value.version}`, value.intendedTag,
      "--registry", REGISTRY,
    ], root);
  }
  const after = await fetchJson(packageUrl(value.name));
  verifyDistTags(value, after, "promoted");
  assertFinalPromotionVersion(value.version, latestDistTag(after));
  console.log(`promoted ${value.name}@${value.version} to ${value.intendedTag}`);
}

function option(args: string[], name: string, fallback?: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? fallback : args[index + 1];
  check(value && !value.startsWith("--"), `missing ${name}`);
  return value;
}

async function main(): Promise<void> {
  const root = resolve(process.cwd());
  const [subcommand, ...args] = process.argv.slice(2);
  const manifest = loadManifest(root);
  if (subcommand === "pack") {
    verifyDeterministicPack(root);
  } else if (subcommand === "reject-direct-publish") {
    throw new Error(
      "direct npm publish is forbidden; the release workflow must publish the preserved verified tarball",
    );
  } else if (subcommand === "preflight") {
    assertTrustedPublishEnvironment(manifest, process.env, currentToolchain(root));
    assertGitContext(root, manifest, process.env);
    await assertLiveReleaseControls(manifest, process.env);
    console.log("trusted release preflight verified");
  } else if (subcommand === "candidate") {
    assertTrustedPublishEnvironment(manifest, process.env, currentToolchain(root));
    assertGitContext(root, manifest, process.env);
    const artifactPath = resolve(option(args, "--artifact"));
    const commit = text(process.env.GITHUB_SHA, "GITHUB_SHA");
    const pack = verifyDeterministicPack(root, artifactPath, commit);
    const value = candidateFrom(
      manifest,
      pack,
      commit,
      artifactPath,
    );
    const output = resolve(option(args, "--out"));
    writeFileSync(output, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    console.log(`wrote release candidate ${output}`);
  } else if (subcommand === "ensure-unpublished") {
    const value = loadCandidate(resolve(option(args, "--candidate")));
    verifyCandidateArtifact(value);
    await ensureUnpublished(value);
  } else if (subcommand === "publish-staged") {
    assertTrustedPublishEnvironment(manifest, process.env, currentToolchain(root));
    assertGitContext(root, manifest, process.env);
    const value = loadCandidate(resolve(option(args, "--candidate")));
    assertCandidateContext(value, manifest, process.env);
    verifyCandidateArtifact(value);
    run("npm", [
      "publish", value.artifactPath, "--ignore-scripts", "--provenance", "--access", "public",
      "--tag", value.stagingTag, "--registry", REGISTRY,
    ], root, { inherit: true, timeoutMs: 300_000 });
  } else if (subcommand === "verify-registry") {
    const value = loadCandidate(resolve(option(args, "--candidate")));
    verifyCandidateArtifact(value);
    const retry = parseRetryOptions(
      option(args, "--attempts", "4"),
      option(args, "--delay-ms", "5000"),
    );
    const phase = option(args, "--phase", "staged");
    check(phase === "staged" || phase === "promoted", "phase must be staged or promoted");
    await verifyRegistryRelease(value, phase, retry.attempts, retry.delayMs);
  } else if (subcommand === "promote") {
    await promoteDistTag(
      root,
      manifest,
      loadCandidate(resolve(option(args, "--candidate"))),
      process.env,
    );
  } else {
    throw new Error(
      "usage: release-provenance.ts pack | reject-direct-publish | preflight | " +
        "candidate --out FILE --artifact FILE | ensure-unpublished --candidate FILE | " +
        "publish-staged --candidate FILE | verify-registry --candidate FILE " +
        "[--phase staged|promoted] | promote --candidate FILE",
    );
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(`release provenance failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
