#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

export const RELEASE_WORKFLOW = ".github/workflows/release.yml";
export const PUBLISH_PREDICATE =
  "https://github.com/npm/attestation/tree/main/specs/publish/v0.1";
export const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
const REGISTRY = "https://registry.npmjs.org";
const MIN_NPM = [11, 5, 1] as const;

interface Manifest {
  name: string;
  version: string;
  repository: string | { url: string };
  publishConfig?: { registry?: string; access?: string };
}

export interface PackResult {
  name: string;
  version: string;
  filename: string;
  shasum: string;
  integrity: string;
  files: Array<{ path: string; size: number; mode: number }>;
}

export interface ReleaseCandidate {
  schema: "hasna.accounts.release-candidate/v1";
  name: string;
  version: string;
  tag: string;
  commit: string;
  repository: string;
  workflow: typeof RELEASE_WORKFLOW;
  integrity: string;
  shasum: string;
  filename: string;
  fileCount: number;
}

type RecordValue = Record<string, unknown>;

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

function run(executable: string, args: string[], cwd: string, inherit = false): string {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    stdio: inherit ? "inherit" : "pipe",
    env: {
      ...process.env,
      NO_UPDATE_NOTIFIER: "1",
      NPM_CONFIG_AUDIT: "false",
      NPM_CONFIG_FUND: "false",
    },
  });
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
  return `npm/${slug}/v${manifest.version}`;
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
    files: value.files.map((entry, index) => {
      const file = record(entry, `pack file ${index}`);
      check(Number.isInteger(file.size) && Number.isInteger(file.mode), `invalid pack file ${index}`);
      return {
        path: text(file.path, `pack file ${index} path`),
        size: file.size as number,
        mode: file.mode as number,
      };
    }),
  };
}

export function assertDeterministicPacks(first: PackResult, second: PackResult): void {
  check(
    JSON.stringify(first) === JSON.stringify(second),
    "two clean build-and-pack runs produced different artifacts; refusing release",
  );
}

function buildAndPack(root: string): PackResult {
  run("bun", ["run", "build"], root, true);
  const destination = mkdtempSync(join(tmpdir(), "accounts-pack-"));
  try {
    const pack = parsePack(run("npm", [
      "pack", "--ignore-scripts", "--json", "--pack-destination", destination,
    ], root));
    check(basename(pack.filename) === pack.filename, "npm pack returned an unsafe filename");
    const bytes = readFileSync(join(destination, pack.filename));
    check(
      createHash("sha1").update(bytes).digest("hex") === pack.shasum &&
        `sha512-${createHash("sha512").update(bytes).digest("base64")}` === pack.integrity,
      "npm pack metadata does not match the tarball bytes",
    );
    return pack;
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
}

export function verifyDeterministicPack(root: string): PackResult {
  const first = buildAndPack(root);
  const second = buildAndPack(root);
  assertDeterministicPacks(first, second);
  console.log(
    `verified deterministic package ${second.name}@${second.version}: ` +
      `${second.files.length} files, ${second.integrity}`,
  );
  return second;
}

function versionAtLeast(actual: number[], minimum: readonly number[]): boolean {
  for (let index = 0; index < minimum.length; index++) {
    if (actual[index] !== minimum[index]) return actual[index]! > minimum[index]!;
  }
  return true;
}

export function assertTrustedPublishEnvironment(
  manifest: Manifest,
  env: NodeJS.ProcessEnv,
  npmVersion: string,
): void {
  const repository = repositorySlug(manifest);
  const tag = releaseTag(manifest);
  const expected: Record<string, string> = {
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF_TYPE: "tag",
    GITHUB_REF_NAME: tag,
    GITHUB_REPOSITORY: repository,
    GITHUB_WORKFLOW_REF: `${repository}/${RELEASE_WORKFLOW}@refs/tags/${tag}`,
  };
  for (const [name, value] of Object.entries(expected)) {
    check(env[name] === value, `${name} must be ${value}; received ${env[name] ?? "<unset>"}`);
  }
  check(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, "GitHub OIDC is missing");
  check(!env.NODE_AUTH_TOKEN && !env.NPM_TOKEN, "long-lived npm publish tokens are forbidden");
  const npmMatch = npmVersion.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  check(npmMatch && versionAtLeast(npmMatch.slice(1).map(Number), MIN_NPM),
    `npm ${MIN_NPM.join(".")} or newer is required`);
  check(env.GITHUB_SHA?.match(/^[0-9a-f]{40}$/), "GITHUB_SHA must be a full commit SHA");
  check(manifest.publishConfig?.registry === REGISTRY, `publish registry must be ${REGISTRY}`);
  check(manifest.publishConfig?.access === "public", "publish access must be public");
}

function assertGitContext(root: string, manifest: Manifest, env: NodeJS.ProcessEnv): void {
  const sha = text(env.GITHUB_SHA, "GITHUB_SHA");
  const tag = releaseTag(manifest);
  check(run("git", ["rev-parse", "HEAD"], root).trim() === sha, "HEAD does not match GITHUB_SHA");
  check(run("git", ["cat-file", "-t", `refs/tags/${tag}`], root).trim() === "tag", `${tag} is not annotated`);
  check(run("git", ["rev-parse", `${tag}^{commit}`], root).trim() === sha, `${tag} does not resolve to HEAD`);
  run("git", ["merge-base", "--is-ancestor", sha, "origin/main"], root);
  check(!run("git", ["status", "--porcelain", "--untracked-files=all"], root).trim(), "release checkout is dirty");
}

function candidate(manifest: Manifest, pack: PackResult, commit: string): ReleaseCandidate {
  check(pack.name === manifest.name && pack.version === manifest.version, "pack metadata disagrees with package.json");
  return {
    schema: "hasna.accounts.release-candidate/v1",
    name: manifest.name,
    version: manifest.version,
    tag: releaseTag(manifest),
    commit,
    repository: repositorySlug(manifest),
    workflow: RELEASE_WORKFLOW,
    integrity: pack.integrity,
    shasum: pack.shasum,
    filename: pack.filename,
    fileCount: pack.files.length,
  };
}

function loadCandidate(path: string): ReleaseCandidate {
  const value = record(JSON.parse(readFileSync(path, "utf8")), "release candidate");
  check(value.schema === "hasna.accounts.release-candidate/v1", "unsupported candidate schema");
  check(Number.isInteger(value.fileCount) && (value.fileCount as number) > 0, "invalid candidate file count");
  return {
    schema: "hasna.accounts.release-candidate/v1",
    name: text(value.name, "candidate name"),
    version: text(value.version, "candidate version"),
    tag: text(value.tag, "candidate tag"),
    commit: text(value.commit, "candidate commit"),
    repository: text(value.repository, "candidate repository"),
    workflow: RELEASE_WORKFLOW,
    integrity: text(value.integrity, "candidate integrity"),
    shasum: text(value.shasum, "candidate shasum"),
    filename: text(value.filename, "candidate filename"),
    fileCount: value.fileCount as number,
  };
}

function packageUrl(name: string, version = ""): string {
  return `${REGISTRY}/${encodeURIComponent(name)}${version ? `/${encodeURIComponent(version)}` : ""}`;
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, { headers: { accept: "application/json" }, redirect: "error" });
  check(response.ok, `GET ${url} returned ${response.status}`);
  return response.json();
}

async function ensureUnpublished(value: ReleaseCandidate): Promise<void> {
  const response = await fetch(packageUrl(value.name, value.version), { redirect: "error" });
  check(response.status === 404, response.ok
    ? `${value.name}@${value.version} already exists; versions are immutable`
    : `registry preflight returned ${response.status}`);
  console.log(`${value.name}@${value.version} is not published`);
}

function safeUrl(value: unknown, label: string, prefix: string): URL {
  const url = new URL(text(value, label));
  check(url.origin === REGISTRY && url.pathname.startsWith(prefix), `unsafe ${label}`);
  return url;
}

export function verifyRegistryMetadata(
  value: ReleaseCandidate,
  input: unknown,
): { tarballUrl: URL; attestationsUrl: URL } {
  const metadata = record(input, "registry metadata");
  check(metadata.name === value.name && metadata.version === value.version, "registry package identity disagrees");
  check(metadata.gitHead === value.commit, "registry gitHead disagrees");
  const dist = record(metadata.dist, "registry dist");
  check(dist.integrity === value.integrity && dist.shasum === value.shasum, "registry integrity disagrees");
  const attestations = record(dist.attestations, "registry attestations");
  check(
    record(attestations.provenance, "registry provenance").predicateType === PROVENANCE_PREDICATE,
    "registry does not advertise SLSA v1 provenance",
  );
  return {
    tarballUrl: safeUrl(dist.tarball, "tarball URL", `/${value.name}/-/`),
    attestationsUrl: safeUrl(attestations.url, "attestations URL", "/-/npm/v1/attestations/"),
  };
}

function integrityHex(integrity: string): string {
  const match = integrity.match(/^sha512-([A-Za-z0-9+/]+={0,2})$/);
  check(match?.[1], "candidate integrity is not sha512");
  return Buffer.from(match[1], "base64").toString("hex");
}

function statement(item: unknown, value: ReleaseCandidate): RecordValue {
  const attestation = record(item, "attestation");
  const predicateType = text(attestation.predicateType, "predicate type");
  const envelope = record(record(attestation.bundle, "bundle").dsseEnvelope, "DSSE envelope");
  const decoded = record(
    JSON.parse(Buffer.from(text(envelope.payload, "DSSE payload"), "base64").toString("utf8")),
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
  const entries = record(input, "attestations document").attestations;
  check(Array.isArray(entries), "attestations document has no entries");
  const statements = new Map(entries.map((entry) => {
    const decoded = statement(entry, value);
    return [text(decoded.predicateType, "predicate type"), decoded];
  }));
  const publish = statements.get(PUBLISH_PREDICATE);
  const provenance = statements.get(PROVENANCE_PREDICATE);
  check(publish && provenance, "both npm publish and SLSA provenance attestations are required");
  const published = record(publish.predicate, "publish predicate");
  check(
    published.name === value.name && published.version === value.version && published.registry === REGISTRY,
    "publish attestation disagrees",
  );
  const build = record(record(provenance.predicate, "provenance predicate").buildDefinition, "build definition");
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

async function verifyTarball(value: ReleaseCandidate, url: URL): Promise<void> {
  const response = await fetch(url, { redirect: "error" });
  check(response.ok, `registry tarball returned ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  check(
    createHash("sha1").update(bytes).digest("hex") === value.shasum &&
      `sha512-${createHash("sha512").update(bytes).digest("base64")}` === value.integrity,
    "downloaded registry tarball differs from the reviewed pack",
  );
}

function verifyExactInstall(value: ReleaseCandidate): void {
  const root = mkdtempSync(join(tmpdir(), "accounts-consumer-"));
  try {
    writeFileSync(join(root, "package.json"), JSON.stringify({ private: true }));
    run("npm", [
      "install", "--ignore-scripts", "--audit=false", "--fund=false", "--save-exact",
      `${value.name}@${value.version}`,
    ], root);
    const installedPath = join(root, "node_modules", ...value.name.split("/"), "package.json");
    const installed = record(JSON.parse(readFileSync(installedPath, "utf8")), "installed package");
    check(installed.name === value.name && installed.version === value.version, "exact install resolved another version");
    run("npm", ["audit", "signatures"], root, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

async function verifyRegistryRelease(value: ReleaseCandidate, attempts: number, delayMs: number): Promise<void> {
  let failure: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const urls = verifyRegistryMetadata(value, await fetchJson(packageUrl(value.name, value.version)));
      verifyAttestations(value, await fetchJson(urls.attestationsUrl.href));
      await verifyTarball(value, urls.tarballUrl);
      verifyExactInstall(value);
      console.log(
        `verified ${value.name}@${value.version}: gitHead, tag, integrity, tarball, ` +
          "attestations, exact install, and npm signatures agree",
      );
      return;
    } catch (error) {
      failure = error;
      if (attempt < attempts) await Bun.sleep(delayMs);
    }
  }
  throw failure;
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
  } else if (subcommand === "require-trusted-publish") {
    assertTrustedPublishEnvironment(manifest, process.env, run("npm", ["--version"], root).trim());
    assertGitContext(root, manifest, process.env);
    console.log("trusted publish context verified");
  } else if (subcommand === "candidate") {
    assertTrustedPublishEnvironment(manifest, process.env, run("npm", ["--version"], root).trim());
    assertGitContext(root, manifest, process.env);
    const value = candidate(manifest, verifyDeterministicPack(root), text(process.env.GITHUB_SHA, "GITHUB_SHA"));
    const output = resolve(option(args, "--out"));
    writeFileSync(output, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    console.log(`wrote release candidate ${output}`);
  } else if (subcommand === "ensure-unpublished") {
    await ensureUnpublished(loadCandidate(resolve(option(args, "--candidate"))));
  } else if (subcommand === "verify-registry") {
    const attempts = Number(option(args, "--attempts", "12"));
    const delayMs = Number(option(args, "--delay-ms", "5000"));
    check(Number.isInteger(attempts) && attempts > 0, "invalid attempts");
    check(Number.isInteger(delayMs) && delayMs >= 0, "invalid delay");
    await verifyRegistryRelease(loadCandidate(resolve(option(args, "--candidate"))), attempts, delayMs);
  } else {
    throw new Error(
      "usage: release-provenance.ts pack | require-trusted-publish | candidate --out FILE | " +
        "ensure-unpublished --candidate FILE | verify-registry --candidate FILE",
    );
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(`release provenance failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
