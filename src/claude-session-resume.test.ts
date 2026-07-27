import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import type { Profile } from "./types.js";

const SOURCE_UUID = "11111111-1111-4111-8111-111111111111";
const FORK_UUID = "22222222-2222-4222-8222-222222222222";

function findNodeBinary(): string | undefined {
  const extensions =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";")
      : [""];
  for (const entry of (process.env.PATH ?? "").split(delimiter)) {
    if (!entry) continue;
    for (const extension of extensions) {
      const candidate = join(entry, `node${extension.toLowerCase()}`);
      if (existsSync(candidate)) return candidate;
      const upper = join(entry, `node${extension.toUpperCase()}`);
      if (process.platform === "win32" && existsSync(upper)) return upper;
    }
  }
  return undefined;
}

const requestedNodeBinary = process.env.ACCOUNTS_TEST_NODE_BINARY;
const NODE_BINARY =
  requestedNodeBinary && existsSync(requestedNodeBinary)
    ? requestedNodeBinary
    : findNodeBinary();

let root: string;
let accountsHome: string;
let profilesRoot: string;
let fakeHome: string;
let binDir: string;
let projectDir: string;
let launchLog: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "accounts-session-resume-"));
  accountsHome = join(root, "accounts");
  profilesRoot = join(accountsHome, "profiles");
  fakeHome = join(root, "home");
  binDir = join(root, "bin");
  projectDir = join(root, "repo");
  launchLog = join(root, "claude-launches.jsonl");
  for (const path of [profilesRoot, fakeHome, binDir, projectDir]) {
    mkdirSync(path, { recursive: true });
  }
  writeFakeClaude();
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function profile(name: string): Profile {
  return {
    name,
    tool: "claude",
    dir: join(profilesRoot, "claude", name),
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

function writeStore(profiles: Profile[]): void {
  mkdirSync(accountsHome, { recursive: true, mode: 0o700 });
  for (const entry of profiles) mkdirSync(entry.dir, { recursive: true, mode: 0o700 });
  writeFileSync(
    join(accountsHome, "accounts.json"),
    JSON.stringify({
      version: 1,
      current: {},
      applied: {},
      toolLocks: Object.fromEntries(profiles.map((entry) => [entry.name, entry.tool])),
      tools: [],
      profiles,
    }),
    { mode: 0o600 },
  );
}

function sessionPath(owner: Profile, encodedProject = "-repo", uuid = SOURCE_UUID): string {
  const directory = join(owner.dir, "projects", encodedProject);
  mkdirSync(directory, { recursive: true });
  return join(directory, `${uuid}.jsonl`);
}

function writeSession(
  owner: Profile,
  options: {
    encodedProject?: string;
    uuid?: string;
    cwd?: string;
    complete?: boolean;
    malformed?: boolean;
  } = {},
): string {
  const uuid = options.uuid ?? SOURCE_UUID;
  const path = sessionPath(owner, options.encodedProject, uuid);
  const first = JSON.stringify({
    type: "user",
    sessionId: uuid,
    cwd: options.cwd ?? projectDir,
    message: { role: "user", content: "TRANSCRIPT_SECRET_MUST_NOT_ESCAPE" },
  });
  const second = options.malformed
    ? "{\"type\":"
    : JSON.stringify({
        type: "assistant",
        sessionId: uuid,
        cwd: options.cwd ?? projectDir,
        message: { role: "assistant", content: "ASSISTANT_SECRET_MUST_NOT_ESCAPE" },
      });
  writeFileSync(path, `${first}\n${second}${options.complete === false ? "" : "\n"}`, { mode: 0o600 });
  return path;
}

function writeFakeClaude(): void {
  const path = join(binDir, "claude");
  writeFileSync(
    path,
    `#!/usr/bin/env bun
import { appendFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const log = process.env.FAKE_CLAUDE_LOG;
if (args.length === 1 && args[0] === "--version") {
  if (log) appendFileSync(log, JSON.stringify({ kind: "version", args }) + "\\n");
  console.log(process.env.FAKE_CLAUDE_VERSION || "2.1.220 (Claude Code)");
  if (process.env.FAKE_CLAUDE_MUTATE_AFTER_VERSION === "1") {
    appendFileSync(process.argv[1], "\\n// changed after version probe\\n");
  }
  process.exit(0);
}
const configDir = process.env.CLAUDE_CONFIG_DIR;
if (log) {
  appendFileSync(log, JSON.stringify({
    kind: "launch",
    args,
    cwd: process.cwd(),
    configDir,
    apiKeyPresent: Boolean(process.env.ANTHROPIC_API_KEY),
    directCredentialOverridePresent: [
      "ANTHROPIC_AWS_API_KEY",
      "ANTHROPIC_FEDERATION_RULE_ID",
      "ANTHROPIC_FOUNDRY_API_KEY",
      "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
      "ANTHROPIC_ORGANIZATION_ID",
      "AWS_BEARER_TOKEN_BEDROCK",
      "CLOUDSDK_AUTH_ACCESS_TOKEN",
      "CLAUDE_CODE_HFI_BEARER_TOKEN",
      "CLAUDE_CODE_HOST_CREDS_FILE",
      "CLAUDE_CODE_OAUTH_TOKEN",
      "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
      "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
      "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
      "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
      "CLAUDE_TRUSTED_DEVICE_TOKEN",
    ].some((key) => Boolean(process.env[key])),
  }) + "\\n");
}
if (process.env.FAKE_CLAUDE_MODE === "fail") process.exit(70);
if (args[0] === "--resume" && args[2] === "--fork-session" && configDir) {
  const sourceUuid = args[1];
  const projects = join(configDir, "projects");
  let seed;
  let project;
  for (const encoded of readdirSync(projects)) {
    const candidate = join(projects, encoded, sourceUuid + ".jsonl");
    try {
      readFileSync(candidate);
      seed = candidate;
      project = join(projects, encoded);
      break;
    } catch {}
  }
  if (!seed || !project) process.exit(71);
  const forkUuid = process.env.FAKE_CLAUDE_FORK_UUID || "${FORK_UUID}";
  const history = readFileSync(seed, "utf8");
  mkdirSync(project, { recursive: true });
  writeFileSync(
    join(project, forkUuid + ".jsonl"),
    history + JSON.stringify({
      type: "user",
      sessionId: forkUuid,
      cwd: process.cwd(),
      parentUuid: sourceUuid,
      message: { role: "user", content: "FAKE_FORK_CONTENT" },
    }) + "\\n",
  );
}
`,
    { mode: 0o700 },
  );
  chmodSync(path, 0o700);
}

function cliEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_ENV: "test",
    HOME: fakeHome,
    ACCOUNTS_HOME: accountsHome,
    NO_COLOR: "1",
    PATH: `${binDir}:${process.env.PATH ?? ""}`,
    FAKE_CLAUDE_LOG: launchLog,
    FAKE_CLAUDE_FORK_UUID: FORK_UUID,
    HTTP_PROXY: "http://127.0.0.1:1",
    HTTPS_PROXY: "http://127.0.0.1:1",
    NO_PROXY: "",
    ...extra,
  };
}

function runCli(args: string[], extraEnv: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: cliEnv(extraEnv),
  });
}

function launchEvents(): Array<{
  kind: string;
  args: string[];
  cwd?: string;
  configDir?: string;
  apiKeyPresent?: boolean;
  directCredentialOverridePresent?: boolean;
}> {
  if (!existsSync(launchLog)) return [];
  return readFileSync(launchLog, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

describe("accounts sessions resume", () => {
  test("same owner launches exact native --resume UUID with source cwd and no continue semantics", () => {
    const source = profile("source");
    writeStore([source]);
    const sourcePath = writeSession(source);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      source.name,
      "--json",
    ]);

    expect(result.status).toBe(0);
    const launch = launchEvents().find((entry) => entry.kind === "launch");
    expect(launch).toEqual({
      kind: "launch",
      args: ["--resume", SOURCE_UUID],
      cwd: projectDir,
      configDir: source.dir,
      apiKeyPresent: false,
      directCredentialOverridePresent: false,
    });
    expect(result.stdout).not.toContain("TRANSCRIPT_SECRET");
    expect(result.stderr).not.toContain("TRANSCRIPT_SECRET");
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "same_owner",
      source: sourcePath,
      destination: sourcePath,
      target: source.name,
      cwd: projectDir,
      transaction: null,
    });
  });

  test("cross owner copies privately, launches exact fork argv, and preserves an independent fork", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const sourceBytes = readFileSync(sourcePath);
    const sourceStat = lstatSync(sourcePath);

    const result = runCli(
      [
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        target.name,
        "--json",
      ],
      {
        ANTHROPIC_AWS_API_KEY: "caller-override",
        ANTHROPIC_FEDERATION_RULE_ID: "caller-override",
        ANTHROPIC_FOUNDRY_API_KEY: "caller-override",
        ANTHROPIC_FOUNDRY_AUTH_TOKEN: "caller-override",
        ANTHROPIC_ORGANIZATION_ID: "caller-override",
        AWS_BEARER_TOKEN_BEDROCK: "caller-override",
        CLOUDSDK_AUTH_ACCESS_TOKEN: "caller-override",
        CLAUDE_CODE_HFI_BEARER_TOKEN: "caller-override",
        CLAUDE_CODE_HOST_CREDS_FILE: "caller-override",
        CLAUDE_CODE_OAUTH_TOKEN: "caller-override",
        CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR: "9",
        CLAUDE_CODE_SESSION_ACCESS_TOKEN: "caller-override",
        CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR: "10",
        CLAUDE_SESSION_INGRESS_TOKEN_FILE: "caller-override",
        CLAUDE_TRUSTED_DEVICE_TOKEN: "caller-override",
      },
    );

    expect(result.status).toBe(0);
    const output = JSON.parse(result.stdout) as {
      mode: string;
      destination: string;
      fork: string;
      transaction: string;
    };
    expect(output.mode).toBe("cross_owner_fork");
    expect(output.transaction).toContain("session-resume-transactions");
    expect(readFileSync(sourcePath)).toEqual(sourceBytes);
    expect(lstatSync(sourcePath).ino).toBe(sourceStat.ino);
    expect(readFileSync(output.destination)).toEqual(sourceBytes);
    expect(lstatSync(output.destination).ino).not.toBe(sourceStat.ino);
    expect(lstatSync(output.fork).ino).not.toBe(sourceStat.ino);
    expect(statSync(dirnameOf(output.transaction)).mode & 0o777).toBe(0o700);
    expect(statSync(output.transaction).mode & 0o777).toBe(0o600);
    expect(launchEvents().find((entry) => entry.kind === "launch")?.args).toEqual([
      "--resume",
      SOURCE_UUID,
      "--fork-session",
    ]);
    expect(
      launchEvents().find((entry) => entry.kind === "launch")
        ?.directCredentialOverridePresent,
    ).toBe(false);
    expect(result.stdout).not.toContain("TRANSCRIPT_SECRET");
    expect(result.stderr).not.toContain("TRANSCRIPT_SECRET");
  });

  test("dry-run validates the adapter and layout without journaling, copying, or launching", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
      "--json",
    ]);

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "cross_owner_fork",
      target: target.name,
      transaction: null,
    });
    expect(existsSync(join(target.dir, "projects"))).toBe(false);
    expect(existsSync(join(accountsHome, "session-resume-transactions"))).toBe(false);
    expect(launchEvents().map((entry) => entry.kind)).toEqual(["version"]);
  });

  test("bare UUID fails closed when owner and project identity are ambiguous", () => {
    const one = profile("one");
    const two = profile("two");
    const target = profile("target");
    writeStore([one, two, target]);
    writeSession(one, { encodedProject: "-one" });
    writeSession(two, { encodedProject: "-two", cwd: join(root, "other-repo") });

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("ambiguous");
    expect(result.stderr).not.toContain("TRANSCRIPT_SECRET");
    expect(launchEvents()).toEqual([]);
  });

  test("opaque catalog reference selects the exact tuple when UUIDs collide", () => {
    const one = profile("one");
    const two = profile("two");
    writeStore([one, two]);
    writeSession(one, { encodedProject: "-one" });
    writeSession(two, { encodedProject: "-two", cwd: join(root, "other-repo") });
    const listed = runCli(["sessions", "list", "--json"]);
    expect(listed.status).toBe(0);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === one.name)?.catalogRef;
    expect(catalogRef).toBeTruthy();

    const result = runCli([
      "sessions",
      "resume",
      catalogRef!,
      "--account",
      one.name,
      "--dry-run",
      "--json",
    ]);

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "same_owner",
      target: one.name,
    });
  });

  test("cross owner refuses malformed or incomplete root JSONL before mutation", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source, { malformed: true, complete: false });

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("complete");
    expect(existsSync(join(target.dir, "projects"))).toBe(false);
    expect(launchEvents()).toEqual([]);
  });

  test.each([
    {
      label: "unknown record type",
      record: {
        type: "file-history-snapshot",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: {},
      },
      expected: "simple user/assistant",
    },
    {
      label: "dependency-bearing record",
      record: {
        type: "user",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: { role: "user", content: "dependency" },
        taskId: "external-task",
      },
      expected: "dependency-bearing",
    },
  ])("cross owner refuses $label outside the explicit simple subset", ({ record, expected }) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const resolvedRecord = {
      ...record,
      cwd: record.cwd === "PROJECT_DIR" ? projectDir : record.cwd,
    };
    writeFileSync(
      sourcePath,
      `${readFileSync(sourcePath, "utf8")}${JSON.stringify(resolvedRecord)}\n`,
      { mode: 0o600 },
    );

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain(expected);
    expect(launchEvents()).toEqual([]);
  });

  test("cross owner bounds a JSONL line before parsing or allocation growth", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    writeFileSync(
      sourcePath,
      `${readFileSync(sourcePath, "utf8")}${"x".repeat(16 * 1024 * 1024 + 1)}\n`,
      { mode: 0o600 },
    );

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("safety bound");
    expect(launchEvents()).toEqual([]);
  });

  test("cross owner refuses unclassified UUID sidecars and unsupported Claude versions", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const sidecar = join(source.dir, "tasks", SOURCE_UUID);
    mkdirSync(sidecar, { recursive: true });
    writeFileSync(join(sidecar, "task.json"), "{}\n");

    const sidecarResult = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);
    expect(sidecarResult.status).toBe(1);
    expect(sidecarResult.stderr).toContain("sidecar");
    expect(launchEvents()).toEqual([]);

    rmSync(join(source.dir, "tasks"), { recursive: true, force: true });
    const versionResult = runCli(
      [
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        target.name,
        "--dry-run",
      ],
      { FAKE_CLAUDE_VERSION: "2.1.221 (Claude Code)" },
    );
    expect(versionResult.status).toBe(1);
    expect(versionResult.stderr).toContain("2.1.220");
    expect(launchEvents().map((entry) => entry.kind)).toEqual(["version"]);
  });

  test.each([
    "companion",
    "tasks",
    "file-history",
    "unknown",
  ] as const)("cross owner refuses %s UUID dependency state", (kind) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    if (kind === "companion") {
      mkdirSync(sourcePath.replace(/\.jsonl$/, ""), { recursive: true });
    } else if (kind === "unknown") {
      const path = join(source.dir, "future-state", "nested");
      mkdirSync(path, { recursive: true });
      writeFileSync(join(path, `${SOURCE_UUID}.state`), "{}\n");
    } else {
      const path = join(source.dir, kind, SOURCE_UUID);
      mkdirSync(path, { recursive: true });
      writeFileSync(join(path, "state.json"), "{}\n");
    }

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("sidecar");
    expect(launchEvents()).toEqual([]);
  });

  test("cross owner refuses active writers, hardlinks, and escaping UUID links", async () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const writerScript = join(root, "writer.ts");
    writeFileSync(
      writerScript,
      `import { openSync } from "node:fs";
const fd = openSync(process.argv[2], "a");
console.log("READY");
setInterval(() => void fd, 1000);
`,
    );
    const writer = spawn(process.execPath, ["run", writerScript, sourcePath], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    await new Promise<void>((resolveReady, rejectReady) => {
      writer.once("error", rejectReady);
      writer.stdout!.once("data", () => resolveReady());
    });
    try {
      const active = runCli([
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        target.name,
        "--dry-run",
      ]);
      expect(active.status).toBe(1);
      expect(active.stderr).toContain("active writer");
      expect(launchEvents()).toEqual([]);
    } finally {
      writer.kill("SIGTERM");
      await new Promise<void>((resolveExit) => writer.once("exit", () => resolveExit()));
    }

    const hardlink = join(sourcePath, "..", `${SOURCE_UUID}.hardlink`);
    linkSync(sourcePath, hardlink);
    const linked = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);
    expect(linked.status).toBe(1);
    expect(linked.stderr).toContain("no Accounts-owned Claude session");
    rmSync(hardlink);

    const outside = join(root, "outside-state");
    writeFileSync(outside, "{}\n");
    symlinkSync(outside, join(source.dir, `${SOURCE_UUID}.link`));
    const escaped = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);
    expect(escaped.status).toBe(1);
    expect(escaped.stderr).toContain("sidecar");
  });

  test("cross owner refuses ambiguous transcript cwd, target collisions, and mutation races", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    writeFileSync(
      sourcePath,
      `${JSON.stringify({
        type: "user",
        sessionId: SOURCE_UUID,
        cwd: projectDir,
        message: { role: "user", content: "one" },
      })}\n` +
        `${JSON.stringify({
          type: "assistant",
          sessionId: SOURCE_UUID,
          cwd: join(root, "other"),
          message: { role: "assistant", content: "two" },
        })}\n`,
    );
    const ambiguous = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);
    expect(ambiguous.status).toBe(1);
    expect(ambiguous.stderr).toContain("ambiguous cwd");

    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    writeSession(target);
    const collision = runCli([
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--dry-run",
    ]);
    expect(collision.status).toBe(1);
    expect(collision.stderr).toContain("collision");
    rmSync(sessionPath(target));

    const lock = join(accountsHome, `.session-resume-${target.name}.lock`);
    writeFileSync(lock, "other-writer\n", { mode: 0o600 });
    const raced = runCli([
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ]);
    expect(raced.status).toBe(1);
    expect(raced.stderr).toContain("mutation in progress");
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(0);
  });

  test("opaque references fail closed after the local profile registry becomes stale", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const stale = { ...source, dir: join(root, "foreign-profile") };
    mkdirSync(stale.dir, { recursive: true });
    writeStore([stale, target]);

    const result = runCli([
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("stale");
    expect(launchEvents()).toEqual([]);
  });

  test("same-owner resume enforces current-uid ownership before native launch", () => {
    if (typeof process.getuid !== "function" || process.getuid() !== 0) return;
    const source = profile("source");
    writeStore([source]);
    const sourcePath = writeSession(source);
    chownSync(sourcePath, 65534, 65534);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      source.name,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("uid trust domain");
    expect(launchEvents()).toEqual([]);
  });

  test("explicit absolute cwd is honored without inferring the caller directory", () => {
    const source = profile("source");
    const target = profile("target");
    const explicitCwd = join(root, "explicit-cwd");
    mkdirSync(explicitCwd);
    writeStore([source, target]);
    writeSession(source);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--cwd",
      explicitCwd,
      "--json",
    ]);

    expect(result.status).toBe(0);
    expect(launchEvents().find((entry) => entry.kind === "launch")?.cwd).toBe(explicitCwd);
    expect(JSON.parse(result.stdout).cwd).toBe(explicitCwd);
  });

  test("a failed launch is journaled once and retry never launches another fork", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const args = [
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ];

    const failed = runCli(args, { FAKE_CLAUDE_MODE: "fail" });
    expect(failed.status).toBe(70);
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);

    const retry = runCli(args);
    expect(retry.status).toBe(1);
    expect(retry.stderr).toContain("recovery");
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
    const transactionsRoot = join(accountsHome, "session-resume-transactions");
    expect(readdirSync(transactionsRoot)).toHaveLength(1);
  });

  test("a dead target mutation lock is recovered without stealing a live lock", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const lock = join(accountsHome, `.session-resume-${target.name}.lock`);
    writeFileSync(
      lock,
      "2147483647:33333333-3333-4333-8333-333333333333\n",
      { mode: 0o600 },
    );

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--json",
    ]);

    expect(result.status).toBe(0);
    expect(existsSync(lock)).toBe(false);
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
  });

  test.each([
    "snapshotted",
    "fork_created",
  ] as const)(
    "retry recovers a valid %s crash window without overwriting",
    (state) => {
      const source = profile("source");
      const target = profile("target");
      writeStore([source, target]);
      writeSession(source);
      const listed = runCli(["sessions", "list", "--json"]);
      const catalogRef = (
        JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
      ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
      const args = [
        "sessions",
        "resume",
        catalogRef,
        "--account",
        target.name,
        "--json",
      ];
      const failed = runCli(args, { FAKE_CLAUDE_MODE: "fail" });
      expect(failed.status).toBe(70);
      const failedOutput = JSON.parse(failed.stdout) as {
        destination: string;
        transaction: string;
      };
      const journal = JSON.parse(readFileSync(failedOutput.transaction, "utf8")) as {
        state: string;
        launch?: unknown;
        fork?: unknown;
      };
      journal.state = state;
      delete journal.launch;
      delete journal.fork;
      if (state === "snapshotted") rmSync(failedOutput.destination);
      writeFileSync(
        failedOutput.transaction,
        `${JSON.stringify(journal, null, 2)}\n`,
        { mode: 0o600 },
      );

      const recovered = runCli(args);

      expect(recovered.status).toBe(0);
      expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(2);
      const recoveredOutput = JSON.parse(recovered.stdout) as {
        destination: string;
        fork: string;
      };
      expect(recoveredOutput.destination).toBeTruthy();
      expect(readFileSync(recoveredOutput.destination)).toEqual(readFileSync(sessionPath(source)));
      expect(existsSync(recoveredOutput.fork)).toBe(true);
    },
    15_000,
  );

  test("retry rejects a journal rebound to a different target path", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const args = [
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ];
    const failed = runCli(args, { FAKE_CLAUDE_MODE: "fail" });
    expect(failed.status).toBe(70);
    const transaction = (JSON.parse(failed.stdout) as { transaction: string }).transaction;
    const journal = JSON.parse(readFileSync(transaction, "utf8")) as {
      target: { configDir: string };
    };
    journal.target.configDir = join(root, "foreign-target");
    writeFileSync(transaction, `${JSON.stringify(journal, null, 2)}\n`, { mode: 0o600 });

    const retry = runCli(args);

    expect(retry.status).toBe(1);
    expect(retry.stderr).toContain("identity is stale or inconsistent");
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
    expect(existsSync(journal.target.configDir)).toBe(false);
  });

  test("committed retry revalidates the target seed before Claude can consume it", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const args = [
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ];
    const failed = runCli(args, { FAKE_CLAUDE_MODE: "fail" });
    expect(failed.status).toBe(70);
    const output = JSON.parse(failed.stdout) as {
      destination: string;
      transaction: string;
    };
    const journal = JSON.parse(readFileSync(output.transaction, "utf8")) as {
      state: string;
      launch?: unknown;
      fork?: unknown;
    };
    journal.state = "committed";
    delete journal.launch;
    delete journal.fork;
    writeFileSync(output.transaction, `${JSON.stringify(journal, null, 2)}\n`, {
      mode: 0o600,
    });
    writeFileSync(output.destination, "mutated seed\n", { mode: 0o600 });

    const retry = runCli(args);

    expect(retry.status).toBe(1);
    expect(retry.stderr).toContain("committed target");
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
  });

  test("successful replay revalidates retained seed and fork artifacts", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const args = [
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ];
    const first = runCli(args);
    expect(first.status).toBe(0);
    const output = JSON.parse(first.stdout) as {
      destination: string;
      fork: string;
    };
    writeFileSync(output.destination, "mutated retained seed\n", { mode: 0o600 });

    const replay = runCli(args);

    expect(replay.status).toBe(1);
    expect(replay.stderr).toContain("committed target");
    expect(existsSync(output.fork)).toBe(true);
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
  });

  test("cross-owner launch refuses a Claude executable changed after version probing", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);

    const result = runCli(
      [
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        target.name,
        "--dry-run",
      ],
      { FAKE_CLAUDE_MUTATE_AFTER_VERSION: "1" },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("executable changed");
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(0);
  });

  test.skipIf(!NODE_BINARY)(
    "built Node CLI resolves and pins the selected Claude executable without Bun globals",
    () => {
      const source = profile("source");
      const target = profile("target");
      writeStore([source, target]);
      writeSession(source);
      const buildDir = join(root, "node-build");
      const build = spawnSync(
        process.execPath,
        [
          "build",
          "src/cli.ts",
          "--outdir",
          buildDir,
          "--target",
          "node",
        ],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          env: cliEnv(),
        },
      );
      expect(build.status, `${build.stdout}\n${build.stderr}`).toBe(0);

      const result = spawnSync(
        NODE_BINARY!,
        [
          join(buildDir, "cli.js"),
          "sessions",
          "resume",
          SOURCE_UUID,
          "--account",
          target.name,
          "--dry-run",
          "--json",
        ],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          env: cliEnv(),
        },
      );

      expect(
        result.status,
        `${String(result.error ?? "")}\n${result.stdout}\n${result.stderr}`,
      ).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        mode: "cross_owner_fork",
        target: target.name,
        transaction: null,
      });
      expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(0);
    },
    30_000,
  );
});

function dirnameOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}
