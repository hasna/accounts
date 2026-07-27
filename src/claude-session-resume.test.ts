import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
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
import {
  CLAUDE_API_AUTH_ENV_KEYS,
  CLAUDE_CONTINUATION_SCRUB_ENV_KEYS,
  CLAUDE_NETWORK_ROUTING_ENV_KEYS,
} from "./lib/claude-auth.js";
import type { Profile } from "./types.js";

const SOURCE_UUID = "11111111-1111-4111-8111-111111111111";
const FORK_UUID = "22222222-2222-4222-8222-222222222222";
const FIRST_TURN_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECOND_TURN_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const FORK_TURN_UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const CLAUDE_220_AWS_METADATA_ENV_KEYS = [
  "AWS_EC2_METADATA_DISABLED",
  "AWS_EC2_METADATA_IPV4_ADDRESS",
  "AWS_EC2_METADATA_IPV6_ADDRESS",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
  "AWS_EC2_METADATA_V1_DISABLED",
] as const;
const CLAUDE_220_SETTINGS_OVERRIDE_ENV_KEYS = [
  "CLAUDE_CODE_MANAGED_SETTINGS_PATH",
  "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
  "CLAUDE_CODE_REMOTE_SETTINGS_PATH",
] as const;
// Unprefixed proxy and TLS-trust variables redirect and un-verify the launched
// session even though no vendor prefix names them.
const CLAUDE_220_CALLER_SDK_CONFIG_ENV_KEYS = [
  "AWS_CONFIG_FILE",
  "AWS_PROFILE",
  "AWS_REGION",
  "AWS_SHARED_CREDENTIALS_FILE",
  "CLOUDSDK_CONFIG",
  "GOOGLE_APPLICATION_CREDENTIALS",
] as const;
const CLAUDE_220_GENERIC_ROUTING_ENV_KEYS = [
  "ALL_PROXY",
  "CURL_CA_BUNDLE",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NO_PROXY",
  "REQUESTS_CA_BUNDLE",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "all_proxy",
  "http_proxy",
  "https_proxy",
  "no_proxy",
] as const;

function callerRoutingOverride(key: string): string {
  return /proxy/i.test(key) ? "http://127.0.0.1:1" : "caller-override";
}

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

function encodedProject(cwd: string): string {
  return cwd.replace(/[^A-Za-z0-9]/g, "-");
}

function sessionPath(
  owner: Profile,
  encoded = encodedProject(projectDir),
  uuid = SOURCE_UUID,
): string {
  const directory = join(owner.dir, "projects", encoded);
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
    parentUuid: null,
    isSidechain: false,
    type: "user",
    uuid: FIRST_TURN_UUID,
    sessionId: uuid,
    cwd: options.cwd ?? projectDir,
    message: { role: "user", content: "TRANSCRIPT_SECRET_MUST_NOT_ESCAPE" },
  });
  const second = options.malformed
    ? "{\"type\":"
    : JSON.stringify({
        parentUuid: FIRST_TURN_UUID,
        isSidechain: false,
        type: "assistant",
        uuid: SECOND_TURN_UUID,
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
import { appendFileSync, mkdirSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const log = process.env.FAKE_CLAUDE_LOG;
// Bun predefines HTTP_PROXY, HTTPS_PROXY, NO_PROXY, and
// NODE_TLS_REJECT_UNAUTHORIZED as own properties of process.env even when the
// process was started without them, so presence has to be read from the value.
const poisonedEnvKeys = (process.env.FAKE_CLAUDE_POISON_KEYS || "")
  .split(",")
  .filter((key) => key && process.env[key] !== undefined);
if (args.length === 1 && args[0] === "--version") {
  if (log) {
    appendFileSync(log, JSON.stringify({
      kind: "version",
      args,
      configDir: process.env.CLAUDE_CONFIG_DIR,
      secureStorageConfigDir: process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR,
      awsEc2MetadataDisabled: process.env.AWS_EC2_METADATA_DISABLED,
      poisonedEnvKeys,
    }) + "\\n");
  }
  console.log(process.env.FAKE_CLAUDE_VERSION || "2.1.220 (Claude Code)");
  if (process.env.FAKE_CLAUDE_SWAP_PATH) {
    writeFileSync(
      process.env.FAKE_CLAUDE_SWAP_PATH,
      "#!/usr/bin/env bun\\nprocess.exit(91);\\n",
    );
  }
  if (process.env.FAKE_CLAUDE_MUTATE_AFTER_VERSION === "1") {
    appendFileSync(process.argv[1], "\\n// changed after version probe\\n");
  }
  if (process.env.FAKE_CLAUDE_SWAP_SETTINGS_PATH) {
    writeFileSync(
      process.env.FAKE_CLAUDE_SWAP_SETTINGS_PATH,
      JSON.stringify({ proxyAuthHelper: "caller-command" }) + "\\n",
    );
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
    secureStorageConfigDir: process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR,
    awsEc2MetadataDisabled: process.env.AWS_EC2_METADATA_DISABLED,
    apiKeyPresent: Boolean(process.env.ANTHROPIC_API_KEY),
    directCredentialOverridePresent: poisonedEnvKeys.length > 0,
    poisonedEnvKeys,
  }) + "\\n");
}
if (process.env.FAKE_CLAUDE_REPLACE_LOCK_PATH) {
  unlinkSync(process.env.FAKE_CLAUDE_REPLACE_LOCK_PATH);
  writeFileSync(
    process.env.FAKE_CLAUDE_REPLACE_LOCK_PATH,
    "replacement-lock\\n",
    { mode: 0o600 },
  );
}
if (process.env.FAKE_CLAUDE_LAUNCH_DELAY_MS) {
  await new Promise((resolve) =>
    setTimeout(resolve, Number(process.env.FAKE_CLAUDE_LAUNCH_DELAY_MS)),
  );
}
if (process.env.FAKE_CLAUDE_MODE === "fail") process.exit(70);
if (args[0] === "--resume" && args[2] === "--fork-session" && configDir) {
  const sourceUuid = args[1];
  const projects = join(configDir, "projects");
  const projectKey = process.cwd().replace(/[^A-Za-z0-9]/g, "-");
  const project = join(projects, projectKey);
  const seed = join(project, sourceUuid + ".jsonl");
  try {
    readFileSync(seed);
  } catch {
    process.exit(71);
  }
  const forkUuid = process.env.FAKE_CLAUDE_FORK_UUID || "${FORK_UUID}";
  const mode = process.env.FAKE_CLAUDE_FORK_MODE || "valid";
  let history = readFileSync(seed, "utf8")
    .trimEnd()
    .split("\\n")
    .map((line) => {
      const record = JSON.parse(line);
      record.sessionId = forkUuid;
      return JSON.stringify(record);
    })
    .join("\\n") + "\\n";
  if (mode === "mixed-prefix-session") {
    const lines = history.trimEnd().split("\\n");
    const first = JSON.parse(lines[0]);
    first.sessionId = sourceUuid;
    lines[0] = JSON.stringify(first);
    history = lines.join("\\n") + "\\n";
  } else if (mode === "prefix-substitution") {
    const lines = history.trimEnd().split("\\n");
    const first = JSON.parse(lines[0]);
    first.message.content = "SUBSTITUTED_PREFIX";
    lines[0] = JSON.stringify(first);
    history = lines.join("\\n") + "\\n";
  } else if (mode === "prefix-truncation") {
    const lines = history.trimEnd().split("\\n");
    history = lines.slice(0, -1).join("\\n") + "\\n";
  }
  const destinationProject =
    mode === "wrong-project"
      ? join(projects, "-wrong-project")
      : project;
  mkdirSync(destinationProject, { recursive: true });
  writeFileSync(
    join(destinationProject, forkUuid + ".jsonl"),
    history + JSON.stringify({
      type: "user",
      uuid:
        mode === "duplicate-turn-uuid"
          ? "${SECOND_TURN_UUID}"
          : "${FORK_TURN_UUID}",
      isSidechain: false,
      sessionId: mode === "wrong-session" ? sourceUuid : forkUuid,
      cwd: mode === "wrong-cwd" ? configDir : process.cwd(),
      parentUuid:
        mode === "wrong-parent"
          ? "33333333-3333-4333-8333-333333333333"
          : "${SECOND_TURN_UUID}",
      message: { role: "user", content: "FAKE_FORK_CONTENT" },
    }) + "\\n",
  );
  if (mode === "fork-sidecar") {
    const sidecars = join(configDir, "future-state");
    mkdirSync(sidecars, { recursive: true });
    writeFileSync(join(sidecars, forkUuid + ".state"), "{}\\n");
  } else if (mode === "non-uuid-sidecar") {
    const sidecars = join(configDir, "projects", projectKey, "future-state");
    mkdirSync(sidecars, { recursive: true });
    writeFileSync(join(sidecars, "state.json"), "{}\\n");
  } else if (mode === "empty-sidecar") {
    mkdirSync(
      join(configDir, "projects", projectKey, "future-empty-state"),
      { recursive: true },
    );
  } else if (mode === "fork-symlink") {
    symlinkSync(seed, join(configDir, "projects", projectKey, "future-link"));
  }
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
    PATH: `${binDir}${delimiter}${process.env.PATH ?? ""}`,
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

function targetLockPath(targetDir: string): string {
  const identity = createHash("sha256")
    .update(targetDir)
    .digest("hex")
    .slice(0, 32);
  return join(accountsHome, `.session-resume-${identity}.lock`);
}

function runCliAsync(
  args: string[],
  extraEnv: NodeJS.ProcessEnv = {},
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, ["run", "src/cli.ts", ...args], {
      cwd: process.cwd(),
      env: cliEnv(extraEnv),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout!.setEncoding("utf8");
    child.stderr!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr!.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", rejectRun);
    child.once("exit", (status) => resolveRun({ status, stdout, stderr }));
  });
}

function launchEvents(): Array<{
  kind: string;
  args: string[];
  cwd?: string;
  configDir?: string;
  secureStorageConfigDir?: string;
  awsEc2MetadataDisabled?: string;
  apiKeyPresent?: boolean;
  directCredentialOverridePresent?: boolean;
  poisonedEnvKeys?: string[];
}> {
  if (!existsSync(launchLog)) return [];
  return readFileSync(launchLog, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

describe.skipIf(process.platform !== "linux")("accounts sessions resume", () => {
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
      secureStorageConfigDir: source.dir,
      awsEc2MetadataDisabled: "true",
      apiKeyPresent: false,
      directCredentialOverridePresent: false,
      poisonedEnvKeys: [],
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
    expect(CLAUDE_CONTINUATION_SCRUB_ENV_KEYS).toEqual(
      expect.arrayContaining([
        ...CLAUDE_220_AWS_METADATA_ENV_KEYS,
        ...CLAUDE_220_SETTINGS_OVERRIDE_ENV_KEYS,
        ...CLAUDE_220_CALLER_SDK_CONFIG_ENV_KEYS,
      ]),
    );
    expect(CLAUDE_NETWORK_ROUTING_ENV_KEYS).toEqual(
      expect.arrayContaining([...CLAUDE_220_GENERIC_ROUTING_ENV_KEYS]),
    );

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
        ...Object.fromEntries(
          [
            ...CLAUDE_API_AUTH_ENV_KEYS,
            ...CLAUDE_CONTINUATION_SCRUB_ENV_KEYS,
          ].map((key) => [key, "caller-override"]),
        ),
        ...Object.fromEntries(
          CLAUDE_NETWORK_ROUTING_ENV_KEYS.map((key) => [
            key,
            callerRoutingOverride(key),
          ]),
        ),
        CLAUDE_CODE_HOST_AUTH_ENV_VAR: "CALLER_DYNAMIC_TOKEN",
        CALLER_DYNAMIC_TOKEN: "caller-override",
        AWS_BEARER_TOKEN_CUSTOM: "caller-override",
        AWS_ENDPOINT_URL_BEDROCK: "caller-override",
        BUN_OPTIONS: "",
        LD_PRELOAD: "",
        NODE_OPTIONS: "",
        FAKE_CLAUDE_POISON_KEYS: [
          ...CLAUDE_API_AUTH_ENV_KEYS,
          ...CLAUDE_CONTINUATION_SCRUB_ENV_KEYS.filter(
            (key) => key !== "AWS_EC2_METADATA_DISABLED",
          ),
          ...CLAUDE_NETWORK_ROUTING_ENV_KEYS,
          "CALLER_DYNAMIC_TOKEN",
          "AWS_BEARER_TOKEN_CUSTOM",
          "AWS_ENDPOINT_URL_BEDROCK",
          "BUN_OPTIONS",
          "LD_PRELOAD",
          "NODE_OPTIONS",
        ].join(","),
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
    expect(
      launchEvents().find((entry) => entry.kind === "launch")?.poisonedEnvKeys,
    ).toEqual([]);
    expect(
      launchEvents().find((entry) => entry.kind === "version")?.poisonedEnvKeys,
    ).toEqual([]);
    expect(
      launchEvents().find((entry) => entry.kind === "version")
        ?.secureStorageConfigDir,
    ).toBe(target.dir);
    expect(
      launchEvents().find((entry) => entry.kind === "version")
        ?.awsEc2MetadataDisabled,
    ).toBe("true");
    expect(
      launchEvents().find((entry) => entry.kind === "launch")
        ?.secureStorageConfigDir,
    ).toBe(target.dir);
    expect(
      launchEvents().find((entry) => entry.kind === "launch")
        ?.awsEc2MetadataDisabled,
    ).toBe("true");
    expect(result.stdout).not.toContain("TRANSCRIPT_SECRET");
    expect(result.stderr).not.toContain("TRANSCRIPT_SECRET");
  });

  test("dry-run validates the adapter and layout without journaling, copying, or launching", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const sourceBytes = readFileSync(sourcePath);
    const sourceStat = lstatSync(sourcePath);
    const targetBefore = readdirSync(target.dir);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
      "--json",
    ], { ANTHROPIC_MODEL: "caller-model-override" });

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "cross_owner_fork",
      target: target.name,
      transaction: null,
    });
    expect(existsSync(join(target.dir, "projects"))).toBe(false);
    expect(existsSync(join(accountsHome, "session-resume-transactions"))).toBe(false);
    expect(readFileSync(sourcePath)).toEqual(sourceBytes);
    expect(lstatSync(sourcePath).ino).toBe(sourceStat.ino);
    expect(lstatSync(sourcePath).mtimeMs).toBe(sourceStat.mtimeMs);
    expect(readdirSync(target.dir)).toEqual(targetBefore);
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

  test("bare UUID fails closed when another matching catalog path was skipped", () => {
    const visible = profile("visible");
    const unreadable = profile("unreadable");
    writeStore([visible, unreadable]);
    writeSession(visible, { encodedProject: "-visible" });
    const unreadablePath = writeSession(unreadable, {
      encodedProject: "-unreadable",
      cwd: join(root, "other-repo"),
    });
    chmodSync(unreadablePath, 0o000);

    const ambiguous = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      visible.name,
      "--dry-run",
    ]);

    expect(ambiguous.status).toBe(1);
    expect(ambiguous.stderr).toContain("matching catalog path was skipped");
    const listed = runCli(["sessions", "list", "--json"]);
    const reference = (
      JSON.parse(listed.stdout) as Array<{ ownerProfile: string; catalogRef: string }>
    ).find((entry) => entry.ownerProfile === visible.name)!.catalogRef;
    const exact = runCli([
      "sessions",
      "resume",
      reference,
      "--account",
      visible.name,
      "--dry-run",
      "--json",
    ]);
    expect(exact.status).toBe(0);
  });

  test("bare UUID fails closed when any registered catalog root was skipped", () => {
    const visible = profile("visible");
    const missing = profile("missing");
    writeStore([visible, missing]);
    writeSession(visible);
    rmSync(missing.dir, { recursive: true, force: true });

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      visible.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("catalog path was skipped");
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
    ...[
      ["attachment", { attachments: [{ path: "foreign" }] }],
      ["tool", { tools: [{ name: "foreign" }] }],
      ["scheduled task", { scheduleId: "scheduled" }],
      ["subagent", { subagents: [{ id: "foreign" }] }],
    ].map(([label, dependency]) => ({
      label,
      record: {
        type: "user",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: { role: "user", content: "dependency" },
        ...(dependency as Record<string, unknown>),
      },
      expected: "dependency-bearing",
    })),
  ])("cross owner refuses $label outside the explicit simple subset", ({ record, expected }) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const resolvedRecord = {
      ...record,
      cwd: record.cwd === "PROJECT_DIR" ? projectDir : record.cwd,
      parentUuid: SECOND_TURN_UUID,
      isSidechain: false,
      uuid: FORK_TURN_UUID,
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

  test.each([
    {
      label: "unknown top-level field",
      record: {
        type: "user",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: { role: "user", content: "text" },
        futureField: true,
      },
    },
    {
      label: "unknown message field",
      record: {
        type: "user",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: { role: "user", content: "text", futureField: true },
      },
    },
    {
      label: "unknown content-block field",
      record: {
        type: "assistant",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: {
          role: "assistant",
          content: [{ type: "text", text: "text", futureField: true }],
        },
      },
    },
    {
      label: "unknown usage field",
      record: {
        type: "assistant",
        sessionId: SOURCE_UUID,
        cwd: "PROJECT_DIR",
        message: {
          role: "assistant",
          content: "text",
          usage: { input_tokens: 1, futureField: 1 },
        },
      },
    },
  ])("cross owner rejects $label in the explicit adapter schema", ({ record }) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const resolved = JSON.parse(
      JSON.stringify(record).replaceAll("PROJECT_DIR", projectDir),
    );
    resolved.parentUuid = SECOND_TURN_UUID;
    resolved.isSidechain = false;
    resolved.uuid = FORK_TURN_UUID;
    appendFileSync(sourcePath, `${JSON.stringify(resolved)}\n`);

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--dry-run",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("unsupported field");
    expect(launchEvents()).toEqual([]);
  });

  test.each([
    {
      label: "non-canonical JSON",
      mutate: (lines: string[]) => [` ${lines[0]}`, ...lines.slice(1)],
      expected: "canonical JSON lines",
    },
    {
      label: "missing turn UUID",
      mutate: (lines: string[]) => {
        const second = JSON.parse(lines[1]!);
        delete second.uuid;
        return [lines[0]!, JSON.stringify(second)];
      },
      expected: "UUID for every persisted turn",
    },
    {
      label: "duplicate turn UUID",
      mutate: (lines: string[]) => {
        const second = JSON.parse(lines[1]!);
        second.uuid = FIRST_TURN_UUID;
        return [lines[0]!, JSON.stringify(second)];
      },
      expected: "duplicate persisted turn UUID",
    },
    {
      label: "broken ancestry",
      mutate: (lines: string[]) => {
        const second = JSON.parse(lines[1]!);
        second.parentUuid = null;
        return [lines[0]!, JSON.stringify(second)];
      },
      expected: "linear persisted-turn ancestry",
    },
    {
      label: "sidechain turn",
      mutate: (lines: string[]) => {
        const second = JSON.parse(lines[1]!);
        second.isSidechain = true;
        return [lines[0]!, JSON.stringify(second)];
      },
      expected: "isSidechain=false",
    },
    {
      label: "tool stop reason",
      mutate: (lines: string[]) => {
        const second = JSON.parse(lines[1]!);
        second.message.stop_reason = "tool_use";
        return [lines[0]!, JSON.stringify(second)];
      },
      expected: "benign simple-turn enum",
    },
  ])("cross owner rejects $label outside canonical linear turns", ({ mutate, expected }) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const lines = readFileSync(sourcePath, "utf8").trimEnd().split("\n");
    writeFileSync(sourcePath, `${mutate(lines).join("\n")}\n`, { mode: 0o600 });

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

  test.each(["awsAuthRefresh", "proxyAuthHelper"])(
    "cross owner rejects effective %s hooks before version probing",
    (hook) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    writeFileSync(
      join(target.dir, "settings.json"),
      `${JSON.stringify({ [hook]: "caller-command" })}\n`,
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
    expect(result.stderr).toContain("provider auth hook");
    expect(launchEvents()).toEqual([]);
    },
  );

  test.each(["HTTPS_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED"])(
    "cross owner rejects effective settings env override %s before version probing",
    (key) => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    writeFileSync(
      join(target.dir, "settings.json"),
      `${JSON.stringify({ env: { [key]: callerRoutingOverride(key) } })}\n`,
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
    expect(result.stderr).toContain(`provider override "${key}"`);
    expect(launchEvents()).toEqual([]);
    },
  );

  test("settings swapped after version probing are rejected before transaction or launch", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const settings = join(target.dir, "settings.json");
    writeFileSync(settings, "{}\n", { mode: 0o600 });

    const result = runCli(
      [
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        target.name,
        "--json",
      ],
      { FAKE_CLAUDE_SWAP_SETTINGS_PATH: settings },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("provider auth hook");
    expect(launchEvents().map((entry) => entry.kind)).toEqual(["version"]);
    expect(existsSync(join(accountsHome, "session-resume-transactions"))).toBe(false);
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

  test("cross owner scans a large allowed line with bounded linear buffering", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    appendFileSync(
      sourcePath,
      `${JSON.stringify({
        parentUuid: SECOND_TURN_UUID,
        isSidechain: false,
        type: "user",
        uuid: FORK_TURN_UUID,
        sessionId: SOURCE_UUID,
        cwd: projectDir,
        message: {
          role: "user",
          content: "x".repeat(8 * 1024 * 1024),
        },
      })}\n`,
    );

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
    expect(launchEvents().map((entry) => entry.kind)).toEqual(["version"]);
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
    expect(escaped.stderr).toContain("symbolic link");
  });

  test("cross owner refuses ambiguous transcript cwd, target collisions, and mutation races", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    writeFileSync(
      sourcePath,
      `${JSON.stringify({
        parentUuid: null,
        isSidechain: false,
        type: "user",
        uuid: FIRST_TURN_UUID,
        sessionId: SOURCE_UUID,
        cwd: projectDir,
        message: { role: "user", content: "one" },
      })}\n` +
        `${JSON.stringify({
          parentUuid: FIRST_TURN_UUID,
          isSidechain: false,
          type: "assistant",
          uuid: SECOND_TURN_UUID,
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

    const lock = targetLockPath(target.dir);
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

  test("sessions resume fails closed outside the Linux uid trust domain", () => {
    const source = profile("source");
    writeStore([source]);
    writeSession(source);

    const result = runCli(
      [
        "sessions",
        "resume",
        SOURCE_UUID,
        "--account",
        source.name,
      ],
      { ACCOUNTS_TEST_FORCE_UNSUPPORTED_CONTINUATION_PLATFORM: "1" },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("only on Linux");
    expect(launchEvents()).toEqual([]);
  });

  test("cross-owner continuation rejects a cwd different from the source project", () => {
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

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("exact source cwd");
    expect(launchEvents()).toEqual([]);
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

  test(
    "simultaneous aliases of one target storage root produce exactly one fork launch",
    async () => {
      const source = profile("source");
      const target = profile("target");
      const alias = { ...target, name: "target-renamed" };
      writeStore([source, target, alias]);
      writeSession(source);
      const listed = runCli(["sessions", "list", "--json"]);
      const catalogRef = (
        JSON.parse(listed.stdout) as Array<{
          ownerProfile: string;
          catalogRef: string;
        }>
      ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
      const baseArgs = [
        "sessions",
        "resume",
        catalogRef,
        "--json",
      ];

      const [one, two] = await Promise.all([
        runCliAsync([...baseArgs, "--account", target.name], {
          FAKE_CLAUDE_LAUNCH_DELAY_MS: "400",
        }),
        runCliAsync([...baseArgs, "--account", alias.name], {
          FAKE_CLAUDE_LAUNCH_DELAY_MS: "400",
        }),
      ]);

      expect([one.status, two.status].sort()).toEqual([0, 1]);
      expect(
        launchEvents().filter((entry) => entry.kind === "launch"),
      ).toHaveLength(1);
      const replay = runCli([...baseArgs, "--account", alias.name]);
      expect(replay.status).toBe(0);
      expect(
        launchEvents().filter((entry) => entry.kind === "launch"),
      ).toHaveLength(1);
      expect(readdirSync(join(accountsHome, "session-resume-transactions"))).toHaveLength(1);
    },
    20_000,
  );

  test("target lock replacement during Claude launch is detected before final journaling", () => {
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
        "--json",
      ],
      { FAKE_CLAUDE_REPLACE_LOCK_PATH: targetLockPath(target.dir) },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("lock identity changed");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

  test("a dead target mutation lock is recovered without stealing a live lock", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const lock = targetLockPath(target.dir);
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
    "promoted",
    "validated",
    "committed",
  ] as const)(
    "retry recovers a real SIGKILL at the %s durability boundary",
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
      const crashed = runCli(args, {
        ACCOUNTS_TEST_SESSION_RESUME_CRASH_AT: state,
      });
      expect(crashed.signal).toBe("SIGKILL");
      expect(
        launchEvents().filter((entry) => entry.kind === "launch"),
      ).toHaveLength(0);

      const recovered = runCli(args);

      expect(recovered.status).toBe(0);
      expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
      const recoveredOutput = JSON.parse(recovered.stdout) as {
        destination: string;
        fork: string;
      };
      expect(recoveredOutput.destination).toBeTruthy();
      expect(readFileSync(recoveredOutput.destination)).toEqual(readFileSync(sessionPath(source)));
      expect(existsSync(recoveredOutput.fork)).toBe(true);
      expect(readdirSync(join(accountsHome, "session-resume-transactions"))).toHaveLength(1);
    },
    15_000,
  );

  test("schema-v1 development journals are rejected without launch", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
      }>
    ).find((entry) => entry.ownerProfile === source.name)!.catalogRef;
    const args = [
      "sessions",
      "resume",
      catalogRef,
      "--account",
      target.name,
      "--json",
    ];
    const crashed = runCli(args, {
      ACCOUNTS_TEST_SESSION_RESUME_CRASH_AT: "snapshotted",
    });
    expect(crashed.signal).toBe("SIGKILL");
    const transactions = join(accountsHome, "session-resume-transactions");
    const transaction = join(
      transactions,
      readdirSync(transactions)[0]!,
      "journal.json",
    );
    const journal = JSON.parse(readFileSync(transaction, "utf8"));
    journal.schemaVersion = 1;
    writeFileSync(transaction, `${JSON.stringify(journal, null, 2)}\n`, {
      mode: 0o600,
    });

    const retry = runCli(args);

    expect(retry.status).toBe(1);
    expect(retry.stderr).toContain("unsupported development contract");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(0);
  });

  test("a journal-less transaction directory fails closed", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const orphan = join(
      accountsHome,
      "session-resume-transactions",
      "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    );
    mkdirSync(orphan, { recursive: true, mode: 0o700 });

    const result = runCli([
      "sessions",
      "resume",
      SOURCE_UUID,
      "--account",
      target.name,
      "--json",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("missing its journal");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(0);
  });

  test("a PR22 catalogRef alias is canonicalized only after full journal binding", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalog = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
        catalogRefAliases: string[];
      }>
    ).find((entry) => entry.ownerProfile === source.name)!;
    expect(catalog.catalogRefAliases.length).toBeGreaterThan(0);
    const args = [
      "sessions",
      "resume",
      catalog.catalogRef,
      "--account",
      target.name,
      "--json",
    ];
    const failed = runCli(args, { FAKE_CLAUDE_MODE: "fail" });
    expect(failed.status).toBe(70);
    const transaction = (JSON.parse(failed.stdout) as { transaction: string })
      .transaction;
    const journal = JSON.parse(readFileSync(transaction, "utf8"));
    journal.state = "committed";
    journal.source.catalogRef = catalog.catalogRefAliases[0];
    delete journal.launch;
    delete journal.fork;
    writeFileSync(transaction, `${JSON.stringify(journal, null, 2)}\n`, {
      mode: 0o600,
    });

    const retry = runCli(args);

    expect(retry.status).toBe(0);
    expect(JSON.parse(readFileSync(transaction, "utf8")).source.catalogRef).toBe(
      catalog.catalogRef,
    );
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(2);
  });

  test("an unknown development catalogRef is rejected without another launch", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
      }>
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
    const transaction = (JSON.parse(failed.stdout) as { transaction: string })
      .transaction;
    const journal = JSON.parse(readFileSync(transaction, "utf8"));
    journal.state = "committed";
    journal.source.catalogRef = "claude-session:development-ref";
    delete journal.launch;
    delete journal.fork;
    writeFileSync(transaction, `${JSON.stringify(journal, null, 2)}\n`, {
      mode: 0o600,
    });

    const retry = runCli(args);

    expect(retry.status).toBe(1);
    expect(retry.stderr).toContain("unsupported development catalogRef");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

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

  test.each([
    "mixed-prefix-session",
    "prefix-substitution",
    "prefix-truncation",
    "wrong-project",
    "wrong-session",
    "wrong-cwd",
    "wrong-parent",
    "duplicate-turn-uuid",
    "fork-sidecar",
    "non-uuid-sidecar",
    "empty-sidecar",
    "fork-symlink",
  ])("cross-owner fork rejects %s output after exactly one launch", (mode) => {
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
        "--json",
      ],
      { FAKE_CLAUDE_FORK_MODE: mode },
    );

    expect(result.status).toBe(1);
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

  test("successful replay permits only a valid chained append after the authenticated fork prefix", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    const sourcePath = writeSession(source);
    const sourceBytes = readFileSync(sourcePath);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
      }>
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
    const output = JSON.parse(first.stdout) as { fork: string };
    const appendedTurn = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    appendFileSync(
      output.fork,
      `${JSON.stringify({
        parentUuid: FORK_TURN_UUID,
        isSidechain: false,
        type: "assistant",
        uuid: appendedTurn,
        sessionId: FORK_UUID,
        cwd: projectDir,
        message: {
          role: "assistant",
          content: "later valid turn",
          stop_reason: "end_turn",
        },
      })}\n`,
    );

    const replay = runCli(args);

    expect(replay.status).toBe(0);
    expect(readFileSync(sourcePath)).toEqual(sourceBytes);
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

  test("successful replay rejects a rewrite inside the authenticated fork prefix", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
      }>
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
    const output = JSON.parse(first.stdout) as { fork: string };
    const lines = readFileSync(output.fork, "utf8").trimEnd().split("\n");
    const turn = JSON.parse(lines[2]!);
    turn.message.content = "rewritten validated turn";
    lines[2] = JSON.stringify(turn);
    writeFileSync(output.fork, `${lines.join("\n")}\n`, { mode: 0o600 });

    const replay = runCli(args);

    expect(replay.status).toBe(1);
    expect(replay.stderr).toContain("retained");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

  test("successful replay rejects a session-id rewrite inside the authenticated fork prefix", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    const listed = runCli(["sessions", "list", "--json"]);
    const catalogRef = (
      JSON.parse(listed.stdout) as Array<{
        ownerProfile: string;
        catalogRef: string;
      }>
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
    const output = JSON.parse(first.stdout) as { fork: string };
    const lines = readFileSync(output.fork, "utf8").trimEnd().split("\n");
    const turn = JSON.parse(lines[0]!);
    turn.sessionId = SOURCE_UUID;
    lines[0] = JSON.stringify(turn);
    writeFileSync(output.fork, `${lines.join("\n")}\n`, { mode: 0o600 });

    const replay = runCli(args);

    expect(replay.status).toBe(1);
    expect(replay.stderr).toContain("session identity");
    expect(
      launchEvents().filter((entry) => entry.kind === "launch"),
    ).toHaveLength(1);
  });

  test.skipIf(!existsSync("/usr/bin/strace"))(
    "post-launch validation makes no Linux internet-family syscalls",
    () => {
      const source = profile("source");
      const target = profile("target");
      writeStore([source, target]);
      writeSession(source);
      const trace = join(root, "network-trace");

      const result = spawnSync(
        "/usr/bin/strace",
        [
          "-e",
          "trace=network",
          "-o",
          trace,
          process.execPath,
          "run",
          "src/cli.ts",
          "sessions",
          "resume",
          SOURCE_UUID,
          "--account",
          target.name,
          "--json",
        ],
        {
          cwd: process.cwd(),
          encoding: "utf8",
          env: cliEnv(),
        },
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      const networkSyscalls = readFileSync(trace, "utf8");
      expect(networkSyscalls).not.toMatch(/\bAF_INET6?\b/);
      expect(
        launchEvents().filter((entry) => entry.kind === "launch"),
      ).toHaveLength(1);
    },
    20_000,
  );

  test("cross-owner launch executes the verified private copy after the PATH executable is swapped", () => {
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
        "--json",
      ],
      { FAKE_CLAUDE_SWAP_PATH: join(binDir, "claude") },
    );

    expect(result.status).toBe(0);
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "cross_owner_fork",
      target: target.name,
    });
  });

  test("cross-owner launch pins the entry execvp would run, not an earlier non-executable one", () => {
    const source = profile("source");
    const target = profile("target");
    writeStore([source, target]);
    writeSession(source);
    // A stale shim without the executable bit: execvp skips it, so the pinned
    // private copy must be taken from the real binary further along PATH.
    const shadowDir = join(root, "shadow-bin");
    mkdirSync(shadowDir, { recursive: true });
    const shadow = join(shadowDir, "claude");
    writeFileSync(shadow, "#!/usr/bin/env bun\nprocess.exit(91);\n");
    chmodSync(shadow, 0o644);

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
        PATH: `${shadowDir}${delimiter}${binDir}${delimiter}${process.env.PATH ?? ""}`,
      },
    );

    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(launchEvents().filter((entry) => entry.kind === "launch")).toHaveLength(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      mode: "cross_owner_fork",
      target: target.name,
    });
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
      });
      expect(
        launchEvents().filter((entry) => entry.kind === "launch"),
      ).toHaveLength(1);
    },
    30_000,
  );
});

function dirnameOf(path: string): string {
  const index = path.lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}
