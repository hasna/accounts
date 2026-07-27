import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
  type Stats,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { accountsHome, profilesDir } from "../storage.js";
import { AccountsError, type Profile, type ToolDef } from "../types.js";
import {
  CLAUDE_API_AUTH_ENV_KEYS,
  CLAUDE_CONTINUATION_SCRUB_ENV_KEYS,
  CLAUDE_NETWORK_ROUTING_ENV_KEYS,
} from "./claude-auth.js";
import { resolveExecutable, runClaudeLaunch } from "./claude-launch.js";
import {
  isClaudeSessionUuid,
  listClaudeSessions,
  matchesClaudeSessionReference,
  resolveClaudeSessionReference,
  type ClaudeSessionCatalogEntry,
  type ClaudeSessionScanSkip,
} from "./claude-sessions.js";
import { getTool } from "./tools.js";

export const CLAUDE_CONTINUATION_ADAPTER = {
  schemaVersion: 1,
  id: "claude-local-root-jsonl",
  cliVersion: "2.1.220",
} as const;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TRANSACTIONS_DIR = "session-resume-transactions";
const JOURNAL_FILE = "journal.json";
const MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024;
const MAX_SIDECAR_SCAN_ENTRIES = 50_000;
const TRANSACTION_STATES = new Set<TransactionState>([
  "snapshotted",
  "fork_created",
  "promoted",
  "validated",
  "committed",
  "launched",
  "failed",
]);

type TransactionState =
  | "snapshotted"
  | "fork_created"
  | "promoted"
  | "validated"
  | "committed"
  | "launched"
  | "failed";

interface SourceFingerprint {
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

interface StableFileIdentity {
  dev: number;
  ino: number;
  mode: number;
  nlink: number;
  uid: number;
}

interface TransactionJournal {
  schemaVersion: 2;
  id: string;
  adapter: typeof CLAUDE_CONTINUATION_ADAPTER;
  state: TransactionState;
  source: {
    catalogRef: string;
    path: string;
    fingerprint: SourceFingerprint;
    digest: string;
    byteLength: number;
    normalizedDigest: string;
    lineCount: number;
    lastRecordIdentity: string;
    cwd: string;
  };
  target: {
    account: string;
    configDir: string;
    cwd: string;
    destination: string;
  };
  artifacts: {
    backup: string;
    candidate: string;
    journal: string;
  };
  fork?: {
    uuid: string;
    path: string;
    lineCount: number;
    byteLength?: number;
    digest?: string;
    identity?: StableFileIdentity;
  };
  launch?: {
    status: "started" | "completed";
    exitCode?: number;
  };
  recovery: string;
  createdAt: string;
  updatedAt: string;
}

interface JsonlInspection {
  cwd: string;
  cwds: Set<string>;
  lineCount: number;
  sessionIds: Set<string>;
  fingerprint: SourceFingerprint;
  rawDigest: string;
  byteLength: number;
  normalizedDigest: string;
  lastRecordIdentity: string;
  prefixDigest?: string;
  suffixLineCount: number;
  suffixSessionIds: Set<string>;
  suffixCwds: Set<string>;
  firstSuffixParentIdentity?: string;
  prefixBoundaryByteLength?: number;
  retainedPrefixDigest?: string;
  retainedPrefixBoundaryByteLength?: number;
}

interface PinnedClaudeTool {
  tool: ToolDef;
  fingerprint: SourceFingerprint;
  digest: string;
  executableFd: number;
  pinDirectory: string;
  pinPath: string;
}

export interface ClaudeSessionResumeOptions {
  profiles: readonly Profile[];
  targetProfile: Profile;
  referenceOrUuid: string;
  cwd?: string;
  dryRun?: boolean;
}

export interface ClaudeSessionResumeResult {
  mode: "same_owner" | "cross_owner_fork";
  source: string;
  destination: string;
  target: string;
  cwd: string;
  transaction: string | null;
  recovery: string;
  fork?: string;
}

export interface ClaudeSessionResumeRun {
  result: ClaudeSessionResumeResult;
  exitCode: number;
}

function errorCode(error: unknown): string {
  return error && typeof error === "object" && "code" in error
    ? String((error as NodeJS.ErrnoException).code)
    : "";
}

function crashAtTestPoint(point: string): void {
  if (
    process.env.NODE_ENV === "test" &&
    process.env.ACCOUNTS_TEST_SESSION_RESUME_CRASH_AT === point
  ) {
    process.kill(process.pid, "SIGKILL");
  }
}

function safeLstat(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function assertLinuxTrustDomain(): void {
  const forcedUnsupported =
    process.env.NODE_ENV === "test" &&
    process.env.ACCOUNTS_TEST_FORCE_UNSUPPORTED_CONTINUATION_PLATFORM === "1";
  if (process.platform !== "linux" || forcedUnsupported) {
    throw new AccountsError(
      "sessions resume is supported only on Linux with a local uid trust domain",
    );
  }
  if (typeof process.getuid !== "function") {
    throw new AccountsError(
      "sessions resume requires a Linux runtime with current-uid ownership checks",
    );
  }
}

function currentUid(): number {
  assertLinuxTrustDomain();
  return process.getuid!();
}

function fingerprint(stat: Stats): SourceFingerprint {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    uid: stat.uid,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
  };
}

function sameFingerprint(a: SourceFingerprint, b: SourceFingerprint): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.mode === b.mode &&
    a.nlink === b.nlink &&
    a.uid === b.uid &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.ctimeMs === b.ctimeMs
  );
}

function stableFileIdentity(stat: Stats | SourceFingerprint): StableFileIdentity {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    uid: stat.uid,
  };
}

function sameStableFileIdentity(
  a: StableFileIdentity,
  b: Stats | SourceFingerprint,
): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.mode === b.mode &&
    a.nlink === b.nlink &&
    a.uid === b.uid
  );
}

function assertOwned(stat: Stats, label: string): void {
  if (stat.uid !== currentUid()) {
    throw new AccountsError(`${label} is outside the current local uid trust domain`);
  }
}

function fsyncDirectory(path: string): void {
  const directoryFd = openSync(
    path,
    constants.O_RDONLY |
      (typeof constants.O_DIRECTORY === "number" ? constants.O_DIRECTORY : 0),
  );
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
}

function fsyncRegularFile(path: string): void {
  const fd = openSync(
    path,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function assertPrivateRegularFile(path: string, label: string): Stats {
  const stat = safeLstat(path);
  if (!stat?.isFile() || stat.isSymbolicLink()) {
    throw new AccountsError(`${label} must be one regular file`);
  }
  if (stat.nlink !== 1) {
    throw new AccountsError(`${label} has a hardlink anomaly`);
  }
  assertOwned(stat, label);
  return stat;
}

function assertPrivateMode(stat: Stats, label: string): void {
  if ((stat.mode & 0o077) !== 0) {
    throw new AccountsError(`${label} permissions are not private`);
  }
}

function assertRealOwnedDirectory(path: string, label: string): string {
  const stat = safeLstat(path);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) {
    throw new AccountsError(`${label} must be one real local directory`);
  }
  assertOwned(stat, label);
  try {
    return realpathSync.native(path);
  } catch {
    throw new AccountsError(`${label} could not be canonicalized`);
  }
}

function assertPrivateDirectory(path: string, label: string): string {
  const canonical = assertRealOwnedDirectory(path, label);
  const stat = lstatSync(path);
  assertPrivateMode(stat, label);
  return canonical;
}

function verifiedProfileDir(profile: Profile): string {
  if (profile.tool !== "claude") {
    throw new AccountsError(`target account "${profile.name}" is not a Claude profile`);
  }
  const actual = resolve(profile.dir);
  const managedRoot = resolve(profilesDir(), "claude");
  const defaultDir = resolve(getTool("claude").defaultDir);
  const managedRelative = relative(managedRoot, actual);
  const isManagedDirectChild =
    managedRelative !== "" &&
    managedRelative !== ".." &&
    !managedRelative.startsWith(`..${sep}`) &&
    !isAbsolute(managedRelative) &&
    dirname(managedRelative) === ".";
  if (!isManagedDirectChild && actual !== defaultDir) {
    throw new AccountsError(
      `profile "${profile.name}" is stale or outside the local Accounts registry trust domain`,
    );
  }
  const canonical = assertRealOwnedDirectory(
    actual,
    `profile "${profile.name}" config directory`,
  );
  if (isManagedDirectChild) {
    const canonicalRoot = assertRealOwnedDirectory(
      managedRoot,
      "Accounts-managed Claude profiles directory",
    );
    if (canonical !== join(canonicalRoot, managedRelative)) {
      throw new AccountsError(
        `profile "${profile.name}" is stale or outside the local Accounts registry trust domain`,
      );
    }
  } else if (canonical !== assertRealOwnedDirectory(defaultDir, "default Claude profile")) {
    throw new AccountsError(
      `profile "${profile.name}" is stale or outside the local Accounts registry trust domain`,
    );
  }
  return canonical;
}

function canonicalLaunchCwd(value: string | undefined, entry: ClaudeSessionCatalogEntry): string {
  const chosen = value ?? entry.cwd;
  if (!chosen) {
    throw new AccountsError(
      "session cwd is unavailable; pass an explicit absolute --cwd instead of using the caller cwd",
    );
  }
  if (!isAbsolute(chosen) || chosen.includes("\0") || /[\r\n]/.test(chosen)) {
    throw new AccountsError("--cwd must be an absolute local directory");
  }
  return assertRealOwnedDirectory(resolve(chosen), "launch cwd");
}

function claudeProjectKey(cwd: string): string {
  const key = cwd.replace(/[^A-Za-z0-9]/g, "-");
  if (key.length > 200) {
    throw new AccountsError(
      "cross-account continuation does not support Claude hashed project keys",
    );
  }
  return key;
}

function claudeSessionEnv(profile: Profile): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
  };
  const dynamicHostAuthKey = env.CLAUDE_CODE_HOST_AUTH_ENV_VAR;
  for (const key of CLAUDE_API_AUTH_ENV_KEYS) delete env[key];
  // The wider provider surface is broker-only: `accounts env` and `accounts use`
  // must not touch a caller's AWS, Azure, or Google SDK configuration, but the
  // continuation child inherits nothing that could redirect or re-credential it.
  for (const key of CLAUDE_CONTINUATION_SCRUB_ENV_KEYS) delete env[key];
  // Generic proxy and TLS-trust variables are provider routing without a vendor
  // prefix: keeping them would let the caller MITM the profile bearer token.
  for (const key of CLAUDE_NETWORK_ROUTING_ENV_KEYS) delete env[key];
  for (const key of [
    "BUN_OPTIONS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
  ]) {
    delete env[key];
  }
  if (
    dynamicHostAuthKey &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(dynamicHostAuthKey)
  ) {
    delete env[dynamicHostAuthKey];
  }
  for (const key of Object.keys(env)) {
    if (
      key.startsWith("AWS_BEARER_TOKEN_") ||
      key.startsWith("AWS_ENDPOINT_URL_")
    ) {
      delete env[key];
    }
  }
  // Deleting this flag would re-enable ambient instance-metadata credentials.
  // The broker forces IMDS off after removing every caller-supplied value.
  env.AWS_EC2_METADATA_DISABLED = "true";
  env.CLAUDE_CONFIG_DIR = profile.dir;
  env.CLAUDE_SECURESTORAGE_CONFIG_DIR = profile.dir;
  env.TELEGRAM_STATE_DIR = join(profile.dir, "channels", "telegram");
  return env;
}

function inspectProviderAuthSettings(profileDir: string, cwd: string): string {
  const candidates = [
    join(profileDir, "settings.json"),
    join(profileDir, "settings.local.json"),
    join(cwd, ".claude", "settings.json"),
    join(cwd, ".claude", "settings.local.json"),
    "/etc/claude-code/managed-settings.json",
  ];
  const forbidden = new Set([
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "proxyAuthHelper",
  ]);
  const forbiddenEnv = new Set<string>([
    ...CLAUDE_API_AUTH_ENV_KEYS,
    ...CLAUDE_CONTINUATION_SCRUB_ENV_KEYS,
    ...CLAUDE_NETWORK_ROUTING_ENV_KEYS,
    "BUN_OPTIONS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
  ]);
  const manifest: Array<{
    path: string;
    fingerprint?: SourceFingerprint;
    digest?: string;
  }> = [];
  for (const path of new Set(candidates)) {
    if (!existsSync(path)) {
      manifest.push({ path });
      continue;
    }
    const fd = openSync(
      path,
      constants.O_RDONLY |
        (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
    );
    let bytes: Buffer;
    let opened: SourceFingerprint;
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.nlink !== 1 ||
        (stat.uid !== currentUid() && stat.uid !== 0) ||
        stat.size > 1024 * 1024
      ) {
        throw new AccountsError(
          "effective Claude settings cannot be classified safely for provider auth hooks",
        );
      }
      opened = fingerprint(stat);
      bytes = readFileSync(fd);
      if (!sameFingerprint(opened, fingerprint(fstatSync(fd)))) {
        throw new AccountsError(
          "effective Claude settings changed during provider auth inspection",
        );
      }
    } finally {
      closeSync(fd);
    }
    const pathname = safeLstat(path);
    if (
      !pathname?.isFile() ||
      pathname.isSymbolicLink() ||
      !sameFingerprint(opened!, fingerprint(pathname))
    ) {
      throw new AccountsError(
        "effective Claude settings path changed during provider auth inspection",
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes!.toString("utf8"));
    } catch {
      throw new AccountsError(
        "effective Claude settings are not valid JSON",
      );
    }
    const pending: unknown[] = [parsed];
    let seen = 0;
    while (pending.length > 0) {
      const value = pending.pop();
      seen += 1;
      if (seen > 50_000) {
        throw new AccountsError(
          "effective Claude settings exceed the auth-hook inspection bound",
        );
      }
      if (!value || typeof value !== "object") continue;
      if (Array.isArray(value)) {
        pending.push(...value);
        continue;
      }
      for (const [key, child] of Object.entries(
        value as Record<string, unknown>,
      )) {
        if (forbidden.has(key)) {
          throw new AccountsError(
            `effective Claude settings contain provider auth hook "${key}"`,
          );
        }
        if (key === "env") {
          const settingsEnv = plainRecord(
            child,
            "effective Claude settings env",
          );
          const dynamic = settingsEnv.CLAUDE_CODE_HOST_AUTH_ENV_VAR;
          for (const envKey of Object.keys(settingsEnv)) {
            if (
              forbiddenEnv.has(envKey) ||
              envKey.startsWith("AWS_BEARER_TOKEN_") ||
              envKey.startsWith("AWS_ENDPOINT_URL_") ||
              (typeof dynamic === "string" && envKey === dynamic)
            ) {
              throw new AccountsError(
                `effective Claude settings env contains provider override "${envKey}"`,
              );
            }
          }
        }
        pending.push(child);
      }
    }
    manifest.push({
      path,
      fingerprint: opened!,
      digest: createHash("sha256").update(bytes!).digest("hex"),
    });
  }
  return createHash("sha256")
    .update(JSON.stringify(manifest))
    .digest("hex");
}

function assertProviderAuthSettingsUnchanged(
  expected: string,
  profileDir: string,
  cwd: string,
): void {
  if (inspectProviderAuthSettings(profileDir, cwd) !== expected) {
    throw new AccountsError(
      "effective Claude settings changed after provider auth validation",
    );
  }
}

function probeClaudeVersion(
  pinned: PinnedClaudeTool,
  profile: Profile,
  cwd: string,
): void {
  const result = spawnSync(pinned.tool.bin, ["--version"], {
    cwd,
    env: claudeSessionEnv(profile),
    encoding: "utf8",
    timeout: 10_000,
    stdio: ["ignore", "pipe", "pipe", pinned.executableFd],
  });
  if (result.error || result.status !== 0) {
    throw new AccountsError(
      `could not verify the versioned Claude continuation adapter for ${CLAUDE_CONTINUATION_ADAPTER.cliVersion}`,
    );
  }
  const combined = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  const match = combined.match(/(?:^|\s)(\d+\.\d+\.\d+)(?:\s|$)/);
  if (match?.[1] !== CLAUDE_CONTINUATION_ADAPTER.cliVersion) {
    throw new AccountsError(
      `cross-account continuation is supported only by the Claude ${CLAUDE_CONTINUATION_ADAPTER.cliVersion} adapter`,
    );
  }
}

function digestStableExecutableFd(fd: number): {
  digest: string;
  fingerprint: SourceFingerprint;
} {
  const beforeStat = fstatSync(fd);
  if (!beforeStat.isFile()) {
    throw new AccountsError("versioned Claude executable is not one stable regular file");
  }
  const before = fingerprint(beforeStat);
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(256 * 1024);
  let position = 0;
  while (true) {
    const bytesRead = readSync(fd, buffer, 0, buffer.length, position);
    if (bytesRead === 0) break;
    hash.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  const after = fingerprint(fstatSync(fd));
  if (!sameFingerprint(before, after)) {
    throw new AccountsError("versioned Claude executable changed during verification");
  }
  return { digest: hash.digest("hex"), fingerprint: after };
}

function pinClaudeTool(
  tool: ToolDef,
  profile: Profile,
  cwd: string,
  requireAdapterVersion = true,
  beforeVersionProbe?: () => void,
): PinnedClaudeTool {
  assertLinuxTrustDomain();
  const located = resolveExecutable(tool.bin, claudeSessionEnv(profile));
  let canonical: string;
  try {
    canonical = realpathSync.native(located);
  } catch {
    throw new AccountsError("could not canonicalize the versioned Claude executable");
  }
  const stat = safeLstat(canonical);
  if (!stat?.isFile() || stat.isSymbolicLink()) {
    throw new AccountsError("versioned Claude executable is not one stable regular file");
  }
  const sourceFd = openSync(
    canonical,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  const pinDirectory = mkdtempSync(join(tmpdir(), "accounts-claude-pin-"));
  chmodSync(pinDirectory, 0o700);
  const pinPath = join(pinDirectory, "claude");
  let destinationFd: number | undefined;
  let executableFd: number | undefined;
  try {
    const sourceBefore = fingerprint(fstatSync(sourceFd));
    destinationFd = openSync(pinPath, "wx", 0o700);
    const buffer = Buffer.allocUnsafe(256 * 1024);
    let sourcePosition = 0;
    while (true) {
      const bytesRead = readSync(
        sourceFd,
        buffer,
        0,
        buffer.length,
        sourcePosition,
      );
      if (bytesRead === 0) break;
      sourcePosition += bytesRead;
      let written = 0;
      while (written < bytesRead) {
        written += writeSync(
          destinationFd,
          buffer,
          written,
          bytesRead - written,
          null,
        );
      }
    }
    if (!sameFingerprint(sourceBefore, fingerprint(fstatSync(sourceFd)))) {
      throw new AccountsError("versioned Claude executable changed while it was pinned");
    }
    fsyncSync(destinationFd);
    chmodSync(pinPath, 0o500);
    fsyncSync(destinationFd);
    closeSync(destinationFd);
    destinationFd = undefined;
    fsyncDirectory(pinDirectory);

    executableFd = openSync(
      pinPath,
      constants.O_RDONLY |
        (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
    );
    const identity = digestStableExecutableFd(executableFd);
    fsyncDirectory(pinDirectory);

    const pinned: PinnedClaudeTool = {
      // The executable target is the inherited descriptor, not this private
      // copy's pathname. Keeping the path linked allows shebang interpreters to
      // reopen /proc/self/fd/3 while descriptor identity pins the actual bytes.
      tool: { ...tool, bin: "/proc/self/fd/3" },
      fingerprint: identity.fingerprint,
      digest: identity.digest,
      executableFd,
      pinDirectory,
      pinPath,
    };
    if (requireAdapterVersion) {
      beforeVersionProbe?.();
      probeClaudeVersion(pinned, profile, cwd);
    }
    assertPinnedClaudeTool(pinned);
    return pinned;
  } catch (error) {
    if (executableFd !== undefined) closeSync(executableFd);
    try {
      chmodSync(pinDirectory, 0o700);
      rmSync(pinDirectory, { recursive: true, force: true });
    } catch {
      // The primary pinning error is more useful than temp cleanup failure.
    }
    throw error;
  } finally {
    closeSync(sourceFd);
    if (destinationFd !== undefined) closeSync(destinationFd);
  }
}

function assertPinnedClaudeTool(pinned: PinnedClaudeTool): void {
  const identity = digestStableExecutableFd(pinned.executableFd);
  const pathStat = safeLstat(pinned.pinPath);
  if (
    !pathStat?.isFile() ||
    pathStat.isSymbolicLink() ||
    !sameFingerprint(pinned.fingerprint, fingerprint(pathStat)) ||
    !sameFingerprint(pinned.fingerprint, identity.fingerprint) ||
    pinned.digest !== identity.digest
  ) {
    throw new AccountsError("versioned Claude executable changed before launch");
  }
}

function closePinnedClaudeTool(pinned: PinnedClaudeTool): void {
  try {
    closeSync(pinned.executableFd);
  } finally {
    chmodSync(pinned.pinDirectory, 0o700);
    unlinkSync(pinned.pinPath);
    fsyncDirectory(pinned.pinDirectory);
    rmdirSync(pinned.pinDirectory);
    fsyncDirectory(dirname(pinned.pinDirectory));
  }
}

function assertNoWritableHandle(path: string): void {
  const result = spawnSync("/usr/bin/lsof", ["-w", "-Fnpa", "--", path], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000,
  });
  if (result.error) {
    throw new AccountsError("could not prove the source session is quiescent");
  }
  if (result.status === 1 && !(result.stdout ?? "").trim()) return;
  if (result.status !== 0) {
    throw new AccountsError("could not prove the source session is quiescent");
  }
  const access = String(result.stdout ?? "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("a"))
    .map((line) => line.slice(1));
  if (access.some((value) => value === "w" || value === "u")) {
    throw new AccountsError("source session has an active writer");
  }
}

function canonicalTranscriptCwd(value: unknown): string | undefined {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    value.includes("\0") ||
    /[\r\n]/.test(value)
  ) {
    return undefined;
  }
  const resolved = resolve(value);
  try {
    return realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

const COMMON_TRANSCRIPT_KEYS = new Set([
  "cwd",
  "gitBranch",
  "isMeta",
  "isSidechain",
  "message",
  "parentUuid",
  "sessionId",
  "timestamp",
  "type",
  "userType",
  "uuid",
  "version",
]);
const USER_TRANSCRIPT_KEYS = COMMON_TRANSCRIPT_KEYS;
const ASSISTANT_TRANSCRIPT_KEYS = new Set([
  ...COMMON_TRANSCRIPT_KEYS,
  "requestId",
]);
const USER_MESSAGE_KEYS = new Set(["content", "role"]);
const ASSISTANT_MESSAGE_KEYS = new Set([
  "content",
  "id",
  "model",
  "role",
  "stop_reason",
  "stop_sequence",
  "type",
  "usage",
]);
const TEXT_BLOCK_KEYS = new Set(["text", "type"]);
const THINKING_BLOCK_KEYS = new Set(["signature", "thinking", "type"]);
const REDACTED_THINKING_BLOCK_KEYS = new Set(["data", "type"]);
const USAGE_KEYS = new Set([
  "cache_creation",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
  "input_tokens",
  "output_tokens",
  "service_tier",
]);
const CACHE_CREATION_KEYS = new Set([
  "ephemeral_1h_input_tokens",
  "ephemeral_5m_input_tokens",
]);
const DEPENDENCY_TRANSCRIPT_KEYS = new Set([
  "agentId",
  "agentSessionId",
  "attachments",
  "fileHistorySnapshot",
  "scheduleId",
  "sidechainId",
  "snapshot",
  "subagent",
  "subagents",
  "taskId",
  "tasks",
  "toolUseResult",
  "tools",
]);

function plainRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError(`${label} must be one plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AccountsError(`${label} must be one plain object`);
  }
  return value as Record<string, unknown>;
}

function assertAllowedKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    const first = unknown.sort()[0]!;
    if (DEPENDENCY_TRANSCRIPT_KEYS.has(first)) {
      throw new AccountsError(
        `${label} contains dependency-bearing field "${first}" outside the supported simple subset`,
      );
    }
    throw new AccountsError(
      `${label} contains unsupported field "${first}"`,
    );
  }
}

function assertOptionalString(
  value: unknown,
  label: string,
  nullable = false,
): void {
  if (value === undefined || (nullable && value === null)) return;
  if (typeof value !== "string") {
    throw new AccountsError(`${label} must be a string`);
  }
}

function assertUsage(value: unknown): void {
  if (value === undefined) return;
  const usage = plainRecord(value, "assistant message usage");
  assertAllowedKeys(usage, USAGE_KEYS, "assistant message usage");
  for (const [key, item] of Object.entries(usage)) {
    if (key === "service_tier") {
      assertOptionalString(item, "assistant message usage service_tier", true);
      continue;
    }
    if (key === "cache_creation") {
      const cache = plainRecord(item, "assistant message cache_creation");
      assertAllowedKeys(
        cache,
        CACHE_CREATION_KEYS,
        "assistant message cache_creation",
      );
      if (
        Object.values(cache).some(
          (count) => typeof count !== "number" || !Number.isSafeInteger(count) || count < 0,
        )
      ) {
        throw new AccountsError(
          "assistant message cache_creation contains an invalid token count",
        );
      }
      continue;
    }
    if (typeof item !== "number" || !Number.isSafeInteger(item) || item < 0) {
      throw new AccountsError(
        `assistant message usage ${key} contains an invalid token count`,
      );
    }
  }
}

function assertMessageContent(
  value: unknown,
  recordType: "user" | "assistant",
): void {
  if (typeof value === "string") return;
  if (!Array.isArray(value)) {
    throw new AccountsError(
      `${recordType} message content is outside the supported simple transcript subset`,
    );
  }
  for (const rawBlock of value) {
    const block = plainRecord(rawBlock, `${recordType} message content block`);
    const blockType = block.type;
    if (blockType === "text") {
      assertAllowedKeys(block, TEXT_BLOCK_KEYS, `${recordType} text block`);
      if (typeof block.text !== "string") {
        throw new AccountsError(`${recordType} text block must contain text`);
      }
      continue;
    }
    if (recordType === "assistant" && blockType === "thinking") {
      assertAllowedKeys(
        block,
        THINKING_BLOCK_KEYS,
        "assistant thinking block",
      );
      if (
        typeof block.thinking !== "string" ||
        typeof block.signature !== "string"
      ) {
        throw new AccountsError(
          "assistant thinking block is outside the supported simple transcript subset",
        );
      }
      continue;
    }
    if (recordType === "assistant" && blockType === "redacted_thinking") {
      assertAllowedKeys(
        block,
        REDACTED_THINKING_BLOCK_KEYS,
        "assistant redacted thinking block",
      );
      if (typeof block.data !== "string") {
        throw new AccountsError(
          "assistant redacted thinking block is outside the supported simple transcript subset",
        );
      }
      continue;
    }
    throw new AccountsError(
      `${recordType} message contains a tool, attachment, or unsupported content block`,
    );
  }
}

interface InspectedTranscriptRecord {
  cwd: string;
  normalized: string;
  parentIdentity?: string;
  recordIdentity: string;
  sessionId: string;
}

function inspectTranscriptRecord(
  raw: unknown,
  allowedSessionIds: ReadonlySet<string>,
): InspectedTranscriptRecord {
  const top = plainRecord(raw, "session root JSONL record");
  const recordType = top.type;
  if (recordType !== "user" && recordType !== "assistant") {
    throw new AccountsError(
      "session root JSONL is outside the supported simple user/assistant transcript subset",
    );
  }
  assertAllowedKeys(
    top,
    recordType === "user" ? USER_TRANSCRIPT_KEYS : ASSISTANT_TRANSCRIPT_KEYS,
    `${recordType} transcript record`,
  );
  if (top.isSidechain !== false) {
    throw new AccountsError(
      "session root JSONL requires isSidechain=false for every simple turn",
    );
  }
  if (top.isMeta !== undefined && top.isMeta !== false) {
    throw new AccountsError(
      "session root JSONL contains unsupported meta records",
    );
  }
  assertOptionalString(top.gitBranch, `${recordType} transcript gitBranch`, true);
  assertOptionalString(top.timestamp, `${recordType} transcript timestamp`);
  assertOptionalString(top.userType, `${recordType} transcript userType`);
  assertOptionalString(top.version, `${recordType} transcript version`);
  if (recordType === "assistant") {
    assertOptionalString(top.requestId, "assistant transcript requestId");
  }
  if (
    typeof top.sessionId !== "string" ||
    !UUID_RE.test(top.sessionId) ||
    !allowedSessionIds.has(top.sessionId.toLowerCase())
  ) {
    throw new AccountsError("session root JSONL has an ambiguous session identity");
  }
  const sessionId = top.sessionId.toLowerCase();
  const cwd = canonicalTranscriptCwd(top.cwd);
  if (!cwd) throw new AccountsError("session root JSONL has an ambiguous cwd/project");

  let parentIdentity: string | undefined;
  if (top.parentUuid !== undefined && top.parentUuid !== null) {
    if (typeof top.parentUuid !== "string" || !UUID_RE.test(top.parentUuid)) {
      throw new AccountsError(
        "session root JSONL has an invalid parent record identity",
      );
    }
    parentIdentity = top.parentUuid.toLowerCase();
  }
  if (typeof top.uuid !== "string" || !UUID_RE.test(top.uuid)) {
    throw new AccountsError(
      "session root JSONL requires one UUID for every persisted turn",
    );
  }
  const recordIdentity = top.uuid.toLowerCase();

  const message = plainRecord(top.message, `${recordType} message`);
  assertAllowedKeys(
    message,
    recordType === "user" ? USER_MESSAGE_KEYS : ASSISTANT_MESSAGE_KEYS,
    `${recordType} message`,
  );
  if (message.role !== recordType) {
    throw new AccountsError(
      `${recordType} message role is outside the supported simple transcript subset`,
    );
  }
  assertMessageContent(message.content, recordType);
  if (recordType === "assistant") {
    assertOptionalString(message.id, "assistant message id");
    assertOptionalString(message.model, "assistant message model");
    if (
      message.stop_reason !== undefined &&
      message.stop_reason !== null &&
      message.stop_reason !== "end_turn" &&
      message.stop_reason !== "max_tokens" &&
      message.stop_reason !== "stop_sequence" &&
      message.stop_reason !== "refusal"
    ) {
      throw new AccountsError(
        "assistant message stop_reason is outside the benign simple-turn enum",
      );
    }
    assertOptionalString(message.stop_sequence, "assistant message stop_sequence", true);
    if (message.type !== undefined && message.type !== "message") {
      throw new AccountsError(
        "assistant message type is outside the supported simple transcript subset",
      );
    }
    assertUsage(message.usage);
  }

  return {
    cwd,
    // Canonical source/fork comparison normalizes only Claude's expected
    // session-id rewrite. It preserves key order and every nested byte-level
    // semantic choice instead of applying a generic JSON transform.
    normalized: JSON.stringify({
      ...top,
      sessionId: "00000000-0000-4000-8000-000000000000",
    }),
    ...(parentIdentity ? { parentIdentity } : {}),
    recordIdentity,
    sessionId,
  };
}

async function inspectCompleteJsonl(
  path: string,
  allowedSessionIds: ReadonlySet<string>,
  allowMultipleCwds = false,
  expectedPrefix?: { digest: string; byteLength: number; lineCount: number },
  retainedPrefix?: { digest: string; byteLength: number; lineCount: number },
): Promise<JsonlInspection> {
  const beforeStat = assertPrivateRegularFile(path, "session root JSONL");
  if (beforeStat.size <= 0) {
    throw new AccountsError("session root JSONL is not complete");
  }
  const fd = openSync(
    path,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  const cwds = new Set<string>();
  const sessionIds = new Set<string>();
  const suffixCwds = new Set<string>();
  const suffixSessionIds = new Set<string>();
  const normalizedHash = createHash("sha256");
  const rawHash = createHash("sha256");
  const prefixHash = expectedPrefix ? createHash("sha256") : undefined;
  const retainedPrefixHash = retainedPrefix ? createHash("sha256") : undefined;
  const recordIdentities = new Set<string>();
  let lineCount = 0;
  let suffixLineCount = 0;
  let firstSuffixParentIdentity: string | undefined;
  let lastRecordIdentity = "";
  let parsedByteLength = 0;
  let prefixBoundaryByteLength: number | undefined;
  let retainedPrefixBoundaryByteLength: number | undefined;
  const inspectLine = (bytes: Buffer): void => {
    if (bytes.length === 0 || bytes.length > MAX_JSONL_LINE_BYTES) {
      throw new AccountsError("session root JSONL is not a complete simple transcript");
    }
    let record: unknown;
    try {
      record = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new AccountsError("session root JSONL is not complete and parseable");
    }
    if (bytes.toString("utf8") !== JSON.stringify(record)) {
      throw new AccountsError(
        "session root JSONL must use canonical JSON lines without duplicate keys or alternate encoding",
      );
    }
    const inspected = inspectTranscriptRecord(record, allowedSessionIds);
    if (recordIdentities.has(inspected.recordIdentity)) {
      throw new AccountsError(
        "session root JSONL contains a duplicate persisted turn UUID",
      );
    }
    if (
      (lineCount === 0 && inspected.parentIdentity !== undefined) ||
      (lineCount > 0 && inspected.parentIdentity !== lastRecordIdentity)
    ) {
      throw new AccountsError(
        "session root JSONL is not one linear persisted-turn ancestry",
      );
    }
    recordIdentities.add(inspected.recordIdentity);
    const normalized = `${inspected.normalized}\n`;
    normalizedHash.update(normalized);
    if (expectedPrefix && lineCount < expectedPrefix.lineCount) {
      prefixHash!.update(normalized);
    }
    if (retainedPrefix && lineCount < retainedPrefix.lineCount) {
      retainedPrefixHash!.update(normalized);
    }
    if (expectedPrefix && lineCount >= expectedPrefix.lineCount) {
      suffixLineCount += 1;
      suffixCwds.add(inspected.cwd);
      suffixSessionIds.add(inspected.sessionId);
      if (suffixLineCount === 1) {
        firstSuffixParentIdentity = inspected.parentIdentity ?? "";
      }
    }
    cwds.add(inspected.cwd);
    sessionIds.add(inspected.sessionId);
    lastRecordIdentity = inspected.recordIdentity;
    lineCount += 1;
    parsedByteLength += bytes.length + 1;
    if (expectedPrefix && lineCount === expectedPrefix.lineCount) {
      prefixBoundaryByteLength = parsedByteLength;
    }
    if (retainedPrefix && lineCount === retainedPrefix.lineCount) {
      retainedPrefixBoundaryByteLength = parsedByteLength;
    }
  };

  try {
    const last = Buffer.allocUnsafe(1);
    if (readSync(fd, last, 0, 1, beforeStat.size - 1) !== 1 || last[0] !== 0x0a) {
      throw new AccountsError("session root JSONL is not complete");
    }
    const chunk = Buffer.allocUnsafe(64 * 1024);
    const line = Buffer.allocUnsafe(
      Math.min(MAX_JSONL_LINE_BYTES, Math.max(1, beforeStat.size)),
    );
    let filePosition = 0;
    let lineLength = 0;
    while (true) {
      const bytesRead = readSync(
        fd,
        chunk,
        0,
        chunk.length,
        filePosition,
      );
      if (bytesRead === 0) break;
      const raw = chunk.subarray(0, bytesRead);
      rawHash.update(raw);
      filePosition += bytesRead;
      let offset = 0;
      while (offset < bytesRead) {
        const newline = chunk.indexOf(0x0a, offset);
        const boundedNewline =
          newline >= 0 && newline < bytesRead ? newline : -1;
        const segmentEnd = boundedNewline === -1 ? bytesRead : boundedNewline;
        const segmentLength = segmentEnd - offset;
        if (lineLength + segmentLength > MAX_JSONL_LINE_BYTES) {
          throw new AccountsError(
            "session root JSONL line exceeds the supported safety bound",
          );
        }
        chunk.copy(line, lineLength, offset, segmentEnd);
        lineLength += segmentLength;
        if (boundedNewline === -1) break;
        inspectLine(line.subarray(0, lineLength));
        lineLength = 0;
        offset = boundedNewline + 1;
      }
    }
    if (lineLength !== 0) {
      throw new AccountsError("session root JSONL is not complete");
    }
    const after = fingerprint(fstatSync(fd));
    const before = fingerprint(beforeStat);
    if (!sameFingerprint(before, after)) {
      throw new AccountsError("session root JSONL changed during validation");
    }
  } finally {
    closeSync(fd);
  }

  if (lineCount === 0 || cwds.size === 0 || (!allowMultipleCwds && cwds.size !== 1)) {
    throw new AccountsError("session root JSONL has an ambiguous cwd/project");
  }
  if (sessionIds.size === 0 || !lastRecordIdentity) {
    throw new AccountsError("session root JSONL has an ambiguous session identity");
  }
  if (
    expectedPrefix &&
    (beforeStat.size < expectedPrefix.byteLength ||
      lineCount < expectedPrefix.lineCount ||
      prefixBoundaryByteLength !== expectedPrefix.byteLength)
  ) {
    throw new AccountsError(
      "session root JSONL does not contain the exact source byte prefix",
    );
  }
  if (
    retainedPrefix &&
    (beforeStat.size < retainedPrefix.byteLength ||
      lineCount < retainedPrefix.lineCount ||
      retainedPrefixBoundaryByteLength !== retainedPrefix.byteLength)
  ) {
    throw new AccountsError(
      "session root JSONL does not contain the retained validated byte prefix",
    );
  }
  return {
    cwd: [...cwds][0]!,
    cwds,
    lineCount,
    sessionIds,
    fingerprint: fingerprint(beforeStat),
    rawDigest: rawHash.digest("hex"),
    byteLength: beforeStat.size,
    normalizedDigest: normalizedHash.digest("hex"),
    lastRecordIdentity,
    ...(prefixHash ? { prefixDigest: prefixHash.digest("hex") } : {}),
    ...(retainedPrefixHash
      ? { retainedPrefixDigest: retainedPrefixHash.digest("hex") }
      : {}),
    ...(prefixBoundaryByteLength !== undefined
      ? { prefixBoundaryByteLength }
      : {}),
    ...(retainedPrefixBoundaryByteLength !== undefined
      ? { retainedPrefixBoundaryByteLength }
      : {}),
    suffixLineCount,
    suffixSessionIds,
    suffixCwds,
    ...(firstSuffixParentIdentity ? { firstSuffixParentIdentity } : {}),
  };
}

function relatedToUuid(name: string, uuid: string): boolean {
  return name.toLowerCase().includes(uuid.toLowerCase());
}

function assertNoSessionSidecars(
  profileDir: string,
  sourcePath: string | undefined,
  uuid: string,
  context: "source" | "target",
): void {
  let seen = 0;
  const pending = [profileDir];
  while (pending.length > 0) {
    const directory = pending.pop()!;
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      throw new AccountsError("could not classify the Claude session dependency closure");
    }
    for (const entry of entries) {
      seen += 1;
      if (seen > MAX_SIDECAR_SCAN_ENTRIES) {
        throw new AccountsError("Claude session sidecar classification exceeded its safety bound");
      }
      const path = join(directory, entry.name);
      if (sourcePath && resolve(path) === resolve(sourcePath)) continue;
      if (entry.isSymbolicLink()) {
        throw new AccountsError(
          "Claude session dependency closure contains a symbolic link",
        );
      }
      if (!entry.isDirectory() && !entry.isFile()) {
        throw new AccountsError(
          "Claude session dependency closure contains a special filesystem entry",
        );
      }
      if (relatedToUuid(entry.name, uuid)) {
        throw new AccountsError(
          context === "target"
            ? "target session collision or unclassified UUID sidecar"
            : "Claude session has a companion or unclassified UUID sidecar",
        );
      }
      if (entry.isDirectory()) pending.push(path);
    }
  }
}

function ensurePrivateDirectory(path: string): void {
  const existed = existsSync(path);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = safeLstat(path);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) {
    throw new AccountsError(`unsafe private directory at ${path}`);
  }
  assertOwned(stat, "private transaction directory");
  chmodSync(path, 0o700);
  fsyncDirectory(path);
  if (!existed) fsyncDirectory(dirname(path));
}

function writePrivateJson(path: string, value: unknown): void {
  ensurePrivateDirectory(resolve(path, ".."));
  const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temp, "wx", 0o600);
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    chmodSync(path, 0o600);
    fsyncRegularFile(path);
    fsyncDirectory(dirname(path));
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

function isSourceFingerprint(value: unknown): value is SourceFingerprint {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    ["dev", "ino", "mode", "nlink", "uid", "size"].every(
      (key) => Number.isSafeInteger(record[key]) && Number(record[key]) >= 0,
    ) &&
    ["mtimeMs", "ctimeMs"].every(
      (key) => typeof record[key] === "number" && Number.isFinite(record[key]),
    )
  );
}

function isStableFileIdentity(value: unknown): value is StableFileIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return ["dev", "ino", "mode", "nlink", "uid"].every(
    (key) => Number.isSafeInteger(record[key]) && Number(record[key]) >= 0,
  );
}

function readPrivateJournal(path: string): TransactionJournal {
  const stat = assertPrivateRegularFile(path, "transaction journal");
  assertPrivateMode(stat, "transaction journal");
  const directory = dirname(path);
  assertPrivateDirectory(directory, "transaction directory");
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as TransactionJournal;
    if (
      parsed.schemaVersion !== 2 ||
      parsed.id !== basename(directory) ||
      parsed.adapter?.schemaVersion !== CLAUDE_CONTINUATION_ADAPTER.schemaVersion ||
      parsed.adapter?.id !== CLAUDE_CONTINUATION_ADAPTER.id ||
      parsed.adapter?.cliVersion !== CLAUDE_CONTINUATION_ADAPTER.cliVersion ||
      !TRANSACTION_STATES.has(parsed.state) ||
      !parsed.source?.catalogRef ||
      !isAbsolute(parsed.source?.path ?? "") ||
      !isSourceFingerprint(parsed.source?.fingerprint) ||
      !/^[0-9a-f]{64}$/i.test(parsed.source?.digest ?? "") ||
      !Number.isSafeInteger(parsed.source?.byteLength) ||
      parsed.source.byteLength <= 0 ||
      parsed.source.byteLength !== parsed.source.fingerprint.size ||
      !/^[0-9a-f]{64}$/i.test(parsed.source?.normalizedDigest ?? "") ||
      !Number.isSafeInteger(parsed.source?.lineCount) ||
      parsed.source.lineCount <= 0 ||
      !UUID_RE.test(parsed.source?.lastRecordIdentity ?? "") ||
      !isAbsolute(parsed.source?.cwd ?? "") ||
      !parsed.target?.account ||
      !isAbsolute(parsed.target?.configDir ?? "") ||
      !parsed.target?.cwd ||
      !isAbsolute(parsed.target?.cwd ?? "") ||
      !isAbsolute(parsed.target?.destination ?? "") ||
      resolve(parsed.artifacts?.journal ?? "") !== resolve(path) ||
      resolve(parsed.artifacts?.backup ?? "") !== resolve(directory, "source-backup.jsonl") ||
      resolve(parsed.artifacts?.candidate ?? "") !== resolve(directory, "target-candidate.jsonl")
    ) {
      throw new Error("invalid");
    }
    if (
      parsed.fork &&
      (!UUID_RE.test(parsed.fork.uuid) ||
        !isAbsolute(parsed.fork.path) ||
        !Number.isSafeInteger(parsed.fork.lineCount) ||
        parsed.fork.lineCount <= parsed.source.lineCount ||
        typeof parsed.fork.byteLength !== "number" ||
        !Number.isSafeInteger(parsed.fork.byteLength) ||
        parsed.fork.byteLength <= parsed.source.byteLength ||
        !/^[0-9a-f]{64}$/i.test(parsed.fork.digest ?? "") ||
        !isStableFileIdentity(parsed.fork.identity))
    ) {
      throw new Error("invalid");
    }
    if (
      parsed.launch &&
      (parsed.launch.status !== "started" && parsed.launch.status !== "completed")
    ) {
      throw new Error("invalid");
    }
    const preLaunch =
      parsed.state === "snapshotted" ||
      parsed.state === "fork_created" ||
      parsed.state === "promoted" ||
      parsed.state === "validated" ||
      parsed.state === "committed";
    if (preLaunch && (parsed.launch || parsed.fork)) {
      throw new Error("invalid");
    }
    if (
      parsed.state === "launched" &&
      (!parsed.launch ||
        (parsed.launch.status === "started" &&
          (parsed.launch.exitCode !== undefined || parsed.fork !== undefined)) ||
        (parsed.launch.status === "completed" &&
          (!Number.isSafeInteger(parsed.launch.exitCode) ||
            parsed.launch.exitCode !== 0 ||
            !parsed.fork)))
    ) {
      throw new Error("invalid");
    }
    if (
      parsed.state === "failed" &&
      (!parsed.launch ||
        parsed.launch.status !== "completed" ||
        !Number.isSafeInteger(parsed.launch.exitCode) ||
        parsed.launch.exitCode === 0 ||
        parsed.fork !== undefined)
    ) {
      throw new Error("invalid");
    }
    if (
      parsed.fork &&
      (parsed.state !== "launched" ||
        parsed.launch?.status !== "completed" ||
        parsed.launch.exitCode !== 0)
    ) {
      throw new Error("invalid");
    }
    return parsed;
  } catch {
    throw new AccountsError(
      "transaction journal is malformed or from an unsupported development contract; recovery requires manual inspection",
    );
  }
}

function transactionsRoot(): string {
  return join(accountsHome(), TRANSACTIONS_DIR);
}

function matchingJournals(
  entry: ClaudeSessionCatalogEntry,
  targetAccount: string,
  targetDir: string,
  cwd: string,
): TransactionJournal[] {
  const root = transactionsRoot();
  if (!existsSync(root)) return [];
  assertPrivateDirectory(root, "session resume transaction root");
  const matches: TransactionJournal[] = [];
  for (const directoryEntry of readdirSync(root, { withFileTypes: true })) {
    if (
      !directoryEntry.isDirectory() ||
      directoryEntry.isSymbolicLink() ||
      !UUID_RE.test(directoryEntry.name)
    ) {
      throw new AccountsError(
        "session resume transaction root contains an unclassified entry; recovery requires manual inspection",
      );
    }
    const journalPath = join(root, directoryEntry.name, JOURNAL_FILE);
    if (!existsSync(journalPath)) {
      throw new AccountsError(
        `session resume transaction is missing its journal; recovery: inspect ${join(root, directoryEntry.name)}`,
      );
    }
    let journal = readPrivateJournal(journalPath);
    const sameTargetIdentity =
      resolve(journal.target.configDir) === resolve(targetDir) ||
      journal.target.account === targetAccount;
    const sameRequestCoordinates =
      sameTargetIdentity &&
      journal.target.cwd === cwd &&
      resolve(journal.source.path) === resolve(entry.sourcePath);
    const recognizedReference = matchesClaudeSessionReference(
      entry,
      journal.source.catalogRef,
    );
    if (sameRequestCoordinates && !recognizedReference) {
      throw new AccountsError(
        `continuation journal uses an unsupported development catalogRef; recovery: inspect ${journal.artifacts.journal}`,
      );
    }
    if (
      recognizedReference &&
      sameTargetIdentity &&
      resolve(journal.source.path) === resolve(entry.sourcePath) &&
      journal.target.cwd === cwd
    ) {
      matches.push(journal);
    }
  }
  if (matches.length > 1) {
    throw new AccountsError(
      "multiple continuation transactions match this request; recovery is ambiguous",
    );
  }
  return matches;
}

function updateJournal(
  journal: TransactionJournal,
  changes: Partial<TransactionJournal>,
): TransactionJournal {
  const next: TransactionJournal = {
    ...journal,
    ...changes,
    updatedAt: new Date().toISOString(),
  };
  writePrivateJson(journal.artifacts.journal, next);
  return next;
}

function atomicCopyStagingPath(destination: string): string {
  return join(
    dirname(destination),
    `.accounts-copy-${createHash("sha256")
      .update(resolve(destination))
      .digest("hex")
      .slice(0, 32)}.tmp`,
  );
}

function recoverAtomicCopyStaging(destination: string): void {
  const staging = atomicCopyStagingPath(destination);
  if (!existsSync(staging)) return;
  const stagingStat = safeLstat(staging);
  if (
    !stagingStat?.isFile() ||
    stagingStat.isSymbolicLink() ||
    (stagingStat.nlink !== 1 && stagingStat.nlink !== 2)
  ) {
    throw new AccountsError("atomic copy staging identity is unsafe");
  }
  assertOwned(stagingStat, "atomic copy staging file");
  assertPrivateMode(stagingStat, "atomic copy staging file");
  const destinationStat = safeLstat(destination);
  if (
    destinationStat &&
    (destinationStat.dev !== stagingStat.dev ||
      destinationStat.ino !== stagingStat.ino)
  ) {
    throw new AccountsError("atomic copy staging conflicts with the final artifact");
  }
  unlinkSync(staging);
  fsyncDirectory(dirname(staging));
}

function copyRegularExclusive(
  source: string,
  destination: string,
  expected?: SourceFingerprint,
): { digest: string; fingerprint: SourceFingerprint } {
  const sourceFd = openSync(
    source,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  const staging = atomicCopyStagingPath(destination);
  let destinationFd: number | undefined;
  try {
    const opened = fingerprint(fstatSync(sourceFd));
    if (expected && !sameFingerprint(expected, opened)) {
      throw new AccountsError("source session changed before snapshot");
    }
    recoverAtomicCopyStaging(destination);
    destinationFd = openSync(staging, "wx", 0o600);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(128 * 1024);
    while (true) {
      const bytesRead = readSync(sourceFd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      let offset = 0;
      while (offset < bytesRead) {
        offset += writeSync(
          destinationFd,
          buffer,
          offset,
          bytesRead - offset,
          null,
        );
      }
    }
    fsyncSync(destinationFd);
    closeSync(destinationFd);
    destinationFd = undefined;
    chmodSync(staging, 0o600);
    fsyncRegularFile(staging);
    linkSync(staging, destination);
    fsyncDirectory(dirname(destination));
    unlinkSync(staging);
    fsyncDirectory(dirname(destination));
    const finalSource = fingerprint(fstatSync(sourceFd));
    if (!sameFingerprint(opened, finalSource)) {
      throw new AccountsError("source session changed during snapshot");
    }
    return { digest: hash.digest("hex"), fingerprint: finalSource };
  } finally {
    closeSync(sourceFd);
    if (destinationFd !== undefined) closeSync(destinationFd);
    if (existsSync(staging)) {
      try {
        const destinationStat = safeLstat(destination);
        const stagingStat = safeLstat(staging);
        if (
          stagingStat?.isFile() &&
          !stagingStat.isSymbolicLink() &&
          (!destinationStat ||
            (destinationStat.dev === stagingStat.dev &&
              destinationStat.ino === stagingStat.ino))
        ) {
          unlinkSync(staging);
          fsyncDirectory(dirname(staging));
        }
      } catch {
        // A retained private staging file is safer than deleting an identity
        // that changed during error recovery.
      }
    }
  }
}

function digestFile(path: string, privateArtifact = false): string {
  const stat = assertPrivateRegularFile(path, "transaction artifact");
  if (privateArtifact) assertPrivateMode(stat, "transaction artifact");
  const fd = openSync(
    path,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  try {
    const before = fingerprint(fstatSync(fd));
    if (!sameFingerprint(fingerprint(stat), before)) {
      throw new AccountsError("transaction artifact changed before validation");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(128 * 1024);
    let total = 0;
    while (true) {
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    const after = fingerprint(fstatSync(fd));
    if (total !== stat.size || !sameFingerprint(before, after)) {
      throw new AccountsError("transaction artifact changed during validation");
    }
    return hash.digest("hex");
  } finally {
    closeSync(fd);
  }
}

function ensureTargetProjectDirectory(
  targetDir: string,
  encodedProject: string,
): string {
  const projects = join(targetDir, "projects");
  if (existsSync(projects)) {
    assertRealOwnedDirectory(projects, "target Claude projects directory");
  } else {
    mkdirSync(projects, { mode: 0o700 });
    chmodSync(projects, 0o700);
    fsyncDirectory(projects);
    fsyncDirectory(targetDir);
  }
  const project = join(projects, encodedProject);
  if (existsSync(project)) {
    assertRealOwnedDirectory(project, "target Claude project directory");
  } else {
    mkdirSync(project, { mode: 0o700 });
    chmodSync(project, 0o700);
    fsyncDirectory(project);
    fsyncDirectory(projects);
  }
  return project;
}

interface RootJsonlSnapshot {
  digest: string;
  fingerprint: SourceFingerprint;
}

function snapshotRootJsonlPaths(
  profileDir: string,
): Map<string, RootJsonlSnapshot> {
  const results = new Map<string, RootJsonlSnapshot>();
  const projects = join(profileDir, "projects");
  if (!existsSync(projects)) return results;
  assertRealOwnedDirectory(projects, "target Claude projects closure");
  let seen = 0;
  const pending: Array<{ directory: string; depth: number }> = [
    { directory: projects, depth: 0 },
  ];
  while (pending.length > 0) {
    const { directory, depth } = pending.pop()!;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      seen += 1;
      if (seen > MAX_SIDECAR_SCAN_ENTRIES) {
        throw new AccountsError(
          "target Claude projects closure exceeded its safety bound",
        );
      }
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new AccountsError(
          "target Claude projects closure contains a symbolic link",
        );
      }
      if (entry.isDirectory()) {
        if (depth >= 1) {
          throw new AccountsError(
            "target Claude projects closure contains an unclassified sidecar",
          );
        }
        assertRealOwnedDirectory(path, "target Claude projects directory");
        pending.push({ directory: path, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) {
        throw new AccountsError(
          "target Claude projects closure contains a special filesystem entry",
        );
      }
      const stat = safeLstat(path);
      if (!stat) {
        throw new AccountsError("target Claude projects closure changed during inspection");
      }
      assertOwned(stat, "target Claude projects artifact");
      const rootUuid = entry.name.replace(/\.jsonl$/i, "");
      if (
        depth !== 1 ||
        !entry.name.toLowerCase().endsWith(".jsonl") ||
        !UUID_RE.test(rootUuid)
      ) {
        throw new AccountsError(
          "target Claude projects closure contains an unclassified sidecar",
        );
      }
      const root = assertPrivateRegularFile(path, "target root JSONL");
      results.set(path, {
        fingerprint: fingerprint(root),
        digest: digestFile(path, false),
      });
    }
  }
  return results;
}

function assertNoWritableTree(path: string): void {
  const result = spawnSync("/usr/bin/lsof", ["-w", "-Fnpa", "+D", path], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000,
  });
  if (result.error) {
    throw new AccountsError("could not prove the target profile is quiescent");
  }
  if (result.status === 1 && !(result.stdout ?? "").trim()) return;
  if (result.status !== 0) {
    throw new AccountsError("could not prove the target profile is quiescent");
  }
  const access = String(result.stdout ?? "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("a"))
    .map((line) => line.slice(1));
  if (access.some((value) => value === "w" || value === "u")) {
    throw new AccountsError("target profile has an active writer");
  }
}

function createdRootJsonl(
  before: ReadonlyMap<string, RootJsonlSnapshot>,
  after: ReadonlyMap<string, RootJsonlSnapshot>,
): string {
  for (const [path, prior] of before) {
    const current = after.get(path);
    if (
      !current ||
      !sameFingerprint(prior.fingerprint, current.fingerprint) ||
      prior.digest !== current.digest
    ) {
      throw new AccountsError(
        "Claude changed or deleted an existing target root JSONL during fork",
      );
    }
  }
  const created = [...after.keys()].filter((path) => !before.has(path));
  if (created.length !== 1) {
    throw new AccountsError(
      "Claude did not create exactly one new target root JSONL",
    );
  }
  return created[0]!;
}

function processAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== "ESRCH";
  }
}

interface TargetLock {
  assertHeld: () => void;
  release: () => void;
}

function acquireTargetLock(
  targetAccount: string,
  targetDir: string,
): TargetLock {
  ensurePrivateDirectory(accountsHome());
  const storageIdentity = createHash("sha256")
    .update(resolve(targetDir))
    .digest("hex")
    .slice(0, 32);
  const path = join(accountsHome(), `.session-resume-${storageIdentity}.lock`);
  const token = `${process.pid}:${randomUUID()}\n`;
  let fd: number | undefined;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      fd = openSync(path, "wx", 0o600);
      writeFileSync(fd, token, "utf8");
      fsyncSync(fd);
      fchmodSync(fd, 0o600);
      fsyncSync(fd);
      fsyncDirectory(dirname(path));
      break;
    } catch (error) {
      if (fd !== undefined) {
        closeSync(fd);
        fd = undefined;
      }
      if (errorCode(error) !== "EEXIST") throw error;
      let existing = "";
      try {
        const stat = assertPrivateRegularFile(path, "target mutation lock");
        assertPrivateMode(stat, "target mutation lock");
        existing = readFileSync(path, "utf8");
      } catch {
        throw new AccountsError(
          `target account "${targetAccount}" already has an unsafe session mutation lock`,
        );
      }
      const match = existing.match(
        /^([1-9][0-9]*):([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\n$/i,
      );
      if (!match || processAlive(Number(match[1]))) {
        throw new AccountsError(
          `target account "${targetAccount}" already has a session mutation in progress`,
        );
      }
      try {
        if (readFileSync(path, "utf8") === existing) {
          unlinkSync(path);
          fsyncDirectory(dirname(path));
        }
      } catch {
        throw new AccountsError(
          `target account "${targetAccount}" session mutation lock changed during recovery`,
        );
      }
    }
  }
  if (fd === undefined || !existsSync(path)) {
    throw new AccountsError(
      `target account "${targetAccount}" session mutation lock could not be acquired`,
    );
  }
  const heldFd = fd;
  const heldIdentity = fingerprint(fstatSync(heldFd));
  const assertHeld = (): void => {
    const descriptor = fingerprint(fstatSync(heldFd));
    const pathname = safeLstat(path);
    if (
      !sameFingerprint(heldIdentity, descriptor) ||
      !pathname?.isFile() ||
      pathname.isSymbolicLink() ||
      pathname.dev !== descriptor.dev ||
      pathname.ino !== descriptor.ino ||
      readFileSync(path, "utf8") !== token
    ) {
      throw new AccountsError(
        `target account "${targetAccount}" session mutation lock identity changed`,
      );
    }
  };
  assertHeld();
  return {
    assertHeld,
    release: () => {
      try {
        assertHeld();
        unlinkSync(path);
        fsyncDirectory(dirname(path));
      } catch {
        // A replaced lock belongs to another process and must not be removed.
      } finally {
        closeSync(heldFd);
      }
    },
  };
}

async function validateForkTranscript(
  journal: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
): Promise<JsonlInspection> {
  if (!journal.fork) {
    throw new AccountsError(
      `continuation journal has no retained fork; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const expectedForkPath = join(
    journal.target.configDir,
    "projects",
    entry.encodedProject,
    `${journal.fork.uuid}.jsonl`,
  );
  if (resolve(journal.fork.path) !== resolve(expectedForkPath)) {
    throw new AccountsError(
      `retained fork is outside the expected project identity; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const retainedPrefix =
    journal.fork.digest &&
    journal.fork.byteLength &&
    journal.fork.identity
      ? {
          digest: journal.fork.digest,
          byteLength: journal.fork.byteLength,
          lineCount: journal.fork.lineCount,
        }
      : undefined;
  if (
    (journal.fork.digest !== undefined ||
      journal.fork.byteLength !== undefined ||
      journal.fork.identity !== undefined) &&
    !retainedPrefix
  ) {
    throw new AccountsError(
      `retained fork proof is incomplete; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const forkStat = assertPrivateRegularFile(
    journal.fork.path,
    "retained fork session",
  );
  if (
    journal.fork.identity &&
    (!sameStableFileIdentity(journal.fork.identity, forkStat) ||
      forkStat.size < journal.fork.byteLength!)
  ) {
    throw new AccountsError(
      `retained fork inode or mode changed; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const inspection = await inspectCompleteJsonl(
    journal.fork.path,
    new Set([journal.fork.uuid]),
    true,
    {
      digest: journal.source.normalizedDigest,
      byteLength: journal.source.byteLength,
      lineCount: journal.source.lineCount,
    },
    retainedPrefix,
  );
  if (
    inspection.prefixDigest !== journal.source.normalizedDigest ||
    inspection.prefixBoundaryByteLength !== journal.source.byteLength ||
    inspection.sessionIds.size !== 1 ||
    !inspection.sessionIds.has(journal.fork.uuid) ||
    (retainedPrefix &&
      (inspection.retainedPrefixDigest !== retainedPrefix.digest ||
        inspection.retainedPrefixBoundaryByteLength !==
          retainedPrefix.byteLength)) ||
    inspection.lineCount < journal.fork.lineCount ||
    inspection.suffixLineCount < 1 ||
    inspection.suffixSessionIds.size !== 1 ||
    !inspection.suffixSessionIds.has(journal.fork.uuid) ||
    inspection.suffixCwds.size !== 1 ||
    !inspection.suffixCwds.has(journal.target.cwd) ||
    inspection.firstSuffixParentIdentity !== journal.source.lastRecordIdentity
  ) {
    throw new AccountsError(
      `retained fork does not prove the exact source prefix and persisted fork ancestry; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  assertNoSessionSidecars(
    journal.target.configDir,
    journal.fork.path,
    journal.fork.uuid,
    "target",
  );
  return inspection;
}

async function completedResult(
  journal: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
): Promise<ClaudeSessionResumeRun> {
  if (
    journal.state !== "launched" ||
    journal.launch?.status !== "completed" ||
    journal.launch.exitCode !== 0 ||
    !journal.fork
  ) {
    throw new AccountsError(
      `prior transaction is not safely replayable; recovery: inspect ${journal.artifacts.journal}; no new fork was launched`,
    );
  }
  requireDigest(journal.artifacts.backup, journal.source.digest, "source backup");
  requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
  requireDigest(journal.target.destination, journal.source.digest, "committed target");
  const sourceStat = assertPrivateRegularFile(journal.source.path, "source session");
  if (!sameFingerprint(journal.source.fingerprint, fingerprint(sourceStat))) {
    throw new AccountsError(
      `source session changed after the retained fork; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  requireDigest(journal.source.path, journal.source.digest, "source session", false);
  const sourceInspection = await inspectCompleteJsonl(
    journal.source.path,
    new Set([entry.uuid]),
  );
  if (
    sourceInspection.normalizedDigest !== journal.source.normalizedDigest ||
    sourceInspection.lineCount !== journal.source.lineCount ||
    sourceInspection.lastRecordIdentity !== journal.source.lastRecordIdentity ||
    sourceInspection.cwd !== journal.source.cwd
  ) {
    throw new AccountsError(
      `source transcript ancestry changed after the retained fork; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const destinationStat = assertPrivateRegularFile(
    journal.target.destination,
    "committed target session",
  );
  const forkStat = assertPrivateRegularFile(journal.fork.path, "retained fork session");
  await validateForkTranscript(journal, entry);
  // A replay may append valid turns to retained roots, but it must not acquire
  // a new nested/sidecar representation outside the versioned adapter.
  snapshotRootJsonlPaths(journal.target.configDir);
  assertNoSessionSidecars(
    journal.target.configDir,
    journal.target.destination,
    entry.uuid,
    "target",
  );
  assertPrivateMode(destinationStat, "committed target session");
  assertPrivateMode(forkStat, "retained fork session");
  if (
    (sourceStat.dev === destinationStat.dev && sourceStat.ino === destinationStat.ino) ||
    (sourceStat.dev === forkStat.dev && sourceStat.ino === forkStat.ino) ||
    (destinationStat.dev === forkStat.dev && destinationStat.ino === forkStat.ino)
  ) {
    throw new AccountsError(
      `retained continuation artifacts are not independent; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  return {
    exitCode: 0,
    result: {
      mode: "cross_owner_fork",
      source: journal.source.path,
      destination: journal.target.destination,
      target: journal.target.account,
      cwd: journal.target.cwd,
      transaction: journal.artifacts.journal,
      recovery: journal.recovery,
      fork: journal.fork.path,
    },
  };
}

function assertJournalRetryable(journal: TransactionJournal): void {
  if (journal.state === "launched") {
    if (journal.launch?.status === "completed" && journal.launch.exitCode === 0) return;
    throw new AccountsError(
      `prior launch state is uncertain; recovery: inspect ${journal.artifacts.journal}; the broker will not launch another fork`,
    );
  }
  if (journal.state === "failed") {
    throw new AccountsError(
      `prior transaction failed; recovery: inspect ${journal.artifacts.journal}; the broker will not launch another fork`,
    );
  }
}

async function createTransaction(
  entry: ClaudeSessionCatalogEntry,
  targetProfile: Profile,
  targetDir: string,
  cwd: string,
  sourceInspection: JsonlInspection,
): Promise<TransactionJournal> {
  ensurePrivateDirectory(transactionsRoot());
  const id = randomUUID();
  const directory = join(transactionsRoot(), id);
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  fsyncDirectory(directory);
  fsyncDirectory(transactionsRoot());
  const journalPath = join(directory, JOURNAL_FILE);
  const backup = join(directory, "source-backup.jsonl");
  const candidate = join(directory, "target-candidate.jsonl");
  const destination = join(
    targetDir,
    "projects",
    entry.encodedProject,
    `${entry.uuid}.jsonl`,
  );
  const now = new Date().toISOString();
  const journal: TransactionJournal = {
    schemaVersion: 2,
    id,
    adapter: CLAUDE_CONTINUATION_ADAPTER,
    state: "snapshotted",
    source: {
      catalogRef: entry.catalogRef,
      path: entry.sourcePath,
      fingerprint: sourceInspection.fingerprint,
      digest: sourceInspection.rawDigest,
      byteLength: sourceInspection.byteLength,
      normalizedDigest: sourceInspection.normalizedDigest,
      lineCount: sourceInspection.lineCount,
      lastRecordIdentity: sourceInspection.lastRecordIdentity,
      cwd: sourceInspection.cwd,
    },
    target: {
      account: targetProfile.name,
      configDir: targetDir,
      cwd,
      destination,
    },
    artifacts: {
      backup,
      candidate,
      journal: journalPath,
    },
    recovery:
      "private transaction artifacts are retained; reruns are idempotent and never force or overwrite a fork",
    createdAt: now,
    updatedAt: now,
  };
  // Persist the request identity before the first artifact copy. If the copy
  // is interrupted, the snapshotted state can reconstruct only the missing
  // private backup from the still-pinned source rather than leaving an
  // undiscoverable transaction directory.
  writePrivateJson(journalPath, journal);
  crashAtTestPoint("snapshotted");
  assertNoWritableHandle(entry.sourcePath);
  const copied = copyRegularExclusive(
    entry.sourcePath,
    backup,
    sourceInspection.fingerprint,
  );
  if (copied.digest !== sourceInspection.rawDigest) {
    throw new AccountsError("source session changed while its canonical snapshot was created");
  }
  const after = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
  if (!sameFingerprint(sourceInspection.fingerprint, after)) {
    throw new AccountsError("source session changed after snapshot");
  }
  return journal;
}

function requireDigest(
  path: string,
  expected: string,
  label: string,
  privateArtifact = true,
): void {
  if (digestFile(path, privateArtifact) !== expected) {
    throw new AccountsError(`${label} no longer matches the snapshotted dependency closure`);
  }
}

function validateExistingJournalBinding(
  journal: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
  targetDir: string,
  cwd: string,
): void {
  const expectedDestination = join(
    targetDir,
    "projects",
    entry.encodedProject,
    `${entry.uuid}.jsonl`,
  );
  if (
    !matchesClaudeSessionReference(entry, journal.source.catalogRef) ||
    resolve(journal.source.path) !== resolve(entry.sourcePath) ||
    journal.source.cwd !== entry.cwd ||
    resolve(journal.target.configDir) !== resolve(targetDir) ||
    journal.target.cwd !== cwd ||
    resolve(journal.target.destination) !== resolve(expectedDestination)
  ) {
    throw new AccountsError(
      `continuation transaction identity is stale or inconsistent; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  if (journal.fork) {
    const expectedFork = join(
      targetDir,
      "projects",
      entry.encodedProject,
      `${journal.fork.uuid}.jsonl`,
    );
    if (
      !UUID_RE.test(journal.fork.uuid) ||
      journal.fork.uuid === entry.uuid ||
      resolve(journal.fork.path) !== resolve(expectedFork)
    ) {
      throw new AccountsError(
        `continuation transaction fork identity is inconsistent; recovery: inspect ${journal.artifacts.journal}`,
      );
    }
  }
}

async function prepareTransaction(
  initial: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
): Promise<TransactionJournal> {
  let journal = initial;
  assertJournalRetryable(journal);
  if (journal.state === "launched") return journal;

  if (journal.state === "snapshotted") {
    recoverAtomicCopyStaging(journal.artifacts.backup);
    if (!existsSync(journal.artifacts.backup)) {
      const recovered = copyRegularExclusive(
        entry.sourcePath,
        journal.artifacts.backup,
        journal.source.fingerprint,
      );
      if (recovered.digest !== journal.source.digest) {
        throw new AccountsError("recovered source backup does not match the journal");
      }
    }
  }
  requireDigest(journal.artifacts.backup, journal.source.digest, "source backup");
  const currentSource = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
  if (!sameFingerprint(journal.source.fingerprint, currentSource)) {
    throw new AccountsError("source session changed since the transaction snapshot");
  }
  assertNoWritableHandle(entry.sourcePath);

  if (journal.state === "snapshotted") {
    recoverAtomicCopyStaging(journal.artifacts.candidate);
    if (existsSync(journal.artifacts.candidate)) {
      requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
    } else {
      copyRegularExclusive(journal.artifacts.backup, journal.artifacts.candidate);
    }
    requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
    journal = updateJournal(journal, { state: "fork_created" });
    crashAtTestPoint("fork_created");
  }

  if (journal.state === "fork_created") {
    const projectDir = ensureTargetProjectDirectory(
      journal.target.configDir,
      entry.encodedProject,
    );
    const expectedDestination = join(projectDir, `${entry.uuid}.jsonl`);
    if (expectedDestination !== journal.target.destination) {
      throw new AccountsError("transaction target project identity changed");
    }
    recoverAtomicCopyStaging(expectedDestination);
    if (existsSync(expectedDestination)) {
      requireDigest(expectedDestination, journal.source.digest, "promoted target");
    } else {
      try {
        copyRegularExclusive(journal.artifacts.candidate, expectedDestination);
      } catch (error) {
        if (errorCode(error) === "EEXIST") {
          throw new AccountsError("target session collision; no overwrite is allowed");
        }
        throw error;
      }
    }
    journal = updateJournal(journal, { state: "promoted" });
    crashAtTestPoint("promoted");
  }

  if (journal.state === "promoted") {
    requireDigest(journal.target.destination, journal.source.digest, "promoted target");
    const sourceStat = assertPrivateRegularFile(entry.sourcePath, "source session");
    const destinationStat = assertPrivateRegularFile(
      journal.target.destination,
      "promoted target session",
    );
    if (sourceStat.dev === destinationStat.dev && sourceStat.ino === destinationStat.ino) {
      throw new AccountsError("target session shares a writable transcript inode with the source");
    }
    journal = updateJournal(journal, { state: "validated" });
    crashAtTestPoint("validated");
  }

  if (journal.state === "validated") {
    const current = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
    if (!sameFingerprint(journal.source.fingerprint, current)) {
      throw new AccountsError("source session changed before commit");
    }
    assertNoWritableHandle(entry.sourcePath);
    requireDigest(journal.target.destination, journal.source.digest, "committed target");
    journal = updateJournal(journal, { state: "committed" });
    crashAtTestPoint("committed");
  }
  return journal;
}

function validateCommittedTransaction(
  journal: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
): void {
  requireDigest(journal.artifacts.backup, journal.source.digest, "source backup");
  requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
  requireDigest(journal.target.destination, journal.source.digest, "committed target");
  const sourceStat = assertPrivateRegularFile(entry.sourcePath, "source session");
  if (!sameFingerprint(journal.source.fingerprint, fingerprint(sourceStat))) {
    throw new AccountsError("source session changed after transaction commit");
  }
  assertNoWritableHandle(entry.sourcePath);
  assertNoSessionSidecars(
    journal.target.configDir,
    journal.target.destination,
    entry.uuid,
    "target",
  );
  const destinationStat = assertPrivateRegularFile(
    journal.target.destination,
    "committed target session",
  );
  assertPrivateMode(destinationStat, "committed target session");
  if (
    sourceStat.dev === destinationStat.dev &&
    sourceStat.ino === destinationStat.ino
  ) {
    throw new AccountsError("committed target shares a writable transcript inode with the source");
  }
}

async function launchCommittedFork(
  initial: TransactionJournal,
  entry: ClaudeSessionCatalogEntry,
  targetProfile: Profile,
  pinned: PinnedClaudeTool,
  assertLockHeld: () => void,
): Promise<ClaudeSessionResumeRun> {
  if (initial.state === "launched") return await completedResult(initial, entry);
  if (initial.state !== "committed") {
    throw new AccountsError("continuation transaction did not reach a committed state");
  }
  assertLockHeld();
  validateCommittedTransaction(initial, entry);
  assertPinnedClaudeTool(pinned);
  assertNoWritableTree(initial.target.configDir);
  const before = snapshotRootJsonlPaths(initial.target.configDir);
  let journal = updateJournal(initial, {
    state: "launched",
    launch: { status: "started" },
  });
  assertLockHeld();
  const exitCode = await runClaudeLaunch(
    targetProfile,
    pinned.tool,
    ["--resume", entry.uuid, "--fork-session"],
    claudeSessionEnv(targetProfile),
    journal.target.cwd,
    pinned.executableFd,
  );
  assertLockHeld();
  if (exitCode !== 0) {
    journal = updateJournal(journal, {
      state: "failed",
      launch: { status: "completed", exitCode },
      recovery: `launch exited ${exitCode}; recovery: inspect ${journal.artifacts.journal}; all artifacts are retained and retry will not launch another fork`,
    });
    return {
      exitCode,
      result: {
        mode: "cross_owner_fork",
        source: journal.source.path,
        destination: journal.target.destination,
        target: journal.target.account,
        cwd: journal.target.cwd,
        transaction: journal.artifacts.journal,
        recovery: journal.recovery,
      },
    };
  }

  assertNoWritableTree(journal.target.configDir);
  const after = snapshotRootJsonlPaths(journal.target.configDir);
  let forkPath: string;
  try {
    forkPath = createdRootJsonl(before, after);
  } catch {
    updateJournal(journal, {
      state: "failed",
      launch: { status: "completed", exitCode: 1 },
      recovery: `fork outcome is uncertain; recovery: inspect ${journal.artifacts.journal}; every artifact is retained`,
    });
    throw new AccountsError(
      `Claude fork outcome is uncertain; recovery: inspect ${journal.artifacts.journal}; no retry will launch another fork`,
    );
  }
  const filename = forkPath.slice(forkPath.lastIndexOf("/") + 1);
  const forkUuid = filename.replace(/\.jsonl$/i, "").toLowerCase();
  if (!UUID_RE.test(forkUuid) || forkUuid === entry.uuid) {
    throw new AccountsError(
      `Claude did not produce one new destination UUID; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  if (
    [...before.keys()].some(
      (path) =>
        basename(path).replace(/\.jsonl$/i, "").toLowerCase() === forkUuid,
    )
  ) {
    throw new AccountsError(
      `Claude reused an existing destination UUID in another project; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const expectedForkDirectory = join(
    journal.target.configDir,
    "projects",
    entry.encodedProject,
  );
  if (resolve(dirname(forkPath)) !== resolve(expectedForkDirectory)) {
    throw new AccountsError(
      `Claude created the fork under the wrong project identity; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  assertLockHeld();
  chmodSync(forkPath, 0o600);
  fsyncRegularFile(forkPath);
  fsyncDirectory(dirname(forkPath));
  const provisional: TransactionJournal = {
    ...journal,
    fork: {
      uuid: forkUuid,
      path: forkPath,
      lineCount: journal.source.lineCount + 1,
    },
  };
  const forkInspection = await validateForkTranscript(provisional, entry);
  const sourceNow = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
  if (!sameFingerprint(journal.source.fingerprint, sourceNow)) {
    throw new AccountsError(
      `source session changed after fork; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  requireDigest(entry.sourcePath, journal.source.digest, "source session", false);
  requireDigest(journal.target.destination, journal.source.digest, "promoted target");
  const sourceStat = assertPrivateRegularFile(entry.sourcePath, "source session");
  const destinationStat = assertPrivateRegularFile(
    journal.target.destination,
    "promoted target session",
  );
  const forkStat = assertPrivateRegularFile(forkPath, "fork session");
  assertPrivateMode(destinationStat, "promoted target session");
  assertPrivateMode(forkStat, "fork session");
  if (
    (sourceStat.dev === destinationStat.dev && sourceStat.ino === destinationStat.ino) ||
    (sourceStat.dev === forkStat.dev && sourceStat.ino === forkStat.ino) ||
    (destinationStat.dev === forkStat.dev && destinationStat.ino === forkStat.ino)
  ) {
    throw new AccountsError(
      `fork transcript independence could not be proved; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  assertLockHeld();
  journal = updateJournal(journal, {
    state: "launched",
    launch: { status: "completed", exitCode: 0 },
    fork: {
      uuid: forkUuid,
      path: forkPath,
      lineCount: forkInspection.lineCount,
      byteLength: forkInspection.byteLength,
      digest: forkInspection.normalizedDigest,
      identity: stableFileIdentity(forkInspection.fingerprint),
    },
    recovery:
      "successful fork and all private transaction artifacts are retained; rerun returns this result without launching another fork",
  });
  return await completedResult(journal, entry);
}

async function sameOwnerResume(
  entry: ClaudeSessionCatalogEntry,
  targetProfile: Profile,
  cwd: string,
  dryRun: boolean,
): Promise<ClaudeSessionResumeRun> {
  const sourceStat = assertPrivateRegularFile(entry.sourcePath, "source session");
  const canonicalSource = realpathSync.native(entry.sourcePath);
  if (canonicalSource !== resolve(entry.sourcePath)) {
    throw new AccountsError("source session path identity is stale or foreign");
  }
  assertOwned(sourceStat, "source session");
  const result: ClaudeSessionResumeResult = {
    mode: "same_owner",
    source: entry.sourcePath,
    destination: entry.sourcePath,
    target: targetProfile.name,
    cwd,
    transaction: null,
    recovery: dryRun
      ? "dry run; no files changed and no Claude process launched"
      : "native owner resume completed; no session files were copied",
  };
  if (dryRun) return { result, exitCode: 0 };
  const pinned = pinClaudeTool(getTool("claude"), targetProfile, cwd, false);
  try {
    const code = await runClaudeLaunch(
      targetProfile,
      pinned.tool,
      ["--resume", entry.uuid],
      claudeSessionEnv(targetProfile),
      cwd,
      pinned.executableFd,
    );
    return { result, exitCode: code };
  } finally {
    closePinnedClaudeTool(pinned);
  }
}

async function crossOwnerResume(
  entry: ClaudeSessionCatalogEntry,
  sourceProfile: Profile,
  targetProfile: Profile,
  targetDir: string,
  cwd: string,
  dryRun: boolean,
): Promise<ClaudeSessionResumeRun> {
  const tool = getTool("claude");
  const sourceInspection = await inspectCompleteJsonl(
    entry.sourcePath,
    new Set([entry.uuid]),
  );
  if (!entry.cwd || sourceInspection.cwd !== entry.cwd) {
    throw new AccountsError("session catalog cwd/project identity is stale or ambiguous");
  }
  if (cwd !== sourceInspection.cwd) {
    throw new AccountsError(
      "cross-account continuation requires the exact source cwd; a different --cwd is outside the simple adapter",
    );
  }
  if (entry.encodedProject !== claudeProjectKey(cwd)) {
    throw new AccountsError(
      "session catalog encoded project does not match the Claude 2.1.220 cwd identity",
    );
  }
  const providerSettingsProof = inspectProviderAuthSettings(targetDir, cwd);
  const assertProviderSettingsStable = (): void =>
    assertProviderAuthSettingsUnchanged(
      providerSettingsProof,
      targetDir,
      cwd,
    );
  assertNoWritableHandle(entry.sourcePath);
  const sourceDir = verifiedProfileDir(sourceProfile);
  const expectedSourceRoot = resolve(entry.sourcePath, "..", "..", "..");
  if (sourceDir !== expectedSourceRoot) {
    throw new AccountsError("session catalog source profile is stale or foreign");
  }
  assertNoSessionSidecars(sourceDir, entry.sourcePath, entry.uuid, "source");

  if (dryRun) {
    assertNoSessionSidecars(targetDir, undefined, entry.uuid, "target");
    assertNoWritableTree(targetDir);
    snapshotRootJsonlPaths(targetDir);
    assertProviderSettingsStable();
    const pinned = pinClaudeTool(
      tool,
      targetProfile,
      cwd,
      true,
      assertProviderSettingsStable,
    );
    try {
      assertProviderSettingsStable();
      return {
        exitCode: 0,
        result: {
          mode: "cross_owner_fork",
          source: entry.sourcePath,
          destination: join(
            targetDir,
            "projects",
            entry.encodedProject,
            `${entry.uuid}.jsonl`,
          ),
          target: targetProfile.name,
          cwd,
          transaction: null,
          recovery:
            "dry run; adapter, source closure, target collision, and quiescence gates passed without session or model mutation",
        },
      };
    } finally {
      closePinnedClaudeTool(pinned);
    }
  }

  const targetLock = acquireTargetLock(targetProfile.name, targetDir);
  try {
    targetLock.assertHeld();
    assertProviderSettingsStable();
    assertNoWritableTree(targetDir);
    let existing = matchingJournals(
      entry,
      targetProfile.name,
      targetDir,
      cwd,
    )[0];
    if (existing) {
      validateExistingJournalBinding(
        existing,
        entry,
        targetDir,
        cwd,
      );
      if (
        existing.source.catalogRef !== entry.catalogRef ||
        existing.target.account !== targetProfile.name
      ) {
        existing = updateJournal(existing, {
          source: {
            ...existing.source,
            catalogRef: entry.catalogRef,
          },
          target: {
            ...existing.target,
            account: targetProfile.name,
          },
        });
        existing = readPrivateJournal(existing.artifacts.journal);
        validateExistingJournalBinding(
          existing,
          entry,
          targetDir,
          cwd,
        );
      }
    }
    if (existing?.state === "launched" && existing.launch?.exitCode === 0) {
      targetLock.assertHeld();
      existing = readPrivateJournal(existing.artifacts.journal);
      validateExistingJournalBinding(
        existing,
        entry,
        targetDir,
        cwd,
      );
      return await completedResult(existing, entry);
    }
    if (existing) assertJournalRetryable(existing);
    if (!existing) {
      assertNoSessionSidecars(targetDir, undefined, entry.uuid, "target");
    }
    assertProviderSettingsStable();
    const pinned = pinClaudeTool(
      tool,
      targetProfile,
      cwd,
      true,
      assertProviderSettingsStable,
    );
    try {
      assertProviderSettingsStable();
      let journal =
        existing ??
        (await createTransaction(
          entry,
          targetProfile,
          targetDir,
          cwd,
          sourceInspection,
        ));
      // Journal identity and state are always reread after acquiring the target
      // lock and again before the irreversible launch boundary.
      targetLock.assertHeld();
      journal = readPrivateJournal(journal.artifacts.journal);
      validateExistingJournalBinding(
        journal,
        entry,
        targetDir,
        cwd,
      );
      journal = await prepareTransaction(journal, entry);
      targetLock.assertHeld();
      journal = readPrivateJournal(journal.artifacts.journal);
      validateExistingJournalBinding(
        journal,
        entry,
        targetDir,
        cwd,
      );
      return await launchCommittedFork(
        journal,
        entry,
        targetProfile,
        pinned,
        () => {
          targetLock.assertHeld();
          assertProviderSettingsStable();
        },
      );
    } finally {
      closePinnedClaudeTool(pinned);
    }
  } finally {
    targetLock.release();
  }
}

export async function runClaudeSessionResume(
  options: ClaudeSessionResumeOptions,
): Promise<ClaudeSessionResumeRun> {
  assertLinuxTrustDomain();
  const target = options.profiles.find(
    (profile) =>
      profile.name === options.targetProfile.name &&
      profile.tool === "claude" &&
      resolve(profile.dir) === resolve(options.targetProfile.dir),
  );
  if (!target) {
    throw new AccountsError(
      `target account "${options.targetProfile.name}" is stale or foreign to the local registry`,
    );
  }
  const targetDir = verifiedProfileDir(target);
  const skipped: ClaudeSessionScanSkip[] = [];
  const sessions = listClaudeSessions(options.profiles, {
    onSkip: (skip) => skipped.push(skip),
  });
  if (
    isClaudeSessionUuid(options.referenceOrUuid) &&
    skipped.length > 0
  ) {
    throw new AccountsError(
      "Claude session UUID cannot be resolved safely because another matching catalog path was skipped; use a canonical catalogRef after the catalog is complete",
    );
  }
  const entry = resolveClaudeSessionReference(
    sessions,
    options.referenceOrUuid,
  );
  const cwd = canonicalLaunchCwd(options.cwd, entry);
  const sourceRoot = resolve(entry.sourcePath, "..", "..", "..");
  const sourceProfile = options.profiles.find(
    (profile) =>
      profile.tool === "claude" &&
      resolve(profile.dir) === sourceRoot,
  );
  if (!sourceProfile) {
    throw new AccountsError("session catalog source profile is stale or foreign");
  }
  if (targetDir === sourceRoot) {
    return await sameOwnerResume(entry, target, cwd, options.dryRun === true);
  }
  return await crossOwnerResume(
    entry,
    sourceProfile,
    target,
    targetDir,
    cwd,
    options.dryRun === true,
  );
}
