import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  createReadStream,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
  type Stats,
} from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { accountsHome, profilesDir } from "../storage.js";
import { AccountsError, type Profile, type ToolDef } from "../types.js";
import { claudeApiAuthClearingEnv } from "./env.js";
import { resolveExecutable, runClaudeLaunch } from "./claude-launch.js";
import {
  listClaudeSessions,
  resolveClaudeSessionReference,
  type ClaudeSessionCatalogEntry,
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
  uid?: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

interface TransactionJournal {
  schemaVersion: 1;
  id: string;
  adapter: typeof CLAUDE_CONTINUATION_ADAPTER;
  state: TransactionState;
  source: {
    catalogRef: string;
    path: string;
    fingerprint: SourceFingerprint;
    digest: string;
    lineCount: number;
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
}

interface PinnedClaudeTool {
  tool: ToolDef;
  fingerprint: SourceFingerprint;
  digest: string;
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

function safeLstat(path: string): Stats | undefined {
  try {
    return lstatSync(path);
  } catch {
    return undefined;
  }
}

function fingerprint(stat: Stats): SourceFingerprint {
  return {
    dev: stat.dev,
    ino: stat.ino,
    mode: stat.mode,
    nlink: stat.nlink,
    ...(typeof stat.uid === "number" ? { uid: stat.uid } : {}),
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

function assertOwned(stat: Stats, label: string): void {
  if (typeof process.getuid !== "function") return;
  if (stat.uid !== process.getuid()) {
    throw new AccountsError(`${label} is outside the current local uid trust domain`);
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
  const managed = resolve(profilesDir(), "claude", profile.name);
  const defaultDir = resolve(getTool("claude").defaultDir);
  if (actual !== managed && actual !== defaultDir) {
    throw new AccountsError(
      `profile "${profile.name}" is stale or outside the local Accounts registry trust domain`,
    );
  }
  return assertRealOwnedDirectory(actual, `profile "${profile.name}" config directory`);
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

function claudeSessionEnv(profile: Profile): NodeJS.ProcessEnv {
  return {
    ...process.env,
    CLAUDE_CONFIG_DIR: profile.dir,
    TELEGRAM_STATE_DIR: join(profile.dir, "channels", "telegram"),
    ...claudeApiAuthClearingEnv(),
  };
}

function probeClaudeVersion(tool: ToolDef, profile: Profile, cwd: string): void {
  const result = spawnSync(tool.bin, ["--version"], {
    cwd,
    env: claudeSessionEnv(profile),
    encoding: "utf8",
    timeout: 10_000,
    stdio: ["ignore", "pipe", "pipe"],
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

function digestStableExecutable(path: string): {
  digest: string;
  fingerprint: SourceFingerprint;
} {
  const fd = openSync(
    path,
    constants.O_RDONLY |
      (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0),
  );
  try {
    const beforeStat = fstatSync(fd);
    if (!beforeStat.isFile()) {
      throw new AccountsError("versioned Claude executable is not one stable regular file");
    }
    const before = fingerprint(beforeStat);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(256 * 1024);
    while (true) {
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = fingerprint(fstatSync(fd));
    if (!sameFingerprint(before, after)) {
      throw new AccountsError("versioned Claude executable changed during verification");
    }
    return { digest: hash.digest("hex"), fingerprint: after };
  } finally {
    closeSync(fd);
  }
}

function pinClaudeTool(tool: ToolDef, profile: Profile, cwd: string): PinnedClaudeTool {
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
  const identity = digestStableExecutable(canonical);
  const pinned: PinnedClaudeTool = {
    tool: { ...tool, bin: canonical },
    fingerprint: identity.fingerprint,
    digest: identity.digest,
  };
  probeClaudeVersion(pinned.tool, profile, cwd);
  assertPinnedClaudeTool(pinned);
  return pinned;
}

function assertPinnedClaudeTool(pinned: PinnedClaudeTool): void {
  const current = safeLstat(pinned.tool.bin);
  if (!current?.isFile() || current.isSymbolicLink()) {
    throw new AccountsError("versioned Claude executable changed before launch");
  }
  if (!sameFingerprint(pinned.fingerprint, fingerprint(current))) {
    throw new AccountsError("versioned Claude executable changed before launch");
  }
  const identity = digestStableExecutable(pinned.tool.bin);
  if (
    !sameFingerprint(pinned.fingerprint, identity.fingerprint) ||
    pinned.digest !== identity.digest
  ) {
    throw new AccountsError("versioned Claude executable changed before launch");
  }
}

function assertNoWritableHandle(path: string): void {
  const result = spawnSync("lsof", ["-w", "-Fnpa", "--", path], {
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

async function inspectCompleteJsonl(
  path: string,
  allowedSessionIds: ReadonlySet<string>,
  allowMultipleCwds = false,
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
  try {
    const last = Buffer.allocUnsafe(1);
    if (readSync(fd, last, 0, 1, beforeStat.size - 1) !== 1 || last[0] !== 0x0a) {
      throw new AccountsError("session root JSONL is not complete");
    }
  } finally {
    closeSync(fd);
  }

  const cwds = new Set<string>();
  const sessionIds = new Set<string>();
  let lineCount = 0;
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
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new AccountsError("session root JSONL is not a complete simple transcript");
    }
    const top = record as {
      type?: unknown;
      cwd?: unknown;
      sessionId?: unknown;
      message?: unknown;
      isSidechain?: unknown;
      agentId?: unknown;
      agentSessionId?: unknown;
      fileHistorySnapshot?: unknown;
      sidechainId?: unknown;
      snapshot?: unknown;
      taskId?: unknown;
    };
    if (
      (top.type !== "user" && top.type !== "assistant") ||
      !top.message ||
      typeof top.message !== "object" ||
      Array.isArray(top.message)
    ) {
      throw new AccountsError(
        "session root JSONL is outside the supported simple user/assistant transcript subset",
      );
    }
    if (
      top.isSidechain === true ||
      top.agentId !== undefined ||
      top.agentSessionId !== undefined ||
      top.fileHistorySnapshot !== undefined ||
      top.sidechainId !== undefined ||
      top.snapshot !== undefined ||
      top.taskId !== undefined
    ) {
      throw new AccountsError(
        "session root JSONL contains dependency-bearing records outside the supported simple subset",
      );
    }
    const cwd = canonicalTranscriptCwd(top.cwd);
    if (!cwd) throw new AccountsError("session root JSONL has an ambiguous cwd/project");
    cwds.add(cwd);
    if (
      typeof top.sessionId !== "string" ||
      !UUID_RE.test(top.sessionId) ||
      !allowedSessionIds.has(top.sessionId.toLowerCase())
    ) {
      throw new AccountsError("session root JSONL has an ambiguous session identity");
    }
    sessionIds.add(top.sessionId.toLowerCase());
    lineCount += 1;
  };
  const input = createReadStream(path);
  let pending = Buffer.alloc(0);
  try {
    for await (const rawChunk of input) {
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      let offset = 0;
      while (offset < chunk.length) {
        const newline = chunk.indexOf(0x0a, offset);
        if (newline === -1) {
          const tail = chunk.subarray(offset);
          if (pending.length + tail.length > MAX_JSONL_LINE_BYTES) {
            throw new AccountsError("session root JSONL line exceeds the supported safety bound");
          }
          pending = pending.length === 0 ? Buffer.from(tail) : Buffer.concat([pending, tail]);
          break;
        }
        const segment = chunk.subarray(offset, newline);
        if (pending.length + segment.length > MAX_JSONL_LINE_BYTES) {
          throw new AccountsError("session root JSONL line exceeds the supported safety bound");
        }
        inspectLine(
          pending.length === 0 ? segment : Buffer.concat([pending, segment]),
        );
        pending = Buffer.alloc(0);
        offset = newline + 1;
      }
    }
  } finally {
    input.destroy();
  }
  if (pending.length !== 0) {
    throw new AccountsError("session root JSONL is not complete");
  }
  if (lineCount === 0 || cwds.size === 0 || (!allowMultipleCwds && cwds.size !== 1)) {
    throw new AccountsError("session root JSONL has an ambiguous cwd/project");
  }
  if (sessionIds.size === 0) {
    throw new AccountsError("session root JSONL has an ambiguous session identity");
  }
  const after = fingerprint(assertPrivateRegularFile(path, "session root JSONL"));
  const before = fingerprint(beforeStat);
  if (!sameFingerprint(before, after)) {
    throw new AccountsError("session root JSONL changed during validation");
  }
  return {
    cwd: [...cwds][0]!,
    cwds,
    lineCount,
    sessionIds,
    fingerprint: after,
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
  const walk = (directory: string): void => {
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
      if (relatedToUuid(entry.name, uuid)) {
        throw new AccountsError(
          context === "target"
            ? "target session collision or unclassified UUID sidecar"
            : "Claude session has a companion or unclassified UUID sidecar",
        );
      }
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(path);
    }
  };
  walk(profileDir);
}

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = safeLstat(path);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) {
    throw new AccountsError(`unsafe private directory at ${path}`);
  }
  assertOwned(stat, "private transaction directory");
  chmodSync(path, 0o700);
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
  } finally {
    if (fd !== undefined) closeSync(fd);
    rmSync(temp, { force: true });
  }
}

function readPrivateJournal(path: string): TransactionJournal {
  const stat = assertPrivateRegularFile(path, "transaction journal");
  assertPrivateMode(stat, "transaction journal");
  const directory = dirname(path);
  assertPrivateDirectory(directory, "transaction directory");
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as TransactionJournal;
    if (
      parsed.schemaVersion !== 1 ||
      parsed.id !== basename(directory) ||
      parsed.adapter?.schemaVersion !== CLAUDE_CONTINUATION_ADAPTER.schemaVersion ||
      parsed.adapter?.id !== CLAUDE_CONTINUATION_ADAPTER.id ||
      parsed.adapter?.cliVersion !== CLAUDE_CONTINUATION_ADAPTER.cliVersion ||
      !TRANSACTION_STATES.has(parsed.state) ||
      !parsed.source?.catalogRef ||
      !isAbsolute(parsed.source?.path ?? "") ||
      !/^[0-9a-f]{64}$/i.test(parsed.source?.digest ?? "") ||
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
    return parsed;
  } catch {
    throw new AccountsError("transaction journal is malformed; recovery requires manual inspection");
  }
}

function transactionsRoot(): string {
  return join(accountsHome(), TRANSACTIONS_DIR);
}

function matchingJournals(
  sourceCatalogRef: string,
  targetAccount: string,
  cwd: string,
): TransactionJournal[] {
  const root = transactionsRoot();
  if (!existsSync(root)) return [];
  assertPrivateDirectory(root, "session resume transaction root");
  const matches: TransactionJournal[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    const journalPath = join(root, entry.name, JOURNAL_FILE);
    if (!existsSync(journalPath)) continue;
    const journal = readPrivateJournal(journalPath);
    if (
      journal.source.catalogRef === sourceCatalogRef &&
      journal.target.account === targetAccount &&
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
  let destinationFd: number | undefined;
  try {
    const opened = fingerprint(fstatSync(sourceFd));
    if (expected && !sameFingerprint(expected, opened)) {
      throw new AccountsError("source session changed before snapshot");
    }
    destinationFd = openSync(destination, "wx", 0o600);
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
    chmodSync(destination, 0o600);
    const finalSource = fingerprint(fstatSync(sourceFd));
    if (!sameFingerprint(opened, finalSource)) {
      throw new AccountsError("source session changed during snapshot");
    }
    return { digest: hash.digest("hex"), fingerprint: finalSource };
  } finally {
    closeSync(sourceFd);
    if (destinationFd !== undefined) closeSync(destinationFd);
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
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(128 * 1024);
    let total = 0;
    while (true) {
      const bytesRead = readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      total += bytesRead;
    }
    if (total !== stat.size) throw new AccountsError("transaction artifact changed during validation");
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
  }
  const project = join(projects, encodedProject);
  if (existsSync(project)) {
    assertRealOwnedDirectory(project, "target Claude project directory");
  } else {
    mkdirSync(project, { mode: 0o700 });
    chmodSync(project, 0o700);
  }
  return project;
}

function allRootJsonlPaths(profileDir: string): Set<string> {
  const results = new Set<string>();
  const projects = join(profileDir, "projects");
  const projectEntries = safeLstat(projects)?.isDirectory()
    ? readdirSync(projects, { withFileTypes: true })
    : [];
  for (const project of projectEntries) {
    if (!project.isDirectory() || project.isSymbolicLink()) continue;
    const projectPath = join(projects, project.name);
    for (const entry of readdirSync(projectPath, { withFileTypes: true })) {
      if (
        entry.isFile() &&
        !entry.isSymbolicLink() &&
        /^[0-9a-f-]{36}\.jsonl$/i.test(entry.name)
      ) {
        results.add(join(projectPath, entry.name));
      }
    }
  }
  return results;
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

function acquireTargetLock(targetAccount: string): () => void {
  ensurePrivateDirectory(accountsHome());
  const path = join(accountsHome(), `.session-resume-${targetAccount}.lock`);
  const token = `${process.pid}:${randomUUID()}\n`;
  let fd: number | undefined;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      fd = openSync(path, "wx", 0o600);
      writeFileSync(fd, token, "utf8");
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      chmodSync(path, 0o600);
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
        if (readFileSync(path, "utf8") === existing) unlinkSync(path);
      } catch {
        throw new AccountsError(
          `target account "${targetAccount}" session mutation lock changed during recovery`,
        );
      }
    }
  }
  if (fd !== undefined || !existsSync(path)) {
    throw new AccountsError(
      `target account "${targetAccount}" session mutation lock could not be acquired`,
    );
  }
  return () => {
    try {
      if (readFileSync(path, "utf8") === token) unlinkSync(path);
    } catch {
      // Missing means already released. A replaced lock belongs to another process.
    }
  };
}

function completedResult(journal: TransactionJournal): ClaudeSessionResumeRun {
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
  const destinationStat = assertPrivateRegularFile(
    journal.target.destination,
    "committed target session",
  );
  const forkStat = assertPrivateRegularFile(journal.fork.path, "retained fork session");
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
  const journalPath = join(directory, JOURNAL_FILE);
  const backup = join(directory, "source-backup.jsonl");
  const candidate = join(directory, "target-candidate.jsonl");
  assertNoWritableHandle(entry.sourcePath);
  const copied = copyRegularExclusive(
    entry.sourcePath,
    backup,
    sourceInspection.fingerprint,
  );
  const after = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
  if (!sameFingerprint(sourceInspection.fingerprint, after)) {
    throw new AccountsError("source session changed after snapshot");
  }
  const destination = join(
    targetDir,
    "projects",
    entry.encodedProject,
    `${entry.uuid}.jsonl`,
  );
  const now = new Date().toISOString();
  const journal: TransactionJournal = {
    schemaVersion: 1,
    id,
    adapter: CLAUDE_CONTINUATION_ADAPTER,
    state: "snapshotted",
    source: {
      catalogRef: entry.catalogRef,
      path: entry.sourcePath,
      fingerprint: sourceInspection.fingerprint,
      digest: copied.digest,
      lineCount: sourceInspection.lineCount,
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
  writePrivateJson(journalPath, journal);
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
  targetProfile: Profile,
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
    journal.source.catalogRef !== entry.catalogRef ||
    resolve(journal.source.path) !== resolve(entry.sourcePath) ||
    journal.source.cwd !== entry.cwd ||
    journal.target.account !== targetProfile.name ||
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

  requireDigest(journal.artifacts.backup, journal.source.digest, "source backup");
  const currentSource = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
  if (!sameFingerprint(journal.source.fingerprint, currentSource)) {
    throw new AccountsError("source session changed since the transaction snapshot");
  }
  assertNoWritableHandle(entry.sourcePath);

  if (journal.state === "snapshotted") {
    if (existsSync(journal.artifacts.candidate)) {
      requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
    } else {
      copyRegularExclusive(journal.artifacts.backup, journal.artifacts.candidate);
    }
    requireDigest(journal.artifacts.candidate, journal.source.digest, "target candidate");
    journal = updateJournal(journal, { state: "fork_created" });
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
  }

  if (journal.state === "validated") {
    const current = fingerprint(assertPrivateRegularFile(entry.sourcePath, "source session"));
    if (!sameFingerprint(journal.source.fingerprint, current)) {
      throw new AccountsError("source session changed before commit");
    }
    assertNoWritableHandle(entry.sourcePath);
    requireDigest(journal.target.destination, journal.source.digest, "committed target");
    journal = updateJournal(journal, { state: "committed" });
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
): Promise<ClaudeSessionResumeRun> {
  if (initial.state === "launched") return completedResult(initial);
  if (initial.state !== "committed") {
    throw new AccountsError("continuation transaction did not reach a committed state");
  }
  validateCommittedTransaction(initial, entry);
  assertPinnedClaudeTool(pinned);
  const before = allRootJsonlPaths(initial.target.configDir);
  let journal = updateJournal(initial, {
    state: "launched",
    launch: { status: "started" },
  });
  const exitCode = await runClaudeLaunch(
    targetProfile,
    pinned.tool,
    ["--resume", entry.uuid, "--fork-session"],
    claudeSessionEnv(targetProfile),
    journal.target.cwd,
  );
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

  const after = allRootJsonlPaths(journal.target.configDir);
  const created = [...after].filter((path) => !before.has(path));
  if (created.length !== 1) {
    updateJournal(journal, {
      state: "failed",
      launch: { status: "completed", exitCode: 1 },
      recovery: `fork outcome is uncertain; recovery: inspect ${journal.artifacts.journal}; every artifact is retained`,
    });
    throw new AccountsError(
      `Claude fork outcome is uncertain; recovery: inspect ${journal.artifacts.journal}; no retry will launch another fork`,
    );
  }
  const forkPath = created[0]!;
  const filename = forkPath.slice(forkPath.lastIndexOf("/") + 1);
  const forkUuid = filename.replace(/\.jsonl$/i, "").toLowerCase();
  if (!UUID_RE.test(forkUuid) || forkUuid === entry.uuid) {
    throw new AccountsError(
      `Claude did not produce one new destination UUID; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
  const forkInspection = await inspectCompleteJsonl(
    forkPath,
    new Set([entry.uuid, forkUuid]),
    true,
  );
  if (
    !forkInspection.sessionIds.has(forkUuid) ||
    forkInspection.lineCount <= journal.source.lineCount ||
    !forkInspection.cwds.has(journal.source.cwd) ||
    !forkInspection.cwds.has(journal.target.cwd)
  ) {
    throw new AccountsError(
      `Claude fork did not prove persisted copied history; recovery: inspect ${journal.artifacts.journal}`,
    );
  }
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
  assertPrivateRegularFile(forkPath, "fork session");
  chmodSync(forkPath, 0o600);
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
  journal = updateJournal(journal, {
    state: "launched",
    launch: { status: "completed", exitCode: 0 },
    fork: {
      uuid: forkUuid,
      path: forkPath,
      lineCount: forkInspection.lineCount,
    },
    recovery:
      "successful fork and all private transaction artifacts are retained; rerun returns this result without launching another fork",
  });
  return completedResult(journal);
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
  const code = await runClaudeLaunch(
    targetProfile,
    getTool("claude"),
    ["--resume", entry.uuid],
    claudeSessionEnv(targetProfile),
    cwd,
  );
  return { result, exitCode: code };
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
  assertNoWritableHandle(entry.sourcePath);
  const sourceDir = verifiedProfileDir(sourceProfile);
  const expectedSourceRoot = resolve(entry.sourcePath, "..", "..", "..");
  if (sourceDir !== expectedSourceRoot) {
    throw new AccountsError("session catalog source profile is stale or foreign");
  }
  assertNoSessionSidecars(sourceDir, entry.sourcePath, entry.uuid, "source");
  const existing = matchingJournals(entry.catalogRef, targetProfile.name, cwd)[0];
  if (existing) {
    validateExistingJournalBinding(existing, entry, targetProfile, targetDir, cwd);
  }
  if (existing?.state === "launched" && existing.launch?.exitCode === 0) {
    return completedResult(existing);
  }
  if (existing) assertJournalRetryable(existing);
  if (!existing) assertNoSessionSidecars(targetDir, undefined, entry.uuid, "target");
  const pinned = pinClaudeTool(tool, targetProfile, cwd);

  if (dryRun) {
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
          "dry run; adapter, source closure, target collision, and quiescence gates passed without writes or launch",
      },
    };
  }

  const release = acquireTargetLock(targetProfile.name);
  try {
    if (!existing) assertNoSessionSidecars(targetDir, undefined, entry.uuid, "target");
    let journal =
      existing ??
      (await createTransaction(
        entry,
        targetProfile,
        targetDir,
        cwd,
        sourceInspection,
      ));
    journal = await prepareTransaction(journal, entry);
    return await launchCommittedFork(journal, entry, targetProfile, pinned);
  } finally {
    release();
  }
}

export async function runClaudeSessionResume(
  options: ClaudeSessionResumeOptions,
): Promise<ClaudeSessionResumeRun> {
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
  const sessions = listClaudeSessions(options.profiles);
  const entry = resolveClaudeSessionReference(
    sessions,
    options.referenceOrUuid,
  );
  const cwd = canonicalLaunchCwd(options.cwd, entry);
  const sourceProfile = options.profiles.find(
    (profile) =>
      profile.name === entry.ownerProfile &&
      profile.tool === "claude" &&
      resolve(profile.dir) === resolve(entry.sourcePath, "..", "..", ".."),
  );
  if (!sourceProfile) {
    throw new AccountsError("session catalog source profile is stale or foreign");
  }
  if (entry.ownerProfile === target.name) {
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
