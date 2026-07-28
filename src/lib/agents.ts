import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import type { Profile } from "../types.js";
import { controlledProbeEnv } from "./env.js";
import { redactPublicValue, redactText } from "./redaction.js";
import { getTool } from "./tools.js";

export type AgentEntry = Record<string, unknown>;

/** Minimal profile shape needed to query agents (allows synthetic entries). */
export type ProfileLike = Pick<Profile, "name" | "tool" | "dir"> & { email?: string };

export interface ProfileAgents {
  profile: string;
  tool: string;
  email?: string;
  dir: string;
  agents: AgentEntry[];
  error?: string;
}

export interface AgentsRunnerResult {
  ok: boolean;
  raw: string;
  error?: string;
}

export type AgentsRunner = (profile: ProfileLike) => AgentsRunnerResult;

export interface ProcessInfo {
  pid: number;
  ppid: number;
  command: string;
  configDir?: string;
}

export type ProcessScanner = (toolId: string) => ProcessInfo[];

function isProjectedRecord(value: unknown): value is AgentEntry {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Convert provider-owned agent data into getter-free, cycle-safe public
 * records. Strings are recursively redacted and unsafe values are omitted
 * before either JSON serialization or human rendering can observe them.
 */
export function projectAgentEntries(value: unknown): AgentEntry[] {
  const projected = redactPublicValue(value);
  if (!Array.isArray(projected)) return [];
  return projected.filter(isProjectedRecord);
}

function projectProcessInfo(value: unknown): ProcessInfo[] {
  return projectAgentEntries(value).flatMap((entry) => {
    const { pid, ppid, command, configDir } = entry;
    if (
      typeof pid !== "number" ||
      !Number.isSafeInteger(pid) ||
      pid <= 0 ||
      typeof ppid !== "number" ||
      !Number.isSafeInteger(ppid) ||
      ppid < 0 ||
      typeof command !== "string"
    ) {
      return [];
    }
    return [{
      pid,
      ppid,
      command,
      ...(typeof configDir === "string" ? { configDir } : {}),
    }];
  });
}

function isProviderAgentEntry(entry: AgentEntry): boolean {
  if (entry.kind !== "background" && entry.kind !== "interactive") return false;
  if (!Object.hasOwn(entry, "pid")) return true;
  return (
    typeof entry.pid === "number" &&
    Number.isSafeInteger(entry.pid) &&
    entry.pid > 0
  );
}

function scriptExecutable(): string {
  return existsSync("/usr/bin/script") ? "/usr/bin/script" : "script";
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

const MAX_AGENT_JSON_NESTING = 32_768;
const MAX_AGENT_JSON_FALLBACK_CANDIDATES = 32;
const MAX_AGENT_JSON_CANDIDATE_BYTES = 1024 * 1024;

interface AgentJsonCandidate {
  start: number;
  depth: number;
  inString: boolean;
  escaped: boolean;
  byteLength: number;
}

interface InvalidAgentJsonRegion {
  depth: number;
  inString: boolean;
  escaped: boolean;
}

function utf8ByteWidthAt(text: string, index: number): number {
  const code = text.charCodeAt(index);
  if (code <= 0x7f) return 1;
  if (code <= 0x7ff) return 2;
  if (code >= 0xd800 && code <= 0xdbff) {
    const next = text.charCodeAt(index + 1);
    return next >= 0xdc00 && next <= 0xdfff ? 4 : 3;
  }
  if (code >= 0xdc00 && code <= 0xdfff) {
    const previous = text.charCodeAt(index - 1);
    return previous >= 0xd800 && previous <= 0xdbff ? 0 : 3;
  }
  return 3;
}

function advanceArrayScanState(
  state: Pick<AgentJsonCandidate, "depth" | "inString" | "escaped">,
  char: string,
): boolean {
  if (state.inString) {
    if (state.escaped) state.escaped = false;
    else if (char === "\\") state.escaped = true;
    else if (char === '"') state.inString = false;
    return false;
  }
  if (char === '"') state.inString = true;
  else if (char === "[") state.depth++;
  else if (char === "]") state.depth--;
  return state.depth === 0;
}

function stripTerminalControlSequences(raw: string): string {
  const chunks: string[] = [];
  let plainStart = 0;
  let index = 0;

  const appendPlain = (end: number): void => {
    if (end > plainStart) chunks.push(raw.slice(plainStart, end));
  };

  const consumeStringControl = (
    start: number,
    options: { allowBell: boolean; recoverAtNewline: boolean },
  ): number => {
    let cursor = start;
    while (cursor < raw.length) {
      if (raw[cursor] === "\u0018" || raw[cursor] === "\u001a") return cursor + 1;
      if (options.allowBell && raw[cursor] === "\u0007") return cursor + 1;
      if (raw[cursor] === "\u009c") return cursor + 1;
      if (raw[cursor] === "\u001b" && raw[cursor + 1] === "\\") return cursor + 2;
      if (options.recoverAtNewline && (raw[cursor] === "\n" || raw[cursor] === "\r")) {
        return cursor;
      }
      cursor++;
    }
    return raw.length;
  };

  const consumeCsi = (start: number): number => {
    let cursor = start;
    while (cursor < raw.length) {
      const code = raw.charCodeAt(cursor);
      if (code === 0x0a || code === 0x0d) return cursor;
      cursor++;
      if (code === 0x18 || code === 0x1a) break;
      if (code >= 0x40 && code <= 0x7e) break;
    }
    return cursor;
  };

  while (index < raw.length) {
    const char = raw[index]!;
    if (
      char !== "\u001b" &&
      char !== "\u0090" &&
      char !== "\u0098" &&
      char !== "\u009b" &&
      char !== "\u009d" &&
      char !== "\u009e" &&
      char !== "\u009f"
    ) {
      index++;
      continue;
    }

    appendPlain(index);
    if (char === "\u009b") {
      index = consumeCsi(index + 1);
    } else if (char === "\u009d") {
      index = consumeStringControl(index + 1, {
        allowBell: true,
        recoverAtNewline: true,
      });
    } else if (
      char === "\u0090" ||
      char === "\u0098" ||
      char === "\u009e" ||
      char === "\u009f"
    ) {
      index = consumeStringControl(index + 1, {
        allowBell: false,
        recoverAtNewline: false,
      });
    } else {
      const command = raw[index + 1];
      if (command === "[") index = consumeCsi(index + 2);
      else if (command === "]") {
        index = consumeStringControl(index + 2, {
          allowBell: true,
          recoverAtNewline: true,
        });
      } else if (command === "P" || command === "X" || command === "^" || command === "_") {
        index = consumeStringControl(index + 2, {
          allowBell: false,
          recoverAtNewline: false,
        });
      } else {
        index = Math.min(index + 2, raw.length);
      }
    }
    plainStart = index;
  }

  appendPlain(raw.length);
  return chunks.join("").replaceAll("\r", "");
}

function parseAgentArrayCandidate(
  text: string,
  start: number,
  end: number,
): unknown[] | undefined {
  const candidate = text.slice(start, end);
  if (Buffer.byteLength(candidate, "utf8") > MAX_AGENT_JSON_CANDIDATE_BYTES) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(candidate) as unknown;
    if (
      !Array.isArray(parsed) ||
      !parsed.every((entry) => entry !== null && typeof entry === "object" && !Array.isArray(entry)) ||
      (
        parsed.length > 0 &&
        !parsed.some(
          (entry) =>
            (entry as Record<string, unknown>).kind === "background" ||
            (entry as Record<string, unknown>).kind === "interactive",
        )
      )
    ) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

/**
 * Extract the first top-level JSON array from output that may be wrapped in
 * pty/ANSI noise (`claude agents --json` only works on a TTY, so we run it
 * under `script` and the JSON arrives surrounded by control sequences).
 */
export function extractJsonArray(raw: string): unknown[] | undefined {
  const text = stripTerminalControlSequences(raw);
  const active: AgentJsonCandidate[] = [];
  let completed: { start: number; parsed: unknown[] } | undefined;
  let emptyCompleted: { start: number; parsed: unknown[] } | undefined;
  let invalidRegion: InvalidAgentJsonRegion | undefined;

  scan:
  for (let index = 0; index < text.length; index++) {
    const char = text[index]!;
    if (invalidRegion) {
      if (advanceArrayScanState(invalidRegion, char)) invalidRegion = undefined;
      continue;
    }

    const byteWidth = utf8ByteWidthAt(text, index);
    for (let candidateIndex = active.length - 1; candidateIndex >= 0; candidateIndex--) {
      const candidate = active[candidateIndex]!;
      candidate.byteLength += byteWidth;
      if (candidate.byteLength > MAX_AGENT_JSON_CANDIDATE_BYTES) {
        const root = active[0]!;
        const region: InvalidAgentJsonRegion = {
          depth: root.depth,
          inString: root.inString,
          escaped: root.escaped,
        };
        invalidRegion = advanceArrayScanState(region, char) ? undefined : region;
        if (completed && completed.start > root.start) completed = undefined;
        if (emptyCompleted && emptyCompleted.start > root.start) emptyCompleted = undefined;
        active.length = 0;
        continue scan;
      }

      if (candidate.inString) {
        if (candidate.escaped) candidate.escaped = false;
        else if (char === "\\") candidate.escaped = true;
        else if (char === '"') candidate.inString = false;
        else if (char === "\n") active.splice(candidateIndex, 1);
        continue;
      }
      const closed = advanceArrayScanState(candidate, char);
      if (candidate.depth > MAX_AGENT_JSON_NESTING) {
        const root = active[0]!;
        const region: InvalidAgentJsonRegion = {
          depth: root.depth,
          inString: root.inString,
          escaped: root.escaped,
        };
        invalidRegion =
          candidateIndex === 0 || !advanceArrayScanState(region, char)
            ? region
            : undefined;
        if (completed && completed.start > root.start) completed = undefined;
        if (emptyCompleted && emptyCompleted.start > root.start) emptyCompleted = undefined;
        active.length = 0;
        continue scan;
      }
      if (closed) {
        active.splice(candidateIndex, 1);
        const parsed = parseAgentArrayCandidate(text, candidate.start, index + 1);
        if (parsed?.length === 0) {
          if (!emptyCompleted || candidate.start < emptyCompleted.start) {
            emptyCompleted = { start: candidate.start, parsed };
          }
        } else if (parsed && (!completed || candidate.start < completed.start)) {
          completed = { start: candidate.start, parsed };
        }
      }
    }

    if (char === "[") {
      if (active.length >= MAX_AGENT_JSON_FALLBACK_CANDIDATES) {
        active.splice(1, 1);
      }
      active.push({
        start: index,
        depth: 1,
        inString: false,
        escaped: false,
        byteLength: 1,
      });
    }

    if (completed) {
      if (!active.some((candidate) => candidate.start < completed!.start)) {
        return completed.parsed;
      }
    }
  }

  return completed?.parsed ?? emptyCompleted?.parsed;
}

/**
 * Run `<bin> agents --json` for a profile's config dir under a pseudo-TTY.
 * Claude Code switches to print-mode argument parsing when stdout is not a
 * TTY and never reaches the `agents` subcommand, so a plain pipe won't work.
 */
export function runClaudeAgentsJson(profile: ProfileLike, timeoutMs = 20_000): AgentsRunnerResult {
  const tool = getTool(profile.tool);
  const bin = tool.bin ?? "claude";
  const env = controlledProbeEnv(process.env, { [tool.envVar]: profile.dir });
  const args =
    platform() === "darwin"
      ? ["-q", "/dev/null", bin, "agents", "--json"]
      : ["-qefc", `${shellQuote(bin)} agents --json`, "/dev/null"];
  const res = spawnSync(scriptExecutable(), args, {
    encoding: "utf8",
    env,
    timeout: timeoutMs,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (res.error) return { ok: false, raw: "", error: redactText(res.error.message) };
  if (res.signal) {
    return {
      ok: false,
      raw: redactText(res.stdout ?? ""),
      error: `timed out (${res.signal})`,
    };
  }
  if (res.status !== 0) {
    const detail = (res.stderr || res.stdout || "").trim().split("\n").pop() ?? "";
    return {
      ok: false,
      raw: redactText(res.stdout ?? ""),
      error: `exit ${res.status}${detail ? `: ${redactText(detail)}` : ""}`,
    };
  }
  return { ok: true, raw: res.stdout ?? "" };
}

/**
 * True when a `ps` command line looks like a real agent session process for
 * the tool — not a daemon, pty host, pre-warmed spare, shell snapshot, our
 * own `agents` listing invocation, or an `accounts` wrapper.
 */
interface CommandToken {
  value: string;
  start: number;
  end: number;
}

interface InterpreterOptionSchema {
  optionsWithValues: ReadonlySet<string>;
  detachedOnlyValueOptions: ReadonlySet<string>;
  optionsWithOptionalAttachedValues: ReadonlySet<string>;
  optionsWithoutValues: ReadonlySet<string>;
  executionModeOptions: ReadonlySet<string>;
  attachedShortValueOptions: readonly string[];
}

const NODE_OPTION_SCHEMA: InterpreterOptionSchema = {
  optionsWithValues: new Set([
    "-r",
    "-C",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--conditions",
    "--inspect-port",
    "--title",
    "--icu-data-dir",
    "--openssl-config",
    "--redirect-warnings",
    "--diagnostic-dir",
    "--cpu-prof-dir",
    "--heap-prof-dir",
    "--snapshot-blob",
    "--env-file",
    "--env-file-if-exists",
    "--debug-port",
    "--cpu-prof-name",
    "--cpu-prof-interval",
    "--heap-prof-name",
    "--heap-prof-interval",
    "--experimental-config-file",
    "--experimental-default-type",
    "--experimental-test-isolation",
    "--disable-proto",
    "--disable-warning",
    "--heapsnapshot-near-heap-limit",
    "--heapsnapshot-signal",
    "--inspect-publish-uid",
    "--localstorage-file",
    "--max-old-space-size-percentage",
    "--network-family-autoselection-attempt-timeout",
    "--watch-path",
    "--watch-kill-signal",
    "--test-concurrency",
    "--test-coverage-branches",
    "--test-coverage-exclude",
    "--test-coverage-functions",
    "--test-coverage-include",
    "--test-coverage-lines",
    "--test-name-pattern",
    "--test-reporter",
    "--test-reporter-destination",
    "--test-shard",
    "--test-skip-pattern",
    "--test-timeout",
    "--report-directory",
    "--report-dir",
    "--report-filename",
    "--report-signal",
    "--secure-heap",
    "--secure-heap-min",
    "--tls-cipher-list",
    "--tls-keylog",
    "--trace-event-categories",
    "--trace-event-file-pattern",
    "--trace-require-module",
    "--use-largepages",
    "--v8-pool-size",
    "--max-http-header-size",
    "--dns-result-order",
    "--unhandled-rejections",
  ]),
  detachedOnlyValueOptions: new Set(["-r", "-C"]),
  optionsWithOptionalAttachedValues: new Set([
    "--inspect",
    "--inspect-brk",
    "--inspect-wait",
  ]),
  optionsWithoutValues: new Set([
    "--abort-on-uncaught-exception",
    "--cpu-prof",
    "--disallow-code-generation-from-strings",
    "--enable-source-maps",
    "--expose-gc",
    "--force-context-aware",
    "--frozen-intrinsics",
    "--heap-prof",
    "--insecure-http-parser",
    "--jitless",
    "--no-addons",
    "--no-deprecation",
    "--no-warnings",
    "--openssl-legacy-provider",
    "--openssl-shared-config",
    "--pending-deprecation",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--prof",
    "--report-compact",
    "--report-exclude-env",
    "--report-exclude-network",
    "--report-on-fatalerror",
    "--report-on-signal",
    "--report-uncaught-exception",
    "--throw-deprecation",
    "--trace-deprecation",
    "--trace-env",
    "--trace-env-js-stack",
    "--trace-env-native-stack",
    "--trace-exit",
    "--trace-promises",
    "--trace-sigint",
    "--trace-sync-io",
    "--trace-tls",
    "--trace-uncaught",
    "--trace-warnings",
    "--track-heap-objects",
    "--use-bundled-ca",
    "--use-openssl-ca",
    "--use-system-ca",
    "--watch",
    "--watch-preserve-output",
    "--zero-fill-buffers",
  ]),
  executionModeOptions: new Set([
    "-",
    "--build-snapshot",
    "-c",
    "--check",
    "--completion-bash",
    "--build-snapshot-config",
    "-e",
    "--eval",
    "--experimental-sea-config",
    "-h",
    "--help",
    "-i",
    "--interactive",
    "--input-type",
    "-p",
    "--print",
    "--prof-process",
    "--run",
    "--test",
    "-v",
    "--version",
    "--v8-options",
  ]),
  attachedShortValueOptions: [],
};

const BUN_OPTION_SCHEMA: InterpreterOptionSchema = {
  optionsWithValues: new Set([
    "-r",
    "-c",
    "--preload",
    "--require",
    "--import",
    "--loader",
    "--cpu-prof-name",
    "--cpu-prof-dir",
    "--cpu-prof-interval",
    "--heap-prof-name",
    "--heap-prof-dir",
    "--install",
    "--port",
    "--conditions",
    "--fetch-preconnect",
    "--max-http-header-size",
    "--dns-result-order",
    "--title",
    "--unhandled-rejections",
    "--console-depth",
    "--user-agent",
    "--cron-title",
    "--cron-period",
    "--elide-lines",
    "--env-file",
    "--cwd",
    "--config",
  ]),
  detachedOnlyValueOptions: new Set(),
  optionsWithOptionalAttachedValues: new Set([
    "--inspect",
    "--inspect-brk",
    "--inspect-wait",
  ]),
  optionsWithoutValues: new Set([
    "-b",
    "-i",
    "--bun",
    "--cpu-prof",
    "--cpu-prof-md",
    "--experimental-http2-fetch",
    "--experimental-http3-fetch",
    "--expose-gc",
    "--heap-prof",
    "--heap-prof-md",
    "--hot",
    "--if-present",
    "--no-addons",
    "--no-clear-screen",
    "--no-deprecation",
    "--no-env-file",
    "--no-exit-on-error",
    "--no-install",
    "--no-orphans",
    "--prefer-latest",
    "--prefer-offline",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--redis-preconnect",
    "--silent",
    "--smol",
    "--sql-preconnect",
    "--throw-deprecation",
    "--use-bundled-ca",
    "--use-openssl-ca",
    "--use-system-ca",
    "--watch",
    "--zero-fill-buffers",
  ]),
  executionModeOptions: new Set([
    "-e",
    "--eval",
    "-h",
    "--help",
    "-p",
    "--print",
    "--revision",
    "-F",
    "--filter",
    "--parallel",
    "--sequential",
    "--shell",
    "-v",
    "--version",
    "--workspaces",
  ]),
  attachedShortValueOptions: ["-r", "-c", "-F"],
};

const CLAUDE_OPTIONS_WITH_VALUES = new Set([
  "--config",
  "--config-dir",
  "--allowedTools",
  "--allowed-tools",
  "--betas",
  "-d",
  "--debug",
  "--debug-file",
  "--disallowedTools",
  "--disallowed-tools",
  "--effort",
  "--file",
  "--from-pr",
  "--thinking",
  "--thinking-display",
  "--max-thinking-tokens",
  "--task-budget",
  "--permission-prompt-tool",
  "--settings",
  "--managed-settings",
  "--model",
  "--permission-mode",
  "--session-id",
  "-r",
  "--resume",
  "--resume-session-at",
  "--name",
  "-n",
  "--output-format",
  "--input-format",
  "--system-prompt",
  "--system-prompt-file",
  "--append-system-prompt",
  "--append-system-prompt-file",
  "--append-subagent-system-prompt",
  "--plan-mode-instructions",
  "--fallback-model",
  "--json-schema",
  "--max-budget-usd",
  "--mcp-config",
  "--agent",
  "--agents",
  "--agent-id",
  "--agent-name",
  "--agent-type",
  "--agent-color",
  "--team-name",
  "--parent-session-id",
  "--teammate-mode",
  "--add-dir",
  "--channels",
  "--dangerously-load-development-channels",
  "--plugin-dir",
  "--plugin-dir-no-mcp",
  "--plugin-url",
  "--prompt-suggestions",
  "--prefill",
  "--prefill-b64",
  "--deep-link-repo",
  "--deep-link-last-fetch",
  "--deep-link-cwd-b64",
  "--advisor",
  "--sdk-url",
  "--workload",
  "--remote-control",
  "--teleport",
  "--cloud",
  "--remote",
  "--rc",
  "--remote-control-session-name-prefix",
  "--setting-sources",
  "--tools",
  "--max-turns",
  "--budget-usd",
  "--worktree",
  "-w",
]);

const CLAUDE_OPTIONS_WITH_OPTIONAL_VALUES = new Set([
  "-d",
  "--debug",
  "--from-pr",
  "--prompt-suggestions",
  "--remote-control",
  "--teleport",
  "--cloud",
  "--remote",
  "--rc",
  "-r",
  "--resume",
  "-w",
  "--worktree",
]);

const CLAUDE_OPTIONS_WITH_VARIADIC_VALUES = new Set([
  "--add-dir",
  "--allowedTools",
  "--allowed-tools",
  "--betas",
  "--channels",
  "--dangerously-load-development-channels",
  "--disallowedTools",
  "--disallowed-tools",
  "--file",
  "--mcp-config",
  "--tools",
]);

const CLAUDE_TERMINAL_OPTIONS = new Set([
  "-h",
  "--help",
  "-v",
  "-V",
  "--version",
  "--update",
  "--upgrade",
  "--init-only",
  "--rewind-files",
  "--handle-uri",
]);

const CLAUDE_HELPER_OPTIONS = new Set([
  "--bg-pty-host",
  "--bg-spare",
  "--chrome-native-host",
  "--claude-in-chrome-mcp",
  "--computer-use-mcp",
  "--daemon-worker",
  "--preload",
]);

const CLAUDE_NON_SESSION_COMMANDS = new Set([
  "agents",
  "auth",
  "auto-mode",
  "daemon",
  "doctor",
  "gateway",
  "install",
  "mcp",
  "plugin",
  "plugins",
  "project",
  "rc",
  "remote-control",
  "setup-token",
  "ultrareview",
  "update",
  "upgrade",
]);

function commandBasename(value: string): string {
  return value.replaceAll("\\", "/").split("/").pop() ?? value;
}

function hasPathComponent(value: string): boolean {
  return value.includes("/") || value.includes("\\");
}

function normalizeExecutablePath(value: string): string {
  const normalized = value.replaceAll("\\", "/");
  return /^[A-Za-z]:\//.test(normalized) ? normalized.toLowerCase() : normalized;
}

function readCommandToken(command: string, offset: number): CommandToken | undefined {
  let start = offset;
  while (start < command.length && /\s/.test(command[start]!)) start++;
  if (start >= command.length) return undefined;

  const quote = command[start] === '"' || command[start] === "'" ? command[start]! : undefined;
  if (!quote) {
    let end = start;
    while (end < command.length && !/\s/.test(command[end]!)) end++;
    return { value: command.slice(start, end), start, end };
  }

  let value = "";
  let end = start + 1;
  while (end < command.length) {
    const char = command[end]!;
    if (char === quote) return { value, start, end: end + 1 };
    if (
      char === "\\" &&
      end + 1 < command.length &&
      (command[end + 1] === quote || command[end + 1] === "\\")
    ) {
      value += command[end + 1]!;
      end += 2;
      continue;
    }
    value += char;
    end++;
  }
  return { value, start, end };
}

function executableTokenMatches(
  observed: string,
  configured: string,
): boolean {
  const configuredHasPath = hasPathComponent(configured);
  const observedHasPath = hasPathComponent(observed);
  if (configuredHasPath && observedHasPath) {
    return normalizeExecutablePath(observed) === normalizeExecutablePath(configured);
  }
  if (configuredHasPath) return false;
  return commandBasename(observed) === commandBasename(configured);
}

function isVersionedToolBuild(observed: string, configured: string): boolean {
  if (hasPathComponent(configured)) return false;
  const tool = commandBasename(configured).replace(/\.exe$/i, "");
  const trustedRoot = normalizeExecutablePath(
    `${homedir().replaceAll("\\", "/")}/.local/share/${tool}/versions`,
  );
  const normalizedObserved = normalizeExecutablePath(observed);
  if (!normalizedObserved.startsWith(`${trustedRoot}/`)) return false;
  const version = normalizedObserved.slice(trustedRoot.length + 1);
  return (
    !version.includes("/") &&
    /^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/.test(version)
  );
}

function matchExecutableAt(
  command: string,
  offset: number,
  configured: string,
): { end: number } | undefined {
  let start = offset;
  while (start < command.length && /\s/.test(command[start]!)) start++;

  if (hasPathComponent(configured)) {
    const rawObserved = command.slice(start, start + configured.length);
    const boundary = command[start + configured.length];
    if (
      executableTokenMatches(rawObserved, configured) &&
      (boundary === undefined || /\s/.test(boundary))
    ) {
      return { end: start + configured.length };
    }
  }

  const token = readCommandToken(command, start);
  if (!token) return undefined;
  if (
    executableTokenMatches(token.value, configured) ||
    isVersionedToolBuild(token.value, configured)
  ) {
    return { end: token.end };
  }
  return undefined;
}

function optionName(value: string): string {
  const equals = value.indexOf("=");
  return equals === -1 ? value : value.slice(0, equals);
}

function resolveInterpreterOption(
  value: string,
  schema: InterpreterOptionSchema,
): { name: string; hasAttachedValue: boolean } {
  const name = optionName(value);
  const hasAttachedValue = name !== value;
  if (hasAttachedValue) return { name, hasAttachedValue };

  for (const shortName of schema.attachedShortValueOptions) {
    if (value.startsWith(shortName) && value.length > shortName.length) {
      return { name: shortName, hasAttachedValue: true };
    }
  }
  return { name, hasAttachedValue: false };
}

function interpreterChildOffset(
  command: string,
  offset: number,
  configured: string,
  schema: InterpreterOptionSchema,
): number | undefined {
  let cursor = offset;
  while (true) {
    const executable = matchExecutableAt(command, cursor, configured);
    if (executable) {
      let start = cursor;
      while (start < command.length && /\s/.test(command[start]!)) start++;
      return start;
    }

    const token = readCommandToken(command, cursor);
    if (!token) return undefined;
    if (token.value === "--") {
      const child = readCommandToken(command, token.end);
      return child && matchExecutableAt(command, child.start, configured)
        ? child.start
        : undefined;
    }
    if (!token.value.startsWith("-") || token.value === "-") return undefined;

    cursor = token.end;
    const { name, hasAttachedValue } = resolveInterpreterOption(token.value, schema);
    if (schema.executionModeOptions.has(name)) return undefined;
    if (schema.optionsWithValues.has(name)) {
      if (hasAttachedValue) {
        if (schema.detachedOnlyValueOptions.has(name)) return undefined;
        continue;
      }
      const value = readCommandToken(command, cursor);
      if (!value) return undefined;
      cursor = value.end;
      continue;
    }
    if (schema.optionsWithOptionalAttachedValues.has(name)) {
      continue;
    }
    if (schema.optionsWithoutValues.has(name)) {
      if (hasAttachedValue) return undefined;
      continue;
    }
    return undefined;
  }
}

function commandArguments(command: string, offset: number): string[] {
  const args: string[] = [];
  let cursor = offset;
  while (true) {
    const token = readCommandToken(command, cursor);
    if (!token) return args;
    args.push(token.value);
    cursor = token.end;
  }
}

function classifyClaudeArguments(args: string[]): {
  helper: boolean;
  terminal: boolean;
  invalid?: boolean;
  mode?: string;
} {
  const handleUriIndex = args.indexOf("--handle-uri");
  if (handleUriIndex !== -1 && args[handleUriIndex + 1]) {
    return { helper: false, terminal: true };
  }

  let mode: string | undefined;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") return { helper: false, terminal: false, mode };
    if (!arg.startsWith("-") || arg === "-") {
      mode ??= arg;
      continue;
    }
    const name = optionName(arg);
    if (CLAUDE_TERMINAL_OPTIONS.has(name)) return { helper: false, terminal: true };
    if (CLAUDE_HELPER_OPTIONS.has(name)) {
      return { helper: true, terminal: false };
    }
    if (CLAUDE_OPTIONS_WITH_VARIADIC_VALUES.has(name) && !arg.includes("=")) {
      if (args[index + 1] === undefined) {
        return { helper: false, terminal: false, invalid: true };
      }
      index++;
      while (args[index + 1] !== undefined && !args[index + 1]!.startsWith("-")) {
        index++;
      }
      continue;
    }
    if (CLAUDE_OPTIONS_WITH_VALUES.has(name) && !arg.includes("=")) {
      const next = args[index + 1];
      if (!CLAUDE_OPTIONS_WITH_OPTIONAL_VALUES.has(name)) {
        if (next === undefined) {
          return { helper: false, terminal: false, invalid: true };
        }
        index++;
      } else if (next !== undefined && !next.startsWith("-")) {
        index++;
      }
    }
  }
  return { helper: false, terminal: false, mode };
}

export function isToolSessionCommand(command: string, bin: string): boolean {
  const first = readCommandToken(command, 0);
  if (!first) return false;

  let executableOffset = first.start;
  const interpreter = commandBasename(first.value).toLowerCase().replace(/\.exe$/, "");
  if (interpreter === "node" || interpreter === "nodejs" || interpreter === "bun") {
    const childOffset = interpreterChildOffset(
      command,
      first.end,
      bin,
      interpreter === "bun" ? BUN_OPTION_SCHEMA : NODE_OPTION_SCHEMA,
    );
    if (childOffset === undefined) return false;
    executableOffset = childOffset;
  }

  const executable = matchExecutableAt(command, executableOffset, bin);
  if (!executable) return false;

  if (commandBasename(bin).toLowerCase().replace(/\.exe$/, "") !== "claude") {
    return true;
  }

  const args = commandArguments(command, executable.end);
  const classification = classifyClaudeArguments(args);
  if (classification.helper || classification.terminal || classification.invalid) return false;
  if (
    classification.mode &&
    CLAUDE_NON_SESSION_COMMANDS.has(classification.mode)
  ) {
    return false;
  }
  return true;
}

/** Scan running processes for agent sessions of a tool (pid, ppid, command, config dir). */
export function scanToolProcesses(toolId = "claude"): ProcessInfo[] {
  const tool = getTool(toolId);
  const bin = tool.bin ?? toolId;
  const res = spawnSync("ps", ["-axo", "pid=,ppid=,args="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (res.status !== 0 || !res.stdout) return [];

  const out: ProcessInfo[] = [];
  for (const line of res.stdout.split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    const ppid = Number(m[2]);
    const command = m[3]!.trim();
    if (pid === process.pid) continue;
    if (!isToolSessionCommand(command, bin)) continue;
    const configDir = readProcessEnvVar(pid, tool.envVar);
    out.push({ pid, ppid, command, ...(configDir ? { configDir } : {}) });
  }
  return out;
}

/** Best-effort read of one env var from a running process (Linux /proc only). */
function readProcessEnvVar(pid: number, envVar: string): string | undefined {
  try {
    const environ = readFileSync(`/proc/${pid}/environ`, "utf8");
    for (const kv of environ.split("\0")) {
      if (kv.startsWith(`${envVar}=`)) return kv.slice(envVar.length + 1) || undefined;
    }
  } catch {
    /* macOS, or process exited */
  }
  return undefined;
}

export interface ListAgentsOptions {
  /**
   * Registered profiles for the tool, resolved by the caller through the Store
   * (`resolveStore().listProfiles(tool)`). This module never reads the local
   * registry directly, so in self_hosted/cloud mode the cloud registry drives
   * the listing. Defaults to none.
   */
  profiles?: ProfileLike[];
  tool?: string;
  profile?: string;
  backgroundOnly?: boolean;
  runner?: AgentsRunner;
  /** Override the tool's default config dir (used by tests). */
  defaultDir?: string;
  processScanner?: ProcessScanner;
}

/**
 * List agent sessions for every profile of a tool (default: claude).
 *
 * Besides registered profiles this also queries the tool's DEFAULT config
 * dir (e.g. ~/.claude) as a synthetic "(default)" entry — headless sessions
 * started without the accounts CLI live there — and cross-checks the daemon
 * listings against a process scan, reporting session processes no daemon
 * knows about under "(untracked)".
 */
export function listAgentsAcrossProfiles(opts: ListAgentsOptions = {}): ProfileAgents[] {
  const toolId = opts.tool ?? "claude";
  const runner = opts.runner ?? runClaudeAgentsJson;
  const tool = getTool(toolId);

  const registered = (opts.profiles ?? []).filter((p) => p.tool === toolId);
  const entries: ProfileLike[] = [...registered];
  const defaultDir = opts.defaultDir ?? tool.defaultDir;
  if (defaultDir && !registered.some((p) => p.dir === defaultDir) && existsSync(defaultDir)) {
    entries.unshift({ name: "(default)", tool: toolId, dir: defaultDir });
  }

  const wanted = entries.filter(
    (p) => !opts.profile || p.name === opts.profile || (opts.profile === "default" && p.name === "(default)"),
  );

  // pids reported by any daemon, collected BEFORE the kind filter so that
  // interactive sessions never show up again as "(untracked)" processes
  const reported = new Set<number>();

  const results = wanted.map((profile) => {
    const base: ProfileAgents = {
      profile: profile.name,
      tool: profile.tool,
      ...(profile.email ? { email: profile.email } : {}),
      dir: profile.dir,
      agents: [],
    };
    const result = runner(profile);
    if (!result.ok) return { ...base, error: result.error ?? "failed to list agents" };

    const parsed = extractJsonArray(result.raw);
    if (!parsed) return { ...base, error: "could not parse agents output" };

    const publicAgents = projectAgentEntries(parsed).filter(
      isProviderAgentEntry,
    );
    for (const a of publicAgents) {
      if (typeof a.pid === "number") reported.add(a.pid);
    }
    const agents = publicAgents.filter(
      (a) => !opts.backgroundOnly || a.kind === "background",
    );
    return { ...base, agents };
  });

  // Cross-check daemon listings against actually-running processes; anything
  // the daemons don't report (e.g. headless loops on stale daemons) is shown
  // rather than silently dropped. Skipped when filtering to one profile.
  if (!opts.profile) {
    const scanner = opts.processScanner ?? scanToolProcesses;
    const scanned = projectProcessInfo(scanner(toolId));
    if (scanned.length > 0) {
      const untracked = scanned.filter(
        (p) =>
          !reported.has(p.pid) &&
          !reported.has(p.ppid) &&
          !scanned.some((q) => q.ppid === p.pid && reported.has(q.pid)),
      );
      if (untracked.length > 0) {
        results.push({
          profile: "(untracked)",
          tool: toolId,
          dir: "",
          agents: untracked.map((p) => ({
            kind: "process",
            pid: p.pid,
            command: p.command,
            ...(p.configDir ? { configDir: p.configDir } : {}),
          })),
        });
      }
    }
  }

  return results;
}
