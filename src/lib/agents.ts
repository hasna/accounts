import { spawnSync } from "node:child_process";
import {
  accessSync,
  constants,
  existsSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import { homedir, platform } from "node:os";
import { delimiter, join, resolve } from "node:path";
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
const MAX_AGENT_JSON_QUARANTINE_CONTAINERS = MAX_AGENT_JSON_NESTING * 2;
const MAX_AGENT_JSON_FALLBACK_CANDIDATES = 32;
const MAX_AGENT_JSON_CANDIDATE_BYTES = 1024 * 1024;

interface AgentJsonCandidate {
  start: number;
  containers: Array<"]" | "}">;
  inString: boolean;
  escaped: boolean;
  byteLength: number;
}

interface InvalidAgentJsonRegion {
  containers: Array<"]" | "}">;
  inString: boolean;
  escaped: boolean;
  overflowed: boolean;
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

function advanceJsonContainerScanState(
  state: Pick<AgentJsonCandidate, "containers" | "inString" | "escaped">,
  char: string,
): boolean {
  if (state.inString) {
    if (state.escaped) state.escaped = false;
    else if (char === "\\") state.escaped = true;
    else if (char === '"') state.inString = false;
    return false;
  }
  if (char === '"') state.inString = true;
  else if (char === "[") state.containers.push("]");
  else if (char === "{") state.containers.push("}");
  else if (
    (char === "]" || char === "}") &&
    state.containers.at(-1) === char
  ) {
    state.containers.pop();
  }
  return state.containers.length === 0;
}

function invalidAgentJsonRegion(
  state: Pick<AgentJsonCandidate, "containers" | "inString" | "escaped">,
): InvalidAgentJsonRegion {
  return {
    containers: [...state.containers],
    inString: state.inString,
    escaped: state.escaped,
    overflowed: false,
  };
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
      if (!invalidRegion.overflowed) {
        const closed = advanceJsonContainerScanState(invalidRegion, char);
        if (
          invalidRegion.containers.length >
          MAX_AGENT_JSON_QUARANTINE_CONTAINERS
        ) {
          invalidRegion.containers.length = 0;
          invalidRegion.inString = false;
          invalidRegion.escaped = false;
          invalidRegion.overflowed = true;
        } else if (closed) {
          invalidRegion = undefined;
        }
      }
      continue;
    }

    const byteWidth = utf8ByteWidthAt(text, index);
    for (let candidateIndex = active.length - 1; candidateIndex >= 0; candidateIndex--) {
      const candidate = active[candidateIndex]!;
      candidate.byteLength += byteWidth;
      if (candidate.byteLength > MAX_AGENT_JSON_CANDIDATE_BYTES) {
        const root = active[0]!;
        const region = invalidAgentJsonRegion(root);
        invalidRegion =
          region.overflowed ||
          !advanceJsonContainerScanState(region, char)
            ? region
            : undefined;
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
      const closed = advanceJsonContainerScanState(candidate, char);
      if (candidate.containers.length > MAX_AGENT_JSON_NESTING) {
        const root = active[0]!;
        const region = invalidAgentJsonRegion(root);
        invalidRegion =
          candidateIndex === 0 ||
          region.overflowed ||
          !advanceJsonContainerScanState(region, char)
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
        containers: ["]"],
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
  attachedOnlyValueOptions: ReadonlySet<string>;
  optionsRejectingOptionValues: ReadonlySet<string>;
  optionsWithOptionalAttachedValues: ReadonlySet<string>;
  optionsWithoutValues: ReadonlySet<string>;
  executionModeOptions: ReadonlySet<string>;
  passthroughCommands: ReadonlySet<string>;
  passthroughOptionsWithValues: ReadonlySet<string>;
  passthroughOptionsWithoutValues: ReadonlySet<string>;
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
    "--max-old-space-size",
    "--max-semi-space-size",
    "--stack-trace-limit",
    "--dns-result-order",
    "--unhandled-rejections",
    "--allow-fs-read",
    "--allow-fs-write",
  ]),
  detachedOnlyValueOptions: new Set(["-r", "-C"]),
  attachedOnlyValueOptions: new Set([
    "--max-old-space-size",
    "--max-semi-space-size",
    "--stack-trace-limit",
  ]),
  optionsRejectingOptionValues: new Set([
    "--allow-fs-read",
    "--allow-fs-write",
  ]),
  optionsWithOptionalAttachedValues: new Set([
    "--inspect",
    "--inspect-brk",
    "--inspect-wait",
  ]),
  optionsWithoutValues: new Set([
    "--abort-on-uncaught-exception",
    "--allow-addons",
    "--allow-child-process",
    "--allow-wasi",
    "--allow-worker",
    "--cpu-prof",
    "--disable-sigusr1",
    "--disable-wasm-trap-handler",
    "--disallow-code-generation-from-strings",
    "--enable-etw-stack-walking",
    "--enable-fips",
    "--enable-network-family-autoselection",
    "--enable-source-maps",
    "--entry-url",
    "--experimental-addon-modules",
    "--experimental-async-context-frame",
    "--experimental-default-config-file",
    "--experimental-eventsource",
    "--experimental-import-meta-resolve",
    "--experimental-inspector-network-resource",
    "--experimental-network-inspection",
    "--experimental-permission",
    "--permission",
    "--experimental-print-required-tla",
    "--experimental-test-coverage",
    "--experimental-test-module-mocks",
    "--experimental-transform-types",
    "--experimental-vm-modules",
    "--experimental-webstorage",
    "--experimental-worker-inspection",
    "--expose-gc",
    "--force-context-aware",
    "--force-fips",
    "--force-node-api-uncaught-exceptions-policy",
    "--frozen-intrinsics",
    "--heap-prof",
    "--huge-max-old-generation-size",
    "--insecure-http-parser",
    "--interpreted-frames-native-stack",
    "--jitless",
    "--no-addons",
    "--no-deprecation",
    "--no-experimental-detect-module",
    "--no-experimental-fetch",
    "--no-experimental-global-customevent",
    "--no-experimental-global-navigator",
    "--no-experimental-global-webcrypto",
    "--no-experimental-repl-await",
    "--no-experimental-require-module",
    "--no-experimental-sqlite",
    "--no-experimental-strip-types",
    "--no-experimental-websocket",
    "--no-extra-info-on-fatal-exception",
    "--no-force-async-hooks-checks",
    "--no-global-search-paths",
    "--no-network-family-autoselection",
    "--no-warnings",
    "--node-memory-debug",
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
    "--test-force-exit",
    "--test-only",
    "--test-update-snapshots",
    "--throw-deprecation",
    "--tls-max-v1.2",
    "--tls-max-v1.3",
    "--tls-min-v1.0",
    "--tls-min-v1.1",
    "--tls-min-v1.2",
    "--tls-min-v1.3",
    "--trace-atomics-wait",
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
    "--use-env-proxy",
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
  passthroughCommands: new Set(),
  passthroughOptionsWithValues: new Set(),
  passthroughOptionsWithoutValues: new Set(),
  attachedShortValueOptions: [],
};

const BUN_OPTION_SCHEMA: InterpreterOptionSchema = {
  optionsWithValues: new Set([
    "-r",
    "-c",
    "-d",
    "-l",
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
    "--main-fields",
    "--extension-order",
    "--tsconfig-override",
    "--define",
    "--drop",
    "--feature",
    "--loader",
    "--jsx-factory",
    "--jsx-fragment",
    "--jsx-import-source",
    "--jsx-runtime",
  ]),
  detachedOnlyValueOptions: new Set(),
  attachedOnlyValueOptions: new Set(),
  optionsRejectingOptionValues: new Set(),
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
    "--no-macros",
    "--no-orphans",
    "--prefer-latest",
    "--prefer-offline",
    "--preserve-symlinks",
    "--preserve-symlinks-main",
    "--redis-preconnect",
    "--silent",
    "--smol",
    "--sql-preconnect",
    "--jsx-side-effects",
    "--ignore-dce-annotations",
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
  passthroughCommands: new Set(["run"]),
  passthroughOptionsWithValues: new Set(["-F", "--filter", "--shell"]),
  passthroughOptionsWithoutValues: new Set([
    "--parallel",
    "--sequential",
    "--workspaces",
  ]),
  attachedShortValueOptions: ["-r", "-c", "-d", "-l", "-F"],
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
  "doctor",
  "gateway",
  "install",
  "mcp",
  "plugin",
  "plugins",
  "project",
  "setup-token",
  "ultrareview",
  "update",
  "upgrade",
]);

const CLAUDE_BRIDGE_COMMANDS = new Set([
  "remote-control",
  "rc",
  "remote",
  "sync",
  "bridge",
]);

const CLAUDE_BACKGROUND_CONTROL_COMMANDS = new Set([
  "logs",
  "attach",
  "stop",
  "kill",
  "respawn",
  "rm",
]);

const CLAUDE_BACKGROUND_LAUNCHER_FLAGS = new Set([
  "--bg",
  "--background",
]);

const CLAUDE_DAEMON_PREFIX_FLAGS = new Set([
  "--dangerously-skip-permissions",
  "--allow-dangerously-skip-permissions",
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

function resolvedBareExecutablePaths(configured: string): ReadonlySet<string> {
  const pathValue = process.env.PATH ?? "";
  const pathExt = process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD";
  const paths = new Set<string>();
  const names =
    platform() === "win32" && !/\.[A-Za-z0-9]+$/.test(configured)
      ? pathExt
          .split(";")
          .filter(Boolean)
          .map((extension) => `${configured}${extension.toLowerCase()}`)
      : [configured];
  for (const entry of pathValue.split(delimiter)) {
    const root = resolve(entry || ".");
    let found = false;
    for (const name of names) {
      const candidate = join(root, name);
      try {
        if (!statSync(candidate).isFile()) continue;
        accessSync(candidate, constants.X_OK);
      } catch {
        continue;
      }
      found = true;
      paths.add(normalizeExecutablePath(candidate));
      try {
        paths.add(normalizeExecutablePath(realpathSync(candidate)));
      } catch {
        // The PATH entry itself is still the exact configured target.
      }
    }
    if (found) break;
  }
  return paths;
}

function executableIdentityPaths(value: string): ReadonlySet<string> {
  const paths = new Set<string>([normalizeExecutablePath(value)]);
  try {
    paths.add(normalizeExecutablePath(realpathSync(value)));
  } catch {
    // A process may exit between ps and identity verification. The observed
    // path remains useful only when it exactly matches a trusted identity.
  }
  return paths;
}

function processExecutableMatchesInterpreter(
  processExecutable: string | undefined,
  interpreter: string,
): boolean {
  if (!processExecutable) return false;
  const trusted = resolvedBareExecutablePaths(interpreter);
  if (trusted.size === 0) return false;
  for (const identity of executableIdentityPaths(processExecutable)) {
    if (trusted.has(identity)) return true;
  }
  return false;
}

function processExecutableMatchesDirectTool(
  processExecutable: string | undefined,
  observed: string,
  configured: string,
): boolean {
  if (!processExecutable) return false;
  const trusted = hasPathComponent(configured)
    ? executableIdentityPaths(configured)
    : hasPathComponent(observed)
      ? executableIdentityPaths(observed)
      : resolvedBareExecutablePaths(configured);
  if (trusted.size === 0) return false;
  for (const identity of executableIdentityPaths(processExecutable)) {
    if (trusted.has(identity)) return true;
  }
  return false;
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
  if (!observedHasPath) {
    if (platform() === "win32") {
      return (
        observed.replace(/\.exe$/i, "").toLowerCase() ===
        configured.replace(/\.exe$/i, "").toLowerCase()
      );
    }
    return observed === configured;
  }
  return resolvedBareExecutablePaths(configured).has(
    normalizeExecutablePath(observed),
  );
}

function resolvedBareExecutableTokenMatches(
  observed: string,
  configured: string,
): boolean {
  if (hasPathComponent(configured)) return false;
  const resolved = resolvedBareExecutablePaths(configured);
  if (resolved.size === 0) return false;
  if (hasPathComponent(observed)) {
    return resolved.has(normalizeExecutablePath(observed));
  }
  return executableTokenMatches(observed, configured);
}

const STRICT_SEMVER_PATTERN = new RegExp(
  "^(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)" +
    "(?:-(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)" +
    "(?:\\.(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*))*)?" +
    "(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
);

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
    STRICT_SEMVER_PATTERN.test(version)
  );
}

function matchExecutableAt(
  command: string,
  offset: number,
  configured: string,
  requireResolvedBare = false,
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
    (
      requireResolvedBare
        ? (
            hasPathComponent(configured)
              ? executableTokenMatches(token.value, configured)
              : (
                  hasPathComponent(token.value) &&
                  resolvedBareExecutableTokenMatches(token.value, configured)
                )
          )
        : executableTokenMatches(token.value, configured)
    ) ||
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
): {
  name: string;
  hasAttachedValue: boolean;
  hasNonemptyAttachedValue: boolean;
} {
  for (const shortName of schema.attachedShortValueOptions) {
    if (value.startsWith(shortName) && value.length > shortName.length) {
      return {
        name: shortName,
        hasAttachedValue: true,
        hasNonemptyAttachedValue: true,
      };
    }
  }
  const name = optionName(value);
  const hasAttachedValue = name !== value;
  if (hasAttachedValue) {
    return {
      name,
      hasAttachedValue,
      hasNonemptyAttachedValue: value.length > name.length + 1,
    };
  }
  return {
    name,
    hasAttachedValue: false,
    hasNonemptyAttachedValue: false,
  };
}

function interpreterChildOffset(
  command: string,
  offset: number,
  configured: string,
  schema: InterpreterOptionSchema,
): number | undefined {
  let cursor = offset;
  let enteredPassthrough = false;
  while (true) {
    const executable = matchExecutableAt(
      command,
      cursor,
      configured,
      true,
    );
    if (executable) {
      let start = cursor;
      while (start < command.length && /\s/.test(command[start]!)) start++;
      return start;
    }

    const token = readCommandToken(command, cursor);
    if (!token) return undefined;
    if (schema.passthroughCommands.has(token.value)) {
      if (enteredPassthrough) return undefined;
      enteredPassthrough = true;
      cursor = token.end;
      continue;
    }
    if (token.value === "--") {
      const child = readCommandToken(command, token.end);
      return child && matchExecutableAt(
        command,
        child.start,
        configured,
        true,
      )
        ? child.start
        : undefined;
    }
    if (!token.value.startsWith("-") || token.value === "-") return undefined;

    cursor = token.end;
    const {
      name,
      hasAttachedValue,
      hasNonemptyAttachedValue,
    } = resolveInterpreterOption(token.value, schema);
    if (enteredPassthrough && schema.passthroughOptionsWithValues.has(name)) {
      if (hasAttachedValue) {
        if (!hasNonemptyAttachedValue) return undefined;
        continue;
      }
      const value = readCommandToken(command, cursor);
      if (!value || value.value.startsWith("-")) return undefined;
      cursor = value.end;
      continue;
    }
    if (
      enteredPassthrough &&
      schema.passthroughOptionsWithoutValues.has(name)
    ) {
      if (hasAttachedValue) return undefined;
      continue;
    }
    if (schema.executionModeOptions.has(name)) return undefined;
    if (schema.optionsWithValues.has(name)) {
      if (hasAttachedValue) {
        if (schema.detachedOnlyValueOptions.has(name)) return undefined;
        if (!hasNonemptyAttachedValue) return undefined;
        continue;
      }
      if (schema.attachedOnlyValueOptions.has(name)) return undefined;
      const value = readCommandToken(command, cursor);
      if (!value) return undefined;
      if (
        schema.optionsRejectingOptionValues.has(name) &&
        value.value.startsWith("-")
      ) {
        return undefined;
      }
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

function claudeFastPath(args: string[]): "session" | "control" | undefined {
  if (
    CLAUDE_BRIDGE_COMMANDS.has(args[0] ?? "") ||
    CLAUDE_BACKGROUND_CONTROL_COMMANDS.has(args[0] ?? "")
  ) {
    return "control";
  }
  let index = 0;
  while (CLAUDE_DAEMON_PREFIX_FLAGS.has(args[index] ?? "")) index++;
  if (args[index] === "daemon") return "control";
  if (args.some((arg) => CLAUDE_BACKGROUND_LAUNCHER_FLAGS.has(arg))) {
    return "control";
  }
  return undefined;
}

export function isToolSessionCommand(
  command: string,
  bin: string,
  toolId = commandBasename(bin).toLowerCase().replace(/\.exe$/, ""),
  processExecutable?: string,
  requireKernelAttribution = false,
): boolean {
  const first = readCommandToken(command, 0);
  if (!first) return false;

  let executable = matchExecutableAt(command, first.start, bin);
  if (
    executable &&
    requireKernelAttribution &&
    !processExecutableMatchesDirectTool(
      processExecutable,
      first.value,
      bin,
    )
  ) {
    return false;
  }
  if (!executable) {
    const interpreter = commandBasename(first.value)
      .toLowerCase()
      .replace(/\.exe$/, "");
    if (interpreter !== "node" && interpreter !== "nodejs" && interpreter !== "bun") {
      return false;
    }
    if (!resolvedBareExecutableTokenMatches(first.value, interpreter)) {
      return false;
    }
    if (!processExecutableMatchesInterpreter(processExecutable, interpreter)) {
      return false;
    }
    if (requireKernelAttribution) {
      // The kernel executable proves only Node/Bun itself. Both runtimes allow
      // a same-user process to rewrite argv/process.title after startup, and
      // Linux exposes no durable script identity once the runtime closes it.
      // A live process scan therefore cannot prove the wrapped child and must
      // fail closed instead of trusting mutable command text.
      return false;
    }
    const childOffset = interpreterChildOffset(
      command,
      first.end,
      bin,
      interpreter === "bun" ? BUN_OPTION_SCHEMA : NODE_OPTION_SCHEMA,
    );
    if (childOffset === undefined) return false;
    executable = matchExecutableAt(command, childOffset, bin, true);
  }
  if (!executable) return false;

  if (toolId !== "claude") {
    return true;
  }

  const args = commandArguments(command, executable.end);
  const fastPath = claudeFastPath(args);
  if (fastPath) return fastPath === "session";
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
    if (
      !isToolSessionCommand(
        command,
        bin,
        toolId,
        readProcessExecutable(pid),
        true,
      )
    ) {
      continue;
    }
    const configDir = readProcessEnvVar(pid, tool.envVar);
    out.push({ pid, ppid, command, ...(configDir ? { configDir } : {}) });
  }
  return out;
}

/** Read the kernel-owned executable identity for a process (Linux /proc only). */
function readProcessExecutable(pid: number): string | undefined {
  try {
    return readlinkSync(`/proc/${pid}/exe`) || undefined;
  } catch {
    // Unsupported platform, inaccessible process, or process exited. Wrapper
    // attribution must fail closed when the executable cannot be proven.
    return undefined;
  }
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
