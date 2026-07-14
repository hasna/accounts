import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { platform } from "node:os";
import type { Profile } from "../types.js";
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

export type ProcessScanner = () => ProcessInfo[];

/**
 * Extract the first top-level JSON array from output that may be wrapped in
 * pty/ANSI noise (`claude agents --json` only works on a TTY, so we run it
 * under `script` and the JSON arrives surrounded by control sequences).
 */
export function extractJsonArray(raw: string): unknown[] | undefined {
  const text = raw.replace(/\r/g, "");
  for (let start = text.indexOf("["); start !== -1; start = text.indexOf("[", start + 1)) {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === "[") depth++;
      else if (ch === "]") {
        depth--;
        if (depth === 0) {
          try {
            const parsed = JSON.parse(text.slice(start, i + 1)) as unknown;
            if (Array.isArray(parsed)) return parsed;
          } catch {
            /* not valid JSON from this bracket — try the next candidate */
          }
          break;
        }
      }
    }
  }
  return undefined;
}

/**
 * Run `<bin> agents --json` for a profile's config dir under a pseudo-TTY.
 * Claude Code switches to print-mode argument parsing when stdout is not a
 * TTY and never reaches the `agents` subcommand, so a plain pipe won't work.
 */
export function runClaudeAgentsJson(profile: ProfileLike, timeoutMs = 20_000): AgentsRunnerResult {
  const tool = getTool(profile.tool);
  const bin = tool.bin ?? "claude";
  const env = { ...process.env, [tool.envVar]: profile.dir };
  const args =
    platform() === "darwin"
      ? ["-q", "/dev/null", bin, "agents", "--json"]
      : ["-qefc", `${bin} agents --json`, "/dev/null"];
  const res = spawnSync("script", args, {
    encoding: "utf8",
    env,
    timeout: timeoutMs,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (res.error) return { ok: false, raw: "", error: res.error.message };
  if (res.signal) return { ok: false, raw: res.stdout ?? "", error: `timed out (${res.signal})` };
  if (res.status !== 0) {
    const detail = (res.stderr || res.stdout || "").trim().split("\n").pop() ?? "";
    return { ok: false, raw: res.stdout ?? "", error: `exit ${res.status}${detail ? `: ${detail}` : ""}` };
  }
  return { ok: true, raw: res.stdout ?? "" };
}

/**
 * True when a `ps` command line looks like a real agent session process for
 * the tool — not a daemon, pty host, pre-warmed spare, shell snapshot, our
 * own `agents` listing invocation, or an `accounts` wrapper.
 */
export function isToolSessionCommand(command: string, bin: string): boolean {
  const argv = command.trim().split(/\s+/);
  if (argv.length === 0) return false;
  const base = (p: string) => p.split("/").pop() ?? p;

  let head = argv[0] ?? "";
  let rest = argv.slice(1);
  // unwrap interpreter wrappers: `node /path/to/bin/claude ...`
  if ((base(head) === "node" || base(head) === "bun") && rest[0]) {
    head = rest[0]!;
    rest = rest.slice(1);
  }
  // versioned native builds live under .../<bin>/versions/<semver>
  const isVersionedBuild = head.includes(`/${bin}/versions/`);
  if (base(head) !== bin && !isVersionedBuild) return false;

  if (rest[0] === "agents") return false; // our own listing call
  const joined = rest.join(" ");
  if (/--bg-pty-host|--bg-spare/.test(joined)) return false; // daemon helpers
  if (rest[0] === "daemon") return false;
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

    for (const a of parsed as AgentEntry[]) {
      if (typeof a.pid === "number") reported.add(a.pid);
    }
    const agents = (parsed as AgentEntry[]).filter(
      (a) => !opts.backgroundOnly || a.kind === "background",
    );
    return { ...base, agents };
  });

  // Cross-check daemon listings against actually-running processes; anything
  // the daemons don't report (e.g. headless loops on stale daemons) is shown
  // rather than silently dropped. Skipped when filtering to one profile.
  if (!opts.profile) {
    const scanner = opts.processScanner ?? scanToolProcesses;
    const scanned = scanner();
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
