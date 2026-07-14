import { execFileSync, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, extname, isAbsolute, join } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { claudeKeychainCredentialFromProfile } from "./claude-auth.js";
import { CLAUDE_KEYCHAIN_SERVICE } from "./claude-layout.js";
import {
  captureClaudeKeychain,
  keychainSupported,
  securityExecutable,
  writeClaudeKeychain,
} from "./keychain.js";

export interface ClaudeLaunchOptions {
  headless?: boolean;
  background?: boolean;
  bg?: boolean;
  name?: string;
}

export type ClaudeLaunchMode = "interactive" | "headless" | "background";

export interface ClaudeLaunchPlan {
  mode: ClaudeLaunchMode;
  args: string[];
  nonInteractive: boolean;
}

const PRINT_FLAGS = ["-p", "--print"];
const BACKGROUND_FLAGS = ["--bg", "--background"];
const NAME_FLAGS = ["--name", "-n"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_NAME_LENGTH = 128;

function countBooleanFlags(args: string[], flags: string[], label: string): number {
  let count = 0;
  for (const arg of args) {
    if (flags.includes(arg)) count += 1;
    else if (flags.some((flag) => arg.startsWith(`${flag}=`))) {
      throw new AccountsError(`Claude ${label} does not take a value.`);
    }
  }
  return count;
}

function optionValues(args: string[], flags: string[], label: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    const equalsFlag = flags.find((flag) => arg.startsWith(`${flag}=`));
    if (equalsFlag) {
      const value = arg.slice(equalsFlag.length + 1);
      if (!value) throw new AccountsError(`Claude ${label} requires a value.`);
      values.push(value);
      continue;
    }
    const attachedShort = flags.find(
      (flag) => flag.length === 2 && arg.startsWith(flag) && arg.length > flag.length,
    );
    if (attachedShort) {
      values.push(arg.slice(attachedShort.length));
      continue;
    }
    if (!flags.includes(arg)) continue;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("-")) {
      throw new AccountsError(`Claude ${label} requires a value.`);
    }
    values.push(value);
    index += 1;
  }
  return values;
}

function onlyValue(values: string[], label: string): string | undefined {
  if (values.length > 1) throw new AccountsError(`Claude ${label} may be supplied only once.`);
  return values[0];
}

function validateName(value: string): string {
  if (!value || value.trim() !== value) {
    throw new AccountsError("Claude --name must be non-empty without leading or trailing whitespace.");
  }
  if ([...value].length > MAX_NAME_LENGTH) {
    throw new AccountsError(`Claude --name must be at most ${MAX_NAME_LENGTH} characters.`);
  }
  if (/\p{C}/u.test(value)) {
    throw new AccountsError("Claude --name must not contain control or format characters.");
  }
  return value;
}

function validateSessionId(value: string | undefined): void {
  if (value !== undefined && !UUID_RE.test(value)) {
    throw new AccountsError("Claude --session-id must be a valid UUID.");
  }
}

/** Build the complete Claude argv before prelaunch, profile mutation, or keychain access. */
export function planClaudeLaunch(
  tool: ToolDef,
  rawArgs: string[],
  options: ClaudeLaunchOptions = {},
): ClaudeLaunchPlan {
  const wantsHeadless = options.headless === true;
  const wantsBackground = options.background === true || options.bg === true;
  const wantsName = options.name !== undefined;
  const hasConvenience = wantsHeadless || wantsBackground || wantsName;

  if (tool.id !== "claude") {
    if (hasConvenience) {
      throw new AccountsError("--headless, --background/--bg, and --name are supported only with --tool claude.");
    }
    return { mode: "interactive", args: [...rawArgs], nonInteractive: false };
  }

  if (options.background && options.bg) {
    throw new AccountsError("Claude --background and --bg are aliases; supply only one.");
  }
  if (wantsHeadless && wantsBackground) {
    throw new AccountsError("Claude --headless cannot be combined with --background/--bg.");
  }

  const rawPrintCount = countBooleanFlags(rawArgs, PRINT_FLAGS, "-p/--print");
  const rawBackgroundCount = countBooleanFlags(rawArgs, BACKGROUND_FLAGS, "--bg/--background");
  if (rawPrintCount > 1) throw new AccountsError("Claude -p/--print may be supplied only once.");
  if (rawBackgroundCount > 1) throw new AccountsError("Claude --bg/--background may be supplied only once.");

  const rawName = onlyValue(optionValues(rawArgs, NAME_FLAGS, "--name/-n"), "--name/-n");
  const rawSessionId = onlyValue(optionValues(rawArgs, ["--session-id"], "--session-id"), "--session-id");
  if (rawName !== undefined) validateName(rawName);
  validateSessionId(rawSessionId);

  const rawPrint = rawPrintCount === 1;
  const rawBackground = rawBackgroundCount === 1;
  if (rawPrint && rawBackground) {
    throw new AccountsError("Claude --bg/--background cannot be combined with -p/--print.");
  }
  if (wantsHeadless && rawPrint) {
    throw new AccountsError("Claude --headless duplicates raw -p/--print.");
  }
  if (wantsHeadless && rawBackground) {
    throw new AccountsError("Claude --headless cannot be combined with raw --bg/--background.");
  }
  if (wantsBackground && rawBackground) {
    throw new AccountsError("Claude --background/--bg duplicates a raw background flag.");
  }
  if (wantsBackground && rawPrint) {
    throw new AccountsError("Claude --background/--bg cannot be combined with raw -p/--print.");
  }
  if (wantsName && rawName !== undefined) {
    throw new AccountsError("Claude --name cannot be supplied as both an Accounts option and a raw flag.");
  }

  const convenienceName = options.name === undefined ? undefined : validateName(options.name);
  const background = wantsBackground || rawBackground;
  if (convenienceName !== undefined && !background) {
    throw new AccountsError("Claude --name requires --background/--bg.");
  }

  if (wantsHeadless) return { mode: "headless", args: ["-p", ...rawArgs], nonInteractive: true };
  if (wantsBackground) {
    return {
      mode: "background",
      args: ["--bg", ...(convenienceName ? ["--name", convenienceName] : []), ...rawArgs],
      nonInteractive: true,
    };
  }
  if (rawBackground && convenienceName) {
    const index = rawArgs.findIndex((arg) => BACKGROUND_FLAGS.includes(arg));
    const args = [...rawArgs];
    args.splice(index + 1, 0, "--name", convenienceName);
    return { mode: "background", args, nonInteractive: true };
  }
  if (rawBackground) return { mode: "background", args: [...rawArgs], nonInteractive: true };
  if (rawPrint) return { mode: "headless", args: [...rawArgs], nonInteractive: true };
  return { mode: "interactive", args: [...rawArgs], nonInteractive: false };
}

const SECRET_VALUE_FLAG = /(?:api[-_]?key|auth(?:orization)?|credential|password|secret|token)$/i;
const SECRET_PATTERN = /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[oprsu]_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b/g;

export function redactText(value: string): string {
  return value.replace(SECRET_PATTERN, "[REDACTED]");
}

export function redactArgv(argv: string[]): string[] {
  const redacted: string[] = [];
  let redactNext = false;
  for (const arg of argv) {
    if (redactNext) {
      redacted.push("[REDACTED]");
      redactNext = false;
      continue;
    }
    const equals = arg.indexOf("=");
    if (equals > 0 && SECRET_VALUE_FLAG.test(arg.slice(0, equals).replace(/^--?/, ""))) {
      redacted.push(`${arg.slice(0, equals + 1)}[REDACTED]`);
      continue;
    }
    redacted.push(redactText(arg));
    if (SECRET_VALUE_FLAG.test(arg.replace(/^--?/, ""))) redactNext = true;
  }
  return redacted;
}

function numericTestSetting(name: string, fallback: number): number {
  if (process.env.NODE_ENV !== "test") return fallback;
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function keychainLockPath(): string {
  if (process.env.NODE_ENV === "test" && process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH) {
    return process.env.ACCOUNTS_TEST_KEYCHAIN_LOCK_PATH;
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  return join(tmpdir(), `accounts-claude-keychain-${uid}.lock`);
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function acquireKeychainLock(): Promise<() => void> {
  const path = keychainLockPath();
  const token = `${process.pid}:${randomUUID()}`;
  const deadline = Date.now() + numericTestSetting("ACCOUNTS_TEST_KEYCHAIN_LOCK_TIMEOUT_MS", 600_000);

  while (true) {
    try {
      const fd = openSync(path, "wx", 0o600);
      try {
        writeFileSync(fd, token, { encoding: "utf8" });
      } finally {
        closeSync(fd);
      }
      return () => {
        try {
          if (readFileSync(path, "utf8") === token) unlinkSync(path);
        } catch {
          // A missing lock is already released; a replaced lock belongs to another process.
        }
      };
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
      if (code !== "EEXIST") throw new AccountsError(`failed to acquire Claude keychain lock: ${redactText(String(error))}`);
    }

    try {
      const owner = Number(readFileSync(path, "utf8").split(":", 1)[0]);
      if (Number.isInteger(owner) && owner > 0 && !processAlive(owner)) unlinkSync(path);
    } catch {
      // The owner may have released the lock between open attempts.
    }
    if (Date.now() >= deadline) throw new AccountsError("timed out waiting for the Claude keychain lock");
    await sleep(25);
  }
}

function clearClaudeKeychain(): void {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      execFileSync(securityExecutable(), ["delete-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE], {
        stdio: "ignore",
      });
    } catch (error) {
      const status = error && typeof error === "object" && "status" in error
        ? Number((error as { status?: unknown }).status)
        : undefined;
      if (status === 44) return;
      if (captureClaudeKeychain() === undefined) return;
      throw new AccountsError("keychain restore failed after Claude launch");
    }
  }
  throw new AccountsError("keychain restore found too many Claude credential entries");
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (signal === "SIGINT") return 130;
  if (signal === "SIGTERM") return 143;
  return signal ? 1 : 0;
}

function resolveExecutable(bin: string, env: NodeJS.ProcessEnv): string {
  if (process.platform !== "win32" || isAbsolute(bin) || /[\\/]/.test(bin)) return bin;
  const envValue = (name: string): string | undefined => {
    const key = Object.keys(env).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? env[key] : undefined;
  };
  const extensions = extname(bin)
    ? [""]
    : (envValue("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  for (const entry of (envValue("PATH") ?? "").split(delimiter)) {
    const directory = entry.replace(/^"(.*)"$/, "$1");
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = join(directory, `${bin}${extension.toLowerCase()}`);
      if (existsSync(candidate)) return candidate;
      const upperCandidate = join(directory, `${bin}${extension.toUpperCase()}`);
      if (existsSync(upperCandidate)) return upperCandidate;
    }
  }
  return bin;
}

async function relayProcess(tool: ToolDef, args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const child = spawn(resolveExecutable(tool.bin, env), args, { cwd, env, stdio: "inherit" });
    let forwardedSignal: NodeJS.Signals | undefined;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    const forward = (signal: NodeJS.Signals) => {
      if (forwardedSignal) return;
      forwardedSignal = signal;
      child.kill(signal);
      killTimer = setTimeout(() => child.kill("SIGKILL"), numericTestSetting("ACCOUNTS_TEST_CHILD_KILL_TIMEOUT_MS", 2_500));
      killTimer.unref();
    };
    const onSigint = () => forward("SIGINT");
    const onSigterm = () => forward("SIGTERM");
    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);

    const cleanup = () => {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
      if (killTimer) clearTimeout(killTimer);
    };
    child.once("error", (error) => {
      cleanup();
      reject(new AccountsError(`failed to launch ${tool.bin}: ${redactText(error.message)}`));
    });
    child.once("exit", (code, signal) => {
      cleanup();
      resolve(forwardedSignal ? signalExitCode(forwardedSignal) : (code ?? signalExitCode(signal)));
    });
  });
}

/** Relay a launch directly to Claude, leasing the global keychain only when the profile needs it. */
export async function runClaudeLaunch(
  profile: Profile,
  tool: ToolDef,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
): Promise<number> {
  if (tool.id !== "claude" || !keychainSupported()) return relayProcess(tool, args, env, cwd);
  const credential = claudeKeychainCredentialFromProfile(profile.dir, profile.name);
  if (!credential) return relayProcess(tool, args, env, cwd);

  const release = await acquireKeychainLock();
  let pendingSignal: NodeJS.Signals | undefined;
  const rememberSigint = () => { pendingSignal ??= "SIGINT"; };
  const rememberSigterm = () => { pendingSignal ??= "SIGTERM"; };
  process.once("SIGINT", rememberSigint);
  process.once("SIGTERM", rememberSigterm);
  let prior: ReturnType<typeof captureClaudeKeychain>;
  let keychainTouched = false;
  try {
    prior = captureClaudeKeychain();
    keychainTouched = true;
    writeClaudeKeychain(credential);
    const code = await relayProcess(tool, args, env, cwd);
    return pendingSignal ? signalExitCode(pendingSignal) : code;
  } finally {
    try {
      if (keychainTouched) {
        if (prior) writeClaudeKeychain(prior);
        else clearClaudeKeychain();
      }
    } finally {
      process.removeListener("SIGINT", rememberSigint);
      process.removeListener("SIGTERM", rememberSigterm);
      release();
    }
  }
}
