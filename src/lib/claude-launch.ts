import { randomUUID } from "node:crypto";
import type { ToolDef } from "../types.js";
import { AccountsError } from "../types.js";

export interface ClaudeLaunchOptions {
  headless?: boolean;
  background?: boolean;
  bg?: boolean;
  name?: string;
}

export type ClaudeLaunchMode = "interactive" | "headless" | "background" | "raw-background";

export interface ClaudeLaunchPlan {
  mode: ClaudeLaunchMode;
  args: string[];
  name?: string;
  sessionId?: string;
  nonInteractive: boolean;
}

export interface ClaudeLaunchPlannerOptions {
  sessionId?: () => string;
}

const PRINT_FLAGS = ["-p", "--print"];
const BACKGROUND_FLAGS = ["--bg", "--background"];
const INTERACTIVE_FLAGS = ["-c", "--continue", "-r", "--resume", "--fork-session", "--ide"];

function hasFlag(args: string[], flags: string[]): boolean {
  return args.some((arg) => flags.some((flag) => arg === flag || arg.startsWith(`${flag}=`)));
}

function optionValues(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg.startsWith(`${flag}=`)) {
      const value = arg.slice(flag.length + 1);
      if (!value) throw new AccountsError(`Claude ${flag} requires a value.`);
      values.push(value);
      continue;
    }
    if (arg !== flag) continue;
    const value = args[index + 1];
    if (!value || value.startsWith("-")) throw new AccountsError(`Claude ${flag} requires a value.`);
    values.push(value);
    index++;
  }
  return values;
}

function onlyValue(values: string[], flag: string): string | undefined {
  if (values.length > 1) throw new AccountsError(`Claude ${flag} may be supplied only once.`);
  return values[0];
}

function normalizedName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const name = value.trim();
  if (!name) throw new AccountsError("Claude --name requires a non-empty value.");
  return name;
}

/** Build a deterministic invocation before profile mutation or process launch. */
export function planClaudeLaunch(
  tool: ToolDef,
  rawArgs: string[],
  options: ClaudeLaunchOptions = {},
  planner: ClaudeLaunchPlannerOptions = {},
): ClaudeLaunchPlan {
  const wantsHeadless = options.headless === true;
  const wantsBackground = options.background === true || options.bg === true;
  const wantsName = options.name !== undefined;
  const hasConvenience = wantsHeadless || wantsBackground || wantsName;

  if (!hasConvenience) {
    if (hasFlag(rawArgs, PRINT_FLAGS)) return { mode: "headless", args: [...rawArgs], nonInteractive: true };
    if (hasFlag(rawArgs, BACKGROUND_FLAGS)) return { mode: "raw-background", args: [...rawArgs], nonInteractive: true };
    return { mode: "interactive", args: [...rawArgs], nonInteractive: false };
  }

  if (tool.id !== "claude") {
    throw new AccountsError("--headless, --background/--bg, and --name are supported only with --tool claude.");
  }
  if (options.background && options.bg) {
    throw new AccountsError("Claude --background and --bg are aliases; supply only one.");
  }
  if (wantsHeadless && wantsBackground) {
    throw new AccountsError("Claude --headless cannot be combined with --background/--bg.");
  }

  const rawPrint = hasFlag(rawArgs, PRINT_FLAGS);
  const rawBackground = hasFlag(rawArgs, BACKGROUND_FLAGS);
  const rawInteractive = hasFlag(rawArgs, INTERACTIVE_FLAGS);
  const rawName = onlyValue(optionValues(rawArgs, "--name"), "--name");
  const rawSessionId = onlyValue(optionValues(rawArgs, "--session-id"), "--session-id");

  if (wantsHeadless) {
    if (rawPrint) throw new AccountsError("Claude --headless duplicates raw -p/--print; choose convenience or passthrough syntax.");
    if (rawBackground) throw new AccountsError("Claude --headless cannot be combined with raw --background/--bg.");
    if (rawInteractive) throw new AccountsError("Claude --headless cannot be combined with interactive resume/continue/fork/IDE flags.");
    if (wantsName || rawName) throw new AccountsError("Claude --name is supported only with --background/--bg.");
    return {
      mode: "headless",
      args: ["-p", ...rawArgs],
      ...(rawSessionId ? { sessionId: rawSessionId } : {}),
      nonInteractive: true,
    };
  }

  if (!wantsBackground) throw new AccountsError("Claude --name requires --background or --bg.");
  if (rawPrint) throw new AccountsError("Claude --background/--bg cannot be combined with raw -p/--print.");
  if (rawBackground) throw new AccountsError("Claude --background/--bg duplicates a raw background flag; choose convenience or passthrough syntax.");
  if (rawInteractive) throw new AccountsError("Claude --background/--bg cannot be combined with interactive resume/continue/fork/IDE flags.");
  if (wantsName && rawName) {
    throw new AccountsError("Claude --name cannot be supplied both as an accounts option and a raw passthrough flag.");
  }

  const name = normalizedName(options.name) ?? rawName;
  const sessionId = rawSessionId ?? (planner.sessionId ?? randomUUID)();
  const args = rawSessionId ? [...rawArgs] : ["--session-id", sessionId, ...rawArgs];
  return {
    mode: "background",
    args,
    ...(name ? { name } : {}),
    sessionId,
    nonInteractive: true,
  };
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
