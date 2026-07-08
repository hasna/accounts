import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile } from "./apply.js";
import { prepareClaudeProfileKeychain } from "./claude-auth.js";
import { claudeApiAuthClearingEnv, formatEnvAssignments, formatExportLines, profileEnv } from "./env.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { getTool, mergeToolArgs, normalizePermissionPreset } from "./tools.js";

export type SwitchMode = "auto" | "apply" | "env" | "active";

export interface SwitchOptions {
  tool?: string;
  mode?: SwitchMode;
  resume?: boolean;
  args?: string[];
  permissions?: string;
}

export interface SwitchResult {
  profile: Profile;
  tool: ToolDef;
  applied: boolean;
  active: boolean;
  env: Record<string, string>;
  exports: string;
  command: string[];
  commandLine: string;
  permissions?: string;
  restartRequired: boolean;
  message: string;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(value)) return value;
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function commandLine(env: Record<string, string>, command: string[]): string {
  return `${formatEnvAssignments(env)} ${command.map(shellQuote).join(" ")}`.trim();
}

function commandFor(profile: Profile, tool: ToolDef, opts: SwitchOptions): string[] {
  const args = [...(opts.resume ? (tool.resumeArgs ?? []) : []), ...(opts.args ?? [])];
  return [tool.bin, ...mergeToolArgs(tool, args, { permissions: opts.permissions, profile })];
}

export async function switchProfile(
  name: string,
  opts: SwitchOptions = {},
  store: AccountsStore = resolveStore(),
): Promise<SwitchResult> {
  const profile = await store.getProfile(name, opts.tool);
  const tool = getTool(profile.tool);
  const mode = opts.mode ?? "auto";
  if (!["auto", "apply", "env", "active"].includes(mode)) {
    throw new AccountsError(`invalid switch mode "${mode}"`);
  }
  let applied = false;

  if (mode === "apply" || (mode === "auto" && tool.id === "claude")) {
    await applyProfile(profile.name, tool.id, store);
    applied = true;
  } else {
    await store.useProfile(profile.name, tool.id);
  }

  const env = applied && tool.id === "claude" ? claudeApiAuthClearingEnv() : profileEnv(profile, tool);
  const command = commandFor(profile, tool, opts);
  prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
  const restartRequired = opts.resume === true || applied || mode === "env";
  const message = applied
    ? `${profile.name} is now the live/default ${tool.label} profile`
    : `${profile.name} is now the active ${tool.label} profile`;

  return {
    profile: await store.getProfile(profile.name, tool.id),
    tool,
    applied,
    active: true,
    env,
    exports: formatExportLines(env),
    command,
    commandLine: commandLine(env, command),
    ...(opts.permissions ? { permissions: normalizePermissionPreset(opts.permissions) } : {}),
    restartRequired,
    message,
  };
}
