import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile } from "./apply.js";
import { prepareClaudeProfileKeychain } from "./claude-auth.js";
import {
  claudeApiAuthClearingEnv,
  formatEnvAssignments,
  formatExportLines,
  profileEnv,
  quotePosixShellWord,
} from "./env.js";
import { ensureSharedCapabilities } from "./shared-capabilities.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  BUILTIN_TOOLS,
  getTool,
  mergeToolArgs,
  normalizePermissionPreset,
} from "./tools.js";
import { redactArgv, redactEnvironment, redactText } from "./redaction.js";

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

export interface PublicSwitchResult {
  schema: "hasna.accounts.switch-output/v1";
  profile: {
    name: string;
    tool: string;
  };
  tool: {
    id: string;
    label: string;
  };
  applied: boolean;
  active: boolean;
  command: string[];
  commandLine: string;
  permissions?: string;
  restartRequired: boolean;
  message: string;
}

function commandLine(env: Record<string, string>, command: string[]): string {
  return `${formatEnvAssignments(env)} ${command.map(quotePosixShellWord).join(" ")}`.trim();
}

/** Return a trusted display label without reflecting caller-controlled custom labels. */
export function publicToolLabel(toolId: string): string {
  return BUILTIN_TOOLS.find((tool) => tool.id === toolId)?.label ?? "Custom tool";
}

export function publicSwitchMessage(
  profileName: string,
  toolLabel: string,
  applied: boolean,
): string {
  return applied
    ? `${profileName} is now the live/default ${toolLabel} profile`
    : `${profileName} is now the active ${toolLabel} profile`;
}

/** Project an internal launch result to the only shape allowed on public output. */
export function publicSwitchResult(result: SwitchResult): PublicSwitchResult {
  const command = redactArgv(result.command);
  const toolLabel = publicToolLabel(result.tool.id);
  return {
    schema: "hasna.accounts.switch-output/v1",
    profile: {
      name: result.profile.name,
      tool: result.profile.tool,
    },
    tool: {
      id: result.tool.id,
      label: toolLabel,
    },
    applied: result.applied,
    active: result.active,
    command,
    commandLine: commandLine(redactEnvironment(result.env), command),
    ...(result.permissions ? { permissions: redactText(result.permissions) } : {}),
    restartRequired: result.restartRequired,
    message: publicSwitchMessage(result.profile.name, toolLabel, result.applied),
  };
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

  // In applied mode the session reads the live home rather than the profile
  // dir, so `profileEnv` is skipped — but the profile dir must still be
  // repaired, or `switch` (the headline way to change profiles) leaves it
  // broken for every later isolated launch.
  ensureSharedCapabilities(profile.dir, tool);
  const env = applied && tool.id === "claude" ? claudeApiAuthClearingEnv() : profileEnv(profile, tool);
  const command = commandFor(profile, tool, opts);
  prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
  const restartRequired = opts.resume === true || applied || mode === "env";
  const message = publicSwitchMessage(
    profile.name,
    publicToolLabel(tool.id),
    applied,
  );

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
