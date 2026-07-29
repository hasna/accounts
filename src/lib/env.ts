import type { Profile, ToolDef } from "../types.js";
import {
  CLAUDE_API_AUTH_ENV_KEYS,
  healSwitchedProfileDir,
  recoverParkedCredential,
  sanitizeClaudeProfileApiSettings,
} from "./claude-auth.js";
import { ensureCodexAppProfileConfig } from "./codex-app.js";
import { ensureSharedCapabilities } from "./shared-capabilities.js";

function renderTemplate(value: string, profile: Profile): string {
  return value.replaceAll("{profileDir}", profile.dir).replaceAll("{profileName}", profile.name).replaceAll("{toolId}", profile.tool);
}

export function profileEnv(profile: Profile, tool: ToolDef): Record<string, string> {
  const env: Record<string, string> = {
    [tool.envVar]: profile.dir,
  };
  for (const [name, value] of Object.entries(tool.extraEnv ?? {})) {
    env[name] = renderTemplate(value, profile);
  }
  // Every launch surface goes through here, so profiles created before shared
  // capabilities existed are repaired the next time they are used.
  ensureSharedCapabilities(profile.dir, tool);
  if (tool.id === "claude") {
    // A dir whose own credential was rotated away by another copy of the same
    // account has parked material nothing else reaches — put it back before the
    // launch, so the session starts with a working credential instead of a
    // blank one. Runs BEFORE the switched-away heal because it refuses the
    // identity-changing case outright, leaving that to the function below.
    recoverParkedCredential(profile.dir, tool, profile.name);
    // A dir left switched to another account by `switch-account` must not
    // launch as that other account: restore the profile's own auth (or refuse
    // loudly while live sessions still use the dir).
    healSwitchedProfileDir(profile.dir, tool, profile.name);
    sanitizeClaudeProfileApiSettings(profile.dir, tool);
    for (const key of CLAUDE_API_AUTH_ENV_KEYS) env[key] = "";
  }
  if (tool.id === "codex-app") ensureCodexAppProfileConfig(profile.dir);
  return env;
}

export function claudeApiAuthClearingEnv(): Record<string, string> {
  return Object.fromEntries(CLAUDE_API_AUTH_ENV_KEYS.map((key) => [key, ""]));
}

export function formatEnvAssignments(env: Record<string, string>): string {
  return Object.entries(env)
    .map(([name, value]) => `${name}=${JSON.stringify(value)}`)
    .join(" ");
}

export function formatExportLines(env: Record<string, string>): string {
  return Object.entries(env)
    .map(([name, value]) => `export ${name}=${JSON.stringify(value)}`)
    .join("\n");
}
