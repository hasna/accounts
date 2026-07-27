import type { Profile, ToolDef } from "../types.js";
import { CLAUDE_API_AUTH_ENV_KEYS, sanitizeClaudeProfileApiSettings } from "./claude-auth.js";
import { ensureCodexAppProfileConfig } from "./codex-app.js";
import { ensureSharedCapabilities } from "./shared-capabilities.js";

/**
 * Runtime request diagnostics that can print provider request headers or
 * credential-bearing payloads. These are intentionally narrow: provider
 * launches keep the caller's PATH, proxy, TLS, Bedrock, Vertex, and cloud SDK
 * environment because they remain inside the caller's existing trust binding.
 */
export const UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS = [
  "BUN_CONFIG_VERBOSE_FETCH",
  "NODE_DEBUG",
  "NODE_DEBUG_NATIVE",
] as const;

const UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEY_SET = new Set(
  UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS.map((name) => name.toLowerCase()),
);

function isUnsafeProviderRequestDebugEnvKey(name: string): boolean {
  return UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEY_SET.has(name.toLowerCase());
}

function removeUnsafeProviderRequestDebugEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  for (const name of Object.keys(env)) {
    if (isUnsafeProviderRequestDebugEnvKey(name)) delete env[name];
  }
  return env;
}

function requestDebugUnsetKeys(parentEnv: NodeJS.ProcessEnv = process.env): string[] {
  const keys: string[] = [...UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS];
  for (const name of Object.keys(parentEnv)) {
    if (isUnsafeProviderRequestDebugEnvKey(name) && !keys.includes(name)) keys.push(name);
  }
  return keys;
}

function renderTemplate(value: string, profile: Profile): string {
  return value.replaceAll("{profileDir}", profile.dir).replaceAll("{profileName}", profile.name).replaceAll("{toolId}", profile.tool);
}

/**
 * Assemble the final environment at the credential-bearing provider boundary.
 * Scrubbing after every overlay prevents a custom tool setting from re-enabling
 * a dangerous inherited diagnostic, including on case-insensitive platforms.
 */
export function providerLaunchEnv(
  parentEnv: NodeJS.ProcessEnv,
  ...overlays: Array<NodeJS.ProcessEnv | Record<string, string>>
): NodeJS.ProcessEnv {
  return removeUnsafeProviderRequestDebugEnv(Object.assign({}, parentEnv, ...overlays));
}

/** A separately named policy for bounded helper processes that capture output. */
export function controlledProbeEnv(
  parentEnv: NodeJS.ProcessEnv = process.env,
  ...overlays: Array<NodeJS.ProcessEnv | Record<string, string>>
): NodeJS.ProcessEnv {
  return providerLaunchEnv(parentEnv, ...overlays);
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
    sanitizeClaudeProfileApiSettings(profile.dir, tool);
    for (const key of CLAUDE_API_AUTH_ENV_KEYS) env[key] = "";
  }
  if (tool.id === "codex-app") ensureCodexAppProfileConfig(profile.dir);
  return removeUnsafeProviderRequestDebugEnv(env) as Record<string, string>;
}

export function claudeApiAuthClearingEnv(): Record<string, string> {
  return Object.fromEntries(CLAUDE_API_AUTH_ENV_KEYS.map((key) => [key, ""]));
}

export function formatEnvAssignments(
  env: Record<string, string>,
  parentEnv: NodeJS.ProcessEnv = process.env,
): string {
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env });
  const unset = requestDebugUnsetKeys(parentEnv).flatMap((name) => ["-u", name]);
  return [
    "env",
    ...unset,
    ...Object.entries(sanitized).map(([name, value]) => `${name}=${JSON.stringify(value)}`),
  ].join(" ");
}

export function formatExportLines(
  env: Record<string, string>,
  parentEnv: NodeJS.ProcessEnv = process.env,
): string {
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env });
  return [
    `unset ${requestDebugUnsetKeys(parentEnv).join(" ")}`,
    ...Object.entries(sanitized).map(([name, value]) => `export ${name}=${JSON.stringify(value)}`),
  ].join("\n");
}
