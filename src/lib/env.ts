import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  CLAUDE_API_AUTH_ENV_KEYS,
  healSwitchedProfileDir,
  recoverParkedCredential,
  sanitizeClaudeProfileApiSettings,
} from "./claude-auth.js";
import { convergeDirCredential } from "./credential-broker.js";
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
const PORTABLE_ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

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

function assertPortableEnvName(name: string): void {
  if (!PORTABLE_ENV_NAME_PATTERN.test(name)) {
    throw new AccountsError(`invalid environment variable name "${name}" for POSIX shell handoff`);
  }
}

/**
 * Serialize one POSIX shell word without expansion. Single quotes preserve
 * spaces, newlines, backslashes, dollars, backticks, and leading hyphens; the
 * close/quoted-quote/reopen sequence handles embedded single quotes.
 */
export function quotePosixShellWord(value: string): string {
  if (value.includes("\0")) {
    throw new AccountsError("POSIX shell handoffs cannot represent NUL bytes");
  }
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function shellEnvEntries(env: Record<string, string>): Array<[string, string]> {
  return Object.entries(env).map(([name, value]) => {
    assertPortableEnvName(name);
    return [name, value];
  });
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
    // A dir whose own credential was rotated away by another copy of the same
    // account has parked material nothing else reaches — put it back before the
    // launch, so the session starts with a working credential instead of a
    // blank one. Runs BEFORE the switched-away heal because it refuses the
    // identity-changing case outright, leaving that to the function below.
    const recovery = recoverParkedCredential(profile.dir, tool, profile.name);
    // b29f5b6c: the launched session reads an EMPTY (logged-out) root while
    // `login`/`usage` report logged-in. The empty root is Claude Code's own
    // `rotated-away` blank, written in place after a DUPLICATE live copy of this
    // same account rotated the refresh token out. `recoverParkedCredential`
    // above then REFUSES to restore the intact parked copy with
    // `account-live-elsewhere` — because a blind restore of a possibly-superseded
    // PREDECESSOR credential, while the account is live in another dir, would put
    // two DIFFERENT tokens on disk and the next refresh would revoke one
    // (defect bb267228). That refusal is correct for a restore, but it leaves the
    // dir logged-out.
    //
    // The safe heal for a dir that legitimately holds its OWN account is
    // CONVERGENCE, not restore. `convergeDirCredential` is pure file I/O (no
    // token exchange) that fans the CURRENT WINNING credential — the freshest
    // copy across the central store, the profile snapshots, and every live dir,
    // which includes the still-valid copy that is live elsewhere — into every
    // copy, so all dirs end holding the SAME token. It never introduces a second,
    // superseded token, so it cannot cause the double-refresh revocation the
    // restore refusal guards against, and it re-checks each dir's occupant
    // identity (and, since #99, its content binding) at write time.
    //
    // NARROWED TO LEGITIMATE DUPLICATE DOORS ONLY, and this condition is
    // load-bearing rather than defensive. `account-live-elsewhere` covers two
    // shapes that "the account is running somewhere else" does not distinguish:
    // another dir that OWNS this account and is running it, and a dir owned by a
    // DIFFERENT account that is merely carrying this one after an in-place
    // switch. Converging through the second one sources and fans a credential
    // across a custody boundary the squatted dir's real owner never consented
    // to — the class of write the bb267228 gate exists to prevent, which
    // `src/repair-auth-gates.test.ts` ("a blanket launch cannot create the
    // second copy") asserts a launch must not perform. So a single guest door
    // anywhere in the live set stops the heal; `liveElsewhereAllOwnDoors` is
    // `every` over a non-empty list and is consulted with an explicit `=== true`
    // so an absent field can never be read as permission.
    //
    // Best-effort: a launch must never fail on a heal.
    if (recovery.outcome === "account-live-elsewhere" && recovery.liveElsewhereAllOwnDoors === true) {
      try {
        convergeDirCredential(profile.dir, { tool });
      } catch {
        // The session still launches and reaches its own auth error.
      }
    }
    // A dir left switched to another account by `switch-account` must not
    // launch as that other account: restore the profile's own auth (or refuse
    // loudly while live sessions still use the dir).
    healSwitchedProfileDir(profile.dir, tool, profile.name);
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
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env }) as Record<string, string>;
  const unset = requestDebugUnsetKeys(parentEnv).flatMap((name) => {
    assertPortableEnvName(name);
    return ["-u", name];
  });
  return [
    "env",
    ...unset,
    "--",
    ...shellEnvEntries(sanitized).map(([name, value]) => `${name}=${quotePosixShellWord(value)}`),
  ].join(" ");
}

export function formatExportLines(
  env: Record<string, string>,
  parentEnv: NodeJS.ProcessEnv = process.env,
): string {
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env }) as Record<string, string>;
  const unsetKeys = requestDebugUnsetKeys(parentEnv);
  for (const name of unsetKeys) assertPortableEnvName(name);
  return [
    `unset ${unsetKeys.join(" ")}`,
    ...shellEnvEntries(sanitized).map(([name, value]) => `export ${name}=${quotePosixShellWord(value)}`),
  ].join("\n");
}
