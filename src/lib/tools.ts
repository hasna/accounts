import { homedir } from "node:os";
import { join } from "node:path";
import { type Profile, type ToolDef, AccountsError, toolDefSchema } from "../types.js";
import { loadStore, saveStore } from "../storage.js";

/**
 * Built-in tools. Users can register more at runtime with `accounts tools add`,
 * which persists them in the store — so the CLI scales to any app that reads a
 * config dir from an environment variable, without a code change.
 */
export const BUILTIN_TOOLS: ToolDef[] = [
  {
    id: "claude",
    label: "Claude Code",
    envVar: "CLAUDE_CONFIG_DIR",
    extraEnv: {
      TELEGRAM_STATE_DIR: "{profileDir}/channels/telegram",
    },
    defaultDir: join(homedir(), ".claude"),
    bin: "claude",
    loginHint: "run /login inside Claude, then /exit when done",
    resumeArgs: ["--continue"],
    permissionArgs: {
      dangerous: ["--dangerously-skip-permissions"],
      "allow-dangerous": ["--allow-dangerously-skip-permissions"],
      bypass: ["--permission-mode", "bypassPermissions"],
      auto: ["--permission-mode", "auto"],
      "accept-edits": ["--permission-mode", "acceptEdits"],
      "dont-ask": ["--permission-mode", "dontAsk"],
      plan: ["--permission-mode", "plan"],
    },
    accountFile: ".claude.json",
    emailPath: ["oauthAccount", "emailAddress"],
  },
  {
    id: "codex-app",
    label: "Codex App",
    envVar: "CODEX_HOME",
    defaultDir: join(homedir(), ".codex"),
    bin: "/Applications/Codex.app/Contents/MacOS/Codex",
    loginHint: "sign in inside Codex.app, then quit the app when the profile is ready",
    launchArgs: ["--user-data-dir={profileDir}/electron-user-data"],
    accountFile: "auth.json",
  },
  {
    id: "codex",
    label: "Codex CLI",
    envVar: "CODEX_HOME",
    defaultDir: join(homedir(), ".codex"),
    bin: "codex",
    loginArgs: ["login"],
    loginHint: "complete the Codex login flow for this CODEX_HOME",
    resumeArgs: ["resume", "--last"],
    permissionArgs: {
      dangerous: ["--dangerously-bypass-approvals-and-sandbox"],
    },
  },
  {
    id: "codewith",
    label: "Codewith",
    envVar: "CODEWITH_HOME",
    extraEnv: {
      CODEX_HOME: "{profileDir}",
    },
    defaultDir: join(homedir(), ".codewith"),
    bin: "codewith",
    loginArgs: ["login"],
    loginHint: "complete Codewith login for this CODEWITH_HOME",
    resumeArgs: ["resume", "--last"],
    permissionArgs: {
      dangerous: ["--dangerously-bypass-approvals-and-sandbox"],
    },
    accountFile: "auth.json",
  },
  {
    id: "takumi",
    label: "Takumi",
    envVar: "TAKUMI_CONFIG_DIR",
    defaultDir: join(homedir(), ".takumi"),
    bin: "takumi",
    loginHint: "complete Takumi auth in this TAKUMI_CONFIG_DIR",
    resumeArgs: ["--continue"],
    permissionArgs: {
      dangerous: ["--dangerously-skip-permissions"],
      "allow-dangerous": ["--allow-dangerously-skip-permissions"],
      bypass: ["--permission-mode", "bypassPermissions"],
      auto: ["--permission-mode", "auto"],
      "accept-edits": ["--permission-mode", "acceptEdits"],
      "dont-ask": ["--permission-mode", "dontAsk"],
      plan: ["--permission-mode", "plan"],
    },
    accountFile: ".claude.json",
    emailPath: ["oauthAccount", "emailAddress"],
  },
  {
    id: "gemini",
    label: "Gemini CLI",
    envVar: "GEMINI_CONFIG_DIR",
    defaultDir: join(homedir(), ".gemini"),
    bin: "gemini",
    loginHint: "complete Gemini auth in this GEMINI_CONFIG_DIR",
    permissionArgs: {
      dangerous: ["--yolo"],
      yolo: ["--yolo"],
      "auto-edit": ["--approval-mode", "auto_edit"],
      plan: ["--approval-mode", "plan"],
    },
  },
  {
    id: "opencode",
    label: "opencode",
    envVar: "OPENCODE_CONFIG_DIR",
    extraEnv: {
      XDG_CONFIG_HOME: "{profileDir}/xdg-config",
      XDG_DATA_HOME: "{profileDir}/xdg-data",
    },
    defaultDir: join(homedir(), ".config", "opencode"),
    bin: "opencode",
    loginArgs: ["auth", "login"],
    loginHint: "complete opencode auth login for this isolated config/data root",
    resumeArgs: ["--continue"],
  },
  {
    id: "cursor",
    label: "Cursor Agent",
    envVar: "CURSOR_CONFIG_DIR",
    defaultDir: join(homedir(), ".cursor"),
    bin: "cursor-agent",
    loginArgs: ["login"],
    loginHint: "complete cursor-agent login for this CURSOR_CONFIG_DIR",
  },
  {
    id: "pi",
    label: "Pi Coding Agent",
    envVar: "PI_CODING_AGENT_HOME",
    defaultDir: join(homedir(), ".pi"),
    bin: "pi",
    loginHint: "complete Pi coding agent auth in this PI_CODING_AGENT_HOME",
  },
  {
    id: "hermes",
    label: "Hermes",
    envVar: "HERMES_HOME",
    defaultDir: join(homedir(), ".hermes"),
    bin: "hermes",
    loginHint: "complete Hermes auth in this HERMES_HOME",
    permissionArgs: {
      dangerous: ["--yolo"],
      yolo: ["--yolo"],
    },
  },
  {
    id: "kimi",
    label: "Kimi Code",
    envVar: "KIMI_CODE_HOME",
    defaultDir: join(homedir(), ".kimi-code"),
    bin: "kimi",
    loginArgs: ["login"],
    loginHint: "complete kimi login for this KIMI_CODE_HOME",
    permissionArgs: {
      dangerous: ["--yolo"],
      yolo: ["--yolo"],
      auto: ["--auto"],
      plan: ["--plan"],
    },
  },
  {
    id: "grok",
    label: "Grok Build",
    envVar: "HOME",
    defaultDir: join(homedir(), ".grok"),
    bin: "grok",
    loginArgs: ["login"],
    loginHint: "complete grok login in this process-scoped HOME; prefer launch/shell over exporting HOME globally",
  },
];

export const DEFAULT_TOOL = "claude";

export interface ToolArgOptions {
  permissions?: string;
  profile?: Profile;
}

export const CLAUDE_DANGEROUS_PERMISSION_ARG = "--dangerously-skip-permissions";
const CLAUDE_PERMISSION_MODE_ARG = "--permission-mode";
const CLAUDE_NATIVE_PERMISSION_MODE_PRESETS = new Map(
  Object.entries(
    BUILTIN_TOOLS.find((tool) => tool.id === "claude")?.permissionArgs ?? {},
  ).flatMap(([preset, args]) =>
    args.length === 2 && args[0] === CLAUDE_PERMISSION_MODE_ARG
      ? [[args[1]!, preset] as const]
      : []
  ),
);

export interface PermissionInputs {
  permissions?: string;
  dangerouslySkipPermissions?: boolean;
  passthroughArgs?: readonly string[];
}

export interface ResolvedPermissionInputs {
  preset?: string;
  args: string[];
}

const PERMISSION_ALIASES = new Map<string, string>([
  ["danger", "dangerous"],
  ["dangerously-skip-permissions", "dangerous"],
  ["skip-permissions", "dangerous"],
  ["skip", "dangerous"],
  ["bypasspermissions", "bypass"],
  ["bypass-permissions", "bypass"],
  ["acceptedits", "accept-edits"],
  ["accept-edit", "accept-edits"],
  ["autoedit", "auto-edit"],
  ["auto-edits", "auto-edit"],
  ["auto_edit", "auto-edit"],
  ["dontask", "dont-ask"],
  ["dont-ask-permissions", "dont-ask"],
]);

export function normalizePermissionPreset(value: string): string {
  const normalized = value.trim().replace(/^--/, "").replaceAll("_", "-").toLowerCase();
  return PERMISSION_ALIASES.get(normalized) ?? normalized;
}

function validateClaudeNativePermissionMode(value: string): void {
  if (CLAUDE_NATIVE_PERMISSION_MODE_PRESETS.has(value)) return;

  const normalizedPreset = normalizePermissionPreset(value);
  const canonical = [...CLAUDE_NATIVE_PERMISSION_MODE_PRESETS.entries()]
    .find(([, preset]) => preset === normalizedPreset)?.[0];
  if (canonical) {
    throw new AccountsError(
      `${CLAUDE_PERMISSION_MODE_ARG} requires the exact canonical Claude mode "${canonical}"`,
    );
  }
  throw new AccountsError(
    `${CLAUDE_PERMISSION_MODE_ARG} requires an exact canonical Claude mode. ` +
    `Supported modes: ${[...CLAUDE_NATIVE_PERMISSION_MODE_PRESETS.keys()].join(", ")}`,
  );
}

/**
 * Validate permission sources before tool selection or any profile mutation.
 * Native Claude pass-through remains supported, but it is one permission
 * source: it cannot be repeated or combined with an Accounts preset/alias.
 */
export function validatePermissionInputs(inputs: PermissionInputs): void {
  const passthroughArgs = inputs.passthroughArgs ?? [];
  const nativeOccurrences = passthroughArgs.filter(
    (arg) => arg === CLAUDE_DANGEROUS_PERMISSION_ARG,
  ).length;
  const passthroughPresetOccurrences = passthroughArgs.filter(
    (arg) => arg === "--permissions" || arg.startsWith("--permissions="),
  ).length;
  if (nativeOccurrences > 1) {
    throw new AccountsError("--permissions may be supplied only once");
  }
  if (passthroughPresetOccurrences > 1) {
    throw new AccountsError("--permissions may be supplied only once");
  }
  if (inputs.dangerouslySkipPermissions && inputs.permissions) {
    throw new AccountsError(`${CLAUDE_DANGEROUS_PERMISSION_ARG} cannot be combined with --permissions`);
  }
  if (inputs.dangerouslySkipPermissions && nativeOccurrences > 0) {
    throw new AccountsError(
      `${CLAUDE_DANGEROUS_PERMISSION_ARG} cannot be supplied both directly and after --`,
    );
  }
  if (inputs.permissions && nativeOccurrences > 0) {
    throw new AccountsError(
      `--permissions cannot be combined with ${CLAUDE_DANGEROUS_PERMISSION_ARG} after --`,
    );
  }
  if (inputs.permissions && passthroughPresetOccurrences > 0) {
    throw new AccountsError("--permissions cannot be supplied both directly and after --");
  }
  if (inputs.dangerouslySkipPermissions && passthroughPresetOccurrences > 0) {
    throw new AccountsError(`${CLAUDE_DANGEROUS_PERMISSION_ARG} cannot be combined with --permissions after --`);
  }
  if (nativeOccurrences > 0 && passthroughPresetOccurrences > 0) {
    throw new AccountsError(
      `${CLAUDE_DANGEROUS_PERMISSION_ARG} cannot be combined with --permissions after --`,
    );
  }
}

/**
 * Treat exact native Claude permission modes as a permission source. Accounts
 * presets accept aliases, but raw Claude argv stays fail-closed so aliases,
 * casing variants, whitespace, and unknown values cannot bypass validation.
 */
function validateClaudePermissionModeInputs(inputs: PermissionInputs): string | undefined {
  const passthroughArgs = inputs.passthroughArgs ?? [];
  const nativeModes: string[] = [];
  for (let index = 0; index < passthroughArgs.length; index += 1) {
    const arg = passthroughArgs[index]!;
    if (arg === CLAUDE_PERMISSION_MODE_ARG) {
      const value = passthroughArgs[index + 1];
      if (!value?.trim() || value.startsWith("-")) {
        throw new AccountsError(`${CLAUDE_PERMISSION_MODE_ARG} requires a value`);
      }
      validateClaudeNativePermissionMode(value);
      nativeModes.push(value);
      index += 1;
      continue;
    }
    if (arg.startsWith(`${CLAUDE_PERMISSION_MODE_ARG}=`)) {
      const value = arg.slice(CLAUDE_PERMISSION_MODE_ARG.length + 1);
      if (!value.trim()) {
        throw new AccountsError(`${CLAUDE_PERMISSION_MODE_ARG} requires a value`);
      }
      validateClaudeNativePermissionMode(value);
      nativeModes.push(value);
    }
  }
  if (nativeModes.length > 1) {
    throw new AccountsError("--permissions may be supplied only once");
  }
  const nativeMode = nativeModes[0];
  if (!nativeMode) return undefined;

  const hasOtherSource =
    Boolean(inputs.permissions) ||
    Boolean(inputs.dangerouslySkipPermissions) ||
    passthroughArgs.some(
      (arg) =>
        arg === CLAUDE_DANGEROUS_PERMISSION_ARG ||
        arg === "--permissions" ||
        arg.startsWith("--permissions="),
    );
  if (hasOtherSource) {
    throw new AccountsError(
      `${CLAUDE_PERMISSION_MODE_ARG} cannot be combined with another permission source`,
    );
  }
  return nativeMode;
}

/** Reject duplicate Accounts/native permission switches directly from argv. */
export function validateRawPermissionInputs(argv: readonly string[]): void {
  let permissionsOccurrences = 0;
  let compatibilityOccurrences = 0;
  for (const arg of argv) {
    if (arg === "--permissions" || arg.startsWith("--permissions=")) {
      permissionsOccurrences += 1;
    }
    if (arg === CLAUDE_DANGEROUS_PERMISSION_ARG) compatibilityOccurrences += 1;
  }
  if (permissionsOccurrences > 1 || compatibilityOccurrences > 1) {
    throw new AccountsError("--permissions may be supplied only once");
  }
}

export function resolvePermissionInputs(
  tool: ToolDef,
  inputs: PermissionInputs,
): ResolvedPermissionInputs {
  validatePermissionInputs(inputs);
  if (tool.id === "claude") validateClaudePermissionModeInputs(inputs);
  const hasNativePassthrough = (inputs.passthroughArgs ?? []).includes(
    CLAUDE_DANGEROUS_PERMISSION_ARG,
  );
  if ((inputs.dangerouslySkipPermissions || hasNativePassthrough) && tool.id !== "claude") {
    throw new AccountsError(
      `${CLAUDE_DANGEROUS_PERMISSION_ARG} is only supported for Claude; ` +
      "use --permissions <preset> for tool-specific modes",
    );
  }
  const requested = inputs.dangerouslySkipPermissions || hasNativePassthrough
    ? "dangerous"
    : inputs.permissions;
  const preset = requested ? normalizePermissionPreset(requested) : undefined;
  return {
    ...(preset ? { preset } : {}),
    args: permissionArgsFor(tool, preset),
  };
}

export function permissionArgsFor(tool: ToolDef, permissions?: string): string[] {
  if (!permissions) return [];
  const preset = normalizePermissionPreset(permissions);
  if (preset === "default" || preset === "none" || preset === "off") return [];
  const args = tool.permissionArgs?.[preset];
  if (!args) {
    const supported = Object.keys(tool.permissionArgs ?? {}).sort();
    const suffix = supported.length > 0 ? ` Supported permissions: ${supported.join(", ")}.` : " No permission presets are configured.";
    throw new AccountsError(`tool "${tool.id}" does not support permissions "${permissions}".${suffix}`);
  }
  return args;
}

function renderToolArg(value: string, profile: Profile): string {
  return value
    .replaceAll("{profileDir}", profile.dir)
    .replaceAll("{profileName}", profile.name)
    .replaceAll("{toolId}", profile.tool);
}

export function launchArgsFor(tool: ToolDef, profile?: Profile): string[] {
  const args = tool.launchArgs ?? [];
  return profile ? args.map((arg) => renderToolArg(arg, profile)) : args;
}

function includesArgVector(args: readonly string[], vector: readonly string[]): boolean {
  if (vector.length === 0) return true;
  for (let index = 0; index <= args.length - vector.length; index += 1) {
    if (vector.every((arg, offset) => args[index + offset] === arg)) return true;
  }
  return false;
}

export function mergeToolArgs(tool: ToolDef, args: string[], opts: ToolArgOptions = {}): string[] {
  const launchArgs = launchArgsFor(tool, opts.profile).filter((arg) => !args.includes(arg));
  const configuredPermissionArgs = permissionArgsFor(tool, opts.permissions);
  let hasConfiguredPermissionArgs = includesArgVector(args, configuredPermissionArgs);
  let claudePermissionMode: string | undefined;
  let configuredClaudePermissionMode: string | undefined;
  if (tool.id === "claude") {
    validatePermissionInputs({ passthroughArgs: args });
    claudePermissionMode = validateClaudePermissionModeInputs({ passthroughArgs: args });
    configuredClaudePermissionMode = validateClaudePermissionModeInputs({
      passthroughArgs: configuredPermissionArgs,
    });
  }
  if (tool.id === "claude" && opts.permissions) {
    const hasEquivalentNativeMode =
      claudePermissionMode !== undefined &&
      configuredClaudePermissionMode !== undefined &&
      claudePermissionMode === configuredClaudePermissionMode;
    hasConfiguredPermissionArgs ||= hasEquivalentNativeMode;
    if (
      configuredPermissionArgs.length > 0 &&
      hasConfiguredPermissionArgs
    ) {
      // Preserve the public helper's compatibility behavior for an explicitly
      // repeated equivalent mode while still rejecting a second native source.
      validatePermissionInputs({ passthroughArgs: args });
      validateClaudePermissionModeInputs({ passthroughArgs: args });
    } else {
      resolvePermissionInputs(tool, {
        permissions: opts.permissions,
        passthroughArgs: args,
      });
    }
  }
  const permissionArgs = hasConfiguredPermissionArgs ? [] : configuredPermissionArgs;
  return [...permissionArgs, ...launchArgs, ...args];
}

const BUILTIN_IDS = new Set(BUILTIN_TOOLS.map((t) => t.id));
let customToolsCache: ToolDef[] | undefined;

export function isBuiltinTool(id: string): boolean {
  return BUILTIN_IDS.has(id);
}

/** All tools: built-ins plus any user-registered ones (custom wins on id clash). */
export function listTools(): ToolDef[] {
  const custom = customToolsCache ?? loadStore().tools;
  const byId = new Map<string, ToolDef>();
  for (const t of BUILTIN_TOOLS) byId.set(t.id, t);
  for (const t of custom) byId.set(t.id, t);
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function getTool(id: string): ToolDef {
  const tool = listTools().find((t) => t.id === id);
  if (!tool) {
    const known = listTools()
      .map((t) => t.id)
      .join(", ");
    throw new AccountsError(`unknown tool "${id}". Supported tools: ${known}`);
  }
  return tool;
}

/** Register (or update) a custom tool, persisted in the store. */
export function addCustomTool(def: ToolDef): ToolDef {
  const parsed = toolDefSchema.safeParse(def);
  if (!parsed.success) {
    throw new AccountsError(parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  }
  const tool = parsed.data;
  if (isBuiltinTool(tool.id)) throw new AccountsError(`"${tool.id}" is a built-in tool and cannot be redefined`);
  const store = loadStore();
  const idx = store.tools.findIndex((t) => t.id === tool.id);
  if (idx === -1) store.tools.push(tool);
  else store.tools[idx] = tool;
  saveStore(store);
  return tool;
}

/**
 * Replace the process-local cache of custom tool definitions. Cloud reads must
 * never create or rewrite accounts.json merely to make synchronous launch/apply
 * helpers aware of a remote tool. ApiStore hydrates this cache before returning
 * a custom-tool profile to machine-local orchestration.
 */
export function setCustomToolsCache(defs: ToolDef[]): void {
  customToolsCache = defs.filter((d) => !isBuiltinTool(d.id)).map((d) => structuredClone(d));
}

/** Clear process-only cloud tool state (primarily for isolated tests). */
export function clearCustomToolsCache(): void {
  customToolsCache = undefined;
}

/** Remove a custom tool. Fails if profiles still reference it. */
export function removeCustomTool(id: string): void {
  if (isBuiltinTool(id)) throw new AccountsError(`"${id}" is a built-in tool and cannot be removed`);
  const store = loadStore();
  const idx = store.tools.findIndex((t) => t.id === id);
  if (idx === -1) throw new AccountsError(`no custom tool "${id}"`);
  const inUse = store.profiles.filter((p) => p.tool === id).map((p) => p.name);
  if (inUse.length > 0) {
    throw new AccountsError(`cannot remove "${id}": still used by profile(s) ${inUse.join(", ")}`);
  }
  store.tools.splice(idx, 1);
  saveStore(store);
}
