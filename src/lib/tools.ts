import { homedir } from "node:os";
import { join } from "node:path";
import { type ToolDef, AccountsError, toolDefSchema } from "../types.js";
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
    defaultDir: join(homedir(), ".claude"),
    bin: "claude",
    loginHint: "run /login inside Claude, then /exit when done",
    resumeArgs: ["--continue"],
    accountFile: ".claude.json",
    emailPath: ["oauthAccount", "emailAddress"],
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
    id: "kimi",
    label: "Kimi Code",
    envVar: "KIMI_CODE_HOME",
    defaultDir: join(homedir(), ".kimi-code"),
    bin: "kimi",
    loginArgs: ["login"],
    loginHint: "complete kimi login for this KIMI_CODE_HOME",
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

const BUILTIN_IDS = new Set(BUILTIN_TOOLS.map((t) => t.id));

export function isBuiltinTool(id: string): boolean {
  return BUILTIN_IDS.has(id);
}

/** All tools: built-ins plus any user-registered ones (custom wins on id clash). */
export function listTools(): ToolDef[] {
  const custom = loadStore().tools;
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
