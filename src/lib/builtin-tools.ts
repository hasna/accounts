// Built-in tool table — a LEAF module.
//
// Extracted from tools.ts so that modules needing only the tool table (notably
// the profile-dir policy, which the cloud server's request schemas import) do
// not pull in storage.ts and the rest of the local CLI surface. tools.ts
// re-exports BUILTIN_TOOLS, so this move is invisible to existing callers.

import { homedir } from "node:os";
import { join } from "node:path";
import type { ToolDef } from "../types.js";

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
    // Measured on Claude Code 2.1.220: the user-scope skill root is
    // `<CLAUDE_CONFIG_DIR>/skills` and the subagent root is
    // `<CLAUDE_CONFIG_DIR>/agents`, so a profile with an empty config dir has
    // neither.
    //
    // `rules`/`CLAUDE.md` are NOT handled here and the current arrangement is
    // not by design: memory is discovered by walking the working directory's
    // ancestors, so a copy inside a config dir would be inert, and the shared
    // files load today only because the working directory happens to sit under
    // the home dir that contains them. A cwd outside it loses them silently.
    sharedEntries: ["skills", "agents"],
    // Also measured: user-scope MCP servers are read only from
    // `<CLAUDE_CONFIG_DIR>/.claude.json`; `settings.json` and `mcp.json` inside
    // the config dir are not consulted. That file also holds OAuth state, so it
    // is merged rather than linked.
    //
    // The account file is read at runtime but is not necessarily the rendered
    // one — on a machine whose config is templated it can carry unsubstituted
    // `{{PLACEHOLDER}}` commands. Rendered files are listed first so their
    // definitions win, and placeholder-bearing members are dropped entirely.
    sharedConfig: {
      target: ".claude.json",
      sources: ["settings.json", "mcp.json", "../.claude.json"],
      keys: ["mcpServers"],
      // A vault-retrieval server is the closest thing to sharing tokens without
      // literally doing so; the user drew the line at "only tokens should not".
      exclude: ["secrets"],
    },
    // Measured on this machine: transcripts live at
    // `<CLAUDE_CONFIG_DIR>/projects/<encoded-cwd>/<sessionId>.jsonl`, with
    // subagent transcripts and per-project memory nested beneath the same root,
    // and the prompt history at `<CLAUDE_CONFIG_DIR>/history.jsonl`.
    //
    // `sessions/` is NOT listed and must not be: it holds one file per running
    // process (`<pid>.json` with a status heartbeat and `peerProtocol`), so
    // sharing it would show every profile the other profiles' live processes as
    // its own peers, and each instance reaps entries whose PID it believes to be
    // dead. Nothing is lost by keeping it per-profile — a finished session's
    // durable record is the transcript under `projects/`.
    sessions: { transcripts: "projects", history: "history.jsonl" },
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
    // Codewith owns its own profile directories; the accounts registry records
    // them where they already live rather than moving them.
    nativeProfilesDir: "auth_profiles",
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
