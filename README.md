# @hasna/accounts

> Manage and switch between multiple AI coding tool profiles/accounts on one
> machine — Claude Code, Takumi, Codex CLI, Gemini CLI, opencode, Cursor
> Agent, Pi Coding Agent, Hermes, Kimi Code, Grok Build, and custom tools.

`accounts` is a local-first CLI. Each **profile** is an isolated config directory.
Switch **in the terminal** with `CLAUDE_CONFIG_DIR`, or **in Cursor / VS Code** with
`accounts apply` (syncs auth to live `~/.claude` paths).

- **Isolated profiles** — separate config dirs (skills, settings, sessions). Nothing leaks.
- **Apply mode** — sync OAuth / credentials to live paths for IDEs (Claude-only today).
- **Remembers the email** — auto-detected from `.claude.json` when possible.
- **Multi-tool** — first-class built-ins for Claude, Takumi, Codex, Gemini,
  opencode, Cursor Agent, Pi, Hermes, Kimi Code, and Grok Build; custom tools
  via `accounts tools add`.
- **Per-tool names** — `work` can exist for Claude, Codex, Cursor, etc.; pass
  `--tool` when a bare profile name is ambiguous.
- **Local-first** — registry at `~/.hasna/accounts/`. No network, no telemetry.

## Install

```bash
bun install -g @hasna/accounts
accounts --help
```

Requires Node ≥ 18 (or Bun ≥ 1.0).

## Quick start (two Claude subscriptions)

```bash
# 1. Import your current install (optional)
accounts import main --dir ~/.claude

# 2. Create profiles
accounts add work --email work@company.com
accounts add personal --email me@gmail.com

# 3. Log in once per profile (isolated dir)
accounts login work        # run /login inside Claude, then /exit; accounts auto-applies it
accounts login personal    # same: login, exit; it becomes the live/default account

# 4. Switch
accounts apply work                 # Cursor / VS Code — live ~/.claude auth
accounts apply personal

# Or terminal-only (parallel sessions OK):
accounts launch work
eval "$(accounts env personal)"      # other terminal

# Or supervised: lets MCP switch/restart this Claude process automatically
accounts use work
accounts run claude --resume
accounts switch personal --supervisor   # from another terminal
```

After `accounts login <name>`, `accounts` snapshots the auth Claude wrote,
updates the detected email, and applies that profile to live `~/.claude` paths
automatically. `accounts apply` still refuses profiles without auth so live OAuth
is not wiped.

## Three pointers (active, applied, isolated)

| Pointer / mode | Set by | Meaning |
|----------------|--------|---------|
| **Active** | `accounts use`, `launch`, `pick` | Registry `current` — which profile you intend (terminal + hook) |
| **Applied** | `accounts apply`, `pick` (default) | Registry `applied` — auth on live `~/.claude` (what Cursor sees) |
| **Isolated** | `env`, `launch`, `shell` | Per-process `CLAUDE_CONFIG_DIR`; does not change live disk |

| Mode | Command | Best for |
|------|---------|----------|
| **Isolated** | `accounts launch`, `accounts env`, `accounts shell` | Terminal, two accounts at once |
| **Apply** | `accounts apply <name>` | Cursor, VS Code, single global auth |
| **Picker** | `accounts pick` | Interactive choose; default applies to live paths |

`accounts use` alone does **not** change Cursor — run `accounts apply` for IDE auth.

A child process cannot change your parent shell — use `eval "$(accounts env …)"` or the
[shell hook](docs/hook.md) (terminal `claude` only, not IDE extensions).

Implementation details: [docs/IMPLEMENT.md](docs/IMPLEMENT.md).

## Switching modes (summary)

- **`accounts active`** — prints active profile (`store.current`); scripting.
- **`accounts applied`** — prints applied profile (`store.applied`); scripting.
- **`accounts current`** — human-readable active (+ applied hint) per tool.
- **`accounts list`** — `●` active, `◉` applied, `●◉` when both are the same profile.

## Commands

| Command | Description |
|---------|-------------|
| `accounts add <name>` | Create a profile. `--tool`, `--email`, `--dir`, `--description`. |
| `accounts import [name]` | Import existing config dir (default `~/.claude`). `--copy` for managed copy. |
| `accounts login <name>` | Launch the profile's tool login flow in an isolated profile dir. Use `--tool` only for new or ambiguous profiles. |
| `accounts apply <name>` | Apply profile auth to live Claude paths (requires snapshot; Claude-only). |
| `accounts pick` | Interactive picker; default applies. `--env`, `--no-act`. |
| `accounts switch <name>` | Switch profile and print a restart/resume command. Add `--resume`, `--launch`, or `--permissions <preset>`. Use `--tool` only when ambiguous. |
| `accounts switch <name> --supervisor` | Ask a running `accounts run <tool>` supervisor to restart under that profile. Supports `--permissions <preset>`. |
| `accounts use <name>` | Mark profile active; prints apply/env hints. |
| `accounts list` (`ls`) | List profiles (`●` active, `◉` applied, `●◉` both). |
| `accounts show <name> --tool <tool>` | Profile details including active/applied flags. |
| `accounts current` | Active profile per tool (with applied hint). |
| `accounts active [tool]` | Print active profile name (scripting). |
| `accounts applied [tool]` | Print applied profile name (scripting). |
| `accounts env [name]` | Print one or more `export ...` lines for the profile. Use `--tool` only when ambiguous or when no name is passed. |
| `accounts launch <name>` | Launch tool once with profile env. Supports `--permissions <preset>`. |
| `accounts run <tool> [args...]` | Run a tool under the supervisor so MCP/CLI can switch and restart it. Supports `--permissions <preset>`. |
| `accounts supervisor status [tool]` | Show running supervisors. |
| `accounts supervisor switch <name>` | Switch a running supervisor to another profile. Use `--tool` only when ambiguous. |
| `accounts supervisor stop <tool>` | Stop a running supervisor and its child process. |
| `accounts shell <name>` | Subshell with profile env. |
| `accounts hook install` | Install `claude()` wrapper — see [docs/hook.md](docs/hook.md). |
| `accounts hook uninstall` | Remove hook script. |
| `accounts hook path` | Print hook script path. |
| `accounts agents` | List Claude agent sessions across **all** profiles, the default `~/.claude` dir, and untracked processes (`claude agents` only shows the current account). `--background`, `--profile <name>`, `--json`. |
| `accounts detect <name>` | Re-detect email from config dir. |
| `accounts doctor` | Check registry and dirs (exits 1 on errors). |

See `accounts --help` for `set`, `rename`, `remove`, `tools`, etc.

## Agent / MCP Switching

`accounts` ships a stdio MCP server:

```bash
accounts-mcp
```

Add it to Claude/Codex/opencode/Cursor MCP config as a command server named
`accounts`. It exposes:

- `list_tools`
- `list_profiles`
- `current_profile`
- `switch_profile`

For automatic agent restarts, start the agent through `accounts run`:

```bash
accounts use account001
accounts run claude --resume
```

When `switch_profile` is called from that Claude session, `accounts-mcp` contacts
the supervisor. The supervisor applies/switches the profile, closes the current
Claude process, and restarts it with the selected profile. Claude uses
`claude --continue`; Codex uses `codex resume --last`; opencode uses
`opencode --continue`; custom tools can define `resumeArgs`.

If the agent was not started through `accounts run`, MCP falls back to the safe
handoff behavior and returns a command such as:
`CLAUDE_CONFIG_DIR=... claude --continue`.

Human equivalent:

```bash
accounts switch account001 --resume
accounts switch account001 --resume --launch
accounts switch account001 --resume --permissions dangerous
accounts switch account001 --supervisor
accounts switch codex-work --tool codex --resume
accounts switch ops --tool opencode --resume
```

`--permissions <preset>` maps a permission mode to the tool's own flags. For
example, `--permissions dangerous` launches Claude/Takumi with
`--dangerously-skip-permissions`, Codex with
`--dangerously-bypass-approvals-and-sandbox`, and Gemini/Hermes/Kimi with their
YOLO mode flags. Unsupported tools fail with a list of configured presets.

## Shell hook (optional)

```bash
accounts hook install
# Add to ~/.zshrc or ~/.bashrc:
source "$(accounts hook path)"
```

The wrapper runs `accounts apply` when the **active** profile differs from **applied**,
then invokes the real `claude` binary. Full behavior and footguns: [docs/hook.md](docs/hook.md).

## Storage layout

```
~/.hasna/accounts/
  accounts.json              # registry: profiles, current, applied (mode 600)
  claude-hook.sh             # optional shell wrapper
  supervisors/
    claude.sock              # local control socket for `accounts run claude`
    claude.json              # supervisor pid/profile/command metadata
  profiles/
    claude/<name>/           # managed config dir
    claude/<name>/.accounts-auth/   # auth snapshots for apply mode
      oauth-account.json
      credentials.json       # Linux / file-based auth
      keychain.json          # macOS keychain payload
```

Overrides: `ACCOUNTS_HOME`, `ACCOUNTS_STORE_PATH`.

The native storage API is available from `@hasna/accounts/storage`. It exposes
the local registry paths, snapshot helpers, and optional S3 registry sync for
internal cross-machine use:

```ts
import { getAccountsStorageStatus, storagePush } from "@hasna/accounts/storage";

console.log(getAccountsStorageStatus().local.storePath);
await storagePush();
```

Remote sync uses service-owned S3 env names and only syncs the accounts registry
JSON by default; auth snapshots stay local.

- `HASNA_ACCOUNTS_STORAGE_MODE=local|remote|hybrid`
- `HASNA_ACCOUNTS_S3_BUCKET=hasna-xyz-opensource-accounts-prod`
- `HASNA_ACCOUNTS_S3_PREFIX=accounts/`
- `HASNA_ACCOUNTS_AWS_REGION=us-east-1`

## Supported tools

| Tool | id | Env var | Default dir |
|------|----|---------|-------------|
| Claude Code | `claude` | `CLAUDE_CONFIG_DIR` | `~/.claude` |
| Takumi | `takumi` | `TAKUMI_CONFIG_DIR` | `~/.takumi` |
| Codex CLI | `codex` | `CODEX_HOME` | `~/.codex` |
| Gemini CLI | `gemini` | `GEMINI_CONFIG_DIR` | `~/.gemini` |
| opencode | `opencode` | `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` | `~/.config/opencode` |
| Cursor Agent | `cursor` | `CURSOR_CONFIG_DIR` | `~/.cursor` |
| Pi Coding Agent | `pi` | `PI_CODING_AGENT_HOME` | `~/.pi` |
| Hermes | `hermes` | `HERMES_HOME` | `~/.hermes` |
| Kimi Code | `kimi` | `KIMI_CODE_HOME` | `~/.kimi-code` |
| Grok Build | `grok` | `HOME` (process-scoped) | `~/.grok` |

`apply` is **Claude-only** today. Use `launch` / `env` for other tools.
For Grok Build, prefer `accounts launch` or `accounts shell`; exporting `HOME`
globally is intentionally not recommended.

Custom tools can join supervised resume switching with `accounts tools add ... --resume-arg <arg>`.
They can also define permission presets with `--permission-arg preset=--flag`.

## Library

```ts
import { addProfile, applyProfile, importProfile } from "@hasna/accounts";
```

## License

Apache-2.0 © Andrei Hasna
