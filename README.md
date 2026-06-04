# @hasna/accounts

> Manage and switch between multiple AI coding tool profiles/accounts on one
> machine — Claude Code, Codex CLI, opencode, Cursor Agent, Kimi Code, Grok
> Build, and custom tools.

`accounts` is a local-first CLI. Each **profile** is an isolated config directory.
Switch **in the terminal** with `CLAUDE_CONFIG_DIR`, or **in Cursor / VS Code** with
`accounts apply` (syncs auth to live `~/.claude` paths).

- **Isolated profiles** — separate config dirs (skills, settings, sessions). Nothing leaks.
- **Apply mode** — sync OAuth / credentials to live paths for IDEs (Claude-only today).
- **Remembers the email** — auto-detected from `.claude.json` when possible.
- **Multi-tool** — first-class built-ins for Claude, Codex, opencode, Cursor Agent,
  Kimi Code, and Grok Build; custom tools via `accounts tools add`.
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
accounts apply work --tool claude   # Cursor / VS Code — live ~/.claude auth
accounts apply personal

# Or terminal-only (parallel sessions OK):
accounts launch work --tool claude
eval "$(accounts env personal --tool claude)"   # other terminal
```

After `accounts login <name> --tool claude`, `accounts` snapshots the auth Claude
wrote, updates the detected email, and applies that profile to live `~/.claude`
paths automatically. `accounts apply` still refuses profiles without auth so live
OAuth is not wiped.

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
| `accounts login <name> --tool <tool>` | Launch the tool's login flow in an isolated profile dir. |
| `accounts apply <name> --tool claude` | Apply profile auth to live Claude paths (requires snapshot; Claude-only). |
| `accounts pick` | Interactive picker; default applies. `--env`, `--no-act`. |
| `accounts switch <name> --tool <tool>` | Switch profile and print a restart/resume command. Add `--resume`; add `--launch` to run it. |
| `accounts use <name> --tool <tool>` | Mark profile active; prints apply/env hints. |
| `accounts list` (`ls`) | List profiles (`●` active, `◉` applied, `●◉` both). |
| `accounts show <name> --tool <tool>` | Profile details including active/applied flags. |
| `accounts current` | Active profile per tool (with applied hint). |
| `accounts active [tool]` | Print active profile name (scripting). |
| `accounts applied [tool]` | Print applied profile name (scripting). |
| `accounts env [name] --tool <tool>` | Print one or more `export ...` lines for the profile. |
| `accounts launch\|run <name> --tool <tool>` | Launch tool with profile env. |
| `accounts shell <name> --tool <tool>` | Subshell with profile env. |
| `accounts hook install` | Install `claude()` wrapper — see [docs/hook.md](docs/hook.md). |
| `accounts hook uninstall` | Remove hook script. |
| `accounts hook path` | Print hook script path. |
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

`switch_profile` applies Claude live auth when the target profile is Claude and
returns a restart handoff command. MCP servers cannot safely kill their parent
agent process, so the tool returns an instruction such as: exit this session and
run `CLAUDE_CONFIG_DIR=... claude --continue`.

Human equivalent:

```bash
accounts switch account001 --tool claude --resume
accounts switch account001 --tool claude --resume --launch
accounts switch codex-work --tool codex --resume
accounts switch ops --tool opencode --resume
```

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
  profiles/
    claude/<name>/           # managed config dir
    claude/<name>/.accounts-auth/   # auth snapshots for apply mode
      oauth-account.json
      credentials.json       # Linux / file-based auth
      keychain.json          # macOS keychain payload
```

Overrides: `ACCOUNTS_HOME`, `ACCOUNTS_STORE_PATH`.

## Supported tools

| Tool | id | Env var | Default dir |
|------|----|---------|-------------|
| Claude Code | `claude` | `CLAUDE_CONFIG_DIR` | `~/.claude` |
| Codex CLI | `codex` | `CODEX_HOME` | `~/.codex` |
| opencode | `opencode` | `OPENCODE_CONFIG_DIR`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME` | `~/.config/opencode` |
| Cursor Agent | `cursor` | `CURSOR_CONFIG_DIR` | `~/.cursor` |
| Kimi Code | `kimi` | `KIMI_CODE_HOME` | `~/.kimi-code` |
| Grok Build | `grok` | `HOME` (process-scoped) | `~/.grok` |

`apply` is **Claude-only** today. Use `launch` / `env` for other tools.
For Grok Build, prefer `accounts launch` or `accounts shell`; exporting `HOME`
globally is intentionally not recommended.

## Library

```ts
import { addProfile, applyProfile, importProfile } from "@hasna/accounts";
```

## License

Apache-2.0 © Andrei Hasna
