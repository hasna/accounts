# CLI reference

This page mirrors the command tree registered by `src/cli.ts` and
`src/lib/claude-sessions-cli.ts`. Commander also provides `-h, --help` on every
command. Arguments after a variadic `[args...]` are passed to the target tool.

## Profile registry

| Command | Arguments and options |
| --- | --- |
| `accounts add <name>` | `-t, --tool <tool>` (default `claude`), `-e, --email`, `--display-name`, `--identity`, `--card-last4`, repeatable `--metadata <key=value>`, `-d, --dir`, `--description` |
| `accounts import [name]` | Name defaults to `main`; `-t, --tool` (default `claude`), `-d, --dir`, `-e, --email`, `--description`, `--copy` |
| `accounts login <name>` | `-t, --tool`; without it, Accounts uses the profile’s locked tool or an interactive tool chooser |
| `accounts list` | Alias `ls`; `-t, --tool`, `--json` |
| `accounts show <name>` | `-t, --tool`, `--json` |
| `accounts set <name>` | `-t, --tool`, `-e, --email`, `--display-name`, `--identity`, `--card-last4`, repeatable `--metadata`, `--description`, `-d, --dir`; at least one update is required |
| `accounts detect <name>` | `-t, --tool`; re-detects email from the tool’s account file |
| `accounts rename <name> <new-name>` | `-t, --tool` |
| `accounts remove <name>` | Alias `rm`; `-t, --tool`, `--purge` to archive a managed config directory |
| `accounts path <name>` | `-t, --tool`; prints only the config directory |

Names are lowercase alphanumeric/hyphen slugs and are keyed by tool plus name.
A bare name that exists for several tools requires `--tool`. Profile directory
options are constrained by the [profile directory policy](profile-directories.md).
Metadata values parse as string, finite number, boolean, or null.

## Selection and switching

| Command | Behavior and options |
| --- | --- |
| `accounts use <name>` | Set the active/current profile; `-t, --tool` |
| `accounts apply <name>` | Set active and copy auth to live Claude paths; `-t, --tool`; Claude-only |
| `accounts pick` | Interactive active+apply by default; `-t, --tool` defaults to Claude, `--env`, `--no-act`, or non-interactive `--healthiest` with `--min-headroom`, `--refresh`, `--json` |
| `accounts active [tool]` | Print the active name for scripting; tool defaults to Claude |
| `accounts applied [tool]` | Print the machine-local applied name for scripting; tool defaults to Claude |
| `accounts current` | Human-readable active selection for every tool; `-t, --tool` filters |
| `accounts switch <name> [args...]` | Print a handoff command; `-t, --tool`, `--mode <auto|apply|env|active>`, `--resume`, `--permissions`, `--launch`, `--supervisor`, `--json`, plus configs options |
| `accounts switch-account [name]` | Change the current Claude config directory’s credentials in place; picker when omitted; `-t, --tool`, `--dir`, `--yes`, `--json` |

`switch --launch` and `switch --supervisor` are mutually exclusive. Supervisor
switches resume by default. In-place switching affects every live Claude session
that shares the selected config directory and requires `--yes` when more than
one is observed.

## Launch and supervision

| Command | Behavior and options |
| --- | --- |
| `accounts env [name]` | Print shell `export` lines; `-t, --tool`; name defaults to the active profile for the selected/default Claude tool |
| `accounts launch <name> [args...]` | Launch once; `-t, --tool`, `--permissions`, Claude `--headless`, `--background`/`--bg`, `--name`, plus configs options |
| `accounts run <target> [args...]` | Supervise a tool id or profile name; `-p, --profile` for a tool target, `-t, --tool` for a profile target, `--resume`, `--permissions`, Claude `--headless`, `--background`/`--bg`, `--name`, plus configs options |
| `accounts shell <name>` | Open an interactive subshell with profile environment; `-t, --tool` |
| `accounts supervisor status [tool]` | List live/stale supervisor state; `--json` |
| `accounts supervisor switch <name> [args...]` | Switch a running supervisor; `-t, --tool`, `--mode`, `--no-resume`, `--permissions`, `--json`, plus configs options |
| `accounts supervisor stop <tool>` | Stop the supervisor and child process |

`--headless` and `--background` are Claude-native non-interactive launch modes;
with `accounts run` they intentionally bypass the supervisor. Interactive
`launch`, `run`, and `shell` mark the profile active.

Commands that say “configs options” accept:

- `--configs <apply|plan|skip>` (default `apply`), `--configs-dry-run`, or
  `--skip-configs`;
- `--allow-configs-failure`;
- `--configs-bin <path>` and `--identities-bin <path>`; and
- repeatable `--identity-export <path>`.

Configs prelaunch is supported for Claude, Codex, Codewith, opencode, and Cursor.

## Usage-aware switching

| Command | Options |
| --- | --- |
| `accounts usage` | `-t, --tool` (Claude-only, default Claude), `--refresh`, `--max-age <seconds>`, `--json`, `--quiet` |
| `accounts usage-hook` | `-t, --tool`, `--dir`, `--threshold`, `--min-headroom`, `--min-session-headroom`, `--cooldown`, `--max-age`, `--print-install` |

The hook is fail-open and cache-only. It is not installed automatically. See
[Usage-aware automatic switching](usage-aware-switching.md) for required cache
warming and the two-window selection rules.

## Claude sessions and agents

| Command | Options |
| --- | --- |
| `accounts agents` | `-t, --tool` (default Claude), `-p, --profile`, `-b, --background`, `--json` |
| `accounts sessions` | Default alias of `sessions list`; `--profile`, `--project`, `--uuid`, `--json` |
| `accounts sessions list` | Same options and behavior as `accounts sessions` |
| `accounts sessions merge` | `--dry-run`, `--profile`, variadic `--from <dir...>`, `--link`, `--active-window-ms`, `--json` |

Catalog commands never emit transcript content. Merge only adds or retains data;
`--link` is the explicit step that replaces registered profile session trees
with links after verification.

## Auth and diagnostics

| Command | Options and behavior |
| --- | --- |
| `accounts auth` | Defaults to `auth status` |
| `accounts auth status` | `--json`; list the UUID-keyed identity index |
| `accounts auth migrate` | `--json`; mirror every Claude profile snapshot into the central store |
| `accounts auth sweep` | `--json`, `--delete`; dry-run by default, and deletion moves bytes to `auth-trash` |
| `accounts health` | Alias `readiness`; `--json`; exits nonzero only when status is `unavailable` |
| `accounts doctor` | `--accept-capability-baseline`; errors on missing dirs, stale pointers, or broken shared capabilities |

See [Central auth snapshot store](auth-store.md) for sweep safeguards and
compatibility behavior.

## Hooks and Codex App

| Command | Options and behavior |
| --- | --- |
| `accounts hook install` | Write/update `~/.hasna/accounts/claude-hook.sh` |
| `accounts hook uninstall` | Remove that generated script |
| `accounts hook path` | Print its path |
| `accounts codex-app menubar` | `--accounts-bin <path>`; run the native macOS menu-bar helper |
| `accounts codex-app menu-state` | `--json`; print Codex App profile state |
| `accounts codex-app menu-switch <name>` | `--no-quit`, `--no-launch`, `--json` |

## Tool registry

| Command | Options |
| --- | --- |
| `accounts tools` | Defaults to `tools list` |
| `accounts tools list` | `--json` |
| `accounts tools add <id>` | Required `--label`, `--env-var`, `--bin`; optional `--default-dir`, variadic `--extra-env`, `--login-arg`, `--launch-arg`, `--resume-arg`, `--permission-arg`, `--account-file`, `--email-path` |
| `accounts tools remove <id>` | Alias `rm`; removes custom tools only |

Template-bearing environment and launch arguments support `{profileDir}`,
`{profileName}`, and `{toolId}`. Permission arguments use
`<preset>=<argument>` entries.

## Compatibility and contracts

| Command | Options and behavior |
| --- | --- |
| `accounts storage` | Defaults to `storage status`; deprecated local/API compatibility status |
| `accounts storage status` | `--json` |
| `accounts storage push|pull|sync` | Retained migration errors; `--json` is accepted but does not change the diagnostic |
| `accounts contracts capability-card` | `-j, --json` |
| `accounts contracts work-run` | `--tool`, `--profile`, `-j, --json` |
| `accounts contracts no-cloud-scan [path]` | Path defaults to `.`; `-j, --json` |
| `accounts events ...` | Shared `@hasna/events` event commands, including `emit`; run `accounts events --help` for the installed dependency’s options |
| `accounts webhooks ...` | Shared `@hasna/events` webhook commands; run `accounts webhooks --help` for the installed dependency’s options |

## Other binaries

| Binary | Usage |
| --- | --- |
| `accounts-mcp` | Stdio MCP server with `list_tools`, `list_profiles`, `current_profile`, `supervisor_status`, and `switch_profile` |
| `accounts-serve` | `accounts-serve [--port <port>] [--host <host>]`; see [HTTP API and SDK](http-api.md) |
| `accounts-migrate` | `accounts-migrate [--dry-run]`; requires cloud mode, a database URL, and `HASNA_ACCOUNTS_RUNTIME_ROLE` |
