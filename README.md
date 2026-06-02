# @hasna/accounts

> Manage and switch between multiple **Claude Code** (and other AI coding tool)
> profiles/accounts on one machine — isolated config dirs, a remembered email per
> account, and one-command switching.

`accounts` is a small, local-first CLI. Each **profile** is an isolated config
directory that a tool reads via an environment variable (Claude Code uses
`CLAUDE_CONFIG_DIR`, Codex uses `CODEX_HOME`). `accounts` tracks those profiles,
remembers which **email** each one belongs to, and switches between them — so you can
run a work account and a personal account side by side without logging in and out.

- 🗂️ **Isolated profiles** — every profile gets its own config dir (skills, settings,
  sessions, memory). Nothing leaks between accounts.
- 📧 **Remembers the email** — auto-detected from the tool's account file when
  available, or set it yourself.
- 🔀 **One-command switching** — `accounts launch work` starts the tool with the right
  config dir; `eval "$(accounts env work)"` exports it into your shell.
- 🧰 **Multi-tool** — Claude Code today, Codex too; trivially extensible.
- 🪶 **Local-first, no web** — a single JSON registry under `~/.hasna/accounts/`. No
  servers, no telemetry.

## Install

```bash
bun install -g @hasna/accounts   # or: npm install -g @hasna/accounts
accounts --help
```

Requires Node ≥ 18 (or Bun ≥ 1.0).

## Quick start

```bash
# Create a profile (config dir is created for you)
accounts add work --email work@company.com --description "Work account"
accounts add personal --email me@gmail.com

# Import an existing config dir (email auto-detected from .claude.json)
accounts add main --dir ~/.claude

# See what you have
accounts list
accounts current

# Use one — pick whichever fits your shell workflow:
accounts launch work             # start `claude` with work's config dir
eval "$(accounts env work)"      # export CLAUDE_CONFIG_DIR into THIS shell
accounts shell work              # open a subshell with it set
```

### Why three ways to "switch"?

A child process (this CLI) can't mutate its parent shell's environment. So:

| You want… | Use |
|-----------|-----|
| To just run the tool now with a profile | `accounts launch <name> [-- args]` |
| The profile active for the rest of this shell | `eval "$(accounts env <name>)"` |
| A throwaway subshell scoped to a profile | `accounts shell <name>` |

`accounts use <name>` records the active profile (shown in `list`/`current`) and prints
the two activation options.

## Commands

| Command | Description |
|---------|-------------|
| `accounts add <name>` | Create a profile. `--tool`, `--email`, `--dir`, `--description`. |
| `accounts list` (`ls`) | List profiles. `--tool`, `--json`. |
| `accounts show <name>` | Full details. `--json`. |
| `accounts use <name>` | Mark a profile active for its tool. |
| `accounts env [name]` | Print `export VAR=dir` (for `eval`). `--tool` when no name. |
| `accounts launch <name> [-- args]` (`run`) | Launch the tool's binary with the profile. |
| `accounts shell <name>` | Open a subshell with the profile's env set. |
| `accounts current` | Show the active profile per tool. `--tool`. |
| `accounts set <name>` | Update `--email`, `--description`, `--dir`. |
| `accounts detect <name>` | Re-detect the email from the profile's config dir. |
| `accounts rename <old> <new>` | Rename a profile. |
| `accounts remove <name>` (`rm`) | Remove a profile. `--purge` deletes the managed dir. |
| `accounts path <name>` | Print just the config dir (for scripting). |
| `accounts tools` | List supported tools. `--json`. |
| `accounts tools add <id>` | Register a custom app. `--label`, `--env-var`, `--bin`, `--default-dir`, `--account-file`, `--email-path`. |
| `accounts tools remove <id>` | Remove a custom tool. |
| `accounts doctor` | Check the registry and profile dirs. |

## Supported tools

| Tool | id | Env var | Default dir |
|------|----|---------|-------------|
| Claude Code | `claude` | `CLAUDE_CONFIG_DIR` | `~/.claude` |
| Codex CLI | `codex` | `CODEX_HOME` | `~/.codex` |

Email auto-detection currently reads `<dir>/.claude.json → oauthAccount.emailAddress`
for Claude Code. For other tools, set the email with `--email` / `accounts set`.

Add a profile for a specific tool with `--tool`:

```bash
accounts add work-codex --tool codex --email work@company.com
accounts launch work-codex
```

### Register any app at runtime (scalable)

`accounts` isn't limited to the built-ins. Any app that reads its config dir from an
environment variable can be registered as a tool — no code change, persisted in your
store:

```bash
accounts tools add cursor \
  --label "Cursor" \
  --env-var CURSOR_CONFIG_DIR \
  --bin cursor \
  --account-file .cursor.json \
  --email-path account.email     # optional: where to auto-detect the email

accounts add design --tool cursor --email design@company.com
accounts launch design           # runs `cursor` with CURSOR_CONFIG_DIR set

accounts tools                   # built-ins are tagged built-in, yours as custom
accounts tools remove cursor     # (only when no profile uses it)
```

`tools add` options: `--label`, `--env-var` (required), `--bin` (required),
`--default-dir` (defaults to `~/.<id>`), `--account-file` + `--email-path` (optional,
enable email auto-detection). Built-in tool ids can't be redefined or removed.

## How it stores things

```
~/.hasna/accounts/
  accounts.json                 # the registry (profiles + active pointers), mode 600
  profiles/
    claude/<name>/              # managed config dir for a Claude profile
    codex/<name>/               # managed config dir for a Codex profile
```

Environment overrides (handy for testing/automation):

- `ACCOUNTS_HOME` — base dir (default `~/.hasna/accounts`)
- `ACCOUNTS_STORE_PATH` — exact path to the registry JSON

Profiles created without `--dir` get a managed dir under `profiles/`. Profiles created
with `--dir` (e.g. importing `~/.claude`) point at that dir and are never deleted by
`--purge`.

## Shell helper (optional)

Add a quick switcher to your `~/.zshrc` / `~/.bashrc`:

```bash
ccacct() { eval "$(accounts env "$1")" && echo "Claude profile → $1"; }
# usage: ccacct work
```

## Library use

```ts
import { listProfiles, addProfile, useProfile } from "@hasna/accounts";

addProfile({ name: "work", email: "work@company.com" });
useProfile("work");
console.log(listProfiles());
```

## License

Apache-2.0 © Andrei Hasna
