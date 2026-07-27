# Shell hook — `claude()`

Optional bash/zsh wrapper so the terminal `claude` command auto-applies the **active** profile when it differs from **applied**.

## Install

```bash
accounts hook install
# Add to ~/.zshrc or ~/.bashrc (path from hook install output):
source "$(accounts hook path)"
```

`accounts hook path` prints the script location (respects `ACCOUNTS_HOME`).

## Uninstall

```bash
accounts hook uninstall   # removes the hook script if it was created by accounts
```

## Behavior

1. Resolves the real `claude` binary with `command -v` (avoids calling itself recursively).
2. Reads `accounts active claude` and `accounts applied claude`.
3. If active is set, valid, and ≠ applied, runs `accounts apply <active>` (errors go to stderr; hook still launches Claude).
4. Runs the provider child through
   `env -u BUN_CONFIG_VERBOSE_FETCH -u NODE_DEBUG -u NODE_DEBUG_NATIVE`.
   This leaves the parent shell unchanged and preserves all other inherited
   settings and arguments. The wrapper does **not** use `exec`.

Profile names are validated in the hook (`^[a-z0-9][a-z0-9-]*$`) before `accounts apply`.

## What the hook does **not** do

- Does **not** affect Cursor, VS Code, or other IDE extensions (they read live `~/.claude`, not this wrapper).
- Does **not** set `CLAUDE_CONFIG_DIR` — use `accounts env` / `accounts launch` for isolated terminal sessions.
- Does **not** unset request-debug controls in the parent shell; they are
  removed only at the `claude` child invocation boundary.
- Does **not** run if you never ran `accounts use` (no active profile → no auto-apply).

## Strict mode

If apply fails, the hook prints a warning and still starts Claude. For debugging apply failures, run `accounts apply <name>` manually and see stderr.

## Footguns

| Issue | Mitigation |
|-------|------------|
| Hook sourced but `accounts` not on `PATH` | Install `@hasna/accounts` globally or add to PATH before sourcing |
| `ACCOUNTS_HOME` differs between hook install and daily shell | Use the same env in shell startup as when you run `accounts` |
| Active profile has no auth snapshot | Run `accounts login` + `accounts detect` before relying on auto-apply |
| fish / nushell | Hook and generated `accounts env` output are POSIX-oriented; use `accounts apply`, `accounts launch`, or `accounts shell` instead |
| PowerShell | Generated shell syntax is not supported; use `accounts apply` or `accounts launch` |

See [IMPLEMENT.md](./IMPLEMENT.md) for the active vs applied model.
