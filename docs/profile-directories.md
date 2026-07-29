# Profile directory policy

Accounts stores profile paths in local and cloud registries, then treats those
paths as tool configuration roots. A bad path can make agent/session discovery
read an unrelated worktree, scratchpad, cache, or temporary directory. The cloud
API therefore validates profile paths at its request boundary before storing them.

## Profile paths

A profile `dir` supplied to `POST /v1/accounts` or
`PATCH /v1/accounts/{tool}/{name}` must be:

- a string containing no control characters;
- absolute;
- outside ephemeral roots such as `/tmp`, `/var/tmp`, `/var/folders`,
  `/dev/shm`, and `/run`;
- beneath a recognized user home root (`/home/<user>` or `/Users/<user>` by
  default); and
- beneath either `~/.hasna/accounts/profiles` or a built-in tool home such as
  `~/.claude`, `~/.codex`, `~/.codewith`, or `~/.config/opencode`.

The last rule is an allowlist. Paths under `~/.hasna/repos/worktrees`,
`~/.hasna/projects/workspaces`, `~/.cache`, and other sibling directories are
rejected even though they are inside a user home.

The managed root is intentionally the default `~/.hasna/accounts/profiles`, not
an `ACCOUNTS_HOME` override. An override changes where local state is read and
written; it does not grant permission to register profiles from an arbitrary
scratch directory.

## Alternate home roots

Operators with a different home layout can set a colon-separated list of
absolute home roots:

```bash
HASNA_ACCOUNTS_PROFILE_DIR_ROOTS=/srv/home:/mnt/users accounts-serve
```

This replaces the default `/home:/Users` home-root list. It does not widen the
profile-root allowlist and can never admit an ephemeral root.

## Custom tools

`POST /v1/tools` validates custom tool homes with the same absolute, persistent, home-anchored rules. They do not use the built-in profile-root allowlist because registering a custom tool is how a
new home such as `~/.config/aicopilot` becomes known.

## Cloud behavior

The API performs lexical validation only. It cannot stat a path belonging to a
client machine, resolve its symlinks, or require that it already exists. Local
JSON mode does not apply this cloud trust-boundary policy; tests and one-machine
workflows can still use isolated temporary roots without writing those paths to a
shared registry.
