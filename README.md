# @hasna/accounts

> Manage and switch between multiple AI coding tool profiles/accounts on one
> machine — Claude Code, Takumi, Codex CLI, Codex App, Gemini CLI, opencode,
> Cursor Agent, Pi Coding Agent, Hermes, Kimi Code, Grok Build, and custom tools.

`accounts` is a local-first CLI. Each **profile** is an isolated config directory.
Switch **in the terminal** with `CLAUDE_CONFIG_DIR`, or **in Cursor / VS Code** with
`accounts apply` (syncs auth to live `~/.claude` paths).

- **Isolated profiles** — separate config dirs (skills, settings, sessions). Nothing leaks.
- **Apply mode** — sync OAuth / credentials to live paths for IDEs (Claude-only today).
- **Remembers the email** — auto-detected from `.claude.json` when possible.
- **Multi-tool** — first-class built-ins for Claude, Takumi, Codex CLI, Codex
  App, Gemini, opencode, Cursor Agent, Pi, Hermes, Kimi Code, and Grok Build;
  custom tools via `accounts tools add`.
- **Tool lock-in** — first login/use chooses the tool for a profile name, so
  later bare commands like `accounts launch work` keep using that tool.
- **Local-first** — registry at `~/.hasna/accounts/`. No network, no telemetry.
- **Open source** — source, docs, and contribution guidelines live in this repository.

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
accounts login work --tool claude        # or omit --tool and choose Claude in the prompt
accounts login personal --tool claude    # login, exit; it becomes the live/default account

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

## Codex App profiles on macOS

Codex CLI profiles use `--tool codex`. The macOS desktop app needs its own tool
because it also needs an isolated Electron user data directory:

```bash
# Create/sign into a desktop app profile. Quit Codex.app after login finishes.
accounts login personal --tool codex-app
accounts login work --tool codex-app

# Switch by launching the desired app profile.
accounts launch personal --tool codex-app
accounts launch work --tool codex-app

# Or print/launch the exact handoff command.
accounts switch work --tool codex-app
accounts switch work --tool codex-app --launch

# Or run a native macOS menu-bar switcher.
accounts codex-app menubar
```

`codex` and `codex-app` are separate tool ids for the same account name. If you
run `accounts login personal` before either profile is locked, the chooser shows
both options; choosing one locks bare commands for `personal` to that tool. Use
`--tool codex` or `--tool codex-app` when you want to bypass or change that
choice explicitly. The same rule applies to future registered variants such as a
custom `claude-app` or `claude-cowork`: each tool id gets its own profile
directory and can be selected without changing the account name.

Each `codex-app` profile gets its own `CODEX_HOME` and
`--user-data-dir=<profile>/electron-user-data`. Before login, launch, switch, or
shell commands, `accounts` ensures the profile root `config.toml` has
`cli_auth_credentials_store = "file"` so ChatGPT auth stays in that profile
directory instead of sharing one macOS Keychain credential.

The menu-bar switcher lists `codex-app` profiles, marks the active profile, and
switches with a button click. A switch marks the selected profile active, asks a
running Codex.app to quit, waits briefly, and relaunches Codex.app with the
selected profile's isolated `CODEX_HOME` and Electron user data directory.

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
| **In-place** | `accounts switch-account <name>` | Change the RUNNING Claude session's account mid-conversation, no restart |

**In-place switching** works because Claude Code re-reads `<configDir>/.credentials.json`
from disk on every API request (measured on 2.1.220): `switch-account` snapshots the
dir's outgoing credentials back to their owning profile, installs the target profile's
credentials + `oauthAccount` into the session's config dir, and the session's next
message runs as the new account with the conversation intact. Every live session
sharing that config dir switches together, so the command refuses multi-session dirs
without `--yes`. If a target profile's auth is expired it fails loudly before touching
anything.

`accounts use` alone does **not** change Cursor — run `accounts apply` for IDE auth.

A child process cannot change your parent shell — use `eval "$(accounts env …)"` or the
[shell hook](docs/hook.md) (terminal `claude` only, not IDE extensions).

Implementation details: [docs/IMPLEMENT.md](docs/IMPLEMENT.md). The additive v2
migration preflight and durability contract is documented in
[docs/V2_MIGRATION_SIDECAR.md](docs/V2_MIGRATION_SIDECAR.md).

## What is isolated, and what is shared

Only **credentials** are per-profile. Capabilities belong to the person at the
machine, so every profile reads the same corpus:

| Concern | Where it lives | Shared? |
|---------|----------------|---------|
| OAuth account, credentials, keychain snapshot | `<profile>/.claude.json`, `<profile>/.credentials.json`, `<profile>/.accounts-auth/` | No — per profile |
| Live per-process session state | `<profile>/sessions` | No — per profile |
| Transcripts (sessions, subagents, workflows) | `<profile>/projects` → `~/.claude/projects` | Yes — symlink, **after `accounts sessions merge`** |
| Prompt history | `<profile>/history.jsonl` → `~/.claude/history.jsonl` | Yes — symlink, **after `accounts sessions merge`** |
| Skills | `<profile>/skills` → `~/.claude/skills` | Yes — symlink |
| Subagents | `<profile>/agents` → `~/.claude/agents` | Yes — symlink |
| MCP servers | `mcpServers` merged into `<profile>/.claude.json` | Yes — merged (the profile's own entries always win) |

The links are plain symlinks, so this is **write-through**: creating or deleting a
skill from inside any profile changes the one shared corpus for all of them. That
cuts both ways — one `rm -rf` through a link empties the corpus for every profile
at once — so `accounts` records the size of each corpus when it links it and
`accounts doctor` fails if the corpus later shrinks. Once you have confirmed a
deletion was intended, accept it with:

```bash
accounts doctor --accept-capability-baseline
```

MCP servers cannot be linked (the file that holds them is rewritten in place), so
they are merged member-by-member instead — a profile gains anything new in the
shared set and never loses its own entries. Servers are unioned across the tool's
declared sources with the first definition of a name winning, so rendered config
takes precedence over templated config; a server whose command still contains an
unsubstituted `{{PLACEHOLDER}}` is dropped rather than shipped broken, and the
`secrets` server is excluded outright — a vault-retrieval tool in another
identity's tool list is the closest thing to sharing tokens without sharing them.
If the profile's own config file exists but does not parse, the merge is refused
and reported: it is never rebuilt from scratch over whatever the file still held.

### Sessions: merge first, then link

Sessions are the one capability that cannot simply be linked. A profile created
before session sharing already owns a real, populated `projects/` directory, and
the linker deliberately refuses to replace a real directory a profile owns — that
guard is what stops a link from swallowing real data. Listing sessions as a shared
entry on its own would therefore do nothing at all while reporting success. The
contents have to be unioned into the shared home first:

```bash
accounts sessions merge --dry-run      # report only, writes nothing
accounts sessions merge                # union every profile's sessions into the shared home
accounts sessions merge --link         # …and then point each registered profile at it
```

What the merge guarantees:

- **Nothing is deleted, ever.** Source files are only read. When `--link` replaces
  a profile's own directory, the original is *renamed* to
  `<profile>/.accounts-session-migration/<timestamp>/`, never removed, and if the
  swap fails at any point the rename is undone and that profile is left exactly as
  it was.
- **Files are merged with `link(2)`, not copied.** The shared home gets the same
  inode, so a transcript that is still being appended to arrives whole instead of
  as a torn prefix of itself, mtimes are preserved (the tool prunes sessions by
  age — a copy that reset them would stop pruning entirely), the migration costs
  no disk, and a re-run is a no-op by construction: the same inode means the file
  is already merged. Copying is the fallback for a source on another filesystem,
  and it refuses a JSONL body that does not end in a newline.
- **Files are keyed by their full path under `projects/`, never by name.** The
  tree is nested — subagent and workflow transcripts sit several directories down,
  and `journal.jsonl` alone occurs at hundreds of distinct paths — so a
  name-keyed merge would collapse unrelated files into one.
- **A conflict never overwrites.** Same path, identical bytes: nothing to do. Same
  path, and the shared copy is a *proven* byte prefix of the incoming one:
  the longer one replaces it atomically, which cannot lose a byte. Anything else
  is a genuine fork, and both copies are kept — the second under a deterministic
  `<name>.from-<source>.<hash>.jsonl`, so a re-run finds its own copy instead of
  making another.
- **Sources are enumerated from the filesystem, not the registry.** Profile
  directories that Accounts has forgotten still hold real transcripts, and they
  are merged too. They are never *linked*, because only registered profiles are
  visited by the launch-time repair that keeps a link pointing at the right place;
  they are listed in the report so you can `accounts import` them and merge again.
- **`--from <dir>` merges extra read-only trees**, such as a backup taken before
  the migration, so a transcript deleted from the live tree since the backup is
  restored rather than lost.
- **It verifies before *and after* it links.** Transcript counts are taken
  recursively on the shared side — adding the sources back in would double-count
  every hardlink — and the shared tree must have grown by exactly the transcripts
  the run placed. The count is re-taken after the link step, because that is the
  only part of the run that can destroy anything. A profile is linked only when
  everything under it is demonstrably in the shared home, and anything written to
  it during the run is merged out of the retained tree before the swap is
  accepted.
- **Symlinks inside the tree are reproduced, not discarded.** Claude Code creates
  them for forked and resumed subagent transcripts. They are rewritten relative
  so the shared corpus stays portable; a link pointing out of the tree is refused
  with guidance rather than followed.
- **A dry run reports bounds, not exact counts.** It places nothing, so each
  source is compared against a shared tree that never received the earlier ones:
  merge counts are an upper bound and collision counts a lower bound.

`<profile>/sessions` is deliberately *not* shared: it holds one file per running
process, with a status heartbeat, and each instance reaps entries whose process it
believes to be dead — two profiles sharing it would reap each other's live
sessions. Nothing is lost by keeping it per-profile, because a session's durable
record is its transcript under `projects/`.

Because the shared corpus is write-through, `accounts doctor` records a floor for
it and fails if it shrinks. For `projects/` that floor is counted **recursively**:
its top level is one directory per project, so a top-level count would not move
even if every transcript inside were deleted.

Instruction files (`CLAUDE.md`, `rules/`) are **not** handled here, and the status
quo is not by design: Claude Code discovers memory by walking the working
directory's ancestors, not the config dir, so a copy inside a profile would never
be read. They load today only when the working directory happens to sit under the
home directory that holds them — a session started outside it loses them silently.

Sharing is materialized when a profile is created and re-checked on every launch,
so profiles created by older versions are repaired the next time they are used;
`accounts doctor` reports any profile that is not actually sharing. Which entries
and config keys are shared is per-tool data (`sharedEntries` / `sharedConfig` on a
tool definition), so a custom tool registered with `accounts tools add` can opt in.
The shared home defaults to the tool's default config dir and can be overridden
per machine with `ACCOUNTS_SHARED_HOME_<TOOL_ID>` (e.g. `ACCOUNTS_SHARED_HOME_CLAUDE`).

## Switching modes (summary)

- **`accounts active`** — prints active profile (`store.current`); scripting.
- **`accounts applied`** — prints applied profile (`store.applied`); scripting.
- **`accounts current`** — human-readable active (+ applied hint) per tool.
- **`accounts list`** — `●` active, `◉` applied, `●◉` when both are the same profile.

## Commands

| Command | Description |
|---------|-------------|
| `accounts add <name>` | Create a profile. `--tool`, `--email`, `--display-name`, `--identity`, `--card-last4`, `--metadata key=value`, `--dir`, `--description`. |
| `accounts import [name]` | Import existing config dir (default `~/.claude`). `--copy` for managed copy. |
| `accounts login <name>` | Choose a tool when needed, lock the profile name to that tool, then launch that tool's login flow in an isolated profile dir. Use `--tool` to bypass or change the chooser. |
| `accounts apply <name>` | Apply profile auth to live Claude paths (requires snapshot; Claude-only). |
| `accounts pick` | Interactive picker; default applies. `--env`, `--no-act`. |
| `accounts switch <name>` | Switch profile and print a restart/resume command. Add `--resume`, `--launch`, or `--permissions <preset>`. Use `--tool` only when ambiguous. |
| `accounts switch <name> --supervisor` | Ask a running `accounts run <tool>` supervisor to restart under that profile. Supports `--permissions <preset>`. |
| `accounts switch-account [name]` | Switch the CURRENT session's account in place — no restart, conversation intact (Claude-only; the running session re-reads `.credentials.json` on its next request). Picker when no name; `--dir`, `--yes`, `--json`. |
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
| `accounts sessions` (`sessions list`) | Read-only catalog of root Claude sessions owned by registered local profiles. `--profile`, `--project`, `--uuid`, `--json`. |
| `accounts health` (`readiness`) | Print the sanitized account/provider readiness contract. Use `--json` for automation. |
| `accounts detect <name>` | Re-detect email from config dir. |
| `accounts doctor` | Check registry and dirs (exits 1 on errors). |
| `accounts-serve` | Start the Bun HTTP API for the cloud storage mode. Supports `--port`, `--host`, public probes, and authenticated `/v1` account routes. |
| `accounts-migrate` | Check or apply the cloud Postgres schema migrations. Use `--dry-run` to print the pending migration plan without mutating the database. |

See `accounts --help` for `set`, `rename`, `remove`, `tools`, etc.

### Claude session catalog

`accounts sessions` and `accounts sessions list` scan only
`projects/<encoded-project>/<uuid>.jsonl` under verified local Claude profiles.
The live `~/.claude` directory is included only when an Accounts profile
explicitly represents it. Foreign or missing profile paths and symlinks are
rejected with a warning. A renamed managed profile remains represented through
its stored canonical config dir, provided that dir is still a direct child of
the Accounts-managed Claude profiles root. Traversal and nested roots are
rejected. Session files with multiple hard links are also rejected.

The default table shows owner, project, UUID, update time, size, and a bounded
session-ID check. `BOUNDED-MISMATCH` and `NOT-OBSERVED` remain visible instead
of looking like healthy entries. `--json` also returns an opaque `catalogRef`,
the source profile identity, canonical profile and source paths, the encoded
project key, and the bounded `sessionIdCheck` result needed to distinguish
collisions or report a filename/metadata mismatch. The v2 reference includes the
canonical profile root, encoded project key, UUID, and source path, but no
mutable account name or profile identity. Multiple account records representing
the same canonical source storage are emitted as one entry with sorted
`representations`; the deterministic primary representation remains in the
flat compatibility fields and the table shows every represented owner.
`catalogRefAliases` contains the sorted, deduplicated v1 references emitted by
the landed catalog, and the catalog resolver accepts either a canonical ref or
one of those explicit aliases. Unknown development refs fail closed. A
continuation journal must canonicalize a resolved alias before creating a new
transaction rather than treating an alias change as a second request. The
bounded metadata scan is discovery only and does not assert that the whole
transcript is valid; continuation brokers must validate the complete source
strictly.

`--uuid` requires canonical hexadecimal `8-4-4-4-12` UUID syntax. A valid UUID
with no match returns an empty result successfully; malformed syntax exits
nonzero with a validation error.

Catalog reads never change transcript content and prompts/messages are never
emitted. On platforms that support it, Accounts requests `O_NOATIME`; when the
flag is unavailable or not permitted, the read-only fallback may update
filesystem access-time metadata.

Scanning a machine that is actively writing sessions never truncates the
catalog silently. A path that keeps changing is retried, and anything still
unreadable is listed as a `warning:` on stderr, so a consumer can tell "no such
session" from "not observed on this pass". Registered Claude roots that are
missing or outside the trusted direct-child/default-root boundary are also
reported instead of disappearing silently. A represented profile with malformed
UTF-16 identity metadata is skipped and reported by reason and canonical source
path only; the identity text is not emitted. stdout stays a clean stream:
closing the pipe early — `accounts sessions --json | head` — exits 0 without a
stack trace.

## Cloud Runtime Entrypoints

The published package also includes two operator entrypoints for the
Postgres-backed API runtime. They are separate from the local-first `accounts`
CLI and are intended for service deployments, one-shot migration jobs, and local
ops against the same cloud storage mode.

Start the HTTP service with:

```bash
HASNA_ACCOUNTS_STORAGE_MODE=cloud \
HASNA_ACCOUNTS_DATABASE_URL=postgres://... \
HASNA_ACCOUNTS_API_SIGNING_KEY=... \
accounts-serve --port 8080 --host 0.0.0.0
```

`accounts-serve` runs on Bun. It reads `PORT` or `ACCOUNTS_SERVE_PORT` when
`--port` is omitted, defaults to port `8080`, and defaults to host `0.0.0.0`.
It requires `HASNA_ACCOUNTS_STORAGE_MODE=cloud`,
`HASNA_ACCOUNTS_DATABASE_URL`, and an API signing key from
`HASNA_ACCOUNTS_API_SIGNING_KEY` or the shared `HASNA_API_SIGNING_KEY` fallback.

The public probes are:

- `GET /health` — database reachability and package version.
- `GET /ready` — database reachability plus migration ledger status.
- `GET /version` — package version.

Authenticated `/v1` account routes require API keys with the `accounts:read` or
`accounts:write` scopes.

Run migrations before serving, or as a deployment one-shot:

```bash
HASNA_ACCOUNTS_STORAGE_MODE=cloud \
HASNA_ACCOUNTS_DATABASE_URL=postgres://... \
accounts-migrate --dry-run
```

`accounts-migrate` is idempotent and uses the checksum-guarded migration ledger
for the accounts schema. `--dry-run` prints the current plan as JSON without
DDL. Without `--dry-run`, it applies pending migrations and prints a JSON
summary; when the ledger is already current it exits successfully with a
`migrate_noop` event.

## Account Metadata

Profiles can carry non-secret ownership metadata alongside their isolated config
directory:

```bash
accounts add account001 \
  --email owner@example.com \
  --display-name "Owner Name" \
  --identity agent:owner-name \
  --card-last4 4242 \
  --metadata machine=spark02

accounts set account001 --identity identity_abc123 --metadata source=spark01
accounts show account001 --json
```

`cardLast4` is validated as exactly four digits. `metadata` accepts repeated
`key=value` pairs with string, finite number, boolean, or null values. Metadata
keys may use letters, digits, `_`, `.`, `:`, and `-`; object prototype keys such
as `__proto__`, `prototype`, and `constructor` are rejected. Do not store
secrets, tokens, full card numbers, or billing addresses in profile metadata.

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

`launch`, `run`, and `switch --launch` run a configs prelaunch step by default
for supported tools (`claude`, `codex`, `codewith`, `opencode`, `cursor`). The
prelaunch call applies into the profile's locked tool and isolated config dir:

```bash
accounts launch account001
accounts run account001
accounts switch account001 --launch
```

Use `--configs-dry-run` or `--configs plan` to preview without writing,
`--skip-configs` for legacy/no-configs runs, and `--allow-configs-failure` only
when intentionally bypassing a failed prelaunch check. If the account profile has
`identity: agent:marcus`, accounts exports that OpenIdentities overlay into the
profile home and passes it to `configs session apply` as `--identity-export`.
Repeat `--identity-export <path>` to add prebuilt global/tool/account exports.

`accounts list`, `accounts show`, and `accounts supervisor status --json`
include redacted prelaunch diagnostics: last run mode/result, audited
skip/bypass reason, OpenConfigs manifest path/hash, generated timestamp, source
ids/counts, and missing/stale/drift status.

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

Registry access is selected through `AccountsStore`:

- `local` uses the atomic on-machine JSON registry.
- `self_hosted` and `cloud` use the authenticated Accounts HTTP API.
- Explicit `self_hosted`/`cloud` modes fail closed unless both the API URL
  and key are configured.
- Retired `remote`, `hybrid`, and `s3` aliases are ignored for migration
  safety; any other unknown mode is rejected.

```ts
import { resolveStore } from "@hasna/accounts";

const store = resolveStore();
console.log(store.transport);
console.log(await store.listProfiles());
```

Configure API mode with:

- `HASNA_ACCOUNTS_STORAGE_MODE=local|self_hosted|cloud`
- `HASNA_ACCOUNTS_API_URL=https://accounts.example.com`
- `HASNA_ACCOUNTS_API_KEY` from the service operator

The `@hasna/accounts/storage` entry point and `accounts storage` command
group retain deprecated source/CLI compatibility shims. Local status and
snapshot helpers continue to work. `push`, `pull`, and `sync` fail
explicitly because the retired provider-backed transport is not present. Their
legacy optional environment arguments remain accepted, and the retired CLI
commands still parse `--json` before returning the same deterministic
retirement diagnostic.

For server compatibility, an older client may create an account using a
previously local custom tool id without first registering a Tool definition.
The server distinguishes that unseen id from an explicitly removed id using a
durable PostgreSQL tombstone; only an explicit tools registration reactivates a
removed id.

Production PostgreSQL uses separate identities: an object-owning migration role
for `accounts-migrate`, and a DML-only `LOGIN NOINHERIT` role for
`accounts-serve`. `accounts-migrate` requires
`HASNA_ACCOUNTS_RUNTIME_ROLE` to name the server role so it validates and
reapplies the least-privilege grants.
The server role must never own the schema or run migrations. See
[Accounts Storage Stabilization](docs/STORAGE_STABILIZATION.md#database-role-contract)
for the exact grants and rollout order.

## Supported tools

| Tool | id | Env var | Default dir |
|------|----|---------|-------------|
| Claude Code | `claude` | `CLAUDE_CONFIG_DIR`, `TELEGRAM_STATE_DIR` | `~/.claude` |
| Takumi | `takumi` | `TAKUMI_CONFIG_DIR` | `~/.takumi` |
| Codex CLI | `codex` | `CODEX_HOME` | `~/.codex` |
| Codex App | `codex-app` | `CODEX_HOME` + `--user-data-dir` | `~/.codex` |
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
Use `--launch-arg` for app-level arguments that should be prepended to every
login/launch/run command; templates support `{profileDir}`, `{profileName}`, and
`{toolId}`.

`accounts login <name>` builds its chooser from this registry, including custom
tools. Installed tools are listed first; tools whose binary or required app
install is missing are marked as requiring installation. In non-interactive
shells, `accounts` does not prompt and instead prints explicit `--tool` commands
to run.

## Library

```ts
import { addProfile, applyProfile, importProfile } from "@hasna/accounts";
```

## License

Apache-2.0 © Andrei Hasna
