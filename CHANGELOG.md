# Changelog

All notable changes to `@hasna/accounts` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.14] - 2026-06-17

### Added

- `--permissions <preset>` for launch, switch, supervised switch, run, and MCP profile switching so tool-specific permission modes can be requested without hand-writing flags.
- Built-in dangerous permission mappings for Claude, Takumi, Codex, Gemini, Hermes, and Kimi, plus custom tool `--permission-arg preset=flag` support.

### Fixed

- macOS keychain write failures now report sanitized stderr/status instead of command arguments.


## [0.1.12] - 2026-06-17

### Fixed

- Claude OAuth profiles now strip `apiKeyHelper` and API auth env settings before login, env, launch, supervisor restart, and apply so subscription profiles do not fall back to API-key auth.


## [0.1.5] - 2026-06-04

### Added

- `accounts run <tool>` supervisor mode. It starts Claude/Codex/opencode/etc. under `accounts` so a profile switch can restart the child process.
- Supervisor control commands: `accounts supervisor status`, `accounts supervisor switch`, and `accounts supervisor stop`.
- `accounts switch <profile> --supervisor` to ask a running supervisor to switch/restart the tool from another terminal.
- MCP `switch_profile` now talks to a running supervisor first; if found, it queues a real close/restart instead of only returning a handoff command.
- MCP `supervisor_status` tool.

## [0.1.4] - 2026-06-04

### Added

- `accounts switch <name> --tool <tool>` to switch profiles and print or launch a restart/resume command.
- `accounts-mcp` stdio server with `list_tools`, `list_profiles`, `current_profile`, and `switch_profile`.
- Resume handoff defaults for Claude (`claude --continue`), Codex (`codex resume --last`), and opencode (`opencode --continue`).

## [0.1.3] - 2026-06-04

### Fixed

- `accounts login <name> --tool claude` now finalizes the login automatically after Claude exits:
  snapshots profile auth, refreshes detected email, and applies the profile to live/default Claude.

### Added

- Built-in profile adapters for opencode, Cursor Agent, Kimi Code, and Grok Build.
- Multi-env profile rendering (`extraEnv`) for tools that need more than one environment variable.
- Per-tool profile names: the same profile name can exist for different tools; ambiguous commands require `--tool`.

### Fixed

- Docs/UX aligned with CLI: three-pointer model (`current` / `applied` / isolated), hook guide,
  `pick` flags, `doctor` stale `current` check, `show` active/applied lines, dual list markers.

## [0.1.2] - 2026-06-04

### Fixed

- Apply lock creates `ACCOUNTS_HOME` before opening `.apply.lock` (fixes ENOENT on fresh installs).
- `pick --no-act` no longer applies (Commander `act: false` mapping).
- `loadStore` prunes stale `current` pointers; doctor reports stale `current`.
- `saveStore` / live writes scoped under `accountsHome()` / live base for macOS `/var` symlink safety.

### Added

- `src/security.test.ts` (11 tests), `docs/IMPLEMENT.md`, `docs/hook.md`.

## [0.1.1] - 2026-06-04

### Fixed

- Apply refuses profiles without auth (no longer deletes live OAuth).
- Import snapshots auth from the profile dir, not live disk.
- `rename` / `remove` maintain `store.applied` pointers.
- macOS keychain restore allowlists `Claude Code-credentials` only.
- Symlink guard on auth snapshot writes; profile names re-validated on store load.
- Apply uses an exclusive lock file; hook validates profile names and surfaces apply errors.
- `doctor` exits 1 on problems; checks stale `applied` pointers.

## [0.1.0] - 2026-06-04

### Added

- **Apply mode** (`accounts apply`) — sync profile auth to live Claude paths for Cursor/VS Code.
- Auth snapshots under `<profile>/.accounts-auth/` (OAuth, file credentials, macOS keychain).
- `accounts import`, `accounts login`, `accounts pick` (interactive).
- `accounts active` / `accounts applied` for scripting.
- `accounts hook install` — optional `claude()` shell wrapper.
- Store field `applied` per tool (separate from `current` for env/launch).

## [0.0.1] - 2026-06-02

### Added

- Initial release — a local-first CLI for managing multiple Claude Code (and other
  AI coding tool) profiles/accounts.
- Profiles with isolated config dirs and a remembered account email per profile.
- Email auto-detection from a tool's account file (Claude Code: `.claude.json` →
  `oauthAccount.emailAddress`).
- Commands: `add`, `list`/`ls`, `show`, `use`, `env`, `launch`/`run`, `shell`,
  `current`, `set`, `detect`, `rename`, `remove`/`rm`, `path`, `doctor`.
- Built-in tools: Claude Code (`CLAUDE_CONFIG_DIR`) and Codex CLI (`CODEX_HOME`).
- Runtime tool registration (`accounts tools add/remove`) so the CLI scales to any
  app that reads a config dir from an environment variable — no code change required.
