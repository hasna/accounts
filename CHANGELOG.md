# Changelog

All notable changes to `@hasna/accounts` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Clear diagnostic when the self-hosted server predates an endpoint.** When a
  mutating registry call (`accounts rename`, `accounts tools add`, `accounts
  tools remove`) hits a route-missing `404` (`{ "error": "not found" }`) — the
  signature of a deployed `accounts-serve` build older than the client — the CLI
  now surfaces an actionable message instructing the operator to update
  `accounts-serve`, instead of a raw HTTP failure. Entity-level `404`s (a real
  "no profile"/"no custom tool") are unchanged and never masked. Local mode is
  unaffected. No package version or deployment target is asserted by this
  source change.

- Explicit `cloud` and `self_hosted` modes now fail closed when API
  configuration is incomplete. Cold custom-tool login/import/launch paths
  hydrate before synchronous lookup.
- Account rename/remove reconciles raw machine-local pointers. PostgreSQL
  selection updates are protected by row locks and an additive cascading
  foreign key migration. Migration `0004` archives orphan selections before
  cleanup, and the migrator rejects unknown applied migrations before its
  privilege-safe no-op path.
- Custom-tool add/remove and account creation share a transaction-scoped
  advisory lock, preventing tool deletion from racing a new dependent account.
  Additive migration `0005` durably distinguishes unseen legacy custom tool
  ids (accepted for old-client account creation) from explicitly removed ids
  (rejected until explicit re-registration), including older direct SQL writers.
- Migration `0005` trigger functions now remain owner-controlled
  `SECURITY INVOKER` functions with a fixed schema-safe `search_path` and no
  public execution. The owner-run migrator validates and applies an explicit
  DML-only `accounts-serve` role contract; required PostgreSQL tests run normal
  and raw old-server race operations through that separate role.
- Pull requests run a checksum-pinned gitleaks binary over the complete
  base-to-head commit range in a read-only, secret-free, fully redacted job.
- Deprecated storage exports and CLI commands remain as compatibility shims;
  retired provider-backed sync operations preserve optional environment
  arguments and `--json` parsing, then fail explicitly.

## [0.2.8] - 2026-07-14

### Added

- `accounts launch` and `accounts run` accept Claude-only convenience modes:
  `--headless` relays native print mode, while `--background`/`--bg` and an
  optional validated `--name` relay exactly to Claude's native `--bg --name`
  lifecycle. Claude remains the owner of session ids, status, logs, attach, and
  stop behavior.

### Fixed

- Validate raw, convenience, alias, duplicate, name, and explicit session UUID
  conflicts before configs prelaunch, active-profile mutation, keychain access,
  or process launch. Noninteractive invocations neither select a profile nor
  inherit `ACCOUNTS_ACTIVE`.
- Serialize temporary macOS keychain use across processes and restore the prior
  credential after Claude confirms dispatch or exits, including launch errors
  and forwarded termination signals. Lock files contain no credential values.
- Keep Claude stdout unmodified, send Accounts diagnostics to stderr, preserve
  Claude exit status, and map forwarded termination signals to nonzero exits.

### Changed

- Release provenance identifies the source repository as
  `hasna/accounts-legacy`. This source prepares `@hasna/accounts@0.2.8`
  without publishing, tagging, or installing it.

## [0.1.32] - 2026-07-06

### Added

- **Cloud service surface (`accounts-serve`)**: an HTTP API for the accounts
  registry. `GET /health`, `/ready`, `/version` plus API-key-authenticated
  versioned CRUD under `/v1` (`accounts`, `current` selection, `tools`).
  PURE REMOTE per Amendment A1 — reads/writes go directly to the app's cloud
  Postgres via the vendored `@hasna/contracts` storage kit; no local cache.
- **API-key auth** via `@hasna/contracts/auth` (`verifyApiKey`, `ApiKeyStore`):
  `accounts:read` for GETs, `accounts:write` for mutations; per-request audit.
- **Generated SDK (`@hasna/accounts/sdk`)**: a typed, dependency-free fetch
  client generated from the `accounts-serve` OpenAPI document, plus
  `createAccountsClientFromEnv()` (`ACCOUNTS_API_URL` + `ACCOUNTS_API_KEY`).
- **Migrations**: `migrations/*.sql` + the `accounts-migrate` bin/runner
  (checksum-guarded ledger, privilege-safe readiness probe).
- **Deploy assets**: ARM64 Bun `Dockerfile`, `docker-compose.yml`, and
  `hasna.contract.json` service manifest.

## [0.1.30] - 2026-06-29

### Fixed

- `accounts launch`, `accounts shell`, `accounts env`, `accounts switch`, MCP
  `switch_profile`, and supervised Claude starts now
  best-effort sync the selected profile's file credentials into the macOS
  `Claude Code-credentials` keychain item before spawning Claude. This prevents
  GUI-launched Claude from preferring a stale global keychain login over the
  selected profile's valid `CLAUDE_CONFIG_DIR` credentials.
- Applying a Claude profile now synthesizes the macOS keychain payload from the
  profile credential snapshot when no explicit keychain snapshot exists.
- Stale keychain snapshots no longer override fresher profile file credentials.
- Re-applying the same Claude profile no longer snapshots newer but unusable
  live credentials over a profile's valid refresh-token credentials.

## [0.1.29] - 2026-06-26

### Added

- `accounts login <name>` now prompts for a registry-driven tool choice when a
  profile name is not already locked, including built-in and custom registered
  tool variants.
- Profile names now persist a selected tool lock so bare `login`, `show`, `use`,
  and `launch` commands resolve to the chosen tool when duplicate names exist
  across tools.

### Fixed

- Missing Cursor installs are handled before launching `cursor-agent`, with
  accounts-level guidance to choose another tool, keep Cursor selected with
  install instructions, or cancel without partial state.
- Non-interactive login commands now fail clearly with explicit `--tool`
  commands instead of waiting on prompts.

## [0.1.28] - 2026-06-24

### Fixed

- Claude apply-mode handoff commands now use live/default auth instead of
  relaunching with `CLAUDE_CONFIG_DIR`, preventing restarts into isolated
  profile dirs that Claude reports as logged out.
- Applying a Claude profile no longer fails solely because macOS denies a
  non-interactive keychain write when file credentials were already restored.

## [0.1.27] - 2026-06-24

### Fixed

- Claude keychain operations now call `/usr/bin/security` on macOS, avoiding
  failures when another `security` CLI appears earlier in `PATH`.
- `accounts apply` and Claude auto-switching now reject OAuth-only profiles
  without restorable credentials instead of marking them applied and launching
  a logged-out Claude session.

## [0.1.26] - 2026-06-22

### Added

- Native macOS Codex App menu-bar switcher via `accounts codex-app menubar`,
  backed by JSON state/switch helpers that list `codex-app` profiles, mark the
  active profile, and safely quit/relaunch Codex.app under the selected profile.

### Fixed

- `accounts login <name>` now prefers an existing Claude profile when a profile
  name is shared with other tools, so bare Claude account login commands keep
  working without `--tool`.

## [0.1.25] - 2026-06-22

### Fixed

- `accounts login <name>` now reuses an existing unambiguous profile before
  creating a login profile, avoiding misleading duplicate Claude profile errors.

## [0.1.24] - 2026-06-22

### Fixed

- Codex App profile preparation now normalizes existing root
  `cli_auth_credentials_store` settings to `file` without duplicating the TOML
  key, keeping macOS desktop profile auth isolated from the shared Keychain.

## [0.1.23] - 2026-06-22

### Changed

- Superseded npm release; use `0.1.24` for the Codex App profile config fix.

## [0.1.22] - 2026-06-22

### Fixed

- Profile creation and updates now prevent duplicate config directory ownership
  across profiles.

## [0.1.21] - 2026-06-21

### Added

- Profile ownership metadata: `displayName`, `identity`, `cardLast4`, and
  JSON-safe `metadata` fields, with CLI support via `accounts add` and
  `accounts set`.

### Fixed

- Profile metadata updates now reject empty identity/name fields, reserved
  prototype keys, and non-finite numbers before writing the registry.

## [0.1.20] - 2026-06-21

### Fixed

- Hardened safe write-path symlink handling for account store writes.

## [0.1.19] - 2026-06-21

### Fixed

- Hardened account store file permissions.

## [0.1.18] - 2026-06-21

### Fixed

- Hardened profile purge path boundary checks.

## [0.1.17] - 2026-06-20

### Fixed

- Disambiguated active profile lookup by tool.

## [0.1.16] - 2026-06-18

### Added

- Built-in `codex-app` tool for macOS Codex.app profile switching. It isolates
  both `CODEX_HOME` and Electron `--user-data-dir` per profile.
- Tool `launchArgs` templates for app-level launch arguments, including
  `{profileDir}`, `{profileName}`, and `{toolId}`.

### Fixed

- New Codex App profiles default to file-based Codex credential caching so
  ChatGPT auth stays inside the selected profile directory.

## [0.1.15] - 2026-06-17

### Changed

- `accounts login <name>` now infers the tool from an existing unambiguous profile instead of defaulting to Claude before lookup. `--tool` is only needed when creating a missing non-Claude profile or disambiguating duplicate names.
- README and CLI hints now prefer bare profile commands for unambiguous profiles.


## [0.1.14] - 2026-06-17

### Added

- `--permissions <preset>` for launch, switch, supervised switch, run, and MCP profile switching so tool-specific permission modes can be requested without hand-writing flags.
- Built-in dangerous permission mappings for Claude, Takumi, Codex, Gemini, Hermes, and Kimi, plus custom tool `--permission-arg preset=flag` support.

### Fixed

- macOS keychain write failures now report sanitized stderr/status instead of command arguments.

## [0.1.13] - 2026-06-17

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.12] - 2026-06-17

### Fixed

- Claude OAuth profiles now strip `apiKeyHelper` and API auth env settings before login, env, launch, supervisor restart, and apply so subscription profiles do not fall back to API-key auth.

## [0.1.11] - 2026-06-16

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.10] - 2026-06-16

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.9] - 2026-06-16

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.8] - 2026-06-11

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.7] - 2026-06-10

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

## [0.1.6] - 2026-06-04

### Changed

- Maintenance publish; no user-facing change note was recorded for this release.

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
