# Changelog

All notable changes to `@hasna/accounts` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Profile-dir policy for the cloud registry (`src/lib/profile-dir-policy.ts`).
  `POST /v1/accounts` and `PATCH /v1/accounts/:tool/:name` now refuse a `dir`
  that sits under an ephemeral root (`/tmp`, `/var/tmp`, `/var/folders`,
  `/dev/shm`, `/run`, and the macOS `/private` aliases), is not anchored under a
  home root, or does not sit in a tool home directory. Previously any string was
  accepted, which let test harnesses and agents write throwaway paths into the
  shared registry. The check is deliberately filesystem-free — the service
  validates dirs belonging to other machines and must judge them lexically — and
  the ephemeral check runs before the home check, so widening
  `HASNA_ACCOUNTS_PROFILE_DIR_ROOTS` for an unusual machine layout cannot
  re-admit a temp path. Enforcement is server-side only: the cloud client also
  talks to test doubles and non-production instances and cannot know which, so
  it does not judge dirs locally.

- Central identity-keyed auth snapshot store (`docs/auth-store.md`):
  `~/.hasna/accounts/auth/<accountUuid>/{credentials.json,oauth-account.json}`
  replaces the per-profile `.accounts-auth/` dirs as the canonical credential
  home, with a read-both/write-new compatibility window for <= 0.2.15
  binaries (writes mirrored to both stores, reads pick the `betterCredential`
  winner, nothing deleted). New CLI: `accounts auth status | migrate | sweep`
  (sweep is dry-run by default, refuses in api storage mode, and only ever
  MOVES orphaned entries to `auth-trash/`). `buildIdentityIndex()` and the
  central-store surface are exported from the package root.

- Usage-aware automatic account switching (`docs/usage-aware-switching.md`):
  - `accounts usage` — per-ACCOUNT usage from Claude's `/api/oauth/usage`
    (`Authorization: Bearer <accessToken>` + `anthropic-beta: oauth-2025-04-20`),
    keyed on `oauthAccount.accountUuid` and deduplicated across profile dirs —
    one query per distinct account however many dirs hold it. Reports session
    and weekly windows (structured `limits[]` preferred), headroom
    (100 − worst unscoped window), expired/credential-less accounts as states
    (never crashes), and caches per uuid under `cache/usage/`.
  - `accounts pick --healthiest` — non-interactive selector: the account with
    the most headroom, never the one the session currently runs as (the
    silent-no-op case), resolved to a profile door; reports "all limited"
    honestly instead of flapping. No identity exclusions (user-ratified
    2026-07-28: switching across all client identities is fine).
  - `accounts usage-hook` — a Claude Code `UserPromptSubmit` handler that
    auto-switches the session in place (via `switch-account`) when any
    unscoped window crosses the threshold (default 90% used). Cached-only
    decisions with a detached background refresh (never blocks a prompt),
    fail-open on every error, cooldown against flapping, loud `systemMessage`
    announcements for switches AND failed switches, and a mandatory
    post-switch assertion that the active `accountUuid` actually changed.
    NOT installed automatically — `--print-install` prints the settings.json
    snippet for operator opt-in.
  - Identity enumeration lives behind one accessor
    (`buildIdentityIndex()`), reading the future central auth home
    `~/.hasna/accounts/auth/<accountUuid>/` first with per-profile
    `.accounts-auth/` fallback, ready for the auth-store migration.

- Two-window (5-hour session vs 7-day weekly) rate-limit selection. Anthropic
  enforces two independent limits that fail differently, and the selector
  previously ranked accounts on a single blended headroom
  (100 − worst unscoped window) — which scores an account whose 5-hour window
  is spent but recovers in minutes identically to one that is dead until next
  week. Both windows are now carried separately end to end:
  - `src/lib/usage-windows.ts` classifies each window from the payload's
    `group` discriminator (measured live 2026-07-28 across 8 accounts:
    `kind=session group=session`, `kind=weekly_all group=weekly`,
    `kind=weekly_scoped group=weekly scoped`), falling back to `kind` and then
    to a deliberately ASYMMETRIC reset-horizon rule — a horizon over the
    session window's 5-hour maximum implies weekly, but a short horizon does
    NOT imply session (a live `weekly_all` window was measured 0.86h from its
    reset). Horizon-derived classes are flagged `inferred`.
  - `selectHealthiestAccount` excludes weekly-exhausted accounts until their
    weekly reset and session-exhausted accounts only until their 5-hour roll,
    reporting a per-account reason and `eligibleAt`; survivors rank by weekly
    headroom, then session headroom, then uuid. A window whose `resets_at` has
    passed since the reading is re-read as recovered (INFERRED), which is what
    lets an account return without a fresh fetch; a `resets_at` already past at
    read time is treated as a malformed payload, not a roll. New
    `--min-session-headroom` / `ACCOUNTS_USAGE_SWITCH_MIN_SESSION_HEADROOM`
    floor (default 10) keeps switches off targets with no immediate runway.
  - `state/exhaustion-ledger.json` — restart-durable per-account cooldowns
    with exponential backoff (15 min base, doubling), released at the later of
    the reported reset and the backoff step, capped at 5h (session/unknown) and
    24h (weekly) so a misclassified window can never retire an account
    permanently. Corrupt or path-hostile entries degrade to "no cooldown".
  - The switch announcement and `accounts usage` now report both windows rather
    than one blended percentage. `accounts usage` labels each window with its
    class and marks a window whose reset has passed as reset rather than
    printing a stale "100% used" the selector disagrees with.
  - `accounts pick --healthiest` reads the same exhaustion ledger the hook
    writes, so the CLI and the hook no longer disagree about the pool.
  - Exhaustion is decided by utilization alone; `severity` is not consulted.
    Measured in the Claude Code 2.1.220 bundle (binary-safe): `severity:"normal"`
    0, `severity:"critical"` 0, `severity:"exhausted"` 0, against positive
    controls on the same file of `severity:"error"` 27, `"warning"` 22,
    `"fatal"` 6 and bare `severity` 295. The reference client reads `kind`,
    `scope`, `percent`, `resets_at` and `extra_usage.*` off a limit entry and
    never reads `severity` from the usage payload.
  - The ledger lives under `state/`, not `cache/` — a store whose purpose is
    surviving restarts must not sit in a directory whose name licenses
    deletion. (Motivated by a live observation that
    `cache/auto-switch-state.json` is absent despite two switches 60s apart
    under a 10-minute cooldown; the cause of that loss is NOT established and
    is tracked separately.) No migration: nothing was ever released writing
    the old path.

- `accounts switch-account [name]` — switch the CURRENT Claude Code session's
  account in place, with no restart and the conversation intact. Measured on
  Claude Code 2.1.220: a running session `stat()`s `<configDir>/.credentials.json`
  on every API request and re-reads it when the mtime changes (the stat sits
  above the token-still-valid early return, inside the per-request client
  factory) — so installing another profile's credentials +
  `oauthAccount` into the session's config dir flips its identity on the next
  message. The verb snapshots the dir's outgoing credentials back to their owning
  profile first, records a `switched-account` marker so snapshot machinery never
  cross-contaminates profiles, refuses dead-auth targets loudly before touching
  anything, and refuses config dirs shared by multiple live sessions without
  `--yes` (they all flip together). The live default dir routes through the
  existing `apply` semantics.

### Fixed

- Share capabilities across profiles instead of isolating them. A profile is an
  isolated config dir, so pointing Claude Code at a freshly created one gave it
  none of the machine's skills, subagents, or MCP servers — only credentials are
  meant to be per-profile. `skills/` and `agents/` are now linked to the tool's
  shared home and user-scope `mcpServers` are merged into the profile's account
  file, both idempotently, on profile creation and on every launch (so profiles
  created by earlier versions are repaired the next time they are used). Which
  entries and keys are shared is per-tool data (`ToolDef.sharedEntries` /
  `ToolDef.sharedConfig`), not a hard-coded Claude mapping.

- Never rebuild a profile's account file from an unreadable one. A `.claude.json`
  that exists but does not parse is now reported and left byte-for-byte intact;
  previously it was treated as an empty object and replaced by the merge result,
  destroying `oauthAccount`, `userID` and `machineID`.
- Write the merged account file atomically (temp file, `fsync`, `rename`, explicit
  `chmod`) instead of truncating a ~200 KB credential-bearing file in place. The
  shared primitive now backs `saveStore` too. `writeFileSync`'s `mode` does not
  tighten a pre-existing file, so the mode is applied after the rename.
- Take shared MCP server definitions from rendered config before templated
  config, union members across all declared sources instead of letting the first
  non-empty file win outright, and drop any server whose definition still carries
  an unsubstituted `{{PLACEHOLDER}}`. `secrets` is excluded from sharing.
- Materialize shared capabilities from `accounts switch` as well. In applied mode
  it skips `profileEnv`, so the headline way to change Claude profiles used to
  leave the profile dir unrepaired for later isolated launches.

### Changed

- `accounts doctor` now checks capability sharing by realpath, so a profile with
  no skills, no subagents, no MCP servers, or a dangling capability link is
  reported as a problem instead of a green check.
- `accounts doctor` also fails when a shared corpus has shrunk below the size
  recorded when it was linked. Realpath equality only proves the pointer is
  correct; it says nothing about whether a write-through delete emptied the
  corpus. `accounts doctor --accept-capability-baseline` accepts a deliberate
  deletion as the new floor.
- Tool definitions may not declare credential artifacts (`.credentials.json`,
  `auth.json`, `keychain.json`, …) as shared entries or as a merge target, may not
  share credential-bearing config keys (`oauthAccount`, `customApiKeyResponses`,
  …), and may not contain control characters in shared paths. Tool definitions can
  arrive from a registry, so this is enforced in the schema rather than by
  convention.

## [0.2.12] - 2026-07-27

### Added

- Add the read-only `accounts sessions` / `accounts sessions list` catalog for
  Claude sessions represented by verified Accounts-managed profiles. The
  command provides deterministic table and JSON views with bounded metadata;
  it performs no application writes to session or profile trees, never writes
  credential or transcript content, and never emits credentials, prompts,
  messages, or transcript content. Read-only fallback may update filesystem
  access-time metadata when `O_NOATIME` is unavailable or not permitted.

### Changed

- Derive canonical `catalogRef` values from the physical storage/session tuple
  instead of mutable account metadata. Managed roots remain visible across
  account renames, multiple account records for the same root are
  deduplicated, and the resolver accepts the deterministic v1 references
  exposed through `catalogRefAliases`.
- Harden the bundled MCP build graph by pinning patched `fast-uri` and `hono`
  versions, keeping its validation dependencies out of clean consumer
  installs, enforcing high-severity dependency audits in CI, and extending
  Bun's release-age quarantine to seven days.

### Fixed

- Keep large JSON output complete under Bun, format large built-package tables
  without overflowing Node's call-argument ceiling, treat a closed stdout pipe
  as a normal exit, preserve settled entries while session trees churn, and
  isolate Windows home-directory fixtures so the portable suite exercises the
  intended managed roots.

### Not Included

- The cross-owner continuation broker is not part of 0.2.12. It remains
  fail-closed and unreleased; this release provides read-only discovery only.

## [0.2.11] - 2026-07-24

### Testing

- Regression coverage locking `--allow-empty-sources` onto the `accounts run` /
  supervisor codewith configs-prelaunch path for identity-less profiles (e.g.
  `accountNNN`): `runSupervisedTool` now has an explicit test asserting the
  `configs session apply` invocation carries `--allow-empty-sources` (and no
  `--identity-export`) when zero identity exports resolve, plus a direct
  `runConfigsPrelaunch` test for the shared apply path. The behavior itself
  shipped in 0.2.9 via the shared `configsPrelaunchCommand` (used by `launch`,
  `run`, and the supervisor); stations still dead-lettering with "Session render
  has no instruction sources" are running a pre-0.2.9 binary and need the
  package update, not a code change.

## [0.2.10] - 2026-07-24

### Changed

- Test suite is now isolated from live environments: keychain platform/security
  resolution is factored into pure, injectable helpers (`keychainSupportedFor`,
  `securityExecutableFor`) and the PostgreSQL integration tests run through a
  signal-safe launcher (`test/run-postgres.ts`) that tears down its controlled
  root on SIGINT/SIGTERM/SIGHUP. No runtime behavior change for the CLI.

### Documentation

- Documented the accounts runtime entrypoints in the README.

## [0.2.9] - 2026-07-24

### Fixed

- Configs prelaunch now performs an explicit empty session render for profiles
  with no instruction sources. When accounts resolves zero identity exports for a
  `configs session plan`/`apply`, it appends `--allow-empty-sources` so `configs`
  writes a valid empty render (`CLAUDE.md` + a `sourceCount: 0` manifest, exit 0)
  instead of failing closed. This unblocks `accounts launch` / `accounts run` for
  identity-less profiles (e.g. `accountNNN`), which previously aborted with
  `configs prelaunch apply failed ... Session render has no instruction sources`.
  Profiles that resolve one or more instruction sources are unchanged and never
  receive the flag.

## [0.2.8] - 2026-07-15

### Changed

- `accounts launch` and `accounts run` treat Claude-only convenience modes as
  thin native relays:
  `--headless` relays native print mode, while `--background`/`--bg` and an
  optional validated `--name` relay exactly to Claude's native `--bg --name`
  lifecycle. Claude remains the owner of session ids, status, logs, attach, and
  stop behavior.
- Explicit `cloud` and `self_hosted` modes now fail closed when API
  configuration is incomplete. Cold custom-tool login/import/launch paths
  hydrate before synchronous lookup.
- Pull requests run a checksum-pinned gitleaks binary over the complete
  base-to-head commit range with read-only repository permissions and fully
  redacted output.
- Deprecated storage exports and CLI commands remain as compatibility shims;
  retired provider-backed sync operations preserve optional environment
  arguments and `--json` parsing, then fail explicitly.
- Release provenance identifies the source repository as
  `hasna/accounts-legacy`.

### Fixed

- Account rename/remove reconciles raw machine-local pointers. PostgreSQL
  selection updates are protected by row locks and an additive cascading
  foreign key migration. Migration `0004` archives orphan selections before
  cleanup, and the migrator rejects unknown applied migrations before its
  privilege-safe no-op path.
- Custom-tool add/remove and account creation share a transaction-scoped
  advisory lock, preventing tool deletion from racing a new dependent account.
  Additive migration `0005` durably distinguishes unseen legacy custom tool
  ids from explicitly removed ids, including for older direct SQL writers.
- Migration `0005` trigger functions remain owner-controlled
  `SECURITY INVOKER` functions with a fixed schema-safe `search_path` and no
  public execution. The owner-run migrator validates and applies an explicit
  DML-only `accounts-serve` role contract.
- Validate raw, convenience, alias, duplicate, name, and explicit session UUID
  conflicts before configs prelaunch, active-profile mutation, keychain access,
  or process launch. Noninteractive invocations neither select a profile nor
  inherit `ACCOUNTS_ACTIVE`.
- Serialize temporary macOS keychain use across processes and restore the prior
  credential after Claude confirms dispatch or exits, including launch errors
  and forwarded termination signals. Lock files contain no credential values.
- Resolve Claude from Windows `PATH`/`PATHEXT`, invoke only resolved `.cmd` and
  `.bat` shims through `cmd.exe` with line-break rejection and escaped
  arguments, and keep native executables on the direct-spawn path.
- Keep Claude stdout unmodified, send Accounts diagnostics to stderr, preserve
  Claude exit status, and map forwarded termination signals to nonzero exits.

## [0.2.7] - 2026-07-14

### Added

- First-class Claude worker flags on `accounts launch` and `accounts run`:
  `--headless` maps to Claude `-p`, `--background` / `--bg` maps to Claude
  `--bg`, and `--name <name>` names a background Claude agent. These flags compose
  with `--permissions dangerous`, leaving the existing `-- ...` passthrough path
  intact for raw Claude options.
- Regression coverage for Claude worker argument placement, passthrough
  de-duplication, and invalid flag combinations so dangerous permissions continue
  to appear before worker-mode args.

### Changed

- The package repository metadata now points at `hasna/accounts-legacy`, the
  current source home for the launcher-era `@hasna/accounts` npm package. The
  clean `hasna/accounts` repository is a separate capacity-service product line.

## [0.2.6] - 2026-07-09

### Fixed

- **`accounts-serve` OpenAPI `Tool` response schema is wire-additive again.** The
  refactor that enriched `GET /v1/tools` (returning the full `ToolDef` plus custom
  tools from the cloud registry) had also grown the `Tool` schema's `required` set
  to `["id","label","envVar","defaultDir","bin"]`. The deployed (0.1.x) server only
  guaranteed `["id","label"]` and never emitted `defaultDir`, so the change was a
  non-additive contract narrowing that the server-redeploy safety gate blocked. The
  extra `ToolDef` fields are now documented as **optional** and `required` is back to
  `["id","label"]`, making the HTTP response contract a strict SUPERSET of the
  deployed version. Runtime behavior is unchanged (the handler still returns the full
  `ToolDef` + custom tools); old `/v1` clients — which parse the response without
  strict validation — keep working. No route was removed or renamed; the new
  `rename` / custom-tool endpoints remain additive alongside the old surface.

## [0.2.4] - 2026-07-08

### Changed

- **Clear diagnostic when the self-hosted server predates an endpoint.** When a
  mutating registry call (`accounts rename`, `accounts tools add`, `accounts
  tools remove`) hits a route-missing `404` (`{ "error": "not found" }`) — the
  signature of a deployed `accounts-serve` build older than the client — the CLI
  now surfaces an actionable message instructing the operator to redeploy
  `accounts-serve`, instead of a raw HTTP failure. Entity-level `404`s (a real
  "no profile"/"no custom tool") are unchanged and never masked. Local mode is
  unaffected. (The rename + tools endpoints already exist in `src/server`; the
  live fix for cloud mode is an ECS redeploy of `accounts-serve` to >= 0.2.4.)

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
