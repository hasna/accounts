# Implementation guide — `@hasna/accounts`

For contributors and coding agents working in this repo.

## Three-pointer model

Profiles are keyed by **tool + name**. The same name can be reused across tools
(`work` for Claude, Codex, Cursor, etc.). Bare name lookup is allowed only when
it resolves to one profile; otherwise commands must pass `--tool`.

Each tool (e.g. `claude`) tracks **two registry pointers** plus an optional **isolated runtime** mode:

| Pointer / mode | Store field | CLI surface | What it controls |
|----------------|-------------|-------------|------------------|
| **Active** (intent) | `store.current[toolId]` | `accounts use`, `accounts active`, `accounts pick` (always), `launch`/`shell` | Which profile you mean for terminal workflows and the shell hook |
| **Applied** (live auth) | `store.applied[toolId]` | `accounts apply`, `accounts applied`, `accounts pick` (default) | OAuth/credentials on live `~/.claude` paths (what Cursor/VS Code read) |
| **Isolated** (no pointer) | — | `accounts env`, `accounts launch`, `accounts shell` | Tool env vars rendered from `src/lib/env.ts` for one process/shell only |

**Rules:**

- `accounts use` updates **active** only — it does **not** change IDE auth.
- `accounts apply` updates **applied** and also sets **active** to the same profile.
- `accounts pick` defaults to **active + apply**; use `--env` or `--no-act` for other modes.
- The shell hook compares **active** vs **applied** and runs `accounts apply` when they differ ([hook docs](./hook.md)).
- `apply` is Claude-only until another tool has a verified live-path adapter.

Registry file: `~/.hasna/accounts/accounts.json` (fields `current` and `applied`, not `active`).

## Key modules

| Path | Role |
|------|------|
| `src/storage.ts` | `ACCOUNTS_HOME`, atomic temp+rename saves, pruned local reads, raw machine-pointer reads |
| `src/lib/store.ts` | Local/API registry routing, cloud custom-tool hydration, API path cleanup |
| `src/lib/profiles.ts` | CRUD, profile metadata/identity/card-last4 validation, `useProfile` → `current`, rename/remove pointer hygiene |
| `src/lib/tools.ts` | Built-in and custom tool registry |
| `src/lib/env.ts` | Per-tool env rendering (`{profileDir}`, `{profileName}`, `{toolId}` templates), including Claude channel state |
| `src/lib/codex-app.ts` | Codex App profile preparation, including file-based credential cache defaults |
| `src/lib/codex-app-menu.ts` | macOS Codex App menu-bar state, switch, safe quit/relaunch, and Swift status-item launcher |
| `src/lib/apply.ts` | `applyProfile`, `applied` pointer, live path sync |
| `src/lib/claude-auth.ts` | Auth snapshots under `<profile>/.accounts-auth/` |
| `src/lib/import-profile.ts` | `import` / `login` |
| `src/lib/pick.ts` | Interactive picker |
| `src/lib/hook.ts` | `claude-hook.sh` generator |
| `src/cli.ts` | Commander CLI |

## Request-debug boundary

`src/lib/env.ts` owns a deliberately narrow three-key policy:
`BUN_CONFIG_VERBOSE_FETCH`, `NODE_DEBUG`, and `NODE_DEBUG_NATIVE` are removed
case-insensitively after all provider env overlays. Generated export handoffs
explicitly `unset` them, and generated command handoffs use `env -u`, so an
inherited value cannot survive merely because the caller executes printed
output instead of using an Accounts-owned spawn. The optional bash/zsh
`claude()` hook uses the same child-only `env -u` boundary: it preserves the
parent shell and every other inherited environment variable.

Generated handoffs target POSIX sh/bash/zsh syntax. `src/lib/env.ts` rejects
non-portable variable names, quotes every value as a non-expanding POSIX word,
and inserts `env --` before assignments so a leading-hyphen provider binary
cannot be parsed as an `env` option. Embedded quotes, newlines, backslashes,
dollars, and backticks remain literal. Tool schemas validate `extraEnv` keys
at registration/load time, while the renderer validates again at the execution
boundary for defense in depth. fish, nushell, and PowerShell output is not
claimed; use an Accounts-owned launch there (or `accounts shell` for
fish/nushell when `SHELL` identifies that shell).

Do not broaden that list without evidence that another control dumps provider
requests. `PATH`, proxy/TLS configuration, Bedrock/Vertex selection, and
AWS/Google SDK settings are intentionally preserved as part of the caller's
existing trust binding. Provider flags/config, edited handoff commands, and
other caller-selected diagnostics remain residual caller-trusted controls.

`src/lib/redaction.ts` applies a separate output boundary to controlled launch
and prelaunch diagnostics. Its sensitive-header scanner tracks quote, escape,
separator, blank-fold, and record state with linear forward scanning. The same
record scanner handles generic credential keys such as `x-api-key`,
`client-secret`, and token fields, rather than redacting only a first token. It
does not use an authorization-parameter allowlist: arbitrary extension
parameters and cookie names remain inside a folded credential record. Open
quotes and ambiguous indented continuations fail closed. A new header, an
unambiguous structured diagnostic record, or an explicit `status`, `message`,
`stack`, or `detail` record after a syntactically complete non-separated value
ends the record. Unknown assignment names, whitespace-only folds,
diagnostic-looking names after an empty value or dangling credential separator,
separator-only folds, raw quoted tails, and serialized-looking malformed tails
remain sensitive. A quoted value terminates at its closing quote only when its
quoted key and following sibling form a structural serialized-field boundary;
raw comma or semicolon tails are not trusted. Controlled prelaunch stderr and
stdout are separated by a record boundary before line bounding and redaction.
This keeps provably independent records visible without repeated suffix scans,
fusing process streams, or exposing malformed folds.
Credential-key classification is centralized and normalizes separators and
camel case, including dot and space boundaries, before applying terminal
semantic tokens. Valid JSON documents are walked recursively after JSON key
escape decoding; escaped and single-quoted keys in malformed serialized
fragments use the same fail-closed record boundary. Argument redaction handles
credential-bearing long options separated by `=`, `:`, or the next argv item,
plus the supported `-k value` and `-kvalue` forms.

`src/lib/switch.ts` separates the internal `SwitchResult`, which may contain
raw launch material, from the explicit public
`hasna.accounts.switch-output/v1` projection. CLI, MCP, and supervisor switch
surfaces emit only that DTO: bounded profile/tool identity, status, redacted
command/handoff data, and message. Environment maps, export scripts, complete
profiles, and complete tool definitions remain internal. The supervisor client
also projects socket responses rather than trusting unknown fields, and legacy
state parsing constructs the current schema field by field instead of spreading
persisted data.

Supervisor arguments remain raw only in memory long enough to spawn the
provider child. State files, legacy-state reads, switch responses, and
live/stale status output all use argument-aware redaction before data leaves
that boundary. On Unix, the supervisor directory is forced to `0700` and its
state file and control socket to `0600`, including when `ACCOUNTS_HOME` points
at a pre-existing permissive directory.

## Apply safety

- Refuse apply when the profile has no auth snapshot and no oauth in the profile dir.
- Never delete live oauth unless replacing with target profile auth.
- Exclusive lock: `src/lib/apply-lock.ts`.
- Live paths in tests: set `ACCOUNTS_TEST_LIVE_DIR` (never touch real `~/.claude`).

## Doctor

`accounts doctor` exits **1** when:

- A profile config dir is missing
- `applied.<tool>` or `current.<tool>` points at a removed profile

Warnings (exit 0): no email, no auth snapshot, active ≠ applied drift.

## Profile metadata

The store keeps account ownership metadata directly on each profile:

- `email` — account email, auto-detected for tools with an account file.
- `displayName` — human-readable account owner/name.
- `identity` — identity identifier/ref from `identities`.
- `cardLast4` — optional payment card last four digits only, validated as `^\d{4}$`.
- `metadata` — JSON-safe string/finite-number/boolean/null map for operational tags;
  reserved object prototype keys are rejected.

Never store secrets, access tokens, full card numbers, billing addresses, or
private identity documents in `metadata`.

## Tests

```bash
bun test
bun run typecheck
bun run build
bun run contracts:no-cloud-scan
bun run conformance
ACCOUNTS_REQUIRE_POSTGRES=1 HASNA_ACCOUNTS_TEST_DATABASE_URL=<isolated-test-db> bun run test:postgres
```

Use isolated `ACCOUNTS_HOME` and `ACCOUNTS_TEST_LIVE_DIR` in every test (`accounts.test.ts`, `switcher.test.ts`).
PostgreSQL tests create and drop random owner/runtime roles plus a random
schema. Migrations run as the non-superuser schema owner; server and raw legacy
SQL operations reconnect through the documented DML-only runtime grants. CI
provides a disposable PostgreSQL service and treats role separation,
migration/concurrency coverage, and the checksum-pinned full-PR-range gitleaks
scan as required.
