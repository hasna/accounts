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
