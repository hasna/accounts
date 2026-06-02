# AGENTS.md — @hasna/accounts

Short guide for AI coding agents working in this repo.

## What this is

A local-first CLI to manage multiple **profiles/accounts** for AI coding tools
(Claude Code, Codex, and any app registered at runtime). A profile = an isolated config
dir (pointed at by an env var like `CLAUDE_CONFIG_DIR`) + a remembered email.

## Conventions

- **Bun + TypeScript, ESM.** Use `bun install`, `bun test`, `bun run build`.
- Strict TS (`noUncheckedIndexedAccess`, `noUnusedLocals`). Validate input with `zod`.
- CLI built with `commander`, colors with `chalk`. **CLI only — no web/server/MCP.**
- State lives in `~/.hasna/accounts/accounts.json` (override with `ACCOUNTS_HOME` /
  `ACCOUNTS_STORE_PATH` — used by tests for isolation).

## Layout

- `src/types.ts` — types, zod schemas, `AccountsError`.
- `src/storage.ts` — load/save the JSON registry.
- `src/lib/tools.ts` — `BUILTIN_TOOLS` + runtime custom tools.
- `src/lib/detect.ts` — email auto-detection.
- `src/lib/profiles.ts` — profile CRUD + active-profile logic.
- `src/cli.ts` — the `accounts` binary.

## Before you finish

1. `bun run typecheck` — clean.
2. `bun test` — all green (never weaken a test to pass).
3. `bun run build` — succeeds.
4. Smoke-test the built binary: `ACCOUNTS_HOME=$(mktemp -d) node dist/cli.js <cmd>`.

## Adding a new app

Prefer runtime registration (`accounts tools add`). For a built-in, add to
`BUILTIN_TOOLS` with `accountFile` + `emailPath` if the app stores its account email.
