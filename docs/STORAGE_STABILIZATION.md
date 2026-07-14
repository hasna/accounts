# Accounts Storage Stabilization

This change consolidates registry access behind `AccountsStore`:

- `LocalStore` owns the local `accounts.json` registry.
- `ApiStore` owns self-hosted/cloud registry access through `/v1`.
- Machine-local profile directories, applied pointers, and launch processes stay local.
- Cloud custom tool definitions hydrate a process-only cache. Readiness, health,
  list, and lookup operations do not create or rewrite `accounts.json`.

## Scope And Blast Radius

The source change covers four related surfaces:

1. AccountsStore routing for CLI, MCP, login, launch, supervisor, readiness, and
   profile registry operations.
2. Retirement of the legacy provider-backed remote/hybrid subsystem, with
   source-compatible shims but no provider runtime.
3. PostgreSQL migrations for custom-tool definitions, selection integrity, and
   durable removed-tool tombstones, plus additive custom-tool/rename endpoints.
4. Readiness and server compatibility, including additive Tool responses and
   transactional account/current-selection updates.

Local-only mode remains supported. No publish or deployment is part of this
source change.

## Compatibility Shims

No breaking removal is approved for this restack. The
`@hasna/accounts/storage` entry point retains its prior constants, types,
status/config functions, local snapshot functions, and sync function
signatures. The implementation has no provider runtime: `storagePush`,
`storagePull`, and `storageSync` reject with migration guidance.

The root `ensureProfileForLogin` export remains as a deprecated, synchronous,
local-only shim. New callers use async `prepareLogin` so custom tools can be
hydrated from the active Store.

The `accounts storage status|push|pull|sync` command group remains
discoverable. Status reports local/API compatibility state; provider-backed
mutations fail explicitly. The three retired mutations continue to accept
`--json` and the source functions retain their optional environment argument,
so legacy parsers and TypeScript call sites receive a retirement diagnostic
instead of a parse or compile failure. The retired `remote`, `hybrid`, and
`s3` mode words are ignored. Other unknown modes fail validation.

## Deployment Order

1. Take and verify a restorable Accounts database backup. This is mandatory:
   migration `0004` changes live selection rows.
2. Provision separate database identities. Both are dedicated
   `LOGIN NOINHERIT` roles with no elevated attributes or memberships. The
   migration owner owns the Accounts schema and its objects and is used only by
   `accounts-migrate`; the other role is used only by `accounts-serve`.
3. Run `accounts-migrate` with the owner DSN and
   `HASNA_ACCOUNTS_RUNTIME_ROLE=<accounts-serve-role>`. Migration
   `0003` is additive and creates `custom_tools`. Migration `0004` copies
   orphan current selections to `current_selection_orphan_archive`, removes
   those orphans from the live table, preserves valid selections, then adds a
   cascading account foreign key. Migration `0005` additively creates
   `custom_tool_tombstones` and database guards that serialize account
   creation, explicit removal, and explicit re-registration. All three
   migrations are checksum-ledgered and restart-idempotent. The migrator
   reapplies and verifies the runtime grant contract after migrations and on a
   current-schema no-op run. Inspect and retain
   the orphan archive for reconciliation; do not treat it as disposable
   migration scratch state.
4. Deploy `accounts-serve` with the DML-only role DSN and verify `/health`,
   `/ready`, `/version`,
   `GET /v1/tools`, and the OpenAPI document.
5. Roll out new clients only after the server is ready.

Server-before-client is required for `accounts rename`, `accounts tools add`,
and `accounts tools remove`. A new client connected to an older server returns
an actionable redeploy error for those route-missing mutations. Existing
account reads and writes continue to use their original endpoints.

## Database Role Contract

The migration owner and runtime role must be distinct. Both are provisioned
without elevated attributes or memberships. The owner gets DDL authority by
owning only the Accounts schema and its objects; it is not used by
`accounts-serve`:

```sql
CREATE ROLE accounts_migrator
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE accounts_app
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA accounts AUTHORIZATION accounts_migrator;
ALTER ROLE accounts_migrator SET search_path = accounts, pg_catalog;
ALTER ROLE accounts_app SET search_path = accounts, pg_catalog;
```

Authentication material is provisioned outside the repository. Both roles must
have no memberships, and the runtime role must not own any Accounts object.
`accounts` must be a dedicated schema; both migration and server connections
must resolve it as `current_schema()` through the shown role setting or an
equivalent connection-level `search_path`.
`accounts-migrate` fails closed if this contract is not met.

With `HASNA_ACCOUNTS_RUNTIME_ROLE=accounts_app`, the owner-run migrator applies
only these direct grants after revoking `PUBLIC` access on the managed schema
and tables:

- `USAGE` on the Accounts schema, without `CREATE`.
- `SELECT, INSERT, UPDATE, DELETE` on `accounts`,
  `current_selections`, and `custom_tools`.
- `SELECT, INSERT, DELETE` on `custom_tool_tombstones`; no `UPDATE`,
  `TRUNCATE`, `REFERENCES`, or `TRIGGER`.
- `SELECT` on `schema_migrations` and `api_keys` for readiness and
  API-key revocation checks.
- No direct `EXECUTE` on the four migration `0005` trigger functions.

The trigger functions are `SECURITY INVOKER`, owned by the migration owner,
have `search_path` fixed to `pg_catalog` plus the migration schema, and have
public execution revoked. Their table access therefore stays within the
runtime role's audited direct grants. Re-run the owner migrator after every
schema migration so grants for the current manifest are revalidated.

## Compatibility Matrix

| Client | Server | Result |
| --- | --- | --- |
| Old | Old | Existing account and selection operations are unchanged. |
| Old | New | Compatible after migration 0005. Account creation with a previously local, unseen custom tool id succeeds without a tools-registration call. A durably removed id is rejected. |
| New | Old | Existing operations work. Minimal legacy built-in Tool responses are accepted. Rename and custom-tool mutations require a server upgrade and fail with an actionable error. |
| New | New before migrations 0003/0004/0005 | `/ready` is unavailable with a pending-migration reason. Do not send traffic. |
| New | New after migrations 0003/0004/0005 | Full AccountsStore routing, durable tool lifecycle state, row/advisory-locked account/tool mutations, rename/remove/current updates, and pointer reconciliation are available. |

## Rollback And Forward Fix

- Before client rollout, the application server image may be rolled back.
  Leave migrations `0003`, `0004`, and `0005` in place. Database triggers
  make older account writers observe tombstones and turn older direct
  `custom_tools` deletes into durable removals. An explicit registration is
  the only operation that clears a tombstone.
- An application rollback continues to use the DML-only runtime role. Keep the
  migration `0005` functions, their locked `search_path`, and the grants
  applied by the new owner-run migrator. Do not switch the server to the owner
  DSN as a rollback shortcut.
- Never run a pre-`0003`/`0005` `accounts-migrate` binary after newer
  migrations are recorded. The checksum ledger rejects migrations unknown to
  the supplied manifest as a deterministic downgrade guard. An application
  rollback must retain the new migrator binary/job; otherwise forward-fix.
- If migration `0004` requires data recovery, stop writes and restore the
  mandatory pre-migration backup. The orphan archive is evidence for
  reconciliation, not a substitute for the backup.
- After new clients use rename or custom-tool endpoints, prefer a server
  forward-fix. Rolling the server below those endpoints makes the new mutations
  unavailable until it is restored.
- A client rollback does not remove cloud custom tools. Older clients may not
  resolve those tools for launch, but account and tool records remain intact.
- Do not drop `custom_tools`, `custom_tool_tombstones`, their guard triggers,
  or the selection foreign key as an application rollback. Restore service with
  a corrected server build, then reconcile data through supported endpoints.

## Verification

- `bun test` covers local/no-cloud behavior, process-only hydration,
  cold custom-tool lookup/launch, endpoint compatibility, and transaction use.
- `bun run test:postgres` requires
  `HASNA_ACCOUNTS_TEST_DATABASE_URL`. It uses an isolated schema to verify the
  `0003` upgrade, `0004` orphan archival and valid-row preservation, `0005`
  direct-SQL idempotency, unseen legacy ids, durable removal rejection,
  old-server trigger behavior, both removal/creation orderings, restart
  idempotency, old-migrator downgrade rejection, rollback/forward-fix behavior,
  transaction rollback, and concurrent row/advisory locking. The suite creates
  a non-superuser migration owner and a separate DML-only app role, migrates as
  the owner, reconnects as the app role, proves normal account/custom-tool
  operations, and runs both forced raw `INSERT accounts` versus
  `DELETE custom_tools` orderings without `AccountsRepo` locks.
- Pull requests install gitleaks `v8.30.1` from its checksum-pinned official
  Linux x64 archive and scan the complete base-to-head commit range with full
  redaction. The scan job has read-only contents permission, persists no
  checkout credential, receives no repository secrets, and ignores
  PR-controlled gitleaks config, ignore files, and inline allow directives.
- Contract, no-cloud, generated SDK, and vendored storage-kit checks remain
  required before release.
