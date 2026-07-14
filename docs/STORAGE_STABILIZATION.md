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
2. Removal of the legacy S3 remote/hybrid storage subsystem and its sync API.
3. PostgreSQL migration `0003_custom_tools.sql` plus additive custom-tool and
   rename endpoints.
4. Readiness and server compatibility, including additive Tool responses and
   transactional account/current-selection updates.

Local-only mode remains supported. No publish or deployment is part of this
source change.

## Removed Public Surfaces

The `@hasna/accounts/storage` entry point remains, but these legacy S3 exports
are removed:

- `ACCOUNTS_STORAGE_ENV`, `ACCOUNTS_STORAGE_FALLBACK_ENV`,
  `STORAGE_MODE_ENV`, and `STORAGE_TABLES`
- `AccountsStorageMode`, `AccountsStorageConfig`,
  `AccountsStorageStatus`, `AccountsStorageSnapshot`, and
  `AccountsStorageSyncResult`
- `getAccountsStorageConfig`, `getAccountsStorageStatus`,
  `getStorageStatus`, `createAccountsStorageSnapshot`,
  `restoreAccountsStorageSnapshot`, and `accountsStorageSnapshotKey`
- `storagePush`, `storagePull`, and `storageSync`

The root export `ensureProfileForLogin` is removed. Callers should use
`prepareLogin` or `importProfile` and route profile reads/writes through
`resolveStore()`.

The CLI group `accounts storage status|push|pull|sync` is removed. Use local
mode for an on-machine registry or configure the Accounts API URL and key for
self-hosted/cloud mode. The retired `remote`, `hybrid`, and `s3` mode words
are ignored.

## Deployment Order

1. Back up the Accounts database using the normal database procedure.
2. Run `accounts-migrate` with the new source against PostgreSQL. Migration
   `0003` is additive and creates `custom_tools`; it does not rewrite account
   or current-selection rows.
3. Deploy `accounts-serve` and verify `/health`, `/ready`, `/version`,
   `GET /v1/tools`, and the OpenAPI document.
4. Roll out new clients only after the server is ready.

Server-before-client is required for `accounts rename`, `accounts tools add`,
and `accounts tools remove`. A new client connected to an older server returns
an actionable redeploy error for those route-missing mutations. Existing
account reads and writes continue to use their original endpoints.

## Compatibility Matrix

| Client | Server | Result |
| --- | --- | --- |
| Old | Old | Existing account and selection operations are unchanged. |
| Old | New | Compatible. Routes are additive and Tool only requires `id` and `label`; enriched fields are optional. |
| New | Old | Existing operations work. Minimal legacy built-in Tool responses are accepted. Rename and custom-tool mutations require a server upgrade and fail with an actionable error. |
| New | New before migration 0003 | `/ready` is unavailable with a pending-migration reason. Do not send traffic. |
| New | New after migration 0003 | Full AccountsStore routing, custom tools, rename, and transactional selection updates are available. |

## Rollback And Forward Fix

- Before client rollout, the server may be rolled back. Leave migration `0003`
  in place because it is additive and older servers ignore `custom_tools`.
- After new clients use rename or custom-tool endpoints, prefer a server
  forward-fix. Rolling the server below those endpoints makes the new mutations
  unavailable until it is restored.
- A client rollback does not remove cloud custom tools. Older clients may not
  resolve those tools for launch, but account and tool records remain intact.
- Do not drop `custom_tools` as an application rollback. Restore service with a
  corrected server build, then reconcile data through supported endpoints.

## Verification

- `bun test` covers local/no-cloud behavior, process-only hydration,
  cold custom-tool lookup/launch, endpoint compatibility, and transaction use.
- `bun run test:postgres` requires
  `HASNA_ACCOUNTS_TEST_DATABASE_URL`. It uses an isolated schema to verify the
  `0003` upgrade, restart idempotency, and real rollback semantics.
- Contract, no-cloud, generated SDK, and vendored storage-kit checks remain
  required before release.
