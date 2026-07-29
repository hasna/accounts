# Breaking Account-Name Uniqueness Migration

Migration `0006_unique_account_names.sql` adds `UNIQUE (name)` to the Accounts
PostgreSQL registry. It deliberately retains `PRIMARY KEY (tool, name)` because
existing foreign keys and clients identify rows by that composite key. This is
the database enforcement phase after R6-9 made every supported local and server
writer refuse a name already held by another tool.

This repository's cloud service is a single-registry deployment and its schema
has no tenant column. Do not reuse the global constraint in a multi-tenant
schema. A tenant-aware deployment must use `UNIQUE (tenant_id, name)`, scope
the collision report and writer locks to `tenant_id`, and prove that two tenants
can both own (for example) `account001`.

## Required Announcement Before Landing

Post the following to the operator announcements channel before merging the
change, and retain the post link with the release evidence:

> **[BREAKING] Accounts names become unique across tools**
>
> What: the next Accounts database migration adds `UNIQUE (name)` while
> retaining `PRIMARY KEY (tool, name)`. A name can no longer be shared by two
> tools in one registry.
>
> Blast radius: all cloud Accounts writers and any direct SQL automation. The
> migration refuses to run if duplicate names remain; it does not delete or
> rewrite rows. Local and API writers must already include R6-9.
>
> When: deploy only after the restored-snapshot rehearsal and the immediately
> pre-migration production collision report both read zero.
>
> Rollback: roll back the application image but retain migration `0006` and the
> new migrator. If a database rollback is unavoidable, stop all writes and
> restore the verified pre-migration snapshot; do not drop the constraint under
> live traffic.

## Restored-Snapshot Rehearsal

This rehearsal is a release gate, not a substitute for the production report.

1. Restore the latest production snapshot into an isolated database and verify
   its restore checks.
2. Point the migration-owner connection at the restored database, set the
   DML-only runtime role, and run `accounts-migrate --dry-run`. Retain the JSON
   `account_name_collision_report`; `conflictingNames` must be `0`.
3. Run `accounts-migrate` against that restored database. Verify the migrator
   applied `accounts_0006_unique_account_names` and `/ready` reports ready.
4. Verify PostgreSQL still reports primary-key columns `tool, name` and a
   separate unique constraint on `name`. Exercise one normal create, rename,
   selection, and delete through the runtime role.

If the report is nonzero, reconcile the restored data using the same reviewed
mapping intended for production, restore a fresh snapshot, and repeat the full
rehearsal.

## Production Run

1. Verify R6-9 is deployed to every writer and retain the announcement and
   successful rehearsal evidence.
2. Take and verify a restorable production snapshot.
3. Run `accounts-migrate` once with the migration-owner role. When `0006` is
   pending, the command automatically emits the collision report immediately
   before invoking the migration and refuses a nonzero result.
4. Migration `0006` takes a write-blocking table lock and repeats the collision
   check before adding the constraint. This closes the multi-machine race
   between the report and enforcement. A collision aborts without changing or
   deleting either account.
5. Retain the zero report and migration output, then verify `/ready` and normal
   account operations through the runtime role.
