-- Snapshot-before-delete for migration 0006_purge_test_tool_fixtures.
--
-- 0006 is a destructive production migration: it DELETEs from `accounts` and
-- `custom_tools` with no preserved original. That meets all three conditions of
-- the standing irreversible-mutation freeze (writes a production store, deletes
-- in place, keeps no original), so it may not run unguarded.
--
-- This migration is ordered IMMEDIATELY BEFORE 0006 in APP_MIGRATION_FILES.
-- The ledger applies migrations sequentially and stops on the first error, so
-- either this archive commits or 0006 never runs. That ordering — not a
-- convention or a comment — is what makes the snapshot unskippable.
--
-- Blast radius archived here is THREE tables, not the two 0006 names:
--   accounts           -- direct DELETE in 0006
--   current_selections -- removed by current_selections_account_fk ON DELETE
--                         CASCADE (migration 0004) when the account row goes
--   custom_tools       -- direct DELETE in 0006
-- The cascade is invisible in 0006's own SQL text, which is precisely why it
-- has to be named here.
--
-- Idempotent: the primary key plus ON CONFLICT DO NOTHING means re-executing
-- this file (the integration suite does exactly that to prove restart-safety)
-- neither duplicates nor overwrites an earlier capture.

CREATE TABLE IF NOT EXISTS destructive_migration_archive (
  migration_id TEXT        NOT NULL,
  table_name   TEXT        NOT NULL,
  -- Injective, separator-safe row identity: a JSON array of the primary-key
  -- columns. Plain concatenation would collide when a tool or profile name
  -- contains the separator, and Postgres text cannot hold a NUL byte.
  row_key      TEXT        NOT NULL,
  row_data     JSONB       NOT NULL,
  captured_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (migration_id, table_name, row_key)
);

COMMENT ON TABLE destructive_migration_archive IS
  'Preserved originals for destructive migrations. Restore with accounts-migrate --restore-purge-archive.';

-- accounts: 0006 deletes these directly so it can get past migration 0005''s
-- in-use guard, which would otherwise refuse to tombstone a tool still in use.
INSERT INTO destructive_migration_archive (migration_id, table_name, row_key, row_data)
SELECT
  'accounts_0006_purge_test_tool_fixtures',
  'accounts',
  to_jsonb(ARRAY[archived.tool, archived.name])::text,
  to_jsonb(archived)
FROM accounts AS archived
WHERE archived.tool IN (
  'fake-login',
  'fake-variant',
  'missing-review',
  'review-state-shape'
)
ON CONFLICT (migration_id, table_name, row_key) DO NOTHING;

-- current_selections: no DELETE names these, they vanish by FK cascade.
INSERT INTO destructive_migration_archive (migration_id, table_name, row_key, row_data)
SELECT
  'accounts_0006_purge_test_tool_fixtures',
  'current_selections',
  to_jsonb(ARRAY[archived.tool])::text,
  to_jsonb(archived)
FROM current_selections AS archived
WHERE archived.tool IN (
  'fake-login',
  'fake-variant',
  'missing-review',
  'review-state-shape'
)
ON CONFLICT (migration_id, table_name, row_key) DO NOTHING;

-- custom_tools: the four leaked fixture definitions 0006 exists to remove.
INSERT INTO destructive_migration_archive (migration_id, table_name, row_key, row_data)
SELECT
  'accounts_0006_purge_test_tool_fixtures',
  'custom_tools',
  to_jsonb(ARRAY[archived.id])::text,
  to_jsonb(archived)
FROM custom_tools AS archived
WHERE archived.id IN (
  'fake-login',
  'fake-variant',
  'missing-review',
  'review-state-shape'
)
ON CONFLICT (migration_id, table_name, row_key) DO NOTHING;
