-- R-P1-4 (2026-07-31-accounts-debloat-design.md, "Remediation cycle 1"):
-- "each renamed record gains aliases: [<old-name>] and nativeName:
-- <tool-native/on-disk name>" so a rename is recorded, not just performed.
--
-- Representation: JSONB array for `aliases` (bounded, small, matches the
-- existing `metadata` JSONB column's precedent — see 0001_accounts.sql) rather
-- than a separate alias table. A join table would only pay for itself if
-- aliases needed independent rows (their own metadata, deletion audit, etc.);
-- they don't — they are an append-only, per-account history list, and the one
-- read this migration exists to support (accounts show <old-name> -> which
-- OTHER record used to be called that) reads the WHOLE table via
-- AccountsStore.listProfiles() and filters in the client, so no reverse index
-- is required at this scale. `native_name` is a plain TEXT column: a single
-- fixed identifier, not a growing history, so it does not need JSONB.
--
-- This migration adds the columns only. It does NOT backfill the 13 renamed
-- records from the accounts-debloat migration — that is separate, tracked
-- work, deliberately out of scope here (see the PR description).
ALTER TABLE accounts
  ADD COLUMN IF NOT EXISTS native_name TEXT,
  ADD COLUMN IF NOT EXISTS aliases JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Supports "which record used to be called X" (accounts show <old-name>)
-- without a full table scan once the registry grows past trivial size.
CREATE INDEX IF NOT EXISTS accounts_aliases_idx ON accounts USING gin (aliases jsonb_path_ops);
