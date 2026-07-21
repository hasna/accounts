-- Persist the state displaced by a transactional activation so rollback can
-- undo only that operation without trusting a stale client-side snapshot.
ALTER TABLE current_login_operations
  ADD COLUMN IF NOT EXISTS previous_name TEXT,
  ADD COLUMN IF NOT EXISTS previous_target_last_used_at TIMESTAMPTZ;
