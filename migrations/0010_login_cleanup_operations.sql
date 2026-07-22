-- Persist conditional login-created profile cleanup results so response-loss
-- retries return the original result without treating an already-completed
-- delete as a concurrent replacement.
CREATE TABLE IF NOT EXISTS account_login_cleanup_operations (
  operation_id UUID PRIMARY KEY,
  operation_class TEXT NOT NULL DEFAULT 'remove-created'
    CHECK (operation_class = 'remove-created'),
  tool TEXT NOT NULL,
  name TEXT NOT NULL,
  target_incarnation_id UUID NOT NULL,
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  removed BOOLEAN,
  requested_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  CHECK (
    (completed_at IS NULL AND removed IS NULL) OR
    (completed_at IS NOT NULL AND removed IS NOT NULL)
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS account_login_cleanup_operations_expiry_idx
  ON account_login_cleanup_operations (requested_at)
  WHERE completed_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS account_login_cleanup_operations_target_retention_idx
  ON account_login_cleanup_operations
  (operation_class, tool, name, completed_at DESC, operation_id DESC)
  WHERE completed_at IS NOT NULL;
