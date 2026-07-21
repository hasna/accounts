-- Monotonic generations make conditional rollback distinguish a login's own
-- current-selection write from a newer same-profile selection.
CREATE SEQUENCE IF NOT EXISTS current_selection_revision_seq;

ALTER TABLE current_selections
  ADD COLUMN IF NOT EXISTS revision BIGINT,
  ADD COLUMN IF NOT EXISTS login_operation_id TEXT;

-- Login activation idempotency must outlive the mutable current-selection row.
-- Otherwise a lost response followed by a newer selection makes retrying the
-- original operation overwrite that newer selection.
CREATE TABLE IF NOT EXISTS current_login_operations (
  operation_id UUID PRIMARY KEY,
  tool TEXT NOT NULL,
  name TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('completed', 'cancelled')),
  updated_at TIMESTAMPTZ,
  revision BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT current_login_operations_terminal_state_check CHECK (
    (state = 'completed' AND updated_at IS NOT NULL AND revision IS NOT NULL)
    OR (state = 'cancelled' AND updated_at IS NULL AND revision IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS current_login_operations_tool_created_idx
  ON current_login_operations (tool, created_at);

UPDATE current_selections
   SET revision = nextval('current_selection_revision_seq')
 WHERE revision IS NULL;

ALTER TABLE current_selections
  ALTER COLUMN revision DROP DEFAULT,
  ALTER COLUMN revision SET NOT NULL;

-- Older accounts-serve replicas do not mention `revision` in their conflict
-- update. Advance it in the database so a mixed-version rollout cannot make a
-- newer selection look owned by an interrupted login from a newer client.
CREATE OR REPLACE FUNCTION advance_current_selection_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  NEW.revision := pg_catalog.nextval(
    pg_catalog.format('%I.current_selection_revision_seq', TG_TABLE_SCHEMA)::pg_catalog.regclass
  );
  IF TG_OP = 'UPDATE' AND NEW.login_operation_id IS NOT DISTINCT FROM OLD.login_operation_id THEN
    NEW.login_operation_id := NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS current_selection_revision_trigger ON current_selections;
CREATE TRIGGER current_selection_revision_trigger
BEFORE INSERT OR UPDATE ON current_selections
FOR EACH ROW EXECUTE FUNCTION advance_current_selection_revision();

-- The narrow trigger is owner-scoped so legacy replicas never need direct
-- sequence access. Pin name resolution and expose no callable public API.
DO $migration$
DECLARE
  target_schema TEXT := current_schema();
BEGIN
  EXECUTE format(
    'ALTER FUNCTION %I.advance_current_selection_revision() SET search_path = pg_catalog, %I',
    target_schema,
    target_schema
  );
END
$migration$;

REVOKE ALL PRIVILEGES ON FUNCTION advance_current_selection_revision() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SEQUENCE current_selection_revision_seq FROM PUBLIC;
