-- Distinguish an unseen legacy custom tool id from one explicitly removed.
-- Missing rows are intentionally allowed for old-client account creation;
-- tombstones are durable and prevent account creation until an explicit tool
-- registration reactivates the id.
CREATE TABLE IF NOT EXISTS custom_tool_tombstones (
  id         TEXT PRIMARY KEY,
  removed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every account writer, including an older server build, participates in the
-- same tool-scoped lock and observes durable removals.
CREATE OR REPLACE FUNCTION accounts_guard_removed_custom_tool()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('accounts:tool:' || NEW.tool, 0));
  IF EXISTS (SELECT 1 FROM custom_tool_tombstones WHERE id = NEW.tool) THEN
    RAISE EXCEPTION 'custom tool "%" was explicitly removed', NEW.tool
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS accounts_guard_removed_custom_tool ON accounts;
CREATE TRIGGER accounts_guard_removed_custom_tool
  BEFORE INSERT OR UPDATE OF tool ON accounts
  FOR EACH ROW EXECUTE FUNCTION accounts_guard_removed_custom_tool();

-- Tombstone writes take the same lock and cannot commit while dependent
-- accounts exist, preventing a remove/create race from leaving a dangling row.
CREATE OR REPLACE FUNCTION custom_tool_tombstone_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('accounts:tool:' || NEW.id, 0));
  IF EXISTS (SELECT 1 FROM accounts WHERE tool = NEW.id) THEN
    RAISE EXCEPTION 'cannot remove "%": accounts still use this tool', NEW.id
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS custom_tool_tombstone_guard ON custom_tool_tombstones;
CREATE TRIGGER custom_tool_tombstone_guard
  BEFORE INSERT OR UPDATE OF id ON custom_tool_tombstones
  FOR EACH ROW EXECUTE FUNCTION custom_tool_tombstone_guard();

-- A deliberate registration is the only operation that reactivates a removed
-- id. The trigger keeps direct/older custom-tool writers wire-compatible.
CREATE OR REPLACE FUNCTION custom_tool_registration_reactivate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('accounts:tool:' || NEW.id, 0));
  DELETE FROM custom_tool_tombstones WHERE id = NEW.id;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS custom_tool_registration_reactivate ON custom_tools;
CREATE TRIGGER custom_tool_registration_reactivate
  BEFORE INSERT OR UPDATE OF id ON custom_tools
  FOR EACH ROW EXECUTE FUNCTION custom_tool_registration_reactivate();

-- A pre-0005 server deletes from custom_tools directly. Preserve that removal
-- intent durably so rolling back the application image cannot bypass 0005.
CREATE OR REPLACE FUNCTION custom_tool_registration_tombstone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('accounts:tool:' || OLD.id, 0));
  IF EXISTS (SELECT 1 FROM accounts WHERE tool = OLD.id) THEN
    RAISE EXCEPTION 'cannot remove "%": accounts still use this tool', OLD.id
      USING ERRCODE = '23503';
  END IF;
  INSERT INTO custom_tool_tombstones (id)
    VALUES (OLD.id)
    ON CONFLICT (id) DO NOTHING;
  RETURN OLD;
END
$$;

DROP TRIGGER IF EXISTS custom_tool_registration_tombstone ON custom_tools;
CREATE TRIGGER custom_tool_registration_tombstone
  BEFORE DELETE ON custom_tools
  FOR EACH ROW EXECUTE FUNCTION custom_tool_registration_tombstone();

-- These remain SECURITY INVOKER so the runtime role receives only the direct
-- table privileges documented for accounts-serve. Pin name resolution to the
-- migration-owned schema (with pg_catalog first), and do not expose trigger
-- functions as a callable public API.
DO $migration$
DECLARE
  target_schema TEXT := current_schema();
BEGIN
  EXECUTE format(
    'ALTER FUNCTION %I.accounts_guard_removed_custom_tool() SET search_path = pg_catalog, %I',
    target_schema,
    target_schema
  );
  EXECUTE format(
    'ALTER FUNCTION %I.custom_tool_tombstone_guard() SET search_path = pg_catalog, %I',
    target_schema,
    target_schema
  );
  EXECUTE format(
    'ALTER FUNCTION %I.custom_tool_registration_reactivate() SET search_path = pg_catalog, %I',
    target_schema,
    target_schema
  );
  EXECUTE format(
    'ALTER FUNCTION %I.custom_tool_registration_tombstone() SET search_path = pg_catalog, %I',
    target_schema,
    target_schema
  );
END
$migration$;

REVOKE ALL PRIVILEGES ON FUNCTION accounts_guard_removed_custom_tool() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION custom_tool_tombstone_guard() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION custom_tool_registration_reactivate() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION custom_tool_registration_tombstone() FROM PUBLIC;
