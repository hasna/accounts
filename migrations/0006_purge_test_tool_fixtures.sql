-- Four login/review test harness tools escaped into the production registry.
-- Remove their dependent test profiles before deleting the tool definitions:
-- migration 0005 intentionally refuses to remove an in-use custom tool.
-- Tombstone every id even when its definition is already absent so an older
-- account writer cannot silently recreate the leaked fixture.
DO $migration$
DECLARE
  leaked_tool_id TEXT;
BEGIN
  -- Serialize with account/tool writers in the same deterministic order used
  -- by the custom-tool lifecycle guards.
  FOR leaked_tool_id IN
    SELECT fixture.id
    FROM (VALUES
      ('fake-login'),
      ('fake-variant'),
      ('missing-review'),
      ('review-state-shape')
    ) AS fixture(id)
    ORDER BY fixture.id
  LOOP
    PERFORM pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended('accounts:tool:' || leaked_tool_id, 0)
    );
  END LOOP;

  DELETE FROM accounts
  WHERE tool IN (
    'fake-login',
    'fake-variant',
    'missing-review',
    'review-state-shape'
  );

  DELETE FROM custom_tools
  WHERE id IN (
    'fake-login',
    'fake-variant',
    'missing-review',
    'review-state-shape'
  );

  INSERT INTO custom_tool_tombstones (id)
  VALUES
    ('fake-login'),
    ('fake-variant'),
    ('missing-review'),
    ('review-state-shape')
  ON CONFLICT (id) DO NOTHING;
END
$migration$;
