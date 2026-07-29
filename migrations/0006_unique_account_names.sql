-- BREAKING: account names are unique across tools in this single-registry
-- schema. Keep PRIMARY KEY (tool, name): current_selections and existing
-- clients continue to identify an account by the composite key.
--
-- The table lock makes the collision check and constraint installation one
-- atomic enforcement boundary across every writer in the fleet. Reconcile all
-- reported collisions before retrying; this migration never deletes or
-- rewrites an account.
LOCK TABLE accounts IN SHARE ROW EXCLUSIVE MODE;

DO $migration$
DECLARE
  collision_count BIGINT;
  collision_sample TEXT;
BEGIN
  SELECT count(*)
    INTO collision_count
    FROM (
      SELECT name
      FROM accounts
      GROUP BY name
      HAVING count(*) > 1
    ) AS collisions;

  SELECT string_agg(name, ', ' ORDER BY name)
    INTO collision_sample
    FROM (
      SELECT name
      FROM accounts
      GROUP BY name
      HAVING count(*) > 1
      ORDER BY name
      LIMIT 10
    ) AS collisions;

  IF collision_count > 0 THEN
    RAISE EXCEPTION
      'migration 0006 refused: account-name collision report is not zero (% conflicting names; sample: %)',
      collision_count,
      collision_sample
      USING ERRCODE = '23505',
            HINT = 'Reconcile every duplicate account name, rerun the collision report, then retry.';
  END IF;
END
$migration$;

DO $migration$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint AS constraint_row
    JOIN pg_attribute AS name_column
      ON name_column.attrelid = constraint_row.conrelid
     AND name_column.attname = 'name'
    WHERE constraint_row.conrelid = 'accounts'::regclass
      AND constraint_row.contype = 'u'
      AND constraint_row.conkey = ARRAY[name_column.attnum]::smallint[]
  ) THEN
    ALTER TABLE accounts
      ADD CONSTRAINT accounts_name_key UNIQUE (name);
  END IF;
END
$migration$;
