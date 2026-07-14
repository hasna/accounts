-- Preserve any pre-existing orphan selection before enforcing referential
-- integrity. Operators must take a database backup before this migration; the
-- archive provides row-level evidence for reconciliation after the upgrade.
CREATE TABLE IF NOT EXISTS current_selection_orphan_archive (
  tool        TEXT NOT NULL,
  name        TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason      TEXT NOT NULL DEFAULT 'missing account during migration 0004',
  PRIMARY KEY (tool, name, updated_at)
);

INSERT INTO current_selection_orphan_archive (tool, name, updated_at)
SELECT current.tool, current.name, current.updated_at
FROM current_selections AS current
WHERE NOT EXISTS (
  SELECT 1
  FROM accounts
  WHERE accounts.tool = current.tool
    AND accounts.name = current.name
)
ON CONFLICT (tool, name, updated_at) DO NOTHING;

DELETE FROM current_selections AS current
WHERE NOT EXISTS (
  SELECT 1
  FROM accounts
  WHERE accounts.tool = current.tool
    AND accounts.name = current.name
);

-- Keep current selections referentially tied to accounts. Cascades make
-- rename/remove atomic with the selected pointer, while row locks in the
-- repository serialize those operations against setCurrent.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'current_selections_account_fk'
      AND conrelid = 'current_selections'::regclass
  ) THEN
    ALTER TABLE current_selections
      ADD CONSTRAINT current_selections_account_fk
      FOREIGN KEY (tool, name)
      REFERENCES accounts (tool, name)
      ON UPDATE CASCADE
      ON DELETE CASCADE;
  END IF;
END
$$;
