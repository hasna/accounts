-- Keep current selections referentially tied to accounts. Cascades make
-- rename/remove atomic with the selected pointer, while row locks in the
-- repository serialize those operations against setCurrent.
DELETE FROM current_selections AS current
WHERE NOT EXISTS (
  SELECT 1
  FROM accounts
  WHERE accounts.tool = current.tool
    AND accounts.name = current.name
);

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
