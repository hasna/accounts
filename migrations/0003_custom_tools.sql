-- custom tools registry: user-registered tools/apps (on top of the built-ins).
-- Mirrors the local ToolDef shape (src/types.ts) but persisted in cloud Postgres
-- per Amendment A1 (PURE REMOTE): the accounts-serve API reads and writes here
-- directly, so a custom tool registered on one machine propagates to the shared
-- fleet registry. The full ToolDef is stored as JSONB under `definition`.
CREATE TABLE IF NOT EXISTS custom_tools (
  id          TEXT PRIMARY KEY,
  definition  JSONB NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
