import { describe, expect, test } from "bun:test";
import { accountsMigrations, resolveMigrationsDir, APP_MIGRATION_FILES } from "./migrations.js";

describe("accounts migrations", () => {
  test("resolves the migrations dir and loads the app SQL files", () => {
    const dir = resolveMigrationsDir();
    expect(dir).toContain("migrations");
    expect(APP_MIGRATION_FILES.length).toBeGreaterThanOrEqual(2);
  });

  test("builds a de-duplicated, checksum-stamped migration list (app + auth)", () => {
    const migrations = accountsMigrations();
    // app (2) + api-key auth (2)
    expect(migrations.length).toBeGreaterThanOrEqual(4);
    const ids = migrations.map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain("accounts_0001_accounts");
    expect(ids).toContain("accounts_0003_custom_tools");
    expect(ids).toContain("accounts_0004_current_selection_account_fk");
    expect(ids).toContain("accounts_0005_custom_tool_tombstones");
    expect(ids).toContain("accounts_0006_current_selection_revisions");
    expect(ids.some((id) => id.startsWith("hasna_auth_"))).toBe(true);
    for (const m of migrations) {
      expect(m.checksum.startsWith("sha256:")).toBe(true);
      expect(m.sql.length).toBeGreaterThan(0);
    }
  });

  test("checksums are deterministic across builds", () => {
    const a = accountsMigrations().map((m) => `${m.id}:${m.checksum}`);
    const b = accountsMigrations().map((m) => `${m.id}:${m.checksum}`);
    expect(a).toEqual(b);
  });

  test("current-selection revisions advance for legacy conflict updates", () => {
    const migration = accountsMigrations().find((item) => item.id === "accounts_0006_current_selection_revisions");
    expect(migration?.sql).toMatch(/BEFORE INSERT OR UPDATE ON current_selections/);
    expect(migration?.sql).toMatch(
      /NEW\.revision := pg_catalog\.nextval\([\s\S]*TG_TABLE_SCHEMA[\s\S]*pg_catalog\.regclass/,
    );
    expect(migration?.sql).toMatch(/SECURITY DEFINER/);
    expect(migration?.sql).toMatch(/ALTER COLUMN revision DROP DEFAULT/);
    expect(migration?.sql).toMatch(/CREATE TABLE IF NOT EXISTS current_login_operations/);
    expect(migration?.sql).toMatch(/operation_id UUID PRIMARY KEY/);
    expect(migration?.sql).toMatch(/REVOKE ALL PRIVILEGES ON SEQUENCE current_selection_revision_seq FROM PUBLIC/);
  });
});
