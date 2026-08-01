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
    expect(ids).toContain("accounts_0006_purge_test_tool_fixtures");
    expect(ids.some((id) => id.startsWith("hasna_auth_"))).toBe(true);
    for (const m of migrations) {
      expect(m.checksum.startsWith("sha256:")).toBe(true);
      expect(m.sql.length).toBeGreaterThan(0);
    }
  });

  test("fixture purge migration names every leaked production test tool", () => {
    const purge = accountsMigrations().find(
      (migration) => migration.id === "accounts_0006_purge_test_tool_fixtures",
    );
    expect(purge).toBeDefined();
    for (const id of ["fake-login", "fake-variant", "missing-review", "review-state-shape"]) {
      expect(purge!.sql).toContain(`('${id}')`);
    }
  });

  test("checksums are deterministic across builds", () => {
    const a = accountsMigrations().map((m) => `${m.id}:${m.checksum}`);
    const b = accountsMigrations().map((m) => `${m.id}:${m.checksum}`);
    expect(a).toEqual(b);
  });
});

// R-P1-4 (2026-07-31-accounts-debloat-design.md): the `accounts` table gains
// `aliases`/`native_name` columns so a rename can be recorded, not just
// performed.
test("migration 0007 adds the aliases/native_name columns", () => {
  const migrations = accountsMigrations();
  const ids = migrations.map((m) => m.id);
  expect(ids).toContain("accounts_0007_alias_records");
  const migration = migrations.find((m) => m.id === "accounts_0007_alias_records")!;
  expect(migration.sql).toMatch(/ALTER TABLE\s+accounts/i);
  expect(migration.sql).toMatch(/aliases/i);
  expect(migration.sql).toMatch(/native_name/i);
});
