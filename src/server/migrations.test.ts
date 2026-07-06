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
});
