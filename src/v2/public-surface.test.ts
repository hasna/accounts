import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as v2 from "./index.js";

const migrationsDir = join(process.cwd(), "migrations");

/** Every shipped migration concatenated, so table checks are schema-derived. */
function shippedMigrationSql(): string {
  return readdirSync(migrationsDir)
    .filter((file) => file.endsWith(".sql"))
    .sort()
    .map((file) => readFileSync(join(migrationsDir, file), "utf8"))
    .join("\n");
}

describe("v2 public entry point", () => {
  test("exports the PostgreSQL adapter only once its tables have a shipped migration", () => {
    const sql = shippedMigrationSql();
    const migrated = ["accounts_v2", "runtimes_v2"].every((table) => sql.includes(table));
    // Publishing the adapter before the migration slice lands would hand
    // consumers a registry whose first query fails on a missing relation.
    expect(Object.keys(v2).includes("PostgresAccountsRegistry")).toBe(migrated);
  });

  test("exports the adapters whose backends need no shipped migration", () => {
    expect(Object.keys(v2)).toContain("LocalAccountsRegistry");
    expect(Object.keys(v2)).toContain("HttpAccountsRegistry");
  });
});
