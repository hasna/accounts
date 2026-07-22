import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  accountsMigrations,
  assertAccountsMigrationDeploySafe,
  resolveMigrationsDir,
  APP_MIGRATION_FILES,
} from "./migrations.js";

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
    expect(ids).toContain("accounts_0007_login_operation_rollback_state");
    expect(ids).toContain("accounts_0008_account_incarnations");
    expect(ids).toContain("accounts_0009_login_operation_target_incarnation");
    expect(ids).toContain("accounts_0010_login_cleanup_operations");
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

  test("shipped migration 0006 stays checksum-stable and rollback ownership remains additive", () => {
    const migrations = accountsMigrations();
    const revisions = migrations.find((item) => item.id === "accounts_0006_current_selection_revisions");
    const rollbackState = migrations.find((item) => item.id === "accounts_0007_login_operation_rollback_state");
    const accountIncarnations = migrations.find((item) => item.id === "accounts_0008_account_incarnations");
    const operationTargetIncarnation = migrations.find(
      (item) => item.id === "accounts_0009_login_operation_target_incarnation",
    );
    const cleanupOperations = migrations.find(
      (item) => item.id === "accounts_0010_login_cleanup_operations",
    );
    expect(revisions?.checksum).toBe(
      "sha256:fb55c634d8062524ffa86cf4ab45630d294f7750fd3c817e0c0a90c6b53d873c",
    );
    expect(rollbackState?.sql).toMatch(/ADD COLUMN IF NOT EXISTS previous_name TEXT/);
    expect(rollbackState?.sql).toMatch(/ADD COLUMN IF NOT EXISTS previous_target_last_used_at TIMESTAMPTZ/);
    expect(accountIncarnations?.sql).toMatch(/ADD COLUMN IF NOT EXISTS incarnation_id UUID/);
    expect(accountIncarnations?.sql).toMatch(/SET DEFAULT pg_catalog\.gen_random_uuid\(\)/);
    expect(operationTargetIncarnation?.sql).toMatch(
      /ADD COLUMN IF NOT EXISTS target_incarnation_id UUID/,
    );
    expect(cleanupOperations?.sql).toMatch(
      /CREATE TABLE IF NOT EXISTS account_login_cleanup_operations/,
    );
    expect(cleanupOperations?.sql).toMatch(/operation_id UUID PRIMARY KEY/);
    expect(cleanupOperations?.sql).toMatch(/request_digest/);
    expect(cleanupOperations?.sql).toMatch(/operation_class/);
    expect(cleanupOperations?.sql).toMatch(/requested_at TIMESTAMPTZ NOT NULL/);
    expect(cleanupOperations?.sql).toMatch(/completed_at TIMESTAMPTZ/);
    expect(cleanupOperations?.sql).toMatch(/completed_at IS NULL AND removed IS NULL/);
  });

  test("deployment remains blocked while cleanup migration atomicity is unresolved", () => {
    expect(() => assertAccountsMigrationDeploySafe({
      ledgerPresent: true,
      pending: ["accounts_0010_login_cleanup_operations"],
      unknown: [],
      checksumMismatches: [],
    })).toThrow(/f799e8a5-fc9e-4735-bfb9-8a0c17b90b25/);
    const deploymentGuide = readFileSync(
      join(process.cwd(), "docs", "STORAGE_STABILIZATION.md"),
      "utf8",
    );
    expect(deploymentGuide).toContain("Do not run `accounts-migrate`");
    expect(deploymentGuide).toContain("Source merge does not apply migrations");
    expect(deploymentGuide).toContain("f799e8a5-fc9e-4735-bfb9-8a0c17b90b25");
    const migrator = readFileSync(join(process.cwd(), "src", "server", "migrate.ts"), "utf8");
    const gate = migrator.indexOf("assertAccountsMigrationDeploySafe(status);");
    const apply = migrator.indexOf("const ledger = new MigrationLedger");
    expect(gate).toBeGreaterThanOrEqual(0);
    expect(apply).toBeGreaterThan(gate);
  });
});
