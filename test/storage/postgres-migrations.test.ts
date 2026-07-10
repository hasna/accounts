import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";

import {
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_MIGRATIONS,
  POSTGRES_MIGRATION_V1,
  POSTGRES_REQUIRED_TABLES,
  POSTGRES_SCHEMA_VERSION,
} from "../../src/storage/postgres-migrations";

describe("Postgres migration contract", () => {
  test("pins the checked migration bytes", () => {
    const digest = `sha256:${createHash("sha256").update(POSTGRES_MIGRATION_V1, "utf8").digest("hex")}`;
    expect(POSTGRES_SCHEMA_VERSION).toBe(1);
    expect(POSTGRES_MIGRATION_CHECKSUM).toBe(digest);
    expect(POSTGRES_MIGRATIONS).toEqual([
      { version: 1, checksum: digest, sql: POSTGRES_MIGRATION_V1 },
    ]);
  });

  test("defines every final contract table", () => {
    for (const table of POSTGRES_REQUIRED_TABLES) {
      expect(POSTGRES_MIGRATION_V1).toContain(`CREATE TABLE accounts.${table}`);
    }
  });

  test("creates a least-privilege runtime role and force-enables RLS", () => {
    expect(POSTGRES_MIGRATION_V1).toMatch(
      /CREATE ROLE accounts_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS/,
    );
    expect(POSTGRES_MIGRATION_V1).toContain("pg_catalog.pg_auth_members");
    expect(POSTGRES_MIGRATION_V1).toContain("REVOKE ALL ON SCHEMA accounts FROM PUBLIC");
    expect(POSTGRES_MIGRATION_V1).toContain(
      "GRANT SELECT ON TABLE accounts.schema_migrations TO accounts_runtime",
    );
    for (const table of POSTGRES_REQUIRED_TABLES.filter(
      (candidate) => candidate !== "schema_migrations",
    )) {
      expect(POSTGRES_MIGRATION_V1).toContain(
        `ALTER TABLE accounts.${table} FORCE ROW LEVEL SECURITY`,
      );
    }
  });

  test("binds tenant policies to transaction-local principal and realm settings", () => {
    expect(POSTGRES_MIGRATION_V1).toContain("current_setting('accounts.principal', true)");
    expect(POSTGRES_MIGRATION_V1).toContain("current_setting('accounts.identity_realm', true)");
    expect(POSTGRES_MIGRATION_V1).toContain("WITH CHECK (accounts.row_owned_by(owner_ref))");
    expect(POSTGRES_MIGRATION_V1).toContain(
      "WITH CHECK (accounts.realm_is_current(identity_realm))",
    );
    expect(POSTGRES_MIGRATION_V1).not.toMatch(/USING\s*\(\s*true\s*\)/i);
  });

  test("enforces terminal credential shape and immutable lineage in the database", () => {
    expect(POSTGRES_MIGRATION_V1).toContain("credential_bindings_terminal_shape");
    expect(POSTGRES_MIGRATION_V1).toContain("credential_binding_handles_nonterminal");
    expect(POSTGRES_MIGRATION_V1).toContain("delete_credential_handle_for_revocation");
    expect(POSTGRES_MIGRATION_V1).toContain("provider_subject_claims");
    expect(POSTGRES_MIGRATION_V1).toContain("capacity_domain_claims");
    expect(POSTGRES_MIGRATION_V1).toContain("credential_family_claims");
    expect(POSTGRES_MIGRATION_V1).toContain("credential_operations_one_active_family_domain");
  });
});
