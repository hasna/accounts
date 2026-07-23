import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";

import {
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_MIGRATIONS,
  POSTGRES_MIGRATION_V1,
  POSTGRES_MIGRATION_V2,
  POSTGRES_MIGRATION_V3,
  POSTGRES_REQUIRED_TABLES,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations.js";

describe("Postgres migration contract", () => {
  test("pins the checked migration bytes", () => {
    const digestV1 = `sha256:${createHash("sha256").update(POSTGRES_MIGRATION_V1, "utf8").digest("hex")}`;
    const digestV2 = `sha256:${createHash("sha256").update(POSTGRES_MIGRATION_V2, "utf8").digest("hex")}`;
    const digestV3 = `sha256:${createHash("sha256").update(POSTGRES_MIGRATION_V3, "utf8").digest("hex")}`;
    expect(POSTGRES_SCHEMA_VERSION).toBe(3);
    expect(POSTGRES_MIGRATION_CHECKSUM).toBe(digestV3);
    expect(POSTGRES_MIGRATIONS).toEqual([
      { version: 1, checksum: digestV1, sql: POSTGRES_MIGRATION_V1 },
      { version: 2, checksum: digestV2, sql: POSTGRES_MIGRATION_V2 },
      { version: 3, checksum: digestV3, sql: POSTGRES_MIGRATION_V3 },
    ]);
  });

  test("defines every final contract table", () => {
    for (const table of POSTGRES_REQUIRED_TABLES) {
      expect(POSTGRES_MIGRATION_V1).toContain(`CREATE TABLE accounts.${table}`);
    }
  });

  test("keeps stable schema bytes role-agnostic and force-enables RLS", () => {
    expect(POSTGRES_MIGRATION_V1).not.toContain("accounts_runtime");
    expect(POSTGRES_MIGRATION_V1).not.toMatch(/CREATE ROLE/i);
    expect(POSTGRES_MIGRATION_V1).toContain("REVOKE ALL ON SCHEMA accounts FROM PUBLIC");
    expect(POSTGRES_MIGRATION_V1).toContain("FOR SELECT TO PUBLIC");
    expect(POSTGRES_MIGRATION_V1).toContain(
      "REVOKE ALL ON ALL TABLES IN SCHEMA accounts FROM PUBLIC",
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

  test("adds durable one-live maintenance reservations and ordinal-one receipts", () => {
    expect(POSTGRES_MIGRATION_V2).toContain("CREATE TABLE accounts.capsule_maintenance_grants");
    expect(POSTGRES_MIGRATION_V2).toContain("CREATE TABLE accounts.capsule_maintenance_uses");
    expect(POSTGRES_MIGRATION_V2).toContain("capsule_maintenance_one_live_reservation");
    expect(POSTGRES_MIGRATION_V2).toContain("WHERE state = 'live'");
    expect(POSTGRES_MIGRATION_V2).toContain("UNIQUE (owner_ref, idempotency_key_digest)");
    expect(POSTGRES_MIGRATION_V2).toContain("grant_id UUID PRIMARY KEY");
    expect(POSTGRES_MIGRATION_V2).toContain("capsule_maintenance_uses_immutable");
    expect(POSTGRES_MIGRATION_V2).toContain(
      "ALTER TABLE accounts.capsule_maintenance_grants FORCE ROW LEVEL SECURITY",
    );
    expect(POSTGRES_MIGRATION_V2).toContain(
      "ALTER TABLE accounts.capsule_maintenance_uses FORCE ROW LEVEL SECURITY",
    );
  });

  test("adds durable owner-scoped capability-use CAS and immutable ordinal-one evidence", () => {
    expect(POSTGRES_MIGRATION_V3).toContain("CREATE TABLE accounts.capability_use_consumptions");
    expect(POSTGRES_MIGRATION_V3).toContain("PRIMARY KEY (owner_ref, consume_request_id)");
    expect(POSTGRES_MIGRATION_V3).toContain("UNIQUE (owner_ref, capability_id)");
    expect(POSTGRES_MIGRATION_V3).toContain("UNIQUE (owner_ref, idempotency_key_digest)");
    expect(POSTGRES_MIGRATION_V3).toContain("FOR EACH ROW EXECUTE FUNCTION accounts.reject_append_only_change()");
    expect(POSTGRES_MIGRATION_V3).toContain("FORCE ROW LEVEL SECURITY");
    expect(POSTGRES_MIGRATION_V3).toContain("accounts.row_owned_by(owner_ref)");
  });
});
