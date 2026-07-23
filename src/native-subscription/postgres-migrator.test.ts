import { describe, expect, test } from "bun:test";

import { AccountsError } from "./errors.js";
import {
  POSTGRES_FINAL_TABLES,
  POSTGRES_GLOBAL_REALM_TABLES,
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_MUTABLE_RUNTIME_TABLES,
  POSTGRES_OWNER_TABLES,
  POSTGRES_RUNTIME_INSERT_ONLY_TABLES,
  POSTGRES_RUNTIME_MUTABLE_TABLES,
} from "./postgres-migrations.js";
import { runPostgresMigrations } from "./postgres-migrator.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

const RUNTIME_ROLE = {
  mode: "direct",
  roleName: "accounts_runtime_test",
} as const;

const FUNCTION_SIGNATURES = [
  "current_principal()",
  "current_identity_realm()",
  "row_owned_by(candidate text)",
  "realm_is_current(candidate text)",
  "reject_terminal_credential_handle()",
  "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)",
  "require_handle_removed_before_revoke()",
  "reject_append_only_change()",
  "enforce_capsule_maintenance_grant_transition()",
] as const;

const RUNTIME_FUNCTIONS = new Set([
  "current_principal()",
  "current_identity_realm()",
  "row_owned_by(candidate text)",
  "realm_is_current(candidate text)",
  "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)",
]);

const TRIGGERS = new Map([
  ["credential_binding_handles_nonterminal", ["credential_binding_handles", "reject_terminal_credential_handle"]],
  ["credential_bindings_revoke_removes_handle", ["credential_bindings", "require_handle_removed_before_revoke"]],
  ["provider_subject_claims_immutable", ["provider_subject_claims", "reject_append_only_change"]],
  ["capacity_domain_claims_immutable", ["capacity_domain_claims", "reject_append_only_change"]],
  ["credential_family_claims_immutable", ["credential_family_claims", "reject_append_only_change"]],
  ["evidence_records_immutable", ["evidence_records", "reject_append_only_change"]],
  ["recovery_ledger_receipts_immutable", ["recovery_ledger_receipts", "reject_append_only_change"]],
  ["slot_eligibility_audit_immutable", ["slot_eligibility_audit", "reject_append_only_change"]],
  ["account_events_immutable", ["account_events", "reject_append_only_change"]],
  ["idempotency_records_immutable", ["idempotency_records", "reject_append_only_change"]],
  [
    "capsule_maintenance_grants_transition",
    ["capsule_maintenance_grants", "enforce_capsule_maintenance_grant_transition"],
  ],
  ["capsule_maintenance_uses_immutable", ["capsule_maintenance_uses", "reject_append_only_change"]],
  ["capability_use_consumptions_immutable", ["capability_use_consumptions", "reject_append_only_change"]],
]);

interface FakeMigrationState {
  tableExists: boolean;
  rows: Array<{ version: string; checksum: string }>;
  appliedSql: string[];
  driftRls?: boolean;
}

function fakeClient(state: FakeMigrationState): PostgresSqlClient {
  const transaction = (async (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<unknown[]> => {
    const query = strings.join("?").replace(/\s+/g, " ").trim();
    if (query.includes("pg_advisory_xact_lock")) return [];
    if (query.includes("to_regclass('accounts.schema_migrations')")) {
      return [{ migration_table: state.tableExists ? "accounts.schema_migrations" : null }];
    }
    if (query.includes("SELECT version::text AS version, checksum")) {
      return [...state.rows].sort((left, right) => Number(left.version) - Number(right.version));
    }
    if (query.includes("INSERT INTO accounts.schema_migrations")) {
      state.tableExists = true;
      state.rows.push({ version: String(values[0]), checksum: String(values[1]) });
      return [];
    }
    if (query === "SELECT current_user AS owner") {
      return [{ owner: "accounts_migration_owner_test" }];
    }
    if (query.includes("FROM pg_catalog.pg_roles AS role")) {
      return [String(values[0])].map((rolname) => ({
        rolname,
        rolsuper: false,
        rolinherit: false,
        rolcreaterole: false,
        rolcreatedb: false,
        rolcanlogin: true,
        rolreplication: false,
        rolbypassrls: false,
        memberships: [],
        members: [],
        admin_memberships: 0,
      }));
    }
    if (
      query.includes("FROM pg_catalog.pg_namespace AS namespace") &&
      query.includes("foreign_objects")
    ) {
      return [{
        owner_is_current: true,
        runtime_usage: true,
        runtime_create: false,
        public_usage: false,
        public_create: false,
        foreign_objects: 0,
        foreign_grants: 0,
      }];
    }
    if (query.includes("relation.relrowsecurity AS row_security")) {
      const mutable = new Set<string>(POSTGRES_RUNTIME_MUTABLE_TABLES);
      const insertOnly = new Set<string>(POSTGRES_RUNTIME_INSERT_ONLY_TABLES);
      return [...POSTGRES_FINAL_TABLES].sort().map((relname) => ({
        relname,
        owner_is_current: true,
        row_security: relname !== "schema_migrations",
        force_row_security: relname !== "schema_migrations" &&
          !(state.driftRls === true && relname === "provider_accounts"),
        runtime_select: true,
        runtime_insert: mutable.has(relname) || insertOnly.has(relname),
        runtime_update: mutable.has(relname),
        runtime_delete: false,
        runtime_truncate: false,
        runtime_references: false,
        runtime_trigger: false,
        public_any: false,
      }));
    }
    if (query.includes("pg_get_function_identity_arguments")) {
      return [...FUNCTION_SIGNATURES].sort().map((signature) => ({
        signature,
        owner_is_current: true,
        security_invoker: signature !==
          "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)",
        safe_search_path: true,
        public_execute: false,
        runtime_execute: RUNTIME_FUNCTIONS.has(signature),
      }));
    }
    if (query.includes("trigger.tgname AS trigger_name")) {
      return [...TRIGGERS].sort(([left], [right]) => left.localeCompare(right)).map(
        ([trigger_name, contract]) => ({
          trigger_name,
          table_name: contract[0],
          function_name: contract[1],
          enabled: "O",
        }),
      );
    }
    if (query.includes("policy.polname AS policy_name")) return policyRows();
    throw new Error(`unexpected fake query: ${query}`);
  }) as unknown as PostgresTransaction;
  transaction.unsafe = ((sql: string) => ({
    simple: async () => {
      state.appliedSql.push(sql);
      if (sql.includes("CREATE TABLE accounts.schema_migrations")) state.tableExists = true;
      return [];
    },
  })) as PostgresTransaction["unsafe"];

  return {
    begin: async (_mode, callback) => callback(transaction),
  };
}

function policyRows(): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  const add = (
    table: string,
    scope: "owner" | "realm",
    expression: string,
    mutable: boolean,
  ) => {
    rows.push({
      policy_name: `${table}_${scope}_select`,
      table_name: table,
      command: "r",
      public_only: true,
      permissive: true,
      using_expression: expression,
      check_expression: null,
    });
    rows.push({
      policy_name: `${table}_${scope}_insert`,
      table_name: table,
      command: "a",
      public_only: true,
      permissive: true,
      using_expression: null,
      check_expression: expression,
    });
    if (mutable) {
      rows.push({
        policy_name: `${table}_${scope}_update`,
        table_name: table,
        command: "w",
        public_only: true,
        permissive: true,
        using_expression: expression,
        check_expression: expression,
      });
    }
  };
  for (const table of POSTGRES_OWNER_TABLES) {
    add(
      table,
      "owner",
      "accounts.row_owned_by(owner_ref)",
      POSTGRES_MUTABLE_RUNTIME_TABLES.includes(
        table as (typeof POSTGRES_MUTABLE_RUNTIME_TABLES)[number],
      ),
    );
  }
  for (const table of POSTGRES_GLOBAL_REALM_TABLES) {
    add(
      table,
      "realm",
      "accounts.realm_is_current(identity_realm)",
      POSTGRES_MUTABLE_RUNTIME_TABLES.includes(
        table as (typeof POSTGRES_MUTABLE_RUNTIME_TABLES)[number],
      ),
    );
  }
  add(
    "capsule_maintenance_grants",
    "owner",
    "accounts.row_owned_by(owner_ref)",
    true,
  );
  add("capsule_maintenance_uses", "owner", "accounts.row_owned_by(owner_ref)", false);
  add("capability_use_consumptions", "owner", "accounts.row_owned_by(owner_ref)", false);
  return rows.sort((left, right) =>
    String(left.policy_name).localeCompare(String(right.policy_name))
  );
}

describe("Postgres migration runner", () => {
  test("applies, catalog-attests, and reattests without reapplying package SQL", async () => {
    const state: FakeMigrationState = { tableExists: false, rows: [], appliedSql: [] };
    const client = fakeClient(state);

    const first = await runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE });
    const second = await runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE });

    expect(first.appliedVersions).toEqual(["1", "2", "3"]);
    expect(second.appliedVersions).toEqual([]);
    expect(first.migrationChecksum).toBe(POSTGRES_MIGRATION_CHECKSUM);
    expect(first.runtimeRole).toBe(RUNTIME_ROLE.roleName);
    expect(first.runtimeRoleMode).toBe("direct");
    expect(
      state.appliedSql.filter((sql) => sql.includes("CREATE TABLE accounts.")).length,
    ).toBe(3);
  });

  test("rejects a checksum mismatch without applying SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{ version: "1", checksum: `sha256:${"0".repeat(64)}` }],
      appliedSql: [],
    };
    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("rejects a newer schema before applying package SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{ version: "4", checksum: `sha256:${"1".repeat(64)}` }],
      appliedSql: [],
    };
    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_VERSION_UNSUPPORTED",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("rejects catalog drift even when the checksum ledger is intact", async () => {
    const state: FakeMigrationState = { tableExists: false, rows: [], appliedSql: [] };
    const client = fakeClient(state);
    await runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE });
    state.driftRls = true;
    await expect(
      runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    });
  });
});
