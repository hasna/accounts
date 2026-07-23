import { describe, expect, test } from "bun:test";

import { AccountsError } from "./errors.js";
import {
  POSTGRES_FINAL_TABLES,
  POSTGRES_GLOBAL_REALM_TABLES,
  POSTGRES_MIGRATIONS,
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_MUTABLE_RUNTIME_TABLES,
  POSTGRES_OWNER_TABLES,
  POSTGRES_RUNTIME_INSERT_ONLY_TABLES,
  POSTGRES_RUNTIME_MUTABLE_TABLES,
} from "./postgres-migrations.js";
import { runPostgresMigrations } from "./postgres-migrator.js";
import { POSTGRES_SCHEMA_MANIFEST } from "./postgres-schema-manifest.js";
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
  ["schema_migrations_immutable", ["schema_migrations", "reject_append_only_change"]],
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
  rows: Array<{
    version: string;
    checksum: string;
    appliedAt?: string;
    ledgerSequence?: string;
  }>;
  appliedSql: string[];
  hasLedgerSequence?: boolean;
  residualObjectCount?: number;
  driftRls?: boolean;
  extraSchemaObject?: boolean;
  extraSchemaType?: boolean;
  driftTypeAcl?: boolean;
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
    if (query.includes("AS package_owned_objects")) {
      return [{ package_owned_objects: state.residualObjectCount ?? 0 }];
    }
    if (query.includes("AS has_ledger_sequence")) {
      return [{
        has_ledger_sequence: state.hasLedgerSequence ?? false,
        ledger_sequence_is_identity: state.hasLedgerSequence ?? false,
      }];
    }
    if (query.includes("SELECT version::text AS version, checksum")) {
      const rows = [...state.rows];
      if (
        query.includes("ORDER BY applied_at ASC") &&
        rows.every((row) => row.appliedAt !== undefined)
      ) {
        rows.sort((left, right) =>
          left.appliedAt!.localeCompare(right.appliedAt!)
        );
      }
      if (query.includes("ORDER BY ledger_sequence ASC")) {
        rows.sort((left, right) =>
          BigInt(left.ledgerSequence ?? "0") < BigInt(right.ledgerSequence ?? "0")
            ? -1
            : 1
        );
      }
      return rows.map(({ version, checksum, appliedAt, ledgerSequence }) => ({
        version,
        checksum,
        applied_at: appliedAt ?? `implicit-${version}`,
        applied_at_is_finite: appliedAt !== "infinity" && appliedAt !== "-infinity",
        applied_at_occurrences: appliedAt === undefined
          ? "1"
          : String(state.rows.filter((row) => row.appliedAt === appliedAt).length),
        ledger_sequence: ledgerSequence ?? null,
        ledger_sequence_occurrences: ledgerSequence === undefined
          ? "0"
          : String(
            state.rows.filter((row) => row.ledgerSequence === ledgerSequence).length,
          ),
      }));
    }
    if (query.includes("INSERT INTO accounts.schema_migrations")) {
      state.tableExists = true;
      state.rows.push({
        version: String(values[0]),
        checksum: String(values[1]),
        appliedAt: new Date(Date.UTC(2030, 0, 1) + state.rows.length).toISOString(),
        ...(state.hasLedgerSequence
          ? {
            ledgerSequence: String(
              state.rows.reduce(
                (highest, row) =>
                  row.ledgerSequence !== undefined &&
                    BigInt(row.ledgerSequence) > highest
                    ? BigInt(row.ledgerSequence)
                    : highest,
                0n,
              ) + 1n,
            ),
          }
          : {}),
      });
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
    if (query.includes("relation.relname AS object_name")) {
      const rows = [
        ...POSTGRES_FINAL_TABLES.map((object_name) => ({
          object_name,
          object_kind: "r",
          owner_is_current: true,
          acl_is_null: true,
        })),
        ...POSTGRES_SCHEMA_MANIFEST.constraints
          .filter((entry) => entry[2] === "p" || entry[2] === "u")
          .map((entry) => ({
            object_name: entry[1],
            object_kind: "i",
            owner_is_current: true,
            acl_is_null: true,
          })),
        ...POSTGRES_SCHEMA_MANIFEST.indexes.map((entry) => ({
          object_name: entry[1],
          object_kind: "i",
          owner_is_current: true,
          acl_is_null: true,
        })),
        {
          object_name: "schema_migrations_ledger_sequence_seq",
          object_kind: "S",
          owner_is_current: true,
          acl_is_null: false,
        },
      ];
      if (state.extraSchemaObject === true) {
        rows.push({
          object_name: "unexpected_view",
          object_kind: "v",
          owner_is_current: true,
          acl_is_null: true,
        });
      }
      return rows.sort((left, right) =>
        left.object_name.localeCompare(right.object_name) ||
        left.object_kind.localeCompare(right.object_kind)
      );
    }
    if (query.includes("type_entry.typname AS type_name")) {
      const rows = POSTGRES_FINAL_TABLES.flatMap((tableName) => [
        {
          type_name: tableName,
          type_kind: "c",
          type_category: "C",
          relation_name: tableName,
          relation_kind: "r",
          element_type_name: null,
          owner_is_current: true,
          public_usage: !(state.driftTypeAcl === true &&
            tableName === "provider_accounts"),
          runtime_usage: true,
          foreign_grants: "0",
          acl_is_null: !(state.driftTypeAcl === true &&
            tableName === "provider_accounts"),
        },
        {
          type_name: `_${tableName}`,
          type_kind: "b",
          type_category: "A",
          relation_name: null,
          relation_kind: null,
          element_type_name: tableName,
          owner_is_current: true,
          public_usage: true,
          runtime_usage: true,
          foreign_grants: "0",
          acl_is_null: true,
        },
      ]);
      if (state.extraSchemaType === true) {
        rows.push({
          type_name: "unexpected_status",
          type_kind: "e",
          type_category: "E",
          relation_name: null,
          relation_kind: null,
          element_type_name: null,
          owner_is_current: true,
          public_usage: true,
          runtime_usage: true,
          foreign_grants: "0",
          acl_is_null: true,
        });
      }
      return rows.sort((left, right) =>
        left.type_name.localeCompare(right.type_name)
      );
    }
    if (query.includes("pg_catalog.pg_sequence AS sequence")) {
      return [{
        sequence_name: "schema_migrations_ledger_sequence_seq",
        owner_is_current: true,
        owned_by_ledger_sequence: true,
        data_type: "bigint",
        increment: "1",
        minimum_value: "1",
        maximum_value: "9223372036854775807",
        cache_size: "1",
        cycles: false,
        public_select: false,
        public_usage: false,
        public_update: false,
        runtime_select: false,
        runtime_usage: false,
        runtime_update: false,
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
    if (query.includes("attribute.attnum AS ordinal_position")) {
      return POSTGRES_SCHEMA_MANIFEST.columns.map((entry) => ({
        table_name: entry[0],
        ordinal_position: entry[1],
        column_name: entry[2],
        data_type: entry[3],
        not_null: entry[4],
        default_expression: entry[5],
        identity_kind: entry[6],
        generated_kind: entry[7],
        collation_name: entry[8],
      }));
    }
    if (query.includes("constraint_entry.conname AS constraint_name")) {
      return POSTGRES_SCHEMA_MANIFEST.constraints.map((entry) => ({
        table_name: entry[0],
        constraint_name: entry[1],
        constraint_type: entry[2],
        definition: entry[3],
        deferrable: entry[4],
        initially_deferred: entry[5],
        validated: entry[6],
      }));
    }
    if (query.includes("index_relation.relname AS index_name")) {
      return POSTGRES_SCHEMA_MANIFEST.indexes.map((entry) => ({
        table_name: entry[0],
        index_name: entry[1],
        access_method: entry[2],
        unique_index: entry[3],
        valid: entry[4],
        ready: entry[5],
        live: entry[6],
        definition: entry[7],
        predicate: entry[8],
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
      if (sql.includes("ADD COLUMN ledger_sequence BIGINT")) {
        state.hasLedgerSequence = true;
        state.rows.forEach((row, index) => {
          row.ledgerSequence = String(index + 1);
        });
      }
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

    expect(first.appliedVersions).toEqual(["1", "2", "3", "4"]);
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

  test("rejects a gapped ledger before applying SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [POSTGRES_MIGRATIONS[0], POSTGRES_MIGRATIONS[2]].map((migration) => ({
        version: String(migration.version),
        checksum: migration.checksum,
      })),
      appliedSql: [],
    };
    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("rejects an empty ledger before applying SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [],
      appliedSql: [],
    };
    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("rejects a missing ledger when package-owned objects remain", async () => {
    const state: FakeMigrationState = {
      tableExists: false,
      rows: [],
      appliedSql: [],
      residualObjectCount: 1,
    };
    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("applies only migrations after a valid non-empty ledger prefix", async () => {
    const firstMigration = POSTGRES_MIGRATIONS[0];
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{
        version: String(firstMigration.version),
        checksum: firstMigration.checksum,
      }],
      appliedSql: [],
    };

    const report = await runPostgresMigrations(
      fakeClient(state),
      { runtimeRole: RUNTIME_ROLE },
    );

    expect(report.appliedVersions).toEqual(["2", "3", "4"]);
    expect(state.appliedSql.filter((sql) =>
      POSTGRES_MIGRATIONS.some((migration) => migration.sql === sql)
    )).toEqual([
      POSTGRES_MIGRATIONS[1].sql,
      POSTGRES_MIGRATIONS[2].sql,
      POSTGRES_MIGRATIONS[3].sql,
    ]);
  });

  test("rejects duplicate and out-of-order ledger rows before applying SQL", async () => {
    const validRows = POSTGRES_MIGRATIONS.map((migration) => ({
      version: String(migration.version),
      checksum: migration.checksum,
    }));
    for (const rows of [
      [validRows[0], validRows[1], validRows[1]],
      [validRows[1], validRows[0]],
    ]) {
      const state: FakeMigrationState = {
        tableExists: true,
        rows,
        appliedSql: [],
      };
      await expect(
        runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
      ).rejects.toMatchObject({
        code: "SCHEMA_CHECKSUM_MISMATCH",
      } satisfies Partial<AccountsError>);
      expect(state.appliedSql).toEqual([]);
    }
  });

  test("rejects equal-timestamp insertion order before applying SQL", async () => {
    const appliedAt = "2030-07-18T12:00:00.000Z";
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [POSTGRES_MIGRATIONS[1], POSTGRES_MIGRATIONS[0]].map((migration) => ({
        version: String(migration.version),
        checksum: migration.checksum,
        appliedAt,
      })),
      appliedSql: [],
    };

    await expect(
      runPostgresMigrations(fakeClient(state), { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("accepts a valid sequenced ledger independently of timestamp ties", async () => {
    const appliedAt = "2030-07-18T12:00:00.000Z";
    const state: FakeMigrationState = {
      tableExists: true,
      hasLedgerSequence: true,
      rows: POSTGRES_MIGRATIONS.map((migration, index) => ({
        version: String(migration.version),
        checksum: migration.checksum,
        appliedAt,
        ledgerSequence: String(index + 1),
      })),
      appliedSql: [],
    };

    const report = await runPostgresMigrations(
      fakeClient(state),
      { runtimeRole: RUNTIME_ROLE },
    );

    expect(report.appliedVersions).toEqual([]);
    expect(state.appliedSql.filter((sql) =>
      POSTGRES_MIGRATIONS.some((migration) => migration.sql === sql)
    )).toEqual([]);
  });

  test("rejects non-finite legacy timestamps before applying SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{
        version: String(POSTGRES_MIGRATIONS[0].version),
        checksum: POSTGRES_MIGRATIONS[0].checksum,
        appliedAt: "infinity",
      }],
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
      rows: [{ version: "5", checksum: `sha256:${"1".repeat(64)}` }],
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

    state.driftRls = false;
    state.extraSchemaObject = true;
    await expect(
      runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    });

    state.extraSchemaObject = false;
    state.extraSchemaType = true;
    await expect(
      runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    });

    state.extraSchemaType = false;
    state.driftTypeAcl = true;
    await expect(
      runPostgresMigrations(client, { runtimeRole: RUNTIME_ROLE }),
    ).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    });
  });
});
