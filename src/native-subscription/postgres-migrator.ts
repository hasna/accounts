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
  POSTGRES_RUNTIME_READ_ONLY_TABLES,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations.js";
import {
  quotePostgresIdentifier,
  validatePostgresRuntimeRoleBoundary,
  type PostgresRuntimeRoleBoundary,
} from "./postgres-runtime.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

interface MigrationRow {
  readonly version: string | number | bigint;
  readonly checksum: string;
}

interface RoleRow {
  readonly rolname: string;
  readonly rolsuper: boolean;
  readonly rolinherit: boolean;
  readonly rolcreaterole: boolean;
  readonly rolcreatedb: boolean;
  readonly rolcanlogin: boolean;
  readonly rolreplication: boolean;
  readonly rolbypassrls: boolean;
  readonly memberships: readonly string[];
  readonly members: readonly string[];
  readonly admin_memberships: number;
}

interface TableCatalogRow {
  readonly relname: string;
  readonly owner_is_current: boolean;
  readonly row_security: boolean;
  readonly force_row_security: boolean;
  readonly runtime_select: boolean;
  readonly runtime_insert: boolean;
  readonly runtime_update: boolean;
  readonly runtime_delete: boolean;
  readonly runtime_truncate: boolean;
  readonly runtime_references: boolean;
  readonly runtime_trigger: boolean;
  readonly public_any: boolean;
}

interface FunctionCatalogRow {
  readonly signature: string;
  readonly owner_is_current: boolean;
  readonly security_invoker: boolean;
  readonly safe_search_path: boolean;
  readonly public_execute: boolean;
  readonly runtime_execute: boolean;
}

interface TriggerCatalogRow {
  readonly trigger_name: string;
  readonly table_name: string;
  readonly function_name: string;
  readonly enabled: string;
}

interface PolicyCatalogRow {
  readonly policy_name: string;
  readonly table_name: string;
  readonly command: string;
  readonly public_only: boolean;
  readonly permissive: boolean;
  readonly using_expression: string | null;
  readonly check_expression: string | null;
}

interface ExpectedPolicy {
  readonly tableName: string;
  readonly command: "r" | "a" | "w";
  readonly usingExpression: string | null;
  readonly checkExpression: string | null;
}

const RUNTIME_FUNCTIONS = new Set([
  "current_principal()",
  "current_identity_realm()",
  "row_owned_by(candidate text)",
  "realm_is_current(candidate text)",
  "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)",
]);

const EXPECTED_FUNCTIONS = Object.freeze([
  "current_principal()",
  "current_identity_realm()",
  "row_owned_by(candidate text)",
  "realm_is_current(candidate text)",
  "reject_terminal_credential_handle()",
  "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)",
  "require_handle_removed_before_revoke()",
  "reject_append_only_change()",
  "enforce_capsule_maintenance_grant_transition()",
] as const);

const SECURITY_DEFINER_FUNCTION =
  "delete_credential_handle_for_revocation(target_binding_id uuid, target_owner_ref text)";

const EXPECTED_TRIGGERS = new Map<string, {
  readonly tableName: string;
  readonly functionName: string;
}>([
  ["credential_binding_handles_nonterminal", {
    tableName: "credential_binding_handles",
    functionName: "reject_terminal_credential_handle",
  }],
  ["credential_bindings_revoke_removes_handle", {
    tableName: "credential_bindings",
    functionName: "require_handle_removed_before_revoke",
  }],
  ...[
    "provider_subject_claims",
    "capacity_domain_claims",
    "credential_family_claims",
    "evidence_records",
    "recovery_ledger_receipts",
    "slot_eligibility_audit",
    "account_events",
    "idempotency_records",
  ].map((tableName) => [
    `${tableName}_immutable`,
    { tableName, functionName: "reject_append_only_change" },
  ] as const),
  [
    "capsule_maintenance_grants_transition",
    {
      tableName: "capsule_maintenance_grants",
      functionName: "enforce_capsule_maintenance_grant_transition",
    },
  ],
  ["capsule_maintenance_uses_immutable", {
    tableName: "capsule_maintenance_uses",
    functionName: "reject_append_only_change",
  }],
  ["capability_use_consumptions_immutable", {
    tableName: "capability_use_consumptions",
    functionName: "reject_append_only_change",
  }],
]);

export interface PostgresMigrationOptions {
  readonly runtimeRole: PostgresRuntimeRoleBoundary;
}

export interface PostgresMigrationReport {
  readonly schemaVersion: string;
  readonly migrationChecksum: string;
  readonly appliedVersions: readonly string[];
  readonly runtimeRole: string;
  readonly runtimeRoleMode: PostgresRuntimeRoleBoundary["mode"];
}

/**
 * Applies only package-owned, checksummed SQL while holding a transaction-level
 * advisory lock. The caller must use a dedicated migration-owner connection
 * and explicitly configure either a direct LOGIN role or a LOGIN -> NOLOGIN
 * SET ROLE boundary for runtime traffic.
 */
export async function runPostgresMigrations(
  client: PostgresSqlClient,
  options: PostgresMigrationOptions,
): Promise<PostgresMigrationReport> {
  const runtimeRole = validatePostgresRuntimeRoleBoundary(options.runtimeRole);
  try {
    return await client.begin("read write", async (transaction) => {
      await transaction`
        SELECT pg_catalog.pg_advisory_xact_lock(
          pg_catalog.hashtextextended('hasna.accounts.schema-migrations.v1', 0)
        )
      `;

      const [{ migration_table: migrationTable } = { migration_table: null }] =
        await transaction<Array<{ migration_table: string | null }>>`
          SELECT pg_catalog.to_regclass('accounts.schema_migrations')::text AS migration_table
        `;

      const existing = new Map<number, string>();
      if (migrationTable !== null) {
        const rows = await transaction<MigrationRow[]>`
          SELECT version::text AS version, checksum
          FROM accounts.schema_migrations
          ORDER BY version ASC
        `;
        for (const row of rows) existing.set(Number(row.version), row.checksum);
      }

      const highest = Math.max(0, ...existing.keys());
      if (highest > POSTGRES_SCHEMA_VERSION) {
        throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Postgres schema is newer", {
          details: { adapter: "postgres", schemaVersion: String(highest) },
        });
      }

      const applied: string[] = [];
      for (const migration of POSTGRES_MIGRATIONS) {
        const storedChecksum = existing.get(migration.version);
        if (storedChecksum !== undefined) {
          if (storedChecksum !== migration.checksum) {
            throw catalogMismatch("migration_checksum", String(migration.version));
          }
          continue;
        }
        await transaction.unsafe(migration.sql).simple();
        await transaction`
          INSERT INTO accounts.schema_migrations(version, checksum)
          VALUES (${migration.version}, ${migration.checksum})
        `;
        applied.push(String(migration.version));
      }

      await assertMigrationLedger(transaction);
      await assertRoleBoundary(transaction, runtimeRole);
      await applyRuntimeGrants(transaction, runtimeRole.roleName);
      await attestCatalog(transaction, runtimeRole.roleName);

      return Object.freeze({
        schemaVersion: String(POSTGRES_SCHEMA_VERSION),
        migrationChecksum: POSTGRES_MIGRATION_CHECKSUM,
        appliedVersions: Object.freeze(applied),
        runtimeRole: runtimeRole.roleName,
        runtimeRoleMode: runtimeRole.mode,
      });
    });
  } catch (error) {
    if (error instanceof AccountsError) throw error;
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres migration failed", {
      details: { adapter: "postgres" },
    });
  }
}

async function assertMigrationLedger(transaction: PostgresTransaction): Promise<void> {
  const rows = await transaction<MigrationRow[]>`
    SELECT version::text AS version, checksum
    FROM accounts.schema_migrations
    ORDER BY version ASC
  `;
  if (
    rows.length !== POSTGRES_MIGRATIONS.length ||
    rows.some((row, index) => {
      const expected = POSTGRES_MIGRATIONS[index];
      return expected === undefined ||
        Number(row.version) !== expected.version ||
        row.checksum !== expected.checksum;
    })
  ) {
    throw catalogMismatch("migration_history");
  }
}

async function assertRoleBoundary(
  transaction: PostgresTransaction,
  runtime: PostgresRuntimeRoleBoundary,
): Promise<void> {
  const [{ owner: migrationOwner } = { owner: "" }] = await transaction<Array<{
    readonly owner: string;
  }>>`SELECT current_user AS owner`;
  const names = runtime.mode === "direct"
    ? [migrationOwner, runtime.roleName]
    : [migrationOwner, runtime.roleName, runtime.loginRoleName];
  const rows: RoleRow[] = [];
  for (const name of names) {
    const found = await transaction<RoleRow[]>`
      SELECT
        role.rolname,
        role.rolsuper,
        role.rolinherit,
        role.rolcreaterole,
        role.rolcreatedb,
        role.rolcanlogin,
        role.rolreplication,
        role.rolbypassrls,
        ARRAY(
          SELECT parent.rolname
          FROM pg_catalog.pg_auth_members AS membership
          JOIN pg_catalog.pg_roles AS parent ON parent.oid = membership.roleid
          WHERE membership.member = role.oid
          ORDER BY parent.rolname
        ) AS memberships,
        ARRAY(
          SELECT child.rolname
          FROM pg_catalog.pg_auth_members AS membership
          JOIN pg_catalog.pg_roles AS child ON child.oid = membership.member
          WHERE membership.roleid = role.oid
          ORDER BY child.rolname
        ) AS members,
        (
          SELECT count(*)::int
          FROM pg_catalog.pg_auth_members AS membership
          WHERE membership.member = role.oid AND membership.admin_option
        ) AS admin_memberships
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname = ${name}
    `;
    rows.push(...found);
  }
  const byName = new Map(rows.map((row) => [row.rolname, row]));
  const ownerRow = byName.get(migrationOwner);
  const runtimeRow = byName.get(runtime.roleName);
  if (
    ownerRow === undefined ||
    hasElevatedAttributes(ownerRow) ||
    !ownerRow.rolcanlogin ||
    ownerRow.memberships.length !== 0 ||
    ownerRow.members.length !== 0
  ) {
    throw catalogMismatch("migration_owner_role", migrationOwner);
  }
  if (runtimeRow === undefined || hasElevatedAttributes(runtimeRow)) {
    throw catalogMismatch("runtime_role", runtime.roleName);
  }
  if (runtime.mode === "direct") {
    if (
      !runtimeRow.rolcanlogin ||
      runtimeRow.memberships.length !== 0 ||
      runtimeRow.members.length !== 0
    ) {
      throw catalogMismatch("runtime_role_direct", runtime.roleName);
    }
    return;
  }

  const loginRow = byName.get(runtime.loginRoleName);
  if (
    runtimeRow.rolcanlogin ||
    loginRow === undefined ||
    hasElevatedAttributes(loginRow) ||
    !loginRow.rolcanlogin ||
    !sameStrings(runtimeRow.members, [runtime.loginRoleName]) ||
    runtimeRow.memberships.length !== 0 ||
    !sameStrings(loginRow.memberships, [runtime.roleName]) ||
    loginRow.members.length !== 0
  ) {
    throw catalogMismatch("runtime_role_set_role", runtime.roleName);
  }
}

function hasElevatedAttributes(role: RoleRow): boolean {
  return role.rolsuper ||
    role.rolinherit ||
    role.rolcreaterole ||
    role.rolcreatedb ||
    role.rolreplication ||
    role.rolbypassrls ||
    role.admin_memberships !== 0;
}

async function applyRuntimeGrants(
  transaction: PostgresTransaction,
  roleName: string,
): Promise<void> {
  const role = quotePostgresIdentifier(roleName);
  const tables = (names: readonly string[]) =>
    names.map((name) => `accounts.${quotePostgresIdentifier(name)}`).join(", ");
  const allowedFunctions = [
    "accounts.current_principal()",
    "accounts.current_identity_realm()",
    "accounts.row_owned_by(TEXT)",
    "accounts.realm_is_current(TEXT)",
    "accounts.delete_credential_handle_for_revocation(UUID, TEXT)",
  ].join(", ");
  await transaction.unsafe(`
    REVOKE ALL ON SCHEMA accounts FROM PUBLIC;
    REVOKE ALL ON SCHEMA accounts FROM ${role};
    GRANT USAGE ON SCHEMA accounts TO ${role};
    REVOKE ALL ON ALL TABLES IN SCHEMA accounts FROM PUBLIC;
    REVOKE ALL ON ALL TABLES IN SCHEMA accounts FROM ${role};
    GRANT SELECT ON TABLE ${tables(POSTGRES_RUNTIME_READ_ONLY_TABLES)} TO ${role};
    GRANT SELECT, INSERT, UPDATE ON TABLE ${tables(POSTGRES_RUNTIME_MUTABLE_TABLES)} TO ${role};
    GRANT SELECT, INSERT ON TABLE ${tables(POSTGRES_RUNTIME_INSERT_ONLY_TABLES)} TO ${role};
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA accounts FROM PUBLIC;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA accounts FROM ${role};
    GRANT EXECUTE ON FUNCTION ${allowedFunctions} TO ${role};
  `).simple();
}

async function attestCatalog(
  transaction: PostgresTransaction,
  runtimeRole: string,
): Promise<void> {
  const [schema] = await transaction<Array<{
    readonly owner_is_current: boolean;
    readonly runtime_usage: boolean;
    readonly runtime_create: boolean;
    readonly public_usage: boolean;
    readonly public_create: boolean;
    readonly foreign_objects: number;
    readonly foreign_grants: number;
  }>>`
    SELECT
      namespace.nspowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      pg_catalog.has_schema_privilege(${runtimeRole}, namespace.oid, 'USAGE') AS runtime_usage,
      pg_catalog.has_schema_privilege(${runtimeRole}, namespace.oid, 'CREATE') AS runtime_create,
      pg_catalog.has_schema_privilege('public', namespace.oid, 'USAGE') AS public_usage,
      pg_catalog.has_schema_privilege('public', namespace.oid, 'CREATE') AS public_create,
      (
        SELECT count(*)::int
        FROM pg_catalog.pg_class AS object
        WHERE object.relnamespace = namespace.oid
          AND object.relowner <> pg_catalog.to_regrole(current_user)
      ) AS foreign_objects,
      (
        SELECT count(*)::int
        FROM (
          SELECT grant_entry.grantee
          FROM pg_catalog.pg_namespace AS granted_namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
              granted_namespace.nspacl,
              pg_catalog.acldefault('n', granted_namespace.nspowner)
            )
          ) AS grant_entry
          WHERE granted_namespace.oid = namespace.oid
          UNION ALL
          SELECT grant_entry.grantee
          FROM pg_catalog.pg_class AS granted_relation
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
              granted_relation.relacl,
              pg_catalog.acldefault('r', granted_relation.relowner)
            )
          ) AS grant_entry
          WHERE granted_relation.relnamespace = namespace.oid
          UNION ALL
          SELECT grant_entry.grantee
          FROM pg_catalog.pg_proc AS granted_function
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
              granted_function.proacl,
              pg_catalog.acldefault('f', granted_function.proowner)
            )
          ) AS grant_entry
          WHERE granted_function.pronamespace = namespace.oid
        ) AS explicit_grant
        WHERE explicit_grant.grantee NOT IN (
          0::oid,
          pg_catalog.to_regrole(current_user)::oid,
          pg_catalog.to_regrole(${runtimeRole})::oid
        )
      ) AS foreign_grants
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname = 'accounts'
  `;
  if (
    schema === undefined ||
    !schema.owner_is_current ||
    !schema.runtime_usage ||
    schema.runtime_create ||
    schema.public_usage ||
    schema.public_create ||
    schema.foreign_objects !== 0 ||
    schema.foreign_grants !== 0
  ) {
    throw catalogMismatch("schema_ownership_or_grants");
  }

  await attestTables(transaction, runtimeRole);
  await attestFunctions(transaction, runtimeRole);
  await attestTriggers(transaction);
  await attestPolicies(transaction);
}

async function attestTables(
  transaction: PostgresTransaction,
  runtimeRole: string,
): Promise<void> {
  const rows = await transaction<TableCatalogRow[]>`
    SELECT
      relation.relname,
      relation.relowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      relation.relrowsecurity AS row_security,
      relation.relforcerowsecurity AS force_row_security,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'SELECT') AS runtime_select,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'INSERT') AS runtime_insert,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'UPDATE') AS runtime_update,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'DELETE') AS runtime_delete,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'TRUNCATE') AS runtime_truncate,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'REFERENCES') AS runtime_references,
      pg_catalog.has_table_privilege(${runtimeRole}, relation.oid, 'TRIGGER') AS runtime_trigger,
      (
        pg_catalog.has_table_privilege('public', relation.oid, 'SELECT') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'INSERT') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'UPDATE') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'DELETE') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'TRUNCATE') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'REFERENCES') OR
        pg_catalog.has_table_privilege('public', relation.oid, 'TRIGGER')
      ) AS public_any
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'accounts' AND relation.relkind = 'r'
    ORDER BY relation.relname
  `;
  if (!sameStrings(rows.map((row) => row.relname), [...POSTGRES_FINAL_TABLES].sort())) {
    throw catalogMismatch("tables");
  }
  const mutable = new Set<string>(POSTGRES_RUNTIME_MUTABLE_TABLES);
  const insertOnly = new Set<string>(POSTGRES_RUNTIME_INSERT_ONLY_TABLES);
  const readOnly = new Set<string>(POSTGRES_RUNTIME_READ_ONLY_TABLES);
  for (const row of rows) {
    const rlsRequired = row.relname !== "schema_migrations";
    if (
      !row.owner_is_current ||
      row.row_security !== rlsRequired ||
      row.force_row_security !== rlsRequired ||
      !row.runtime_select ||
      row.runtime_insert !== (mutable.has(row.relname) || insertOnly.has(row.relname)) ||
      row.runtime_update !== mutable.has(row.relname) ||
      row.runtime_delete ||
      row.runtime_truncate ||
      row.runtime_references ||
      row.runtime_trigger ||
      row.public_any ||
      (!mutable.has(row.relname) && !insertOnly.has(row.relname) && !readOnly.has(row.relname))
    ) {
      throw catalogMismatch("table_contract", row.relname);
    }
  }
}

async function attestFunctions(
  transaction: PostgresTransaction,
  runtimeRole: string,
): Promise<void> {
  const rows = await transaction<FunctionCatalogRow[]>`
    SELECT
      function.proname || '(' ||
        pg_catalog.pg_get_function_identity_arguments(function.oid) || ')' AS signature,
      function.proowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      NOT function.prosecdef AS security_invoker,
      function.proconfig = ARRAY['search_path=pg_catalog']::text[] AS safe_search_path,
      pg_catalog.has_function_privilege('public', function.oid, 'EXECUTE') AS public_execute,
      pg_catalog.has_function_privilege(${runtimeRole}, function.oid, 'EXECUTE') AS runtime_execute
    FROM pg_catalog.pg_proc AS function
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace
    WHERE namespace.nspname = 'accounts'
    ORDER BY signature
  `;
  if (!sameStrings(rows.map((row) => row.signature), [...EXPECTED_FUNCTIONS].sort())) {
    throw catalogMismatch("functions");
  }
  for (const row of rows) {
    if (
      !row.owner_is_current ||
      row.security_invoker !== (row.signature !== SECURITY_DEFINER_FUNCTION) ||
      !row.safe_search_path ||
      row.public_execute ||
      row.runtime_execute !== RUNTIME_FUNCTIONS.has(row.signature)
    ) {
      throw catalogMismatch("function_contract", row.signature);
    }
  }
}

async function attestTriggers(transaction: PostgresTransaction): Promise<void> {
  const rows = await transaction<TriggerCatalogRow[]>`
    SELECT
      trigger.tgname AS trigger_name,
      relation.relname AS table_name,
      function.proname AS function_name,
      trigger.tgenabled AS enabled
    FROM pg_catalog.pg_trigger AS trigger
    JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger.tgrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_proc AS function ON function.oid = trigger.tgfoid
    WHERE namespace.nspname = 'accounts' AND NOT trigger.tgisinternal
    ORDER BY trigger.tgname
  `;
  if (!sameStrings(rows.map((row) => row.trigger_name), [...EXPECTED_TRIGGERS.keys()].sort())) {
    throw catalogMismatch("triggers");
  }
  for (const row of rows) {
    const expected = EXPECTED_TRIGGERS.get(row.trigger_name);
    if (
      expected === undefined ||
      row.table_name !== expected.tableName ||
      row.function_name !== expected.functionName ||
      row.enabled !== "O"
    ) {
      throw catalogMismatch("trigger_contract", row.trigger_name);
    }
  }
}

async function attestPolicies(transaction: PostgresTransaction): Promise<void> {
  const expected = expectedPolicies();
  const rows = await transaction<PolicyCatalogRow[]>`
    SELECT
      policy.polname AS policy_name,
      relation.relname AS table_name,
      policy.polcmd AS command,
      policy.polroles = ARRAY[0::oid] AS public_only,
      policy.polpermissive AS permissive,
      pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) AS using_expression,
      pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) AS check_expression
    FROM pg_catalog.pg_policy AS policy
    JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'accounts'
    ORDER BY policy.polname
  `;
  if (!sameStrings(rows.map((row) => row.policy_name), [...expected.keys()].sort())) {
    throw catalogMismatch("policies");
  }
  for (const row of rows) {
    const contract = expected.get(row.policy_name);
    if (
      contract === undefined ||
      row.table_name !== contract.tableName ||
      row.command !== contract.command ||
      !row.public_only ||
      !row.permissive ||
      normalizeExpression(row.using_expression) !==
        normalizeExpression(contract.usingExpression) ||
      normalizeExpression(row.check_expression) !==
        normalizeExpression(contract.checkExpression)
    ) {
      throw catalogMismatch("policy_contract", row.policy_name);
    }
  }
}

function expectedPolicies(): Map<string, ExpectedPolicy> {
  const result = new Map<string, ExpectedPolicy>();
  for (const table of POSTGRES_OWNER_TABLES) {
    addPolicies(
      result,
      table,
      "owner",
      "accounts.row_owned_by(owner_ref)",
      POSTGRES_MUTABLE_RUNTIME_TABLES.includes(
        table as (typeof POSTGRES_MUTABLE_RUNTIME_TABLES)[number],
      ),
    );
  }
  for (const table of POSTGRES_GLOBAL_REALM_TABLES) {
    addPolicies(
      result,
      table,
      "realm",
      "accounts.realm_is_current(identity_realm)",
      POSTGRES_MUTABLE_RUNTIME_TABLES.includes(
        table as (typeof POSTGRES_MUTABLE_RUNTIME_TABLES)[number],
      ),
    );
  }
  addPolicies(
    result,
    "capsule_maintenance_grants",
    "owner",
    "accounts.row_owned_by(owner_ref)",
    true,
  );
  addPolicies(
    result,
    "capsule_maintenance_uses",
    "owner",
    "accounts.row_owned_by(owner_ref)",
    false,
  );
  addPolicies(
    result,
    "capability_use_consumptions",
    "owner",
    "accounts.row_owned_by(owner_ref)",
    false,
  );
  return result;
}

function addPolicies(
  target: Map<string, ExpectedPolicy>,
  table: string,
  scope: "owner" | "realm",
  expression: string,
  mutable: boolean,
): void {
  target.set(`${table}_${scope}_select`, {
    tableName: table,
    command: "r",
    usingExpression: expression,
    checkExpression: null,
  });
  target.set(`${table}_${scope}_insert`, {
    tableName: table,
    command: "a",
    usingExpression: null,
    checkExpression: expression,
  });
  if (mutable) {
    target.set(`${table}_${scope}_update`, {
      tableName: table,
      command: "w",
      usingExpression: expression,
      checkExpression: expression,
    });
  }
}

function normalizeExpression(value: string | null): string | null {
  return value === null ? null : value.replace(/[\s()]/g, "");
}

function sameStrings(actual: readonly string[], expected: readonly string[]): boolean {
  return actual.length === expected.length &&
    actual.every((value, index) => value === expected[index]);
}

function catalogMismatch(component: string, object?: string): AccountsError {
  return new AccountsError(
    "SCHEMA_CHECKSUM_MISMATCH",
    "Postgres catalog does not match the Accounts schema contract",
    { details: { adapter: "postgres", component, ...(object ? { object } : {}) } },
  );
}
