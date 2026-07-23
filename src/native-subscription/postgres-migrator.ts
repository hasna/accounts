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
import {
  POSTGRES_SCHEMA_MANIFEST,
  type PostgresColumnManifestEntry,
  type PostgresConstraintManifestEntry,
  type PostgresIndexManifestEntry,
} from "./postgres-schema-manifest.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

interface MigrationRow {
  readonly version: string | number | bigint;
  readonly checksum: string;
}

interface LegacyMigrationRow extends MigrationRow {
  readonly applied_at: string;
  readonly applied_at_is_finite: boolean;
  readonly applied_at_occurrences: string | number | bigint;
}

interface SequencedMigrationRow extends MigrationRow {
  readonly applied_at_is_finite: boolean;
  readonly ledger_sequence: string | number | bigint;
  readonly ledger_sequence_occurrences: string | number | bigint;
}

interface ParsedMigrationRow {
  readonly version: bigint;
  readonly checksum: string;
  readonly ledgerSequence: bigint | null;
}

interface PackageOwnedObjectRow {
  readonly package_owned_objects: string | number | bigint;
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

interface SchemaObjectCatalogRow {
  readonly object_name: string;
  readonly object_kind: string;
  readonly owner_is_current: boolean;
  readonly acl_is_null: boolean;
}

interface SchemaTypeCatalogRow {
  readonly type_name: string;
  readonly type_kind: string;
  readonly type_category: string;
  readonly relation_name: string | null;
  readonly relation_kind: string | null;
  readonly element_type_name: string | null;
  readonly owner_is_current: boolean;
  readonly public_usage: boolean;
  readonly runtime_usage: boolean;
  readonly foreign_grants: string | number | bigint;
  readonly acl_is_null: boolean;
}

interface SequenceCatalogRow {
  readonly sequence_name: string;
  readonly owner_is_current: boolean;
  readonly owned_by_ledger_sequence: boolean;
  readonly data_type: string;
  readonly increment: string | number | bigint;
  readonly minimum_value: string | number | bigint;
  readonly maximum_value: string | number | bigint;
  readonly cache_size: string | number | bigint;
  readonly cycles: boolean;
  readonly public_select: boolean;
  readonly public_usage: boolean;
  readonly public_update: boolean;
  readonly runtime_select: boolean;
  readonly runtime_usage: boolean;
  readonly runtime_update: boolean;
}

interface ColumnCatalogRow {
  readonly table_name: string;
  readonly ordinal_position: number;
  readonly column_name: string;
  readonly data_type: string;
  readonly not_null: boolean;
  readonly default_expression: string | null;
  readonly identity_kind: string;
  readonly generated_kind: string;
  readonly collation_name: string | null;
}

interface ConstraintCatalogRow {
  readonly table_name: string;
  readonly constraint_name: string;
  readonly constraint_type: "p" | "u" | "c" | "f";
  readonly definition: string;
  readonly deferrable: boolean;
  readonly initially_deferred: boolean;
  readonly validated: boolean;
}

interface IndexCatalogRow {
  readonly table_name: string;
  readonly index_name: string;
  readonly access_method: string;
  readonly unique_index: boolean;
  readonly valid: boolean;
  readonly ready: boolean;
  readonly live: boolean;
  readonly definition: string;
  readonly predicate: string | null;
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

const EXPECTED_SCHEMA_OBJECTS = Object.freeze([
  ...POSTGRES_FINAL_TABLES.map((name) => [name, "r"] as const),
  ...POSTGRES_SCHEMA_MANIFEST.constraints
    .filter((entry) => entry[2] === "p" || entry[2] === "u")
    .map((entry) => [entry[1], "i"] as const),
  ...POSTGRES_SCHEMA_MANIFEST.indexes.map((entry) => [entry[1], "i"] as const),
  ["schema_migrations_ledger_sequence_seq", "S"] as const,
].sort(([leftName, leftKind], [rightName, rightKind]) =>
  leftName.localeCompare(rightName) || leftKind.localeCompare(rightKind)
));

const EXPECTED_TRIGGERS = new Map<string, {
  readonly tableName: string;
  readonly functionName: string;
}>([
  ["schema_migrations_immutable", {
    tableName: "schema_migrations",
    functionName: "reject_append_only_change",
  }],
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

      const existing = await preflightMigrationLedger(transaction, migrationTable);

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

async function preflightMigrationLedger(
  transaction: PostgresTransaction,
  migrationTable: string | null,
): Promise<ReadonlyMap<number, string>> {
  if (migrationTable === null) {
    const [
      { package_owned_objects: packageOwnedObjects } = { package_owned_objects: 0 },
    ] = await transaction<PackageOwnedObjectRow[]>`
      SELECT (
        (
          SELECT count(*)
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'accounts'
        ) + (
          SELECT count(*)
          FROM pg_catalog.pg_proc AS function_entry
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = function_entry.pronamespace
          WHERE namespace.nspname = 'accounts'
        ) + (
          SELECT count(*)
          FROM pg_catalog.pg_type AS type_entry
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = type_entry.typnamespace
          WHERE namespace.nspname = 'accounts'
        )
      )::bigint AS package_owned_objects
    `;
    if (BigInt(packageOwnedObjects) !== 0n) {
      throw catalogMismatch("migration_history", "missing_ledger");
    }
    return new Map();
  }

  const { rows, sequenced } = await readMigrationLedger(transaction);
  if (rows.length === 0) {
    throw catalogMismatch("migration_history", "empty_ledger");
  }

  const highest = rows.reduce(
    (candidate, row) => row.version > candidate ? row.version : candidate,
    0n,
  );
  if (highest > BigInt(POSTGRES_SCHEMA_VERSION)) {
    throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Postgres schema is newer", {
      details: { adapter: "postgres", schemaVersion: String(highest) },
    });
  }

  const existing = new Map<number, string>();
  let previousSequence = 0n;
  for (const [index, row] of rows.entries()) {
    const expected = POSTGRES_MIGRATIONS[index];
    if (
      expected === undefined ||
      row.version !== BigInt(expected.version) ||
      row.checksum !== expected.checksum ||
      (
        sequenced &&
        (
          row.ledgerSequence === null ||
          row.ledgerSequence <= previousSequence
        )
      )
    ) {
      throw catalogMismatch("migration_history", String(row.version));
    }
    if (row.ledgerSequence !== null) previousSequence = row.ledgerSequence;
    existing.set(expected.version, row.checksum);
  }
  return existing;
}

async function assertMigrationLedger(transaction: PostgresTransaction): Promise<void> {
  const { rows, sequenced } = await readMigrationLedger(transaction);
  if (
    !sequenced ||
    rows.length !== POSTGRES_MIGRATIONS.length ||
    rows.some((row, index) => {
      const expected = POSTGRES_MIGRATIONS[index];
      return expected === undefined ||
        row.version !== BigInt(expected.version) ||
        row.checksum !== expected.checksum;
    })
  ) {
    throw catalogMismatch("migration_history");
  }
}

async function readMigrationLedger(
  transaction: PostgresTransaction,
): Promise<{
  readonly rows: readonly ParsedMigrationRow[];
  readonly sequenced: boolean;
}> {
  const [{
    has_ledger_sequence: hasLedgerSequence,
    ledger_sequence_is_identity: ledgerSequenceIsIdentity,
  } = {
    has_ledger_sequence: false,
    ledger_sequence_is_identity: false,
  }] = await transaction<Array<{
    readonly has_ledger_sequence: boolean;
    readonly ledger_sequence_is_identity: boolean;
  }>>`
    SELECT
      count(*) = 1 AS has_ledger_sequence,
      COALESCE(
        bool_and(
          attribute.atttypid = 'pg_catalog.int8'::pg_catalog.regtype
          AND attribute.attnotnull
          AND attribute.attidentity = 'a'
        ),
        false
      ) AS ledger_sequence_is_identity
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'accounts'
      AND relation.relname = 'schema_migrations'
      AND relation.relkind = 'r'
      AND attribute.attname = 'ledger_sequence'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  `;
  if (hasLedgerSequence && !ledgerSequenceIsIdentity) {
    throw catalogMismatch("migration_history", "ledger_sequence_contract");
  }

  if (hasLedgerSequence) {
    const rows = await transaction<SequencedMigrationRow[]>`
      SELECT
        version::text AS version,
        checksum,
        pg_catalog.isfinite(applied_at) AS applied_at_is_finite,
        ledger_sequence::text AS ledger_sequence,
        count(*) OVER (
          PARTITION BY ledger_sequence
        )::text AS ledger_sequence_occurrences
      FROM accounts.schema_migrations
      ORDER BY ledger_sequence ASC
    `;
    return {
      rows: Object.freeze(rows.map((row) => {
        if (
          !row.applied_at_is_finite ||
          String(row.ledger_sequence_occurrences) !== "1"
        ) {
          throw catalogMismatch("migration_history", String(row.version));
        }
        return parseMigrationRow(row, row.ledger_sequence);
      })),
      sequenced: true,
    };
  }

  const rows = await transaction<LegacyMigrationRow[]>`
    SELECT
      version::text AS version,
      checksum,
      applied_at::text AS applied_at,
      pg_catalog.isfinite(applied_at) AS applied_at_is_finite,
      count(*) OVER (
        PARTITION BY applied_at
      )::text AS applied_at_occurrences
    FROM accounts.schema_migrations
    ORDER BY applied_at ASC
  `;
  return {
    rows: Object.freeze(rows.map((row) => {
      if (
        !row.applied_at_is_finite ||
        String(row.applied_at_occurrences) !== "1"
      ) {
        throw catalogMismatch("migration_history", String(row.version));
      }
      return parseMigrationRow(row, null);
    })),
    sequenced: false,
  };
}

function parseMigrationRow(
  row: MigrationRow,
  ledgerSequence: string | number | bigint | null,
): ParsedMigrationRow {
  const versionText = String(row.version);
  const sequenceText = ledgerSequence === null ? null : String(ledgerSequence);
  if (
    !/^[1-9][0-9]*$/.test(versionText) ||
    (sequenceText !== null && !/^[1-9][0-9]*$/.test(sequenceText))
  ) {
    throw catalogMismatch("migration_history", versionText);
  }
  return {
    version: BigInt(versionText),
    checksum: row.checksum,
    ledgerSequence: sequenceText === null ? null : BigInt(sequenceText),
  };
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

  await attestSchemaObjects(transaction);
  await attestSchemaTypes(transaction, runtimeRole);
  await attestTables(transaction, runtimeRole);
  await attestSequences(transaction, runtimeRole);
  await attestSchemaManifest(transaction);
  await attestFunctions(transaction, runtimeRole);
  await attestTriggers(transaction);
  await attestPolicies(transaction);
}

async function attestSchemaObjects(
  transaction: PostgresTransaction,
): Promise<void> {
  const rows = await transaction<SchemaObjectCatalogRow[]>`
    SELECT
      relation.relname AS object_name,
      relation.relkind::text AS object_kind,
      relation.relowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      relation.relacl IS NULL AS acl_is_null
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'accounts'
    ORDER BY relation.relname, relation.relkind
  `;
  const actual = rows.map((row) => [row.object_name, row.object_kind] as const);
  if (
    JSON.stringify(actual) !== JSON.stringify(EXPECTED_SCHEMA_OBJECTS) ||
    rows.some((row) =>
      !row.owner_is_current ||
      (row.object_kind === "i" && !row.acl_is_null)
    )
  ) {
    const unexpected = rows.find((row, index) =>
      !row.owner_is_current ||
      (row.object_kind === "i" && !row.acl_is_null) ||
      row.object_name !== EXPECTED_SCHEMA_OBJECTS[index]?.[0] ||
      row.object_kind !== EXPECTED_SCHEMA_OBJECTS[index]?.[1]
    );
    throw catalogMismatch("schema_objects", unexpected?.object_name);
  }
}

async function attestSchemaTypes(
  transaction: PostgresTransaction,
  runtimeRole: string,
): Promise<void> {
  const rows = await transaction<SchemaTypeCatalogRow[]>`
    SELECT
      type_entry.typname AS type_name,
      type_entry.typtype::text AS type_kind,
      type_entry.typcategory::text AS type_category,
      relation.relname AS relation_name,
      relation.relkind::text AS relation_kind,
      element_type.typname AS element_type_name,
      type_entry.typowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      pg_catalog.has_type_privilege(
        'public',
        type_entry.oid,
        'USAGE'
      ) AS public_usage,
      pg_catalog.has_type_privilege(
        ${runtimeRole},
        type_entry.oid,
        'USAGE'
      ) AS runtime_usage,
      (
        SELECT count(*)::bigint
        FROM pg_catalog.aclexplode(
          COALESCE(
            type_entry.typacl,
            pg_catalog.acldefault('T', type_entry.typowner)
          )
        ) AS grant_entry
        WHERE grant_entry.grantee NOT IN (
          0::oid,
          pg_catalog.to_regrole(current_user)::oid,
          pg_catalog.to_regrole(${runtimeRole})::oid
        )
      ) AS foreign_grants,
      type_entry.typacl IS NULL AS acl_is_null
    FROM pg_catalog.pg_type AS type_entry
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = type_entry.typnamespace
    LEFT JOIN pg_catalog.pg_class AS relation
      ON relation.oid = type_entry.typrelid
    LEFT JOIN pg_catalog.pg_type AS element_type
      ON element_type.oid = type_entry.typelem
    WHERE namespace.nspname = 'accounts'
    ORDER BY type_entry.typname
  `;
  const allowedTables = new Set<string>(POSTGRES_FINAL_TABLES);
  const rowTypes = new Set<string>();
  const arrayElementTypes = new Set<string>();
  for (const row of rows) {
    const rowType = row.type_kind === "c" &&
      row.type_category === "C" &&
      row.relation_kind === "r" &&
      row.relation_name === row.type_name &&
      allowedTables.has(row.type_name) &&
      row.element_type_name === null;
    const arrayType = row.type_kind === "b" &&
      row.type_category === "A" &&
      row.relation_name === null &&
      row.relation_kind === null &&
      row.element_type_name !== null &&
      allowedTables.has(row.element_type_name) &&
      row.type_name === `_${row.element_type_name}`;
    if (
      (!rowType && !arrayType) ||
      !row.owner_is_current ||
      !row.public_usage ||
      !row.runtime_usage ||
      BigInt(row.foreign_grants) !== 0n ||
      !row.acl_is_null
    ) {
      throw catalogMismatch("schema_types", row.type_name);
    }
    if (rowType) rowTypes.add(row.type_name);
    if (arrayType) arrayElementTypes.add(row.element_type_name!);
  }
  if (
    rows.length !== POSTGRES_FINAL_TABLES.length * 2 ||
    !sameStrings([...rowTypes].sort(), [...POSTGRES_FINAL_TABLES].sort()) ||
    !sameStrings([...arrayElementTypes].sort(), [...POSTGRES_FINAL_TABLES].sort())
  ) {
    throw catalogMismatch("schema_types");
  }
}

async function attestSequences(
  transaction: PostgresTransaction,
  runtimeRole: string,
): Promise<void> {
  const rows = await transaction<SequenceCatalogRow[]>`
    SELECT
      relation.relname AS sequence_name,
      relation.relowner = pg_catalog.to_regrole(current_user) AS owner_is_current,
      EXISTS (
        SELECT 1
        FROM pg_catalog.pg_depend AS dependency
        JOIN pg_catalog.pg_attribute AS attribute
          ON attribute.attrelid = dependency.refobjid
          AND attribute.attnum = dependency.refobjsubid
        WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
          AND dependency.objid = relation.oid
          AND dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
          AND dependency.refobjid =
            'accounts.schema_migrations'::pg_catalog.regclass
          AND dependency.deptype = 'i'
          AND attribute.attname = 'ledger_sequence'
      ) AS owned_by_ledger_sequence,
      pg_catalog.format_type(sequence.seqtypid, NULL) AS data_type,
      sequence.seqincrement AS increment,
      sequence.seqmin AS minimum_value,
      sequence.seqmax AS maximum_value,
      sequence.seqcache AS cache_size,
      sequence.seqcycle AS cycles,
      pg_catalog.has_sequence_privilege(
        'public',
        relation.oid,
        'SELECT'
      ) AS public_select,
      pg_catalog.has_sequence_privilege(
        'public',
        relation.oid,
        'USAGE'
      ) AS public_usage,
      pg_catalog.has_sequence_privilege(
        'public',
        relation.oid,
        'UPDATE'
      ) AS public_update,
      pg_catalog.has_sequence_privilege(
        ${runtimeRole},
        relation.oid,
        'SELECT'
      ) AS runtime_select,
      pg_catalog.has_sequence_privilege(
        ${runtimeRole},
        relation.oid,
        'USAGE'
      ) AS runtime_usage,
      pg_catalog.has_sequence_privilege(
        ${runtimeRole},
        relation.oid,
        'UPDATE'
      ) AS runtime_update
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_sequence AS sequence
      ON sequence.seqrelid = relation.oid
    WHERE namespace.nspname = 'accounts'
    ORDER BY relation.relname
  `;
  if (
    rows.length !== 1 ||
    rows[0]?.sequence_name !== "schema_migrations_ledger_sequence_seq"
  ) {
    throw catalogMismatch("sequences");
  }
  const [sequence] = rows;
  if (
    sequence === undefined ||
    !sequence.owner_is_current ||
    !sequence.owned_by_ledger_sequence ||
    sequence.data_type !== "bigint" ||
    BigInt(sequence.increment) !== 1n ||
    BigInt(sequence.minimum_value) !== 1n ||
    BigInt(sequence.maximum_value) !== 9_223_372_036_854_775_807n ||
    BigInt(sequence.cache_size) !== 1n ||
    sequence.cycles ||
    sequence.public_select ||
    sequence.public_usage ||
    sequence.public_update ||
    sequence.runtime_select ||
    sequence.runtime_usage ||
    sequence.runtime_update
  ) {
    throw catalogMismatch("sequence_contract", sequence?.sequence_name);
  }
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

async function attestSchemaManifest(transaction: PostgresTransaction): Promise<void> {
  const columnRows = await transaction<ColumnCatalogRow[]>`
    SELECT
      relation.relname AS table_name,
      attribute.attnum AS ordinal_position,
      attribute.attname AS column_name,
      pg_catalog.format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
      attribute.attnotnull AS not_null,
      pg_catalog.pg_get_expr(
        default_value.adbin,
        default_value.adrelid,
        true
      ) AS default_expression,
      attribute.attidentity AS identity_kind,
      attribute.attgenerated AS generated_kind,
      CASE
        WHEN attribute.attcollation = 0 THEN NULL
        ELSE collation_namespace.nspname || '.' || collation_catalog.collname
      END AS collation_name
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_attrdef AS default_value
      ON default_value.adrelid = attribute.attrelid
      AND default_value.adnum = attribute.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_catalog
      ON collation_catalog.oid = attribute.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_catalog.collnamespace
    WHERE namespace.nspname = 'accounts'
      AND relation.relkind = 'r'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
    ORDER BY relation.relname, attribute.attnum
  `;
  const columns: PostgresColumnManifestEntry[] = columnRows.map((row) => [
    row.table_name,
    row.ordinal_position,
    row.column_name,
    row.data_type,
    row.not_null,
    row.default_expression,
    row.identity_kind,
    row.generated_kind,
    row.collation_name,
  ]);
  assertManifestEntries("columns", columns, POSTGRES_SCHEMA_MANIFEST.columns);

  const constraintRows = await transaction<ConstraintCatalogRow[]>`
    SELECT
      relation.relname AS table_name,
      constraint_entry.conname AS constraint_name,
      constraint_entry.contype AS constraint_type,
      pg_catalog.pg_get_constraintdef(constraint_entry.oid, true) AS definition,
      constraint_entry.condeferrable AS deferrable,
      constraint_entry.condeferred AS initially_deferred,
      constraint_entry.convalidated AS validated
    FROM pg_catalog.pg_constraint AS constraint_entry
    JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_entry.conrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'accounts'
      AND constraint_entry.contype IN ('p', 'u', 'c', 'f')
    ORDER BY relation.relname, constraint_entry.conname
  `;
  const constraints: PostgresConstraintManifestEntry[] = constraintRows.map((row) => [
    row.table_name,
    row.constraint_name,
    row.constraint_type,
    row.definition,
    row.deferrable,
    row.initially_deferred,
    row.validated,
  ]);
  assertManifestEntries(
    "constraints",
    constraints,
    POSTGRES_SCHEMA_MANIFEST.constraints,
  );

  const indexRows = await transaction<IndexCatalogRow[]>`
    SELECT
      table_relation.relname AS table_name,
      index_relation.relname AS index_name,
      access_method.amname AS access_method,
      index_entry.indisunique AS unique_index,
      index_entry.indisvalid AS valid,
      index_entry.indisready AS ready,
      index_entry.indislive AS live,
      pg_catalog.pg_get_indexdef(index_relation.oid, 0, true) AS definition,
      pg_catalog.pg_get_expr(
        index_entry.indpred,
        index_entry.indrelid,
        true
      ) AS predicate
    FROM pg_catalog.pg_index AS index_entry
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_entry.indexrelid
    JOIN pg_catalog.pg_class AS table_relation
      ON table_relation.oid = index_entry.indrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = table_relation.relnamespace
    JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
    LEFT JOIN pg_catalog.pg_constraint AS constraint_entry
      ON constraint_entry.conindid = index_entry.indexrelid
    WHERE namespace.nspname = 'accounts'
      AND constraint_entry.oid IS NULL
    ORDER BY table_relation.relname, index_relation.relname
  `;
  const indexes: PostgresIndexManifestEntry[] = indexRows.map((row) => [
    row.table_name,
    row.index_name,
    row.access_method,
    row.unique_index,
    row.valid,
    row.ready,
    row.live,
    row.definition,
    row.predicate,
  ]);
  assertManifestEntries("indexes", indexes, POSTGRES_SCHEMA_MANIFEST.indexes);
}

function assertManifestEntries<T extends readonly unknown[]>(
  component: "columns" | "constraints" | "indexes",
  actual: readonly T[],
  expected: readonly T[],
): void {
  const mismatchIndex = actual.findIndex(
    (entry, index) => JSON.stringify(entry) !== JSON.stringify(expected[index]),
  );
  if (actual.length !== expected.length || mismatchIndex !== -1) {
    const index = mismatchIndex === -1
      ? Math.min(actual.length, expected.length)
      : mismatchIndex;
    const entry = actual[index] ?? expected[index];
    const object = entry === undefined
      ? undefined
      : entry.slice(0, Math.min(3, entry.length)).map(String).join(".");
    throw catalogMismatch(component, object);
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
