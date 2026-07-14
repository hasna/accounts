import type { PoolQueryClient } from "../generated/storage-kit/index.js";

const RUNTIME_TABLES = ["accounts", "current_selections", "custom_tools"] as const;
const READ_ONLY_TABLES = ["schema_migrations", "api_keys"] as const;
const TRIGGER_FUNCTIONS = [
  "accounts_guard_removed_custom_tool",
  "custom_tool_tombstone_guard",
  "custom_tool_registration_reactivate",
  "custom_tool_registration_tombstone",
] as const;

function quoteIdentifier(value: string): string {
  if (value.length === 0 || value.includes("\0")) {
    throw new Error("PostgreSQL identifiers must be non-empty and contain no NUL bytes");
  }
  return `"${value.replaceAll('"', '""')}"`;
}

interface RoleRow {
  rolname: string;
  rolsuper: boolean;
  rolinherit: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolcanlogin: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
  memberships: number;
}

/**
 * Apply the direct, least-privilege grants required by accounts-serve.
 *
 * Call this through the migration-owner connection after every migration. The
 * Both identities must be dedicated NOINHERIT logins with no elevated
 * attributes or memberships; inherited or owner privileges would make this
 * contract impossible to audit.
 */
export async function grantAccountsRuntimeRole(
  client: PoolQueryClient,
  roleName: string,
): Promise<{ owner: string; role: string; schema: string }> {
  const context = await client.one<{ owner: string; schema: string | null }>(
    "SELECT current_user AS owner, current_schema() AS schema",
  );
  if (!context.schema) throw new Error("accounts runtime grants require a current schema");
  if (context.owner === roleName) {
    throw new Error("accounts migration owner and runtime role must be different roles");
  }

  const roles = await client.many<RoleRow>(
    `SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole,
            r.rolcreatedb, r.rolcanlogin, r.rolreplication, r.rolbypassrls,
            count(m.roleid)::int AS memberships
       FROM pg_catalog.pg_roles AS r
       LEFT JOIN pg_catalog.pg_auth_members AS m ON m.member = r.oid
      WHERE r.rolname = ANY($1::text[])
      GROUP BY r.oid, r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole,
               r.rolcreatedb, r.rolcanlogin, r.rolreplication, r.rolbypassrls`,
    [[context.owner, roleName]],
  );
  for (const [kind, name] of [
    ["migration owner", context.owner],
    ["runtime role", roleName],
  ] as const) {
    const role = roles.find((candidate) => candidate.rolname === name);
    if (!role) throw new Error(`accounts ${kind} "${name}" does not exist`);
    if (
      role.rolsuper ||
      role.rolinherit ||
      role.rolcreaterole ||
      role.rolcreatedb ||
      !role.rolcanlogin ||
      role.rolreplication ||
      role.rolbypassrls ||
      role.memberships !== 0
    ) {
      throw new Error(
        `accounts ${kind} "${name}" must be LOGIN NOINHERIT NOSUPERUSER ` +
          "NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS with no role memberships",
      );
    }
  }

  const ownership = await client.one<{ schema_owned: boolean; objects_not_owned: number }>(
    `SELECT
       n.nspowner = pg_catalog.to_regrole(current_user) AS schema_owned,
       (
         SELECT count(*)::int
           FROM pg_catalog.pg_class AS c
          WHERE c.relnamespace = n.oid
            AND c.relowner <> pg_catalog.to_regrole(current_user)
       ) + (
         SELECT count(*)::int
           FROM pg_catalog.pg_proc AS p
          WHERE p.pronamespace = n.oid
            AND p.proowner <> pg_catalog.to_regrole(current_user)
       ) AS objects_not_owned
     FROM pg_catalog.pg_namespace AS n
     WHERE n.nspname = $1`,
    [context.schema],
  );
  if (!ownership.schema_owned || ownership.objects_not_owned !== 0) {
    throw new Error("accounts runtime grants must be applied by the schema and object owner");
  }

  const schema = quoteIdentifier(context.schema);
  const runtimeRole = quoteIdentifier(roleName);
  const qualified = (name: string) => `${schema}.${quoteIdentifier(name)}`;
  const runtimeTables = RUNTIME_TABLES.map(qualified).join(", ");
  const readOnlyTables = READ_ONLY_TABLES.map(qualified).join(", ");
  const tombstones = qualified("custom_tool_tombstones");
  const triggerFunctions = TRIGGER_FUNCTIONS.map((name) => `${qualified(name)}()`).join(", ");

  await client.transaction(async (tx) => {
    await tx.execute(`REVOKE ALL PRIVILEGES ON SCHEMA ${schema} FROM PUBLIC`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON SCHEMA ${schema} FROM ${runtimeRole}`);
    await tx.execute(`GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole}`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${runtimeTables} FROM PUBLIC`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${runtimeTables} FROM ${runtimeRole}`);
    await tx.execute(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ${runtimeTables} TO ${runtimeRole}`,
    );
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${tombstones} FROM PUBLIC`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${tombstones} FROM ${runtimeRole}`);
    await tx.execute(`GRANT SELECT, INSERT, DELETE ON TABLE ${tombstones} TO ${runtimeRole}`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${readOnlyTables} FROM PUBLIC`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON TABLE ${readOnlyTables} FROM ${runtimeRole}`);
    await tx.execute(`GRANT SELECT ON TABLE ${readOnlyTables} TO ${runtimeRole}`);
    await tx.execute(`REVOKE ALL PRIVILEGES ON FUNCTION ${triggerFunctions} FROM ${runtimeRole}`);
  });

  return { owner: context.owner, role: roleName, schema: context.schema };
}
