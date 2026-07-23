import { AccountsError } from "./errors.js";
import type { PostgresTransaction } from "./postgres-sql.js";

const ROLE_NAME = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;

export type PostgresRuntimeRoleBoundary =
  | {
      /** Connect directly as this dedicated LOGIN role. */
      readonly mode: "direct";
      readonly roleName: string;
    }
  | {
      /** Connect as loginRoleName, then transaction-locally SET ROLE roleName. */
      readonly mode: "set-role";
      readonly roleName: string;
      readonly loginRoleName: string;
    };

export interface PostgresRuntimeContext {
  readonly principalRef: string;
  readonly role: PostgresRuntimeRoleBoundary;
}

export function validatePostgresRuntimeRoleBoundary(
  source: PostgresRuntimeRoleBoundary,
): PostgresRuntimeRoleBoundary {
  if (source === null || typeof source !== "object") throw invalidRoleBoundary();
  if (!ROLE_NAME.test(source.roleName)) throw invalidRoleBoundary("roleName");
  if (source.mode === "direct") {
    return Object.freeze({ mode: "direct", roleName: source.roleName });
  }
  if (
    source.mode !== "set-role" ||
    !ROLE_NAME.test(source.loginRoleName) ||
    source.loginRoleName === source.roleName
  ) {
    throw invalidRoleBoundary("loginRoleName");
  }
  return Object.freeze({
    mode: "set-role",
    roleName: source.roleName,
    loginRoleName: source.loginRoleName,
  });
}

export async function installPostgresRuntimeContext(
  transaction: PostgresTransaction,
  source: PostgresRuntimeContext,
): Promise<void> {
  const role = validatePostgresRuntimeRoleBoundary(source.role);
  if (role.mode === "set-role") {
    await transaction.unsafe(`SET LOCAL ROLE ${quoteIdentifier(role.roleName)}`).simple();
  }
  await transaction.unsafe(
    "SET LOCAL search_path = pg_catalog, accounts; SET LOCAL row_security = on",
  ).simple();
  await transaction`
    SELECT
      set_config('accounts.principal', ${source.principalRef}, true),
      set_config('accounts.identity_realm', 'hasna', true)
  `;
  const [context] = await transaction<Array<{
    readonly principal: string | null;
    readonly realm: string | null;
    readonly role_name: string;
    readonly login_role_name: string;
  }>>`
    SELECT
      accounts.current_principal() AS principal,
      accounts.current_identity_realm() AS realm,
      current_user AS role_name,
      session_user AS login_role_name
  `;
  const expectedLoginRole = role.mode === "direct" ? role.roleName : role.loginRoleName;
  if (
    context?.principal !== source.principalRef ||
    context.realm !== "hasna" ||
    context.role_name !== role.roleName ||
    context.login_role_name !== expectedLoginRole
  ) {
    throw new AccountsError("FORBIDDEN", "Postgres runtime context was not installed", {
      details: { adapter: "postgres", roleMode: role.mode },
    });
  }
}

export function quotePostgresIdentifier(value: string): string {
  if (!ROLE_NAME.test(value)) throw invalidRoleBoundary("roleName");
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteIdentifier(value: string): string {
  return quotePostgresIdentifier(value);
}

function invalidRoleBoundary(field = "role"): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Postgres runtime role boundary is invalid", {
    details: { field },
  });
}
