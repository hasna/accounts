import type {
  PoolQueryClient,
  QueryResult,
} from "../generated/storage-kit/index.js";
import type { QueryResultRow } from "pg";
import {
  accountIdSchema,
  accountSchema,
  assertAccountCreationTransition,
  assertAccountLookupIdentity,
  assertAccountRenameRequest,
  assertAccountRenameTransition,
  assertEntityScope,
  assertRuntimeRegistrationTransition,
  assertRuntimeLookupIdentity,
  assertUniqueAccountIds,
  assertUniqueRuntimeIds,
  parseAccountRenameInput,
  RegistryConflictError,
  RegistryNotFoundError,
  registryScopeSchema,
  runtimeIdSchema,
  runtimeSchema,
  type Account,
  type AccountId,
  type RegistryScope,
  type Runtime,
  type RuntimeId,
} from "./domain.js";
import type { AccountsRegistry } from "./registry.js";

interface AccountRow {
  account_id: string;
  tenant_id: string;
  scope_id: string;
  name: string;
  runtime_id: string;
  email: string | null;
  created_at: string | Date;
  updated_at: string | Date;
}

interface RuntimeRow {
  runtime_id: string;
  tenant_id: string;
  scope_id: string;
  key: string;
  label: string;
  created_at: string | Date;
  updated_at: string | Date;
}

/**
 * Scoped PostgreSQL adapter for the additive v2 tables. It does not create,
 * migrate, backfill or constrain those tables; migration/enforcement remains a
 * separate gated slice. Every statement binds tenant_id and scope_id.
 */
export class PostgresAccountsRegistry implements AccountsRegistry {
  constructor(private readonly client: PoolQueryClient) {}

  async listAccounts(scopeInput: RegistryScope): Promise<readonly Account[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    const rows = await this.client.many<AccountRow>(
      `SELECT account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at
       FROM accounts_v2
       WHERE tenant_id = $1 AND scope_id = $2
       ORDER BY name, account_id`,
      [scope.tenantId, scope.scopeId],
    );
    const accounts = rows.map((row) => {
      const account = toAccount(row);
      assertEntityScope(scope, account);
      return account;
    });
    assertUniqueAccountIds(accounts);
    return accounts;
  }

  async getAccount(scopeInput: RegistryScope, accountIdInput: AccountId): Promise<Account | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const result = await this.client.query<AccountRow>(
      `SELECT account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at
       FROM accounts_v2
       WHERE tenant_id = $1 AND scope_id = $2 AND account_id = $3`,
      [scope.tenantId, scope.scopeId, accountId],
    );
    const row = optionalExactRow(result, "account lookup");
    if (!row) return null;
    const account = toAccount(row);
    assertEntityScope(scope, account);
    assertAccountLookupIdentity(accountId, account);
    return account;
  }

  async createAccount(scopeInput: RegistryScope, accountInput: Account): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const account = accountSchema.parse(accountInput);
    assertEntityScope(scope, account);
    try {
      return await this.client.transaction(async (client) => {
        const result = await client.query<AccountRow>(
          `INSERT INTO accounts_v2
             (account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at`,
          [
            account.id,
            scope.tenantId,
            scope.scopeId,
            account.name,
            account.runtimeId,
            account.email ?? null,
            account.createdAt,
            account.updatedAt,
          ],
        );
        const created = toAccount(requiredExactRow(result, "account creation"));
        assertEntityScope(scope, created);
        assertAccountCreationTransition(account, created);
        return created;
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new RegistryConflictError(`account id "${account.id}" already exists in this scope`);
      }
      throw error;
    }
  }

  async renameAccount(
    scopeInput: RegistryScope,
    accountIdInput: AccountId,
    nameInput: string,
    updatedAt: string,
  ): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const rename = parseAccountRenameInput(nameInput, updatedAt);
    return this.client.transaction(async (client) => {
      const currentResult = await client.query<AccountRow>(
        `SELECT account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at
         FROM accounts_v2
         WHERE tenant_id = $1 AND scope_id = $2 AND account_id = $3
         FOR UPDATE`,
        [scope.tenantId, scope.scopeId, accountId],
      );
      const currentRow = optionalExactRow(currentResult, "account rename pre-read");
      if (!currentRow) {
        throw new RegistryNotFoundError(
          `account id "${accountId}" was not found in this scope`,
        );
      }
      const current = toAccount(currentRow);
      assertEntityScope(scope, current);
      assertAccountLookupIdentity(accountId, current);
      assertAccountRenameRequest(current, rename);

      const result = await client.query<AccountRow>(
        `UPDATE accounts_v2
         SET name = $4, updated_at = $5
         WHERE tenant_id = $1 AND scope_id = $2 AND account_id = $3
           AND name = $6 AND runtime_id = $7 AND created_at = $8 AND updated_at = $9
           AND email IS NOT DISTINCT FROM $10
         RETURNING account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at`,
        [
          scope.tenantId,
          scope.scopeId,
          accountId,
          rename.name,
          rename.updatedAt,
          current.name,
          current.runtimeId,
          current.createdAt,
          current.updatedAt,
          current.email ?? null,
        ],
      );
      const renamed = toAccount(requiredExactRow(result, "account rename"));
      assertEntityScope(scope, renamed);
      assertAccountRenameTransition(current, rename, renamed);
      return renamed;
    });
  }

  async listRuntimes(scopeInput: RegistryScope): Promise<readonly Runtime[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    const rows = await this.client.many<RuntimeRow>(
      `SELECT runtime_id, tenant_id, scope_id, key, label, created_at, updated_at
       FROM runtimes_v2
       WHERE tenant_id = $1 AND scope_id = $2
       ORDER BY key, runtime_id`,
      [scope.tenantId, scope.scopeId],
    );
    const runtimes = rows.map((row) => {
      const runtime = toRuntime(row);
      assertEntityScope(scope, runtime);
      return runtime;
    });
    assertUniqueRuntimeIds(runtimes);
    return runtimes;
  }

  async getRuntime(scopeInput: RegistryScope, runtimeIdInput: RuntimeId): Promise<Runtime | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const result = await this.client.query<RuntimeRow>(
      `SELECT runtime_id, tenant_id, scope_id, key, label, created_at, updated_at
       FROM runtimes_v2
       WHERE tenant_id = $1 AND scope_id = $2 AND runtime_id = $3`,
      [scope.tenantId, scope.scopeId, runtimeId],
    );
    const row = optionalExactRow(result, "runtime lookup");
    if (!row) return null;
    const runtime = toRuntime(row);
    assertEntityScope(scope, runtime);
    assertRuntimeLookupIdentity(runtimeId, runtime);
    return runtime;
  }

  async registerRuntime(scopeInput: RegistryScope, runtimeInput: Runtime): Promise<Runtime> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtime = runtimeSchema.parse(runtimeInput);
    assertEntityScope(scope, runtime);
    try {
      return await this.client.transaction(async (client) => {
        const result = await client.query<RuntimeRow>(
          `INSERT INTO runtimes_v2
             (runtime_id, tenant_id, scope_id, key, label, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING runtime_id, tenant_id, scope_id, key, label, created_at, updated_at`,
          [
            runtime.id,
            scope.tenantId,
            scope.scopeId,
            runtime.key,
            runtime.label,
            runtime.createdAt,
            runtime.updatedAt,
          ],
        );
        const created = toRuntime(requiredExactRow(result, "runtime registration"));
        assertEntityScope(scope, created);
        assertRuntimeRegistrationTransition(runtime, created);
        return created;
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new RegistryConflictError(`runtime id "${runtime.id}" already exists in this scope`);
      }
      throw error;
    }
  }
}

function toAccount(row: AccountRow): Account {
  return accountSchema.parse({
    id: row.account_id,
    tenantId: row.tenant_id,
    scopeId: row.scope_id,
    name: row.name,
    runtimeId: row.runtime_id,
    ...(row.email === null ? {} : { email: row.email }),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function toRuntime(row: RuntimeRow): Runtime {
  return runtimeSchema.parse({
    id: row.runtime_id,
    tenantId: row.tenant_id,
    scopeId: row.scope_id,
    key: row.key,
    label: row.label,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function iso(value: string | Date): string {
  return value instanceof Date ? value.toISOString() : value;
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && (error as { code?: unknown }).code === "23505");
}

function optionalExactRow<T extends QueryResultRow>(
  result: QueryResult<T>,
  operation: string,
): T | null {
  if (result.rowCount === 0 && result.rows.length === 0) return null;
  return requiredExactRow(result, operation);
}

function requiredExactRow<T extends QueryResultRow>(
  result: QueryResult<T>,
  operation: string,
): T {
  if (result.rowCount !== 1 || result.rows.length !== 1) {
    throw new RegistryConflictError(
      `v2 PostgreSQL ${operation} must return exactly one row`,
    );
  }
  return result.rows[0] as T;
}
