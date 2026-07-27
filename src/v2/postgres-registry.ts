import type { PoolQueryClient } from "../generated/storage-kit/index.js";
import {
  accountIdSchema,
  accountSchema,
  assertEntityScope,
  RegistryConflictError,
  RegistryNotFoundError,
  renameAccountInputSchema,
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
    return rows.map((row) => {
      const account = toAccount(row);
      assertEntityScope(scope, account);
      return account;
    });
  }

  async getAccount(scopeInput: RegistryScope, accountIdInput: AccountId): Promise<Account | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const row = await this.client.get<AccountRow>(
      `SELECT account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at
       FROM accounts_v2
       WHERE tenant_id = $1 AND scope_id = $2 AND account_id = $3`,
      [scope.tenantId, scope.scopeId, accountId],
    );
    if (!row) return null;
    const account = toAccount(row);
    assertEntityScope(scope, account);
    return account;
  }

  async createAccount(scopeInput: RegistryScope, accountInput: Account): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const account = accountSchema.parse(accountInput);
    assertEntityScope(scope, account);
    try {
      const row = await this.client.one<AccountRow>(
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
      const created = toAccount(row);
      assertEntityScope(scope, created);
      return created;
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
    const rename = renameAccountInputSchema.parse({ name: nameInput, updatedAt });
    const row = await this.client.get<AccountRow>(
      `UPDATE accounts_v2
       SET name = $4, updated_at = $5
       WHERE tenant_id = $1 AND scope_id = $2 AND account_id = $3
       RETURNING account_id, tenant_id, scope_id, name, runtime_id, email, created_at, updated_at`,
      [scope.tenantId, scope.scopeId, accountId, rename.name, rename.updatedAt],
    );
    if (!row) throw new RegistryNotFoundError(`account id "${accountId}" was not found in this scope`);
    const renamed = toAccount(row);
    assertEntityScope(scope, renamed);
    return renamed;
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
    return rows.map((row) => {
      const runtime = toRuntime(row);
      assertEntityScope(scope, runtime);
      return runtime;
    });
  }

  async getRuntime(scopeInput: RegistryScope, runtimeIdInput: RuntimeId): Promise<Runtime | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const row = await this.client.get<RuntimeRow>(
      `SELECT runtime_id, tenant_id, scope_id, key, label, created_at, updated_at
       FROM runtimes_v2
       WHERE tenant_id = $1 AND scope_id = $2 AND runtime_id = $3`,
      [scope.tenantId, scope.scopeId, runtimeId],
    );
    if (!row) return null;
    const runtime = toRuntime(row);
    assertEntityScope(scope, runtime);
    return runtime;
  }

  async registerRuntime(scopeInput: RegistryScope, runtimeInput: Runtime): Promise<Runtime> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtime = runtimeSchema.parse(runtimeInput);
    assertEntityScope(scope, runtime);
    try {
      const row = await this.client.one<RuntimeRow>(
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
      const created = toRuntime(row);
      assertEntityScope(scope, created);
      return created;
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
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isUniqueViolation(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && (error as { code?: unknown }).code === "23505");
}
