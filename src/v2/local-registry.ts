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

export interface LocalRegistrySeed {
  accounts?: readonly Account[];
  runtimes?: readonly Runtime[];
}

/**
 * Machine-local adapter over an isolated v2 state object.
 *
 * It intentionally neither reads nor rewrites accounts.json. The migration
 * slice can hydrate/persist snapshots without coupling the domain port to a
 * premature sidecar format.
 */
export class LocalAccountsRegistry implements AccountsRegistry {
  private readonly accounts = new Map<string, Account>();
  private readonly runtimes = new Map<string, Runtime>();

  constructor(seed: LocalRegistrySeed = {}) {
    for (const runtime of seed.runtimes ?? []) this.seedRuntime(runtime);
    for (const account of seed.accounts ?? []) this.seedAccount(account);
  }

  async listAccounts(scopeInput: RegistryScope): Promise<readonly Account[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    return [...this.accounts.values()]
      .filter((account) => inScope(scope, account))
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  }

  async getAccount(scopeInput: RegistryScope, accountIdInput: AccountId): Promise<Account | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    return this.accounts.get(key(scope, accountId)) ?? null;
  }

  async createAccount(scopeInput: RegistryScope, accountInput: Account): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const account = accountSchema.parse(accountInput);
    assertEntityScope(scope, account);
    const accountKey = key(scope, account.id);
    if (this.accounts.has(accountKey)) {
      throw new RegistryConflictError(`account id "${account.id}" already exists in this scope`);
    }
    this.accounts.set(accountKey, account);
    return account;
  }

  async renameAccount(
    scopeInput: RegistryScope,
    accountIdInput: AccountId,
    nameInput: string,
    updatedAtInput: string,
  ): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const rename = renameAccountInputSchema.parse({
      name: nameInput,
      updatedAt: updatedAtInput,
    });
    const current = this.accounts.get(key(scope, accountId));
    if (!current) throw new RegistryNotFoundError(`account id "${accountId}" was not found in this scope`);
    const renamed = accountSchema.parse({
      ...current,
      name: rename.name,
      updatedAt: rename.updatedAt,
    });
    this.accounts.set(key(scope, accountId), renamed);
    return renamed;
  }

  async listRuntimes(scopeInput: RegistryScope): Promise<readonly Runtime[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    return [...this.runtimes.values()]
      .filter((runtime) => inScope(scope, runtime))
      .sort((a, b) => a.key.localeCompare(b.key) || a.id.localeCompare(b.id));
  }

  async getRuntime(scopeInput: RegistryScope, runtimeIdInput: RuntimeId): Promise<Runtime | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    return this.runtimes.get(key(scope, runtimeId)) ?? null;
  }

  async registerRuntime(scopeInput: RegistryScope, runtimeInput: Runtime): Promise<Runtime> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtime = runtimeSchema.parse(runtimeInput);
    assertEntityScope(scope, runtime);
    const runtimeKey = key(scope, runtime.id);
    if (this.runtimes.has(runtimeKey)) {
      throw new RegistryConflictError(`runtime id "${runtime.id}" already exists in this scope`);
    }
    this.runtimes.set(runtimeKey, runtime);
    return runtime;
  }

  snapshot(): { accounts: readonly Account[]; runtimes: readonly Runtime[] } {
    return {
      accounts: [...this.accounts.values()],
      runtimes: [...this.runtimes.values()],
    };
  }

  private seedAccount(input: Account): void {
    const account = accountSchema.parse(input);
    this.accounts.set(key(account, account.id), account);
  }

  private seedRuntime(input: Runtime): void {
    const runtime = runtimeSchema.parse(input);
    this.runtimes.set(key(runtime, runtime.id), runtime);
  }
}

function key(scope: RegistryScope, id: string): string {
  return `${scope.tenantId}\0${scope.scopeId}\0${id}`;
}

function inScope(
  scope: RegistryScope,
  value: Pick<Account | Runtime, "tenantId" | "scopeId">,
): boolean {
  return value.tenantId === scope.tenantId && value.scopeId === scope.scopeId;
}
