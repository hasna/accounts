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
 * In-memory structural test double over an isolated v2 state object.
 *
 * It intentionally neither reads nor rewrites accounts.json and does not
 * represent production local-storage parity. A later migration slice can
 * hydrate/persist snapshots without coupling the domain port to a premature
 * sidecar format.
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
    return Object.freeze(
      [...this.accounts.values()]
        .filter((account) => inScope(scope, account))
        .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
        .map(immutableAccount),
    );
  }

  async getAccount(scopeInput: RegistryScope, accountIdInput: AccountId): Promise<Account | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const account = this.accounts.get(key(scope, accountId));
    return account ? immutableAccount(account) : null;
  }

  async createAccount(scopeInput: RegistryScope, accountInput: Account): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const account = immutableAccount(accountInput);
    assertEntityScope(scope, account);
    const accountKey = key(scope, account.id);
    if (this.accounts.has(accountKey)) {
      throw new RegistryConflictError(`account id "${account.id}" already exists in this scope`);
    }
    this.accounts.set(accountKey, account);
    return immutableAccount(account);
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
    const renamed = immutableAccount({
      ...current,
      name: rename.name,
      updatedAt: rename.updatedAt,
    });
    this.accounts.set(key(scope, accountId), renamed);
    return immutableAccount(renamed);
  }

  async listRuntimes(scopeInput: RegistryScope): Promise<readonly Runtime[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    return Object.freeze(
      [...this.runtimes.values()]
        .filter((runtime) => inScope(scope, runtime))
        .sort((a, b) => a.key.localeCompare(b.key) || a.id.localeCompare(b.id))
        .map(immutableRuntime),
    );
  }

  async getRuntime(scopeInput: RegistryScope, runtimeIdInput: RuntimeId): Promise<Runtime | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const runtime = this.runtimes.get(key(scope, runtimeId));
    return runtime ? immutableRuntime(runtime) : null;
  }

  async registerRuntime(scopeInput: RegistryScope, runtimeInput: Runtime): Promise<Runtime> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtime = immutableRuntime(runtimeInput);
    assertEntityScope(scope, runtime);
    const runtimeKey = key(scope, runtime.id);
    if (this.runtimes.has(runtimeKey)) {
      throw new RegistryConflictError(`runtime id "${runtime.id}" already exists in this scope`);
    }
    this.runtimes.set(runtimeKey, runtime);
    return immutableRuntime(runtime);
  }

  snapshot(): { accounts: readonly Account[]; runtimes: readonly Runtime[] } {
    return Object.freeze({
      accounts: Object.freeze([...this.accounts.values()].map(immutableAccount)),
      runtimes: Object.freeze([...this.runtimes.values()].map(immutableRuntime)),
    });
  }

  private seedAccount(input: Account): void {
    const account = immutableAccount(input);
    const accountKey = key(account, account.id);
    if (this.accounts.has(accountKey)) {
      throw new RegistryConflictError(`account id "${account.id}" already exists in this scope`);
    }
    this.accounts.set(accountKey, account);
  }

  private seedRuntime(input: Runtime): void {
    const runtime = immutableRuntime(input);
    const runtimeKey = key(runtime, runtime.id);
    if (this.runtimes.has(runtimeKey)) {
      throw new RegistryConflictError(`runtime id "${runtime.id}" already exists in this scope`);
    }
    this.runtimes.set(runtimeKey, runtime);
  }
}

function immutableAccount(input: Account): Account {
  return Object.freeze(accountSchema.parse(input));
}

function immutableRuntime(input: Runtime): Runtime {
  return Object.freeze(runtimeSchema.parse(input));
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
