import type {
  Account,
  AccountId,
  RegistryScope,
  Runtime,
  RuntimeId,
} from "./domain.js";

/**
 * The only v2 registry domain port. Every operation carries its authenticated
 * tenant/scope explicitly; adapters may not infer scope from account names.
 *
 * IDs and an account's runtime are immutable because this additive foundation
 * exposes create/read/rename only. Name uniqueness and runtime constraints are
 * intentionally deferred to the evidence-gated enforcement slice.
 */
export interface AccountsRegistry {
  listAccounts(scope: RegistryScope): Promise<readonly Account[]>;
  getAccount(scope: RegistryScope, accountId: AccountId): Promise<Account | null>;
  createAccount(scope: RegistryScope, account: Account): Promise<Account>;
  renameAccount(
    scope: RegistryScope,
    accountId: AccountId,
    name: string,
    updatedAt: string,
  ): Promise<Account>;
  listRuntimes(scope: RegistryScope): Promise<readonly Runtime[]>;
  getRuntime(scope: RegistryScope, runtimeId: RuntimeId): Promise<Runtime | null>;
  registerRuntime(scope: RegistryScope, runtime: Runtime): Promise<Runtime>;
}
