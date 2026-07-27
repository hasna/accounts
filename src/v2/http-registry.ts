import {
  accountIdSchema,
  accountSchema,
  accountV2ListSchema,
  assertAccountLookupIdentity,
  assertAccountRenameTransition,
  assertEntityScope,
  assertRuntimeLookupIdentity,
  assertSameAccountIdentity,
  assertSameRuntimeIdentity,
  parseAccountRename,
  toAccountRenameRequest,
  RegistryConflictError,
  RegistryNotFoundError,
  registryScopeSchema,
  runtimeIdSchema,
  runtimeSchema,
  runtimeV2ListSchema,
  toAccountV2Dto,
  toRuntimeV2Dto,
  type Account,
  type AccountId,
  type RegistryScope,
  type Runtime,
  type RuntimeId,
} from "./domain.js";
import type { AccountsRegistry } from "./registry.js";

export interface HttpAccountsRegistryOptions {
  baseUrl: string;
  apiKey: string;
  fetchImpl?: typeof fetch;
}

/**
 * Structural client foundation for future v2 HTTP routes. The repository does
 * not activate those routes yet, and fixture coverage is not backend parity.
 */
export class HttpAccountsRegistry implements AccountsRegistry {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpAccountsRegistryOptions) {
    if (!options.baseUrl.trim()) throw new Error("v2 registry baseUrl is required");
    if (!options.apiKey.trim()) throw new Error("v2 registry apiKey is required");
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async listAccounts(scopeInput: RegistryScope): Promise<readonly Account[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    const body = await this.request(scope, "/accounts", { method: "GET" });
    const accounts = accountV2ListSchema.parse(body).accounts;
    for (const account of accounts) assertEntityScope(scope, account);
    return accounts;
  }

  async getAccount(scopeInput: RegistryScope, accountIdInput: AccountId): Promise<Account | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const body = await this.request(scope, `/accounts/${encodeURIComponent(accountId)}`, {
      method: "GET",
      allowNotFound: true,
    });
    if (body === null) return null;
    const account = accountSchema.parse(body);
    assertEntityScope(scope, account);
    assertAccountLookupIdentity(accountId, account);
    return account;
  }

  async createAccount(scopeInput: RegistryScope, accountInput: Account): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const account = accountSchema.parse(accountInput);
    assertEntityScope(scope, account);
    const body = await this.request(scope, "/accounts", {
      method: "POST",
      body: toAccountV2Dto(account),
    });
    const created = accountSchema.parse(body);
    assertEntityScope(scope, created);
    assertSameAccountIdentity(account, created);
    return created;
  }

  async renameAccount(
    scopeInput: RegistryScope,
    accountIdInput: AccountId,
    nameInput: string,
    updatedAt: string,
  ): Promise<Account> {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    const current = await this.getAccount(scope, accountId);
    if (!current) {
      throw new RegistryNotFoundError(`account id "${accountId}" was not found in this scope`);
    }
    const rename = parseAccountRename(current, nameInput, updatedAt);
    const request = toAccountRenameRequest(current, rename);
    const body = await this.request(scope, `/accounts/${encodeURIComponent(accountId)}/rename`, {
      method: "POST",
      body: request,
      headers: {
        "If-Match": `"${request.expectedUpdatedAt}"`,
      },
    });
    const renamed = accountSchema.parse(body);
    assertEntityScope(scope, renamed);
    assertAccountRenameTransition(current, rename, renamed);
    return renamed;
  }

  async listRuntimes(scopeInput: RegistryScope): Promise<readonly Runtime[]> {
    const scope = registryScopeSchema.parse(scopeInput);
    const body = await this.request(scope, "/runtimes", { method: "GET" });
    const runtimes = runtimeV2ListSchema.parse(body).runtimes;
    for (const runtime of runtimes) assertEntityScope(scope, runtime);
    return runtimes;
  }

  async getRuntime(scopeInput: RegistryScope, runtimeIdInput: RuntimeId): Promise<Runtime | null> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const body = await this.request(scope, `/runtimes/${encodeURIComponent(runtimeId)}`, {
      method: "GET",
      allowNotFound: true,
    });
    if (body === null) return null;
    const runtime = runtimeSchema.parse(body);
    assertEntityScope(scope, runtime);
    assertRuntimeLookupIdentity(runtimeId, runtime);
    return runtime;
  }

  async registerRuntime(scopeInput: RegistryScope, runtimeInput: Runtime): Promise<Runtime> {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtime = runtimeSchema.parse(runtimeInput);
    assertEntityScope(scope, runtime);
    const body = await this.request(scope, "/runtimes", {
      method: "POST",
      body: toRuntimeV2Dto(runtime),
    });
    const created = runtimeSchema.parse(body);
    assertEntityScope(scope, created);
    assertSameRuntimeIdentity(runtime, created);
    return created;
  }

  private async request(
    scope: RegistryScope,
    suffix: string,
    options: {
      method: string;
      body?: unknown;
      allowNotFound?: boolean;
      headers?: Readonly<Record<string, string>>;
    },
  ): Promise<unknown | null> {
    const root =
      `${this.baseUrl}/v2/tenants/${encodeURIComponent(scope.tenantId)}` +
      `/scopes/${encodeURIComponent(scope.scopeId)}`;
    const response = await this.fetchImpl(`${root}${suffix}`, {
      method: options.method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        ...(options.body === undefined ? {} : { "Content-Type": "application/json" }),
        ...options.headers,
      },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
    if (options.allowNotFound && response.status === 404) return null;
    if (!response.ok) {
      if (response.status === 409) throw new RegistryConflictError("v2 registry conflict");
      if (response.status === 404) throw new RegistryNotFoundError("v2 registry entity was not found");
      throw new Error(`v2 accounts registry request failed with status ${response.status}`);
    }
    return response.status === 204 ? null : response.json();
  }
}
