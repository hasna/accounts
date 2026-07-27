import { describe, expect, test } from "bun:test";
import type {
  PoolQueryClient,
  QueryResult,
  TypedQueryClient,
} from "../generated/storage-kit/index.js";
import {
  accountSchema,
  registryScopeSchema,
  runtimeSchema,
  type Account,
  type RegistryScope,
  type Runtime,
} from "./domain.js";
import { HttpAccountsRegistry } from "./http-registry.js";
import { LocalAccountsRegistry } from "./local-registry.js";
import {
  MachineBindingOverlay,
  machineBindingSchema,
  type MachineBinding,
} from "./machine-binding.js";
import { PostgresAccountsRegistry } from "./postgres-registry.js";

const NOW = "2026-07-27T10:00:00.000Z";
const LATER = "2026-07-27T11:00:00.000Z";
const OLDER = "2026-07-27T09:00:00.000Z";
const scope = registryScopeSchema.parse({
  tenantId: "tenant_000000000001",
  scopeId: "scope_000000000001",
});
const otherScope = registryScopeSchema.parse({
  tenantId: "tenant_000000000002",
  scopeId: "scope_000000000002",
});

function runtime(
  scopeInput: RegistryScope = scope,
  id = "runtime_00000000001",
): Runtime {
  return runtimeSchema.parse({
    id,
    ...scopeInput,
    key: "claude",
    label: "Claude Code",
    createdAt: NOW,
    updatedAt: NOW,
  });
}

function account(
  scopeInput: RegistryScope = scope,
  id = "account_00000000001",
  runtimeId = runtime(scopeInput).id,
): Account {
  return accountSchema.parse({
    id,
    ...scopeInput,
    name: "work",
    runtimeId,
    createdAt: NOW,
    updatedAt: NOW,
  });
}

function binding(
  overrides: Partial<MachineBinding> = {},
  scopeInput: RegistryScope = scope,
): MachineBinding {
  return machineBindingSchema.parse({
    id: "binding_00000000001",
    ...scopeInput,
    accountId: "account_00000000001",
    runtimeId: "runtime_00000000001",
    machineId: "machine_00000000001",
    rootPath: "/machines/one/accounts/work",
    credentialRef: "vault:machine-one",
    authentication: "authenticated",
    generation: 2,
    ...overrides,
  });
}

describe("machine binding authorization generations", () => {
  test("rejects stale and non-idempotent same-generation updates atomically", () => {
    const original = binding();
    const overlay = new MachineBindingOverlay(original.machineId);
    overlay.put(scope, original);
    overlay.setCurrent(scope, original.runtimeId, original.id);
    overlay.setApplied(scope, original.runtimeId, original.id);

    for (const candidate of [
      binding({ generation: 1 }),
      binding({ rootPath: "/machines/one/accounts/rebound" }),
      binding({ credentialRef: "vault:replacement" }),
      binding({ authentication: "needs_login" }),
    ]) {
      expect(() => overlay.put(scope, candidate)).toThrow(/generation|idempotent/i);
      expect(overlay.get(scope, original.id)).toEqual(original);
      expect(overlay.current(scope, original.runtimeId)).toEqual(original);
      expect(overlay.applied(scope, original.runtimeId)).toEqual(original);
    }

    expect(overlay.put(scope, { ...original })).toEqual(original);
  });

  test("allows first registration and strictly newer transitions independently by id and scope", () => {
    const first = binding({ generation: 0 });
    const overlay = new MachineBindingOverlay(first.machineId);
    expect(overlay.put(scope, first)).toEqual(first);

    const next = binding({
      rootPath: "/machines/one/accounts/rebound",
      credentialRef: "vault:replacement",
      authentication: "needs_login",
      generation: 1,
    });
    expect(overlay.put(scope, next)).toEqual(next);

    const otherId = binding({
      id: "binding_00000000002",
      rootPath: "/machines/one/accounts/second",
      generation: 0,
    });
    expect(overlay.put(scope, otherId)).toEqual(otherId);

    const sameIdOtherScope = binding(
      {
        rootPath: "/machines/one/accounts/other-scope",
        generation: 0,
      },
      otherScope,
    );
    expect(overlay.put(otherScope, sameIdOtherScope)).toEqual(sameIdOtherScope);
    expect(overlay.get(scope, first.id)).toEqual(next);
    expect(overlay.get(scope, otherId.id)).toEqual(otherId);
    expect(overlay.get(otherScope, sameIdOtherScope.id)).toEqual(sameIdOtherScope);
  });
});

describe("shared account rename transition invariant", () => {
  test.each([
    ["same name", "work", LATER, /different/],
    ["unchanged timestamp", "renamed", NOW, /advance/],
    ["older timestamp", "renamed", OLDER, /advance/],
  ])(
    "local rejects %s without changing stored state",
    async (_label, requestedName, requestedAt, error) => {
      const before = account();
      const registry = new LocalAccountsRegistry({ accounts: [before] });
      await expect(
        registry.renameAccount(scope, before.id, requestedName, requestedAt),
      ).rejects.toThrow(error);
      expect(await registry.getAccount(scope, before.id)).toEqual(before);
    },
  );

  test.each([
    ["same name", "work", LATER, /different/],
    ["unchanged timestamp", "renamed", NOW, /advance/],
    ["older timestamp", "renamed", OLDER, /advance/],
  ])(
    "PostgreSQL rejects %s transactionally without issuing an update",
    async (_label, requestedName, requestedAt, error) => {
      const before = account();
      const harness = postgresHarness({ accounts: [before] });
      await expect(
        harness.registry.renameAccount(scope, before.id, requestedName, requestedAt),
      ).rejects.toThrow(error);
      expect(harness.account(before.id)).toEqual(before);
      expect(harness.operations.filter((operation) => operation === "renameAccount")).toEqual([]);
      expect(harness.rollbacks()).toBe(1);
    },
  );

  test("HTTP, local and PostgreSQL apply the same exact rename transition", async () => {
    const before = account();
    const local = new LocalAccountsRegistry({ accounts: [before] });
    const postgres = postgresHarness({ accounts: [before] });
    const http = new HttpAccountsRegistry({
      baseUrl: "https://accounts.example.test",
      apiKey: "fixture-authorization",
      fetchImpl: (async (_input, init) =>
        response(
          (init?.method ?? "GET") === "GET"
            ? before
            : { ...before, name: "renamed", updatedAt: LATER },
        )) as typeof fetch,
    });

    for (const registry of [local, postgres.registry, http]) {
      await expect(registry.renameAccount(scope, before.id, "renamed", LATER)).resolves.toEqual({
        ...before,
        name: "renamed",
        updatedAt: LATER,
      });
    }
  });
});

describe("PostgreSQL exact-row identity and rollback boundaries", () => {
  test("getAccount rejects a wrong same-scope account id", async () => {
    const before = account();
    const harness = postgresHarness({
      accounts: [before],
      tamper: (operation, row) =>
        operation === "getAccount"
          ? { ...row, account_id: "account_00000000002" }
          : row,
    });

    await expect(harness.registry.getAccount(scope, before.id)).rejects.toThrow(
      /account identity/i,
    );
  });

  test.each([
    ["id", { account_id: "account_00000000002" }],
    ["runtime", { runtime_id: "runtime_00000000002" }],
    ["createdAt", { created_at: OLDER }],
  ])("createAccount rejects wrong returned %s and rolls back", async (_label, patch) => {
    const input = account();
    const harness = postgresHarness({
      tamper: (operation, row) =>
        operation === "createAccount" ? { ...row, ...patch } : row,
    });

    await expect(harness.registry.createAccount(scope, input)).rejects.toThrow(/identity/i);
    expect(harness.account(input.id)).toBeNull();
    expect(harness.rollbacks()).toBe(1);
  });

  test("rename rejects a wrong pre-read id before mutation", async () => {
    const before = account();
    const harness = postgresHarness({
      accounts: [before],
      tamper: (operation, row) =>
        operation === "renameRead"
          ? { ...row, account_id: "account_00000000002" }
          : row,
    });

    await expect(
      harness.registry.renameAccount(scope, before.id, "renamed", LATER),
    ).rejects.toThrow(/identity/i);
    expect(harness.account(before.id)).toEqual(before);
    expect(harness.operations.filter((operation) => operation === "renameAccount")).toEqual([]);
    expect(harness.rollbacks()).toBe(1);
  });

  test.each([
    ["id", { account_id: "account_00000000002" }, /identity/i],
    ["runtime", { runtime_id: "runtime_00000000002" }, /identity/i],
    ["createdAt", { created_at: OLDER }, /identity/i],
    ["name", { name: "wrong-name" }, /requested name/i],
    ["timestamp", { updated_at: "2026-07-27T12:00:00.000Z" }, /requested timestamp/i],
  ])("rename rejects a wrong returned %s and rolls back", async (_label, patch, error) => {
    const before = account();
    const harness = postgresHarness({
      accounts: [before],
      tamper: (operation, row) =>
        operation === "renameAccount" ? { ...row, ...patch } : row,
    });

    await expect(
      harness.registry.renameAccount(scope, before.id, "renamed", LATER),
    ).rejects.toThrow(error);
    expect(harness.account(before.id)).toEqual(before);
    expect(harness.rollbacks()).toBe(1);
  });

  test("getRuntime rejects a wrong same-scope runtime id", async () => {
    const before = runtime();
    const harness = postgresHarness({
      runtimes: [before],
      tamper: (operation, row) =>
        operation === "getRuntime"
          ? { ...row, runtime_id: "runtime_00000000002" }
          : row,
    });

    await expect(harness.registry.getRuntime(scope, before.id)).rejects.toThrow(
      /runtime identity/i,
    );
  });

  test.each([
    ["id", { runtime_id: "runtime_00000000002" }],
    ["createdAt", { created_at: OLDER }],
  ])("registerRuntime rejects wrong returned %s and rolls back", async (_label, patch) => {
    const input = runtime();
    const harness = postgresHarness({
      tamper: (operation, row) =>
        operation === "registerRuntime" ? { ...row, ...patch } : row,
    });

    await expect(harness.registry.registerRuntime(scope, input)).rejects.toThrow(/identity/i);
    expect(harness.runtime(input.id)).toBeNull();
    expect(harness.rollbacks()).toBe(1);
  });

  test.each(["getAccount", "createAccount", "renameRead", "renameAccount", "getRuntime", "registerRuntime"])(
    "%s rejects non-exact row counts",
    async (operation) => {
      const existingAccount = account();
      const existingRuntime = runtime();
      const harness = postgresHarness({
        accounts: [existingAccount],
        runtimes: [existingRuntime],
        resultOverride: (seenOperation, result) =>
          seenOperation === operation
            ? { rows: [...result.rows, ...result.rows], rowCount: 2 }
            : result,
      });

      const action =
        operation === "getAccount"
          ? harness.registry.getAccount(scope, existingAccount.id)
          : operation === "createAccount"
            ? harness.registry.createAccount(
                scope,
                account(scope, "account_00000000002", existingRuntime.id),
              )
            : operation === "renameRead" || operation === "renameAccount"
              ? harness.registry.renameAccount(scope, existingAccount.id, "renamed", LATER)
              : operation === "getRuntime"
                ? harness.registry.getRuntime(scope, existingRuntime.id)
                : harness.registry.registerRuntime(
                    scope,
                    runtime(scope, "runtime_00000000002"),
                  );

      await expect(action).rejects.toThrow(/exactly one row/i);
      if (
        operation === "createAccount" ||
        operation === "renameRead" ||
        operation === "renameAccount" ||
        operation === "registerRuntime"
      ) {
        expect(harness.rollbacks()).toBe(1);
      }
    },
  );
});

type PostgresOperation =
  | "getAccount"
  | "createAccount"
  | "renameRead"
  | "renameAccount"
  | "getRuntime"
  | "registerRuntime"
  | "listAccounts"
  | "listRuntimes";

interface AccountRow extends Record<string, unknown> {
  account_id: string;
  tenant_id: string;
  scope_id: string;
  name: string;
  runtime_id: string;
  email: string | null;
  created_at: string;
  updated_at: string;
}

interface RuntimeRow extends Record<string, unknown> {
  runtime_id: string;
  tenant_id: string;
  scope_id: string;
  key: string;
  label: string;
  created_at: string;
  updated_at: string;
}

interface PostgresHarnessOptions {
  accounts?: readonly Account[];
  runtimes?: readonly Runtime[];
  tamper?: (
    operation: PostgresOperation,
    row: Record<string, unknown>,
  ) => Record<string, unknown>;
  resultOverride?: (
    operation: PostgresOperation,
    result: QueryResult<Record<string, unknown>>,
  ) => QueryResult<Record<string, unknown>>;
}

function postgresHarness(options: PostgresHarnessOptions = {}) {
  let accounts = new Map(
    (options.accounts ?? []).map((value) => [entityKey(value, value.id), accountRow(value)]),
  );
  let runtimes = new Map(
    (options.runtimes ?? []).map((value) => [entityKey(value, value.id), runtimeRow(value)]),
  );
  let rollbackCount = 0;
  const operations: PostgresOperation[] = [];

  const query = async <T extends Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<QueryResult<T>> => {
    const operation = classifyPostgresOperation(sql);
    operations.push(operation);
    const isAccount = sql.includes("accounts_v2");
    const source = isAccount ? accounts : runtimes;
    const id = String(params[2] ?? params[0]);
    const key = `${params[isAccount && sql.includes("INSERT") ? 1 : 0]}\0${
      params[isAccount && sql.includes("INSERT") ? 2 : 1]
    }\0${id}`;
    let rows: Record<string, unknown>[] = [];

    if (operation === "listAccounts" || operation === "listRuntimes") {
      const prefix = `${params[0]}\0${params[1]}\0`;
      rows = [...source.entries()]
        .filter(([storedKey]) => storedKey.startsWith(prefix))
        .map(([, value]) => value);
    } else if (operation === "getAccount" || operation === "renameRead" || operation === "getRuntime") {
      const value = source.get(key);
      rows = value ? [value] : [];
    } else if (operation === "createAccount") {
      if (source.has(key)) throw Object.assign(new Error("duplicate"), { code: "23505" });
      const value: AccountRow = {
        account_id: String(params[0]),
        tenant_id: String(params[1]),
        scope_id: String(params[2]),
        name: String(params[3]),
        runtime_id: String(params[4]),
        email: params[5] === null ? null : String(params[5]),
        created_at: String(params[6]),
        updated_at: String(params[7]),
      };
      source.set(key, value);
      rows = [value];
    } else if (operation === "registerRuntime") {
      if (source.has(key)) throw Object.assign(new Error("duplicate"), { code: "23505" });
      const value: RuntimeRow = {
        runtime_id: String(params[0]),
        tenant_id: String(params[1]),
        scope_id: String(params[2]),
        key: String(params[3]),
        label: String(params[4]),
        created_at: String(params[5]),
        updated_at: String(params[6]),
      };
      source.set(key, value);
      rows = [value];
    } else {
      const value = source.get(key);
      if (value) {
        const updated = {
          ...value,
          name: String(params[3]),
          updated_at: String(params[4]),
        };
        source.set(key, updated);
        rows = [updated];
      }
    }

    rows = rows.map((row) => options.tamper?.(operation, { ...row }) ?? { ...row });
    const rawResult: QueryResult<Record<string, unknown>> = {
      rows,
      rowCount: rows.length,
    };
    const result = options.resultOverride?.(operation, rawResult) ?? rawResult;
    return result as QueryResult<T>;
  };

  const typedClient: TypedQueryClient = {
    query,
    async many<T extends Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
    ): Promise<T[]> {
      return (await query<T>(sql, params)).rows;
    },
    async get<T extends Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
    ): Promise<T | null> {
      return (await query<T>(sql, params)).rows[0] ?? null;
    },
    async one<T extends Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
    ): Promise<T> {
      const result = await query<T>(sql, params);
      if (result.rows.length !== 1) throw new Error(`Expected exactly one row, got ${result.rows.length}.`);
      return result.rows[0]!;
    },
    async execute(sql: string, params?: readonly unknown[]): Promise<void> {
      await query(sql, params);
    },
  };

  const client: PoolQueryClient = {
    ...typedClient,
    pool: {} as never,
    async close() {},
    async transaction<T>(fn: (transactionClient: TypedQueryClient) => Promise<T>): Promise<T> {
      const beforeAccounts = new Map(accounts);
      const beforeRuntimes = new Map(runtimes);
      try {
        return await fn(typedClient);
      } catch (error) {
        accounts = beforeAccounts;
        runtimes = beforeRuntimes;
        rollbackCount += 1;
        throw error;
      }
    },
  };

  return {
    registry: new PostgresAccountsRegistry(client),
    operations,
    rollbacks: () => rollbackCount,
    account: (id: Account["id"]) => {
      const row = accounts.get(entityKey(scope, id));
      return row ? accountSchema.parse(accountFromRow(row)) : null;
    },
    runtime: (id: Runtime["id"]) => {
      const row = runtimes.get(entityKey(scope, id));
      return row ? runtimeSchema.parse(runtimeFromRow(row)) : null;
    },
  };
}

function classifyPostgresOperation(sql: string): PostgresOperation {
  const statement = sql.trimStart();
  if (sql.includes("accounts_v2")) {
    if (statement.startsWith("INSERT")) return "createAccount";
    if (statement.startsWith("UPDATE")) return "renameAccount";
    if (sql.includes("account_id = $3")) {
      return sql.includes("FOR UPDATE") ? "renameRead" : "getAccount";
    }
    return "listAccounts";
  }
  if (statement.startsWith("INSERT")) return "registerRuntime";
  if (sql.includes("runtime_id = $3")) return "getRuntime";
  return "listRuntimes";
}

function entityKey(scopeInput: RegistryScope, id: string): string {
  return `${scopeInput.tenantId}\0${scopeInput.scopeId}\0${id}`;
}

function accountRow(value: Account): AccountRow {
  return {
    account_id: value.id,
    tenant_id: value.tenantId,
    scope_id: value.scopeId,
    name: value.name,
    runtime_id: value.runtimeId,
    email: value.email ?? null,
    created_at: value.createdAt,
    updated_at: value.updatedAt,
  };
}

function runtimeRow(value: Runtime): RuntimeRow {
  return {
    runtime_id: value.id,
    tenant_id: value.tenantId,
    scope_id: value.scopeId,
    key: value.key,
    label: value.label,
    created_at: value.createdAt,
    updated_at: value.updatedAt,
  };
}

function accountFromRow(row: AccountRow): Account {
  return {
    id: row.account_id as Account["id"],
    tenantId: row.tenant_id as Account["tenantId"],
    scopeId: row.scope_id as Account["scopeId"],
    name: row.name,
    runtimeId: row.runtime_id as Account["runtimeId"],
    ...(row.email === null ? {} : { email: row.email }),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function runtimeFromRow(row: RuntimeRow): Runtime {
  return {
    id: row.runtime_id as Runtime["id"],
    tenantId: row.tenant_id as Runtime["tenantId"],
    scopeId: row.scope_id as Runtime["scopeId"],
    key: row.key,
    label: row.label,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
