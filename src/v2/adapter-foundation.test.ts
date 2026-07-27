import { describe, expect, test } from "bun:test";
import type { PoolQueryClient } from "../generated/storage-kit/index.js";
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
import { PostgresAccountsRegistry } from "./postgres-registry.js";
import type { AccountsRegistry } from "./registry.js";

const NOW = "2026-07-27T10:00:00.000Z";
const LATER = "2026-07-27T11:00:00.000Z";
const scopeA = registryScopeSchema.parse({
  tenantId: "tenant_000000000001",
  scopeId: "scope_000000000001",
});
const scopeB = registryScopeSchema.parse({
  tenantId: "tenant_000000000002",
  scopeId: "scope_000000000002",
});

function runtime(scope: RegistryScope, suffix: string): Runtime {
  return runtimeSchema.parse({
    id: `runtime_000000000${suffix}`,
    ...scope,
    key: "claude",
    label: "Claude Code",
    createdAt: NOW,
    updatedAt: NOW,
  });
}

function account(scope: RegistryScope, id: string, runtimeId: Runtime["id"]): Account {
  return accountSchema.parse({
    id,
    ...scope,
    name: "same-name",
    runtimeId,
    createdAt: NOW,
    updatedAt: NOW,
  });
}

interface AdapterFixture {
  name: string;
  registry: AccountsRegistry;
  evidence: () => readonly string[];
}

describe("AccountsRegistry structural adapter foundation", () => {
  for (const fixture of fixtures()) {
    test(`${fixture.name} preserves the same scoped create/read/rename behavior`, async () => {
      const runtimeA = runtime(scopeA, "01");
      const runtimeB = runtime(scopeB, "02");
      const first = account(scopeA, "account_00000000001", runtimeA.id);
      const sameName = account(scopeA, "account_00000000002", runtimeA.id);
      const foreign = account(scopeB, "account_00000000003", runtimeB.id);

      await fixture.registry.registerRuntime(scopeA, runtimeA);
      await fixture.registry.registerRuntime(scopeB, runtimeB);
      await fixture.registry.createAccount(scopeA, first);
      await fixture.registry.createAccount(scopeA, sameName);
      await fixture.registry.createAccount(scopeB, foreign);

      const renamed = await fixture.registry.renameAccount(scopeA, first.id, "renamed", LATER);
      expect({
        id: renamed.id,
        name: renamed.name,
        runtimeId: renamed.runtimeId,
        tenantId: renamed.tenantId,
        scopeId: renamed.scopeId,
        updatedAt: renamed.updatedAt,
      }).toEqual({
        id: first.id,
        name: "renamed",
        runtimeId: first.runtimeId,
        tenantId: scopeA.tenantId,
        scopeId: scopeA.scopeId,
        updatedAt: LATER,
      });

      expect((await fixture.registry.listAccounts(scopeA)).map((item) => item.name)).toEqual([
        "renamed",
        "same-name",
      ]);
      expect((await fixture.registry.listAccounts(scopeB)).map((item) => item.id)).toEqual([
        foreign.id,
      ]);
      expect(await fixture.registry.getAccount(scopeB, first.id)).toBeNull();
      expect((await fixture.registry.getRuntime(scopeA, runtimeA.id))?.key).toBe("claude");
      expect(await fixture.registry.getRuntime(scopeB, runtimeA.id)).toBeNull();
      expect(fixture.evidence().length).toBeGreaterThan(0);
    });
  }

  test("HTTP paths and PostgreSQL statements carry both tenant and scope", async () => {
    const all = fixtures();
    const http = all.find((fixture) => fixture.name === "http");
    const postgres = all.find((fixture) => fixture.name === "postgres");
    if (!http || !postgres) throw new Error("missing fixtures");
    const runtimeA = runtime(scopeA, "01");
    const accountA = account(scopeA, "account_00000000001", runtimeA.id);
    await http.registry.registerRuntime(scopeA, runtimeA);
    await http.registry.createAccount(scopeA, accountA);
    await http.registry.listAccounts(scopeA);
    await postgres.registry.registerRuntime(scopeA, runtimeA);
    await postgres.registry.createAccount(scopeA, accountA);
    await postgres.registry.listAccounts(scopeA);

    for (const path of http.evidence()) {
      expect(path).toContain(`/tenants/${scopeA.tenantId}/scopes/${scopeA.scopeId}/`);
    }
    for (const statement of postgres.evidence()) {
      expect(statement).toContain("tenant_id");
      expect(statement).toContain("scope_id");
      expect(statement).not.toMatch(/\bmetadata\b/);
    }
  });

  test("all adapters reject metadata envelopes before local, HTTP or PostgreSQL serialization", async () => {
    const unsafeAccount = {
      ...account(scopeA, "account_00000000001", runtime(scopeA, "01").id),
      metadata: {
        rootPath: "/machine/private/nested-root",
        credentialRef: "vault:nested-item",
        authentication: "authenticated",
        current: true,
        applied: true,
      },
    } as unknown as Account;

    for (const fixture of fixtures()) {
      await expect(fixture.registry.createAccount(scopeA, unsafeAccount)).rejects.toThrow();
      expect(fixture.evidence()).toEqual([]);
    }
  });

  test("HTTP rejects a valid response from the wrong tenant/scope", async () => {
    const foreign = account(
      scopeB,
      "account_00000000009",
      runtime(scopeB, "09").id,
    );
    const registry = new HttpAccountsRegistry({
      baseUrl: "https://accounts.example.test",
      apiKey: "fixture-authorization",
      fetchImpl: (async () => response({ accounts: [foreign] })) as typeof fetch,
    });
    await expect(registry.listAccounts(scopeA)).rejects.toThrow(/does not belong/);
  });

  test.each([
    [
      "scope",
      account(scopeB, "account_00000000001", runtime(scopeB, "01").id),
      /does not belong/,
    ],
    [
      "id",
      account(scopeA, "account_00000000002", runtime(scopeA, "01").id),
      /identity/,
    ],
  ])("HTTP rename rejects a pre-read with the wrong %s before mutation", async (_label, before, error) => {
    const methods: string[] = [];
    const registry = new HttpAccountsRegistry({
      baseUrl: "https://accounts.example.test",
      apiKey: "fixture-authorization",
      fetchImpl: (async (_input, init) => {
        const method = init?.method ?? "GET";
        methods.push(method);
        if (method === "GET") return response(before);
        return response({ ...before, name: "renamed", updatedAt: LATER });
      }) as typeof fetch,
    });

    await expect(
      registry.renameAccount(scopeA, "account_00000000001" as Account["id"], "renamed", LATER),
    ).rejects.toThrow(error);
    expect(methods).toEqual(["GET"]);
  });

  test.each([
    [
      "scope",
      account(scopeB, "account_00000000001", runtime(scopeB, "01").id),
      /does not belong/,
    ],
    [
      "id",
      account(scopeA, "account_00000000002", runtime(scopeA, "01").id),
      /identity/,
    ],
    [
      "runtime",
      account(scopeA, "account_00000000001", runtime(scopeA, "02").id),
      /identity/,
    ],
  ])("HTTP rename rejects a response that changes immutable %s", async (_label, after, error) => {
    const before = account(scopeA, "account_00000000001", runtime(scopeA, "01").id);
    const methods: string[] = [];
    const registry = new HttpAccountsRegistry({
      baseUrl: "https://accounts.example.test",
      apiKey: "fixture-authorization",
      fetchImpl: (async (_input, init) => {
        const method = init?.method ?? "GET";
        methods.push(method);
        return method === "GET"
          ? response(before)
          : response({ ...after, name: "renamed", updatedAt: LATER });
      }) as typeof fetch,
    });

    await expect(registry.renameAccount(scopeA, before.id, "renamed", LATER)).rejects.toThrow(error);
    expect(methods).toEqual(["GET", "POST"]);
  });

  test("Postgres validates rename input before issuing a mutation", async () => {
    const postgres = postgresFixture();
    const accountId = account(
      scopeA,
      "account_00000000001",
      runtime(scopeA, "01").id,
    ).id;
    await expect(
      postgres.registry.renameAccount(scopeA, accountId, "renamed", "not-a-timestamp"),
    ).rejects.toThrow();
    expect(postgres.evidence()).toEqual([]);
  });
});

function fixtures(): AdapterFixture[] {
  const local = new LocalAccountsRegistry();
  const http = httpFixture();
  const postgres = postgresFixture();
  return [
    {
      name: "local",
      registry: local,
      evidence: () =>
        local.snapshot().accounts.map(
          (item) => `${item.tenantId}/${item.scopeId}/${item.id}`,
        ),
    },
    http,
    postgres,
  ];
}

function httpFixture(): AdapterFixture {
  const accounts = new Map<string, Account>();
  const runtimes = new Map<string, Runtime>();
  const paths: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    paths.push(url.pathname);
    expect(new Headers(init?.headers).get("authorization")).toBe("Bearer fixture-authorization");
    const parts = url.pathname.split("/").filter(Boolean);
    const tenantId = parts[2]!;
    const scopeId = parts[4]!;
    const entity = parts[5]!;
    const id = parts[6];
    const action = parts[7];
    const prefix = `${tenantId}\0${scopeId}\0`;
    const collection = entity === "accounts" ? accounts : runtimes;
    const method = init?.method ?? "GET";
    const parsedBody = init?.body ? JSON.parse(String(init.body)) : undefined;

    if (method === "POST" && !id) {
      const value =
        entity === "accounts"
          ? accountSchema.parse(parsedBody)
          : runtimeSchema.parse(parsedBody);
      const valueId = value.id;
      const itemKey = `${prefix}${valueId}`;
      if (collection.has(itemKey)) return response({ error: "conflict" }, 409);
      collection.set(itemKey, value as Account & Runtime);
      return response(value, 201);
    }
    if (method === "POST" && entity === "accounts" && id && action === "rename") {
      const itemKey = `${prefix}${id}`;
      const existing = accounts.get(itemKey);
      if (!existing) return response({ error: "missing" }, 404);
      const renamed = accountSchema.parse({
        ...existing,
        name: parsedBody.name,
        updatedAt: parsedBody.updatedAt,
      });
      accounts.set(itemKey, renamed);
      return response(renamed);
    }
    if (method === "GET" && id) {
      const value = collection.get(`${prefix}${id}`);
      return value ? response(value) : response({ error: "missing" }, 404);
    }
    const values = [...collection.entries()]
      .filter(([itemKey]) => itemKey.startsWith(prefix))
      .map(([, value]) => value);
    return response(entity === "accounts" ? { accounts: values } : { runtimes: values });
  }) as typeof fetch;
  return {
    name: "http",
    registry: new HttpAccountsRegistry({
      baseUrl: "https://accounts.example.test",
      apiKey: "fixture-authorization",
      fetchImpl,
    }),
    evidence: () => paths,
  };
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function postgresFixture(): AdapterFixture {
  const accounts = new Map<string, Record<string, unknown>>();
  const runtimes = new Map<string, Record<string, unknown>>();
  const statements: string[] = [];
  const scopedKey = (params: readonly unknown[], idIndex = 2) =>
    `${params[0]}\0${params[1]}\0${params[idIndex]}`;
  const client = {
    pool: {} as never,
    close: async () => {},
    async many(sql: string, params: readonly unknown[] = []) {
      statements.push(sql);
      const source = sql.includes("accounts_v2") ? accounts : runtimes;
      const prefix = `${params[0]}\0${params[1]}\0`;
      return [...source.entries()]
        .filter(([itemKey]) => itemKey.startsWith(prefix))
        .map(([, value]) => value);
    },
    async get(sql: string, params: readonly unknown[] = []) {
      statements.push(sql);
      const source = sql.includes("accounts_v2") ? accounts : runtimes;
      const itemKey = scopedKey(params);
      if (sql.trimStart().startsWith("UPDATE")) {
        const existing = source.get(itemKey);
        if (!existing) return null;
        const updated = {
          ...existing,
          name: params[3],
          updated_at: params[4],
        };
        source.set(itemKey, updated);
        return updated;
      }
      return source.get(itemKey) ?? null;
    },
    async one(sql: string, params: readonly unknown[] = []) {
      statements.push(sql);
      if (sql.includes("accounts_v2")) {
        const itemKey = `${params[1]}\0${params[2]}\0${params[0]}`;
        if (accounts.has(itemKey)) throw Object.assign(new Error("duplicate"), { code: "23505" });
        const row = {
          account_id: params[0],
          tenant_id: params[1],
          scope_id: params[2],
          name: params[3],
          runtime_id: params[4],
          email: params[5],
          created_at: params[6],
          updated_at: params[7],
        };
        accounts.set(itemKey, row);
        return row;
      }
      const itemKey = `${params[1]}\0${params[2]}\0${params[0]}`;
      if (runtimes.has(itemKey)) throw Object.assign(new Error("duplicate"), { code: "23505" });
      const row = {
        runtime_id: params[0],
        tenant_id: params[1],
        scope_id: params[2],
        key: params[3],
        label: params[4],
        created_at: params[5],
        updated_at: params[6],
      };
      runtimes.set(itemKey, row);
      return row;
    },
    async query() {
      throw new Error("unexpected query");
    },
    async execute() {
      throw new Error("unexpected execute");
    },
    async transaction<T>(fn: (value: PoolQueryClient) => Promise<T>): Promise<T> {
      return fn(this as unknown as PoolQueryClient);
    },
  } as unknown as PoolQueryClient;
  return {
    name: "postgres",
    registry: new PostgresAccountsRegistry(client),
    evidence: () => statements,
  };
}
