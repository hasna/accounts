import { describe, expect, test } from "bun:test";
import type { PoolQueryClient, TypedQueryClient } from "../generated/storage-kit/index.js";
import { AccountsRepo } from "./repo.js";

const OLD_ROW = {
  tool: "claude",
  name: "old",
  email: null,
  display_name: null,
  identity: null,
  card_last4: null,
  metadata: {},
  dir: null,
  description: null,
  created_at: "2020-01-01T00:00:00Z",
  last_used_at: null,
};

function transactionalClient(failOnAccountWrite: boolean) {
  let transactions = 0;
  let rolledBack = false;
  let completedOperation: {
    operation_id: string;
    tool: string;
    name: string;
    state: "completed" | "cancelled";
    updated_at: string | null;
    revision: string | null;
    previous_name: string | null;
    previous_target_last_used_at: string | null;
  } | null = null;
  const statements: string[] = [];
  const direct = () => {
    throw new Error("repository write escaped the transaction");
  };
  const tx: TypedQueryClient = {
    async query(sql) {
      statements.push(sql);
      if (sql.startsWith("DELETE FROM accounts")) return { rows: [{ tool: "claude" }], rowCount: 1 };
      if (sql.includes("UPDATE current_selections")) return { rows: [{ tool: "claude" }], rowCount: 1 };
      if (sql.includes("DELETE FROM current_selections")) return { rows: [{ tool: "claude" }], rowCount: 1 };
      throw new Error("unexpected query: " + sql);
    },
    async many(sql, params) {
      statements.push(sql);
      if (sql.includes("FROM accounts") && sql.includes("ANY($2::text[])")) {
        return ((params?.[1] as string[] | undefined) ?? [])
          .filter((name) => name === "old")
          .map((name) => ({ name }));
      }
      return [];
    },
    async get(sql, params) {
      statements.push(sql);
      if (sql.includes("FROM current_login_operations")) {
        return completedOperation;
      }
      if (sql.includes("FROM current_selections") && sql.includes("login_operation_id")) {
        return { updated_at: "2026-07-21T00:00:00.000Z" };
      }
      if (sql.includes("SELECT name FROM current_selections")) return { name: "old" };
      if (sql.includes("SELECT updated_at") && sql.includes("FROM current_selections")) {
        return { updated_at: "2026-07-21T00:00:00.000Z" };
      }
      return params?.[1] === "old" ? OLD_ROW : null;
    },
    async one(sql, params) {
      statements.push(sql);
      if (sql.startsWith("WITH stamp AS")) {
        return {
          tool: "claude",
          name: "old",
          updated_at: "2026-07-21T00:00:00.000Z",
          revision: "7",
          login_operation_id: String(params?.[2] ?? "operation"),
        };
      }
      if (sql.startsWith("UPDATE accounts SET name")) {
        if (failOnAccountWrite) throw new Error("account update failed");
        return { ...OLD_ROW, name: "new" };
      }
      throw new Error("unexpected one: " + sql);
    },
    async execute(sql, params) {
      statements.push(sql);
      if (sql.includes("INSERT INTO current_login_operations")) {
        completedOperation = {
          operation_id: String(params?.[0]),
          tool: String(params?.[1]),
          name: String(params?.[2]),
          state: sql.includes("'cancelled'") ? "cancelled" : "completed",
          updated_at: sql.includes("'cancelled'") ? null : String(params?.[3]),
          revision: sql.includes("'cancelled'") ? null : String(params?.[4]),
          previous_name: sql.includes("'cancelled'") ? null : String(params?.[5]),
          previous_target_last_used_at: sql.includes("'cancelled'") ? null : (params?.[6] as string | null),
        };
      }
    },
  };
  const client = {
    pool: {} as never,
    close: async () => {},
    query: direct,
    many: direct,
    get: direct,
    one: direct,
    execute: direct,
    async transaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T> {
      transactions += 1;
      try {
        return await fn(tx);
      } catch (error) {
        rolledBack = true;
        throw error;
      }
    },
  } as unknown as PoolQueryClient;
  return { client, evidence: () => ({ transactions, rolledBack, statements }) };
}

describe("AccountsRepo account/current atomicity", () => {
  test("restoreProfile conditionally touches only finalization-owned fields", async () => {
    const statements: string[] = [];
    const client = {
      pool: {} as never,
      close: async () => {},
      async get(sql: string) {
        statements.push(sql);
        return OLD_ROW;
      },
    } as unknown as PoolQueryClient;
    const restored = await new AccountsRepo(client).restoreProfile("claude", "old", {
      email: { expected: "failed@example.com", restore: null },
      lastUsedAt: { expected: "2026-07-21T00:00:00.000Z", restore: null },
    });
    expect(restored.name).toBe("old");
    expect(statements[0]).toContain("IS NOT DISTINCT FROM");
    expect(statements[0]).not.toContain("description =");
  });

  test("setCurrent uses a wire-stable millisecond timestamp for last-used rollback", async () => {
    const fixture = transactionalClient(false);
    await new AccountsRepo(fixture.client).setCurrent("claude", "old");
    expect(fixture.evidence().statements.some((sql) => /date_trunc\('milliseconds', now\(\)\)/.test(sql))).toBe(true);
  });

  test("login activation persists a client operation id and operation rollback owns the write", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    const operationId = "11111111-1111-4111-8111-111111111111";
    expect((await repo.setCurrentForLogin("claude", "old", operationId)).operationId).toBe(operationId);
    expect(await repo.restoreCurrentOperation("claude", "old", operationId, undefined, null)).toBe(true);
    const statements = fixture.evidence().statements;
    expect(statements.some((sql) => /login_operation_id/.test(sql))).toBe(true);
    expect(statements.some((sql) => /INSERT INTO current_login_operations/.test(sql))).toBe(true);
    expect(statements.some((sql) => /WHERE tool = \$1 AND name = \$2 AND login_operation_id = \$3/.test(sql))).toBe(true);
    expect(statements.some((sql) => /SET last_used_at = NULL/.test(sql))).toBe(true);
    const rollbackAccountLock = statements.findIndex((sql) => /name = ANY\(\$2::text\[\]\)/.test(sql));
    const rollbackCurrentLock = statements.findIndex((sql, index) =>
      index > rollbackAccountLock && /FROM current_selections[\s\S]*login_operation_id/.test(sql),
    );
    expect(rollbackAccountLock).toBeGreaterThanOrEqual(0);
    expect(rollbackCurrentLock).toBeGreaterThan(rollbackAccountLock);
  });

  test("rollback before activation durably cancels the operation", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    const operationId = "33333333-3333-4333-8333-333333333333";

    expect(await repo.restoreCurrentOperation("claude", "old", operationId)).toBe(true);
    expect(fixture.evidence().statements.some((sql) =>
      /INSERT INTO current_login_operations[\s\S]*cancelled/.test(sql),
    )).toBe(true);
    await expect(repo.setCurrentForLogin("claude", "old", operationId)).rejects.toThrow(/cancelled/);
    expect(fixture.evidence().statements.filter((sql) => sql.startsWith("WITH stamp AS"))).toHaveLength(0);
  });

  test("rename locks and updates the account in one transaction; the FK cascades current", async () => {
    const fixture = transactionalClient(false);
    const renamed = await new AccountsRepo(fixture.client).rename("claude", "old", "new");
    expect(renamed.name).toBe("new");
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().statements.some((sql) => /FOR UPDATE/.test(sql))).toBe(true);
    expect(fixture.evidence().statements.some((sql) => /UPDATE current_selections/.test(sql))).toBe(false);
  });

  test("rename rolls back when the account update fails", async () => {
    const fixture = transactionalClient(true);
    await expect(new AccountsRepo(fixture.client).rename("claude", "old", "new")).rejects.toThrow(
      "account update failed",
    );
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().rolledBack).toBe(true);
  });

  test("remove locks and deletes the account; the FK cascades current", async () => {
    const fixture = transactionalClient(false);
    expect(await new AccountsRepo(fixture.client).remove("claude", "old")).toBe(true);
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().statements.some((sql) => /FOR UPDATE/.test(sql))).toBe(true);
    expect(fixture.evidence().statements.some((sql) => /DELETE FROM current_selections/.test(sql))).toBe(false);
  });

  test("restoreCurrent conditionally replaces or clears only the expected selection", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    expect(await repo.restoreCurrent("claude", "failed", "7", "old")).toBe(true);
    expect(await repo.restoreCurrent("claude", "failed", "8")).toBe(true);
    const statements = fixture.evidence().statements;
    expect(statements.some((sql) => /UPDATE current_selections[\s\S]*revision = \$3::bigint/.test(sql))).toBe(true);
    expect(statements.some((sql) => /DELETE FROM current_selections[\s\S]*revision = \$3::bigint/.test(sql))).toBe(true);
  });

  test("revision rollback restores lastUsedAt only while it owns the activation timestamp", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    expect(await repo.restoreCurrent("claude", "old", "7", undefined, null)).toBe(true);
    const statements = fixture.evidence().statements;
    expect(statements.some((sql) => /SELECT updated_at[\s\S]*revision = \$3::bigint[\s\S]*FOR UPDATE/.test(sql))).toBe(true);
    expect(statements.some((sql) => /UPDATE accounts[\s\S]*last_used_at IS NOT DISTINCT FROM \$3::timestamptz/.test(sql))).toBe(true);
  });

  test("restoreCurrent preserves the legacy name-conditional request path", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    expect(await repo.restoreCurrent("claude", "failed", undefined, "old")).toBe(true);
    expect(await repo.restoreCurrent("claude", "failed")).toBe(true);
    const statements = fixture.evidence().statements;
    expect(statements.some((sql) => /UPDATE current_selections[\s\S]*WHERE tool = \$1 AND name = \$2(?![\s\S]*revision)/.test(sql))).toBe(true);
    expect(statements.some((sql) => /DELETE FROM current_selections WHERE tool = \$1 AND name = \$2 RETURNING tool/.test(sql))).toBe(true);
  });
});
