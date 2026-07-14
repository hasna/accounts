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

function transactionalClient(failOnCurrent: boolean) {
  let transactions = 0;
  let rolledBack = false;
  const statements: string[] = [];
  const direct = () => {
    throw new Error("repository write escaped the transaction");
  };
  const tx: TypedQueryClient = {
    async query(sql) {
      statements.push(sql);
      if (sql.startsWith("DELETE FROM accounts")) return { rows: [{ tool: "claude" }], rowCount: 1 };
      throw new Error("unexpected query: " + sql);
    },
    async many() {
      return [];
    },
    async get(sql, params) {
      statements.push(sql);
      return params?.[1] === "old" ? OLD_ROW : null;
    },
    async one(sql) {
      statements.push(sql);
      if (sql.startsWith("UPDATE accounts SET name")) return { ...OLD_ROW, name: "new" };
      throw new Error("unexpected one: " + sql);
    },
    async execute(sql) {
      statements.push(sql);
      if (failOnCurrent && /current_selections/.test(sql)) throw new Error("selection update failed");
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
  test("rename updates the account and current selection in one transaction", async () => {
    const fixture = transactionalClient(false);
    const renamed = await new AccountsRepo(fixture.client).rename("claude", "old", "new");
    expect(renamed.name).toBe("new");
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().statements.some((sql) => /UPDATE current_selections/.test(sql))).toBe(true);
  });

  test("rename rolls back when current-selection update fails", async () => {
    const fixture = transactionalClient(true);
    await expect(new AccountsRepo(fixture.client).rename("claude", "old", "new")).rejects.toThrow(
      "selection update failed",
    );
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().rolledBack).toBe(true);
  });

  test("remove deletes the account and current selection in one transaction", async () => {
    const fixture = transactionalClient(false);
    expect(await new AccountsRepo(fixture.client).remove("claude", "old")).toBe(true);
    expect(fixture.evidence().transactions).toBe(1);
    expect(fixture.evidence().statements.some((sql) => /DELETE FROM current_selections/.test(sql))).toBe(true);
  });
});
