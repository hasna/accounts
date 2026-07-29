import { describe, expect, test } from "bun:test";
import type { PoolQueryClient, TypedQueryClient } from "../generated/storage-kit/index.js";
import { accountNameLockKey, AccountsRepo, toolLockKey } from "./repo.js";

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
      if (sql.startsWith("UPDATE accounts SET name")) {
        if (failOnAccountWrite) throw new Error("account update failed");
        return { ...OLD_ROW, name: "new" };
      }
      throw new Error("unexpected one: " + sql);
    },
    async execute(sql) {
      statements.push(sql);
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
});

/**
 * A client that records the advisory-lock KEYS a call takes, in order.
 *
 * `existingName` is the only name the fake registry knows about, matched
 * against any bound parameter so the fixture does not have to mirror the exact
 * shape of the repository's lookup query.
 */
function lockRecordingClient(existingName: string | null) {
  const lockKeys: string[] = [];
  const row = {
    ...OLD_ROW,
    name: existingName ?? OLD_ROW.name,
  };
  const tx: TypedQueryClient = {
    async query() {
      return { rows: [], rowCount: 0 };
    },
    async many() {
      return [];
    },
    async get(_sql, params) {
      const wanted = existingName !== null && (params ?? []).includes(existingName);
      return wanted ? row : null;
    },
    async one() {
      return row;
    },
    async execute(sql, params) {
      if (/pg_advisory_xact_lock/.test(sql)) lockKeys.push(String(params?.[0]));
    },
  };
  const client = {
    pool: {} as never,
    close: async () => {},
    async transaction<T>(fn: (client: TypedQueryClient) => Promise<T>): Promise<T> {
      return fn(tx);
    },
  } as unknown as PoolQueryClient;
  return { client, lockKeys };
}

describe("AccountsRepo advisory lock keys", () => {
  test("create takes the tool lock before the name lock", async () => {
    const fixture = lockRecordingClient(null);
    await new AccountsRepo(fixture.client).create({ tool: "claude", name: "alpha" });
    expect(fixture.lockKeys).toEqual([toolLockKey("claude"), accountNameLockKey("alpha")]);
  });

  test("rename takes both name locks in sorted order whichever way round it is called", async () => {
    // Two opposing renames over the same pair. If each followed its own
    // argument order these two sequences would be reverses of each other,
    // which is the deadlock. Sorting collapses them onto one order.
    const forward = lockRecordingClient("alpha");
    await new AccountsRepo(forward.client).rename("claude", "alpha", "beta");
    const backward = lockRecordingClient("beta");
    await new AccountsRepo(backward.client).rename("codex", "beta", "alpha");

    const sorted = [accountNameLockKey("alpha"), accountNameLockKey("beta")];
    expect(forward.lockKeys).toEqual(sorted);
    expect(backward.lockKeys).toEqual(sorted);
  });

  test("rename to the same name takes that name lock once", async () => {
    const fixture = lockRecordingClient("alpha");
    await new AccountsRepo(fixture.client).rename("claude", "alpha", "alpha");
    expect(fixture.lockKeys).toEqual([accountNameLockKey("alpha")]);
  });

  test("rename takes name locks and NO tool lock, so the two lock kinds cannot cycle", async () => {
    // Deadlock freedom rests on rename never wanting a tool lock while holding
    // a name lock, since `create` takes them the other way round.
    //
    // The tool-lock half alone is not evidence: before this change `rename`
    // took no advisory lock of any kind, so asserting "no tool lock" passed
    // identically pre- and post-fix. The name-lock assertion is what makes this
    // test able to fail — it is empty on the old code — and the two together
    // state the actual invariant rather than half of it.
    const fixture = lockRecordingClient("alpha");
    await new AccountsRepo(fixture.client).rename("claude", "alpha", "beta");
    expect(fixture.lockKeys.filter((key) => key.startsWith("accounts:name:")).length).toBeGreaterThan(0);
    expect(fixture.lockKeys.filter((key) => key.startsWith("accounts:tool:"))).toEqual([]);
  });
});
