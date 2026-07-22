import { describe, expect, test } from "bun:test";
import type { PoolQueryClient, TypedQueryClient } from "../generated/storage-kit/index.js";
import {
  AccountsRepo,
  LOGIN_CLEANUP_MAX_PER_TARGET,
  loginCleanupRequestDigest,
} from "./repo.js";

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
  incarnation_id: "11111111-1111-4111-8111-111111111111",
  last_used_at: null,
};

function transactionalClient(failOnAccountWrite: boolean) {
  let transactions = 0;
  let rolledBack = false;
  let accountRow = OLD_ROW;
  let completedOperation: {
    operation_id: string;
    tool: string;
    name: string;
    state: "completed" | "cancelled";
    updated_at: string | null;
    revision: string | null;
    previous_name: string | null;
    target_incarnation_id: string | null;
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
      return params?.[1] === "old" ? accountRow : null;
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
          target_incarnation_id: sql.includes("target_incarnation_id")
            ? String(params?.[8])
            : null,
          previous_target_last_used_at: sql.includes("'cancelled'") ? null : (params?.[7] as string | null),
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
  return {
    client,
    replaceAccount(row: typeof OLD_ROW) {
      accountRow = row;
    },
    evidence: () => ({ transactions, rolledBack, statements }),
  };
}

describe("AccountsRepo account/current atomicity", () => {
  test("cleanup request digest is canonical and binds every conditional field", () => {
    const base = {
      cleanupOperationId: "33333333-3333-4333-8333-333333333333",
      cleanupRequestedAt: "2026-07-22T00:00:00.000Z",
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: "old@example.test",
      expectedDisplayName: "Old",
      expectedIdentity: "identity-old",
      expectedCardLast4: "4242",
      expectedMetadata: { z: true, a: "first" },
      expectedDir: "/profiles/old",
      expectedDescription: "old profile",
      expectedLastUsedAt: "2026-07-21T00:00:00.000Z",
    };
    const digest = loginCleanupRequestDigest("claude", "old", base);
    expect(loginCleanupRequestDigest("claude", "old", {
      ...base,
      expectedMetadata: { a: "first", z: true },
    })).toBe(digest);
    const variants = [
      ["tool", () => loginCleanupRequestDigest("codex", "old", base)],
      ["name", () => loginCleanupRequestDigest("claude", "new", base)],
      ["cleanupOperationId", () => loginCleanupRequestDigest("claude", "old", { ...base, cleanupOperationId: "44444444-4444-4444-8444-444444444444" })],
      ["cleanupRequestedAt", () => loginCleanupRequestDigest("claude", "old", { ...base, cleanupRequestedAt: "2026-07-22T00:00:01.000Z" })],
      ["expectedIncarnationId", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedIncarnationId: "55555555-5555-4555-8555-555555555555" })],
      ["expectedCreatedAt", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedCreatedAt: "2020-01-02T00:00:00.000Z" })],
      ["expectedEmail", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedEmail: null })],
      ["expectedDisplayName", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedDisplayName: null })],
      ["expectedIdentity", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedIdentity: null })],
      ["expectedCardLast4", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedCardLast4: null })],
      ["expectedMetadata", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedMetadata: { a: "changed", z: true } })],
      ["expectedDir", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedDir: null })],
      ["expectedDescription", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedDescription: null })],
      ["expectedLastUsedAt", () => loginCleanupRequestDigest("claude", "old", { ...base, expectedLastUsedAt: null })],
    ] as const;
    for (const [field, variant] of variants) {
      expect({ field, changed: variant() !== digest }).toEqual({ field, changed: true });
    }
  });

  test("login cleanup deletes only an unchanged created account that is not currently selected", async () => {
    const statements: string[] = [];
    const tx = {
      async get(sql: string) {
        statements.push(sql);
        if (/incomplete_count/.test(sql)) {
          return { incomplete_count: "0", terminal_count: "0" };
        }
        if (/account_login_cleanup_operations/.test(sql)) return null;
        if (/FROM current_selections/.test(sql)) return null;
        return OLD_ROW;
      },
      async execute(sql: string) {
        statements.push(sql);
      },
      async query(sql: string) {
        statements.push(sql);
        return { rows: [OLD_ROW], rowCount: 1 };
      },
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        return fn(tx);
      },
    } as unknown as PoolQueryClient;
    const removed = await (new AccountsRepo(client) as any).removeCreated("claude", "old", {
      cleanupOperationId: "11111111-1111-4111-8111-111111111111",
      cleanupRequestedAt: new Date().toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: OLD_ROW.description,
      expectedLastUsedAt: OLD_ROW.last_used_at,
    });

    expect(removed).toMatchObject({ removed: true, currentExists: false, expired: false });
    expect(statements.some((sql) => /FROM accounts[\s\S]*FOR UPDATE/.test(sql))).toBe(true);
    expect(statements.some((sql) => /FROM current_selections[\s\S]*FOR UPDATE/.test(sql))).toBe(true);
    const deletion = statements.find((sql) => /DELETE FROM accounts/.test(sql)) ?? "";
    expect(deletion).toContain("incarnation_id");
    expect(deletion).toContain("IS NOT DISTINCT FROM");
    expect(statements.some((sql) => /requested_at < now\(\)/.test(sql))).toBe(true);
    expect(statements.some((sql) => /incomplete_count/.test(sql))).toBe(true);
    expect(statements.some((sql) => /OFFSET \$4/.test(sql))).toBe(true);
  });

  test("login cleanup response-loss replay returns the durable result after an authoritative row check", async () => {
    const statements: string[] = [];
    const cleanupOperationId = "11111111-1111-4111-8111-111111111111";
    const input = {
      cleanupOperationId,
      cleanupRequestedAt: new Date().toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: OLD_ROW.description,
      expectedLastUsedAt: OLD_ROW.last_used_at,
    };
    const tx = {
      async get(sql: string) {
        statements.push(sql);
        if (/account_login_cleanup_operations/.test(sql)) {
          return {
            tool: "claude",
            name: "old",
            target_incarnation_id: OLD_ROW.incarnation_id,
            request_digest: loginCleanupRequestDigest("claude", "old", input),
            removed: true,
            completed_at: new Date().toISOString(),
          };
        }
        if (/FROM accounts/.test(sql)) return null;
        throw new Error("unexpected replay read");
      },
      async execute(sql: string) {
        statements.push(sql);
      },
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        return fn(tx);
      },
    } as unknown as PoolQueryClient;

    const removed = await new AccountsRepo(client).removeCreated("claude", "old", input);

    expect(removed).toMatchObject({ removed: true, expired: false });
    expect(statements.some((sql) => /FROM accounts[\s\S]*FOR UPDATE/.test(sql))).toBe(true);
    expect(statements.some((sql) => /DELETE FROM accounts/.test(sql))).toBe(false);
  });

  test("login cleanup replay rejects reuse with any changed conditional field", async () => {
    const tx = {
      async get(sql: string) {
        if (/account_login_cleanup_operations/.test(sql)) {
          return {
            tool: "claude",
            name: "old",
            target_incarnation_id: OLD_ROW.incarnation_id,
            request_digest: "a".repeat(64),
            removed: true,
            completed_at: new Date().toISOString(),
          };
        }
        throw new Error("digest-mismatched replay must not read the account");
      },
      async execute() {},
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        return fn(tx);
      },
    } as unknown as PoolQueryClient;

    await expect(new AccountsRepo(client).removeCreated("claude", "old", {
      cleanupOperationId: "11111111-1111-4111-8111-111111111111",
      cleanupRequestedAt: new Date().toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: "changed-on-replay",
      expectedLastUsedAt: OLD_ROW.last_used_at,
    } as never)).rejects.toThrow(/conditional request/);
  });

  test("expired cleanup replay prunes the journal and never re-executes account deletion", async () => {
    const statements: string[] = [];
    const tx = {
      async get(sql: string) {
        statements.push(sql);
        throw new Error("expired cleanup must not read an account or replay row");
      },
      async execute(sql: string) {
        statements.push(sql);
      },
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        return fn(tx);
      },
    } as unknown as PoolQueryClient;

    const result = await new AccountsRepo(client).removeCreated("claude", "old", {
      cleanupOperationId: "22222222-2222-4222-8222-222222222222",
      cleanupRequestedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1_000).toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: OLD_ROW.description,
      expectedLastUsedAt: OLD_ROW.last_used_at,
    });

    expect(result).toEqual({ removed: false, currentExists: false, expired: true });
    expect(statements.some((sql) => /DELETE FROM account_login_cleanup_operations/.test(sql))).toBe(true);
    expect(statements.some((sql) => /DELETE FROM accounts/.test(sql))).toBe(false);
    expect(statements.some((sql) => /INSERT INTO account_login_cleanup_operations/.test(sql))).toBe(false);
  });

  test("more than 64 terminal cleanup operations do not block a new login cleanup", async () => {
    const statements: string[] = [];
    let transactions = 0;
    const tx = {
      async get(sql: string) {
        statements.push(sql);
        if (/incomplete_count/.test(sql)) {
          return {
            incomplete_count: "0",
            terminal_count: String(LOGIN_CLEANUP_MAX_PER_TARGET + 1),
          };
        }
        if (/account_login_cleanup_operations/.test(sql)) return null;
        if (/FROM current_selections/.test(sql)) return null;
        if (/FROM accounts/.test(sql)) return OLD_ROW;
        throw new Error("unexpected cleanup read");
      },
      async execute(sql: string) {
        statements.push(sql);
      },
      async query(sql: string) {
        statements.push(sql);
        return { rows: [OLD_ROW], rowCount: 1 };
      },
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        transactions += 1;
        return fn(tx);
      },
    } as unknown as PoolQueryClient;

    const result = await new AccountsRepo(client).removeCreated("claude", "old", {
      cleanupOperationId: "66666666-6666-4666-8666-666666666666",
      cleanupRequestedAt: new Date().toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: OLD_ROW.description,
      expectedLastUsedAt: OLD_ROW.last_used_at,
    });

    expect(result).toEqual({ removed: true, currentExists: false, expired: false });
    expect(transactions).toBe(1);
    expect(statements.some((sql) => /pg_advisory_xact_lock/.test(sql))).toBe(true);
    expect(statements.some((sql) => /DELETE FROM accounts/.test(sql))).toBe(true);
    expect(statements.some((sql) => /INSERT INTO account_login_cleanup_operations/.test(sql))).toBe(true);
    expect(statements.some((sql) => /completed_at IS NOT NULL[\s\S]*OFFSET \$4/.test(sql))).toBe(true);
  });

  test("incomplete cleanup saturation fails closed without deleting active idempotency state", async () => {
    const statements: string[] = [];
    const tx = {
      async get(sql: string) {
        statements.push(sql);
        if (/incomplete_count/.test(sql)) {
          return {
            incomplete_count: String(LOGIN_CLEANUP_MAX_PER_TARGET),
            terminal_count: "0",
          };
        }
        if (/account_login_cleanup_operations/.test(sql)) return null;
        throw new Error("incomplete saturation must fail before reading the account");
      },
      async execute(sql: string) {
        statements.push(sql);
      },
    };
    const client = {
      pool: {} as never,
      close: async () => {},
      async transaction<T>(fn: (client: any) => Promise<T>): Promise<T> {
        return fn(tx);
      },
    } as unknown as PoolQueryClient;

    const cleanup = new AccountsRepo(client).removeCreated("claude", "old", {
      cleanupOperationId: "77777777-7777-4777-8777-777777777777",
      cleanupRequestedAt: new Date().toISOString(),
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedCreatedAt: new Date(OLD_ROW.created_at).toISOString(),
      expectedEmail: OLD_ROW.email,
      expectedDisplayName: OLD_ROW.display_name,
      expectedIdentity: OLD_ROW.identity,
      expectedCardLast4: OLD_ROW.card_last4,
      expectedMetadata: OLD_ROW.metadata,
      expectedDir: OLD_ROW.dir,
      expectedDescription: OLD_ROW.description,
      expectedLastUsedAt: OLD_ROW.last_used_at,
    });

    await expect(cleanup).rejects.toThrow(/too many incomplete operations/);
    expect(statements.some((sql) => /DELETE FROM accounts/.test(sql))).toBe(false);
    expect(statements.some((sql) => /INSERT INTO account_login_cleanup_operations/.test(sql))).toBe(false);
    const journalDeletes = statements.filter(
      (sql) => /DELETE FROM account_login_cleanup_operations/.test(sql),
    );
    expect(journalDeletes.length).toBeGreaterThanOrEqual(2);
    expect(journalDeletes.every((sql) => /completed_at IS NOT NULL/.test(sql))).toBe(true);
  });

  test("login email redetection is a no-op after a concurrent same-incarnation edit", async () => {
    const concurrent = { ...OLD_ROW, email: "concurrent@example.test" };
    const statements: string[] = [];
    const client = {
      pool: {} as never,
      close: async () => {},
      async get(sql: string) {
        statements.push(sql);
        return sql.startsWith("UPDATE accounts") ? null : concurrent;
      },
    } as unknown as PoolQueryClient;

    const updated = await new AccountsRepo(client).updateForLogin("claude", "old", {
      expectedIncarnationId: OLD_ROW.incarnation_id,
      expectedEmail: OLD_ROW.email,
      email: "detected@example.test",
    } as never);

    expect(updated.email).toBe("concurrent@example.test");
    expect(statements[0]).toContain("email IS NOT DISTINCT FROM");
  });

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
      expectedIncarnationId: OLD_ROW.incarnation_id,
      email: { expected: "failed@example.com", restore: null },
      lastUsedAt: { expected: "2026-07-21T00:00:00.000Z", restore: null },
    });
    expect(restored.name).toBe("old");
    expect(statements[0]).toContain("IS NOT DISTINCT FROM");
    expect(statements[0]).toContain("incarnation_id");
    expect(statements[0]).not.toContain("description =");
  });

  test("restoreProfile is a no-op for a replacement account incarnation", async () => {
    const replacement = {
      ...OLD_ROW,
      email: "fixture@example.test",
      incarnation_id: "22222222-2222-4222-8222-222222222222",
    };
    const statements: string[] = [];
    const client = {
      pool: {} as never,
      close: async () => {},
      async get(sql: string) {
        statements.push(sql);
        return sql.startsWith("UPDATE accounts") ? null : replacement;
      },
    } as unknown as PoolQueryClient;

    const restored = await new AccountsRepo(client).restoreProfile("claude", "old", {
      expectedIncarnationId: OLD_ROW.incarnation_id,
      email: { expected: "fixture@example.test", restore: null },
    });

    expect(restored.email).toBe("fixture@example.test");
    expect(restored.incarnationId).toBe(replacement.incarnation_id);
    expect(statements[0]).toContain("incarnation_id =");
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
    expect((await repo.setCurrentForLogin(
      "claude",
      "old",
      operationId,
      OLD_ROW.incarnation_id,
    )).operationId).toBe(operationId);
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

  test("completed login operation remains bound to its original target incarnation", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    const operationId = "22222222-2222-4222-8222-222222222222";
    await repo.setCurrentForLogin("claude", "old", operationId, OLD_ROW.incarnation_id);
    fixture.replaceAccount({
      ...OLD_ROW,
      incarnation_id: "22222222-2222-4222-8222-222222222222",
    });

    await expect(
      repo.setCurrentForLogin(
        "claude",
        "old",
        operationId,
        "22222222-2222-4222-8222-222222222222",
      ),
    ).rejects.toThrow(/operation id is already bound to another profile incarnation/);
  });

  test("rollback before activation durably cancels the operation", async () => {
    const fixture = transactionalClient(false);
    const repo = new AccountsRepo(fixture.client);
    const operationId = "33333333-3333-4333-8333-333333333333";

    expect(await repo.restoreCurrentOperation("claude", "old", operationId)).toBe(true);
    expect(fixture.evidence().statements.some((sql) =>
      /INSERT INTO current_login_operations[\s\S]*cancelled/.test(sql),
    )).toBe(true);
    await expect(repo.setCurrentForLogin(
      "claude",
      "old",
      operationId,
      OLD_ROW.incarnation_id,
    )).rejects.toThrow(/cancelled/);
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
