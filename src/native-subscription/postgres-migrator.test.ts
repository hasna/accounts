import { describe, expect, test } from "bun:test";
import type { SQL, TransactionSQL } from "bun";

import { AccountsError } from "./errors";
import { POSTGRES_MIGRATION_CHECKSUM } from "./postgres-migrations";
import { runPostgresMigrations } from "./postgres-migrator";

interface FakeMigrationState {
  tableExists: boolean;
  rows: Array<{ version: string; checksum: string }>;
  appliedSql: string[];
}

function fakeClient(state: FakeMigrationState): SQL {
  const transaction = (async (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<unknown[]> => {
    const query = strings.join("?").replace(/\s+/g, " ").trim();
    if (query.includes("pg_advisory_xact_lock")) return [];
    if (query.includes("to_regclass('accounts.schema_migrations')")) {
      return [{ migration_table: state.tableExists ? "accounts.schema_migrations" : null }];
    }
    if (query.includes("SELECT version::text AS version, checksum")) {
      return [...state.rows].sort((left, right) => Number(left.version) - Number(right.version));
    }
    if (query.includes("INSERT INTO accounts.schema_migrations")) {
      state.tableExists = true;
      state.rows.push({ version: String(values[0]), checksum: String(values[1]) });
      return [];
    }
    throw new Error("unexpected fake query");
  }) as unknown as TransactionSQL;
  transaction.unsafe = ((sql: string) => ({
    simple: async () => {
      state.appliedSql.push(sql);
      state.tableExists = true;
      return [];
    },
  })) as TransactionSQL["unsafe"];

  return {
    begin: async (_mode: string, callback: (value: TransactionSQL) => Promise<unknown>) =>
      callback(transaction),
  } as unknown as SQL;
}

describe("Postgres migration runner", () => {
  test("applies a fresh migration once and then verifies without reapplying", async () => {
    const state: FakeMigrationState = { tableExists: false, rows: [], appliedSql: [] };
    const client = fakeClient(state);

    const first = await runPostgresMigrations(client);
    const second = await runPostgresMigrations(client);

    expect(first.appliedVersions).toEqual(["1", "2", "3"]);
    expect(second.appliedVersions).toEqual([]);
    expect(first.migrationChecksum).toBe(POSTGRES_MIGRATION_CHECKSUM);
    expect(state.appliedSql).toHaveLength(3);
  });

  test("rejects a checksum mismatch without applying SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{ version: "1", checksum: `sha256:${"0".repeat(64)}` }],
      appliedSql: [],
    };

    await expect(runPostgresMigrations(fakeClient(state))).rejects.toMatchObject({
      code: "SCHEMA_CHECKSUM_MISMATCH",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });

  test("rejects a newer schema before applying package SQL", async () => {
    const state: FakeMigrationState = {
      tableExists: true,
      rows: [{ version: "4", checksum: `sha256:${"1".repeat(64)}` }],
      appliedSql: [],
    };

    await expect(runPostgresMigrations(fakeClient(state))).rejects.toMatchObject({
      code: "SCHEMA_VERSION_UNSUPPORTED",
    } satisfies Partial<AccountsError>);
    expect(state.appliedSql).toEqual([]);
  });
});
