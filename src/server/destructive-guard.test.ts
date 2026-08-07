import { describe, expect, test } from "bun:test";
import { accountsMigrations } from "./migrations.js";
import {
  assertArchivePrecedesPurge,
  preflightDestructiveMigrations,
  ARCHIVE_MIGRATION_ID,
  PURGE_MIGRATION_ID,
  LEAKED_FIXTURE_TOOL_IDS,
  DESTRUCTIVE_ACK_ENV,
  DESTRUCTIVE_ACK_VALUE,
} from "./destructive-guard.js";
import type { Migration, TypedQueryClient } from "../generated/storage-kit/index.js";

function migration(id: string): Migration {
  return { id, sql: `-- ${id}`, checksum: `sha256:${id}` } as Migration;
}

/**
 * Minimal client stub. `to_regclass` probes answer "table present"; count
 * queries answer from the supplied per-table map. Enough to drive both sides of
 * the envelope check without a database.
 */
function stubClient(counts: Record<string, number>, missing: string[] = []): TypedQueryClient {
  const answer = (sql: string, params?: readonly unknown[]) => {
    if (sql.includes("to_regclass")) {
      const table = String((params ?? [])[0]);
      return { present: !missing.includes(table) };
    }
    const match = sql.match(/FROM (\w+) WHERE/);
    const table = match?.[1] ?? "";
    return { matched: counts[table] ?? 0 };
  };
  const client = {
    async get<T>(sql: string, params?: readonly unknown[]) {
      return answer(sql, params) as T;
    },
    async many() {
      return [];
    },
    async one<T>(sql: string, params?: readonly unknown[]) {
      return answer(sql, params) as T;
    },
    async query() {
      return { rows: [], rowCount: 0 };
    },
    async execute() {},
  };
  return client as unknown as TypedQueryClient;
}

describe("destructive-migration gate, ARM 1 (snapshot ordering)", () => {
  test("the shipped migration list puts the archive before the purge", () => {
    const migrations = accountsMigrations();
    const ids = migrations.map((m) => m.id);
    expect(ids).toContain(ARCHIVE_MIGRATION_ID);
    expect(ids).toContain(PURGE_MIGRATION_ID);
    expect(ids.indexOf(ARCHIVE_MIGRATION_ID)).toBeLessThan(ids.indexOf(PURGE_MIGRATION_ID));
    expect(() => assertArchivePrecedesPurge(migrations)).not.toThrow();
  });

  test("REFUSES a build where the purge ships without its archive", () => {
    expect(() => assertArchivePrecedesPurge([migration(PURGE_MIGRATION_ID)])).toThrow(
      /snapshot migration .* is missing/,
    );
  });

  test("REFUSES a build where the archive is ordered after the purge", () => {
    expect(() =>
      assertArchivePrecedesPurge([migration(PURGE_MIGRATION_ID), migration(ARCHIVE_MIGRATION_ID)]),
    ).toThrow(/must be ordered BEFORE/);
  });

  test("stays silent when the purge is not in the build at all", () => {
    expect(() => assertArchivePrecedesPurge([migration("accounts_0001_accounts")])).not.toThrow();
  });

  test("the archive SQL captures all three affected tables, cascade included", () => {
    const archive = accountsMigrations().find((m) => m.id === ARCHIVE_MIGRATION_ID)!;
    for (const table of ["accounts", "current_selections", "custom_tools"]) {
      expect(archive.sql).toContain(`FROM ${table} AS archived`);
    }
    for (const id of LEAKED_FIXTURE_TOOL_IDS) {
      expect(archive.sql).toContain(`'${id}'`);
    }
  });
});

describe("destructive-migration gate, ARM 2 (pre-flight refusal)", () => {
  const pending = [PURGE_MIGRATION_ID];

  test("PROCEEDS on the expected envelope: zero accounts, at most the four tools", async () => {
    const report = await preflightDestructiveMigrations(
      stubClient({ accounts: 0, current_selections: 0, custom_tools: 4 }),
      { pending },
      [],
      {},
    );
    expect(report.withinEnvelope).toBe(true);
    expect(report.counts.find((c) => c.table === "custom_tools")?.matched).toBe(4);
  });

  test("REFUSES when a real account row would be destroyed", async () => {
    await expect(
      preflightDestructiveMigrations(
        stubClient({ accounts: 1, current_selections: 0, custom_tools: 4 }),
        { pending },
        [],
        {},
      ),
    ).rejects.toThrow(/REFUSING TO DEPLOY/);
  });

  test("REFUSES on a cascaded current_selections row, which no DELETE names", async () => {
    await expect(
      preflightDestructiveMigrations(
        stubClient({ accounts: 0, current_selections: 1, custom_tools: 4 }),
        { pending },
        [],
        {},
      ),
    ).rejects.toThrow(/current_selections/);
  });

  test("the refusal names the restore command and the acknowledgement", async () => {
    const error = await preflightDestructiveMigrations(
      stubClient({ accounts: 2, current_selections: 0, custom_tools: 4 }),
      { pending },
      [],
      {},
    ).catch((err: Error) => err);
    expect((error as Error).message).toContain("accounts-migrate --restore-purge-archive");
    expect((error as Error).message).toContain(DESTRUCTIVE_ACK_ENV);
  });

  test("an explicit acknowledgement converts the refusal into a proceed", async () => {
    const report = await preflightDestructiveMigrations(
      stubClient({ accounts: 5, current_selections: 0, custom_tools: 4 }),
      { pending },
      [],
      { [DESTRUCTIVE_ACK_ENV]: DESTRUCTIVE_ACK_VALUE },
    );
    expect(report.withinEnvelope).toBe(false);
    expect(report.acknowledged).toBe(true);
  });

  test("a fresh database with no tables yet is the safe state, not a refusal", async () => {
    const report = await preflightDestructiveMigrations(
      stubClient({}, ["accounts", "current_selections", "custom_tools"]),
      { pending },
      [],
      {},
    );
    expect(report.withinEnvelope).toBe(true);
    expect(report.counts.every((c) => c.tablePresent === false)).toBe(true);
  });

  test("does nothing when the purge is already applied", async () => {
    const report = await preflightDestructiveMigrations(
      stubClient({ accounts: 999, current_selections: 999, custom_tools: 999 }),
      { pending: [] },
      [],
      {},
    );
    expect(report.purgePending).toBe(false);
    expect(report.counts).toEqual([]);
  });
});

describe("destructive-migration gate, stale-snapshot window", () => {
  /**
   * The archive normally runs immediately before the purge in one ledger pass.
   * If the purge then fails, a re-run finds the archive already applied and the
   * ledger will not re-run it — so rows created in between would be deleted with
   * nothing preserved. The pre-flight re-executes the archive SQL in exactly
   * that state, and only in that state.
   */
  function recordingClient(counts: Record<string, number>): {
    client: TypedQueryClient;
    executed: string[];
  } {
    const executed: string[] = [];
    const client = {
      async get<T>(sql: string, params?: readonly unknown[]) {
        if (sql.includes("to_regclass")) return { present: true } as T;
        const table = sql.match(/FROM (\w+) WHERE/)?.[1] ?? "";
        return { matched: counts[table] ?? 0 } as T;
      },
      async many() {
        return [];
      },
      async one<T>() {
        return {} as T;
      },
      async query() {
        return { rows: [], rowCount: 0 };
      },
      async execute(sql: string) {
        executed.push(sql);
      },
    };
    return { client: client as unknown as TypedQueryClient, executed };
  }

  const archive = { id: ARCHIVE_MIGRATION_ID, sql: "-- archive sql", checksum: "sha256:a" } as Migration;
  const safe = { accounts: 0, current_selections: 0, custom_tools: 4 };

  test("REFRESHES the snapshot when the archive is applied but the purge is still pending", async () => {
    const { client, executed } = recordingClient(safe);
    const report = await preflightDestructiveMigrations(
      client,
      { pending: [PURGE_MIGRATION_ID], ledgerPresent: true },
      [archive],
      {},
    );
    expect(report.snapshotRefreshed).toBe(true);
    expect(executed).toContain("-- archive sql");
  });

  test("does NOT re-execute the archive when it is itself still pending", async () => {
    const { client, executed } = recordingClient(safe);
    const report = await preflightDestructiveMigrations(
      client,
      { pending: [ARCHIVE_MIGRATION_ID, PURGE_MIGRATION_ID], ledgerPresent: true },
      [archive],
      {},
    );
    expect(report.snapshotRefreshed).toBe(false);
    expect(executed).toEqual([]);
  });

  test("does NOT re-execute the archive on a fresh database with no ledger", async () => {
    const { client, executed } = recordingClient(safe);
    const report = await preflightDestructiveMigrations(
      client,
      { pending: [PURGE_MIGRATION_ID], ledgerPresent: false },
      [archive],
      {},
    );
    expect(report.snapshotRefreshed).toBe(false);
    expect(executed).toEqual([]);
  });
});
