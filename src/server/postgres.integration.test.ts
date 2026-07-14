import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { Pool } from "pg";
import {
  createQueryClient,
  MigrationLedger,
  type PoolQueryClient,
} from "../generated/storage-kit/index.js";
import { accountsMigrations, readMigrationStatus } from "./migrations.js";
import { AccountsRepo } from "./repo.js";

const DATABASE_URL = process.env.HASNA_ACCOUNTS_TEST_DATABASE_URL;

if (process.env.ACCOUNTS_REQUIRE_POSTGRES === "1" && !DATABASE_URL) {
  test("PostgreSQL integration requires an explicit test database", () => {
    throw new Error(
      "Set HASNA_ACCOUNTS_TEST_DATABASE_URL to an isolated PostgreSQL database; no service was started automatically.",
    );
  });
}

const describePostgres = DATABASE_URL ? describe : describe.skip;

describePostgres("PostgreSQL migration and repository integration", () => {
  const schema = "accounts_it_" + randomBytes(6).toString("hex");
  let adminPool: Pool;
  let client: PoolQueryClient;

  function openClient(): PoolQueryClient {
    const pool = new Pool({
      connectionString: DATABASE_URL,
      options: "-c search_path=" + schema,
      max: 2,
    });
    return createQueryClient(pool);
  }

  beforeAll(async () => {
    adminPool = new Pool({ connectionString: DATABASE_URL, max: 1 });
    await adminPool.query(`CREATE SCHEMA "${schema}"`);
    client = openClient();
  });

  afterAll(async () => {
    await client?.close();
    await adminPool?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await adminPool?.end();
  });

  test("migration 0003 upgrades an existing schema and is restart-idempotent", async () => {
    const appMigrations = accountsMigrations().filter((migration) =>
      migration.id.startsWith("accounts_"),
    );
    const beforeCustomTools = appMigrations.filter(
      (migration) => migration.id !== "accounts_0003_custom_tools",
    );

    await new MigrationLedger(client, beforeCustomTools).migrate();
    expect(
      await client.get<{ table_name: string | null }>(
        "SELECT to_regclass('custom_tools')::text AS table_name",
      ),
    ).toEqual({ table_name: null });

    const upgraded = await new MigrationLedger(client, appMigrations).migrate();
    expect(
      upgraded.plan.find((item) => item.migration.id === "accounts_0003_custom_tools")?.state,
    ).toBe("pending");
    expect(
      await client.get<{ table_name: string | null }>(
        "SELECT to_regclass('custom_tools')::text AS table_name",
      ),
    ).toEqual({ table_name: "custom_tools" });

    await client.close();
    client = openClient();
    const restarted = await new MigrationLedger(client, appMigrations).migrate();
    expect(restarted.plan.every((item) => item.state === "already_applied")).toBe(true);
    expect((await readMigrationStatus(client, appMigrations)).pending).toEqual([]);
  });

  test("rename and remove roll back account changes when current-selection updates fail", async () => {
    const repo = new AccountsRepo(client);
    await repo.create({ tool: "claude", name: "old" });
    await repo.setCurrent("claude", "old");
    await client.execute(`
      CREATE FUNCTION fail_current_selection_change() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'forced current selection failure';
      END;
      $$
    `);
    await client.execute(`
      CREATE TRIGGER fail_current_selection_change
      BEFORE UPDATE OR DELETE ON current_selections
      FOR EACH ROW EXECUTE FUNCTION fail_current_selection_change()
    `);

    await expect(repo.rename("claude", "old", "new")).rejects.toThrow(
      "forced current selection failure",
    );
    expect((await repo.get("claude", "old"))?.name).toBe("old");
    expect(await repo.get("claude", "new")).toBeNull();
    expect((await repo.getCurrent("claude"))?.name).toBe("old");

    await expect(repo.remove("claude", "old")).rejects.toThrow(
      "forced current selection failure",
    );
    expect((await repo.get("claude", "old"))?.name).toBe("old");
    expect((await repo.getCurrent("claude"))?.name).toBe("old");
  });
});
