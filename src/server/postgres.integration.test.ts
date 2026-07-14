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
    const customToolsIndex = appMigrations.findIndex(
      (migration) => migration.id === "accounts_0003_custom_tools",
    );
    const beforeCustomTools = appMigrations.slice(0, customToolsIndex);

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
    expect(
      await client.get<{ present: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM pg_constraint
           WHERE conname = 'current_selections_account_fk'
             AND conrelid = 'current_selections'::regclass
         ) AS present`,
      ),
    ).toEqual({ present: true });

    await client.close();
    client = openClient();
    const restarted = await new MigrationLedger(client, appMigrations).migrate();
    expect(restarted.plan.every((item) => item.state === "already_applied")).toBe(true);
    expect((await readMigrationStatus(client, appMigrations)).pending).toEqual([]);
  });

  test("rollback leaves additive 0003 in place and forward-fix remains idempotent", async () => {
    await client.execute(
      "INSERT INTO accounts (tool, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      ["rollback-probe", "old-server"],
    );
    expect(
      await client.get<{ table_name: string | null }>(
        "SELECT to_regclass('custom_tools')::text AS table_name",
      ),
    ).toEqual({ table_name: "custom_tools" });
    const appMigrations = accountsMigrations().filter((migration) => migration.id.startsWith("accounts_"));
    const forward = await new MigrationLedger(client, appMigrations).migrate();
    expect(forward.plan.every((item) => item.state === "already_applied")).toBe(true);
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

    try {
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
    } finally {
      await client.execute("DROP TRIGGER IF EXISTS fail_current_selection_change ON current_selections");
      await client.execute("DROP FUNCTION IF EXISTS fail_current_selection_change()");
    }
  });

  test("foreign key rejects orphan current selections", async () => {
    await expect(
      client.execute(
        "INSERT INTO current_selections (tool, name) VALUES ($1, $2)",
        ["missing-tool", "missing-profile"],
      ),
    ).rejects.toThrow(/foreign key constraint/);
  });

  test("setCurrent serializes with concurrent rename and remove", async () => {
    const second = openClient();
    try {
      const firstRepo = new AccountsRepo(client);
      const secondRepo = new AccountsRepo(second);

      for (let attempt = 0; attempt < 5; attempt += 1) {
        const oldName = `rename-old-${attempt}`;
        const newName = `rename-new-${attempt}`;
        await firstRepo.create({ tool: "race", name: oldName });
        await firstRepo.setCurrent("race", oldName);
        const [setResult, renameResult] = await Promise.allSettled([
          firstRepo.setCurrent("race", oldName),
          secondRepo.rename("race", oldName, newName),
        ]);
        expect(renameResult.status).toBe("fulfilled");
        if (setResult.status === "rejected") {
          expect(String(setResult.reason)).toContain(`no profile named "${oldName}"`);
        }
        expect((await firstRepo.getCurrent("race"))?.name).toBe(newName);
        expect(await firstRepo.get("race", oldName)).toBeNull();
        expect((await firstRepo.get("race", newName))?.name).toBe(newName);
      }

      for (let attempt = 0; attempt < 5; attempt += 1) {
        const name = `remove-${attempt}`;
        await firstRepo.create({ tool: "remove-race", name });
        await firstRepo.setCurrent("remove-race", name);
        const [setResult, removeResult] = await Promise.allSettled([
          firstRepo.setCurrent("remove-race", name),
          secondRepo.remove("remove-race", name),
        ]);
        expect(removeResult).toEqual({ status: "fulfilled", value: true });
        if (setResult.status === "rejected") {
          expect(String(setResult.reason)).toContain(`no profile named "${name}"`);
        }
        expect(await firstRepo.getCurrent("remove-race")).toBeNull();
        expect(await firstRepo.get("remove-race", name)).toBeNull();
      }
    } finally {
      await second.close();
    }
  });
});
