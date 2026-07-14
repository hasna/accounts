import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { Pool } from "pg";
import { mintApiKey, verifyApiKey } from "@hasna/contracts/auth";
import {
  createQueryClient,
  MigrationLedger,
  type PoolQueryClient,
} from "../generated/storage-kit/index.js";
import {
  accountsMigrations,
  assertMigrationStatusCompatible,
  readMigrationStatus,
} from "./migrations.js";
import { AccountsRepo } from "./repo.js";
import { createHandler, type ServiceContext } from "./app.js";
import { grantAccountsRuntimeRole } from "./runtime-role.js";

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
  const signingSecret = "postgres-integration-signing-secret";
  const suffix = randomBytes(6).toString("hex");
  const schema = "accounts_it_" + suffix;
  const migrationOwnerRole = "accounts_owner_" + suffix;
  const runtimeRole = "accounts_app_" + suffix;
  const migrationOwnerPassword = randomBytes(24).toString("hex");
  const runtimePassword = randomBytes(24).toString("hex");
  let adminPool: Pool;
  let client: PoolQueryClient;
  let appClient: PoolQueryClient;

  function roleConnectionString(role: string, password: string): string {
    const url = new URL(DATABASE_URL!);
    url.username = role;
    url.password = password;
    return url.toString();
  }

  function openRoleClient(
    role: string,
    password: string,
    applicationName: string,
  ): PoolQueryClient {
    const pool = new Pool({
      connectionString: roleConnectionString(role, password),
      options: "-c search_path=" + schema,
      application_name: applicationName,
      max: 2,
    });
    return createQueryClient(pool);
  }

  function openClient(applicationName = "accounts-postgres-integration"): PoolQueryClient {
    return openRoleClient(migrationOwnerRole, migrationOwnerPassword, applicationName);
  }

  function openAppClient(applicationName = "accounts-app-integration"): PoolQueryClient {
    return openRoleClient(runtimeRole, runtimePassword, applicationName);
  }

  async function waitForAdvisoryWait(applicationName: string): Promise<void> {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const waiting = await adminPool.query<{ waiting: boolean }>(
        `SELECT EXISTS (
           SELECT 1
           FROM pg_stat_activity
           WHERE datname = current_database()
             AND application_name = $1
             AND wait_event = 'advisory'
         ) AS waiting`,
        [applicationName],
      );
      if (waiting.rows[0]?.waiting) return;
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    throw new Error(`timed out waiting for advisory lock: ${applicationName}`);
  }

  async function runOrderedToolRace<T, U>(
    tool: string,
    firstName: string,
    first: () => Promise<T>,
    secondName: string,
    second: () => Promise<U>,
  ): Promise<[PromiseSettledResult<T>, PromiseSettledResult<U>]> {
    const blocker = openClient(`blocker-${tool}`);
    let releaseLock!: () => void;
    let signalLocked!: () => void;
    const locked = new Promise<void>((resolve) => {
      signalLocked = resolve;
    });
    const released = new Promise<void>((resolve) => {
      releaseLock = resolve;
    });
    const held = blocker.transaction(async (tx) => {
      await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [`accounts:tool:${tool}`],
      );
      signalLocked();
      await released;
    });

    try {
      await locked;
      const firstPromise = first();
      await waitForAdvisoryWait(firstName);
      const secondPromise = second();
      await waitForAdvisoryWait(secondName);
      releaseLock();
      await held;
      return await Promise.allSettled([firstPromise, secondPromise]);
    } finally {
      releaseLock();
      await held.catch(() => {});
      await blocker.close();
    }
  }

  function createLiveHandler(repo: AccountsRepo): (request: Request) => Promise<Response> {
    const context: ServiceContext = {
      repo,
      verifier: verifyApiKey({ app: "accounts", signingSecret }),
      health: async () => ({ ok: true }),
      ready: async () => ({ ready: true }),
      mode: "cloud",
      version: "postgres-integration",
      close: async () => {},
    };
    return createHandler(context);
  }

  function oldClientCreateRequest(tool: string, name: string): Request {
    const token = mintApiKey({
      app: "accounts",
      scopes: ["accounts:write"],
      signingSecret,
    }).token;
    return new Request("http://localhost/v1/accounts", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": token,
      },
      body: JSON.stringify({ tool, name }),
    });
  }

  beforeAll(async () => {
    adminPool = new Pool({ connectionString: DATABASE_URL, max: 1 });
    await adminPool.query(
      `CREATE ROLE "${migrationOwnerRole}" LOGIN PASSWORD '${migrationOwnerPassword}' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`,
    );
    await adminPool.query(
      `CREATE ROLE "${runtimeRole}" LOGIN PASSWORD '${runtimePassword}' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`,
    );
    await adminPool.query(`CREATE SCHEMA "${schema}" AUTHORIZATION "${migrationOwnerRole}"`);
    client = openClient();
  });

  afterAll(async () => {
    await appClient?.close();
    await client?.close();
    await adminPool?.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await adminPool?.query(`DROP ROLE IF EXISTS "${runtimeRole}"`);
    await adminPool?.query(`DROP ROLE IF EXISTS "${migrationOwnerRole}"`);
    await adminPool?.end();
  });

  test("migrations 0003/0004/0005 upgrade existing data and are restart-idempotent", async () => {
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

    await client.execute(
      "INSERT INTO accounts (tool, name) VALUES ($1, $2)",
      ["migration-probe", "valid"],
    );
    await client.execute(
      "INSERT INTO current_selections (tool, name) VALUES ($1, $2), ($3, $4)",
      ["migration-probe", "valid", "migration-orphan", "missing"],
    );

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
    expect(
      await client.get<{ table_name: string | null }>(
        "SELECT to_regclass('custom_tool_tombstones')::text AS table_name",
      ),
    ).toEqual({ table_name: "custom_tool_tombstones" });
    expect(
      await client.many<{ tool: string; name: string }>(
        "SELECT tool, name FROM current_selections WHERE tool LIKE 'migration-%' ORDER BY tool",
      ),
    ).toEqual([{ tool: "migration-probe", name: "valid" }]);
    expect(
      await client.many<{ tool: string; name: string; reason: string }>(
        "SELECT tool, name, reason FROM current_selection_orphan_archive ORDER BY tool",
      ),
    ).toEqual([
      {
        tool: "migration-orphan",
        name: "missing",
        reason: "missing account during migration 0004",
      },
    ]);

    await client.close();
    client = openClient();
    const restarted = await new MigrationLedger(client, appMigrations).migrate();
    expect(restarted.plan.every((item) => item.state === "already_applied")).toBe(true);
    expect((await readMigrationStatus(client, appMigrations)).pending).toEqual([]);
    expect(
      await client.get<{ count: number }>(
        "SELECT count(*)::int AS count FROM current_selection_orphan_archive",
      ),
    ).toEqual({ count: 1 });

    const tombstoneMigration = appMigrations.find(
      (migration) => migration.id === "accounts_0005_custom_tool_tombstones",
    );
    expect(tombstoneMigration).toBeDefined();
    await client.execute(tombstoneMigration!.sql);
    const fullMigration = await new MigrationLedger(client, accountsMigrations()).migrate();
    expect(
      fullMigration.plan
        .filter((item) => !item.migration.id.startsWith("accounts_"))
        .every((item) => item.state === "pending"),
    ).toBe(true);
    const runtimeGrant = await grantAccountsRuntimeRole(client, runtimeRole);
    expect(runtimeGrant).toEqual({
      owner: migrationOwnerRole,
      role: runtimeRole,
      schema,
    });
    expect(await grantAccountsRuntimeRole(client, runtimeRole)).toEqual(runtimeGrant);
    appClient = openAppClient();
    expect(
      await client.get<{ table_name: string | null }>(
        "SELECT to_regclass('custom_tool_tombstones')::text AS table_name",
      ),
    ).toEqual({ table_name: "custom_tool_tombstones" });
  });

  test("migration owner grants a DML-only runtime role that supports normal server flows", async () => {
    const role = await appClient.one<{
      current_user: string;
      schema_usage: boolean;
      schema_create: boolean;
      account_dml: boolean;
      tombstone_select: boolean;
      tombstone_insert: boolean;
      tombstone_delete: boolean;
      tombstone_update: boolean;
      ledger_select: boolean;
      api_key_select: boolean;
    }>(
      `SELECT current_user,
              has_schema_privilege(current_user, current_schema(), 'USAGE') AS schema_usage,
              has_schema_privilege(current_user, current_schema(), 'CREATE') AS schema_create,
              has_table_privilege(current_user, 'accounts', 'SELECT,INSERT,UPDATE,DELETE') AS account_dml,
              has_table_privilege(current_user, 'custom_tool_tombstones', 'SELECT') AS tombstone_select,
              has_table_privilege(current_user, 'custom_tool_tombstones', 'INSERT') AS tombstone_insert,
              has_table_privilege(current_user, 'custom_tool_tombstones', 'DELETE') AS tombstone_delete,
              has_table_privilege(current_user, 'custom_tool_tombstones', 'UPDATE') AS tombstone_update,
              has_table_privilege(current_user, 'schema_migrations', 'SELECT') AS ledger_select,
              has_table_privilege(current_user, 'api_keys', 'SELECT') AS api_key_select`,
    );
    expect(role).toEqual({
      current_user: runtimeRole,
      schema_usage: true,
      schema_create: false,
      account_dml: true,
      tombstone_select: true,
      tombstone_insert: true,
      tombstone_delete: true,
      tombstone_update: false,
      ledger_select: true,
      api_key_select: true,
    });
    expect(
      await client.one<{
        schema_usage: boolean;
        schema_create: boolean;
        account_select: boolean;
        tombstone_select: boolean;
      }>(
        `SELECT has_schema_privilege('public', $1, 'USAGE') AS schema_usage,
                has_schema_privilege('public', $1, 'CREATE') AS schema_create,
                has_table_privilege('public', $2, 'SELECT') AS account_select,
                has_table_privilege('public', $3, 'SELECT') AS tombstone_select`,
        [schema, `${schema}.accounts`, `${schema}.custom_tool_tombstones`],
      ),
    ).toEqual({
      schema_usage: false,
      schema_create: false,
      account_select: false,
      tombstone_select: false,
    });
    await expect(appClient.execute("CREATE TABLE forbidden_runtime_ddl (id int)")).rejects.toThrow(
      /permission denied for schema/,
    );

    const functions = await client.many<{
      proname: string;
      owner: string;
      security_definer: boolean;
      config: string[];
      public_execute: boolean;
      runtime_execute: boolean;
    }>(
      `SELECT p.proname,
              pg_get_userbyid(p.proowner) AS owner,
              p.prosecdef AS security_definer,
              p.proconfig AS config,
              has_function_privilege('public', p.oid, 'EXECUTE') AS public_execute,
              has_function_privilege($1, p.oid, 'EXECUTE') AS runtime_execute
         FROM pg_catalog.pg_proc AS p
         JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname = $2
          AND p.proname = ANY($3::text[])
        ORDER BY p.proname`,
      [
        runtimeRole,
        schema,
        [
          "accounts_guard_removed_custom_tool",
          "custom_tool_registration_reactivate",
          "custom_tool_registration_tombstone",
          "custom_tool_tombstone_guard",
        ],
      ],
    );
    expect(functions).toHaveLength(4);
    for (const fn of functions) {
      expect(fn.owner).toBe(migrationOwnerRole);
      expect(fn.security_definer).toBe(false);
      expect(fn.config).toEqual([`search_path=pg_catalog, ${schema}`]);
      expect(fn.public_execute).toBe(false);
      expect(fn.runtime_execute).toBe(false);
    }

    expect((await readMigrationStatus(appClient)).pending).toEqual([]);
    const repo = new AccountsRepo(appClient);
    await repo.addCustomTool({
      id: "runtime-role-tool",
      label: "Runtime Role Tool",
      envVar: "RUNTIME_ROLE_HOME",
      defaultDir: "/tmp/runtime-role",
      bin: "runtime-role",
    });
    await repo.create({ tool: "runtime-role-tool", name: "profile" });
    await repo.setCurrent("runtime-role-tool", "profile");
    expect((await repo.getCurrent("runtime-role-tool"))?.name).toBe("profile");
    expect(await repo.remove("runtime-role-tool", "profile")).toBe(true);
    expect(await repo.removeCustomTool("runtime-role-tool")).toBe(true);
    expect(
      await appClient.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        ["runtime-role-tool"],
      ),
    ).toEqual({ id: "runtime-role-tool" });
  });

  test("legacy migrator is downgrade-guarded; app rollback keeps the new migrator", async () => {
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
    const customToolsIndex = appMigrations.findIndex(
      (migration) => migration.id === "accounts_0003_custom_tools",
    );
    const authMigrations = accountsMigrations().filter(
      (migration) => !migration.id.startsWith("accounts_"),
    );
    const legacyMigrations = [...appMigrations.slice(0, customToolsIndex), ...authMigrations];
    const legacyStatus = await readMigrationStatus(client, legacyMigrations);
    expect(legacyStatus.pending).toEqual([]);
    expect(legacyStatus.unknown).toEqual([
      "accounts_0003_custom_tools",
      "accounts_0004_current_selection_account_fk",
      "accounts_0005_custom_tool_tombstones",
    ]);
    expect(() => assertMigrationStatusCompatible(legacyStatus)).toThrow(
      /not recognized by this build \(downgrade\?\)/,
    );
    await expect(
      new MigrationLedger(client, legacyMigrations).migrate({ dryRun: true }),
    ).rejects.toThrow(/not recognized by this build \(downgrade\?\)/);

    const forward = await new MigrationLedger(client, accountsMigrations()).migrate();
    expect(forward.plan.every((item) => item.state === "already_applied")).toBe(true);
    expect((await readMigrationStatus(client, accountsMigrations())).pending).toEqual([]);

    await client.execute(
      `INSERT INTO custom_tools (id, definition)
       VALUES ($1, $2::jsonb)`,
      [
        "rollback-custom",
        JSON.stringify({
          id: "rollback-custom",
          label: "Rollback Custom",
          envVar: "ROLLBACK_CUSTOM_HOME",
          defaultDir: "/tmp/rollback-custom",
          bin: "rollback-custom",
        }),
      ],
    );
    await client.execute("DELETE FROM custom_tools WHERE id = $1", ["rollback-custom"]);
    expect(
      await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        ["rollback-custom"],
      ),
    ).toEqual({ id: "rollback-custom" });
    await expect(
      client.execute(
        "INSERT INTO accounts (tool, name) VALUES ($1, $2)",
        ["rollback-custom", "old-server-create"],
      ),
    ).rejects.toThrow('custom tool "rollback-custom" was explicitly removed');
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

      await firstRepo.addCustomTool({
        id: "race",
        label: "Race",
        envVar: "RACE_HOME",
        defaultDir: "/tmp/race",
        bin: "race",
      });
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

      await firstRepo.addCustomTool({
        id: "remove-race",
        label: "Remove Race",
        envVar: "REMOVE_RACE_HOME",
        defaultDir: "/tmp/remove-race",
        bin: "remove-race",
      });
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

  test("unseen legacy custom tool IDs remain valid for old-client account creation", async () => {
    const repo = new AccountsRepo(client);
    const response = await createLiveHandler(repo)(
      oldClientCreateRequest("legacy-unseen", "profile"),
    );
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      tool: "legacy-unseen",
      name: "profile",
    });
    expect(
      await client.get<{ id: string }>(
        "SELECT id FROM custom_tools WHERE id = $1",
        ["legacy-unseen"],
      ),
    ).toBeNull();
    expect(
      await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        ["legacy-unseen"],
      ),
    ).toBeNull();
  });

  test("explicit removal durably rejects later account creation", async () => {
    const repo = new AccountsRepo(client);
    expect(await repo.removeCustomTool("legacy-removed")).toBe(false);
    expect(
      await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        ["legacy-removed"],
      ),
    ).toEqual({ id: "legacy-removed" });
    const response = await createLiveHandler(repo)(
      oldClientCreateRequest("legacy-removed", "profile"),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'custom tool "legacy-removed" was explicitly removed',
    });
    expect(await repo.get("legacy-removed", "profile")).toBeNull();

    await repo.addCustomTool({
      id: "legacy-removed",
      label: "Legacy Reactivated",
      envVar: "LEGACY_REACTIVATED_HOME",
      defaultDir: "/tmp/legacy-reactivated",
      bin: "legacy-reactivated",
    });
    expect(
      await client.get<{ id: string }>(
        "SELECT id FROM custom_tool_tombstones WHERE id = $1",
        ["legacy-removed"],
      ),
    ).toBeNull();
    const reactivated = await createLiveHandler(repo)(
      oldClientCreateRequest("legacy-removed", "reactivated"),
    );
    expect(reactivated.status).toBe(201);
  });

  test("custom-tool removal and account creation serialize in both orderings", async () => {
    const createFirstClient = openClient("race-create-first");
    const removeSecondClient = openClient("race-remove-second");
    const removeFirstClient = openClient("race-remove-first");
    const createSecondClient = openClient("race-create-second");
    try {
      const createFirstRepo = new AccountsRepo(createFirstClient);
      const removeSecondRepo = new AccountsRepo(removeSecondClient);
      const [created, removeAfterCreate] = await runOrderedToolRace(
        "legacy-create-first",
        "race-create-first",
        () => createFirstRepo.create({ tool: "legacy-create-first", name: "profile" }),
        "race-remove-second",
        () => removeSecondRepo.removeCustomTool("legacy-create-first"),
      );
      expect(created.status).toBe("fulfilled");
      expect(removeAfterCreate.status).toBe("rejected");
      expect(String(removeAfterCreate.status === "rejected" ? removeAfterCreate.reason : "")).toContain(
        "still used by profile(s) profile",
      );
      expect((await createFirstRepo.get("legacy-create-first", "profile"))?.name).toBe("profile");
      expect(
        await client.get("SELECT id FROM custom_tool_tombstones WHERE id = $1", ["legacy-create-first"]),
      ).toBeNull();

      const seedRepo = new AccountsRepo(client);
      await seedRepo.addCustomTool({
        id: "legacy-remove-first",
        label: "Legacy Remove First",
        envVar: "LEGACY_REMOVE_FIRST_HOME",
        defaultDir: "/tmp/legacy-remove-first",
        bin: "legacy-remove-first",
      });
      const removeFirstRepo = new AccountsRepo(removeFirstClient);
      const createSecondRepo = new AccountsRepo(createSecondClient);
      const [removed, createAfterRemove] = await runOrderedToolRace(
        "legacy-remove-first",
        "race-remove-first",
        () => removeFirstRepo.removeCustomTool("legacy-remove-first"),
        "race-create-second",
        () => createSecondRepo.create({ tool: "legacy-remove-first", name: "profile" }),
      );
      expect(removed).toEqual({ status: "fulfilled", value: true });
      expect(createAfterRemove.status).toBe("rejected");
      expect(String(createAfterRemove.status === "rejected" ? createAfterRemove.reason : "")).toContain(
        'custom tool "legacy-remove-first" was explicitly removed',
      );
      expect(await createSecondRepo.get("legacy-remove-first", "profile")).toBeNull();
      expect(
        await client.get<{ id: string }>(
          "SELECT id FROM custom_tool_tombstones WHERE id = $1",
          ["legacy-remove-first"],
        ),
      ).toEqual({ id: "legacy-remove-first" });
    } finally {
      await Promise.all([
        createFirstClient.close(),
        removeSecondClient.close(),
        removeFirstClient.close(),
        createSecondClient.close(),
      ]);
    }
  });

  test("raw old-server account inserts and tool deletes serialize under the app role", async () => {
    const createFirstClient = openAppClient("raw-create-first");
    const deleteSecondClient = openAppClient("raw-delete-second");
    const deleteFirstClient = openAppClient("raw-delete-first");
    const createSecondClient = openAppClient("raw-create-second");
    try {
      await appClient.execute(
        "INSERT INTO custom_tools (id, definition) VALUES ($1, $2::jsonb)",
        [
          "raw-create-first-tool",
          JSON.stringify({
            id: "raw-create-first-tool",
            label: "Raw Create First",
            envVar: "RAW_CREATE_FIRST_HOME",
            defaultDir: "/tmp/raw-create-first",
            bin: "raw-create-first",
          }),
        ],
      );
      const [created, deletedAfterCreate] = await runOrderedToolRace(
        "raw-create-first-tool",
        "raw-create-first",
        () =>
          createFirstClient.execute(
            "INSERT INTO accounts (tool, name) VALUES ($1, $2)",
            ["raw-create-first-tool", "profile"],
          ),
        "raw-delete-second",
        () =>
          deleteSecondClient.execute("DELETE FROM custom_tools WHERE id = $1", [
            "raw-create-first-tool",
          ]),
      );
      expect(created.status).toBe("fulfilled");
      expect(deletedAfterCreate.status).toBe("rejected");
      expect(
        String(deletedAfterCreate.status === "rejected" ? deletedAfterCreate.reason : ""),
      ).toContain('cannot remove "raw-create-first-tool": accounts still use this tool');
      expect(
        await appClient.get("SELECT tool FROM accounts WHERE tool = $1 AND name = $2", [
          "raw-create-first-tool",
          "profile",
        ]),
      ).toEqual({ tool: "raw-create-first-tool" });
      expect(
        await appClient.get("SELECT id FROM custom_tools WHERE id = $1", [
          "raw-create-first-tool",
        ]),
      ).toEqual({ id: "raw-create-first-tool" });
      expect(
        await appClient.get("SELECT id FROM custom_tool_tombstones WHERE id = $1", [
          "raw-create-first-tool",
        ]),
      ).toBeNull();

      await appClient.execute(
        "INSERT INTO custom_tools (id, definition) VALUES ($1, $2::jsonb)",
        [
          "raw-delete-first-tool",
          JSON.stringify({
            id: "raw-delete-first-tool",
            label: "Raw Delete First",
            envVar: "RAW_DELETE_FIRST_HOME",
            defaultDir: "/tmp/raw-delete-first",
            bin: "raw-delete-first",
          }),
        ],
      );
      const [deleted, createdAfterDelete] = await runOrderedToolRace(
        "raw-delete-first-tool",
        "raw-delete-first",
        () =>
          deleteFirstClient.execute("DELETE FROM custom_tools WHERE id = $1", [
            "raw-delete-first-tool",
          ]),
        "raw-create-second",
        () =>
          createSecondClient.execute(
            "INSERT INTO accounts (tool, name) VALUES ($1, $2)",
            ["raw-delete-first-tool", "profile"],
          ),
      );
      expect(deleted.status).toBe("fulfilled");
      expect(createdAfterDelete.status).toBe("rejected");
      expect(
        String(createdAfterDelete.status === "rejected" ? createdAfterDelete.reason : ""),
      ).toContain('custom tool "raw-delete-first-tool" was explicitly removed');
      expect(
        await appClient.get("SELECT tool FROM accounts WHERE tool = $1 AND name = $2", [
          "raw-delete-first-tool",
          "profile",
        ]),
      ).toBeNull();
      expect(
        await appClient.get("SELECT id FROM custom_tools WHERE id = $1", [
          "raw-delete-first-tool",
        ]),
      ).toBeNull();
      expect(
        await appClient.get("SELECT id FROM custom_tool_tombstones WHERE id = $1", [
          "raw-delete-first-tool",
        ]),
      ).toEqual({ id: "raw-delete-first-tool" });
    } finally {
      await Promise.all([
        createFirstClient.close(),
        deleteSecondClient.close(),
        deleteFirstClient.close(),
        createSecondClient.close(),
      ]);
    }
  });
});
