import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { SQL } from "bun";
import { Pool } from "pg";

import type {
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import { PostgresCapsuleMaintenanceLedger } from "./postgres-capsule-maintenance.js";
import {
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations.js";
import { runPostgresMigrations } from "./postgres-migrator.js";
import {
  installPostgresRuntimeContext,
  type PostgresRuntimeRoleBoundary,
} from "./postgres-runtime.js";
import type { PostgresSqlClient } from "./postgres-sql.js";

const DATABASE_URL = process.env.HASNA_ACCOUNTS_TEST_DATABASE_URL;

if (process.env.ACCOUNTS_REQUIRE_POSTGRES === "1" && !DATABASE_URL) {
  test("native-subscription PostgreSQL integration requires an explicit test database", () => {
    throw new Error(
      "Set HASNA_ACCOUNTS_TEST_DATABASE_URL to an isolated PostgreSQL database; no service was started automatically.",
    );
  });
}

const describePostgres = DATABASE_URL ? describe : describe.skip;

describePostgres("native-subscription PostgreSQL catalog and concurrency", () => {
  const suffix = randomBytes(6).toString("hex");
  const ownerRole = `accounts_native_owner_${suffix}`;
  const runtimeRole = `accounts_native_runtime_${suffix}`;
  const loginRole = `accounts_native_login_${suffix}`;
  const directRole = `accounts_native_direct_${suffix}`;
  const ownerPassword = randomBytes(24).toString("hex");
  const loginPassword = randomBytes(24).toString("hex");
  const directPassword = randomBytes(24).toString("hex");
  const roleBoundary: PostgresRuntimeRoleBoundary = {
    mode: "set-role",
    roleName: runtimeRole,
    loginRoleName: loginRole,
  };
  const ownerA = "principal:service:hasna:native-integration-a";
  const ownerB = "principal:service:hasna:native-integration-b";
  const grantId = "018f0f00-1001-7000-8000-000000000001";
  const digest = (character: string) => `sha256:${character.repeat(64)}`;

  let admin: Pool;
  let ownerSql: SQL;
  let loginSql: SQL;
  let directSql: SQL;

  function roleUrl(role: string, password: string): string {
    const url = new URL(DATABASE_URL!);
    url.username = role;
    url.password = password;
    return url.toString();
  }

  function grant(): CapsuleMaintenanceGrantReservation {
    return {
      grantId,
      ownerRef: ownerA,
      idempotencyKeyDigest: digest("0"),
      requestDigest: digest("1"),
      reservationKeyDigest: digest("2"),
      grantDigest: digest("3"),
      grantBytes: Uint8Array.from(Buffer.from('{"grant":"live-concurrency"}')),
      expiresAt: "2030-07-18T12:10:00.000Z",
    };
  }

  function use(): CapsuleMaintenanceUseCommit {
    return {
      grantId,
      ownerRef: ownerA,
      idempotencyKeyDigest: digest("4"),
      requestDigest: digest("5"),
      maintenanceUseId: digest("6"),
      consumeReceiptDigest: digest("7"),
      consumeReceiptBytes: Uint8Array.from(Buffer.from('{"receipt":"live-concurrency"}')),
      committedAt: "2030-07-18T12:01:00.000Z",
    };
  }

  beforeAll(async () => {
    admin = new Pool({ connectionString: DATABASE_URL, max: 2 });
    await admin.query(
      `CREATE ROLE "${ownerRole}" LOGIN PASSWORD '${ownerPassword}' ` +
        "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    );
    await admin.query(
      `CREATE ROLE "${runtimeRole}" NOLOGIN NOINHERIT NOSUPERUSER ` +
        "NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    );
    await admin.query(
      `CREATE ROLE "${loginRole}" LOGIN PASSWORD '${loginPassword}' ` +
        "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    );
    await admin.query(
      `CREATE ROLE "${directRole}" LOGIN PASSWORD '${directPassword}' ` +
        "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
    );
    await admin.query(`GRANT "${runtimeRole}" TO "${loginRole}"`);
    await admin.query(`CREATE SCHEMA accounts AUTHORIZATION "${ownerRole}"`);
    ownerSql = new SQL(roleUrl(ownerRole, ownerPassword), { max: 2 });
    loginSql = new SQL(roleUrl(loginRole, loginPassword), { max: 8 });
    directSql = new SQL(roleUrl(directRole, directPassword), { max: 2 });
  });

  afterAll(async () => {
    await loginSql?.close({ timeout: 1 });
    await directSql?.close({ timeout: 1 });
    await ownerSql?.close({ timeout: 1 });
    await admin?.query("DROP SCHEMA IF EXISTS accounts CASCADE");
    await admin?.query(`DROP ROLE IF EXISTS "${loginRole}"`);
    await admin?.query(`DROP ROLE IF EXISTS "${runtimeRole}"`);
    await admin?.query(`DROP ROLE IF EXISTS "${directRole}"`);
    await admin?.query(`DROP ROLE IF EXISTS "${ownerRole}"`);
    await admin?.end();
  });

  test("applies, reapplies, catalog-attests, and uses the configured SET ROLE boundary", async () => {
    const first = await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    );
    const replay = await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    );
    expect(first).toEqual({
      schemaVersion: String(POSTGRES_SCHEMA_VERSION),
      migrationChecksum: POSTGRES_MIGRATION_CHECKSUM,
      appliedVersions: ["1", "2", "3"],
      runtimeRole,
      runtimeRoleMode: "set-role",
    });
    expect(replay.appliedVersions).toEqual([]);

    const context = await loginSql.begin("read only", async (transaction) => {
      await installPostgresRuntimeContext(transaction, {
        principalRef: ownerA,
        role: roleBoundary,
      });
      const [row] = await transaction<Array<{
        current_user: string;
        session_user: string;
      }>>`SELECT current_user, session_user`;
      return row;
    });
    expect(context).toEqual({ current_user: runtimeRole, session_user: loginRole });
  });

  test("serializes concurrent reserve/consume races and re-reads exact replay bytes", async () => {
    const first = new PostgresCapsuleMaintenanceLedger(
      loginSql as unknown as PostgresSqlClient,
      ownerA,
      roleBoundary,
    );
    const second = new PostgresCapsuleMaintenanceLedger(
      loginSql as unknown as PostgresSqlClient,
      ownerA,
      roleBoundary,
    );
    const reservations = await Promise.all([first.reserve(grant()), second.reserve(grant())]);
    expect(reservations.map((result) => result.status).sort()).toEqual([
      "replayed",
      "reserved",
    ]);
    for (const result of reservations) {
      if (result.status === "reserved" || result.status === "replayed") {
        expect(result.grantBytes).toEqual(grant().grantBytes);
      }
    }

    const consumptions = await Promise.all([first.consume(use()), second.consume(use())]);
    expect(consumptions.map((result) => result.status).sort()).toEqual([
      "consumed",
      "replayed",
    ]);
    for (const result of consumptions) {
      if (result.status === "consumed" || result.status === "replayed") {
        expect(result.consumeReceiptBytes).toEqual(use().consumeReceiptBytes);
      }
    }
  });

  test("enforces forced RLS isolation and append-only evidence at runtime", async () => {
    const otherOwner = new PostgresCapsuleMaintenanceLedger(
      loginSql as unknown as PostgresSqlClient,
      ownerB,
      roleBoundary,
    );
    expect((await otherOwner.consume({ ...use(), ownerRef: ownerB })).status).toBe("not_found");

    await expect(loginSql.begin("read write", async (transaction) => {
      await installPostgresRuntimeContext(transaction, {
        principalRef: ownerA,
        role: roleBoundary,
      });
      await transaction`
        UPDATE accounts.capsule_maintenance_uses
        SET request_digest = ${digest("8")}
        WHERE owner_ref = ${ownerA} AND grant_id = ${grantId}::uuid
      `;
    })).rejects.toThrow(/permission denied for table capsule_maintenance_uses/);

    await expect(admin.query(
      `UPDATE accounts.capsule_maintenance_uses
       SET request_digest = $1
       WHERE owner_ref = $2 AND grant_id = $3::uuid`,
      [digest("8"), ownerA, grantId],
    )).rejects.toThrow(/append-only Accounts row cannot be changed/);
  });

  test("detects catalog drift and rejects a newer ledger while preserving forward repair", async () => {
    await ownerSql`ALTER TABLE accounts.capsule_maintenance_grants NO FORCE ROW LEVEL SECURITY`;
    await expect(runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    await ownerSql`ALTER TABLE accounts.capsule_maintenance_grants FORCE ROW LEVEL SECURITY`;
    expect((await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).appliedVersions).toEqual([]);

    await ownerSql`
      INSERT INTO accounts.schema_migrations(version, checksum)
      VALUES (999, ${digest("9")})
    `;
    await expect(runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_VERSION_UNSUPPORTED" });
    await ownerSql`DELETE FROM accounts.schema_migrations WHERE version = 999`;
    expect((await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).appliedVersions).toEqual([]);
  });

  test("rolls back package SQL when runtime-role attestation fails", async () => {
    await ownerSql`DROP SCHEMA accounts CASCADE`;
    await admin.query(`CREATE SCHEMA accounts AUTHORIZATION "${ownerRole}"`);
    await expect(runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      {
        runtimeRole: {
          mode: "direct",
          roleName: `missing_runtime_${suffix}`,
        },
      },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    const [row] = await ownerSql<Array<{ migration_table: string | null }>>`
      SELECT pg_catalog.to_regclass('accounts.schema_migrations')::text AS migration_table
    `;
    expect(row?.migration_table).toBeNull();
  });

  test("supports a separately provisioned direct LOGIN runtime boundary", async () => {
    const directBoundary = { mode: "direct", roleName: directRole } as const;
    const report = await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: directBoundary },
    );
    expect(report.runtimeRoleMode).toBe("direct");
    const context = await directSql.begin("read only", async (transaction) => {
      await installPostgresRuntimeContext(transaction, {
        principalRef: ownerB,
        role: directBoundary,
      });
      const [row] = await transaction<Array<{
        current_user: string;
        session_user: string;
      }>>`SELECT current_user, session_user`;
      return row;
    });
    expect(context).toEqual({ current_user: directRole, session_user: directRole });
  });
});
