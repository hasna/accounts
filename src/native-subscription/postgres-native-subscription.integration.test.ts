import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { SQL } from "bun";
import { Pool } from "pg";

import type {
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import {
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
  maintenanceTargetDigest,
} from "./capsule-maintenance.js";
import { canonicalJson, canonicalSha256 } from "./json.js";
import { PostgresCapsuleMaintenanceLedger } from "./postgres-capsule-maintenance.js";
import {
  POSTGRES_MIGRATIONS,
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations.js";
import { runPostgresMigrations } from "./postgres-migrator.js";
import { POSTGRES_SCHEMA_MANIFEST } from "./postgres-schema-manifest.js";
import {
  installPostgresRuntimeContext,
  type PostgresRuntimeRoleBoundary,
} from "./postgres-runtime.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

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
  const maintenanceOperationId = "018f0f00-1002-7000-8000-000000000002";
  const providerAccountId = "018f0f00-1003-7000-8000-000000000003";
  const accountLaneId = "018f0f00-1004-7000-8000-000000000004";
  const capacityPoolId = "018f0f00-1005-7000-8000-000000000005";
  const authCapsuleId = "018f0f00-1006-7000-8000-000000000006";
  const canonicalNodeId = "018f0f00-1007-7000-8000-000000000007";
  const consumeReceiptId = "018f0f00-1008-7000-8000-000000000008";
  const signature = Buffer.alloc(64, 9).toString("base64url");
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

  function grantEvidence(): Record<string, string> {
    return {
      schema_version: CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
      schema_digest: CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
      grant_id: grantId,
      issuer: "accounts-maintenance",
      issuer_incarnation: "accounts-maintenance-1",
      key_id: "accounts-maintenance-key-1",
      audience: "infinity",
      effect_namespace_id: "accounts-native-subscription",
      maintenance_authority_epoch: "1",
      maintenance_operation_id: maintenanceOperationId,
      operation_digest: digest("0"),
      operation_execution_epoch: "1",
      operation_execution_expires_at: "2030-07-18T12:20:00.000Z",
      execution_fence_digest: digest("1"),
      action: "PROBE_NATIVE",
      effect_class: "read_only",
      target_kind: "native_capsule",
      subject: ownerA,
      actor_principal: ownerA,
      maintenance_executor_principal: ownerA,
      sender_key_thumbprint: digest("2"),
      channel_binding_digest: digest("3"),
      owner_ref: ownerA,
      provider_account_id: providerAccountId,
      provider_subject_ref: "provider-subject",
      account_lane_id: accountLaneId,
      capacity_pool_id: capacityPoolId,
      capacity_domain_ref: "capacity-domain",
      serialization_key_digest: digest("4"),
      access_transport: "native_session",
      credential_family_id: "credential-family",
      capacity_generation: "1",
      deny_generation: "0",
      expected_record_revision: "1",
      expected_credential_generation: "1",
      maintenance_decision_digest: digest("5"),
      canonical_request_digest: digest("6"),
      approval_mode: "NOT_REQUIRED",
      policy_digest: digest("7"),
      catalog_incarnation: "catalog-1",
      recovery_frontier_sequence: "1",
      recovery_frontier_hash: digest("8"),
      issued_at: "2030-07-18T12:00:00.000Z",
      not_before: "2030-07-18T12:00:00.000Z",
      expires_at: "2030-07-18T12:10:00.000Z",
      nonce: "nonce-1",
      max_uses: "1",
      signature,
      auth_capsule_id: authCapsuleId,
      canonical_node_id: canonicalNodeId,
      node_key_thumbprint: digest("9"),
      node_generation: "1",
      placement_generation: "1",
      expected_auth_generation: "1",
      expected_auth_state_revision: "1",
    };
  }

  function grant(): CapsuleMaintenanceGrantReservation {
    const evidence = grantEvidence();
    return {
      grantId,
      ownerRef: ownerA,
      idempotencyKeyDigest: digest("0"),
      requestDigest: digest("1"),
      reservationKeyDigest: canonicalSha256({
        effect_namespace_id: evidence.effect_namespace_id,
        execution_fence_digest: evidence.execution_fence_digest,
        expected_credential_generation: evidence.expected_credential_generation,
        expected_record_revision: evidence.expected_record_revision,
        schema_version: "accounts.capsule-maintenance-reservation-key.v1",
        serialization_key_digest: evidence.serialization_key_digest,
        target_digest: maintenanceTargetDigest(evidence),
      }),
      grantDigest: canonicalSha256(evidence),
      grantBytes: Uint8Array.from(Buffer.from(canonicalJson(evidence), "utf8")),
      expiresAt: "2030-07-18T12:10:00.000Z",
    };
  }

  function consumeEvidence(): Record<string, string> {
    return {
      schema_version: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
      schema_digest: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
      consume_receipt_id: consumeReceiptId,
      grant_id: grantId,
      grant_digest: grant().grantDigest,
      issuer: "accounts-maintenance",
      issuer_incarnation: "accounts-maintenance-1",
      key_id: "accounts-maintenance-key-1",
      audience: "infinity",
      effect_namespace_id: "accounts-native-subscription",
      maintenance_authority_epoch: "1",
      maintenance_operation_id: maintenanceOperationId,
      operation_digest: digest("0"),
      operation_step_id: "probe_native",
      operation_execution_epoch: "1",
      operation_execution_expires_at: "2030-07-18T12:20:00.000Z",
      action: "PROBE_NATIVE",
      target_digest: digest("1"),
      subject: ownerA,
      actor_principal: ownerA,
      maintenance_executor_principal: ownerA,
      sender_key_thumbprint: digest("2"),
      channel_binding_digest: digest("3"),
      execution_fence_digest: digest("4"),
      max_uses: "1",
      prior_use_count: "0",
      next_use_count: "1",
      use_ordinal: "1",
      maintenance_use_id: digest("6"),
      committed_at: "2030-07-18T12:01:00.000Z",
      expires_at: "2030-07-18T12:02:00.000Z",
      catalog_incarnation: "catalog-1",
      recovery_frontier_sequence: "1",
      recovery_frontier_hash: digest("5"),
      signature,
    };
  }

  function use(): CapsuleMaintenanceUseCommit {
    const evidence = consumeEvidence();
    return {
      grantId,
      ownerRef: ownerA,
      idempotencyKeyDigest: digest("4"),
      requestDigest: digest("5"),
      maintenanceUseId: digest("6"),
      consumeReceiptDigest: canonicalSha256(evidence),
      consumeReceiptBytes: Uint8Array.from(
        Buffer.from(canonicalJson(evidence), "utf8"),
      ),
      committedAt: "2030-07-18T12:01:00.000Z",
    };
  }

  function identifier(value: string): string {
    return `"${value.replaceAll('"', '""')}"`;
  }

  async function resetAccountsSchema(): Promise<void> {
    await admin.query("DROP SCHEMA IF EXISTS accounts CASCADE");
    await admin.query(
      `CREATE SCHEMA accounts AUTHORIZATION ${identifier(ownerRole)}`,
    );
  }

  async function createMigrationLedger(
    rows: readonly {
      readonly version: number;
      readonly checksum: string;
      readonly appliedAt?: string;
    }[],
  ): Promise<void> {
    await ownerSql`
      CREATE TABLE accounts.schema_migrations (
        version BIGINT PRIMARY KEY CHECK (version > 0),
        checksum TEXT NOT NULL CHECK (checksum ~ '^sha256:[0-9a-f]{64}$'),
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
      )
    `;
    for (const row of rows) {
      if (row.appliedAt === undefined) {
        await ownerSql`
          INSERT INTO accounts.schema_migrations(version, checksum)
          VALUES (${row.version}, ${row.checksum})
        `;
      } else {
        await ownerSql`
          INSERT INTO accounts.schema_migrations(version, checksum, applied_at)
          VALUES (${row.version}, ${row.checksum}, ${row.appliedAt}::timestamptz)
        `;
      }
    }
  }

  function observeMigrationSql(): {
    readonly client: PostgresSqlClient;
    readonly appliedSql: string[];
  } {
    const appliedSql: string[] = [];
    return {
      client: {
        begin: async (options, callback) =>
          ownerSql.begin(options, async (transaction) => {
            const tracked = Object.assign(
              (
                strings: TemplateStringsArray,
                ...values: unknown[]
              ) => transaction(strings, ...values),
              {
                unsafe: (statement: string) => {
                  appliedSql.push(statement);
                  return transaction.unsafe(statement);
                },
              },
            ) as unknown as PostgresTransaction;
            return callback(tracked);
          }),
      },
      appliedSql,
    };
  }

  async function expectSchemaDrift(
    mutations: readonly string[],
    restorations: readonly string[],
  ): Promise<void> {
    for (const mutation of mutations) await ownerSql.unsafe(mutation).simple();
    try {
      await expect(runPostgresMigrations(
        ownerSql as unknown as PostgresSqlClient,
        { runtimeRole: roleBoundary },
      )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    } finally {
      for (const restoration of restorations) {
        await ownerSql.unsafe(restoration).simple();
      }
    }
    expect((await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).appliedVersions).toEqual([]);
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

  test("preflights invalid ledgers before SQL and applies a valid prefix", async () => {
    await ownerSql`CREATE TABLE accounts.residual_marker (id BIGINT PRIMARY KEY)`;
    let observed = observeMigrationSql();
    await expect(runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    expect(observed.appliedSql).toEqual([]);

    await resetAccountsSchema();
    await createMigrationLedger([]);
    observed = observeMigrationSql();
    await expect(runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    expect(observed.appliedSql).toEqual([]);

    await resetAccountsSchema();
    await createMigrationLedger([
      POSTGRES_MIGRATIONS[0],
      POSTGRES_MIGRATIONS[2],
    ]);
    observed = observeMigrationSql();
    await expect(runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    expect(observed.appliedSql).toEqual([]);

    await resetAccountsSchema();
    await createMigrationLedger([
      POSTGRES_MIGRATIONS[1],
      POSTGRES_MIGRATIONS[0],
    ]);
    observed = observeMigrationSql();
    await expect(runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    expect(observed.appliedSql).toEqual([]);

    await resetAccountsSchema();
    const appliedAt = "2030-07-18T12:00:00.000Z";
    await createMigrationLedger([
      { ...POSTGRES_MIGRATIONS[1], appliedAt },
      { ...POSTGRES_MIGRATIONS[0], appliedAt },
    ]);
    observed = observeMigrationSql();
    await expect(runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    expect(observed.appliedSql).toEqual([]);

    await resetAccountsSchema();
    await ownerSql.unsafe(POSTGRES_MIGRATIONS[0].sql).simple();
    await ownerSql`
      INSERT INTO accounts.schema_migrations(version, checksum)
      VALUES (${POSTGRES_MIGRATIONS[0].version}, ${POSTGRES_MIGRATIONS[0].checksum})
    `;
    observed = observeMigrationSql();
    const prefixReport = await runPostgresMigrations(
      observed.client,
      { runtimeRole: roleBoundary },
    );
    expect(prefixReport.appliedVersions).toEqual(["2", "3", "4"]);
    expect(observed.appliedSql).not.toContain(POSTGRES_MIGRATIONS[0].sql);
    expect(observed.appliedSql).toContain(POSTGRES_MIGRATIONS[1].sql);
    expect(observed.appliedSql).toContain(POSTGRES_MIGRATIONS[2].sql);
    expect(observed.appliedSql).toContain(POSTGRES_MIGRATIONS[3].sql);

    await resetAccountsSchema();
  });

  test("serializes concurrent clean migration, replays the sequenced ledger, and uses SET ROLE", async () => {
    const reports = await Promise.all([
      runPostgresMigrations(
        ownerSql as unknown as PostgresSqlClient,
        { runtimeRole: roleBoundary },
      ),
      runPostgresMigrations(
        ownerSql as unknown as PostgresSqlClient,
        { runtimeRole: roleBoundary },
      ),
    ]);
    expect(reports.map((report) => report.appliedVersions.length).sort()).toEqual([
      0,
      POSTGRES_MIGRATIONS.length,
    ]);
    const first = reports.find((report) => report.appliedVersions.length > 0)!;
    const replay = reports.find((report) => report.appliedVersions.length === 0)!;
    expect(first).toEqual({
      schemaVersion: String(POSTGRES_SCHEMA_VERSION),
      migrationChecksum: POSTGRES_MIGRATION_CHECKSUM,
      appliedVersions: ["1", "2", "3", "4"],
      runtimeRole,
      runtimeRoleMode: "set-role",
    });
    expect(replay.appliedVersions).toEqual([]);
    expect(await ownerSql<Array<{
      version: string;
      ledger_sequence: string;
    }>>`
      SELECT
        version::text AS version,
        ledger_sequence::text AS ledger_sequence
      FROM accounts.schema_migrations
      ORDER BY ledger_sequence
    `).toEqual([
      { version: "1", ledger_sequence: "1" },
      { version: "2", ledger_sequence: "2" },
      { version: "3", ledger_sequence: "3" },
      { version: "4", ledger_sequence: "4" },
    ]);

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

  test("rejects malformed DTOs and evidence without persisting a live reservation or use", async () => {
    const ledger = new PostgresCapsuleMaintenanceLedger(
      loginSql as unknown as PostgresSqlClient,
      ownerA,
      roleBoundary,
    );
    const [{ live_before: liveBefore, uses_before: usesBefore }] = await ownerSql<
      Array<{ live_before: string; uses_before: string }>
    >`
      SELECT
        (
          SELECT count(*)::text
          FROM accounts.capsule_maintenance_grants
          WHERE owner_ref = ${ownerA} AND state = 'live'
        ) AS live_before,
        (
          SELECT count(*)::text
          FROM accounts.capsule_maintenance_uses
          WHERE owner_ref = ${ownerA}
        ) AS uses_before
    `;
    const malformedIds = [
      "018f0f00-1101-7000-8000-000000000001",
      "018f0f00-1102-7000-8000-000000000002",
      "018f0f00-1103-7000-8000-000000000003",
      "018f0f00-1104-7000-8000-000000000004",
      "018f0f00-1105-7000-8000-000000000005",
      "018f0f00-1106-7000-8000-000000000006",
      "018f0f00-1107-7000-8000-000000000007",
      "018f0f00-1108-7000-8000-000000000008",
      "018f0f00-1109-7000-8000-000000000009",
    ] as const;
    const reservation = (
      id: string,
      mutate: (evidence: Record<string, string>) => void,
      canonical = true,
    ): CapsuleMaintenanceGrantReservation => {
      const evidence = { ...grantEvidence(), grant_id: id };
      mutate(evidence);
      const encoded = canonicalJson(evidence);
      return {
        ...grant(),
        grantId: id,
        idempotencyKeyDigest: digest("a"),
        reservationKeyDigest: digest("b"),
        grantDigest: canonicalSha256(evidence),
        grantBytes: Uint8Array.from(
          Buffer.from(canonical ? encoded : ` ${encoded}`, "utf8"),
        ),
        expiresAt: String(evidence.expires_at),
      };
    };
    const malformedReservations = [
      {
        ...reservation(malformedIds[0], () => {}),
        unexpected: "closed-dto-violation",
      },
      {
        ...reservation(malformedIds[1], () => {}),
        expiresAt: "infinity",
      },
      reservation(malformedIds[2], (evidence) => {
        evidence.schema_version = "accounts.capsule-maintenance/v2";
      }),
      reservation(malformedIds[3], (evidence) => {
        evidence.unexpected = "closed-envelope-violation";
      }),
      reservation(malformedIds[4], (evidence) => {
        evidence.grant_id = grantId;
      }),
      reservation(malformedIds[5], () => {}, false),
      {
        ...reservation(malformedIds[6], () => {}),
        expiresAt: Number.POSITIVE_INFINITY,
      },
      {
        ...reservation(malformedIds[7], () => {}),
        expiresAt: "2030-07-18 12:00:00+00",
      },
      {
        ...reservation(malformedIds[8], () => {}),
        grantBytes: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      },
    ] as unknown as CapsuleMaintenanceGrantReservation[];
    for (const malformed of malformedReservations) {
      expect(() => ledger.reserve(malformed)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
    }

    const receipt = consumeEvidence();
    const unsupportedReceipt = {
      ...receipt,
      schema_version: "accounts.capsule-maintenance-consume-receipt.v2",
    };
    const malformedCommits = [
      { ...use(), unexpected: "closed-dto-violation" },
      { ...use(), committedAt: "infinity" },
      { ...use(), committedAt: Number.POSITIVE_INFINITY },
      { ...use(), committedAt: "2030-07-18 12:00:00+00" },
      {
        ...use(),
        consumeReceiptBytes: Uint8Array.from(
          Buffer.from(canonicalJson(unsupportedReceipt), "utf8"),
        ),
        consumeReceiptDigest: canonicalSha256(unsupportedReceipt),
      },
      {
        ...use(),
        consumeReceiptBytes: Uint8Array.from(
          Buffer.from(` ${canonicalJson(receipt)}`, "utf8"),
        ),
      },
      {
        ...use(),
        consumeReceiptBytes: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]),
      },
    ] as unknown as CapsuleMaintenanceUseCommit[];
    for (const malformed of malformedCommits) {
      expect(() => ledger.consume(malformed)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
    }

    const [{ live_after: liveAfter, uses_after: usesAfter }] = await ownerSql<
      Array<{ live_after: string; uses_after: string }>
    >`
      SELECT
        (
          SELECT count(*)::text
          FROM accounts.capsule_maintenance_grants
          WHERE owner_ref = ${ownerA} AND state = 'live'
        ) AS live_after,
        (
          SELECT count(*)::text
          FROM accounts.capsule_maintenance_uses
          WHERE owner_ref = ${ownerA}
        ) AS uses_after
    `;
    expect(liveAfter).toBe(liveBefore);
    expect(usesAfter).toBe(usesBefore);
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
    await ownerSql`ALTER TABLE accounts.schema_migrations
      DISABLE TRIGGER schema_migrations_immutable`;
    try {
      await ownerSql`DELETE FROM accounts.schema_migrations WHERE version = 999`;
    } finally {
      await ownerSql`ALTER TABLE accounts.schema_migrations
        ENABLE TRIGGER schema_migrations_immutable`;
    }
    expect((await runPostgresMigrations(
      ownerSql as unknown as PostgresSqlClient,
      { runtimeRole: roleBoundary },
    )).appliedVersions).toEqual([]);
  });

  test("rejects standalone type and non-table relation drift in the final catalog", async () => {
    const fixtures = [
      [
        "CREATE TYPE accounts.unexpected_status AS ENUM ('active')",
        "DROP TYPE accounts.unexpected_status",
      ],
      [
        "CREATE DOMAIN accounts.unexpected_digest AS text",
        "DROP DOMAIN accounts.unexpected_digest",
      ],
      [
        "CREATE VIEW accounts.unexpected_view AS SELECT version FROM accounts.schema_migrations",
        "DROP VIEW accounts.unexpected_view",
      ],
      [
        "CREATE MATERIALIZED VIEW accounts.unexpected_materialized AS SELECT version FROM accounts.schema_migrations WITH NO DATA",
        "DROP MATERIALIZED VIEW accounts.unexpected_materialized",
      ],
      [
        "CREATE SEQUENCE accounts.unexpected_sequence",
        "DROP SEQUENCE accounts.unexpected_sequence",
      ],
    ] as const;
    for (const [mutation, restoration] of fixtures) {
      await expectSchemaDrift([mutation], [restoration]);
    }
  });

  test("rejects ACL drift on an allowed schema type", async () => {
    await ownerSql`REVOKE USAGE ON TYPE accounts.provider_accounts FROM PUBLIC`;
    try {
      await expect(runPostgresMigrations(
        ownerSql as unknown as PostgresSqlClient,
        { runtimeRole: roleBoundary },
      )).rejects.toMatchObject({ code: "SCHEMA_CHECKSUM_MISMATCH" });
    } finally {
      await resetAccountsSchema();
      await runPostgresMigrations(
        ownerSql as unknown as PostgresSqlClient,
        { runtimeRole: roleBoundary },
      );
    }
  });

  test("rejects every dropped CAS and maintenance PK/UNIQUE/CHECK/FK invariant", async () => {
    const tables = new Set([
      "capability_use_consumptions",
      "capsule_maintenance_grants",
      "capsule_maintenance_uses",
    ]);
    const referencedUnique =
      "capsule_maintenance_grants_grant_id_owner_ref_key";
    const dependentForeignKey =
      "capsule_maintenance_uses_grant_id_owner_ref_fkey";
    const constraints = POSTGRES_SCHEMA_MANIFEST.constraints.filter(
      (entry) => tables.has(entry[0]),
    );

    for (const [tableName, constraintName, , definition] of constraints) {
      if (constraintName === referencedUnique) continue;
      await expectSchemaDrift(
        [
          `ALTER TABLE accounts.${identifier(tableName)} ` +
          `DROP CONSTRAINT ${identifier(constraintName)}`,
        ],
        [
          `ALTER TABLE accounts.${identifier(tableName)} ` +
          `ADD CONSTRAINT ${identifier(constraintName)} ${definition}`,
        ],
      );
    }

    const uniqueDefinition = constraints.find(
      (entry) => entry[1] === referencedUnique,
    )?.[3];
    const foreignKeyDefinition = constraints.find(
      (entry) => entry[1] === dependentForeignKey,
    )?.[3];
    expect(uniqueDefinition).toBeDefined();
    expect(foreignKeyDefinition).toBeDefined();
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capsule_maintenance_uses ` +
        `DROP CONSTRAINT ${identifier(dependentForeignKey)}`,
        `ALTER TABLE accounts.capsule_maintenance_grants ` +
        `DROP CONSTRAINT ${identifier(referencedUnique)}`,
      ],
      [
        `ALTER TABLE accounts.capsule_maintenance_grants ` +
        `ADD CONSTRAINT ${identifier(referencedUnique)} ${uniqueDefinition}`,
        `ALTER TABLE accounts.capsule_maintenance_uses ` +
        `ADD CONSTRAINT ${identifier(dependentForeignKey)} ${foreignKeyDefinition}`,
      ],
    );
    expect(constraints).toHaveLength(27);
  });

  test("rejects altered column, collation, ordered-key, FK-action, check, and partial-index contracts", async () => {
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capability_use_consumptions
         ALTER COLUMN committed_at DROP NOT NULL`,
      ],
      [
        `ALTER TABLE accounts.capability_use_consumptions
         ALTER COLUMN committed_at SET NOT NULL`,
      ],
    );
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capsule_maintenance_grants
         ALTER COLUMN expires_at DROP NOT NULL`,
      ],
      [
        `ALTER TABLE accounts.capsule_maintenance_grants
         ALTER COLUMN expires_at SET NOT NULL`,
      ],
    );
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capsule_maintenance_uses
         ALTER COLUMN committed_at DROP NOT NULL`,
      ],
      [
        `ALTER TABLE accounts.capsule_maintenance_uses
         ALTER COLUMN committed_at SET NOT NULL`,
      ],
    );
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capability_use_consumptions
         ALTER COLUMN receipt_jcs_base64url TYPE text COLLATE "C"`,
      ],
      [
        `ALTER TABLE accounts.capability_use_consumptions
         ALTER COLUMN receipt_jcs_base64url TYPE text COLLATE "default"`,
      ],
    );

    const capabilityOrdinalConstraint =
      "capability_use_consumptions_owner_ref_capability_id_key";
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capability_use_consumptions
         DROP CONSTRAINT ${identifier(capabilityOrdinalConstraint)}`,
        `ALTER TABLE accounts.capability_use_consumptions
         ADD CONSTRAINT ${identifier(capabilityOrdinalConstraint)}
         UNIQUE (capability_id, owner_ref)`,
      ],
      [
        `ALTER TABLE accounts.capability_use_consumptions
         DROP CONSTRAINT ${identifier(capabilityOrdinalConstraint)}`,
        `ALTER TABLE accounts.capability_use_consumptions
         ADD CONSTRAINT ${identifier(capabilityOrdinalConstraint)}
         UNIQUE (owner_ref, capability_id)`,
      ],
    );

    const capabilityDigestCheck =
      "capability_use_consumptions_request_digest_check";
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capability_use_consumptions
         DROP CONSTRAINT ${identifier(capabilityDigestCheck)}`,
        `ALTER TABLE accounts.capability_use_consumptions
         ADD CONSTRAINT ${identifier(capabilityDigestCheck)}
         CHECK (request_digest LIKE 'sha256:%')`,
      ],
      [
        `ALTER TABLE accounts.capability_use_consumptions
         DROP CONSTRAINT ${identifier(capabilityDigestCheck)}`,
        `ALTER TABLE accounts.capability_use_consumptions
         ADD CONSTRAINT ${identifier(capabilityDigestCheck)}
         CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$')`,
      ],
    );

    const maintenanceUseForeignKey =
      "capsule_maintenance_uses_grant_id_owner_ref_fkey";
    await expectSchemaDrift(
      [
        `ALTER TABLE accounts.capsule_maintenance_uses
         DROP CONSTRAINT ${identifier(maintenanceUseForeignKey)}`,
        `ALTER TABLE accounts.capsule_maintenance_uses
         ADD CONSTRAINT ${identifier(maintenanceUseForeignKey)}
         FOREIGN KEY (grant_id, owner_ref)
         REFERENCES accounts.capsule_maintenance_grants(grant_id, owner_ref)
         ON DELETE CASCADE`,
      ],
      [
        `ALTER TABLE accounts.capsule_maintenance_uses
         DROP CONSTRAINT ${identifier(maintenanceUseForeignKey)}`,
        `ALTER TABLE accounts.capsule_maintenance_uses
         ADD CONSTRAINT ${identifier(maintenanceUseForeignKey)}
         FOREIGN KEY (grant_id, owner_ref)
         REFERENCES accounts.capsule_maintenance_grants(grant_id, owner_ref)
         ON DELETE RESTRICT`,
      ],
    );

    const reservationIndex = "capsule_maintenance_one_live_reservation";
    await expectSchemaDrift(
      [`DROP INDEX accounts.${identifier(reservationIndex)}`],
      [
        `CREATE UNIQUE INDEX ${identifier(reservationIndex)}
         ON accounts.capsule_maintenance_grants(owner_ref, reservation_key_digest)
         WHERE state = 'live'`,
      ],
    );
    await expectSchemaDrift(
      [
        `DROP INDEX accounts.${identifier(reservationIndex)}`,
        `CREATE UNIQUE INDEX ${identifier(reservationIndex)}
         ON accounts.capsule_maintenance_grants(reservation_key_digest, owner_ref)
         WHERE state = 'live'`,
      ],
      [
        `DROP INDEX accounts.${identifier(reservationIndex)}`,
        `CREATE UNIQUE INDEX ${identifier(reservationIndex)}
         ON accounts.capsule_maintenance_grants(owner_ref, reservation_key_digest)
         WHERE state = 'live'`,
      ],
    );
    await expectSchemaDrift(
      [
        `DROP INDEX accounts.${identifier(reservationIndex)}`,
        `CREATE UNIQUE INDEX ${identifier(reservationIndex)}
         ON accounts.capsule_maintenance_grants(owner_ref, reservation_key_digest)
         WHERE state IN ('live', 'expired')`,
      ],
      [
        `DROP INDEX accounts.${identifier(reservationIndex)}`,
        `CREATE UNIQUE INDEX ${identifier(reservationIndex)}
         ON accounts.capsule_maintenance_grants(owner_ref, reservation_key_digest)
         WHERE state = 'live'`,
      ],
    );
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
