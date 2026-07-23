import type { SQL } from "bun";

import { AccountsError } from "./errors";
import {
  POSTGRES_MIGRATIONS,
  POSTGRES_MIGRATION_CHECKSUM,
  POSTGRES_SCHEMA_VERSION,
} from "./postgres-migrations";

interface MigrationRow {
  readonly version: string | number | bigint;
  readonly checksum: string;
}

export interface PostgresMigrationReport {
  readonly schemaVersion: string;
  readonly migrationChecksum: string;
  readonly appliedVersions: readonly string[];
}

/**
 * Applies only package-owned, checksummed SQL while holding a transaction-level
 * advisory lock. This function must be called with the migration/admin client,
 * never with the Accounts runtime role.
 */
export async function runPostgresMigrations(
  client: SQL,
): Promise<PostgresMigrationReport> {
  try {
    return await client.begin("read write", async (transaction) => {
      await transaction`
        SELECT pg_catalog.pg_advisory_xact_lock(
          pg_catalog.hashtextextended('hasna.accounts.schema-migrations.v1', 0)
        )
      `;

      const [{ migration_table: migrationTable } = { migration_table: null }] =
        await transaction<Array<{ migration_table: string | null }>>`
          SELECT pg_catalog.to_regclass('accounts.schema_migrations')::text AS migration_table
        `;

      const existing = new Map<number, string>();
      if (migrationTable !== null) {
        const rows = await transaction<MigrationRow[]>`
          SELECT version::text AS version, checksum
          FROM accounts.schema_migrations
          ORDER BY version ASC
        `;
        for (const row of rows) existing.set(Number(row.version), row.checksum);
      }

      const highest = Math.max(0, ...existing.keys());
      if (highest > POSTGRES_SCHEMA_VERSION) {
        throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Postgres schema is newer", {
          details: { adapter: "postgres", schemaVersion: String(highest) },
        });
      }

      const applied: string[] = [];
      for (const migration of POSTGRES_MIGRATIONS) {
        const storedChecksum = existing.get(migration.version);
        if (storedChecksum !== undefined) {
          if (storedChecksum !== migration.checksum) {
            throw new AccountsError(
              "SCHEMA_CHECKSUM_MISMATCH",
              "Postgres migration checksum changed",
              { details: { adapter: "postgres", schemaVersion: String(migration.version) } },
            );
          }
          continue;
        }

        await transaction.unsafe(migration.sql).simple();
        await transaction`
          INSERT INTO accounts.schema_migrations(version, checksum)
          VALUES (${migration.version}, ${migration.checksum})
        `;
        applied.push(String(migration.version));
      }

      const rows = await transaction<MigrationRow[]>`
        SELECT version::text AS version, checksum
        FROM accounts.schema_migrations
        ORDER BY version ASC
      `;
      if (
        rows.length !== POSTGRES_MIGRATIONS.length ||
        rows.some((row, index) => {
          const expected = POSTGRES_MIGRATIONS[index];
          return expected === undefined ||
            Number(row.version) !== expected.version ||
            row.checksum !== expected.checksum;
        })
      ) {
        throw new AccountsError(
          "SCHEMA_CHECKSUM_MISMATCH",
          "Postgres migration history is incomplete",
          { details: { adapter: "postgres" } },
        );
      }

      return Object.freeze({
        schemaVersion: String(POSTGRES_SCHEMA_VERSION),
        migrationChecksum: POSTGRES_MIGRATION_CHECKSUM,
        appliedVersions: Object.freeze(applied),
      });
    });
  } catch (error) {
    if (error instanceof AccountsError) throw error;
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Postgres migration failed", {
      details: { adapter: "postgres" },
    });
  }
}
