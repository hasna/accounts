// Migration set for the accounts cloud service.
//
// Combines the app schema (SQL files under `migrations/`) with the shared
// api-keys table migrations from `@hasna/contracts/auth`, and exposes them as
// the vendored kit's `Migration[]` (checksum-guarded ledger). PURE REMOTE
// (Amendment A1): these run against the cloud Postgres only.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { apiKeyMigrations } from "@hasna/contracts/auth";
import {
  defineMigration,
  DEFAULT_MIGRATION_LEDGER_TABLE,
  type Migration,
  type TypedQueryClient,
} from "../generated/storage-kit/index.js";
import { API_KEYS_TABLE } from "./config.js";

/** Ordered app-schema SQL files, applied before the auth table migrations. */
export const APP_MIGRATION_FILES = ["0001_accounts.sql", "0002_current_selections.sql"] as const;

function moduleDir(): string {
  try {
    return dirname(fileURLToPath(import.meta.url));
  } catch {
    return process.cwd();
  }
}

/** Resolve the repo/package `migrations/` directory across dev, dist, and Docker. */
export function resolveMigrationsDir(): string {
  const here = moduleDir();
  const candidates = [
    join(here, "..", "..", "migrations"), // dev: src/server -> repo/migrations
    join(here, "..", "migrations"), // dist: dist/server -> dist? (unused) fallback
    join(here, "migrations"),
    join(process.cwd(), "migrations"),
    "/app/migrations", // Docker image layout
  ];
  for (const candidate of candidates) {
    if (existsSync(join(candidate, APP_MIGRATION_FILES[0]))) return candidate;
  }
  // Last resort: any candidate directory that exists.
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(
    `Could not locate the accounts migrations directory. Looked in: ${candidates.join(", ")}`,
  );
}

function readAppMigration(dir: string, file: string): Migration {
  const sql = readFileSync(join(dir, file), "utf8");
  // Migration id is the file's numeric+slug stem, e.g. "0001_accounts".
  const id = file.replace(/\.sql$/, "");
  return defineMigration(`accounts_${id}`, sql);
}

/**
 * Build the full ordered migration list: app schema (from `migrations/*.sql`)
 * then the api-keys table (from the contracts auth kit).
 */
export function accountsMigrations(): Migration[] {
  const dir = resolveMigrationsDir();
  const seen = new Set(readdirSync(dir).filter((f) => f.endsWith(".sql")));
  for (const file of APP_MIGRATION_FILES) {
    if (!seen.has(file)) throw new Error(`Missing expected migration file: ${file}`);
  }
  const app = APP_MIGRATION_FILES.map((file) => readAppMigration(dir, file));
  const auth = apiKeyMigrations(API_KEYS_TABLE).map((m) => defineMigration(m.id, m.sql));
  return [...app, ...auth];
}

export interface MigrationStatus {
  /** True once the ledger table exists (schema has been initialized). */
  ledgerPresent: boolean;
  /** Defined migration ids not yet recorded as applied. */
  pending: string[];
}

/**
 * Read migration status WITHOUT any DDL (no CREATE), so the least-privilege app
 * role can probe readiness. Returns `ledgerPresent: false` when the ledger table
 * has not been created yet. This avoids the kit ledger's `ensureLedger()` CREATE,
 * which the DML-only app role is (correctly) not allowed to run.
 */
export async function readMigrationStatus(
  client: TypedQueryClient,
  migrations: readonly Migration[] = accountsMigrations(),
): Promise<MigrationStatus> {
  const exists = await client.get<{ present: boolean }>(
    "SELECT to_regclass($1) IS NOT NULL AS present",
    [DEFAULT_MIGRATION_LEDGER_TABLE],
  );
  if (!exists?.present) {
    return { ledgerPresent: false, pending: migrations.map((m) => m.id) };
  }
  const rows = await client.many<{ id: string }>(`SELECT id FROM ${DEFAULT_MIGRATION_LEDGER_TABLE}`);
  const applied = new Set(rows.map((r) => r.id));
  const pending = migrations.filter((m) => !applied.has(m.id)).map((m) => m.id);
  return { ledgerPresent: true, pending };
}
