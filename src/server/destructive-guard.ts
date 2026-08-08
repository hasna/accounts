// Destructive-migration gate for the accounts deploy path.
//
// Migration 0006_purge_test_tool_fixtures DELETEs production rows and preserves
// no original, which meets every condition of the standing irreversible-mutation
// freeze. This module is the gate that lets it run at all, and it has two arms:
//
//   ARM 1 - SNAPSHOT. `0005a_archive_purged_fixtures.sql` copies every row the
//     0006 predicates match into `destructive_migration_archive` and is ordered
//     immediately before 0006. The ledger applies migrations in order and stops
//     on the first error, so either the archive commits or 0006 never runs.
//     `assertArchivePrecedesPurge` enforces that ordering statically, with no
//     database, so CI fails the moment someone reorders or drops the archive.
//
//   ARM 2 - REFUSE. `preflightDestructiveMigrations` runs a pre-flight
//     SELECT COUNT on the 0006 predicates against the live database and refuses
//     the deploy when the result is outside the expected envelope, naming what
//     to do. Expected is: zero account rows, zero cascaded selections, and at
//     most the four known fixture tools.
//
// Both arms are required. A gate that only refuses is an outage; a snapshot
// nobody can restore from is theatre, so the refusal message names the restore
// command and `restorePurgeArchive` implements it.

import type { Migration, TypedQueryClient } from "../generated/storage-kit/index.js";

/** The four login/review harness tool ids that leaked into the production registry. */
export const LEAKED_FIXTURE_TOOL_IDS = [
  "fake-login",
  "fake-variant",
  "missing-review",
  "review-state-shape",
] as const;

export const PURGE_MIGRATION_ID = "accounts_0006_purge_test_tool_fixtures";
export const ARCHIVE_MIGRATION_ID = "accounts_0005a_archive_purged_fixtures";
export const ARCHIVE_TABLE = "destructive_migration_archive";

/** Opt-in acknowledgement for a purge whose pre-flight count is outside the envelope. */
export const DESTRUCTIVE_ACK_ENV = "HASNA_ACCOUNTS_ALLOW_DESTRUCTIVE_PURGE";
export const DESTRUCTIVE_ACK_VALUE = "confirm";

/**
 * A table 0006 destroys, the column its predicate keys on, and how many matches
 * are tolerable before the deploy refuses.
 *
 * `current_selections` carries no DELETE of its own in 0006: those rows are
 * removed by `current_selections_account_fk ... ON DELETE CASCADE` (migration
 * 0004). Naming it here is the whole reason the gate sees the real blast radius
 * rather than the two tables 0006's SQL text mentions.
 */
export interface DestructivePredicate {
  readonly table: "accounts" | "current_selections" | "custom_tools";
  readonly column: "tool" | "id";
  readonly values: readonly string[];
  /** Largest match count that still counts as the expected, safe state. */
  readonly maxExpected: number;
  readonly note: string;
}

export const PURGE_PREDICATES: readonly DestructivePredicate[] = [
  {
    table: "accounts",
    column: "tool",
    values: LEAKED_FIXTURE_TOOL_IDS,
    maxExpected: 0,
    note: "real account rows; 0006 deletes these only to defeat 0005's in-use guard",
  },
  {
    table: "current_selections",
    column: "tool",
    values: LEAKED_FIXTURE_TOOL_IDS,
    maxExpected: 0,
    note: "removed by ON DELETE CASCADE, named in no DELETE statement",
  },
  {
    table: "custom_tools",
    column: "id",
    values: LEAKED_FIXTURE_TOOL_IDS,
    maxExpected: LEAKED_FIXTURE_TOOL_IDS.length,
    note: "the four leaked fixture definitions 0006 exists to remove",
  },
];

/** Restore order matters: see `restorePurgeArchive`. */
const RESTORE_ORDER = ["custom_tools", "accounts", "current_selections"] as const;

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

function assertIdentifier(name: string): string {
  if (!IDENTIFIER.test(name)) throw new Error(`Refusing to interpolate unsafe identifier: ${name}`);
  return name;
}

export const RESTORE_COMMAND = "accounts-migrate --restore-purge-archive";

/**
 * ARM 1, statically. The archive migration must exist and must be ordered
 * before the purge. Pure function over the migration list: no database, no
 * credentials, so CI runs it on every push.
 */
export function assertArchivePrecedesPurge(migrations: readonly Migration[]): void {
  const ids = migrations.map((migration) => migration.id);
  const purgeIndex = ids.indexOf(PURGE_MIGRATION_ID);
  if (purgeIndex === -1) return; // the destructive migration is not in this build
  const archiveIndex = ids.indexOf(ARCHIVE_MIGRATION_ID);
  if (archiveIndex === -1) {
    throw new Error(
      `${PURGE_MIGRATION_ID} deletes production rows but its snapshot migration ` +
        `${ARCHIVE_MIGRATION_ID} is missing from this build. The purge must never ship ` +
        `without the archive that precedes it.`,
    );
  }
  if (archiveIndex > purgeIndex) {
    throw new Error(
      `${ARCHIVE_MIGRATION_ID} must be ordered BEFORE ${PURGE_MIGRATION_ID} in ` +
        `APP_MIGRATION_FILES (archive is at ${archiveIndex}, purge at ${purgeIndex}). ` +
        `A snapshot taken after the delete preserves nothing.`,
    );
  }
}

export interface PredicateCount extends DestructivePredicate {
  readonly tablePresent: boolean;
  readonly matched: number;
  readonly withinEnvelope: boolean;
}

export interface PreflightReport {
  readonly purgePending: boolean;
  readonly counts: readonly PredicateCount[];
  readonly withinEnvelope: boolean;
  readonly acknowledged: boolean;
  /** True when the archive SQL was re-executed to close a stale-snapshot window. */
  readonly snapshotRefreshed: boolean;
}

async function countMatches(
  client: TypedQueryClient,
  predicate: DestructivePredicate,
): Promise<{ tablePresent: boolean; matched: number }> {
  const table = assertIdentifier(predicate.table);
  const column = assertIdentifier(predicate.column);
  const present = await client.get<{ present: boolean }>(
    "SELECT to_regclass($1) IS NOT NULL AS present",
    [table],
  );
  // A fresh database has no tables yet; nothing exists to destroy, so this is
  // the safe state and not a reason to refuse. Refusing here would make a
  // first-ever deploy impossible to bootstrap.
  if (!present?.present) return { tablePresent: false, matched: 0 };
  const row = await client.get<{ matched: number }>(
    `SELECT count(*)::int AS matched FROM ${table} WHERE ${column} = ANY($1::text[])`,
    [[...predicate.values]],
  );
  return { tablePresent: true, matched: row?.matched ?? 0 };
}

/**
 * ARM 2. Pre-flight SELECT COUNT on the 0006 predicates. Returns the report
 * when the deploy may proceed; throws a loud, actionable error when it may not.
 *
 * Also refreshes the snapshot when it can go stale. The archive normally runs
 * immediately before the purge in one ledger pass, leaving no window. But if the
 * archive commits and the purge then fails — refused here, or any error — a later
 * re-run finds the archive already applied and the purge still pending, and the
 * ledger will not re-run an applied migration. Rows created in between would then
 * be deleted with nothing preserved. Re-executing the archive SQL closes that
 * window: it is idempotent by construction (CREATE TABLE IF NOT EXISTS plus
 * ON CONFLICT DO NOTHING), and re-using the migration's own SQL keeps one source
 * of truth rather than a second copy of the predicates.
 */
export async function preflightDestructiveMigrations(
  client: TypedQueryClient,
  status: { readonly pending: readonly string[]; readonly ledgerPresent?: boolean },
  migrations: readonly Migration[] = [],
  env: NodeJS.ProcessEnv = process.env,
): Promise<PreflightReport> {
  const pending = status.pending;
  const purgePending = pending.includes(PURGE_MIGRATION_ID);
  if (!purgePending) {
    return {
      purgePending: false,
      counts: [],
      withinEnvelope: true,
      acknowledged: false,
      snapshotRefreshed: false,
    };
  }

  // Only when the archive already ran: if it is still pending the ledger applies
  // it in the correct position, and on a fresh database its tables do not exist
  // yet, so executing it here would fail.
  const archiveAlreadyApplied =
    status.ledgerPresent === true && !pending.includes(ARCHIVE_MIGRATION_ID);
  let snapshotRefreshed = false;
  if (archiveAlreadyApplied) {
    const archive = migrations.find((migration) => migration.id === ARCHIVE_MIGRATION_ID);
    if (archive) {
      await client.execute(archive.sql);
      snapshotRefreshed = true;
    }
  }

  const counts: PredicateCount[] = [];
  for (const predicate of PURGE_PREDICATES) {
    const { tablePresent, matched } = await countMatches(client, predicate);
    counts.push({
      ...predicate,
      tablePresent,
      matched,
      withinEnvelope: matched <= predicate.maxExpected,
    });
  }

  const withinEnvelope = counts.every((count) => count.withinEnvelope);
  const acknowledged = env[DESTRUCTIVE_ACK_ENV]?.trim() === DESTRUCTIVE_ACK_VALUE;

  if (!withinEnvelope && !acknowledged) {
    const offenders = counts
      .filter((count) => !count.withinEnvelope)
      .map(
        (count) =>
          `  ${count.table}.${count.column}: ${count.matched} row(s) match, at most ` +
          `${count.maxExpected} expected — ${count.note}`,
      )
      .join("\n");
    throw new Error(
      `REFUSING TO DEPLOY: ${PURGE_MIGRATION_ID} would destroy more than the four known ` +
        `fixture rows.\n${offenders}\n` +
        `Predicate: ${count_columns()} IN (${LEAKED_FIXTURE_TOOL_IDS.join(", ")}).\n` +
        `Every matched row is snapshotted into ${ARCHIVE_TABLE} by ${ARCHIVE_MIGRATION_ID} ` +
        `before the delete, and is restored with: ${RESTORE_COMMAND}\n` +
        `If destroying these rows is genuinely intended, re-run with ` +
        `${DESTRUCTIVE_ACK_ENV}=${DESTRUCTIVE_ACK_VALUE}.`,
    );
  }

  return { purgePending, counts, withinEnvelope, acknowledged, snapshotRefreshed };
}

function count_columns(): string {
  return PURGE_PREDICATES.map((predicate) => `${predicate.table}.${predicate.column}`).join(" / ");
}

export interface RestoreResult {
  readonly migrationId: string;
  readonly restored: Record<string, number>;
  readonly archived: Record<string, number>;
}

/**
 * Read the preserved originals back out of `destructive_migration_archive`.
 *
 * TWO THINGS HERE ARE LOAD-BEARING, and both are why this is a command rather
 * than a line of documentation telling an operator to write the INSERT by hand.
 *
 * 1. ORDER. `custom_tools` restores FIRST: inserting a custom tool fires
 *    `custom_tool_registration_reactivate` (migration 0005), which deletes the
 *    tombstone 0006 wrote. Until that tombstone is gone,
 *    `accounts_guard_removed_custom_tool` raises on every account insert — so
 *    the obvious restore order, accounts first, fails outright.
 *
 * 2. COLUMN INTERSECTION. The archive is captured at 0005a; migration 0007 then
 *    adds `aliases JSONB NOT NULL DEFAULT '[]'` to `accounts`. A restore written
 *    as `SELECT (jsonb_populate_record(NULL::accounts, row_data)).*` yields NULL
 *    for every column the snapshot predates and violates that NOT NULL. So the
 *    insert names only the columns the snapshot actually carries and lets the
 *    table's own defaults fill the rest. A snapshot that cannot be restored is
 *    not a preserved original, which is the entire point of the gate.
 */
export async function restorePurgeArchive(
  client: TypedQueryClient,
  migrationId: string = PURGE_MIGRATION_ID,
): Promise<RestoreResult> {
  const restored: Record<string, number> = {};
  const archived: Record<string, number> = {};

  for (const table of RESTORE_ORDER) {
    const safeTable = assertIdentifier(table);
    const before = await client.get<{ n: number }>(`SELECT count(*)::int AS n FROM ${safeTable}`);
    const archivedRow = await client.get<{ n: number }>(
      `SELECT count(*)::int AS n FROM ${ARCHIVE_TABLE} WHERE migration_id = $1 AND table_name = $2`,
      [migrationId, table],
    );
    archived[table] = archivedRow?.n ?? 0;

    if (archived[table] > 0) {
      // Columns present in BOTH the snapshot and the table as it stands now.
      const columns = await client.many<{ column_name: string }>(
        `SELECT c.column_name
           FROM information_schema.columns AS c
          WHERE c.table_name = $2
            AND c.table_schema = current_schema()
            AND c.column_name IN (
              SELECT DISTINCT jsonb_object_keys(a.row_data)
                FROM ${ARCHIVE_TABLE} AS a
               WHERE a.migration_id = $1 AND a.table_name = $2
            )
          ORDER BY c.ordinal_position`,
        [migrationId, table],
      );
      if (columns.length === 0) {
        throw new Error(
          `${ARCHIVE_TABLE} holds ${archived[table]} row(s) for ${table} but none of their ` +
            `columns still exist on that table; the snapshot cannot be restored.`,
        );
      }
      const names = columns.map((column) => assertIdentifier(column.column_name));
      const columnList = names.join(", ");
      const projection = names.map((name) => `(populated.record).${name}`).join(", ");
      await client.execute(
        `INSERT INTO ${safeTable} (${columnList})
         SELECT ${projection}
           FROM (
             SELECT jsonb_populate_record(NULL::${safeTable}, archive.row_data) AS record
               FROM ${ARCHIVE_TABLE} AS archive
              WHERE archive.migration_id = $1 AND archive.table_name = $2
           ) AS populated
         ON CONFLICT DO NOTHING`,
        [migrationId, table],
      );
    }

    const after = await client.get<{ n: number }>(`SELECT count(*)::int AS n FROM ${safeTable}`);
    restored[table] = (after?.n ?? 0) - (before?.n ?? 0);
  }

  return { migrationId, restored, archived };
}
