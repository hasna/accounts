#!/usr/bin/env bun
// accounts-migrate — apply the accounts cloud schema to Postgres.
//
// Uses the vendored kit's checksum-guarded MigrationLedger against the cloud
// database resolved from HASNA_ACCOUNTS_DATABASE_URL. Idempotent. `--dry-run`
// reports the plan without mutating. Intended for the ECS one-shot migration
// task and local ops.

import { createCloudPoolFromEnv, MigrationLedger, resolveStorageMode } from "../generated/storage-kit/index.js";
import { accountsMigrations, readMigrationStatus } from "./migrations.js";
import { APP_SLUG } from "./config.js";

async function main(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  const resolution = resolveStorageMode(APP_SLUG, process.env);
  if (resolution.mode !== "cloud") {
    console.error("accounts-migrate requires HASNA_ACCOUNTS_STORAGE_MODE=cloud and HASNA_ACCOUNTS_DATABASE_URL.");
    process.exit(1);
  }
  const { client } = createCloudPoolFromEnv(APP_SLUG, { applicationName: "accounts-migrate", max: 2 });
  try {
    const migrations = accountsMigrations();
    // First, a privilege-safe status probe (no DDL). When the schema is already
    // current this exits 0 without touching DDL, so the ECS one-shot task runs
    // green under the least-privilege app role. DDL (the owner role) is only
    // attempted when there is actual pending work.
    const status = await readMigrationStatus(client, migrations);
    if (status.ledgerPresent && status.pending.length === 0) {
      console.log(JSON.stringify({ evt: "migrate_noop", dryRun, total: migrations.length, pending: [] }, null, 2));
      return;
    }
    if (dryRun) {
      console.log(
        JSON.stringify(
          { evt: "migrate_plan", dryRun, total: migrations.length, ledgerPresent: status.ledgerPresent, pending: status.pending },
          null,
          2,
        ),
      );
      return;
    }
    // Pending work exists -> apply via the checksum-guarded ledger (owner role
    // required for the CREATE/DDL).
    const ledger = new MigrationLedger(client, migrations);
    const result = await ledger.migrate({ dryRun: false });
    const appliedNow = result.plan.filter((p) => p.state === "pending").map((p) => p.migration.id);
    console.log(
      JSON.stringify(
        { evt: "migrate_done", dryRun, total: result.plan.length, appliedNow, ledgerTotal: result.applied.length },
        null,
        2,
      ),
    );
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
