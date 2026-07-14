#!/usr/bin/env bun
// accounts-migrate — apply the accounts cloud schema to Postgres.
//
// Uses the vendored kit's checksum-guarded MigrationLedger against the cloud
// database resolved from HASNA_ACCOUNTS_DATABASE_URL. Idempotent. `--dry-run`
// reports the plan without mutating. Intended for the ECS one-shot migration
// task and local ops.

import { createCloudPoolFromEnv, MigrationLedger, resolveStorageMode } from "../generated/storage-kit/index.js";
import {
  accountsMigrations,
  assertMigrationStatusCompatible,
  readMigrationStatus,
} from "./migrations.js";
import { APP_SLUG } from "./config.js";
import { grantAccountsRuntimeRole } from "./runtime-role.js";

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
    const runtimeRole = process.env.HASNA_ACCOUNTS_RUNTIME_ROLE?.trim();
    if (!runtimeRole) {
      throw new Error(
        "accounts-migrate requires HASNA_ACCOUNTS_RUNTIME_ROLE for the DML-only accounts-serve role.",
      );
    }
    // First, a privilege-safe status probe (no DDL). The migration owner still
    // runs every migration task so a current-schema no-op can revalidate and
    // reapply the runtime role's direct grants.
    const status = await readMigrationStatus(client, migrations);
    assertMigrationStatusCompatible(status);
    if (status.ledgerPresent && status.pending.length === 0) {
      if (!dryRun) {
        const grant = await grantAccountsRuntimeRole(client, runtimeRole);
        console.log(JSON.stringify({ evt: "runtime_role_granted", ...grant }, null, 2));
      }
      console.log(JSON.stringify({ evt: "migrate_noop", dryRun, total: migrations.length, pending: [] }, null, 2));
      return;
    }
    if (dryRun) {
      console.log(
        JSON.stringify(
          {
            evt: "migrate_plan",
            dryRun,
            total: migrations.length,
            ledgerPresent: status.ledgerPresent,
            pending: status.pending,
            unknown: status.unknown,
            checksumMismatches: status.checksumMismatches,
          },
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
    const grant = await grantAccountsRuntimeRole(client, runtimeRole);
    console.log(JSON.stringify({ evt: "runtime_role_granted", ...grant }, null, 2));
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
