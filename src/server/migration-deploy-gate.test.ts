// Deployment-gate regression tests.
//
// Context: bumping @hasna/contracts from 0.5.x to 0.8.x adds a THIRD auth
// migration (`hasna_auth_0003_api_keys_tenant`, an additive `ADD COLUMN tid`)
// to the ledger this service checks, and the 0.8.x `ApiKeyStore.insert()` names
// `tid` in its INSERT column list unconditionally. accounts-serve does not
// auto-migrate (migrations run only via the separate `accounts-migrate` bin),
// so deploying the new binary against an unmigrated database leaves a service
// whose reads work (`SELECT *`) and whose new-column writes do not.
//
// These tests pin the gate that separates those two states, and pin the
// deployment probe to the endpoint that actually reads it.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createHandler, type ServiceContext } from "./app.js";
import type { AccountsStore } from "./repo.js";
import {
  accountsMigrations,
  evaluateMigrationReadiness,
  readMigrationStatus,
  type MigrationStatus,
} from "./migrations.js";
import type { TypedQueryClient } from "../generated/storage-kit/index.js";

const TENANT_MIGRATION_ID = "hasna_auth_0003_api_keys_tenant";

/**
 * Minimal ledger-only query client. `readMigrationStatus` issues exactly two
 * reads: a `to_regclass` existence probe and a `SELECT id, checksum` over the
 * ledger. Everything else throws, so a test cannot pass by accident on a path
 * this fake silently stubbed.
 */
function ledgerClient(rows: { id: string; checksum: string }[] | null): TypedQueryClient {
  const unexpected = (sql: string) => {
    throw new Error(`unexpected query in ledger fake: ${sql}`);
  };
  return {
    async get(sql: string) {
      if (sql.includes("to_regclass")) return { present: rows !== null } as never;
      return unexpected(sql);
    },
    async many(sql: string) {
      if (sql.includes("FROM ")) return (rows ?? []) as never;
      return unexpected(sql);
    },
    async query(sql: string) {
      return unexpected(sql);
    },
    async one(sql: string) {
      return unexpected(sql);
    },
    async execute(sql: string) {
      return unexpected(sql);
    },
  } as TypedQueryClient;
}

/** The ledger as it exists on a database migrated by a pre-0.8 accounts build. */
function ledgerWithoutTenantMigration(): { id: string; checksum: string }[] {
  return accountsMigrations()
    .filter((migration) => migration.id !== TENANT_MIGRATION_ID)
    .map((migration) => ({ id: migration.id, checksum: migration.checksum }));
}

describe("migration ledger gate", () => {
  test("the auth tenant migration is part of the ledger this build enforces", () => {
    // Guards the dependency: if a future @hasna/contracts drops or renames the
    // tenant migration, the deployment ordering documented in
    // docs/STORAGE_STABILIZATION.md silently stops matching the code.
    const ids = accountsMigrations().map((migration) => migration.id);
    expect(ids).toContain(TENANT_MIGRATION_ID);
  });

  test("a database migrated by a pre-0.8 build reports the tenant migration pending", async () => {
    const status = await readMigrationStatus(
      ledgerClient(ledgerWithoutTenantMigration()),
      accountsMigrations(),
    );
    expect(status.ledgerPresent).toBe(true);
    expect(status.pending).toEqual([TENANT_MIGRATION_ID]);
    expect(status.unknown).toEqual([]);
    expect(status.checksumMismatches).toEqual([]);
  });

  test("a fully migrated database reports nothing pending", async () => {
    // Positive control for the test above: the same fake, given the complete
    // ledger, must produce the READY verdict. Without this, "pending" could be
    // an artifact of the fake rather than of the missing migration.
    const rows = accountsMigrations().map((m) => ({ id: m.id, checksum: m.checksum }));
    const status = await readMigrationStatus(ledgerClient(rows), accountsMigrations());
    expect(status.pending).toEqual([]);
    expect(evaluateMigrationReadiness(status)).toEqual({ ready: true });
  });

  test("pending migrations fail readiness closed, naming the migration", async () => {
    const status = await readMigrationStatus(
      ledgerClient(ledgerWithoutTenantMigration()),
      accountsMigrations(),
    );
    const verdict = evaluateMigrationReadiness(status);
    expect(verdict.ready).toBe(false);
    expect(verdict.reason).toContain("pending migrations");
    expect(verdict.reason).toContain(TENANT_MIGRATION_ID);
  });

  test("rolling the binary back behind an applied migration also fails readiness closed", async () => {
    // The downgrade direction, which the forward test does not cover: once the
    // tenant migration is applied, an older build does not recognize it. That
    // build must stay out of the load balancer rather than serve against a
    // schema it cannot vouch for.
    const olderBuildManifest = accountsMigrations().filter((m) => m.id !== TENANT_MIGRATION_ID);
    const migratedLedger = accountsMigrations().map((m) => ({ id: m.id, checksum: m.checksum }));

    const status = await readMigrationStatus(ledgerClient(migratedLedger), olderBuildManifest);
    expect(status.pending).toEqual([]);
    expect(status.unknown).toEqual([TENANT_MIGRATION_ID]);

    const verdict = evaluateMigrationReadiness(status);
    expect(verdict.ready).toBe(false);
    expect(verdict.reason).toContain("unknown applied migrations");
    expect(verdict.reason).toContain(TENANT_MIGRATION_ID);
  });

  test("an absent ledger is not ready", async () => {
    const status = await readMigrationStatus(ledgerClient(null), accountsMigrations());
    expect(status.ledgerPresent).toBe(false);
    expect(evaluateMigrationReadiness(status).ready).toBe(false);
  });
});

describe("deployment probe endpoint", () => {
  function contextWith(ready: () => Promise<{ ready: boolean; reason?: string }>): ServiceContext {
    return {
      repo: {} as AccountsStore,
      verifier: { authenticate: async () => ({ ok: true }) } as unknown as ServiceContext["verifier"],
      health: async () => ({ ok: true }),
      ready,
      mode: "cloud",
      version: "0.0.0-test",
      close: async () => {},
    };
  }

  test("/health reports ok while /ready reports 503 for a pending migration", async () => {
    // The two behaviours a deployment probe must separate. A reachable database
    // behind the binary's ledger is EXACTLY the state that produced a container
    // reporting healthy while writes failed, so assert both sides on one
    // context rather than trusting /health alone.
    const status = await readMigrationStatus(
      ledgerClient(ledgerWithoutTenantMigration()),
      accountsMigrations(),
    );
    const handle = createHandler(contextWith(async () => evaluateMigrationReadiness(status)));

    const health = await handle(new Request("http://accounts.test/health"));
    expect(health.status).toBe(200);
    expect((await health.json()).status).toBe("ok");

    const ready = await handle(new Request("http://accounts.test/ready"));
    expect(ready.status).toBe(503);
    const body = (await ready.json()) as { ready: boolean; reason: string };
    expect(body.ready).toBe(false);
    expect(body.reason).toContain(TENANT_MIGRATION_ID);
  });

  test("/ready returns 200 once the ledger is complete", async () => {
    // Positive control for the probe: the same handler must return 200 when the
    // schema matches, otherwise a permanently-503 /ready would pass the test
    // above for the wrong reason.
    const rows = accountsMigrations().map((m) => ({ id: m.id, checksum: m.checksum }));
    const status = await readMigrationStatus(ledgerClient(rows), accountsMigrations());
    const handle = createHandler(contextWith(async () => evaluateMigrationReadiness(status)));

    const ready = await handle(new Request("http://accounts.test/ready"));
    expect(ready.status).toBe(200);
    expect((await ready.json()).ready).toBe(true);
  });

  test("the shipped compose healthcheck probes /ready, not /health", () => {
    // /health proves only that the database answers. A compose healthcheck on
    // /health marks an unmigrated container healthy, which is how a broken
    // deploy reaches traffic. The probe must read the migration-aware endpoint.
    const compose = readFileSync(join(import.meta.dir, "../../docker-compose.yml"), "utf8");
    const probe = compose
      .split("\n")
      .find((line) => line.includes("test:") && line.includes("fetch("));

    expect(probe).toBeDefined();
    expect(probe).toContain("/ready");
    expect(probe).not.toContain("/health");
  });
});
