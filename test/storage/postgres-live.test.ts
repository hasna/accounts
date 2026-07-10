import { SQL } from "bun";
import { expect, test } from "bun:test";

import { AccountsCatalog } from "../../src/domain/catalog";
import { PostgresAccountsRepository } from "../../src/storage/postgres";
import { runPostgresMigrations } from "../../src/storage/postgres-migrator";
import {
  ACTOR_REF,
  CATALOG_INCARNATION,
  NOW,
  TEST_AUTHORITY_POLICY,
  TEST_CREDENTIAL_USE_AUTHORIZER,
  TEST_CREDENTIAL_VERIFIER,
  clock,
  digest,
  makeCredentialHandleFor,
  makeFixtureGraph,
  makeTestRecoveryLedger,
  seedActiveCatalog,
} from "../fixtures";

const testUrl = process.env.ACCOUNTS_TEST_POSTGRES_URL;
const liveTest = testUrl === undefined ? test.skip : test;

liveTest("runs the authoritative catalog and RLS flow against live PostgreSQL", async () => {
  if (testUrl === undefined) throw new Error("live PostgreSQL URL was not configured");
  const client = new SQL(testUrl, {
    adapter: "postgres",
    tls: false,
    bigint: true,
    max: 4,
  });
  const recoveryLedger = makeTestRecoveryLedger();
  const authority = {
    principalRef: ACTOR_REF,
    identityRealm: "hasna" as const,
    organizationRef: "organization:hasna",
    catalogIncarnation: CATALOG_INCARNATION,
    buildDigest: digest("a"),
    configurationAttestationDigest: digest("b"),
    recoveryLedger,
    credentialVerifier: TEST_CREDENTIAL_VERIFIER,
    credentialUseAuthorizer: TEST_CREDENTIAL_USE_AUTHORIZER,
  };
  const repository = new PostgresAccountsRepository(
    client,
    authority,
    "loopback-test-only",
  );
  const otherOwner = new PostgresAccountsRepository(
    client,
    {
      ...authority,
      principalRef: "principal:human:hasna:owner-b",
    },
    "loopback-test-only",
  );

  try {
    const migration = await runPostgresMigrations(client);
    expect(migration.schemaVersion).toBe("1");
    await repository.initialize();

    const base = makeFixtureGraph("api_key", 190);
    const graph = {
      ...base,
      handle: makeCredentialHandleFor(base, 190, "accounts-self-hosted"),
    };
    const catalog = new AccountsCatalog(
      repository,
      clock,
      TEST_AUTHORITY_POLICY,
    );
    await seedActiveCatalog(catalog, graph, "postgres-live");

    const eligibility = await catalog.eligibility({
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    });
    expect(eligibility.eligible).toBe(true);
    expect((await repository.list("account")).map((record) => record.id)).toEqual([
      graph.account.id,
    ]);

    const claimed = await repository.claimOutbox({
      workerRef: "principal:service:hasna:postgres-live-worker",
      limit: 1,
      now: NOW.toISOString(),
      claimExpiresAt: new Date(NOW.getTime() + 30_000).toISOString(),
    });
    expect(claimed).toHaveLength(1);
    const acknowledged = await repository.acknowledgeOutbox({
      outboxId: claimed[0]!.id,
      workerRef: "principal:service:hasna:postgres-live-worker",
      expectedAttemptCount: claimed[0]!.attemptCount,
      outcome: "delivered",
      now: new Date(NOW.getTime() + 1_000).toISOString(),
    });
    expect(acknowledged.status).toBe("delivered");

    await otherOwner.initialize();
    expect(await otherOwner.list("account")).toEqual([]);
    expect(await otherOwner.get("account", graph.account.id)).toBeUndefined();
  } finally {
    await otherOwner.close();
    await repository.close();
    await client.close();
  }
});
