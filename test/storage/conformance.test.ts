import { Database } from "bun:sqlite";
import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";

import {
  AccountsError,
  MAX_COUNTER,
  createSQLiteAccounts,
  parseCounter,
  type Account,
} from "../../src/index";
import { AccountsCatalog } from "../../src/domain/catalog";
import { transitionEntity } from "../../src/domain/state";
import { InMemoryAccountsRepository } from "../../src/storage/memory";
import type { AccountsRepository } from "../../src/storage/repository";
import { SQLiteAccountsRepository } from "../../src/storage/sqlite";
import {
  C0,
  NOW,
  clock,
  makeFixtureGraph,
  mutationContext,
  seedActiveCatalog,
} from "../fixtures";

const TEMP_ROOT = join(import.meta.dir, "..", "..", ".tmp", "storage-tests");
mkdirSync(TEMP_ROOT, { recursive: true, mode: 0o700 });
chmodSync(join(import.meta.dir, "..", "..", ".tmp"), 0o700);
chmodSync(TEMP_ROOT, 0o700);

const cleanup: string[] = [];
afterAll(() => {
  for (const path of cleanup) rmSync(path, { recursive: true, force: true });
});

type AdapterFactory = () => {
  repository: AccountsRepository;
  catalog: AccountsCatalog;
  directory?: string;
};

const adapters: ReadonlyArray<readonly ["memory" | "sqlite", AdapterFactory]> = [
  [
    "memory",
    () => {
      const repository = new InMemoryAccountsRepository();
      return { repository, catalog: new AccountsCatalog(repository, clock) };
    },
  ],
  [
    "sqlite",
    () => {
      const directory = mkdtempSync(join(TEMP_ROOT, "sqlite-"));
      cleanup.push(directory);
      const repository = new SQLiteAccountsRepository(join(directory, "accounts.db"));
      return { repository, catalog: new AccountsCatalog(repository, clock), directory };
    },
  ],
];

for (const [adapterName, factory] of adapters) {
  describe(`${adapterName} repository conformance`, () => {
    test("runs the same complete catalog and eligibility flow", async () => {
      const { catalog } = factory();
      const graph = makeFixtureGraph();
      await seedActiveCatalog(catalog, graph, `${adapterName}:flow`);
      const result = await catalog.eligibility({
        accessMethodId: graph.method.id,
        operation: "responses.create",
        model: "model.example",
        dataClassification: "internal",
        destinationPolicyClass: "default",
      });
      expect(result.eligible).toBe(true);
      const doctor = await catalog.doctor();
      expect(doctor.integrity).toBe("ok");
      expect(doctor.adapter).toBe(adapterName);
      await catalog.close();
    });

    test("replays the original idempotent response after later mutation", async () => {
      const { repository } = factory();
      const account = makeFixtureGraph("native_session", 11).account;
      const context = mutationContext(`${adapterName}:idempotent-insert`);
      const inserted = await repository.insert("account", account, context);
      const active = transitionEntity("account", account, "active", NOW.toISOString());
      await repository.replace(
        "account",
        active,
        account.revision,
        mutationContext(`${adapterName}:later-update`),
      );
      const replay = await repository.insert("account", account, context);
      expect(replay.replayed).toBe(true);
      expect(replay.eventId).toBe(inserted.eventId);
      expect(replay.record.revision).toBe(C0);
      expect(replay.record.status).toBe("pending");
      await repository.close();
    });

    test("rejects idempotency reuse when audited reason changes", async () => {
      const { repository } = factory();
      const account = makeFixtureGraph("native_session", 12).account;
      await repository.insert(
        "account",
        account,
        mutationContext(`${adapterName}:reason-conflict`, "FIRST_REASON"),
      );
      await expect(
        repository.insert(
          "account",
          account,
          mutationContext(`${adapterName}:reason-conflict`, "SECOND_REASON"),
        ),
      ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
      await repository.close();
    });

    test("preserves exact signed-64-bit counters beyond Number precision", async () => {
      const { repository } = factory();
      const source = makeFixtureGraph("native_session", 13).account;
      const record: Account = {
        ...source,
        status: "revoked",
        revision: parseCounter(MAX_COUNTER.toString(10)),
      };
      await repository.insert("account", record, mutationContext(`${adapterName}:int64`));
      const loaded = await repository.get("account", record.id);
      expect(String(loaded?.revision)).toBe("9223372036854775807");
      expect(typeof loaded?.revision).toBe("string");
      await repository.close();
    });

    test("orders UUID identifiers deterministically and rejects missing parents", async () => {
      const { catalog } = factory();
      const later = makeFixtureGraph("native_session", 21);
      const earlier = makeFixtureGraph("native_session", 20);
      await catalog.add("account", later.account, mutationContext(`${adapterName}:later`));
      await catalog.add("account", earlier.account, mutationContext(`${adapterName}:earlier`));
      const records = await catalog.list("account");
      expect(records.map((record) => record.id)).toEqual(
        [later.account.id, earlier.account.id].sort((left, right) => (left < right ? -1 : 1)),
      );
      await expect(
        catalog.add(
          "entitlement",
          makeFixtureGraph("native_session", 22).entitlement,
          mutationContext(`${adapterName}:missing-parent`),
        ),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
      await catalog.close();
    });

    test("serializes racing provider-subject ownership", async () => {
      const { catalog } = factory();
      const first = makeFixtureGraph("native_session", 31).account;
      const secondSource = makeFixtureGraph("native_session", 32).account;
      const second = { ...secondSource, providerSubjectRef: first.providerSubjectRef! };
      await catalog.add("account", first, mutationContext(`${adapterName}:race:first:add`));
      await catalog.add("account", second, mutationContext(`${adapterName}:race:second:add`));
      const outcomes = await Promise.allSettled([
        catalog.transition(
          "account",
          first.id,
          "active",
          C0,
          mutationContext(`${adapterName}:race:first:active`),
        ),
        catalog.transition(
          "account",
          second.id,
          "active",
          C0,
          mutationContext(`${adapterName}:race:second:active`),
        ),
      ]);
      expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
      await catalog.close();
    });

    test("keeps credential-family purpose lineage immutable across generations", async () => {
      const { repository, catalog } = factory();
      const graph = makeFixtureGraph("api_key", 41);
      await seedActiveCatalog(catalog, graph, `${adapterName}:family`);
      const conflicting = {
        ...graph.binding,
        id: makeFixtureGraph("workload_identity", 42).binding.id,
        purpose: "workload_identity" as const,
        resolver: "workload_identity" as const,
        credentialGeneration: parseCounter("1"),
        revision: C0,
        status: "pending" as const,
      };
      await expect(
        repository.insert(
          "credential_binding",
          conflicting,
          mutationContext(`${adapterName}:family:conflict`),
        ),
      ).rejects.toMatchObject({ code: "CAPACITY_DOMAIN_CONFLICT" });
      await catalog.close();
    });

    test("preserves provider-subject ownership after terminal revocation", async () => {
      const { repository } = factory();
      const firstPending = makeFixtureGraph("native_session", 51).account;
      await repository.insert(
        "account",
        firstPending,
        mutationContext(`${adapterName}:subject:first:add`),
      );
      const firstActive = transitionEntity("account", firstPending, "active", NOW.toISOString());
      await repository.replace(
        "account",
        firstActive,
        firstPending.revision,
        mutationContext(`${adapterName}:subject:first:active`),
      );
      const firstRevoked = transitionEntity(
        "account",
        firstActive,
        "revoked",
        new Date(NOW.getTime() + 1).toISOString(),
      );
      await repository.replace(
        "account",
        firstRevoked,
        firstActive.revision,
        mutationContext(`${adapterName}:subject:first:revoked`),
      );
      const secondSource = makeFixtureGraph("native_session", 52).account;
      const secondPending: Account = {
        ...secondSource,
        ownerRef: "principal:human:hasna:owner-b",
        providerKey: firstPending.providerKey,
        providerSubjectRef: firstPending.providerSubjectRef!,
      };
      await repository.insert(
        "account",
        secondPending,
        mutationContext(`${adapterName}:subject:second:add`),
      );
      const secondActive = transitionEntity(
        "account",
        secondPending,
        "active",
        new Date(NOW.getTime() + 2).toISOString(),
      );
      await expect(
        repository.replace(
          "account",
          secondActive,
          secondPending.revision,
          mutationContext(`${adapterName}:subject:second:active`),
        ),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      await repository.close();
    });

    test("replays an earlier transition after subsequent state changes", async () => {
      const { catalog } = factory();
      const graph = makeFixtureGraph("api_key", 61);
      await seedActiveCatalog(catalog, graph, `${adapterName}:replay-parents`);
      const draft = {
        ...makeFixtureGraph("api_key", 62).method,
        entitlementId: graph.entitlement.id,
        capacityPoolId: graph.pool.id,
      };
      await catalog.add(
        "access_method",
        draft,
        mutationContext(`${adapterName}:replay:add`),
      );
      const firstContext = mutationContext(`${adapterName}:replay:disable`);
      const first = await catalog.transition(
        "access_method",
        draft.id,
        "disabled",
        C0,
        firstContext,
      );
      await catalog.transition(
        "access_method",
        draft.id,
        "draft",
        first.record.revision,
        mutationContext(`${adapterName}:replay:draft`),
      );
      const replay = await catalog.transition(
        "access_method",
        draft.id,
        "disabled",
        C0,
        firstContext,
      );
      expect(replay.replayed).toBe(true);
      expect(replay.record.revision).toBe(first.record.revision);
      await catalog.close();
    });
  });
}

describe("SQLite migration and filesystem hardening", () => {
  test("public local evaluation stays denied without a recovery frontier", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "public-deny-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const repository = new SQLiteAccountsRepository(filename);
    const internalCatalog = new AccountsCatalog(repository, clock);
    const graph = makeFixtureGraph();
    await seedActiveCatalog(internalCatalog, graph, "public-deny");
    await internalCatalog.close();

    const publicCapacity = createSQLiteAccounts({ path: filename, clock });
    const result = await publicCapacity.eligibility({
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    });
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toEqual(["DEPENDENCY_UNAVAILABLE"]);
    await publicCapacity.close();
  });

  test("creates owner-only database files and WAL mode", async () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "permissions-"));
    cleanup.push(directory);
    const filename = join(directory, "accounts.db");
    const repository = new SQLiteAccountsRepository(filename);
    const doctor = await repository.doctor();
    expect(doctor.journalMode).toBe("wal");
    await repository.close();
    expect(statSync(directory).mode & 0o777).toBe(0o700);
    expect(statSync(filename).mode & 0o777).toBe(0o600);
  });

  test("refuses symbolic-link path components", () => {
    const directory = mkdtempSync(join(TEMP_ROOT, "symlink-"));
    const target = mkdtempSync(join(TEMP_ROOT, "target-"));
    cleanup.push(directory, target);
    const link = join(directory, "linked");
    symlinkSync(target, link, "dir");
    expect(() => new SQLiteAccountsRepository(join(link, "accounts.db"))).toThrow(
      expect.objectContaining({ code: "DATABASE_PATH_UNSAFE" }),
    );
  });

  test("refuses unknown newer and checksum-mismatched schemas", () => {
    for (const [name, version, checksum] of [
      ["newer", 2n, "sha256:future"],
      ["mismatch", 1n, "sha256:mismatch"],
    ] as const) {
      const directory = mkdtempSync(join(TEMP_ROOT, `${name}-`));
      cleanup.push(directory);
      const filename = join(directory, "accounts.db");
      const database = new Database(filename, { safeIntegers: true });
      database.exec(
        "CREATE TABLE accounts_schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)",
      );
      database
        .query("INSERT INTO accounts_schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)")
        .run(version, checksum, NOW.toISOString());
      database.close();
      chmodSync(filename, 0o600);
      expect(() => new SQLiteAccountsRepository(filename)).toThrow(AccountsError);
    }
  });
});
