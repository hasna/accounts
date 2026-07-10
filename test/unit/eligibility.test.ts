import { describe, expect, test } from "bun:test";

import {
  parseCounter,
  type EligibilityRequest,
} from "../../src/index";
import { AccountsCatalog } from "../../src/domain/catalog";
import { transitionEntity } from "../../src/domain/state";
import { canonicalSha256 } from "../../src/serialization/json";
import { InMemoryAccountsRepository } from "../../src/storage/memory";
import {
  C1,
  NOW,
  clock,
  makeFixtureGraph,
  mutationContext,
  seedActiveCatalog,
  TEST_CREDENTIAL_VERIFIER,
  makeTestRecoveryLedger,
  TEST_AUTHORITY_POLICY,
} from "../fixtures";

function requestFor(methodId: ReturnType<typeof makeFixtureGraph>["method"]["id"]): EligibilityRequest {
  return {
    accessMethodId: methodId,
    operation: "responses.create",
    model: "model.example",
    dataClassification: "internal",
    destinationPolicyClass: "default",
  };
}

describe("non-reservational slot eligibility", () => {
  test("returns complete native metadata without creating a reservation", async () => {
    const catalog = referenceCatalog();
    const graph = makeFixtureGraph("native_session");
    await seedActiveCatalog(catalog, graph);
    const before = await catalog.list("access_method");
    const result = await catalog.eligibility(requestFor(graph.method.id));
    const after = await catalog.list("access_method");

    expect(result.eligible).toBe(true);
    expect(result.evidenceClass).toBe("local_diagnostic");
    expect(result.authority).toBe("none");
    expect(result.reservation).toBe("none");
    expect(result.accessTarget.kind).toBe("native");
    expect(result.eligibilityRequestDigest).toBe(canonicalSha256({
      schema_version: "accounts.eligibility-request.v1",
      account_lane_id: graph.method.id,
      data_classification: "internal",
      destination_policy_class: "default",
      model: "model.example",
      operation: "responses.create",
    }));
    expect(Object.keys(result)).not.toContain("holder");
    expect(Object.keys(result)).not.toContain("leaseId");
    expect(after).toEqual(before);
    await catalog.close();
  });

  test.each(["api_key", "workload_identity"] as const)(
    "supports brokered %s transport without an AuthCapsule",
    async (transport) => {
      const catalog = referenceCatalog();
      const graph = makeFixtureGraph(transport);
      await seedActiveCatalog(catalog, graph, transport);
      const result = await catalog.eligibility(requestFor(graph.method.id));
      expect(result.eligible).toBe(true);
      expect(result.accessTarget.kind).toBe("brokered");
      expect(result.recordRevisionSet).not.toHaveProperty("auth_capsule");
      await catalog.close();
    },
  );

  test("current deny wins over still-unexpired positive evidence", async () => {
    const catalog = referenceCatalog();
    const graph = makeFixtureGraph();
    await seedActiveCatalog(catalog, graph);
    const request = requestFor(graph.method.id);
    const oldEvidence = await catalog.eligibility(request);
    expect(oldEvidence.eligible).toBe(true);
    expect(Date.parse(oldEvidence.expiresAt)).toBeGreaterThan(NOW.getTime());

    await catalog.transition(
      "capacity_pool",
      graph.pool.id,
      "draining",
      C1,
      mutationContext("deny:pool", "ROTATION_BARRIER"),
    );
    await catalog.transition(
      "access_method",
      graph.method.id,
      "draining",
      C1,
      mutationContext("deny:method", "ROTATION_BARRIER"),
    );

    const rechecked = await catalog.checkCurrent(oldEvidence, request);
    expect(rechecked.eligible).toBe(false);
    expect(rechecked.reasonCodes).toEqual(["CURRENT_DENY"]);
    await catalog.close();
  });

  test("a retiring binding is never eligible even if corrupted storage leaves capacity allowed", async () => {
    const repository = new InMemoryAccountsRepository(
      TEST_CREDENTIAL_VERIFIER,
      makeTestRecoveryLedger(),
    );
    const catalog = new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY);
    const graph = makeFixtureGraph();
    await seedActiveCatalog(catalog, graph);
    const activeBinding = await catalog.get("credential_binding", graph.binding.id);
    const retiring = transitionEntity(
      "credential_binding",
      activeBinding,
      "retiring",
      new Date(NOW.getTime() + 10).toISOString(),
    );
    await repository.replace(
      "credential_binding",
      retiring,
      activeBinding.revision,
      mutationContext("corrupt:retiring", "STORAGE_CORRUPTION_TEST"),
    );
    const result = await catalog.eligibility(requestFor(graph.method.id));
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toContain("CREDENTIAL_BINDING_RETIRING");
    await catalog.close();
  });

  test("stale terms and policy evidence fail closed with stable reasons", async () => {
    let observed = new Date(NOW);
    const repository = new InMemoryAccountsRepository(
      TEST_CREDENTIAL_VERIFIER,
      makeTestRecoveryLedger(),
    );
    const catalog = new AccountsCatalog(
      repository,
      () => new Date(observed),
      TEST_AUTHORITY_POLICY,
    );
    const graph = makeFixtureGraph();
    await seedActiveCatalog(catalog, graph);
    observed = new Date("2026-07-10T14:00:00.000Z");
    const result = await catalog.eligibility(requestFor(graph.method.id));
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toContain("TERMS_STALE");
    expect(result.reasonCodes).toContain("POLICY_EVIDENCE_STALE");
    expect(result.reasonCodes).toContain("ATTESTATION_STALE");
    await catalog.close();
  });

  test("repository unavailability becomes a denial, not cached success", async () => {
    const repository = new InMemoryAccountsRepository(
      TEST_CREDENTIAL_VERIFIER,
      makeTestRecoveryLedger(),
    );
    const catalog = new AccountsCatalog(repository, clock, TEST_AUTHORITY_POLICY);
    const graph = makeFixtureGraph();
    await repository.close();
    const result = await catalog.eligibility(requestFor(graph.method.id));
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toEqual(["DEPENDENCY_UNAVAILABLE"]);
  });

  test("native mutation remains unavailable after metadata drain", async () => {
    const catalog = referenceCatalog();
    const graph = makeFixtureGraph();
    await seedActiveCatalog(catalog, graph);
    await catalog.transition(
      "capacity_pool",
      graph.pool.id,
      "draining",
      C1,
      mutationContext("native-unavailable:pool"),
    );
    await catalog.transition(
      "access_method",
      graph.method.id,
      "draining",
      C1,
      mutationContext("native-unavailable:method"),
    );
    await expect(
      catalog.transition(
        "auth_capsule",
        graph.capsule!.id,
        "bootstrapping",
        parseCounter("2"),
        mutationContext("native-unavailable:capsule"),
      ),
    ).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });
    await catalog.close();
  });

  test("stale capsule health cannot transition to ready", async () => {
    const catalog = referenceCatalog();
    const source = makeFixtureGraph();
    const graph = {
      ...source,
      capsule: {
        ...source.capsule!,
        lastHealthAt: "2000-01-01T00:00:00.000Z",
      },
    };
    await catalog.add("account", graph.account, mutationContext("stale-health:account:add"));
    await catalog.activateProviderAccount(
      graph.activeAccount,
      graph.ownershipEvidence,
      graph.ownershipFence,
      parseCounter("0"),
      mutationContext("stale-health:account:active"),
    );
    await catalog.add(
      "entitlement",
      graph.entitlement,
      mutationContext("stale-health:entitlement:add"),
    );
    await catalog.activateEntitlement(
      graph.activeEntitlement,
      graph.entitlementEvidence,
      parseCounter("0"),
      mutationContext("stale-health:entitlement:active"),
    );
    await catalog.addCapacityPoolFromEvidence(
      graph.pool,
      graph.capacityEvidence,
      graph.capacityFence,
      mutationContext("stale-health:pool:add"),
    );
    await catalog.transition(
      "capacity_pool",
      graph.pool.id,
      "active",
      parseCounter("0"),
      mutationContext("stale-health:pool:active"),
    );
    await catalog.add("access_method", graph.method, mutationContext("stale-health:method:add"));
    await catalog.activateAccessMethod(
      graph.readyMethod,
      graph.laneEvidence,
      parseCounter("0"),
      mutationContext("stale-health:method:ready"),
    );
    await catalog.add("auth_capsule", graph.capsule, mutationContext("stale-health:capsule:add"));
    await catalog.transition(
      "auth_capsule",
      graph.capsule.id,
      "bootstrapping",
      parseCounter("0"),
      mutationContext("stale-health:capsule:bootstrapping"),
    );
    await expect(
      catalog.transition(
        "auth_capsule",
        graph.capsule.id,
        "ready",
        parseCounter("1"),
        mutationContext("stale-health:capsule:ready"),
      ),
    ).rejects.toMatchObject({ code: "CAPSULE_NOT_READY" });
    await catalog.close();
  });

  test("central native revoke is unavailable without an atomic terminal barrier", async () => {
    const catalog = referenceCatalog();
    const graph = makeFixtureGraph();
    await seedActiveCatalog(catalog, graph, "revoke-unavailable");
    await expect(
      catalog.transition(
        "auth_capsule",
        graph.capsule!.id,
        "revoked",
        parseCounter("2"),
        mutationContext("revoke-unavailable:capsule"),
      ),
    ).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });
    await expect(
      catalog.transition(
        "credential_binding",
        graph.binding.id,
        "revoked",
        parseCounter("1"),
        mutationContext("revoke-unavailable:binding"),
      ),
    ).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });
    await expect(
      catalog.transition(
        "account",
        graph.account.id,
        "suspended",
        parseCounter("1"),
        mutationContext("revoke-unavailable:account"),
      ),
    ).rejects.toMatchObject({ code: "NOT_IMPLEMENTED" });
    await catalog.close();
  });
});

function referenceCatalog(): AccountsCatalog {
  return new AccountsCatalog(
    new InMemoryAccountsRepository(TEST_CREDENTIAL_VERIFIER, makeTestRecoveryLedger()),
    clock,
    TEST_AUTHORITY_POLICY,
  );
}
