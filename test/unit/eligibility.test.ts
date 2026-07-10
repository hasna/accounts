import { describe, expect, test } from "bun:test";

import {
  createInMemoryAccounts,
  parseCounter,
  type EligibilityRequest,
} from "../../src/index";
import { AccountsCatalog } from "../../src/domain/catalog";
import { transitionEntity } from "../../src/domain/state";
import { InMemoryAccountsRepository } from "../../src/storage/memory";
import {
  C1,
  NOW,
  clock,
  makeFixtureGraph,
  mutationContext,
  seedActiveCatalog,
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
    const catalog = createInMemoryAccounts({ clock });
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
    expect(Object.keys(result)).not.toContain("holder");
    expect(Object.keys(result)).not.toContain("leaseId");
    expect(after).toEqual(before);
    await catalog.close();
  });

  test.each(["api_key", "workload_identity"] as const)(
    "supports brokered %s transport without an AuthCapsule",
    async (transport) => {
      const catalog = createInMemoryAccounts({ clock });
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
    const catalog = createInMemoryAccounts({ clock });
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
    const repository = new InMemoryAccountsRepository();
    const catalog = new AccountsCatalog(repository, clock);
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
    const catalog = createInMemoryAccounts({ clock: () => new Date(observed) });
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
    const repository = new InMemoryAccountsRepository();
    const catalog = new AccountsCatalog(repository, clock);
    const graph = makeFixtureGraph();
    await repository.close();
    const result = await catalog.eligibility(requestFor(graph.method.id));
    expect(result.eligible).toBe(false);
    expect(result.reasonCodes).toEqual(["DEPENDENCY_UNAVAILABLE"]);
  });

  test("native mutation remains unavailable after metadata drain", async () => {
    const catalog = createInMemoryAccounts({ clock });
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
});
