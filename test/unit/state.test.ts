import { describe, expect, test } from "bun:test";

import {
  AccountsError,
  assertTransition,
  incrementCounter,
  newCredentialBindingId,
  validateNativeReauthenticationCandidate,
  validateRoutineNativeRefreshCandidate,
  type AccessMethod,
  type AuthCapsule,
  type CredentialBinding,
} from "../../src/index";
import { transitionEntity } from "../../src/domain/state";
import { C0, C1, CREATED_AT, FUTURE, makeFixtureGraph, NOW } from "../fixtures";

describe("closed lifecycle state machines", () => {
  test("accepts frozen edges and rejects terminal revival", () => {
    expect(() => assertTransition("account", "pending", "active")).not.toThrow();
    expect(() => assertTransition("credential_binding", "active", "retiring")).not.toThrow();
    expect(() => assertTransition("credential_binding", "retiring", "revoked")).not.toThrow();
    expect(() => assertTransition("credential_binding", "retiring", "active")).toThrow(
      expect.objectContaining({ code: "INVALID_TRANSITION" }),
    );
    expect(() => assertTransition("auth_capsule", "revoked", "ready")).toThrow(AccountsError);
    expect(() => assertTransition("capacity_pool", "retired", "active")).toThrow(AccountsError);
  });

  test("capacity drain advances deny and capacity generations before mutation", () => {
    const pool = makeFixtureGraph().pool;
    const active = transitionEntity("capacity_pool", pool, "active", NOW.toISOString());
    const draining = transitionEntity(
      "capacity_pool",
      active,
      "draining",
      new Date(NOW.getTime() + 1).toISOString(),
    );
    expect(draining.denyState).toBe("denied");
    expect(String(draining.denyGeneration)).toBe("1");
    expect(String(draining.capacityGeneration)).toBe("2");

    const denied = transitionEntity(
      "capacity_pool",
      draining,
      "denied",
      new Date(NOW.getTime() + 2).toISOString(),
    );
    const pending = transitionEntity(
      "capacity_pool",
      denied,
      "pending",
      new Date(NOW.getTime() + 3).toISOString(),
    );
    expect(pending.denyState).toBe("denied");
    expect(BigInt(pending.denyGeneration)).toBeGreaterThanOrEqual(BigInt(denied.denyGeneration));
  });
});

describe("native metadata candidate fencing", () => {
  const graph = makeFixtureGraph();
  const method = { ...graph.readyMethod, status: "draining" } satisfies AccessMethod;
  const activePool = transitionEntity("capacity_pool", graph.pool, "active", NOW.toISOString());
  const pool = transitionEntity(
    "capacity_pool",
    activePool,
    "draining",
    new Date(NOW.getTime() + 1).toISOString(),
  );
  const beforeCapsule = {
    ...graph.capsule!,
    status: "bootstrapping",
    revision: C1,
    updatedAt: NOW.toISOString(),
  } satisfies AuthCapsule;
  const beforeBinding = {
    ...graph.binding,
    status: "active",
    revision: C1,
    updatedAt: NOW.toISOString(),
  } satisfies CredentialBinding;

  test("routine refresh keeps generations fixed and CAS-advances only auth state", () => {
    const updatedAt = new Date(NOW.getTime() + 1).toISOString();
    const afterCapsule = {
      ...beforeCapsule,
      authStateRevision: C1,
      revision: incrementCounter(beforeCapsule.revision),
      updatedAt,
    };
    const afterBinding = {
      ...beforeBinding,
      authStateRevision: C1,
      revision: incrementCounter(beforeBinding.revision),
      updatedAt,
    };
    expect(() =>
      validateRoutineNativeRefreshCandidate(
        method,
        pool,
        beforeCapsule,
        afterCapsule,
        beforeBinding,
        afterBinding,
      ),
    ).not.toThrow();

    expect(() =>
      validateRoutineNativeRefreshCandidate(
        method,
        pool,
        beforeCapsule,
        { ...afterCapsule, placementGeneration: incrementCounter(afterCapsule.placementGeneration) },
        beforeBinding,
        afterBinding,
      ),
    ).toThrow(expect.objectContaining({ code: "STALE_AUTH_STATE_REVISION" }));
  });

  test("reauth advances capsule and credential generation together without changing lineage", () => {
    const retiring = { ...beforeBinding, status: "retiring" } satisfies CredentialBinding;
    const replacement = {
      ...beforeBinding,
      id: newCredentialBindingId(NOW.getTime() + 50),
      status: "pending",
      credentialGeneration: C1,
      authStateRevision: C0,
      revision: C0,
      createdAt: new Date(NOW.getTime() + 2).toISOString(),
      updatedAt: new Date(NOW.getTime() + 2).toISOString(),
      expiresAt: FUTURE,
    } satisfies CredentialBinding;
    const afterCapsule = {
      ...beforeCapsule,
      authGeneration: C1,
      authStateRevision: C0,
      revision: incrementCounter(beforeCapsule.revision),
      updatedAt: new Date(NOW.getTime() + 2).toISOString(),
    };
    expect(() =>
      validateNativeReauthenticationCandidate(
        method,
        pool,
        beforeCapsule,
        afterCapsule,
        retiring,
        replacement,
      ),
    ).not.toThrow();

    expect(() =>
      validateNativeReauthenticationCandidate(
        method,
        pool,
        beforeCapsule,
        afterCapsule,
        retiring,
        { ...replacement, policyDigest: `sha256:${"e".repeat(64)}` },
      ),
    ).toThrow(expect.objectContaining({ code: "STALE_CREDENTIAL_GENERATION" }));
  });

  test("draining metadata alone never exposes a native execution command", () => {
    expect(Object.keys(method)).not.toContain("resourceLeaseId");
    expect(Object.keys(pool)).not.toContain("holder");
    expect(CREATED_AT).not.toBe("");
  });
});
