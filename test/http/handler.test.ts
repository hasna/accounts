import { describe, expect, test } from "bun:test";

import { createAccountsHttpHandler } from "../../src/http/handler";
import { ACCOUNTS_CAPACITY_OPENAPI } from "../../src/http/openapi";
import {
  MemoryBootstrapIntentStore,
  MemoryHttpIdempotencyStore,
} from "../../src/http/stores";
import type {
  AccountsAuthenticatedPrincipal,
  AccountsHttpScope,
  CatalogHttpService,
} from "../../src/http/types";
import {
  newAccountEventId,
  newEligibilityEvidenceId,
  parseCounter,
  type EntityKind,
  type EntityMap,
  type EligibilityRequest,
  type SlotEligibilityMetadata,
} from "../../src/index";
import { makeFixtureGraph, ACTOR_REF, CREATED_AT, FUTURE, NOW, digest } from "../fixtures";

const CONTRACT_SHA = "07b636588973646b6c3745690908d92d2daa64ce47f1c6bf90498f2d4ccffd2e";
const OTHER_OWNER = "principal:human:hasna:owner-b";

class FakeCatalog implements CatalogHttpService {
  readonly records = new Map<EntityKind, EntityMap[EntityKind][]>([
    ["account", []],
    ["entitlement", []],
    ["capacity_pool", []],
    ["access_method", []],
    ["auth_capsule", []],
    ["credential_binding", []],
  ]);

  async get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K]> {
    const record = this.records.get(kind)!.find((candidate) => candidate.id === id);
    if (record === undefined) {
      const { AccountsError } = await import("../../src/errors");
      throw new AccountsError("NOT_FOUND", "not found");
    }
    return record as EntityMap[K];
  }

  async list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    return this.records.get(kind)! as EntityMap[K][];
  }

  async add<K extends EntityKind>(kind: K, record: EntityMap[K]) {
    this.records.get(kind)!.push(record as EntityMap[EntityKind]);
    return { record, eventId: newAccountEventId(NOW.getTime() + 900), replayed: false };
  }

  async eligibility(request: EligibilityRequest): Promise<SlotEligibilityMetadata> {
    return {
      schemaVersion: "accounts.slot-eligibility.v1",
      evidenceId: newEligibilityEvidenceId(NOW.getTime() + 901),
      evidenceClass: "local_diagnostic",
      authority: "none",
      reservation: "none",
      accessMethodId: request.accessMethodId,
      accessTarget: { kind: "unresolved" },
      eligibilityRequestDigest: digest("e"),
      issuedAt: CREATED_AT,
      expiresAt: FUTURE,
      eligible: false,
      reasonCodes: ["ACCOUNT_NOT_ACTIVE"],
      recordRevisionSet: {},
    };
  }

  async doctor() {
    return {
      adapter: "memory" as const,
      schemaVersion: "accounts.capacity.v1",
      migrationChecksum: digest("1"),
      foreignKeys: "not_applicable" as const,
      journalMode: "memory" as const,
      integrity: "ok" as const,
      readiness: "ready" as const,
      recoveryFrontier: {
        catalogIncarnation: "catalog:test",
        sequence: parseCounter("1"),
        hash: digest("2"),
        signatureDigest: digest("3"),
      },
      recoveryHold: false,
      positiveEligibility: true,
    };
  }
}

function principal(
  ownerRef = ACTOR_REF,
  scopes: readonly AccountsHttpScope[] = ["accounts:read"],
  overrides: Partial<AccountsAuthenticatedPrincipal> = {},
): AccountsAuthenticatedPrincipal {
  return {
    actorRef: ownerRef,
    subjectRef: ownerRef,
    issuer: "authority:identities",
    audience: "accounts-capacity-public",
    scopes: new Set(scopes),
    authorizedOwnerRefs: new Set([ownerRef]),
    ...overrides,
  };
}

function handlerFor(
  catalog: FakeCatalog,
  authenticated = principal(),
  overrides: Partial<Parameters<typeof createAccountsHttpHandler>[0]> = {},
) {
  return createAccountsHttpHandler({
    deployment: {
      mode: "self_hosted",
      identityRealm: "hasna",
      organizationRef: "organization:hasna",
      publicAudience: "accounts-capacity-public",
      internalAudience: "accounts-capacity-internal",
      allowedIssuers: new Set(["authority:identities"]),
    },
    authenticator: {
      authenticate: async (_request, expectedAudience) => ({
        ...authenticated,
        audience: authenticated.audience === "dynamic" ? expectedAudience : authenticated.audience,
      }),
    },
    catalog,
    packageVersion: "1.0.0-test",
    contractSha256: CONTRACT_SHA,
    openApiDocument: ACCOUNTS_CAPACITY_OPENAPI,
    now: () => new Date(NOW),
    ...overrides,
  });
}

function jsonRequest(path: string, body: unknown, init: RequestInit = {}): Request {
  return new Request(`https://accounts.capacity.hasna.internal${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
    body: JSON.stringify(body),
    ...init,
  });
}

describe("Accounts capacity HTTP boundary", () => {
  test("serves only safe unauthenticated diagnostics and the frozen capacity OpenAPI", async () => {
    const catalog = new FakeCatalog();
    const handler = handlerFor(catalog);
    const health = await handler(new Request("https://accounts.capacity.hasna.internal/health"));
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ schemaVersion: "accounts.health.v1", status: "ok" });

    const openapi = await handler(new Request("https://accounts.capacity.hasna.internal/openapi.json"));
    const source = await openapi.text();
    expect(openapi.status).toBe(200);
    expect(source).not.toContain("provider-login");
    expect(source).not.toContain("device-code");
    expect(source).not.toContain("/lease");
  });

  test("derives actor/audience from authentication and rejects wrong issuer or audience", async () => {
    const catalog = new FakeCatalog();
    const wrongAudience = handlerFor(catalog, principal(ACTOR_REF, ["accounts:read"], { audience: "legacy-profile" }));
    expect((await wrongAudience(new Request("https://accounts.capacity.hasna.internal/v1/provider-accounts"))).status).toBe(403);

    const wrongIssuer = handlerFor(catalog, principal(ACTOR_REF, ["accounts:read"], { issuer: "authority:legacy" }));
    expect((await wrongIssuer(new Request("https://accounts.capacity.hasna.internal/v1/provider-accounts"))).status).toBe(403);
  });

  test("owner-filters list responses and redacts provider subjects", async () => {
    const catalog = new FakeCatalog();
    const graph = makeFixtureGraph("api_key");
    catalog.records.get("account")!.push(graph.activeAccount);
    catalog.records.get("account")!.push({
      ...makeFixtureGraph("api_key", 20).activeAccount,
      ownerRef: OTHER_OWNER,
    });
    const handler = handlerFor(catalog);
    const response = await handler(new Request("https://accounts.capacity.hasna.internal/v1/provider-accounts"));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body.records).toHaveLength(1);
    expect(body.records[0].ownerRef).toBe(ACTOR_REF);
    expect(body.records[0].providerSubjectRef).toBeUndefined();
    expect(body.records[0].providerSubjectRefRedacted).toBe(true);
  });

  test("creates only a closed pending account and rejects a caller actor claim", async () => {
    const catalog = new FakeCatalog();
    const handler = handlerFor(
      catalog,
      principal(ACTOR_REF, ["accounts:write"]),
      { idempotency: new MemoryHttpIdempotencyStore() },
    );
    const body = {
      schemaVersion: "accounts.provider-account.create.v1",
      providerKey: "openai",
      ownerRef: ACTOR_REF,
      displayLabel: "Owner account",
    };
    const response = await handler(jsonRequest("/v1/provider-accounts", body, {
      headers: { "content-type": "application/json", "idempotency-key": "account-create-1" },
    }));
    expect(response.status).toBe(201);
    expect((await response.json()).data).toMatchObject({ status: "pending", revision: "0" });

    const forged = await handler(jsonRequest("/v1/provider-accounts", { ...body, actorRef: OTHER_OWNER }, {
      headers: { "content-type": "application/json", "idempotency-key": "account-create-2" },
    }));
    expect(forged.status).toBe(400);
    expect(catalog.records.get("account")).toHaveLength(1);
  });

  test("capacity query is owner-bound and remains explicitly non-reservational", async () => {
    const catalog = new FakeCatalog();
    const graph = makeFixtureGraph("api_key");
    catalog.records.get("account")!.push(graph.account);
    catalog.records.get("entitlement")!.push(graph.entitlement);
    catalog.records.get("capacity_pool")!.push(graph.pool);
    catalog.records.get("access_method")!.push(graph.method);
    const handler = handlerFor(catalog);
    const response = await handler(jsonRequest("/v1/capacity/query", {
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    }));
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(body.reservation).toBe("none");
    expect(body.data.reservation).toBe("none");
    expect(body.data).not.toHaveProperty("leaseId");
  });

  test("bootstrap endpoint creates inert metadata only and has no consume route", async () => {
    const catalog = new FakeCatalog();
    const graph = makeFixtureGraph("native_session");
    const capsule = {
      ...graph.capsule!,
      refreshOwnerRef: ACTOR_REF,
      refreshMode: "interactive_owner" as const,
    };
    catalog.records.get("account")!.push(graph.account);
    catalog.records.get("entitlement")!.push(graph.entitlement);
    catalog.records.get("capacity_pool")!.push(graph.pool);
    catalog.records.get("access_method")!.push(graph.method);
    catalog.records.get("auth_capsule")!.push(capsule);
    const handler = handlerFor(
      catalog,
      principal(ACTOR_REF, ["accounts:capsules:bootstrap-intent"]),
      {
        idempotency: new MemoryHttpIdempotencyStore(),
        bootstrapIntents: new MemoryBootstrapIntentStore(),
      },
    );
    const response = await handler(jsonRequest(
      `/v1/auth-capsules/${capsule.id}/bootstrap-intents`,
      { schemaVersion: "accounts.bootstrap-intent.create.v1", reasonCode: "OWNER_BOOTSTRAP" },
      {
        headers: {
          "content-type": "application/json",
          "idempotency-key": "bootstrap-1",
          "if-match": '"0"',
        },
      },
    ));
    const body = await response.json();
    expect(response.status).toBe(201);
    expect(body).toMatchObject({ status: "pending", authCapsuleId: capsule.id });
    expect(JSON.stringify(body)).not.toMatch(/device|code|provider|credential/i);

    const consume = await handler(jsonRequest(
      `/v1/auth-capsules/${capsule.id}/bootstrap-intents/${body.id}/consume`,
      {},
    ));
    expect(consume.status).toBe(404);
  });

  test("rejects native credential-operation requests before calling an effect service", async () => {
    const catalog = new FakeCatalog();
    const graph = makeFixtureGraph("native_session");
    catalog.records.get("account")!.push(graph.account);
    catalog.records.get("entitlement")!.push(graph.entitlement);
    catalog.records.get("capacity_pool")!.push(graph.pool);
    catalog.records.get("access_method")!.push(graph.method);
    catalog.records.get("credential_binding")!.push(graph.binding);
    let called = false;
    const handler = handlerFor(
      catalog,
      principal(ACTOR_REF, ["accounts:credentials:request"]),
      {
        idempotency: new MemoryHttpIdempotencyStore(),
        credentialOperations: {
          request: async () => {
            called = true;
            throw new Error("must not run");
          },
          get: async () => undefined,
          list: async () => [],
        },
      },
    );
    const response = await handler(jsonRequest("/v1/credential-operations", {
      schemaVersion: "accounts.credential-operation.request.v1",
      kind: "rotation",
      credentialBindingId: graph.binding.id,
      expectedRevision: "0",
      reasonCode: "ROTATE",
    }, {
      headers: { "content-type": "application/json", "idempotency-key": "native-rotate-1" },
    }));
    expect(response.status).toBe(422);
    expect(called).toBe(false);
  });
});
