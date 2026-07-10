import { createHash } from "node:crypto";

import { parseCounter, type Counter } from "../domain/counter";
import {
  generateUuidV7,
  newAccessMethodId,
  newAccountId,
  newEntitlementId,
  parseAccessMethodId,
  parseAccountId,
  parseAuthCapsuleId,
  parseCapacityPoolId,
  parseCredentialBindingId,
  parseCredentialOperationId,
  parseEntitlementId,
} from "../domain/ids";
import type {
  Account,
  AccessMethod,
  CredentialBinding,
  EntityKind,
  EntityMap,
  Entitlement,
} from "../domain/models";
import { AccountsError, asAccountsError, toErrorEnvelope } from "../errors";
import { validateEligibilityRequest, validateEntity } from "../serialization/dto";
import {
  assertNoSensitiveFields,
  canonicalJson,
  canonicalSha256,
  parseClosedJson,
} from "../serialization/json";
import type { MutationContext } from "../storage/repository";
import {
  ACCOUNTS_HTTP_SCOPES,
  HTTP_ENTITY_ROUTES,
  type AccountsAuthenticatedPrincipal,
  type AccountsHttpHandlerOptions,
  type AccountsHttpScope,
  type HttpEntityRoute,
  type StoredHttpResponse,
} from "./types";

type JsonObject = Record<string, unknown>;

const JSON_HEADERS = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
});
const OWNER_PATTERN = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CURSOR_PATTERN = /^[A-Za-z0-9_-]{48}$/;

export type AccountsHttpHandler = (request: Request) => Promise<Response>;

export function createAccountsHttpHandler(options: AccountsHttpHandlerOptions): AccountsHttpHandler {
  validateDeployment(options);
  const now = options.now ?? (() => new Date());

  return async (request: Request): Promise<Response> => {
    const requestId = generateUuidV7(now().getTime());
    try {
      if (request.signal.aborted) throw abortError();
      const url = new URL(request.url);
      rejectCredentialBearingUrl(url);
      const path = normalizePath(url.pathname);

      if (request.method === "GET" && path === "/health") {
        return jsonResponse(200, {
          schemaVersion: "accounts.health.v1",
          status: "ok",
        });
      }
      if (request.method === "GET" && path === "/version") {
        return jsonResponse(200, {
          schemaVersion: "accounts.version.v1",
          version: options.packageVersion,
          contractSha256: options.contractSha256,
        });
      }
      if (request.method === "GET" && path === "/openapi.json") {
        return jsonResponse(200, options.openApiDocument);
      }
      if (request.method === "GET" && path === "/ready") {
        const doctor = await options.catalog.doctor();
        if (doctor.readiness !== "ready" || doctor.recoveryHold || !doctor.positiveEligibility) {
          return jsonResponse(503, {
            schemaVersion: "accounts.readiness.v1",
            status: "not_ready",
          });
        }
        return jsonResponse(200, {
          schemaVersion: "accounts.readiness.v1",
          status: "ready",
        });
      }

      const internal = path.startsWith("/internal/");
      const audience = internal
        ? options.deployment.internalAudience
        : options.deployment.publicAudience;
      const principal = await authenticate(request, audience, options);

      if (internal) {
        return await handleInternal(request, path, principal, options);
      }

      if (path === "/v1/capacity/query") {
        requireMethod(request, "POST");
        requireScope(principal, "accounts:read");
        const body = await readJsonObject(request);
        exactKeys(
          body,
          [
            "accessMethodId",
            "operation",
            "model",
            "dataClassification",
            "destinationPolicyClass",
          ],
        );
        const eligibilityRequest = validateEligibilityRequest(body);
        const ownerRef = await ownerForEntity(
          options,
          "access_method",
          eligibilityRequest.accessMethodId,
        );
        requireOwner(principal, ownerRef);
        const result = await options.catalog.eligibility(eligibilityRequest);
        // This public route is diagnostic evidence only and never a reservation or lease.
        if (result.evidenceClass !== "local_diagnostic" || result.reservation !== "none") {
          throw new AccountsError("POLICY_DENIED", "Capacity query returned an unsafe evidence class");
        }
        return jsonResponse(200, {
          schemaVersion: "accounts.capacity-query.v1",
          reservation: "none",
          data: result,
        });
      }

      const bootstrapMatch = /^\/v1\/auth-capsules\/([^/]+)\/bootstrap-intents(?:\/([^/]+))?$/.exec(path);
      if (bootstrapMatch !== null) {
        return await handleBootstrapIntent(
          request,
          parseAuthCapsuleId(bootstrapMatch[1]),
          bootstrapMatch[2],
          principal,
          options,
          now,
        );
      }

      if (path === "/v1/credential-operations" || path.startsWith("/v1/credential-operations/")) {
        return await handleCredentialOperations(request, path, principal, options);
      }

      const resourceMatch = /^\/v1\/([^/]+)(?:\/([^/]+))?$/.exec(path);
      if (resourceMatch !== null && Object.hasOwn(HTTP_ENTITY_ROUTES, resourceMatch[1]!)) {
        const route = resourceMatch[1] as HttpEntityRoute;
        const kind = HTTP_ENTITY_ROUTES[route];
        if (request.method === "GET") {
          requireScope(principal, "accounts:read");
          if (resourceMatch[2] === undefined) {
            return await listEntities(request, route, kind, principal, options);
          }
          return await getEntity(kind, resourceMatch[2], principal, options);
        }
        if (request.method === "POST" && resourceMatch[2] === undefined) {
          return await createPendingEntity(request, route, principal, options, now);
        }
        throw methodNotAllowed();
      }

      throw new AccountsError("NOT_FOUND", "Route not found");
    } catch (error) {
      if (isAbort(error)) {
        return errorResponse(new AccountsError("DEPENDENCY_UNAVAILABLE", "Request aborted"), requestId, 503);
      }
      const safe = asAccountsError(error);
      return errorResponse(safe, requestId, statusForError(safe));
    }
  };
}

function validateDeployment(options: AccountsHttpHandlerOptions): void {
  const deployment = options.deployment;
  if (deployment.mode !== "self_hosted") {
    throw new AccountsError("VALIDATION_FAILED", "HTTP requires explicit self_hosted deployment", {
      details: { field: "deployment.mode" },
    });
  }
  for (const [field, value] of [
    ["identityRealm", deployment.identityRealm],
    ["organizationRef", deployment.organizationRef],
    ["publicAudience", deployment.publicAudience],
    ["internalAudience", deployment.internalAudience],
  ] as const) {
    if (!REFERENCE_PATTERN.test(value)) {
      throw new AccountsError("VALIDATION_FAILED", "HTTP deployment identifier is invalid", {
        details: { field: `deployment.${field}` },
      });
    }
  }
  if (deployment.identityRealm !== "hasna") {
    throw new AccountsError("VALIDATION_FAILED", "Outside-realm HTTP deployment is forbidden", {
      details: { field: "deployment.identityRealm" },
    });
  }
  if (
    deployment.publicAudience === deployment.internalAudience ||
    deployment.allowedIssuers.size === 0
  ) {
    throw new AccountsError("VALIDATION_FAILED", "HTTP audiences and issuers are invalid", {
      details: { field: "deployment.audience" },
    });
  }
  for (const issuer of deployment.allowedIssuers) {
    if (!REFERENCE_PATTERN.test(issuer)) {
      throw new AccountsError("VALIDATION_FAILED", "HTTP issuer is invalid", {
        details: { field: "deployment.allowedIssuers" },
      });
    }
  }
  if (!/^[0-9a-f]{64}$/.test(options.contractSha256)) {
    throw new AccountsError("VALIDATION_FAILED", "Contract digest is invalid", {
      details: { field: "contractSha256" },
    });
  }
}

async function authenticate(
  request: Request,
  audience: string,
  options: AccountsHttpHandlerOptions,
): Promise<AccountsAuthenticatedPrincipal> {
  const principal = await options.authenticator.authenticate(request, audience);
  if (principal === undefined) throw new AccountsError("FORBIDDEN", "Authentication is required");
  if (
    !options.deployment.allowedIssuers.has(principal.issuer) ||
    principal.audience !== audience ||
    !OWNER_PATTERN.test(principal.actorRef) ||
    !OWNER_PATTERN.test(principal.subjectRef)
  ) {
    throw new AccountsError("FORBIDDEN", "Authentication context is not accepted");
  }
  if (principal.authorizedOwnerRefs.size === 0) {
    throw new AccountsError("FORBIDDEN", "No owner authorization is present");
  }
  for (const ownerRef of principal.authorizedOwnerRefs) {
    if (!OWNER_PATTERN.test(ownerRef)) throw new AccountsError("FORBIDDEN", "Owner authorization is invalid");
  }
  const allowedScopes = new Set<string>(ACCOUNTS_HTTP_SCOPES);
  for (const scope of principal.scopes) {
    if (!allowedScopes.has(scope)) throw new AccountsError("FORBIDDEN", "Unknown scope is forbidden");
  }
  return principal;
}

async function listEntities<K extends EntityKind>(
  request: Request,
  route: HttpEntityRoute,
  kind: K,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<Response> {
  const url = new URL(request.url);
  rejectUnknownQuery(url, new Set(["cursor", "limit"]));
  const limit = parseLimit(url.searchParams.get("limit"));
  const cursor = decodeCursor(url.searchParams.get("cursor"));
  const all = [...(await options.catalog.list(kind))].sort((left, right) =>
    String(left.id).localeCompare(String(right.id)),
  );
  const visible: EntityMap[K][] = [];
  for (const record of all) {
    if (cursor !== undefined && String(record.id) <= cursor) continue;
    const ownerRef = await ownerForRecord(options, kind, record);
    if (!principal.authorizedOwnerRefs.has(ownerRef)) continue;
    visible.push(record);
    if (visible.length === limit + 1) break;
  }
  const hasMore = visible.length > limit;
  const page = visible.slice(0, limit).map((record) => redactEntity(kind, record));
  const last = page.at(-1) as { readonly id?: unknown } | undefined;
  return jsonResponse(200, {
    schemaVersion: "accounts.list.v1",
    kind,
    records: page,
    nextCursor: hasMore && typeof last?.id === "string" ? encodeCursor(last.id) : null,
    route: `/v1/${route}`,
  });
}

async function getEntity<K extends EntityKind>(
  kind: K,
  rawId: string,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<Response> {
  const id = parseEntityId(kind, rawId);
  const record = await options.catalog.get(kind, id);
  requireOwner(principal, await ownerForRecord(options, kind, record));
  return jsonResponse(200, {
    schemaVersion: "accounts.record.v1",
    kind,
    data: redactEntity(kind, record),
  });
}

async function createPendingEntity(
  request: Request,
  route: HttpEntityRoute,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
  now: () => Date,
): Promise<Response> {
  requireScope(principal, "accounts:write");
  if (route === "capacity-pools" || route === "credential-bindings" || route === "auth-capsules") {
    throw methodNotAllowed();
  }
  if (options.catalog.add === undefined || options.idempotency === undefined) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Durable mutation service is unavailable");
  }
  const idempotencyKey = requireIdempotencyKey(request);
  const body = await readJsonObject(request);
  const requestDigest = canonicalSha256(body);
  const timestamp = now().toISOString();
  const routePath = `/v1/${route}`;
  const stored = await options.idempotency.execute(
    {
      actorRef: principal.actorRef,
      audience: principal.audience,
      method: request.method,
      route: routePath,
      key: idempotencyKey,
      requestDigest,
    },
    async (): Promise<StoredHttpResponse> => {
      let result: Awaited<ReturnType<NonNullable<typeof options.catalog.add>>>;
      const context = mutationContext(principal, idempotencyKey, routePath, requestDigest, "CREATE");
      if (route === "provider-accounts") {
        const record = parseProviderAccountCreate(body, timestamp, principal);
        result = await options.catalog.add!("account", record, context);
      } else if (route === "entitlements") {
        const record = await parseEntitlementCreate(body, timestamp, principal, options);
        result = await options.catalog.add!("entitlement", record, context);
      } else {
        const record = await parseLaneCreate(body, timestamp, principal, options);
        result = await options.catalog.add!("access_method", record, context);
      }
      const responseBody = canonicalJson({
        schemaVersion: "accounts.mutation-result.v1",
        kind: HTTP_ENTITY_ROUTES[route],
        data: redactEntity(HTTP_ENTITY_ROUTES[route], result.record as never),
        eventId: result.eventId,
        replayed: result.replayed,
      });
      return { status: 201, body: responseBody };
    },
  );
  return responseFromStored(stored);
}

function parseProviderAccountCreate(
  body: JsonObject,
  timestamp: string,
  principal: AccountsAuthenticatedPrincipal,
): Account {
  exactKeys(
    body,
    ["schemaVersion", "providerKey", "ownerRef", "displayLabel"],
    ["providerSubjectCandidateRef", "providerDisplayHint"],
  );
  literal(body.schemaVersion, "accounts.provider-account.create.v1", "schemaVersion");
  const ownerRef = owner(body.ownerRef, "ownerRef");
  requireOwner(principal, ownerRef);
  const candidate: Account = {
    id: newAccountId(Date.parse(timestamp)),
    providerKey: reference(body.providerKey, "providerKey", /^[a-z0-9][a-z0-9._-]{0,63}$/),
    ownerRef,
    displayLabel: boundedString(body.displayLabel, "displayLabel", 128),
    ...(body.providerSubjectCandidateRef === undefined
      ? {}
      : { providerSubjectCandidateRef: reference(body.providerSubjectCandidateRef, "providerSubjectCandidateRef") }),
    ...(body.providerDisplayHint === undefined
      ? {}
      : { providerDisplayHint: boundedString(body.providerDisplayHint, "providerDisplayHint", 128) }),
    status: "pending",
    revision: parseCounter("0"),
    createdAt: timestamp,
    updatedAt: timestamp,
  };
  return validateEntity("account", candidate);
}

async function parseEntitlementCreate(
  body: JsonObject,
  timestamp: string,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<Entitlement> {
  exactKeys(body, ["schemaVersion", "providerAccountId", "fundingKind"]);
  literal(body.schemaVersion, "accounts.entitlement.create.v1", "schemaVersion");
  const accountId = parseAccountId(body.providerAccountId);
  requireOwner(principal, await ownerForEntity(options, "account", accountId));
  const fundingKind = enumString(
    body.fundingKind,
    ["subscription", "metered", "credit", "contract", "externally_managed"] as const,
    "fundingKind",
  );
  return validateEntity("entitlement", {
    id: newEntitlementId(Date.parse(timestamp)),
    accountId,
    fundingKind,
    status: "pending",
    revision: parseCounter("0"),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

async function parseLaneCreate(
  body: JsonObject,
  timestamp: string,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<AccessMethod> {
  exactKeys(body, [
    "schemaVersion",
    "entitlementId",
    "capacityPoolId",
    "adapterKey",
    "adapterVersion",
    "accessTransport",
  ]);
  literal(body.schemaVersion, "accounts.account-lane.create.v1", "schemaVersion");
  const entitlementId = parseEntitlementId(body.entitlementId);
  const capacityPoolId = parseCapacityPoolId(body.capacityPoolId);
  const [entitlementOwner, poolOwner] = await Promise.all([
    ownerForEntity(options, "entitlement", entitlementId),
    ownerForEntity(options, "capacity_pool", capacityPoolId),
  ]);
  requireOwner(principal, entitlementOwner);
  requireOwner(principal, poolOwner);
  if (entitlementOwner !== poolOwner) throw new AccountsError("FORBIDDEN", "Cross-owner lane is forbidden");
  return validateEntity("access_method", {
    id: newAccessMethodId(Date.parse(timestamp)),
    entitlementId,
    capacityPoolId,
    adapterKey: reference(body.adapterKey, "adapterKey", /^[a-z0-9][a-z0-9._-]{0,63}$/),
    adapterVersion: reference(body.adapterVersion, "adapterVersion"),
    accessTransport: enumString(
      body.accessTransport,
      ["native_session", "api_key", "workload_identity"] as const,
      "accessTransport",
    ),
    status: "draft",
    revision: parseCounter("0"),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

async function handleBootstrapIntent(
  request: Request,
  capsuleId: ReturnType<typeof parseAuthCapsuleId>,
  rawIntentId: string | undefined,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
  now: () => Date,
): Promise<Response> {
  requireScope(principal, "accounts:capsules:bootstrap-intent");
  const store = options.bootstrapIntents;
  if (store === undefined) throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Bootstrap intent store is unavailable");
  const capsule = await options.catalog.get("auth_capsule", capsuleId);
  requireOwner(principal, capsule.ownerRef);

  if (request.method === "GET" && rawIntentId !== undefined) {
    if (!/^[0-9a-f-]{36}$/.test(rawIntentId)) throw new AccountsError("NOT_FOUND", "Intent not found");
    const intent = await store.get(capsuleId, rawIntentId);
    if (intent === undefined || intent.ownerRef !== capsule.ownerRef) {
      throw new AccountsError("NOT_FOUND", "Intent not found");
    }
    return jsonResponse(200, intent);
  }
  if (request.method !== "POST" || rawIntentId !== undefined) throw methodNotAllowed();
  if (options.idempotency === undefined) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Durable idempotency store is unavailable");
  }
  if (capsule.status === "revoked" || capsule.refreshMode !== "interactive_owner") {
    throw new AccountsError("CAPSULE_NOT_READY", "Capsule does not allow an interactive bootstrap intent");
  }
  if (!principal.actorRef.startsWith("principal:human:hasna:") || principal.actorRef !== capsule.ownerRef) {
    throw new AccountsError("FORBIDDEN", "Bootstrap intent requires the authenticated human owner");
  }
  const expectedRevision = requireIfMatch(request);
  if (expectedRevision !== capsule.revision) {
    throw new AccountsError("STALE_REVISION", "Capsule revision changed", {
      details: {
        aggregateKind: "auth_capsule",
        aggregateId: capsule.id,
        expectedRevision,
        actualRevision: capsule.revision,
      },
    });
  }
  const idempotencyKey = requireIdempotencyKey(request);
  const body = await readJsonObject(request);
  exactKeys(body, ["schemaVersion", "reasonCode"]);
  literal(body.schemaVersion, "accounts.bootstrap-intent.create.v1", "schemaVersion");
  const reasonCode = reason(body.reasonCode);
  const requestDigest = canonicalSha256({ body, expectedRevision });
  const route = `/v1/auth-capsules/${capsule.id}/bootstrap-intents`;
  const stored = await options.idempotency.execute(
    {
      actorRef: principal.actorRef,
      audience: principal.audience,
      method: request.method,
      route,
      key: idempotencyKey,
      requestDigest,
    },
    async () => {
      const intent = await store.create({
        principal,
        capsule,
        idempotencyKey,
        reasonCode,
        requestDigest,
        now: now().toISOString(),
      });
      return { status: 201, body: canonicalJson(intent) };
    },
  );
  return responseFromStored(stored);
}

async function handleCredentialOperations(
  request: Request,
  path: string,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<Response> {
  const service = options.credentialOperations;
  if (service === undefined) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Credential operation intent service is unavailable");
  }
  if (request.method === "GET") {
    requireScope(principal, "accounts:read");
    const idMatch = /^\/v1\/credential-operations\/([^/]+)$/.exec(path);
    if (idMatch !== null) {
      const operation = await service.get(parseCredentialOperationId(idMatch[1]));
      if (operation === undefined) throw new AccountsError("NOT_FOUND", "Credential operation not found");
      const bindingId = operation.sourceBindingId ?? operation.targetBindingId;
      if (bindingId === undefined) throw new AccountsError("NOT_FOUND", "Credential operation not found");
      requireOwner(principal, await ownerForEntity(options, "credential_binding", bindingId));
      return jsonResponse(200, {
        schemaVersion: "accounts.credential-operation.v1",
        data: operation,
      });
    }
    if (path !== "/v1/credential-operations") throw new AccountsError("NOT_FOUND", "Route not found");
    const records = (
      await Promise.all([...principal.authorizedOwnerRefs].map((ownerRef) => service.list(ownerRef)))
    )
      .flat()
      .sort((left, right) => String(left.id).localeCompare(String(right.id)));
    return jsonResponse(200, {
      schemaVersion: "accounts.credential-operation-list.v1",
      records,
    });
  }
  if (request.method !== "POST" || path !== "/v1/credential-operations") throw methodNotAllowed();
  requireScope(principal, "accounts:credentials:request");
  if (options.idempotency === undefined) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Durable idempotency store is unavailable");
  }
  const idempotencyKey = requireIdempotencyKey(request);
  const body = await readJsonObject(request);
  exactKeys(body, [
    "schemaVersion",
    "kind",
    "credentialBindingId",
    "expectedRevision",
    "reasonCode",
  ]);
  literal(body.schemaVersion, "accounts.credential-operation.request.v1", "schemaVersion");
  const kind = enumString(body.kind, ["rotation", "revocation"] as const, "kind");
  const bindingId = parseCredentialBindingId(body.credentialBindingId);
  const expectedRevision = parseCounter(body.expectedRevision, "expectedRevision");
  const reasonCode = reason(body.reasonCode);
  const binding = await options.catalog.get("credential_binding", bindingId);
  requireOwner(principal, await ownerForRecord(options, "credential_binding", binding));
  if (binding.status === "revoked") {
    throw new AccountsError("INVALID_TRANSITION", "A terminal credential binding cannot create an operation");
  }
  if (binding.resolver === "capsule_local_native") {
    throw new AccountsError("POLICY_DENIED", "Native credential ceremonies are not exposed by HTTP");
  }
  if (binding.revision !== expectedRevision) {
    throw new AccountsError("STALE_REVISION", "Credential binding revision changed", {
      details: {
        aggregateKind: "credential_binding",
        aggregateId: binding.id,
        expectedRevision,
        actualRevision: binding.revision,
      },
    });
  }
  const requestDigest = canonicalSha256(body);
  const stored = await options.idempotency.execute(
    {
      actorRef: principal.actorRef,
      audience: principal.audience,
      method: request.method,
      route: path,
      key: idempotencyKey,
      requestDigest,
    },
    async () => {
      const operation = await service.request({
        kind,
        binding: binding as Extract<CredentialBinding, { status: "pending" | "active" | "retiring" }>,
        expectedRevision,
        principal,
        idempotencyKey,
        reasonCode,
        requestDigest,
      });
      return {
        status: 202,
        body: canonicalJson({ schemaVersion: "accounts.credential-operation.v1", data: operation }),
      };
    },
  );
  return responseFromStored(stored);
}

async function handleInternal(
  request: Request,
  path: string,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<Response> {
  requireMethod(request, "POST");
  const definition = {
    "/internal/v1/slot-eligibility": ["accounts:eligibility:issue", "issueSlotEligibility"],
    "/internal/v1/generation-check": ["accounts:generation:check", "checkGeneration"],
    "/internal/v1/capacity-pool-evidence": ["accounts:capacity-pools:attest", "ingestCapacityPoolEvidence"],
    "/internal/v1/execution-policy-evidence": ["accounts:execution-policy:attest", "ingestExecutionPolicyEvidence"],
    "/internal/v1/credential-binding-receipts": ["accounts:credentials:issue", "ingestCredentialBindingReceipt"],
  } as const;
  const selected = definition[path as keyof typeof definition];
  if (selected === undefined) throw new AccountsError("NOT_FOUND", "Internal route not found");
  requireScope(principal, selected[0]);
  const service = options.internal?.[selected[1]];
  if (service === undefined) throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Internal verifier is unavailable");
  const body = await readJsonObject(request);
  // Raw handles, capabilities, device codes, and credential locators are rejected at this boundary.
  assertNoSensitiveFields(body);
  await requireInternalOwner(body, principal, options);
  const result = await service(body, principal);
  assertNoSensitiveFields(result);
  return jsonResponse(200, result);
}

async function requireInternalOwner(
  body: JsonObject,
  principal: AccountsAuthenticatedPrincipal,
  options: AccountsHttpHandlerOptions,
): Promise<void> {
  const candidates: readonly [string, EntityKind][] = [
    ["account_lane_id", "access_method"],
    ["credential_binding_id", "credential_binding"],
    ["capacity_pool_id", "capacity_pool"],
    ["entitlement_id", "entitlement"],
    ["provider_account_id", "account"],
  ];
  for (const [field, kind] of candidates) {
    if (body[field] === undefined) continue;
    const id = parseEntityId(kind, body[field]);
    requireOwner(principal, await ownerForEntity(options, kind, id));
    return;
  }
  throw new AccountsError("VALIDATION_FAILED", "Internal request is missing an owner-bound aggregate", {
    details: { field: "ownerBoundAggregate" },
  });
}

async function ownerForEntity<K extends EntityKind>(
  options: AccountsHttpHandlerOptions,
  kind: K,
  id: EntityMap[K]["id"],
): Promise<string> {
  return ownerForRecord(options, kind, await options.catalog.get(kind, id));
}

async function ownerForRecord<K extends EntityKind>(
  options: AccountsHttpHandlerOptions,
  kind: K,
  record: EntityMap[K],
): Promise<string> {
  switch (kind) {
    case "account":
      return (record as EntityMap["account"]).ownerRef;
    case "entitlement":
      return ownerForEntity(options, "account", (record as EntityMap["entitlement"]).accountId);
    case "capacity_pool":
      return ownerForEntity(options, "account", (record as EntityMap["capacity_pool"]).accountId);
    case "access_method":
      return ownerForEntity(
        options,
        "entitlement",
        (record as EntityMap["access_method"]).entitlementId,
      );
    case "auth_capsule":
      return (record as EntityMap["auth_capsule"]).ownerRef;
    case "credential_binding":
      return ownerForEntity(
        options,
        "access_method",
        (record as EntityMap["credential_binding"]).accessMethodId,
      );
  }
}

function redactEntity<K extends EntityKind>(kind: K, record: EntityMap[K]): Readonly<Record<string, unknown>> {
  const safe = { ...(record as unknown as Record<string, unknown>) };
  if (kind === "account") {
    const hadSubject = safe.providerSubjectRef !== undefined || safe.providerSubjectCandidateRef !== undefined;
    delete safe.providerSubjectRef;
    delete safe.providerSubjectCandidateRef;
    if (hadSubject) safe.providerSubjectRefRedacted = true;
  }
  assertNoSensitiveFields(safe);
  return Object.freeze(safe);
}

function parseEntityId<K extends EntityKind>(kind: K, value: unknown): EntityMap[K]["id"] {
  switch (kind) {
    case "account":
      return parseAccountId(value) as EntityMap[K]["id"];
    case "entitlement":
      return parseEntitlementId(value) as EntityMap[K]["id"];
    case "capacity_pool":
      return parseCapacityPoolId(value) as EntityMap[K]["id"];
    case "access_method":
      return parseAccessMethodId(value) as EntityMap[K]["id"];
    case "auth_capsule":
      return parseAuthCapsuleId(value) as EntityMap[K]["id"];
    case "credential_binding":
      return parseCredentialBindingId(value) as EntityMap[K]["id"];
  }
}

async function readJsonObject(request: Request): Promise<JsonObject> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) {
    throw new AccountsError("VALIDATION_FAILED", "Content-Type must be application/json", {
      details: { field: "contentType" },
    });
  }
  if (request.signal.aborted) throw abortError();
  const body = parseClosedJson(await request.text());
  if (request.signal.aborted) throw abortError();
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new AccountsError("VALIDATION_FAILED", "JSON body must be an object", {
      details: { field: "body" },
    });
  }
  assertNoSensitiveFields(body);
  return body as JsonObject;
}

function exactKeys(value: JsonObject, required: readonly string[], optional: readonly string[] = []): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new AccountsError("VALIDATION_FAILED", "Unknown request field", {
        details: { field: key.replace(/[^A-Za-z0-9_.]/g, "_").slice(0, 64) },
      });
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) {
      throw new AccountsError("VALIDATION_FAILED", "Required request field is missing", {
        details: { field: key },
      });
    }
  }
}

function requireScope(principal: AccountsAuthenticatedPrincipal, scope: AccountsHttpScope): void {
  if (!principal.scopes.has(scope)) throw new AccountsError("FORBIDDEN", "Required scope is missing");
}

function requireOwner(principal: AccountsAuthenticatedPrincipal, ownerRef: string): void {
  if (!principal.authorizedOwnerRefs.has(ownerRef)) {
    // Cross-owner identifiers are deliberately indistinguishable from missing records.
    throw new AccountsError("NOT_FOUND", "Record not found");
  }
}

function requireMethod(request: Request, method: string): void {
  if (request.method !== method) throw methodNotAllowed();
}

function methodNotAllowed(): AccountsError {
  return new AccountsError("FORBIDDEN", "HTTP method is not exposed");
}

function requireIdempotencyKey(request: Request): string {
  const values = [...request.headers.entries()]
    .filter(([name]) => name.toLowerCase() === "idempotency-key")
    .map(([, value]) => value);
  const value = values[0];
  if (values.length !== 1 || value === undefined || !IDEMPOTENCY_PATTERN.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Idempotency-Key is required", {
      details: { field: "Idempotency-Key" },
    });
  }
  return value;
}

function requireIfMatch(request: Request): Counter {
  const raw = request.headers.get("if-match");
  if (raw === null || raw.includes(",") || raw.startsWith("W/")) {
    throw new AccountsError("VALIDATION_FAILED", "A strong If-Match revision is required", {
      details: { field: "If-Match" },
    });
  }
  const value = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;
  return parseCounter(value, "expectedRevision");
}

function mutationContext(
  principal: AccountsAuthenticatedPrincipal,
  idempotencyKey: string,
  route: string,
  requestDigest: string,
  reasonCode: string,
): MutationContext {
  const scopedKey = createHash("sha256")
    .update([principal.actorRef, principal.audience, route, idempotencyKey, requestDigest].join("\u0000"))
    .digest("hex");
  return { actorRef: principal.actorRef, idempotencyKey: `http:${scopedKey}`, reasonCode };
}

function rejectCredentialBearingUrl(url: URL): void {
  if (url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new AccountsError("VALIDATION_FAILED", "Credential-bearing or fragment URL is forbidden", {
      details: { field: "url" },
    });
  }
}

function normalizePath(path: string): string {
  if (!path.startsWith("/") || path.includes("//") || path.includes("\\") || /%2f|%5c/i.test(path)) {
    throw new AccountsError("VALIDATION_FAILED", "Route path is invalid", {
      details: { field: "path" },
    });
  }
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

function rejectUnknownQuery(url: URL, allowed: ReadonlySet<string>): void {
  const seen = new Set<string>();
  for (const [key] of url.searchParams) {
    if (!allowed.has(key) || seen.has(key)) {
      throw new AccountsError("VALIDATION_FAILED", "Query parameter is invalid", {
        details: { field: key.replace(/[^A-Za-z0-9_.]/g, "_").slice(0, 64) },
      });
    }
    seen.add(key);
  }
}

function parseLimit(raw: string | null): number {
  if (raw === null) return 50;
  if (!/^(?:[1-9]|[1-9][0-9]|100)$/.test(raw)) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination limit is invalid", {
      details: { field: "limit" },
    });
  }
  return Number(raw);
}

function encodeCursor(id: string): string {
  return Buffer.from(id, "ascii").toString("base64url");
}

function decodeCursor(raw: string | null): string | undefined {
  if (raw === null) return undefined;
  if (!CURSOR_PATTERN.test(raw)) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination cursor is invalid", {
      details: { field: "cursor" },
    });
  }
  const decoded = Buffer.from(raw, "base64url").toString("ascii");
  if (encodeCursor(decoded) !== raw || !/^[0-9a-f-]{36}$/.test(decoded)) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination cursor is invalid", {
      details: { field: "cursor" },
    });
  }
  return decoded;
}

function boundedString(value: unknown, field: string, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value
  ) {
    throw new AccountsError("VALIDATION_FAILED", "String field is invalid", { details: { field } });
  }
  return value;
}

function reference(value: unknown, field: string, pattern = REFERENCE_PATTERN): string {
  const result = boundedString(value, field, 255);
  if (!pattern.test(result)) {
    throw new AccountsError("VALIDATION_FAILED", "Reference field is invalid", { details: { field } });
  }
  return result;
}

function owner(value: unknown, field: string): string {
  const result = boundedString(value, field, 160);
  if (!OWNER_PATTERN.test(result)) {
    throw new AccountsError("VALIDATION_FAILED", "Owner reference is invalid", { details: { field } });
  }
  return result;
}

function reason(value: unknown): string {
  const result = boundedString(value, "reasonCode", 64);
  if (!REASON_PATTERN.test(result)) {
    throw new AccountsError("VALIDATION_FAILED", "Reason code is invalid", {
      details: { field: "reasonCode" },
    });
  }
  return result;
}

function literal(value: unknown, expected: string, field: string): void {
  if (value !== expected) {
    throw new AccountsError("VALIDATION_FAILED", "Schema discriminator is invalid", {
      details: { field },
    });
  }
}

function enumString<const T extends readonly string[]>(value: unknown, allowed: T, field: string): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Enum field is invalid", { details: { field } });
  }
  return value as T[number];
}

function jsonResponse(status: number, body: unknown): Response {
  assertNoSensitiveFields(body);
  return new Response(canonicalJson(body), { status, headers: JSON_HEADERS });
}

function responseFromStored(stored: StoredHttpResponse): Response {
  const headers = { ...JSON_HEADERS, ...(stored.headers ?? {}) };
  return new Response(stored.body, { status: stored.status, headers });
}

function errorResponse(error: AccountsError, requestId: string, status: number): Response {
  return new Response(canonicalJson(toErrorEnvelope(error, requestId)), {
    status,
    headers: JSON_HEADERS,
  });
}

function statusForError(error: AccountsError): number {
  switch (error.code) {
    case "VALIDATION_FAILED":
    case "SCHEMA_VERSION_UNSUPPORTED":
      return 400;
    case "NOT_FOUND":
      return 404;
    case "FORBIDDEN":
      return 403;
    case "IDEMPOTENCY_CONFLICT":
    case "CONFLICT":
    case "STALE_REVISION":
    case "INVALID_TRANSITION":
    case "CAPACITY_DOMAIN_CONFLICT":
      return 409;
    case "TERMS_NOT_ALLOWED":
    case "POLICY_DENIED":
    case "CAPSULE_NOT_READY":
    case "STALE_ATTESTATION":
    case "STALE_CREDENTIAL_GENERATION":
    case "STALE_AUTH_STATE_REVISION":
    case "CURRENT_DENY":
    case "INVALID_ACCESS_TARGET":
      return 422;
    case "DEPENDENCY_UNAVAILABLE":
    case "RECOVERY_HOLD":
    case "NOT_IMPLEMENTED":
    case "SCHEMA_CHECKSUM_MISMATCH":
    case "DATABASE_PATH_UNSAFE":
      return 503;
    case "COUNTER_EXHAUSTED":
      return 409;
  }
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
