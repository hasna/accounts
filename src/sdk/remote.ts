import type { Counter } from "../domain/counter";
import type { EntityKind, EntityMap, EligibilityRequest } from "../domain/models";
import { ACCOUNT_ERROR_CODES, AccountsError, type AccountErrorCode } from "../errors";
import { validateEntity, validateSlotEligibility } from "../serialization/dto";
import { assertNoSensitiveFields, canonicalJson, parseClosedJson } from "../serialization/json";
import type { BootstrapIntent } from "../http/types";
import type {
  AccountsAuthProvider,
  AccountsCapacity,
  BootstrapIntentInput,
  CallOptions,
  CreateAccountLaneInput,
  CreateEntitlementInput,
  CreateProviderAccountInput,
  ListOptions,
  MutationOptions,
  Page,
  ProviderAccountView,
  RevisionMutationOptions,
} from "./types";

type JsonObject = Record<string, unknown>;

const ERROR_CODES = new Set<string>(ACCOUNT_ERROR_CODES);
const FORBIDDEN_AUTH_HEADERS = new Set([
  "cookie",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
  "x-legacy-api-key",
]);

export function createSelfHostedAccountsCapacity(
  baseUrl: string,
  authProvider: AccountsAuthProvider,
): AccountsCapacity {
  const transport = new AccountsHttpTransport(baseUrl, authProvider);

  return Object.freeze({
    providerAccounts: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("provider-accounts", "account", options, decodeProviderAccount),
      get: (id: EntityMap["account"]["id"], options?: CallOptions) =>
        transport.get("provider-accounts", "account", id, options, decodeProviderAccount),
      create: (input: CreateProviderAccountInput, options: MutationOptions) =>
        transport.create(
          "provider-accounts",
          "account",
          {
            schemaVersion: "accounts.provider-account.create.v1",
            ...input,
          },
          options,
          decodeProviderAccount,
        ),
    }),
    entitlements: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("entitlements", "entitlement", options, (value) =>
          validateEntity("entitlement", value),
        ),
      get: (id: EntityMap["entitlement"]["id"], options?: CallOptions) =>
        transport.get("entitlements", "entitlement", id, options, (value) =>
          validateEntity("entitlement", value),
        ),
      create: (input: CreateEntitlementInput, options: MutationOptions) =>
        transport.create(
          "entitlements",
          "entitlement",
          {
            schemaVersion: "accounts.entitlement.create.v1",
            providerAccountId: input.providerAccountId,
            fundingKind: input.fundingKind,
          },
          options,
          (value) => validateEntity("entitlement", value),
        ),
    }),
    capacityPools: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("capacity-pools", "capacity_pool", options, (value) =>
          validateEntity("capacity_pool", value),
        ),
      get: (id: EntityMap["capacity_pool"]["id"], options?: CallOptions) =>
        transport.get("capacity-pools", "capacity_pool", id, options, (value) =>
          validateEntity("capacity_pool", value),
        ),
    }),
    lanes: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("account-lanes", "access_method", options, (value) =>
          validateEntity("access_method", value),
        ),
      get: (id: EntityMap["access_method"]["id"], options?: CallOptions) =>
        transport.get("account-lanes", "access_method", id, options, (value) =>
          validateEntity("access_method", value),
        ),
      create: (input: CreateAccountLaneInput, options: MutationOptions) =>
        transport.create(
          "account-lanes",
          "access_method",
          {
            schemaVersion: "accounts.account-lane.create.v1",
            ...input,
          },
          options,
          (value) => validateEntity("access_method", value),
        ),
    }),
    capsules: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("auth-capsules", "auth_capsule", options, (value) =>
          validateEntity("auth_capsule", value),
        ),
      get: (id: EntityMap["auth_capsule"]["id"], options?: CallOptions) =>
        transport.get("auth-capsules", "auth_capsule", id, options, (value) =>
          validateEntity("auth_capsule", value),
        ),
      createBootstrapIntent: (
        id: EntityMap["auth_capsule"]["id"],
        input: BootstrapIntentInput,
        options: RevisionMutationOptions,
      ) => transport.createBootstrapIntent(id, input, options),
      getBootstrapIntent: (
        id: EntityMap["auth_capsule"]["id"],
        intentId: string,
        options?: CallOptions,
      ) => transport.getBootstrapIntent(id, intentId, options),
    }),
    credentialBindings: Object.freeze({
      list: (options?: ListOptions) =>
        transport.list("credential-bindings", "credential_binding", options, (value) =>
          validateEntity("credential_binding", value),
        ),
      get: (id: EntityMap["credential_binding"]["id"], options?: CallOptions) =>
        transport.get("credential-bindings", "credential_binding", id, options, (value) =>
          validateEntity("credential_binding", value),
        ),
    }),
    capacity: Object.freeze({
      query: (request: EligibilityRequest, options?: CallOptions) =>
        transport.queryCapacity(request, options),
    }),
    close: async (options?: CallOptions): Promise<void> => {
      throwIfAborted(options?.signal);
    },
  });
}

class AccountsHttpTransport {
  private readonly baseUrl: URL;

  constructor(
    rawBaseUrl: string,
    private readonly authProvider: AccountsAuthProvider,
  ) {
    this.baseUrl = validateBaseUrl(rawBaseUrl);
  }

  async list<K extends EntityKind, T>(
    route: string,
    kind: K,
    options: ListOptions | undefined,
    decode: (value: unknown) => T,
  ): Promise<Page<T>> {
    const query = new URLSearchParams();
    if (options?.cursor !== undefined) query.set("cursor", options.cursor);
    if (options?.limit !== undefined) {
      if (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 100) {
        throw new AccountsError("VALIDATION_FAILED", "Pagination limit is invalid", {
          details: { field: "limit" },
        });
      }
      query.set("limit", String(options.limit));
    }
    const suffix = query.size === 0 ? "" : `?${query.toString()}`;
    const body = await this.request("GET", `/v1/${route}${suffix}`, undefined, options?.signal);
    const envelope = closedObject(body, ["schemaVersion", "kind", "records", "nextCursor", "route"]);
    literal(envelope.schemaVersion, "accounts.list.v1", "schemaVersion");
    literal(envelope.kind, kind, "kind");
    if (!Array.isArray(envelope.records)) invalid("records");
    if (envelope.nextCursor !== null && typeof envelope.nextCursor !== "string") invalid("nextCursor");
    return Object.freeze({
      records: Object.freeze(envelope.records.map(decode)),
      nextCursor: envelope.nextCursor as string | null,
    });
  }

  async get<K extends EntityKind, T>(
    route: string,
    kind: K,
    id: EntityMap[K]["id"],
    options: CallOptions | undefined,
    decode: (value: unknown) => T,
  ): Promise<T> {
    const body = await this.request("GET", `/v1/${route}/${encodeURIComponent(id)}`, undefined, options?.signal);
    const envelope = closedObject(body, ["schemaVersion", "kind", "data"]);
    literal(envelope.schemaVersion, "accounts.record.v1", "schemaVersion");
    literal(envelope.kind, kind, "kind");
    return decode(envelope.data);
  }

  async create<K extends EntityKind, T>(
    route: string,
    kind: K,
    body: unknown,
    options: MutationOptions,
    decode: (value: unknown) => T,
  ): Promise<T> {
    validateIdempotencyKey(options.idempotencyKey);
    const response = await this.request(
      "POST",
      `/v1/${route}`,
      body,
      options.signal,
      { "idempotency-key": options.idempotencyKey },
    );
    const envelope = closedObject(response, ["schemaVersion", "kind", "data", "eventId", "replayed"]);
    literal(envelope.schemaVersion, "accounts.mutation-result.v1", "schemaVersion");
    literal(envelope.kind, kind, "kind");
    return decode(envelope.data);
  }

  async createBootstrapIntent(
    id: EntityMap["auth_capsule"]["id"],
    input: BootstrapIntentInput,
    options: RevisionMutationOptions,
  ): Promise<BootstrapIntent> {
    validateIdempotencyKey(options.idempotencyKey);
    const response = await this.request(
      "POST",
      `/v1/auth-capsules/${encodeURIComponent(id)}/bootstrap-intents`,
      {
        schemaVersion: "accounts.bootstrap-intent.create.v1",
        reasonCode: input.reasonCode,
      },
      options.signal,
      {
        "idempotency-key": options.idempotencyKey,
        "if-match": `"${options.expectedRevision}"`,
      },
    );
    return decodeBootstrapIntent(response);
  }

  async getBootstrapIntent(
    id: EntityMap["auth_capsule"]["id"],
    intentId: string,
    options: CallOptions | undefined,
  ): Promise<BootstrapIntent> {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(intentId)) {
      invalid("intentId");
    }
    const response = await this.request(
      "GET",
      `/v1/auth-capsules/${encodeURIComponent(id)}/bootstrap-intents/${encodeURIComponent(intentId)}`,
      undefined,
      options?.signal,
    );
    return decodeBootstrapIntent(response);
  }

  async queryCapacity(request: EligibilityRequest, options: CallOptions | undefined) {
    const response = await this.request("POST", "/v1/capacity/query", request, options?.signal);
    const envelope = closedObject(response, ["schemaVersion", "reservation", "data"]);
    literal(envelope.schemaVersion, "accounts.capacity-query.v1", "schemaVersion");
    literal(envelope.reservation, "none", "reservation");
    return validateSlotEligibility(envelope.data);
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
    extraHeaders: Readonly<Record<string, string>> = {},
  ): Promise<unknown> {
    throwIfAborted(signal);
    const url = new URL(path, this.baseUrl);
    if (url.origin !== this.baseUrl.origin) {
      throw new AccountsError("VALIDATION_FAILED", "Request origin escape is forbidden", {
        details: { field: "baseUrl" },
      });
    }
    const headers = new Headers({ accept: "application/json", ...extraHeaders });
    if (body !== undefined) headers.set("content-type", "application/json");
    try {
      await this.authProvider.authorize(headers, signal);
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capacity authentication is unavailable");
    }
    throwIfAborted(signal);
    validateAuthorizationHeaders(headers);
    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        ...(body === undefined ? {} : { body: canonicalJson(body) }),
        ...(signal === undefined ? {} : { signal }),
        redirect: "error",
        credentials: "omit",
        cache: "no-store",
      });
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capacity service is unavailable", {
        retryable: true,
      });
    }
    throwIfAborted(signal);
    const source = await response.text();
    throwIfAborted(signal);
    let decoded: unknown;
    try {
      decoded = parseClosedJson(source);
    } catch {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capacity service returned invalid JSON");
    }
    if (!response.ok) throw decodeHttpError(decoded);
    assertNoSensitiveFields(decoded);
    return decoded;
  }
}

function validateBaseUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AccountsError("VALIDATION_FAILED", "Self-hosted base URL is invalid", {
      details: { field: "baseUrl" },
    });
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.hostname === ""
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Self-hosted base URL must be an HTTPS origin", {
      details: { field: "baseUrl" },
    });
  }
  return new URL(`${url.origin}/`);
}

function validateAuthorizationHeaders(headers: Headers): void {
  const authorization = headers.get("authorization");
  if (authorization === null || !/^Bearer [\x21-\x7e]{1,4096}$/.test(authorization)) {
    throw new AccountsError("FORBIDDEN", "Capacity authorization is missing or invalid");
  }
  for (const name of FORBIDDEN_AUTH_HEADERS) {
    if (headers.has(name)) {
      throw new AccountsError("VALIDATION_FAILED", "Legacy or ambient credential header is forbidden", {
        details: { field: name.replace(/-/g, "_") },
      });
    }
  }
}

function decodeProviderAccount(value: unknown): ProviderAccountView {
  const record = closedObject(
    value,
    ["id", "providerKey", "ownerRef", "displayLabel", "status", "revision", "createdAt", "updatedAt"],
    [
      "providerDisplayHint",
      "providerSubjectRefRedacted",
      "ownershipEvidenceRef",
      "ownershipEvidenceIssuerRef",
      "ownershipEvidenceVersion",
      "ownershipEvidenceDigest",
      "ownershipEvidenceIssuedAt",
      "ownershipEvidenceExpiresAt",
      "ownershipGeneration",
    ],
  );
  if (Object.hasOwn(record, "providerSubjectRef") || Object.hasOwn(record, "providerSubjectCandidateRef")) {
    invalid("providerSubjectRef");
  }
  if (record.providerSubjectRefRedacted !== undefined && record.providerSubjectRefRedacted !== true) {
    invalid("providerSubjectRefRedacted");
  }
  // Reuse the exact domain validator with a non-exported opaque placeholder,
  // then return only the redacted wire view.
  const { providerSubjectRefRedacted: _redacted, ...domainRecord } = record;
  const validationCandidate =
    record.status === "active" || record.status === "suspended" ||
    (record.status === "revoked" && record.ownershipEvidenceRef !== undefined)
      ? { ...domainRecord, providerSubjectRef: "redacted:verified" }
      : domainRecord;
  validateEntity("account", validationCandidate);
  return Object.freeze(record as unknown as ProviderAccountView);
}

function decodeBootstrapIntent(value: unknown): BootstrapIntent {
  const record = closedObject(value, [
    "schemaVersion",
    "id",
    "authCapsuleId",
    "ownerRef",
    "canonicalNodeId",
    "nodeGeneration",
    "placementGeneration",
    "authGeneration",
    "capsuleRevision",
    "status",
    "createdAt",
    "expiresAt",
  ]);
  literal(record.schemaVersion, "accounts.bootstrap-intent.v1", "schemaVersion");
  if (record.status !== "pending" && record.status !== "expired") invalid("status");
  for (const field of ["nodeGeneration", "placementGeneration", "authGeneration", "capsuleRevision"] as const) {
    if (typeof record[field] !== "string") invalid(field);
  }
  return Object.freeze(record as unknown as BootstrapIntent);
}

function decodeHttpError(value: unknown): AccountsError {
  try {
    const envelope = closedObject(value, ["schemaVersion", "error"]);
    literal(envelope.schemaVersion, "accounts.error.v1", "schemaVersion");
    const error = closedObject(envelope.error, ["code", "message", "requestId", "retryable", "details"]);
    if (typeof error.code !== "string" || !ERROR_CODES.has(error.code)) throw new Error("invalid");
    return new AccountsError(error.code as AccountErrorCode, "Remote Accounts error", {
      retryable: error.retryable === true,
      details:
        error.details !== null && typeof error.details === "object" && !Array.isArray(error.details)
          ? (error.details as Record<string, string | boolean | readonly string[]>)
          : {},
    });
  } catch {
    return new AccountsError("DEPENDENCY_UNAVAILABLE", "Capacity service returned an invalid error");
  }
}

function closedObject(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) invalid("response");
  const record = value as JsonObject;
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) if (!allowed.has(key)) invalid(key);
  for (const key of required) if (!Object.hasOwn(record, key)) invalid(key);
  assertNoSensitiveFields(record);
  return record;
}

function literal(value: unknown, expected: string, field: string): void {
  if (value !== expected) invalid(field);
}

function validateIdempotencyKey(value: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) invalid("idempotencyKey");
}

function invalid(field: string): never {
  throw new AccountsError("VALIDATION_FAILED", "SDK response or request validation failed", {
    details: { field: field.replace(/[^A-Za-z0-9_.]/g, "_").slice(0, 64) },
  });
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
}

function isAbort(error: unknown, signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true || (error instanceof DOMException && error.name === "AbortError");
}
