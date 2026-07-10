import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

import { AccountsCatalog } from "../domain/catalog";
import { parseCounter } from "../domain/counter";
import {
  newAccessMethodId,
  newAccountId,
  newEntitlementId,
  parseAccountId,
  parseAccessMethodId,
  parseAuthCapsuleId,
  parseCapacityPoolId,
  parseCredentialBindingId,
  parseEntitlementId,
} from "../domain/ids";
import type { EntityKind, EntityMap, EligibilityRequest } from "../domain/models";
import { AccountsError } from "../errors";
import { MemoryBootstrapIntentStore } from "../http/stores";
import type { BootstrapIntent } from "../http/types";
import { validateEntity } from "../serialization/dto";
import { canonicalSha256 } from "../serialization/json";
import { SQLiteAccountsRepository } from "../storage/sqlite";
import { FileRecoveryLedger } from "../storage/file-recovery-ledger";
import type {
  AccountsCapacity,
  BootstrapIntentInput,
  CallOptions,
  CreateAccountLaneInput,
  CreateEntitlementInput,
  CreateProviderAccountInput,
  ListOptions,
  LocalRecoveryConfiguration,
  MutationOptions,
  Page,
  ProviderAccountView,
  RevisionMutationOptions,
} from "./types";

const OWNER_PATTERN = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function createLocalAccountsCapacity(
  actorRef: string,
  sqlitePath?: string,
  recovery?: LocalRecoveryConfiguration,
): AccountsCapacity {
  if (!OWNER_PATTERN.test(actorRef)) {
    throw new AccountsError("VALIDATION_FAILED", "Local actor reference is invalid", {
      details: { field: "actorRef" },
    });
  }
  const path = sqlitePath ?? join(homedir(), ".hasna", "accounts", "accounts.db");
  if (!isAbsolute(path) || resolve(path) !== path) {
    throw new AccountsError("VALIDATION_FAILED", "Local SQLite path must be absolute and normalized", {
      details: { field: "sqlitePath" },
    });
  }
  if (recovery !== undefined) {
    if (!isAbsolute(recovery.ledgerPath) || resolve(recovery.ledgerPath) !== recovery.ledgerPath) {
      throw new AccountsError("VALIDATION_FAILED", "Local recovery path must be absolute and normalized", {
        details: { field: "recovery.ledgerPath" },
      });
    }
  }
  const recoveryLedger =
    recovery === undefined
      ? undefined
      : new FileRecoveryLedger({
          path: recovery.ledgerPath,
          catalogIncarnation: recovery.catalogIncarnation,
          signingKey: recovery.signingKey,
        });
  const catalog = new AccountsCatalog(
    new SQLiteAccountsRepository(path, {
      ...(recoveryLedger === undefined ? {} : { recoveryLedger }),
      ...(recovery === undefined ? {} : { catalogIncarnation: recovery.catalogIncarnation }),
    }),
  );
  return createLocalAccountsCapacityFromCatalog(catalog, actorRef);
}

/** Integration seam for a catalog configured with the package-owned persistent recovery ledger. */
export function createLocalAccountsCapacityFromCatalog(
  catalog: AccountsCatalog,
  actorRef: string,
): AccountsCapacity {
  if (!OWNER_PATTERN.test(actorRef)) {
    throw new AccountsError("VALIDATION_FAILED", "Local actor reference is invalid", {
      details: { field: "actorRef" },
    });
  }
  const bootstrapIntents = new MemoryBootstrapIntentStore();

  return Object.freeze({
    providerAccounts: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "account", actorRef, options, redactAccount),
      get: async (id: EntityMap["account"]["id"], options?: CallOptions) => {
        const value = await ownedGet(catalog, "account", parseAccountId(id), actorRef, options?.signal);
        return redactAccount(value);
      },
      create: async (input: CreateProviderAccountInput, options: MutationOptions) => {
        throwIfAborted(options.signal);
        validateIdempotency(options.idempotencyKey);
        if (input.ownerRef !== actorRef) throw new AccountsError("NOT_FOUND", "Owner not found");
        const timestamp = new Date().toISOString();
        const record = validateEntity("account", {
          id: newAccountId(Date.parse(timestamp)),
          providerKey: input.providerKey,
          ownerRef: input.ownerRef,
          displayLabel: input.displayLabel,
          ...(input.providerSubjectCandidateRef === undefined
            ? {}
            : { providerSubjectCandidateRef: input.providerSubjectCandidateRef }),
          ...(input.providerDisplayHint === undefined
            ? {}
            : { providerDisplayHint: input.providerDisplayHint }),
          status: "pending",
          revision: parseCounter("0"),
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        const result = await catalog.add("account", record, {
          actorRef,
          idempotencyKey: scopedIdempotency("account", options.idempotencyKey, input),
          reasonCode: "CREATE",
        });
        throwIfAborted(options.signal);
        return redactAccount(result.record);
      },
    }),
    entitlements: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "entitlement", actorRef, options),
      get: (id: EntityMap["entitlement"]["id"], options?: CallOptions) =>
        ownedGet(catalog, "entitlement", parseEntitlementId(id), actorRef, options?.signal),
      create: async (input: CreateEntitlementInput, options: MutationOptions) => {
        throwIfAborted(options.signal);
        validateIdempotency(options.idempotencyKey);
        const account = await ownedGet(catalog, "account", input.providerAccountId, actorRef, options.signal);
        const timestamp = new Date().toISOString();
        const record = validateEntity("entitlement", {
          id: newEntitlementId(Date.parse(timestamp)),
          accountId: account.id,
          fundingKind: input.fundingKind,
          status: "pending",
          revision: parseCounter("0"),
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        const result = await catalog.add("entitlement", record, {
          actorRef,
          idempotencyKey: scopedIdempotency("entitlement", options.idempotencyKey, input),
          reasonCode: "CREATE",
        });
        throwIfAborted(options.signal);
        return result.record;
      },
    }),
    capacityPools: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "capacity_pool", actorRef, options),
      get: (id: EntityMap["capacity_pool"]["id"], options?: CallOptions) =>
        ownedGet(catalog, "capacity_pool", parseCapacityPoolId(id), actorRef, options?.signal),
    }),
    lanes: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "access_method", actorRef, options),
      get: (id: EntityMap["access_method"]["id"], options?: CallOptions) =>
        ownedGet(catalog, "access_method", parseAccessMethodId(id), actorRef, options?.signal),
      create: async (input: CreateAccountLaneInput, options: MutationOptions) => {
        throwIfAborted(options.signal);
        validateIdempotency(options.idempotencyKey);
        await Promise.all([
          ownedGet(catalog, "entitlement", input.entitlementId, actorRef, options.signal),
          ownedGet(catalog, "capacity_pool", input.capacityPoolId, actorRef, options.signal),
        ]);
        const timestamp = new Date().toISOString();
        const record = validateEntity("access_method", {
          id: newAccessMethodId(Date.parse(timestamp)),
          entitlementId: input.entitlementId,
          capacityPoolId: input.capacityPoolId,
          adapterKey: input.adapterKey,
          adapterVersion: input.adapterVersion,
          accessTransport: input.accessTransport,
          status: "draft",
          revision: parseCounter("0"),
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        const result = await catalog.add("access_method", record, {
          actorRef,
          idempotencyKey: scopedIdempotency("access_method", options.idempotencyKey, input),
          reasonCode: "CREATE",
        });
        throwIfAborted(options.signal);
        return result.record;
      },
    }),
    capsules: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "auth_capsule", actorRef, options),
      get: (id: EntityMap["auth_capsule"]["id"], options?: CallOptions) =>
        ownedGet(catalog, "auth_capsule", parseAuthCapsuleId(id), actorRef, options?.signal),
      createBootstrapIntent: async (
        id: EntityMap["auth_capsule"]["id"],
        input: BootstrapIntentInput,
        options: RevisionMutationOptions,
      ): Promise<BootstrapIntent> => {
        throwIfAborted(options.signal);
        validateIdempotency(options.idempotencyKey);
        if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(input.reasonCode)) {
          throw new AccountsError("VALIDATION_FAILED", "Reason code is invalid", {
            details: { field: "reasonCode" },
          });
        }
        const capsule = await ownedGet(catalog, "auth_capsule", id, actorRef, options.signal);
        if (
          capsule.revision !== options.expectedRevision ||
          capsule.status === "revoked" ||
          capsule.refreshMode !== "interactive_owner" ||
          capsule.ownerRef !== actorRef ||
          !actorRef.startsWith("principal:human:hasna:")
        ) {
          throw new AccountsError(
            capsule.revision !== options.expectedRevision ? "STALE_REVISION" : "CAPSULE_NOT_READY",
            "Capsule does not permit a local bootstrap intent",
          );
        }
        const requestDigest = canonicalSha256({ input, expectedRevision: options.expectedRevision });
        const intent = await bootstrapIntents.create({
          principal: {
            actorRef,
            subjectRef: actorRef,
            issuer: "accounts-local",
            audience: "accounts-local",
            scopes: new Set(["accounts:capsules:bootstrap-intent"]),
            authorizedOwnerRefs: new Set([actorRef]),
          },
          capsule,
          idempotencyKey: options.idempotencyKey,
          reasonCode: input.reasonCode,
          requestDigest,
          now: new Date().toISOString(),
        });
        throwIfAborted(options.signal);
        return intent;
      },
      getBootstrapIntent: async (
        id: EntityMap["auth_capsule"]["id"],
        intentId: string,
        options?: CallOptions,
      ): Promise<BootstrapIntent> => {
        throwIfAborted(options?.signal);
        await ownedGet(catalog, "auth_capsule", id, actorRef, options?.signal);
        const intent = await bootstrapIntents.get(id, intentId);
        if (intent === undefined || intent.ownerRef !== actorRef) {
          throw new AccountsError("NOT_FOUND", "Bootstrap intent not found");
        }
        throwIfAborted(options?.signal);
        return intent;
      },
    }),
    credentialBindings: Object.freeze({
      list: (options?: ListOptions) => list(catalog, "credential_binding", actorRef, options),
      get: (id: EntityMap["credential_binding"]["id"], options?: CallOptions) =>
        ownedGet(catalog, "credential_binding", parseCredentialBindingId(id), actorRef, options?.signal),
    }),
    capacity: Object.freeze({
      query: async (request: EligibilityRequest, options?: CallOptions) => {
        throwIfAborted(options?.signal);
        await ownedGet(catalog, "access_method", request.accessMethodId, actorRef, options?.signal);
        const result = await catalog.eligibility(request);
        throwIfAborted(options?.signal);
        return result;
      },
    }),
    close: async (options?: CallOptions): Promise<void> => {
      throwIfAborted(options?.signal);
      await catalog.close();
      throwIfAborted(options?.signal);
    },
  });
}

async function list<K extends EntityKind, T = EntityMap[K]>(
  catalog: AccountsCatalog,
  kind: K,
  actorRef: string,
  options: ListOptions | undefined,
  project: (record: EntityMap[K]) => T = (record) => record as unknown as T,
): Promise<Page<T>> {
  throwIfAborted(options?.signal);
  const limit = options?.limit ?? 50;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination limit is invalid", {
      details: { field: "limit" },
    });
  }
  const cursor = options?.cursor === undefined ? undefined : decodeCursor(options.cursor);
  const all = [...(await catalog.list(kind))].sort((left, right) =>
    String(left.id).localeCompare(String(right.id)),
  );
  const visible: T[] = [];
  let lastId: string | undefined;
  let hasMore = false;
  for (const record of all) {
    if (cursor !== undefined && String(record.id) <= cursor) continue;
    if ((await ownerFor(catalog, kind, record)) !== actorRef) continue;
    if (visible.length === limit) {
      hasMore = true;
      break;
    }
    visible.push(project(record));
    lastId = String(record.id);
  }
  throwIfAborted(options?.signal);
  return Object.freeze({
    records: Object.freeze(visible),
    nextCursor: hasMore && lastId !== undefined ? encodeCursor(lastId) : null,
  });
}

async function ownedGet<K extends EntityKind>(
  catalog: AccountsCatalog,
  kind: K,
  id: EntityMap[K]["id"],
  actorRef: string,
  signal?: AbortSignal,
): Promise<EntityMap[K]> {
  throwIfAborted(signal);
  const record = await catalog.get(kind, id);
  if ((await ownerFor(catalog, kind, record)) !== actorRef) {
    throw new AccountsError("NOT_FOUND", "Record not found");
  }
  throwIfAborted(signal);
  return record;
}

async function ownerFor<K extends EntityKind>(
  catalog: AccountsCatalog,
  kind: K,
  record: EntityMap[K],
): Promise<string> {
  switch (kind) {
    case "account":
      return (record as EntityMap["account"]).ownerRef;
    case "entitlement":
      return (await catalog.get("account", (record as EntityMap["entitlement"]).accountId)).ownerRef;
    case "capacity_pool":
      return (await catalog.get("account", (record as EntityMap["capacity_pool"]).accountId)).ownerRef;
    case "access_method": {
      const entitlement = await catalog.get(
        "entitlement",
        (record as EntityMap["access_method"]).entitlementId,
      );
      return (await catalog.get("account", entitlement.accountId)).ownerRef;
    }
    case "auth_capsule":
      return (record as EntityMap["auth_capsule"]).ownerRef;
    case "credential_binding": {
      const method = await catalog.get(
        "access_method",
        (record as EntityMap["credential_binding"]).accessMethodId,
      );
      const entitlement = await catalog.get("entitlement", method.entitlementId);
      return (await catalog.get("account", entitlement.accountId)).ownerRef;
    }
  }
}

function redactAccount(record: EntityMap["account"]): ProviderAccountView {
  const safe = { ...record } as Record<string, unknown>;
  const hadSubject = safe.providerSubjectRef !== undefined || safe.providerSubjectCandidateRef !== undefined;
  delete safe.providerSubjectRef;
  delete safe.providerSubjectCandidateRef;
  if (hadSubject) safe.providerSubjectRefRedacted = true;
  return Object.freeze(safe as unknown as ProviderAccountView);
}

function scopedIdempotency(kind: EntityKind, key: string, body: unknown): string {
  return `sdk:${canonicalSha256({ kind, key, body }).slice("sha256:".length)}`;
}

function validateIdempotency(key: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(key)) {
    throw new AccountsError("VALIDATION_FAILED", "Idempotency key is invalid", {
      details: { field: "idempotencyKey" },
    });
  }
}

function encodeCursor(id: string): string {
  return Buffer.from(id, "ascii").toString("base64url");
}

function decodeCursor(cursor: string): string {
  if (!/^[A-Za-z0-9_-]{48}$/.test(cursor)) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination cursor is invalid", {
      details: { field: "cursor" },
    });
  }
  const id = Buffer.from(cursor, "base64url").toString("ascii");
  if (encodeCursor(id) !== cursor || !/^[0-9a-f-]{36}$/.test(id)) {
    throw new AccountsError("VALIDATION_FAILED", "Pagination cursor is invalid", {
      details: { field: "cursor" },
    });
  }
  return id;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
}
