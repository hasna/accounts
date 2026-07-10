import { AccountsError } from "../errors";
import { newAccountEventId } from "../domain/ids";
import type { EntityKind, EntityMap } from "../domain/models";
import type {
  AccountEvent,
  AccountsRepository,
  MutationContext,
  MutationResult,
  RepositoryDoctor,
  EligibilitySnapshot,
} from "./repository";
import {
  assertReplacement,
  cloneEntity,
  idempotencyScope,
  mutationHash,
  validateMutationContext,
} from "./shared";
import { incrementCounter, type Counter } from "../domain/counter";
import { deserializeRecordEnvelope, serializeRecordEnvelope } from "../serialization/dto";

interface IdempotencyEntry {
  readonly hash: string;
  readonly kind: EntityKind;
  readonly aggregateId: string;
  readonly eventId: AccountEvent["id"];
  readonly response: string;
}

export class InMemoryAccountsRepository implements AccountsRepository {
  private readonly records: {
    [K in EntityKind]: Map<string, EntityMap[K]>;
  } = {
    account: new Map(),
    entitlement: new Map(),
    capacity_pool: new Map(),
    access_method: new Map(),
    auth_capsule: new Map(),
    credential_binding: new Map(),
  };

  private readonly eventLog: AccountEvent[] = [];
  private readonly idempotency = new Map<string, IdempotencyEntry>();
  private closed = false;

  async get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined> {
    this.assertOpen();
    const record = this.records[kind].get(id) as EntityMap[K] | undefined;
    return record === undefined ? undefined : cloneEntity(kind, record);
  }

  async list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]> {
    this.assertOpen();
    return [...this.records[kind].values()]
      .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
      .map((record) => cloneEntity(kind, record as EntityMap[K]));
  }

  async readEligibilitySnapshot(
    accessMethodId: EntityMap["access_method"]["id"],
  ): Promise<EligibilitySnapshot> {
    this.assertOpen();
    const method = this.records.access_method.get(accessMethodId);
    const entitlement =
      method === undefined ? undefined : this.records.entitlement.get(method.entitlementId);
    const account =
      entitlement === undefined ? undefined : this.records.account.get(entitlement.accountId);
    const pool = method === undefined ? undefined : this.records.capacity_pool.get(method.capacityPoolId);
    return {
      ...(method === undefined ? {} : { method: cloneEntity("access_method", method) }),
      ...(entitlement === undefined
        ? {}
        : { entitlement: cloneEntity("entitlement", entitlement) }),
      ...(account === undefined ? {} : { account: cloneEntity("account", account) }),
      ...(pool === undefined ? {} : { pool: cloneEntity("capacity_pool", pool) }),
      capsules: [...this.records.auth_capsule.values()]
        .filter((candidate) => candidate.accessMethodId === accessMethodId)
        .map((candidate) => cloneEntity("auth_capsule", candidate)),
      bindings: [...this.records.credential_binding.values()]
        .filter((candidate) => candidate.accessMethodId === accessMethodId)
        .map((candidate) => cloneEntity("credential_binding", candidate)),
    };
  }

  async insert<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    const scope = idempotencyScope("insert", kind, context);
    const hash = mutationHash("insert", kind, record, context);
    const replay = this.replay(kind, scope, hash);
    if (replay !== undefined) return replay as MutationResult<EntityMap[K]>;
    if (this.records[kind].has(record.id)) {
      throw new AccountsError("CONFLICT", "Record already exists", {
        details: { aggregateKind: kind, aggregateId: record.id },
      });
    }
    this.assertUniqueness(kind, record);
    const event = this.makeEvent(kind, record, context);
    this.records[kind].set(record.id, record);
    this.eventLog.push(event);
    this.idempotency.set(scope, {
      hash,
      kind,
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope(kind, record),
    });
    return { record: cloneEntity(kind, record), eventId: event.id, replayed: false };
  }

  async replace<K extends EntityKind>(
    kind: K,
    input: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>> {
    this.assertOpen();
    validateMutationContext(context);
    const record = cloneEntity(kind, input);
    const scope = idempotencyScope("replace", kind, context);
    const hash = mutationHash("replace", kind, record, context, expectedRevision);
    const replay = this.replay(kind, scope, hash);
    if (replay !== undefined) return replay as MutationResult<EntityMap[K]>;
    const previous = this.records[kind].get(record.id) as EntityMap[K] | undefined;
    if (previous === undefined) {
      throw new AccountsError("NOT_FOUND", "Record not found", {
        details: { aggregateKind: kind, aggregateId: record.id },
      });
    }
    assertReplacement(kind, previous, record, expectedRevision);
    this.assertUniqueness(kind, record);
    const event = this.makeEvent(kind, record, context);
    this.records[kind].set(record.id, record);
    this.eventLog.push(event);
    this.idempotency.set(scope, {
      hash,
      kind,
      aggregateId: record.id,
      eventId: event.id,
      response: serializeRecordEnvelope(kind, record),
    });
    return { record: cloneEntity(kind, record), eventId: event.id, replayed: false };
  }

  async events(): Promise<readonly AccountEvent[]> {
    this.assertOpen();
    return this.eventLog.map((event) => ({ ...event }));
  }

  async findReplacementReplay<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]> | undefined> {
    this.assertOpen();
    validateMutationContext(context);
    const scope = idempotencyScope("replace", kind, context);
    const entry = this.idempotency.get(scope);
    if (entry === undefined) return undefined;
    const envelope = deserializeRecordEnvelope(entry.response);
    if (envelope.kind !== kind) throw new AccountsError("IDEMPOTENCY_CONFLICT", "Stored replay kind changed");
    const record = envelope.data as EntityMap[K];
    const expectedHash = mutationHash("replace", kind, record, context, expectedRevision);
    if (
      entry.hash !== expectedHash ||
      record.id !== id ||
      record.status !== to ||
      record.revision !== incrementCounter(expectedRevision)
    ) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotent transition input changed");
    }
    return { record, eventId: entry.eventId, replayed: true };
  }

  async doctor(): Promise<RepositoryDoctor> {
    this.assertOpen();
    return {
      adapter: "memory",
      schemaVersion: "1",
      migrationChecksum: "memory-reference-v1",
      foreignKeys: "not_applicable",
      journalMode: "memory",
      integrity: "ok",
      readiness: "metadata_only",
      recoveryFrontier: "unavailable",
      positiveEligibility: false,
    };
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  private replay<K extends EntityKind>(
    requestedKind: K,
    scope: string,
    hash: string,
  ): MutationResult<EntityMap[K]> | undefined {
    const entry = this.idempotency.get(scope);
    if (entry === undefined) return undefined;
    if (entry.hash !== hash) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency key was reused for different input");
    }
    if (entry.kind !== requestedKind) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency scope changed");
    }
    const envelope = deserializeRecordEnvelope(entry.response);
    if (envelope.kind !== requestedKind) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Idempotency result kind is invalid");
    }
    const record = envelope.data as EntityMap[K];
    return { record: cloneEntity(requestedKind, record), eventId: entry.eventId, replayed: true };
  }

  private makeEvent<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): AccountEvent {
    return {
      id: newAccountEventId(Date.parse(record.updatedAt)),
      aggregateKind: kind,
      aggregateId: record.id,
      aggregateRevision: record.revision,
      actorRef: context.actorRef,
      reasonCode: context.reasonCode,
      occurredAt: record.updatedAt,
    };
  }

  private assertUniqueness<K extends EntityKind>(kind: K, record: EntityMap[K]): void {
    if (kind === "account") {
      const item = record as EntityMap["account"];
      if (
        item.status !== "pending" &&
        item.providerSubjectRef !== undefined &&
        [...this.records.account.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.status !== "pending" &&
            candidate.providerKey === item.providerKey &&
            candidate.providerSubjectRef === item.providerSubjectRef,
        )
      ) {
        throw new AccountsError("CONFLICT", "Provider subject is permanently claimed");
      }
    } else if (kind === "capacity_pool") {
      const item = record as EntityMap["capacity_pool"];
      const account = this.records.account.get(item.accountId);
      if (
        [...this.records.capacity_pool.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            (candidate.serializationKey === item.serializationKey ||
              (candidate.capacityDomainRef === item.capacityDomainRef &&
                this.records.account.get(candidate.accountId)?.providerKey === account?.providerKey)),
        )
      ) {
        throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Capacity domain is already claimed");
      }
    } else if (kind === "auth_capsule") {
      const item = record as EntityMap["auth_capsule"];
      if (
        item.status !== "revoked" &&
        [...this.records.auth_capsule.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.status !== "revoked" &&
            candidate.capacityPoolId === item.capacityPoolId,
        )
      ) {
        throw new AccountsError("CONFLICT", "A live capsule already exists for this capacity pool");
      }
    } else if (kind === "credential_binding") {
      const item = record as EntityMap["credential_binding"];
      if (
        [...this.records.credential_binding.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.credentialFamilyId === item.credentialFamilyId &&
            (candidate.credentialGeneration === item.credentialGeneration ||
              candidate.capacityPoolId !== item.capacityPoolId ||
              candidate.purpose !== item.purpose ||
              candidate.resolver !== item.resolver),
        )
      ) {
        throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Credential family lineage already exists");
      }
      if (
        item.resolver === "capsule_local_native" &&
        item.status === "active" &&
        [...this.records.credential_binding.values()].some(
          (candidate) =>
            candidate.id !== item.id &&
            candidate.resolver === "capsule_local_native" &&
            candidate.status === "active" &&
            candidate.capacityPoolId === item.capacityPoolId &&
            candidate.purpose === item.purpose,
        )
      ) {
        throw new AccountsError("CONFLICT", "An active native binding already exists");
      }
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Repository is closed", {
        details: { adapter: "memory" },
      });
    }
  }
}
