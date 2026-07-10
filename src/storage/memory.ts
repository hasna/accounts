import { AccountsError } from "../errors";
import { newAccountEventId } from "../domain/ids";
import type { EntityKind, EntityMap } from "../domain/models";
import type {
  AccountEvent,
  AccountsRepository,
  MutationContext,
  MutationResult,
  RepositoryDoctor,
} from "./repository";
import {
  assertReplacement,
  cloneEntity,
  idempotencyScope,
  mutationHash,
  validateMutationContext,
} from "./shared";
import type { Counter } from "../domain/counter";
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

  async doctor(): Promise<RepositoryDoctor> {
    this.assertOpen();
    return {
      adapter: "memory",
      schemaVersion: "1",
      migrationChecksum: "memory-reference-v1",
      foreignKeys: "not_applicable",
      journalMode: "memory",
      integrity: "ok",
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

  private assertOpen(): void {
    if (this.closed) {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Repository is closed", {
        details: { adapter: "memory" },
      });
    }
  }
}
