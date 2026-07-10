import type { Counter } from "../domain/counter";
import type { AccountEventId, EntityId } from "../domain/ids";
import type { EntityKind, EntityMap } from "../domain/models";

export interface MutationContext {
  readonly actorRef: string;
  readonly idempotencyKey: string;
  readonly reasonCode: string;
}

export interface AccountEvent {
  readonly id: AccountEventId;
  readonly aggregateKind: EntityKind;
  readonly aggregateId: EntityId;
  readonly aggregateRevision: Counter;
  readonly actorRef: string;
  readonly reasonCode: string;
  readonly occurredAt: string;
}

export interface MutationResult<T> {
  readonly record: T;
  readonly eventId: AccountEventId;
  readonly replayed: boolean;
}

export interface RepositoryDoctor {
  readonly adapter: "memory" | "sqlite";
  readonly schemaVersion: string;
  readonly migrationChecksum: string;
  readonly foreignKeys: boolean | "not_applicable";
  readonly journalMode: "memory" | "wal";
  readonly integrity: "ok";
}

export interface AccountsRepository {
  get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined>;
  list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]>;
  insert<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
  replace<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
  events(): Promise<readonly AccountEvent[]>;
  doctor(): Promise<RepositoryDoctor>;
  close(): Promise<void>;
}

export const POSTGRES_ADAPTER_STATUS = Object.freeze({
  adapter: "postgres" as const,
  implemented: false as const,
  conformanceClaim: false as const,
  target: "self_hosted" as const,
});
