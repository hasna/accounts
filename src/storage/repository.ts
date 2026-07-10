import type { Counter } from "../domain/counter";
import type { AccountEventId, EntityId } from "../domain/ids";
import type {
  Account,
  AccessMethod,
  AuthCapsule,
  CapacityPool,
  CredentialBinding,
  EntityKind,
  EntityMap,
  Entitlement,
} from "../domain/models";

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
  readonly readiness: "metadata_only";
  readonly recoveryFrontier: "unavailable";
  readonly positiveEligibility: false;
}

export interface EligibilitySnapshot {
  readonly method?: AccessMethod;
  readonly entitlement?: Entitlement;
  readonly account?: Account;
  readonly pool?: CapacityPool;
  readonly capsules: readonly AuthCapsule[];
  readonly bindings: readonly CredentialBinding[];
}

export interface AccountsRepository {
  get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K] | undefined>;
  list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]>;
  readEligibilitySnapshot(accessMethodId: AccessMethod["id"]): Promise<EligibilitySnapshot>;
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
  findReplacementReplay<K extends EntityKind>(
    kind: K,
    id: EntityMap[K]["id"],
    to: EntityMap[K]["status"],
    expectedRevision: Counter,
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]> | undefined>;
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
