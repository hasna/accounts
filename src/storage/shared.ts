import { AccountsError } from "../errors";
import { compareCounters, incrementCounter, type Counter } from "../domain/counter";
import type { EntityKind, EntityMap } from "../domain/models";
import { assertTransition } from "../domain/state";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import {
  deserializeRecordEnvelope,
  serializeRecordEnvelope,
  validateEntity,
} from "../serialization/dto";
import type { MutationContext } from "./repository";

const ACTOR_PATTERN = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

export function validateMutationContext(context: MutationContext): void {
  if (!ACTOR_PATTERN.test(context.actorRef)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid mutation actor", {
      details: { field: "actorRef" },
    });
  }
  if (!IDEMPOTENCY_PATTERN.test(context.idempotencyKey)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid idempotency key", {
      details: { field: "idempotencyKey" },
    });
  }
  if (!REASON_PATTERN.test(context.reasonCode)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid mutation reason code", {
      details: { field: "reasonCode" },
    });
  }
}

export function cloneEntity<K extends EntityKind>(kind: K, record: EntityMap[K]): EntityMap[K] {
  const envelope = deserializeRecordEnvelope(serializeRecordEnvelope(kind, record));
  return envelope.data as EntityMap[K];
}

export function mutationHash<K extends EntityKind>(
  operation: "insert" | "replace",
  kind: K,
  record: EntityMap[K],
  context: MutationContext,
  expectedRevision?: Counter,
): string {
  return canonicalSha256({
    operation,
    kind,
    record: validateEntity(kind, record),
    reasonCode: context.reasonCode,
    ...(expectedRevision === undefined ? {} : { expectedRevision }),
  });
}

export function idempotencyScope(
  operation: "insert" | "replace",
  kind: EntityKind,
  context: MutationContext,
): string {
  return `${context.actorRef}|${operation}|${kind}|${context.idempotencyKey}`;
}

export function assertReplacement<K extends EntityKind>(
  kind: K,
  previous: EntityMap[K],
  next: EntityMap[K],
  expectedRevision: Counter,
): void {
  if (previous.revision !== expectedRevision) {
    throw new AccountsError("STALE_REVISION", "Expected revision does not match current state", {
      details: {
        aggregateKind: kind,
        aggregateId: previous.id,
        expectedRevision,
        actualRevision: previous.revision,
      },
    });
  }
  if (next.id !== previous.id || next.createdAt !== previous.createdAt) {
    throw new AccountsError("VALIDATION_FAILED", "Immutable record identity changed");
  }
  if (Date.parse(next.updatedAt) <= Date.parse(previous.updatedAt)) {
    throw new AccountsError("VALIDATION_FAILED", "Replacement timestamp did not advance", {
      details: { field: "updatedAt" },
    });
  }
  if (next.revision !== incrementCounter(expectedRevision)) {
    throw new AccountsError("STALE_REVISION", "Replacement revision is not the exact successor", {
      details: {
        aggregateKind: kind,
        aggregateId: previous.id,
        expectedRevision: incrementCounter(expectedRevision),
        actualRevision: next.revision,
      },
    });
  }
  assertTransition(kind, previous.status, next.status);
  if (canonicalJson(stableFields(kind, previous)) !== canonicalJson(stableFields(kind, next))) {
    throw new AccountsError("VALIDATION_FAILED", "Immutable aggregate fields changed", {
      details: { aggregateKind: kind, aggregateId: previous.id },
    });
  }
  if (kind === "capacity_pool") {
    const before = previous as EntityMap["capacity_pool"];
    const after = next as EntityMap["capacity_pool"];
    if (
      compareCounters(after.capacityGeneration, before.capacityGeneration) < 0 ||
      compareCounters(after.denyGeneration, before.denyGeneration) < 0
    ) {
      throw new AccountsError("CURRENT_DENY", "Capacity generations cannot move backward");
    }
    if (
      before.denyState === "allowed" &&
      after.denyState === "denied" &&
      compareCounters(after.denyGeneration, before.denyGeneration) <= 0
    ) {
      throw new AccountsError("CURRENT_DENY", "A denial transition must advance deny generation");
    }
  }
}

function stableFields<K extends EntityKind>(kind: K, entity: EntityMap[K]): unknown {
  const common = entity as EntityMap[EntityKind];
  const { status: _status, revision: _revision, updatedAt: _updatedAt, ...base } = common;
  if (kind !== "capacity_pool") return base;
  const {
    capacityGeneration: _capacityGeneration,
    denyGeneration: _denyGeneration,
    denyState: _denyState,
    ...stable
  } = base as Omit<EntityMap["capacity_pool"], "status" | "revision" | "updatedAt">;
  return stable;
}
