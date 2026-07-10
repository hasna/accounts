import { createHash } from "node:crypto";

import { generateUuidV7 } from "../domain/ids";
import { AccountsError } from "../errors";
import type {
  BootstrapIntent,
  BootstrapIntentCreateContext,
  BootstrapIntentStore,
  HttpIdempotencyRequest,
  HttpIdempotencyStore,
  StoredHttpResponse,
} from "./types";

function stableScope(parts: readonly string[]): string {
  return createHash("sha256").update(parts.join("\u0000"), "utf8").digest("hex");
}

/**
 * Process-local implementation for local/test use. Self-hosted multi-replica
 * deployments must inject a durable store with the same conditional-insert
 * behavior.
 */
export class MemoryHttpIdempotencyStore implements HttpIdempotencyStore {
  private readonly entries = new Map<
    string,
    { readonly requestDigest: string; readonly result: Promise<StoredHttpResponse> }
  >();

  async execute(
    request: HttpIdempotencyRequest,
    operation: () => Promise<StoredHttpResponse>,
  ): Promise<StoredHttpResponse> {
    const scope = stableScope([
      request.actorRef,
      request.audience,
      request.method,
      request.route,
      request.key,
    ]);
    const existing = this.entries.get(scope);
    if (existing !== undefined) {
      if (existing.requestDigest !== request.requestDigest) {
        throw new AccountsError("IDEMPOTENCY_CONFLICT", "Idempotency request digest mismatch");
      }
      return existing.result;
    }

    const result = operation();
    this.entries.set(scope, { requestDigest: request.requestDigest, result });
    try {
      return await result;
    } catch (error) {
      if (this.entries.get(scope)?.result === result) this.entries.delete(scope);
      throw error;
    }
  }
}

/** Inert metadata only. There is intentionally no API-consumption method. */
export class MemoryBootstrapIntentStore implements BootstrapIntentStore {
  private readonly intents = new Map<string, BootstrapIntent>();
  private readonly replay = new Map<
    string,
    { readonly requestDigest: string; readonly intentId: string }
  >();

  constructor(private readonly lifetimeMs = 5 * 60_000) {
    if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 1_000 || lifetimeMs > 15 * 60_000) {
      throw new AccountsError("VALIDATION_FAILED", "Bootstrap intent lifetime is invalid", {
        details: { field: "bootstrapIntentLifetimeMs" },
      });
    }
  }

  async create(context: BootstrapIntentCreateContext): Promise<BootstrapIntent> {
    const replayKey = stableScope([
      context.principal.actorRef,
      context.principal.audience,
      String(context.capsule.id),
      context.idempotencyKey,
    ]);
    const prior = this.replay.get(replayKey);
    if (prior !== undefined) {
      if (prior.requestDigest !== context.requestDigest) {
        throw new AccountsError("IDEMPOTENCY_CONFLICT", "Bootstrap intent replay mismatch");
      }
      const intent = this.intents.get(prior.intentId);
      if (intent === undefined) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Bootstrap intent replay is unavailable");
      }
      return this.projectStatus(intent, Date.parse(context.now));
    }

    const createdAt = new Date(context.now).toISOString();
    const intent: BootstrapIntent = Object.freeze({
      schemaVersion: "accounts.bootstrap-intent.v1",
      id: generateUuidV7(Date.parse(createdAt)),
      authCapsuleId: context.capsule.id,
      ownerRef: context.capsule.ownerRef,
      canonicalNodeId: context.capsule.placementRef,
      nodeGeneration: context.capsule.nodeGeneration,
      placementGeneration: context.capsule.placementGeneration,
      authGeneration: context.capsule.authGeneration,
      capsuleRevision: context.capsule.revision,
      status: "pending",
      createdAt,
      expiresAt: new Date(Date.parse(createdAt) + this.lifetimeMs).toISOString(),
    });
    this.intents.set(intent.id, intent);
    this.replay.set(replayKey, { requestDigest: context.requestDigest, intentId: intent.id });
    return intent;
  }

  async get(authCapsuleId: BootstrapIntent["authCapsuleId"], intentId: string): Promise<BootstrapIntent | undefined> {
    const intent = this.intents.get(intentId);
    if (intent === undefined || intent.authCapsuleId !== authCapsuleId) return undefined;
    return this.projectStatus(intent, Date.now());
  }

  private projectStatus(intent: BootstrapIntent, now: number): BootstrapIntent {
    if (now < Date.parse(intent.expiresAt)) return intent;
    return Object.freeze({ ...intent, status: "expired" });
  }
}
