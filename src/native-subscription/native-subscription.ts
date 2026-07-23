import {
  sign as signBytes,
  type KeyLike,
} from "node:crypto";

import { AccountsError } from "./errors.js";
import { parseCounter, type Counter } from "./counter.js";
import { generateUuidV7, isUuidV7 } from "./ids.js";
import {
  canonicalJson,
  canonicalSha256,
} from "./json.js";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
  type OnlineGenerationReceiptUseCasRequest,
  type OnlineGenerationReceiptUseCasResult,
  type OnlineGenerationReceiptUseStore,
} from "./online-generation-receipt.js";
export const NATIVE_SUBSCRIPTION_PROBE_REQUEST_SCHEMA_VERSION =
  "accounts.native-subscription-probe-request/v1" as const;
export const NATIVE_SUBSCRIPTION_PROBE_RESULT_SCHEMA_VERSION =
  "accounts.native-subscription-probe-result/v1" as const;

const PRINCIPAL =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const PROBE_KEYS = Object.freeze([
  "schema_version",
  "command",
  "owner_ref",
  "provider_account_id",
  "subscription_id",
  "account_lane_id",
  "auth_capsule_id",
  "canonical_node_id",
  "node_key_thumbprint",
  "node_generation",
  "placement_generation",
  "auth_generation",
  "auth_state_revision",
] as const);

const CAPABILITY_USE_REQUEST_KEYS = Object.freeze([
  "schema_version",
  "schema_digest",
  "consume_request_id",
  "capability_id",
  "capability_digest",
  "nonce",
  "subject",
  "actor_principal",
  "effect_namespace_id",
  "account_lane_id",
  "capacity_pool_id",
  "capacity_domain_ref",
  "serialization_key_digest",
  "credential_family_id",
  "resource_lease_id",
  "resource_id",
  "resource_lifecycle_generation",
  "operation_id",
  "operation_digest",
  "operation_execution_epoch",
  "sender_key_thumbprint",
  "channel_binding_digest",
  "canonical_request_digest",
  "provider_destination_policy_digest",
  "online_receipt_id",
  "online_receipt_digest",
  "model_call_anchor_digest",
  "expected_use_count",
  "max_uses",
  "not_after",
  "idempotency_key_digest",
] as const);

export interface NativeSubscriptionProbeRequest {
  readonly schema_version: typeof NATIVE_SUBSCRIPTION_PROBE_REQUEST_SCHEMA_VERSION;
  readonly command: "PROBE_NATIVE";
  readonly owner_ref: string;
  readonly provider_account_id: string;
  readonly subscription_id: string;
  readonly account_lane_id: string;
  readonly auth_capsule_id: string;
  readonly canonical_node_id: string;
  readonly node_key_thumbprint: string;
  readonly node_generation: Counter;
  readonly placement_generation: Counter;
  readonly auth_generation: Counter;
  readonly auth_state_revision: Counter;
}

export interface NativeSubscriptionBindingSnapshot {
  readonly ownerRef: string;
  readonly providerAccountId: string;
  readonly subscriptionId: string;
  readonly accountLaneId: string;
  readonly authCapsuleId: string;
  readonly canonicalNodeId: string;
  readonly nodeKeyThumbprint: string;
  readonly nodeGeneration: Counter;
  readonly placementGeneration: Counter;
  readonly authGeneration: Counter;
  readonly authStateRevision: Counter;
  readonly accountRevision: Counter;
  readonly capsuleRevision: Counter;
  readonly accountStatus: "active" | "suspended" | "revoked";
  readonly subscriptionStatus: "active" | "paused" | "expired" | "revoked";
  readonly accountLaneStatus: "ready" | "draining" | "disabled" | "retired";
  readonly capsuleStatus: "ready" | "degraded" | "maintenance" | "quiescing" | "revoked";
  readonly liveLeaseCount: Counter;
  readonly drainState: "not_started" | "draining" | "drained";
  readonly zeroLiveEvidenceDigest: string;
  readonly drainEvidenceDigest: string;
  readonly evidenceExpiresAt: string;
}

export interface NativeSubscriptionSnapshotSource {
  read(accountLaneId: string):
    | NativeSubscriptionBindingSnapshot
    | undefined
    | Promise<NativeSubscriptionBindingSnapshot | undefined>;
}

export interface NativeSubscriptionProbeResult {
  readonly schema_version: typeof NATIVE_SUBSCRIPTION_PROBE_RESULT_SCHEMA_VERSION;
  readonly capability_eligible: boolean;
  readonly maintenance_ready: boolean;
  readonly reason_codes: readonly string[];
  readonly owner_ref: string;
  readonly provider_account_id: string;
  readonly subscription_id: string;
  readonly account_lane_id: string;
  readonly auth_capsule_id: string;
  readonly canonical_node_id: string;
  readonly node_key_thumbprint: string;
  readonly node_generation: Counter;
  readonly placement_generation: Counter;
  readonly auth_generation: Counter;
  readonly auth_state_revision: Counter;
  readonly account_revision: Counter;
  readonly capsule_revision: Counter;
  readonly account_status: NativeSubscriptionBindingSnapshot["accountStatus"];
  readonly subscription_status: NativeSubscriptionBindingSnapshot["subscriptionStatus"];
  readonly account_lane_status: NativeSubscriptionBindingSnapshot["accountLaneStatus"];
  readonly capsule_status: NativeSubscriptionBindingSnapshot["capsuleStatus"];
  readonly live_lease_count: Counter;
  readonly drain_state: NativeSubscriptionBindingSnapshot["drainState"];
  readonly zero_live_evidence_digest: string;
  readonly drain_evidence_digest: string;
  readonly evidence_expires_at: string;
  readonly binding_digest: string;
}

type JsonObject = Record<string, unknown>;

export async function evaluateNativeSubscriptionProbe(
  source: unknown,
  snapshotSource: NativeSubscriptionSnapshotSource,
  authenticatedOwnerRef: string,
  now: Date = new Date(),
): Promise<NativeSubscriptionProbeResult> {
  const request = parseProbeRequest(source);
  principal(authenticatedOwnerRef);
  validDate(now);
  const found = await snapshotSource.read(request.account_lane_id);
  if (found === undefined) throw new AccountsError("NOT_FOUND", "Native subscription was not found");
  const snapshot = validateSnapshot(found);
  const bindingReasons: string[] = [];
  if (request.owner_ref !== authenticatedOwnerRef || snapshot.ownerRef !== authenticatedOwnerRef) {
    bindingReasons.push("OWNER_MISMATCH");
  }
  if (
    request.provider_account_id !== snapshot.providerAccountId ||
    request.subscription_id !== snapshot.subscriptionId ||
    request.account_lane_id !== snapshot.accountLaneId ||
    request.auth_capsule_id !== snapshot.authCapsuleId
  ) {
    bindingReasons.push("SUBSCRIPTION_BINDING_MISMATCH");
  }
  if (
    request.canonical_node_id !== snapshot.canonicalNodeId ||
    request.node_key_thumbprint !== snapshot.nodeKeyThumbprint
  ) {
    bindingReasons.push("NODE_BINDING_MISMATCH");
  }
  if (
    request.node_generation !== snapshot.nodeGeneration ||
    request.placement_generation !== snapshot.placementGeneration ||
    request.auth_generation !== snapshot.authGeneration ||
    request.auth_state_revision !== snapshot.authStateRevision
  ) {
    bindingReasons.push("GENERATION_MISMATCH");
  }
  const capabilityReasons = [...bindingReasons];
  if (snapshot.accountStatus !== "active") capabilityReasons.push("ACCOUNT_NOT_ACTIVE");
  if (snapshot.subscriptionStatus !== "active") capabilityReasons.push("SUBSCRIPTION_NOT_ACTIVE");
  if (snapshot.accountLaneStatus !== "ready") capabilityReasons.push("ACCOUNT_LANE_NOT_READY");
  if (snapshot.capsuleStatus !== "ready") capabilityReasons.push("CAPSULE_NOT_READY");
  const maintenanceReasons = [...bindingReasons];
  if (snapshot.accountStatus === "revoked") maintenanceReasons.push("ACCOUNT_REVOKED");
  if (snapshot.subscriptionStatus === "expired" || snapshot.subscriptionStatus === "revoked") {
    maintenanceReasons.push("SUBSCRIPTION_TERMINAL");
  }
  if (snapshot.accountLaneStatus === "disabled" || snapshot.accountLaneStatus === "retired") {
    maintenanceReasons.push("ACCOUNT_LANE_TERMINAL");
  }
  if (snapshot.capsuleStatus === "revoked") maintenanceReasons.push("CAPSULE_REVOKED");
  if (snapshot.liveLeaseCount !== "0") maintenanceReasons.push("LIVE_LEASES_PRESENT");
  if (snapshot.drainState !== "drained") maintenanceReasons.push("DRAIN_NOT_COMPLETE");
  if (Date.parse(snapshot.evidenceExpiresAt) <= now.getTime()) {
    maintenanceReasons.push("DRAIN_EVIDENCE_STALE");
  }
  const uniqueReasons = [...new Set([...capabilityReasons, ...maintenanceReasons])].sort();
  const projection = {
    schema_version: NATIVE_SUBSCRIPTION_PROBE_RESULT_SCHEMA_VERSION,
    capability_eligible: capabilityReasons.length === 0,
    maintenance_ready: maintenanceReasons.length === 0,
    reason_codes: Object.freeze(uniqueReasons),
    owner_ref: snapshot.ownerRef,
    provider_account_id: snapshot.providerAccountId,
    subscription_id: snapshot.subscriptionId,
    account_lane_id: snapshot.accountLaneId,
    auth_capsule_id: snapshot.authCapsuleId,
    canonical_node_id: snapshot.canonicalNodeId,
    node_key_thumbprint: snapshot.nodeKeyThumbprint,
    node_generation: snapshot.nodeGeneration,
    placement_generation: snapshot.placementGeneration,
    auth_generation: snapshot.authGeneration,
    auth_state_revision: snapshot.authStateRevision,
    account_revision: snapshot.accountRevision,
    capsule_revision: snapshot.capsuleRevision,
    account_status: snapshot.accountStatus,
    subscription_status: snapshot.subscriptionStatus,
    account_lane_status: snapshot.accountLaneStatus,
    capsule_status: snapshot.capsuleStatus,
    live_lease_count: snapshot.liveLeaseCount,
    drain_state: snapshot.drainState,
    zero_live_evidence_digest: snapshot.zeroLiveEvidenceDigest,
    drain_evidence_digest: snapshot.drainEvidenceDigest,
    evidence_expires_at: snapshot.evidenceExpiresAt,
    binding_digest: canonicalSha256({
      auth_capsule_id: snapshot.authCapsuleId,
      auth_generation: snapshot.authGeneration,
      auth_state_revision: snapshot.authStateRevision,
      canonical_node_id: snapshot.canonicalNodeId,
      node_generation: snapshot.nodeGeneration,
      node_key_thumbprint: snapshot.nodeKeyThumbprint,
      owner_ref: snapshot.ownerRef,
      placement_generation: snapshot.placementGeneration,
      provider_account_id: snapshot.providerAccountId,
      schema_version: "accounts.native-subscription-binding/v1",
      subscription_id: snapshot.subscriptionId,
    }),
  } satisfies NativeSubscriptionProbeResult;
  return Object.freeze(projection);
}

export interface NativeCapabilityUseCurrentState {
  readonly catalogIncarnation: string;
  readonly recoveryFrontierSequence: Counter;
  readonly recoveryFrontierHash: string;
}

export interface NativeCapabilityUseReceiptIssuerOptions {
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly keyId: string;
  readonly audience: string;
  readonly privateKey: KeyLike;
}

export interface InMemoryNativeCapabilityUseStoreOptions
  extends NativeCapabilityUseReceiptIssuerOptions {
  readonly clock?: () => Date;
  readonly idFactory?: (nowMs: number) => string;
  readonly validateCurrent: (
    request: OnlineGenerationReceiptUseCasRequest,
  ) => NativeCapabilityUseCurrentState | Promise<NativeCapabilityUseCurrentState>;
}

/**
 * Process-local conformance adapter only. It proves CAS/replay semantics but is
 * deliberately not a production substitute for the durable Accounts store.
 */
export class InMemoryNativeCapabilityUseStore implements OnlineGenerationReceiptUseStore {
  private readonly clock: () => Date;
  private readonly idFactory: (nowMs: number) => string;
  private readonly requests = new Map<string, { readonly hash: string; readonly bytes: Uint8Array }>();
  private readonly idempotencyKeys = new Map<string, string>();
  private readonly capabilities = new Set<string>();
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly options: InMemoryNativeCapabilityUseStoreOptions) {
    reference(options.issuer);
    reference(options.issuerIncarnation);
    reference(options.keyId);
    reference(options.audience);
    this.clock = options.clock ?? (() => new Date());
    this.idFactory = options.idFactory ?? generateUuidV7;
  }

  async compareAndConsume(
    source: OnlineGenerationReceiptUseCasRequest,
  ): Promise<OnlineGenerationReceiptUseCasResult> {
    const request = parseCapabilityUseRequest(source);
    const requestHash = canonicalSha256(request);
    return this.serialize(async () => {
      const prior = this.requests.get(request.consume_request_id);
      if (prior !== undefined) {
        return prior.hash === requestHash
          ? { status: "replayed", signedReceipt: Uint8Array.from(prior.bytes) }
          : { status: "idempotency_conflict" };
      }
      if (this.idempotencyKeys.has(request.idempotency_key_digest)) {
        return { status: "idempotency_conflict" };
      }
      if (this.capabilities.has(request.capability_id)) return { status: "exhausted" };
      const now = validDate(this.clock());
      if (Date.parse(request.not_after) <= now.getTime()) return { status: "conflict" };
      const current = validateCapabilityUseCurrentState(
        await this.options.validateCurrent(Object.freeze({ ...request })),
      );
      const bytes = issueNativeCapabilityUseReceipt(
        request,
        current,
        this.options,
        now,
        this.idFactory,
      );
      this.requests.set(request.consume_request_id, { hash: requestHash, bytes });
      this.idempotencyKeys.set(
        request.idempotency_key_digest,
        request.consume_request_id,
      );
      this.capabilities.add(request.capability_id);
      return { status: "consumed", signedReceipt: Uint8Array.from(bytes) };
    });
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

export class StaticNativeSubscriptionSnapshotSource implements NativeSubscriptionSnapshotSource {
  private readonly records = new Map<string, NativeSubscriptionBindingSnapshot>();

  constructor(records: readonly NativeSubscriptionBindingSnapshot[]) {
    for (const record of records) {
      const snapshot = validateSnapshot(record);
      if (this.records.has(snapshot.accountLaneId)) throw new AccountsError("CONFLICT", "Duplicate native subscription");
      this.records.set(snapshot.accountLaneId, snapshot);
    }
  }

  read(accountLaneId: string): NativeSubscriptionBindingSnapshot | undefined {
    const value = this.records.get(accountLaneId);
    return value === undefined ? undefined : Object.freeze({ ...value });
  }
}

export function parseNativeSubscriptionProbeRequest(source: unknown): NativeSubscriptionProbeRequest {
  return parseProbeRequest(source);
}

export function parseNativeCapabilityUseRequest(
  source: unknown,
): OnlineGenerationReceiptUseCasRequest {
  return parseCapabilityUseRequest(source);
}

export function validateNativeCapabilityUseCurrentState(
  source: unknown,
): NativeCapabilityUseCurrentState {
  return validateCapabilityUseCurrentState(source);
}

export function issueNativeCapabilityUseReceipt(
  source: OnlineGenerationReceiptUseCasRequest,
  currentSource: NativeCapabilityUseCurrentState,
  issuer: NativeCapabilityUseReceiptIssuerOptions,
  committedAt: Date,
  idFactory: (nowMs: number) => string = generateUuidV7,
): Uint8Array {
  const request = parseCapabilityUseRequest(source);
  const current = validateCapabilityUseCurrentState(currentSource);
  reference(issuer.issuer);
  reference(issuer.issuerIncarnation);
  reference(issuer.keyId);
  reference(issuer.audience);
  const now = validDate(committedAt);
  if (Date.parse(request.not_after) <= now.getTime()) {
    throw new AccountsError("CONFLICT", "Capability use expired before commit");
  }
  const consumeReceiptId = idFactory(now.getTime());
  if (!isUuidV7(consumeReceiptId)) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Identifier source failed");
  }
  const useId = canonicalSha256({
    capability_id: request.capability_id,
    channel_binding_digest: request.channel_binding_digest,
    model_call_anchor_digest: request.model_call_anchor_digest,
    nonce: request.nonce,
    operation_id: request.operation_id,
    resource_lease_id: request.resource_lease_id,
    schema_version: "accounts.capability-use.v1",
    sender_key_thumbprint: request.sender_key_thumbprint,
    use_ordinal: "1",
  });
  const unsigned = {
    schema_version: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
    schema_digest: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    consume_request_id: request.consume_request_id,
    consume_receipt_id: consumeReceiptId,
    issuer: issuer.issuer,
    issuer_incarnation: issuer.issuerIncarnation,
    key_id: issuer.keyId,
    audience: issuer.audience,
    capability_id: request.capability_id,
    capability_digest: request.capability_digest,
    nonce: request.nonce,
    subject: request.subject,
    actor_principal: request.actor_principal,
    effect_namespace_id: request.effect_namespace_id,
    account_lane_id: request.account_lane_id,
    capacity_pool_id: request.capacity_pool_id,
    serialization_key_digest: request.serialization_key_digest,
    resource_lease_id: request.resource_lease_id,
    operation_id: request.operation_id,
    operation_execution_epoch: request.operation_execution_epoch,
    sender_key_thumbprint: request.sender_key_thumbprint,
    channel_binding_digest: request.channel_binding_digest,
    canonical_request_digest: request.canonical_request_digest,
    online_receipt_digest: request.online_receipt_digest,
    model_call_anchor_digest: request.model_call_anchor_digest,
    max_uses: "1",
    prior_use_count: "0",
    next_use_count: "1",
    use_ordinal: "1",
    use_id: useId,
    committed_at: now.toISOString(),
    expires_at: request.not_after,
    catalog_incarnation: current.catalogIncarnation,
    recovery_frontier_sequence: current.recoveryFrontierSequence,
    recovery_frontier_hash: current.recoveryFrontierHash,
  } as const;
  const receipt = { ...unsigned, signature: signCanonical(unsigned, issuer.privateKey) };
  return Uint8Array.from(Buffer.from(canonicalJson(receipt), "utf8"));
}

function parseProbeRequest(source: unknown): NativeSubscriptionProbeRequest {
  const value = plainObject(source);
  exactKeys(value, PROBE_KEYS);
  if (value.schema_version !== NATIVE_SUBSCRIPTION_PROBE_REQUEST_SCHEMA_VERSION) throw invalid("schema_version");
  if (value.command !== "PROBE_NATIVE") throw invalid("command");
  principal(value.owner_ref);
  for (const key of ["provider_account_id", "subscription_id", "account_lane_id", "auth_capsule_id", "canonical_node_id"] as const) uuid(value[key]);
  digest(value.node_key_thumbprint);
  for (const key of ["node_generation", "placement_generation", "auth_generation", "auth_state_revision"] as const) parseCounter(value[key]);
  return Object.freeze({ ...value }) as unknown as NativeSubscriptionProbeRequest;
}

function parseCapabilityUseRequest(source: unknown): OnlineGenerationReceiptUseCasRequest {
  const value = plainObject(source);
  exactKeys(value, CAPABILITY_USE_REQUEST_KEYS);
  if (
    value.schema_version !== CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION ||
    value.schema_digest !== CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST
  ) throw invalid("schema_version");
  for (const key of ["consume_request_id", "capability_id", "account_lane_id", "capacity_pool_id", "resource_lease_id", "operation_id", "online_receipt_id"] as const) uuid(value[key]);
  for (const key of ["capability_digest", "serialization_key_digest", "operation_digest", "sender_key_thumbprint", "channel_binding_digest", "canonical_request_digest", "provider_destination_policy_digest", "online_receipt_digest", "model_call_anchor_digest", "idempotency_key_digest"] as const) digest(value[key]);
  for (const key of ["nonce", "effect_namespace_id", "capacity_domain_ref", "credential_family_id", "resource_id"] as const) reference(value[key]);
  principal(value.subject);
  principal(value.actor_principal);
  for (const key of ["resource_lifecycle_generation", "operation_execution_epoch", "expected_use_count", "max_uses"] as const) parseCounter(value[key]);
  if (value.expected_use_count !== "0" || value.max_uses !== "1") throw invalid("max_uses");
  timestamp(value.not_after);
  return Object.freeze({ ...value }) as unknown as OnlineGenerationReceiptUseCasRequest;
}

function validateCapabilityUseCurrentState(source: unknown): NativeCapabilityUseCurrentState {
  const value = plainObject(source);
  exactKeys(value, ["catalogIncarnation", "recoveryFrontierSequence", "recoveryFrontierHash"]);
  reference(value.catalogIncarnation);
  parseCounter(value.recoveryFrontierSequence);
  digest(value.recoveryFrontierHash);
  return Object.freeze({ ...value }) as unknown as NativeCapabilityUseCurrentState;
}

function validateSnapshot(source: unknown): NativeSubscriptionBindingSnapshot {
  const value = plainObject(source);
  exactKeys(value, [
    "ownerRef", "providerAccountId", "subscriptionId", "accountLaneId", "authCapsuleId",
    "canonicalNodeId", "nodeKeyThumbprint", "nodeGeneration", "placementGeneration",
    "authGeneration", "authStateRevision", "accountRevision", "capsuleRevision",
    "accountStatus", "subscriptionStatus", "accountLaneStatus", "capsuleStatus",
    "liveLeaseCount", "drainState", "zeroLiveEvidenceDigest", "drainEvidenceDigest",
    "evidenceExpiresAt",
  ]);
  principal(value.ownerRef);
  for (const key of ["providerAccountId", "subscriptionId", "accountLaneId", "authCapsuleId", "canonicalNodeId"] as const) uuid(value[key]);
  digest(value.nodeKeyThumbprint);
  for (const key of ["nodeGeneration", "placementGeneration", "authGeneration", "authStateRevision", "accountRevision", "capsuleRevision", "liveLeaseCount"] as const) parseCounter(value[key]);
  if (!["active", "suspended", "revoked"].includes(String(value.accountStatus))) throw invalid("accountStatus");
  if (!["active", "paused", "expired", "revoked"].includes(String(value.subscriptionStatus))) throw invalid("subscriptionStatus");
  if (!["ready", "draining", "disabled", "retired"].includes(String(value.accountLaneStatus))) throw invalid("accountLaneStatus");
  if (!["ready", "degraded", "maintenance", "quiescing", "revoked"].includes(String(value.capsuleStatus))) throw invalid("capsuleStatus");
  if (!["not_started", "draining", "drained"].includes(String(value.drainState))) throw invalid("drainState");
  digest(value.zeroLiveEvidenceDigest);
  digest(value.drainEvidenceDigest);
  timestamp(value.evidenceExpiresAt);
  return Object.freeze({ ...value }) as unknown as NativeSubscriptionBindingSnapshot;
}

function plainObject(value: unknown): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw invalid("body");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw invalid("body");
  if (Object.getOwnPropertySymbols(value).length !== 0) throw invalid("body");
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) throw invalid("body");
  }
  return value as JsonObject;
}

function exactKeys(value: JsonObject, expected: readonly string[]): void {
  if (Object.keys(value).length !== expected.length) throw invalid("body");
  const allowed = new Set(expected);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw invalid("body");
  for (const key of expected) if (!Object.hasOwn(value, key)) throw invalid("body");
}

function reference(value: unknown): string {
  if (typeof value !== "string" || !REFERENCE.test(value)) throw invalid("reference");
  return value;
}

function principal(value: unknown): string {
  if (typeof value !== "string" || !PRINCIPAL.test(value)) throw invalid("ownerRef");
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value)) throw invalid("digest");
  return value;
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !isUuidV7(value)) throw invalid("id");
  return value;
}

function timestamp(value: unknown): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) throw invalid("timestamp");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) throw invalid("timestamp");
  return value;
}

function validDate(value: unknown): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw invalid("clock");
  return new Date(value);
}

function signCanonical(value: unknown, key: KeyLike): string {
  return signBytes(null, Buffer.from(canonicalJson(value), "utf8"), key).toString("base64url");
}

function invalid(field: string): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Native subscription input is invalid", {
    details: { field },
  });
}
