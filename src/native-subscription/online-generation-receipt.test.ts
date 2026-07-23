import { describe, expect, test } from "bun:test";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as ed25519Sign,
  type KeyObject,
} from "node:crypto";

import { AccountsError } from "./errors.js";
import { parseCounter } from "./counter.js";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION,
  consumeOnlineGenerationCheckReceiptUse,
  projectOnlineGenerationCheckReceipt,
  verifyAllowedOnlineGenerationCheckReceipt,
  verifyOnlineGenerationCheckReceipt,
  type OnlineGenerationCheckReceiptDraft,
  type OnlineGenerationCheckReceiptExpectation,
  type OnlineGenerationCheckReceiptTrustRoot,
  type OnlineGenerationReceiptUseCasRequest,
  type OnlineGenerationReceiptUseGuard,
  type OnlineGenerationReceiptUseStore,
  type ProviderDestinationPolicy,
} from "./online-generation-receipt.js";
import {
  canonicalJson,
  canonicalSha256,
  parseClosedJsonBytes,
} from "./json.js";

const NOW = new Date("2026-07-10T12:00:30.000Z");
const ISSUED_AT = "2026-07-10T12:00:00.000Z";
const NOT_BEFORE = "2026-07-10T11:59:59.000Z";
const EXPIRES_AT = "2026-07-10T12:01:00.000Z";
const LEASE_EXPIRES_AT = "2026-07-10T12:02:00.000Z";
const EXECUTION_EXPIRES_AT = "2026-07-10T12:01:30.000Z";
const OTHER_TIMESTAMP = "2026-07-10T12:00:01.000Z";

const IDS = {
  receipt: "018f0f00-0001-7000-8000-000000000001",
  capability: "018f0f00-0002-7000-8000-000000000002",
  routeLineage: "018f0f00-0003-7000-8000-000000000003",
  route: "018f0f00-0004-7000-8000-000000000004",
  run: "018f0f00-0005-7000-8000-000000000005",
  attempt: "018f0f00-0006-7000-8000-000000000006",
  attemptLease: "018f0f00-0007-7000-8000-000000000007",
  resourceLease: "018f0f00-0008-7000-8000-000000000008",
  operation: "018f0f00-0009-7000-8000-000000000009",
  providerAccount: "018f0f00-000a-7000-8000-00000000000a",
  accountLane: "018f0f00-000b-7000-8000-00000000000b",
  capacityPool: "018f0f00-000c-7000-8000-00000000000c",
  credentialBinding: "018f0f00-000d-7000-8000-00000000000d",
  authCapsule: "018f0f00-000e-7000-8000-00000000000e",
  canonicalNode: "018f0f00-000f-7000-8000-00000000000f",
  credentialFamily: "018f0f00-0010-7000-8000-000000000010",
  consumeRequest: "018f0f00-0011-7000-8000-000000000011",
  consumeReceipt: "018f0f00-0012-7000-8000-000000000012",
  other: "018f0f00-0099-7000-8000-000000000099",
  other2: "018f0f00-0098-7000-8000-000000000098",
} as const;

const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;
const C0 = parseCounter("0");
const C1 = parseCounter("1");
const C2 = parseCounter("2");
const C3 = parseCounter("3");
const SELF_HOSTED_ISSUER = "accounts:self-hosted:primary";
const AUDIENCE = "infinity:self-hosted:primary";
const SUBJECT = "principal:service:hasna:infinity";

const destinationPolicy = Object.freeze({
  scheme: "https",
  normalized_host: "api.example.test",
  port: "443",
  operation_path: "/v1/responses",
  model: "model.example",
  request_body_digest: D0,
  tls_server_name: "api.example.test",
  resolved_address_class: "public_global",
  egress_policy_digest: D1,
} as const satisfies ProviderDestinationPolicy);
const destinationPolicyDigest = canonicalSha256(destinationPolicy);

const keys = generateKeyPairSync("ed25519");
const forgedKeys = generateKeyPairSync("ed25519");
// Generated independently with Python cryptography 41 from seed bytes 0x01..0x20.
const goldenPrivateKey = createPrivateKey({
  key: Buffer.from(
    "MC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
    "base64",
  ),
  format: "der",
  type: "pkcs8",
});
const goldenPublicKey = createPublicKey({
  key: Buffer.from(
    "MCowBQYDK2VwAyEAebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=",
    "base64",
  ),
  format: "der",
  type: "spki",
});
const PYTHON_GOLDEN_SIGNATURE =
  "4GkyUaNlXLhpVuRWI7IXlvKi23r0lvo54Dn2sKOC6jqdqIXcaUKRLWNSTDuDii0ONlhdm3iMEdfkZj3BSdtKAQ";

function commonDraft() {
  return {
    schema_version: ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION,
    schema_digest: D2,
    receipt_id: IDS.receipt,
    issuer: SELF_HOSTED_ISSUER,
    issuer_incarnation: "accounts-deployment-2026-07-10",
    key_id: "accounts-signing-1",
    audience: AUDIENCE,
    nonce: "nonce-018f0f00-0001",
    issued_at: ISSUED_AT,
    not_before: NOT_BEFORE,
    expires_at: EXPIRES_AT,
    capability_id: IDS.capability,
    capability_digest: D3,
    authority_epoch: C3,
    route_lineage_id: IDS.routeLineage,
    route_id: IDS.route,
    route_epoch: C2,
    run_id: IDS.run,
    attempt_id: IDS.attempt,
    attempt_lease_id: IDS.attemptLease,
    lease_epoch: C2,
    resource_lease_id: IDS.resourceLease,
    resource_id: "account-resource:lane-a",
    resource_lifecycle_generation: C1,
    lease_expires_at: LEASE_EXPIRES_AT,
    operation_id: IDS.operation,
    operation_digest: D4,
    operation_execution_epoch: C1,
    operation_execution_expires_at: EXECUTION_EXPIRES_AT,
    subject: SUBJECT,
    actor_principal: "principal:human:hasna:owner-a",
    lease_holder_principal: "principal:service:hasna:scheduler-a",
    operation_executor_principal: "principal:service:hasna:executor-a",
    sender_key_thumbprint: D0,
    provider_account_id: IDS.providerAccount,
    account_lane_id: IDS.accountLane,
    capacity_pool_id: IDS.capacityPool,
    capacity_domain_ref: "provider:openai:shared-limit-a",
    credential_family_id: IDS.credentialFamily,
    allowed: true as const,
    deny_state: "allowed" as const,
    reason_codes: [] as const,
    capacity_generation: C2,
    deny_generation: C1,
    credential_generation: C3,
    accounts_revision_set_digest: D1,
    slot_eligibility_digest: D2,
    approval_ref: "approval:owner-a:operation-a",
    policy_digest: D3,
    canonical_request_digest: D4,
    provider_destination_policy: destinationPolicy,
    provider_destination_policy_digest: destinationPolicyDigest,
    sender_constraint_confirmation: D0,
    max_uses: C1,
    use_count: C0,
    catalog_incarnation: "accounts-catalog-2026-07-10",
    recovery_frontier_sequence: C3,
    recovery_frontier_hash: D1,
  };
}

function nativeDraft(
  overrides: Readonly<Record<string, unknown>> = {},
): OnlineGenerationCheckReceiptDraft {
  return {
    ...commonDraft(),
    access_transport: "native_session",
    allowed_channel_class: "capsule_remote_tool",
    auth_capsule_id: IDS.authCapsule,
    canonical_node_id: IDS.canonicalNode,
    node_key_thumbprint: D1,
    node_generation: C2,
    placement_generation: C3,
    auth_generation: C2,
    auth_state_revision: C3,
    ...overrides,
  } as OnlineGenerationCheckReceiptDraft;
}

function brokeredDraft(
  transport: "api_key" | "workload_identity" = "api_key",
  overrides: Readonly<Record<string, unknown>> = {},
): OnlineGenerationCheckReceiptDraft {
  return {
    ...commonDraft(),
    access_transport: transport,
    allowed_channel_class: "brokered_provider_proxy",
    credential_binding_id: IDS.credentialBinding,
    broker_ref: "broker:secrets:primary",
    ...overrides,
  } as OnlineGenerationCheckReceiptDraft;
}

function deniedDraft(
  base: OnlineGenerationCheckReceiptDraft = nativeDraft(),
): OnlineGenerationCheckReceiptDraft {
  return {
    ...base,
    allowed: false,
    deny_state: "denied",
    reason_codes: ["CURRENT_DENY"],
    current_deny: true,
  } as OnlineGenerationCheckReceiptDraft;
}

function policyDeniedDraft(): OnlineGenerationCheckReceiptDraft {
  return {
    ...brokeredDraft(),
    allowed: false,
    deny_state: "allowed",
    reason_codes: ["POLICY_DENIED"],
  } as OnlineGenerationCheckReceiptDraft;
}

function trust(
  publicKey: KeyObject = keys.publicKey,
): OnlineGenerationCheckReceiptTrustRoot {
  return {
    schemaDigest: D2,
    issuer: SELF_HOSTED_ISSUER,
    issuerIncarnation: "accounts-deployment-2026-07-10",
    keyId: "accounts-signing-1",
    audience: AUDIENCE,
    publicKey,
    revoked: false,
  };
}

function expectationFor(
  draft: OnlineGenerationCheckReceiptDraft,
): OnlineGenerationCheckReceiptExpectation {
  const target = "auth_capsule_id" in draft
    ? {
        kind: "native" as const,
        authCapsuleId: draft.auth_capsule_id,
        canonicalNodeId: draft.canonical_node_id,
        nodeKeyThumbprint: draft.node_key_thumbprint,
        nodeGeneration: draft.node_generation,
        placementGeneration: draft.placement_generation,
        authGeneration: draft.auth_generation,
        authStateRevision: draft.auth_state_revision,
      }
    : {
        kind: "brokered" as const,
        credentialBindingId: draft.credential_binding_id,
        brokerRef: draft.broker_ref,
      };
  const decision = draft.allowed
    ? { allowed: true as const, denyState: "allowed" as const, reasonCodes: [] as const }
    : draft.deny_state === "denied"
      ? {
          allowed: false as const,
          denyState: "denied" as const,
          reasonCodes: draft.reason_codes,
          currentDeny: true as const,
        }
      : {
          allowed: false as const,
          denyState: "allowed" as const,
          reasonCodes: draft.reason_codes,
        };
  return {
    now: new Date(NOW),
    maximumAgeMs: 60_000,
    maximumLifetimeMs: 120_000,
    allowedClockSkewMs: 0,
    authenticatedActorPrincipal: draft.actor_principal,
    receipt: {
      receiptId: draft.receipt_id,
      nonce: draft.nonce,
      issuedAt: draft.issued_at,
      notBefore: draft.not_before,
      expiresAt: draft.expires_at,
    },
    capability: {
      capabilityId: draft.capability_id,
      capabilityDigest: draft.capability_digest,
    },
    route: {
      authorityEpoch: draft.authority_epoch,
      routeLineageId: draft.route_lineage_id,
      routeId: draft.route_id,
      routeEpoch: draft.route_epoch,
    },
    attempt: {
      runId: draft.run_id,
      attemptId: draft.attempt_id,
      attemptLeaseId: draft.attempt_lease_id,
      leaseEpoch: draft.lease_epoch,
    },
    resourceLease: {
      resourceLeaseId: draft.resource_lease_id,
      resourceId: draft.resource_id,
      resourceLifecycleGeneration: draft.resource_lifecycle_generation,
      leaseExpiresAt: draft.lease_expires_at,
    },
    operation: {
      operationId: draft.operation_id,
      operationDigest: draft.operation_digest,
      operationExecutionEpoch: draft.operation_execution_epoch,
      operationExecutionExpiresAt: draft.operation_execution_expires_at,
    },
    principals: {
      subject: draft.subject,
      actorPrincipal: draft.actor_principal,
      leaseHolderPrincipal: draft.lease_holder_principal,
      operationExecutorPrincipal: draft.operation_executor_principal,
      senderKeyThumbprint: draft.sender_key_thumbprint,
    },
    account: {
      providerAccountId: draft.provider_account_id,
      accountLaneId: draft.account_lane_id,
      capacityPoolId: draft.capacity_pool_id,
      capacityDomainRef: draft.capacity_domain_ref,
      accessTransport: draft.access_transport,
      credentialFamilyId: draft.credential_family_id,
      allowedChannelClass: draft.allowed_channel_class,
    },
    decision,
    generations: {
      capacityGeneration: draft.capacity_generation,
      denyGeneration: draft.deny_generation,
      credentialGeneration: draft.credential_generation,
      accountsRevisionSetDigest: draft.accounts_revision_set_digest,
    },
    authorization: {
      slotEligibilityDigest: draft.slot_eligibility_digest,
      approvalRef: draft.approval_ref,
      policyDigest: draft.policy_digest,
      canonicalRequestDigest: draft.canonical_request_digest,
      senderConstraintConfirmation: draft.sender_constraint_confirmation,
      maxUses: draft.max_uses,
      useCount: draft.use_count,
    },
    destination: {
      policy: draft.provider_destination_policy,
      policyDigest: draft.provider_destination_policy_digest,
    },
    recovery: {
      catalogIncarnation: draft.catalog_incarnation,
      recoveryFrontierSequence: draft.recovery_frontier_sequence,
      recoveryFrontierHash: draft.recovery_frontier_hash,
    },
    target,
  } as OnlineGenerationCheckReceiptExpectation;
}

function signDraft(draft: OnlineGenerationCheckReceiptDraft): Uint8Array {
  return signUnchecked(draft, keys.privateKey);
}

function decoded(source: Uint8Array): Record<string, unknown> {
  return parseClosedJsonBytes(source) as Record<string, unknown>;
}

function signUnchecked(
  value: object,
  privateKey: KeyObject = keys.privateKey,
): Uint8Array {
  const record = value as Readonly<Record<string, unknown>>;
  const { signature: _signature, ...unsigned } = record;
  const signature = ed25519Sign(
    null,
    Buffer.from(canonicalJson(unsigned), "utf8"),
    privateKey,
  ).toString("base64url");
  return Buffer.from(canonicalJson({ ...unsigned, signature }), "utf8");
}

function changedExpectation(
  source: OnlineGenerationCheckReceiptExpectation,
  path: string,
  value: unknown,
): OnlineGenerationCheckReceiptExpectation {
  const copy = structuredClone(source) as unknown as Record<string, unknown>;
  const parts = path.split(".");
  let cursor = copy;
  for (const part of parts.slice(0, -1)) cursor = cursor[part] as Record<string, unknown>;
  cursor[parts.at(-1)!] = value;
  return copy as unknown as OnlineGenerationCheckReceiptExpectation;
}

function useGuard(
  draft: OnlineGenerationCheckReceiptDraft,
  clock: () => Date = () => new Date(NOW),
  refreshExpectation: OnlineGenerationReceiptUseGuard["refreshExpectation"] = () =>
    expectationFor(draft),
  overrides: Partial<OnlineGenerationReceiptUseGuard> = {},
): OnlineGenerationReceiptUseGuard {
  return {
    clock,
    refreshExpectation,
    authenticatedChannelBindingDigest: draft.sender_constraint_confirmation,
    effectNamespaceId: "effect-namespace-a",
    serializationKeyDigest: D2,
    approvedDescriptorRefreeze: {
      successorContractDigest: D4,
      requestSchemaDigest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
      receiptSchemaDigest: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    },
    consumeRequestId: IDS.consumeRequest,
    modelCallAnchorDigest: D3,
    idempotencyKeyDigest: D4,
    ...overrides,
  } as OnlineGenerationReceiptUseGuard;
}

function useTupleKey(request: OnlineGenerationReceiptUseCasRequest): string {
  return canonicalSha256({
    schema_version: "accounts.capability-use-tombstone-key.v1",
    capability_id: request.capability_id,
    nonce: request.nonce,
    operation_id: request.operation_id,
    resource_lease_id: request.resource_lease_id,
    sender_key_thumbprint: request.sender_key_thumbprint,
    channel_binding_digest: request.channel_binding_digest,
  });
}

function consumeUseId(request: OnlineGenerationReceiptUseCasRequest): string {
  return canonicalSha256({
    capability_id: request.capability_id,
    channel_binding_digest: request.channel_binding_digest,
    model_call_anchor_digest: request.model_call_anchor_digest,
    nonce: request.nonce,
    operation_id: request.operation_id,
    resource_lease_id: request.resource_lease_id,
    schema_version: "accounts.capability-use.v1",
    sender_key_thumbprint: request.sender_key_thumbprint,
    use_ordinal: C1,
  });
}

function signedConsumeReceipt(
  request: OnlineGenerationReceiptUseCasRequest,
  draft: OnlineGenerationCheckReceiptDraft,
  committedAt = NOW.toISOString(),
  overrides: Readonly<Record<string, unknown>> = {},
  privateKey: KeyObject = keys.privateKey,
): Uint8Array {
  return signUnchecked({
    schema_version: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
    schema_digest: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    consume_request_id: request.consume_request_id,
    consume_receipt_id: IDS.consumeReceipt,
    issuer: SELF_HOSTED_ISSUER,
    issuer_incarnation: "accounts-deployment-2026-07-10",
    key_id: "accounts-signing-1",
    audience: AUDIENCE,
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
    max_uses: C1,
    prior_use_count: C0,
    next_use_count: C1,
    use_ordinal: C1,
    use_id: consumeUseId(request),
    committed_at: committedAt,
    expires_at: request.not_after,
    catalog_incarnation: draft.catalog_incarnation,
    recovery_frontier_sequence: draft.recovery_frontier_sequence,
    recovery_frontier_hash: draft.recovery_frontier_hash,
    ...overrides,
  }, privateKey);
}

function fixedUseStore(
  signedReceipt: Uint8Array,
  status: "consumed" | "replayed" = "consumed",
): OnlineGenerationReceiptUseStore {
  return {
    compareAndConsume() {
      return { status, signedReceipt };
    },
  };
}

function durableUseStore(
  draft: OnlineGenerationCheckReceiptDraft = nativeDraft(),
  clock: () => Date = () => new Date(NOW),
): OnlineGenerationReceiptUseStore {
  const idempotencyRecords = new Map<
    string,
    { readonly request: string; readonly signedReceipt: Uint8Array }
  >();
  const tombstones = new Set<string>();
  return {
    compareAndConsume(request: OnlineGenerationReceiptUseCasRequest) {
      const requestBytes = canonicalJson(request);
      const existing = idempotencyRecords.get(request.consume_request_id);
      if (existing !== undefined) {
        if (existing.request !== requestBytes) return { status: "idempotency_conflict" };
        return { status: "replayed", signedReceipt: existing.signedReceipt };
      }
      const tupleKey = useTupleKey(request);
      if (tombstones.has(tupleKey)) return { status: "exhausted" };
      const committedAt = clock().toISOString();
      if (Date.parse(committedAt) >= Date.parse(request.not_after)) {
        return { status: "exhausted" };
      }
      const receipt = signedConsumeReceipt(request, draft, committedAt);
      tombstones.add(tupleKey);
      idempotencyRecords.set(request.consume_request_id, {
        request: requestBytes,
        signedReceipt: receipt,
      });
      return { status: "consumed", signedReceipt: receipt };
    },
  };
}

describe("closed online_generation_check_receipt", () => {
  test("matches an independent Python JCS and Ed25519 full-envelope golden vector", () => {
    expect(destinationPolicyDigest).toBe(
      "sha256:88ac0134eb384cc8fc6650213bc31e361a905b5d439579cd0e1d2a4ba817faa2",
    );
    const draft = nativeDraft();
    const source = signUnchecked(draft, goldenPrivateKey);
    expect(decoded(source).signature).toBe(PYTHON_GOLDEN_SIGNATURE);
    expect(new TextDecoder().decode(source)).toBe(canonicalJson(decoded(source)));
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        source,
        trust(goldenPublicKey),
        expectationFor(draft),
      ),
    ).not.toThrow();
  });

  test("verifies and freezes the complete native receipt, then projects camelCase only after verification", () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const verified = verifyOnlineGenerationCheckReceipt(source, trust(), expectationFor(draft));

    expect(verified.allowed).toBe(true);
    expect(verified.access_transport).toBe("native_session");
    expect("auth_capsule_id" in verified).toBe(true);
    expect("credential_binding_id" in verified).toBe(false);
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.provider_destination_policy)).toBe(true);
    expect(new TextDecoder().decode(source)).toBe(canonicalJson(decoded(source)));

    const projected = projectOnlineGenerationCheckReceipt(verified);
    expect(projected.schemaVersion).toBe(ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION);
    expect(projected.providerDestinationPolicy.normalizedHost).toBe("api.example.test");
    expect(projected).not.toHaveProperty("delegationRef");
    expect(projected).not.toHaveProperty("delegationDigest");
    expect(projected.target).toEqual({
      kind: "native",
      authCapsuleId: IDS.authCapsule,
      canonicalNodeId: IDS.canonicalNode,
      nodeKeyThumbprint: D1,
      nodeGeneration: C2,
      placementGeneration: C3,
      authGeneration: C2,
      authStateRevision: C3,
    });
    expect(projected).not.toHaveProperty("schema_version");
    expect(projected.providerDestinationPolicy).not.toHaveProperty("normalized_host");
    expect(Object.isFrozen(projected)).toBe(true);
  });

  test.each(["api_key", "workload_identity"] as const)(
    "verifies the complete brokered %s variant and excludes every native target field",
    (transport) => {
      const draft = brokeredDraft(transport);
      const verified = verifyAllowedOnlineGenerationCheckReceipt(
        signDraft(draft),
        trust(),
        expectationFor(draft),
      );
      expect(verified.access_transport).toBe(transport);
      expect(verified.allowed_channel_class).toBe("brokered_provider_proxy");
      expect("credential_binding_id" in verified).toBe(true);
      expect("auth_capsule_id" in verified).toBe(false);
    },
  );

  test("validates negative receipts but never brands current deny or policy denial as allowed", () => {
    const currentDeny = deniedDraft();
    const denied = verifyOnlineGenerationCheckReceipt(
      signDraft(currentDeny),
      trust(),
      expectationFor(currentDeny),
    );
    expect(denied).toMatchObject({
      allowed: false,
      deny_state: "denied",
      current_deny: true,
      reason_codes: ["CURRENT_DENY"],
    });
    expect(() =>
      verifyAllowedOnlineGenerationCheckReceipt(
        signDraft(currentDeny),
        trust(),
        expectationFor(currentDeny),
      ),
    ).toThrow(expect.objectContaining({ code: "CURRENT_DENY" }));

    const currentDenyWithDifferentStableReason = {
      ...currentDeny,
      reason_codes: ["CAPACITY_DOMAIN_CONFLICT"],
    } as OnlineGenerationCheckReceiptDraft;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(currentDenyWithDifferentStableReason),
        trust(),
        expectationFor(currentDenyWithDifferentStableReason),
      ),
    ).not.toThrow();

    const policyDenied = policyDeniedDraft();
    expect(() =>
      verifyAllowedOnlineGenerationCheckReceipt(
        signDraft(policyDenied),
        trust(),
        expectationFor(policyDenied),
      ),
    ).toThrow(expect.objectContaining({ code: "POLICY_DENIED" }));
  });

  test("uses the exact Accounts one-use request and returns an identical signed idempotent replay", async () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const expected = expectationFor(draft);
    const guard = useGuard(draft);
    const sequentialStore = durableUseStore(draft);
    const consumed = await consumeOnlineGenerationCheckReceiptUse(
      source,
      trust(),
      expected,
      sequentialStore,
      guard,
    );
    expect(consumed.use.request).toEqual({
      schema_version: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
      schema_digest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
      consume_request_id: IDS.consumeRequest,
      capability_id: IDS.capability,
      capability_digest: D3,
      nonce: draft.nonce,
      subject: SUBJECT,
      actor_principal: draft.actor_principal,
      effect_namespace_id: "effect-namespace-a",
      account_lane_id: IDS.accountLane,
      capacity_pool_id: IDS.capacityPool,
      capacity_domain_ref: draft.capacity_domain_ref,
      serialization_key_digest: D2,
      credential_family_id: IDS.credentialFamily,
      resource_lease_id: IDS.resourceLease,
      resource_id: draft.resource_id,
      resource_lifecycle_generation: C1,
      operation_id: IDS.operation,
      operation_digest: D4,
      operation_execution_epoch: C1,
      sender_key_thumbprint: D0,
      channel_binding_digest: D0,
      canonical_request_digest: D4,
      provider_destination_policy_digest: destinationPolicyDigest,
      online_receipt_id: IDS.receipt,
      online_receipt_digest: canonicalSha256(decoded(source)),
      model_call_anchor_digest: D3,
      expected_use_count: C0,
      max_uses: C1,
      not_after: EXPIRES_AT,
      idempotency_key_digest: D4,
    });
    expect(consumed.use.priorUseCount).toBe(C0);
    expect(consumed.use.nextUseCount).toBe(C1);
    expect(consumed.use.useOrdinal).toBe(C1);
    expect(consumed.use.useId).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(consumed.use.consumeReceiptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(consumed.use.replayed).toBe(false);
    expect(consumed.use.consumeReceipt.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Object.isFrozen(consumed)).toBe(true);
    expect(Object.isFrozen(consumed.use.request)).toBe(true);
    expect(Object.isFrozen(consumed.use.consumeReceipt)).toBe(true);

    const replayed = await consumeOnlineGenerationCheckReceiptUse(
      source,
      trust(),
      expected,
      sequentialStore,
      guard,
    );
    expect(replayed.use.replayed).toBe(true);
    expect(replayed.use.consumeReceiptDigest).toBe(consumed.use.consumeReceiptDigest);
    expect(replayed.use.consumeReceipt).toEqual(consumed.use.consumeReceipt);

    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        source,
        trust(),
        expected,
        sequentialStore,
        useGuard(draft, undefined, undefined, { idempotencyKeyDigest: D0 }),
      ),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        source,
        trust(),
        expected,
        sequentialStore,
        useGuard(draft, undefined, undefined, { consumeRequestId: IDS.other }),
      ),
    ).rejects.toMatchObject({ code: "CONFLICT" });

    const concurrentStore = durableUseStore(draft);
    const attempts = await Promise.allSettled([
      consumeOnlineGenerationCheckReceiptUse(source, trust(), expected, concurrentStore, guard),
      consumeOnlineGenerationCheckReceiptUse(source, trust(), expected, concurrentStore, guard),
    ]);
    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(2);
    const concurrentDigests = attempts.flatMap((attempt) =>
      attempt.status === "fulfilled" ? [attempt.value.use.consumeReceiptDigest] : []
    );
    expect(new Set(concurrentDigests).size).toBe(1);

    await expect(
      consumeOnlineGenerationCheckReceiptUse(source, trust(), expected, {
        compareAndConsume() {
          throw new Error("store unavailable");
        },
      }, guard),
    ).rejects.toMatchObject({ code: "DEPENDENCY_UNAVAILABLE", retryable: true });
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        source,
        trust(),
        expected,
        fixedUseStore(Buffer.from("{}")),
        guard,
      ),
    ).rejects.toBeInstanceOf(AccountsError);
  });

  test("pins the consume descriptors and verifies every field of the closed signed receipt", async () => {
    const requestFields = [
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
    ] as const;
    const receiptFields = [
      "schema_version",
      "schema_digest",
      "consume_request_id",
      "consume_receipt_id",
      "issuer",
      "issuer_incarnation",
      "key_id",
      "audience",
      "capability_id",
      "capability_digest",
      "nonce",
      "subject",
      "actor_principal",
      "effect_namespace_id",
      "account_lane_id",
      "capacity_pool_id",
      "serialization_key_digest",
      "resource_lease_id",
      "operation_id",
      "operation_execution_epoch",
      "sender_key_thumbprint",
      "channel_binding_digest",
      "canonical_request_digest",
      "online_receipt_digest",
      "model_call_anchor_digest",
      "max_uses",
      "prior_use_count",
      "next_use_count",
      "use_ordinal",
      "use_id",
      "committed_at",
      "expires_at",
      "catalog_incarnation",
      "recovery_frontier_sequence",
      "recovery_frontier_hash",
      "signature",
    ] as const;
    expect(canonicalSha256({
      fields: requestFields,
      schema_version: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_VERSION,
    })).toBe(CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST);
    expect(canonicalSha256({
      fields: receiptFields,
      schema_version: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_VERSION,
    })).toBe(CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST);

    const draft = nativeDraft();
    const source = signDraft(draft);
    const expected = expectationFor(draft);
    const guard = useGuard(draft);
    let captured: OnlineGenerationReceiptUseCasRequest | undefined;
    const delegate = durableUseStore(draft);
    const accepted = await consumeOnlineGenerationCheckReceiptUse(
      source,
      trust(),
      expected,
      {
        compareAndConsume(request) {
          captured = request;
          return delegate.compareAndConsume(request);
        },
      },
      guard,
    );
    expect(captured).toBeDefined();
    expect(Object.keys(captured!).sort()).toEqual([...requestFields].sort());
    expect(Object.keys(accepted.use.consumeReceipt).sort()).toEqual([...receiptFields].sort());

    const valid = accepted.use.consumeReceipt as unknown as Record<string, unknown>;
    for (const key of Object.keys(valid)) {
      const missing = { ...valid };
      delete missing[key];
      const candidate = key === "signature"
        ? Buffer.from(canonicalJson(missing))
        : signUnchecked(missing);
      await expect(
        consumeOnlineGenerationCheckReceiptUse(
          source,
          trust(),
          expected,
          fixedUseStore(candidate),
          guard,
        ),
        key,
      ).rejects.toBeInstanceOf(AccountsError);
    }

    const mismatches: Record<string, unknown>[] = [
      { ...valid, schema_version: "accounts.capability-use-consume-receipt.v2" },
      { ...valid, schema_digest: D0 },
      { ...valid, consume_request_id: IDS.other },
      { ...valid, consume_receipt_id: "not-a-uuid" },
      { ...valid, issuer: "accounts:self-hosted:other" },
      { ...valid, issuer_incarnation: "accounts-deployment-other" },
      { ...valid, key_id: "accounts-signing-other" },
      { ...valid, audience: "infinity:self-hosted:other" },
      { ...valid, capability_id: IDS.other },
      { ...valid, capability_digest: D0 },
      { ...valid, nonce: "nonce-other" },
      { ...valid, subject: "principal:service:hasna:other" },
      { ...valid, actor_principal: "principal:human:hasna:other" },
      { ...valid, account_lane_id: IDS.other },
      { ...valid, capacity_pool_id: IDS.other },
      { ...valid, resource_lease_id: IDS.other },
      { ...valid, operation_id: IDS.other },
      { ...valid, operation_execution_epoch: C2 },
      { ...valid, sender_key_thumbprint: D1 },
      { ...valid, channel_binding_digest: D1 },
      { ...valid, canonical_request_digest: D0 },
      { ...valid, online_receipt_digest: D0 },
      { ...valid, model_call_anchor_digest: D0 },
      { ...valid, max_uses: C2 },
      { ...valid, prior_use_count: C1 },
      { ...valid, next_use_count: C0 },
      { ...valid, use_ordinal: C2 },
      { ...valid, use_id: D0 },
      { ...valid, committed_at: "2026-07-10T11:59:58.000Z" },
      { ...valid, committed_at: EXPIRES_AT },
      { ...valid, expires_at: LEASE_EXPIRES_AT },
      { ...valid, catalog_incarnation: "accounts-catalog-other" },
      { ...valid, recovery_frontier_sequence: C2 },
      { ...valid, recovery_frontier_hash: D0 },
      { ...valid, unknown_security_field: "forbidden" },
    ];
    for (const candidate of mismatches) {
      await expect(
        consumeOnlineGenerationCheckReceiptUse(
          source,
          trust(),
          expected,
          fixedUseStore(signUnchecked(candidate)),
          guard,
        ),
      ).rejects.toBeInstanceOf(AccountsError);
    }

    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        source,
        trust(),
        expected,
        fixedUseStore(signUnchecked(valid, forgedKeys.privateKey)),
        guard,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        source,
        trust(),
        expected,
        fixedUseStore(Buffer.concat([
          Buffer.from(canonicalJson(valid)),
          Buffer.from("\n"),
        ])),
        guard,
      ),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
  });

  test("snapshots mutable receipt and trust inputs before the asynchronous Accounts CAS", async () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const mutableTrust = { ...trust() };
    let captured: OnlineGenerationReceiptUseCasRequest | undefined;
    let resume: (() => void) | undefined;
    const store: OnlineGenerationReceiptUseStore = {
      compareAndConsume(request) {
        captured = request;
        return new Promise((resolve) => {
          resume = () => resolve({
            status: "consumed",
            signedReceipt: signedConsumeReceipt(request, draft),
          });
        });
      },
    };
    const pending = consumeOnlineGenerationCheckReceiptUse(
      source,
      mutableTrust,
      expectationFor(draft),
      store,
      useGuard(draft),
    );
    expect(captured).toBeDefined();
    source.fill(0);
    mutableTrust.issuer = "accounts:self-hosted:other";
    mutableTrust.publicKey = forgedKeys.publicKey;
    mutableTrust.revoked = true;
    resume!();
    await expect(pending).resolves.toMatchObject({
      use: { replayed: false, useOrdinal: C1 },
    });

    let storeTouched = false;
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        signDraft(draft),
        trust(),
        expectationFor(draft),
        {
          compareAndConsume() {
            storeTouched = true;
            return { status: "conflict" };
          },
        },
        useGuard(draft, undefined, undefined, {
          authenticatedChannelBindingDigest: D1,
        }),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(storeTouched).toBe(false);
  });

  test("keeps the one-use tombstone stable across higher operation execution epochs", async () => {
    const first = nativeDraft();
    const second = nativeDraft({
      receipt_id: IDS.other,
      operation_execution_epoch: C2,
    });
    const store = durableUseStore(first);
    await consumeOnlineGenerationCheckReceiptUse(
      signDraft(first),
      trust(),
      expectationFor(first),
      store,
      useGuard(first),
    );
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        signDraft(second),
        trust(),
        expectationFor(second),
        store,
        useGuard(second, undefined, undefined, { consumeRequestId: IDS.other2 }),
      ),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  test("fails closed when CAS or the final current-state check crosses the effective receipt deadline", async () => {
    const cases = [
      {
        draft: nativeDraft(),
        cutoff: EXPIRES_AT,
        maximumLifetimeMs: 120_000,
      },
    ] as const;
    for (const { draft, cutoff, maximumLifetimeMs } of cases) {
      const expected = {
        ...expectationFor(draft),
        maximumLifetimeMs,
      };
      let clockReads = 0;
      const guard = useGuard(
        draft,
        () => new Date(clockReads++ === 0 ? NOW : new Date(cutoff)),
        () => expected,
      );
      let observedNotAfter: string | undefined;
      const delegate = durableUseStore(draft);
      const store: OnlineGenerationReceiptUseStore = {
        compareAndConsume(request) {
          observedNotAfter = request.not_after;
          return delegate.compareAndConsume(request);
        },
      };
      await expect(
        consumeOnlineGenerationCheckReceiptUse(
          signDraft(draft),
          trust(),
          expected,
          store,
          guard,
        ),
      ).rejects.toMatchObject({ code: "STALE_ATTESTATION" });
      expect(observedNotAfter).toBe(cutoff);
    }

    const draft = nativeDraft();
    const expected = expectationFor(draft);
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        signDraft(draft),
        trust(),
        expected,
        {
          compareAndConsume(request) {
            return {
              status: "consumed",
              signedReceipt: signedConsumeReceipt(
                request,
                draft,
                request.not_after,
              ),
            };
          },
        },
        useGuard(draft),
      ),
    ).rejects.toMatchObject({ code: "STALE_ATTESTATION" });
  });

  test("rechecks the coherent current deny/generation tuple after durable consumption", async () => {
    const draft = nativeDraft();
    const expected = expectationFor(draft);
    const newlyDenied: OnlineGenerationCheckReceiptExpectation = {
      ...expected,
      generations: { ...expected.generations, denyGeneration: C2 },
      decision: {
        allowed: false,
        denyState: "denied",
        reasonCodes: ["CAPACITY_DOMAIN_CONFLICT"],
        currentDeny: true,
      },
    };
    await expect(
      consumeOnlineGenerationCheckReceiptUse(
        signDraft(draft),
        trust(),
        expected,
        durableUseStore(draft),
        useGuard(draft, () => new Date(NOW), () => newlyDenied),
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  test("binds every common fence, identity, time, generation, request, revision, and frontier field", () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const expected = expectationFor(draft);
    const mismatches: ReadonlyArray<readonly [string, unknown]> = [
      ["receipt.receiptId", IDS.other],
      ["receipt.nonce", "nonce-other"],
      ["receipt.issuedAt", OTHER_TIMESTAMP],
      ["receipt.notBefore", OTHER_TIMESTAMP],
      ["receipt.expiresAt", LEASE_EXPIRES_AT],
      ["capability.capabilityId", IDS.other],
      ["capability.capabilityDigest", D0],
      ["route.authorityEpoch", C2],
      ["route.routeLineageId", IDS.other],
      ["route.routeId", IDS.other],
      ["route.routeEpoch", C3],
      ["attempt.runId", IDS.other],
      ["attempt.attemptId", IDS.other],
      ["attempt.attemptLeaseId", IDS.other],
      ["attempt.leaseEpoch", C3],
      ["resourceLease.resourceLeaseId", IDS.other],
      ["resourceLease.resourceId", "account-resource:other"],
      ["resourceLease.resourceLifecycleGeneration", C2],
      ["resourceLease.leaseExpiresAt", OTHER_TIMESTAMP],
      ["operation.operationId", IDS.other],
      ["operation.operationDigest", D0],
      ["operation.operationExecutionEpoch", C2],
      ["operation.operationExecutionExpiresAt", LEASE_EXPIRES_AT],
      ["authenticatedActorPrincipal", "principal:human:hasna:other"],
      ["principals.subject", "principal:service:hasna:other"],
      ["principals.actorPrincipal", "principal:human:hasna:other"],
      ["principals.leaseHolderPrincipal", "principal:service:hasna:other"],
      ["principals.operationExecutorPrincipal", "principal:service:hasna:other"],
      ["principals.senderKeyThumbprint", D1],
      ["account.providerAccountId", IDS.other],
      ["account.accountLaneId", IDS.other],
      ["account.capacityPoolId", IDS.other],
      ["account.capacityDomainRef", "provider:openai:other-limit"],
      ["account.accessTransport", "api_key"],
      ["account.credentialFamilyId", IDS.other],
      ["account.allowedChannelClass", "brokered_provider_proxy"],
      ["generations.capacityGeneration", C3],
      ["generations.denyGeneration", C2],
      ["generations.credentialGeneration", C2],
      ["generations.accountsRevisionSetDigest", D0],
      ["authorization.slotEligibilityDigest", D0],
      ["authorization.approvalRef", "approval:other"],
      ["authorization.policyDigest", D0],
      ["authorization.canonicalRequestDigest", D0],
      ["authorization.senderConstraintConfirmation", D1],
      ["authorization.maxUses", C2],
      ["authorization.useCount", C1],
      ["destination.policyDigest", D0],
      ["recovery.catalogIncarnation", "accounts-catalog-other"],
      ["recovery.recoveryFrontierSequence", C2],
      ["recovery.recoveryFrontierHash", D0],
      ["target.authCapsuleId", IDS.other],
      ["target.canonicalNodeId", IDS.other],
      ["target.nodeKeyThumbprint", D0],
      ["target.nodeGeneration", C3],
      ["target.placementGeneration", C2],
      ["target.authGeneration", C3],
      ["target.authStateRevision", C2],
    ];

    for (const [path, value] of mismatches) {
      expect(
        () => verifyOnlineGenerationCheckReceipt(
          source,
          trust(),
          changedExpectation(expected, path, value),
        ),
        path,
      ).toThrow(AccountsError);
    }

    const changedPolicy = {
      ...destinationPolicy,
      operation_path: "/v1/chat/completions",
    } as const;
    const changedDestination: OnlineGenerationCheckReceiptExpectation = {
      ...expected,
      destination: {
        policy: changedPolicy,
        policyDigest: canonicalSha256(changedPolicy),
      },
    };
    expect(() => verifyOnlineGenerationCheckReceipt(source, trust(), changedDestination)).toThrow(
      AccountsError,
    );
  });

  test("binds every brokered target member and rejects cross-variant replay", () => {
    const draft = brokeredDraft();
    const source = signDraft(draft);
    const expected = expectationFor(draft);
    for (const [path, value] of [
      ["target.credentialBindingId", IDS.other],
      ["target.brokerRef", "broker:other"],
    ] as const) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          source,
          trust(),
          changedExpectation(expected, path, value),
        ),
      ).toThrow(AccountsError);
    }
    expect(() =>
      verifyOnlineGenerationCheckReceipt(source, trust(), expectationFor(nativeDraft())),
    ).toThrow(AccountsError);
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(nativeDraft()),
        trust(),
        expectationFor(brokeredDraft()),
      ),
    ).toThrow(AccountsError);
  });

  test("rejects every missing field in both closed target variants", () => {
    for (const draft of [nativeDraft(), brokeredDraft(), deniedDraft()]) {
      const valid = decoded(signDraft(draft));
      for (const key of Object.keys(valid)) {
        const missing = { ...valid };
        delete missing[key];
        const source = key === "signature"
          ? Buffer.from(canonicalJson(missing), "utf8")
          : signUnchecked(missing);
        expect(
          () => verifyOnlineGenerationCheckReceipt(
            source,
            trust(),
            expectationFor(draft),
          ),
          `${draft.access_transport}:${key}`,
        ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
      }
    }
  });

  test("rejects every unknown field, shorthand, camelCase alias, and contradictory alias even when signed", () => {
    const draft = nativeDraft();
    const base = decoded(signDraft(draft));
    const aliases = [
      "routeAuthorityEpoch",
      "leaseEpoch",
      "executionEpoch",
      "epoch",
      "authority_generation",
      "producer_epoch",
      "run_lease_id",
      "attempt_lease_epoch",
      "allocation_generation",
      "issuer_incarnation_id",
      "issuerKey",
      "key",
      "serializationKey",
      "accessTarget",
      "credentialGeneration",
      "canonicalRequestDigest",
      "currentDeny",
      "delegation_ref",
      "delegation_digest",
      "delegation",
      "unknown_security_field",
    ];
    for (const alias of aliases) {
      expect(
        () => verifyOnlineGenerationCheckReceipt(
          signUnchecked({ ...base, [alias]: "forbidden" }),
          trust(),
          expectationFor(draft),
        ),
        alias,
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }

    const nested = {
      ...base,
      provider_destination_policy: {
        ...(base.provider_destination_policy as Record<string, unknown>),
        normalizedHost: "api.example.test",
      },
    };
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signUnchecked(nested),
        trust(),
        expectationFor(draft),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });

  test("rejects mixed, unresolved, and transport-incompatible target variants before an effect sink", () => {
    const native = decoded(signDraft(nativeDraft()));
    const brokered = decoded(signDraft(brokeredDraft()));
    const cases: Record<string, unknown>[] = [
      { ...native, credential_binding_id: IDS.credentialBinding, broker_ref: "broker:secrets:primary" },
      { ...brokered, auth_capsule_id: IDS.authCapsule },
      Object.fromEntries(Object.entries(native).filter(([key]) => key !== "canonical_node_id")),
      Object.fromEntries(Object.entries(brokered).filter(([key]) => key !== "broker_ref")),
      { ...native, access_transport: "api_key" },
      { ...brokered, access_transport: "native_session" },
      { ...native, allowed_channel_class: "brokered_provider_proxy" },
      { ...brokered, allowed_channel_class: "capsule_remote_tool" },
    ];
    for (const candidate of cases) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(candidate),
          trust(),
          expectationFor(nativeDraft()),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("rejects delegation fields while binding distinct subject and authenticated actor", () => {
    const draft = nativeDraft();
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(draft),
        trust(),
        expectationFor(draft),
      ),
    ).not.toThrow();

    const base = decoded(signDraft(draft));
    const invalid: Record<string, unknown>[] = [
      { ...base, delegation_ref: "delegation:owner-a:infinity" },
      { ...base, delegation_digest: D2 },
      {
        ...base,
        delegation_ref: "delegation:owner-a:infinity",
        delegation_digest: D2,
      },
    ];
    for (const candidate of invalid) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(candidate),
          trust(),
          expectationFor(nativeDraft()),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("rejects contradictory allowed, deny_state, reason_codes, and current_deny combinations", () => {
    const allowed = decoded(signDraft(nativeDraft()));
    const denied = decoded(signDraft(deniedDraft()));
    const invalid = [
      { ...allowed, reason_codes: ["POLICY_DENIED"] },
      { ...allowed, deny_state: "denied", current_deny: true },
      { ...allowed, current_deny: true },
      { ...allowed, allowed: false },
      { ...denied, reason_codes: [] },
      Object.fromEntries(Object.entries(denied).filter(([key]) => key !== "current_deny")),
      { ...denied, current_deny: false },
      { ...denied, deny_state: "allowed" },
      { ...denied, reason_codes: ["CURRENT_DENY", "CURRENT_DENY"] },
      { ...denied, reason_codes: ["POLICY_DENIED", "CURRENT_DENY"] },
      { ...denied, reason_codes: ["not_stable"] },
    ];
    for (const candidate of invalid) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(candidate),
          trust(),
          expectationFor(nativeDraft()),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("rejects stale positive evidence after a higher current deny generation even when its signature is valid", () => {
    const draft = nativeDraft();
    const expected = expectationFor(draft);
    const current: OnlineGenerationCheckReceiptExpectation = {
      ...expected,
      generations: { ...expected.generations, denyGeneration: C2 },
      decision: {
        allowed: false,
        denyState: "denied",
        reasonCodes: ["CURRENT_DENY"],
        currentDeny: true,
      },
    };
    expect(() =>
      verifyAllowedOnlineGenerationCheckReceipt(signDraft(draft), trust(), current),
    ).toThrow(AccountsError);
  });

  test("checks provider destination policy closure and the literal V1 one-use law", () => {
    const draft = nativeDraft();
    const base = decoded(signDraft(draft));
    const policy = base.provider_destination_policy as Record<string, unknown>;
    const invalidPolicies = [
      { ...policy, extra: true },
      { ...policy, scheme: "http" },
      { ...policy, normalized_host: "API.EXAMPLE.TEST" },
      { ...policy, port: "0443" },
      { ...policy, port: "65536" },
      { ...policy, operation_path: "v1/responses" },
      { ...policy, operation_path: "https://alternate.example/v1/responses" },
      { ...policy, operation_path: "//alternate.example/v1/responses" },
      { ...policy, operation_path: "///alternate.example/v1/responses" },
      { ...policy, operation_path: "/v1//responses" },
      { ...policy, operation_path: "/v1/responses/" },
      { ...policy, operation_path: "/v1/./responses" },
      { ...policy, operation_path: "/v1/../admin" },
      { ...policy, operation_path: "/v1/%2E%2E/admin" },
      { ...policy, operation_path: "/v1/%2e%2e/admin" },
      { ...policy, operation_path: "/v1/%2Fadmin" },
      { ...policy, operation_path: "/v1/\\admin" },
      { ...policy, request_body_digest: "sha256:ABC" },
    ];
    for (const candidate of invalidPolicies) {
      const value = {
        ...base,
        provider_destination_policy: candidate,
        provider_destination_policy_digest: canonicalSha256(candidate),
      };
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(value),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }

    for (const candidate of [
      { ...base, provider_destination_policy_digest: D0 },
      { ...base, use_count: C2 },
      { ...base, use_count: C1 },
      { ...base, max_uses: C0 },
      { ...base, max_uses: C2 },
      { ...base, max_uses: "17" },
    ]) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(candidate),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }

    const exhausted = {
      ...policyDeniedDraft(),
      use_count: C1,
      reason_codes: ["USE_LIMIT_REACHED"],
    } as OnlineGenerationCheckReceiptDraft;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(exhausted),
        trust(),
        expectationFor(exhausted),
      ),
    ).not.toThrow();
    const exhaustedWithoutStableReason = {
      ...policyDeniedDraft(),
      use_count: C1,
    } as OnlineGenerationCheckReceiptDraft;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(exhaustedWithoutStableReason),
        trust(),
        expectationFor(exhaustedWithoutStableReason),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    const falseExhaustion = {
      ...policyDeniedDraft(),
      use_count: C0,
      reason_codes: ["USE_LIMIT_REACHED"],
    } as OnlineGenerationCheckReceiptDraft;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(falseExhaustion),
        trust(),
        expectationFor(falseExhaustion),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });

  test("rejects duplicate keys at every security-significant depth before JSON object construction", () => {
    const draft = nativeDraft();
    const source = new TextDecoder().decode(signDraft(draft));
    const duplicates = [
      source.replace(`"receipt_id":"${IDS.receipt}"`, `"receipt_id":"${IDS.receipt}","receipt_id":"${IDS.receipt}"`),
      source.replace(`"normalized_host":"api.example.test"`, `"normalized_host":"api.example.test","normalized_host":"api.example.test"`),
      source.replace(`"signature":`, `"signature":"${Buffer.alloc(64).toString("base64url")}","signature":`),
    ];
    for (const candidate of duplicates) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          Buffer.from(candidate),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("requires canonical UTF-8 JCS wire bytes and compares Unicode as exact code points", () => {
    const composedPolicy = {
      ...destinationPolicy,
      operation_path: "/v1/r\u00e9ponses",
    } as const;
    const composed = nativeDraft({
      provider_destination_policy: composedPolicy,
      provider_destination_policy_digest: canonicalSha256(composedPolicy),
    });
    const source = signDraft(composed);
    expect(() =>
      verifyOnlineGenerationCheckReceipt(source, trust(), expectationFor(composed)),
    ).not.toThrow();

    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        Buffer.from(JSON.stringify(decoded(source), null, 2)),
        trust(),
        expectationFor(composed),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    const decomposedPolicy = {
      ...composedPolicy,
      operation_path: "/v1/re\u0301ponses",
    } as const;
    const decomposed: OnlineGenerationCheckReceiptExpectation = {
      ...expectationFor(composed),
      destination: {
        policy: decomposedPolicy,
        policyDigest: canonicalSha256(decomposedPolicy),
      },
    };
    expect(() => verifyOnlineGenerationCheckReceipt(source, trust(), decomposed)).toThrow(
      expect.objectContaining({ code: "FORBIDDEN" }),
    );

    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        Uint8Array.of(0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d),
        trust(),
        expectationFor(composed),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    const raw = new TextDecoder().decode(source);
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        Buffer.from(raw.replace('"operation_path":"/v1/réponses"', '"operation_path":"\\ud800"')),
        trust(),
        expectationFor(composed),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });

  test("rejects numeric, leading-zero, overflow, and noncanonical counter spellings", () => {
    const draft = nativeDraft();
    const base = decoded(signDraft(draft));
    for (const candidate of [
      { ...base, authority_epoch: "01" },
      { ...base, authority_epoch: "9223372036854775808" },
      { ...base, max_uses: "0" },
      { ...base, use_count: "-1" },
      { ...base, credential_family_id: "credential-family-a" },
    ]) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signUnchecked(candidate),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
    const source = new TextDecoder().decode(signDraft(draft));
    for (const candidate of [
      source.replace('"authority_epoch":"3"', '"authority_epoch":3'),
      source.replace('"authority_epoch":"3"', '"authority_epoch":3.0'),
      source.replace('"authority_epoch":"3"', '"authority_epoch":9007199254740993'),
    ]) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          Buffer.from(candidate),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("verifies Ed25519 over exactly the closed payload with only top-level signature omitted", () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const base = decoded(source);
    const forged = Buffer.from(base.signature as string, "base64url");
    forged[0] = forged[0]! ^ 1;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        Buffer.from(canonicalJson({ ...base, signature: forged.toString("base64url") })),
        trust(),
        expectationFor(draft),
      ),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));

    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signUnchecked({ ...base, operation_digest: D0 }, forgedKeys.privateKey),
        trust(),
        expectationFor(draft),
      ),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(source, trust(rsa), expectationFor(draft)),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));
  });

  test("rejects revoked, wrong issuer/incarnation/key/audience/schema trust and local/test issuers", () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    const valid = trust();
    const wrongTrusts: OnlineGenerationCheckReceiptTrustRoot[] = [
      { ...valid, schemaDigest: D0 },
      { ...valid, issuer: "accounts:local:installation-a" },
      { ...valid, issuer: "accounts:test:fixture" },
      { ...valid, issuerIncarnation: "accounts-deployment-other" },
      { ...valid, keyId: "accounts-signing-other" },
      { ...valid, audience: "accounts:local" },
      { ...valid, publicKey: forgedKeys.publicKey },
      { ...valid, revoked: true },
    ];
    for (const candidate of wrongTrusts) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(source, candidate, expectationFor(draft)),
      ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));
    }
  });

  test("uses only the trusted clock for not-before, expiry, maximum age, lifetime, and live lease fences", () => {
    const cases: ReadonlyArray<
      readonly [OnlineGenerationCheckReceiptDraft, Partial<OnlineGenerationCheckReceiptExpectation>]
    > = [
      [nativeDraft({
        issued_at: "2026-07-10T12:00:31.000Z",
        expires_at: "2026-07-10T12:01:31.000Z",
        operation_execution_expires_at: "2026-07-10T12:01:31.000Z",
      }), {}],
      [nativeDraft({ not_before: "2026-07-10T12:00:31.000Z" }), {}],
      [nativeDraft({ expires_at: NOW.toISOString() }), {}],
      [nativeDraft({ issued_at: "2026-07-10T11:59:29.999Z" }), {}],
      [nativeDraft({
        expires_at: "2026-07-10T12:02:00.001Z",
        lease_expires_at: "2026-07-10T12:03:00.000Z",
        operation_execution_expires_at: "2026-07-10T12:03:00.000Z",
      }), {}],
    ];
    for (const [draft, overrides] of cases) {
      const expected = Object.assign(expectationFor(draft), overrides);
      expect(() =>
        verifyOnlineGenerationCheckReceipt(signDraft(draft), trust(), expected),
      ).toThrow(expect.objectContaining({ code: "STALE_ATTESTATION" }));
    }

    const skewed = nativeDraft({
      issued_at: "2026-07-10T12:00:31.000Z",
      expires_at: "2026-07-10T12:01:31.000Z",
      operation_execution_expires_at: "2026-07-10T12:01:31.000Z",
    });
    const skewExpectation: OnlineGenerationCheckReceiptExpectation = {
      ...expectationFor(skewed),
      allowedClockSkewMs: 1_000,
    };
    expect(() =>
      verifyOnlineGenerationCheckReceipt(signDraft(skewed), trust(), skewExpectation),
    ).not.toThrow();
  });

  test("positive receipt expiry never outlives its resource or operation fence", () => {
    for (const draft of [
      nativeDraft({ lease_expires_at: "2026-07-10T12:00:59.000Z" }),
      nativeDraft({ operation_execution_expires_at: "2026-07-10T12:00:59.000Z" }),
    ]) {
      expect(() =>
        verifyOnlineGenerationCheckReceipt(
          signDraft(draft),
          trust(),
          expectationFor(draft),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("accepts canonical RFC3339 UTC timestamps without forcing millisecond precision", () => {
    const draft = nativeDraft({
      issued_at: "2026-07-10T12:00:00Z",
      not_before: "2026-07-10T11:59:59.0Z",
      expires_at: "2026-07-10T12:01:00.00Z",
      lease_expires_at: "2026-07-10T12:02:00Z",
      operation_execution_expires_at: "2026-07-10T12:01:30.0Z",
    });
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signDraft(draft),
        trust(),
        expectationFor(draft),
      ),
    ).not.toThrow();
    const malformed = decoded(signDraft(nativeDraft()));
    malformed.issued_at = "2026-07-10T12:00:00.1234Z";
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signUnchecked(malformed),
        trust(),
        expectationFor(nativeDraft()),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });

  test("allows a fresh negative receipt to carry expired live operation fences only as denial evidence", () => {
    const draft = {
      ...policyDeniedDraft(),
      lease_expires_at: NOW.toISOString(),
      operation_execution_expires_at: NOW.toISOString(),
    } as OnlineGenerationCheckReceiptDraft;
    expect(() =>
      verifyOnlineGenerationCheckReceipt(signDraft(draft), trust(), expectationFor(draft)),
    ).not.toThrow();
    expect(() =>
      verifyAllowedOnlineGenerationCheckReceipt(signDraft(draft), trust(), expectationFor(draft)),
    ).toThrow(expect.objectContaining({ code: "POLICY_DENIED" }));
  });

  test("rejects invalid verifier clock and freshness policy instead of falling back to wall clock", () => {
    const draft = nativeDraft();
    const source = signDraft(draft);
    for (const expected of [
      { ...expectationFor(draft), now: new Date(Number.NaN) },
      { ...expectationFor(draft), maximumAgeMs: 0 },
      { ...expectationFor(draft), maximumAgeMs: 60_001 },
      { ...expectationFor(draft), maximumLifetimeMs: 120_001 },
      { ...expectationFor(draft), maximumLifetimeMs: Number.MAX_SAFE_INTEGER + 1 },
      { ...expectationFor(draft), allowedClockSkewMs: -1 },
      { ...expectationFor(draft), allowedClockSkewMs: 5_001 },
    ]) {
      expect(() => verifyOnlineGenerationCheckReceipt(source, trust(), expected)).toThrow(
        expect.objectContaining({ code: "VALIDATION_FAILED" }),
      );
    }
  });

  test("keeps fixture signing out of production exports and rejects signed malformed drafts", async () => {
    const module = await import("./online-generation-receipt");
    expect("signOnlineGenerationCheckReceiptForTest" in module).toBe(false);
    const malformed = nativeDraft({ unknown: true });
    expect(() =>
      verifyOnlineGenerationCheckReceipt(
        signUnchecked(malformed),
        trust(),
        expectationFor(nativeDraft()),
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });
});
