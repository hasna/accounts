import { describe, expect, test } from "bun:test";
import { generateKeyPairSync, sign as signBytes, type KeyLike } from "node:crypto";

import { AccountsError } from "./errors.js";
import { parseCounter } from "./counter.js";
import {
  CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_ISSUANCE_REQUEST_SCHEMA_VERSION,
  CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION,
  INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST,
  INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION,
  CapsuleMaintenanceAuthority,
  InMemoryCapsuleMaintenanceLedger,
  InMemoryCapsuleMaintenanceLedgerState,
  maintenanceTargetDigest,
  verifyCapsuleMaintenanceGrant,
  verifyInfinityMaintenanceHeldReceipt,
  type CapsuleMaintenanceCurrentState,
  type CapsuleMaintenanceTransportBinding,
} from "./capsule-maintenance.js";
import {
  InMemoryNativeCapabilityUseStore,
  StaticNativeSubscriptionSnapshotSource,
  evaluateNativeSubscriptionProbe,
  type NativeSubscriptionBindingSnapshot,
  type NativeSubscriptionProbeRequest,
} from "./native-subscription.js";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
  type OnlineGenerationReceiptUseCasRequest,
} from "./online-generation-receipt.js";
import { canonicalJson, canonicalSha256, parseClosedJsonBytes } from "./json.js";

const NOW = new Date("2030-07-18T12:00:00.000Z");
const OWNER = "principal:human:hasna:owner-a";
const OTHER_OWNER = "principal:human:hasna:owner-b";
const EXECUTOR = "principal:service:hasna:authcapsule-a";
const SUBJECT = "principal:service:hasna:infinity-a";
const IDS = {
  provider: "018f0f00-0001-7000-8000-000000000001",
  subscription: "018f0f00-0002-7000-8000-000000000002",
  lane: "018f0f00-0003-7000-8000-000000000003",
  capsule: "018f0f00-0004-7000-8000-000000000004",
  node: "018f0f00-0005-7000-8000-000000000005",
  grant1: "018f0f00-0006-7000-8000-000000000006",
  operation: "018f0f00-0007-7000-8000-000000000007",
  consumeReceipt: "018f0f00-0008-7000-8000-000000000008",
  capability: "018f0f00-0009-7000-8000-000000000009",
  capacityPool: "018f0f00-000a-7000-8000-00000000000a",
  resourceLease: "018f0f00-000b-7000-8000-00000000000b",
  onlineReceipt: "018f0f00-000c-7000-8000-00000000000c",
  consume1: "018f0f00-000d-7000-8000-00000000000d",
  consume2: "018f0f00-000e-7000-8000-00000000000e",
  capabilityReceipt: "018f0f00-000f-7000-8000-00000000000f",
  holdReceipt: "018f0f00-0010-7000-8000-000000000010",
  hold: "018f0f00-0011-7000-8000-000000000011",
  accountResource: "018f0f00-0012-7000-8000-000000000012",
  grant2: "018f0f00-0013-7000-8000-000000000013",
  grant3: "018f0f00-0014-7000-8000-000000000014",
} as const;
const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;
const D5 = `sha256:${"5".repeat(64)}`;
const D6 = `sha256:${"6".repeat(64)}`;
const C0 = parseCounter("0");
const C1 = parseCounter("1");
const C2 = parseCounter("2");

function canonicalBytes(value: unknown): Uint8Array {
  return Uint8Array.from(Buffer.from(canonicalJson(value), "utf8"));
}

function signedBytes(unsigned: Record<string, unknown>, key: KeyLike): Uint8Array {
  const signature = signBytes(null, Buffer.from(canonicalJson(unsigned), "utf8"), key)
    .toString("base64url");
  return canonicalBytes({ ...unsigned, signature });
}

function snapshot(
  overrides: Partial<NativeSubscriptionBindingSnapshot> = {},
): NativeSubscriptionBindingSnapshot {
  return {
    ownerRef: OWNER,
    providerAccountId: IDS.provider,
    subscriptionId: IDS.subscription,
    accountLaneId: IDS.lane,
    authCapsuleId: IDS.capsule,
    canonicalNodeId: IDS.node,
    nodeKeyThumbprint: D0,
    nodeGeneration: C1,
    placementGeneration: C1,
    authGeneration: C2,
    authStateRevision: C2,
    accountRevision: C2,
    capsuleRevision: C2,
    accountStatus: "active",
    subscriptionStatus: "active",
    accountLaneStatus: "ready",
    capsuleStatus: "ready",
    liveLeaseCount: C0,
    drainState: "drained",
    zeroLiveEvidenceDigest: D1,
    drainEvidenceDigest: D2,
    evidenceExpiresAt: "2030-07-18T12:05:00.000Z",
    ...overrides,
  };
}

function probeRequest(
  overrides: Partial<NativeSubscriptionProbeRequest> = {},
): NativeSubscriptionProbeRequest {
  return {
    schema_version: "accounts.native-subscription-probe-request/v1",
    command: "PROBE_NATIVE",
    owner_ref: OWNER,
    provider_account_id: IDS.provider,
    subscription_id: IDS.subscription,
    account_lane_id: IDS.lane,
    auth_capsule_id: IDS.capsule,
    canonical_node_id: IDS.node,
    node_key_thumbprint: D0,
    node_generation: C1,
    placement_generation: C1,
    auth_generation: C2,
    auth_state_revision: C2,
    ...overrides,
  };
}

function transport(
  overrides: Partial<CapsuleMaintenanceTransportBinding> = {},
): CapsuleMaintenanceTransportBinding {
  return {
    authenticatedOwnerRef: OWNER,
    authenticatedActorPrincipal: OWNER,
    authenticatedMaintenanceExecutorPrincipal: EXECUTOR,
    authenticatedSenderKeyThumbprint: D4,
    authenticatedChannelBindingDigest: D5,
    ...overrides,
  };
}

function grantDraft(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    effect_namespace_id: "effect-namespace-a",
    maintenance_authority_epoch: C1,
    maintenance_operation_id: IDS.operation,
    operation_execution_epoch: C1,
    operation_execution_expires_at: "2030-07-18T12:05:00.000Z",
    execution_fence_digest: D6,
    action: "REAUTHENTICATE_NATIVE",
    effect_class: "mutation",
    target_kind: "native_capsule",
    subject: SUBJECT,
    owner_ref: OWNER,
    provider_account_id: IDS.provider,
    provider_subject_ref: "provider-subject-a",
    account_lane_id: IDS.lane,
    capacity_pool_id: IDS.capacityPool,
    capacity_domain_ref: "capacity-domain-a",
    serialization_key_digest: D3,
    access_transport: "native_session",
    credential_family_id: "credential-family-a",
    capacity_generation: C2,
    deny_generation: C1,
    expected_record_revision: C2,
    expected_credential_generation: C2,
    maintenance_decision_digest: D1,
    approval_mode: "NOT_REQUIRED",
    policy_digest: D2,
    catalog_incarnation: "catalog-a",
    recovery_frontier_sequence: C2,
    recovery_frontier_hash: D3,
    nonce: "maintenance-nonce-a",
    auth_capsule_id: IDS.capsule,
    canonical_node_id: IDS.node,
    node_key_thumbprint: D0,
    node_generation: C1,
    placement_generation: C1,
    expected_auth_generation: C2,
    expected_auth_state_revision: C2,
    ...overrides,
  };
}

function requestDigest(draft: Record<string, unknown>, targetDigest: string): string {
  return canonicalSha256({
    access_transport: draft.access_transport,
    account_lane_id: draft.account_lane_id,
    action: draft.action,
    capacity_domain_ref: draft.capacity_domain_ref,
    capacity_pool_id: draft.capacity_pool_id,
    credential_family_id: draft.credential_family_id,
    effect_class: draft.effect_class,
    operation_role: draft.effect_class === "containment_mutation" ? "CONTAINMENT" : "ORDINARY",
    owner_ref: draft.owner_ref,
    provider_account_id: draft.provider_account_id,
    provider_subject_ref: draft.provider_subject_ref,
    schema_version: "accounts.credential-effect-request.v1",
    serialization_key_digest: draft.serialization_key_digest,
    source_credential_generation: draft.expected_credential_generation,
    source_record_revision: draft.expected_record_revision,
    target_digest: targetDigest,
  });
}

function sourceLineageDigest(
  draft: Record<string, unknown>,
  targetDigest: string,
  canonicalRequestDigest: string,
): string {
  return canonicalSha256({
    action: draft.action,
    credential_family_id: draft.credential_family_id,
    effect_namespace_id: draft.effect_namespace_id,
    operation_role: draft.effect_class === "containment_mutation" ? "CONTAINMENT" : "ORDINARY",
    request_digest: canonicalRequestDigest,
    schema_version: "accounts.credential-effect-source-lineage.v1",
    serialization_key_digest: draft.serialization_key_digest,
    target_digest: targetDigest,
  });
}

function operationDigest(
  draft: Record<string, unknown>,
  targetDigest: string,
  canonicalRequestDigest: string,
  lineageDigest: string,
): string {
  const steps: Record<string, string> = {
    BOOTSTRAP_NATIVE: "bootstrap_native",
    CLEANUP_CREDENTIAL: "cleanup_credential",
    REAUTHENTICATE_NATIVE: "reauthenticate_native",
    REFRESH_NATIVE: "refresh_native",
    REVOKE_BROKERED: "revoke_brokered",
    REVOKE_PROVIDER_SESSION: "revoke_provider_session",
    ROTATE_BROKERED: "rotate_brokered",
  };
  return canonicalSha256({
    action: draft.action,
    canonical_request_digest: canonicalRequestDigest,
    effect_namespace_id: draft.effect_namespace_id,
    maintenance_operation_id: draft.maintenance_operation_id,
    operation_step_id: steps[String(draft.action)],
    schema_version: "accounts.credential-effect-operation.v1",
    source_lineage_digest: lineageDigest,
    target_digest: targetDigest,
  });
}

function accountGrantDraft(): Record<string, unknown> {
  const {
    auth_capsule_id: _authCapsuleId,
    canonical_node_id: _canonicalNodeId,
    node_key_thumbprint: _nodeKeyThumbprint,
    node_generation: _nodeGeneration,
    placement_generation: _placementGeneration,
    expected_auth_generation: _expectedAuthGeneration,
    expected_auth_state_revision: _expectedAuthStateRevision,
    ...common
  } = grantDraft();
  return {
    ...common,
    action: "ROTATE_BROKERED",
    target_kind: "account_record",
    access_transport: "api_key",
    credential_binding_id: IDS.grant3,
    expected_binding_revision: C2,
  };
}

function heldReceiptBytes(draft: Record<string, unknown>, infinityKey: KeyLike): Uint8Array {
  const target = maintenanceTargetDigest(draft);
  const request = requestDigest(draft, target);
  const lineage = sourceLineageDigest(draft, target, request);
  const operation = operationDigest(draft, target, request, lineage);
  return signedBytes({
    schema_version: INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_VERSION,
    schema_digest: INFINITY_MAINTENANCE_HELD_RECEIPT_SCHEMA_DIGEST,
    receipt_id: IDS.holdReceipt,
    issuer: "infinity-self-hosted",
    issuer_incarnation: "infinity-incarnation-a",
    key_id: "infinity-hold-key-a",
    audience: "accounts-self-hosted",
    effect_namespace_id: draft.effect_namespace_id,
    authority_epoch: C1,
    hold_id: IDS.hold,
    hold_generation: C1,
    hold_state: "HELD",
    hold_begin_receipt_digest: D0,
    barrier_head_receipt_digest: D0,
    maintenance_operation_id: draft.maintenance_operation_id,
    operation_digest: operation,
    source_lineage_digest: lineage,
    operation_execution_epoch: draft.operation_execution_epoch,
    operation_execution_expires_at: draft.operation_execution_expires_at,
    execution_fence_digest: draft.execution_fence_digest,
    action: draft.action,
    effect_class: draft.effect_class,
    drain_receipt_digest: D2,
    account_resource_id: IDS.accountResource,
    resource_lifecycle_generation: C1,
    target_digest: target,
    owner_ref: draft.owner_ref,
    provider_account_id: draft.provider_account_id,
    provider_subject_ref: draft.provider_subject_ref,
    account_lane_id: draft.account_lane_id,
    capacity_pool_id: draft.capacity_pool_id,
    capacity_domain_ref: draft.capacity_domain_ref,
    serialization_key_digest: draft.serialization_key_digest,
    access_transport: draft.access_transport,
    credential_family_id: draft.credential_family_id,
    capacity_generation: draft.capacity_generation,
    deny_generation: draft.deny_generation,
    credential_generation: draft.expected_credential_generation,
    resource_lease_frontier_sequence: C2,
    resource_lease_frontier_hash: D1,
    model_effect_frontier_sequence: C2,
    model_effect_frontier_hash: D2,
    delivery_frontier_sequence: C2,
    delivery_frontier_hash: D3,
    active_resource_lease_count: C0,
    unresolved_effect_count: C0,
    queued_delivery_count: C0,
    inflight_delivery_count: C0,
    ambiguity_obligation_count: C0,
    obligation_set_digest: D0,
    issued_at: NOW.toISOString(),
    observed_at: NOW.toISOString(),
    expires_at: "2030-07-18T12:01:00.000Z",
  }, infinityKey);
}

function fixture(
  ledger = new InMemoryCapsuleMaintenanceLedger(),
  ids: string[] = [IDS.grant1, IDS.consumeReceipt],
) {
  const accountsKeys = generateKeyPairSync("ed25519");
  const infinityKeys = generateKeyPairSync("ed25519");
  let heldHeadChecks = 0;
  const currentState: CapsuleMaintenanceCurrentState = {
    verifyIssuance: () => undefined,
    verifyConsume: () => undefined,
    verifyCurrentHeldHead: () => { heldHeadChecks += 1; },
  };
  const value = new CapsuleMaintenanceAuthority({
    issuer: "accounts-self-hosted",
    issuerIncarnation: "accounts-incarnation-a",
    keyId: "accounts-maintenance-key-a",
    audience: "authcapsule-self-hosted",
    publicKey: accountsKeys.publicKey,
    privateKey: accountsKeys.privateKey,
    infinityHeldTrust: {
      issuer: "infinity-self-hosted",
      issuerIncarnation: "infinity-incarnation-a",
      keyId: "infinity-hold-key-a",
      audience: "accounts-self-hosted",
      publicKey: infinityKeys.publicKey,
      authorityEpoch: C1,
    },
    currentState,
    ledger,
    maintenanceAuthorityEpoch: C1,
    clock: () => new Date(NOW),
    idFactory: () => ids.shift() ?? IDS.consumeReceipt,
  });
  return { accountsKeys, infinityKeys, value, heldHeadChecks: () => heldHeadChecks };
}

function issuanceRequest(draft: Record<string, unknown>, holdBytes: Uint8Array, key = D0) {
  return {
    schema_version: CAPSULE_MAINTENANCE_ISSUANCE_REQUEST_SCHEMA_VERSION,
    account_lane_id: IDS.lane,
    idempotency_key_digest: key,
    hold_receipt_jcs_base64url: Buffer.from(holdBytes).toString("base64url"),
    draft,
  };
}

describe("native subscription and maintenance contract", () => {
  test("PROBE_NATIVE remains closed, owner/node bound, and credential-free", async () => {
    const source = new StaticNativeSubscriptionSnapshotSource([snapshot()]);
    const result = await evaluateNativeSubscriptionProbe(probeRequest(), source, OWNER, NOW);
    expect(result.capability_eligible).toBe(true);
    expect(result.maintenance_ready).toBe(true);
    expect(Object.keys(result).some((key) => /credential|token|secret|password/i.test(key))).toBe(false);
    await expect(
      evaluateNativeSubscriptionProbe({ ...probeRequest(), unexpected: true }, source, OWNER, NOW),
    ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    const mismatch = await evaluateNativeSubscriptionProbe(
      probeRequest({ owner_ref: OTHER_OWNER }), source, OTHER_OWNER, NOW,
    );
    expect(mismatch.capability_eligible).toBe(false);
    expect(mismatch.reason_codes).toContain("OWNER_MISMATCH");
  });

  test("pins the exact expanded grant descriptor and exact target sum", async () => {
    expect(canonicalSha256(CAPSULE_MAINTENANCE_GRANT_DESCRIPTOR)).toBe(
      CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
    );
    const { infinityKeys, value } = fixture();
    const draft = grantDraft();
    const hold = heldReceiptBytes(draft, infinityKeys.privateKey);
    const grant = await value.issueMaintenanceGrant(issuanceRequest(draft, hold), transport());
    expect(grant.action).toBe("REAUTHENTICATE_NATIVE");
    expect(grant.target_kind).toBe("native_capsule");
    expect(grant).not.toHaveProperty("credential_binding_id");
    expect(grant).toHaveProperty("maintenance_hold_receipt_digest", canonicalSha256(parseClosedJsonBytes(hold)));

    await expect(value.issueMaintenanceGrant(
      issuanceRequest({ ...draft, credential_binding_id: IDS.grant3 }, hold, D1),
      transport(),
    )).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
  });

  test("issues PROBE_NATIVE only as the distinct read-only, hold-free variant", async () => {
    const { value } = fixture();
    const draft = grantDraft({ action: "PROBE_NATIVE", effect_class: "read_only" });
    const grant = await value.issueMaintenanceGrant({
      schema_version: CAPSULE_MAINTENANCE_ISSUANCE_REQUEST_SCHEMA_VERSION,
      account_lane_id: IDS.lane,
      idempotency_key_digest: D0,
      hold_receipt_jcs_base64url: null,
      draft,
    }, transport());
    expect(grant.action).toBe("PROBE_NATIVE");
    expect(grant.effect_class).toBe("read_only");
    expect(grant).not.toHaveProperty("source_lineage_digest");
    expect(grant).not.toHaveProperty("maintenance_hold_receipt_digest");
    expect(grant).not.toHaveProperty("drain_receipt_digest");
  });

  test("issues the exact account-record target without native target members", async () => {
    const { infinityKeys, value } = fixture();
    const draft = accountGrantDraft();
    const hold = heldReceiptBytes(draft, infinityKeys.privateKey);
    const grant = await value.issueMaintenanceGrant(issuanceRequest(draft, hold), transport());
    expect(grant.action).toBe("ROTATE_BROKERED");
    expect(grant.target_kind).toBe("account_record");
    expect(grant).toHaveProperty("credential_binding_id", IDS.grant3);
    expect(grant).not.toHaveProperty("auth_capsule_id");
    expect(grant).not.toHaveProperty("node_key_thumbprint");
  });

  test("rejects forged HELD evidence and caller-spoofed transport", async () => {
    const { infinityKeys, value } = fixture();
    const draft = grantDraft();
    const hold = heldReceiptBytes(draft, infinityKeys.privateKey);
    const parsed = parseClosedJsonBytes(hold) as Record<string, unknown>;
    const signature = String(parsed.signature);
    const forged = canonicalBytes({
      ...parsed,
      signature: `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`,
    });
    await expect(value.issueMaintenanceGrant(
      issuanceRequest(draft, forged), transport(),
    )).rejects.toMatchObject({ code: "FORBIDDEN" });
    const grant = await value.issueMaintenanceGrant(issuanceRequest(draft, hold), transport());
    await expect(value.consumeMaintenanceGrant({
      schema_version: CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION,
      account_lane_id: IDS.lane,
      idempotency_key_digest: D1,
      grant_jcs_base64url: Buffer.from(canonicalBytes(grant)).toString("base64url"),
      hold_receipt_jcs_base64url: Buffer.from(hold).toString("base64url"),
    }, transport({ authenticatedSenderKeyThumbprint: D3 }))).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  test("survives authority restart and rejects concurrent distinct live grants", async () => {
    const shared = new InMemoryCapsuleMaintenanceLedgerState();
    const ledgerA = new InMemoryCapsuleMaintenanceLedger(shared);
    const first = fixture(ledgerA, [IDS.grant1]);
    const draft = grantDraft();
    const hold = heldReceiptBytes(draft, first.infinityKeys.privateKey);
    const original = await first.value.issueMaintenanceGrant(issuanceRequest(draft, hold), transport());

    const restarted = new CapsuleMaintenanceAuthority({
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-maintenance-key-a",
      audience: "authcapsule-self-hosted",
      publicKey: first.accountsKeys.publicKey,
      privateKey: first.accountsKeys.privateKey,
      infinityHeldTrust: {
        issuer: "infinity-self-hosted",
        issuerIncarnation: "infinity-incarnation-a",
        keyId: "infinity-hold-key-a",
        audience: "accounts-self-hosted",
        publicKey: first.infinityKeys.publicKey,
        authorityEpoch: C1,
      },
      currentState: {
        verifyIssuance: () => undefined,
        verifyConsume: () => undefined,
        verifyCurrentHeldHead: () => undefined,
      },
      ledger: new InMemoryCapsuleMaintenanceLedger(shared),
      maintenanceAuthorityEpoch: C1,
      clock: () => new Date(NOW),
      idFactory: () => IDS.grant2,
    });
    expect(await restarted.issueMaintenanceGrant(issuanceRequest(draft, hold), transport())).toEqual(original);

    const racingState = new InMemoryCapsuleMaintenanceLedgerState();
    const racingKeys = fixture(new InMemoryCapsuleMaintenanceLedger(racingState), [IDS.grant2]);
    const racingHold = heldReceiptBytes(draft, racingKeys.infinityKeys.privateKey);
    const otherAuthority = new CapsuleMaintenanceAuthority({
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-maintenance-key-a",
      audience: "authcapsule-self-hosted",
      publicKey: racingKeys.accountsKeys.publicKey,
      privateKey: racingKeys.accountsKeys.privateKey,
      infinityHeldTrust: {
        issuer: "infinity-self-hosted", issuerIncarnation: "infinity-incarnation-a",
        keyId: "infinity-hold-key-a", audience: "accounts-self-hosted",
        publicKey: racingKeys.infinityKeys.publicKey, authorityEpoch: C1,
      },
      currentState: {
        verifyIssuance: () => undefined, verifyConsume: () => undefined,
        verifyCurrentHeldHead: () => undefined,
      },
      ledger: new InMemoryCapsuleMaintenanceLedger(racingState),
      maintenanceAuthorityEpoch: C1,
      clock: () => new Date(NOW),
      idFactory: () => IDS.grant3,
    });
    const settled = await Promise.allSettled([
      racingKeys.value.issueMaintenanceGrant(issuanceRequest(draft, racingHold, D1), transport()),
      otherAuthority.issueMaintenanceGrant(issuanceRequest(draft, racingHold, D2), transport()),
    ]);
    expect(settled.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(settled.filter((item) => item.status === "rejected")).toHaveLength(1);
  });

  test("atomically consumes ordinal one and returns identical replay bytes", async () => {
    const { accountsKeys, infinityKeys, value, heldHeadChecks } = fixture();
    const draft = grantDraft();
    const hold = heldReceiptBytes(draft, infinityKeys.privateKey);
    const grant = await value.issueMaintenanceGrant(issuanceRequest(draft, hold), transport());
    const request = {
      schema_version: CAPSULE_MAINTENANCE_CONSUME_REQUEST_SCHEMA_VERSION,
      account_lane_id: IDS.lane,
      idempotency_key_digest: D1,
      grant_jcs_base64url: Buffer.from(canonicalBytes(grant)).toString("base64url"),
      hold_receipt_jcs_base64url: Buffer.from(hold).toString("base64url"),
    } as const;
    const consumed = await value.consumeMaintenanceGrant(request, transport());
    const replay = await value.consumeMaintenanceGrant(request, transport());
    expect(replay).toEqual(consumed);
    expect(consumed.use_ordinal).toBe("1");
    expect(heldHeadChecks()).toBeGreaterThanOrEqual(3);
    expect(verifyCapsuleMaintenanceGrant(
      canonicalBytes(grant),
      {
        issuer: "accounts-self-hosted", issuerIncarnation: "accounts-incarnation-a",
        keyId: "accounts-maintenance-key-a", audience: "authcapsule-self-hosted",
        publicKey: accountsKeys.publicKey,
      },
      NOW,
    )).toEqual(grant);
    expect(verifyInfinityMaintenanceHeldReceipt(hold, {
      issuer: "infinity-self-hosted", issuerIncarnation: "infinity-incarnation-a",
      keyId: "infinity-hold-key-a", audience: "accounts-self-hosted",
      publicKey: infinityKeys.publicKey, authorityEpoch: C1,
    }, NOW)).toHaveProperty("hold_state", "HELD");
    await expect(value.consumeMaintenanceGrant({ ...request, idempotency_key_digest: D2 }, transport()))
      .rejects.toMatchObject({ code: "CONFLICT" });
  });

  test("capability-use conformance store carries corrected effect and serialization identities", async () => {
    const keys = generateKeyPairSync("ed25519");
    const store = new InMemoryNativeCapabilityUseStore({
      issuer: "accounts-self-hosted",
      issuerIncarnation: "accounts-incarnation-a",
      keyId: "accounts-capability-use-a",
      audience: "infinity-self-hosted",
      privateKey: keys.privateKey,
      clock: () => new Date(NOW),
      idFactory: () => IDS.capabilityReceipt,
      validateCurrent: () => ({
        catalogIncarnation: "catalog-a",
        recoveryFrontierSequence: C2,
        recoveryFrontierHash: D2,
      }),
    });
    const request = capabilityRequest();
    expect(request.schema_digest).toBe(CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST);
    const consumed = await store.compareAndConsume(request);
    expect(consumed.status).toBe("consumed");
    if (consumed.status !== "consumed") throw new Error("expected consumed");
    const receipt = parseClosedJsonBytes(consumed.signedReceipt) as Record<string, unknown>;
    expect(receipt.schema_digest).toBe(CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST);
    expect(receipt.effect_namespace_id).toBe("effect-namespace-a");
    expect(receipt.serialization_key_digest).toBe(D3);
    expect((await store.compareAndConsume(request)).status).toBe("replayed");
    expect((await store.compareAndConsume({ ...request, nonce: "changed" })).status)
      .toBe("idempotency_conflict");
    expect((await store.compareAndConsume({
      ...request,
      consume_request_id: IDS.consume2,
      capability_id: IDS.grant2,
    })).status).toBe("idempotency_conflict");
  });
});

function capabilityRequest(): OnlineGenerationReceiptUseCasRequest {
  return {
    schema_version: "accounts.capability-use-consume-request.v1",
    schema_digest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
    consume_request_id: IDS.consume1,
    capability_id: IDS.capability,
    capability_digest: D0,
    nonce: "nonce-native-a",
    subject: SUBJECT,
    actor_principal: OWNER,
    effect_namespace_id: "effect-namespace-a",
    account_lane_id: IDS.lane,
    capacity_pool_id: IDS.capacityPool,
    capacity_domain_ref: "capacity-domain-a",
    serialization_key_digest: D3,
    credential_family_id: "credential-family-a",
    resource_lease_id: IDS.resourceLease,
    resource_id: "resource-native-a",
    resource_lifecycle_generation: C1,
    operation_id: IDS.operation,
    operation_digest: D1,
    operation_execution_epoch: C1,
    sender_key_thumbprint: D0,
    channel_binding_digest: D1,
    canonical_request_digest: D2,
    provider_destination_policy_digest: D0,
    online_receipt_id: IDS.onlineReceipt,
    online_receipt_digest: D1,
    model_call_anchor_digest: D2,
    expected_use_count: C0,
    max_uses: C1,
    not_after: "2030-07-18T12:05:00.000Z",
    idempotency_key_digest: D1,
  };
}
