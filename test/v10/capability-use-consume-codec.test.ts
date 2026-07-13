import { afterEach, describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AccountsError } from "../../src/errors";
import { parseCounter } from "../../src/domain/counter";
import { generateUuidV7 } from "../../src/domain/ids";
import { canonicalJson, canonicalSha256, parseClosedJsonBytes } from "../../src/serialization/json";
import * as publicApi from "../../src/index";
import {
  createAccountsSlotEligibilityAdapter,
  createDeterministicAccountsSlotEligibilitySource,
  signOnlineGenerationCheckReceiptV1,
  signSlotEligibilityV1,
  type AccountsEvidenceSigner,
  type AccountsEvidenceSignerHistoryV2,
  type AccountsOnlineGenerationContextV1,
  type AccountsSlotEligibilityRequestV1,
  type AllowedOnlineGenerationCheckReceiptV1,
  type SlotEligibilityPositiveV1,
} from "../../src/v10";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
  CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST,
} from "../../src/v10/capability-use-ledger";
import { parseCapabilityUseConsumeRequestV1 } from "../../src/v10/capability-use-consume";
import type {
  CapabilityUseOperationBinding,
  InfinityAccountsOperationPort,
  VerifiedConsumeBoundOperation,
  VerifiedPreparedOpenOperation,
} from "../../src/v10/infinity-operation-port";

interface Fixture {
  readonly wire: Record<string, unknown>;
}

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as {
  readonly wire_fixtures: Readonly<Record<string, Fixture>>;
};

const NOW = new Date("2026-07-11T10:00:15.000Z");
const SLOT_REQUEST: AccountsSlotEligibilityRequestV1 = {
  schema_version: "accounts.eligibility-request.v1",
  account_lane_id: "0198a0a0-0000-7000-8000-000000000002",
  data_classification: "internal",
  destination_policy_class: "provider_api",
  model: "provider-model-1",
  operation: "generate",
};
const CHANNEL_DIGEST = `sha256:${"7".repeat(64)}` as const;
const ANCHOR_BYTES = new TextEncoder().encode(canonicalJson({ anchor: "prepared-open-1" }));
const ANCHOR_DIGEST = digest(ANCHOR_BYTES);
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function digest(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function bytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}

function stringField(value: Readonly<Record<string, unknown>>, field: string): string {
  const result = value[field];
  if (typeof result !== "string") throw new Error(`fixture ${field} must be a string`);
  return result;
}

function fixtureBytes(name: string): Uint8Array {
  return bytes(fixtureDocument.wire_fixtures[name]!.wire);
}

function contextFromFixture(
  fixtureName = "online_generation_check_positive",
): AccountsOnlineGenerationContextV1 {
  const wire = fixtureDocument.wire_fixtures[fixtureName]!.wire;
  return {
    authenticated_actor_principal: wire.actor_principal,
    account_lane_id: wire.account_lane_id,
    capability_id: wire.capability_id,
    capability_digest: wire.capability_digest,
    nonce: wire.nonce,
    authority_epoch: wire.authority_epoch,
    route_lineage_id: wire.route_lineage_id,
    route_id: wire.route_id,
    route_epoch: wire.route_epoch,
    run_id: wire.run_id,
    attempt_id: wire.attempt_id,
    attempt_lease_id: wire.attempt_lease_id,
    lease_epoch: wire.lease_epoch,
    resource_lease_id: wire.resource_lease_id,
    resource_id: wire.resource_id,
    resource_lifecycle_generation: wire.resource_lifecycle_generation,
    lease_expires_at: wire.lease_expires_at,
    operation_id: wire.operation_id,
    operation_digest: wire.operation_digest,
    operation_execution_epoch: wire.operation_execution_epoch,
    operation_execution_expires_at: wire.operation_execution_expires_at,
    subject: wire.subject,
    actor_principal: wire.actor_principal,
    lease_holder_principal: wire.lease_holder_principal,
    operation_executor_principal: wire.operation_executor_principal,
    sender_key_thumbprint: wire.sender_key_thumbprint,
    approval_mode: wire.approval_mode,
    approval_binding_digest: wire.approval_binding_digest,
    policy_digest: wire.policy_digest,
    canonical_request_digest: wire.canonical_request_digest,
    provider_destination_policy: structuredClone(wire.provider_destination_policy),
    provider_destination_policy_digest: wire.provider_destination_policy_digest,
    sender_constraint_confirmation: CHANNEL_DIGEST,
    max_uses: wire.max_uses,
  } as AccountsOnlineGenerationContextV1;
}

function signedEvidence() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer = {
    issuer: "accounts:self-hosted",
    issuerIncarnation: "accounts-v11-consume-tests",
    audience: "infinity:self-hosted",
    keyId: "accounts-current",
    privateKey,
  } satisfies AccountsEvidenceSigner;
  const signerHistory: AccountsEvidenceSignerHistoryV2 = {
    schema_version: "accounts.evidence-signer-history/v2",
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    current_key_id: signer.keyId,
    keys: [{
      key_id: signer.keyId,
      public_key_spki_base64url: publicKey
        .export({ format: "der", type: "spki" })
        .toString("base64url"),
      activated_at: "2026-07-11T09:00:00.000Z",
      expires_at: "2026-07-12T00:00:00.000Z",
      retired_at: null,
      revoked_at: null,
    }],
  };
  const slotDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    eligibility_request_digest: digest(bytes(SLOT_REQUEST)),
  };
  delete slotDraft.signature;
  const slotBytes = signSlotEligibilityV1(slotDraft, signer);
  const slotSource = createDeterministicAccountsSlotEligibilitySource({
    slot: slotBytes,
    online: fixtureBytes("online_generation_check_positive"),
  });
  const slotPort = createAccountsSlotEligibilityAdapter(slotSource, {
    signerHistory,
    now: NOW,
    expectedEffectNamespaceId: "effect-namespace-1",
  });
  const onlineDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    sender_constraint_confirmation: CHANNEL_DIGEST,
    slot_eligibility_digest: digest(slotBytes),
  };
  delete onlineDraft.signature;
  const onlineBytes = signOnlineGenerationCheckReceiptV1(onlineDraft, signer);
  const denyDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_resolved_negative!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    sender_constraint_confirmation: CHANNEL_DIGEST,
    slot_eligibility_digest: digest(slotBytes),
  };
  delete denyDraft.signature;
  const denyBytes = signOnlineGenerationCheckReceiptV1(denyDraft, signer);
  return { signer, signerHistory, slotBytes, slotPort, onlineBytes, denyBytes };
}

async function positiveSlot(
  evidence: ReturnType<typeof signedEvidence>,
): Promise<SlotEligibilityPositiveV1> {
  const slot = await evidence.slotPort.getSlotEligibility(SLOT_REQUEST);
  if (!slot.eligible) throw new Error("expected positive SlotEligibility fixture");
  return slot;
}

function requestFor(
  onlineBytes: Uint8Array,
  overrides: Readonly<Record<string, unknown>> = {},
): Uint8Array {
  const online = parseClosedJsonBytes(onlineBytes) as Record<string, unknown>;
  return bytes({
    schema_version: "accounts.capability-use-consume-request.v1",
    schema_digest: CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
    consume_request_id: generateUuidV7(NOW.getTime()),
    capability_id: online.capability_id,
    capability_digest: online.capability_digest,
    nonce: online.nonce,
    subject: online.subject,
    actor_principal: online.actor_principal,
    effect_namespace_id: online.effect_namespace_id,
    account_lane_id: online.account_lane_id,
    capacity_pool_id: online.capacity_pool_id,
    capacity_domain_ref: online.capacity_domain_ref,
    serialization_key_digest: online.serialization_key_digest,
    credential_family_id: online.credential_family_id,
    resource_lease_id: online.resource_lease_id,
    resource_id: online.resource_id,
    resource_lifecycle_generation: online.resource_lifecycle_generation,
    operation_id: online.operation_id,
    operation_digest: online.operation_digest,
    operation_execution_epoch: online.operation_execution_epoch,
    sender_key_thumbprint: online.sender_key_thumbprint,
    channel_binding_digest: CHANNEL_DIGEST,
    canonical_request_digest: online.canonical_request_digest,
    provider_destination_policy_digest: online.provider_destination_policy_digest,
    online_receipt_id: online.receipt_id,
    online_receipt_digest: digest(onlineBytes),
    model_call_anchor_digest: ANCHOR_DIGEST,
    expected_use_count: "0",
    max_uses: "1",
    not_after: online.expires_at,
    idempotency_key_digest: `sha256:${"a".repeat(64)}`,
    ...overrides,
  });
}

function bindingFromRequest(requestBytes: Uint8Array): CapabilityUseOperationBinding {
  const request = parseClosedJsonBytes(requestBytes) as Record<string, unknown>;
  return {
    effectNamespaceId: stringField(request, "effect_namespace_id"),
    capabilityId: stringField(request, "capability_id"),
    capabilityDigest: stringField(request, "capability_digest") as `sha256:${string}`,
    nonce: stringField(request, "nonce"),
    subject: stringField(request, "subject"),
    actorPrincipal: stringField(request, "actor_principal"),
    accountLaneId: stringField(request, "account_lane_id"),
    capacityPoolId: stringField(request, "capacity_pool_id"),
    capacityDomainRef: stringField(request, "capacity_domain_ref"),
    serializationKeyDigest: stringField(request, "serialization_key_digest") as `sha256:${string}`,
    credentialFamilyId: stringField(request, "credential_family_id"),
    resourceLeaseId: stringField(request, "resource_lease_id"),
    resourceId: stringField(request, "resource_id"),
    resourceLifecycleGeneration: stringField(request, "resource_lifecycle_generation"),
    operationId: stringField(request, "operation_id"),
    operationDigest: stringField(request, "operation_digest") as `sha256:${string}`,
    operationExecutionEpoch: stringField(request, "operation_execution_epoch"),
    senderKeyThumbprint: stringField(request, "sender_key_thumbprint") as `sha256:${string}`,
    channelBindingDigest: stringField(request, "channel_binding_digest") as `sha256:${string}`,
    canonicalRequestDigest: stringField(request, "canonical_request_digest") as `sha256:${string}`,
    providerDestinationPolicyDigest: stringField(
      request,
      "provider_destination_policy_digest",
    ) as `sha256:${string}`,
    onlineReceiptId: stringField(request, "online_receipt_id"),
    onlineReceiptDigest: stringField(request, "online_receipt_digest") as `sha256:${string}`,
    modelCallAnchorDigest: stringField(request, "model_call_anchor_digest") as `sha256:${string}`,
  };
}

function infinityFor(requestBytes: Uint8Array) {
  const binding = bindingFromRequest(requestBytes);
  const openHoldBytes = bytes({ hold: "open-1" });
  const prepared: VerifiedPreparedOpenOperation = {
    schemaVersion: "infinity.model-call-prepared-anchor/v1",
    schemaDigest: "sha256:39f247a54d025353bdb2cf98907ccfe9ad49d8c03ba4244bf66c72da667e924e",
    recordKind: "PREPARED",
    holdState: "OPEN",
    binding,
    preparedAnchorJcsBase64url: Buffer.from(ANCHOR_BYTES).toString("base64url"),
    preparedAnchorDigest: ANCHOR_DIGEST,
    openHoldReceiptJcsBase64url: Buffer.from(openHoldBytes).toString("base64url"),
    openHoldReceiptDigest: digest(openHoldBytes),
    holdAuthorityEpoch: "1",
    holdId: "hold-1",
    holdGeneration: "1",
    resourceLeaseFrontierSequence: "10",
    resourceLeaseFrontierHash: `sha256:${"1".repeat(64)}`,
    preparedModelEffectFrontierSequence: "11",
    preparedModelEffectFrontierHash: `sha256:${"2".repeat(64)}`,
    deliveryFrontierSequence: "12",
    deliveryFrontierHash: `sha256:${"3".repeat(64)}`,
    holdModelFrontierDigest: `sha256:${"4".repeat(64)}`,
  };
  const calls = { read: 0, preparedCurrent: 0, bind: 0, assert: 0 };
  let unavailableAt: "read" | "preparedCurrent" | "bind" | "assert" | undefined;
  let preparedOverride: VerifiedPreparedOpenOperation | undefined;
  let bound: VerifiedConsumeBoundOperation | undefined;
  let transformBound = (value: VerifiedConsumeBoundOperation) => value;
  const port: InfinityAccountsOperationPort = {
    readPreparedOpenOperation: async () => {
      calls.read += 1;
      if (unavailableAt === "read") throw new Error("unavailable");
      return preparedOverride ?? prepared;
    },
    assertPreparedOpenCurrent: async ({ prepared: candidate }) => {
      calls.preparedCurrent += 1;
      if (unavailableAt === "preparedCurrent") throw new Error("unavailable");
      return candidate;
    },
    bindCapabilityUse: async (input) => {
      calls.bind += 1;
      if (unavailableAt === "bind") throw new Error("unavailable");
      const wire = bytes({
        prepared_anchor_digest: prepared.preparedAnchorDigest,
        consume_receipt_digest: input.consumeReceiptDigest,
        use_id: input.useId,
      });
      bound = {
        schemaVersion: "infinity.model-call-consume-binding/v1",
        schemaDigest: "sha256:5ed69a61c6162ac1aa42e50e8d718b92fc8bbfab9b1da0d78ecbe91c24f621d2",
        recordKind: "CONSUME_BOUND",
        holdState: "OPEN",
        prepared: input.prepared,
        consumeReceiptDigest: input.consumeReceiptDigest,
        useId: input.useId,
        consumeBindingJcsBase64url: Buffer.from(wire).toString("base64url"),
        consumeBindingDigest: digest(wire),
        boundModelEffectFrontierSequence: "12",
        boundModelEffectFrontierHash: `sha256:${"5".repeat(64)}`,
      };
      return transformBound(bound);
    },
    assertConsumeBoundCurrent: async (input) => {
      calls.assert += 1;
      if (unavailableAt === "assert") throw new Error("unavailable");
      return input.consumeBound;
    },
  };
  return {
    port,
    calls,
    prepared,
    setUnavailableAt: (value: typeof unavailableAt) => { unavailableAt = value; },
    setPrepared: (value: VerifiedPreparedOpenOperation) => { preparedOverride = value; },
    setBoundTransform: (
      value: (bound: VerifiedConsumeBoundOperation) => VerifiedConsumeBoundOperation,
    ) => { transformBound = value; },
  };
}

function consumerOptions(
  root: string,
  evidence: ReturnType<typeof signedEvidence>,
  infinity: InfinityAccountsOperationPort,
) {
  const online = parseClosedJsonBytes(evidence.onlineBytes) as Record<string, unknown>;
  return {
    infinity,
    receiptSigner: evidence.signer,
    receiptSignerHistory: evidence.signerHistory,
    onlineTrust: {
      signerHistory: evidence.signerHistory,
      expectedEffectNamespaceId: "effect-namespace-1",
    },
    expectedSerializationKeyDigest: stringField(
      online,
      "serialization_key_digest",
    ) as `sha256:${string}`,
    clock: () => new Date(NOW),
    ledger: {
      ledgerPath: join(root, "capability-use.log"),
      mirrorPath: join(root, "capability-use.sqlite"),
      catalogIncarnation: "catalog-incarnation-1",
      signingKey: new Uint8Array(32).fill(0x61),
    },
  } as const;
}

async function consumeInput(
  evidence: ReturnType<typeof signedEvidence>,
  requestBytes: Uint8Array,
) {
  return {
    consumeRequestBytes: requestBytes,
    authenticatedChannelBindingDigest: CHANNEL_DIGEST,
    expectedSlotEligibility: await positiveSlot(evidence),
    onlineReceiptBytes: evidence.onlineBytes,
  } as const;
}

describe("v11 capability-use consume production composition", () => {
  test("exports only the composed consumer and corrected identities from package root", () => {
    expect(publicApi.createAccountsCapabilityUseConsumer).toBeFunction();
    expect(publicApi).toMatchObject({
      CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
      CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    });
    expect(publicApi).not.toHaveProperty("consumeOnlineGenerationCheckReceiptUse");
    expect(publicApi).not.toHaveProperty("NonRewindableCapabilityUseLedger");
    expect(publicApi).not.toHaveProperty("verifyCapabilityUseEvidence");
    expect(publicApi).not.toHaveProperty("CapabilityUseEvidenceVerifier");
    expect(Object.values(publicApi)).not.toContain(
      "sha256:a7cdc1dfbebeaea3bad6a5014cfb5189be40fb010f57161b46437458492cd1bc",
    );
    expect(Object.values(publicApi)).not.toContain(
      "sha256:a0999ffabc197f46f6fdeb8a6b78521364b0f2153d52a0e6e63ee360bb408bce",
    );
  });

  test("consumes once, binds current Infinity evidence, conflicts a second request, and replays exact bytes", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const first = await consumer.consume(await consumeInput(evidence, requestBytes));
    expect(first.replayed).toBe(false);
    expect(first.bindingCurrent).toBe(true);
    expect(first.consumeBound).toMatchObject({
      recordKind: "CONSUME_BOUND",
      consumeReceiptDigest: first.consumeReceiptDigest,
      useId: first.useId,
    });
    expect(first.consumeReceiptDigest).toBe(digest(first.receiptBytes));
    expect(first.tombstoneDigest).toBe(digest(first.tombstoneBytes));
    expect(Object.isFrozen(first)).toBe(true);
    const storedReceiptBytes = Uint8Array.from(first.receiptBytes);
    const storedTombstoneBytes = Uint8Array.from(first.tombstoneBytes);
    first.receiptBytes[0] = first.receiptBytes[0]! ^ 0xff;
    first.tombstoneBytes[0] = first.tombstoneBytes[0]! ^ 0xff;
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 1 });

    const conflictingBytes = requestFor(evidence.onlineBytes, {
      consume_request_id: generateUuidV7(NOW.getTime() + 1),
      idempotency_key_digest: `sha256:${"b".repeat(64)}`,
    });
    await expect(consumer.consume(await consumeInput(evidence, conflictingBytes))).rejects.toEqual(
      expect.objectContaining({ code: "CONFLICT" }),
    );
    consumer.close();

    const unavailable = infinityFor(requestBytes);
    unavailable.setUnavailableAt("read");
    const reopened = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, unavailable.port),
    );
    const replay = await reopened.consume(await consumeInput(evidence, requestBytes));
    expect(replay.replayed).toBe(true);
    expect(replay.bindingCurrent).toBe(false);
    expect(replay.consumeBound).toBeUndefined();
    expect(replay.receiptBytes).toEqual(storedReceiptBytes);
    expect(replay.consumeReceiptDigest).toBe(first.consumeReceiptDigest);
    expect(replay.tombstoneBytes).toEqual(storedTombstoneBytes);
    expect(replay.tombstoneDigest).toBe(first.tombstoneDigest);
    expect(replay.tombstoneDigest).toBe(digest(replay.tombstoneBytes));
    expect(unavailable.calls).toEqual({ read: 0, preparedCurrent: 0, bind: 0, assert: 0 });
    reopened.close();
  });

  test("serializes concurrent identical first consumes onto one exact stored receipt", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-concurrent-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const input = await consumeInput(evidence, requestBytes);
    const [left, right] = await Promise.all([consumer.consume(input), consumer.consume(input)]);
    expect([left.replayed, right.replayed].sort()).toEqual([false, true]);
    expect(left.receiptBytes).toEqual(right.receiptBytes);
    expect(left.consumeReceiptDigest).toBe(right.consumeReceiptDigest);
    expect(left.tombstoneBytes).toEqual(right.tombstoneBytes);
    expect(left.tombstoneDigest).toBe(right.tombstoneDigest);
    consumer.close();
  });

  test("request codec rejects stale identities, noncanonical bytes, unknown fields, and changed literals", () => {
    const evidence = signedEvidence();
    const validBytes = requestFor(evidence.onlineBytes);
    const valid = parseClosedJsonBytes(validBytes) as Record<string, unknown>;
    for (const mutant of [
      { ...valid, schema_digest: "sha256:a7cdc1dfbebeaea3bad6a5014cfb5189be40fb010f57161b46437458492cd1bc" },
      { ...valid, unexpected: "field" },
      { ...valid, expected_use_count: "1" },
      { ...valid, max_uses: "2" },
    ]) {
      expect(() => parseCapabilityUseConsumeRequestV1(bytes(mutant))).toThrow(AccountsError);
    }
    const noncanonical = new TextEncoder().encode(` ${new TextDecoder().decode(validBytes)}`);
    expect(() => parseCapabilityUseConsumeRequestV1(noncanonical)).toThrow(AccountsError);
  });

  test("rejects accessor-backed composition inputs without invoking them", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-accessor-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const input = await consumeInput(evidence, requestBytes);
    let invoked = false;
    Object.defineProperty(input, "authenticatedChannelBindingDigest", {
      enumerable: true,
      get() {
        invoked = true;
        return CHANNEL_DIGEST;
      },
    });
    await expect(consumer.consume(input)).rejects.toBeInstanceOf(AccountsError);
    expect(invoked).toBe(false);
    consumer.close();
  });

  test("rejects wrong channel, anchor, signature, expiry, deny, and unavailable Infinity before append", async () => {
    const scenarios: ReadonlyArray<readonly [string, (state: {
      evidence: ReturnType<typeof signedEvidence>;
      requestBytes: Uint8Array;
      input: Awaited<ReturnType<typeof consumeInput>>;
      infinity: ReturnType<typeof infinityFor>;
    }) => void]> = [
      ["wrong channel", ({ input }) => {
        (input as { authenticatedChannelBindingDigest: string }).authenticatedChannelBindingDigest =
          `sha256:${"8".repeat(64)}`;
      }],
      ["wrong anchor", ({ requestBytes, infinity }) => {
        infinity.setPrepared({
          ...infinity.prepared,
          preparedAnchorDigest: `sha256:${"9".repeat(64)}`,
        });
        void requestBytes;
      }],
      ["non-open prepared evidence", ({ infinity }) => {
        infinity.setPrepared({
          ...infinity.prepared,
          holdState: "HELD" as "OPEN",
        });
      }],
      ["zero hold authority epoch", ({ infinity }) => {
        infinity.setPrepared({
          ...infinity.prepared,
          holdAuthorityEpoch: "0",
        });
      }],
      ["bad signature", ({ evidence, input }) => {
        const wire = parseClosedJsonBytes(evidence.onlineBytes) as Record<string, unknown>;
        wire.signature = Buffer.alloc(64, 0x42).toString("base64url");
        (input as { onlineReceiptBytes: Uint8Array }).onlineReceiptBytes = bytes(wire);
      }],
      ["deny", ({ evidence, input }) => {
        (input as { onlineReceiptBytes: Uint8Array }).onlineReceiptBytes = evidence.denyBytes;
      }],
      ["Infinity unavailable", ({ infinity }) => infinity.setUnavailableAt("read")],
      ["Infinity PREPARED currentness unavailable", ({ infinity }) =>
        infinity.setUnavailableAt("preparedCurrent")],
    ];
    for (const [name, mutate] of scenarios) {
      const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-reject-"));
      chmodSync(root, 0o700);
      roots.push(root);
      const evidence = signedEvidence();
      const requestBytes = requestFor(evidence.onlineBytes);
      const input = await consumeInput(evidence, requestBytes);
      const infinity = infinityFor(requestBytes);
      mutate({ evidence, requestBytes, input, infinity });
      const consumer = publicApi.createAccountsCapabilityUseConsumer(
        consumerOptions(root, evidence, infinity.port),
      );
      await expect(consumer.consume(input)).rejects.toBeInstanceOf(AccountsError);
      expect(name).toBeString();
      consumer.close();
    }

    const expiredRoot = mkdtempSync(join(tmpdir(), "accounts-v11-consume-expired-"));
    chmodSync(expiredRoot, 0o700);
    roots.push(expiredRoot);
    const expiredEvidence = signedEvidence();
    const expiredRequest = requestFor(expiredEvidence.onlineBytes);
    const expiredInfinity = infinityFor(expiredRequest);
    const expiredConsumer = publicApi.createAccountsCapabilityUseConsumer({
      ...consumerOptions(expiredRoot, expiredEvidence, expiredInfinity.port),
      clock: () => new Date("2026-07-11T11:00:00.000Z"),
    });
    await expect(expiredConsumer.consume(
      await consumeInput(expiredEvidence, expiredRequest),
    )).rejects.toBeInstanceOf(AccountsError);
    expect(expiredInfinity.calls).toEqual({ read: 0, preparedCurrent: 0, bind: 0, assert: 0 });
    expiredConsumer.close();
  });

  test("rejects retired, revoked, expired, or mismatched receipt signing keys", () => {
    for (const state of ["retired", "revoked", "expired", "mismatched"] as const) {
      const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-signer-"));
      chmodSync(root, 0o700);
      roots.push(root);
      const evidence = signedEvidence();
      const requestBytes = requestFor(evidence.onlineBytes);
      const infinity = infinityFor(requestBytes);
      const key = evidence.signerHistory.keys[0]!;
      const history: AccountsEvidenceSignerHistoryV2 = {
        ...evidence.signerHistory,
        keys: [{
          ...key,
          ...(state === "retired" ? { retired_at: "2026-07-11T10:00:00.000Z" } : {}),
          ...(state === "revoked" ? { revoked_at: "2026-07-11T10:00:00.000Z" } : {}),
          ...(state === "expired" ? { expires_at: "2026-07-11T10:00:00.000Z" } : {}),
        }],
      };
      const signer = state === "mismatched"
        ? { ...evidence.signer, privateKey: generateKeyPairSync("ed25519").privateKey }
        : evidence.signer;
      expect(() => publicApi.createAccountsCapabilityUseConsumer({
        ...consumerOptions(root, evidence, infinity.port),
        receiptSigner: signer,
        receiptSignerHistory: history,
      })).toThrow(AccountsError);
    }
  });

  test("requires factory-pinned online trust and serialization identity", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-online-trust-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const options = consumerOptions(root, evidence, infinity.port);
    expect(() => publicApi.createAccountsCapabilityUseConsumer({
      ...options,
      onlineTrust: { signerHistory: evidence.signerHistory },
    } as never)).toThrow(AccountsError);
    const key = evidence.signerHistory.keys[0]!;
    expect(() => publicApi.createAccountsCapabilityUseConsumer({
      ...options,
      onlineTrust: {
        ...options.onlineTrust,
        signerHistory: {
          ...evidence.signerHistory,
          keys: [{ ...key, revoked_at: NOW.toISOString() }],
        },
      },
    })).toThrow(AccountsError);
    const wrongSerialization = publicApi.createAccountsCapabilityUseConsumer({
      ...options,
      expectedSerializationKeyDigest: `sha256:${"f".repeat(64)}`,
    });
    await expect(wrongSerialization.consume(
      await consumeInput(evidence, requestBytes),
    )).rejects.toBeInstanceOf(AccountsError);
    wrongSerialization.close();

    const consumer = publicApi.createAccountsCapabilityUseConsumer(options);
    const injected = {
      ...await consumeInput(evidence, requestBytes),
      onlineTrust: {
        signerHistory: signedEvidence().signerHistory,
        expectedEffectNamespaceId: "effect-namespace-1",
      },
    };
    await expect(consumer.consume(injected as never)).rejects.toBeInstanceOf(AccountsError);
    expect(infinity.calls).toEqual({ read: 0, preparedCurrent: 0, bind: 0, assert: 0 });
    consumer.close();
  });

  test("a post-append Infinity bind failure leaves the use durably consumed and replayable", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-bind-fail-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    infinity.setUnavailableAt("bind");
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const input = await consumeInput(evidence, requestBytes);
    await expect(consumer.consume(input)).rejects.toEqual(
      expect.objectContaining({ code: "DEPENDENCY_UNAVAILABLE" }),
    );
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 0 });
    const replay = await consumer.consume(input);
    expect(replay.replayed).toBe(true);
    expect(replay.bindingCurrent).toBe(false);
    expect(replay.consumeBound).toBeUndefined();
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 0 });
    consumer.close();
  });

  test("rejects a noncontiguous Infinity bound frontier after durably consuming the use", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-bound-frontier-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    infinity.setBoundTransform((bound) => ({
      ...bound,
      boundModelEffectFrontierSequence: "13",
    }));
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const input = await consumeInput(evidence, requestBytes);
    await expect(consumer.consume(input)).rejects.toBeInstanceOf(AccountsError);
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 1, assert: 0 });
    const replay = await consumer.consume(input);
    expect(replay.replayed).toBe(true);
    expect(replay.bindingCurrent).toBe(false);
    consumer.close();
  });

  test("rechecks online expiry after the asynchronous Infinity read before durable append", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-expiry-race-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const advancingClock = () => new Date(
      infinity.calls.preparedCurrent === 0
        ? NOW
        : "2026-07-11T11:00:00.000Z",
    );
    const consumer = publicApi.createAccountsCapabilityUseConsumer({
      ...consumerOptions(root, evidence, infinity.port),
      clock: advancingClock,
    });
    const input = await consumeInput(evidence, requestBytes);
    await expect(consumer.consume(input)).rejects.toBeInstanceOf(AccountsError);
    expect(infinity.calls).toEqual({ read: 1, preparedCurrent: 1, bind: 0, assert: 0 });
    consumer.close();

    const retryInfinity = infinityFor(requestBytes);
    const retry = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, retryInfinity.port),
    );
    const result = await retry.consume(input);
    expect(result.replayed).toBe(false);
    retry.close();
  });

  test("receipt wire is closed, signed, cross-bound, fresh, and uses corrected descriptors", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v11-consume-wire-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const evidence = signedEvidence();
    const requestBytes = requestFor(evidence.onlineBytes);
    const infinity = infinityFor(requestBytes);
    const consumer = publicApi.createAccountsCapabilityUseConsumer(
      consumerOptions(root, evidence, infinity.port),
    );
    const result = await consumer.consume(await consumeInput(evidence, requestBytes));
    const receipt = parseClosedJsonBytes(result.receiptBytes) as Record<string, unknown>;
    const tombstone = parseClosedJsonBytes(result.tombstoneBytes) as Record<string, unknown>;
    const request = parseClosedJsonBytes(requestBytes) as Record<string, unknown>;
    expect(receipt).toMatchObject({
      schema_version: "accounts.capability-use-consume-receipt.v1",
      schema_digest: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
      consume_request_id: request.consume_request_id,
      effect_namespace_id: request.effect_namespace_id,
      serialization_key_digest: request.serialization_key_digest,
      prior_use_count: "0",
      next_use_count: "1",
      use_ordinal: "1",
      max_uses: "1",
      catalog_incarnation: "catalog-incarnation-1",
    });
    expect(receipt.use_id).toBe(canonicalSha256({
      capability_id: request.capability_id,
      channel_binding_digest: request.channel_binding_digest,
      model_call_anchor_digest: request.model_call_anchor_digest,
      nonce: request.nonce,
      operation_id: request.operation_id,
      resource_lease_id: request.resource_lease_id,
      schema_version: "accounts.capability-use.v1",
      sender_key_thumbprint: request.sender_key_thumbprint,
      use_ordinal: "1",
    }));
    expect(Date.parse(stringField(receipt, "expires_at")) - Date.parse(
      stringField(receipt, "committed_at"),
    )).toBeLessThanOrEqual(60_000);
    expect(stringField(receipt, "recovery_frontier_sequence")).toBe(
      parseCounter(stringField(
        parseClosedJsonBytes(evidence.onlineBytes) as Record<string, unknown>,
        "recovery_frontier_sequence",
      )),
    );
    expect(tombstone).toMatchObject({
      schema_version: "accounts.capability-use-tombstone.v1",
      schema_digest: CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST,
      record_kind: "CONSUMED",
      consume_request_id: request.consume_request_id,
      idempotency_key_digest: request.idempotency_key_digest,
      effect_namespace_id: request.effect_namespace_id,
      serialization_key_digest: request.serialization_key_digest,
      capability_id: request.capability_id,
      capability_digest: request.capability_digest,
      nonce: request.nonce,
      online_receipt_digest: request.online_receipt_digest,
      model_call_anchor_digest: request.model_call_anchor_digest,
      use_id: receipt.use_id,
      consume_request_jcs_sha256: digest(requestBytes),
      consume_request_jcs_base64url: Buffer.from(requestBytes).toString("base64url"),
      consume_receipt_digest: result.consumeReceiptDigest,
      consume_receipt_jcs_base64url: Buffer.from(result.receiptBytes).toString("base64url"),
      committed_at: receipt.committed_at,
      consume_receipt_expires_at: receipt.expires_at,
      catalog_incarnation: receipt.catalog_incarnation,
      recovery_frontier_sequence: receipt.recovery_frontier_sequence,
      recovery_frontier_hash: receipt.recovery_frontier_hash,
      signer_ref: evidence.signerHistory.issuer,
      signer_incarnation: evidence.signerHistory.issuer_incarnation,
      key_id: evidence.signerHistory.current_key_id,
      audience: evidence.signerHistory.audience,
    });
    expect(result.tombstoneDigest).toBe(digest(result.tombstoneBytes));
    consumer.close();
  });
});
