import {
  createHash,
  createPublicKey,
  verify as ed25519Verify,
} from "node:crypto";

import { parseCounter } from "../domain/counter";
import { generateUuidV7 } from "../domain/ids";
import { AccountsError } from "../errors";
import { canonicalJson } from "../serialization/json";
import { ACCOUNTS_V10_MAX_CLOCK_SKEW_MS } from "./constants";
import {
  CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR,
  CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPABILITY_USE_CONSUME_REQUEST_DESCRIPTOR,
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
  CAPABILITY_USE_TOMBSTONE_DESCRIPTOR,
  CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST,
  NonRewindableCapabilityUseLedger,
  verifyCapabilityUseEvidenceWithTombstone,
  type CapabilityUseLedgerRecord,
} from "./capability-use-ledger";
import {
  INFINITY_MODEL_CALL_CONSUME_BINDING_SCHEMA_DIGEST,
  INFINITY_MODEL_CALL_PREPARED_ANCHOR_SCHEMA_DIGEST,
  type CapabilityUseOperationBinding,
  type InfinityAccountsOperationPort,
  type VerifiedConsumeBoundOperation,
  type VerifiedPreparedOpenOperation,
} from "./infinity-operation-port";
import {
  parseOnlineGenerationCheckReceiptV1,
  requireAllowedOnlineGenerationCheckReceiptV1,
} from "./online";
import {
  assertSignatureShape,
  canonicalBytes,
  cloneWire,
  counter,
  invariant,
  nonemptyString,
  normalizeTrust,
  parseCanonicalWireBytes,
  positiveCounter,
  requiredKeys,
  sha256Digest,
  signEvidenceBytes,
  timestampMs,
  uuidV7,
  validateSignerHistory,
} from "./primitives";
import { encodeSlotEligibilityV1, parseSlotEligibilityV1 } from "./slot";
import type {
  AccountsEvidenceSigner,
  AccountsEvidenceSignerHistoryV2,
  AccountsEvidenceTrustV1,
  AllowedOnlineGenerationCheckReceiptV1,
  SlotEligibilityPositiveV1,
  V10Sha256Digest,
} from "./types";

const MAX_CONSUME_RECEIPT_LIFETIME_MS = 60_000;
const MAX_EVIDENCE_BYTES = 1024 * 1024;

type Sha256Digest = `sha256:${string}`;

export interface CapabilityUseConsumeRequestV1 {
  readonly schema_version: "accounts.capability-use-consume-request.v1";
  readonly schema_digest: typeof CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST;
  readonly consume_request_id: string;
  readonly capability_id: string;
  readonly capability_digest: Sha256Digest;
  readonly nonce: string;
  readonly subject: string;
  readonly actor_principal: string;
  readonly effect_namespace_id: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly capacity_domain_ref: string;
  readonly serialization_key_digest: Sha256Digest;
  readonly credential_family_id: string;
  readonly resource_lease_id: string;
  readonly resource_id: string;
  readonly resource_lifecycle_generation: string;
  readonly operation_id: string;
  readonly operation_digest: Sha256Digest;
  readonly operation_execution_epoch: string;
  readonly sender_key_thumbprint: Sha256Digest;
  readonly channel_binding_digest: Sha256Digest;
  readonly canonical_request_digest: Sha256Digest;
  readonly provider_destination_policy_digest: Sha256Digest;
  readonly online_receipt_id: string;
  readonly online_receipt_digest: Sha256Digest;
  readonly model_call_anchor_digest: Sha256Digest;
  readonly expected_use_count: "0";
  readonly max_uses: "1";
  readonly not_after: string;
  readonly idempotency_key_digest: Sha256Digest;
}

export interface CapabilityUseConsumeReceiptV1 {
  readonly schema_version: "accounts.capability-use-consume-receipt.v1";
  readonly schema_digest: typeof CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST;
  readonly consume_request_id: string;
  readonly consume_receipt_id: string;
  readonly issuer: string;
  readonly issuer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly capability_id: string;
  readonly capability_digest: Sha256Digest;
  readonly nonce: string;
  readonly subject: string;
  readonly actor_principal: string;
  readonly effect_namespace_id: string;
  readonly account_lane_id: string;
  readonly capacity_pool_id: string;
  readonly serialization_key_digest: Sha256Digest;
  readonly resource_lease_id: string;
  readonly operation_id: string;
  readonly operation_execution_epoch: string;
  readonly sender_key_thumbprint: Sha256Digest;
  readonly channel_binding_digest: Sha256Digest;
  readonly canonical_request_digest: Sha256Digest;
  readonly online_receipt_digest: Sha256Digest;
  readonly model_call_anchor_digest: Sha256Digest;
  readonly max_uses: "1";
  readonly prior_use_count: "0";
  readonly next_use_count: "1";
  readonly use_ordinal: "1";
  readonly use_id: Sha256Digest;
  readonly committed_at: string;
  readonly expires_at: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string;
  readonly recovery_frontier_hash: Sha256Digest;
  readonly signature: string;
}

export interface CapabilityUseTombstoneV1 {
  readonly schema_version: "accounts.capability-use-tombstone.v1";
  readonly schema_digest: typeof CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST;
  readonly record_kind: "CONSUMED";
  readonly consume_request_id: string;
  readonly idempotency_key_digest: Sha256Digest;
  readonly effect_namespace_id: string;
  readonly serialization_key_digest: Sha256Digest;
  readonly capability_id: string;
  readonly capability_digest: Sha256Digest;
  readonly nonce: string;
  readonly online_receipt_digest: Sha256Digest;
  readonly model_call_anchor_digest: Sha256Digest;
  readonly use_id: Sha256Digest;
  readonly consume_request_jcs_sha256: Sha256Digest;
  readonly consume_request_jcs_base64url: string;
  readonly consume_receipt_digest: Sha256Digest;
  readonly consume_receipt_jcs_base64url: string;
  readonly committed_at: string;
  readonly consume_receipt_expires_at: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: string;
  readonly recovery_frontier_hash: Sha256Digest;
  readonly signer_ref: string;
  readonly signer_incarnation: string;
  readonly key_id: string;
  readonly audience: string;
  readonly signature: string;
}

export type AccountsCapabilityUseOnlineTrust = Omit<
  AccountsEvidenceTrustV1,
  | "now"
  | "clock"
  | "expectedEffectNamespaceId"
  | "expectedSlotEligibility"
  | "previousSlotEligibility"
> & {
  readonly expectedEffectNamespaceId: string;
};

export interface AccountsCapabilityUseConsumeInput {
  readonly consumeRequestBytes: Uint8Array;
  /** Derived from the authenticated channel, never from caller JSON. */
  readonly authenticatedChannelBindingDigest: Sha256Digest;
  readonly expectedSlotEligibility: SlotEligibilityPositiveV1;
  readonly onlineReceiptBytes: Uint8Array;
}

export interface AccountsCapabilityUseConsumeResult {
  readonly receiptBytes: Uint8Array;
  readonly consumeReceiptDigest: Sha256Digest;
  readonly tombstoneBytes: Uint8Array;
  readonly tombstoneDigest: Sha256Digest;
  readonly useId: Sha256Digest;
  readonly replayed: boolean;
  /** True only when this call re-verified the live Infinity binding. */
  readonly bindingCurrent: boolean;
  readonly consumeBound?: VerifiedConsumeBoundOperation;
}

export interface AccountsCapabilityUseConsumerOptions {
  readonly infinity: InfinityAccountsOperationPort;
  readonly receiptSigner: AccountsEvidenceSigner;
  readonly receiptSignerHistory: AccountsEvidenceSignerHistoryV2;
  readonly onlineTrust: AccountsCapabilityUseOnlineTrust;
  readonly expectedSerializationKeyDigest: Sha256Digest;
  readonly clock?: () => Date;
  readonly ledger: AccountsCapabilityUseLedgerOptions;
}

export interface AccountsCapabilityUseLedgerOptions {
  readonly ledgerPath: string;
  readonly mirrorPath: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
}

export interface AccountsCapabilityUseConsumer {
  consume(input: AccountsCapabilityUseConsumeInput): Promise<AccountsCapabilityUseConsumeResult>;
  close(): void;
}

interface ReceiptVerificationContext {
  readonly request: CapabilityUseConsumeRequestV1;
  readonly online: AllowedOnlineGenerationCheckReceiptV1;
  readonly signerHistory: AccountsEvidenceSignerHistoryV2;
  readonly now: Date;
  readonly allowedClockSkewMs: number;
  readonly catalogIncarnation: string;
}

export interface CapabilityUseTombstoneVerificationContext {
  readonly consumeRequestBytes: Uint8Array;
  readonly consumeReceiptBytes: Uint8Array;
  readonly signerHistory: AccountsEvidenceSignerHistoryV2;
  readonly now: Date;
}

export function parseCapabilityUseConsumeRequestV1(
  source: Uint8Array,
): CapabilityUseConsumeRequestV1 {
  const wire = parseCanonicalWireBytes(
    copyBytes(source, "consume request"),
    "capability-use consume request",
  );
  requiredKeys(
    wire,
    CAPABILITY_USE_CONSUME_REQUEST_DESCRIPTOR.fields,
    "capability-use consume request",
  );
  invariant(
    wire.schema_version === CAPABILITY_USE_CONSUME_REQUEST_DESCRIPTOR.schema_version &&
      wire.schema_digest === CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST,
    "capability-use consume request descriptor mismatch",
  );
  for (const field of [
    "consume_request_id",
    "account_lane_id",
    "capacity_pool_id",
    "credential_family_id",
    "online_receipt_id",
  ]) {
    uuidV7(wire[field], `capability-use consume request ${field}`);
  }
  for (const field of [
    "nonce",
    "capability_id",
    "subject",
    "actor_principal",
    "effect_namespace_id",
    "capacity_domain_ref",
    "resource_lease_id",
    "resource_id",
    "operation_id",
  ]) {
    nonemptyString(wire[field], `capability-use consume request ${field}`);
  }
  for (const field of [
    "capability_digest",
    "serialization_key_digest",
    "operation_digest",
    "sender_key_thumbprint",
    "channel_binding_digest",
    "canonical_request_digest",
    "provider_destination_policy_digest",
    "online_receipt_digest",
    "model_call_anchor_digest",
    "idempotency_key_digest",
  ]) {
    sha256Digest(wire[field], `capability-use consume request ${field}`);
  }
  positiveCounter(
    wire.resource_lifecycle_generation,
    "capability-use consume request resource_lifecycle_generation",
  );
  positiveCounter(
    wire.operation_execution_epoch,
    "capability-use consume request operation_execution_epoch",
  );
  invariant(
    wire.expected_use_count === "0" && wire.max_uses === "1",
    "capability-use consume request use literals mismatch",
  );
  timestampMs(wire.not_after, "capability-use consume request not_after");
  return Object.freeze(wire) as unknown as CapabilityUseConsumeRequestV1;
}

export function parseCapabilityUseConsumeReceiptV1(
  source: Uint8Array,
  context: ReceiptVerificationContext,
): CapabilityUseConsumeReceiptV1 {
  const wire = parseCapabilityUseConsumeReceiptWire(source);
  assertReceiptBindings(wire, context);
  assertReceiptFreshness(wire, context);
  verifyReceiptSignature(wire, context);
  return Object.freeze(wire) as unknown as CapabilityUseConsumeReceiptV1;
}

function parseCapabilityUseConsumeReceiptWire(source: Uint8Array): Record<string, unknown> {
  const wire = parseCanonicalWireBytes(
    copyBytes(source, "consume receipt"),
    "capability-use consume receipt",
  );
  requiredKeys(
    wire,
    CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR.fields,
    "capability-use consume receipt",
  );
  invariant(
    wire.schema_version === CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR.schema_version &&
      wire.schema_digest === CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    "capability-use consume receipt descriptor mismatch",
  );
  for (const field of [
    "consume_request_id",
    "consume_receipt_id",
    "account_lane_id",
    "capacity_pool_id",
  ]) {
    uuidV7(wire[field], `capability-use consume receipt ${field}`);
  }
  for (const field of [
    "issuer",
    "issuer_incarnation",
    "key_id",
    "audience",
    "capability_id",
    "nonce",
    "subject",
    "actor_principal",
    "effect_namespace_id",
    "resource_lease_id",
    "operation_id",
    "catalog_incarnation",
  ]) {
    nonemptyString(wire[field], `capability-use consume receipt ${field}`);
  }
  for (const field of [
    "capability_digest",
    "serialization_key_digest",
    "sender_key_thumbprint",
    "channel_binding_digest",
    "canonical_request_digest",
    "online_receipt_digest",
    "model_call_anchor_digest",
    "use_id",
    "recovery_frontier_hash",
  ]) {
    sha256Digest(wire[field], `capability-use consume receipt ${field}`);
  }
  positiveCounter(
    wire.operation_execution_epoch,
    "capability-use consume receipt operation_execution_epoch",
  );
  counter(
    wire.recovery_frontier_sequence,
    "capability-use consume receipt recovery_frontier_sequence",
  );
  invariant(
    wire.max_uses === "1" &&
      wire.prior_use_count === "0" &&
      wire.next_use_count === "1" &&
      wire.use_ordinal === "1",
    "capability-use consume receipt use literals mismatch",
  );
  assertSignatureShape(wire.signature);
  timestampMs(wire.committed_at, "capability-use consume receipt committed_at");
  timestampMs(wire.expires_at, "capability-use consume receipt expires_at");
  return wire;
}

export function parseCapabilityUseTombstoneV1(
  source: Uint8Array,
  context: CapabilityUseTombstoneVerificationContext,
): CapabilityUseTombstoneV1 {
  const contextRecord = exactTombstoneContext(context);
  const requestBytes = copyBytes(contextRecord.consumeRequestBytes, "tombstone consume request");
  const receiptBytes = copyBytes(contextRecord.consumeReceiptBytes, "tombstone consume receipt");
  const request = parseCapabilityUseConsumeRequestV1(requestBytes);
  const receipt = parseCapabilityUseConsumeReceiptWire(receiptBytes);
  const wire = parseCanonicalWireBytes(
    copyBytes(source, "capability-use tombstone"),
    "capability-use tombstone",
  );
  requiredKeys(wire, CAPABILITY_USE_TOMBSTONE_DESCRIPTOR.fields, "capability-use tombstone");
  invariant(
    wire.schema_version === CAPABILITY_USE_TOMBSTONE_DESCRIPTOR.schema_version &&
      wire.schema_digest === CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST &&
      wire.record_kind === CAPABILITY_USE_TOMBSTONE_DESCRIPTOR.record_kind,
    "capability-use tombstone descriptor mismatch",
  );
  for (const field of [
    "consume_request_id",
    "effect_namespace_id",
    "capability_id",
    "nonce",
    "catalog_incarnation",
    "signer_ref",
    "signer_incarnation",
    "key_id",
    "audience",
  ]) {
    nonemptyString(wire[field], `capability-use tombstone ${field}`);
  }
  for (const field of [
    "idempotency_key_digest",
    "serialization_key_digest",
    "capability_digest",
    "online_receipt_digest",
    "model_call_anchor_digest",
    "use_id",
    "consume_request_jcs_sha256",
    "consume_receipt_digest",
    "recovery_frontier_hash",
  ]) {
    sha256Digest(wire[field], `capability-use tombstone ${field}`);
  }
  counter(
    wire.recovery_frontier_sequence,
    "capability-use tombstone recovery_frontier_sequence",
  );
  timestampMs(wire.committed_at, "capability-use tombstone committed_at");
  timestampMs(
    wire.consume_receipt_expires_at,
    "capability-use tombstone consume_receipt_expires_at",
  );
  assertSignatureShape(wire.signature);
  assertEmbeddedConsumeReceipt(request, receipt, contextRecord.signerHistory, contextRecord.now);
  assertTombstoneBindings(wire, request, requestBytes, receipt, receiptBytes);
  verifyTombstoneSignature(wire, contextRecord.signerHistory, contextRecord.now);
  return Object.freeze(wire) as unknown as CapabilityUseTombstoneV1;
}

export function createAccountsCapabilityUseConsumer(
  options: AccountsCapabilityUseConsumerOptions,
): AccountsCapabilityUseConsumer {
  const infinity = validateInfinityPort(options.infinity);
  const clock = options.clock ?? (() => new Date());
  const initialNow = trustedNow(clock);
  const signerHistory = cloneWire(
    options.receiptSignerHistory,
    "capability-use receipt signer history",
  ) as unknown as AccountsEvidenceSignerHistoryV2;
  const receiptSigner = validateReceiptSigner(
    options.receiptSigner,
    signerHistory,
    initialNow,
  );
  const onlineTrustConfiguration = snapshotOnlineTrust(options.onlineTrust);
  normalizeTrust(onlineTrustAt(onlineTrustConfiguration, initialNow));
  validateSignerHistory(onlineTrustConfiguration.signerHistory, initialNow.getTime());
  const expectedSerializationKeyDigest = sha256Digest(
    options.expectedSerializationKeyDigest,
    "capability-use expected serialization key digest",
  ) as Sha256Digest;
  const ledgerOptions = Object.freeze({
    ledgerPath: options.ledger.ledgerPath,
    mirrorPath: options.ledger.mirrorPath,
    catalogIncarnation: options.ledger.catalogIncarnation,
    signingKey: Uint8Array.from(options.ledger.signingKey),
  });
  const ledger = new NonRewindableCapabilityUseLedger(ledgerOptions);
  let closed = false;

  return Object.freeze({
    consume: async (input: AccountsCapabilityUseConsumeInput) => {
      if (closed) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capability-use consumer closed");
      }
      const inputRecord = exactInput(input);
      const requestBytes = copyBytes(inputRecord.consumeRequestBytes, "consume request");
      const request = parseCapabilityUseConsumeRequestV1(requestBytes);
      invariant(
        request.effect_namespace_id === onlineTrustConfiguration.expectedEffectNamespaceId &&
          request.serialization_key_digest === expectedSerializationKeyDigest,
        "Capability-use request differs from factory-pinned namespace or serialization identity",
      );
      const authenticatedChannelBindingDigest = sha256Digest(
        inputRecord.authenticatedChannelBindingDigest,
        "authenticated channel binding",
      ) as Sha256Digest;
      if (authenticatedChannelBindingDigest !== request.channel_binding_digest) {
        throw new AccountsError("FORBIDDEN", "Authenticated channel binding differs");
      }

      const replay = exactReplay(ledger, request, requestBytes);
      if (replay !== undefined) return consumeResult(replay, true);
      assertNoExistingConflict(ledger, request);

      const now = trustedNow(clock);
      validateReceiptSigner(receiptSigner, signerHistory, now);
      const onlineTrust = onlineTrustAt(onlineTrustConfiguration, now);
      const slotBytes = encodeSlotEligibilityV1(inputRecord.expectedSlotEligibility);
      const verifiedSlot = parseSlotEligibilityV1(
        slotBytes,
        onlineTrust,
      );
      invariant(verifiedSlot.eligible, "capability use requires positive SlotEligibility");
      const onlineReceiptBytes = copyBytes(inputRecord.onlineReceiptBytes, "online receipt");
      const online = requireAllowedOnlineGenerationCheckReceiptV1(
        parseOnlineGenerationCheckReceiptV1(onlineReceiptBytes, {
          ...onlineTrust,
          expectedSlotEligibility: verifiedSlot,
        }),
      );
      assertRequestBindings(
        request,
        online,
        onlineReceiptBytes,
        authenticatedChannelBindingDigest,
      );
      const operationBinding = operationBindingFromRequest(request);
      const prepared = await readPrepared(infinity, operationBinding);
      const commitNow = trustedNow(clock);
      invariant(
        commitNow.getTime() >= now.getTime(),
        "Trusted capability-use clock moved backwards during consume",
      );
      validateReceiptSigner(receiptSigner, signerHistory, commitNow);
      const commitOnlineTrust = onlineTrustAt(onlineTrustConfiguration, commitNow);
      const commitSlot = parseSlotEligibilityV1(slotBytes, commitOnlineTrust);
      invariant(commitSlot.eligible, "capability use requires positive SlotEligibility at commit");
      const commitOnline = requireAllowedOnlineGenerationCheckReceiptV1(
        parseOnlineGenerationCheckReceiptV1(onlineReceiptBytes, {
          ...commitOnlineTrust,
          expectedSlotEligibility: commitSlot,
        }),
      );
      assertRequestBindings(
        request,
        commitOnline,
        onlineReceiptBytes,
        authenticatedChannelBindingDigest,
      );
      const receiptBytes = signConsumeReceipt(
        request,
        commitOnline,
        receiptSigner,
        signerHistory,
        commitNow,
        ledgerOptions.catalogIncarnation,
        commitOnlineTrust.allowedClockSkewMs ?? 5_000,
      );
      const receipt = parseCapabilityUseConsumeReceiptV1(receiptBytes, {
        request,
        online: commitOnline,
        signerHistory,
        now: commitNow,
        allowedClockSkewMs: commitOnlineTrust.allowedClockSkewMs ?? 5_000,
        catalogIncarnation: ledgerOptions.catalogIncarnation,
      });
      const tombstoneBytes = signCapabilityUseTombstone(
        request,
        requestBytes,
        receipt,
        receiptBytes,
        receiptSigner,
        signerHistory,
        commitNow,
      );
      parseCapabilityUseTombstoneV1(tombstoneBytes, {
        consumeRequestBytes: requestBytes,
        consumeReceiptBytes: receiptBytes,
        signerHistory,
        now: commitNow,
      });
      const verified = await verifyCapabilityUseEvidenceWithTombstone(
        { consumeRequestBytes: requestBytes, consumeReceiptBytes: receiptBytes, tombstoneBytes },
        {
          verify: async () => ({
            consumeRequestId: request.consume_request_id,
            idempotencyKeyDigest: request.idempotency_key_digest,
            effectNamespaceId: request.effect_namespace_id,
            serializationKeyDigest: request.serialization_key_digest,
            capabilityId: request.capability_id,
            capabilityDigest: request.capability_digest,
            nonce: request.nonce,
            onlineReceiptDigest: request.online_receipt_digest,
            modelCallAnchorDigest: request.model_call_anchor_digest,
            useId: receipt.use_id,
            committedAt: receipt.committed_at,
            consumeReceiptExpiresAt: receipt.expires_at,
            catalogIncarnation: receipt.catalog_incarnation,
            recoveryFrontierSequence: parseCounter(receipt.recovery_frontier_sequence),
            recoveryFrontierHash: receipt.recovery_frontier_hash,
          }),
        },
      );
      const currentPrepared = await assertPreparedCurrent(infinity, prepared);
      const finalNow = trustedNow(clock);
      invariant(
        finalNow.getTime() >= commitNow.getTime(),
        "Trusted capability-use clock moved backwards before durable append",
      );
      validateReceiptSigner(receiptSigner, signerHistory, finalNow);
      const finalOnlineTrust = onlineTrustAt(onlineTrustConfiguration, finalNow);
      const finalSlot = parseSlotEligibilityV1(slotBytes, finalOnlineTrust);
      invariant(finalSlot.eligible, "capability use requires positive SlotEligibility at append");
      const finalOnline = requireAllowedOnlineGenerationCheckReceiptV1(
        parseOnlineGenerationCheckReceiptV1(onlineReceiptBytes, {
          ...finalOnlineTrust,
          expectedSlotEligibility: finalSlot,
        }),
      );
      assertRequestBindings(
        request,
        finalOnline,
        onlineReceiptBytes,
        authenticatedChannelBindingDigest,
      );
      parseCapabilityUseConsumeReceiptV1(receiptBytes, {
        request,
        online: finalOnline,
        signerHistory,
        now: finalNow,
        allowedClockSkewMs: finalOnlineTrust.allowedClockSkewMs ?? 5_000,
        catalogIncarnation: ledgerOptions.catalogIncarnation,
      });
      parseCapabilityUseTombstoneV1(tombstoneBytes, {
        consumeRequestBytes: requestBytes,
        consumeReceiptBytes: receiptBytes,
        signerHistory,
        now: finalNow,
      });

      let appended: CapabilityUseLedgerRecord;
      let replayed = false;
      try {
        const result = ledger.append(verified);
        appended = result.record;
        replayed = result.kind === "REPLAYED";
      } catch (error) {
        if (
          error instanceof AccountsError &&
          (error.code === "IDEMPOTENCY_CONFLICT" || error.code === "CONFLICT")
        ) {
          const raced = exactReplay(ledger, request, requestBytes);
          if (raced !== undefined) {
            appended = raced;
            replayed = true;
          } else {
            throw error;
          }
        } else {
          throw error;
        }
      }

      const consumeBound = await bindAndAssertCurrent(infinity, currentPrepared, appended);
      return consumeResult(appended, replayed, consumeBound);
    },
    close: () => {
      if (closed) return;
      closed = true;
      ledger.close();
    },
  });
}

function exactInput(input: AccountsCapabilityUseConsumeInput): AccountsCapabilityUseConsumeInput {
  const expected = [
    "consumeRequestBytes",
    "authenticatedChannelBindingDigest",
    "expectedSlotEligibility",
    "onlineReceiptBytes",
  ] as const;
  invariant(
    input !== null && typeof input === "object" && !Array.isArray(input),
    "capability-use consume input must be an object",
  );
  invariant(
    Object.getPrototypeOf(input) === Object.prototype || Object.getPrototypeOf(input) === null,
    "capability-use consume input must be a plain object",
  );
  invariant(
    Object.getOwnPropertySymbols(input).length === 0,
    "capability-use consume input cannot contain symbol fields",
  );
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const actual = Object.keys(descriptors).sort();
  invariant(
    actual.length === expected.length &&
      actual.every((key, index) => key === [...expected].sort()[index]),
    "capability-use consume input fields differ",
  );
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of expected) {
    const descriptor = descriptors[key];
    invariant(
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor &&
        descriptor.get === undefined && descriptor.set === undefined,
      `capability-use consume input ${key} must be a data field`,
    );
    result[key] = descriptor.value;
  }
  return result as unknown as AccountsCapabilityUseConsumeInput;
}

function exactTombstoneContext(
  context: CapabilityUseTombstoneVerificationContext,
): CapabilityUseTombstoneVerificationContext {
  const expected = ["consumeRequestBytes", "consumeReceiptBytes", "signerHistory", "now"] as const;
  invariant(
    context !== null && typeof context === "object" && !Array.isArray(context),
    "capability-use tombstone context must be an object",
  );
  invariant(
    Object.getPrototypeOf(context) === Object.prototype || Object.getPrototypeOf(context) === null,
    "capability-use tombstone context must be a plain object",
  );
  invariant(
    Object.getOwnPropertySymbols(context).length === 0,
    "capability-use tombstone context cannot contain symbol fields",
  );
  const descriptors = Object.getOwnPropertyDescriptors(context);
  const actual = Object.keys(descriptors).sort();
  invariant(
    actual.length === expected.length &&
      actual.every((key, index) => key === [...expected].sort()[index]),
    "capability-use tombstone context fields differ",
  );
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of expected) {
    const descriptor = descriptors[key];
    invariant(
      descriptor !== undefined && descriptor.enumerable && "value" in descriptor &&
        descriptor.get === undefined && descriptor.set === undefined,
      `capability-use tombstone context ${key} must be a data field`,
    );
    result[key] = descriptor.value;
  }
  invariant(
    result.now instanceof Date && Number.isFinite(result.now.getTime()),
    "capability-use tombstone context now is invalid",
  );
  return Object.freeze({
    consumeRequestBytes: copyBytes(
      result.consumeRequestBytes,
      "tombstone context consume request",
    ),
    consumeReceiptBytes: copyBytes(
      result.consumeReceiptBytes,
      "tombstone context consume receipt",
    ),
    signerHistory: cloneWire(
      result.signerHistory,
      "capability-use tombstone signer history",
    ) as unknown as AccountsEvidenceSignerHistoryV2,
    now: new Date(result.now.getTime()),
  });
}

function snapshotOnlineTrust(
  source: AccountsCapabilityUseOnlineTrust,
): AccountsCapabilityUseOnlineTrust {
  const wire = cloneWire(source, "capability-use online trust") as unknown as Record<string, unknown>;
  requiredKeys(wire, [
    "signerHistory",
    "expectedEffectNamespaceId",
    ...optionalPresentKeys(wire, [
      "allowedClockSkewMs",
      "slotMaximumLifetimeMs",
      "slotMaximumAgeMs",
      "onlineMaximumLifetimeMs",
      "onlineMaximumAgeMs",
    ]),
  ], "capability-use online trust");
  return Object.freeze(wire) as unknown as AccountsCapabilityUseOnlineTrust;
}

function onlineTrustAt(
  source: AccountsCapabilityUseOnlineTrust,
  now: Date,
): AccountsEvidenceTrustV1 {
  return { ...source, now };
}

function optionalPresentKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
): string[] {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(record)) {
    invariant(
      key === "signerHistory" || key === "expectedEffectNamespaceId" || allowedSet.has(key),
      `capability-use online trust contains unknown field ${key}`,
    );
  }
  return allowed.filter((key) => Object.hasOwn(record, key));
}

function validateReceiptSigner(
  signer: AccountsEvidenceSigner,
  history: AccountsEvidenceSignerHistoryV2,
  now: Date,
): AccountsEvidenceSigner {
  const keys = validateSignerHistory(history, now.getTime());
  invariant(
    signer !== null && typeof signer === "object" &&
      signer.issuer === history.issuer &&
      signer.issuerIncarnation === history.issuer_incarnation &&
      signer.audience === history.audience &&
      signer.keyId === history.current_key_id,
    "capability-use receipt signer identity differs from current history",
  );
  const current = keys.find((key) => key.key_id === history.current_key_id)!;
  const publicKey = signerPublicKey(current.public_key_spki_base64url);
  const challenge = canonicalBytes({
    purpose: "accounts.capability-use-consume-signer-check/v1",
  });
  const signature = signEvidenceBytes(
    { purpose: "accounts.capability-use-consume-signer-check/v1" },
    signer.privateKey,
  );
  invariant(
    ed25519Verify(null, challenge, publicKey, signature),
    "capability-use receipt signer private key differs from current public key",
  );
  return Object.freeze({ ...signer });
}

function assertRequestBindings(
  request: CapabilityUseConsumeRequestV1,
  online: AllowedOnlineGenerationCheckReceiptV1,
  onlineBytes: Uint8Array,
  authenticatedChannelBindingDigest: Sha256Digest,
): void {
  const same = [
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
    "canonical_request_digest",
    "provider_destination_policy_digest",
  ] as const;
  for (const field of same) {
    invariant(request[field] === online[field], `consume request ${field} differs from online receipt`);
  }
  invariant(
    request.channel_binding_digest === authenticatedChannelBindingDigest &&
      request.channel_binding_digest === online.sender_constraint_confirmation,
    "consume request channel binding differs from authenticated online receipt",
  );
  invariant(
    request.online_receipt_id === online.receipt_id &&
      request.online_receipt_digest === digestBytes(onlineBytes),
    "consume request online receipt identity mismatch",
  );
  invariant(
    request.expected_use_count === online.use_count &&
      request.max_uses === online.max_uses &&
      request.not_after === online.expires_at,
    "consume request use/expiry consequence mismatch",
  );
}

function operationBindingFromRequest(
  request: CapabilityUseConsumeRequestV1,
): CapabilityUseOperationBinding {
  return Object.freeze({
    effectNamespaceId: request.effect_namespace_id,
    capabilityId: request.capability_id,
    capabilityDigest: request.capability_digest,
    nonce: request.nonce,
    subject: request.subject,
    actorPrincipal: request.actor_principal,
    accountLaneId: request.account_lane_id,
    capacityPoolId: request.capacity_pool_id,
    capacityDomainRef: request.capacity_domain_ref,
    serializationKeyDigest: request.serialization_key_digest,
    credentialFamilyId: request.credential_family_id,
    resourceLeaseId: request.resource_lease_id,
    resourceId: request.resource_id,
    resourceLifecycleGeneration: request.resource_lifecycle_generation,
    operationId: request.operation_id,
    operationDigest: request.operation_digest,
    operationExecutionEpoch: request.operation_execution_epoch,
    senderKeyThumbprint: request.sender_key_thumbprint,
    channelBindingDigest: request.channel_binding_digest,
    canonicalRequestDigest: request.canonical_request_digest,
    providerDestinationPolicyDigest: request.provider_destination_policy_digest,
    onlineReceiptId: request.online_receipt_id,
    onlineReceiptDigest: request.online_receipt_digest,
    modelCallAnchorDigest: request.model_call_anchor_digest,
  });
}

async function readPrepared(
  infinity: InfinityAccountsOperationPort,
  binding: CapabilityUseOperationBinding,
): Promise<VerifiedPreparedOpenOperation> {
  let raw: VerifiedPreparedOpenOperation;
  try {
    raw = await infinity.readPreparedOpenOperation(binding);
  } catch (error) {
    return dependencyFailure(error, "Infinity PREPARED/OPEN reader unavailable");
  }
  return validatePrepared(raw, binding);
}

async function assertPreparedCurrent(
  infinity: InfinityAccountsOperationPort,
  prepared: VerifiedPreparedOpenOperation,
): Promise<VerifiedPreparedOpenOperation> {
  let raw: VerifiedPreparedOpenOperation;
  try {
    raw = await infinity.assertPreparedOpenCurrent({ prepared });
  } catch (error) {
    return dependencyFailure(error, "Infinity PREPARED/OPEN currentness unavailable");
  }
  const current = validatePrepared(raw, prepared.binding);
  invariant(
    canonicalJson(current) === canonicalJson(prepared),
    "Infinity current PREPARED/OPEN evidence differs from original proof",
  );
  return current;
}

function validatePrepared(
  value: VerifiedPreparedOpenOperation,
  expectedBinding: CapabilityUseOperationBinding,
): VerifiedPreparedOpenOperation {
  const wire = cloneWire(value, "Infinity PREPARED/OPEN evidence");
  requiredKeys(wire, [
    "schemaVersion",
    "schemaDigest",
    "recordKind",
    "holdState",
    "binding",
    "preparedAnchorJcsBase64url",
    "preparedAnchorDigest",
    "openHoldReceiptJcsBase64url",
    "openHoldReceiptDigest",
    "holdAuthorityEpoch",
    "holdId",
    "holdGeneration",
    "resourceLeaseFrontierSequence",
    "resourceLeaseFrontierHash",
    "preparedModelEffectFrontierSequence",
    "preparedModelEffectFrontierHash",
    "deliveryFrontierSequence",
    "deliveryFrontierHash",
    "holdModelFrontierDigest",
  ], "Infinity PREPARED/OPEN evidence");
  invariant(
    wire.schemaVersion === "infinity.model-call-prepared-anchor/v1" &&
      wire.schemaDigest === INFINITY_MODEL_CALL_PREPARED_ANCHOR_SCHEMA_DIGEST &&
      wire.recordKind === "PREPARED" && wire.holdState === "OPEN",
    "Infinity PREPARED/OPEN evidence literal mismatch",
  );
  const binding = validateOperationBinding(wire.binding);
  invariant(
    canonicalJson(binding) === canonicalJson(expectedBinding),
    "Infinity PREPARED binding differs from consume request",
  );
  for (const field of [
    "preparedAnchorDigest",
    "openHoldReceiptDigest",
    "resourceLeaseFrontierHash",
    "preparedModelEffectFrontierHash",
    "deliveryFrontierHash",
    "holdModelFrontierDigest",
  ]) {
    sha256Digest(wire[field], `Infinity PREPARED/OPEN ${field}`);
  }
  for (const field of [
    "holdGeneration",
    "resourceLeaseFrontierSequence",
    "preparedModelEffectFrontierSequence",
    "deliveryFrontierSequence",
  ]) {
    counter(wire[field], `Infinity PREPARED/OPEN ${field}`);
  }
  positiveCounter(wire.holdAuthorityEpoch, "Infinity PREPARED/OPEN holdAuthorityEpoch");
  nonemptyString(wire.holdId, "Infinity PREPARED/OPEN holdId");
  const anchorBytes = canonicalBase64urlBytes(
    wire.preparedAnchorJcsBase64url,
    "Infinity PREPARED anchor bytes",
  );
  const holdBytes = canonicalBase64urlBytes(
    wire.openHoldReceiptJcsBase64url,
    "Infinity OPEN hold bytes",
  );
  parseCanonicalWireBytes(anchorBytes, "Infinity PREPARED anchor bytes");
  parseCanonicalWireBytes(holdBytes, "Infinity OPEN hold bytes");
  invariant(
    digestBytes(anchorBytes) === wire.preparedAnchorDigest &&
      digestBytes(holdBytes) === wire.openHoldReceiptDigest &&
      wire.preparedAnchorDigest === expectedBinding.modelCallAnchorDigest,
    "Infinity PREPARED/OPEN evidence digest mismatch",
  );
  return Object.freeze(wire) as unknown as VerifiedPreparedOpenOperation;
}

function validateOperationBinding(value: unknown): CapabilityUseOperationBinding {
  const wire = cloneWire(value, "Infinity operation binding");
  const fields = [
    "effectNamespaceId",
    "capabilityId",
    "capabilityDigest",
    "nonce",
    "subject",
    "actorPrincipal",
    "accountLaneId",
    "capacityPoolId",
    "capacityDomainRef",
    "serializationKeyDigest",
    "credentialFamilyId",
    "resourceLeaseId",
    "resourceId",
    "resourceLifecycleGeneration",
    "operationId",
    "operationDigest",
    "operationExecutionEpoch",
    "senderKeyThumbprint",
    "channelBindingDigest",
    "canonicalRequestDigest",
    "providerDestinationPolicyDigest",
    "onlineReceiptId",
    "onlineReceiptDigest",
    "modelCallAnchorDigest",
  ] as const;
  requiredKeys(wire, fields, "Infinity operation binding");
  for (const field of fields) nonemptyString(wire[field], `Infinity operation binding ${field}`);
  for (const field of [
    "capabilityDigest",
    "serializationKeyDigest",
    "operationDigest",
    "senderKeyThumbprint",
    "channelBindingDigest",
    "canonicalRequestDigest",
    "providerDestinationPolicyDigest",
    "onlineReceiptDigest",
    "modelCallAnchorDigest",
  ]) {
    sha256Digest(wire[field], `Infinity operation binding ${field}`);
  }
  positiveCounter(
    wire.resourceLifecycleGeneration,
    "Infinity operation binding resourceLifecycleGeneration",
  );
  positiveCounter(wire.operationExecutionEpoch, "Infinity operation binding operationExecutionEpoch");
  return Object.freeze(wire) as unknown as CapabilityUseOperationBinding;
}

function signConsumeReceipt(
  request: CapabilityUseConsumeRequestV1,
  online: AllowedOnlineGenerationCheckReceiptV1,
  signer: AccountsEvidenceSigner,
  signerHistory: AccountsEvidenceSignerHistoryV2,
  now: Date,
  catalogIncarnation: string,
  allowedClockSkewMs: number,
): Uint8Array {
  const nowMs = now.getTime();
  const expiresAt = Math.min(
    Date.parse(request.not_after),
    nowMs + MAX_CONSUME_RECEIPT_LIFETIME_MS,
  );
  invariant(expiresAt > nowMs, "capability-use consume receipt would already be expired");
  const unsigned = {
    schema_version: CAPABILITY_USE_CONSUME_RECEIPT_DESCRIPTOR.schema_version,
    schema_digest: CAPABILITY_USE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    consume_request_id: request.consume_request_id,
    consume_receipt_id: generateUuidV7(nowMs),
    issuer: signerHistory.issuer,
    issuer_incarnation: signerHistory.issuer_incarnation,
    key_id: signerHistory.current_key_id,
    audience: signerHistory.audience,
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
    use_id: capabilityUseId(request),
    committed_at: now.toISOString(),
    expires_at: new Date(expiresAt).toISOString(),
    catalog_incarnation: catalogIncarnation,
    recovery_frontier_sequence: online.recovery_frontier_sequence,
    recovery_frontier_hash: online.recovery_frontier_hash,
  } as const;
  const signature = signEvidenceBytes(unsigned, signer.privateKey);
  const signed = canonicalBytes({
    ...unsigned,
    signature: Buffer.from(signature).toString("base64url"),
  });
  parseCapabilityUseConsumeReceiptV1(signed, {
    request,
    online,
    signerHistory,
    now,
    allowedClockSkewMs,
    catalogIncarnation,
  });
  return signed;
}

function signCapabilityUseTombstone(
  request: CapabilityUseConsumeRequestV1,
  requestBytes: Uint8Array,
  receipt: CapabilityUseConsumeReceiptV1,
  receiptBytes: Uint8Array,
  signer: AccountsEvidenceSigner,
  signerHistory: AccountsEvidenceSignerHistoryV2,
  now: Date,
): Uint8Array {
  validateReceiptSigner(signer, signerHistory, now);
  const unsigned = {
    schema_version: CAPABILITY_USE_TOMBSTONE_DESCRIPTOR.schema_version,
    schema_digest: CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST,
    record_kind: CAPABILITY_USE_TOMBSTONE_DESCRIPTOR.record_kind,
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
    consume_request_jcs_sha256: digestBytes(requestBytes),
    consume_request_jcs_base64url: Buffer.from(requestBytes).toString("base64url"),
    consume_receipt_digest: digestBytes(receiptBytes),
    consume_receipt_jcs_base64url: Buffer.from(receiptBytes).toString("base64url"),
    committed_at: receipt.committed_at,
    consume_receipt_expires_at: receipt.expires_at,
    catalog_incarnation: receipt.catalog_incarnation,
    recovery_frontier_sequence: receipt.recovery_frontier_sequence,
    recovery_frontier_hash: receipt.recovery_frontier_hash,
    signer_ref: signerHistory.issuer,
    signer_incarnation: signerHistory.issuer_incarnation,
    key_id: signerHistory.current_key_id,
    audience: signerHistory.audience,
  } as const;
  const signature = signEvidenceBytes(unsigned, signer.privateKey);
  return canonicalBytes({
    ...unsigned,
    signature: Buffer.from(signature).toString("base64url"),
  });
}

function assertTombstoneBindings(
  tombstone: Record<string, unknown>,
  request: CapabilityUseConsumeRequestV1,
  requestBytes: Uint8Array,
  receipt: Record<string, unknown>,
  receiptBytes: Uint8Array,
): void {
  for (const field of [
    "consume_request_id",
    "idempotency_key_digest",
    "effect_namespace_id",
    "serialization_key_digest",
    "capability_id",
    "capability_digest",
    "nonce",
    "online_receipt_digest",
    "model_call_anchor_digest",
  ] as const) {
    invariant(
      tombstone[field] === request[field],
      `capability-use tombstone ${field} differs from request`,
    );
  }
  invariant(
    tombstone.consume_request_jcs_sha256 === digestBytes(requestBytes) &&
      tombstone.consume_request_jcs_base64url === Buffer.from(requestBytes).toString("base64url"),
    "capability-use tombstone request bytes mismatch",
  );
  invariant(
    tombstone.consume_receipt_digest === digestBytes(receiptBytes) &&
      tombstone.consume_receipt_jcs_base64url === Buffer.from(receiptBytes).toString("base64url"),
    "capability-use tombstone receipt bytes mismatch",
  );
  const receiptBindings = {
    use_id: "use_id",
    committed_at: "committed_at",
    consume_receipt_expires_at: "expires_at",
    catalog_incarnation: "catalog_incarnation",
    recovery_frontier_sequence: "recovery_frontier_sequence",
    recovery_frontier_hash: "recovery_frontier_hash",
  } as const;
  for (const [tombstoneField, receiptField] of Object.entries(receiptBindings)) {
    invariant(
      tombstone[tombstoneField] === receipt[receiptField],
      `capability-use tombstone ${tombstoneField} differs from receipt`,
    );
  }
}

function assertEmbeddedConsumeReceipt(
  request: CapabilityUseConsumeRequestV1,
  receipt: Record<string, unknown>,
  signerHistory: AccountsEvidenceSignerHistoryV2,
  now: Date,
): void {
  for (const field of [
    "consume_request_id",
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
  ] as const) {
    invariant(
      receipt[field] === request[field],
      `embedded consume receipt ${field} differs from request`,
    );
  }
  invariant(
    receipt.use_id === capabilityUseId(request),
    "embedded consume receipt use_id consequence mismatch",
  );
  const committedAt = timestampMs(
    receipt.committed_at,
    "embedded consume receipt committed_at",
  );
  const expiresAt = timestampMs(
    receipt.expires_at,
    "embedded consume receipt expires_at",
  );
  invariant(
    committedAt <= now.getTime() + ACCOUNTS_V10_MAX_CLOCK_SKEW_MS &&
      committedAt < expiresAt &&
      expiresAt <= timestampMs(request.not_after, "consume request not_after") &&
      expiresAt - committedAt <= MAX_CONSUME_RECEIPT_LIFETIME_MS,
    "embedded consume receipt freshness mismatch",
  );

  const keys = validateSignerHistory(signerHistory, now.getTime());
  invariant(
    receipt.issuer === signerHistory.issuer &&
      receipt.issuer_incarnation === signerHistory.issuer_incarnation &&
      receipt.audience === signerHistory.audience &&
      receipt.key_id === signerHistory.current_key_id,
    "embedded consume receipt signer identity mismatch",
  );
  const current = keys.find((candidate) => candidate.key_id === signerHistory.current_key_id)!;
  const signature = canonicalBase64urlBytes(
    receipt.signature,
    "embedded consume receipt signature",
    64,
  );
  const unsigned = { ...receipt };
  delete unsigned.signature;
  invariant(
    ed25519Verify(
      null,
      canonicalBytes(unsigned),
      signerPublicKey(current.public_key_spki_base64url),
      signature,
    ),
    "embedded consume receipt Ed25519 signature mismatch",
  );
}

function verifyTombstoneSignature(
  tombstone: Record<string, unknown>,
  signerHistory: AccountsEvidenceSignerHistoryV2,
  now: Date,
): void {
  invariant(now instanceof Date && Number.isFinite(now.getTime()), "tombstone trust time is invalid");
  const keys = validateSignerHistory(signerHistory, now.getTime());
  invariant(
    tombstone.signer_ref === signerHistory.issuer &&
      tombstone.signer_incarnation === signerHistory.issuer_incarnation &&
      tombstone.audience === signerHistory.audience &&
      tombstone.key_id === signerHistory.current_key_id,
    "capability-use tombstone signer identity mismatch",
  );
  const current = keys.find((candidate) => candidate.key_id === signerHistory.current_key_id)!;
  const committedAt = timestampMs(tombstone.committed_at, "tombstone committed_at");
  invariant(
    timestampMs(current.activated_at, "tombstone signer activated_at") <= committedAt &&
      committedAt < timestampMs(current.expires_at, "tombstone signer expires_at") &&
      current.retired_at === null && current.revoked_at === null,
    "capability-use tombstone signer was not current at commit",
  );
  const signature = canonicalBase64urlBytes(tombstone.signature, "tombstone signature", 64);
  const unsigned = { ...tombstone };
  delete unsigned.signature;
  invariant(
    ed25519Verify(
      null,
      canonicalBytes(unsigned),
      signerPublicKey(current.public_key_spki_base64url),
      signature,
    ),
    "capability-use tombstone Ed25519 signature mismatch",
  );
}

function assertReceiptBindings(
  receipt: Record<string, unknown>,
  context: ReceiptVerificationContext,
): void {
  const request = context.request;
  const same = [
    "consume_request_id",
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
  ] as const;
  for (const field of same) {
    invariant(receipt[field] === request[field], `consume receipt ${field} differs from request`);
  }
  invariant(receipt.use_id === capabilityUseId(request), "consume receipt use_id consequence mismatch");
  invariant(
    receipt.catalog_incarnation === context.catalogIncarnation &&
      receipt.catalog_incarnation === context.online.catalog_incarnation,
    "consume receipt catalog incarnation mismatch",
  );
  invariant(
    receipt.recovery_frontier_sequence === context.online.recovery_frontier_sequence &&
      receipt.recovery_frontier_hash === context.online.recovery_frontier_hash,
    "consume receipt recovery frontier mismatch",
  );
}

function assertReceiptFreshness(
  receipt: Record<string, unknown>,
  context: ReceiptVerificationContext,
): void {
  const committedAt = timestampMs(receipt.committed_at, "consume receipt committed_at");
  const expiresAt = timestampMs(receipt.expires_at, "consume receipt expires_at");
  const nowMs = context.now.getTime();
  invariant(
    committedAt >= Date.parse(context.online.issued_at) &&
      committedAt <= nowMs + context.allowedClockSkewMs &&
      committedAt < expiresAt &&
      nowMs < expiresAt &&
      expiresAt <= Date.parse(context.request.not_after) &&
      expiresAt - committedAt <= MAX_CONSUME_RECEIPT_LIFETIME_MS,
    "capability-use consume receipt freshness mismatch",
  );
}

function verifyReceiptSignature(
  receipt: Record<string, unknown>,
  context: ReceiptVerificationContext,
): void {
  const keys = validateSignerHistory(context.signerHistory, context.now.getTime());
  invariant(
    receipt.issuer === context.signerHistory.issuer &&
      receipt.issuer_incarnation === context.signerHistory.issuer_incarnation &&
      receipt.audience === context.signerHistory.audience &&
      receipt.key_id === context.signerHistory.current_key_id,
    "capability-use consume receipt signer identity mismatch",
  );
  const current = keys.find((key) => key.key_id === context.signerHistory.current_key_id)!;
  const committedAt = timestampMs(receipt.committed_at, "consume receipt committed_at");
  invariant(
    timestampMs(current.activated_at, "consume signer activated_at") <= committedAt &&
      committedAt < timestampMs(current.expires_at, "consume signer expires_at") &&
      current.retired_at === null && current.revoked_at === null,
    "capability-use consume receipt signer was not current at commit",
  );
  const signature = canonicalBase64urlBytes(receipt.signature, "consume receipt signature", 64);
  const unsigned = { ...receipt };
  delete unsigned.signature;
  invariant(
    ed25519Verify(
      null,
      canonicalBytes(unsigned),
      signerPublicKey(current.public_key_spki_base64url),
      signature,
    ),
    "capability-use consume receipt Ed25519 signature mismatch",
  );
}

function capabilityUseId(request: CapabilityUseConsumeRequestV1): Sha256Digest {
  return digestObject({
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
}

async function bindAndAssertCurrent(
  infinity: InfinityAccountsOperationPort,
  prepared: VerifiedPreparedOpenOperation,
  record: CapabilityUseLedgerRecord,
): Promise<VerifiedConsumeBoundOperation> {
  let rawBound: VerifiedConsumeBoundOperation;
  try {
    rawBound = await infinity.bindCapabilityUse({
      prepared,
      consumeReceiptDigest: record.consumeReceiptDigest,
      useId: record.useId,
    });
  } catch (error) {
    return dependencyFailure(error, "Infinity consume binding unavailable");
  }
  const bound = validateConsumeBound(
    rawBound,
    prepared,
    record.consumeReceiptDigest,
    record.useId,
  );
  let rawCurrent: VerifiedConsumeBoundOperation;
  try {
    rawCurrent = await infinity.assertConsumeBoundCurrent({ consumeBound: bound });
  } catch (error) {
    return dependencyFailure(error, "Infinity consume binding currentness unavailable");
  }
  const current = validateConsumeBound(
    rawCurrent,
    prepared,
    record.consumeReceiptDigest,
    record.useId,
  );
  invariant(
    canonicalJson(current) === canonicalJson(bound),
    "Infinity current consume binding differs from appended binding",
  );
  return current;
}

function validateConsumeBound(
  value: VerifiedConsumeBoundOperation,
  expectedPrepared: VerifiedPreparedOpenOperation,
  expectedReceiptDigest: Sha256Digest,
  expectedUseId: Sha256Digest,
): VerifiedConsumeBoundOperation {
  const wire = cloneWire(value, "Infinity CONSUME_BOUND evidence");
  requiredKeys(wire, [
    "schemaVersion",
    "schemaDigest",
    "recordKind",
    "holdState",
    "prepared",
    "consumeReceiptDigest",
    "useId",
    "consumeBindingJcsBase64url",
    "consumeBindingDigest",
    "boundModelEffectFrontierSequence",
    "boundModelEffectFrontierHash",
  ], "Infinity CONSUME_BOUND evidence");
  invariant(
    wire.schemaVersion === "infinity.model-call-consume-binding/v1" &&
      wire.schemaDigest === INFINITY_MODEL_CALL_CONSUME_BINDING_SCHEMA_DIGEST &&
      wire.recordKind === "CONSUME_BOUND" && wire.holdState === "OPEN",
    "Infinity CONSUME_BOUND evidence literal mismatch",
  );
  const prepared = validatePrepared(
    wire.prepared as VerifiedPreparedOpenOperation,
    expectedPrepared.binding,
  );
  invariant(
    canonicalJson(prepared) === canonicalJson(expectedPrepared) &&
      wire.consumeReceiptDigest === expectedReceiptDigest && wire.useId === expectedUseId,
    "Infinity CONSUME_BOUND evidence binding mismatch",
  );
  sha256Digest(wire.consumeReceiptDigest, "Infinity CONSUME_BOUND consumeReceiptDigest");
  sha256Digest(wire.useId, "Infinity CONSUME_BOUND useId");
  sha256Digest(wire.consumeBindingDigest, "Infinity CONSUME_BOUND consumeBindingDigest");
  sha256Digest(
    wire.boundModelEffectFrontierHash,
    "Infinity CONSUME_BOUND boundModelEffectFrontierHash",
  );
  const boundModelEffectFrontierSequence = counter(
    wire.boundModelEffectFrontierSequence,
    "Infinity CONSUME_BOUND boundModelEffectFrontierSequence",
  );
  invariant(
    BigInt(boundModelEffectFrontierSequence) ===
      BigInt(expectedPrepared.preparedModelEffectFrontierSequence) + 1n,
    "Infinity CONSUME_BOUND model-effect frontier is not contiguous",
  );
  const bindingBytes = canonicalBase64urlBytes(
    wire.consumeBindingJcsBase64url,
    "Infinity CONSUME_BOUND bytes",
  );
  parseCanonicalWireBytes(bindingBytes, "Infinity CONSUME_BOUND bytes");
  invariant(
    digestBytes(bindingBytes) === wire.consumeBindingDigest,
    "Infinity CONSUME_BOUND digest mismatch",
  );
  return Object.freeze({ ...wire, prepared }) as unknown as VerifiedConsumeBoundOperation;
}

function exactReplay(
  ledger: NonRewindableCapabilityUseLedger,
  request: CapabilityUseConsumeRequestV1,
  requestBytes: Uint8Array,
): CapabilityUseLedgerRecord | undefined {
  const byRequest = ledger.lookup({ consumeRequestId: request.consume_request_id });
  if (byRequest !== undefined) {
    if (!equalBytes(byRequest.consumeRequestBytes, requestBytes)) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Consume request replay changed bytes");
    }
    assertExternalTombstonePresent(byRequest);
    return byRequest;
  }
  const byIdempotency = ledger.lookup({ idempotencyKeyDigest: request.idempotency_key_digest });
  if (byIdempotency !== undefined) {
    if (!equalBytes(byIdempotency.consumeRequestBytes, requestBytes)) {
      throw new AccountsError("IDEMPOTENCY_CONFLICT", "Consume idempotency changed bytes");
    }
    assertExternalTombstonePresent(byIdempotency);
    return byIdempotency;
  }
  return undefined;
}

function assertNoExistingConflict(
  ledger: NonRewindableCapabilityUseLedger,
  request: CapabilityUseConsumeRequestV1,
): void {
  if (ledger.lookup({ capabilityId: request.capability_id, nonce: request.nonce }) !== undefined) {
    throw new AccountsError("CONFLICT", "Capability nonce is already consumed");
  }
  if (ledger.lookup({ useId: capabilityUseId(request) }) !== undefined) {
    throw new AccountsError("CONFLICT", "Capability use is already consumed");
  }
}

function consumeResult(
  record: CapabilityUseLedgerRecord,
  replayed: boolean,
  consumeBound?: VerifiedConsumeBoundOperation,
): AccountsCapabilityUseConsumeResult {
  assertExternalTombstonePresent(record);
  return Object.freeze({
    receiptBytes: Uint8Array.from(record.consumeReceiptBytes),
    consumeReceiptDigest: record.consumeReceiptDigest,
    tombstoneBytes: Uint8Array.from(record.tombstoneBytes),
    tombstoneDigest: record.tombstoneDigest,
    useId: record.useId,
    replayed,
    bindingCurrent: consumeBound !== undefined,
    ...(consumeBound === undefined ? {} : { consumeBound }),
  });
}

function assertExternalTombstonePresent(
  record: CapabilityUseLedgerRecord,
): asserts record is CapabilityUseLedgerRecord & {
  readonly tombstoneBytes: Uint8Array;
  readonly tombstoneDigest: Sha256Digest;
} {
  if (record.tombstoneBytes === undefined || record.tombstoneDigest === undefined) {
    throw new AccountsError(
      "RECOVERY_HOLD",
      "Capability-use ledger record lacks the required external tombstone",
    );
  }
}

function validateInfinityPort(value: InfinityAccountsOperationPort): InfinityAccountsOperationPort {
  invariant(
    value !== null && typeof value === "object" &&
      typeof value.readPreparedOpenOperation === "function" &&
      typeof value.assertPreparedOpenCurrent === "function" &&
      typeof value.bindCapabilityUse === "function" &&
      typeof value.assertConsumeBoundCurrent === "function",
    "Infinity Accounts operation port is invalid",
  );
  return value;
}

function trustedNow(clock: () => Date): Date {
  let value: Date;
  try {
    value = clock();
  } catch (error) {
    return dependencyFailure(error, "Trusted capability-use clock unavailable");
  }
  invariant(value instanceof Date && Number.isFinite(value.getTime()), "Trusted clock is invalid");
  return new Date(value.getTime());
}

function copyBytes(value: unknown, label: string): Uint8Array {
  invariant(
    value instanceof Uint8Array && value.byteLength > 0 && value.byteLength <= MAX_EVIDENCE_BYTES,
    `${label} must be bounded nonempty bytes`,
  );
  return Uint8Array.from(value);
}

function canonicalBase64urlBytes(
  value: unknown,
  label: string,
  expectedLength?: number,
): Uint8Array {
  invariant(
    typeof value === "string" && value.length > 0 && value.length <= 2 * MAX_EVIDENCE_BYTES &&
      /^[A-Za-z0-9_-]+$/.test(value),
    `${label} must be bounded unpadded base64url`,
  );
  const decoded = Uint8Array.from(Buffer.from(value, "base64url"));
  invariant(Buffer.from(decoded).toString("base64url") === value, `${label} is not canonical base64url`);
  if (expectedLength !== undefined) invariant(decoded.byteLength === expectedLength, `${label} length mismatch`);
  return decoded;
}

function signerPublicKey(spki: string) {
  const bytes = canonicalBase64urlBytes(spki, "capability-use signer SPKI");
  try {
    const key = createPublicKey({ key: Buffer.from(bytes), format: "der", type: "spki" });
    invariant(key.asymmetricKeyType === "ed25519", "capability-use signer key must be Ed25519");
    return key;
  } catch (error) {
    if (error instanceof AccountsError) throw error;
    throw new AccountsError("VALIDATION_FAILED", "Capability-use signer public key is invalid");
  }
}

function digestBytes(value: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function digestObject(value: unknown): Sha256Digest {
  return digestBytes(canonicalBytes(value));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function dependencyFailure(error: unknown, message: string): never {
  if (error instanceof AccountsError) throw error;
  throw new AccountsError("DEPENDENCY_UNAVAILABLE", message);
}

// Compile-time assertion that corrected identities remain typed as sha256 values.
const _correctedRequestDigest: V10Sha256Digest =
  CAPABILITY_USE_CONSUME_REQUEST_SCHEMA_DIGEST as V10Sha256Digest;
void _correctedRequestDigest;
