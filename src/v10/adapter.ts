import {
  ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1,
  ONLINE_GENERATION_CONTEXT_FIELDS_V1,
  PROVIDER_DESTINATION_POLICY_FIELDS_V1,
} from "./constants";
import {
  assertAllDigestFields,
  assertAllStringFields,
  canonicalDigest,
  cloneWire,
  invariant,
  nonemptyString,
  positiveCounter,
  counter,
  parseCanonicalWireBytes,
  record,
  requiredKeys,
  timestamp,
  uuidV7,
} from "./primitives";
import { parseOnlineGenerationCheckReceiptV1 } from "./online";
import { encodeSlotEligibilityV1, parseSlotEligibilityV1 } from "./slot";
import type {
  AccountsEvidenceTrustV1,
  AccountsOnlineGenerationCheckRequest,
  AccountsOnlineGenerationContextV1,
  AccountsOnlineGenerationSourceRequestV1,
  AccountsSlotEligibilityRequestV1,
  AccountsSlotEligibilityAdapterTrustV1,
  AccountsSlotEligibilityPort,
  AccountsSlotEligibilitySource,
  DeterministicAccountsSlotEligibilitySource,
} from "./types";
import { AccountsError } from "../errors";

function isolatedBytes(value: Uint8Array, label: string): Uint8Array {
  invariant(value instanceof Uint8Array, `${label} source must return Uint8Array`);
  return Uint8Array.from(value);
}

function eligibilityRequest(
  value: AccountsSlotEligibilityRequestV1,
): AccountsSlotEligibilityRequestV1 {
  const request = cloneWire(value, "SlotEligibility adapter request");
  requiredKeys(request, [
    "schema_version",
    "account_lane_id",
    "data_classification",
    "destination_policy_class",
    "model",
    "operation",
  ], "SlotEligibility adapter request");
  invariant(
    request.schema_version === ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1,
    "SlotEligibility request schema/version mismatch",
  );
  uuidV7(request.account_lane_id, "SlotEligibility request account_lane_id");
  for (const field of [
    "data_classification",
    "destination_policy_class",
    "model",
    "operation",
  ]) {
    nonemptyString(request[field], `SlotEligibility request ${field}`);
  }
  return request as unknown as AccountsSlotEligibilityRequestV1;
}

function onlineContext(value: AccountsOnlineGenerationContextV1): AccountsOnlineGenerationContextV1 {
  const context = cloneWire(value, "online-check context");
  requiredKeys(context, ONLINE_GENERATION_CONTEXT_FIELDS_V1, "online-check context");
  assertAllStringFields(
    context,
    ONLINE_GENERATION_CONTEXT_FIELDS_V1,
    new Set(["provider_destination_policy"]),
    "online-check context",
  );
  uuidV7(context.account_lane_id, "online-check context account_lane_id");
  invariant(
    context.authenticated_actor_principal === context.actor_principal,
    "online-check authenticated actor does not match actor_principal",
  );
  invariant(context.max_uses === "1", "online-check context max_uses must be 1");
  invariant(
    context.approval_mode === "NOT_REQUIRED" || context.approval_mode === "REQUIRED",
    "online-check context approval_mode is invalid",
  );
  for (const field of [
    "authority_epoch",
    "route_epoch",
    "lease_epoch",
    "resource_lifecycle_generation",
    "operation_execution_epoch",
  ]) {
    positiveCounter(context[field], `online-check context ${field}`);
  }
  timestamp(context.lease_expires_at, "online-check context lease_expires_at");
  timestamp(
    context.operation_execution_expires_at,
    "online-check context operation_execution_expires_at",
  );
  assertAllDigestFields(context, "online-check context");
  const destination = record(
    context.provider_destination_policy,
    "online-check context provider_destination_policy",
  );
  requiredKeys(
    destination,
    PROVIDER_DESTINATION_POLICY_FIELDS_V1,
    "online-check context provider_destination_policy",
  );
  assertAllStringFields(
    destination,
    PROVIDER_DESTINATION_POLICY_FIELDS_V1,
    new Set(),
    "online-check context provider_destination_policy",
  );
  assertAllDigestFields(destination, "online-check context provider_destination_policy");
  invariant(
    context.provider_destination_policy_digest === canonicalDigest(destination),
    "online-check context provider destination digest mismatch",
  );
  return context as unknown as AccountsOnlineGenerationContextV1;
}

function assertOnlineContextBinding(
  receipt: Readonly<Record<string, unknown>>,
  context: AccountsOnlineGenerationContextV1,
): void {
  for (const field of ONLINE_GENERATION_CONTEXT_FIELDS_V1) {
    if (field === "authenticated_actor_principal") {
      invariant(
        receipt.actor_principal === context.authenticated_actor_principal,
        "online-check authenticated actor binding mismatch",
      );
    } else if (field === "provider_destination_policy") {
      invariant(
        canonicalDigest(receipt.provider_destination_policy) ===
          canonicalDigest(context.provider_destination_policy),
        "online-check provider destination policy binding mismatch",
      );
    } else {
      invariant(receipt[field] === context[field], `online-check ${field} binding mismatch`);
    }
  }
}

export function createDeterministicAccountsSlotEligibilitySource(fixture: {
  readonly slot: Uint8Array;
  readonly online: Uint8Array;
}): DeterministicAccountsSlotEligibilitySource {
  let slot = isolatedBytes(fixture.slot, "deterministic SlotEligibility");
  let online = isolatedBytes(fixture.online, "deterministic online-check");
  let unavailable = false;
  deterministicWire(slot, "deterministic SlotEligibility");
  deterministicWire(online, "deterministic online-check");
  return Object.freeze({
    getSlotEligibility: async (_request: AccountsSlotEligibilityRequestV1) => {
      if (unavailable) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Deterministic source is unavailable");
      }
      return Uint8Array.from(slot);
    },
    checkOnlineGeneration: async (_request: AccountsOnlineGenerationSourceRequestV1) => {
      if (unavailable) {
        throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Deterministic source is unavailable");
      }
      return Uint8Array.from(online);
    },
    advance: (next: { readonly slot: Uint8Array; readonly online: Uint8Array }) => {
      const nextSlot = isolatedBytes(next.slot, "deterministic SlotEligibility");
      const nextOnline = isolatedBytes(next.online, "deterministic online-check");
      assertDeterministicAdvance(slot, nextSlot, "SlotEligibility");
      assertDeterministicAdvance(online, nextOnline, "online-check");
      slot = nextSlot;
      online = nextOnline;
    },
    setUnavailable: (nextUnavailable: boolean) => {
      invariant(typeof nextUnavailable === "boolean", "deterministic availability must be boolean");
      unavailable = nextUnavailable;
    },
  });
}

function deterministicWire(bytes: Uint8Array, label: string): Record<string, unknown> {
  return parseCanonicalWireBytes(bytes, label);
}

function assertDeterministicAdvance(
  currentBytes: Uint8Array,
  nextBytes: Uint8Array,
  label: string,
): void {
  const current = deterministicWire(currentBytes, `current deterministic ${label}`);
  const next = deterministicWire(nextBytes, `next deterministic ${label}`);
  for (const field of [
    "account_lane_id",
    "catalog_incarnation",
    "effect_namespace_id",
  ]) {
    if (Object.hasOwn(current, field) || Object.hasOwn(next, field)) {
      invariant(current[field] === next[field], `deterministic ${label} changed ${field}`);
    }
  }
  const currentFrontier = counter(
    current.recovery_frontier_sequence,
    `current deterministic ${label} recovery_frontier_sequence`,
  );
  const nextFrontier = counter(
    next.recovery_frontier_sequence,
    `next deterministic ${label} recovery_frontier_sequence`,
  );
  invariant(
    BigInt(nextFrontier) >= BigInt(currentFrontier),
    `deterministic ${label} recovery frontier rewound`,
  );
  if (nextFrontier === currentFrontier) {
    invariant(
      next.recovery_frontier_hash === current.recovery_frontier_hash,
      `deterministic ${label} recovery frontier forked`,
    );
  }
  for (const field of [
    "capacity_generation",
    "deny_generation",
    "credential_generation",
  ]) {
    if (Object.hasOwn(current, field) && Object.hasOwn(next, field)) {
      invariant(
        BigInt(counter(next[field], `next deterministic ${label} ${field}`)) >=
          BigInt(counter(current[field], `current deterministic ${label} ${field}`)),
        `deterministic ${label} ${field} rewound`,
      );
    }
  }
}

export function createAccountsSlotEligibilityAdapter(
  source: AccountsSlotEligibilitySource,
  trust: AccountsSlotEligibilityAdapterTrustV1,
): AccountsSlotEligibilityPort {
  invariant(
    source !== null &&
      typeof source === "object" &&
      typeof source.getSlotEligibility === "function" &&
      typeof source.checkOnlineGeneration === "function",
    "Accounts SlotEligibility source is invalid",
  );
  nonemptyString(
    trust.expectedEffectNamespaceId,
    "Accounts adapter expectedEffectNamespaceId",
  );
  const trustSnapshot = Object.freeze({
    ...trust,
    signerHistory: cloneWire(
      trust.signerHistory,
      "evidence signer history",
    ) as unknown as AccountsEvidenceTrustV1["signerHistory"],
    ...(trust.now === undefined ? {} : { now: new Date(trust.now.getTime()) }),
    ...(trust.expectedSlotEligibility === undefined
      ? {}
      : {
          expectedSlotEligibility: cloneWire(
            trust.expectedSlotEligibility,
            "expected SlotEligibility",
          ) as unknown as NonNullable<AccountsEvidenceTrustV1["expectedSlotEligibility"]>,
        }),
    ...(trust.previousSlotEligibility === undefined
      ? {}
      : {
          previousSlotEligibility: cloneWire(
            trust.previousSlotEligibility,
            "previous SlotEligibility",
          ) as unknown as NonNullable<AccountsEvidenceTrustV1["previousSlotEligibility"]>,
        }),
  });
  return Object.freeze({
    getSlotEligibility: async (input: AccountsSlotEligibilityRequestV1) => {
      const request = eligibilityRequest(input);
      const expectedAccountLaneId = request.account_lane_id;
      const expectedRequestDigest = canonicalDigest(request);
      const sourceRequest = cloneWire(
        request,
        "SlotEligibility source request",
      ) as unknown as AccountsSlotEligibilityRequestV1;
      const bytes = isolatedBytes(
        await source.getSlotEligibility(sourceRequest),
        "SlotEligibility",
      );
      const slot = parseSlotEligibilityV1(bytes, trustSnapshot);
      invariant(
        slot.account_lane_id === expectedAccountLaneId,
        "SlotEligibility account_lane_id does not match request",
      );
      invariant(
        slot.eligibility_request_digest === expectedRequestDigest,
        "SlotEligibility eligibility_request_digest does not match request",
      );
      return slot;
    },
    checkOnlineGeneration: async (input: AccountsOnlineGenerationCheckRequest) => {
      requiredKeys(
        input,
        ["context", "expectedSlotEligibility"],
        "online-check adapter request",
      );
      const verifiedSlot = parseSlotEligibilityV1(
        encodeSlotEligibilityV1(input.expectedSlotEligibility),
        trustSnapshot,
      );
      invariant(verifiedSlot.eligible, "online-check requires a positive verified SlotEligibility");
      const context = onlineContext(input.context);
      invariant(
        context.account_lane_id === verifiedSlot.account_lane_id,
        "online-check account_lane_id differs from SlotEligibility",
      );
      const slotEligibilityDigest = canonicalDigest(verifiedSlot);
      const bindingContext = cloneWire(
        context,
        "online-check binding context",
      ) as unknown as AccountsOnlineGenerationContextV1;
      const sourceContext = cloneWire(
        context,
        "online-check source context",
      ) as unknown as AccountsOnlineGenerationContextV1;
      const bytes = isolatedBytes(
        await source.checkOnlineGeneration({
          context: sourceContext,
          slot_eligibility_digest: slotEligibilityDigest,
        }),
        "online-check",
      );
      const reverifiedSlot = parseSlotEligibilityV1(
        encodeSlotEligibilityV1(verifiedSlot),
        trustSnapshot,
      );
      invariant(
        reverifiedSlot.eligible,
        "online-check requires a still-valid positive SlotEligibility",
      );
      const receipt = parseOnlineGenerationCheckReceiptV1(bytes, {
        ...trustSnapshot,
        expectedSlotEligibility: reverifiedSlot,
      });
      invariant(
        receipt.slot_eligibility_digest === slotEligibilityDigest,
        "online-check SlotEligibility digest binding mismatch",
      );
      assertOnlineContextBinding(receipt, bindingContext);
      return receipt;
    },
  });
}
