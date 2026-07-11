/**
 * Accounts consumes Infinity evidence; it does not own the provider effect.
 * These types deliberately return the exact signed records that were verified
 * by the Infinity adapter instead of reducing authorization to a boolean.
 */

export type InfinitySha256Digest = `sha256:${string}`;
export type InfinityCounter = string;

/** Exact dual-reviewed Infinity integration consumed by this Accounts boundary. */
export const INFINITY_INTEGRATION_COMMIT =
  "6c2ba3d490cd58c7192d6e274514a9d849575ab8" as const;

export const INFINITY_MODEL_CALL_PREPARED_ANCHOR_SCHEMA_DIGEST =
  "sha256:39f247a54d025353bdb2cf98907ccfe9ad49d8c03ba4244bf66c72da667e924e" as const;
export const INFINITY_MODEL_CALL_CONSUME_BINDING_SCHEMA_DIGEST =
  "sha256:5ed69a61c6162ac1aa42e50e8d718b92fc8bbfab9b1da0d78ecbe91c24f621d2" as const;

export interface CapabilityUseOperationBinding {
  readonly effectNamespaceId: string;
  readonly capabilityId: string;
  readonly capabilityDigest: InfinitySha256Digest;
  readonly nonce: string;
  readonly subject: string;
  readonly actorPrincipal: string;
  readonly accountLaneId: string;
  readonly capacityPoolId: string;
  readonly capacityDomainRef: string;
  readonly serializationKeyDigest: InfinitySha256Digest;
  readonly credentialFamilyId: string;
  readonly resourceLeaseId: string;
  readonly resourceId: string;
  readonly resourceLifecycleGeneration: InfinityCounter;
  readonly operationId: string;
  readonly operationDigest: InfinitySha256Digest;
  readonly operationExecutionEpoch: InfinityCounter;
  readonly senderKeyThumbprint: InfinitySha256Digest;
  readonly channelBindingDigest: InfinitySha256Digest;
  readonly canonicalRequestDigest: InfinitySha256Digest;
  readonly providerDestinationPolicyDigest: InfinitySha256Digest;
  readonly onlineReceiptId: string;
  readonly onlineReceiptDigest: InfinitySha256Digest;
  readonly modelCallAnchorDigest: InfinitySha256Digest;
}

/** Exact signed PREPARED evidence plus the same-domain OPEN hold/frontiers. */
export interface VerifiedPreparedOpenOperation {
  readonly schemaVersion: "infinity.model-call-prepared-anchor/v1";
  readonly schemaDigest: typeof INFINITY_MODEL_CALL_PREPARED_ANCHOR_SCHEMA_DIGEST;
  readonly recordKind: "PREPARED";
  readonly holdState: "OPEN";
  readonly binding: CapabilityUseOperationBinding;
  readonly preparedAnchorJcsBase64url: string;
  readonly preparedAnchorDigest: InfinitySha256Digest;
  readonly openHoldReceiptJcsBase64url: string;
  readonly openHoldReceiptDigest: InfinitySha256Digest;
  readonly holdAuthorityEpoch: InfinityCounter;
  readonly holdId: string;
  readonly holdGeneration: InfinityCounter;
  readonly resourceLeaseFrontierSequence: InfinityCounter;
  readonly resourceLeaseFrontierHash: InfinitySha256Digest;
  readonly preparedModelEffectFrontierSequence: InfinityCounter;
  readonly preparedModelEffectFrontierHash: InfinitySha256Digest;
  readonly deliveryFrontierSequence: InfinityCounter;
  readonly deliveryFrontierHash: InfinitySha256Digest;
  readonly holdModelFrontierDigest: InfinitySha256Digest;
}

export interface BindCapabilityUseRequest {
  readonly prepared: VerifiedPreparedOpenOperation;
  readonly consumeReceiptDigest: InfinitySha256Digest;
  readonly useId: InfinitySha256Digest;
}

export interface AssertPreparedOpenCurrentRequest {
  readonly prepared: VerifiedPreparedOpenOperation;
}

/**
 * Exact signed CONSUME_BOUND evidence. A future narrow broker resolver must
 * require this value together with the durable Accounts tombstone; PREPARED is
 * intentionally not a credential-resolution authorization.
 */
export interface VerifiedConsumeBoundOperation {
  readonly schemaVersion: "infinity.model-call-consume-binding/v1";
  readonly schemaDigest: typeof INFINITY_MODEL_CALL_CONSUME_BINDING_SCHEMA_DIGEST;
  readonly recordKind: "CONSUME_BOUND";
  readonly holdState: "OPEN";
  readonly prepared: VerifiedPreparedOpenOperation;
  readonly consumeReceiptDigest: InfinitySha256Digest;
  readonly useId: InfinitySha256Digest;
  readonly consumeBindingJcsBase64url: string;
  readonly consumeBindingDigest: InfinitySha256Digest;
  readonly boundModelEffectFrontierSequence: InfinityCounter;
  readonly boundModelEffectFrontierHash: InfinitySha256Digest;
}

export interface AssertConsumeBoundCurrentRequest {
  readonly consumeBound: VerifiedConsumeBoundOperation;
}

export interface InfinityAccountsOperationPort {
  /** Resolve and verify the exact signed PREPARED anchor and current OPEN hold. */
  readPreparedOpenOperation(
    binding: CapabilityUseOperationBinding,
  ): Promise<VerifiedPreparedOpenOperation>;

  /** Re-resolve immediately before the Accounts one-use CAS. */
  assertPreparedOpenCurrent(
    request: AssertPreparedOpenCurrentRequest,
  ): Promise<VerifiedPreparedOpenOperation>;

  /** Ask the Infinity effect owner to append the exact CONSUME_BOUND record. */
  bindCapabilityUse(request: BindCapabilityUseRequest): Promise<VerifiedConsumeBoundOperation>;

  /** Re-resolve the binding and prove that its OPEN generation/frontier remains current. */
  assertConsumeBoundCurrent(
    request: AssertConsumeBoundCurrentRequest,
  ): Promise<VerifiedConsumeBoundOperation>;
}
