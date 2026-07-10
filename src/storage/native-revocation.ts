import { AccountsError } from "../errors";
import { incrementCounter, parseCounter } from "../domain/counter";
import type {
  AccessMethod,
  AuthCapsule,
  CapacityPool,
  CredentialBinding,
  CredentialOperation,
} from "../domain/models";
import { transitionEntity } from "../domain/state";
import { validateEntity } from "../serialization/dto";
import { canonicalSha256 } from "../serialization/json";
import type { NativeRevocationRequest, NativeRevocationResult } from "./repository";

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const KEYED_DIGEST_PATTERN = /^hmac-sha256:[0-9a-f]{64}$/;

export interface NativeRevocationSource {
  readonly pool: CapacityPool;
  readonly method: AccessMethod;
  readonly capsule: AuthCapsule;
  readonly binding: CredentialBinding;
  readonly credentialHandleAuditDigest: string;
}

export function deriveNativeRevocation(
  source: NativeRevocationSource,
  request: NativeRevocationRequest,
  revocationBarrierReceiptDigest: string,
): Omit<NativeRevocationResult, "replayed"> {
  const { pool, method, capsule, binding, credentialHandleAuditDigest } = source;
  if (!DIGEST_PATTERN.test(revocationBarrierReceiptDigest)) {
    throw new AccountsError("VALIDATION_FAILED", "Revocation receipt digest is invalid", {
      details: { field: "revocationBarrierReceiptDigest" },
    });
  }
  if (!KEYED_DIGEST_PATTERN.test(credentialHandleAuditDigest)) {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Credential handle audit digest is invalid");
  }
  const occurredAtMs = Date.parse(request.occurredAt);
  if (
    !Number.isFinite(occurredAtMs) ||
    new Date(occurredAtMs).toISOString() !== request.occurredAt ||
    [pool.updatedAt, method.updatedAt, capsule.updatedAt, binding.updatedAt].some(
      (timestamp) => Date.parse(timestamp) >= occurredAtMs,
    )
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Revocation timestamp is invalid", {
      details: { field: "occurredAt" },
    });
  }
  if (
    pool.revision !== request.expectedPoolRevision ||
    method.revision !== request.expectedMethodRevision ||
    capsule.revision !== request.expectedCapsuleRevision ||
    binding.revision !== request.expectedBindingRevision
  ) {
    throw new AccountsError("STALE_REVISION", "Native revocation expected revision is stale");
  }
  if (
    pool.status !== "active" ||
    pool.denyState !== "allowed" ||
    method.status !== "ready" ||
    capsule.status === "revoked" ||
    binding.status !== "active" ||
    method.accessTransport !== "native_session" ||
    binding.resolver !== "capsule_local_native" ||
    binding.purpose !== "provider_session" ||
    method.capacityPoolId !== pool.id ||
    capsule.id !== request.capsuleId ||
    capsule.accessMethodId !== method.id ||
    capsule.capacityPoolId !== pool.id ||
    binding.id !== request.bindingId ||
    binding.accessMethodId !== method.id ||
    binding.capacityPoolId !== pool.id ||
    binding.authCapsuleId !== capsule.id ||
    binding.credentialGeneration !== capsule.authGeneration ||
    binding.authStateRevision !== capsule.authStateRevision
  ) {
    throw new AccountsError("INVALID_ACCESS_TARGET", "Native revocation lineage is invalid");
  }
  if (request.barrierBindingId === binding.id) {
    throw new AccountsError("VALIDATION_FAILED", "Revocation barrier requires a distinct binding id");
  }

  const nextGeneration = incrementCounter(capsule.authGeneration);
  const nextPool = transitionEntity("capacity_pool", pool, "draining", request.occurredAt);
  const nextMethod = transitionEntity("access_method", method, "draining", request.occurredAt);
  const nextCapsule = validateEntity("auth_capsule", {
    ...transitionEntity("auth_capsule", capsule, "revoked", request.occurredAt),
    authGeneration: nextGeneration,
  });
  const retiredBinding = validateEntity("credential_binding", {
    ...transitionEntity("credential_binding", binding, "revoked", request.occurredAt),
    terminalKind: "retired_handle_generation",
    credentialHandleAuditDigest,
    revocationBarrierReceiptDigest,
    revokedAt: request.occurredAt,
  });
  const {
    bindingEvidenceRef: _bindingEvidenceRef,
    bindingEvidenceIssuerRef: _bindingEvidenceIssuerRef,
    bindingEvidenceDigest: _bindingEvidenceDigest,
    bindingEvidenceExpiresAt: _bindingEvidenceExpiresAt,
    expiresAt: _expiresAt,
    ...barrierLineage
  } = binding;
  const barrierBinding = validateEntity("credential_binding", {
    ...barrierLineage,
    id: request.barrierBindingId,
    credentialGeneration: nextGeneration,
    status: "revoked",
    terminalKind: "revocation_barrier",
    lastUsableCredentialGeneration: binding.credentialGeneration,
    revocationBarrierReceiptDigest,
    revokedAt: request.occurredAt,
    rotatedAt: request.occurredAt,
    revision: parseCounter("0"),
    createdAt: request.occurredAt,
    updatedAt: request.occurredAt,
  });
  const operation: CredentialOperation = Object.freeze({
    id: request.operationId,
    kind: "revocation",
    sourceBindingId: binding.id,
    targetBindingId: barrierBinding.id,
    credentialFamilyId: binding.credentialFamilyId,
    capacityPoolId: pool.id,
    serializationKey: pool.serializationKey,
    expectedSourceGeneration: binding.credentialGeneration,
    ...(binding.authStateRevision === undefined
      ? {}
      : { expectedAuthStateRevision: binding.authStateRevision }),
    proposedTargetGeneration: nextGeneration,
    ...(binding.authStateRevision === undefined
      ? {}
      : { proposedAuthStateRevision: binding.authStateRevision }),
    state: "verifying",
    idempotencyRequestHash: canonicalSha256({
      kind: "native_revocation",
      capsuleId: capsule.id,
      bindingId: binding.id,
      barrierBindingId: barrierBinding.id,
      expectedPoolRevision: request.expectedPoolRevision,
      expectedMethodRevision: request.expectedMethodRevision,
      expectedCapsuleRevision: request.expectedCapsuleRevision,
      expectedBindingRevision: request.expectedBindingRevision,
      revocationBarrierReceiptDigest,
    }),
    barrierReceiptDigest: revocationBarrierReceiptDigest,
    revision: parseCounter("0"),
    createdAt: request.occurredAt,
    updatedAt: request.occurredAt,
  });
  return {
    pool: nextPool,
    method: nextMethod,
    capsule: nextCapsule,
    retiredBinding,
    barrierBinding,
    operation,
  };
}
