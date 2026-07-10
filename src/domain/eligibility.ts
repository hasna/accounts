import { AccountsError } from "../errors";
import type { AccountsRepository } from "../storage/repository";
import { newEligibilityEvidenceId } from "./ids";
import type {
  Account,
  AccessMethod,
  AuthCapsule,
  CapacityPool,
  CredentialBinding,
  EligibilityReasonCode,
  EligibilityRequest,
  Entitlement,
  SlotEligibilityMetadata,
} from "./models";
import { canonicalSha256 } from "../serialization/json";
import { validateSlotEligibility } from "../serialization/dto";

export async function evaluateSlotEligibility(
  repository: AccountsRepository,
  request: EligibilityRequest,
  clock: () => Date = () => new Date(),
): Promise<SlotEligibilityMetadata> {
  const now = clock();
  const requestDigest = canonicalSha256({
    accessMethodId: request.accessMethodId,
    operation: request.operation,
    model: request.model,
    dataClassification: request.dataClassification,
    destinationPolicyClass: request.destinationPolicyClass,
  });

  let method: AccessMethod | undefined;
  let entitlement: Entitlement | undefined;
  let account: Account | undefined;
  let pool: CapacityPool | undefined;
  let capsule: AuthCapsule | undefined;
  let binding: CredentialBinding | undefined;
  try {
    method = await repository.get("access_method", request.accessMethodId);
    if (method === undefined) {
      throw new AccountsError("NOT_FOUND", "Access method was not found", {
        details: { aggregateKind: "access_method", aggregateId: request.accessMethodId },
      });
    }
    entitlement = await repository.get("entitlement", method.entitlementId);
    pool = await repository.get("capacity_pool", method.capacityPoolId);
    if (entitlement !== undefined) account = await repository.get("account", entitlement.accountId);
    const bindings = await repository.list("credential_binding");
    const matchingBindings = bindings.filter(
      (candidate) =>
        candidate.accessMethodId === method!.id && candidate.capacityPoolId === method!.capacityPoolId,
    );
    binding = chooseBinding(matchingBindings);
    if (method.accessTransport === "native_session") {
      const capsules = await repository.list("auth_capsule");
      capsule = capsules.find(
        (candidate) =>
          candidate.accessMethodId === method!.id &&
          candidate.capacityPoolId === method!.capacityPoolId &&
          candidate.status !== "revoked",
      );
    }
  } catch (error) {
    if (error instanceof AccountsError && error.code === "NOT_FOUND") throw error;
    return ineligibleBase(request, requestDigest, now, ["DEPENDENCY_UNAVAILABLE"]);
  }

  if (pool?.denyState === "denied") {
    return buildResult({
      request,
      requestDigest,
      now,
      method,
      entitlement,
      account,
      pool,
      capsule,
      binding,
      reasons: ["CURRENT_DENY"],
    });
  }

  const reasons: EligibilityReasonCode[] = [];
  if (account?.status !== "active") reasons.push("ACCOUNT_NOT_ACTIVE");
  if (entitlement?.status !== "active") reasons.push("ENTITLEMENT_NOT_ACTIVE");
  if (entitlement !== undefined) {
    if (entitlement.termsDecision.decision !== "allowed") reasons.push("TERMS_NOT_ALLOWED");
    if (
      Date.parse(entitlement.termsDecision.expiresAt) <= now.getTime() ||
      Date.parse(entitlement.dataPolicyExpiresAt) <= now.getTime()
    ) {
      reasons.push("TERMS_STALE");
    }
    if (!entitlement.capabilitySet.operations.includes(request.operation)) reasons.push("OPERATION_NOT_ALLOWED");
    if (!entitlement.capabilitySet.models.includes(request.model)) reasons.push("MODEL_NOT_ALLOWED");
    if (!entitlement.dataPolicy.allowedClassifications.includes(request.dataClassification)) {
      reasons.push("DATA_CLASSIFICATION_NOT_ALLOWED");
    }
  }
  if (pool?.status !== "active") reasons.push("CAPACITY_POOL_NOT_ACTIVE");
  if (pool !== undefined && Date.parse(pool.evidenceExpiresAt) <= now.getTime()) {
    reasons.push("CAPACITY_EVIDENCE_STALE");
  }
  if (method.status !== "ready") reasons.push("ACCESS_METHOD_NOT_READY");
  if (method.health?.state !== "healthy") reasons.push("HEALTH_NOT_HEALTHY");
  if (
    method.health === undefined ||
    Date.parse(method.health.expiresAt) <= now.getTime() ||
    Date.parse(method.isolationEvidenceExpiresAt) <= now.getTime()
  ) {
    reasons.push("HEALTH_STALE");
  }

  if (method.accessTransport === "native_session") {
    if (capsule === undefined) {
      reasons.push("CAPSULE_REQUIRED");
    } else {
      if (capsule.status !== "ready") reasons.push("CAPSULE_NOT_READY");
      if (account !== undefined && capsule.ownerRef !== account.ownerRef) reasons.push("CAPSULE_OWNER_MISMATCH");
      if (capsule.placementKind !== "enrolled_node") reasons.push("CAPSULE_PLACEMENT_INVALID");
      if (
        capsule.attestation === undefined ||
        Date.parse(capsule.attestation.expiresAt) <= now.getTime()
      ) {
        reasons.push("ATTESTATION_STALE");
      }
    }
  }

  if (binding === undefined) {
    reasons.push("CREDENTIAL_BINDING_REQUIRED");
  } else {
    if (binding.status === "retiring") reasons.push("CREDENTIAL_BINDING_RETIRING");
    else if (binding.status !== "active") reasons.push("CREDENTIAL_BINDING_NOT_ACTIVE");
    if (binding.expiresAt !== undefined && Date.parse(binding.expiresAt) <= now.getTime()) {
      reasons.push("CREDENTIAL_BINDING_EXPIRED");
    }
    const expectedResolver =
      method.accessTransport === "native_session"
        ? "capsule_local_native"
        : method.accessTransport === "api_key"
          ? "brokered_secret"
          : "workload_identity";
    if (binding.resolver !== expectedResolver) reasons.push("INVALID_ACCESS_TARGET");
    if (
      capsule !== undefined &&
      method.accessTransport === "native_session" &&
      (binding.authCapsuleId !== capsule.id ||
        binding.credentialGeneration !== capsule.authGeneration ||
        binding.authStateRevision !== capsule.authStateRevision)
    ) {
      reasons.push("GENERATION_MISMATCH");
    }
  }
  if (method.accessTransport === "native_session" && pool?.maxConcurrency !== "1") {
    reasons.push("INVALID_ACCESS_TARGET");
  }

  return buildResult({
    request,
    requestDigest,
    now,
    method,
    entitlement,
    account,
    pool,
    capsule,
    binding,
    reasons: uniqueReasons(reasons),
  });
}

function chooseBinding(bindings: readonly CredentialBinding[]): CredentialBinding | undefined {
  const active = bindings.filter((binding) => binding.status === "active");
  if (active.length > 1) return undefined;
  if (active.length === 1) return active[0];
  const retiring = bindings.filter((binding) => binding.status === "retiring");
  if (retiring.length > 0) return retiring[0];
  return bindings[0];
}

function buildResult(input: {
  request: EligibilityRequest;
  requestDigest: string;
  now: Date;
  method: AccessMethod;
  entitlement: Entitlement | undefined;
  account: Account | undefined;
  pool: CapacityPool | undefined;
  capsule: AuthCapsule | undefined;
  binding: CredentialBinding | undefined;
  reasons: readonly EligibilityReasonCode[];
}): SlotEligibilityMetadata {
  const { request, requestDigest, now, method, entitlement, account, pool, capsule, binding, reasons } = input;
  const accessTarget =
    method.accessTransport === "native_session" && capsule !== undefined
      ? {
          kind: "native" as const,
          authCapsuleId: capsule.id,
          canonicalNodeId: capsule.placementRef,
          nodeKeyThumbprint: capsule.hardwareKeyThumbprint,
          nodeGeneration: capsule.nodeGeneration,
          placementGeneration: capsule.placementGeneration,
          authGeneration: capsule.authGeneration,
          authStateRevision: capsule.authStateRevision,
        }
      : method.accessTransport !== "native_session" && binding !== undefined && binding.resolver !== "capsule_local_native"
        ? {
            kind: "brokered" as const,
            credentialBindingId: binding.id,
            resolver: binding.resolver,
          }
        : { kind: "unresolved" as const };
  const recordRevisionSet = {
    access_method: method.revision,
    ...(entitlement === undefined ? {} : { entitlement: entitlement.revision }),
    ...(account === undefined ? {} : { account: account.revision }),
    ...(pool === undefined ? {} : { capacity_pool: pool.revision }),
    ...(capsule === undefined ? {} : { auth_capsule: capsule.revision }),
    ...(binding === undefined ? {} : { credential_binding: binding.revision }),
  };
  const expiresAt = new Date(
    Math.max(
      now.getTime() + 1,
      Math.min(
        now.getTime() + 30_000,
        ...[
          entitlement?.termsDecision.expiresAt,
          entitlement?.dataPolicyExpiresAt,
          pool?.evidenceExpiresAt,
          method.health?.expiresAt,
          method.isolationEvidenceExpiresAt,
          capsule?.attestation?.expiresAt,
          binding?.expiresAt,
        ]
          .filter((value): value is string => value !== undefined)
          .map(Date.parse)
          .filter((value) => value > now.getTime()),
      ),
    ),
  ).toISOString();
  const candidate = {
    schemaVersion: "accounts.slot-eligibility.v1",
    evidenceId: newEligibilityEvidenceId(now.getTime()),
    evidenceClass: "local_diagnostic",
    authority: "none",
    reservation: "none",
    accessMethodId: request.accessMethodId,
    ...(account === undefined ? {} : { accountId: account.id, ownerRef: account.ownerRef }),
    ...(entitlement === undefined ? {} : { entitlementId: entitlement.id }),
    ...(pool === undefined
      ? {}
      : {
          capacityPoolId: pool.id,
          serializationKey: pool.serializationKey,
          maxConcurrency: pool.maxConcurrency,
          capacityGeneration: pool.capacityGeneration,
          denyGeneration: pool.denyGeneration,
          denyState: pool.denyState,
        }),
    accessTransport: method.accessTransport,
    accessTarget,
    ...(binding === undefined
      ? {}
      : {
          credentialFamilyId: binding.credentialFamilyId,
          credentialGeneration: binding.credentialGeneration,
        }),
    recordRevisionSet,
    eligibilityRequestDigest: requestDigest,
    eligible: reasons.length === 0,
    reasonCodes: reasons,
    issuedAt: now.toISOString(),
    expiresAt,
  };
  return validateSlotEligibility(candidate);
}

function ineligibleBase(
  request: EligibilityRequest,
  requestDigest: string,
  now: Date,
  reasons: readonly EligibilityReasonCode[],
): SlotEligibilityMetadata {
  return validateSlotEligibility({
    schemaVersion: "accounts.slot-eligibility.v1",
    evidenceId: newEligibilityEvidenceId(now.getTime()),
    evidenceClass: "local_diagnostic",
    authority: "none",
    reservation: "none",
    accessMethodId: request.accessMethodId,
    accessTarget: { kind: "unresolved" },
    recordRevisionSet: {},
    eligibilityRequestDigest: requestDigest,
    eligible: false,
    reasonCodes: reasons,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 1_000).toISOString(),
  });
}

function uniqueReasons(reasons: readonly EligibilityReasonCode[]): readonly EligibilityReasonCode[] {
  return [...new Set(reasons)];
}
