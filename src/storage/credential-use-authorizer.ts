import {
  createPublicKey,
  KeyObject,
  sign as signBytes,
  verify as verifyBytes,
  type KeyLike,
} from "node:crypto";

import { AccountsError } from "../errors";
import { parseCounter } from "../domain/counter";
import { canonicalJson } from "../serialization/json";
import type {
  CredentialResolutionExpected,
  CredentialResolutionGrant,
  CredentialResolutionTransport,
  CredentialUseAuthorizer,
  UnsignedCredentialResolutionGrant,
} from "./repository";

const GRANT_KEYS = Object.freeze([
  "schema_version",
  "issuer_ref",
  "provider_account_id",
  "account_lane_id",
  "capacity_pool_id",
  "credential_binding_id",
  "credential_family_id",
  "credential_generation",
  "purpose",
  "resolver",
  "run_id",
  "attempt_id",
  "resource_lease_id",
  "resource_id",
  "resource_generation",
  "operation_id",
  "operation_digest",
  "execution_epoch",
  "subject_principal",
  "actor_principal",
  "holder_principal",
  "executor_principal",
  "audience",
  "sender_key_thumbprint",
  "catalog_incarnation",
  "recovery_frontier_sequence",
  "recovery_frontier_hash",
  "request_digest",
  "issued_at",
  "expires_at",
  "signature",
] as const);
const PRINCIPAL = /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export class Ed25519CredentialUseAuthorizer implements CredentialUseAuthorizer {
  private readonly publicKeys = new Map<string, KeyObject>();

  constructor(issuerPublicKeys: ReadonlyMap<string, KeyObject | string | Buffer>) {
    for (const [issuerRef, key] of issuerPublicKeys) {
      this.publicKeys.set(issuerRef, key instanceof KeyObject ? key : createPublicKey(key));
    }
  }

  verify(
    grant: CredentialResolutionGrant,
    expected: CredentialResolutionExpected,
    transport: CredentialResolutionTransport,
  ): void {
    const keys = Object.keys(grant).sort();
    if (keys.length !== GRANT_KEYS.length || GRANT_KEYS.some((key) => !Object.hasOwn(grant, key))) {
      denied();
    }
    const key = this.publicKeys.get(grant.issuer_ref);
    const { signature, ...unsigned } = grant;
    const signatureBytes = Buffer.from(signature, "base64url");
    if (
      key === undefined ||
      signatureBytes.byteLength !== 64 ||
      !verifyBytes(null, Buffer.from(canonicalJson(unsigned), "utf8"), key, signatureBytes)
    ) {
      denied();
    }
    for (const counterValue of [
      grant.credential_generation,
      grant.resource_generation,
      grant.execution_epoch,
      grant.recovery_frontier_sequence,
    ]) {
      parseCounter(counterValue);
    }
    if (
      grant.schema_version !== "accounts.handle-resolution.v1" ||
      !REF.test(grant.issuer_ref) ||
      !REF.test(grant.run_id) ||
      !REF.test(grant.attempt_id) ||
      !REF.test(grant.resource_lease_id) ||
      !REF.test(grant.resource_id) ||
      !REF.test(grant.operation_id) ||
      !REF.test(grant.audience) ||
      !PRINCIPAL.test(grant.subject_principal) ||
      !PRINCIPAL.test(grant.actor_principal) ||
      !PRINCIPAL.test(grant.holder_principal) ||
      !PRINCIPAL.test(grant.executor_principal) ||
      !DIGEST.test(grant.operation_digest) ||
      !DIGEST.test(grant.sender_key_thumbprint) ||
      !DIGEST.test(grant.recovery_frontier_hash) ||
      !DIGEST.test(grant.request_digest) ||
      !TIMESTAMP.test(grant.issued_at) ||
      !TIMESTAMP.test(grant.expires_at) ||
      !TIMESTAMP.test(transport.now)
    ) {
      denied();
    }
    const now = Date.parse(transport.now);
    if (
      new Date(now).toISOString() !== transport.now ||
      Date.parse(grant.issued_at) > now ||
      Date.parse(grant.expires_at) <= now ||
      Date.parse(grant.expires_at) - Date.parse(grant.issued_at) > 30_000
    ) {
      denied();
    }
    if (
      grant.provider_account_id !== expected.providerAccountId ||
      grant.account_lane_id !== expected.accessMethodId ||
      grant.capacity_pool_id !== expected.capacityPoolId ||
      grant.credential_binding_id !== expected.bindingId ||
      grant.credential_family_id !== expected.credentialFamilyId ||
      grant.credential_generation !== expected.credentialGeneration ||
      grant.purpose !== expected.purpose ||
      grant.resolver !== expected.resolver ||
      grant.subject_principal !== expected.ownerRef ||
      grant.catalog_incarnation !== expected.catalogIncarnation ||
      grant.recovery_frontier_sequence !== expected.recoveryFrontierSequence ||
      grant.recovery_frontier_hash !== expected.recoveryFrontierHash ||
      grant.actor_principal !== transport.authenticatedActorPrincipal ||
      grant.holder_principal !== transport.authenticatedHolderPrincipal ||
      grant.executor_principal !== transport.authenticatedExecutorPrincipal ||
      grant.sender_key_thumbprint !== transport.authenticatedSenderKeyThumbprint ||
      grant.audience !== transport.audience ||
      grant.run_id !== transport.runId ||
      grant.attempt_id !== transport.attemptId ||
      grant.resource_lease_id !== transport.resourceLeaseId ||
      grant.resource_id !== transport.resourceId ||
      grant.resource_generation !== transport.resourceGeneration ||
      grant.operation_id !== transport.operationId ||
      grant.operation_digest !== transport.operationDigest ||
      grant.execution_epoch !== transport.executionEpoch ||
      grant.request_digest !== transport.requestDigest
    ) {
      denied();
    }
  }
}

export const REJECTING_CREDENTIAL_USE_AUTHORIZER: CredentialUseAuthorizer = Object.freeze({
  verify(): never {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "No credential-use authorizer is configured");
  },
});

export function signCredentialResolutionGrant(
  unsigned: UnsignedCredentialResolutionGrant,
  privateKey: KeyLike,
): CredentialResolutionGrant {
  return Object.freeze({
    ...unsigned,
    signature: signBytes(
      null,
      Buffer.from(canonicalJson(unsigned), "utf8"),
      privateKey,
    ).toString("base64url"),
  });
}

function denied(): never {
  throw new AccountsError("POLICY_DENIED", "Credential-use authority is invalid");
}
