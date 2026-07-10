import {
  createHmac,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
  type KeyLike,
  KeyObject,
} from "node:crypto";

import { AccountsError } from "../errors";
import { canonicalJson } from "../serialization/json";
import type {
  CredentialHandleEnvelope,
  CredentialHandleExpectedClaims,
  CredentialHandleVerification,
  CredentialHandleVerifier,
  UnsignedCredentialHandleEnvelope,
} from "./repository";

export class Ed25519CredentialHandleVerifier implements CredentialHandleVerifier {
  private readonly publicKeys = new Map<string, KeyObject>();
  private readonly auditKey: Buffer;

  constructor(input: {
    readonly issuerPublicKeys: ReadonlyMap<string, KeyObject | string | Buffer>;
    readonly auditKey: Uint8Array;
  }) {
    if (input.auditKey.byteLength < 32) {
      throw new AccountsError("VALIDATION_FAILED", "Credential audit key is too short");
    }
    this.auditKey = Buffer.from(input.auditKey);
    for (const [issuerRef, key] of input.issuerPublicKeys) {
      this.publicKeys.set(issuerRef, key instanceof KeyObject ? key : createPublicKey(key));
    }
  }

  verify(
    envelope: CredentialHandleEnvelope,
    expected: CredentialHandleExpectedClaims,
  ): CredentialHandleVerification {
    const key = this.publicKeys.get(envelope.issuerRef);
    if (key === undefined || canonicalJson(expectedClaims(envelope)) !== canonicalJson(expected)) {
      throw new AccountsError("POLICY_DENIED", "Credential issuer claims do not match catalog lineage");
    }
    let signature: Buffer;
    try {
      signature = Buffer.from(envelope.signature, "base64url");
    } catch {
      throw new AccountsError("POLICY_DENIED", "Credential issuer signature is invalid");
    }
    const { signature: _signature, ...unsigned } = envelope;
    if (
      signature.byteLength !== 64 ||
      !verifyBytes(null, Buffer.from(canonicalJson(unsigned), "utf8"), key, signature)
    ) {
      throw new AccountsError("POLICY_DENIED", "Credential issuer signature is invalid");
    }
    return {
      credentialHandleAuditDigest: `hmac-sha256:${createHmac("sha256", this.auditKey)
        .update(envelope.opaqueHandle, "utf8")
        .digest("hex")}`,
    };
  }
}

export const REJECTING_CREDENTIAL_HANDLE_VERIFIER: CredentialHandleVerifier = Object.freeze({
  verify(): never {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "No credential issuer verifier is configured");
  },
});

export function signCredentialHandleEnvelope(
  unsigned: UnsignedCredentialHandleEnvelope,
  privateKey: KeyLike,
): CredentialHandleEnvelope {
  const signature = signBytes(
    null,
    Buffer.from(canonicalJson(unsigned), "utf8"),
    privateKey,
  ).toString("base64url");
  return Object.freeze({ ...unsigned, signature });
}

function expectedClaims(envelope: CredentialHandleEnvelope): CredentialHandleExpectedClaims {
  return {
    audience: envelope.audience,
    catalogIncarnation: envelope.catalogIncarnation,
    backendClass: envelope.backendClass,
    ownerRef: envelope.ownerRef,
    providerAccountId: envelope.providerAccountId,
    providerKey: envelope.providerKey,
    capacityPoolId: envelope.capacityPoolId,
    capacityDomainRef: envelope.capacityDomainRef,
    accessMethodId: envelope.accessMethodId,
    credentialFamilyId: envelope.credentialFamilyId,
    purpose: envelope.purpose,
    resolver: envelope.resolver,
    policyDigest: envelope.policyDigest,
    credentialGeneration: envelope.credentialGeneration,
    ...(envelope.authCapsuleId === undefined
      ? {}
      : { authCapsuleId: envelope.authCapsuleId }),
    ...(envelope.canonicalNodeId === undefined
      ? {}
      : { canonicalNodeId: envelope.canonicalNodeId }),
    ...(envelope.nodeGeneration === undefined
      ? {}
      : { nodeGeneration: envelope.nodeGeneration }),
    ...(envelope.placementGeneration === undefined
      ? {}
      : { placementGeneration: envelope.placementGeneration }),
  };
}
