import { describe, expect, test } from "bun:test";

import {
  AccountsError,
  canonicalJson,
  decodeRecordEnvelope,
  deserializeRecordEnvelope,
  encodeRecordEnvelope,
  parseClosedJson,
  parseClosedJsonBytes,
  serializeRecordEnvelope,
  validateEntity,
  newCredentialBindingId,
  newEligibilityEvidenceId,
  toErrorEnvelope,
  validateEligibilityRequest,
  validateSlotEligibility,
  type EntityKind,
} from "../../src/index";
import { C0, C1, makeFixtureGraph, NOW, digest } from "../fixtures";

describe("closed versioned record DTOs", () => {
  const graph = makeFixtureGraph();
  const records = [
    ["account", graph.account],
    ["account", graph.activeAccount],
    ["entitlement", graph.entitlement],
    ["entitlement", graph.activeEntitlement],
    ["capacity_pool", graph.pool],
    ["access_method", graph.method],
    ["access_method", graph.readyMethod],
    ["auth_capsule", graph.capsule!],
    ["credential_binding", graph.binding],
  ] as const;

  test.each(records)("round-trips %s without numeric counter coercion", (kind, record) => {
    const source = serializeRecordEnvelope(kind, record);
    const decoded = deserializeRecordEnvelope(source);
    expect(decoded).toEqual(encodeRecordEnvelope(kind, record));
    expect(typeof decoded.data.revision).toBe("string");
  });

  test("rejects every unknown top-level and nested field", () => {
    const envelope = structuredClone(
      encodeRecordEnvelope("account", graph.account),
    ) as unknown as Record<string, unknown>;
    envelope.extra = true;
    expect(() => decodeRecordEnvelope(envelope)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );

    const nested = structuredClone(encodeRecordEnvelope("entitlement", graph.activeEntitlement)) as unknown as {
      data: { capabilitySet: Record<string, unknown> };
    };
    nested.data.capabilitySet.extra = true;
    expect(() => decodeRecordEnvelope(nested)).toThrow(AccountsError);
  });

  test("rejects credential-material and locator-shaped fields before serialization", () => {
    const envelope = structuredClone(encodeRecordEnvelope("account", graph.account)) as unknown as {
      data: Record<string, unknown>;
    };
    envelope.data.clientSecret = true;
    expect(() => decodeRecordEnvelope(envelope)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
  });

  test("rejects token-shaped values even when placed under an otherwise allowed field", () => {
    const envelope = structuredClone(encodeRecordEnvelope("account", graph.account)) as unknown as {
      data: { displayLabel: string };
    };
    envelope.data.displayLabel = `sk-${"x".repeat(24)}`;
    expect(() => decodeRecordEnvelope(envelope)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
  });

  test("rejects duplicate keys, prototype keys, non-RFC whitespace, unsafe numbers, and lone surrogates", () => {
    expect(() => parseClosedJson('{"kind":"a","kind":"b"}')).toThrow(AccountsError);
    expect(() => parseClosedJson('{"__proto__":{}}')).toThrow(AccountsError);
    expect(() => parseClosedJson("{\u00a0\"a\":1}")).toThrow(AccountsError);
    expect(() => parseClosedJson('{"value":9007199254740993}')).toThrow(AccountsError);
    expect(() => parseClosedJson('{"value":"\\ud800"}')).toThrow(AccountsError);
    for (const number of ["-0", "1.0", "1e0", "1E+0"]) {
      expect(() => parseClosedJson(`{"value":${number}}`)).toThrow(AccountsError);
    }
    expect(() => parseClosedJsonBytes(Uint8Array.of(0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d))).toThrow(
      AccountsError,
    );
  });

  test("canonical JSON uses lexicographic key ordering and rejects accessors", () => {
    expect(canonicalJson({ z: 1, a: { y: 2, x: 3 } })).toBe('{"a":{"x":3,"y":2},"z":1}');
    expect(canonicalJson({ "2": "second", "10": "first" })).toBe(
      '{"10":"first","2":"second"}',
    );
    let invoked = false;
    const accessor = Object.defineProperty({}, "value", {
      enumerable: true,
      get() {
        invoked = true;
        return "changed";
      },
    });
    expect(() => canonicalJson(accessor)).toThrow(AccountsError);
    expect(invoked).toBe(false);
  });

  test("enforces the two closed revoked binding shapes without handle metadata", () => {
    const revokedAt = new Date(NOW.getTime() + 10).toISOString();
    const retired = {
      ...graph.binding,
      status: "revoked" as const,
      terminalKind: "retired_handle_generation" as const,
      credentialHandleAuditDigest: `hmac-sha256:${"a".repeat(64)}`,
      revocationBarrierReceiptDigest: digest("b"),
      revokedAt,
      revision: C1,
      updatedAt: revokedAt,
    };
    expect(validateEntity("credential_binding", retired)).toEqual(retired);

    const {
      bindingEvidenceRef: _bindingEvidenceRef,
      bindingEvidenceIssuerRef: _bindingEvidenceIssuerRef,
      bindingEvidenceDigest: _bindingEvidenceDigest,
      bindingEvidenceExpiresAt: _bindingEvidenceExpiresAt,
      expiresAt: _expiresAt,
      ...lineage
    } = graph.binding;
    const barrier = {
      ...lineage,
      id: newCredentialBindingId(NOW.getTime() + 999),
      credentialGeneration: C1,
      status: "revoked" as const,
      terminalKind: "revocation_barrier" as const,
      lastUsableCredentialGeneration: C0,
      revocationBarrierReceiptDigest: digest("b"),
      revokedAt,
      rotatedAt: revokedAt,
      revision: C0,
      createdAt: revokedAt,
      updatedAt: revokedAt,
    };
    expect(validateEntity("credential_binding", barrier)).toEqual(barrier);
    expect(() =>
      validateEntity("credential_binding", {
        ...barrier,
        credentialHandleAuditDigest: `hmac-sha256:${"c".repeat(64)}`,
      }),
    ).toThrow(AccountsError);
    expect(() =>
      validateEntity("credential_binding", {
        ...retired,
        terminalKind: "revocation_barrier",
        lastUsableCredentialGeneration: C0,
      }),
    ).toThrow(AccountsError);
    expect(() =>
      validateEntity("credential_binding", {
        ...graph.binding,
        terminalKind: "retired_handle_generation",
      }),
    ).toThrow(AccountsError);
  });

  test("positive eligibility cannot omit critical chain fields or use unresolved target", () => {
    const partial = {
      schemaVersion: "accounts.slot-eligibility.v1",
      evidenceId: newEligibilityEvidenceId(NOW.getTime() + 500),
      evidenceClass: "local_diagnostic",
      authority: "none",
      reservation: "none",
      accessMethodId: graph.method.id,
      accessTarget: { kind: "unresolved" },
      recordRevisionSet: {},
      eligibilityRequestDigest: digest("f"),
      eligible: true,
      reasonCodes: [],
      issuedAt: NOW.toISOString(),
      expiresAt: new Date(NOW.getTime() + 1_000).toISOString(),
    };
    expect(() => validateSlotEligibility(partial)).toThrow(AccountsError);
  });

  test("eligibility decisions have a closed eligible/reasonCodes relation", () => {
    const negative = {
      schemaVersion: "accounts.slot-eligibility.v1",
      evidenceId: newEligibilityEvidenceId(NOW.getTime() + 501),
      evidenceClass: "local_diagnostic",
      authority: "none",
      reservation: "none",
      accessMethodId: graph.method.id,
      accessTarget: { kind: "unresolved" },
      recordRevisionSet: {},
      eligibilityRequestDigest: digest("f"),
      eligible: false,
      reasonCodes: ["CURRENT_DENY"],
      issuedAt: NOW.toISOString(),
      expiresAt: new Date(NOW.getTime() + 1_000).toISOString(),
    } as const;
    expect(validateSlotEligibility(negative)).toEqual(negative);
    expect(() => validateSlotEligibility({ ...negative, reasonCodes: [] })).toThrow(AccountsError);
    expect(() => validateSlotEligibility({
      ...negative,
      reasonCodes: ["TERMS_STALE", "ACCOUNT_NOT_ACTIVE"],
    })).toThrow(AccountsError);
    expect(() =>
      validateSlotEligibility({ ...negative, eligible: true, reasonCodes: ["CURRENT_DENY"] }),
    ).toThrow(AccountsError);
  });

  test("eligibility requests are closed and bounded at runtime", () => {
    const valid = {
      accessMethodId: graph.method.id,
      operation: "responses.create",
      model: "model.example",
      dataClassification: "internal",
      destinationPolicyClass: "default",
    };
    expect(validateEligibilityRequest(valid)).toEqual(valid);
    expect(() => validateEligibilityRequest({ ...valid, extra: true })).toThrow(AccountsError);
    expect(() => validateEligibilityRequest({ ...valid, operation: " invalid " })).toThrow(AccountsError);
  });

  test("public error envelopes use fixed messages and never retain caller text", () => {
    const error = new AccountsError("VALIDATION_FAILED", "caller-controlled diagnostic text", {
      details: { field: "safeField", operation: "safe_operation" },
    });
    const envelope = toErrorEnvelope(error, "request-id");
    expect(error.message).toBe("The request is invalid");
    expect(envelope.error.message).toBe("The request is invalid");
    expect(canonicalJson(envelope)).not.toContain("caller-controlled");
  });

  test("all fixture envelope kinds are explicit", () => {
    expect([...new Set(records.map(([kind]) => kind))].sort()).toEqual(
      ([
        "account",
        "access_method",
        "auth_capsule",
        "capacity_pool",
        "credential_binding",
        "entitlement",
      ] satisfies EntityKind[]).sort(),
    );
  });
});
