import { describe, expect, test } from "bun:test";

import {
  AccountsError,
  canonicalJson,
  decodeRecordEnvelope,
  deserializeRecordEnvelope,
  encodeRecordEnvelope,
  parseClosedJson,
  serializeRecordEnvelope,
  toErrorEnvelope,
  validateEligibilityRequest,
  validateSlotEligibility,
  type EntityKind,
} from "../../src/index";
import { makeFixtureGraph, NOW, digest } from "../fixtures";

describe("closed versioned record DTOs", () => {
  const graph = makeFixtureGraph();
  const records = [
    ["account", graph.account],
    ["entitlement", graph.entitlement],
    ["capacity_pool", graph.pool],
    ["access_method", graph.method],
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

    const nested = structuredClone(encodeRecordEnvelope("entitlement", graph.entitlement)) as unknown as {
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

  test("rejects duplicate keys, prototype keys, non-RFC whitespace, unsafe numbers, and lone surrogates", () => {
    expect(() => parseClosedJson('{"kind":"a","kind":"b"}')).toThrow(AccountsError);
    expect(() => parseClosedJson('{"__proto__":{}}')).toThrow(AccountsError);
    expect(() => parseClosedJson("{\u00a0\"a\":1}")).toThrow(AccountsError);
    expect(() => parseClosedJson('{"value":9007199254740993}')).toThrow(AccountsError);
    expect(() => parseClosedJson('{"value":"\\ud800"}')).toThrow(AccountsError);
  });

  test("canonical JSON is stable for safe local hashing", () => {
    expect(canonicalJson({ z: 1, a: { y: 2, x: 3 } })).toBe('{"a":{"x":3,"y":2},"z":1}');
  });

  test("positive eligibility cannot omit critical chain fields or use unresolved target", () => {
    const partial = {
      schemaVersion: "accounts.slot-eligibility.v1",
      evidenceId: graph.method.id,
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
    expect(records.map(([kind]) => kind).sort()).toEqual(
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
