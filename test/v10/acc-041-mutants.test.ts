import { describe, expect, test } from "bun:test";
import {
  createHash,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";

import { canonicalJson } from "../../src/serialization/json";
import {
  parseOnlineGenerationCheckReceiptV1,
  parseSlotEligibilityV1,
  type AccountsEvidenceSignerHistoryV2,
  type SlotEligibilityPositiveV1,
} from "../../src/v10";

interface Fixture {
  readonly wire: Readonly<Record<string, unknown>>;
}

interface FixtureDocument {
  readonly signer_history: AccountsEvidenceSignerHistoryV2;
  readonly wire_fixtures: Readonly<Record<string, Fixture>>;
}

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as FixtureDocument;

const NOW = new Date("2026-07-11T10:00:15.000Z");
const encoder = new TextEncoder();

interface TestSigner {
  readonly issuer: string;
  readonly issuerIncarnation: string;
  readonly audience: string;
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly history: AccountsEvidenceSignerHistoryV2;
}

function testSigner(overrides: Partial<Pick<
  TestSigner,
  "issuer" | "issuerIncarnation" | "audience" | "keyId"
>> = {}): TestSigner {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const issuer = overrides.issuer ?? "accounts:self-hosted";
  const issuerIncarnation = overrides.issuerIncarnation ?? "accounts-test-incarnation";
  const audience = overrides.audience ?? "infinity:self-hosted";
  const keyId = overrides.keyId ?? "accounts-test-current";
  return {
    issuer,
    issuerIncarnation,
    audience,
    keyId,
    privateKey,
    history: {
      schema_version: "accounts.evidence-signer-history/v2",
      issuer,
      issuer_incarnation: issuerIncarnation,
      audience,
      current_key_id: keyId,
      keys: [{
        key_id: keyId,
        public_key_spki_base64url: publicKey
          .export({ format: "der", type: "spki" })
          .toString("base64url"),
        activated_at: "2026-07-11T09:00:00.000Z",
        expires_at: "2026-07-12T00:00:00.000Z",
        retired_at: null,
        revoked_at: null,
      }],
    },
  };
}

function fixtureWire(name: string): Record<string, unknown> {
  return structuredClone(fixtureDocument.wire_fixtures[name]!.wire);
}

function fixtureBytes(name: string): Uint8Array {
  return encoder.encode(canonicalJson(fixtureWire(name)));
}

function rawSignedMutation(
  name: string,
  signer: TestSigner,
  mutate: (wire: Record<string, any>) => void,
): Uint8Array {
  const wire = fixtureWire(name) as Record<string, any>;
  wire.issuer = signer.issuer;
  wire.issuer_incarnation = signer.issuerIncarnation;
  wire.audience = signer.audience;
  wire.key_id = signer.keyId;
  delete wire.signature;
  mutate(wire);
  wire.signature = sign(
    null,
    encoder.encode(canonicalJson(wire)),
    signer.privateKey,
  ).toString("base64url");
  return encoder.encode(canonicalJson(wire));
}

function sha256Json(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

const originalSlot = parseSlotEligibilityV1(
  fixtureBytes("slot_eligibility_brokered_positive"),
  { signerHistory: fixtureDocument.signer_history, now: NOW },
);
const workloadSlot = parseSlotEligibilityV1(
  fixtureBytes("slot_eligibility_workload_identity_positive"),
  { signerHistory: fixtureDocument.signer_history, now: NOW },
);
if (!originalSlot.eligible || !workloadSlot.eligible) {
  throw new Error("positive SlotEligibility fixtures are required by this suite");
}

function expectSlotRejects(
  fixtureName: string,
  mutate: (wire: Record<string, any>) => void,
  options: {
    readonly expectedEffectNamespaceId?: string;
    readonly previousSlotEligibility?: SlotEligibilityPositiveV1;
  } = {},
): void {
  const signer = testSigner();
  expect(() => parseSlotEligibilityV1(
    rawSignedMutation(fixtureName, signer, mutate),
    {
      signerHistory: signer.history,
      now: NOW,
      ...options,
    },
  )).toThrow();
}

function expectOnlineRejects(
  fixtureName: string,
  mutate: (wire: Record<string, any>) => void,
  options: {
    readonly expectedEffectNamespaceId?: string;
    readonly expectedSlotEligibility?: SlotEligibilityPositiveV1;
  } = {},
): void {
  const signer = testSigner();
  expect(() => parseOnlineGenerationCheckReceiptV1(
    rawSignedMutation(fixtureName, signer, mutate),
    {
      signerHistory: signer.history,
      now: NOW,
      ...options,
    },
  )).toThrow();
}

describe("ACC-041 raw byte preflight mutants", () => {
  test("rejects duplicate keys before JSON.parse can collapse them", () => {
    const canonical = canonicalJson(fixtureWire("slot_eligibility_brokered_positive"));
    const duplicate = canonical.replace(
      "{",
      '{"schema_version":"accounts.slot-eligibility/v1",',
    );
    expect(() => parseSlotEligibilityV1(encoder.encode(duplicate), {
      signerHistory: fixtureDocument.signer_history,
      now: NOW,
    })).toThrow();
  });

  test("rejects invalid UTF-8, lone surrogates, and noncanonical wire bytes", () => {
    const loneSurrogate = '{"raw_probe":"\\ud800"}';
    expect(() => parseSlotEligibilityV1(encoder.encode(loneSurrogate), {
      signerHistory: fixtureDocument.signer_history,
      now: NOW,
    })).toThrow();
    expect(() => parseSlotEligibilityV1(Uint8Array.from([0xff]), {
      signerHistory: fixtureDocument.signer_history,
      now: NOW,
    })).toThrow();
    const canonical = canonicalJson(fixtureWire("slot_eligibility_brokered_positive"));
    expect(() => parseSlotEligibilityV1(encoder.encode(` ${canonical}`), {
      signerHistory: fixtureDocument.signer_history,
      now: NOW,
    })).toThrow();
  });
});

describe("ACC-041 re-signed SlotEligibility mutants", () => {
  const brokeredPositiveMutants = [
    ["revision consequence", (wire: Record<string, any>) => {
      wire.accounts_revision_set_digest = `sha256:${"0".repeat(64)}`;
    }],
    ["serialization consequence", (wire: Record<string, any>) => {
      wire.serialization_key_digest = `sha256:${"0".repeat(64)}`;
    }],
    ["capacity evidence version", (wire: Record<string, any>) => {
      wire.capacity_evidence_version = "capacity/v1";
    }],
    ["capacity evidence consequence", (wire: Record<string, any>) => {
      wire.capacity_evidence_digest = `sha256:${"5".repeat(64)}`;
    }],
    ["zero max concurrency", (wire: Record<string, any>) => {
      wire.max_concurrency = "0";
    }],
    ["overflow max concurrency", (wire: Record<string, any>) => {
      wire.max_concurrency = "9223372036854775808";
    }],
    ["negative recovery frontier", (wire: Record<string, any>) => {
      wire.recovery_frontier_sequence = "-1";
    }],
    ["expiry before issuance", (wire: Record<string, any>) => {
      wire.expires_at = "2026-07-11T09:59:59.000Z";
    }],
    ["current deny contradiction", (wire: Record<string, any>) => {
      wire.deny_state = "denied";
    }],
    ["access target omission", (wire: Record<string, any>) => {
      delete wire.access_target.resolver;
    }],
    ["resolver substitution", (wire: Record<string, any>) => {
      wire.access_target.resolver = "caller_selected";
    }],
    ["record revision overflow", (wire: Record<string, any>) => {
      wire.record_revision_set.provider_account = "9223372036854775808";
    }],
    ["record revision leading zero", (wire: Record<string, any>) => {
      wire.record_revision_set.provider_account = "01";
    }],
    ["negative capacity generation", (wire: Record<string, any>) => {
      wire.capacity_generation = "-1";
    }],
    ["negative deny generation", (wire: Record<string, any>) => {
      wire.deny_generation = "-1";
    }],
    ["negative credential generation", (wire: Record<string, any>) => {
      wire.credential_generation = "-1";
    }],
    ["zero capacity evidence generation", (wire: Record<string, any>) => {
      wire.capacity_evidence_generation = "0";
    }],
    ["zero ownership generation", (wire: Record<string, any>) => {
      wire.ownership_generation = "0";
    }],
    ["generation overflow", (wire: Record<string, any>) => {
      wire.capacity_generation = "9223372036854775808";
    }],
    ["lifetime too long", (wire: Record<string, any>) => {
      wire.expires_at = "2026-07-11T10:00:31.000Z";
    }],
    ["slot exceeds bound evidence expiry", (wire: Record<string, any>) => {
      wire.capacity_evidence_expires_at = "2026-07-11T10:00:20.000Z";
    }],
    ["bound evidence expired", (wire: Record<string, any>) => {
      wire.health_evidence_expires_at = "2026-07-11T10:00:15.000Z";
    }],
    ["malformed UUIDv7", (wire: Record<string, any>) => {
      wire.provider_account_id = "provider-account-1";
    }],
    ["uppercase digest", (wire: Record<string, any>) => {
      wire.recovery_frontier_hash = `sha256:${"A".repeat(64)}`;
    }],
    ["unknown top-level field", (wire: Record<string, any>) => {
      wire.schema_alias = wire.schema_version;
    }],
  ] as const;

  for (const [name, mutate] of brokeredPositiveMutants) {
    test(`rejects ${name}`, () => expectSlotRejects(
      "slot_eligibility_brokered_positive",
      mutate,
    ));
  }

  test("rejects an expected effect-namespace substitution", () => {
    expectSlotRejects("slot_eligibility_brokered_positive", (wire) => {
      wire.effect_namespace_id = "effect-namespace-substituted";
    }, { expectedEffectNamespaceId: "effect-namespace-1" });
  });

  test("rejects a native target counter encoded as a JSON number", () => {
    expectSlotRejects("slot_eligibility_native_positive", (wire) => {
      wire.access_target.node_generation = 4;
    });
  });

  test("rejects target omissions and resolver substitutions in the added v10 variants", () => {
    expectSlotRejects("slot_eligibility_native_resolved_negative", (wire) => {
      delete wire.access_target.auth_generation;
    });
    expectSlotRejects("slot_eligibility_workload_identity_positive", (wire) => {
      wire.access_target.resolver = "brokered_secret";
    });
  });

  test("rejects unknown and shape-inapplicable reasons after valid re-signing", () => {
    expectSlotRejects("slot_eligibility_brokered_resolved_negative", (wire) => {
      wire.reason_codes = ["POLICY_DENIED"];
    });
    expectSlotRejects("slot_eligibility_brokered_resolved_negative", (wire) => {
      wire.reason_codes = ["CAPSULE_NOT_READY"];
    });
    expectSlotRejects("slot_eligibility_native_resolved_negative", (wire) => {
      wire.reason_codes = ["CREDENTIAL_BINDING_EXPIRED"];
    });
    expectSlotRejects("slot_eligibility_unresolved_negative", (wire) => {
      wire.reason_codes = ["CURRENT_DENY"];
    });
  });

  test("rejects a current deny that preserves the previous generation consequence", () => {
    expectSlotRejects("slot_eligibility_brokered_resolved_negative", (wire) => {
      wire.deny_generation = originalSlot.deny_generation;
      wire.record_revision_set = structuredClone(originalSlot.record_revision_set);
      wire.accounts_revision_set_digest = sha256Json({
        record_revision_set: wire.record_revision_set,
        schema_version: "accounts.record-revision-set.v1",
      });
    }, { previousSlotEligibility: originalSlot });
  });
});

describe("ACC-041 re-signed online-check mutants", () => {
  const positiveMutants = [
    ["non-enum current deny state", (wire: Record<string, any>) => {
      wire.deny_state = "current_deny";
    }],
    ["expiry at trusted time", (wire: Record<string, any>) => {
      wire.expires_at = "2026-07-11T10:00:15.000Z";
    }],
    ["lifetime too long", (wire: Record<string, any>) => {
      wire.expires_at = "2026-07-11T10:02:11.000Z";
    }],
    ["maximum age too old", (wire: Record<string, any>) => {
      wire.issued_at = "2026-07-11T09:59:00.000Z";
      wire.not_before = "2026-07-11T09:59:00.000Z";
    }],
    ["not-before at expiry", (wire: Record<string, any>) => {
      wire.not_before = wire.expires_at;
    }],
    ["expired lease fence", (wire: Record<string, any>) => {
      wire.lease_expires_at = "2026-07-11T10:00:15.000Z";
    }],
    ["expired operation fence", (wire: Record<string, any>) => {
      wire.operation_execution_expires_at = "2026-07-11T10:00:15.000Z";
    }],
    ["receipt beyond bound fence", (wire: Record<string, any>) => {
      wire.lease_expires_at = "2026-07-11T10:00:19.000Z";
    }],
    ["zero authority epoch", (wire: Record<string, any>) => {
      wire.authority_epoch = "0";
    }],
    ["negative recovery frontier", (wire: Record<string, any>) => {
      wire.recovery_frontier_sequence = "-1";
    }],
    ["overflow epoch", (wire: Record<string, any>) => {
      wire.authority_epoch = "9223372036854775808";
    }],
    ["destination digest consequence", (wire: Record<string, any>) => {
      wire.provider_destination_policy_digest = `sha256:${"0".repeat(64)}`;
    }],
    ["mixed native target", (wire: Record<string, any>) => {
      wire.auth_capsule_id = "0198a0a0-0000-7000-8000-000000000008";
    }],
    ["wrong max uses", (wire: Record<string, any>) => {
      wire.max_uses = "2";
    }],
    ["unknown approval mode", (wire: Record<string, any>) => {
      wire.approval_mode = "BYPASS";
    }],
    ["unknown top-level field", (wire: Record<string, any>) => {
      wire.delegation_ref = "not-in-v1";
    }],
  ] as const;

  for (const [name, mutate] of positiveMutants) {
    test(`rejects ${name}`, () => expectOnlineRejects(
      "online_generation_check_positive",
      mutate,
    ));
  }

  test("rejects target and namespace substitutions against expected bindings", () => {
    expectOnlineRejects("online_generation_check_positive", (wire) => {
      wire.provider_account_id = "0198a0a0-0000-7000-8000-000000000099";
    }, { expectedSlotEligibility: originalSlot });
    expectOnlineRejects("online_generation_check_positive", (wire) => {
      wire.effect_namespace_id = "effect-namespace-substituted";
    }, { expectedEffectNamespaceId: "effect-namespace-1" });
    expectOnlineRejects("online_generation_check_workload_identity_positive", (wire) => {
      wire.access_transport = "api_key";
    }, { expectedSlotEligibility: workloadSlot });
  });

  test("rejects unknown and state/target-inapplicable reasons after valid re-signing", () => {
    expectOnlineRejects("online_generation_check_unresolved_negative", (wire) => {
      wire.reason_codes = ["POLICY_DENIED"];
    });
    expectOnlineRejects("online_generation_check_resolved_negative", (wire) => {
      wire.reason_codes = ["USE_LIMIT_REACHED"];
    });
    expectOnlineRejects("online_generation_check_resolved_negative", (wire) => {
      wire.reason_codes = ["CURRENT_DENY", "USE_LIMIT_REACHED"];
    });
    expectOnlineRejects("online_generation_check_resolved_negative", (wire) => {
      wire.reason_codes = ["DEPENDENCY_UNAVAILABLE"];
    });
    expectOnlineRejects("online_generation_check_resolved_negative", (wire) => {
      wire.reason_codes = ["CAPSULE_NOT_READY", "CURRENT_DENY"];
    });
  });

  test("rejects a negative receipt whose own signature window is expired or reasonless", () => {
    expectOnlineRejects("online_generation_check_expired_fence_negative", (wire) => {
      wire.expires_at = "2026-07-11T10:00:15.000Z";
    });
    expectOnlineRejects("online_generation_check_expired_fence_negative", (wire) => {
      wire.reason_codes = [];
    });
  });

  test("rejects stale/forked SlotEligibility bindings when an expected slot is supplied", () => {
    expectOnlineRejects("online_generation_check_positive", (wire) => {
      wire.recovery_frontier_sequence = "41";
    }, { expectedSlotEligibility: originalSlot });
    expectOnlineRejects("online_generation_check_positive", (wire) => {
      wire.recovery_frontier_hash = `sha256:${"f".repeat(64)}`;
    }, { expectedSlotEligibility: originalSlot });
    expectOnlineRejects("online_generation_check_positive", (wire) => {
      wire.slot_eligibility_digest = `sha256:${"f".repeat(64)}`;
    }, { expectedSlotEligibility: originalSlot });
  });
});
