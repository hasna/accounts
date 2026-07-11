import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";

import { AccountsError } from "../../src/errors";
import { canonicalJson } from "../../src/serialization/json";
import {
  ACCOUNTS_V10_CONTRACT_SHA256,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1,
  SLOT_ELIGIBILITY_SCHEMA_VERSION_V1,
  createAccountsSlotEligibilityAdapter,
  createDeterministicAccountsSlotEligibilitySource,
  encodeSlotEligibilityV1,
  parseOnlineGenerationCheckReceiptV1,
  parseSlotEligibilityV1,
  requireAllowedOnlineGenerationCheckReceiptV1,
  signOnlineGenerationCheckReceiptV1,
  signSlotEligibilityV1,
  type AccountsEvidenceSignerHistoryV2,
} from "../../src/v10";

interface Fixture {
  readonly public_key_spki_base64url: string;
  readonly wire: Record<string, unknown>;
  readonly wire_jcs_sha256: string;
}

interface FixtureDocument {
  readonly contract_ref: string;
  readonly signer_history: AccountsEvidenceSignerHistoryV2;
  readonly wire_fixtures: Readonly<Record<string, Fixture>>;
}

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as FixtureDocument;

const NOW = new Date("2026-07-11T10:00:15.000Z");
const slotNames = [
  "slot_eligibility_brokered_positive",
  "slot_eligibility_brokered_resolved_negative",
  "slot_eligibility_unresolved_negative",
  "slot_eligibility_native_positive",
  "slot_eligibility_native_resolved_negative",
  "slot_eligibility_workload_identity_positive",
  "slot_eligibility_retired_signer",
] as const;
const onlineNames = [
  "online_generation_check_positive",
  "online_generation_check_native_positive",
  "online_generation_check_resolved_negative",
  "online_generation_check_unresolved_negative",
  "online_generation_check_exhausted",
  "online_generation_check_workload_identity_positive",
  "online_generation_check_expired_fence_negative",
] as const;

function fixtureBytes(name: string): Uint8Array {
  return new TextEncoder().encode(canonicalJson(fixtureDocument.wire_fixtures[name]!.wire));
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("ACC-041 exact v10 codecs", () => {
  test("pins the approved v10 contract and slash-version schemas", () => {
    expect(ACCOUNTS_V10_CONTRACT_SHA256).toBe(
      "eda1c92990d3562a81128a5bd455fdfc32be6b7170820f9519aae611af0a8bdc",
    );
    expect(SLOT_ELIGIBILITY_SCHEMA_VERSION_V1).toBe("accounts.slot-eligibility/v1");
    expect(ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1).toBe(
      "accounts.online-generation-check-receipt/v1",
    );
  });

  test("verifies and byte-round-trips every accepted signed SlotEligibility fixture", () => {
    for (const name of slotNames) {
      const fixture = fixtureDocument.wire_fixtures[name]!;
      const parsed = parseSlotEligibilityV1(fixtureBytes(name), {
        signerHistory: fixtureDocument.signer_history,
        now: NOW,
      });
      const encoded = encodeSlotEligibilityV1(parsed);
      expect(sha256(encoded), name).toBe(fixture.wire_jcs_sha256);
    }
  });

  test("verifies every closed online decision and never brands denial as allowed", () => {
    for (const name of onlineNames) {
      const parsed = parseOnlineGenerationCheckReceiptV1(fixtureBytes(name), {
        signerHistory: fixtureDocument.signer_history,
        now: NOW,
      });
      if (parsed.allowed) {
        expect(requireAllowedOnlineGenerationCheckReceiptV1(parsed).allowed).toBe(true);
      } else {
        expect(() => requireAllowedOnlineGenerationCheckReceiptV1(parsed)).toThrow(AccountsError);
      }
    }
  });

  test("accepts a bounded retired signer but rejects a cryptographically valid revoked signer", () => {
    expect(
      parseSlotEligibilityV1(fixtureBytes("slot_eligibility_retired_signer"), {
        signerHistory: fixtureDocument.signer_history,
        now: NOW,
      }).key_id,
    ).toBe("accounts-slot-key-2-retired");
    expect(() =>
      parseSlotEligibilityV1(fixtureBytes("slot_eligibility_revoked_signer"), {
        signerHistory: fixtureDocument.signer_history,
        now: NOW,
      }),
    ).toThrow(AccountsError);
  });

  test("rejects dot-version, camelCase, descriptor-shortcut, and raw-digest signature bytes", () => {
    const base = fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire;
    const mutations = [
      { ...base, schema_version: "accounts.slot-eligibility.v1" },
      Object.fromEntries(
        Object.entries(base).map(([key, value]) =>
          key === "schema_version" ? ["schemaVersion", value] : [key, value]),
      ),
      { ...base, schema_digest: `sha256:${"0".repeat(64)}` },
      { ...base, signature: `sha256:${"1".repeat(64)}` },
    ];
    for (const mutation of mutations) {
      expect(() =>
        parseSlotEligibilityV1(new TextEncoder().encode(canonicalJson(mutation)), {
          signerHistory: fixtureDocument.signer_history,
          now: NOW,
        }),
      ).toThrow(AccountsError);
    }
  });

  test("production and deterministic sources traverse the same parser and trust history", async () => {
    const slot = fixtureBytes("slot_eligibility_brokered_positive");
    const online = fixtureBytes("online_generation_check_positive");
    const deterministic = createDeterministicAccountsSlotEligibilitySource({ slot, online });
    const production = {
      getSlotEligibility: async () => Uint8Array.from(slot),
      checkOnlineGeneration: async () => Uint8Array.from(online),
    };
    const trust = { signerHistory: fixtureDocument.signer_history, clock: () => NOW };
    const deterministicPort = createAccountsSlotEligibilityAdapter(deterministic, trust);
    const productionPort = createAccountsSlotEligibilityAdapter(production, trust);

    expect(await deterministicPort.getSlotEligibility({})).toEqual(
      await productionPort.getSlotEligibility({}),
    );
    expect(await deterministicPort.checkOnlineGeneration({})).toEqual(
      await productionPort.checkOnlineGeneration({}),
    );
  });

  test("uses one shared Ed25519 signing path for both exact wire schemas", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeySpki = publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const signer = {
      issuer: "accounts:test",
      issuerIncarnation: "accounts-test-incarnation",
      audience: "infinity:test",
      keyId: "accounts-test-current",
      privateKey,
    } as const;
    const history: AccountsEvidenceSignerHistoryV2 = {
      schema_version: "accounts.evidence-signer-history/v2",
      issuer: signer.issuer,
      issuer_incarnation: signer.issuerIncarnation,
      audience: signer.audience,
      current_key_id: signer.keyId,
      keys: [{
        key_id: signer.keyId,
        public_key_spki_base64url: publicKeySpki,
        activated_at: "2026-07-11T09:00:00.000Z",
        expires_at: "2026-07-12T00:00:00.000Z",
        retired_at: null,
        revoked_at: null,
      }],
    };
    const slotDraft = {
      ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
      issuer: signer.issuer,
      issuer_incarnation: signer.issuerIncarnation,
      audience: signer.audience,
      key_id: signer.keyId,
    };
    delete slotDraft.signature;
    const onlineDraft = {
      ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
      issuer: signer.issuer,
      issuer_incarnation: signer.issuerIncarnation,
      audience: signer.audience,
      key_id: signer.keyId,
    };
    delete onlineDraft.signature;

    const slotWire = signSlotEligibilityV1(slotDraft, signer);
    const onlineWire = signOnlineGenerationCheckReceiptV1(onlineDraft, signer);
    expect(parseSlotEligibilityV1(slotWire, { signerHistory: history, now: NOW }).issuer)
      .toBe(signer.issuer);
    expect(parseOnlineGenerationCheckReceiptV1(onlineWire, { signerHistory: history, now: NOW }).issuer)
      .toBe(signer.issuer);
  });
});
