import { describe, expect, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";

import { AccountsError } from "../../src/errors";
import * as packageRoot from "../../src/index";
import { canonicalJson } from "../../src/serialization/json";
import {
  ACCOUNTS_V10_CONTRACT_SHA256,
  ACCOUNTS_V11_CONTRACT_SHA256,
  ONLINE_GENERATION_CONTEXT_FIELDS_V1,
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
  type AccountsOnlineGenerationContextV1,
  type AccountsSlotEligibilityRequestV1,
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

const ADAPTER_SLOT_REQUEST: AccountsSlotEligibilityRequestV1 = {
  schema_version: "accounts.eligibility-request.v1",
  account_lane_id: "0198a0a0-0000-7000-8000-000000000002",
  data_classification: "internal",
  destination_policy_class: "provider_api",
  model: "provider-model-1",
  operation: "generate",
};

function adapterContext(
  fixtureName = "online_generation_check_positive",
): AccountsOnlineGenerationContextV1 {
  const wire = fixtureDocument.wire_fixtures[fixtureName]!.wire;
  return Object.fromEntries(ONLINE_GENERATION_CONTEXT_FIELDS_V1.map((field) => [
    field,
    field === "authenticated_actor_principal"
      ? wire.actor_principal
      : structuredClone(wire[field]),
  ])) as unknown as AccountsOnlineGenerationContextV1;
}

function adapterFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer = {
    issuer: "accounts:self-hosted",
    issuerIncarnation: "accounts-adapter-incarnation",
    audience: "infinity:self-hosted",
    keyId: "accounts-adapter-current",
    privateKey,
  } as const;
  const signerHistory: AccountsEvidenceSignerHistoryV2 = {
    schema_version: "accounts.evidence-signer-history/v2",
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    current_key_id: signer.keyId,
    keys: [{
      key_id: signer.keyId,
      public_key_spki_base64url: publicKey
        .export({ format: "der", type: "spki" })
        .toString("base64url"),
      activated_at: "2026-07-11T09:00:00.000Z",
      expires_at: "2026-07-12T00:00:00.000Z",
      retired_at: null,
      revoked_at: null,
    }],
  };
  const slotDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    eligibility_request_digest: `sha256:${sha256(
      new TextEncoder().encode(canonicalJson(ADAPTER_SLOT_REQUEST)),
    )}`,
  };
  delete slotDraft.signature;
  const slot = signSlotEligibilityV1(slotDraft, signer);
  const onlineDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    slot_eligibility_digest: `sha256:${sha256(slot)}`,
  };
  delete onlineDraft.signature;
  const online = signOnlineGenerationCheckReceiptV1(onlineDraft, signer);
  const slotDenyDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_resolved_negative!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    eligibility_request_digest: slotDraft.eligibility_request_digest,
  };
  delete slotDenyDraft.signature;
  const slotDeny = signSlotEligibilityV1(slotDenyDraft, signer);
  const onlineDenyDraft: Record<string, unknown> = {
    ...fixtureDocument.wire_fixtures.online_generation_check_resolved_negative!.wire,
    issuer: signer.issuer,
    issuer_incarnation: signer.issuerIncarnation,
    audience: signer.audience,
    key_id: signer.keyId,
    slot_eligibility_digest: `sha256:${sha256(slot)}`,
  };
  delete onlineDenyDraft.signature;
  const onlineDeny = signOnlineGenerationCheckReceiptV1(onlineDenyDraft, signer);
  return { slot, online, slotDeny, onlineDeny, signer, signerHistory };
}

function mutateWireBytes(
  bytes: Uint8Array,
  mutate: (wire: Record<string, any>) => void,
): Uint8Array {
  const wire = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, any>;
  mutate(wire);
  return new TextEncoder().encode(canonicalJson(wire));
}

describe("ACC-041 exact v10 codecs", () => {
  test("keeps signing and non-native helper surfaces out of the package root", () => {
    for (const name of [
      "signSlotEligibilityV1",
      "signOnlineGenerationCheckReceiptV1",
      "slotEligibilitySigningBytesV1",
      "onlineGenerationCheckReceiptSigningBytesV1",
      "encodeOnlineGenerationCheckReceiptV1",
      "requireAllowedOnlineGenerationCheckReceiptV1",
      "isResolvedSlotEligibilityV1",
    ]) {
      expect(name in packageRoot, name).toBe(false);
    }
    expect(packageRoot.encodeSlotEligibilityV1).toBeFunction();
    expect(packageRoot.parseSlotEligibilityV1).toBeFunction();
    expect(packageRoot.parseOnlineGenerationCheckReceiptV1).toBeFunction();
  });

  test("pins the approved v10 contract and slash-version schemas", () => {
    expect(ACCOUNTS_V10_CONTRACT_SHA256).toBe(
      "662842e91a4b58475b92f28eec8caeead4cd7955a485f3d20b16032ab4fa9167",
    );
    expect(ACCOUNTS_V11_CONTRACT_SHA256).toBe(ACCOUNTS_V10_CONTRACT_SHA256);
    expect(SLOT_ELIGIBILITY_SCHEMA_VERSION_V1).toBe("accounts.slot-eligibility/v1");
    expect(ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1).toBe(
      "accounts.online-generation-check-receipt/v1",
    );
    expect(ADAPTER_SLOT_REQUEST.schema_version).toBe("accounts.eligibility-request.v1");
    expect(sha256(new TextEncoder().encode(canonicalJson(ADAPTER_SLOT_REQUEST)))).toBe(
      "374487c934b84a03992a56c5747305d06bde6c5a47be9f6bb5f53544415569f9",
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

  test("rejects a non-current signer until its retirement instant", () => {
    const fixture = adapterFixture();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const retiredSigner = {
      issuer: fixture.signer.issuer,
      issuerIncarnation: fixture.signer.issuerIncarnation,
      audience: fixture.signer.audience,
      keyId: "accounts-adapter-future-retired",
      privateKey,
    } as const;
    const history: AccountsEvidenceSignerHistoryV2 = {
      ...fixture.signerHistory,
      keys: [...fixture.signerHistory.keys, {
        key_id: retiredSigner.keyId,
        public_key_spki_base64url: publicKey
          .export({ format: "der", type: "spki" })
          .toString("base64url"),
        activated_at: "2026-07-11T09:00:00.000Z",
        expires_at: "2026-07-12T00:00:00.000Z",
        retired_at: "2026-07-11T10:00:30.000Z",
        revoked_at: null,
      }],
    };
    const draft: Record<string, unknown> = {
      ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
      issuer: retiredSigner.issuer,
      issuer_incarnation: retiredSigner.issuerIncarnation,
      audience: retiredSigner.audience,
      key_id: retiredSigner.keyId,
    };
    delete draft.signature;
    const wire = signSlotEligibilityV1(draft, retiredSigner);

    expect(() => parseSlotEligibilityV1(wire, {
      signerHistory: history,
      now: NOW,
    })).toThrow(AccountsError);
    const boundaryHistory = structuredClone(history);
    (boundaryHistory.keys[1] as { retired_at: string }).retired_at = NOW.toISOString();
    expect(parseSlotEligibilityV1(wire, {
      signerHistory: boundaryHistory,
      now: NOW,
    }).key_id).toBe(retiredSigner.keyId);
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
    const { slot, online, signerHistory } = adapterFixture();
    const deterministic = createDeterministicAccountsSlotEligibilitySource({ slot, online });
    const production = {
      getSlotEligibility: async () => Uint8Array.from(slot),
      checkOnlineGeneration: async () => Uint8Array.from(online),
    };
    const trust = {
      signerHistory,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    };
    const deterministicPort = createAccountsSlotEligibilityAdapter(deterministic, trust);
    const productionPort = createAccountsSlotEligibilityAdapter(production, trust);

    const deterministicSlot = await deterministicPort.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    const productionSlot = await productionPort.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    expect(deterministicSlot).toEqual(productionSlot);
    if (!deterministicSlot.eligible || !productionSlot.eligible) {
      throw new Error("fixture SlotEligibility must be positive");
    }
    expect(await deterministicPort.checkOnlineGeneration({
      context: adapterContext(),
      expectedSlotEligibility: deterministicSlot,
    })).toEqual(await productionPort.checkOnlineGeneration({
      context: adapterContext(),
      expectedSlotEligibility: productionSlot,
    }));
  });

  test("snapshots mutable fixture bytes and trust history at adapter construction", async () => {
    const fixture = adapterFixture();
    const slot = fixture.slot;
    const online = fixture.online;
    const history = structuredClone(fixture.signerHistory);
    const source = createDeterministicAccountsSlotEligibilitySource({ slot, online });
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: history,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    });

    slot.fill(0);
    online.fill(0);
    (history.keys[0] as { public_key_spki_base64url: string }).public_key_spki_base64url =
      "invalid-after-construction";

    const verifiedSlot = await port.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    expect(verifiedSlot.eligible).toBe(true);
    if (!verifiedSlot.eligible) throw new Error("fixture SlotEligibility must be positive");
    expect((await port.checkOnlineGeneration({
      context: adapterContext(),
      expectedSlotEligibility: verifiedSlot,
    })).allowed).toBe(true);
  });

  test("production adapter fails before source contact without a verified positive Slot binding", async () => {
    const fixture = adapterFixture();
    let onlineSourceCalls = 0;
    const source = {
      getSlotEligibility: async () => fixture.slot,
      checkOnlineGeneration: async () => {
        onlineSourceCalls += 1;
        return fixture.online;
      },
    };
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: fixture.signerHistory,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    await expect(port.checkOnlineGeneration({} as never)).rejects.toBeInstanceOf(AccountsError);
    expect(onlineSourceCalls).toBe(0);
  });

  test("production adapter refuses construction without an effect namespace trust binding", () => {
    const fixture = adapterFixture();
    const source = createDeterministicAccountsSlotEligibilitySource({
      slot: fixture.slot,
      online: fixture.online,
    });
    expect(() => createAccountsSlotEligibilityAdapter(source, {
      signerHistory: fixture.signerHistory,
      clock: () => NOW,
    } as never)).toThrow(AccountsError);
  });

  test("production adapter rejects contradictory Slot and online request bindings", async () => {
    const fixture = adapterFixture();
    const port = createAccountsSlotEligibilityAdapter(
      createDeterministicAccountsSlotEligibilitySource(fixture),
      {
        signerHistory: fixture.signerHistory,
        clock: () => NOW,
        expectedEffectNamespaceId: "effect-namespace-1",
      },
    );
    await expect(port.getSlotEligibility({
      ...ADAPTER_SLOT_REQUEST,
      model: "substituted-model",
    })).rejects.toBeInstanceOf(AccountsError);

    const slot = await port.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    if (!slot.eligible) throw new Error("fixture SlotEligibility must be positive");
    await expect(port.checkOnlineGeneration({
      expectedSlotEligibility: slot,
      context: { ...adapterContext(), route_id: "route-substituted" },
    })).rejects.toBeInstanceOf(AccountsError);
    await expect(port.checkOnlineGeneration({
      expectedSlotEligibility: slot,
      context: { ...adapterContext(), nonce: "nonce-substituted" },
    })).rejects.toBeInstanceOf(AccountsError);
    await expect(port.checkOnlineGeneration({
      expectedSlotEligibility: slot,
      context: {
        ...adapterContext(),
        account_lane_id: "0198a0a0-0000-7000-8000-000000000003",
      },
    })).rejects.toBeInstanceOf(AccountsError);
  });

  test("source mutation cannot rewrite the adapter's post-await request bindings", async () => {
    const fixture = adapterFixture();
    const slotMutationSource = {
      getSlotEligibility: async (request: AccountsSlotEligibilityRequestV1) => {
        (request as { model: string }).model = "source-mutated-model";
        const draft: Record<string, unknown> = {
          ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
          issuer: fixture.signer.issuer,
          issuer_incarnation: fixture.signer.issuerIncarnation,
          audience: fixture.signer.audience,
          key_id: fixture.signer.keyId,
          eligibility_request_digest: `sha256:${sha256(
            new TextEncoder().encode(canonicalJson(request)),
          )}`,
        };
        delete draft.signature;
        return signSlotEligibilityV1(draft, fixture.signer);
      },
      checkOnlineGeneration: async () => fixture.online,
    };
    const slotMutationPort = createAccountsSlotEligibilityAdapter(slotMutationSource, {
      signerHistory: fixture.signerHistory,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    await expect(slotMutationPort.getSlotEligibility(ADAPTER_SLOT_REQUEST))
      .rejects.toBeInstanceOf(AccountsError);

    const onlineMutationSource = {
      getSlotEligibility: async () => fixture.slot,
      checkOnlineGeneration: async (request: {
        context: AccountsOnlineGenerationContextV1;
        slot_eligibility_digest: string;
      }) => {
        (request.context as { route_id: string }).route_id = "source-mutated-route";
        const draft: Record<string, unknown> = {
          ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
          ...request.context,
          actor_principal: request.context.authenticated_actor_principal,
          issuer: fixture.signer.issuer,
          issuer_incarnation: fixture.signer.issuerIncarnation,
          audience: fixture.signer.audience,
          key_id: fixture.signer.keyId,
          slot_eligibility_digest: request.slot_eligibility_digest,
        };
        delete draft.authenticated_actor_principal;
        delete draft.signature;
        return signOnlineGenerationCheckReceiptV1(draft, fixture.signer);
      },
    };
    const onlineMutationPort = createAccountsSlotEligibilityAdapter(onlineMutationSource, {
      signerHistory: fixture.signerHistory,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    const slot = await onlineMutationPort.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    if (!slot.eligible) throw new Error("fixture SlotEligibility must be positive");
    await expect(onlineMutationPort.checkOnlineGeneration({
      expectedSlotEligibility: slot,
      context: adapterContext(),
    })).rejects.toBeInstanceOf(AccountsError);
  });

  test("reverifies the positive Slot after online source latency", async () => {
    const fixture = adapterFixture();
    let now = new Date("2026-07-11T10:00:11.000Z");
    const slotDraft: Record<string, unknown> = {
      ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
      issuer: fixture.signer.issuer,
      issuer_incarnation: fixture.signer.issuerIncarnation,
      audience: fixture.signer.audience,
      key_id: fixture.signer.keyId,
      expires_at: "2026-07-11T10:00:12.000Z",
      eligibility_request_digest: `sha256:${sha256(
        new TextEncoder().encode(canonicalJson(ADAPTER_SLOT_REQUEST)),
      )}`,
    };
    delete slotDraft.signature;
    const slotBytes = signSlotEligibilityV1(slotDraft, fixture.signer);
    const onlineDraft: Record<string, unknown> = {
      ...fixtureDocument.wire_fixtures.online_generation_check_positive!.wire,
      issuer: fixture.signer.issuer,
      issuer_incarnation: fixture.signer.issuerIncarnation,
      audience: fixture.signer.audience,
      key_id: fixture.signer.keyId,
      slot_eligibility_digest: `sha256:${sha256(slotBytes)}`,
    };
    delete onlineDraft.signature;
    const onlineBytes = signOnlineGenerationCheckReceiptV1(onlineDraft, fixture.signer);
    const source = {
      getSlotEligibility: async () => slotBytes,
      checkOnlineGeneration: async () => {
        now = new Date("2026-07-11T10:00:13.000Z");
        return onlineBytes;
      },
    };
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: fixture.signerHistory,
      clock: () => now,
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    const slot = await port.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    if (!slot.eligible) throw new Error("fixture SlotEligibility must be positive");
    await expect(port.checkOnlineGeneration({
      expectedSlotEligibility: slot,
      context: adapterContext(),
    })).rejects.toBeInstanceOf(AccountsError);
  });

  test("deterministic source enforces monotonic transitions, current deny, and unavailability", async () => {
    const fixture = adapterFixture();
    const source = createDeterministicAccountsSlotEligibilitySource(fixture);
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: fixture.signerHistory,
      clock: () => NOW,
      expectedEffectNamespaceId: "effect-namespace-1",
    });
    const allowedSlot = await port.getSlotEligibility(ADAPTER_SLOT_REQUEST);
    if (!allowedSlot.eligible) throw new Error("fixture SlotEligibility must be positive");

    expect(() => source.advance({
      slot: mutateWireBytes(fixture.slot, (wire) => {
        wire.recovery_frontier_sequence = "41";
      }),
      online: fixture.online,
    })).toThrow(AccountsError);
    expect(() => source.advance({
      slot: mutateWireBytes(fixture.slot, (wire) => {
        wire.recovery_frontier_hash = `sha256:${"f".repeat(64)}`;
      }),
      online: fixture.online,
    })).toThrow(AccountsError);

    source.advance({ slot: fixture.slotDeny, online: fixture.onlineDeny });
    expect((await port.getSlotEligibility(ADAPTER_SLOT_REQUEST)).eligible).toBe(false);
    expect((await port.checkOnlineGeneration({
      expectedSlotEligibility: allowedSlot,
      context: adapterContext("online_generation_check_resolved_negative"),
    })).allowed).toBe(false);

    source.setUnavailable(true);
    await expect(port.getSlotEligibility(ADAPTER_SLOT_REQUEST)).rejects.toBeInstanceOf(
      AccountsError,
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
    const slotDraft: Record<string, unknown> = {
      ...fixtureDocument.wire_fixtures.slot_eligibility_brokered_positive!.wire,
      issuer: signer.issuer,
      issuer_incarnation: signer.issuerIncarnation,
      audience: signer.audience,
      key_id: signer.keyId,
    };
    delete slotDraft.signature;
    const onlineDraft: Record<string, unknown> = {
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
