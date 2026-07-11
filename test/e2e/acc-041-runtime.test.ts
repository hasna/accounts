import { afterEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { AccountsError } from "../../src/errors";
import {
  createSQLiteAccountsV10Runtime,
  signOnlineGenerationCheckReceiptV1,
  signSlotEligibilityV1,
  type AccountsEvidenceSignerHistoryV2,
  type InfinityAccountsOperationPort,
} from "../../src/v10";

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as {
  wire_fixtures: Record<string, { wire: Record<string, unknown> }>;
};
const NOW = new Date("2026-07-11T10:00:15.000Z");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function makeSignedFixture(name: string, signer: ReturnType<typeof signerFixture>): Uint8Array {
  const draft = {
    ...fixtureDocument.wire_fixtures[name]!.wire,
    issuer: signer.signer.issuer,
    issuer_incarnation: signer.signer.issuerIncarnation,
    audience: signer.signer.audience,
    key_id: signer.signer.keyId,
  };
  delete draft.signature;
  return name.startsWith("slot_")
    ? signSlotEligibilityV1(draft, signer.signer)
    : signOnlineGenerationCheckReceiptV1(draft, signer.signer);
}

function signerFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signer = {
    issuer: "accounts:self-hosted",
    issuerIncarnation: "accounts-incarnation-runtime",
    audience: "infinity:self-hosted",
    keyId: "accounts-runtime-current",
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
  return { signer, signerHistory };
}

describe("ACC-041 executable SQLite brokered lane", () => {
  test("runs one exact use through a live Infinity operation and permanent tombstone", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-"));
    roots.push(root);
    const signing = signerFixture();
    let live = true;
    let providerContacts = 0;
    const infinity: InfinityAccountsOperationPort = {
      assertPreparedOpenOperation: async (binding) => {
        if (!live) throw new AccountsError("CURRENT_DENY", "Infinity operation is not live");
        expect(binding.operation_id).toBe("operation-1");
        expect(binding.model_call_anchor_digest).toBe(`sha256:${"3".repeat(64)}`);
      },
    };
    const runtime = createSQLiteAccountsV10Runtime({
      catalogPath: join(root, "accounts.sqlite"),
      useLedgerPath: join(root, "accounts-use-ledger.sqlite"),
      signer: signing.signer,
      signerHistory: signing.signerHistory,
      infinity,
      clock: () => new Date(NOW),
    });
    const slotAllow = makeSignedFixture("slot_eligibility_brokered_positive", signing);
    const slotDeny = makeSignedFixture("slot_eligibility_brokered_resolved_negative", signing);
    const onlineAllow = makeSignedFixture("online_generation_check_positive", signing);
    const onlineDeny = makeSignedFixture("online_generation_check_resolved_negative", signing);
    runtime.seedBrokeredLane({
      accountLaneId: "0198a0a0-0000-7000-8000-000000000002",
      credentialBindingId: "0198a0a0-0000-7000-8000-000000000006",
      slotAllow,
      slotDeny,
      onlineAllow,
      onlineDeny,
      opaqueCredentialHandle: "fixture-opaque-handle-never-returned-to-the-caller",
    });

    const slot = await runtime.port.getSlotEligibility({});
    const online = await runtime.port.checkOnlineGeneration({});
    expect(slot.eligible).toBe(true);
    expect(online.allowed).toBe(true);

    const result = await runtime.consumeAndExecute({
      onlineReceipt: online,
      consumeRequestId: "0198a0a0-0000-7000-8000-000000000901",
      idempotencyKeyDigest: `sha256:${"4".repeat(64)}`,
      modelCallAnchorDigest: `sha256:${"3".repeat(64)}`,
      authenticatedChannelBindingDigest: online.sender_constraint_confirmation,
      execute: async (credential) => {
        providerContacts += 1;
        expect(credential.opaqueHandle).toBe("fixture-opaque-handle-never-returned-to-the-caller");
        return { providerReceiptDigest: `sha256:${"5".repeat(64)}` };
      },
    });
    expect(result.value).toEqual({ providerReceiptDigest: `sha256:${"5".repeat(64)}` });
    expect(result.consumeReceipt.use_ordinal).toBe("1");
    expect(providerContacts).toBe(1);

    await expect(runtime.consumeAndExecute({
      onlineReceipt: online,
      consumeRequestId: "0198a0a0-0000-7000-8000-000000000902",
      idempotencyKeyDigest: `sha256:${"6".repeat(64)}`,
      modelCallAnchorDigest: `sha256:${"3".repeat(64)}`,
      authenticatedChannelBindingDigest: online.sender_constraint_confirmation,
      execute: async () => {
        providerContacts += 1;
        return {};
      },
    })).rejects.toBeInstanceOf(AccountsError);
    expect(providerContacts).toBe(1);

    runtime.setCurrentDeny(true);
    const denied = await runtime.port.checkOnlineGeneration({});
    expect(denied.allowed).toBe(false);
    await expect(runtime.consumeAndExecute({
      onlineReceipt: denied,
      consumeRequestId: "0198a0a0-0000-7000-8000-000000000903",
      idempotencyKeyDigest: `sha256:${"7".repeat(64)}`,
      modelCallAnchorDigest: `sha256:${"3".repeat(64)}`,
      authenticatedChannelBindingDigest: denied.sender_constraint_confirmation,
      execute: async () => {
        providerContacts += 1;
        return {};
      },
    })).rejects.toBeInstanceOf(AccountsError);
    expect(providerContacts).toBe(1);

    runtime.close();
    live = false;
  });
});
