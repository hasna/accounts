import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AccountsError } from "../../src/errors";
import { canonicalJson } from "../../src/serialization/json";
import {
  CAPABILITY_USE_TOMBSTONE_DESCRIPTOR,
  CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST,
  CAPABILITY_USE_WIRE_CODEC_STATUS,
  NonRewindableCapabilityUseLedger,
  verifyCapabilityUseEvidence,
  type CapabilityUseVerifiedClaims,
} from "../../src/v10/capability-use-ledger";
import type {
  CapabilityUseOperationBinding,
  InfinityAccountsOperationPort,
  VerifiedConsumeBoundOperation,
  VerifiedPreparedOpenOperation,
} from "../../src/v10/infinity-operation-port";

const roots: string[] = [];
const KEY = new Uint8Array(32).fill(0x53);
const encoder = new TextEncoder();

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const path = mkdtempSync(join(tmpdir(), "accounts-v10-use-ledger-"));
  chmodSync(path, 0o700);
  roots.push(path);
  return path;
}

function digest(character: string): `sha256:${string}` {
  return `sha256:${character.repeat(64)}`;
}

function claims(
  overrides: Partial<CapabilityUseVerifiedClaims> = {},
): CapabilityUseVerifiedClaims {
  return {
    consumeRequestId: "0198a0a0-0000-7000-8000-000000000901",
    idempotencyKeyDigest: digest("1"),
    effectNamespaceId: "effect-namespace-1",
    serializationKeyDigest: digest("2"),
    capabilityId: "capability-1",
    capabilityDigest: digest("3"),
    nonce: "nonce-1",
    onlineReceiptDigest: digest("4"),
    modelCallAnchorDigest: digest("5"),
    useId: digest("6"),
    committedAt: "2026-07-11T10:00:15.000Z",
    consumeReceiptExpiresAt: "2026-07-11T10:01:15.000Z",
    catalogIncarnation: "accounts-v10-ledger-test",
    recoveryFrontierSequence: "1" as CapabilityUseVerifiedClaims["recoveryFrontierSequence"],
    recoveryFrontierHash: digest("0"),
    ...overrides,
  };
}

async function verifiedEvidence(
  verifiedClaims: CapabilityUseVerifiedClaims,
  requestMarker = "request-1",
  receiptMarker = "receipt-1",
) {
  const requestBytes = encoder.encode(canonicalJson({ fixture: requestMarker }));
  const receiptBytes = encoder.encode(canonicalJson({ fixture: receiptMarker }));
  let verifierCalls = 0;
  const evidence = await verifyCapabilityUseEvidence(
    { consumeRequestBytes: requestBytes, consumeReceiptBytes: receiptBytes },
    {
      verify: async (input) => {
        verifierCalls += 1;
        expect(input.consumeRequestBytes).toEqual(requestBytes);
        expect(input.consumeReceiptBytes).toEqual(receiptBytes);
        return verifiedClaims;
      },
    },
  );
  expect(verifierCalls).toBe(1);
  return evidence;
}

function ledgerAt(path: string) {
  return new NonRewindableCapabilityUseLedger({
    ledgerPath: join(path, "capability-use.log"),
    mirrorPath: join(path, "capability-use.sqlite"),
    catalogIncarnation: "accounts-v10-ledger-test",
    signingKey: KEY,
  });
}

describe("v10 non-rewindable capability-use ledger", () => {
  test("records opaque preverified bytes, exact-replays, and resolves every unique key", async () => {
    const directory = root();
    const ledger = ledgerAt(directory);
    const evidence = await verifiedEvidence(claims());

    const appended = ledger.append(evidence);
    expect(appended.kind).toBe("APPENDED");
    expect(appended.record.consumeRequestBytes).toEqual(
      encoder.encode(canonicalJson({ fixture: "request-1" })),
    );
    expect(appended.record.consumeReceiptBytes).toEqual(
      encoder.encode(canonicalJson({ fixture: "receipt-1" })),
    );

    const replayed = ledger.append(
      await verifiedEvidence(claims(), "request-1", "a-different-receipt-that-must-not-win"),
    );
    expect(replayed.kind).toBe("REPLAYED");
    expect(replayed.record.consumeReceiptBytes).toEqual(appended.record.consumeReceiptBytes);

    expect(ledger.lookup({ consumeRequestId: claims().consumeRequestId })).toEqual(appended.record);
    expect(ledger.lookup({ idempotencyKeyDigest: claims().idempotencyKeyDigest })).toEqual(
      appended.record,
    );
    expect(ledger.lookup({ capabilityId: claims().capabilityId, nonce: claims().nonce })).toEqual(
      appended.record,
    );
    expect(ledger.lookup({ useId: claims().useId })).toEqual(appended.record);
    expect(ledger.lookup({ useId: digest("f") })).toBeUndefined();

    ledger.close();
    const reopened = ledgerAt(directory);
    expect(reopened.lookup({ useId: claims().useId })).toEqual(appended.record);
    expect(reopened.initialReconciliation.status).toBe("CURRENT");
    reopened.close();
  });

  test("enforces request, idempotency, capability+nonce, and use-id uniqueness", async () => {
    const ledger = ledgerAt(root());
    ledger.append(await verifiedEvidence(claims()));

    await expect(async () =>
      ledger.append(
        await verifiedEvidence(
          claims({ idempotencyKeyDigest: digest("7") }),
          "changed-request-same-request-id",
          "receipt-2",
        ),
      )
    ).toThrow(expect.objectContaining({ code: "IDEMPOTENCY_CONFLICT" }));

    await expect(async () =>
      ledger.append(
        await verifiedEvidence(
          claims({
            consumeRequestId: "0198a0a0-0000-7000-8000-000000000902",
          }),
          "changed-request-same-idempotency-key",
          "receipt-3",
        ),
      )
    ).toThrow(expect.objectContaining({ code: "IDEMPOTENCY_CONFLICT" }));

    await expect(async () =>
      ledger.append(
        await verifiedEvidence(
          claims({
            consumeRequestId: "0198a0a0-0000-7000-8000-000000000903",
            idempotencyKeyDigest: digest("8"),
            useId: digest("9"),
          }),
          "changed-request-same-capability-nonce",
          "receipt-4",
        ),
      )
    ).toThrow(expect.objectContaining({ code: "CONFLICT" }));

    await expect(async () =>
      ledger.append(
        await verifiedEvidence(
          claims({
            consumeRequestId: "0198a0a0-0000-7000-8000-000000000904",
            idempotencyKeyDigest: digest("a"),
            capabilityId: "capability-2",
            nonce: "nonce-2",
          }),
          "changed-request-same-use-id",
          "receipt-5",
        ),
      )
    ).toThrow(expect.objectContaining({ code: "CONFLICT" }));

    ledger.close();
  });

  test("rebuilds a corrupt SQLite mirror only from the signed append log", async () => {
    const directory = root();
    const mirrorPath = join(directory, "capability-use.sqlite");
    const ledger = ledgerAt(directory);
    const appended = ledger.append(await verifiedEvidence(claims()));

    const mirror = new Database(mirrorPath, { strict: true, safeIntegers: true });
    mirror.query("UPDATE capability_use_mirror SET payload_json = ? WHERE sequence = 1")
      .run(canonicalJson({ corrupt: true }));
    mirror.close();

    expect(ledger.reconcile()).toEqual(
      expect.objectContaining({ status: "REBUILT", recordCount: 1 }),
    );
    expect(ledger.lookup({ useId: claims().useId })).toEqual(appended.record);

    const inspected = new Database(mirrorPath, { readonly: true, safeIntegers: true });
    const row = inspected.query("SELECT payload_json FROM capability_use_mirror WHERE sequence = 1")
      .get() as { payload_json: string };
    expect(row.payload_json).toContain('"record_kind":"CONSUMED"');
    expect(row.payload_json).not.toContain("corrupt");
    inspected.close();
    ledger.close();
  });

  test("detects rewind of the authoritative ledger even when the mirror remains ahead", async () => {
    const directory = root();
    const logPath = join(directory, "capability-use.log");
    const ledger = ledgerAt(directory);
    const first = ledger.append(await verifiedEvidence(claims()));
    ledger.append(
      await verifiedEvidence(
        claims({
          consumeRequestId: "0198a0a0-0000-7000-8000-000000000902",
          idempotencyKeyDigest: digest("7"),
          capabilityId: "capability-2",
          nonce: "nonce-2",
          useId: digest("8"),
        }),
        "request-2",
        "receipt-2",
      ),
    );
    ledger.close();

    const lines = readFileSync(logPath, "utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(3);
    writeFileSync(logPath, `${lines.slice(0, 2).join("\n")}\n`, { mode: 0o600 });

    expect(() => ledgerAt(directory)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
    expect(String(first.record.ledgerSequence)).toBe("1");
  });

  test("pins only the collision-free tombstone descriptor and exposes consume codecs as blocked", () => {
    const actual = `sha256:${createHash("sha256")
      .update(canonicalJson(CAPABILITY_USE_TOMBSTONE_DESCRIPTOR))
      .digest("hex")}`;
    expect(actual).toBe(CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST);
    expect(CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST).toBe(
      "sha256:c4d07c912e2d65350269a7425c461989fc747bbaa7c71ef5841135064fea5a12",
    );
    expect(CAPABILITY_USE_WIRE_CODEC_STATUS).toEqual({
      status: "BLOCKED_DESCRIPTOR_DIGEST_COLLISION",
      request: {
        declaredDigest: "sha256:a7cdc1dfbebeaea3bad6a5014cfb5189be40fb010f57161b46437458492cd1bc",
        computedDescriptorDigest:
          "sha256:c248ce62b2acb9bb75f9bc88dfc272b05a9cd627f7e6ac19829bad9ea36de249",
      },
      receipt: {
        declaredDigest: "sha256:a0999ffabc197f46f6fdeb8a6b78521364b0f2153d52a0e6e63ee360bb408bce",
        computedDescriptorDigest:
          "sha256:4e969fab6b3ae55c479357ebffed40b5de1ce207ca955b478462b36c9a345bfc",
      },
    });
  });

  test("uses evidence-returning PREPARED/OPEN and CONSUME_BOUND port methods", async () => {
    const binding: CapabilityUseOperationBinding = {
      effectNamespaceId: "effect-namespace-1",
      capabilityId: "capability-1",
      capabilityDigest: digest("3"),
      nonce: "nonce-1",
      subject: "principal:subject-1",
      actorPrincipal: "principal:actor-1",
      accountLaneId: "lane-1",
      capacityPoolId: "pool-1",
      capacityDomainRef: "capacity-domain-1",
      serializationKeyDigest: digest("2"),
      credentialFamilyId: "credential-family-1",
      resourceLeaseId: "resource-lease-1",
      resourceId: "resource-1",
      resourceLifecycleGeneration: "1",
      operationId: "operation-1",
      operationDigest: digest("a"),
      operationExecutionEpoch: "1",
      senderKeyThumbprint: digest("b"),
      channelBindingDigest: digest("c"),
      canonicalRequestDigest: digest("d"),
      providerDestinationPolicyDigest: digest("e"),
      onlineReceiptId: "online-receipt-1",
      onlineReceiptDigest: digest("4"),
      modelCallAnchorDigest: digest("5"),
    };
    const prepared = {
      schemaVersion: "infinity.model-call-prepared-anchor/v1",
      schemaDigest: "sha256:39f247a54d025353bdb2cf98907ccfe9ad49d8c03ba4244bf66c72da667e924e",
      recordKind: "PREPARED",
      holdState: "OPEN",
      binding,
      preparedAnchorJcsBase64url: Buffer.from("prepared").toString("base64url"),
      preparedAnchorDigest: binding.modelCallAnchorDigest,
      openHoldReceiptJcsBase64url: Buffer.from("open-hold").toString("base64url"),
      openHoldReceiptDigest: digest("f"),
      holdAuthorityEpoch: "1",
      holdId: "hold-1",
      holdGeneration: "1",
      resourceLeaseFrontierSequence: "1",
      resourceLeaseFrontierHash: digest("1"),
      preparedModelEffectFrontierSequence: "2",
      preparedModelEffectFrontierHash: digest("2"),
      deliveryFrontierSequence: "1",
      deliveryFrontierHash: digest("3"),
      holdModelFrontierDigest: digest("4"),
    } satisfies VerifiedPreparedOpenOperation;
    const consumeBound = {
      schemaVersion: "infinity.model-call-consume-binding/v1",
      schemaDigest: "sha256:5ed69a61c6162ac1aa42e50e8d718b92fc8bbfab9b1da0d78ecbe91c24f621d2",
      recordKind: "CONSUME_BOUND",
      holdState: "OPEN",
      prepared,
      consumeReceiptDigest: digest("7"),
      useId: digest("6"),
      consumeBindingJcsBase64url: Buffer.from("consume-bound").toString("base64url"),
      consumeBindingDigest: digest("8"),
      boundModelEffectFrontierSequence: "3",
      boundModelEffectFrontierHash: digest("9"),
    } satisfies VerifiedConsumeBoundOperation;
    const calls: string[] = [];
    const port: InfinityAccountsOperationPort = {
      readPreparedOpenOperation: async (lookup) => {
        calls.push("read");
        expect(lookup).toEqual(binding);
        return prepared;
      },
      bindCapabilityUse: async (request) => {
        calls.push("bind");
        expect(request.prepared).toBe(prepared);
        expect(request.consumeReceiptDigest).toBe(digest("7"));
        return consumeBound;
      },
      assertConsumeBoundCurrent: async (request) => {
        calls.push("assert-current");
        expect(request.consumeBound).toBe(consumeBound);
        return consumeBound;
      },
    };

    const read = await port.readPreparedOpenOperation(binding);
    const bound = await port.bindCapabilityUse({
      prepared: read,
      consumeReceiptDigest: digest("7"),
      useId: digest("6"),
    });
    const current = await port.assertConsumeBoundCurrent({ consumeBound: bound });
    expect(current.recordKind).toBe("CONSUME_BOUND");
    expect(calls).toEqual(["read", "bind", "assert-current"]);
  });

  test("fails closed when the structured opaque-byte verifier rejects", async () => {
    await expect(
      verifyCapabilityUseEvidence(
        {
          consumeRequestBytes: encoder.encode("request"),
          consumeReceiptBytes: encoder.encode("receipt"),
        },
        {
          verify: async () => {
            throw new AccountsError("FORBIDDEN", "fixture rejection");
          },
        },
      ),
    ).rejects.toEqual(expect.objectContaining({ code: "FORBIDDEN" }));
  });

  test("rejects cross-catalog evidence, overlong receipt lifetime, and verifier mutation", async () => {
    const ledger = ledgerAt(root());
    const crossCatalog = await verifiedEvidence(
      claims({ catalogIncarnation: "another-catalog-incarnation" }),
    );
    expect(() => ledger.append(crossCatalog)).toThrow(
      expect.objectContaining({ code: "CONFLICT" }),
    );

    await expect(
      verifiedEvidence(
        claims({ consumeReceiptExpiresAt: "2026-07-11T10:01:15.001Z" }),
      ),
    ).rejects.toEqual(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    await expect(
      verifyCapabilityUseEvidence(
        {
          consumeRequestBytes: encoder.encode("request"),
          consumeReceiptBytes: encoder.encode("receipt"),
        },
        {
          verify: async (input) => {
            input.consumeRequestBytes[0] = 0x00;
            return claims();
          },
        },
      ),
    ).rejects.toEqual(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    ledger.close();
  });
});
