import { afterAll, describe, expect, test } from "bun:test";
import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseCounter } from "../../src/domain/counter";
import { canonicalSha256 } from "../../src/serialization/json";
import {
  EffectDispatchJournal,
  effectDispatchedSigningBytes,
  effectOutcomeSigningBytes,
  providerLookupEvidenceSigningBytes,
  type EffectDispatchedRecord,
  type EffectOutcomeKind,
  type EffectOutcomeRecord,
  type EffectOutcomeSigningInput,
  type EffectPreparedRecord,
  type ProviderLookupEvidence,
  type UnsignedEffectOutcomeRecord,
  type UnsignedProviderLookupEvidence,
} from "../../src/storage/effect-dispatch";

const cleanup: string[] = [];
const JOURNAL_KEY = new Uint8Array(32).fill(0x42);
const CATALOG = "catalog:effect-dispatch-test";
const ENDPOINT = "effect-endpoint:credential-broker";
const ENDPOINT_INCARNATION = "endpoint-incarnation:2026-07-10";
const ENDPOINT_KEY_ID = "endpoint-key:1";
const LOOKUP_ISSUER = "provider-lookup:credential-broker";
const LOOKUP_INCARNATION = "provider-lookup-incarnation:1";
const LOOKUP_KEY_ID = "provider-lookup-key:1";
const DISPATCH_SIGNER = "accounts-effect-sink:spark01";
const DISPATCH_SIGNER_INCARNATION = "accounts-effect-sink-incarnation:1";
const DISPATCH_KEY_ID = "accounts-effect-sink-key:1";
const AUDIENCE = "accounts-self-hosted";
const OPERATION_ID = "018f0f00-0001-7000-8000-000000000011";
const ALTERNATE_OPERATION_ID = "018f0f00-0001-7000-8000-000000000012";
const NOW = new Date("2026-07-10T12:00:00.000Z");
const OUTCOME_SCHEMA_DIGEST =
  "sha256:7ab380a0475ebf79d2ed925e20bcbb9303d78a56c358d09adbdce796e740bf20";

interface TestKeys {
  readonly dispatch: { readonly publicKey: KeyObject; readonly privateKey: KeyObject };
  readonly endpoint: { readonly publicKey: KeyObject; readonly privateKey: KeyObject };
  readonly lookup: { readonly publicKey: KeyObject; readonly privateKey: KeyObject };
}

afterAll(() => {
  for (const path of cleanup) rmSync(path, { recursive: true, force: true });
});

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "accounts-effect-dispatch-"));
  chmodSync(path, 0o700);
  cleanup.push(path);
  return path;
}

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function testKeys(): TestKeys {
  return {
    dispatch: generateKeyPairSync("ed25519"),
    endpoint: generateKeyPairSync("ed25519"),
    lookup: generateKeyPairSync("ed25519"),
  };
}

function journalAt(
  path: string,
  keys: TestKeys = testKeys(),
  clock: () => Date = () => new Date(NOW),
): { journal: EffectDispatchJournal; keys: TestKeys } {
  return {
    keys,
    journal: new EffectDispatchJournal({
      path,
      catalogIncarnation: CATALOG,
      signingKey: JOURNAL_KEY,
      dispatchSigner: {
        signerRef: DISPATCH_SIGNER,
        signerIncarnation: DISPATCH_SIGNER_INCARNATION,
        keyId: DISPATCH_KEY_ID,
        audience: AUDIENCE,
        privateKey: keys.dispatch.privateKey,
      },
      effectEndpointTrust: new Map([
        [
          ENDPOINT,
          {
            incarnation: ENDPOINT_INCARNATION,
            keyId: ENDPOINT_KEY_ID,
            audience: AUDIENCE,
            publicKey: keys.endpoint.publicKey,
          },
        ],
      ]),
      providerLookupTrust: new Map([
        [
          LOOKUP_ISSUER,
          {
            incarnation: LOOKUP_INCARNATION,
            keyId: LOOKUP_KEY_ID,
            audience: AUDIENCE,
            publicKey: keys.lookup.publicKey,
          },
        ],
      ]),
      clock,
    }),
  };
}

function prepareInput(
  epoch: string,
  maintenanceGrantCharacter: string,
  priorReceipt?: string,
) {
  return {
    operation_id: OPERATION_ID,
    operation_step_id: "rotate-provider-credential",
    operation_execution_epoch: parseCounter(epoch),
    credential_family_id: "credential-family:primary",
    serialization_key_digest: digest("a"),
    operation_digest: digest("1"),
    request_digest: digest("b"),
    target_digest: digest("2"),
    source_fences_digest: digest("c"),
    maintenance_fence_digest: digest("3"),
    maintenance_grant_digest: digest(maintenanceGrantCharacter),
    effect_endpoint_ref: ENDPOINT,
    provider_key: "provider-example",
    ...(priorReceipt === undefined
      ? {}
      : { prior_failed_no_effect_receipt_digest: priorReceipt }),
  };
}

function dispatchPrepared(journal: EffectDispatchJournal, prepared: EffectPreparedRecord) {
  return journal.dispatch({
    operation_id: prepared.operation_id,
    operation_step_id: prepared.operation_step_id,
    operation_execution_epoch: prepared.operation_execution_epoch,
    prepared_receipt_digest: journal.readState(
      prepared.operation_id,
      prepared.operation_step_id,
    )!.prepared.receipt_digest,
  });
}

function signOutcome(
  unsigned: UnsignedEffectOutcomeRecord,
  keys: TestKeys,
): EffectOutcomeRecord {
  return {
    ...unsigned,
    endpoint_signature: sign(
      null,
      effectOutcomeSigningBytes(unsigned),
      keys.endpoint.privateKey,
    ).toString("base64url"),
  } as EffectOutcomeRecord;
}

function outcomeInput(
  kind: EffectOutcomeKind,
  prepared: EffectPreparedRecord,
  dispatchedReceipt: string,
  evidenceDigest = digest("d"),
): EffectOutcomeSigningInput {
  const common = {
    operation_id: prepared.operation_id,
    operation_step_id: prepared.operation_step_id,
    operation_execution_epoch: prepared.operation_execution_epoch,
    dispatched_receipt_digest: dispatchedReceipt,
    observed_at: NOW.toISOString(),
  };
  switch (kind) {
    case "succeeded":
      return {
        ...common,
        outcome_kind: kind,
        provider_result_receipt_digest: evidenceDigest,
      };
    case "failed_effect":
      return {
        ...common,
        outcome_kind: kind,
        provider_failure_receipt_digest: evidenceDigest,
      };
    case "failed_no_effect":
      return {
        ...common,
        outcome_kind: kind,
        provider_lookup_evidence_digest: evidenceDigest,
      };
    case "reconciliation_blocked":
      return {
        ...common,
        outcome_kind: kind,
        reconciliation_evidence_digest: evidenceDigest,
      };
  }
}

function lookupEvidence(
  prepared: EffectPreparedRecord,
  dispatched: EffectDispatchedRecord,
  keys: TestKeys,
  overrides: Partial<UnsignedProviderLookupEvidence> = {},
): ProviderLookupEvidence {
  const unsigned = {
    schema_version: "accounts.provider-effect-lookup.v1",
    provider_key: prepared.provider_key,
    provider_lookup_issuer_ref: LOOKUP_ISSUER,
    provider_lookup_issuer_incarnation: LOOKUP_INCARNATION,
    provider_lookup_key_id: LOOKUP_KEY_ID,
    audience: AUDIENCE,
    effect_endpoint_ref: prepared.effect_endpoint_ref,
    provider_idempotency_token_sha256:
      dispatched.provider_idempotency_token_sha256,
    semantic_operation_key_digest: prepared.semantic_operation_key_digest,
    operation_id: prepared.operation_id,
    operation_step_id: prepared.operation_step_id,
    operation_digest: prepared.operation_digest,
    request_digest: prepared.request_digest,
    target_digest: prepared.target_digest,
    source_fences_digest: prepared.source_fences_digest,
    maintenance_fence_digest: prepared.maintenance_fence_digest,
    maintenance_grant_digest: prepared.maintenance_grant_digest,
    operation_execution_epoch: prepared.operation_execution_epoch,
    lookup_result: "rejected_not_accepted_no_state_change",
    provider_observation_id: "provider-observation:1",
    issued_at: NOW.toISOString(),
    expires_at: new Date(NOW.getTime() + 60_000).toISOString(),
    ...overrides,
  } as UnsignedProviderLookupEvidence;
  return {
    ...unsigned,
    provider_signature: sign(
      null,
      providerLookupEvidenceSigningBytes(unsigned),
      keys.lookup.privateKey,
    ).toString("base64url"),
  };
}

function advanceToOutcome(
  journal: EffectDispatchJournal,
  keys: TestKeys,
  kind: EffectOutcomeKind,
) {
  const prepared = journal.prepare(prepareInput("1", "4"));
  const dispatched = dispatchPrepared(journal, prepared.record);
  const proof =
    kind === "failed_no_effect"
      ? lookupEvidence(prepared.record, dispatched.record, keys)
      : undefined;
  const unsigned = journal.outcomeForSigning(
    outcomeInput(
      kind,
      prepared.record,
      dispatched.receipt_digest,
      proof === undefined ? digest("d") : canonicalSha256(proof),
    ),
  );
  const outcome = journal.recordOutcome(signOutcome(unsigned, keys), proof);
  return { prepared, dispatched, outcome, proof };
}

describe("non-rewindable credential effect journal", () => {
  test("uses the exact semantic key and provider-token projections and separates claim, prepared, and external logs", () => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const prepared = journal.prepare(prepareInput("1", "4"));

    const independentlyFrozenSemanticDigest =
      "sha256:5af047bdcb0ab8a2cb323482873f7cd855afaf727c34fff30fbc9236643e62dd";
    expect(
      canonicalSha256({
        schema_version: "accounts.credential-effect-semantic-key.v1",
        catalog_incarnation: CATALOG,
        credential_family_id: prepared.record.credential_family_id,
        serialization_key_digest: prepared.record.serialization_key_digest,
        operation_step_id: prepared.record.operation_step_id,
        request_digest: prepared.record.request_digest,
        source_fences_digest: prepared.record.source_fences_digest,
      }),
    ).toBe(independentlyFrozenSemanticDigest);
    expect(prepared.record.semantic_operation_key_digest).toBe(
      independentlyFrozenSemanticDigest,
    );
    expect(readFileSync(path, "utf8")).not.toContain("PREPARED");
    expect(readFileSync(path, "utf8")).not.toContain("CLAIMED");
    expect(readFileSync(`${path}.claims`, "utf8")).toContain("CLAIMED");
    expect(readFileSync(`${path}.prepared`, "utf8")).toContain("PREPARED");

    const dispatched = dispatchPrepared(journal, prepared.record);
    const expectedTokenDigest = canonicalSha256({
      schema_version: "accounts.provider-idempotency.v1",
      catalog_incarnation: CATALOG,
      effect_endpoint_ref: prepared.record.effect_endpoint_ref,
      operation_id: prepared.record.operation_id,
      operation_step_id: prepared.record.operation_step_id,
      provider_key: prepared.record.provider_key,
      request_digest: prepared.record.request_digest,
      semantic_operation_key_digest:
        prepared.record.semantic_operation_key_digest,
      target_digest: prepared.record.target_digest,
    });
    expect(expectedTokenDigest).toBe(
      "sha256:f27eaa68b871709c9fe13a2cf5def390107af936b61b184879ae80333de22661",
    );
    expect(dispatched.provider_idempotency_token).toBe(
      "accounts-effect-v1.f27eaa68b871709c9fe13a2cf5def390107af936b61b184879ae80333de22661",
    );
    expect(dispatched.record.provider_idempotency_token_sha256).toBe(
      "sha256:04eacb3831eff92c6e9b9c1f8f7c700c7e4b189e1f55207ddd39758017fca5e1",
    );
    expect(
      `sha256:${createHash("sha256")
        .update(dispatched.provider_idempotency_token, "ascii")
        .digest("hex")}`,
    ).toBe(dispatched.record.provider_idempotency_token_sha256);
    expect(Object.keys(dispatched.record).sort()).toEqual(
      [
        "audience",
        "dispatched_at",
        "effect_endpoint_ref",
        "key_id",
        "maintenance_fence_digest",
        "maintenance_grant_digest",
        "operation_digest",
        "operation_execution_epoch",
        "operation_id",
        "operation_step_id",
        "outcome_schema_digest",
        "outcome_schema_version",
        "prepared_receipt_digest",
        "provider_idempotency_token_sha256",
        "provider_key",
        "record_kind",
        "request_digest",
        "schema_version",
        "semantic_operation_key_digest",
        "signature",
        "signer_incarnation",
        "signer_ref",
        "source_fences_digest",
        "target_digest",
      ].sort(),
    );
    expect(dispatched.record.outcome_schema_digest).toBe(OUTCOME_SCHEMA_DIGEST);
    const { signature: _signature, ...unsignedDispatch } = dispatched.record;
    expect(
      verify(
        null,
        effectDispatchedSigningBytes(unsignedDispatch),
        keys.dispatch.publicKey,
        Buffer.from(dispatched.record.signature, "base64url"),
      ),
    ).toBe(true);
    expect(readFileSync(path, "utf8")).not.toContain(
      dispatched.provider_idempotency_token,
    );
  });

  test("keeps one stable operation id for a semantic claim across database rewind", () => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const first = journal.prepare(prepareInput("1", "4"));

    const reopened = journalAt(path, keys).journal;
    expect(() =>
      reopened.prepare({
        ...prepareInput("1", "4"),
        operation_id: ALTERNATE_OPERATION_ID,
      }),
    ).toThrow(expect.objectContaining({ code: "RECOVERY_HOLD" }));

    const replay = reopened.prepare(prepareInput("1", "4"));
    expect(replay.replayed).toBe(true);
    expect(replay.record.operation_id).toBe(first.record.operation_id);
  });

  test.each([
    "succeeded",
    "failed_effect",
    "failed_no_effect",
    "reconciliation_blocked",
  ] as const)("accepts the shared signed %s outcome and no legacy literal", (kind) => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const prepared = journal.prepare(prepareInput("1", "4"));
    const dispatched = dispatchPrepared(journal, prepared.record);
    expect(journal.readState(OPERATION_ID, prepared.record.operation_step_id)).toMatchObject({
      phase: "DISPATCHED",
    });

    const proof =
      kind === "failed_no_effect"
        ? lookupEvidence(prepared.record, dispatched.record, keys)
        : undefined;
    const unsigned = journal.outcomeForSigning(
      outcomeInput(
        kind,
        prepared.record,
        dispatched.receipt_digest,
        proof === undefined ? digest("d") : canonicalSha256(proof),
      ),
    );
    expect(unsigned.schema_version).toBe("infinity.effect-journal-outcome/v1");
    expect(unsigned.schema_digest).toBe(OUTCOME_SCHEMA_DIGEST);
    const accepted = journal.recordOutcome(signOutcome(unsigned, keys), proof);
    expect(accepted.record.outcome_kind).toBe(kind);
    expect(journalAt(path, keys).journal.readState(
      OPERATION_ID,
      prepared.record.operation_step_id,
    )).toMatchObject({ phase: "OUTCOME", outcome_kind: kind });
    const persisted = readFileSync(path, "utf8");
    expect(persisted).not.toContain("outcome_unknown");
    expect(persisted).not.toContain("failed_effect_possible");
  });

  test("represents unknown only as DISPATCHED without an OUTCOME", () => {
    const path = join(directory(), "effects.log");
    const { journal } = journalAt(path);
    const prepared = journal.prepare(prepareInput("1", "4"));
    dispatchPrepared(journal, prepared.record);
    expect(journal.readState(OPERATION_ID, prepared.record.operation_step_id)).toMatchObject({
      phase: "DISPATCHED",
    });
    expect(readFileSync(path, "utf8")).not.toContain("OUTCOME");
  });

  test("permits only the exact +1 failed_no_effect retry with a fresh maintenance grant", () => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const first = advanceToOutcome(journal, keys, "failed_no_effect");
    const retry = prepareInput("2", "5", first.outcome.receipt_digest);

    for (const invalid of [
      prepareInput("3", "5", first.outcome.receipt_digest),
      prepareInput("2", "4", first.outcome.receipt_digest),
      { ...retry, operation_digest: digest("6") },
      { ...retry, request_digest: digest("6") },
      { ...retry, target_digest: digest("6") },
      { ...retry, source_fences_digest: digest("6") },
      { ...retry, maintenance_fence_digest: digest("6") },
      { ...retry, prior_failed_no_effect_receipt_digest: digest("6") },
    ]) {
      expect(() => journal.prepare(invalid)).toThrow(
        expect.objectContaining({ code: "RECOVERY_HOLD" }),
      );
    }

    const secondPrepared = journal.prepare(retry);
    const secondDispatch = dispatchPrepared(journal, secondPrepared.record);
    expect(secondDispatch.provider_idempotency_token).toBe(
      first.dispatched.provider_idempotency_token,
    );
  });

  test("requires a fresh signed full-binding provider lookup proof for failed_no_effect", () => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const prepared = journal.prepare(prepareInput("1", "4"));
    const dispatched = dispatchPrepared(journal, prepared.record);
    const proof = lookupEvidence(prepared.record, dispatched.record, keys);
    const unsigned = journal.outcomeForSigning(
      outcomeInput(
        "failed_no_effect",
        prepared.record,
        dispatched.receipt_digest,
        canonicalSha256(proof),
      ),
    );
    const signedOutcome = signOutcome(unsigned, keys);

    expect(() => journal.recordOutcome(signedOutcome)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
    const wrongBinding = lookupEvidence(prepared.record, dispatched.record, keys, {
      operation_digest: digest("6"),
    });
    expect(() => journal.recordOutcome(signedOutcome, wrongBinding)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
    const stale = lookupEvidence(prepared.record, dispatched.record, keys, {
      issued_at: "2026-07-10T11:58:59.999Z",
      expires_at: "2026-07-10T11:59:59.999Z",
    });
    const staleUnsigned = journal.outcomeForSigning(
      outcomeInput(
        "failed_no_effect",
        prepared.record,
        dispatched.receipt_digest,
        canonicalSha256(stale),
      ),
    );
    expect(() => journal.recordOutcome(signOutcome(staleUnsigned, keys), stale)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );

    expect(journal.recordOutcome(signedOutcome, proof).record.outcome_kind).toBe(
      "failed_no_effect",
    );
  });

  test.each([
    "succeeded",
    "failed_effect",
    "reconciliation_blocked",
  ] as const)("terminal outcome %s never permits redispatch", (kind) => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const first = advanceToOutcome(journal, keys, kind);
    expect(() =>
      journal.prepare(
        prepareInput("2", "5", first.outcome.receipt_digest),
      ),
    ).toThrow(expect.objectContaining({ code: "RECOVERY_HOLD" }));
  });

  test("rejects missing, forged, stale, and wrong-trust outcome signatures", () => {
    const path = join(directory(), "effects.log");
    const { journal, keys } = journalAt(path);
    const prepared = journal.prepare(prepareInput("1", "4"));
    const dispatched = dispatchPrepared(journal, prepared.record);
    const unsigned = journal.outcomeForSigning(
      outcomeInput("succeeded", prepared.record, dispatched.receipt_digest),
    );

    expect(() => journal.recordOutcome(unsigned as EffectOutcomeRecord)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
    const attacker = testKeys();
    expect(() => journal.recordOutcome(signOutcome(unsigned, attacker))).toThrow(
      expect.objectContaining({ code: "FORBIDDEN" }),
    );
    const staleUnsigned = {
      ...unsigned,
      observed_at: "2026-07-10T11:58:59.999Z",
    } as UnsignedEffectOutcomeRecord;
    expect(() => journal.recordOutcome(signOutcome(staleUnsigned, keys))).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );

    journal.recordOutcome(signOutcome(unsigned, keys));
    const wrongKeys = testKeys();
    expect(() => journalAt(path, wrongKeys)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("accepts a positive 64-bit epoch without Number coercion", () => {
    const path = join(directory(), "effects.log");
    const { journal } = journalAt(path);
    const prepared = journal.prepare(prepareInput("9007199254740993", "4"));
    expect(String(prepared.record.operation_execution_epoch)).toBe(
      "9007199254740993",
    );
  });

  test("rejects aliases and accessor-backed security fields without invoking them", () => {
    const path = join(directory(), "effects.log");
    const { journal } = journalAt(path);
    expect(() =>
      journal.prepare({
        ...prepareInput("1", "4"),
        step_id: "rotate-provider-credential",
      } as never),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    let invoked = false;
    const malicious = { ...prepareInput("1", "4") } as Record<string, unknown>;
    Object.defineProperty(malicious, "provider_key", {
      enumerable: true,
      get() {
        invoked = true;
        return "provider-example";
      },
    });
    expect(() => journal.prepare(malicious as never)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
    expect(invoked).toBe(false);
  });

  test("detects external journal corruption and truncation on reopen", () => {
    for (const mutation of ["corrupt", "truncate"] as const) {
      const path = join(directory(), "effects.log");
      const { journal, keys } = journalAt(path);
      const prepared = journal.prepare(prepareInput("1", "4"));
      dispatchPrepared(journal, prepared.record);
      const source = readFileSync(path, "utf8");
      if (mutation === "corrupt") {
        writeFileSync(path, source.replace(digest("b"), digest("6")), {
          mode: 0o600,
        });
      } else {
        const lines = source.trimEnd().split("\n");
        writeFileSync(path, `${lines.slice(0, -1).join("\n")}\n`, { mode: 0o600 });
      }
      expect(() => journalAt(path, keys)).toThrow(
        expect.objectContaining({ code: "RECOVERY_HOLD" }),
      );
    }
  });
});
