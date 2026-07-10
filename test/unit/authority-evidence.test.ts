import { describe, expect, test } from "bun:test";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as ed25519Sign,
  type KeyObject,
} from "node:crypto";

import { AccountsError } from "../../src/errors";
import { parseCounter } from "../../src/domain/counter";
import {
  signAuthorityEvidenceForTest,
  verifyAuthorityEvidence,
  type AuthorityEvidenceDraft,
  type AuthorityEvidenceExpectation,
  type AuthorityEvidencePayload,
  type AuthorityEvidenceTrustRoot,
  type AuthorityEvidenceType,
} from "../../src/domain/authority-evidence";
import { canonicalJson, parseClosedJsonBytes } from "../../src/serialization/json";

const NOW = new Date("2026-07-10T12:00:00.000Z");
const ISSUED_AT = new Date(NOW.getTime() - 30_000).toISOString();
const EXPIRES_AT = new Date(NOW.getTime() + 60_000).toISOString();

const PROVIDER_ACCOUNT_ID = "018f0f00-0001-7000-8000-000000000001";
const ENTITLEMENT_ID = "018f0f00-0002-7000-8000-000000000002";
const LANE_ID = "018f0f00-0003-7000-8000-000000000003";
const CAPACITY_POOL_ID = "018f0f00-0004-7000-8000-000000000004";

const OWNER_REF = "principal:human:hasna:owner-a";
const REALM = "hasna";
const AUDIENCE = "accounts:self-hosted:capacity";
const NONCE = Buffer.alloc(24, 7).toString("base64url");
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const C0 = parseCounter("0");
const C1 = parseCounter("1");
const C2 = parseCounter("2");
const C3 = parseCounter("3");
const C7 = parseCounter("7");
const C30 = parseCounter("30");

// Golden bytes were generated independently with Python 3, RFC 8785-compatible
// json.dumps(sort_keys=True, separators=(",", ":")), and cryptography 41.0.7.
const GOLDEN_PRIVATE_SEED =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const GOLDEN_PUBLIC_KEY =
  "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const GOLDEN_PAYLOAD_JCS =
  '{"identity_realm":"hasna","owner_ref":"principal:human:hasna:owner-golden","ownership_generation":"7","provider_key":"openai","provider_subject_ref":"provider-subject-golden"}';
const GOLDEN_PAYLOAD_DIGEST =
  "sha256:a56a7402fa5bf538571a4e0dce446c5e5136cd5f2905b2bf8bafc194a4346b5a";
const GOLDEN_WIRE =
  '{"aggregate_id":"018f0f00-00a1-7000-8000-0000000000a1","aggregate_kind":"provider_account","aggregate_revision":"3","audience":"accounts:self-hosted:capacity","evidence_generation":"7","evidence_ref":"evidence:golden:python-cryptography-41","evidence_type":"provider_ownership","expires_at":"2026-07-10T12:01:00.000Z","identity_realm":"hasna","issued_at":"2026-07-10T11:59:30.000Z","issuer_class":"provider_ownership_verifier","issuer_incarnation":"018f0f00-00a2-7000-8000-0000000000a2","issuer_ref":"issuer:provider-ownership:golden","key_id":"python-cryptography-41-golden","nonce":"EBESExQVFhcYGRobHB0eHyAhIiMkJSYn","payload":{"identity_realm":"hasna","owner_ref":"principal:human:hasna:owner-golden","ownership_generation":"7","provider_key":"openai","provider_subject_ref":"provider-subject-golden"},"payload_digest":"sha256:a56a7402fa5bf538571a4e0dce446c5e5136cd5f2905b2bf8bafc194a4346b5a","schema_version":"accounts.authority-evidence.v1","signature":"_FQKzHr_97q6nIG3kgEMn2zt2LysHtpW2nEBj5Y5H8jeaueYNgDXwis6EOgCoBX8cDJL0_7ZoQ2fLp5rRFM3DA","subject_ref":"subject:golden:provider-account"}';

const goldenPrivateKey = createPrivateKey({
  key: Buffer.from(`302e020100300506032b657004220420${GOLDEN_PRIVATE_SEED}`, "hex"),
  format: "der",
  type: "pkcs8",
});
const goldenPublicKey = createPublicKey({
  key: Buffer.from(`302a300506032b6570032100${GOLDEN_PUBLIC_KEY}`, "hex"),
  format: "der",
  type: "spki",
});

const keysByRole = {
  provider_ownership_verifier: generateKeyPairSync("ed25519"),
  provider_capacity_verifier: generateKeyPairSync("ed25519"),
  execution_policy_authority: generateKeyPairSync("ed25519"),
  terms_authority: generateKeyPairSync("ed25519"),
  adapter_health_reporter: generateKeyPairSync("ed25519"),
} as const;

const TYPE_CONFIG = {
  provider_ownership: {
    aggregateKind: "provider_account",
    aggregateId: PROVIDER_ACCOUNT_ID,
    issuerClass: "provider_ownership_verifier",
  },
  provider_capacity: {
    aggregateKind: "capacity_pool",
    aggregateId: CAPACITY_POOL_ID,
    issuerClass: "provider_capacity_verifier",
  },
  entitlement_execution_policy: {
    aggregateKind: "entitlement",
    aggregateId: ENTITLEMENT_ID,
    issuerClass: "execution_policy_authority",
  },
  entitlement_terms: {
    aggregateKind: "entitlement",
    aggregateId: ENTITLEMENT_ID,
    issuerClass: "terms_authority",
  },
  entitlement_data_policy: {
    aggregateKind: "entitlement",
    aggregateId: ENTITLEMENT_ID,
    issuerClass: "execution_policy_authority",
  },
  lane_isolation_policy: {
    aggregateKind: "account_lane",
    aggregateId: LANE_ID,
    issuerClass: "execution_policy_authority",
  },
  lane_execution_policy: {
    aggregateKind: "account_lane",
    aggregateId: LANE_ID,
    issuerClass: "execution_policy_authority",
  },
  lane_health: {
    aggregateKind: "account_lane",
    aggregateId: LANE_ID,
    issuerClass: "adapter_health_reporter",
  },
} as const;

const PAYLOADS = {
  provider_ownership: {
    provider_key: "openai",
    provider_subject_ref: "provider-subject-a",
    owner_ref: OWNER_REF,
    identity_realm: REALM,
    ownership_generation: C1,
  },
  provider_capacity: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    provider_key: "openai",
    owner_ref: OWNER_REF,
    capacity_domain_ref: "capacity-domain-primary",
    serialization_key: "serialization-primary",
    max_concurrency: C2,
    decision: "allowed",
    policy_version: "capacity-policy-v1",
  },
  entitlement_execution_policy: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    owner_ref: OWNER_REF,
    provider_key: "openai",
    use_case: "interactive-coding",
    adapter_version: "2026-07-10",
    decision: "allowed",
    capability_set: {
      operations: ["responses.create"],
      models: ["model.example"],
    },
    policy_version: "policy-v1",
  },
  entitlement_terms: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    owner_ref: OWNER_REF,
    provider_key: "openai",
    use_case: "interactive-coding",
    decision: "allowed",
    terms_version: "terms-v1",
    terms_digest: DIGEST_A,
  },
  entitlement_data_policy: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    owner_ref: OWNER_REF,
    provider_key: "openai",
    use_case: "interactive-coding",
    decision: "allowed",
    allowed_classifications: ["internal"],
    retention_class: "bounded",
    max_retention_days: C30,
    policy_version: "policy-v1",
  },
  lane_isolation_policy: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    entitlement_id: ENTITLEMENT_ID,
    capacity_pool_id: CAPACITY_POOL_ID,
    owner_ref: OWNER_REF,
    adapter_key: "openai",
    adapter_version: "2026-07-10",
    access_transport: "api_key",
    decision: "allowed",
    required_isolation_policy_ref: "isolation-policy-v1",
    required_isolation_policy_digest: DIGEST_B,
    policy_version: "policy-v1",
  },
  lane_execution_policy: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    entitlement_id: ENTITLEMENT_ID,
    capacity_pool_id: CAPACITY_POOL_ID,
    owner_ref: OWNER_REF,
    adapter_key: "openai",
    adapter_version: "2026-07-10",
    access_transport: "api_key",
    decision: "allowed",
    allowed_operations: ["responses.create"],
    allowed_models: ["model.example"],
    allowed_destination_policy_classes: ["default"],
    policy_version: "policy-v1",
  },
  lane_health: {
    provider_account_id: PROVIDER_ACCOUNT_ID,
    entitlement_id: ENTITLEMENT_ID,
    capacity_pool_id: CAPACITY_POOL_ID,
    owner_ref: OWNER_REF,
    adapter_key: "openai",
    adapter_version: "2026-07-10",
    state: "healthy",
    observed_at: ISSUED_AT,
  },
} as const satisfies Readonly<Record<AuthorityEvidenceType, AuthorityEvidencePayload>>;

function trustFor(type: AuthorityEvidenceType): AuthorityEvidenceTrustRoot {
  const config = TYPE_CONFIG[type];
  const issuerClass = config.issuerClass;
  return {
    issuerRef: `issuer:${issuerClass}:primary`,
    issuerClass,
    issuerIncarnation: "018f0f00-0010-7000-8000-000000000010",
    audience: AUDIENCE,
    identityRealm: REALM,
    keyId: `key-${issuerClass}-1`,
    publicKey: keysByRole[issuerClass].publicKey,
    revoked: false,
  };
}

function draftFor<T extends AuthorityEvidenceType>(
  type: T,
  payload: AuthorityEvidencePayload<T> = PAYLOADS[type] as unknown as AuthorityEvidencePayload<T>,
): AuthorityEvidenceDraft<T> {
  const config = TYPE_CONFIG[type];
  const trust = trustFor(type);
  return {
    schema_version: "accounts.authority-evidence.v1",
    evidence_type: type,
    evidence_ref: `evidence:${type}:1`,
    subject_ref: `subject:${type}:1`,
    aggregate_kind: config.aggregateKind,
    aggregate_id: config.aggregateId,
    aggregate_revision: C0,
    identity_realm: REALM,
    issuer_ref: trust.issuerRef,
    issuer_class: trust.issuerClass,
    issuer_incarnation: trust.issuerIncarnation,
    audience: trust.audience,
    key_id: trust.keyId,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    nonce: NONCE,
    evidence_generation: C1,
    payload,
  } as unknown as AuthorityEvidenceDraft<T>;
}

function expectationFor<T extends AuthorityEvidenceType>(
  type: T,
): AuthorityEvidenceExpectation<T> {
  const draft = draftFor(type);
  return {
    evidenceType: type,
    subjectRef: draft.subject_ref,
    aggregateKind: draft.aggregate_kind,
    aggregateId: draft.aggregate_id,
    aggregateRevision: draft.aggregate_revision,
    identityRealm: REALM,
    evidenceGeneration: C1,
    nonce: NONCE,
    now: NOW,
    maximumAgeMs: 60_000,
    maximumLifetimeMs: 180_000,
    binding: (() => {
      switch (type) {
        case "provider_ownership":
          return {
            providerKey: "openai",
            providerSubjectRef: "provider-subject-a",
            ownerRef: OWNER_REF,
          };
        case "provider_capacity":
          return {
            providerAccountId: PROVIDER_ACCOUNT_ID,
            providerKey: "openai",
            ownerRef: OWNER_REF,
            capacityDomainRef: "capacity-domain-primary",
            serializationKey: "serialization-primary",
            maxConcurrency: C2,
          };
        case "entitlement_execution_policy":
          return {
            providerAccountId: PROVIDER_ACCOUNT_ID,
            ownerRef: OWNER_REF,
            providerKey: "openai",
            useCase: "interactive-coding",
            adapterVersion: "2026-07-10",
          };
        case "entitlement_terms":
        case "entitlement_data_policy":
          return {
            providerAccountId: PROVIDER_ACCOUNT_ID,
            ownerRef: OWNER_REF,
            providerKey: "openai",
            useCase: "interactive-coding",
          };
        case "lane_isolation_policy":
        case "lane_execution_policy":
          return {
            providerAccountId: PROVIDER_ACCOUNT_ID,
            entitlementId: ENTITLEMENT_ID,
            capacityPoolId: CAPACITY_POOL_ID,
            ownerRef: OWNER_REF,
            adapterKey: "openai",
            adapterVersion: "2026-07-10",
            accessTransport: "api_key",
          };
        case "lane_health":
          return {
            providerAccountId: PROVIDER_ACCOUNT_ID,
            entitlementId: ENTITLEMENT_ID,
            capacityPoolId: CAPACITY_POOL_ID,
            ownerRef: OWNER_REF,
            adapterKey: "openai",
            adapterVersion: "2026-07-10",
          };
      }
    })(),
  } as AuthorityEvidenceExpectation<T>;
}

function signDraft<T extends AuthorityEvidenceType>(draft: AuthorityEvidenceDraft<T>): Uint8Array {
  const issuerClass = TYPE_CONFIG[draft.evidence_type].issuerClass;
  return signAuthorityEvidenceForTest(draft, keysByRole[issuerClass].privateKey);
}

function resignObject(value: Record<string, unknown>, privateKey: KeyObject): Uint8Array {
  const { signature: _signature, ...unsigned } = value;
  const signature = ed25519Sign(null, Buffer.from(canonicalJson(unsigned), "utf8"), privateKey)
    .toString("base64url");
  return Buffer.from(canonicalJson({ ...unsigned, signature }), "utf8");
}

function decoded(bytes: Uint8Array): Record<string, unknown> {
  return parseClosedJsonBytes(bytes) as Record<string, unknown>;
}

describe("closed Ed25519 authority evidence", () => {
  test("matches an independent Python JCS and Ed25519 golden vector byte-for-byte", () => {
    const parsed = parseClosedJsonBytes(Buffer.from(GOLDEN_WIRE)) as Record<string, unknown>;
    const { payload_digest: payloadDigest, signature: _signature, ...draft } = parsed;
    expect(canonicalJson(parsed.payload)).toBe(GOLDEN_PAYLOAD_JCS);
    expect(payloadDigest).toBe(GOLDEN_PAYLOAD_DIGEST);
    expect(
      new TextDecoder().decode(
        signAuthorityEvidenceForTest(
          draft as unknown as AuthorityEvidenceDraft<"provider_ownership">,
          goldenPrivateKey,
        ),
      ),
    ).toBe(GOLDEN_WIRE);

    const verified = verifyAuthorityEvidence(
      Buffer.from(GOLDEN_WIRE),
      {
        issuerRef: "issuer:provider-ownership:golden",
        issuerClass: "provider_ownership_verifier",
        issuerIncarnation: "018f0f00-00a2-7000-8000-0000000000a2",
        audience: AUDIENCE,
        identityRealm: REALM,
        keyId: "python-cryptography-41-golden",
        publicKey: goldenPublicKey,
        revoked: false,
      },
      {
        evidenceType: "provider_ownership",
        subjectRef: "subject:golden:provider-account",
        aggregateKind: "provider_account",
        aggregateId: "018f0f00-00a1-7000-8000-0000000000a1",
        aggregateRevision: C3,
        identityRealm: REALM,
        evidenceGeneration: C7,
        nonce: "EBESExQVFhcYGRobHB0eHyAhIiMkJSYn",
        now: NOW,
        maximumAgeMs: 60_000,
        maximumLifetimeMs: 180_000,
        binding: {
          providerKey: "openai",
          providerSubjectRef: "provider-subject-golden",
          ownerRef: "principal:human:hasna:owner-golden",
        },
      },
    );
    expect(verified.signature).toBe(
      "_FQKzHr_97q6nIG3kgEMn2zt2LysHtpW2nEBj5Y5H8jeaueYNgDXwis6EOgCoBX8cDJL0_7ZoQ2fLp5rRFM3DA",
    );
  });

  for (const type of Object.keys(TYPE_CONFIG) as AuthorityEvidenceType[]) {
    test(`verifies ${type} only against its configured issuer role and bindings`, () => {
      const bytes = signDraft(draftFor(type));
      const verified = verifyAuthorityEvidence(bytes, trustFor(type), expectationFor(type));

      expect(verified.evidence_type).toBe(type);
      expect(verified.payload).toEqual(PAYLOADS[type]);
      expect(new TextDecoder().decode(bytes)).toBe(canonicalJson(decoded(bytes)));
      expect(Object.isFrozen(verified)).toBe(true);
      expect(Object.isFrozen(verified.payload)).toBe(true);
    });
  }

  test("rejects a forged signature and a non-Ed25519 trust key", () => {
    const type = "provider_ownership";
    const bytes = signDraft(draftFor(type));
    const forged = decoded(bytes);
    const forgedSignature = Buffer.from(forged.signature as string, "base64url");
    forgedSignature[0] = forgedSignature[0]! ^ 0x01;
    forged.signature = forgedSignature.toString("base64url");
    expect(() =>
      verifyAuthorityEvidence(
        Buffer.from(canonicalJson(forged)),
        trustFor(type),
        expectationFor(type),
      ),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey;
    expect(() =>
      verifyAuthorityEvidence(bytes, { ...trustFor(type), publicKey: rsa }, expectationFor(type)),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));
  });

  test("rejects cross-role, wrong-audience, wrong-realm, and revoked trust roots", () => {
    const type = "entitlement_terms";
    const bytes = signDraft(draftFor(type));
    const valid = trustFor(type);
    for (const trust of [
      { ...valid, issuerClass: "execution_policy_authority" as const },
      { ...valid, audience: "accounts:local" },
      { ...valid, identityRealm: "outside" },
      { ...valid, issuerIncarnation: "018f0f00-0099-7000-8000-000000000099" },
      { ...valid, keyId: "key-rotated" },
      { ...valid, revoked: true },
    ]) {
      expect(() => verifyAuthorityEvidence(bytes, trust, expectationFor(type))).toThrow(
        expect.objectContaining({ code: "FORBIDDEN" }),
      );
    }
    const { revoked: _revoked, ...missingRevocationState } = valid;
    expect(() =>
      verifyAuthorityEvidence(
        bytes,
        missingRevocationState as AuthorityEvidenceTrustRoot,
        expectationFor(type),
      ),
    ).toThrow(expect.objectContaining({ code: "FORBIDDEN" }));
  });

  test("rejects subject, aggregate, revision, generation, and payload binding mismatches", () => {
    const type = "lane_execution_policy";
    const bytes = signDraft(draftFor(type));
    const expected = expectationFor(type);
    const cases: AuthorityEvidenceExpectation<typeof type>[] = [
      { ...expected, subjectRef: "subject:other" },
      { ...expected, aggregateId: "018f0f00-0099-7000-8000-000000000099" },
      { ...expected, aggregateRevision: C1 },
      { ...expected, evidenceGeneration: C2 },
      { ...expected, nonce: Buffer.alloc(24, 8).toString("base64url") },
      { ...expected, identityRealm: "outside" },
      { ...expected, binding: { ...expected.binding, ownerRef: "principal:human:hasna:owner-b" } },
      { ...expected, binding: { ...expected.binding, adapterVersion: "other" } },
    ];
    for (const candidate of cases) {
      expect(() => verifyAuthorityEvidence(bytes, trustFor(type), candidate)).toThrow(
        expect.objectContaining({ code: "FORBIDDEN" }),
      );
    }
  });

  test("rejects expired, future-issued, over-age, and over-lifetime evidence", () => {
    const type = "lane_health";
    const validDraft = draftFor(type);
    const trust = trustFor(type);
    const expected = expectationFor(type);

    const expired = signDraft({
      ...validDraft,
      issued_at: new Date(NOW.getTime() - 120_000).toISOString(),
      expires_at: NOW.toISOString(),
      payload: { ...validDraft.payload, observed_at: new Date(NOW.getTime() - 120_000).toISOString() },
    });
    expect(() => verifyAuthorityEvidence(expired, trust, expected)).toThrow(
      expect.objectContaining({ code: "STALE_ATTESTATION" }),
    );

    const future = signDraft({
      ...validDraft,
      issued_at: new Date(NOW.getTime() + 1).toISOString(),
      expires_at: new Date(NOW.getTime() + 60_001).toISOString(),
      payload: { ...validDraft.payload, observed_at: new Date(NOW.getTime() + 1).toISOString() },
    });
    expect(() => verifyAuthorityEvidence(future, trust, expected)).toThrow(
      expect.objectContaining({ code: "STALE_ATTESTATION" }),
    );

    const tooOld = signDraft({
      ...validDraft,
      issued_at: new Date(NOW.getTime() - 60_001).toISOString(),
      payload: { ...validDraft.payload, observed_at: new Date(NOW.getTime() - 60_001).toISOString() },
    });
    expect(() => verifyAuthorityEvidence(tooOld, trust, expected)).toThrow(
      expect.objectContaining({ code: "STALE_ATTESTATION" }),
    );

    const tooLong = signDraft({
      ...validDraft,
      expires_at: new Date(NOW.getTime() + 180_001).toISOString(),
    });
    expect(() => verifyAuthorityEvidence(tooLong, trust, expected)).toThrow(
      expect.objectContaining({ code: "STALE_ATTESTATION" }),
    );
  });

  test("rejects duplicate, unknown, camelCase alias, and unknown nested fields even when signed", () => {
    const type = "provider_ownership";
    const bytes = signDraft(draftFor(type));
    const base = decoded(bytes);
    const privateKey = keysByRole.provider_ownership_verifier.privateKey;

    for (const malformed of [
      { ...base, arbitrary: true },
      { ...base, evidenceGeneration: base.evidence_generation },
      {
        ...base,
        payload: { ...(base.payload as Record<string, unknown>), ownerRef: OWNER_REF },
      },
    ]) {
      expect(() =>
        verifyAuthorityEvidence(resignObject(malformed, privateKey), trustFor(type), expectationFor(type)),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }

    const source = new TextDecoder().decode(bytes);
    const duplicate = source.replace(
      '"evidence_type":"provider_ownership"',
      '"evidence_type":"provider_ownership","evidence_type":"provider_ownership"',
    );
    expect(() =>
      verifyAuthorityEvidence(Buffer.from(duplicate), trustFor(type), expectationFor(type)),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
  });

  test("requires canonical UTF-8 JCS wire bytes and preserves exact Unicode code points", () => {
    const type = "provider_ownership";
    const composed = draftFor(type, {
      ...PAYLOADS.provider_ownership,
      provider_subject_ref: "subject-\u00e9",
    });
    const expectation = {
      ...expectationFor(type),
      binding: {
        ...expectationFor(type).binding,
        providerSubjectRef: "subject-\u00e9",
      },
    };
    const bytes = signDraft(composed);
    expect(() => verifyAuthorityEvidence(bytes, trustFor(type), expectation)).not.toThrow();

    const pretty = JSON.stringify(decoded(bytes), null, 2);
    expect(() =>
      verifyAuthorityEvidence(Buffer.from(pretty), trustFor(type), expectation),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    const decomposedExpectation = {
      ...expectation,
      binding: {
        ...expectation.binding,
        providerSubjectRef: "subject-e\u0301",
      },
    };
    expect(() => verifyAuthorityEvidence(bytes, trustFor(type), decomposedExpectation)).toThrow(
      expect.objectContaining({ code: "FORBIDDEN" }),
    );

    expect(() =>
      verifyAuthorityEvidence(
        Uint8Array.of(0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff, 0x7d),
        trustFor(type),
        expectation,
      ),
    ).toThrow(AccountsError);
  });

  test("rejects noncanonical, overflow, numeric, and malformed-Unicode counter envelopes", () => {
    const type = "provider_ownership";
    const bytes = signDraft(draftFor(type));
    const base = decoded(bytes);
    const privateKey = keysByRole.provider_ownership_verifier.privateKey;
    for (const evidenceGeneration of ["01", "9223372036854775808"]) {
      const malformed = {
        ...base,
        evidence_generation: evidenceGeneration,
        payload: {
          ...(base.payload as Record<string, unknown>),
          ownership_generation: evidenceGeneration,
        },
      };
      expect(() =>
        verifyAuthorityEvidence(
          resignObject(malformed, privateKey),
          trustFor(type),
          expectationFor(type),
        ),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }

    const source = new TextDecoder().decode(bytes);
    for (const malformed of [
      source.replace('"aggregate_revision":"0"', '"aggregate_revision":1.0'),
      source.replace('"evidence_generation":"1"', '"evidence_generation":9007199254740993'),
      source.replace('"evidence_ref":"evidence:provider_ownership:1"', '"evidence_ref":"\\ud800"'),
    ]) {
      expect(() =>
        verifyAuthorityEvidence(Buffer.from(malformed), trustFor(type), expectationFor(type)),
      ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    }
  });

  test("rejects a validly signed payload whose digest no longer matches", () => {
    const type = "entitlement_terms";
    const base = decoded(signDraft(draftFor(type)));
    const payload = base.payload as Record<string, unknown>;
    const changed = {
      ...base,
      payload: { ...payload, decision: "denied" },
    };
    const resigned = resignObject(changed, keysByRole.terms_authority.privateKey);
    expect(() => verifyAuthorityEvidence(resigned, trustFor(type), expectationFor(type))).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
  });

  test("test signer refuses wrong-role drafts and non-Ed25519 private keys", () => {
    const draft = draftFor("entitlement_terms");
    const wrongRoleDraft = {
      ...draft,
      issuer_class: "execution_policy_authority" as const,
    };
    expect(() =>
      signAuthorityEvidenceForTest(
        wrongRoleDraft as unknown as AuthorityEvidenceDraft<"entitlement_terms">,
        keysByRole.execution_policy_authority.privateKey,
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));

    const rsaPrivate = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
    expect(() => signAuthorityEvidenceForTest(draft, rsaPrivate)).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
  });
});
