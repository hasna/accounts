import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import {
  MAX_ARCHIVE_ENTRIES,
  MAX_ARCHIVE_ENTRY_BYTES,
  MAX_ARCHIVE_UNPACKED_BYTES,
  MAX_JSON_BYTES,
  MAX_TARBALL_BYTES,
  PUBLISH_PREDICATE,
  PROVENANCE_PREDICATE,
  RELEASE_BUN_VERSION,
  RELEASE_NODE_VERSION,
  RELEASE_NPM_VERSION,
  RELEASE_WORKFLOW,
  assertDeterministicPacks,
  assertExactCliVersion,
  assertFinalPromotionVersion,
  assertGitEvidence,
  assertPromotionSnapshotUnchanged,
  assertPromotionVersion,
  assertTrustedPublishEnvironment,
  expectedSigstoreIdentity,
  extractVerifiedAttestations,
  packagePurl,
  parseRetryOptions,
  readLimited,
  releaseTag,
  repositorySlug,
  stagingDistTag,
  verifyArchive,
  verifyAttestations,
  verifyDistTags,
  verifyDownloadedTarball,
  verifyReleaseEnvironment,
  verifyRegistryMetadata,
  verifyReleaseRulesets,
  verifySigstoreBundle,
  type PackResult,
  type ReleaseCandidate,
} from "./release-provenance";

const manifest = {
  name: "@hasna/accounts",
  version: "0.3.0",
  repository: { url: "git+https://github.com/hasna/accounts.git" },
  publishConfig: { registry: "https://registry.npmjs.org", access: "public" },
};
const digest = Buffer.alloc(64, 0xab);
const candidate: ReleaseCandidate = {
  schema: "hasna.accounts.release-candidate/v3",
  name: manifest.name,
  version: manifest.version,
  tag: "npm/accounts/v0.3.0",
  commit: "0123456789abcdef0123456789abcdef01234567",
  repository: "hasna/accounts",
  workflow: RELEASE_WORKFLOW,
  integrity: `sha512-${digest.toString("base64")}`,
  shasum: "1234567890abcdef1234567890abcdef12345678",
  filename: "hasna-accounts-0.3.0.tgz",
  size: 300,
  fileCount: 2,
  unpackedBytes: 300,
  artifactPath: "/tmp/release-candidate.tgz",
  stagingTag: "release-candidate-0.3.0",
  intendedTag: "latest",
};

function attestation(
  predicateType: string,
  predicate: Record<string, unknown>,
  options: { subject?: string; signed?: boolean } = {},
) {
  const payload = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{
      name: options.subject ?? packagePurl(candidate.name, candidate.version),
      digest: { sha512: digest.toString("hex") },
    }],
    predicateType,
    predicate,
  };
  return {
    predicateType,
    bundle: {
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
      verificationMaterial: {
        certificate: { rawBytes: "synthetic-fixture" },
        tlogEntries: [{ logIndex: "1", integratedTime: "2" }],
      },
      dsseEnvelope: {
        payload: Buffer.from(JSON.stringify(payload)).toString("base64"),
        payloadType: "application/vnd.in-toto+json",
        signatures: options.signed === false ? [] : [{ sig: "synthetic-after-npm-audit-fixture" }],
      },
    },
  };
}

function attestations(options: {
  commit?: string;
  repository?: string;
  workflow?: string;
  tag?: string;
  subject?: string;
  signed?: boolean;
  publishName?: string;
} = {}) {
  return [
    attestation(PUBLISH_PREDICATE, {
      name: options.publishName ?? candidate.name,
      version: candidate.version,
      registry: "https://registry.npmjs.org",
    }, options),
    attestation(PROVENANCE_PREDICATE, {
      buildDefinition: {
        externalParameters: { workflow: {
          ref: `refs/tags/${options.tag ?? candidate.tag}`,
          repository: `https://github.com/${options.repository ?? candidate.repository}`,
          path: options.workflow ?? candidate.workflow,
        } },
        resolvedDependencies: [{
          digest: { gitCommit: options.commit ?? candidate.commit },
        }],
      },
    }, options),
  ];
}

function auditResult(bundles = attestations()) {
  return {
    invalid: [],
    missing: [],
    verified: [{
      name: candidate.name,
      version: candidate.version,
      location: `node_modules/${candidate.name}`,
      attestationBundles: bundles,
    }],
  };
}

function pack(integrity = candidate.integrity): PackResult {
  return {
    name: candidate.name,
    version: candidate.version,
    filename: candidate.filename,
    integrity,
    shasum: candidate.shasum,
    size: candidate.size,
    files: [
      { path: "dist/cli.js", size: 100, mode: 0o644 },
      { path: "package.json", size: 200, mode: 0o644 },
    ],
  };
}

function ruleset(ruleTypes = ["creation", "update", "deletion"]) {
  return {
    id: 19_812_295,
    name: "protect-npm-accounts-release-tags",
    target: "tag",
    enforcement: "active",
    bypass_actors: [{
      actor_id: null,
      actor_type: "OrganizationAdmin",
      bypass_mode: "always",
    }],
    conditions: {
      ref_name: {
        include: ["refs/tags/npm/accounts/v*"],
        exclude: [],
      },
    },
    rules: ruleTypes.map((type) => ({ type })),
  };
}

function tarEntry(
  path: string,
  size: number,
  type = "0",
  content = Buffer.alloc(size),
): Buffer {
  const header = Buffer.alloc(512);
  const writeText = (value: string, offset: number, length: number) => {
    header.write(value, offset, Math.min(Buffer.byteLength(value), length), "utf8");
  };
  const writeOctal = (value: number, offset: number, length: number) => {
    const encoded = value.toString(8).padStart(length - 1, "0");
    writeText(`${encoded}\0`, offset, length);
  };
  writeText(path, 0, 100);
  writeOctal(0o644, 100, 8);
  writeOctal(0, 108, 8);
  writeOctal(0, 116, 8);
  writeOctal(size, 124, 12);
  writeOctal(0, 136, 12);
  header.fill(0x20, 148, 156);
  writeText(type, 156, 1);
  writeText("ustar\0", 257, 6);
  writeText("00", 263, 2);
  writeText(`${header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, "0")}\0 `, 148, 8);
  const body = type === "0"
    ? Buffer.concat([content, Buffer.alloc((512 - (content.length % 512)) % 512)])
    : Buffer.alloc(0);
  return Buffer.concat([header, body]);
}

function archive(entries: Array<ReturnType<typeof tarEntry>>): Buffer {
  return gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
}

test("derives package-owned repository, release tag, staging tag, and purl", () => {
  expect(repositorySlug(manifest)).toBe("hasna/accounts");
  expect(releaseTag(manifest)).toBe(candidate.tag);
  expect(stagingDistTag(manifest.version)).toBe(candidate.stagingTag);
  expect(packagePurl(manifest.name, manifest.version)).toBe("pkg:npm/%40hasna/accounts@0.3.0");
});

test("accepts only the exact tokenless protected GitHub OIDC workflow and pinned toolchain", () => {
  const env = {
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF: `refs/tags/${candidate.tag}`,
    GITHUB_REF_TYPE: "tag",
    GITHUB_REF_NAME: candidate.tag,
    GITHUB_REF_PROTECTED: "true",
    GITHUB_REPOSITORY: candidate.repository,
    GITHUB_WORKFLOW_REF: `${candidate.repository}/${RELEASE_WORKFLOW}@refs/tags/${candidate.tag}`,
    GITHUB_SHA: candidate.commit,
    NPM_DIST_TAG_TOKEN_CONFIGURED: "true",
    RELEASE_GITHUB_ADMIN_TOKEN_CONFIGURED: "true",
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://example.invalid/oidc",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "present",
  };
  const tools = {
    node: `v${RELEASE_NODE_VERSION}`,
    npm: RELEASE_NPM_VERSION,
    bun: RELEASE_BUN_VERSION,
  };
  expect(() => assertTrustedPublishEnvironment(manifest, env, tools)).not.toThrow();
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    GITHUB_REF_NAME: "v0.3.0",
  }, tools)).toThrow("GITHUB_REF_NAME");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    GITHUB_REF_PROTECTED: "false",
  }, tools)).toThrow("GITHUB_REF_PROTECTED");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    NPM_TOKEN: "forbidden",
  }, tools)).toThrow("long-lived npm publish tokens");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    NPM_DIST_TAG_TOKEN_CONFIGURED: "false",
  }, tools)).toThrow("NPM_DIST_TAG_TOKEN is not configured");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    RELEASE_GITHUB_ADMIN_TOKEN_CONFIGURED: "false",
  }, tools)).toThrow("RELEASE_GITHUB_ADMIN_TOKEN is not configured");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    "NPM_CONFIG_//REGISTRY.NPMJS.ORG/:_AUTHTOKEN": "forbidden",
  }, tools)).toThrow("long-lived npm publish tokens");
  expect(() => assertTrustedPublishEnvironment(manifest, env, {
    ...tools,
    npm: "11.16.1",
  })).toThrow(`npm ${RELEASE_NPM_VERSION}`);
  expect(() => assertTrustedPublishEnvironment(manifest, env, {
    ...tools,
    node: "v24.18.1",
  })).toThrow(`Node ${RELEASE_NODE_VERSION}`);
  expect(() => assertTrustedPublishEnvironment(manifest, env, {
    ...tools,
    bun: "1.3.15",
  })).toThrow(`Bun ${RELEASE_BUN_VERSION}`);
});

test("rejects changed deterministic metadata and changed preserved bytes", () => {
  const bytes = Buffer.from("same candidate bytes");
  expect(() => assertDeterministicPacks(pack(), pack(), bytes, bytes)).not.toThrow();
  expect(() => assertDeterministicPacks(
    pack(),
    pack(`sha512-${Buffer.alloc(64, 1).toString("base64")}`),
  )).toThrow("different artifacts");
  expect(() => assertDeterministicPacks(
    pack(),
    pack(),
    bytes,
    Buffer.from("changed candidate bytes"),
  )).toThrow("different tarball bytes");
});

test("requires an annotated, present, clean tag on origin/main", () => {
  const evidence = {
    head: candidate.commit,
    tagObjectType: "tag",
    tagCommit: candidate.commit,
    mainContainsCommit: true,
    status: "",
  };
  expect(() => assertGitEvidence(manifest, candidate.commit, evidence)).not.toThrow();
  expect(() => assertGitEvidence(manifest, candidate.commit, {
    ...evidence,
    tagObjectType: undefined,
  })).toThrow("is missing");
  expect(() => assertGitEvidence(manifest, candidate.commit, {
    ...evidence,
    tagObjectType: "commit",
  })).toThrow("is not annotated");
  expect(() => assertGitEvidence(manifest, candidate.commit, {
    ...evidence,
    tagCommit: "f".repeat(40),
  })).toThrow("does not resolve to HEAD");
  expect(() => assertGitEvidence(manifest, candidate.commit, {
    ...evidence,
    mainContainsCommit: false,
  })).toThrow("not contained in origin/main");
  expect(() => assertGitEvidence(manifest, candidate.commit, {
    ...evidence,
    status: "?? unexpected",
  })).toThrow("checkout is dirty");
});

test("requires a live active release-tag ruleset with immutable restricted authority", () => {
  expect(verifyReleaseRulesets([ruleset()])).toEqual({
    id: 19_812_295,
    name: "protect-npm-accounts-release-tags",
  });
  const { bypass_actors: _hiddenByGitHub, ...readOnlyRuleset } = ruleset();
  expect(() => verifyReleaseRulesets([readOnlyRuleset])).toThrow("bypass actors are unavailable");
  expect(() => verifyReleaseRulesets([{ ...ruleset(), enforcement: "evaluate" }]))
    .toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    conditions: { ref_name: { include: ["refs/tags/v*"], exclude: [] } },
  }])).toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    conditions: {
      ref_name: {
        include: ["refs/tags/npm/accounts/v*"],
        exclude: ["refs/tags/npm/accounts/v0.3.0"],
      },
    },
  }])).toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    conditions: {
      ref_name: {
        include: ["refs/tags/npm/accounts/v*", "refs/tags/npm/other/v*"],
        exclude: [],
      },
    },
  }])).toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([ruleset(["update", "deletion"])]))
    .toThrow("exactly creation, update, and deletion");
  expect(() => verifyReleaseRulesets([ruleset(["creation", "deletion"])]))
    .toThrow("exactly creation, update, and deletion");
  expect(() => verifyReleaseRulesets([ruleset(["creation", "update"])]))
    .toThrow("exactly creation, update, and deletion");
  expect(() => verifyReleaseRulesets([{ ...ruleset(), bypass_actors: [] }]))
    .toThrow("exactly one organization-admin");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    bypass_actors: [{
      actor_id: 123,
      actor_type: "Team",
      bypass_mode: "always",
    }],
  }])).toThrow("exactly one organization-admin");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    bypass_actors: [
      ...ruleset().bypass_actors,
      {
        actor_id: 123,
        actor_type: "Team",
        bypass_mode: "always",
      },
    ],
  }])).toThrow("exactly one organization-admin");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    rules: [...ruleset().rules, { type: "required_signatures" }],
  }])).toThrow("exactly creation, update, and deletion");
});

test("requires protected release-environment reviewers and an exact tag deployment policy", () => {
  const environment = {
    name: "npm-release",
    protection_rules: [
      {
        type: "required_reviewers",
        prevent_self_review: false,
        reviewers: [{ type: "User", reviewer: { id: 123, login: "release-owner" } }],
      },
      { type: "branch_policy" },
    ],
    deployment_branch_policy: {
      protected_branches: false,
      custom_branch_policies: true,
    },
  };
  const policies = {
    total_count: 1,
    branch_policies: [{ id: 456, name: "npm/accounts/v*", type: "tag" }],
  };
  const actor = {
    permission: "admin",
    role_name: "admin",
    user: { id: 123, login: "release-owner" },
  };
  const administrationCredential = {
    identity: { id: 123, login: "release-owner" },
    permission: actor,
  };
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    administrationCredential.identity,
    administrationCredential.permission,
  )).not.toThrow();
  expect(() => verifyReleaseEnvironment({
    ...environment,
    protection_rules: [{ type: "branch_policy" }],
  }, policies, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("require reviewers");
  expect(() => verifyReleaseEnvironment({
    ...environment,
    protection_rules: [
      {
        type: "required_reviewers",
        prevent_self_review: true,
        reviewers: [{ type: "User", reviewer: { id: 123, login: "release-owner" } }],
      },
      { type: "branch_policy" },
    ],
  }, policies, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("allow the authorized reviewer");
  expect(() => verifyReleaseEnvironment({
    ...environment,
    protection_rules: [
      {
        type: "required_reviewers",
        prevent_self_review: false,
        reviewers: [{ type: "User", reviewer: { id: 999, login: "other-owner" } }],
      },
      { type: "branch_policy" },
    ],
  }, policies, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("exactly match the live release actor");
  expect(() => verifyReleaseEnvironment(environment, policies, {
    ...actor,
    permission: "write",
  }, administrationCredential.identity, administrationCredential.permission))
    .toThrow("repository admin permission");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/v*", type: "branch" }],
  }, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/*", type: "tag" }],
  }, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    total_count: 2,
    branch_policies: [
      { id: 456, name: "npm/accounts/v*", type: "tag" },
      { id: 789, name: "main", type: "branch" },
    ],
  }, actor, administrationCredential.identity, administrationCredential.permission))
    .toThrow("exactly one deployment tag policy");
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    { id: 999, login: "other-admin" },
    { permission: "admin", user: { id: 999, login: "other-admin" } },
  )).toThrow("administration credential must belong to the release actor");
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    administrationCredential.identity,
    { ...administrationCredential.permission, permission: "write" },
  )).toThrow("administration credential needs repository admin read authority");
});

test("allows only advancing or exact-idempotent semantic promotion", () => {
  expect(assertPromotionVersion("1.2.3", undefined)).toBe("advance");
  expect(assertPromotionVersion("1.2.3", "1.2.3")).toBe("idempotent");
  expect(assertPromotionVersion("1.2.3", "1.2.2")).toBe("advance");
  expect(() => assertPromotionVersion("1.2.3", "1.2.4")).toThrow("stale or downgrade");
  expect(() => assertPromotionVersion("1.2.3-beta.1", "1.2.3-alpha.9"))
    .toThrow("prerelease");
  expect(() => assertPromotionVersion("2.0.0-rc.1", "1.9.9")).toThrow("prerelease");
  expect(() => assertPromotionVersion("2.0.0-rc.1", undefined)).toThrow("prerelease");
  expect(() => assertPromotionVersion("1.2.3-alpha.9", "1.2.3-beta.1")).toThrow("prerelease");
  expect(() => assertPromotionVersion("1.2.3+two", "1.2.3+one"))
    .toThrow("does not advance semantic precedence");
  expect(() => assertPromotionVersion("not-semver", "1.2.3")).toThrow("valid SemVer");
  expect(() => assertPromotionVersion("1.2.3", "not-semver")).toThrow("registry latest");
  expect(() => assertFinalPromotionVersion("1.2.3", "1.2.3")).not.toThrow();
  expect(() => assertFinalPromotionVersion("1.2.3", "1.2.4"))
    .toThrow("stale or downgrade");
  expect(() => assertFinalPromotionVersion("1.2.3", "1.2.2"))
    .toThrow("registry latest changed during promotion");
  expect(() => assertFinalPromotionVersion("1.2.3", undefined))
    .toThrow("registry latest changed during promotion");
});

test("fails closed when registry latest changes immediately before mutation", () => {
  expect(() => assertPromotionSnapshotUnchanged(undefined, undefined)).not.toThrow();
  expect(() => assertPromotionSnapshotUnchanged("1.2.2", "1.2.2")).not.toThrow();
  expect(() => assertPromotionSnapshotUnchanged(undefined, "1.2.2"))
    .toThrow("changed immediately before promotion");
  expect(() => assertPromotionSnapshotUnchanged("1.2.2", "1.2.3"))
    .toThrow("changed immediately before promotion");
  expect(() => assertPromotionSnapshotUnchanged("1.2.2", undefined))
    .toThrow("changed immediately before promotion");
});

test("pins the exact Fulcio workflow SAN and OIDC issuer for cryptographic verification", async () => {
  const policy = expectedSigstoreIdentity(candidate);
  expect(policy).toEqual({
    certificateIdentityURI:
      "^https://github\\.com/hasna/accounts/\\.github/workflows/release\\.yml@refs/tags/npm/accounts/v0\\.3\\.0$",
    certificateIssuer: "https://token.actions.githubusercontent.com",
  });
  const otherRepository = expectedSigstoreIdentity({
    ...candidate,
    repository: "attacker/accounts",
  });
  expect(otherRepository.certificateIdentityURI).not.toBe(policy.certificateIdentityURI);
  const otherTag = expectedSigstoreIdentity({
    ...candidate,
    tag: "npm/accounts/v9.9.9",
  });
  expect(otherTag.certificateIdentityURI).not.toBe(policy.certificateIdentityURI);
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: "verified-fixture" },
      tlogEntries: [{
        logIndex: "1",
        integratedTime: "2",
      }],
    },
    dsseEnvelope: {
      payload: "e30=",
      payloadType: "application/vnd.in-toto+json",
      signatures: [{ sig: "cryptographic-fixture" }],
    },
  };
  let calls = 0;
  await verifySigstoreBundle(candidate, bundle, async (received, options) => {
    calls++;
    expect(received).toBe(bundle);
    expect(options).toEqual({
      ...policy,
      ctLogThreshold: 1,
      tlogThreshold: 1,
    });
  });
  expect(calls).toBe(1);
  await expect(verifySigstoreBundle(candidate, {
    ...bundle,
    verificationMaterial: { tlogEntries: [] },
  }, async () => {})).rejects.toThrow("Fulcio certificate");
  await expect(verifySigstoreBundle(candidate, bundle, async (_received, options) => {
    if (options?.certificateIdentityURI !== policy.certificateIdentityURI) {
      throw new Error("other valid Fulcio identity rejected");
    }
    throw new Error("other valid signature rejected");
  })).rejects.toThrow("other valid signature rejected");
});

test("requires registry source, integrity, and advertised provenance agreement", () => {
  const metadata = {
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
    dist: {
      integrity: candidate.integrity,
      shasum: candidate.shasum,
      fileCount: candidate.fileCount,
      unpackedSize: candidate.unpackedBytes,
      tarball: "https://registry.npmjs.org/@hasna/accounts/-/accounts-0.3.0.tgz",
      attestations: {
        url: "https://registry.npmjs.org/-/npm/v1/attestations/@hasna%2faccounts@0.3.0",
        provenance: { predicateType: PROVENANCE_PREDICATE },
      },
    },
  };
  expect(() => verifyRegistryMetadata(candidate, metadata)).not.toThrow();
  expect(() => verifyRegistryMetadata(candidate, { ...metadata, gitHead: "f".repeat(40) }))
    .toThrow("gitHead");
  expect(() => verifyRegistryMetadata(candidate, {
    ...metadata,
    dist: { ...metadata.dist, integrity: "sha512-wrong" },
  })).toThrow("integrity");
  expect(() => verifyRegistryMetadata(candidate, {
    ...metadata,
    dist: { ...metadata.dist, fileCount: 99 },
  })).toThrow("fileCount");
  expect(() => verifyRegistryMetadata(candidate, {
    ...metadata,
    dist: { ...metadata.dist, unpackedSize: 999 },
  })).toThrow("unpackedSize");
  expect(() => verifyRegistryMetadata(candidate, {
    ...metadata,
    dist: { ...metadata.dist, attestations: undefined },
  })).toThrow("registry attestations");
  expect(() => verifyRegistryMetadata(candidate, {
    ...metadata,
    dist: {
      ...metadata.dist,
      attestations: {
        ...metadata.dist.attestations,
        url: "https://registry.npmjs.org/-/npm/v1/attestations/@hasna%2fother@0.3.0",
      },
    },
  })).toThrow("attestations URL disagrees");
});

test("keeps staging and intended dist-tags separated until promotion and equal afterward", () => {
  const staged = {
    "dist-tags": {
      [candidate.stagingTag]: candidate.version,
      [candidate.intendedTag]: "0.2.12",
    },
  };
  expect(() => verifyDistTags(candidate, staged, "staged")).not.toThrow();
  expect(() => verifyDistTags(candidate, staged, "promoted")).toThrow("does not agree");
  const promoted = {
    "dist-tags": {
      [candidate.stagingTag]: candidate.version,
      [candidate.intendedTag]: candidate.version,
    },
  };
  expect(() => verifyDistTags(candidate, promoted, "promoted")).not.toThrow();
  expect(() => verifyDistTags(candidate, promoted, "staged")).toThrow("promoted before");
  expect(() => verifyDistTags(candidate, {
    "dist-tags": { [candidate.intendedTag]: candidate.version },
  }, "promoted")).toThrow(candidate.stagingTag);
});

test("trusts only the exact package bundles returned by successful npm signature audit", () => {
  expect(extractVerifiedAttestations(candidate, auditResult())).toHaveLength(2);
  expect(() => extractVerifiedAttestations(candidate, {
    ...auditResult(),
    invalid: [{ name: candidate.name }],
  })).toThrow("invalid signatures");
  expect(() => extractVerifiedAttestations(candidate, {
    ...auditResult(),
    missing: [{ name: candidate.name }],
  })).toThrow("missing signatures");
  expect(() => extractVerifiedAttestations(candidate, {
    invalid: [],
    missing: [],
    verified: [],
  })).toThrow("did not cryptographically verify");
});

test("rejects unsigned synthetic bundles before trusting semantic provenance claims", () => {
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ signed: false }))),
  )).toThrow("unsigned DSSE bundle");
});

test("binds audited attestations to exact subject, workflow, repository, tag, and commit", () => {
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult()),
  )).not.toThrow();
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ commit: "f".repeat(40) }))),
  )).toThrow("bind the release commit");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ repository: "attacker/repo" }))),
  )).toThrow("workflow, repository, or tag");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ workflow: ".github/workflows/other.yml" }))),
  )).toThrow("workflow, repository, or tag");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ tag: "npm/accounts/v9.9.9" }))),
  )).toThrow("workflow, repository, or tag");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ subject: "pkg:npm/attacker@9.9.9" }))),
  )).toThrow("attestation subject");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ publishName: "@hasna/other" }))),
  )).toThrow("publish attestation");
});

test("requires exact gitHead in the preserved and downloaded tarball manifest", () => {
  const manifestBytes = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const bytes = archive([
    tarEntry("package/exact.txt", 5, "0", Buffer.from("exact")),
    tarEntry("package/package.json", manifestBytes.length, "0", manifestBytes),
  ]);
  const exactCandidate = {
    ...candidate,
    size: bytes.length,
    fileCount: 2,
    unpackedBytes: 5 + manifestBytes.length,
    shasum: createHash("sha1").update(bytes).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
  };
  expect(() => verifyDownloadedTarball(exactCandidate, bytes)).not.toThrow();

  const missingManifestBytes = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
  }));
  const missingGitHead = archive([
    tarEntry("package/exact.txt", 5, "0", Buffer.from("exact")),
    tarEntry(
      "package/package.json",
      missingManifestBytes.length,
      "0",
      missingManifestBytes,
    ),
  ]);
  const missingGitHeadCandidate = {
    ...candidate,
    size: missingGitHead.length,
    fileCount: 2,
    unpackedBytes: 5 + missingManifestBytes.length,
    shasum: createHash("sha1").update(missingGitHead).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(missingGitHead).digest("base64")}`,
  };
  expect(() => verifyDownloadedTarball(missingGitHeadCandidate, missingGitHead))
    .toThrow("gitHead");

  const wrongManifestBytes = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: "f".repeat(40),
  }));
  const wrongGitHead = archive([
    tarEntry("package/exact.txt", 5, "0", Buffer.from("exact")),
    tarEntry("package/package.json", wrongManifestBytes.length, "0", wrongManifestBytes),
  ]);
  const wrongGitHeadCandidate = {
    ...candidate,
    size: wrongGitHead.length,
    fileCount: 2,
    unpackedBytes: 5 + wrongManifestBytes.length,
    shasum: createHash("sha1").update(wrongGitHead).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(wrongGitHead).digest("base64")}`,
  };
  expect(() => verifyDownloadedTarball(wrongGitHeadCandidate, wrongGitHead))
    .toThrow("gitHead");

  expect(() => verifyDownloadedTarball(exactCandidate, Buffer.from("the altered registry tarball")))
    .toThrow("size differs");
  const sameSizeChanged = Buffer.from(bytes);
  sameSizeChanged[0] ^= 0xff;
  expect(() => verifyDownloadedTarball(exactCandidate, sameSizeChanged))
    .toThrow("differs from the reviewed pack");
});

test("bounds archive entries, individual bytes, total bytes, paths, and entry types", () => {
  const exact = archive([
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
    tarEntry("package/package.json", 2, "0", Buffer.from("{}")),
  ]);
  expect(verifyArchive(exact)).toEqual({
    fileCount: 2,
    unpackedBytes: 5,
    files: [
      { path: "dist/cli.js", size: 3 },
      { path: "package.json", size: 2 },
    ],
  });
  expect(() => verifyArchive(archive([
    tarEntry("package/../escape", 1, "0", Buffer.from("x")),
  ]))).toThrow("unsafe archive path");
  expect(() => verifyArchive(archive([
    tarEntry("/absolute", 1, "0", Buffer.from("x")),
  ]))).toThrow("unsafe archive path");
  expect(() => verifyArchive(archive([
    tarEntry("package/link", 0, "2"),
  ]))).toThrow("unsupported archive entry type");
  expect(() => verifyArchive(archive([
    tarEntry("package/huge", MAX_ARCHIVE_ENTRY_BYTES + 1),
  ]))).toThrow("individual entry");
  expect(() => verifyArchive(archive([
    tarEntry("package/one", MAX_ARCHIVE_ENTRY_BYTES),
    tarEntry("package/two", MAX_ARCHIVE_ENTRY_BYTES),
    tarEntry("package/three", MAX_ARCHIVE_ENTRY_BYTES),
    tarEntry("package/four", MAX_ARCHIVE_ENTRY_BYTES),
    tarEntry("package/five", 1),
  ]))).toThrow("total unpacked");
  expect(() => verifyArchive(archive(
    Array.from({ length: MAX_ARCHIVE_ENTRIES + 1 }, (_, index) =>
      tarEntry(`package/f${index}`, 0)
    ),
  ))).toThrow("entry count");
});

test("requires the exact installed CLI version", () => {
  expect(() => assertExactCliVersion(candidate, "0.3.0\n")).not.toThrow();
  expect(() => assertExactCliVersion(candidate, "0.2.12\n")).toThrow("accounts --version");
  expect(() => assertExactCliVersion(candidate, "")).toThrow("<empty>");
});

test("caps retry, response, and tarball resource use", async () => {
  expect(parseRetryOptions("4", "5000")).toEqual({ attempts: 4, delayMs: 5000 });
  expect(() => parseRetryOptions("7", "5000")).toThrow("between 1 and 6");
  expect(() => parseRetryOptions("4", "10001")).toThrow("between 0 and 10000");
  expect(() => parseRetryOptions("6", "20000")).toThrow();
  expect(MAX_JSON_BYTES).toBe(8 * 1024 * 1024);
  expect(MAX_TARBALL_BYTES).toBe(32 * 1024 * 1024);
  expect(MAX_ARCHIVE_ENTRIES).toBe(512);
  expect(MAX_ARCHIVE_ENTRY_BYTES).toBe(16 * 1024 * 1024);
  expect(MAX_ARCHIVE_UNPACKED_BYTES).toBe(64 * 1024 * 1024);
  expect(await readLimited(new Response("1234"), 4)).toEqual(Buffer.from("1234"));
  await expect(readLimited(new Response("12345"), 4)).rejects.toThrow("exceeds 4 bytes");
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("123"));
      controller.enqueue(new TextEncoder().encode("45"));
      controller.close();
    },
  });
  await expect(readLimited(new Response(stream), 4)).rejects.toThrow("exceeds 4 bytes");
});

test("release workflow publishes one preserved tarball under staging before promotion", () => {
  const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  const implementation = readFileSync(
    new URL("./release-provenance.ts", import.meta.url),
    "utf8",
  );
  const promotionImplementation = implementation.slice(
    implementation.indexOf("async function promoteDistTag("),
    implementation.indexOf("function option("),
  );
  expect(workflow).toContain('tags:\n      - "npm/accounts/v*"');
  expect(workflow).toContain("group: hasna-accounts-npm-release");
  expect(workflow).not.toContain("group: release-${{ github.ref }}");
  expect(workflow).toContain("id-token: write");
  expect(workflow).toContain("RELEASE_GITHUB_ADMIN_TOKEN_CONFIGURED");
  expect(workflow).toContain("RELEASE_GITHUB_ADMIN_TOKEN: ${{ secrets.RELEASE_GITHUB_ADMIN_TOKEN }}");
  expect(
    workflow.match(/RELEASE_GITHUB_ADMIN_TOKEN: \$\{\{ secrets\.RELEASE_GITHUB_ADMIN_TOKEN \}\}/g),
  ).toHaveLength(3);
  expect(workflow).toContain("bun run test:provenance-crypto");
  expect(workflow).toContain(`node-version: "${RELEASE_NODE_VERSION}"`);
  expect(workflow).toContain(`bun-version: "${RELEASE_BUN_VERSION}"`);
  expect(workflow).toContain(`npm_version="$(npm --version)"`);
  expect(workflow).toContain(`[[ "$npm_version" == "${RELEASE_NPM_VERSION}" ]]`);
  expect(workflow).toContain("--artifact \"$RUNNER_TEMP/release-candidate.tgz\"");
  expect(workflow).toContain("release-provenance.ts publish-staged");
  expect(workflow).toContain("release-provenance.ts verify-registry");
  expect(workflow).toContain("--phase staged");
  expect(workflow).toContain("release-provenance.ts promote");
  expect(workflow).toContain("--phase promoted");
  expect(workflow).not.toContain("npm publish --provenance --access public");
  expect(workflow).not.toMatch(/uses:\s+\S+@v\d/);
  expect(workflow).not.toContain("bun-version: latest");
  expect(workflow).not.toContain('node-version: "24.x"');
  expect(
    promotionImplementation.match(/await fetchJson\(packageUrl\(value\.name\)\)/g),
  ).toHaveLength(3);
  expect(promotionImplementation).toContain("assertPromotionSnapshotUnchanged(");
});

test("package lifecycle rejects direct publication outside the preserved-artifact wrapper", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { scripts: Record<string, string> };
  expect(packageJson.scripts.prepublishOnly).toContain("reject-direct-publish");
  expect(packageJson.scripts["test:provenance-crypto"])
    .toBe("node scripts/verify-sigstore-smoke.mjs");
  expect(packageJson.scripts["verify:pack"]).toContain("release-provenance.ts pack");
  expect(packageJson.devDependencies.semver).toBe("7.7.2");
  expect(packageJson.devDependencies["@sigstore/bundle"]).toBe("4.0.0");
  expect(packageJson.devDependencies["@sigstore/protobuf-specs"]).toBe("0.5.1");
  expect(packageJson.devDependencies["@sigstore/verify"]).toBe("3.1.1");
  expect(packageJson.devDependencies.sigstore).toBeUndefined();
});
