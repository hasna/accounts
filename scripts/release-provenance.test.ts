import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import {
  BREAK_GLASS_ENV,
  BREAK_GLASS_MIN_REASON_LENGTH,
  BREAK_GLASS_REASON_ENV,
  BREAK_GLASS_TOKEN,
  MAX_ARCHIVE_ENTRIES,
  MAX_ARCHIVE_ENTRY_BYTES,
  MAX_ARCHIVE_UNPACKED_BYTES,
  MAX_JSON_BYTES,
  MAX_PROMOTION_ATTEMPTS,
  MAX_TARBALL_BYTES,
  PUBLISH_PREDICATE,
  PROVENANCE_PREDICATE,
  RELEASE_BUN_VERSION,
  RELEASE_NODE_VERSION,
  RELEASE_NPM_VERSION,
  RELEASE_WORKFLOW,
  assertDeterministicPacks,
  assertExactCliVersion,
  assertFinalMonotonicPromotion,
  assertFinalPromotionVersion,
  assertGitEvidence,
  assertPromotionSnapshotUnchanged,
  assertPromotionVersion,
  assertTrustedPublishEnvironment,
  createOriginPackumentReader,
  evaluateDirectPublish,
  expectedSigstoreIdentity,
  extractVerifiedAttestations,
  originIntentPackumentUrl,
  packagePurl,
  parseRetryOptions,
  promoteLatestMonotonically,
  readLimited,
  registryPromotionSnapshot,
  releaseTag,
  repositorySlug,
  stagingDistTag,
  verifyArchive,
  verifyAttestations,
  verifyDistTags,
  verifyDownloadedTarball,
  verifyReleaseEnvironment,
  verifyRegistryMetadata,
  verifyRegistryReleaseAttempt,
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
  options: {
    subject?: string;
    signed?: boolean;
    payloadType?: string;
    statementType?: string;
    omitStatementType?: boolean;
  } = {},
) {
  const payload = {
    ...(options.omitStatementType
      ? {}
      : { _type: options.statementType ?? "https://in-toto.io/Statement/v1" }),
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
        payloadType: options.payloadType ?? "application/vnd.in-toto+json",
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
  payloadType?: string;
  statementType?: string;
  omitStatementType?: boolean;
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

function registryPackage(
  latest: string | undefined,
  versions: string[],
  value: ReleaseCandidate = candidate,
  extraTags: Record<string, string> = {},
): Record<string, unknown> {
  return {
    name: value.name,
    "dist-tags": {
      [value.stagingTag]: value.version,
      ...extraTags,
      ...(latest === undefined ? {} : { latest }),
    },
    versions: Object.fromEntries(
      versions.map((version) => [version, { name: value.name, version }]),
    ),
  };
}

function registryVersionMetadata(value: ReleaseCandidate): Record<string, unknown> {
  return {
    name: value.name,
    version: value.version,
    gitHead: value.commit,
    dist: {
      integrity: value.integrity,
      shasum: value.shasum,
      fileCount: value.fileCount,
      unpackedSize: value.unpackedBytes,
      tarball: `https://registry.npmjs.org/@hasna/accounts/-/accounts-${value.version}.tgz`,
      attestations: {
        url:
          `https://registry.npmjs.org/-/npm/v1/attestations/@hasna%2faccounts@${value.version}`,
        provenance: { predicateType: PROVENANCE_PREDICATE },
      },
    },
  };
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
    // Shaped as `administration: read` actually returns it — measured on the
    // live ruleset: `current_user_can_bypass` present, `bypass_actors` absent.
    // The fixture must match the credential the release actually uses, or it
    // asserts a response the workflow can never receive.
    current_user_can_bypass: "never",
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
    RELEASE_APP_ID_CONFIGURED: "true",
    RELEASE_APP_PRIVATE_KEY_CONFIGURED: "true",
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
    RELEASE_APP_ID_CONFIGURED: "false",
  }, tools)).toThrow("RELEASE_APP_ID is not configured");
  expect(() => assertTrustedPublishEnvironment(manifest, {
    ...env,
    RELEASE_APP_PRIVATE_KEY_CONFIGURED: "false",
  }, tools)).toThrow("RELEASE_APP_PRIVATE_KEY is not configured");
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
  // GitHub withholds the bypass posture without administration-read authority.
  const { current_user_can_bypass: _withheld, ...withoutPosture } = ruleset();
  expect(() => verifyReleaseRulesets([withoutPosture]))
    .toThrow("bypass posture is unavailable");
  // A credential that CAN bypass the ruleset it is certifying is rejected —
  // this is the check that replaced the bypass_actors enumeration, and it is
  // the one a read-only credential can honestly make.
  expect(() => verifyReleaseRulesets([{ ...ruleset(), current_user_can_bypass: "always" }]))
    .toThrow("must not be able to bypass");
  expect(() => verifyReleaseRulesets([{ ...ruleset(), current_user_can_bypass: "pull_request" }]))
    .toThrow("must not be able to bypass");
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
  // A stray `bypass_actors` in the payload must not resurrect the old
  // enumeration or change the verdict: the release no longer decides on it,
  // and an extra field is not a reason to pass or fail.
  expect(verifyReleaseRulesets([{
    ...ruleset(),
    bypass_actors: [{ actor_id: 123, actor_type: "Team", bypass_mode: "always" }],
  }])).toEqual({ id: 19_812_295, name: "protect-npm-accounts-release-tags" });
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
  // The administration credential is an App installation token minted per run.
  // It has no user identity — `GET /user` is 403 for any installation token —
  // so the binding asserted is its SCOPE: exactly this one repository.
  const repository = "hasna/accounts";
  const administrationScope = {
    total_count: 1,
    repositories: [{ id: 1, full_name: "hasna/accounts" }],
  };
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    administrationScope,
    repository,
  )).not.toThrow();
  expect(() => verifyReleaseEnvironment({
    ...environment,
    protection_rules: [{ type: "branch_policy" }],
  }, policies, actor, administrationScope, repository))
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
  }, policies, actor, administrationScope, repository))
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
  }, policies, actor, administrationScope, repository))
    .toThrow("exactly match the live release actor");
  expect(() => verifyReleaseEnvironment(environment, policies, {
    ...actor,
    permission: "write",
  }, administrationScope, repository))
    .toThrow("repository admin permission");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/v*", type: "branch" }],
  }, actor, administrationScope, repository))
    .toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/*", type: "tag" }],
  }, actor, administrationScope, repository))
    .toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    total_count: 2,
    branch_policies: [
      { id: 456, name: "npm/accounts/v*", type: "tag" },
      { id: 789, name: "main", type: "branch" },
    ],
  }, actor, administrationScope, repository))
    .toThrow("exactly one deployment tag policy");
  // A credential that reaches a second repository is rejected: the whole point
  // of the scope binding is that it cannot be a broad, reusable credential.
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    {
      total_count: 2,
      repositories: [
        { id: 1, full_name: "hasna/accounts" },
        { id: 2, full_name: "hasna/todos" },
      ],
    },
    repository,
  )).toThrow("scoped to exactly one repository");
  // Correctly narrow, but narrowed to the WRONG repository.
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    { total_count: 1, repositories: [{ id: 2, full_name: "hasna/todos" }] },
    repository,
  )).toThrow("scoped to the release repository");
  // total_count and the array must agree; a truncated page must not read as narrow.
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    { total_count: 7, repositories: [{ id: 1, full_name: "hasna/accounts" }] },
    repository,
  )).toThrow("scoped to exactly one repository");
  expect(() => verifyReleaseEnvironment(
    environment,
    policies,
    actor,
    { total_count: 1 },
    repository,
  )).toThrow("must list its repositories");
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

test("final promotion verification requires the full monotonic registry state", () => {
  expect(() => assertFinalMonotonicPromotion(
    candidate,
    registryPackage(candidate.version, ["0.2.12", candidate.version]),
  )).not.toThrow();
  expect(() => assertFinalMonotonicPromotion(
    candidate,
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
  )).toThrow("highest stable is 0.4.0");
  expect(() => assertFinalMonotonicPromotion(
    candidate,
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
  )).toThrow("latest is 0.2.12");
});

test("builds a scoped origin-intent packument URL without losing existing query state", () => {
  const base = new URL(
    "https://registry.npmjs.org/%40hasna%2Faccounts?existing=a%2Fb&write=false",
  );
  const url = originIntentPackumentUrl(base, "deterministic-read-1");
  expect(url.origin).toBe("https://registry.npmjs.org");
  expect(url.pathname).toBe("/%40hasna%2Faccounts");
  expect(url.searchParams.get("existing")).toBe("a/b");
  expect(url.href).toContain("existing=a%2Fb");
  expect(url.searchParams.get("write")).toBe("true");
  expect(url.searchParams.getAll("write")).toEqual(["true"]);
  expect(url.searchParams.get("_hasna_origin_read")).toBe("deterministic-read-1");
  expect(url.username).toBe("");
  expect(url.password).toBe("");
  expect(url.hash).toBe("");

  for (const unsafe of [
    "https://registry.npmjs.org/%40hasna%2Faccounts/0.3.0",
    "https://registry.npmjs.org/%40hasna%2Faccounts/-/accounts-0.3.0.tgz",
    "https://registry.npmjs.org/%40hasna%2Faccounts#fragment",
    "https://user:password@registry.npmjs.org/%40hasna%2Faccounts",
    "https://registry.npmjs.org/%40hasna%2Faccounts?authToken=must-not-enter-a-url",
    "https://example.invalid/%40hasna%2Faccounts",
  ]) {
    expect(() => originIntentPackumentUrl(new URL(unsafe), "deterministic-read-2"))
      .toThrow("origin-intent packument");
  }
  for (const unsafeNonce of ["", "contains space", "query&injection", "x".repeat(129)]) {
    expect(() => originIntentPackumentUrl(base, unsafeNonce))
      .toThrow("origin read nonce");
  }
});

test("uses a distinct origin-intent URL at every promotion and compensation read seam", async () => {
  const responses = [
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0"]),
  ];
  const urls: URL[] = [];
  let nonce = 0;
  const readPackage = createOriginPackumentReader(candidate.name, {
    nonce: () => `promotion-seam-${++nonce}`,
    fetcher: async (url, init) => {
      urls.push(new URL(url));
      expect(init.redirect).toBe("error");
      expect(new Headers(init.headers).get("accept")).toBe("application/json");
      expect(init.signal).toBeDefined();
      const next = responses.shift();
      if (!next) throw new Error("unexpected origin read");
      return Response.json(next);
    },
  });
  const writes: string[] = [];

  await expect(promoteLatestMonotonically(candidate, {
    readPackage,
    setLatest: async (version) => {
      writes.push(version);
    },
  })).rejects.toThrow("superseded by newer stable 0.4.0");

  expect(writes).toEqual([candidate.version, "0.4.0"]);
  expect(responses).toHaveLength(0);
  expect(urls).toHaveLength(4);
  expect(new Set(urls.map((url) => url.href)).size).toBe(urls.length);
  expect(urls.map((url) => url.searchParams.get("_hasna_origin_read"))).toEqual([
    "promotion-seam-1",
    "promotion-seam-2",
    "promotion-seam-3",
    "promotion-seam-4",
  ]);
  for (const url of urls) {
    expect(url.searchParams.get("write")).toBe("true");
    expect(url.username).toBe("");
    expect(url.password).toBe("");
  }
});

test("uses distinct origin-intent initial and terminal reads for staged and promoted verification", async () => {
  const packageJson = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const tarball = archive([
    tarEntry("package/package.json", packageJson.length, "0", packageJson),
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
  ]);
  const value: ReleaseCandidate = {
    ...candidate,
    size: tarball.length,
    shasum: createHash("sha1").update(tarball).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    fileCount: 2,
    unpackedBytes: packageJson.length + 3,
  };
  const urls: URL[] = [];
  let nonce = 0;
  const readPackageMetadata = createOriginPackumentReader(value.name, {
    nonce: () => `verification-seam-${++nonce}`,
    fetcher: async (url) => {
      const parsed = new URL(url);
      urls.push(parsed);
      const phase = urls.length <= 2 ? "staged" : "promoted";
      return Response.json(registryPackage(
        phase === "staged" ? "0.2.12" : value.version,
        ["0.2.12", value.version],
        value,
      ));
    },
  });

  for (const phase of ["staged", "promoted"] as const) {
    await expect(verifyRegistryReleaseAttempt(value, phase, {
      readVersionMetadata: async () => registryVersionMetadata(value),
      readPackageMetadata,
      readTarball: async () => tarball,
      verifyConsumer: () => attestations(),
      verifyCryptographically: async () => {},
      verifySemantically: () => {},
    })).resolves.toBeUndefined();
  }

  expect(urls).toHaveLength(4);
  expect(new Set(urls.map((url) => url.href)).size).toBe(urls.length);
  expect(urls.map((url) => url.searchParams.get("_hasna_origin_read"))).toEqual([
    "verification-seam-1",
    "verification-seam-2",
    "verification-seam-3",
    "verification-seam-4",
  ]);
  expect(urls.every((url) => url.searchParams.get("write") === "true")).toBe(true);
});

test("never authorizes cached idempotence when origin-intent reads reveal a newer stable at any promotion seam", async () => {
  const cached = registryPackage(
    candidate.version,
    ["0.2.12", candidate.version],
  );
  const oldOrigin = registryPackage(
    "0.2.12",
    ["0.2.12", candidate.version],
  );
  const newerOrigin = registryPackage(
    "0.4.0",
    ["0.2.12", candidate.version, "0.4.0"],
  );
  const candidateBeforeCompensation = registryPackage(
    candidate.version,
    ["0.2.12", candidate.version, "0.4.0"],
  );
  const scenarios = [
    {
      label: "initial",
      responses: [newerOrigin],
      writes: [],
      error: "superseded before promotion by 0.4.0",
    },
    {
      label: "pre-write",
      responses: [oldOrigin, newerOrigin],
      writes: [],
      error: "superseded before promotion by 0.4.0",
    },
    {
      label: "post-write-and-compensation",
      responses: [
        oldOrigin,
        oldOrigin,
        candidateBeforeCompensation,
        newerOrigin,
      ],
      writes: [candidate.version, "0.4.0"],
      error: "superseded by newer stable 0.4.0",
    },
  ];

  for (const scenario of scenarios) {
    const originResponses = [...scenario.responses];
    const urls: URL[] = [];
    let nonce = 0;
    const readPackage = createOriginPackumentReader(candidate.name, {
      nonce: () => `${scenario.label}-${++nonce}`,
      fetcher: async (url) => {
        const parsed = new URL(url);
        urls.push(parsed);
        const originIntent = parsed.searchParams.get("write") === "true" &&
          parsed.searchParams.has("_hasna_origin_read");
        return Response.json(originIntent ? originResponses.shift()! : cached);
      },
    });
    const writes: string[] = [];

    await expect(promoteLatestMonotonically(candidate, {
      readPackage,
      setLatest: async (version) => {
        writes.push(version);
      },
    })).rejects.toThrow(scenario.error);

    expect(writes).toEqual(scenario.writes);
    expect(originResponses).toHaveLength(0);
    expect(urls).toHaveLength(scenario.responses.length);
    expect(new Set(urls.map((url) => url.href)).size).toBe(urls.length);
    expect(urls.every((url) => url.searchParams.get("write") === "true")).toBe(true);
  }
});

test("terminal promoted verification cannot succeed from a permanently stale plain URL", async () => {
  const packageJson = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const tarball = archive([
    tarEntry("package/package.json", packageJson.length, "0", packageJson),
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
  ]);
  const value: ReleaseCandidate = {
    ...candidate,
    size: tarball.length,
    shasum: createHash("sha1").update(tarball).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    fileCount: 2,
    unpackedBytes: packageJson.length + 3,
  };
  const cached = registryPackage(
    value.version,
    ["0.2.12", value.version],
    value,
  );
  const originResponses = [
    cached,
    registryPackage(
      value.version,
      ["0.2.12", value.version, "0.4.0"],
      value,
    ),
  ];
  const urls: URL[] = [];
  let nonce = 0;
  const readPackageMetadata = createOriginPackumentReader(value.name, {
    nonce: () => `terminal-stale-cache-${++nonce}`,
    fetcher: async (url) => {
      const parsed = new URL(url);
      urls.push(parsed);
      const originIntent = parsed.searchParams.get("write") === "true" &&
        parsed.searchParams.has("_hasna_origin_read");
      return Response.json(originIntent ? originResponses.shift()! : cached);
    },
  });

  await expect(verifyRegistryReleaseAttempt(value, "promoted", {
    readVersionMetadata: async () => registryVersionMetadata(value),
    readPackageMetadata,
    readTarball: async () => tarball,
    verifyConsumer: () => attestations(),
    verifyCryptographically: async () => {},
    verifySemantically: () => {},
  })).rejects.toThrow("highest stable is 0.4.0");

  expect(originResponses).toHaveLength(0);
  expect(urls).toHaveLength(2);
  expect(new Set(urls.map((url) => url.href)).size).toBe(2);
  expect(urls.every((url) => url.searchParams.get("write") === "true")).toBe(true);
});

test("fails closed when an injected origin-read nonce is reused", async () => {
  const reader = createOriginPackumentReader(candidate.name, {
    nonce: () => "deterministic-reused-nonce",
    fetcher: async () => Response.json(
      registryPackage(candidate.version, ["0.2.12", candidate.version]),
    ),
  });
  await expect(reader()).resolves.toEqual(
    registryPackage(candidate.version, ["0.2.12", candidate.version]),
  );
  await expect(reader()).rejects.toThrow("origin read nonce was reused");
});

test("rejects redirects and keeps origin-read query data out of errors", async () => {
  const observed: Array<{ url: URL; init: RequestInit }> = [];
  const reader = createOriginPackumentReader(candidate.name, {
    nonce: () => "redirect-probe-nonce",
    fetcher: async (url, init) => {
      observed.push({ url: new URL(url), init });
      return new Response(null, {
        status: 302,
        headers: { location: "https://example.invalid/credential-leak" },
      });
    },
  });

  let message = "";
  try {
    await reader();
  } catch (error) {
    message = error instanceof Error ? error.message : String(error);
  }
  expect(message).toBe(
    "GET https://registry.npmjs.org/%40hasna%2Faccounts returned 302",
  );
  expect(message).not.toContain("redirect-probe-nonce");
  expect(message).not.toContain("example.invalid");
  expect(observed).toHaveLength(1);
  expect(observed[0]!.init.redirect).toBe("error");
  expect(observed[0]!.url.searchParams.get("write")).toBe("true");
  expect(observed[0]!.url.username).toBe("");
  expect(observed[0]!.url.password).toBe("");

  const oversized = createOriginPackumentReader(candidate.name, {
    nonce: () => "oversized-origin-response",
    fetcher: async () => new Response("{}", {
      headers: { "content-length": String(MAX_JSON_BYTES + 1) },
    }),
  });
  await expect(oversized()).rejects.toThrow(`response exceeds ${MAX_JSON_BYTES} bytes`);
});

test("derives an exact monotonic promotion snapshot from full registry versions and tags", () => {
  expect(registryPromotionSnapshot(
    registryPackage("0.2.12", ["0.2.11", "0.2.12", candidate.version]),
  )).toEqual({
    latest: "0.2.12",
    versions: ["0.2.11", "0.2.12", candidate.version],
    distTags: [
      ["latest", "0.2.12"],
      [candidate.stagingTag, candidate.version],
    ],
    highestStable: candidate.version,
  });
  expect(() => registryPromotionSnapshot(
    registryPackage("0.2.12", ["0.2.12", "not-semver", candidate.version]),
  )).toThrow("registry version not-semver is not canonical SemVer");
  expect(() => registryPromotionSnapshot(
    registryPackage("0.2.12", ["0.2.12", candidate.version, `${candidate.version}+other`]),
  )).toThrow("ambiguous highest stable versions");
  expect(() => registryPromotionSnapshot({
    ...registryPackage("9.9.9", ["0.2.12", candidate.version]),
  })).toThrow("registry dist-tag latest target 9.9.9 is absent from registry versions");
  expect(() => registryPromotionSnapshot(
    registryPackage("0.3.0-beta.1", ["0.3.0-beta.1", candidate.version]),
  )).toThrow("registry latest 0.3.0-beta.1 must not be a prerelease");
  expect(() => registryPromotionSnapshot(
    registryPackage("0.2.12", ["0.2.12", candidate.version], candidate, {
      legacy: "9.9.9",
    }),
  )).toThrow("registry dist-tag legacy target 9.9.9 is absent");
  expect(registryPromotionSnapshot(
    registryPackage(
      "0.2.0",
      ["0.1.0+one", "0.1.0+two", "0.2.0", candidate.version],
    ),
  ).highestStable).toBe(candidate.version);

  for (const invalidName of [
    undefined,
    "@hasna/other",
    "@HASNA/ACCOUNTS",
    " @hasna/accounts",
    "@hasna/accounts ",
    "@hasna/account\u017f",
  ]) {
    const metadata = registryPackage(
      "0.2.12",
      ["0.2.12", candidate.version],
    );
    const versions = metadata.versions as Record<string, Record<string, unknown>>;
    if (invalidName === undefined) {
      delete versions[candidate.version]!.name;
    } else {
      versions[candidate.version]!.name = invalidName;
    }
    expect(() => registryPromotionSnapshot(metadata))
      .toThrow(`registry version ${candidate.version} package identity disagrees`);
  }

  const missingVersion = registryPackage(
    "0.2.12",
    ["0.2.12", candidate.version],
  );
  delete (
    missingVersion.versions as Record<string, Record<string, unknown>>
  )[candidate.version]!.version;
  expect(() => registryPromotionSnapshot(missingVersion))
    .toThrow(`registry version ${candidate.version} manifest identity disagrees`);

  const wrongOlderPackage = registryPackage(
    "0.2.12",
    ["0.2.12", candidate.version],
  );
  (
    wrongOlderPackage.versions as Record<string, Record<string, unknown>>
  )["0.2.12"]!.name = "@hasna/other";
  expect(() => registryPromotionSnapshot(wrongOlderPackage))
    .toThrow("registry version 0.2.12 package identity disagrees");
});

test("compensates when a newer stable release appears after the final pre-mutation read", async () => {
  const reads = [
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0"]),
  ];
  const writes: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      const next = reads.shift();
      if (!next) throw new Error("unexpected registry read");
      return next;
    },
    setLatest: async (version) => {
      writes.push(version);
    },
  })).rejects.toThrow("superseded by newer stable 0.4.0");
  expect(writes).toEqual([candidate.version, "0.4.0"]);
  expect(reads).toHaveLength(0);
});

test("reserves a bounded forward-compensation attempt when maxAttempts is one", async () => {
  const reads = [
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0"]),
  ];
  const writes: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      const next = reads.shift();
      if (!next) throw new Error("unexpected registry read");
      return next;
    },
    setLatest: async (version) => {
      writes.push(version);
    },
  }, 1)).rejects.toThrow(
    "candidate 0.3.0 was superseded by newer stable 0.4.0; registry latest was restored",
  );
  expect(writes).toEqual([candidate.version, "0.4.0"]);
  expect(reads).toHaveLength(0);

  const failedCompensationReads = [
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
  ];
  const failedCompensationWrites: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      const next = failedCompensationReads.shift();
      if (!next) throw new Error("unexpected registry read");
      return next;
    },
    setLatest: async (version) => {
      failedCompensationWrites.push(version);
      if (version === "0.4.0") {
        throw new Error("simulated forward-compensation failure");
      }
    },
  }, 1)).rejects.toThrow(
    "could not restore monotonic latest 0.4.0 within 1 forward-compensation attempt",
  );
  expect(failedCompensationWrites).toEqual([candidate.version, "0.4.0"]);
  expect(failedCompensationReads).toHaveLength(0);

  let latest = "0.2.12";
  let partialFailureRead = 0;
  const partialFailureWrites: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      partialFailureRead++;
      if (partialFailureRead <= 2) {
        return registryPackage(latest, ["0.2.12", candidate.version]);
      }
      return registryPackage(
        latest,
        ["0.2.12", candidate.version, "0.4.0"],
      );
    },
    setLatest: async (version) => {
      partialFailureWrites.push(version);
      latest = version;
      if (version === "0.4.0") {
        throw new Error("ambiguous failure after forward compensation committed");
      }
    },
  }, 1)).rejects.toThrow(
    "candidate 0.3.0 was superseded by newer stable 0.4.0; registry latest was restored",
  );
  expect(partialFailureWrites).toEqual([candidate.version, "0.4.0"]);
  expect(partialFailureRead).toBe(4);
});

test("handles races at every promotion and compensation seam without accepting a stale latest", async () => {
  const beforeMutationWrites: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: (() => {
      const reads = [
        registryPackage("0.2.12", ["0.2.12", candidate.version]),
        registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0"]),
      ];
      return async () => reads.shift()!;
    })(),
    setLatest: async (version) => {
      beforeMutationWrites.push(version);
    },
  })).rejects.toThrow("superseded before promotion");
  expect(beforeMutationWrites).toEqual([]);

  const externalPromotionWrites: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: (() => {
      const reads = [
        registryPackage("0.2.12", ["0.2.12", candidate.version]),
        registryPackage("0.2.12", ["0.2.12", candidate.version]),
        registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0"]),
      ];
      return async () => reads.shift()!;
    })(),
    setLatest: async (version) => {
      externalPromotionWrites.push(version);
    },
  })).rejects.toThrow("superseded by newer stable 0.4.0");
  expect(externalPromotionWrites).toEqual([candidate.version]);

  const compensationWrites: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: (() => {
      const reads = [
        registryPackage("0.2.12", ["0.2.12", candidate.version]),
        registryPackage("0.2.12", ["0.2.12", candidate.version]),
        registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
        registryPackage("0.4.0", ["0.2.12", candidate.version, "0.4.0", "0.5.0"]),
        registryPackage("0.5.0", ["0.2.12", candidate.version, "0.4.0", "0.5.0"]),
      ];
      return async () => reads.shift()!;
    })(),
    setLatest: async (version) => {
      compensationWrites.push(version);
    },
  })).rejects.toThrow("superseded by newer stable 0.5.0");
  expect(compensationWrites).toEqual([candidate.version, "0.4.0", "0.5.0"]);
});

test("bounds ever-advancing promotion races and reports failed compensation", async () => {
  let generation = 4;
  let latest = "0.2.12";
  let reads = 0;
  const writes: string[] = [];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      reads++;
      if (reads <= 2) {
        return registryPackage(latest, ["0.2.12", candidate.version]);
      }
      const newer = `0.${generation++}.0`;
      return registryPackage(
        latest,
        [...new Set(["0.2.12", candidate.version, latest, newer])],
      );
    },
    setLatest: async (version) => {
      writes.push(version);
      latest = version;
    },
  }, 3)).rejects.toThrow("could not restore monotonic latest");
  expect(writes).toHaveLength(4);
  expect(writes[0]).toBe(candidate.version);
  expect(writes.slice(1)).toEqual(["0.4.0", "0.5.0", "0.6.0"]);

  const rollbackReads = [
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage("0.2.12", ["0.2.12", candidate.version]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
    registryPackage(candidate.version, ["0.2.12", candidate.version, "0.4.0"]),
  ];
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      const next = rollbackReads.shift();
      if (!next) return registryPackage(
        candidate.version,
        ["0.2.12", candidate.version, "0.4.0"],
      );
      return next;
    },
    setLatest: async (version) => {
      if (version === "0.4.0") throw new Error("simulated dist-tag failure");
    },
  }, 2)).rejects.toThrow("could not restore monotonic latest 0.4.0");
});

test("handles absent, idempotent, overwritten, malformed, and registry-error promotion states", async () => {
  const absentWrites: string[] = [];
  let absentRead = 0;
  expect(await promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      absentRead++;
      return registryPackage(
        absentRead < 3 ? undefined : candidate.version,
        [candidate.version],
      );
    },
    setLatest: async (version) => {
      absentWrites.push(version);
    },
  })).toBe("promoted");
  expect(absentWrites).toEqual([candidate.version]);

  const idempotentWrites: string[] = [];
  expect(await promoteLatestMonotonically(candidate, {
    readPackage: async () =>
      registryPackage(candidate.version, ["0.2.12", candidate.version]),
    setLatest: async (version) => {
      idempotentWrites.push(version);
    },
  })).toBe("idempotent");
  expect(idempotentWrites).toEqual([]);

  let overwrittenRead = 0;
  const overwrittenWrites: string[] = [];
  expect(await promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      overwrittenRead++;
      return registryPackage(
        overwrittenRead <= 4 ? "0.2.12" : candidate.version,
        ["0.2.12", candidate.version],
      );
    },
    setLatest: async (version) => {
      overwrittenWrites.push(version);
    },
  })).toBe("promoted");
  expect(overwrittenWrites).toEqual([candidate.version, candidate.version]);

  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      throw new Error("simulated registry read error");
    },
    setLatest: async () => {},
  })).rejects.toThrow("simulated registry read error");

  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => ({
      ...registryPackage("0.2.12", ["0.2.12", candidate.version]),
      name: "@hasna/other",
    }),
    setLatest: async () => {},
  })).rejects.toThrow("registry package identity");

  let appliedDespiteErrorRead = 0;
  expect(await promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      appliedDespiteErrorRead++;
      return registryPackage(
        appliedDespiteErrorRead < 3 ? "0.2.12" : candidate.version,
        ["0.2.12", candidate.version],
      );
    },
    setLatest: async () => {
      throw new Error("ambiguous transport failure after registry commit");
    },
  })).toBe("promoted");

  let failedMutationReads = 0;
  await expect(promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      failedMutationReads++;
      return registryPackage("0.2.12", ["0.2.12", candidate.version]);
    },
    setLatest: async () => {
      throw new Error("registry rejected mutation");
    },
  }, 2)).rejects.toThrow("last dist-tag error: registry rejected mutation");
  expect(failedMutationReads).toBeGreaterThanOrEqual(3);

  let fullTagSnapshotRead = 0;
  const fullTagSnapshotWrites: string[] = [];
  expect(await promoteLatestMonotonically(candidate, {
    readPackage: async () => {
      fullTagSnapshotRead++;
      return registryPackage(
        fullTagSnapshotRead < 4 ? "0.2.12" : candidate.version,
        ["0.2.11", "0.2.12", candidate.version],
        candidate,
        { legacy: fullTagSnapshotRead === 1 ? "0.2.11" : "0.2.12" },
      );
    },
    setLatest: async (version) => {
      fullTagSnapshotWrites.push(version);
    },
  })).toBe("promoted");
  expect(fullTagSnapshotWrites).toEqual([candidate.version]);
  expect(fullTagSnapshotRead).toBe(4);

  const prereleaseCandidate = {
    ...candidate,
    version: "0.3.0-beta.1",
    stagingTag: stagingDistTag("0.3.0-beta.1"),
  };
  await expect(promoteLatestMonotonically(prereleaseCandidate, {
    readPackage: async () =>
      registryPackage(
        "0.2.12",
        ["0.2.12", prereleaseCandidate.version],
        prereleaseCandidate,
      ),
    setLatest: async () => {},
  })).rejects.toThrow("prerelease");

  const buildCandidate = {
    ...candidate,
    version: `${candidate.version}+build.2`,
    stagingTag: stagingDistTag(`${candidate.version}+build.2`),
  };
  await expect(promoteLatestMonotonically(buildCandidate, {
    readPackage: async () =>
      registryPackage(
        "0.2.12",
        ["0.2.12", `${candidate.version}+build.1`, buildCandidate.version],
        buildCandidate,
      ),
    setLatest: async () => {},
  })).rejects.toThrow("ambiguous highest stable versions");
  expect(MAX_PROMOTION_ATTEMPTS).toBeGreaterThanOrEqual(4);
  expect(MAX_PROMOTION_ATTEMPTS).toBeLessThanOrEqual(8);
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

test("rejects a staged dist-tag mutation during install and audit before reporting success", async () => {
  const packageJson = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const tarball = archive([
    tarEntry("package/package.json", packageJson.length, "0", packageJson),
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
  ]);
  const value: ReleaseCandidate = {
    ...candidate,
    size: tarball.length,
    shasum: createHash("sha1").update(tarball).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    fileCount: 2,
    unpackedBytes: packageJson.length + 3,
  };
  let packageMetadata = registryPackage(
    "0.2.12",
    ["0.2.12", value.version],
    value,
  );
  let packageReads = 0;

  await expect(verifyRegistryReleaseAttempt(value, "staged", {
    readVersionMetadata: async () => registryVersionMetadata(value),
    readPackageMetadata: async () => {
      packageReads++;
      return packageMetadata;
    },
    readTarball: async () => tarball,
    verifyConsumer: () => {
      packageMetadata = registryPackage(
        value.version,
        ["0.2.12", value.version],
        value,
      );
      return attestations();
    },
    verifyCryptographically: async () => {},
    verifySemantically: () => {},
  })).rejects.toThrow("latest was promoted before registry verification completed");
  expect(packageReads).toBe(2);
});

test("validates every version identity and dist-tag target in every package reread", async () => {
  const packageJson = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const tarball = archive([
    tarEntry("package/package.json", packageJson.length, "0", packageJson),
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
  ]);
  const value: ReleaseCandidate = {
    ...candidate,
    size: tarball.length,
    shasum: createHash("sha1").update(tarball).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    fileCount: 2,
    unpackedBytes: packageJson.length + 3,
  };
  const validForPhase = (phase: "staged" | "promoted") =>
    registryPackage(
      phase === "staged" ? "0.2.12" : value.version,
      ["0.2.12", value.version],
      value,
    );
  const invalidSnapshots: Array<{
    label: string;
    expected: string;
    build: (phase: "staged" | "promoted") => Record<string, unknown>;
  }> = [
    {
      label: "unrelated tag targets an absent version",
      expected: "registry dist-tag legacy target 9.9.9 is absent",
      build: (phase) =>
        registryPackage(
          phase === "staged" ? "0.2.12" : value.version,
          ["0.2.12", value.version],
          value,
          { legacy: "9.9.9" },
        ),
    },
    {
      label: "unrelated tag has a malformed target",
      expected: "registry dist-tag legacy target  0.2.12 is not canonical SemVer",
      build: (phase) =>
        registryPackage(
          phase === "staged" ? "0.2.12" : value.version,
          ["0.2.12", value.version],
          value,
          { legacy: " 0.2.12" },
        ),
    },
    {
      label: "version manifest is partial",
      expected: `registry version ${value.version} package identity disagrees`,
      build: (phase) => {
        const metadata = validForPhase(phase);
        delete (
          metadata.versions as Record<string, Record<string, unknown>>
        )[value.version]!.name;
        return metadata;
      },
    },
  ];

  for (const invalid of invalidSnapshots) {
    for (const phase of ["staged", "promoted"] as const) {
      for (const invalidRead of [1, 2]) {
        let packageReads = 0;
        await expect(verifyRegistryReleaseAttempt(value, phase, {
          readVersionMetadata: async () => registryVersionMetadata(value),
          readPackageMetadata: async () => {
            packageReads++;
            return packageReads === invalidRead
              ? invalid.build(phase)
              : validForPhase(phase);
          },
          readTarball: async () => tarball,
          verifyConsumer: () => attestations(),
          verifyCryptographically: async () => {},
          verifySemantically: () => {},
        })).rejects.toThrow(invalid.expected);
        expect(packageReads).toBe(invalidRead);
      }
    }
  }

  for (const phase of ["staged", "promoted"] as const) {
    const latest = phase === "staged" ? "0.2.12" : value.version;
    const completeTagChanges = [
      {
        initial: validForPhase(phase),
        terminal: registryPackage(
          latest,
          ["0.2.12", value.version],
          value,
          { legacy: "0.2.12" },
        ),
      },
      {
        initial: registryPackage(
          latest,
          ["0.2.12", value.version],
          value,
          { legacy: "0.2.12" },
        ),
        terminal: validForPhase(phase),
      },
      {
        initial: registryPackage(
          latest,
          ["0.2.12", value.version],
          value,
          { legacy: "0.2.12" },
        ),
        terminal: registryPackage(
          latest,
          ["0.2.12", value.version],
          value,
          { legacy: value.version },
        ),
      },
    ];
    for (const change of completeTagChanges) {
      let packageReads = 0;
      await expect(verifyRegistryReleaseAttempt(value, phase, {
        readVersionMetadata: async () => registryVersionMetadata(value),
        readPackageMetadata: async () => {
          packageReads++;
          return packageReads === 1 ? change.initial : change.terminal;
        },
        readTarball: async () => tarball,
        verifyConsumer: () => attestations(),
        verifyCryptographically: async () => {},
        verifySemantically: () => {},
      })).resolves.toBeUndefined();
      expect(packageReads).toBe(2);
    }
  }
});

test("rejects promoted monotonic drift at every slow verification gate before reporting success", async () => {
  const packageJson = Buffer.from(JSON.stringify({
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
  }));
  const tarball = archive([
    tarEntry("package/package.json", packageJson.length, "0", packageJson),
    tarEntry("package/dist/cli.js", 3, "0", Buffer.from("cli")),
  ]);
  const value: ReleaseCandidate = {
    ...candidate,
    size: tarball.length,
    shasum: createHash("sha1").update(tarball).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    fileCount: 2,
    unpackedBytes: packageJson.length + 3,
  };
  const mutationGates = ["tarball", "consumer", "cryptographic", "semantic"] as const;
  for (const mutationGate of mutationGates) {
    let packageMetadata = registryPackage(
      value.version,
      ["0.2.12", value.version],
      value,
    );
    let packageReads = 0;
    const mutatePackage = () => {
      packageMetadata = registryPackage(
        value.version,
        ["0.2.12", value.version, "0.4.0"],
        value,
      );
    };

    await expect(verifyRegistryReleaseAttempt(value, "promoted", {
      readVersionMetadata: async () => registryVersionMetadata(value),
      readPackageMetadata: async () => {
        packageReads++;
        return packageMetadata;
      },
      readTarball: async () => {
        if (mutationGate === "tarball") mutatePackage();
        return tarball;
      },
      verifyConsumer: () => {
        if (mutationGate === "consumer") mutatePackage();
        return attestations();
      },
      verifyCryptographically: async () => {
        if (mutationGate === "cryptographic") mutatePackage();
      },
      verifySemantically: () => {
        if (mutationGate === "semantic") mutatePackage();
      },
    })).rejects.toThrow("highest stable is 0.4.0");
    expect(packageReads).toBe(2);
  }
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
  const missingPayloadType = attestations();
  delete (missingPayloadType[0]!.bundle.dsseEnvelope as {
    payloadType?: string;
  }).payloadType;
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(missingPayloadType)),
  )).toThrow("DSSE payloadType");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ payloadType: "text/plain" }))),
  )).toThrow("DSSE payloadType");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ payloadType: "Application/Vnd.In-Toto+Json" }))),
  )).toThrow("DSSE payloadType");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({
      payloadType: "application/vnd.in-toto+json ",
    }))),
  )).toThrow("DSSE payloadType");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({
      payloadType: "application/vnd.in-toto+json\u00a0",
    }))),
  )).toThrow("DSSE payloadType");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ omitStatementType: true }))),
  )).toThrow("in-toto statement type");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({ statementType: "https://in-toto.io/Statement/v0.1" }))),
  )).toThrow("in-toto statement type");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({
      statementType: "https://in-toto.io/Statement/v1 ",
    }))),
  )).toThrow("in-toto statement type");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(attestations({
      statementType: "https://in-toto.io/statement/v1",
    }))),
  )).toThrow("in-toto statement type");
  const malformedStatement = attestations();
  malformedStatement[0]!.bundle.dsseEnvelope.payload = Buffer
    .from("{not-json")
    .toString("base64");
  expect(() => verifyAttestations(
    candidate,
    extractVerifiedAttestations(candidate, auditResult(malformedStatement)),
  )).toThrow();
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
  // The admin credential is minted per run from the App, never stored, so the
  // presence gate gets the App credentials and the preflight steps get the
  // minted token. Asserting the secret form is ABSENT keeps a stored
  // installation token — which would expire mid-life and fail as an
  // authorization error — from creeping back in.
  expect(workflow).toContain("RELEASE_APP_ID_CONFIGURED");
  expect(workflow).toContain("RELEASE_APP_PRIVATE_KEY_CONFIGURED");
  expect(workflow).not.toContain("secrets.RELEASE_GITHUB_ADMIN_TOKEN");
  expect(workflow).toContain("uses: actions/create-github-app-token");
  expect(workflow).toContain("repositories: accounts");
  // The permission pin is the whole of the P1-1 remedy and it is ONE YAML line.
  // Nothing at runtime can defend it: current_user_can_bypass has no
  // discriminating power over the permission level — a token minted with
  // administration:write returns "never" too, while also being able to author
  // the ruleset it certifies. Measured: write -> POST /rulesets 201 CREATED,
  // read -> 403. So a silent regression from read back to write is invisible
  // everywhere except here.
  expect(workflow).toContain("permission-administration: read");
  expect(workflow).toContain("permission-metadata: read");
  expect(workflow).not.toContain("permission-administration: write");
  expect(workflow).toContain(
    "RELEASE_GITHUB_ADMIN_TOKEN: ${{ steps.release-admin-token.outputs.token }}",
  );
  expect(
    workflow.match(
      /RELEASE_GITHUB_ADMIN_TOKEN: \$\{\{ steps\.release-admin-token\.outputs\.token \}\}/g,
    ),
  ).toHaveLength(3);
  // The token must be minted before the first step that consumes it.
  expect(workflow.indexOf("id: release-admin-token"))
    .toBeLessThan(workflow.indexOf("release-provenance.ts preflight"));
  expect(workflow).toContain("bun run test:provenance-crypto");
  expect(workflow).toContain(`node-version: "${RELEASE_NODE_VERSION}"`);
  expect(workflow).toContain(`bun-version: "${RELEASE_BUN_VERSION}"`);
  expect(workflow).toContain("node scripts/assert-toolchain.mjs");
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
  expect(promotionImplementation).toContain("promoteLatestMonotonically(value");
  expect(promotionImplementation).toContain("readPackage,");
  expect(promotionImplementation).toContain("setLatest:");
  expect(implementation).not.toContain("fetchJson(packageUrl(value.name))");
  expect(implementation.match(/createOriginPackumentReader\(value\.name\)/g))
    .toHaveLength(2);
  const verificationImplementation = implementation.slice(
    implementation.indexOf("async function verifyRegistryRelease("),
    implementation.indexOf("async function promoteDistTag("),
  );
  expect(
    verificationImplementation.indexOf(
      "const readPackageMetadata = createOriginPackumentReader(value.name);",
    ),
  ).toBeLessThan(verificationImplementation.indexOf("for (let attempt = 1;"));
  expect(verificationImplementation).toContain("readPackageMetadata,");
  expect(implementation).toContain(
    "readVersionMetadata: () => fetchJson(packageUrl(value.name, value.version))",
  );
  expect(implementation).toContain(
    "readTarball: (url) => fetchLimited(url, MAX_TARBALL_BYTES)",
  );
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

const breakGlassContext = {
  name: "@hasna/accounts",
  version: "0.2.21",
  commit: "27cffd716ccf99c036f089f3eb75ee13554a7792",
  dirty: false,
};
const breakGlassReason = "npm OIDC degraded during a fleet limit-switching outage";

test("direct publish stays forbidden when no break-glass override is requested", () => {
  expect(() => evaluateDirectPublish({}, breakGlassContext))
    .toThrow("direct npm publish is forbidden");
  expect(() => evaluateDirectPublish({ [BREAK_GLASS_ENV]: "   " }, breakGlassContext))
    .toThrow("direct npm publish is forbidden");
  // The refusal must point at the documented escape hatch instead of dead-ending.
  expect(() => evaluateDirectPublish({}, breakGlassContext)).toThrow(BREAK_GLASS_ENV);
});

test("break-glass refuses ambiguous truthy values so it cannot be enabled by accident", () => {
  for (const value of ["1", "true", "yes", "on", BREAK_GLASS_TOKEN.toUpperCase()]) {
    expect(() =>
      evaluateDirectPublish(
        { [BREAK_GLASS_ENV]: value, [BREAK_GLASS_REASON_ENV]: breakGlassReason },
        breakGlassContext,
      )
    ).toThrow("must be set to exactly");
  }
});

test("break-glass is refused inside GitHub Actions so CI cannot skip verified publication", () => {
  expect(() =>
    evaluateDirectPublish(
      {
        [BREAK_GLASS_ENV]: BREAK_GLASS_TOKEN,
        [BREAK_GLASS_REASON_ENV]: breakGlassReason,
        GITHUB_ACTIONS: "true",
      },
      breakGlassContext,
    )
  ).toThrow("refused inside GitHub Actions");
});

test("break-glass demands a recorded reason of substance", () => {
  expect(() =>
    evaluateDirectPublish({ [BREAK_GLASS_ENV]: BREAK_GLASS_TOKEN }, breakGlassContext)
  ).toThrow(BREAK_GLASS_REASON_ENV);
  expect(() =>
    evaluateDirectPublish(
      { [BREAK_GLASS_ENV]: BREAK_GLASS_TOKEN, [BREAK_GLASS_REASON_ENV]: "oops" },
      breakGlassContext,
    )
  ).toThrow(`at least ${BREAK_GLASS_MIN_REASON_LENGTH} characters`);
});

test("break-glass refuses an untraceable working tree", () => {
  expect(() =>
    evaluateDirectPublish(
      { [BREAK_GLASS_ENV]: BREAK_GLASS_TOKEN, [BREAK_GLASS_REASON_ENV]: breakGlassReason },
      { ...breakGlassContext, dirty: true },
    )
  ).toThrow("working tree");
});

test("break-glass allows an audited emergency publish and announces exactly what was skipped", () => {
  const banner = evaluateDirectPublish(
    { [BREAK_GLASS_ENV]: BREAK_GLASS_TOKEN, [BREAK_GLASS_REASON_ENV]: breakGlassReason },
    breakGlassContext,
  );
  const rendered = banner.join("\n");
  expect(rendered).toContain("BREAK-GLASS DIRECT PUBLISH");
  expect(rendered).toContain(`${breakGlassContext.name}@${breakGlassContext.version}`);
  expect(rendered).toContain(breakGlassContext.commit);
  expect(rendered).toContain(breakGlassReason);
  expect(rendered).toContain("provenance");
  expect(rendered).toContain("docs/RELEASING.md");
});

test("pinned toolchain has exactly one declaration that every consumer reads", () => {
  const pinned = JSON.parse(
    readFileSync(new URL("./release-toolchain.json", import.meta.url), "utf8"),
  ) as Record<string, string>;
  expect(pinned.node).toBe(RELEASE_NODE_VERSION);
  expect(pinned.npm).toBe(RELEASE_NPM_VERSION);
  expect(pinned.bun).toBe(RELEASE_BUN_VERSION);

  const implementation = readFileSync(
    new URL("./release-provenance.ts", import.meta.url),
    "utf8",
  );
  // The literals must not be restated in TypeScript either.
  expect(implementation).toContain("release-toolchain.json");
  expect(implementation).not.toContain(`RELEASE_NODE_VERSION = "${RELEASE_NODE_VERSION}"`);

  for (const relative of ["../.github/workflows/ci.yml", "../.github/workflows/release.yml"]) {
    const workflow = readFileSync(new URL(relative, import.meta.url), "utf8");
    // setup-node / setup-bun inputs cannot read a file, so a test binds them instead.
    expect(workflow).toContain(`node-version: "${RELEASE_NODE_VERSION}"`);
    expect(workflow).toContain(`bun-version: "${RELEASE_BUN_VERSION}"`);
    expect(workflow).toContain("node scripts/assert-toolchain.mjs");
    // No workflow may restate a version as a shell comparison; that is the
    // duplication this file exists to remove, and it fails with no output.
    for (const version of [RELEASE_NODE_VERSION, RELEASE_NPM_VERSION, RELEASE_BUN_VERSION]) {
      expect(workflow).not.toContain(`== "${version}" ]]`);
      expect(workflow).not.toContain(`== "v${version}" ]]`);
    }
  }
});

test("release workflow names its missing environment secrets before doing any work", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const preflightStep = workflow.indexOf("release-provenance.ts preflight");
  const secretsStep = workflow.indexOf("NPM_DIST_TAG_TOKEN is not configured");
  expect(secretsStep).toBeGreaterThan(-1);
  expect(secretsStep).toBeLessThan(preflightStep);
  // Each credential the release actually depends on must still fail BY NAME.
  // The admin token is minted rather than stored, so the names that can be
  // missing are the App's, not the token's.
  expect(workflow).toContain("RELEASE_APP_ID is not configured");
  expect(workflow).toContain("RELEASE_APP_PRIVATE_KEY is not configured");
  expect(workflow.indexOf("uses: actions/checkout")).toBeGreaterThan(secretsStep);
});

// This test exists because the fixture-based tests above CANNOT catch env drift
// between the workflow and the script: they hand-write the environment, so they
// assert a state the workflow may no longer produce. That is exactly how a
// release-blocking defect shipped — the workflow stopped exporting
// RELEASE_GITHUB_ADMIN_TOKEN_CONFIGURED while workflowIdentity() still required
// it, and every test stayed green because every fixture supplied it by hand.
//
// So derive the contract from the two artefacts instead of restating it: what
// the script REQUIRES must be exactly what the workflow PROVIDES. Equality is
// deliberate rather than subset — a presence flag the workflow exports and
// nothing reads is dead configuration that reads as a live guard.
test("every *_CONFIGURED flag the script requires is exactly the set the workflow exports", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("./release-provenance.ts", import.meta.url),
    "utf8",
  );
  const provided = new Set(
    [...workflow.matchAll(/^\s+([A-Z][A-Z0-9_]*_CONFIGURED):/gm)].map((m) => m[1]),
  );
  const required = new Set(
    [...script.matchAll(/env\.([A-Z][A-Z0-9_]*_CONFIGURED)/g)].map((m) => m[1]),
  );
  // Positive control on the extractors themselves: an empty set on either side
  // would make the comparison vacuously pass in the direction that loses.
  expect(provided.size).toBeGreaterThan(0);
  expect(required.size).toBeGreaterThan(0);
  expect([...required].sort()).toEqual([...provided].sort());
});

// `test` is a required status check on main and a separate job would not be, so
// the double build-and-pack must stay in this job — but it belongs last, behind
// every cheaper signal, so a contributor never waits on it to learn something a
// faster step already knew.
test("deterministic pack verification stays in the required test job, and runs last", () => {
  const workflow = readFileSync(
    new URL("../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  const jobStart = workflow.indexOf("\n  test:\n");
  const jobEnd = workflow.indexOf("\n  portable-claude:\n");
  expect(jobStart).toBeGreaterThan(-1);
  expect(jobEnd).toBeGreaterThan(jobStart);
  const testJob = workflow.slice(jobStart, jobEnd);
  const packStep = testJob.indexOf("bun run verify:pack");
  expect(packStep).toBeGreaterThan(-1);
  for (const cheaper of [
    "bun run typecheck",
    "bun test\n",
    "bun run build\n",
    "bun run conformance",
    "bun run test:postgres",
  ]) {
    expect(testJob.indexOf(cheaper)).toBeGreaterThan(-1);
    expect(testJob.indexOf(cheaper)).toBeLessThan(packStep);
  }
});
