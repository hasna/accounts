import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
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
  assertGitEvidence,
  assertTrustedPublishEnvironment,
  extractVerifiedAttestations,
  packagePurl,
  parseRetryOptions,
  readLimited,
  releaseTag,
  repositorySlug,
  stagingDistTag,
  verifyAttestations,
  verifyDistTags,
  verifyDownloadedTarball,
  verifyReleaseEnvironment,
  verifyRegistryMetadata,
  verifyReleaseRulesets,
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
  schema: "hasna.accounts.release-candidate/v2",
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
      verificationMaterial: { tlogEntries: [{}] },
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
  expect(verifyReleaseRulesets([readOnlyRuleset])).toEqual({
    id: 19_812_295,
    name: "protect-npm-accounts-release-tags",
  });
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
    .toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([ruleset(["creation", "deletion"])]))
    .toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([ruleset(["creation", "update"])]))
    .toThrow("no active tag ruleset");
  expect(() => verifyReleaseRulesets([{ ...ruleset(), bypass_actors: [] }]))
    .toThrow("restrict authority");
  expect(() => verifyReleaseRulesets([{
    ...ruleset(),
    bypass_actors: [{
      actor_id: 123,
      actor_type: "Team",
      bypass_mode: "always",
    }],
  }])).toThrow("organization-admin authority");
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
  expect(() => verifyReleaseEnvironment(environment, policies, actor)).not.toThrow();
  expect(() => verifyReleaseEnvironment({
    ...environment,
    protection_rules: [{ type: "branch_policy" }],
  }, policies, actor)).toThrow("require reviewers");
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
  }, policies, actor)).toThrow("allow the authorized reviewer");
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
  }, policies, actor)).toThrow("exactly match the live release actor");
  expect(() => verifyReleaseEnvironment(environment, policies, {
    ...actor,
    permission: "write",
  })).toThrow("repository admin permission");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/v*", type: "branch" }],
  }, actor)).toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    branch_policies: [{ id: 456, name: "npm/accounts/*", type: "tag" }],
  }, actor)).toThrow("exact npm/accounts/v* tag policy");
  expect(() => verifyReleaseEnvironment(environment, {
    ...policies,
    total_count: 2,
    branch_policies: [
      { id: 456, name: "npm/accounts/v*", type: "tag" },
      { id: 789, name: "main", type: "branch" },
    ],
  }, actor)).toThrow("exactly one deployment tag policy");
});

test("requires registry source, integrity, and advertised provenance agreement", () => {
  const metadata = {
    name: candidate.name,
    version: candidate.version,
    gitHead: candidate.commit,
    dist: {
      integrity: candidate.integrity,
      shasum: candidate.shasum,
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

test("rejects changed registry downloads using size and both package digests", () => {
  const bytes = Buffer.from("the exact reviewed tarball");
  const exactCandidate = {
    ...candidate,
    size: bytes.length,
    shasum: createHash("sha1").update(bytes).digest("hex"),
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
  };
  expect(() => verifyDownloadedTarball(exactCandidate, bytes)).not.toThrow();
  expect(() => verifyDownloadedTarball(exactCandidate, Buffer.from("the altered registry tarball")))
    .toThrow("size differs");
  const sameSizeChanged = Buffer.from(bytes);
  sameSizeChanged[0] ^= 0xff;
  expect(() => verifyDownloadedTarball(exactCandidate, sameSizeChanged))
    .toThrow("differs from the reviewed pack");
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
  expect(workflow).toContain('tags:\n      - "npm/accounts/v*"');
  expect(workflow).toContain("id-token: write");
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
});

test("package lifecycle rejects direct publication outside the preserved-artifact wrapper", () => {
  const packageJson = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { scripts: Record<string, string> };
  expect(packageJson.scripts.prepublishOnly).toContain("reject-direct-publish");
  expect(packageJson.scripts["verify:pack"]).toContain("release-provenance.ts pack");
});
