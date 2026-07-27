import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  PUBLISH_PREDICATE,
  PROVENANCE_PREDICATE,
  RELEASE_WORKFLOW,
  assertDeterministicPacks,
  assertTrustedPublishEnvironment,
  packagePurl,
  releaseTag,
  repositorySlug,
  verifyAttestations,
  verifyRegistryMetadata,
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
  schema: "hasna.accounts.release-candidate/v1",
  name: manifest.name,
  version: manifest.version,
  tag: "npm/accounts/v0.3.0",
  commit: "0123456789abcdef0123456789abcdef01234567",
  repository: "hasna/accounts",
  workflow: RELEASE_WORKFLOW,
  integrity: `sha512-${digest.toString("base64")}`,
  shasum: "1234567890abcdef1234567890abcdef12345678",
  filename: "hasna-accounts-0.3.0.tgz",
  fileCount: 2,
};

function attestation(predicateType: string, predicate: Record<string, unknown>) {
  const payload = {
    subject: [{
      name: packagePurl(candidate.name, candidate.version),
      digest: { sha512: digest.toString("hex") },
    }],
    predicateType,
    predicate,
  };
  return {
    predicateType,
    bundle: { dsseEnvelope: { payload: Buffer.from(JSON.stringify(payload)).toString("base64") } },
  };
}

function attestations(commit = candidate.commit) {
  return {
    attestations: [
      attestation(PUBLISH_PREDICATE, {
        name: candidate.name,
        version: candidate.version,
        registry: "https://registry.npmjs.org",
      }),
      attestation(PROVENANCE_PREDICATE, {
        buildDefinition: {
          externalParameters: { workflow: {
            ref: `refs/tags/${candidate.tag}`,
            repository: `https://github.com/${candidate.repository}`,
            path: candidate.workflow,
          } },
          resolvedDependencies: [{ digest: { gitCommit: commit } }],
        },
      }),
    ],
  };
}

function pack(integrity = candidate.integrity): PackResult {
  return {
    name: candidate.name,
    version: candidate.version,
    filename: candidate.filename,
    integrity,
    shasum: candidate.shasum,
    files: [
      { path: "dist/cli.js", size: 100, mode: 0o644 },
      { path: "package.json", size: 200, mode: 0o644 },
    ],
  };
}

test("derives the package-owned repository, tag, and purl", () => {
  expect(repositorySlug(manifest)).toBe("hasna/accounts");
  expect(releaseTag(manifest)).toBe(candidate.tag);
  expect(packagePurl(manifest.name, manifest.version)).toBe("pkg:npm/%40hasna/accounts@0.3.0");
});

test("accepts only the exact tokenless GitHub-hosted OIDC workflow", () => {
  const env = {
    GITHUB_ACTIONS: "true",
    RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_EVENT_NAME: "push",
    GITHUB_REF_TYPE: "tag",
    GITHUB_REF_NAME: candidate.tag,
    GITHUB_REPOSITORY: candidate.repository,
    GITHUB_WORKFLOW_REF: `${candidate.repository}/${RELEASE_WORKFLOW}@refs/tags/${candidate.tag}`,
    GITHUB_SHA: candidate.commit,
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://example.invalid/oidc",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "present",
  };
  expect(() => assertTrustedPublishEnvironment(manifest, env, "11.5.1")).not.toThrow();
  expect(() => assertTrustedPublishEnvironment(manifest, { ...env, GITHUB_REF_NAME: "v0.3.0" }, "11.5.1"))
    .toThrow("GITHUB_REF_NAME");
  expect(() => assertTrustedPublishEnvironment(manifest, { ...env, NPM_TOKEN: "forbidden" }, "11.5.1"))
    .toThrow("long-lived npm publish tokens");
  expect(() => assertTrustedPublishEnvironment(manifest, env, "11.5.0")).toThrow("11.5.1 or newer");
  expect(() => assertTrustedPublishEnvironment(manifest, env, "12.0.0")).not.toThrow();
});

test("rejects non-deterministic packed bytes", () => {
  expect(() => assertDeterministicPacks(pack(), pack())).not.toThrow();
  expect(() => assertDeterministicPacks(
    pack(),
    pack(`sha512-${Buffer.alloc(64, 1).toString("base64")}`),
  )).toThrow("different artifacts");
});

test("requires registry source, integrity, and attestation metadata agreement", () => {
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
    dist: { ...metadata.dist, attestations: undefined },
  })).toThrow("registry attestations");
});

test("binds both attestations to package bytes, workflow, tag, and commit", () => {
  expect(() => verifyAttestations(candidate, attestations())).not.toThrow();
  expect(() => verifyAttestations(candidate, attestations("f".repeat(40))))
    .toThrow("bind the release commit");
  const provenanceOnly = attestations();
  provenanceOnly.attestations.shift();
  expect(() => verifyAttestations(candidate, provenanceOnly))
    .toThrow("both npm publish and SLSA provenance");
});

test("release workflow preserves quarantine and has no token fallback", () => {
  const workflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  expect(workflow).toContain('tags:\n      - "npm/accounts/v*"');
  expect(workflow).toContain("id-token: write");
  expect(workflow).toContain("bun install --frozen-lockfile --minimum-release-age 604800");
  expect(workflow).toContain("npm publish --provenance --access public");
  expect(workflow).not.toContain("NODE_AUTH_TOKEN");
  expect(workflow).not.toContain("NPM_TOKEN");
});
