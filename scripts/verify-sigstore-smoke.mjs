#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PROVENANCE = "https://slsa.dev/provenance/v1";
const ISSUER = "https://token.actions.githubusercontent.com";
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 15_000;
const FIXTURES = [
  {
    package: "sigstore@4.1.1",
    identity:
      "^https://github\\.com/sigstore/sigstore-js/\\.github/workflows/release\\.yml@refs/heads/main$",
  },
  {
    package: "semver@7.8.5",
    identity:
      "^https://github\\.com/npm/node-semver/\\.github/workflows/release-integration\\.yml@refs/heads/main$",
  },
];

async function provenanceBundle(packageSpec) {
  const response = await fetch(
    `https://registry.npmjs.org/-/npm/v1/attestations/${packageSpec}`,
    {
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    },
  );
  if (!response.ok) {
    throw new Error(`attestation fixture ${packageSpec} returned ${response.status}`);
  }
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE_BYTES) {
    throw new Error(`attestation fixture ${packageSpec} exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_RESPONSE_BYTES) {
    throw new Error(`attestation fixture ${packageSpec} exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  const document = JSON.parse(bytes.toString("utf8"));
  const entry = document.attestations?.find((item) => item.predicateType === PROVENANCE);
  if (!entry?.bundle) {
    throw new Error(`attestation fixture ${packageSpec} has no provenance bundle`);
  }
  return entry.bundle;
}

async function mustReject(label, operation) {
  try {
    await operation();
  } catch {
    return;
  }
  throw new Error(`${label} unexpectedly passed Sigstore verification`);
}

function verify(bundle, identity, issuer = ISSUER) {
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./verify-sigstore.mjs", import.meta.url))],
    {
      encoding: "utf8",
      input: JSON.stringify({
        bundle,
        options: {
          certificateIdentityURI: identity,
          certificateIssuer: issuer,
          ctLogThreshold: 1,
          tlogThreshold: 1,
        },
      }),
      maxBuffer: MAX_RESPONSE_BYTES,
      timeout: TIMEOUT_MS,
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Sigstore verifier exited ${result.status}`);
  }
}

const [sigstoreFixture, semverFixture] = await Promise.all(
  FIXTURES.map(async (fixture) => ({
    ...fixture,
    bundle: await provenanceBundle(fixture.package),
  })),
);

verify(sigstoreFixture.bundle, sigstoreFixture.identity);
verify(semverFixture.bundle, semverFixture.identity);
await mustReject("other valid Fulcio identity", async () =>
  verify(semverFixture.bundle, sigstoreFixture.identity)
);
await mustReject("other OIDC issuer", async () =>
  verify(
    sigstoreFixture.bundle,
    sigstoreFixture.identity,
    "https://example.invalid",
  )
);
const corrupt = structuredClone(sigstoreFixture.bundle);
const signature = corrupt.dsseEnvelope?.signatures?.[0]?.sig;
if (typeof signature !== "string" || signature.length < 2) {
  throw new Error("Sigstore smoke fixture has no DSSE signature");
}
corrupt.dsseEnvelope.signatures[0].sig =
  `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
await mustReject("other signature", async () =>
  verify(corrupt, sigstoreFixture.identity)
);
process.stdout.write(
  "verified pinned Sigstore fixtures and rejected other identity, issuer, and signature\n",
);
