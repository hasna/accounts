#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { Verifier, toSignedEntity, toTrustMaterial } from "@sigstore/verify";

const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const MAX_TRUSTED_ROOT_BYTES = 64 * 1024;
const TRUSTED_ROOT_SHA256 =
  "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";
const chunks = [];
let inputBytes = 0;

for await (const chunk of process.stdin) {
  inputBytes += chunk.length;
  if (inputBytes > MAX_INPUT_BYTES) {
    throw new Error(`Sigstore verifier input exceeds ${MAX_INPUT_BYTES} bytes`);
  }
  chunks.push(chunk);
}

const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (!request || typeof request !== "object" || Array.isArray(request)) {
  throw new Error("Sigstore verifier request must be an object");
}
if (!request.bundle || typeof request.bundle !== "object" || Array.isArray(request.bundle)) {
  throw new Error("Sigstore verifier bundle must be an object");
}
if (!request.options || typeof request.options !== "object" || Array.isArray(request.options)) {
  throw new Error("Sigstore verifier options must be an object");
}

const {
  certificateIdentityURI,
  certificateIssuer,
  ctLogThreshold,
  tlogThreshold,
} = request.options;
if (typeof certificateIdentityURI !== "string" || certificateIdentityURI.length === 0) {
  throw new Error("Sigstore verifier requires a certificate identity");
}
if (typeof certificateIssuer !== "string" || certificateIssuer.length === 0) {
  throw new Error("Sigstore verifier requires a certificate issuer");
}
if (ctLogThreshold !== 1 || tlogThreshold !== 1) {
  throw new Error("Sigstore verifier requires CT-log and transparency-log threshold 1");
}

const trustedRootBytes = readFileSync(
  new URL("./sigstore-trusted-root.json", import.meta.url),
);
if (trustedRootBytes.length > MAX_TRUSTED_ROOT_BYTES) {
  throw new Error(`Sigstore trusted root exceeds ${MAX_TRUSTED_ROOT_BYTES} bytes`);
}
const trustedRootDigest = createHash("sha256").update(trustedRootBytes).digest("hex");
if (trustedRootDigest !== TRUSTED_ROOT_SHA256) {
  throw new Error("Sigstore trusted root checksum does not match the reviewed pin");
}
const trustedRoot = TrustedRoot.fromJSON(
  JSON.parse(trustedRootBytes.toString("utf8")),
);
const verifier = new Verifier(toTrustMaterial(trustedRoot), {
  ctlogThreshold: ctLogThreshold,
  tlogThreshold,
});
verifier.verify(toSignedEntity(bundleFromJSON(request.bundle)), {
  subjectAlternativeName: certificateIdentityURI,
  extensions: { issuer: certificateIssuer },
});
process.stdout.write("verified Sigstore bundle\n");
