import {
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
  type KeyLike,
} from "node:crypto";

import { AccountsError } from "../errors";
import {
  canonicalJson,
  canonicalSha256,
  parseClosedJson,
  parseClosedJsonBytes,
} from "../serialization/json";
import {
  ACCOUNTS_EVIDENCE_SIGNER_HISTORY_SCHEMA_VERSION_V2,
  ACCOUNTS_V10_MAX_CLOCK_SKEW_MS,
  ONLINE_GENERATION_CHECK_MAX_AGE_MS,
  ONLINE_GENERATION_CHECK_MAX_LIFETIME_MS,
  SLOT_ELIGIBILITY_MAX_AGE_MS,
  SLOT_ELIGIBILITY_MAX_LIFETIME_MS,
} from "./constants";
import type {
  AccountsEvidenceSignerHistoryV2,
  AccountsEvidenceSignerKeyV2,
  AccountsEvidenceTrustV1,
  V10Counter,
  V10PositiveCounter,
  V10Sha256Digest,
  V10Timestamp,
  V10UuidV7,
  V10WireObject,
} from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const UUID_V7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COUNTER_PATTERN = /^(?:0|[1-9][0-9]{0,18})$/;
const SIGNED_64_MAX = 9_223_372_036_854_775_807n;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface NormalizedTrust {
  readonly history: AccountsEvidenceSignerHistoryV2;
  readonly nowMs: number;
  readonly allowedClockSkewMs: number;
  readonly slotMaximumLifetimeMs: number;
  readonly slotMaximumAgeMs: number;
  readonly onlineMaximumLifetimeMs: number;
  readonly onlineMaximumAgeMs: number;
  readonly expectedEffectNamespaceId?: string;
  readonly expectedSlotEligibility?: AccountsEvidenceTrustV1["expectedSlotEligibility"];
  readonly previousSlotEligibility?: AccountsEvidenceTrustV1["previousSlotEligibility"];
}

export function validationFailure(message: string): never {
  throw new AccountsError("VALIDATION_FAILED", message);
}

export function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) validationFailure(message);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function record(value: unknown, label: string): Record<string, unknown> {
  invariant(isRecord(value), `${label} must be an object`);
  return value;
}

export function requiredKeys(
  value: unknown,
  required: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  invariant(isRecord(value), `${label} must be an object`);
  const expected = new Set(required);
  for (const key of Object.keys(value)) {
    invariant(expected.has(key), `${label} contains unknown field ${key}`);
  }
  for (const key of required) {
    invariant(Object.hasOwn(value, key), `${label} omits required field ${key}`);
  }
}

export function nonemptyString(value: unknown, field: string): string {
  invariant(
    typeof value === "string" && value.length > 0 && value.length <= 4_096,
    `${field} must be a bounded nonempty string`,
  );
  return value;
}

export function uuidV7(value: unknown, field: string): V10UuidV7 {
  invariant(typeof value === "string" && UUID_V7_PATTERN.test(value), `${field} must be UUIDv7`);
  return value as V10UuidV7;
}

export function sha256Digest(value: unknown, field: string): V10Sha256Digest {
  invariant(typeof value === "string" && SHA256_PATTERN.test(value), `${field} must be sha256`);
  return value as V10Sha256Digest;
}

export function counter(value: unknown, field: string): V10Counter {
  invariant(
    typeof value === "string" &&
      COUNTER_PATTERN.test(value) &&
      BigInt(value) <= SIGNED_64_MAX,
    `${field} must be a canonical signed-64 Counter`,
  );
  return value as V10Counter;
}

export function positiveCounter(value: unknown, field: string): V10PositiveCounter {
  const parsed = counter(value, field);
  invariant(parsed !== "0", `${field} must be a positive signed-64 Counter`);
  return parsed as unknown as V10PositiveCounter;
}

export function timestamp(value: unknown, field: string): V10Timestamp {
  invariant(typeof value === "string", `${field} must be an RFC 3339 millisecond timestamp`);
  const milliseconds = Date.parse(value);
  invariant(
    Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value,
    `${field} must be a canonical RFC 3339 millisecond timestamp`,
  );
  return value as V10Timestamp;
}

export function timestampMs(value: unknown, field: string): number {
  return Date.parse(timestamp(value, field));
}

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalJson(value));
}

export function canonicalDigest(value: unknown): V10Sha256Digest {
  return canonicalSha256(value) as V10Sha256Digest;
}

export function parseCanonicalWireBytes(source: Uint8Array, label: string): Record<string, unknown> {
  const parsed = record(parseClosedJsonBytes(source), label);
  let decoded: string;
  try {
    decoded = decoder.decode(source);
  } catch {
    return validationFailure(`${label} must be valid UTF-8`);
  }
  invariant(decoded === canonicalJson(parsed), `${label} must use exact RFC 8785 JCS bytes`);
  return parsed;
}

export function cloneWire(value: unknown, label: string): Record<string, unknown> {
  const canonical = canonicalJson(value);
  return record(parseClosedJson(canonical), label);
}

export function withoutSignature(value: Record<string, unknown>): Record<string, unknown> {
  const result = cloneWire(value, "signed wire object");
  invariant(Object.hasOwn(result, "signature"), "signed wire object omits signature");
  delete result.signature;
  return result;
}

export function signingBytes(value: Record<string, unknown>): Uint8Array {
  return canonicalBytes(withoutSignature(value));
}

function base64UrlBytes(value: unknown, field: string, expectedLength?: number): Uint8Array {
  invariant(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= 1_024 &&
      BASE64URL_PATTERN.test(value),
    `${field} must be unpadded base64url`,
  );
  let bytes: Uint8Array;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    return validationFailure(`${field} must be unpadded base64url`);
  }
  invariant(Buffer.from(bytes).toString("base64url") === value, `${field} is not canonical base64url`);
  if (expectedLength !== undefined) {
    invariant(bytes.byteLength === expectedLength, `${field} has the wrong byte length`);
  }
  return bytes;
}

export function assertSignatureShape(value: unknown): string {
  base64UrlBytes(value, "signature", 64);
  return value as string;
}

function boundedConfiguration(
  configured: number | undefined,
  maximum: number,
  field: string,
): number {
  const value = configured ?? maximum;
  invariant(
    Number.isSafeInteger(value) && value >= 0 && value <= maximum,
    `${field} cannot exceed the v1 normative maximum`,
  );
  return value;
}

function currentTime(options: AccountsEvidenceTrustV1): number {
  invariant(!(options.now !== undefined && options.clock !== undefined), "trust time is ambiguous");
  const value = options.now ?? options.clock?.() ?? new Date();
  invariant(value instanceof Date && Number.isFinite(value.getTime()), "trust clock returned invalid time");
  return value.getTime();
}

export function normalizeTrust(options: AccountsEvidenceTrustV1): NormalizedTrust {
  const expectedEffectNamespaceId = options.expectedEffectNamespaceId;
  if (expectedEffectNamespaceId !== undefined) {
    nonemptyString(expectedEffectNamespaceId, "expectedEffectNamespaceId");
  }
  return {
    history: cloneWire(
      options.signerHistory,
      "evidence signer history",
    ) as unknown as AccountsEvidenceSignerHistoryV2,
    nowMs: currentTime(options),
    allowedClockSkewMs: boundedConfiguration(
      options.allowedClockSkewMs,
      ACCOUNTS_V10_MAX_CLOCK_SKEW_MS,
      "allowedClockSkewMs",
    ),
    slotMaximumLifetimeMs: boundedConfiguration(
      options.slotMaximumLifetimeMs,
      SLOT_ELIGIBILITY_MAX_LIFETIME_MS,
      "slotMaximumLifetimeMs",
    ),
    slotMaximumAgeMs: boundedConfiguration(
      options.slotMaximumAgeMs,
      SLOT_ELIGIBILITY_MAX_AGE_MS,
      "slotMaximumAgeMs",
    ),
    onlineMaximumLifetimeMs: boundedConfiguration(
      options.onlineMaximumLifetimeMs,
      ONLINE_GENERATION_CHECK_MAX_LIFETIME_MS,
      "onlineMaximumLifetimeMs",
    ),
    onlineMaximumAgeMs: boundedConfiguration(
      options.onlineMaximumAgeMs,
      ONLINE_GENERATION_CHECK_MAX_AGE_MS,
      "onlineMaximumAgeMs",
    ),
    ...(expectedEffectNamespaceId === undefined ? {} : { expectedEffectNamespaceId }),
    ...(options.expectedSlotEligibility === undefined
      ? {}
      : { expectedSlotEligibility: options.expectedSlotEligibility }),
    ...(options.previousSlotEligibility === undefined
      ? {}
      : { previousSlotEligibility: options.previousSlotEligibility }),
  };
}

function validateHistoryKey(value: unknown, label: string): AccountsEvidenceSignerKeyV2 {
  requiredKeys(value, [
    "key_id",
    "public_key_spki_base64url",
    "activated_at",
    "expires_at",
    "retired_at",
    "revoked_at",
  ], label);
  nonemptyString(value.key_id, `${label}.key_id`);
  base64UrlBytes(value.public_key_spki_base64url, `${label}.public_key_spki_base64url`);
  const activatedAt = timestampMs(value.activated_at, `${label}.activated_at`);
  const expiresAt = timestampMs(value.expires_at, `${label}.expires_at`);
  invariant(activatedAt < expiresAt, `${label} validity interval is inverted`);
  invariant(value.retired_at === null || typeof value.retired_at === "string", `${label}.retired_at is invalid`);
  invariant(value.revoked_at === null || typeof value.revoked_at === "string", `${label}.revoked_at is invalid`);
  invariant(!(value.retired_at !== null && value.revoked_at !== null), `${label} cannot be retired and revoked`);
  if (value.retired_at !== null) {
    const retiredAt = timestampMs(value.retired_at, `${label}.retired_at`);
    invariant(activatedAt <= retiredAt && retiredAt < expiresAt, `${label} retirement is outside validity`);
  }
  if (value.revoked_at !== null) {
    const revokedAt = timestampMs(value.revoked_at, `${label}.revoked_at`);
    invariant(activatedAt <= revokedAt && revokedAt < expiresAt, `${label} revocation is outside validity`);
  }
  return value as unknown as AccountsEvidenceSignerKeyV2;
}

export function validateSignerHistory(
  history: AccountsEvidenceSignerHistoryV2,
  nowMs: number,
): readonly AccountsEvidenceSignerKeyV2[] {
  requiredKeys(history, [
    "schema_version",
    "issuer",
    "issuer_incarnation",
    "audience",
    "current_key_id",
    "keys",
  ], "evidence signer history");
  invariant(
    history.schema_version === ACCOUNTS_EVIDENCE_SIGNER_HISTORY_SCHEMA_VERSION_V2,
    "evidence signer history schema/version mismatch",
  );
  nonemptyString(history.issuer, "evidence signer history issuer");
  nonemptyString(history.issuer_incarnation, "evidence signer history issuer_incarnation");
  nonemptyString(history.audience, "evidence signer history audience");
  nonemptyString(history.current_key_id, "evidence signer history current_key_id");
  invariant(
    Array.isArray(history.keys) && history.keys.length > 0 && history.keys.length <= 64,
    "evidence signer history key count is invalid",
  );
  const keys = history.keys.map((key, index) => validateHistoryKey(key, `evidence signer history key ${index}`));
  invariant(new Set(keys.map((key) => key.key_id)).size === keys.length, "duplicate evidence signer key_id");
  const current = keys.find((key) => key.key_id === history.current_key_id);
  invariant(current !== undefined, "current evidence signer key is absent");
  invariant(current.retired_at === null && current.revoked_at === null, "current evidence signer key is not live");
  invariant(
    timestampMs(current.activated_at, "current signer activated_at") <= nowMs &&
      nowMs < timestampMs(current.expires_at, "current signer expires_at"),
    "current evidence signer key is not live",
  );
  return keys;
}

export function verifyEvidenceSignature(
  wire: Record<string, unknown>,
  trust: NormalizedTrust,
  maximumLifetimeMs: number,
): void {
  const keys = validateSignerHistory(trust.history, trust.nowMs);
  invariant(
    wire.issuer === trust.history.issuer &&
      wire.issuer_incarnation === trust.history.issuer_incarnation &&
      wire.audience === trust.history.audience &&
      typeof wire.key_id === "string",
    "signed evidence identity is not trusted",
  );
  const key = keys.find((candidate) => candidate.key_id === wire.key_id);
  invariant(key !== undefined, "signed evidence key_id is not trusted");
  const issuedAt = timestampMs(wire.issued_at, "signed evidence issued_at");
  const activatedAt = timestampMs(key.activated_at, "signer activated_at");
  const expiresAt = timestampMs(key.expires_at, "signer expires_at");
  invariant(activatedAt <= issuedAt && issuedAt < expiresAt, "signer key was not active at issuance");
  const signature = base64UrlBytes(wire.signature, "signature", 64);
  let publicKey: ReturnType<typeof createPublicKey>;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(base64UrlBytes(
        key.public_key_spki_base64url,
        "public_key_spki_base64url",
      )),
      format: "der",
      type: "spki",
    });
  } catch {
    return validationFailure("evidence signer public key is invalid");
  }
  invariant(
    publicKey.asymmetricKeyType === "ed25519",
    "evidence signer key must be Ed25519",
  );
  invariant(
    ed25519Verify(null, signingBytes(wire), publicKey, signature),
    "Ed25519 signature verification failed",
  );
  invariant(key.revoked_at === null, "signer key is revoked");
  if (key.retired_at !== null) {
    const retiredAt = timestampMs(key.retired_at, "signer retired_at");
    invariant(retiredAt <= trust.nowMs, "non-current signer is not yet retired");
    invariant(issuedAt <= retiredAt, "retired signer issued evidence after retirement");
    invariant(
      trust.nowMs <= retiredAt + maximumLifetimeMs + trust.allowedClockSkewMs,
      "retired signer verification window expired",
    );
  } else {
    invariant(key.key_id === trust.history.current_key_id, "signer key is not current or bounded-retired");
  }
}

export function signEvidenceBytes(
  unsigned: Record<string, unknown>,
  privateKey: KeyLike,
): Uint8Array {
  let signature: Uint8Array;
  try {
    signature = ed25519Sign(null, canonicalBytes(unsigned), privateKey);
  } catch {
    return validationFailure("Ed25519 signing failed");
  }
  invariant(signature.byteLength === 64, "Ed25519 signer returned an invalid signature");
  return signature;
}

export function assertAllStringFields(
  wire: Record<string, unknown>,
  fields: readonly string[],
  excluded: ReadonlySet<string>,
  label: string,
): void {
  for (const field of fields) {
    if (!excluded.has(field)) nonemptyString(wire[field], `${label}.${field}`);
  }
}

export function assertAllDigestFields(wire: Record<string, unknown>, label: string): void {
  for (const [field, value] of Object.entries(wire)) {
    if (field.endsWith("_digest") || field.endsWith("_hash") || field.endsWith("_thumbprint")) {
      sha256Digest(value, `${label}.${field}`);
    }
  }
}

export function asWireObject(value: Record<string, unknown>): V10WireObject {
  return value as unknown as V10WireObject;
}
