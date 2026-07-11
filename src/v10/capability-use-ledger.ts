import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

import { AccountsError } from "../errors";
import { parseCounter, type Counter } from "../domain/counter";
import {
  OwnerOnlySignedAppendLog,
  type SignedLogRecord,
  type SignedLogSnapshot,
} from "../storage/file-recovery-ledger";
import { canonicalJson, canonicalSha256 } from "../serialization/json";

export const CAPABILITY_USE_LEDGER_ENTRY_SCHEMA_VERSION =
  "accounts.capability-use-ledger-entry/v1" as const;

/**
 * This is the collision-free external tombstone descriptor from the frozen
 * v10 contract. The ledger payload below is an internal record and does not
 * claim to be the externally signed tombstone.
 */
export const CAPABILITY_USE_TOMBSTONE_DESCRIPTOR = Object.freeze({
  fields: Object.freeze([
    "schema_version",
    "schema_digest",
    "record_kind",
    "consume_request_id",
    "idempotency_key_digest",
    "effect_namespace_id",
    "serialization_key_digest",
    "capability_id",
    "capability_digest",
    "nonce",
    "online_receipt_digest",
    "model_call_anchor_digest",
    "use_id",
    "consume_request_jcs_sha256",
    "consume_request_jcs_base64url",
    "consume_receipt_digest",
    "consume_receipt_jcs_base64url",
    "committed_at",
    "consume_receipt_expires_at",
    "catalog_incarnation",
    "recovery_frontier_sequence",
    "recovery_frontier_hash",
    "signer_ref",
    "signer_incarnation",
    "key_id",
    "audience",
    "signature",
  ]),
  record_kind: "CONSUMED",
  schema_version: "accounts.capability-use-tombstone.v1",
});

export const CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST =
  "sha256:c4d07c912e2d65350269a7425c461989fc747bbaa7c71ef5841135064fea5a12" as const;

if (canonicalSha256(CAPABILITY_USE_TOMBSTONE_DESCRIPTOR) !== CAPABILITY_USE_TOMBSTONE_SCHEMA_DIGEST) {
  throw new AccountsError("SCHEMA_CHECKSUM_MISMATCH", "Capability-use tombstone descriptor mismatch");
}

/**
 * No v10 request/receipt codec is provided while the frozen descriptor text
 * names the old digests. The computed values are evidence of the collision,
 * not replacement schema identities.
 */
export const CAPABILITY_USE_WIRE_CODEC_STATUS = Object.freeze({
  status: "BLOCKED_DESCRIPTOR_DIGEST_COLLISION" as const,
  request: Object.freeze({
    declaredDigest:
      "sha256:a7cdc1dfbebeaea3bad6a5014cfb5189be40fb010f57161b46437458492cd1bc",
    computedDescriptorDigest:
      "sha256:c248ce62b2acb9bb75f9bc88dfc272b05a9cd627f7e6ac19829bad9ea36de249",
  }),
  receipt: Object.freeze({
    declaredDigest:
      "sha256:a0999ffabc197f46f6fdeb8a6b78521364b0f2153d52a0e6e63ee360bb408bce",
    computedDescriptorDigest:
      "sha256:4e969fab6b3ae55c479357ebffed40b5de1ce207ca955b478462b36c9a345bfc",
  }),
});

type Sha256Digest = `sha256:${string}`;

export interface CapabilityUseVerifiedClaims {
  readonly consumeRequestId: string;
  readonly idempotencyKeyDigest: Sha256Digest;
  readonly effectNamespaceId: string;
  readonly serializationKeyDigest: Sha256Digest;
  readonly capabilityId: string;
  readonly capabilityDigest: Sha256Digest;
  readonly nonce: string;
  readonly onlineReceiptDigest: Sha256Digest;
  readonly modelCallAnchorDigest: Sha256Digest;
  readonly useId: Sha256Digest;
  readonly committedAt: string;
  readonly consumeReceiptExpiresAt: string;
  readonly catalogIncarnation: string;
  readonly recoveryFrontierSequence: Counter;
  readonly recoveryFrontierHash: Sha256Digest;
}

export interface CapabilityUseOpaqueBytes {
  readonly consumeRequestBytes: Uint8Array;
  readonly consumeReceiptBytes: Uint8Array;
}

/**
 * The missing production implementation is intentionally a structured
 * verifier, not an `assert(): boolean` shortcut. Once the descriptor collision
 * is resolved, the exact codec must return all verified cross-record claims.
 */
export interface CapabilityUseEvidenceVerifier {
  verify(input: CapabilityUseOpaqueBytes): Promise<CapabilityUseVerifiedClaims>;
}

const verifiedEvidenceInstances = new WeakSet<object>();

export interface VerifiedCapabilityUseEvidence extends CapabilityUseVerifiedClaims {
  readonly consumeRequestJcsSha256: Sha256Digest;
  readonly consumeRequestJcsBase64url: string;
  readonly consumeReceiptDigest: Sha256Digest;
  readonly consumeReceiptJcsBase64url: string;
}

export interface CapabilityUseLedgerRecord extends CapabilityUseVerifiedClaims {
  readonly consumeRequestJcsSha256: Sha256Digest;
  readonly consumeRequestBytes: Uint8Array;
  readonly consumeReceiptDigest: Sha256Digest;
  readonly consumeReceiptBytes: Uint8Array;
  readonly ledgerSequence: Counter;
  readonly ledgerHash: Sha256Digest;
  readonly ledgerSignatureDigest: Sha256Digest;
  readonly ledgerPayloadDigest: Sha256Digest;
  readonly ledgerReceiptDigest: Sha256Digest;
}

export type DurableCapabilityUseTombstone = CapabilityUseLedgerRecord;

export type CapabilityUseAppendResult =
  | { readonly kind: "APPENDED"; readonly record: CapabilityUseLedgerRecord }
  | { readonly kind: "REPLAYED"; readonly record: CapabilityUseLedgerRecord };

export type CapabilityUseLookup =
  | { readonly consumeRequestId: string }
  | { readonly idempotencyKeyDigest: Sha256Digest }
  | { readonly capabilityId: string; readonly nonce: string }
  | { readonly useId: Sha256Digest };

export interface CapabilityUseReconciliation {
  readonly status: "CURRENT" | "REBUILT";
  readonly recordCount: number;
  readonly frontierSequence: Counter;
  readonly frontierHash: Sha256Digest;
}

export interface NonRewindableCapabilityUseLedgerOptions {
  readonly ledgerPath: string;
  readonly mirrorPath: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
}

interface CapabilityUseLedgerPayload {
  readonly schema_version: typeof CAPABILITY_USE_LEDGER_ENTRY_SCHEMA_VERSION;
  readonly record_kind: "CONSUMED";
  readonly consume_request_id: string;
  readonly idempotency_key_digest: Sha256Digest;
  readonly effect_namespace_id: string;
  readonly serialization_key_digest: Sha256Digest;
  readonly capability_id: string;
  readonly capability_digest: Sha256Digest;
  readonly nonce: string;
  readonly online_receipt_digest: Sha256Digest;
  readonly model_call_anchor_digest: Sha256Digest;
  readonly use_id: Sha256Digest;
  readonly consume_request_jcs_sha256: Sha256Digest;
  readonly consume_request_jcs_base64url: string;
  readonly consume_receipt_digest: Sha256Digest;
  readonly consume_receipt_jcs_base64url: string;
  readonly committed_at: string;
  readonly consume_receipt_expires_at: string;
  readonly catalog_incarnation: string;
  readonly recovery_frontier_sequence: Counter;
  readonly recovery_frontier_hash: Sha256Digest;
}

interface MirrorRow {
  readonly sequence: bigint;
  readonly payload_digest: string;
  readonly payload_json: string;
  readonly consume_request_id: string;
  readonly idempotency_key_digest: string;
  readonly capability_id: string;
  readonly nonce: string;
  readonly use_id: string;
}

interface MirrorMetaRow {
  readonly frontier_sequence: bigint;
  readonly frontier_hash: string;
  readonly frontier_signature_digest: string;
}

interface LedgerIndexes {
  readonly byRequestId: ReadonlyMap<string, SignedLogRecord<CapabilityUseLedgerPayload>>;
  readonly byIdempotency: ReadonlyMap<string, SignedLogRecord<CapabilityUseLedgerPayload>>;
  readonly byCapabilityNonce: ReadonlyMap<string, SignedLogRecord<CapabilityUseLedgerPayload>>;
  readonly byUseId: ReadonlyMap<string, SignedLogRecord<CapabilityUseLedgerPayload>>;
}

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/+==-]{0,511}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_EVIDENCE_BYTES = 1024 * 1024;
const LOG_KIND = "capability-use" as const;

export async function verifyCapabilityUseEvidence(
  input: CapabilityUseOpaqueBytes,
  verifier: CapabilityUseEvidenceVerifier,
): Promise<VerifiedCapabilityUseEvidence> {
  const inputRecord = exactDataRecord(input, ["consumeRequestBytes", "consumeReceiptBytes"]);
  const request = copyBoundedBytes(inputRecord.consumeRequestBytes, "consumeRequestBytes");
  const receipt = copyBoundedBytes(inputRecord.consumeReceiptBytes, "consumeReceiptBytes");
  if (verifier === null || typeof verifier !== "object" || typeof verifier.verify !== "function") {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use verifier is required");
  }
  const verifierRequest = Uint8Array.from(request);
  const verifierReceipt = Uint8Array.from(receipt);
  const verifiedClaims = validateClaims(
    await verifier.verify({
      consumeRequestBytes: verifierRequest,
      consumeReceiptBytes: verifierReceipt,
    }),
  );
  if (!bytesEqual(request, verifierRequest) || !bytesEqual(receipt, verifierReceipt)) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use verifier mutated evidence bytes");
  }
  const evidence = Object.freeze({
    ...verifiedClaims,
    consumeRequestJcsSha256: sha256Bytes(request),
    consumeRequestJcsBase64url: Buffer.from(request).toString("base64url"),
    consumeReceiptDigest: sha256Bytes(receipt),
    consumeReceiptJcsBase64url: Buffer.from(receipt).toString("base64url"),
  }) satisfies VerifiedCapabilityUseEvidence;
  verifiedEvidenceInstances.add(evidence);
  return evidence;
}

export class NonRewindableCapabilityUseLedger {
  readonly initialReconciliation: CapabilityUseReconciliation;

  private readonly log: OwnerOnlySignedAppendLog<CapabilityUseLedgerPayload>;
  private readonly database: Database;
  private readonly catalogIncarnation: string;
  private closed = false;

  constructor(options: NonRewindableCapabilityUseLedgerOptions) {
    this.catalogIncarnation = safeIdentifier(
      options.catalogIncarnation,
      "catalogIncarnation",
    );
    this.log = new OwnerOnlySignedAppendLog({
      path: options.ledgerPath,
      catalogIncarnation: this.catalogIncarnation,
      signingKey: options.signingKey,
      logKind: LOG_KIND,
      validatePayload: validatePayload,
    });
    const mirrorPath = prepareMirrorPath(options.mirrorPath);
    const previousUmask = process.umask(0o077);
    try {
      this.database = new Database(mirrorPath, {
        create: true,
        strict: true,
        safeIntegers: true,
      });
    } finally {
      process.umask(previousUmask);
    }
    chmodSync(mirrorPath, 0o600);
    this.database.exec("PRAGMA foreign_keys = ON");
    this.database.exec("PRAGMA busy_timeout = 5000");
    this.database.exec("PRAGMA journal_mode = WAL");
    this.migrateMirror();
    secureSQLiteSidecars(mirrorPath);
    this.initialReconciliation = this.reconcile();
  }

  append(evidence: VerifiedCapabilityUseEvidence): CapabilityUseAppendResult {
    this.assertOpen();
    if (!verifiedEvidenceInstances.has(evidence)) {
      throw new AccountsError("FORBIDDEN", "Capability-use evidence was not verified");
    }
    if (evidence.catalogIncarnation !== this.catalogIncarnation) {
      throw new AccountsError("CONFLICT", "Capability-use catalog incarnation conflicts");
    }
    const payload = payloadFromEvidence(evidence);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const snapshot = this.log.readSnapshot();
      const indexes = buildIndexes(snapshot);
      const existing = resolveExisting(indexes, payload);
      if (existing !== undefined) {
        this.reconcile();
        return Object.freeze({ kind: "REPLAYED", record: toPublicRecord(existing) });
      }
      let appended: SignedLogRecord<CapabilityUseLedgerPayload>;
      try {
        appended = this.log.append(snapshot.frontier, payload);
      } catch (error) {
        if (
          attempt === 0 &&
          error instanceof AccountsError &&
          error.code === "RECOVERY_HOLD"
        ) {
          continue;
        }
        throw error;
      }
      this.reconcile();
      return Object.freeze({ kind: "APPENDED", record: toPublicRecord(appended) });
    }
    throw new AccountsError("RECOVERY_HOLD", "Capability-use append could not converge");
  }

  lookup(query: CapabilityUseLookup): CapabilityUseLedgerRecord | undefined {
    this.assertOpen();
    this.reconcile();
    const parsed = validateLookup(query);
    const indexes = buildIndexes(this.log.readSnapshot());
    const record =
      parsed.kind === "request"
        ? indexes.byRequestId.get(parsed.value)
        : parsed.kind === "idempotency"
          ? indexes.byIdempotency.get(parsed.value)
          : parsed.kind === "capability_nonce"
            ? indexes.byCapabilityNonce.get(capabilityNonceKey(parsed.capabilityId, parsed.nonce))
            : indexes.byUseId.get(parsed.value);
    return record === undefined ? undefined : toPublicRecord(record);
  }

  reconcile(): CapabilityUseReconciliation {
    this.assertOpen();
    const snapshot = this.log.readSnapshot();
    buildIndexes(snapshot);
    if (this.mirrorMatches(snapshot)) return reconciliation("CURRENT", snapshot);

    const rebuild = this.database.transaction(() => {
      this.database.exec("DELETE FROM capability_use_mirror");
      this.database.exec("DELETE FROM capability_use_mirror_meta");
      const insert = this.database.query(`
        INSERT INTO capability_use_mirror (
          sequence, payload_digest, payload_json, consume_request_id,
          idempotency_key_digest, capability_id, nonce, use_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const record of snapshot.records) {
        insert.run(
          BigInt(record.sequence),
          record.payloadDigest,
          canonicalJson(record.payload),
          record.payload.consume_request_id,
          record.payload.idempotency_key_digest,
          record.payload.capability_id,
          record.payload.nonce,
          record.payload.use_id,
        );
      }
      this.database.query(`
        INSERT INTO capability_use_mirror_meta (
          singleton, frontier_sequence, frontier_hash, frontier_signature_digest
        ) VALUES (1, ?, ?, ?)
      `).run(
        BigInt(snapshot.frontier.sequence),
        snapshot.frontier.hash,
        snapshot.frontier.signatureDigest,
      );
    });
    try {
      rebuild.immediate();
    } catch {
      throw new AccountsError("RECOVERY_HOLD", "Capability-use mirror reconciliation failed");
    }
    if (!this.mirrorMatches(snapshot)) {
      throw new AccountsError("RECOVERY_HOLD", "Capability-use mirror reconciliation diverged");
    }
    return reconciliation("REBUILT", snapshot);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.database.close();
  }

  private migrateMirror(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS capability_use_mirror (
        sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
        payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 71),
        payload_json TEXT NOT NULL,
        consume_request_id TEXT NOT NULL UNIQUE,
        idempotency_key_digest TEXT NOT NULL UNIQUE,
        capability_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        use_id TEXT NOT NULL UNIQUE,
        UNIQUE (capability_id, nonce)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS capability_use_mirror_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        frontier_sequence INTEGER NOT NULL CHECK (frontier_sequence >= 0),
        frontier_hash TEXT NOT NULL CHECK (length(frontier_hash) = 71),
        frontier_signature_digest TEXT NOT NULL CHECK (length(frontier_signature_digest) = 71)
      ) STRICT;
    `);
  }

  private mirrorMatches(snapshot: SignedLogSnapshot<CapabilityUseLedgerPayload>): boolean {
    try {
      const integrity = this.database.query("PRAGMA quick_check").values()[0]?.[0];
      if (integrity !== "ok") return false;
      const meta = this.database.query(`
        SELECT frontier_sequence, frontier_hash, frontier_signature_digest
        FROM capability_use_mirror_meta WHERE singleton = 1
      `).get() as MirrorMetaRow | null;
      if (
        meta === null ||
        meta.frontier_sequence.toString() !== snapshot.frontier.sequence ||
        meta.frontier_hash !== snapshot.frontier.hash ||
        meta.frontier_signature_digest !== snapshot.frontier.signatureDigest
      ) {
        return false;
      }
      const rows = this.database.query(`
        SELECT sequence, payload_digest, payload_json, consume_request_id,
               idempotency_key_digest, capability_id, nonce, use_id
        FROM capability_use_mirror ORDER BY sequence ASC
      `).all() as MirrorRow[];
      if (rows.length !== snapshot.records.length) return false;
      return rows.every((row, index) => {
        const record = snapshot.records[index];
        return (
          record !== undefined &&
          row.sequence.toString() === record.sequence &&
          row.payload_digest === record.payloadDigest &&
          row.payload_json === canonicalJson(record.payload) &&
          row.consume_request_id === record.payload.consume_request_id &&
          row.idempotency_key_digest === record.payload.idempotency_key_digest &&
          row.capability_id === record.payload.capability_id &&
          row.nonce === record.payload.nonce &&
          row.use_id === record.payload.use_id
        );
      });
    } catch {
      return false;
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Capability-use ledger closed");
  }
}

function exactDataRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Expected a closed data record");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AccountsError("VALIDATION_FAILED", "Expected a plain data record");
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new AccountsError("VALIDATION_FAILED", "Symbol fields are forbidden");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  const expected = [...expectedKeys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new AccountsError("VALIDATION_FAILED", "Closed data record fields do not match");
  }
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      throw new AccountsError("VALIDATION_FAILED", "Accessor fields are forbidden");
    }
    result[key] = descriptor.value;
  }
  return result;
}

function validateClaims(value: unknown): CapabilityUseVerifiedClaims {
  const record = exactDataRecord(value, [
    "consumeRequestId",
    "idempotencyKeyDigest",
    "effectNamespaceId",
    "serializationKeyDigest",
    "capabilityId",
    "capabilityDigest",
    "nonce",
    "onlineReceiptDigest",
    "modelCallAnchorDigest",
    "useId",
    "committedAt",
    "consumeReceiptExpiresAt",
    "catalogIncarnation",
    "recoveryFrontierSequence",
    "recoveryFrontierHash",
  ]);
  const committedAt = canonicalTimestamp(record.committedAt, "committedAt");
  const consumeReceiptExpiresAt = canonicalTimestamp(
    record.consumeReceiptExpiresAt,
    "consumeReceiptExpiresAt",
  );
  const lifetime = Date.parse(consumeReceiptExpiresAt) - Date.parse(committedAt);
  if (lifetime <= 0 || lifetime > 60_000) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use receipt expiry is invalid");
  }
  return Object.freeze({
    consumeRequestId: safeIdentifier(record.consumeRequestId, "consumeRequestId"),
    idempotencyKeyDigest: sha256Digest(record.idempotencyKeyDigest, "idempotencyKeyDigest"),
    effectNamespaceId: safeIdentifier(record.effectNamespaceId, "effectNamespaceId"),
    serializationKeyDigest: sha256Digest(record.serializationKeyDigest, "serializationKeyDigest"),
    capabilityId: safeIdentifier(record.capabilityId, "capabilityId"),
    capabilityDigest: sha256Digest(record.capabilityDigest, "capabilityDigest"),
    nonce: safeIdentifier(record.nonce, "nonce"),
    onlineReceiptDigest: sha256Digest(record.onlineReceiptDigest, "onlineReceiptDigest"),
    modelCallAnchorDigest: sha256Digest(record.modelCallAnchorDigest, "modelCallAnchorDigest"),
    useId: sha256Digest(record.useId, "useId"),
    committedAt,
    consumeReceiptExpiresAt,
    catalogIncarnation: safeIdentifier(record.catalogIncarnation, "catalogIncarnation"),
    recoveryFrontierSequence: counterValue(
      record.recoveryFrontierSequence,
      "recoveryFrontierSequence",
    ),
    recoveryFrontierHash: sha256Digest(record.recoveryFrontierHash, "recoveryFrontierHash"),
  });
}

function payloadFromEvidence(evidence: VerifiedCapabilityUseEvidence): CapabilityUseLedgerPayload {
  return validatePayload({
    schema_version: CAPABILITY_USE_LEDGER_ENTRY_SCHEMA_VERSION,
    record_kind: "CONSUMED",
    consume_request_id: evidence.consumeRequestId,
    idempotency_key_digest: evidence.idempotencyKeyDigest,
    effect_namespace_id: evidence.effectNamespaceId,
    serialization_key_digest: evidence.serializationKeyDigest,
    capability_id: evidence.capabilityId,
    capability_digest: evidence.capabilityDigest,
    nonce: evidence.nonce,
    online_receipt_digest: evidence.onlineReceiptDigest,
    model_call_anchor_digest: evidence.modelCallAnchorDigest,
    use_id: evidence.useId,
    consume_request_jcs_sha256: evidence.consumeRequestJcsSha256,
    consume_request_jcs_base64url: evidence.consumeRequestJcsBase64url,
    consume_receipt_digest: evidence.consumeReceiptDigest,
    consume_receipt_jcs_base64url: evidence.consumeReceiptJcsBase64url,
    committed_at: evidence.committedAt,
    consume_receipt_expires_at: evidence.consumeReceiptExpiresAt,
    catalog_incarnation: evidence.catalogIncarnation,
    recovery_frontier_sequence: evidence.recoveryFrontierSequence,
    recovery_frontier_hash: evidence.recoveryFrontierHash,
  });
}

function validatePayload(value: unknown): CapabilityUseLedgerPayload {
  const record = exactDataRecord(value, [
    "schema_version",
    "record_kind",
    "consume_request_id",
    "idempotency_key_digest",
    "effect_namespace_id",
    "serialization_key_digest",
    "capability_id",
    "capability_digest",
    "nonce",
    "online_receipt_digest",
    "model_call_anchor_digest",
    "use_id",
    "consume_request_jcs_sha256",
    "consume_request_jcs_base64url",
    "consume_receipt_digest",
    "consume_receipt_jcs_base64url",
    "committed_at",
    "consume_receipt_expires_at",
    "catalog_incarnation",
    "recovery_frontier_sequence",
    "recovery_frontier_hash",
  ]);
  if (
    record.schema_version !== CAPABILITY_USE_LEDGER_ENTRY_SCHEMA_VERSION ||
    record.record_kind !== "CONSUMED"
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use ledger literal mismatch");
  }
  const requestBase64 = canonicalBase64url(
    record.consume_request_jcs_base64url,
    "consume_request_jcs_base64url",
  );
  const receiptBase64 = canonicalBase64url(
    record.consume_receipt_jcs_base64url,
    "consume_receipt_jcs_base64url",
  );
  const requestDigest = sha256Digest(
    record.consume_request_jcs_sha256,
    "consume_request_jcs_sha256",
  );
  const receiptDigest = sha256Digest(record.consume_receipt_digest, "consume_receipt_digest");
  if (
    sha256Bytes(Buffer.from(requestBase64, "base64url")) !== requestDigest ||
    sha256Bytes(Buffer.from(receiptBase64, "base64url")) !== receiptDigest
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use evidence digest mismatch");
  }
  const committedAt = canonicalTimestamp(record.committed_at, "committed_at");
  const consumeReceiptExpiresAt = canonicalTimestamp(
    record.consume_receipt_expires_at,
    "consume_receipt_expires_at",
  );
  const lifetime = Date.parse(consumeReceiptExpiresAt) - Date.parse(committedAt);
  if (lifetime <= 0 || lifetime > 60_000) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use receipt expiry is invalid");
  }
  return Object.freeze({
    schema_version: CAPABILITY_USE_LEDGER_ENTRY_SCHEMA_VERSION,
    record_kind: "CONSUMED",
    consume_request_id: safeIdentifier(record.consume_request_id, "consume_request_id"),
    idempotency_key_digest: sha256Digest(record.idempotency_key_digest, "idempotency_key_digest"),
    effect_namespace_id: safeIdentifier(record.effect_namespace_id, "effect_namespace_id"),
    serialization_key_digest: sha256Digest(
      record.serialization_key_digest,
      "serialization_key_digest",
    ),
    capability_id: safeIdentifier(record.capability_id, "capability_id"),
    capability_digest: sha256Digest(record.capability_digest, "capability_digest"),
    nonce: safeIdentifier(record.nonce, "nonce"),
    online_receipt_digest: sha256Digest(record.online_receipt_digest, "online_receipt_digest"),
    model_call_anchor_digest: sha256Digest(
      record.model_call_anchor_digest,
      "model_call_anchor_digest",
    ),
    use_id: sha256Digest(record.use_id, "use_id"),
    consume_request_jcs_sha256: requestDigest,
    consume_request_jcs_base64url: requestBase64,
    consume_receipt_digest: receiptDigest,
    consume_receipt_jcs_base64url: receiptBase64,
    committed_at: committedAt,
    consume_receipt_expires_at: consumeReceiptExpiresAt,
    catalog_incarnation: safeIdentifier(record.catalog_incarnation, "catalog_incarnation"),
    recovery_frontier_sequence: counterValue(
      record.recovery_frontier_sequence,
      "recovery_frontier_sequence",
    ),
    recovery_frontier_hash: sha256Digest(
      record.recovery_frontier_hash,
      "recovery_frontier_hash",
    ),
  });
}

function buildIndexes(snapshot: SignedLogSnapshot<CapabilityUseLedgerPayload>): LedgerIndexes {
  const byRequestId = new Map<string, SignedLogRecord<CapabilityUseLedgerPayload>>();
  const byIdempotency = new Map<string, SignedLogRecord<CapabilityUseLedgerPayload>>();
  const byCapabilityNonce = new Map<string, SignedLogRecord<CapabilityUseLedgerPayload>>();
  const byUseId = new Map<string, SignedLogRecord<CapabilityUseLedgerPayload>>();
  for (const record of snapshot.records) {
    setUnique(byRequestId, record.payload.consume_request_id, record);
    setUnique(byIdempotency, record.payload.idempotency_key_digest, record);
    setUnique(
      byCapabilityNonce,
      capabilityNonceKey(record.payload.capability_id, record.payload.nonce),
      record,
    );
    setUnique(byUseId, record.payload.use_id, record);
  }
  return { byRequestId, byIdempotency, byCapabilityNonce, byUseId };
}

function setUnique(
  index: Map<string, SignedLogRecord<CapabilityUseLedgerPayload>>,
  key: string,
  record: SignedLogRecord<CapabilityUseLedgerPayload>,
): void {
  if (index.has(key)) {
    throw new AccountsError("RECOVERY_HOLD", "Capability-use ledger uniqueness violation");
  }
  index.set(key, record);
}

function resolveExisting(
  indexes: LedgerIndexes,
  candidate: CapabilityUseLedgerPayload,
): SignedLogRecord<CapabilityUseLedgerPayload> | undefined {
  const byRequest = indexes.byRequestId.get(candidate.consume_request_id);
  if (byRequest !== undefined) {
    if (isExactRequestReplay(byRequest.payload, candidate)) return byRequest;
    throw new AccountsError("IDEMPOTENCY_CONFLICT", "Consume request replay conflicts");
  }
  const byIdempotency = indexes.byIdempotency.get(candidate.idempotency_key_digest);
  if (byIdempotency !== undefined) {
    if (isExactRequestReplay(byIdempotency.payload, candidate)) return byIdempotency;
    throw new AccountsError("IDEMPOTENCY_CONFLICT", "Capability-use idempotency conflicts");
  }
  const byCapabilityNonce = indexes.byCapabilityNonce.get(
    capabilityNonceKey(candidate.capability_id, candidate.nonce),
  );
  if (byCapabilityNonce !== undefined) {
    throw new AccountsError("CONFLICT", "Capability nonce is already consumed");
  }
  if (indexes.byUseId.has(candidate.use_id)) {
    throw new AccountsError("CONFLICT", "Capability use id is already consumed");
  }
  return undefined;
}

function isExactRequestReplay(
  existing: CapabilityUseLedgerPayload,
  candidate: CapabilityUseLedgerPayload,
): boolean {
  return (
    existing.consume_request_id === candidate.consume_request_id &&
    existing.idempotency_key_digest === candidate.idempotency_key_digest &&
    existing.consume_request_jcs_sha256 === candidate.consume_request_jcs_sha256 &&
    existing.consume_request_jcs_base64url === candidate.consume_request_jcs_base64url &&
    existing.capability_digest === candidate.capability_digest
  );
}

function toPublicRecord(
  record: SignedLogRecord<CapabilityUseLedgerPayload>,
): CapabilityUseLedgerRecord {
  const payload = record.payload;
  return Object.freeze({
    consumeRequestId: payload.consume_request_id,
    idempotencyKeyDigest: payload.idempotency_key_digest,
    effectNamespaceId: payload.effect_namespace_id,
    serializationKeyDigest: payload.serialization_key_digest,
    capabilityId: payload.capability_id,
    capabilityDigest: payload.capability_digest,
    nonce: payload.nonce,
    onlineReceiptDigest: payload.online_receipt_digest,
    modelCallAnchorDigest: payload.model_call_anchor_digest,
    useId: payload.use_id,
    committedAt: payload.committed_at,
    consumeReceiptExpiresAt: payload.consume_receipt_expires_at,
    catalogIncarnation: payload.catalog_incarnation,
    recoveryFrontierSequence: payload.recovery_frontier_sequence,
    recoveryFrontierHash: payload.recovery_frontier_hash,
    consumeRequestJcsSha256: payload.consume_request_jcs_sha256,
    consumeRequestBytes: Uint8Array.from(
      Buffer.from(payload.consume_request_jcs_base64url, "base64url"),
    ),
    consumeReceiptDigest: payload.consume_receipt_digest,
    consumeReceiptBytes: Uint8Array.from(
      Buffer.from(payload.consume_receipt_jcs_base64url, "base64url"),
    ),
    ledgerSequence: record.sequence,
    ledgerHash: record.hash as Sha256Digest,
    ledgerSignatureDigest: record.signatureDigest as Sha256Digest,
    ledgerPayloadDigest: record.payloadDigest as Sha256Digest,
    ledgerReceiptDigest: record.receiptDigest as Sha256Digest,
  });
}

function validateLookup(query: CapabilityUseLookup):
  | { readonly kind: "request"; readonly value: string }
  | { readonly kind: "idempotency"; readonly value: string }
  | { readonly kind: "capability_nonce"; readonly capabilityId: string; readonly nonce: string }
  | { readonly kind: "use"; readonly value: string } {
  if (query === null || typeof query !== "object" || Array.isArray(query)) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use lookup is invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(query);
  const keys = Object.keys(descriptors).sort();
  if (keys.some((key) => !("value" in descriptors[key]!))) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use lookup accessors are forbidden");
  }
  if (keys.length === 1 && keys[0] === "consumeRequestId") {
    return {
      kind: "request",
      value: safeIdentifier(descriptors.consumeRequestId!.value, "consumeRequestId"),
    };
  }
  if (keys.length === 1 && keys[0] === "idempotencyKeyDigest") {
    return {
      kind: "idempotency",
      value: sha256Digest(descriptors.idempotencyKeyDigest!.value, "idempotencyKeyDigest"),
    };
  }
  if (keys.length === 1 && keys[0] === "useId") {
    return { kind: "use", value: sha256Digest(descriptors.useId!.value, "useId") };
  }
  if (keys.length === 2 && keys[0] === "capabilityId" && keys[1] === "nonce") {
    return {
      kind: "capability_nonce",
      capabilityId: safeIdentifier(descriptors.capabilityId!.value, "capabilityId"),
      nonce: safeIdentifier(descriptors.nonce!.value, "nonce"),
    };
  }
  throw new AccountsError("VALIDATION_FAILED", "Capability-use lookup fields are invalid");
}

function reconciliation(
  status: CapabilityUseReconciliation["status"],
  snapshot: SignedLogSnapshot<CapabilityUseLedgerPayload>,
): CapabilityUseReconciliation {
  return Object.freeze({
    status,
    recordCount: snapshot.records.length,
    frontierSequence: snapshot.frontier.sequence,
    frontierHash: snapshot.frontier.hash as Sha256Digest,
  });
}

function capabilityNonceKey(capabilityId: string, nonce: string): string {
  return `${capabilityId}\u0000${nonce}`;
}

function copyBoundedBytes(value: unknown, field: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength === 0 || value.byteLength > MAX_EVIDENCE_BYTES) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use evidence bytes are invalid", {
      details: { field },
    });
  }
  return Uint8Array.from(value);
}

function sha256Bytes(value: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function sha256Digest(value: unknown, field: string): Sha256Digest {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", "SHA-256 digest is invalid", {
      details: { field },
    });
  }
  return value as Sha256Digest;
}

function safeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !SAFE_IDENTIFIER_PATTERN.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use identifier is invalid", {
      details: { field },
    });
  }
  return value;
}

function counterValue(value: unknown, field: string): Counter {
  return parseCounter(value, field);
}

function canonicalTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use timestamp is invalid", {
      details: { field },
    });
  }
  try {
    if (new Date(value).toISOString() !== value) throw new Error("non-canonical");
  } catch {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use timestamp is invalid", {
      details: { field },
    });
  }
  return value;
}

function canonicalBase64url(value: unknown, field: string): string {
  if (typeof value !== "string" || !BASE64URL_PATTERN.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use evidence encoding is invalid", {
      details: { field },
    });
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength === 0 ||
    decoded.byteLength > MAX_EVIDENCE_BYTES ||
    decoded.toString("base64url") !== value
  ) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use evidence encoding is invalid", {
      details: { field },
    });
  }
  return value;
}

function prepareMirrorPath(path: string): string {
  if (!isAbsolute(path)) {
    throw new AccountsError("VALIDATION_FAILED", "Capability-use mirror path must be absolute");
  }
  const normalized = resolve(path);
  const parent = dirname(normalized);
  let realParent: string;
  try {
    realParent = realpathSync.native(parent);
  } catch {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Capability-use mirror parent is unsafe");
  }
  const parentMetadata = lstatSync(parent);
  if (
    realParent !== parent ||
    !parentMetadata.isDirectory() ||
    parentMetadata.isSymbolicLink() ||
    (typeof process.getuid === "function" && parentMetadata.uid !== process.getuid()) ||
    (parentMetadata.mode & 0o077) !== 0
  ) {
    throw new AccountsError("DATABASE_PATH_UNSAFE", "Capability-use mirror parent is unsafe");
  }
  if (existsSync(normalized)) {
    const metadata = lstatSync(normalized);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.nlink !== 1 ||
      (typeof process.getuid === "function" && metadata.uid !== process.getuid()) ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Capability-use mirror path is unsafe");
    }
  }
  return normalized;
}

function secureSQLiteSidecars(path: string): void {
  for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
    if (!existsSync(candidate)) continue;
    const metadata = lstatSync(candidate);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.nlink !== 1 ||
      (typeof process.getuid === "function" && metadata.uid !== process.getuid()) ||
      (metadata.mode & 0o077) !== 0
    ) {
      throw new AccountsError("DATABASE_PATH_UNSAFE", "Capability-use SQLite sidecar is unsafe");
    }
    chmodSync(candidate, 0o600);
  }
}
