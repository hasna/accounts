import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

import { incrementCounter, parseCounter, type Counter } from "../domain/counter";
import { AccountsError } from "../errors";
import {
  canonicalJson,
  canonicalSha256,
  parseClosedJsonBytes,
} from "../serialization/json";
import type {
  RecoveryFrontier,
  RecoveryLedger,
  RecoveryLedgerEntry,
  RecoveryLedgerReceipt,
} from "./repository";

const SIGNED_LOG_SCHEMA = "accounts.signed-append-log.v1" as const;
const SIGNED_LOG_ANCHOR_SCHEMA = "accounts.signed-append-log-anchor.v1" as const;
const RECOVERY_LOG_KIND = "accounts-recovery" as const;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CATALOG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const LOG_KIND_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const MAX_LEDGER_BYTES = 128 * 1024 * 1024;
const MAX_RECORD_BYTES = 1024 * 1024;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CLOEXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;
const LOCK_SCHEMA = "accounts.signed-log-lock.v2" as const;
const BOOT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PROCESS_START_PATTERN = /^\d+$/;

interface SignedLogHeader {
  readonly schema_version: typeof SIGNED_LOG_SCHEMA;
  readonly log_kind: string;
  readonly catalog_incarnation: string;
  readonly genesis_hash: string;
  readonly genesis_signature_digest: string;
}

interface SignedLogStoredRecord<T> {
  readonly schema_version: typeof SIGNED_LOG_SCHEMA;
  readonly log_kind: string;
  readonly catalog_incarnation: string;
  readonly sequence: Counter;
  readonly previous_hash: string;
  readonly payload: T;
  readonly payload_digest: string;
  readonly hash: string;
  readonly signature_digest: string;
  readonly receipt_digest: string;
}

interface SignedLogAnchor {
  readonly schema_version: typeof SIGNED_LOG_ANCHOR_SCHEMA;
  readonly log_kind: string;
  readonly catalog_incarnation: string;
  readonly sequence: Counter;
  readonly hash: string;
  readonly signature_digest: string;
}

export interface SignedLogFrontier {
  readonly catalogIncarnation: string;
  readonly sequence: Counter;
  readonly hash: string;
  readonly signatureDigest: string;
}

export interface SignedLogRecord<T> extends SignedLogFrontier {
  readonly previousHash: string;
  readonly payload: T;
  readonly payloadDigest: string;
  readonly receiptDigest: string;
}

export interface SignedLogSnapshot<T> {
  readonly frontier: SignedLogFrontier;
  readonly records: readonly SignedLogRecord<T>[];
}

export interface OwnerOnlySignedAppendLogOptions<T> {
  readonly path: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
  readonly logKind: string;
  readonly validatePayload: (value: unknown) => T;
}

function failHold(): never {
  throw new AccountsError("RECOVERY_HOLD", "Signed append log verification failed");
}

function failUnsafePath(): never {
  throw new AccountsError("DATABASE_PATH_UNSAFE", "Signed append log path is unsafe");
}

function isNodeError(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}

function exactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) failHold();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) failHold();
  if (Object.getOwnPropertySymbols(value).length !== 0) failHold();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  const allowed = new Set([...required, ...optional]);
  if (
    keys.length < required.length ||
    keys.some((key) => !allowed.has(key)) ||
    required.some((key) => !Object.hasOwn(descriptors, key))
  ) {
    failHold();
  }
  const record = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (
      !descriptor.enumerable ||
      !("value" in descriptor) ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined
    ) {
      failHold();
    }
    record[key] = descriptor.value;
  }
  return record;
}

function asString(value: unknown): string {
  if (typeof value !== "string") failHold();
  return value;
}

function asDigest(value: unknown): string {
  const digest = asString(value);
  if (!SHA256_PATTERN.test(digest)) failHold();
  return digest;
}

function storedCounter(value: unknown): Counter {
  try {
    return parseCounter(value, "sequence");
  } catch {
    return failHold();
  }
}

function storedIncrement(value: Counter): Counter {
  try {
    return incrementCounter(value);
  } catch {
    return failHold();
  }
}

function digestEqual(left: string, right: string): boolean {
  if (!SHA256_PATTERN.test(left) || !SHA256_PATTERN.test(right)) return false;
  return timingSafeEqual(
    Buffer.from(left.slice("sha256:".length), "hex"),
    Buffer.from(right.slice("sha256:".length), "hex"),
  );
}

function writeAll(descriptor: number, bytes: Uint8Array): void {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const written = writeSync(descriptor, bytes, offset, bytes.byteLength - offset);
    if (written <= 0) failHold();
    offset += written;
  }
}

function assertOwnerOnlyDirectory(path: string): void {
  let real: string;
  try {
    real = realpathSync.native(path);
  } catch {
    failUnsafePath();
  }
  if (real !== path) failUnsafePath();
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) failUnsafePath();
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) failUnsafePath();
  if ((metadata.mode & 0o077) !== 0) failUnsafePath();
}

function assertSecureRegularFile(descriptor: number): void {
  const metadata = fstatSync(descriptor);
  if (!metadata.isFile() || metadata.nlink !== 1) failUnsafePath();
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) failUnsafePath();
  if ((metadata.mode & 0o077) !== 0) failUnsafePath();
}

function openExistingSecure(path: string, flags: number): number {
  let descriptor: number;
  try {
    descriptor = openSync(path, flags | NOFOLLOW | CLOEXEC);
  } catch {
    failUnsafePath();
  }
  try {
    assertSecureRegularFile(descriptor);
    const linkMetadata = lstatSync(path);
    const descriptorMetadata = fstatSync(descriptor);
    if (
      linkMetadata.isSymbolicLink() ||
      linkMetadata.dev !== descriptorMetadata.dev ||
      linkMetadata.ino !== descriptorMetadata.ino
    ) {
      failUnsafePath();
    }
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function createSecure(path: string): number {
  let descriptor: number;
  try {
    descriptor = openSync(
      path,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_RDWR |
        NOFOLLOW |
        CLOEXEC,
      0o600,
    );
  } catch (error) {
    if (isNodeError(error, "EEXIST")) failUnsafePath();
    failUnsafePath();
  }
  try {
    assertSecureRegularFile(descriptor);
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | NOFOLLOW | CLOEXEC);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function readSecureBytes(path: string, maximumBytes: number): Uint8Array {
  const descriptor = openExistingSecure(path, constants.O_RDONLY);
  try {
    const metadata = fstatSync(descriptor);
    if (metadata.size > maximumBytes) failHold();
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

type ProcessStartObservation =
  | { readonly kind: "FOUND"; readonly value: string }
  | { readonly kind: "MISSING" }
  | { readonly kind: "UNAVAILABLE" };

type ProcessIdentity =
  | {
      readonly identityMode: "linux-proc-v1";
      readonly pid: number;
      readonly processStart: string;
      readonly bootId: string;
    }
  | {
      readonly identityMode: "pid-liveness-v1";
      readonly pid: number;
    };

function tryReadBootId(): string | undefined {
  let value: string;
  try {
    value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  } catch {
    return undefined;
  }
  return BOOT_ID_PATTERN.test(value) ? value : undefined;
}

function observeProcessStart(pid: number): ProcessStartObservation {
  let stat: string;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
  } catch (error) {
    if (isNodeError(error, "ENOENT") || isNodeError(error, "ESRCH")) {
      return Object.freeze({ kind: "MISSING" });
    }
    return Object.freeze({ kind: "UNAVAILABLE" });
  }
  const closingParenthesis = stat.lastIndexOf(")");
  if (closingParenthesis < 0) return Object.freeze({ kind: "UNAVAILABLE" });
  const fieldsFromState = stat.slice(closingParenthesis + 2).split(" ");
  const processStart = fieldsFromState[19];
  if (processStart === undefined || !PROCESS_START_PATTERN.test(processStart)) {
    return Object.freeze({ kind: "UNAVAILABLE" });
  }
  return Object.freeze({ kind: "FOUND", value: processStart });
}

function currentProcessIdentity(): ProcessIdentity {
  const bootId = tryReadBootId();
  const processStart = observeProcessStart(process.pid);
  if (bootId !== undefined && processStart.kind === "FOUND") {
    return Object.freeze({
      identityMode: "linux-proc-v1",
      pid: process.pid,
      processStart: processStart.value,
      bootId,
    });
  }
  return Object.freeze({ identityMode: "pid-liveness-v1", pid: process.pid });
}

function pidIsDefinitivelyDead(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    if (isNodeError(error, "ESRCH")) return true;
    return failHold();
  }
}

/**
 * A process-independent, owner-only, signed append log. The companion anchor is
 * deliberately stored outside the append stream so truncating a valid prefix is
 * detected. It is an internal building block, not an authorization source.
 */
export class OwnerOnlySignedAppendLog<T> {
  readonly path: string;
  readonly anchorPath: string;

  private readonly parentPath: string;
  private readonly lockPath: string;
  private readonly signingKey: Buffer;
  private readonly catalogIncarnation: string;
  private readonly logKind: string;
  private readonly validatePayload: (value: unknown) => T;
  private lastObserved?: SignedLogFrontier;

  constructor(options: OwnerOnlySignedAppendLogOptions<T>) {
    if (!isAbsolute(options.path)) {
      throw new AccountsError("VALIDATION_FAILED", "Signed append log path must be absolute");
    }
    this.path = resolve(options.path);
    this.parentPath = dirname(this.path);
    this.anchorPath = `${this.path}.frontier`;
    this.lockPath = `${this.path}.lock`;
    if (!CATALOG_PATTERN.test(options.catalogIncarnation)) {
      throw new AccountsError("VALIDATION_FAILED", "Catalog incarnation is invalid");
    }
    if (!LOG_KIND_PATTERN.test(options.logKind)) {
      throw new AccountsError("VALIDATION_FAILED", "Signed append log kind is invalid");
    }
    if (options.signingKey.byteLength < 32) {
      throw new AccountsError("VALIDATION_FAILED", "Signed append log key is too short");
    }
    this.signingKey = Buffer.from(options.signingKey);
    this.catalogIncarnation = options.catalogIncarnation;
    this.logKind = options.logKind;
    this.validatePayload = options.validatePayload;

    assertOwnerOnlyDirectory(this.parentPath);
    this.withLock(() => {
      const ledgerExists = existsSync(this.path);
      const anchorExists = existsSync(this.anchorPath);
      if (
        (ledgerExists && lstatSync(this.path).isSymbolicLink()) ||
        (anchorExists && lstatSync(this.anchorPath).isSymbolicLink())
      ) {
        failUnsafePath();
      }
      if (!ledgerExists && !anchorExists) {
        this.initialize();
      } else if (!ledgerExists || !anchorExists) {
        failHold();
      }
      this.scan();
    });
  }

  readSnapshot(): SignedLogSnapshot<T> {
    return this.withLock(() => this.scan());
  }

  verifyFrontier(frontier: SignedLogFrontier): boolean {
    try {
      const sequence = parseCounter(frontier.sequence, "sequence");
      if (
        frontier.catalogIncarnation !== this.catalogIncarnation ||
        !SHA256_PATTERN.test(frontier.hash) ||
        !SHA256_PATTERN.test(frontier.signatureDigest)
      ) {
        return false;
      }
      return digestEqual(
        frontier.signatureDigest,
        this.signFrontier({
          catalogIncarnation: frontier.catalogIncarnation,
          sequence,
          hash: frontier.hash,
        }),
      );
    } catch {
      return false;
    }
  }

  append(expected: SignedLogFrontier, payload: T): SignedLogRecord<T> {
    return this.withLock(() => {
      const snapshot = this.scan();
      if (
        !this.verifyFrontier(expected) ||
        expected.catalogIncarnation !== snapshot.frontier.catalogIncarnation ||
        expected.sequence !== snapshot.frontier.sequence ||
        !digestEqual(expected.hash, snapshot.frontier.hash) ||
        !digestEqual(expected.signatureDigest, snapshot.frontier.signatureDigest)
      ) {
        failHold();
      }
      const validated = this.validatePayload(payload);
      const sequence = incrementCounter(snapshot.frontier.sequence);
      const payloadDigest = canonicalSha256(validated);
      const hash = canonicalSha256({
        catalogIncarnation: this.catalogIncarnation,
        logKind: this.logKind,
        sequence,
        previousHash: snapshot.frontier.hash,
        payloadDigest,
      });
      const signatureDigest = this.signFrontier({
        catalogIncarnation: this.catalogIncarnation,
        sequence,
        hash,
      });
      const unsigned = {
        schema_version: SIGNED_LOG_SCHEMA,
        log_kind: this.logKind,
        catalog_incarnation: this.catalogIncarnation,
        sequence,
        previous_hash: snapshot.frontier.hash,
        payload: validated,
        payload_digest: payloadDigest,
        hash,
        signature_digest: signatureDigest,
      } as const;
      const receiptDigest = this.hmac(unsigned);
      const stored: SignedLogStoredRecord<T> = {
        ...unsigned,
        receipt_digest: receiptDigest,
      };
      const line = Buffer.from(`${canonicalJson(stored)}\n`, "utf8");
      if (line.byteLength > MAX_RECORD_BYTES) {
        throw new AccountsError("VALIDATION_FAILED", "Signed append log record is too large");
      }

      const descriptor = openExistingSecure(
        this.path,
        constants.O_WRONLY | constants.O_APPEND,
      );
      try {
        writeAll(descriptor, line);
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }

      const frontier = {
        catalogIncarnation: this.catalogIncarnation,
        sequence,
        hash,
        signatureDigest,
      } satisfies SignedLogFrontier;
      this.writeAnchor(frontier);
      this.lastObserved = frontier;
      return Object.freeze({
        ...frontier,
        previousHash: snapshot.frontier.hash,
        payload: structuredClone(validated),
        payloadDigest,
        receiptDigest,
      });
    });
  }

  private initialize(): void {
    const genesisHash = canonicalSha256({
      kind: "accounts-signed-log-genesis",
      logKind: this.logKind,
      catalogIncarnation: this.catalogIncarnation,
    });
    const frontier = {
      catalogIncarnation: this.catalogIncarnation,
      sequence: parseCounter("0"),
      hash: genesisHash,
      signatureDigest: "",
    };
    frontier.signatureDigest = this.signFrontier({
      catalogIncarnation: frontier.catalogIncarnation,
      sequence: frontier.sequence,
      hash: frontier.hash,
    });
    const header: SignedLogHeader = {
      schema_version: SIGNED_LOG_SCHEMA,
      log_kind: this.logKind,
      catalog_incarnation: this.catalogIncarnation,
      genesis_hash: genesisHash,
      genesis_signature_digest: frontier.signatureDigest,
    };
    const descriptor = createSecure(this.path);
    try {
      writeAll(descriptor, Buffer.from(`${canonicalJson(header)}\n`, "utf8"));
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    fsyncDirectory(this.parentPath);
    this.writeAnchor(frontier);
  }

  private scan(): SignedLogSnapshot<T> {
    const bytes = readSecureBytes(this.path, MAX_LEDGER_BYTES);
    if (bytes.byteLength === 0 || bytes.at(-1) !== 0x0a) failHold();
    let source: string;
    try {
      source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      failHold();
    }
    const lines = source.slice(0, -1).split("\n");
    if (lines.length === 0 || lines.some((line) => line.length === 0)) failHold();
    const headerValue = this.parseCanonicalLine(lines[0]!);
    const headerRecord = exactRecord(headerValue, [
      "schema_version",
      "log_kind",
      "catalog_incarnation",
      "genesis_hash",
      "genesis_signature_digest",
    ]);
    const header = {
      schema_version: asString(headerRecord.schema_version),
      log_kind: asString(headerRecord.log_kind),
      catalog_incarnation: asString(headerRecord.catalog_incarnation),
      genesis_hash: asDigest(headerRecord.genesis_hash),
      genesis_signature_digest: asDigest(headerRecord.genesis_signature_digest),
    };
    if (
      header.schema_version !== SIGNED_LOG_SCHEMA ||
      header.log_kind !== this.logKind ||
      header.catalog_incarnation !== this.catalogIncarnation
    ) {
      failHold();
    }
    const expectedGenesis = canonicalSha256({
      kind: "accounts-signed-log-genesis",
      logKind: this.logKind,
      catalogIncarnation: this.catalogIncarnation,
    });
    const genesisFrontier = {
      catalogIncarnation: this.catalogIncarnation,
      sequence: parseCounter("0"),
      hash: header.genesis_hash,
      signatureDigest: header.genesis_signature_digest,
    } satisfies SignedLogFrontier;
    if (!digestEqual(expectedGenesis, header.genesis_hash) || !this.verifyFrontier(genesisFrontier)) {
      failHold();
    }

    const records: SignedLogRecord<T>[] = [];
    let frontier = genesisFrontier;
    for (const line of lines.slice(1)) {
      if (Buffer.byteLength(line, "utf8") > MAX_RECORD_BYTES) failHold();
      const value = this.parseCanonicalLine(line);
      const record = exactRecord(value, [
        "schema_version",
        "log_kind",
        "catalog_incarnation",
        "sequence",
        "previous_hash",
        "payload",
        "payload_digest",
        "hash",
        "signature_digest",
        "receipt_digest",
      ]);
      const sequence = storedCounter(record.sequence);
      let payload: T;
      try {
        payload = this.validatePayload(record.payload);
      } catch {
        payload = failHold();
      }
      const stored = {
        schema_version: asString(record.schema_version),
        log_kind: asString(record.log_kind),
        catalog_incarnation: asString(record.catalog_incarnation),
        sequence,
        previous_hash: asDigest(record.previous_hash),
        payload,
        payload_digest: asDigest(record.payload_digest),
        hash: asDigest(record.hash),
        signature_digest: asDigest(record.signature_digest),
        receipt_digest: asDigest(record.receipt_digest),
      };
      if (
        stored.schema_version !== SIGNED_LOG_SCHEMA ||
        stored.log_kind !== this.logKind ||
        stored.catalog_incarnation !== this.catalogIncarnation ||
        stored.sequence !== storedIncrement(frontier.sequence) ||
        !digestEqual(stored.previous_hash, frontier.hash) ||
        !digestEqual(stored.payload_digest, canonicalSha256(stored.payload))
      ) {
        failHold();
      }
      const expectedHash = canonicalSha256({
        catalogIncarnation: this.catalogIncarnation,
        logKind: this.logKind,
        sequence: stored.sequence,
        previousHash: stored.previous_hash,
        payloadDigest: stored.payload_digest,
      });
      const storedFrontier = {
        catalogIncarnation: this.catalogIncarnation,
        sequence: stored.sequence,
        hash: stored.hash,
        signatureDigest: stored.signature_digest,
      } satisfies SignedLogFrontier;
      const { receipt_digest: _receiptDigest, ...receiptInput } = stored;
      if (
        !digestEqual(expectedHash, stored.hash) ||
        !this.verifyFrontier(storedFrontier) ||
        !digestEqual(stored.receipt_digest, this.hmac(receiptInput))
      ) {
        failHold();
      }
      records.push(
        Object.freeze({
          ...storedFrontier,
          previousHash: stored.previous_hash,
          payload: structuredClone(stored.payload),
          payloadDigest: stored.payload_digest,
          receiptDigest: stored.receipt_digest,
        }),
      );
      frontier = storedFrontier;
    }

    if (
      this.lastObserved !== undefined &&
      (BigInt(frontier.sequence) < BigInt(this.lastObserved.sequence) ||
        (frontier.sequence === this.lastObserved.sequence &&
          (!digestEqual(frontier.hash, this.lastObserved.hash) ||
            !digestEqual(frontier.signatureDigest, this.lastObserved.signatureDigest))))
    ) {
      failHold();
    }

    const anchor = this.readAnchor();
    if (anchor.catalogIncarnation !== frontier.catalogIncarnation) failHold();
    const anchorSequence = BigInt(anchor.sequence);
    const frontierSequence = BigInt(frontier.sequence);
    if (anchorSequence > frontierSequence) failHold();
    const anchoredFrontier =
      anchor.sequence === genesisFrontier.sequence
        ? genesisFrontier
        : records.find((record) => record.sequence === anchor.sequence);
    if (
      anchoredFrontier === undefined ||
      !digestEqual(anchor.hash, anchoredFrontier.hash) ||
      !digestEqual(anchor.signatureDigest, anchoredFrontier.signatureDigest)
    ) {
      failHold();
    }
    if (anchorSequence < frontierSequence) {
      // append() fsyncs the authenticated line before replacing the anchor.
      // A crash in that window is safe to heal only after the complete tail has
      // passed every canonical, chain, HMAC, and payload validation above.
      this.writeAnchor(frontier);
    }
    this.lastObserved = frontier;
    return Object.freeze({
      frontier: Object.freeze({ ...frontier }),
      records: Object.freeze(records),
    });
  }

  private parseCanonicalLine(line: string): unknown {
    try {
      const value = parseClosedJsonBytes(Buffer.from(line, "utf8"));
      if (canonicalJson(value) !== line) failHold();
      return value;
    } catch {
      return failHold();
    }
  }

  private readAnchor(): SignedLogFrontier {
    const bytes = readSecureBytes(this.anchorPath, MAX_RECORD_BYTES);
    if (bytes.byteLength === 0 || bytes.at(-1) !== 0x0a) failHold();
    let value: unknown;
    try {
      value = parseClosedJsonBytes(bytes.subarray(0, -1));
    } catch {
      return failHold();
    }
    const record = exactRecord(value, [
      "schema_version",
      "log_kind",
      "catalog_incarnation",
      "sequence",
      "hash",
      "signature_digest",
    ]);
    try {
      if (canonicalJson(value) !== new TextDecoder().decode(bytes.subarray(0, -1))) failHold();
    } catch {
      return failHold();
    }
    const frontier = {
      catalogIncarnation: asString(record.catalog_incarnation),
      sequence: storedCounter(record.sequence),
      hash: asDigest(record.hash),
      signatureDigest: asDigest(record.signature_digest),
    } satisfies SignedLogFrontier;
    if (
      record.schema_version !== SIGNED_LOG_ANCHOR_SCHEMA ||
      record.log_kind !== this.logKind ||
      !this.verifyFrontier(frontier)
    ) {
      failHold();
    }
    return frontier;
  }

  private writeAnchor(frontier: SignedLogFrontier): void {
    const anchor: SignedLogAnchor = {
      schema_version: SIGNED_LOG_ANCHOR_SCHEMA,
      log_kind: this.logKind,
      catalog_incarnation: frontier.catalogIncarnation,
      sequence: frontier.sequence,
      hash: frontier.hash,
      signature_digest: frontier.signatureDigest,
    };
    const temporaryPath = `${this.anchorPath}.tmp-${process.pid}-${randomBytes(12).toString("hex")}`;
    const descriptor = createSecure(temporaryPath);
    try {
      writeAll(descriptor, Buffer.from(`${canonicalJson(anchor)}\n`, "utf8"));
      fsyncSync(descriptor);
    } catch (error) {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // Preserve the original write failure.
      }
      throw error;
    } finally {
      closeSync(descriptor);
    }
    try {
      renameSync(temporaryPath, this.anchorPath);
      fsyncDirectory(this.parentPath);
    } catch {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // The ledger is now deliberately held until an operator reconciles it.
      }
      failHold();
    }
  }

  private signFrontier(frontier: Omit<SignedLogFrontier, "signatureDigest">): string {
    return this.hmac(frontier);
  }

  private hmac(value: unknown): string {
    return `sha256:${createHmac("sha256", this.signingKey)
      .update(canonicalJson(value), "utf8")
      .digest("hex")}`;
  }

  private withLock<R>(operation: () => R): R {
    assertOwnerOnlyDirectory(this.parentPath);
    const descriptor = this.acquireLock();
    try {
      assertSecureRegularFile(descriptor);
      const identity = currentProcessIdentity();
      const lock =
        identity.identityMode === "linux-proc-v1"
          ? {
              schema_version: LOCK_SCHEMA,
              identity_mode: identity.identityMode,
              pid: identity.pid,
              process_start: identity.processStart,
              boot_id: identity.bootId,
            }
          : {
              schema_version: LOCK_SCHEMA,
              identity_mode: identity.identityMode,
              pid: identity.pid,
            };
      writeAll(
        descriptor,
        Buffer.from(`${canonicalJson(lock)}\n`, "utf8"),
      );
      fsyncSync(descriptor);
      return operation();
    } finally {
      closeSync(descriptor);
      try {
        unlinkSync(this.lockPath);
        fsyncDirectory(this.parentPath);
      } catch {
        failHold();
      }
    }
  }

  private acquireLock(): number {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return openSync(
          this.lockPath,
          constants.O_CREAT |
            constants.O_EXCL |
            constants.O_WRONLY |
            NOFOLLOW |
            CLOEXEC,
          0o600,
        );
      } catch (error) {
        if (!isNodeError(error, "EEXIST") || attempt !== 0) failHold();
        this.removeStaleLock();
      }
    }
    return failHold();
  }

  private removeStaleLock(): void {
    const descriptor = openExistingSecure(this.lockPath, constants.O_RDONLY);
    try {
      const metadata = fstatSync(descriptor);
      if (metadata.size <= 0 || metadata.size > MAX_RECORD_BYTES) failHold();
      const bytes = readFileSync(descriptor);
      if (bytes.at(-1) !== 0x0a) failHold();
      let value: unknown;
      try {
        value = parseClosedJsonBytes(bytes.subarray(0, -1));
      } catch {
        return failHold();
      }
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, -1));
        if (canonicalJson(value) !== text) failHold();
      } catch {
        return failHold();
      }
      const record = exactRecord(value, [
        "schema_version",
        "identity_mode",
        "pid",
      ], ["process_start", "boot_id"]);
      if (record.schema_version !== LOCK_SCHEMA) failHold();
      const identityMode = record.identity_mode;
      const pid = record.pid;
      if (
        (identityMode !== "linux-proc-v1" && identityMode !== "pid-liveness-v1") ||
        typeof pid !== "number" ||
        !Number.isSafeInteger(pid) ||
        pid <= 0
      ) {
        failHold();
      }

      if (identityMode === "linux-proc-v1") {
        const processStart = record.process_start;
        const bootId = record.boot_id;
        if (
          typeof processStart !== "string" ||
          !PROCESS_START_PATTERN.test(processStart) ||
          typeof bootId !== "string" ||
          !BOOT_ID_PATTERN.test(bootId)
        ) {
          failHold();
        }
        const currentBootId = tryReadBootId();
        if (currentBootId === undefined) failHold();
        if (bootId === currentBootId) {
          const observedStart = observeProcessStart(pid);
          if (observedStart.kind === "UNAVAILABLE") failHold();
          if (observedStart.kind === "FOUND" && observedStart.value === processStart) {
            failHold();
          }
        }
      } else {
        if (Object.hasOwn(record, "process_start") || Object.hasOwn(record, "boot_id")) {
          failHold();
        }
        if (!pidIsDefinitivelyDead(pid)) failHold();
      }

      // Keep the verified inode open while checking that the directory entry
      // still names it, then remove only that stale identity.
      const linkMetadata = lstatSync(this.lockPath);
      if (
        linkMetadata.isSymbolicLink() ||
        linkMetadata.dev !== metadata.dev ||
        linkMetadata.ino !== metadata.ino
      ) {
        failHold();
      }
      unlinkSync(this.lockPath);
      fsyncDirectory(this.parentPath);
    } finally {
      closeSync(descriptor);
    }
  }
}

function validateRecoveryEntry(value: unknown): RecoveryLedgerEntry {
  const record = exactRecord(value, [
    "kind",
    "aggregateKind",
    "aggregateId",
    "mutationDigest",
    "occurredAt",
  ]);
  const kind = asString(record.kind);
  const aggregateKind = asString(record.aggregateKind);
  const aggregateId = asString(record.aggregateId);
  const mutationDigest = asDigest(record.mutationDigest);
  const occurredAt = asString(record.occurredAt);
  let timestampIsCanonical = false;
  try {
    timestampIsCanonical = new Date(occurredAt).toISOString() === occurredAt;
  } catch {
    timestampIsCanonical = false;
  }
  if (
    (kind !== "catalog_mutation" && kind !== "native_revocation_barrier") ||
    ![
      "account",
      "entitlement",
      "capacity_pool",
      "access_method",
      "auth_capsule",
      "credential_binding",
      "credential_operation",
    ].includes(aggregateKind) ||
    !UUID_V7_PATTERN.test(aggregateId) ||
    !timestampIsCanonical
  ) {
    failHold();
  }
  return Object.freeze({
    kind: kind as RecoveryLedgerEntry["kind"],
    aggregateKind: aggregateKind as RecoveryLedgerEntry["aggregateKind"],
    aggregateId,
    mutationDigest,
    occurredAt,
  });
}

export interface FileRecoveryLedgerOptions {
  readonly path: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
}

/** Owner-only, fsync-backed RecoveryLedger implementation for local deployments. */
export class FileRecoveryLedger implements RecoveryLedger {
  private readonly log: OwnerOnlySignedAppendLog<RecoveryLedgerEntry>;

  constructor(options: FileRecoveryLedgerOptions) {
    this.log = new OwnerOnlySignedAppendLog({
      path: options.path,
      catalogIncarnation: options.catalogIncarnation,
      signingKey: options.signingKey,
      logKind: RECOVERY_LOG_KIND,
      validatePayload: validateRecoveryEntry,
    });
  }

  readFreshFrontier(): RecoveryFrontier {
    return { ...this.log.readSnapshot().frontier };
  }

  append(expected: RecoveryFrontier, entry: RecoveryLedgerEntry): RecoveryLedgerReceipt {
    let validated: RecoveryLedgerEntry;
    try {
      validated = validateRecoveryEntry(entry);
    } catch (error) {
      if (error instanceof AccountsError && error.code === "RECOVERY_HOLD") {
        throw new AccountsError("VALIDATION_FAILED", "Recovery ledger entry is invalid");
      }
      throw error;
    }
    const record = this.log.append(expected, validated);
    return Object.freeze({
      catalogIncarnation: record.catalogIncarnation,
      sequence: record.sequence,
      hash: record.hash,
      signatureDigest: record.signatureDigest,
      previousHash: record.previousHash,
      entryDigest: record.payloadDigest,
      receiptDigest: record.receiptDigest,
    });
  }

  verifyFrontier(frontier: RecoveryFrontier): boolean {
    return this.log.verifyFrontier(frontier);
  }
}
