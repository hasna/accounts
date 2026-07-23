export const ACCOUNT_ERROR_CODES = [
  "VALIDATION_FAILED",
  "NOT_FOUND",
  "FORBIDDEN",
  "IDEMPOTENCY_CONFLICT",
  "CONFLICT",
  "STALE_REVISION",
  "INVALID_TRANSITION",
  "TERMS_NOT_ALLOWED",
  "POLICY_DENIED",
  "CAPSULE_NOT_READY",
  "STALE_ATTESTATION",
  "STALE_CREDENTIAL_GENERATION",
  "STALE_AUTH_STATE_REVISION",
  "CAPACITY_DOMAIN_CONFLICT",
  "CURRENT_DENY",
  "INVALID_ACCESS_TARGET",
  "DEPENDENCY_UNAVAILABLE",
  "RECOVERY_HOLD",
  "COUNTER_EXHAUSTED",
  "SCHEMA_VERSION_UNSUPPORTED",
  "SCHEMA_CHECKSUM_MISMATCH",
  "DATABASE_PATH_UNSAFE",
  "NOT_IMPLEMENTED",
] as const;

export type AccountErrorCode = (typeof ACCOUNT_ERROR_CODES)[number];

export type SafeErrorDetail = string | boolean | readonly string[];
export type SafeErrorDetails = Readonly<Record<string, SafeErrorDetail>>;

const PUBLIC_MESSAGES: Readonly<Record<AccountErrorCode, string>> = {
  VALIDATION_FAILED: "The request is invalid",
  NOT_FOUND: "The requested record was not found",
  FORBIDDEN: "The operation is not permitted",
  IDEMPOTENCY_CONFLICT: "The idempotency key conflicts with an earlier request",
  CONFLICT: "The request conflicts with current state",
  STALE_REVISION: "The record revision is stale",
  INVALID_TRANSITION: "The lifecycle transition is invalid",
  TERMS_NOT_ALLOWED: "Current terms evidence does not allow the operation",
  POLICY_DENIED: "Policy denied the operation",
  CAPSULE_NOT_READY: "The authentication capsule is not ready",
  STALE_ATTESTATION: "The authentication capsule attestation is stale",
  STALE_CREDENTIAL_GENERATION: "The credential generation is stale",
  STALE_AUTH_STATE_REVISION: "The authentication state revision is stale",
  CAPACITY_DOMAIN_CONFLICT: "The capacity domain conflicts with current state",
  CURRENT_DENY: "Current denial state blocks the operation",
  INVALID_ACCESS_TARGET: "The access target is invalid",
  DEPENDENCY_UNAVAILABLE: "A required dependency is unavailable",
  RECOVERY_HOLD: "Recovery state blocks the operation",
  COUNTER_EXHAUSTED: "A monotonic counter cannot advance safely",
  SCHEMA_VERSION_UNSUPPORTED: "The schema version is not supported",
  SCHEMA_CHECKSUM_MISMATCH: "The database schema checksum does not match",
  DATABASE_PATH_UNSAFE: "The database path is unsafe",
  NOT_IMPLEMENTED: "The requested adapter is not implemented",
};

const SAFE_DETAIL_KEYS = new Set([
  "aggregateKind",
  "aggregateId",
  "expectedRevision",
  "actualRevision",
  "fromStatus",
  "toStatus",
  "field",
  "reasonCodes",
  "schemaVersion",
  "adapter",
  "operation",
]);

function sanitizeDetails(details: SafeErrorDetails): SafeErrorDetails {
  const safe: Record<string, SafeErrorDetail> = Object.create(null) as Record<
    string,
    SafeErrorDetail
  >;
  for (const [key, value] of Object.entries(details)) {
    if (!SAFE_DETAIL_KEYS.has(key)) continue;
    const valid = (() => {
      if (typeof value === "boolean") return true;
      if (Array.isArray(value)) {
        return value.length <= 16 && value.every((item) => /^[A-Z][A-Z0-9_]{0,63}$/.test(item));
      }
      if (typeof value !== "string") return false;
      switch (key) {
        case "aggregateKind":
          return /^(?:account|entitlement|capacity_pool|access_method|auth_capsule|credential_binding)$/.test(value);
        case "aggregateId":
          return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
        case "expectedRevision":
        case "actualRevision":
          return /^(?:0|[1-9][0-9]{0,18})$/.test(value);
        case "fromStatus":
        case "toStatus":
          return /^[a-z][a-z_]{0,31}$/.test(value);
        case "field":
          return /^[A-Za-z][A-Za-z0-9_.]{0,63}$/.test(value);
        case "schemaVersion":
          return /^[a-z][a-z0-9.-]{0,63}$/.test(value);
        case "adapter":
          return /^(?:memory|sqlite|postgres)$/.test(value);
        case "operation":
          return /^[a-z][a-z0-9_]{0,63}$/.test(value);
        default:
          return false;
      }
    })();
    if (valid) {
      safe[key] = value;
    }
  }
  return Object.freeze(safe);
}

export class AccountsError extends Error {
  readonly code: AccountErrorCode;
  readonly retryable: boolean;
  readonly details: SafeErrorDetails;

  constructor(
    code: AccountErrorCode,
    _message: string,
    options: {
      retryable?: boolean;
      details?: SafeErrorDetails;
    } = {},
  ) {
    super(PUBLIC_MESSAGES[code]);
    this.name = "AccountsError";
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.details = sanitizeDetails(options.details ?? {});
  }
}

export interface ErrorEnvelope {
  readonly schemaVersion: "accounts.error.v1";
  readonly error: {
    readonly code: AccountErrorCode;
    readonly message: string;
    readonly requestId: string;
    readonly retryable: boolean;
    readonly details: SafeErrorDetails;
  };
}

export function asAccountsError(error: unknown): AccountsError {
  if (error instanceof AccountsError) return error;
  return new AccountsError("DEPENDENCY_UNAVAILABLE", PUBLIC_MESSAGES.DEPENDENCY_UNAVAILABLE);
}

export function toErrorEnvelope(error: unknown, requestId: string): ErrorEnvelope {
  const safe = asAccountsError(error);
  return {
    schemaVersion: "accounts.error.v1",
    error: {
      code: safe.code,
      message: PUBLIC_MESSAGES[safe.code],
      requestId,
      retryable: safe.retryable,
      details: safe.details,
    },
  };
}

export function exitCodeForError(error: AccountsError): number {
  switch (error.code) {
    case "VALIDATION_FAILED":
    case "SCHEMA_VERSION_UNSUPPORTED":
      return 2;
    case "NOT_FOUND":
      return 3;
    case "CONFLICT":
    case "IDEMPOTENCY_CONFLICT":
    case "STALE_REVISION":
    case "INVALID_TRANSITION":
    case "COUNTER_EXHAUSTED":
      return 4;
    case "FORBIDDEN":
      return 5;
    case "DEPENDENCY_UNAVAILABLE":
    case "RECOVERY_HOLD":
    case "NOT_IMPLEMENTED":
    case "SCHEMA_CHECKSUM_MISMATCH":
    case "DATABASE_PATH_UNSAFE":
      return 6;
    case "TERMS_NOT_ALLOWED":
    case "POLICY_DENIED":
    case "CAPSULE_NOT_READY":
    case "STALE_ATTESTATION":
    case "STALE_CREDENTIAL_GENERATION":
    case "STALE_AUTH_STATE_REVISION":
    case "CAPACITY_DOMAIN_CONFLICT":
    case "CURRENT_DENY":
    case "INVALID_ACCESS_TARGET":
      return 7;
  }
}
