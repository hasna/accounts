import { AccountsError } from "../errors";

const PRINCIPAL_PATTERN =
  /^principal:(?:human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface PostgresConnectionInput {
  readonly url: string | URL;
  /** Test-only escape hatch. It is accepted exclusively for a literal loopback host. */
  readonly allowInsecureLoopback?: boolean;
}

export interface NormalizedPostgresConnection {
  readonly url: URL;
  readonly tls: false | Readonly<{ rejectUnauthorized: true }>;
}

export interface PostgresRuntimeContext {
  readonly principalRef: string;
  readonly identityRealm: "hasna";
}

/**
 * Validates the connection without ever including the credential-bearing URL in
 * an exception. Self-hosted Accounts only accepts hostname-verified TLS. The
 * sole plaintext exception is an explicit literal-loopback test connection.
 */
export function normalizePostgresConnection(
  input: PostgresConnectionInput,
): NormalizedPostgresConnection {
  let url: URL;
  try {
    url = input.url instanceof URL ? new URL(input.url.href) : new URL(input.url);
  } catch {
    throw invalidConnection();
  }

  if (
    (url.protocol !== "postgres:" && url.protocol !== "postgresql:") ||
    url.hostname.length === 0 ||
    url.pathname.length <= 1 ||
    url.hash.length !== 0
  ) {
    throw invalidConnection();
  }

  const keys = [...url.searchParams.keys()];
  const modes = url.searchParams.getAll("sslmode");
  if (keys.some((key) => key !== "sslmode") || modes.length !== 1) {
    throw invalidConnection();
  }

  const mode = modes[0];
  if (mode === "verify-full") {
    return Object.freeze({
      url,
      tls: Object.freeze({ rejectUnauthorized: true as const }),
    });
  }

  if (
    input.allowInsecureLoopback === true &&
    mode === "disable" &&
    isLiteralLoopback(url.hostname)
  ) {
    return Object.freeze({ url, tls: false as const });
  }

  throw invalidConnection();
}

export function validatePostgresRuntimeContext(input: {
  readonly principalRef: string;
  readonly identityRealm: string;
}): PostgresRuntimeContext {
  if (input.identityRealm !== "hasna" || !PRINCIPAL_PATTERN.test(input.principalRef)) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid Postgres runtime context", {
      details: { field: "runtimeContext" },
    });
  }
  return Object.freeze({
    principalRef: input.principalRef,
    identityRealm: "hasna" as const,
  });
}

function isLiteralLoopback(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower === "[::1]" || lower === "::1") return true;
  const octets = lower.split(".");
  return (
    octets.length === 4 &&
    octets[0] === "127" &&
    octets.every((octet) => /^(?:0|[1-9][0-9]{0,2})$/.test(octet)) &&
    octets.every((octet) => Number(octet) <= 255)
  );
}

function invalidConnection(): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Invalid Postgres connection policy", {
    details: { field: "postgresConnection" },
  });
}
