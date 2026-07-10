import { describe, expect, test } from "bun:test";

import { AccountsError } from "../../src/errors";
import {
  normalizePostgresConnection,
  validatePostgresRuntimeContext,
} from "../../src/storage/postgres-config";

describe("Postgres connection policy", () => {
  test("requires verify-full TLS for a self-hosted network endpoint", () => {
    const normalized = normalizePostgresConnection({
      url: "postgresql://accounts@example.internal/accounts?sslmode=verify-full",
    });

    expect(normalized.url.protocol).toBe("postgresql:");
    expect(normalized.tls).toEqual({ rejectUnauthorized: true });
  });

  test.each(["disable", "prefer", "require", "verify-ca"]) (
    "rejects the non-authoritative %s TLS mode",
    (sslmode) => {
      expect(() =>
        normalizePostgresConnection({
          url: `postgresql://accounts@example.internal/accounts?sslmode=${sslmode}`,
        }),
      ).toThrow(AccountsError);
    },
  );

  test("does not include a credential-bearing URL in validation errors", () => {
    let caught: unknown;
    try {
      normalizePostgresConnection({
        url: "postgresql://accounts:do-not-disclose@example.internal/accounts?sslmode=require",
      });
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(AccountsError);
    expect(String(caught)).not.toContain("do-not-disclose");
    expect(JSON.stringify(caught)).not.toContain("do-not-disclose");
  });

  test("permits explicit plaintext only for loopback integration tests", () => {
    expect(
      normalizePostgresConnection({
        url: "postgresql://localhost/accounts?sslmode=disable",
        allowInsecureLoopback: true,
      }).tls,
    ).toBe(false);

    expect(() =>
      normalizePostgresConnection({
        url: "postgresql://db.internal/accounts?sslmode=disable",
        allowInsecureLoopback: true,
      }),
    ).toThrow(AccountsError);
  });

  test("rejects URL fragments and connection options that can weaken TLS", () => {
    expect(() =>
      normalizePostgresConnection({
        url: "postgresql://accounts@example.internal/accounts?sslmode=verify-full#ignored",
      }),
    ).toThrow(AccountsError);
    expect(() =>
      normalizePostgresConnection({
        url: "postgresql://accounts@example.internal/accounts?sslmode=verify-full&sslrootcert=system",
      }),
    ).toThrow(AccountsError);
  });
});

describe("Postgres runtime context", () => {
  test("accepts closed Hasna principals and the Hasna identity realm", () => {
    expect(
      validatePostgresRuntimeContext({
        principalRef: "principal:service:hasna:accounts-runtime",
        identityRealm: "hasna",
      }),
    ).toEqual({
      principalRef: "principal:service:hasna:accounts-runtime",
      identityRealm: "hasna",
    });
  });

  test.each([
    { principalRef: "principal:service:other:runtime", identityRealm: "hasna" },
    { principalRef: "principal:service:hasna:runtime", identityRealm: "other" },
    { principalRef: "principal:service:hasna:runtime\nset role postgres", identityRealm: "hasna" },
  ])("rejects an invalid or foreign runtime context", (context) => {
    expect(() => validatePostgresRuntimeContext(context)).toThrow(AccountsError);
  });
});
