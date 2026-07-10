import { describe, expect, test } from "bun:test";
import type { SQL } from "bun";

import { AccountsError } from "../../src/errors";
import { InMemoryRecoveryLedger } from "../../src/storage/recovery";
import {
  POSTGRES_ACCOUNTS_CONTRACT_SHA256,
  POSTGRES_ADAPTER_STATUS_V1,
  PostgresAccountsRepository,
  postgresSqlState,
} from "../../src/storage/postgres";
import { ACCOUNTS_V1_CONTRACT_SHA256 } from "../../src/version";

const digest = (character: string): string => `sha256:${character.repeat(64)}`;

const authority = {
  principalRef: "principal:service:hasna:accounts-runtime",
  identityRealm: "hasna" as const,
  organizationRef: "organization:hasna",
  catalogIncarnation: "catalog:postgres-unit",
  buildDigest: digest("a"),
  configurationAttestationDigest: digest("b"),
  recoveryLedger: new InMemoryRecoveryLedger("catalog:postgres-unit", Buffer.alloc(32, 9)),
};

describe("Postgres adapter boundary", () => {
  test("is implemented and wired for self-hosted conformance", () => {
    expect(POSTGRES_ADAPTER_STATUS_V1).toEqual({
      adapter: "postgres",
      implemented: true,
      conformanceClaim: true,
      target: "self_hosted",
    });
    expect(POSTGRES_ACCOUNTS_CONTRACT_SHA256).toBe(ACCOUNTS_V1_CONTRACT_SHA256);
  });

  test("validates authority before touching a database client", () => {
    expect(
      () =>
        new PostgresAccountsRepository(null as unknown as SQL, {
          ...authority,
          buildDigest: "not-a-digest",
        }),
    ).toThrow(AccountsError);
    expect(
      () =>
        new PostgresAccountsRepository(null as unknown as SQL, {
          ...authority,
          principalRef: "principal:service:foreign:runtime",
        }),
    ).toThrow(AccountsError);
  });

  test("refuses to create a network client without verify-full TLS", () => {
    expect(() =>
      PostgresAccountsRepository.connect({
        ...authority,
        url: "postgresql://accounts@example.internal/accounts?sslmode=require",
      }),
    ).toThrow(AccountsError);
  });

  test("bounds the connection pool before creating a client", () => {
    expect(() =>
      PostgresAccountsRepository.connect({
        ...authority,
        url: "postgresql://accounts@example.internal/accounts?sslmode=verify-full",
        maxConnections: 0,
      }),
    ).toThrow(AccountsError);
    expect(() =>
      PostgresAccountsRepository.connect({
        ...authority,
        url: "postgresql://accounts@example.internal/accounts?sslmode=verify-full",
        maxConnections: 33,
      }),
    ).toThrow(AccountsError);
  });

  test("extracts PostgreSQL SQLSTATE from Bun's errno without trusting wrapper codes", () => {
    expect(
      postgresSqlState({ code: "ERR_POSTGRES_SERVER_ERROR", errno: "23505" }),
    ).toBe("23505");
    expect(postgresSqlState({ code: "23503" })).toBe("23503");
    expect(postgresSqlState({ code: "ERR_POSTGRES_SERVER_ERROR" })).toBeUndefined();
  });
});
