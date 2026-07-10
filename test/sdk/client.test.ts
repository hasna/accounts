import { afterEach, describe, expect, mock, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { createAccountsCapacity } from "../../src/sdk";
import { AccountsError } from "../../src/errors";
import { makeFixtureGraph, ACTOR_REF } from "../fixtures";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  mock.restore();
});

function authProvider(onAuthorize?: (signal: AbortSignal | undefined) => void) {
  return {
    authorize: async (headers: Headers, signal?: AbortSignal) => {
      onAuthorize?.(signal);
      headers.set("authorization", "Bearer test-capacity-credential-value");
    },
  };
}

describe("Accounts capacity SDK", () => {
  test("requires an explicit closed deployment and HTTPS self-hosted origin", () => {
    expect(() => createAccountsCapacity({ mode: "self_hosted", baseUrl: "http://accounts.internal", authProvider: authProvider() })).toThrow(AccountsError);
    expect(() => createAccountsCapacity({
      mode: "self_hosted",
      baseUrl: "https://accounts.internal",
      authProvider: authProvider(),
      sqlitePath: "/tmp/forbidden.db",
    } as never)).toThrow(AccountsError);
    expect(() => createAccountsCapacity({ mode: "automatic" } as never)).toThrow(AccountsError);
  });

  test("passes the caller AbortSignal through authentication and fetch", async () => {
    const graph = makeFixtureGraph("api_key");
    const safeAccount = { ...graph.account } as Record<string, unknown>;
    delete safeAccount.providerSubjectCandidateRef;
    safeAccount.providerSubjectRefRedacted = true;
    let authSignal: AbortSignal | undefined;
    let fetchSignal: AbortSignal | null | undefined;
    globalThis.fetch = mock(async (_input: RequestInfo | URL, init?: RequestInit) => {
      fetchSignal = init?.signal;
      return new Response(JSON.stringify({
        schemaVersion: "accounts.record.v1",
        kind: "account",
        data: safeAccount,
      }), { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const client = createAccountsCapacity({
      mode: "self_hosted",
      baseUrl: "https://accounts.internal",
      authProvider: authProvider((signal) => {
        authSignal = signal;
      }),
    });
    const controller = new AbortController();
    const result = await client.providerAccounts.get(graph.account.id, { signal: controller.signal });
    expect(result.id).toBe(graph.account.id);
    expect("providerSubjectCandidateRef" in result).toBe(false);
    expect(result.providerSubjectRefRedacted).toBe(true);
    expect(authSignal).toBe(controller.signal);
    expect(fetchSignal).toBe(controller.signal);
  });

  test("pre-aborted calls never authenticate, fetch, or fall back to local", async () => {
    let authorized = false;
    let fetched = false;
    globalThis.fetch = mock(async () => {
      fetched = true;
      throw new Error("must not fetch");
    }) as unknown as typeof fetch;
    const client = createAccountsCapacity({
      mode: "self_hosted",
      baseUrl: "https://accounts.internal",
      authProvider: authProvider(() => {
        authorized = true;
      }),
    });
    const controller = new AbortController();
    controller.abort();
    await expect(client.providerAccounts.list({ signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
    expect(authorized).toBe(false);
    expect(fetched).toBe(false);
  });

  test("rejects unknown response fields and credential-handle material", async () => {
    const graph = makeFixtureGraph("api_key");
    globalThis.fetch = mock(async () => new Response(JSON.stringify({
      schemaVersion: "accounts.record.v1",
      kind: "credential_binding",
      data: { ...graph.binding, credentialHandle: "forbidden" },
    }), { status: 200, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
    const client = createAccountsCapacity({
      mode: "self_hosted",
      baseUrl: "https://accounts.internal",
      authProvider: authProvider(),
    });
    await expect(client.credentialBindings.get(graph.binding.id)).rejects.toMatchObject({
      code: "VALIDATION_FAILED",
    });
  });

  test("does not reinterpret a self-hosted transport failure as a local result", async () => {
    globalThis.fetch = mock(async () => {
      throw new TypeError("synthetic network failure");
    }) as unknown as typeof fetch;
    const client = createAccountsCapacity({
      mode: "self_hosted",
      baseUrl: "https://accounts.internal",
      authProvider: authProvider(),
    });
    await expect(client.providerAccounts.list()).rejects.toMatchObject({
      code: "DEPENDENCY_UNAVAILABLE",
      retryable: true,
    });
  });

  test("local configuration binds mutations to its explicit audit actor", async () => {
    const directory = mkdtempSync(join(tmpdir(), "accounts-sdk-"));
    const client = createAccountsCapacity({
      mode: "local",
      sqlitePath: join(directory, "accounts.db"),
      actorRef: ACTOR_REF,
    });
    await expect(client.providerAccounts.create({
      providerKey: "openai",
      ownerRef: "principal:human:hasna:owner-b",
      displayLabel: "Cross owner",
    }, { idempotencyKey: "create-cross-owner" })).rejects.toMatchObject({ code: "NOT_FOUND" });
    await client.close();
    rmSync(directory, { recursive: true, force: true });
  });

  test("explicit persistent recovery makes the local SDK writable across reopen", async () => {
    const directory = mkdtempSync(join(tmpdir(), "accounts-sdk-recovery-"));
    const recovery = {
      ledgerPath: join(directory, "accounts.recovery.log"),
      catalogIncarnation: "catalog:sdk-persistent-test",
      signingKey: new Uint8Array(32).fill(0x4d),
    } as const;
    const config = {
      mode: "local" as const,
      sqlitePath: join(directory, "accounts.db"),
      actorRef: ACTOR_REF,
      recovery,
    };
    const first = createAccountsCapacity(config);
    const account = await first.providerAccounts.create(
      {
        providerKey: "provider-example",
        ownerRef: ACTOR_REF,
        displayLabel: "Persistent local account",
        providerSubjectCandidateRef: "provider-subject-local",
      },
      { idempotencyKey: "create-persistent-local" },
    );
    expect(account.status).toBe("pending");
    expect(account.providerSubjectRefRedacted).toBe(true);
    await first.close();

    const reopened = createAccountsCapacity(config);
    const listed = await reopened.providerAccounts.list();
    expect(listed.records.map((record) => record.id)).toContain(account.id);
    await reopened.close();
    rmSync(directory, { recursive: true, force: true });
  });
});
