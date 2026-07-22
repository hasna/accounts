import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderSdk, sdkClientPath } from "./sdk/generate-sdk.js";
import { buildOpenApiDoc } from "./server/openapi.js";

describe("accounts SDK", () => {
  test("generated client.ts is in sync with the OpenAPI spec", () => {
    const onDisk = readFileSync(sdkClientPath(), "utf8");
    const { code, warnings } = renderSdk();
    expect(warnings).toEqual([]);
    expect(onDisk).toBe(code);
  });

  test("SDK re-exports the typed client + env factory", async () => {
    const mod = await import("./sdk/index.js");
    expect(typeof mod.AccountsClient).toBe("function");
    expect(typeof mod.createAccountsClientFromEnv).toBe("function");
  });

  test("createAccountsClientFromEnv reads ACCOUNTS_API_URL/KEY", async () => {
    const { createAccountsClientFromEnv } = await import("./sdk/index.js");
    const client = createAccountsClientFromEnv({ env: { ACCOUNTS_API_URL: "http://x", ACCOUNTS_API_KEY: "k" } as any });
    expect(client).toBeDefined();
    expect(() => createAccountsClientFromEnv({ env: {} as any })).toThrow(/ACCOUNTS_API_URL/);
  });

  test("OpenAPI document covers health/ready/version + versioned CRUD", () => {
    const doc = buildOpenApiDoc("1.2.3");
    expect(doc.info.version).toBe("1.2.3");
    for (const p of ["/health", "/ready", "/version", "/v1/accounts", "/v1/accounts/{tool}/{name}", "/v1/current", "/v1/current/{tool}", "/v1/current/{tool}/login/activate", "/v1/tools"]) {
      expect(doc.paths[p]).toBeDefined();
    }
    expect((doc.paths["/v1/accounts"] as any).post.operationId).toBe("createAccount");
  });

  test("current-selection rollback fields remain additive for old clients", () => {
    const schemas = buildOpenApiDoc("1.2.3").components.schemas;
    expect(schemas.CurrentSelection.required).toEqual(["tool", "name", "updatedAt"]);
    expect(schemas.CurrentSelectionList.required).toEqual(["current"]);
    expect(schemas.CurrentSelection.properties.revision).toBeDefined();
    expect(schemas.CurrentSelection.properties.operationId).toBeDefined();
    expect(schemas.CurrentSelectionList.properties.transactionalLoginRollback).toBeDefined();
    expect(Object.keys(schemas.RestoreCurrentInput.properties).sort()).toEqual(["expectedName", "name"]);
    expect(schemas.RestoreLoginCurrentInput.anyOf).toHaveLength(2);
    expect(schemas.RestoreLoginCurrentInput.anyOf.map((branch: any) => branch.required).sort()).toEqual([
      ["expectedName", "expectedOperationId"],
      ["expectedName", "expectedRevision"],
    ]);
    const { code } = renderSdk();
    expect(code).toContain('export type RestoreLoginCurrentInput =');
    expect(code).toContain('"expectedRevision": string');
    expect(code).toContain('"expectedOperationId": string');
  });

  test("legacy Account responses keep incarnationId additive for old-server/new-client reads", () => {
    const schemas = buildOpenApiDoc("1.2.3").components.schemas;
    expect(schemas.Account.required).toEqual(["tool", "name", "metadata", "createdAt"]);
    expect(schemas.Account.properties.incarnationId).toMatchObject({ type: "string", format: "uuid" });
    const { code } = renderSdk();
    expect(code).toContain('"incarnationId"?: string');
  });

  test("generated login update accepts a no-email account with expectedEmail null", () => {
    const schemas = buildOpenApiDoc("1.2.3").components.schemas;
    expect(schemas.LoginUpdateAccountInput.properties.expectedEmail).toEqual({
      type: "string",
      format: "email",
      nullable: true,
    });
    const { code } = renderSdk();
    expect(code).toContain('"expectedEmail": string | null');
  });

  test("generated cleanup contract carries bounded replay time and authoritative row state", () => {
    const schemas = buildOpenApiDoc("1.2.3").components.schemas;
    expect(schemas.RemoveCreatedAccountInput.required).toContain("cleanupRequestedAt");
    expect(schemas.RemoveCreatedAccountResult.required).toEqual([
      "removed",
      "currentExists",
      "expired",
    ]);
    const { code } = renderSdk();
    expect(code).toContain('"cleanupRequestedAt": string');
    expect(code).toContain('"currentExists": boolean');
    expect(code).toContain('"expired": boolean');
  });
});
