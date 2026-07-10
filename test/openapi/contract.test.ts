import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  ACCOUNTS_CAPACITY_OPENAPI,
  serializeAccountsCapacityOpenApi,
} from "../../src/http/openapi";

const document = ACCOUNTS_CAPACITY_OPENAPI as unknown as {
  readonly paths: Readonly<Record<string, unknown>>;
  readonly components: {
    readonly schemas: Readonly<Record<string, Record<string, unknown>>>;
  };
};

describe("accounts.capacity.v1 OpenAPI", () => {
  test("keeps the generated artifact byte-identical to the served document", () => {
    const source = readFileSync(
      join(import.meta.dir, "..", "..", "openapi", "accounts.capacity.v1.json"),
      "utf8",
    );
    expect(source).toBe(serializeAccountsCapacityOpenApi());
  });

  test("contains every clean capacity route and no legacy or ceremony execution route", () => {
    const paths = Object.keys(document.paths);
    expect(paths).toEqual(expect.arrayContaining([
      "/v1/provider-accounts",
      "/v1/entitlements",
      "/v1/capacity-pools",
      "/v1/account-lanes",
      "/v1/auth-capsules",
      "/v1/auth-capsules/{id}/bootstrap-intents",
      "/v1/credential-bindings",
      "/v1/credential-operations",
      "/v1/capacity/query",
      "/internal/v1/slot-eligibility",
      "/internal/v1/generation-check",
      "/internal/v1/capacity-pool-evidence",
      "/internal/v1/execution-policy-evidence",
      "/internal/v1/credential-binding-receipts",
      "/health",
      "/ready",
      "/version",
      "/openapi.json",
    ]));
    for (const path of paths) {
      expect(path).not.toMatch(/profile|current|tool|launch|apply|switch|device|provider-login|consume|reauthenticate|lease/i);
      expect(path).not.toMatch(/tenant|signup|invite|billing/i);
    }
  });

  test("uses closed state-specific unions for every mutable resource", () => {
    for (const name of [
      "ProviderAccount",
      "Entitlement",
      "CapacityPool",
      "AccountLane",
      "AuthCapsule",
      "CredentialBinding",
    ]) {
      const schema = document.components.schemas[name]!;
      expect(Array.isArray(schema.oneOf)).toBe(true);
      expect((schema.oneOf as unknown[]).length).toBeGreaterThan(1);
      for (const variant of schema.oneOf as Record<string, unknown>[]) {
        expect(variant.additionalProperties).toBe(false);
        expect(variant.type).toBe("object");
      }
    }
  });

  test("sets additionalProperties=false on every object schema", () => {
    const visit = (value: unknown): void => {
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      if (value === null || typeof value !== "object") return;
      const record = value as Record<string, unknown>;
      if (record.type === "object") expect(record.additionalProperties).toBe(false);
      Object.values(record).forEach(visit);
    };
    visit(document.components.schemas);
  });

  test("freezes the exact nested destination policy and full receipt target unions", () => {
    const destination = document.components.schemas.ProviderDestinationPolicy!;
    expect(Object.keys(destination.properties as Record<string, unknown>).sort()).toEqual([
      "egress_policy_digest",
      "model",
      "normalized_host",
      "operation_path",
      "port",
      "request_body_digest",
      "resolved_address_class",
      "scheme",
      "tls_server_name",
    ]);
    const receipt = document.components.schemas.OnlineGenerationCheckReceipt!;
    const variants = receipt.oneOf as Record<string, unknown>[];
    expect(variants).toHaveLength(6);
    const propertySets = variants.map((variant) =>
      new Set(Object.keys(variant.properties as Record<string, unknown>)),
    );
    expect(propertySets.some((fields) => fields.has("credential_binding_id") && fields.has("broker_ref"))).toBe(true);
    expect(propertySets.some((fields) => fields.has("auth_capsule_id") && fields.has("auth_state_revision"))).toBe(true);
    for (const fields of propertySets) {
      for (const field of [
        "authority_epoch",
        "route_epoch",
        "lease_epoch",
        "operation_execution_epoch",
        "actor_principal",
        "lease_holder_principal",
        "operation_executor_principal",
        "provider_destination_policy",
        "recovery_frontier_hash",
      ]) {
        expect(fields.has(field)).toBe(true);
      }
      expect([...fields].some((field) => /[A-Z]/.test(field))).toBe(false);
      expect(fields.has("execution_epoch")).toBe(false);
    }
    for (const variant of variants) {
      const properties = variant.properties as Record<string, Record<string, unknown>>;
      expect(properties.delegation_ref).toBeUndefined();
      expect(properties.delegation_digest).toBeUndefined();
      expect(properties.max_uses!.const).toBe("1");
      expect(properties.use_count!.enum).toEqual(["0", "1"]);
      const allowed = properties.allowed!.const;
      const reasons = properties.reason_codes!;
      if (allowed === true) {
        expect(properties.deny_state!.const).toBe("allowed");
        expect(reasons.maxItems).toBe(0);
        expect(properties.current_deny).toBeUndefined();
        expect(variant["x-hasna-use-count-relation"]).toBe(
          "max_uses = 1 and use_count = 0",
        );
      } else {
        expect(allowed).toBe(false);
        expect(reasons.minItems).toBe(1);
        if (properties.deny_state!.const === "denied") {
          expect(properties.current_deny!.const).toBe(true);
          expect(variant.required as string[]).toContain("current_deny");
        } else {
          expect(properties.deny_state!.const).toBe("allowed");
          expect(properties.current_deny).toBeUndefined();
          expect(variant.required as string[]).not.toContain("current_deny");
        }
        expect(variant["x-hasna-use-count-relation"]).toContain(
          "USE_LIMIT_REACHED",
        );
      }
    }
  });

  test("freezes SlotEligibility wire targets, revision sets, and decision relation", () => {
    const variants = document.components.schemas.SlotEligibilityWire!.oneOf as Record<string, unknown>[];
    expect(variants).toHaveLength(5);
    const unresolved = variants.find((variant) =>
      Object.hasOwn(
        variant.properties as Record<string, unknown>,
        "rejection_stage",
      ),
    )!;
    expect(Object.keys(unresolved.properties as Record<string, unknown>).sort()).toEqual([
      "account_lane_id",
      "audience",
      "catalog_incarnation",
      "eligibility_request_digest",
      "eligible",
      "evidence_id",
      "expires_at",
      "issued_at",
      "issuer",
      "issuer_incarnation",
      "key_id",
      "nonce",
      "reason_codes",
      "rejection_stage",
      "schema_digest",
      "schema_version",
      "signature",
    ]);
    expect((unresolved.properties as Record<string, Record<string, unknown>>).eligible!.const).toBe(false);
    expect((unresolved.properties as Record<string, Record<string, unknown>>).rejection_stage!.const).toBe("unresolved");

    for (const variant of variants.filter((candidate) => candidate !== unresolved)) {
      const properties = variant.properties as Record<string, Record<string, unknown>>;
      for (const field of [
        "provider_key",
        "provider_subject_ref",
        "identity_realm",
        "ownership_evidence_digest",
        "terms_evidence_digest",
        "execution_policy_evidence_digest",
        "data_policy_evidence_digest",
        "isolation_policy_evidence_digest",
        "health_evidence_digest",
        "capacity_evidence_ref",
        "capacity_evidence_issuer_ref",
        "capacity_evidence_version",
        "capacity_evidence_digest",
        "capacity_evidence_issued_at",
        "capacity_evidence_expires_at",
        "capacity_evidence_generation",
        "capacity_policy_version",
        "accounts_revision_set_digest",
        "eligible",
        "reason_codes",
      ]) {
        expect(properties[field]).toBeDefined();
      }
      const target = properties.access_target as unknown as {
        properties: Record<string, unknown>;
      };
      const revisionSet = properties.record_revision_set as unknown as {
        properties: Record<string, unknown>;
      };
      const targetFields = Object.keys(target.properties).sort();
      if (targetFields.includes("auth_capsule_id")) {
        expect(targetFields).toEqual([
          "auth_capsule_id",
          "auth_generation",
          "auth_state_revision",
          "canonical_node_id",
          "kind",
          "node_generation",
          "node_key_thumbprint",
          "placement_generation",
        ]);
        expect(Object.keys(revisionSet.properties).sort()).toContain("auth_capsule");
        expect(Object.keys(revisionSet.properties)).not.toContain("credential_binding");
      } else {
        expect(targetFields).toEqual([
          "broker_ref",
          "credential_binding_id",
          "kind",
          "resolver",
        ]);
        expect(Object.keys(revisionSet.properties)).toContain("credential_binding");
        expect(Object.keys(revisionSet.properties)).not.toContain("auth_capsule");
      }
      if (properties.eligible!.const === true) {
        expect(properties.reason_codes!.maxItems).toBe(0);
        expect(properties.deny_state!.const).toBe("allowed");
      } else {
        expect(properties.eligible!.const).toBe(false);
        expect(properties.reason_codes!.minItems).toBe(1);
      }
    }
  });

  test("contains no SaaS dimensions or raw credential/capability presentation fields", () => {
    const forbidden = new Set([
      "tenantId",
      "tenant_id",
      "customerId",
      "customer_id",
      "signup",
      "invite",
      "credentialHandle",
      "credential_handle",
      "vaultPath",
      "vault_path",
      "roleArn",
      "role_arn",
      "capabilityPresentation",
      "capability_presentation",
      "deviceCode",
      "device_code",
    ]);
    const visit = (value: unknown): void => {
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      if (value === null || typeof value !== "object") return;
      for (const [key, nested] of Object.entries(value)) {
        expect(forbidden.has(key)).toBe(false);
        visit(nested);
      }
    };
    visit(document);
  });
});
