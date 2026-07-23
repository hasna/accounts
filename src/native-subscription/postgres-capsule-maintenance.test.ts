import { describe, expect, test } from "bun:test";

import type {
  CapsuleMaintenanceGrantReservation,
  CapsuleMaintenanceUseCommit,
} from "./capsule-maintenance.js";
import {
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
  CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
  maintenanceTargetDigest,
} from "./capsule-maintenance.js";
import { canonicalJson, canonicalSha256 } from "./json.js";
import { PostgresCapsuleMaintenanceLedger } from "./postgres-capsule-maintenance.js";
import type { PostgresSqlClient, PostgresTransaction } from "./postgres-sql.js";

const OWNER = "principal:service:hasna:accounts-maintenance";
const GRANT_ID = "018f0f00-0001-7000-8000-000000000001";
const D0 = `sha256:${"0".repeat(64)}`;
const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;
const D4 = `sha256:${"4".repeat(64)}`;
const MAINTENANCE_OPERATION_ID = "018f0f00-0002-7000-8000-000000000002";
const PROVIDER_ACCOUNT_ID = "018f0f00-0003-7000-8000-000000000003";
const ACCOUNT_LANE_ID = "018f0f00-0004-7000-8000-000000000004";
const CAPACITY_POOL_ID = "018f0f00-0005-7000-8000-000000000005";
const AUTH_CAPSULE_ID = "018f0f00-0006-7000-8000-000000000006";
const CANONICAL_NODE_ID = "018f0f00-0007-7000-8000-000000000007";
const CONSUME_RECEIPT_ID = "018f0f00-0008-7000-8000-000000000008";
const SIGNATURE = Buffer.alloc(64, 7).toString("base64url");

function maintenanceCanonicalRequestDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
): string {
  return canonicalSha256(source.action === "PROBE_NATIVE"
    ? {
        action: "PROBE_NATIVE",
        auth_capsule_id: source.auth_capsule_id,
        canonical_node_id: source.canonical_node_id,
        expected_auth_generation: source.expected_auth_generation,
        expected_auth_state_revision: source.expected_auth_state_revision,
        node_generation: source.node_generation,
        node_key_thumbprint: source.node_key_thumbprint,
        placement_generation: source.placement_generation,
        schema_version: "accounts.capsule-probe-request.v1",
        target_digest: targetDigest,
      }
    : {
        access_transport: source.access_transport,
        account_lane_id: source.account_lane_id,
        action: source.action,
        capacity_domain_ref: source.capacity_domain_ref,
        capacity_pool_id: source.capacity_pool_id,
        credential_family_id: source.credential_family_id,
        effect_class: source.effect_class,
        operation_role: source.effect_class === "containment_mutation"
          ? "CONTAINMENT"
          : "ORDINARY",
        owner_ref: source.owner_ref,
        provider_account_id: source.provider_account_id,
        provider_subject_ref: source.provider_subject_ref,
        schema_version: "accounts.credential-effect-request.v1",
        serialization_key_digest: source.serialization_key_digest,
        source_credential_generation: source.expected_credential_generation,
        source_record_revision: source.expected_record_revision,
        target_digest: targetDigest,
      });
}

function maintenanceSourceLineageDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
  requestDigest: string,
): string {
  return canonicalSha256({
    action: source.action,
    credential_family_id: source.credential_family_id,
    effect_namespace_id: source.effect_namespace_id,
    operation_role: source.effect_class === "containment_mutation"
      ? "CONTAINMENT"
      : "ORDINARY",
    request_digest: requestDigest,
    schema_version: "accounts.credential-effect-source-lineage.v1",
    serialization_key_digest: source.serialization_key_digest,
    target_digest: targetDigest,
  });
}

function maintenanceOperationDigest(
  source: Readonly<Record<string, unknown>>,
  targetDigest: string,
  requestDigest: string,
  sourceLineageDigest: string | undefined,
): string {
  return canonicalSha256(source.action === "PROBE_NATIVE"
    ? {
        action: "PROBE_NATIVE",
        canonical_request_digest: requestDigest,
        maintenance_operation_id: source.maintenance_operation_id,
        operation_execution_epoch: source.operation_execution_epoch,
        operation_step_id: "probe_native",
        schema_version: "accounts.capsule-probe-operation.v1",
        target_digest: targetDigest,
      }
    : {
        action: source.action,
        canonical_request_digest: requestDigest,
        effect_namespace_id: source.effect_namespace_id,
        maintenance_operation_id: source.maintenance_operation_id,
        operation_step_id: source.action === "REFRESH_NATIVE"
          ? "refresh_native"
          : String(source.action).toLowerCase(),
        schema_version: "accounts.credential-effect-operation.v1",
        source_lineage_digest: sourceLineageDigest,
        target_digest: targetDigest,
      });
}

function maintenanceReservationKeyDigest(
  source: Readonly<Record<string, unknown>>,
): string {
  return canonicalSha256({
    effect_namespace_id: source.effect_namespace_id,
    execution_fence_digest: source.execution_fence_digest,
    expected_credential_generation: source.expected_credential_generation,
    expected_record_revision: source.expected_record_revision,
    schema_version: "accounts.capsule-maintenance-reservation-key.v1",
    serialization_key_digest: source.serialization_key_digest,
    target_digest: maintenanceTargetDigest(source),
  });
}

function maintenanceUseId(source: Readonly<Record<string, unknown>>): string {
  return canonicalSha256({
    schema_version: "accounts.capsule-maintenance-use.v1",
    grant_id: source.grant_id,
    grant_digest: source.grant_digest,
    maintenance_operation_id: source.maintenance_operation_id,
    operation_step_id: source.operation_step_id,
    operation_execution_epoch: source.operation_execution_epoch,
    sender_key_thumbprint: source.sender_key_thumbprint,
    channel_binding_digest: source.channel_binding_digest,
    use_ordinal: source.use_ordinal,
  });
}

interface FakeGrant {
  grant_id: string;
  owner_ref: string;
  idempotency_key_digest: string;
  request_digest: string;
  reservation_key_digest: string;
  grant_digest: string;
  grant_jcs_base64url: string;
  expires_at: string;
  state: "live" | "consumed" | "expired";
}

interface FakeUse {
  grant_id: string;
  owner_ref: string;
  idempotency_key_digest: string;
  request_digest: string;
  maintenance_use_id: string;
  consume_receipt_digest: string;
  consume_receipt_jcs_base64url: string;
}

interface FakeState {
  readonly grants: FakeGrant[];
  readonly uses: FakeUse[];
  readonly modes: string[];
}

function fakeClient(state: FakeState): PostgresSqlClient {
  const transaction = (async (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<unknown[]> => {
    const query = strings.join("?").replace(/\s+/g, " ").trim();
    if (query.includes("set_config('accounts.principal'")) return [];
    if (query.includes("pg_advisory_xact_lock")) return [];
    if (query.includes("accounts.current_principal() AS principal")) {
      return [{
        principal: OWNER,
        realm: "hasna",
        role_name: "accounts_runtime",
        login_role_name: "accounts_runtime",
      }];
    }
    if (query.startsWith("UPDATE accounts.capsule_maintenance_grants") && query.includes("expires_at <=")) {
      return [];
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("idempotency_key_digest =")) {
      return state.grants.filter(
        (row) => row.owner_ref === values[0] && row.idempotency_key_digest === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("reservation_key_digest =")) {
      return state.grants
        .filter(
          (row) =>
            row.owner_ref === values[0] &&
            row.reservation_key_digest === values[1] &&
            row.state === "live",
        )
        .map((row) => ({ grant_id: row.grant_id }));
    }
    if (query.startsWith("INSERT INTO accounts.capsule_maintenance_grants")) {
      state.grants.push({
        grant_id: String(values[0]), owner_ref: String(values[1]),
        idempotency_key_digest: String(values[2]), request_digest: String(values[3]),
        reservation_key_digest: String(values[4]), grant_digest: String(values[5]),
        grant_jcs_base64url: String(values[6]), expires_at: String(values[7]), state: "live",
      });
      return [];
    }
    if (query.includes("FROM accounts.capsule_maintenance_uses") && query.includes("idempotency_key_digest =")) {
      return state.uses.filter(
        (row) => row.owner_ref === values[0] && row.idempotency_key_digest === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_grants") && query.includes("grant_id =")) {
      return state.grants.filter(
        (row) => row.owner_ref === values[0] && row.grant_id === values[1],
      );
    }
    if (query.includes("FROM accounts.capsule_maintenance_uses") && query.includes("grant_id =")) {
      return state.uses
        .filter((row) => row.owner_ref === values[0] && row.grant_id === values[1])
        .map((row) => ({ grant_id: row.grant_id }));
    }
    if (query.startsWith("INSERT INTO accounts.capsule_maintenance_uses")) {
      state.uses.push({
        grant_id: String(values[0]), owner_ref: String(values[1]),
        idempotency_key_digest: String(values[2]), request_digest: String(values[3]),
        maintenance_use_id: String(values[4]), consume_receipt_digest: String(values[5]),
        consume_receipt_jcs_base64url: String(values[6]),
      });
      return [];
    }
    if (query.startsWith("UPDATE accounts.capsule_maintenance_grants") && query.includes("state = 'consumed'")) {
      const grant = state.grants.find(
        (row) => row.owner_ref === values[1] && row.grant_id === values[2],
      );
      if (grant !== undefined) grant.state = "consumed";
      return [];
    }
    throw new Error(`unexpected fake query: ${query}`);
  }) as unknown as PostgresTransaction;
  transaction.unsafe = (() => ({
    simple: async () => [],
  })) as unknown as PostgresTransaction["unsafe"];
  return {
    begin: async (mode: string, callback: (value: PostgresTransaction) => Promise<unknown>) => {
      state.modes.push(mode);
      return callback(transaction);
    },
  } as PostgresSqlClient;
}

function grantEvidence(
  variant: "probe" | "mutation" = "probe",
): Record<string, string> {
  const evidence: Record<string, string> = {
    schema_version: CAPSULE_MAINTENANCE_GRANT_SCHEMA_VERSION,
    schema_digest: CAPSULE_MAINTENANCE_GRANT_SCHEMA_DIGEST,
    grant_id: GRANT_ID,
    issuer: "accounts-maintenance",
    issuer_incarnation: "accounts-maintenance-1",
    key_id: "accounts-maintenance-key-1",
    audience: "infinity",
    effect_namespace_id: "accounts-native-subscription",
    maintenance_authority_epoch: "1",
    maintenance_operation_id: MAINTENANCE_OPERATION_ID,
    operation_execution_epoch: "1",
    operation_execution_expires_at: "2030-07-18T12:05:00.000Z",
    execution_fence_digest: D1,
    action: variant === "probe" ? "PROBE_NATIVE" : "REFRESH_NATIVE",
    effect_class: variant === "probe" ? "read_only" : "mutation",
    target_kind: "native_capsule",
    subject: OWNER,
    actor_principal: OWNER,
    maintenance_executor_principal: OWNER,
    sender_key_thumbprint: D2,
    channel_binding_digest: D3,
    owner_ref: OWNER,
    provider_account_id: PROVIDER_ACCOUNT_ID,
    provider_subject_ref: "provider-subject",
    account_lane_id: ACCOUNT_LANE_ID,
    capacity_pool_id: CAPACITY_POOL_ID,
    capacity_domain_ref: "capacity-domain",
    serialization_key_digest: D4,
    access_transport: "native_session",
    credential_family_id: "credential-family",
    capacity_generation: "1",
    deny_generation: "0",
    expected_record_revision: "1",
    expected_credential_generation: "1",
    maintenance_decision_digest: D0,
    approval_mode: "NOT_REQUIRED",
    policy_digest: D2,
    catalog_incarnation: "catalog-1",
    recovery_frontier_sequence: "1",
    recovery_frontier_hash: D3,
    issued_at: "2030-07-18T12:00:00.000Z",
    not_before: "2030-07-18T12:00:00.000Z",
    expires_at: "2030-07-18T12:01:00.000Z",
    nonce: "nonce-1",
    max_uses: "1",
    signature: SIGNATURE,
    auth_capsule_id: AUTH_CAPSULE_ID,
    canonical_node_id: CANONICAL_NODE_ID,
    node_key_thumbprint: D4,
    node_generation: "1",
    placement_generation: "1",
    expected_auth_generation: "1",
    expected_auth_state_revision: "1",
  };
  const targetDigest = maintenanceTargetDigest(evidence);
  const canonicalRequestDigest = maintenanceCanonicalRequestDigest(
    evidence,
    targetDigest,
  );
  const sourceLineageDigest = variant === "probe"
    ? undefined
    : maintenanceSourceLineageDigest(
        evidence,
        targetDigest,
        canonicalRequestDigest,
      );
  return {
    ...evidence,
    operation_digest: maintenanceOperationDigest(
      evidence,
      targetDigest,
      canonicalRequestDigest,
      sourceLineageDigest,
    ),
    canonical_request_digest: canonicalRequestDigest,
    ...(sourceLineageDigest === undefined
      ? {}
      : {
          source_lineage_digest: sourceLineageDigest,
          maintenance_hold_receipt_digest: D2,
          drain_receipt_digest: D3,
        }),
  };
}

function grantFromEvidence(
  evidence: Record<string, string>,
  overrides: Partial<CapsuleMaintenanceGrantReservation> = {},
): CapsuleMaintenanceGrantReservation {
  const grantBytes = Uint8Array.from(Buffer.from(canonicalJson(evidence), "utf8"));
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D0,
    requestDigest: D1,
    reservationKeyDigest: maintenanceReservationKeyDigest(evidence),
    grantDigest: canonicalSha256(evidence),
    grantBytes,
    expiresAt: evidence.expires_at!,
    ...overrides,
  };
}

function grant(
  overrides: Partial<CapsuleMaintenanceGrantReservation> = {},
): CapsuleMaintenanceGrantReservation {
  return grantFromEvidence(grantEvidence(), overrides);
}

function consumeEvidence(
  sourceGrant: Record<string, string> = grantEvidence(),
): Record<string, string> {
  const grantDigest = canonicalSha256(sourceGrant);
  const evidence: Record<string, string> = {
    schema_version: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_VERSION,
    schema_digest: CAPSULE_MAINTENANCE_CONSUME_RECEIPT_SCHEMA_DIGEST,
    consume_receipt_id: CONSUME_RECEIPT_ID,
    grant_id: GRANT_ID,
    grant_digest: grantDigest,
    issuer: sourceGrant.issuer!,
    issuer_incarnation: sourceGrant.issuer_incarnation!,
    key_id: sourceGrant.key_id!,
    audience: sourceGrant.audience!,
    effect_namespace_id: sourceGrant.effect_namespace_id!,
    maintenance_authority_epoch: sourceGrant.maintenance_authority_epoch!,
    maintenance_operation_id: sourceGrant.maintenance_operation_id!,
    operation_digest: sourceGrant.operation_digest!,
    operation_step_id: sourceGrant.action === "PROBE_NATIVE"
      ? "probe_native"
      : "refresh_native",
    operation_execution_epoch: sourceGrant.operation_execution_epoch!,
    operation_execution_expires_at: sourceGrant.operation_execution_expires_at!,
    action: sourceGrant.action!,
    target_digest: maintenanceTargetDigest(sourceGrant),
    subject: sourceGrant.subject!,
    actor_principal: sourceGrant.actor_principal!,
    maintenance_executor_principal: sourceGrant.maintenance_executor_principal!,
    sender_key_thumbprint: sourceGrant.sender_key_thumbprint!,
    channel_binding_digest: sourceGrant.channel_binding_digest!,
    execution_fence_digest: sourceGrant.execution_fence_digest!,
    max_uses: "1",
    prior_use_count: "0",
    next_use_count: "1",
    use_ordinal: "1",
    committed_at: "2030-07-18T12:00:00.000Z",
    expires_at: "2030-07-18T12:01:00.000Z",
    catalog_incarnation: sourceGrant.catalog_incarnation!,
    recovery_frontier_sequence: sourceGrant.recovery_frontier_sequence!,
    recovery_frontier_hash: sourceGrant.recovery_frontier_hash!,
    signature: SIGNATURE,
    ...(sourceGrant.source_lineage_digest === undefined
      ? {}
      : { source_lineage_digest: sourceGrant.source_lineage_digest }),
  };
  return {
    ...evidence,
    maintenance_use_id: maintenanceUseId(evidence),
  };
}

function useFromEvidence(
  evidence: Record<string, string>,
  overrides: Partial<CapsuleMaintenanceUseCommit> = {},
): CapsuleMaintenanceUseCommit {
  const consumeReceiptBytes = Uint8Array.from(
    Buffer.from(canonicalJson(evidence), "utf8"),
  );
  return {
    grantId: GRANT_ID,
    ownerRef: OWNER,
    idempotencyKeyDigest: D3,
    requestDigest: D4,
    maintenanceUseId: evidence.maintenance_use_id!,
    consumeReceiptDigest: canonicalSha256(evidence),
    consumeReceiptBytes,
    committedAt: evidence.committed_at!,
    ...overrides,
  };
}

function use(
  overrides: Partial<CapsuleMaintenanceUseCommit> = {},
): CapsuleMaintenanceUseCommit {
  return useFromEvidence(consumeEvidence(), overrides);
}

describe("Postgres capsule maintenance ledger", () => {
  test("preserves exact replay across adapter restart and rejects distinct live reservations", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const first = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    const restarted = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    expect(await first.reserve(grant())).toEqual({
      status: "reserved",
      grantBytes: grant().grantBytes,
    });
    expect(await restarted.reserve(grant())).toEqual({
      status: "replayed",
      grantBytes: grant().grantBytes,
    });
    expect((await restarted.reserve(grant({ requestDigest: D4 }))).status)
      .toBe("idempotency_conflict");
    expect((await restarted.reserve(grant({ idempotencyKeyDigest: D4 }))).status)
      .toBe("reservation_conflict");
    expect(state.modes.every((mode) => mode === "isolation level serializable read write")).toBe(true);
  });

  test("commits ordinal-one evidence once and returns exact bytes on replay", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const first = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    const restarted = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    await first.reserve(grant());
    expect(await first.consume(use())).toEqual({
      status: "consumed",
      consumeReceiptBytes: use().consumeReceiptBytes,
    });
    expect(await restarted.consume(use())).toEqual({
      status: "replayed",
      consumeReceiptBytes: use().consumeReceiptBytes,
    });
    expect((await restarted.consume(use({ requestDigest: D0 }))).status)
      .toBe("idempotency_conflict");
    expect((await restarted.consume(use({ idempotencyKeyDigest: D1 }))).status)
      .toBe("exhausted");
    expect(state.uses).toHaveLength(1);
  });

  test("rejects credential-shaped arbitrary values before durable persistence", async () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    expect(() => ledger.reserve(grant({
      grantBytes: Uint8Array.from(Buffer.from(JSON.stringify({
        grant: "one",
        note: "sk-" + "A".repeat(24),
      }))),
    }))).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(() => ledger.consume(use({
      consumeReceiptBytes: Uint8Array.from(Buffer.from(JSON.stringify({
        receipt: "one",
        metadata: { password: "not-a-real-password" },
      }))),
    }))).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(state.grants).toEqual([]);
    expect(state.uses).toEqual([]);
  });

  test("rejects malformed public DTOs and arbitrary evidence before opening a transaction", async () => {
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const malformedReservations = [
      { ...grant(), unexpected: "accepted-by-structural-typing" },
      grant({ grantId: "not-a-uuid" }),
      grant({ expiresAt: "infinity" }),
      grant({ grantBytes: Uint8Array.from(Buffer.from('{"grant":"arbitrary"}')) }),
    ] as unknown as CapsuleMaintenanceGrantReservation[];
    for (const reservation of malformedReservations) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      expect(() => ledger.reserve(reservation)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
      expect(state.modes).toEqual([]);
      expect(state.grants).toEqual([]);
    }

    const malformedCommits = [
      { ...use(), unexpected: "accepted-by-structural-typing" },
      use({ committedAt: "2030-07-18T12:00:00Z" }),
      use({ consumeReceiptBytes: Uint8Array.from(Buffer.from('{"receipt":"arbitrary"}')) }),
    ] as unknown as CapsuleMaintenanceUseCommit[];
    for (const commit of malformedCommits) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      expect(() => ledger.consume(commit)).toThrow(expect.objectContaining({
        code: "VALIDATION_FAILED",
      }));
      expect(state.modes).toEqual([]);
      expect(state.uses).toEqual([]);
    }
  });

  test("rejects forged grant derivations before opening a transaction", () => {
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const validProbe = grantEvidence();
    const validMutation = grantEvidence("mutation");
    const forgedEvidence = [
      { ...validProbe, canonical_request_digest: D1 },
      { ...validProbe, operation_digest: D0 },
      { ...validMutation, source_lineage_digest: D0 },
      {
        ...validMutation,
        source_lineage_digest: D0,
        operation_digest: maintenanceOperationDigest(
          validMutation,
          maintenanceTargetDigest(validMutation),
          validMutation.canonical_request_digest!,
          D0,
        ),
      },
    ];
    for (const evidence of forgedEvidence) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      expect(() => ledger.reserve(grantFromEvidence(evidence))).toThrow(
        expect.objectContaining({ code: "VALIDATION_FAILED" }),
      );
      expect(state.modes).toEqual([]);
      expect(state.grants).toEqual([]);
    }
  });

  test("rejects a forged deterministic maintenance use id before opening a transaction", () => {
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    const forged = { ...consumeEvidence(), maintenance_use_id: D4 };
    expect(() => ledger.consume(useFromEvidence(forged))).toThrow(
      expect.objectContaining({ code: "VALIDATION_FAILED" }),
    );
    expect(state.modes).toEqual([]);
    expect(state.uses).toEqual([]);
  });

  test("compares every consume receipt binding to the stored grant before insert", async () => {
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const bindingFields = [
      "issuer",
      "issuer_incarnation",
      "key_id",
      "audience",
      "effect_namespace_id",
      "maintenance_authority_epoch",
      "maintenance_operation_id",
      "operation_digest",
      "operation_execution_epoch",
      "operation_execution_expires_at",
      "action",
      "target_digest",
      "subject",
      "actor_principal",
      "maintenance_executor_principal",
      "sender_key_thumbprint",
      "channel_binding_digest",
      "execution_fence_digest",
      "catalog_incarnation",
      "recovery_frontier_sequence",
      "recovery_frontier_hash",
    ] as const;
    for (const field of bindingFields) {
      const state: FakeState = { grants: [], uses: [], modes: [] };
      const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      await ledger.reserve(grant());
      const receipt = consumeEvidence();
      const forged = {
        ...receipt,
        [field]: field.endsWith("_digest") ||
          field.endsWith("_hash") ||
          field.endsWith("_thumbprint")
          ? D0
          : field.endsWith("_epoch") || field.endsWith("_sequence")
            ? "2"
            : field === "action"
              ? "BOOTSTRAP_NATIVE"
              : field.endsWith("_at")
                ? "2030-07-18T12:04:00.000Z"
                : field === "subject" ||
                    field === "actor_principal" ||
                    field === "maintenance_executor_principal"
                  ? "principal:service:hasna:forged"
                  : "forged",
      };
      forged.maintenance_use_id = maintenanceUseId(forged);
      await expect(
        Promise.resolve().then(() => ledger.consume(useFromEvidence(forged))),
      ).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
      expect(state.uses).toEqual([]);
    }

    const mutationGrant = grantEvidence("mutation");
    const state: FakeState = { grants: [], uses: [], modes: [] };
    const ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
    await ledger.reserve(grantFromEvidence(mutationGrant));
    const forgedMutationReceipt = {
      ...consumeEvidence(mutationGrant),
      source_lineage_digest: D0,
    };
    forgedMutationReceipt.maintenance_use_id = maintenanceUseId(forgedMutationReceipt);
    await expect(Promise.resolve().then(
      () => ledger.consume(useFromEvidence(forgedMutationReceipt)),
    )).rejects.toMatchObject({ code: "VALIDATION_FAILED" });
    expect(state.uses).toEqual([]);
  });

  test("rejects zero and negative timestamps before opening a transaction", () => {
    const role = { mode: "direct", roleName: "accounts_runtime" } as const;
    const timestamps = [
      "1970-01-01T00:00:00.000Z",
      "1969-12-31T23:59:59.999Z",
    ];
    for (const timestamp of timestamps) {
      let state: FakeState = { grants: [], uses: [], modes: [] };
      let ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      const forgedGrant = {
        ...grantEvidence(),
        expires_at: timestamp,
      };
      expect(() => ledger.reserve(grantFromEvidence(forgedGrant))).toThrow(
        expect.objectContaining({ code: "VALIDATION_FAILED" }),
      );
      expect(state.modes).toEqual([]);
      expect(state.grants).toEqual([]);

      state = { grants: [], uses: [], modes: [] };
      ledger = new PostgresCapsuleMaintenanceLedger(fakeClient(state), OWNER, role);
      const forgedReceipt = {
        ...consumeEvidence(),
        committed_at: timestamp,
      };
      forgedReceipt.maintenance_use_id = maintenanceUseId(forgedReceipt);
      expect(() => ledger.consume(useFromEvidence(forgedReceipt))).toThrow(
        expect.objectContaining({ code: "VALIDATION_FAILED" }),
      );
      expect(state.modes).toEqual([]);
      expect(state.uses).toEqual([]);
    }
  });
});
