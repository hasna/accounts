type Schema = Readonly<Record<string, unknown>>;

const string = (options: Readonly<Record<string, unknown>> = {}): Schema => ({
  type: "string",
  ...options,
});
const object = (
  properties: Readonly<Record<string, Schema>>,
  required: readonly string[],
  options: Readonly<Record<string, unknown>> = {},
): Schema => ({
  type: "object",
  additionalProperties: false,
  properties,
  required,
  ...options,
});
const array = (items: Schema, options: Readonly<Record<string, unknown>> = {}): Schema => ({
  type: "array",
  items,
  ...options,
});
const ref = (name: string): Schema => ({ $ref: `#/components/schemas/${name}` });
const constant = (value: string): Schema => string({ const: value });

const uuid7 = string({
  format: "uuid",
  pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
});
const counter = string({ pattern: "^(0|[1-9][0-9]{0,18})$", maxLength: 19 });
const positiveCounter = string({ pattern: "^[1-9][0-9]{0,18}$", maxLength: 19 });
const oneUseCounter = constant("1");
const oneUseCount = string({ enum: ["0", "1"] });
const timestamp = string({ format: "date-time" });
const reference = string({ pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$", maxLength: 255 });
const owner = string({
  pattern: "^principal:(human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
  maxLength: 160,
});
const digest = string({ pattern: "^sha256:[0-9a-f]{64}$" });
const keyedDigest = string({ pattern: "^hmac-sha256:[0-9a-f]{64}$" });
const reasonCode = string({ pattern: "^[A-Z][A-Z0-9_]{0,63}$", maxLength: 64 });

const recordBase = {
  id: uuid7,
  revision: counter,
  createdAt: timestamp,
  updatedAt: timestamp,
} as const;
const recordBaseRequired = ["id", "revision", "createdAt", "updatedAt"] as const;

const ownershipEvidence = {
  providerSubjectRefRedacted: { type: "boolean", const: true },
  ownershipEvidenceRef: reference,
  ownershipEvidenceIssuerRef: reference,
  ownershipEvidenceVersion: reference,
  ownershipEvidenceDigest: digest,
  ownershipEvidenceIssuedAt: timestamp,
  ownershipEvidenceExpiresAt: timestamp,
  ownershipGeneration: positiveCounter,
} as const;
const ownershipEvidenceRequired = Object.keys(ownershipEvidence);
const accountCommon = {
  ...recordBase,
  providerKey: string({ pattern: "^[a-z0-9][a-z0-9._-]{0,63}$" }),
  ownerRef: owner,
  displayLabel: string({ minLength: 1, maxLength: 128 }),
  providerDisplayHint: string({ minLength: 1, maxLength: 128 }),
} as const;
const accountCommonRequired = [...recordBaseRequired, "providerKey", "ownerRef", "displayLabel"];

const pendingAccount = object(
  {
    ...accountCommon,
    providerSubjectRefRedacted: { type: "boolean", const: true },
    status: constant("pending"),
  },
  [...accountCommonRequired, "status"],
  { title: "PendingProviderAccount" },
);
const evidencedAccount = (status: "active" | "suspended" | "revoked"): Schema =>
  object(
    { ...accountCommon, ...ownershipEvidence, status: constant(status) },
    [...accountCommonRequired, ...ownershipEvidenceRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}ProviderAccount` },
  );
const unevidencedRevokedAccount = object(
  { ...accountCommon, status: constant("revoked") },
  [...accountCommonRequired, "status"],
  { title: "NeverActivatedRevokedProviderAccount" },
);

const termsAllowed = object(
  {
    decision: constant("allowed"),
    useCase: reference,
    evidenceRef: reference,
    verifiedBy: reference,
    verifiedAt: timestamp,
    expiresAt: timestamp,
    termsVersion: reference,
    termsDigest: digest,
  },
  [
    "decision",
    "useCase",
    "evidenceRef",
    "verifiedBy",
    "verifiedAt",
    "expiresAt",
    "termsVersion",
    "termsDigest",
  ],
  { title: "AllowedTermsDecision" },
);
const termsDenied = object(
  {
    ...(termsAllowed.properties as Readonly<Record<string, Schema>>),
    decision: constant("denied"),
  },
  termsAllowed.required as readonly string[],
  { title: "DeniedTermsDecision" },
);
const termsUnknown = object(
  { decision: constant("unknown"), useCase: reference, reasonCode },
  ["decision", "useCase", "reasonCode"],
  { title: "UnknownTermsDecision" },
);
const capabilitySet = object(
  {
    operations: array(reference, { maxItems: 128, uniqueItems: true }),
    models: array(reference, { maxItems: 128, uniqueItems: true }),
  },
  ["operations", "models"],
);
const dataPolicy = object(
  {
    allowedClassifications: array(reference, { maxItems: 128, uniqueItems: true }),
    retentionClass: string({ enum: ["none", "transient", "bounded"] }),
    maxRetentionDays: counter,
  },
  ["allowedClassifications", "retentionClass"],
);
const entitlementCommon = {
  ...recordBase,
  accountId: uuid7,
  fundingKind: string({ enum: ["subscription", "metered", "credit", "contract", "externally_managed"] }),
} as const;
const entitlementCommonRequired = [...recordBaseRequired, "accountId", "fundingKind"];
const entitlementEvidence = {
  capabilitySet,
  capabilityEvidenceRef: reference,
  capabilityDigest: digest,
  capabilityExpiresAt: timestamp,
  executionPolicyDecisionRef: reference,
  executionPolicyDecisionDigest: digest,
  executionPolicyDecisionExpiresAt: timestamp,
  termsDecision: termsAllowed,
  dataPolicy,
  dataPolicyEvidenceRef: reference,
  dataPolicyDigest: digest,
  dataPolicyExpiresAt: timestamp,
  lastVerifiedAt: timestamp,
} as const;
const entitlementEvidenceRequired = Object.keys(entitlementEvidence);
const pendingEntitlement = object(
  {
    ...entitlementCommon,
    status: constant("pending"),
    termsDecision: { oneOf: [termsUnknown, termsDenied] },
  },
  [...entitlementCommonRequired, "status"],
  { title: "PendingEntitlement" },
);
const evidencedEntitlement = (
  status: "active" | "paused" | "expired" | "revoked",
): Schema =>
  object(
    { ...entitlementCommon, ...entitlementEvidence, status: constant(status) },
    [...entitlementCommonRequired, ...entitlementEvidenceRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}Entitlement` },
  );
const unevidencedEntitlement = (status: "paused" | "expired" | "revoked"): Schema =>
  object(
    { ...entitlementCommon, status: constant(status), termsDecision: { oneOf: [termsUnknown, termsDenied] } },
    [...entitlementCommonRequired, "status"],
    { title: `NeverActivated${status[0]!.toUpperCase()}${status.slice(1)}Entitlement` },
  );

const poolCommon = {
  ...recordBase,
  accountId: uuid7,
  capacityDomainRef: reference,
  capacityEvidenceRef: reference,
  capacityEvidenceIssuerRef: reference,
  capacityEvidenceVersion: reference,
  capacityEvidenceDigest: digest,
  capacityEvidenceIssuedAt: timestamp,
  capacityEvidenceExpiresAt: timestamp,
  capacityEvidenceGeneration: positiveCounter,
  capacityPolicyVersion: reference,
  serializationKey: reference,
  maxConcurrency: positiveCounter,
  capacityGeneration: counter,
  denyGeneration: counter,
} as const;
const poolCommonRequired = [...recordBaseRequired, ...Object.keys(poolCommon).filter((key) => !recordBaseRequired.includes(key as never))];
const capacityPoolState = (status: "pending" | "active" | "draining" | "denied" | "retired"): Schema =>
  object(
    {
      ...poolCommon,
      status: constant(status),
      denyState: constant(status === "active" ? "allowed" : "denied"),
    },
    [...poolCommonRequired, "status", "denyState"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}CapacityPool` },
  );

const health = object(
  {
    state: string({ enum: ["healthy", "degraded", "unavailable", "unknown"] }),
    evidenceRef: reference,
    observedAt: timestamp,
    expiresAt: timestamp,
  },
  ["state", "evidenceRef", "observedAt", "expiresAt"],
);
const laneCommon = {
  ...recordBase,
  entitlementId: uuid7,
  capacityPoolId: uuid7,
  adapterKey: string({ pattern: "^[a-z0-9][a-z0-9._-]{0,63}$" }),
  adapterVersion: reference,
  accessTransport: string({ enum: ["native_session", "api_key", "workload_identity"] }),
} as const;
const laneCommonRequired = [...recordBaseRequired, "entitlementId", "capacityPoolId", "adapterKey", "adapterVersion", "accessTransport"];
const laneEvidence = {
  requiredIsolationPolicyRef: reference,
  requiredIsolationPolicyDigest: digest,
  isolationEvidenceExpiresAt: timestamp,
  allowedDestinationPolicyClasses: array(reference, { maxItems: 128, uniqueItems: true }),
  parentPolicyDecisionRef: reference,
  parentPolicyDecisionDigest: digest,
  executionPolicyEvidenceRef: reference,
  executionPolicyDigest: digest,
  executionPolicyExpiresAt: timestamp,
  health,
} as const;
const laneEvidenceRequired = Object.keys(laneEvidence);
const bareLane = (status: "draft" | "disabled" | "retired"): Schema =>
  object(
    { ...laneCommon, status: constant(status) },
    [...laneCommonRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}AccountLane` },
  );
const evidencedLane = (status: "ready" | "draining" | "disabled" | "retired"): Schema =>
  object(
    { ...laneCommon, ...laneEvidence, status: constant(status) },
    [...laneCommonRequired, ...laneEvidenceRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}EvidencedAccountLane` },
  );

const capsuleAttestation = object(
  {
    evidenceRef: reference,
    issuerRef: reference,
    measurementDigest: digest,
    attestedAt: timestamp,
    expiresAt: timestamp,
  },
  ["evidenceRef", "issuerRef", "measurementDigest", "attestedAt", "expiresAt"],
);
const capsuleCommon = {
  ...recordBase,
  accessMethodId: uuid7,
  capacityPoolId: uuid7,
  kind: constant("native_session"),
  ownerRef: owner,
  placementKind: constant("enrolled_node"),
  placementRef: uuid7,
  hardwareKeyThumbprint: digest,
  nodeGeneration: positiveCounter,
  placementGeneration: positiveCounter,
  refreshOwnerRef: owner,
  refreshMode: string({ enum: ["provider_native", "interactive_owner"] }),
  authGeneration: counter,
  authStateRevision: counter,
  isolationPolicyRef: reference,
  isolationPolicyDigest: digest,
} as const;
const capsuleCommonRequired = [...recordBaseRequired, ...Object.keys(capsuleCommon).filter((key) => !recordBaseRequired.includes(key as never))];
const capsuleWithoutPositive = (status: "unprovisioned" | "bootstrapping" | "degraded" | "revoked"): Schema =>
  object(
    { ...capsuleCommon, status: constant(status) },
    [...capsuleCommonRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}AuthCapsule` },
  );
const capsuleWithPositive = (status: "ready" | "bootstrapping" | "degraded" | "revoked"): Schema =>
  object(
    { ...capsuleCommon, status: constant(status), attestation: capsuleAttestation, lastHealthAt: timestamp },
    [...capsuleCommonRequired, "status", "attestation", "lastHealthAt"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}EvidencedAuthCapsule` },
  );

const bindingCommon = {
  ...recordBase,
  accessMethodId: uuid7,
  capacityPoolId: uuid7,
  authCapsuleId: uuid7,
  credentialFamilyId: reference,
  purpose: string({ enum: ["provider_session", "api_key", "workload_identity"] }),
  resolver: string({ enum: ["brokered_secret", "workload_identity", "capsule_local_native"] }),
  credentialGeneration: counter,
  authStateRevision: counter,
  refreshMode: constant("broker_serialized"),
  policyDigest: digest,
  rotatedAt: timestamp,
} as const;
const bindingCommonRequired = [
  ...recordBaseRequired,
  "accessMethodId",
  "capacityPoolId",
  "credentialFamilyId",
  "purpose",
  "resolver",
  "credentialGeneration",
  "policyDigest",
];
const bindingEvidence = {
  bindingEvidenceRef: reference,
  bindingEvidenceIssuerRef: reference,
  bindingEvidenceDigest: digest,
  bindingEvidenceExpiresAt: timestamp,
  expiresAt: timestamp,
} as const;
const bindingEvidenceRequired = [
  "bindingEvidenceRef",
  "bindingEvidenceIssuerRef",
  "bindingEvidenceDigest",
  "bindingEvidenceExpiresAt",
];
const nonterminalBinding = (status: "pending" | "active" | "retiring"): Schema =>
  object(
    { ...bindingCommon, ...bindingEvidence, status: constant(status) },
    [...bindingCommonRequired, ...bindingEvidenceRequired, "status"],
    { title: `${status[0]!.toUpperCase()}${status.slice(1)}CredentialBinding` },
  );
const retiredBinding = object(
  {
    ...bindingCommon,
    ...bindingEvidence,
    status: constant("revoked"),
    terminalKind: constant("retired_handle_generation"),
    credentialHandleAuditDigest: keyedDigest,
    revocationBarrierReceiptDigest: digest,
    revokedAt: timestamp,
  },
  [
    ...bindingCommonRequired,
    ...bindingEvidenceRequired,
    "status",
    "terminalKind",
    "credentialHandleAuditDigest",
    "revocationBarrierReceiptDigest",
    "revokedAt",
  ],
  { title: "RetiredHandleCredentialBinding" },
);
const barrierBinding = object(
  {
    ...bindingCommon,
    status: constant("revoked"),
    terminalKind: constant("revocation_barrier"),
    lastUsableCredentialGeneration: counter,
    revocationBarrierReceiptDigest: digest,
    revokedAt: timestamp,
  },
  [
    ...bindingCommonRequired,
    "status",
    "terminalKind",
    "lastUsableCredentialGeneration",
    "revocationBarrierReceiptDigest",
    "revokedAt",
  ],
  { title: "RevocationBarrierCredentialBinding" },
);

const operation = object(
  {
    ...recordBase,
    kind: string({ enum: ["refresh", "reauthentication", "rotation", "revocation"] }),
    sourceBindingId: uuid7,
    targetBindingId: uuid7,
    credentialFamilyId: reference,
    capacityPoolId: uuid7,
    serializationKey: reference,
    expectedSourceGeneration: counter,
    expectedAuthStateRevision: counter,
    proposedTargetGeneration: counter,
    proposedAuthStateRevision: counter,
    state: string({ enum: ["requested", "quiescing", "applying", "verifying", "completed", "failed_before_dispatch", "failed", "quarantined"] }),
    idempotencyRequestHash: digest,
    barrierReceiptDigest: digest,
    completionReceiptDigest: digest,
  },
  [
    ...recordBaseRequired,
    "kind",
    "credentialFamilyId",
    "capacityPoolId",
    "serializationKey",
    "expectedSourceGeneration",
    "proposedTargetGeneration",
    "state",
    "idempotencyRequestHash",
  ],
);

const destinationPolicy = object(
  {
    scheme: string({ enum: ["https"] }),
    normalized_host: string({ format: "hostname" }),
    port: string({ pattern: "^[1-9][0-9]{0,4}$" }),
    operation_path: string({ pattern: "^/" }),
    model: reference,
    request_body_digest: digest,
    tls_server_name: string({ format: "hostname" }),
    resolved_address_class: reference,
    egress_policy_digest: digest,
  },
  [
    "scheme",
    "normalized_host",
    "port",
    "operation_path",
    "model",
    "request_body_digest",
    "tls_server_name",
    "resolved_address_class",
    "egress_policy_digest",
  ],
  { title: "ProviderDestinationPolicy" },
);

const onlineReceiptCommon = {
  schema_version: constant("accounts.online-generation-check-receipt.v1"),
  schema_digest: digest,
  receipt_id: uuid7,
  issuer: reference,
  issuer_incarnation: reference,
  key_id: reference,
  audience: reference,
  nonce: reference,
  issued_at: timestamp,
  not_before: timestamp,
  expires_at: timestamp,
  signature: string({ minLength: 1, maxLength: 512 }),
  capability_id: uuid7,
  capability_digest: digest,
  authority_epoch: positiveCounter,
  route_lineage_id: uuid7,
  route_id: uuid7,
  route_epoch: positiveCounter,
  run_id: uuid7,
  attempt_id: uuid7,
  attempt_lease_id: uuid7,
  lease_epoch: positiveCounter,
  resource_lease_id: uuid7,
  resource_id: reference,
  resource_lifecycle_generation: positiveCounter,
  lease_expires_at: timestamp,
  operation_id: uuid7,
  operation_digest: digest,
  operation_execution_epoch: positiveCounter,
  operation_execution_expires_at: timestamp,
  subject: owner,
  actor_principal: owner,
  lease_holder_principal: owner,
  operation_executor_principal: owner,
  sender_key_thumbprint: digest,
  provider_account_id: uuid7,
  account_lane_id: uuid7,
  capacity_pool_id: uuid7,
  capacity_domain_ref: reference,
  credential_family_id: reference,
  capacity_generation: counter,
  deny_generation: counter,
  credential_generation: counter,
  accounts_revision_set_digest: digest,
  slot_eligibility_digest: digest,
  approval_ref: reference,
  policy_digest: digest,
  canonical_request_digest: digest,
  provider_destination_policy: destinationPolicy,
  provider_destination_policy_digest: digest,
  sender_constraint_confirmation: digest,
  max_uses: oneUseCounter,
  use_count: oneUseCount,
  catalog_incarnation: reference,
  recovery_frontier_sequence: counter,
  recovery_frontier_hash: digest,
} as const;
const onlineReceiptCommonRequired = Object.keys(onlineReceiptCommon);
const positiveReceiptDecision = {
  allowed: { type: "boolean", const: true },
  deny_state: constant("allowed"),
  reason_codes: array(reasonCode, { maxItems: 0 }),
} as const;
const negativeAllowedReceiptDecision = {
  allowed: { type: "boolean", const: false },
  deny_state: constant("allowed"),
  reason_codes: array(reasonCode, { minItems: 1, uniqueItems: true, "x-hasna-order": "ascii_ascending" }),
} as const;
const negativeDeniedReceiptDecision = {
  allowed: { type: "boolean", const: false },
  deny_state: constant("denied"),
  reason_codes: array(reasonCode, { minItems: 1, uniqueItems: true, "x-hasna-order": "ascii_ascending" }),
  current_deny: { type: "boolean", const: true },
} as const;
type ReceiptDecision =
  | typeof positiveReceiptDecision
  | typeof negativeAllowedReceiptDecision
  | typeof negativeDeniedReceiptDecision;
const brokeredReceipt = (
  decision: ReceiptDecision,
  title: string,
): Schema => object(
  {
    ...onlineReceiptCommon,
    ...decision,
    access_transport: string({ enum: ["api_key", "workload_identity"] }),
    allowed_channel_class: constant("brokered_provider_proxy"),
    credential_binding_id: uuid7,
    broker_ref: reference,
  },
  [
    ...onlineReceiptCommonRequired,
    ...Object.keys(decision),
    "access_transport",
    "allowed_channel_class",
    "credential_binding_id",
    "broker_ref",
  ],
  {
    title,
    "x-hasna-use-count-relation":
      decision.allowed.const === true
        ? "max_uses = 1 and use_count = 0"
        : "max_uses = 1 and use_count = 1 requires reason_codes to contain USE_LIMIT_REACHED",
  },
);
const nativeReceipt = (
  decision: ReceiptDecision,
  title: string,
): Schema => object(
  {
    ...onlineReceiptCommon,
    ...decision,
    access_transport: constant("native_session"),
    allowed_channel_class: constant("capsule_remote_tool"),
    auth_capsule_id: uuid7,
    canonical_node_id: uuid7,
    node_key_thumbprint: digest,
    node_generation: positiveCounter,
    placement_generation: positiveCounter,
    auth_generation: counter,
    auth_state_revision: counter,
  },
  [
    ...onlineReceiptCommonRequired,
    ...Object.keys(decision),
    "access_transport",
    "allowed_channel_class",
    "auth_capsule_id",
    "canonical_node_id",
    "node_key_thumbprint",
    "node_generation",
    "placement_generation",
    "auth_generation",
    "auth_state_revision",
  ],
  {
    title,
    "x-hasna-use-count-relation":
      decision.allowed.const === true
        ? "max_uses = 1 and use_count = 0"
        : "max_uses = 1 and use_count = 1 requires reason_codes to contain USE_LIMIT_REACHED",
  },
);

const bootstrapIntent = object(
  {
    schemaVersion: constant("accounts.bootstrap-intent.v1"),
    id: uuid7,
    authCapsuleId: uuid7,
    ownerRef: owner,
    canonicalNodeId: uuid7,
    nodeGeneration: positiveCounter,
    placementGeneration: positiveCounter,
    authGeneration: counter,
    capsuleRevision: counter,
    status: string({ enum: ["pending", "expired"] }),
    createdAt: timestamp,
    expiresAt: timestamp,
  },
  [
    "schemaVersion",
    "id",
    "authCapsuleId",
    "ownerRef",
    "canonicalNodeId",
    "nodeGeneration",
    "placementGeneration",
    "authGeneration",
    "capsuleRevision",
    "status",
    "createdAt",
    "expiresAt",
  ],
);

const errorEnvelope = object(
  {
    schemaVersion: constant("accounts.error.v1"),
    error: object(
      {
        code: reasonCode,
        message: string({ minLength: 1, maxLength: 160 }),
        requestId: uuid7,
        retryable: { type: "boolean" },
        details: object({}, [], { maxProperties: 16 }),
      },
      ["code", "message", "requestId", "retryable", "details"],
    ),
  },
  ["schemaVersion", "error"],
);

const diagnosticAccessTarget = {
  oneOf: [
    object({ kind: constant("unresolved") }, ["kind"], { title: "UnresolvedDiagnosticTarget" }),
    object(
      {
        kind: constant("brokered"),
        credentialBindingId: uuid7,
        resolver: string({ enum: ["brokered_secret", "workload_identity"] }),
      },
      ["kind", "credentialBindingId", "resolver"],
      { title: "BrokeredDiagnosticTarget" },
    ),
    object(
      {
        kind: constant("native"),
        authCapsuleId: uuid7,
        canonicalNodeId: uuid7,
        nodeKeyThumbprint: digest,
        nodeGeneration: positiveCounter,
        placementGeneration: positiveCounter,
        authGeneration: counter,
        authStateRevision: counter,
      },
      [
        "kind",
        "authCapsuleId",
        "canonicalNodeId",
        "nodeKeyThumbprint",
        "nodeGeneration",
        "placementGeneration",
        "authGeneration",
        "authStateRevision",
      ],
      { title: "NativeDiagnosticTarget" },
    ),
  ],
} as const;
const diagnosticCommon = {
  schemaVersion: constant("accounts.slot-eligibility.v1"),
  evidenceId: uuid7,
  evidenceClass: constant("local_diagnostic"),
  authority: constant("none"),
  reservation: constant("none"),
  accessMethodId: uuid7,
  accessTarget: diagnosticAccessTarget,
  eligibilityRequestDigest: digest,
  catalogIncarnation: reference,
  recoveryFrontierSequence: counter,
  recoveryFrontierHash: digest,
  issuedAt: timestamp,
  expiresAt: timestamp,
} as const;
const diagnosticCommonRequired = [
  "schemaVersion",
  "evidenceId",
  "evidenceClass",
  "authority",
  "reservation",
  "accessMethodId",
  "accessTarget",
  "eligibilityRequestDigest",
  "issuedAt",
  "expiresAt",
];
const diagnosticPositive = object(
  {
    ...diagnosticCommon,
    eligible: { type: "boolean", const: true },
    reasonCodes: { type: "array", maxItems: 0, items: reasonCode },
    accountId: uuid7,
    entitlementId: uuid7,
    capacityPoolId: uuid7,
    ownerRef: owner,
    accessTransport: string({ enum: ["native_session", "api_key", "workload_identity"] }),
    serializationKey: reference,
    maxConcurrency: positiveCounter,
    capacityGeneration: counter,
    denyGeneration: counter,
    denyState: constant("allowed"),
    credentialFamilyId: reference,
    credentialGeneration: counter,
    recordRevisionSet: object(
      {
        account: counter,
        entitlement: counter,
        capacity_pool: counter,
        access_method: counter,
        auth_capsule: counter,
        credential_binding: counter,
      },
      ["account", "entitlement", "capacity_pool", "access_method", "credential_binding"],
    ),
  },
  [
    ...diagnosticCommonRequired,
    "catalogIncarnation",
    "recoveryFrontierSequence",
    "recoveryFrontierHash",
    "eligible",
    "reasonCodes",
    "accountId",
    "entitlementId",
    "capacityPoolId",
    "ownerRef",
    "accessTransport",
    "serializationKey",
    "maxConcurrency",
    "capacityGeneration",
    "denyGeneration",
    "denyState",
    "credentialFamilyId",
    "credentialGeneration",
    "recordRevisionSet",
  ],
  { title: "EligibleDiagnosticSlotEligibility" },
);
const diagnosticNegative = object(
  {
    ...diagnosticCommon,
    eligible: { type: "boolean", const: false },
    reasonCodes: array(reasonCode, { minItems: 1, uniqueItems: true, "x-hasna-order": "ascii_ascending" }),
    accountId: uuid7,
    entitlementId: uuid7,
    capacityPoolId: uuid7,
    ownerRef: owner,
    accessTransport: string({ enum: ["native_session", "api_key", "workload_identity"] }),
    serializationKey: reference,
    maxConcurrency: positiveCounter,
    capacityGeneration: counter,
    denyGeneration: counter,
    denyState: string({ enum: ["allowed", "denied"] }),
    credentialFamilyId: reference,
    credentialGeneration: counter,
    recordRevisionSet: object(
      {
        account: counter,
        entitlement: counter,
        capacity_pool: counter,
        access_method: counter,
        auth_capsule: counter,
        credential_binding: counter,
      },
      [],
    ),
  },
  [...diagnosticCommonRequired, "eligible", "reasonCodes", "recordRevisionSet"],
  { title: "IneligibleDiagnosticSlotEligibility" },
);

const slotRevisionCommon = {
  provider_account: counter,
  entitlement: counter,
  capacity_pool: counter,
  account_lane: counter,
} as const;
const brokeredSlotRevisionSet = object(
  {
    ...slotRevisionCommon,
    credential_binding: counter,
  },
  [...Object.keys(slotRevisionCommon), "credential_binding"],
);
const nativeSlotRevisionSet = object(
  {
    ...slotRevisionCommon,
    auth_capsule: counter,
  },
  [...Object.keys(slotRevisionCommon), "auth_capsule"],
);
const slotEvidenceCohort = {
  ownership_evidence_issuer_ref: reference,
  ownership_evidence_version: reference,
  ownership_evidence_digest: digest,
  ownership_evidence_issued_at: timestamp,
  ownership_evidence_expires_at: timestamp,
  ownership_generation: positiveCounter,
  terms_evidence_issuer_ref: reference,
  terms_evidence_version: reference,
  terms_evidence_digest: digest,
  terms_evidence_issued_at: timestamp,
  terms_evidence_expires_at: timestamp,
  execution_policy_evidence_issuer_ref: reference,
  execution_policy_evidence_version: reference,
  execution_policy_evidence_digest: digest,
  execution_policy_evidence_issued_at: timestamp,
  execution_policy_evidence_expires_at: timestamp,
  data_policy_evidence_issuer_ref: reference,
  data_policy_evidence_version: reference,
  data_policy_evidence_digest: digest,
  data_policy_evidence_issued_at: timestamp,
  data_policy_evidence_expires_at: timestamp,
  isolation_policy_evidence_issuer_ref: reference,
  isolation_policy_evidence_version: reference,
  isolation_policy_evidence_digest: digest,
  isolation_policy_evidence_issued_at: timestamp,
  isolation_policy_evidence_expires_at: timestamp,
  health_evidence_issuer_ref: reference,
  health_evidence_version: reference,
  health_evidence_digest: digest,
  health_evidence_issued_at: timestamp,
  health_evidence_expires_at: timestamp,
} as const;
const slotEvidenceCohortRequired = Object.keys(slotEvidenceCohort);
const slotWireCommon = {
  schema_version: constant("accounts.slot-eligibility.v1"),
  schema_digest: digest,
  evidence_id: uuid7,
  issuer: reference,
  issuer_incarnation: reference,
  catalog_incarnation: reference,
  audience: reference,
  key_id: reference,
  nonce: reference,
  issued_at: timestamp,
  expires_at: timestamp,
  signature: string({ minLength: 1, maxLength: 512 }),
  recovery_frontier_sequence: counter,
  recovery_frontier_hash: digest,
  accounts_build_digest: digest,
  accounts_attestation_issuer_ref: reference,
  accounts_attestation_digest: digest,
  accounts_attested_at: timestamp,
  accounts_attestation_expires_at: timestamp,
  provider_account_id: uuid7,
  entitlement_id: uuid7,
  capacity_pool_id: uuid7,
  capacity_domain_ref: reference,
  account_lane_id: uuid7,
  provider_key: string({ pattern: "^[a-z0-9][a-z0-9._-]{0,63}$" }),
  provider_subject_ref: reference,
  owner_ref: owner,
  identity_realm: reference,
  serialization_key: reference,
  max_concurrency: positiveCounter,
  capacity_evidence_ref: reference,
  capacity_evidence_issuer_ref: reference,
  capacity_evidence_version: reference,
  capacity_evidence_digest: digest,
  capacity_evidence_issued_at: timestamp,
  capacity_evidence_expires_at: timestamp,
  capacity_evidence_generation: positiveCounter,
  capacity_policy_version: reference,
  capacity_generation: counter,
  deny_generation: counter,
  credential_family_id: reference,
  credential_generation: counter,
  accounts_revision_set_digest: digest,
  eligibility_request_digest: digest,
  ...slotEvidenceCohort,
} as const;
const slotWireCommonRequired = Object.keys(slotWireCommon);
const positiveSlotDecision = {
  deny_state: constant("allowed"),
  eligible: { type: "boolean", const: true },
  reason_codes: array(reasonCode, { maxItems: 0 }),
} as const;
const negativeSlotDecision = {
  deny_state: string({ enum: ["allowed", "denied"] }),
  eligible: { type: "boolean", const: false },
  reason_codes: array(reasonCode, { minItems: 1, uniqueItems: true, "x-hasna-order": "ascii_ascending" }),
} as const;
const slotDecisionRequired = ["deny_state", "eligible", "reason_codes"] as const;
const brokeredSlotWire = (
  decision: typeof positiveSlotDecision | typeof negativeSlotDecision,
  title: string,
): Schema => object(
  {
    ...slotWireCommon,
    ...decision,
    access_transport: string({ enum: ["api_key", "workload_identity"] }),
    allowed_channel_class: constant("brokered_provider_proxy"),
    access_target: object(
      {
        kind: constant("brokered"),
        credential_binding_id: uuid7,
        broker_ref: reference,
        resolver: string({ enum: ["brokered_secret", "workload_identity"] }),
      },
      ["kind", "credential_binding_id", "broker_ref", "resolver"],
    ),
    record_revision_set: brokeredSlotRevisionSet,
    binding_policy_digest: digest,
  },
  [
    ...slotWireCommonRequired,
    ...slotDecisionRequired,
    "access_transport",
    "allowed_channel_class",
    "access_target",
    "record_revision_set",
    "binding_policy_digest",
  ],
  { title },
);
const nativeSlotWire = (
  decision: typeof positiveSlotDecision | typeof negativeSlotDecision,
  title: string,
): Schema => object(
  {
    ...slotWireCommon,
    ...decision,
    access_transport: constant("native_session"),
    allowed_channel_class: constant("capsule_remote_tool"),
    access_target: object(
      {
        kind: constant("native"),
        auth_capsule_id: uuid7,
        canonical_node_id: uuid7,
        node_key_thumbprint: digest,
        node_generation: positiveCounter,
        placement_generation: positiveCounter,
        auth_generation: counter,
        auth_state_revision: counter,
      },
      [
        "kind",
        "auth_capsule_id",
        "canonical_node_id",
        "node_key_thumbprint",
        "node_generation",
        "placement_generation",
        "auth_generation",
        "auth_state_revision",
      ],
    ),
    record_revision_set: nativeSlotRevisionSet,
    capsule_attestation_issuer_ref: reference,
    capsule_attestation_version: reference,
    capsule_attestation_digest: digest,
    capsule_attestation_issued_at: timestamp,
    capsule_attestation_expires_at: timestamp,
  },
  [
    ...slotWireCommonRequired,
    ...slotDecisionRequired,
    "access_transport",
    "allowed_channel_class",
    "access_target",
    "record_revision_set",
    "capsule_attestation_issuer_ref",
    "capsule_attestation_version",
    "capsule_attestation_digest",
    "capsule_attestation_issued_at",
    "capsule_attestation_expires_at",
  ],
  { title },
);

const unresolvedNegativeSlotWire = object(
  {
    schema_version: constant("accounts.slot-eligibility.v1"),
    schema_digest: digest,
    evidence_id: uuid7,
    issuer: reference,
    issuer_incarnation: reference,
    catalog_incarnation: reference,
    audience: reference,
    key_id: reference,
    nonce: reference,
    issued_at: timestamp,
    expires_at: timestamp,
    signature: string({ minLength: 1, maxLength: 512 }),
    account_lane_id: uuid7,
    eligibility_request_digest: digest,
    rejection_stage: constant("unresolved"),
    eligible: { type: "boolean", const: false },
    reason_codes: array(reasonCode, { minItems: 1, uniqueItems: true, "x-hasna-order": "ascii_ascending" }),
  },
  [
    "schema_version",
    "schema_digest",
    "evidence_id",
    "issuer",
    "issuer_incarnation",
    "catalog_incarnation",
    "audience",
    "key_id",
    "nonce",
    "issued_at",
    "expires_at",
    "signature",
    "account_lane_id",
    "eligibility_request_digest",
    "rejection_stage",
    "eligible",
    "reason_codes",
  ],
  { title: "UnresolvedIneligibleSlotEligibilityWire" },
);

const schemas = {
  Counter: counter,
  PositiveCounter: positiveCounter,
  ProviderAccount: {
    oneOf: [pendingAccount, evidencedAccount("active"), evidencedAccount("suspended"), evidencedAccount("revoked"), unevidencedRevokedAccount],
    discriminator: { propertyName: "status" },
  },
  Entitlement: {
    oneOf: [
      pendingEntitlement,
      evidencedEntitlement("active"),
      evidencedEntitlement("paused"),
      evidencedEntitlement("expired"),
      evidencedEntitlement("revoked"),
      unevidencedEntitlement("paused"),
      unevidencedEntitlement("expired"),
      unevidencedEntitlement("revoked"),
    ],
    discriminator: { propertyName: "status" },
  },
  CapacityPool: {
    oneOf: (["pending", "active", "draining", "denied", "retired"] as const).map(capacityPoolState),
    discriminator: { propertyName: "status" },
  },
  AccountLane: {
    oneOf: [
      bareLane("draft"),
      evidencedLane("ready"),
      evidencedLane("draining"),
      bareLane("disabled"),
      evidencedLane("disabled"),
      bareLane("retired"),
      evidencedLane("retired"),
    ],
    discriminator: { propertyName: "status" },
  },
  AuthCapsule: {
    oneOf: [
      capsuleWithoutPositive("unprovisioned"),
      capsuleWithoutPositive("bootstrapping"),
      capsuleWithPositive("bootstrapping"),
      capsuleWithPositive("ready"),
      capsuleWithoutPositive("degraded"),
      capsuleWithPositive("degraded"),
      capsuleWithoutPositive("revoked"),
      capsuleWithPositive("revoked"),
    ],
    discriminator: { propertyName: "status" },
  },
  CredentialBinding: {
    oneOf: [
      nonterminalBinding("pending"),
      nonterminalBinding("active"),
      nonterminalBinding("retiring"),
      retiredBinding,
      barrierBinding,
    ],
    discriminator: { propertyName: "status" },
  },
  CredentialOperation: operation,
  BootstrapIntent: bootstrapIntent,
  ProviderDestinationPolicy: destinationPolicy,
  OnlineGenerationCheckReceipt: {
    oneOf: [
      brokeredReceipt(positiveReceiptDecision, "AllowedBrokeredOnlineGenerationCheckReceipt"),
      brokeredReceipt(negativeAllowedReceiptDecision, "RejectedBrokeredOnlineGenerationCheckReceipt"),
      brokeredReceipt(negativeDeniedReceiptDecision, "CurrentlyDeniedBrokeredOnlineGenerationCheckReceipt"),
      nativeReceipt(positiveReceiptDecision, "AllowedNativeOnlineGenerationCheckReceipt"),
      nativeReceipt(negativeAllowedReceiptDecision, "RejectedNativeOnlineGenerationCheckReceipt"),
      nativeReceipt(negativeDeniedReceiptDecision, "CurrentlyDeniedNativeOnlineGenerationCheckReceipt"),
    ],
  },
  DiagnosticSlotEligibility: {
    oneOf: [diagnosticPositive, diagnosticNegative],
    discriminator: { propertyName: "eligible" },
  },
  SlotEligibilityWire: {
    oneOf: [
      brokeredSlotWire(positiveSlotDecision, "EligibleBrokeredSlotEligibilityWire"),
      brokeredSlotWire(negativeSlotDecision, "IneligibleBrokeredSlotEligibilityWire"),
      nativeSlotWire(positiveSlotDecision, "EligibleNativeSlotEligibilityWire"),
      nativeSlotWire(negativeSlotDecision, "IneligibleNativeSlotEligibilityWire"),
      unresolvedNegativeSlotWire,
    ],
  },
  ProviderAccountCreate: object(
    {
      schemaVersion: constant("accounts.provider-account.create.v1"),
      providerKey: string({ pattern: "^[a-z0-9][a-z0-9._-]{0,63}$" }),
      ownerRef: owner,
      displayLabel: string({ minLength: 1, maxLength: 128 }),
      providerSubjectCandidateRef: reference,
      providerDisplayHint: string({ minLength: 1, maxLength: 128 }),
    },
    ["schemaVersion", "providerKey", "ownerRef", "displayLabel"],
  ),
  EntitlementCreate: object(
    {
      schemaVersion: constant("accounts.entitlement.create.v1"),
      providerAccountId: uuid7,
      fundingKind: string({ enum: ["subscription", "metered", "credit", "contract", "externally_managed"] }),
    },
    ["schemaVersion", "providerAccountId", "fundingKind"],
  ),
  AccountLaneCreate: object(
    {
      schemaVersion: constant("accounts.account-lane.create.v1"),
      entitlementId: uuid7,
      capacityPoolId: uuid7,
      adapterKey: string({ pattern: "^[a-z0-9][a-z0-9._-]{0,63}$" }),
      adapterVersion: reference,
      accessTransport: string({ enum: ["native_session", "api_key", "workload_identity"] }),
    },
    ["schemaVersion", "entitlementId", "capacityPoolId", "adapterKey", "adapterVersion", "accessTransport"],
  ),
  BootstrapIntentCreate: object(
    {
      schemaVersion: constant("accounts.bootstrap-intent.create.v1"),
      reasonCode,
    },
    ["schemaVersion", "reasonCode"],
  ),
  CredentialOperationRequest: object(
    {
      schemaVersion: constant("accounts.credential-operation.request.v1"),
      kind: string({ enum: ["rotation", "revocation"] }),
      credentialBindingId: uuid7,
      expectedRevision: counter,
      reasonCode,
    },
    ["schemaVersion", "kind", "credentialBindingId", "expectedRevision", "reasonCode"],
  ),
  CapacityQueryRequest: object(
    {
      accessMethodId: uuid7,
      operation: reference,
      model: reference,
      dataClassification: reference,
      destinationPolicyClass: reference,
    },
    ["accessMethodId", "operation", "model", "dataClassification", "destinationPolicyClass"],
  ),
  InternalSlotEligibilityRequest: object(
    {
      account_lane_id: uuid7,
      operation: reference,
      model: reference,
      data_classification: reference,
      destination_policy_class: reference,
      audience: reference,
      nonce: reference,
    },
    ["account_lane_id", "operation", "model", "data_classification", "destination_policy_class", "audience", "nonce"],
  ),
  InternalGenerationCheckRequest: object(
    {
      account_lane_id: uuid7,
      capability_id: uuid7,
      capability_digest: digest,
      authority_epoch: positiveCounter,
      route_lineage_id: uuid7,
      route_id: uuid7,
      route_epoch: positiveCounter,
      run_id: uuid7,
      attempt_id: uuid7,
      attempt_lease_id: uuid7,
      lease_epoch: positiveCounter,
      resource_lease_id: uuid7,
      resource_id: reference,
      resource_lifecycle_generation: positiveCounter,
      operation_id: uuid7,
      operation_digest: digest,
      operation_execution_epoch: positiveCounter,
      actor_principal: owner,
      lease_holder_principal: owner,
      operation_executor_principal: owner,
      sender_key_thumbprint: digest,
      canonical_request_digest: digest,
      slot_eligibility_digest: digest,
    },
    [
      "account_lane_id",
      "capability_id",
      "capability_digest",
      "authority_epoch",
      "route_lineage_id",
      "route_id",
      "route_epoch",
      "run_id",
      "attempt_id",
      "attempt_lease_id",
      "lease_epoch",
      "resource_lease_id",
      "resource_id",
      "resource_lifecycle_generation",
      "operation_id",
      "operation_digest",
      "operation_execution_epoch",
      "actor_principal",
      "lease_holder_principal",
      "operation_executor_principal",
      "sender_key_thumbprint",
      "canonical_request_digest",
      "slot_eligibility_digest",
    ],
  ),
  SafeEvidenceIngestion: object(
    {
      schema_version: constant("accounts.authority-evidence.v1"),
      evidence_type: reference,
      evidence_ref: reference,
      subject_ref: reference,
      aggregate_kind: reference,
      aggregate_id: uuid7,
      aggregate_revision: counter,
      identity_realm: constant("hasna"),
      issuer_ref: reference,
      issuer_class: reference,
      issuer_incarnation: reference,
      audience: reference,
      key_id: reference,
      issued_at: timestamp,
      expires_at: timestamp,
      nonce: reference,
      evidence_generation: positiveCounter,
      payload_digest: digest,
      signature: string({ minLength: 1, maxLength: 512 }),
      provider_account_id: uuid7,
      entitlement_id: uuid7,
      account_lane_id: uuid7,
      capacity_pool_id: uuid7,
      credential_binding_id: uuid7,
    },
    [
      "schema_version",
      "evidence_type",
      "evidence_ref",
      "subject_ref",
      "aggregate_kind",
      "aggregate_id",
      "aggregate_revision",
      "identity_realm",
      "issuer_ref",
      "issuer_class",
      "issuer_incarnation",
      "audience",
      "key_id",
      "issued_at",
      "expires_at",
      "nonce",
      "evidence_generation",
      "payload_digest",
      "signature",
    ],
  ),
  ErrorEnvelope: errorEnvelope,
} as const;

const successJson = (schema: Schema): Readonly<Record<string, unknown>> => ({
  description: "Success",
  content: { "application/json": { schema } },
});
const errors = {
  "400": { description: "Invalid closed request", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
  "403": { description: "Authentication, scope, or owner denied", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
  "404": { description: "Not found, including cross-owner identifiers", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
  "409": { description: "Revision or idempotency conflict", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
  "422": { description: "Policy denied", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
  "503": { description: "Required authority unavailable", content: { "application/json": { schema: ref("ErrorEnvelope") } } },
} as const;
const security = (scope: string): readonly Readonly<Record<string, readonly string[]>>[] => [
  { capacityBearer: [scope] },
];
const jsonBody = (schemaName: keyof typeof schemas): Readonly<Record<string, unknown>> => ({
  required: true,
  content: { "application/json": { schema: ref(schemaName) } },
});
const recordResponse = (schemaName: keyof typeof schemas): Schema =>
  object(
    {
      schemaVersion: constant("accounts.record.v1"),
      kind: reference,
      data: ref(schemaName),
    },
    ["schemaVersion", "kind", "data"],
  );
const listResponse = (schemaName: keyof typeof schemas): Schema =>
  object(
    {
      schemaVersion: constant("accounts.list.v1"),
      kind: reference,
      route: string({ pattern: "^/v1/" }),
      records: array(ref(schemaName)),
      nextCursor: { oneOf: [string({ pattern: "^[A-Za-z0-9_-]{48}$" }), { type: "null" }] },
    },
    ["schemaVersion", "kind", "route", "records", "nextCursor"],
  );
const listParameters = [
  { name: "cursor", in: "query", required: false, schema: string({ pattern: "^[A-Za-z0-9_-]{48}$" }) },
  { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 100, default: 50 } },
] as const;
const idParameter = { name: "id", in: "path", required: true, schema: uuid7 } as const;
const mutationHeaders = [
  { name: "Idempotency-Key", in: "header", required: true, schema: string({ pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }) },
] as const;

const resourcePaths = (
  route: string,
  schemaName: keyof typeof schemas,
  createSchema?: keyof typeof schemas,
): Readonly<Record<string, unknown>> => ({
  [`/v1/${route}`]: {
    get: {
      operationId: `list${schemaName}`,
      security: security("accounts:read"),
      parameters: listParameters,
      responses: { "200": successJson(listResponse(schemaName)), ...errors },
    },
    ...(createSchema === undefined
      ? {}
      : {
          post: {
            operationId: `create${schemaName}`,
            security: security("accounts:write"),
            parameters: mutationHeaders,
            requestBody: jsonBody(createSchema),
            responses: { "201": successJson(ref(schemaName)), ...errors },
          },
        }),
  },
  [`/v1/${route}/{id}`]: {
    get: {
      operationId: `get${schemaName}`,
      security: security("accounts:read"),
      parameters: [idParameter],
      responses: { "200": successJson(recordResponse(schemaName)), ...errors },
    },
  },
});

export const ACCOUNTS_CAPACITY_OPENAPI = Object.freeze({
  openapi: "3.1.0",
  info: {
    title: "Hasna Accounts Capacity API",
    version: "1.0.0",
    description: "Owner-scoped, non-SaaS Accounts capacity metadata. This API does not issue leases or expose credential material.",
  },
  jsonSchemaDialect: "https://json-schema.org/draft/2020-12/schema",
  servers: [{ url: "https://accounts.capacity.hasna.internal" }],
  tags: [
    { name: "catalog" },
    { name: "capacity" },
    { name: "internal" },
    { name: "operations" },
  ],
  paths: {
    ...resourcePaths("provider-accounts", "ProviderAccount", "ProviderAccountCreate"),
    ...resourcePaths("entitlements", "Entitlement", "EntitlementCreate"),
    ...resourcePaths("capacity-pools", "CapacityPool"),
    ...resourcePaths("account-lanes", "AccountLane", "AccountLaneCreate"),
    ...resourcePaths("auth-capsules", "AuthCapsule"),
    ...resourcePaths("credential-bindings", "CredentialBinding"),
    "/v1/auth-capsules/{id}/bootstrap-intents": {
      post: {
        operationId: "createBootstrapIntent",
        security: security("accounts:capsules:bootstrap-intent"),
        parameters: [
          idParameter,
          ...mutationHeaders,
          { name: "If-Match", in: "header", required: true, schema: counter },
        ],
        requestBody: jsonBody("BootstrapIntentCreate"),
        responses: { "201": successJson(ref("BootstrapIntent")), ...errors },
      },
    },
    "/v1/auth-capsules/{id}/bootstrap-intents/{intentId}": {
      get: {
        operationId: "getBootstrapIntent",
        security: security("accounts:capsules:bootstrap-intent"),
        parameters: [idParameter, { name: "intentId", in: "path", required: true, schema: uuid7 }],
        responses: { "200": successJson(ref("BootstrapIntent")), ...errors },
      },
    },
    "/v1/credential-operations": {
      get: {
        operationId: "listCredentialOperations",
        security: security("accounts:read"),
        responses: { "200": successJson(array(ref("CredentialOperation"))), ...errors },
      },
      post: {
        operationId: "requestCredentialOperation",
        description: "Creates brokered_secret or workload_identity intent only. Native ceremony is rejected.",
        security: security("accounts:credentials:request"),
        parameters: mutationHeaders,
        requestBody: jsonBody("CredentialOperationRequest"),
        responses: { "202": successJson(ref("CredentialOperation")), ...errors },
      },
    },
    "/v1/credential-operations/{id}": {
      get: {
        operationId: "getCredentialOperation",
        security: security("accounts:read"),
        parameters: [idParameter],
        responses: { "200": successJson(ref("CredentialOperation")), ...errors },
      },
    },
    "/v1/capacity/query": {
      post: {
        operationId: "queryCapacity",
        description: "Non-reservational diagnostic only; never acquires or issues a lease.",
        security: security("accounts:read"),
        requestBody: jsonBody("CapacityQueryRequest"),
        responses: { "200": successJson(object({ schemaVersion: constant("accounts.capacity-query.v1"), reservation: constant("none"), data: ref("DiagnosticSlotEligibility") }, ["schemaVersion", "reservation", "data"])), ...errors },
      },
    },
    "/internal/v1/slot-eligibility": {
      post: {
        operationId: "issueSlotEligibility",
        security: security("accounts:eligibility:issue"),
        requestBody: jsonBody("InternalSlotEligibilityRequest"),
        responses: { "200": successJson(ref("SlotEligibilityWire")), ...errors },
      },
    },
    "/internal/v1/generation-check": {
      post: {
        operationId: "checkGeneration",
        security: security("accounts:generation:check"),
        requestBody: jsonBody("InternalGenerationCheckRequest"),
        responses: { "200": successJson(ref("OnlineGenerationCheckReceipt")), ...errors },
      },
    },
    "/internal/v1/capacity-pool-evidence": {
      post: {
        operationId: "ingestCapacityPoolEvidence",
        security: security("accounts:capacity-pools:attest"),
        requestBody: jsonBody("SafeEvidenceIngestion"),
        responses: { "200": successJson(object({}, [], { description: "Safe evidence projection" })), ...errors },
      },
    },
    "/internal/v1/execution-policy-evidence": {
      post: {
        operationId: "ingestExecutionPolicyEvidence",
        security: security("accounts:execution-policy:attest"),
        requestBody: jsonBody("SafeEvidenceIngestion"),
        responses: { "200": successJson(object({}, [], { description: "Safe evidence projection" })), ...errors },
      },
    },
    "/internal/v1/credential-binding-receipts": {
      post: {
        operationId: "ingestCredentialBindingReceipt",
        description: "Safe signed receipt metadata only; raw handles are excluded.",
        security: security("accounts:credentials:issue"),
        requestBody: jsonBody("SafeEvidenceIngestion"),
        responses: { "200": successJson(object({}, [], { description: "Safe receipt projection" })), ...errors },
      },
    },
    "/health": { get: { operationId: "health", security: [], responses: { "200": successJson(object({ schemaVersion: constant("accounts.health.v1"), status: constant("ok") }, ["schemaVersion", "status"])) } } },
    "/ready": { get: { operationId: "ready", security: [], responses: { "200": successJson(object({ schemaVersion: constant("accounts.readiness.v1"), status: constant("ready") }, ["schemaVersion", "status"])), "503": successJson(object({ schemaVersion: constant("accounts.readiness.v1"), status: constant("not_ready") }, ["schemaVersion", "status"])) } } },
    "/version": { get: { operationId: "version", security: [], responses: { "200": successJson(object({ schemaVersion: constant("accounts.version.v1"), version: string(), contractSha256: string({ pattern: "^[0-9a-f]{64}$" }) }, ["schemaVersion", "version", "contractSha256"])) } } },
    "/openapi.json": { get: { operationId: "openApi", security: [], responses: { "200": { description: "This document", content: { "application/json": { schema: object({}, [], { description: "OpenAPI 3.1 document" }) } } } } } },
  },
  components: {
    securitySchemes: {
      capacityBearer: {
        type: "oauth2",
        description: "Separately audienced Hasna capacity credential; legacy profile keys are rejected.",
        flows: {
          clientCredentials: {
            tokenUrl: "https://identities.hasna.internal/oauth/token",
            scopes: Object.fromEntries([
              "accounts:read",
              "accounts:write",
              "accounts:provider-ownership:verify",
              "accounts:capacity-pools:attest",
              "accounts:terms:attest",
              "accounts:execution-policy:attest",
              "accounts:health:report",
              "accounts:placement:attest",
              "accounts:deployment:attest",
              "accounts:capsules:bootstrap-intent",
              "accounts:credentials:request",
              "accounts:credentials:issue",
              "accounts:credentials:handles:read",
              "accounts:eligibility:issue",
              "accounts:generation:check",
              "accounts:admin",
            ].map((scope) => [scope, scope])),
          },
        },
      },
    },
    schemas,
  },
} as const satisfies Readonly<Record<string, unknown>>);

export function serializeAccountsCapacityOpenApi(): string {
  return `${JSON.stringify(ACCOUNTS_CAPACITY_OPENAPI, null, 2)}\n`;
}
