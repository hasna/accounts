import { createHash } from "node:crypto";

export const SQLITE_SCHEMA_VERSION = 2;

export const SQLITE_MIGRATION_V1 = `
CREATE TABLE provider_accounts (
  id TEXT PRIMARY KEY,
  provider_key TEXT NOT NULL,
  owner_ref TEXT NOT NULL,
  provider_subject_ref TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','active','suspended','revoked')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE UNIQUE INDEX provider_accounts_active_subject
  ON provider_accounts(provider_key, provider_subject_ref)
  WHERE provider_subject_ref IS NOT NULL AND status <> 'pending';

CREATE TABLE provider_subject_claims (
  provider_key TEXT NOT NULL,
  provider_subject_ref TEXT NOT NULL,
  owner_ref TEXT NOT NULL,
  provider_account_id TEXT NOT NULL REFERENCES provider_accounts(id) ON DELETE RESTRICT,
  claimed_at TEXT NOT NULL,
  PRIMARY KEY (provider_key, provider_subject_ref),
  UNIQUE (provider_account_id)
);

CREATE TABLE entitlements (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES provider_accounts(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('pending','active','paused','expired','revoked')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE capacity_pools (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES provider_accounts(id) ON DELETE RESTRICT,
  provider_key TEXT NOT NULL,
  capacity_domain_ref TEXT NOT NULL,
  serialization_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','active','draining','denied','retired')),
  deny_state TEXT NOT NULL CHECK (deny_state IN ('allowed','denied')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  capacity_generation INTEGER NOT NULL CHECK (capacity_generation >= 0),
  deny_generation INTEGER NOT NULL CHECK (deny_generation >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE UNIQUE INDEX capacity_pools_provider_domain
  ON capacity_pools(provider_key, capacity_domain_ref);

CREATE TABLE capacity_domain_claims (
  provider_key TEXT NOT NULL,
  capacity_domain_ref TEXT NOT NULL,
  serialization_key TEXT NOT NULL UNIQUE,
  owner_ref TEXT NOT NULL,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  claimed_at TEXT NOT NULL,
  PRIMARY KEY (provider_key, capacity_domain_ref),
  UNIQUE (capacity_pool_id)
);

CREATE TABLE access_methods (
  id TEXT PRIMARY KEY,
  entitlement_id TEXT NOT NULL REFERENCES entitlements(id) ON DELETE RESTRICT,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  access_transport TEXT NOT NULL CHECK (access_transport IN ('native_session','api_key','workload_identity')),
  status TEXT NOT NULL CHECK (status IN ('draft','ready','draining','disabled','retired')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE auth_capsules (
  id TEXT PRIMARY KEY,
  access_method_id TEXT NOT NULL REFERENCES access_methods(id) ON DELETE RESTRICT,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  owner_ref TEXT NOT NULL,
  placement_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('unprovisioned','bootstrapping','ready','degraded','revoked')),
  auth_generation INTEGER NOT NULL CHECK (auth_generation >= 0),
  auth_state_revision INTEGER NOT NULL CHECK (auth_state_revision >= 0),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE UNIQUE INDEX auth_capsules_one_live_per_pool
  ON auth_capsules(capacity_pool_id)
  WHERE status <> 'revoked';

CREATE TABLE credential_family_claims (
  credential_family_id TEXT PRIMARY KEY,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  owner_ref TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('provider_session','api_key','workload_identity')),
  resolver TEXT NOT NULL CHECK (resolver IN ('brokered_secret','workload_identity','capsule_local_native')),
  claimed_at TEXT NOT NULL
);

CREATE TABLE credential_bindings (
  id TEXT PRIMARY KEY,
  access_method_id TEXT NOT NULL REFERENCES access_methods(id) ON DELETE RESTRICT,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  auth_capsule_id TEXT REFERENCES auth_capsules(id) ON DELETE RESTRICT,
  credential_family_id TEXT NOT NULL,
  resolver TEXT NOT NULL CHECK (resolver IN ('brokered_secret','workload_identity','capsule_local_native')),
  purpose TEXT NOT NULL CHECK (purpose IN ('provider_session','api_key','workload_identity')),
  status TEXT NOT NULL CHECK (status IN ('pending','active','retiring','revoked')),
  credential_generation INTEGER NOT NULL CHECK (credential_generation >= 0),
  auth_state_revision INTEGER CHECK (auth_state_revision IS NULL OR auth_state_revision >= 0),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  CHECK (
    (resolver = 'capsule_local_native' AND purpose = 'provider_session' AND auth_capsule_id IS NOT NULL AND auth_state_revision IS NOT NULL)
    OR (resolver = 'brokered_secret' AND purpose = 'api_key' AND auth_capsule_id IS NULL AND auth_state_revision IS NULL)
    OR (resolver = 'workload_identity' AND purpose = 'workload_identity' AND auth_capsule_id IS NULL AND auth_state_revision IS NULL)
  )
);
CREATE UNIQUE INDEX credential_bindings_family_generation
  ON credential_bindings(credential_family_id, credential_generation);
CREATE UNIQUE INDEX credential_bindings_one_active_native
  ON credential_bindings(capacity_pool_id, purpose)
  WHERE resolver = 'capsule_local_native' AND status = 'active';

CREATE TABLE account_events (
  id TEXT PRIMARY KEY,
  aggregate_kind TEXT NOT NULL CHECK (aggregate_kind IN ('account','entitlement','capacity_pool','access_method','auth_capsule','credential_binding')),
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL CHECK (aggregate_revision >= 0),
  actor_ref TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE TABLE idempotency_records (
  scope TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  aggregate_kind TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_id TEXT NOT NULL REFERENCES account_events(id) ON DELETE RESTRICT,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`;

export const SQLITE_MIGRATION_V1_CHECKSUM = `sha256:${createHash("sha256")
  .update(SQLITE_MIGRATION_V1, "utf8")
  .digest("hex")}`;

export const SQLITE_MIGRATION_V2 = `
ALTER TABLE access_methods RENAME TO account_lanes;

CREATE TABLE accounts_installation (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  deployment_mode TEXT NOT NULL CHECK (deployment_mode IN ('local','self_hosted')),
  identity_realm TEXT NOT NULL,
  organization_ref TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  build_digest TEXT NOT NULL,
  configuration_attestation_digest TEXT NOT NULL,
  catalog_incarnation TEXT NOT NULL UNIQUE,
  recovery_frontier_sequence INTEGER NOT NULL CHECK (recovery_frontier_sequence >= 0),
  recovery_frontier_hash TEXT NOT NULL,
  recovery_frontier_signature_digest TEXT NOT NULL,
  database_frontier_sequence INTEGER NOT NULL CHECK (database_frontier_sequence >= 0),
  database_frontier_hash TEXT NOT NULL,
  database_frontier_signature_digest TEXT NOT NULL,
  recovery_hold INTEGER NOT NULL CHECK (recovery_hold IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

ALTER TABLE credential_bindings ADD COLUMN terminal_kind TEXT
  CHECK (terminal_kind IS NULL OR terminal_kind IN ('retired_handle_generation','revocation_barrier'));
ALTER TABLE credential_bindings ADD COLUMN credential_handle_audit_digest TEXT;
ALTER TABLE credential_bindings ADD COLUMN last_usable_credential_generation INTEGER
  CHECK (last_usable_credential_generation IS NULL OR last_usable_credential_generation >= 0);
ALTER TABLE credential_bindings ADD COLUMN revocation_barrier_receipt_digest TEXT;
ALTER TABLE credential_bindings ADD COLUMN revoked_at TEXT;

CREATE TRIGGER credential_bindings_terminal_shape_insert
BEFORE INSERT ON credential_bindings BEGIN
  SELECT CASE
    WHEN NEW.status <> 'revoked' AND (
      NEW.terminal_kind IS NOT NULL OR NEW.credential_handle_audit_digest IS NOT NULL OR
      NEW.last_usable_credential_generation IS NOT NULL OR
      NEW.revocation_barrier_receipt_digest IS NOT NULL OR NEW.revoked_at IS NOT NULL
    ) THEN RAISE(ABORT, 'credential terminal fields on nonterminal row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind = 'retired_handle_generation' AND (
      NEW.credential_handle_audit_digest IS NULL OR NEW.last_usable_credential_generation IS NOT NULL OR
      NEW.revocation_barrier_receipt_digest IS NULL OR NEW.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'invalid retired handle terminal row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind = 'revocation_barrier' AND (
      NEW.credential_handle_audit_digest IS NOT NULL OR NEW.last_usable_credential_generation IS NULL OR
      NEW.revocation_barrier_receipt_digest IS NULL OR NEW.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'invalid revocation barrier row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind IS NULL
      THEN RAISE(ABORT, 'missing credential terminal kind')
  END;
END;

CREATE TRIGGER credential_bindings_terminal_shape_update
BEFORE UPDATE ON credential_bindings BEGIN
  SELECT CASE
    WHEN NEW.status <> 'revoked' AND (
      NEW.terminal_kind IS NOT NULL OR NEW.credential_handle_audit_digest IS NOT NULL OR
      NEW.last_usable_credential_generation IS NOT NULL OR
      NEW.revocation_barrier_receipt_digest IS NOT NULL OR NEW.revoked_at IS NOT NULL
    ) THEN RAISE(ABORT, 'credential terminal fields on nonterminal row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind = 'retired_handle_generation' AND (
      NEW.credential_handle_audit_digest IS NULL OR NEW.last_usable_credential_generation IS NOT NULL OR
      NEW.revocation_barrier_receipt_digest IS NULL OR NEW.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'invalid retired handle terminal row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind = 'revocation_barrier' AND (
      NEW.credential_handle_audit_digest IS NOT NULL OR NEW.last_usable_credential_generation IS NULL OR
      NEW.revocation_barrier_receipt_digest IS NULL OR NEW.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'invalid revocation barrier row')
    WHEN NEW.status = 'revoked' AND NEW.terminal_kind IS NULL
      THEN RAISE(ABORT, 'missing credential terminal kind')
  END;
END;

CREATE TABLE credential_binding_handles (
  binding_id TEXT PRIMARY KEY REFERENCES credential_bindings(id) ON DELETE RESTRICT,
  opaque_handle TEXT NOT NULL CHECK (length(opaque_handle) BETWEEN 64 AND 1024),
  issuer_ref TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience IN ('accounts-local','accounts-self-hosted')),
  catalog_incarnation TEXT NOT NULL,
  backend_class TEXT NOT NULL CHECK (backend_class IN ('secrets_broker','workload_identity_broker','capsule_protected_state')),
  audit_digest TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE TRIGGER credential_binding_handles_nonterminal
BEFORE INSERT ON credential_binding_handles BEGIN
  SELECT CASE WHEN (SELECT status FROM credential_bindings WHERE id = NEW.binding_id) = 'revoked'
    THEN RAISE(ABORT, 'revoked binding cannot retain a handle') END;
END;
CREATE TRIGGER credential_bindings_revoke_removes_handle
BEFORE UPDATE OF status ON credential_bindings
WHEN NEW.status = 'revoked' AND EXISTS (
  SELECT 1 FROM credential_binding_handles WHERE binding_id = NEW.id
)
BEGIN
  SELECT RAISE(ABORT, 'credential handle must be removed before terminal update');
END;

CREATE TABLE credential_operations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('refresh','reauthentication','rotation','revocation')),
  source_binding_id TEXT REFERENCES credential_bindings(id) ON DELETE RESTRICT,
  target_binding_id TEXT REFERENCES credential_bindings(id) ON DELETE RESTRICT,
  credential_family_id TEXT NOT NULL,
  capacity_pool_id TEXT NOT NULL REFERENCES capacity_pools(id) ON DELETE RESTRICT,
  serialization_key TEXT NOT NULL,
  expected_source_generation INTEGER NOT NULL CHECK (expected_source_generation >= 0),
  expected_auth_state_revision INTEGER CHECK (expected_auth_state_revision IS NULL OR expected_auth_state_revision >= 0),
  proposed_target_generation INTEGER NOT NULL CHECK (proposed_target_generation >= 0),
  proposed_auth_state_revision INTEGER CHECK (proposed_auth_state_revision IS NULL OR proposed_auth_state_revision >= 0),
  state TEXT NOT NULL CHECK (state IN ('requested','quiescing','applying','verifying','completed','failed_before_dispatch','failed','quarantined')),
  idempotency_request_hash TEXT NOT NULL,
  barrier_receipt_digest TEXT,
  completion_receipt_digest TEXT,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX credential_operations_one_active_family_domain
  ON credential_operations(credential_family_id, serialization_key)
  WHERE state IN ('requested','quiescing','applying','verifying','failed_before_dispatch','failed');

CREATE TABLE import_candidates (
  id TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  redacted_metadata_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','cancelled','rejected')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE evidence_records (
  id TEXT PRIMARY KEY,
  evidence_type TEXT NOT NULL,
  aggregate_kind TEXT NOT NULL CHECK (aggregate_kind IN ('provider_account','capacity_pool','entitlement','account_lane')),
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL CHECK (aggregate_revision >= 0),
  evidence_generation INTEGER NOT NULL CHECK (evidence_generation > 0),
  nonce TEXT NOT NULL UNIQUE,
  issuer_ref TEXT NOT NULL,
  issuer_class TEXT NOT NULL CHECK (issuer_class IN ('provider_ownership_verifier','provider_capacity_verifier','execution_policy_authority','terms_authority','adapter_health_reporter')),
  issuer_incarnation TEXT NOT NULL,
  audience TEXT NOT NULL,
  identity_realm TEXT NOT NULL,
  key_id TEXT NOT NULL,
  subject_ref TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  envelope_digest TEXT NOT NULL UNIQUE,
  envelope_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX evidence_records_lookup
  ON evidence_records(aggregate_kind, aggregate_id, aggregate_revision, evidence_type);

CREATE TABLE recovery_ledger_receipts (
  sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
  frontier_hash TEXT NOT NULL UNIQUE,
  frontier_signature_digest TEXT NOT NULL,
  catalog_incarnation TEXT NOT NULL,
  receipt_digest TEXT NOT NULL UNIQUE,
  entry_kind TEXT NOT NULL,
  aggregate_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE slot_eligibility_audit (
  id TEXT PRIMARY KEY,
  access_method_id TEXT NOT NULL REFERENCES account_lanes(id) ON DELETE RESTRICT,
  decision TEXT NOT NULL CHECK (decision IN ('eligible','ineligible')),
  reason_codes_json TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  record_revision_digest TEXT NOT NULL,
  recovery_frontier_sequence INTEGER NOT NULL CHECK (recovery_frontier_sequence >= 0),
  recovery_frontier_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE outbox (
  id TEXT PRIMARY KEY,
  topic TEXT NOT NULL CHECK (topic IN ('accounts.aggregate.changed','accounts.capsule.cleanup.requested')),
  aggregate_kind TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_id TEXT REFERENCES account_events(id) ON DELETE RESTRICT,
  payload_digest TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','in_flight','delivered','dead_letter')),
  attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
  claim_owner_ref TEXT,
  claim_expires_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX outbox_pending_order ON outbox(status, created_at, id);
`;

export const SQLITE_MIGRATION_V2_CHECKSUM = `sha256:${createHash("sha256")
  .update(SQLITE_MIGRATION_V2, "utf8")
  .digest("hex")}`;

export const SQLITE_MIGRATION_CHECKSUM = SQLITE_MIGRATION_V2_CHECKSUM;

export const SQLITE_MIGRATIONS = Object.freeze([
  { version: 1, sql: SQLITE_MIGRATION_V1, checksum: SQLITE_MIGRATION_V1_CHECKSUM },
  { version: 2, sql: SQLITE_MIGRATION_V2, checksum: SQLITE_MIGRATION_V2_CHECKSUM },
]);
