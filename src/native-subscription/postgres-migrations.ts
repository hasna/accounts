import { createHash } from "node:crypto";

export const POSTGRES_SCHEMA_VERSION = 3;

export const POSTGRES_REQUIRED_TABLES = Object.freeze([
  "schema_migrations",
  "accounts_installation",
  "provider_accounts",
  "provider_subject_claims",
  "entitlements",
  "capacity_pools",
  "capacity_domain_claims",
  "account_lanes",
  "auth_capsules",
  "credential_family_claims",
  "credential_bindings",
  "credential_binding_handles",
  "credential_operations",
  "import_candidates",
  "evidence_records",
  "recovery_ledger_receipts",
  "slot_eligibility_audit",
  "account_events",
  "outbox",
  "idempotency_records",
] as const);

const GLOBAL_REALM_TABLES = Object.freeze([
  "accounts_installation",
  "recovery_ledger_receipts",
] as const);

const OWNER_TABLES = POSTGRES_REQUIRED_TABLES.filter(
  (table) =>
    table !== "schema_migrations" &&
    !GLOBAL_REALM_TABLES.includes(table as (typeof GLOBAL_REALM_TABLES)[number]),
);

const MUTABLE_RUNTIME_TABLES = Object.freeze([
  "accounts_installation",
  "provider_accounts",
  "entitlements",
  "capacity_pools",
  "account_lanes",
  "auth_capsules",
  "credential_bindings",
  "credential_operations",
  "import_candidates",
  "outbox",
] as const);

const APPEND_ONLY_RUNTIME_TABLES = Object.freeze([
  "provider_subject_claims",
  "capacity_domain_claims",
  "credential_family_claims",
  "evidence_records",
  "recovery_ledger_receipts",
  "slot_eligibility_audit",
  "account_events",
  "idempotency_records",
] as const);

const INSERT_ONLY_RUNTIME_TABLES = Object.freeze([
  "credential_binding_handles",
] as const);

const rlsSql = OWNER_TABLES.map(
  (table) => `
ALTER TABLE accounts.${table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts.${table} FORCE ROW LEVEL SECURITY;
CREATE POLICY ${table}_owner_select ON accounts.${table}
  FOR SELECT TO accounts_runtime
  USING (accounts.row_owned_by(owner_ref));
CREATE POLICY ${table}_owner_insert ON accounts.${table}
  FOR INSERT TO accounts_runtime
  WITH CHECK (accounts.row_owned_by(owner_ref));
${
  MUTABLE_RUNTIME_TABLES.includes(table as (typeof MUTABLE_RUNTIME_TABLES)[number])
    ? `CREATE POLICY ${table}_owner_update ON accounts.${table}
  FOR UPDATE TO accounts_runtime
  USING (accounts.row_owned_by(owner_ref))
  WITH CHECK (accounts.row_owned_by(owner_ref));`
    : ""
}
`,
).join("\n");

const globalRlsSql = GLOBAL_REALM_TABLES.map(
  (table) => `
ALTER TABLE accounts.${table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts.${table} FORCE ROW LEVEL SECURITY;
CREATE POLICY ${table}_realm_select ON accounts.${table}
  FOR SELECT TO accounts_runtime
  USING (accounts.realm_is_current(identity_realm));
CREATE POLICY ${table}_realm_insert ON accounts.${table}
  FOR INSERT TO accounts_runtime
  WITH CHECK (accounts.realm_is_current(identity_realm));
${
  MUTABLE_RUNTIME_TABLES.includes(table as (typeof MUTABLE_RUNTIME_TABLES)[number])
    ? `CREATE POLICY ${table}_realm_update ON accounts.${table}
  FOR UPDATE TO accounts_runtime
  USING (accounts.realm_is_current(identity_realm))
  WITH CHECK (accounts.realm_is_current(identity_realm));`
    : ""
}
`,
).join("\n");

const grantsSql = `
GRANT SELECT, INSERT, UPDATE ON TABLE
  ${MUTABLE_RUNTIME_TABLES.map((table) => `accounts.${table}`).join(",\n  ")}
TO accounts_runtime;
GRANT SELECT, INSERT ON TABLE
  ${[...APPEND_ONLY_RUNTIME_TABLES, ...INSERT_ONLY_RUNTIME_TABLES]
    .map((table) => `accounts.${table}`)
    .join(",\n  ")}
TO accounts_runtime;
`;

export const POSTGRES_MIGRATION_V1 = `
CREATE SCHEMA IF NOT EXISTS accounts;

CREATE TABLE accounts.schema_migrations (
  version BIGINT PRIMARY KEY CHECK (version > 0),
  checksum TEXT NOT NULL CHECK (checksum ~ '^sha256:[0-9a-f]{64}$'),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

DO $accounts_role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'accounts_runtime') THEN
    CREATE ROLE accounts_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  ELSIF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'accounts_runtime'
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolcanlogin OR rolinherit)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS role ON role.oid = membership.member
    WHERE role.rolname = 'accounts_runtime'
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS role ON role.oid = membership.roleid
    WHERE role.rolname = 'accounts_runtime' AND membership.admin_option
  ) THEN
    RAISE EXCEPTION 'accounts_runtime has unsafe role attributes';
  END IF;
END
$accounts_role$;

REVOKE ALL ON SCHEMA accounts FROM PUBLIC;
GRANT USAGE ON SCHEMA accounts TO accounts_runtime;

CREATE OR REPLACE FUNCTION accounts.current_principal()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
  SELECT NULLIF(current_setting('accounts.principal', true), '')
$function$;

CREATE OR REPLACE FUNCTION accounts.current_identity_realm()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
  SELECT NULLIF(current_setting('accounts.identity_realm', true), '')
$function$;

CREATE OR REPLACE FUNCTION accounts.row_owned_by(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
  SELECT candidate = accounts.current_principal()
     AND accounts.current_identity_realm() = 'hasna'
$function$;

CREATE OR REPLACE FUNCTION accounts.realm_is_current(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
  SELECT candidate = accounts.current_identity_realm() AND candidate = 'hasna'
$function$;

REVOKE ALL ON FUNCTION accounts.current_principal() FROM PUBLIC;
REVOKE ALL ON FUNCTION accounts.current_identity_realm() FROM PUBLIC;
REVOKE ALL ON FUNCTION accounts.row_owned_by(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION accounts.realm_is_current(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION accounts.current_principal() TO accounts_runtime;
GRANT EXECUTE ON FUNCTION accounts.current_identity_realm() TO accounts_runtime;
GRANT EXECUTE ON FUNCTION accounts.row_owned_by(TEXT) TO accounts_runtime;
GRANT EXECUTE ON FUNCTION accounts.realm_is_current(TEXT) TO accounts_runtime;

CREATE TABLE accounts.accounts_installation (
  singleton SMALLINT NOT NULL DEFAULT 1 CHECK (singleton = 1),
  deployment_mode TEXT NOT NULL CHECK (deployment_mode = 'self_hosted'),
  identity_realm TEXT NOT NULL CHECK (identity_realm = 'hasna'),
  organization_ref TEXT NOT NULL,
  schema_version TEXT NOT NULL,
  build_digest TEXT NOT NULL CHECK (build_digest ~ '^sha256:[0-9a-f]{64}$'),
  configuration_attestation_digest TEXT NOT NULL CHECK (configuration_attestation_digest ~ '^sha256:[0-9a-f]{64}$'),
  catalog_incarnation TEXT NOT NULL,
  recovery_frontier_sequence BIGINT NOT NULL CHECK (recovery_frontier_sequence BETWEEN 0 AND 9223372036854775807),
  recovery_frontier_hash TEXT NOT NULL CHECK (recovery_frontier_hash ~ '^sha256:[0-9a-f]{64}$'),
  recovery_frontier_signature_digest TEXT NOT NULL CHECK (recovery_frontier_signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  database_frontier_sequence BIGINT NOT NULL CHECK (database_frontier_sequence BETWEEN 0 AND 9223372036854775807),
  database_frontier_hash TEXT NOT NULL CHECK (database_frontier_hash ~ '^sha256:[0-9a-f]{64}$'),
  database_frontier_signature_digest TEXT NOT NULL CHECK (database_frontier_signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  recovery_hold BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (singleton),
  UNIQUE (catalog_incarnation),
  CHECK (updated_at >= created_at)
);

CREATE TABLE accounts.provider_accounts (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL CHECK (owner_ref ~ '^principal:(human|service):hasna:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
  provider_key TEXT NOT NULL,
  provider_subject_ref TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','active','suspended','revoked')),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  UNIQUE (id, owner_ref),
  CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX provider_accounts_active_subject
  ON accounts.provider_accounts(provider_key, provider_subject_ref)
  WHERE provider_subject_ref IS NOT NULL AND status <> 'pending';

CREATE TABLE accounts.provider_subject_claims (
  provider_key TEXT NOT NULL,
  provider_subject_ref TEXT NOT NULL,
  owner_ref TEXT NOT NULL,
  provider_account_id UUID NOT NULL,
  claimed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (provider_key, provider_subject_ref),
  UNIQUE (provider_account_id),
  FOREIGN KEY (provider_account_id, owner_ref)
    REFERENCES accounts.provider_accounts(id, owner_ref) ON DELETE RESTRICT
);

CREATE TABLE accounts.entitlements (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  account_id UUID NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','active','paused','expired','revoked')),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  UNIQUE (id, owner_ref),
  FOREIGN KEY (account_id, owner_ref)
    REFERENCES accounts.provider_accounts(id, owner_ref) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE accounts.capacity_pools (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  account_id UUID NOT NULL,
  provider_key TEXT NOT NULL,
  capacity_domain_ref TEXT NOT NULL,
  serialization_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','active','draining','denied','retired')),
  deny_state TEXT NOT NULL CHECK (deny_state IN ('allowed','denied')),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  capacity_generation BIGINT NOT NULL CHECK (capacity_generation BETWEEN 0 AND 9223372036854775807),
  deny_generation BIGINT NOT NULL CHECK (deny_generation BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  UNIQUE (id, owner_ref),
  UNIQUE (provider_key, capacity_domain_ref),
  FOREIGN KEY (account_id, owner_ref)
    REFERENCES accounts.provider_accounts(id, owner_ref) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE accounts.capacity_domain_claims (
  provider_key TEXT NOT NULL,
  capacity_domain_ref TEXT NOT NULL,
  serialization_key TEXT NOT NULL UNIQUE,
  owner_ref TEXT NOT NULL,
  capacity_pool_id UUID NOT NULL,
  claimed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (provider_key, capacity_domain_ref),
  UNIQUE (capacity_pool_id),
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT
);

CREATE TABLE accounts.account_lanes (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  entitlement_id UUID NOT NULL,
  capacity_pool_id UUID NOT NULL,
  access_transport TEXT NOT NULL CHECK (access_transport IN ('native_session','api_key','workload_identity')),
  status TEXT NOT NULL CHECK (status IN ('draft','ready','draining','disabled','retired')),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  UNIQUE (id, owner_ref),
  FOREIGN KEY (entitlement_id, owner_ref)
    REFERENCES accounts.entitlements(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);

CREATE TABLE accounts.auth_capsules (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  access_method_id UUID NOT NULL,
  capacity_pool_id UUID NOT NULL,
  placement_ref UUID NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('unprovisioned','bootstrapping','ready','degraded','revoked')),
  auth_generation BIGINT NOT NULL CHECK (auth_generation BETWEEN 0 AND 9223372036854775807),
  auth_state_revision BIGINT NOT NULL CHECK (auth_state_revision BETWEEN 0 AND 9223372036854775807),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  UNIQUE (id, owner_ref),
  FOREIGN KEY (access_method_id, owner_ref)
    REFERENCES accounts.account_lanes(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX auth_capsules_one_live_per_pool
  ON accounts.auth_capsules(capacity_pool_id)
  WHERE status <> 'revoked';

CREATE TABLE accounts.credential_family_claims (
  credential_family_id TEXT PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  capacity_pool_id UUID NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('provider_session','api_key','workload_identity')),
  resolver TEXT NOT NULL CHECK (resolver IN ('brokered_secret','workload_identity','capsule_local_native')),
  claimed_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT
);

CREATE TABLE accounts.credential_bindings (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  access_method_id UUID NOT NULL,
  capacity_pool_id UUID NOT NULL,
  auth_capsule_id UUID,
  credential_family_id TEXT NOT NULL,
  resolver TEXT NOT NULL CHECK (resolver IN ('brokered_secret','workload_identity','capsule_local_native')),
  purpose TEXT NOT NULL CHECK (purpose IN ('provider_session','api_key','workload_identity')),
  status TEXT NOT NULL CHECK (status IN ('pending','active','retiring','revoked')),
  credential_generation BIGINT NOT NULL CHECK (credential_generation BETWEEN 0 AND 9223372036854775807),
  auth_state_revision BIGINT CHECK (auth_state_revision BETWEEN 0 AND 9223372036854775807),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  terminal_kind TEXT CHECK (terminal_kind IN ('retired_handle_generation','revocation_barrier')),
  credential_handle_audit_digest TEXT,
  last_usable_credential_generation BIGINT CHECK (last_usable_credential_generation BETWEEN 0 AND 9223372036854775807),
  revocation_barrier_receipt_digest TEXT,
  revoked_at TIMESTAMPTZ,
  UNIQUE (id, owner_ref),
  UNIQUE (credential_family_id, credential_generation),
  FOREIGN KEY (access_method_id, owner_ref)
    REFERENCES accounts.account_lanes(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (auth_capsule_id, owner_ref)
    REFERENCES accounts.auth_capsules(id, owner_ref) ON DELETE RESTRICT,
  CONSTRAINT credential_binding_resolver_shape CHECK (
    (resolver = 'capsule_local_native' AND purpose = 'provider_session' AND auth_capsule_id IS NOT NULL AND auth_state_revision IS NOT NULL)
    OR (resolver = 'brokered_secret' AND purpose = 'api_key' AND auth_capsule_id IS NULL AND auth_state_revision IS NULL)
    OR (resolver = 'workload_identity' AND purpose = 'workload_identity' AND auth_capsule_id IS NULL AND auth_state_revision IS NULL)
  ),
  CONSTRAINT credential_bindings_terminal_shape CHECK (
    (status <> 'revoked' AND terminal_kind IS NULL AND credential_handle_audit_digest IS NULL
      AND last_usable_credential_generation IS NULL AND revocation_barrier_receipt_digest IS NULL AND revoked_at IS NULL)
    OR
    (status = 'revoked' AND terminal_kind = 'retired_handle_generation'
      AND credential_handle_audit_digest IS NOT NULL AND last_usable_credential_generation IS NULL
      AND revocation_barrier_receipt_digest IS NOT NULL AND revoked_at IS NOT NULL)
    OR
    (status = 'revoked' AND terminal_kind = 'revocation_barrier'
      AND credential_handle_audit_digest IS NULL AND last_usable_credential_generation IS NOT NULL
      AND revocation_barrier_receipt_digest IS NOT NULL AND revoked_at IS NOT NULL)
  ),
  CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX credential_bindings_one_active_native
  ON accounts.credential_bindings(capacity_pool_id, purpose)
  WHERE resolver = 'capsule_local_native' AND status = 'active';

CREATE TABLE accounts.credential_binding_handles (
  binding_id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  opaque_handle TEXT NOT NULL CHECK (length(opaque_handle) BETWEEN 64 AND 1024),
  issuer_ref TEXT NOT NULL,
  audience TEXT NOT NULL CHECK (audience = 'accounts-self-hosted'),
  catalog_incarnation TEXT NOT NULL,
  backend_class TEXT NOT NULL CHECK (backend_class IN ('secrets_broker','workload_identity_broker','capsule_protected_state')),
  audit_digest TEXT NOT NULL CHECK (audit_digest ~ '^(sha256|hmac-sha256):[0-9a-f]{64}$'),
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  UNIQUE (binding_id, owner_ref),
  FOREIGN KEY (binding_id, owner_ref)
    REFERENCES accounts.credential_bindings(id, owner_ref) ON DELETE RESTRICT,
  CHECK (expires_at IS NULL OR expires_at > issued_at)
);

CREATE OR REPLACE FUNCTION accounts.reject_terminal_credential_handle()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM accounts.credential_bindings
    WHERE id = NEW.binding_id AND owner_ref = NEW.owner_ref AND status = 'revoked'
  ) THEN
    RAISE EXCEPTION 'revoked binding cannot retain a handle' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$function$;
CREATE TRIGGER credential_binding_handles_nonterminal
  BEFORE INSERT OR UPDATE ON accounts.credential_binding_handles
  FOR EACH ROW EXECUTE FUNCTION accounts.reject_terminal_credential_handle();

CREATE OR REPLACE FUNCTION accounts.delete_credential_handle_for_revocation(
  target_binding_id UUID,
  target_owner_ref TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  removed_count BIGINT;
BEGIN
  IF NOT accounts.row_owned_by(target_owner_ref) THEN
    RAISE EXCEPTION 'credential handle owner is not authorized' USING ERRCODE = '42501';
  END IF;
  DELETE FROM accounts.credential_binding_handles
  WHERE binding_id = target_binding_id AND owner_ref = target_owner_ref;
  GET DIAGNOSTICS removed_count = ROW_COUNT;
  RETURN removed_count = 1;
END
$function$;
REVOKE ALL ON FUNCTION accounts.delete_credential_handle_for_revocation(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION accounts.delete_credential_handle_for_revocation(UUID, TEXT) TO accounts_runtime;

CREATE OR REPLACE FUNCTION accounts.require_handle_removed_before_revoke()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
  IF NEW.status = 'revoked' AND EXISTS (
    SELECT 1 FROM accounts.credential_binding_handles
    WHERE binding_id = NEW.id AND owner_ref = NEW.owner_ref
  ) THEN
    RAISE EXCEPTION 'credential handle must be removed before terminal update' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$function$;
CREATE TRIGGER credential_bindings_revoke_removes_handle
  BEFORE UPDATE OF status ON accounts.credential_bindings
  FOR EACH ROW EXECUTE FUNCTION accounts.require_handle_removed_before_revoke();

CREATE TABLE accounts.credential_operations (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('refresh','reauthentication','rotation','revocation')),
  source_binding_id UUID,
  target_binding_id UUID,
  credential_family_id TEXT NOT NULL,
  capacity_pool_id UUID NOT NULL,
  serialization_key TEXT NOT NULL,
  expected_source_generation BIGINT NOT NULL CHECK (expected_source_generation BETWEEN 0 AND 9223372036854775807),
  expected_auth_state_revision BIGINT CHECK (expected_auth_state_revision BETWEEN 0 AND 9223372036854775807),
  proposed_target_generation BIGINT NOT NULL CHECK (proposed_target_generation BETWEEN 0 AND 9223372036854775807),
  proposed_auth_state_revision BIGINT CHECK (proposed_auth_state_revision BETWEEN 0 AND 9223372036854775807),
  state TEXT NOT NULL CHECK (state IN ('requested','quiescing','applying','verifying','completed','failed_before_dispatch','failed','quarantined')),
  idempotency_request_hash TEXT NOT NULL,
  barrier_receipt_digest TEXT,
  completion_receipt_digest TEXT,
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  UNIQUE (id, owner_ref),
  FOREIGN KEY (source_binding_id, owner_ref)
    REFERENCES accounts.credential_bindings(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (target_binding_id, owner_ref)
    REFERENCES accounts.credential_bindings(id, owner_ref) ON DELETE RESTRICT,
  FOREIGN KEY (capacity_pool_id, owner_ref)
    REFERENCES accounts.capacity_pools(id, owner_ref) ON DELETE RESTRICT,
  CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX credential_operations_one_active_family_domain
  ON accounts.credential_operations(credential_family_id, serialization_key)
  WHERE state IN ('requested','quiescing','applying','verifying','failed_before_dispatch','failed');

CREATE TABLE accounts.import_candidates (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  checksum TEXT NOT NULL,
  redacted_metadata_json TEXT NOT NULL CHECK (octet_length(redacted_metadata_json) <= 1048576),
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','cancelled','rejected')),
  revision BIGINT NOT NULL CHECK (revision BETWEEN 0 AND 9223372036854775807),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  CHECK (updated_at >= created_at)
);

CREATE TABLE accounts.evidence_records (
  id TEXT PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  subject_ref TEXT NOT NULL,
  aggregate_kind TEXT NOT NULL CHECK (aggregate_kind IN ('provider_account','capacity_pool','entitlement','account_lane')),
  aggregate_id UUID NOT NULL,
  aggregate_revision BIGINT NOT NULL CHECK (aggregate_revision BETWEEN 0 AND 9223372036854775807),
  identity_realm TEXT NOT NULL CHECK (identity_realm = 'hasna'),
  issuer_ref TEXT NOT NULL,
  issuer_class TEXT NOT NULL CHECK (issuer_class IN ('provider_ownership_verifier','provider_capacity_verifier','execution_policy_authority','terms_authority','adapter_health_reporter')),
  issuer_incarnation TEXT NOT NULL,
  audience TEXT NOT NULL,
  key_id TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  nonce TEXT NOT NULL UNIQUE CHECK (nonce ~ '^[A-Za-z0-9_-]{22,86}$'),
  evidence_generation BIGINT NOT NULL CHECK (evidence_generation BETWEEN 1 AND 9223372036854775807),
  payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  envelope_digest TEXT NOT NULL UNIQUE CHECK (envelope_digest ~ '^sha256:[0-9a-f]{64}$'),
  envelope_json TEXT NOT NULL CHECK (octet_length(envelope_json) <= 1048576),
  created_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > issued_at)
);
CREATE INDEX evidence_records_lookup
  ON accounts.evidence_records(owner_ref, aggregate_kind, aggregate_id, aggregate_revision, evidence_type);

CREATE TABLE accounts.recovery_ledger_receipts (
  sequence BIGINT NOT NULL CHECK (sequence BETWEEN 0 AND 9223372036854775807),
  identity_realm TEXT NOT NULL CHECK (identity_realm = 'hasna'),
  frontier_hash TEXT NOT NULL UNIQUE CHECK (frontier_hash ~ '^sha256:[0-9a-f]{64}$'),
  frontier_signature_digest TEXT NOT NULL CHECK (frontier_signature_digest ~ '^sha256:[0-9a-f]{64}$'),
  catalog_incarnation TEXT NOT NULL,
  receipt_digest TEXT NOT NULL UNIQUE CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  entry_kind TEXT NOT NULL CHECK (entry_kind IN ('catalog_mutation','native_revocation_barrier')),
  aggregate_id TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (sequence)
);

CREATE TABLE accounts.slot_eligibility_audit (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  access_method_id UUID NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('eligible','ineligible')),
  reason_codes_json TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  record_revision_digest TEXT NOT NULL,
  recovery_frontier_sequence BIGINT NOT NULL CHECK (recovery_frontier_sequence BETWEEN 0 AND 9223372036854775807),
  recovery_frontier_hash TEXT NOT NULL CHECK (recovery_frontier_hash ~ '^sha256:[0-9a-f]{64}$'),
  created_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (access_method_id, owner_ref)
    REFERENCES accounts.account_lanes(id, owner_ref) ON DELETE RESTRICT
);

CREATE TABLE accounts.account_events (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  aggregate_kind TEXT NOT NULL CHECK (aggregate_kind IN ('account','entitlement','capacity_pool','access_method','auth_capsule','credential_binding')),
  aggregate_id UUID NOT NULL,
  aggregate_revision BIGINT NOT NULL CHECK (aggregate_revision BETWEEN 0 AND 9223372036854775807),
  actor_ref TEXT NOT NULL,
  reason_code TEXT NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  occurred_at TIMESTAMPTZ NOT NULL,
  UNIQUE (id, owner_ref)
);

CREATE TABLE accounts.outbox (
  id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  topic TEXT NOT NULL CHECK (topic IN ('accounts.aggregate.changed','accounts.capsule.cleanup.requested')),
  aggregate_kind TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_id UUID,
  payload_digest TEXT NOT NULL CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
  payload_json TEXT NOT NULL CHECK (octet_length(payload_json) <= 1048576),
  status TEXT NOT NULL CHECK (status IN ('pending','in_flight','delivered','dead_letter')),
  attempt_count BIGINT NOT NULL CHECK (attempt_count BETWEEN 0 AND 9223372036854775807),
  claim_owner_ref TEXT,
  claim_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  FOREIGN KEY (event_id, owner_ref)
    REFERENCES accounts.account_events(id, owner_ref) ON DELETE RESTRICT,
  CHECK (
    (status = 'in_flight' AND claim_owner_ref IS NOT NULL AND claim_expires_at IS NOT NULL)
    OR (status <> 'in_flight' AND claim_owner_ref IS NULL AND claim_expires_at IS NULL)
  )
);
CREATE INDEX outbox_pending_order ON accounts.outbox(owner_ref, status, created_at, id);

CREATE TABLE accounts.idempotency_records (
  scope TEXT NOT NULL,
  owner_ref TEXT NOT NULL,
  request_hash TEXT NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
  aggregate_kind TEXT NOT NULL,
  aggregate_id UUID NOT NULL,
  event_id UUID NOT NULL,
  response_json TEXT NOT NULL CHECK (octet_length(response_json) <= 1048576),
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (scope, owner_ref),
  FOREIGN KEY (event_id, owner_ref)
    REFERENCES accounts.account_events(id, owner_ref) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION accounts.reject_append_only_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION 'append-only Accounts row cannot be changed' USING ERRCODE = '23000';
END
$function$;
${APPEND_ONLY_RUNTIME_TABLES.map(
  (table) => `CREATE TRIGGER ${table}_immutable
  BEFORE UPDATE OR DELETE ON accounts.${table}
  FOR EACH ROW EXECUTE FUNCTION accounts.reject_append_only_change();`,
).join("\n")}

${rlsSql}

${globalRlsSql}

${grantsSql}

REVOKE ALL ON TABLE accounts.schema_migrations FROM PUBLIC, accounts_runtime;
GRANT SELECT ON TABLE accounts.schema_migrations TO accounts_runtime;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA accounts FROM accounts_runtime;
`;

export const POSTGRES_MIGRATION_V1_CHECKSUM = `sha256:${createHash("sha256")
  .update(POSTGRES_MIGRATION_V1, "utf8")
  .digest("hex")}`;

export const POSTGRES_MIGRATION_V2 = `
CREATE TABLE accounts.capsule_maintenance_grants (
  grant_id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  idempotency_key_digest TEXT NOT NULL CHECK (idempotency_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  reservation_key_digest TEXT NOT NULL CHECK (reservation_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  grant_digest TEXT NOT NULL CHECK (grant_digest ~ '^sha256:[0-9a-f]{64}$'),
  grant_jcs_base64url TEXT NOT NULL CHECK (
    grant_jcs_base64url ~ '^[A-Za-z0-9_-]+$'
    AND octet_length(grant_jcs_base64url) <= 1398102
  ),
  expires_at TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('live','consumed','expired')),
  created_at TIMESTAMPTZ NOT NULL,
  terminal_at TIMESTAMPTZ,
  UNIQUE (grant_id, owner_ref),
  UNIQUE (owner_ref, idempotency_key_digest),
  UNIQUE (owner_ref, grant_digest),
  CHECK (
    (state = 'live' AND terminal_at IS NULL)
    OR (state IN ('consumed','expired') AND terminal_at IS NOT NULL)
  )
);
CREATE UNIQUE INDEX capsule_maintenance_one_live_reservation
  ON accounts.capsule_maintenance_grants(owner_ref, reservation_key_digest)
  WHERE state = 'live';

CREATE TABLE accounts.capsule_maintenance_uses (
  grant_id UUID PRIMARY KEY,
  owner_ref TEXT NOT NULL,
  idempotency_key_digest TEXT NOT NULL CHECK (idempotency_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  maintenance_use_id TEXT NOT NULL UNIQUE CHECK (maintenance_use_id ~ '^sha256:[0-9a-f]{64}$'),
  consume_receipt_digest TEXT NOT NULL UNIQUE CHECK (consume_receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
  consume_receipt_jcs_base64url TEXT NOT NULL CHECK (
    consume_receipt_jcs_base64url ~ '^[A-Za-z0-9_-]+$'
    AND octet_length(consume_receipt_jcs_base64url) <= 1398102
  ),
  committed_at TIMESTAMPTZ NOT NULL,
  UNIQUE (owner_ref, idempotency_key_digest),
  FOREIGN KEY (grant_id, owner_ref)
    REFERENCES accounts.capsule_maintenance_grants(grant_id, owner_ref) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION accounts.enforce_capsule_maintenance_grant_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
  IF ROW(
    NEW.grant_id, NEW.owner_ref, NEW.idempotency_key_digest, NEW.request_digest,
    NEW.reservation_key_digest, NEW.grant_digest, NEW.grant_jcs_base64url,
    NEW.expires_at, NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.grant_id, OLD.owner_ref, OLD.idempotency_key_digest, OLD.request_digest,
    OLD.reservation_key_digest, OLD.grant_digest, OLD.grant_jcs_base64url,
    OLD.expires_at, OLD.created_at
  ) OR OLD.state <> 'live' OR NEW.state NOT IN ('consumed','expired') THEN
    RAISE EXCEPTION 'invalid capsule maintenance grant transition' USING ERRCODE = '23000';
  END IF;
  RETURN NEW;
END
$function$;
CREATE TRIGGER capsule_maintenance_grants_transition
  BEFORE UPDATE ON accounts.capsule_maintenance_grants
  FOR EACH ROW EXECUTE FUNCTION accounts.enforce_capsule_maintenance_grant_transition();
CREATE TRIGGER capsule_maintenance_uses_immutable
  BEFORE UPDATE OR DELETE ON accounts.capsule_maintenance_uses
  FOR EACH ROW EXECUTE FUNCTION accounts.reject_append_only_change();

ALTER TABLE accounts.capsule_maintenance_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts.capsule_maintenance_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY capsule_maintenance_grants_owner_select ON accounts.capsule_maintenance_grants
  FOR SELECT TO accounts_runtime USING (accounts.row_owned_by(owner_ref));
CREATE POLICY capsule_maintenance_grants_owner_insert ON accounts.capsule_maintenance_grants
  FOR INSERT TO accounts_runtime WITH CHECK (accounts.row_owned_by(owner_ref));
CREATE POLICY capsule_maintenance_grants_owner_update ON accounts.capsule_maintenance_grants
  FOR UPDATE TO accounts_runtime
  USING (accounts.row_owned_by(owner_ref)) WITH CHECK (accounts.row_owned_by(owner_ref));

ALTER TABLE accounts.capsule_maintenance_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts.capsule_maintenance_uses FORCE ROW LEVEL SECURITY;
CREATE POLICY capsule_maintenance_uses_owner_select ON accounts.capsule_maintenance_uses
  FOR SELECT TO accounts_runtime USING (accounts.row_owned_by(owner_ref));
CREATE POLICY capsule_maintenance_uses_owner_insert ON accounts.capsule_maintenance_uses
  FOR INSERT TO accounts_runtime WITH CHECK (accounts.row_owned_by(owner_ref));

GRANT SELECT, INSERT, UPDATE ON TABLE accounts.capsule_maintenance_grants TO accounts_runtime;
GRANT SELECT, INSERT ON TABLE accounts.capsule_maintenance_uses TO accounts_runtime;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON accounts.capsule_maintenance_grants, accounts.capsule_maintenance_uses
  FROM accounts_runtime;
`;

export const POSTGRES_MIGRATION_V2_CHECKSUM = `sha256:${createHash("sha256")
  .update(POSTGRES_MIGRATION_V2, "utf8")
  .digest("hex")}`;

export const POSTGRES_MIGRATION_V3 = `
CREATE TABLE accounts.capability_use_consumptions (
  owner_ref TEXT NOT NULL,
  consume_request_id UUID NOT NULL,
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
  capability_id UUID NOT NULL,
  idempotency_key_digest TEXT NOT NULL CHECK (idempotency_key_digest ~ '^sha256:[0-9a-f]{64}$'),
  receipt_jcs_base64url TEXT NOT NULL CHECK (
    receipt_jcs_base64url ~ '^[A-Za-z0-9_-]+$'
    AND octet_length(receipt_jcs_base64url) <= 1398102
  ),
  committed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (owner_ref, consume_request_id),
  UNIQUE (owner_ref, capability_id),
  UNIQUE (owner_ref, idempotency_key_digest)
);

CREATE TRIGGER capability_use_consumptions_immutable
  BEFORE UPDATE OR DELETE ON accounts.capability_use_consumptions
  FOR EACH ROW EXECUTE FUNCTION accounts.reject_append_only_change();

ALTER TABLE accounts.capability_use_consumptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts.capability_use_consumptions FORCE ROW LEVEL SECURITY;
CREATE POLICY capability_use_consumptions_owner_select
  ON accounts.capability_use_consumptions
  FOR SELECT TO accounts_runtime USING (accounts.row_owned_by(owner_ref));
CREATE POLICY capability_use_consumptions_owner_insert
  ON accounts.capability_use_consumptions
  FOR INSERT TO accounts_runtime WITH CHECK (accounts.row_owned_by(owner_ref));

GRANT SELECT, INSERT ON TABLE accounts.capability_use_consumptions TO accounts_runtime;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON accounts.capability_use_consumptions FROM accounts_runtime;
`;

export const POSTGRES_MIGRATION_V3_CHECKSUM = `sha256:${createHash("sha256")
  .update(POSTGRES_MIGRATION_V3, "utf8")
  .digest("hex")}`;

export const POSTGRES_MIGRATION_CHECKSUM = POSTGRES_MIGRATION_V3_CHECKSUM;

export const POSTGRES_MIGRATIONS = Object.freeze([
  Object.freeze({
    version: 1,
    checksum: POSTGRES_MIGRATION_V1_CHECKSUM,
    sql: POSTGRES_MIGRATION_V1,
  }),
  Object.freeze({
    version: 2,
    checksum: POSTGRES_MIGRATION_V2_CHECKSUM,
    sql: POSTGRES_MIGRATION_V2,
  }),
  Object.freeze({
    version: 3,
    checksum: POSTGRES_MIGRATION_V3_CHECKSUM,
    sql: POSTGRES_MIGRATION_V3,
  }),
]);
