import { createHash } from "node:crypto";

export const SQLITE_SCHEMA_VERSION = 1;

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
  WHERE provider_subject_ref IS NOT NULL AND status <> 'revoked';

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
  capacity_domain_ref TEXT NOT NULL UNIQUE,
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

export const SQLITE_MIGRATION_CHECKSUM = `sha256:${createHash("sha256")
  .update(SQLITE_MIGRATION_V1, "utf8")
  .digest("hex")}`;
