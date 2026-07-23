# Native subscription authority

`@hasna/accounts/native-subscription` is the package-owned authority boundary
used by Infinity and AuthCapsule for native-subscription capacity. It is
additive to the profile-switching API: consumers must import the explicit
subpath, and the existing `@hasna/accounts` root contract remains unchanged.

The boundary carries metadata, signed receipts, generations, and digests only.
It never accepts, returns, persists, or transports credential payloads.

## Contracts

- `evaluateNativeSubscriptionProbe` verifies the authenticated owner together
  with the provider account, subscription, lane, AuthCapsule, canonical node,
  node key thumbprint, and every relevant generation before reporting
  capability or maintenance eligibility.
- `CapsuleMaintenanceAuthority` issues owner- and node-bound, short-lived
  maintenance grants only after it verifies Infinity's signed `HELD` receipt,
  drain evidence, transport identity, current state, and action-specific
  approval fields. Grants and consume receipts are ordinal-one.
- `consumeOnlineGenerationCheckReceiptUse` verifies the closed online
  generation receipt and delegates the one-use CAS to an Accounts-owned
  `OnlineGenerationReceiptUseStore`.
- `PostgresNativeCapabilityUseStore` implements that CAS with SERIALIZABLE
  transactions, deterministic advisory locks, forced row-level security,
  immutable receipt bytes, exact replay, and an owner-scoped unique
  capability tombstone.
- `PostgresCapsuleMaintenanceLedger` durably serializes maintenance grant
  reservation and consumption and returns stored evidence bytes on replay.

The in-memory stores are conformance adapters only. They are not durable
production substitutes.

## Postgres

`runPostgresMigrations` applies the dedicated, checksummed Accounts capacity
schema through version 3. It must run with a dedicated, non-elevated migration
owner connection after an operator provisions the `accounts` schema and runtime
roles. Runtime identity is configuration, never migration SQL: pass either a
dedicated direct `LOGIN` role or a configured `LOGIN` role that is the sole
non-admin member of a dedicated `NOLOGIN` role.

This migration set is separate from the existing `accounts-serve` profile
registry migrations. A self-hosted Infinity deployment should provision the
capacity schema explicitly. Use the same authoritative runtime-role setting
that feeds `HASNA_ACCOUNTS_RUNTIME_ROLE`; do not duplicate the role name in
application source. A direct boundary connects as that DML-only role. A
`set-role` boundary additionally requires a configured login-role name and
executes a transaction-local `SET ROLE`.

```ts
const runtimeRole = {
  mode: "set-role",
  roleName: configuredRuntimeRole,
  loginRoleName: configuredRuntimeLoginRole,
} as const;

await runPostgresMigrations(accountsCapacityMigrationSql, { runtimeRole });
```

The migrator reapplies the exact package-owned ACL and then catalog-attests the
runtime/login role attributes and membership, schema and object ownership,
public and runtime grants, RLS plus `FORCE ROW LEVEL SECURITY`, every policy,
function security/search-path/execute contract, and every trigger. A matching
checksum ledger is necessary but not sufficient; drift fails closed with
`SCHEMA_CHECKSUM_MISMATCH`.

```ts
import {
  PostgresNativeCapabilityUseStore,
  consumeOnlineGenerationCheckReceiptUse,
} from "@hasna/accounts/native-subscription";

const useStore = new PostgresNativeCapabilityUseStore({
  client: accountsCapacitySql,
  principalRef: authenticatedInfinityPrincipal,
  runtimeRole,
  issuer: configuredIssuer,
  issuerIncarnation: configuredIssuerIncarnation,
  keyId: configuredSigningKeyId,
  audience: configuredInfinityAudience,
  privateKey: runtimeSigningKey,
  validateCurrent: async (request, transaction) => {
    // Read the coherent current deny/generation/frontier tuple using this same
    // transaction. Never return cached eligibility.
    return readCurrentCapabilityState(transaction, request);
  },
});

await consumeOnlineGenerationCheckReceiptUse(receiptBytes, expectation, guard, useStore);
```

Signing material is runtime configuration. Do not place it in source, task
evidence, logs, checkpoints, or stored receipt records.

## Downgrade and role changes

- Take and verify a database backup before first apply. The migration
  transaction rolls back package SQL when role or catalog attestation fails.
- Do not run an older migrator after a newer version has recorded a migration
  it does not know. Keep this migrator in place during an application rollback;
  older migration bytes fail checksum or newer-version checks by design.
- Schema migrations are forward-fix only. Do not delete ledger rows, disable
  forced RLS, drop immutable triggers, or rewrite recorded checksums to make an
  older binary start.
- Changing the configured runtime role or boundary mode is a maintenance
  operation. Stop runtime traffic, use the migration owner to revoke the old
  role's package-object grants, provision and validate the new role/membership,
  then rerun this migrator. Catalog attestation rejects leftover grants to an
  earlier runtime role.
