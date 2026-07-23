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
schema through version 3. It must run with the migration/admin connection. The
runtime ledgers install `accounts_runtime`, force row-level security, and bind
each transaction to an authenticated Hasna principal and realm.

This migration set is separate from the existing `accounts-serve` profile
registry migrations. A self-hosted Infinity deployment should provision the
capacity schema explicitly and give runtime code only the DML-only
`accounts_runtime` role.

```ts
import {
  PostgresNativeCapabilityUseStore,
  consumeOnlineGenerationCheckReceiptUse,
} from "@hasna/accounts/native-subscription";

const useStore = new PostgresNativeCapabilityUseStore({
  client: accountsCapacitySql,
  principalRef: authenticatedInfinityPrincipal,
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
