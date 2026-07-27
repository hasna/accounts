# Accounts v2 migration sidecar

The v2 migration sidecar is an additive, preflight-only contract for planning
and recording a future migration from the v1 registry. This foundation does not
run a live migration, rewrite `accounts.json`, move or copy profile roots,
change credentials, activate v2 routes, or retire a v1 client or server.

## Frozen census and immutable identities

`buildMigrationPlan` accepts a strict, scope-bound census:

- exact digests for the v1 registry, session catalog, hooks, and supervisor;
- a verified or explicitly unsafe observation for every legacy profile root;
- device, inode, entry count, byte count, and digest for verified roots;
- authentication health only, never credential contents or references;
- current, applied, and tool-lock pointer observations;
- digested session references and catalog skips;
- historical account and session aliases; and
- one encrypted backup and restore-drill plan.

The backup byte requirement must cover every verified root. A rerun may reuse an
existing plan only when the complete canonical input digest is unchanged.
Opaque runtime, account, and binding IDs are allocated once and then frozen in
the plan. Legacy records are not grouped, renamed, or physically relocated.

The redacted census view hashes machine IDs, authority IDs, profile names,
paths, unsafe-root reasons, source keys, and aliases while retaining counts,
filesystem identity, input digests, allocated IDs, and quarantine evidence.

## Conflict quarantine and aliases

Unsafe roots, unresolved catalog skips, duplicate legacy identities, and the
same mutable name observed across runtimes are quarantined. A partial backfill
may include only records marked `ready`; final cutover remains blocked while
any quarantine exists.

Historical account aliases target the frozen account ID. Historical session
aliases target the frozen machine-binding ID. The alias journal is append-only,
sequence-numbered, and digest-chained. Replaying the exact same alias is
idempotent; changing its source or target fails closed.

## Gates and cutover states

The preflight gate requires:

- no active migration writers;
- an exact match for every frozen input digest;
- enough free space for the backup contract;
- no unknown migration-ledger entries or checksum mismatches;
- no unresolved catalog skips;
- an encrypted, mode `0600`, complete backup manifest;
- database point-in-time recovery and a restore drill completed no later than
  the shared cutover epoch; and
- the exact plan ID, idempotency key, and cutover epoch.

The explicit state sequence is:

```text
planned -> partial_ready -> partial_applied -> final_ready -> final_applied
```

`planned -> final_ready` is permitted only when no record is quarantined.
Entering either readiness state requires current evidence evaluated against the
frozen plan; callers cannot transition to readiness without it. Backward and
skipped transitions fail. These states are contracts only; this foundation does
not make a production cutover decision.

## Transactional backfill hook

`applyScopedBackfill` exposes one tenant/scope transaction callback. It ensures
ready runtimes, accounts, legacy-to-v2 crosswalks, and the shared cutover epoch
inside that transaction. The storage port owns commit and rollback. No
PostgreSQL schema, migration file, or HTTP route is added by this sidecar.

Runtime definitions must be identical for every record sharing a runtime ID.
The crosswalk retains source authority, authority ID, legacy tool/name, and the
frozen account, runtime, and binding IDs.

## Durable file contract and repair

`MigrationSidecarStore` must use a path distinct from the v1 registry, including
hard-link or symlink aliases. Existing sidecar and WAL files must be regular,
non-symlink files with mode `0600`.

Each update uses:

1. an exclusive migration-writer lock;
2. a full-payload WAL containing the exact predecessor and successor digests;
3. WAL file `fsync`, atomic rename, and parent-directory `fsync`;
4. sidecar file `fsync`, atomic rename, and parent-directory `fsync`; and
5. WAL removal followed by another parent-directory `fsync`.

Updates after the initial `planned` install require the exact previously read
integrity digest. This compare-and-swap boundary prevents a stale writer from
overwriting a newer state or alias-journal entry.

`repair()` is idempotent at every durable boundary. It adopts an already
installed exact successor or completes a WAL transition only from its exact
predecessor. A lock owned by a live process is preserved; a valid lock naming a
dead process is removed before repair retries. Ambiguous drift preserves the
WAL and fails closed.

## Compatibility fixture

[`test/fixtures/v2-migration-compatibility.json`](../test/fixtures/v2-migration-compatibility.json)
freezes expected old, transition, and new client/server behavior. Transition
clients may preflight against an old server without writes. New clients require
final cutover before using a transition server. The fixture does not activate
any route or compatibility behavior.
