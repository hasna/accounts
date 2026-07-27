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
Opaque runtime, account, and binding IDs are deterministically allocated from
the canonical frozen input and then frozen in the plan. Rebuilding an identical
input without an existing plan produces identical IDs and an identical
idempotency key. A supplied existing plan is accepted only when its structured
census, source keys, binding identities, input digest, and idempotency key are
self-consistent and its complete plan digest is intact. Deterministic allocation
is namespaced by tenant and scope so identical legacy coordinates in different
scopes cannot collide. Legacy records are not grouped, renamed, or physically
relocated.

The redacted census view hashes machine IDs, authority IDs, runtime tool keys,
runtime labels, profile names, paths, unsafe-root reasons, source keys, and
aliases while retaining only schema-owned enums, counts, filesystem identity,
input digests, allocated opaque IDs, and quarantine evidence. Arbitrary census
text is never emitted verbatim by the redacted view.

## Conflict quarantine and aliases

Unsafe roots, unresolved catalog skips, duplicate legacy identities, the same
mutable name observed across runtimes, and distinct legacy identities resolving
to either the same canonicalized verified real path or the same canonicalized
device/inode identity are quarantined. Device and inode strings are normalized
as decimal integers, so leading-zero aliases cannot evade the physical-root
check. A shared canonical path with contradictory device, inode, or digest
evidence also fails closed, as does one device/inode identity with conflicting
path or digest evidence. Equal content digests alone do not conflate otherwise
distinct roots. Lexical path aliases such as `directory/../root` cannot evade
the path equivalence class, and hard-link aliases cannot evade the device/inode
equivalence class. A partial backfill may include only records marked `ready`;
final cutover remains blocked while any quarantine exists.

Historical account aliases target the frozen account ID. Historical session
aliases target the frozen machine-binding ID. The alias journal is append-only,
sequence-numbered, and digest-chained. Replaying the exact same alias is
idempotent; changing its source or target fails closed.

Every alias is normalized to Unicode NFC before the frozen input digest and ID
allocation. Duplicate aliases, including canonically equivalent Unicode forms,
are rejected before allocation. Plan records store one strictly ordered unique
representation, aliases are globally unique within each alias kind, and the
canonical genesis journal must contain exactly the plan-declared aliases in
that order. Reordering a stored plan and recomputing its unkeyed digest cannot
change the accepted genesis.

## Gates and cutover states

The preflight gate requires:

- no active migration writers;
- an exact match for every frozen input digest;
- enough free space for the backup contract;
- no unknown migration-ledger entries or checksum mismatches;
- no unresolved catalog skips;
- an encrypted, mode `0600`, complete backup manifest;
- database point-in-time recovery and a restore drill completed no later than
  the shared cutover epoch and no earlier than plan creation; and
- the exact plan ID, idempotency key, and cutover epoch.

The explicit state sequence is:

```text
planned -> partial_ready -> partial_applied -> final_ready -> final_applied
```

`planned -> final_ready` is permitted only when no record is quarantined.
Entering either readiness state requires current evidence evaluated against the
frozen plan. The accepted evidence is written into a checksum-protected gate
receipt bound to the exact predecessor sidecar through a bounded, digest-chained
transition journal. Entering either applied state requires the committed,
scope-bound receipt returned by `applyScopedBackfill`; that receipt covers the
plan, idempotency key, scope, exact ready predecessor, ready-record digest,
transaction counts, and epoch result. The unkeyed SHA-256 digests provide
tamper evidence and deterministic drift detection only; they are not signatures,
authentication, authorization, or proof that a writer is trusted. File
permissions, writer locking, compare-and-swap, and deployment authority remain
separate controls. Backward and skipped transitions fail. These states are
contracts only; this foundation does not make a production cutover decision.

## Transactional backfill hook

`applyScopedBackfill` exposes one tenant/scope transaction callback. It ensures
ready runtimes, accounts, legacy-to-v2 crosswalks, and the shared cutover epoch
inside that transaction. The storage port owns commit and rollback. Only after
every runtime, account, crosswalk, and epoch result is validated inside the
transaction does the function return the receipt required for the matching
`*_applied` transition. No PostgreSQL schema, migration file, or HTTP route is
added by this sidecar.

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

An existing WAL or WAL staging file always wins over a later install attempt.
The later writer fails closed and must run `repair()`; it cannot replace the
first crash-recovery intent.

`repair()` is idempotent at every durable boundary. It adopts an already
installed exact successor or completes a WAL transition only from its exact
predecessor after rechecking immutable alias, receipt, and transition-journal
history. A genesis WAL may install only the exact canonical `planned` sidecar
derived from the frozen plan. Every parsed state must retain the complete
canonical plan-required alias journal as an immutable prefix, and every
reconstructed transition predecessor must include that same alias-bearing
genesis. Rehashing a later state after deleting historical aliases therefore
fails closed. A lock owned by a live process is preserved; a valid lock naming
a dead process is removed before repair retries. Ambiguous drift preserves the
WAL and fails closed.

## Compatibility fixture

[`test/fixtures/v2-migration-compatibility.json`](../test/fixtures/v2-migration-compatibility.json)
freezes exactly one case for every old, transition, and new client/server pair.
Transition clients may preflight against an old server without writes. New
clients require final cutover before using a transition server. Old clients
cannot use a new-only server, while transition clients use the v2 contract
against a new server. The fixture does not activate any route or compatibility
behavior.
