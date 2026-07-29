# Accounts v2 foundation

`@hasna/accounts/v2` is an additive contract surface. It does not migrate the
v1 registry, create PostgreSQL tables, change CLI commands, or activate new HTTP
routes.

The domain has one immutable opaque account ID, one immutable opaque runtime
ID, and an explicit tenant/scope on every entity and registry operation.
Authentication is deliberately absent from `Account`: it belongs to a
machine-local `MachineBinding`, together with the physical root, opaque
credential reference, and local current/applied pointers.

Machine-binding generations are authorization state, not display metadata.
Within one tenant/scope and binding ID, a lower generation is rejected, an
equal generation is accepted only as an exact idempotent replay, and only a
strictly newer generation may change the machine-local root, credential
reference, or authentication state. Rejected updates do not alter the binding
or its current/applied pointers. Generations are nonnegative JavaScript safe
integers. `Number.MAX_SAFE_INTEGER - 1` may advance once to
`Number.MAX_SAFE_INTEGER`; at that maximum, only an exact idempotent replay is
valid and any changed state is rejected as exhausted.

Every v2 timestamp uses one canonical wire/storage representation:
`YYYY-MM-DDTHH:mm:ss.SSSZ`. Missing, shorter, or longer fractional precision,
offset aliases, and invalid calendar instants are rejected rather than
normalized. This matches the millisecond precision preserved by JavaScript
`Date` and PostgreSQL driver values, so exact values survive a round trip and
lexical ordering is also chronological ordering. Every account and runtime
also requires `updatedAt >= createdAt`; an impossible chronology is rejected
at local, HTTP, and PostgreSQL ingress before it can be preserved by a later
rename.

`AccountsRegistry` is the only v2 domain port. The in-memory local adapter is a
test double, while the HTTP and PostgreSQL adapters are structural foundations
for future routes and tables. Their fixture tests check contract shape and
scope propagation only; they do not establish behavior or operational parity
with real HTTP or PostgreSQL backends. Name uniqueness and runtime-association
enforcement are intentionally deferred until the tenant-backfill and collision
gates are complete.

The PostgreSQL adapter is therefore not exported from the published
`@hasna/accounts/v2` entry point. Its `accounts_v2` and `runtimes_v2` tables
have no shipped migration, so exporting it would hand consumers a registry whose
first query fails on a missing relation, and its optimistic-lock and
unique-violation paths are covered only by in-repo fixtures rather than by a
real PostgreSQL. It joins the public entry point in the migration slice that
creates those tables and exercises it against a live database.

The process-local adapter and machine-binding overlay isolate their stored state
from callers: constructor and write inputs are parsed into frozen snapshots, and
every object or collection returned by read, write, or snapshot operations is a
fresh frozen view. Duplicate scoped IDs in local constructor seeds fail instead
of overwriting earlier entities. The HTTP adapter also treats responses as
untrusted: exact lookups must return the requested identity, and rename
responses must apply the requested new name and an advancing requested
timestamp without changing any other account field. HTTP and PostgreSQL create
and runtime-registration responses must reproduce every requested field
exactly, including mutable display fields and timestamps. Scoped list responses
must contain one unambiguous entity per opaque ID; identical and conflicting
duplicates are both rejected.

Local, HTTP, and PostgreSQL rename operations share that same transition
invariant: the requested name must differ, the requested timestamp must
advance, and the accepted result must apply both without changing ID, scope,
runtime association, email, creation time, or any other non-target field.
PostgreSQL exact lookups and write
responses additionally require an exact zero-or-one or one-row result as
appropriate. Creates, runtime registrations, and renames validate the complete
requested transition inside transactions so a malformed response or count
mismatch rolls back instead of committing partially trusted state.

The future v2 HTTP rename route must enforce optimistic concurrency. The
foundation client pre-reads the account, sends that exact canonical
`updatedAt` as both `expectedUpdatedAt` in the strict request body and
`If-Match`, and treats both HTTP `409 Conflict` and `412 Precondition Failed`
as a typed `RegistryConflictError`. The HTTP status is retained on the error,
while untrusted response details are not copied into its message or cause.
Fixture coverage proves the contract and stale-request behavior only; this PR
does not add or claim a production v2 route.

The HTTP and PostgreSQL adapters are contract-first foundations for the later
wire/schema migration slice. Both constrain every operation by tenant and
scope. V2 DTOs omit arbitrary account metadata and reject or strip machine
paths, credential references, authentication, and current/applied state,
including those fields nested inside a metadata envelope. The existing v1 API
may retain those legacy fields only inside its isolated compatibility contract.

Synchronous profile functions exported from the package root are now explicit
local-only compatibility. They can never select the async hosted registry, so
under hosted/self-hosted authority they are not answering for the store of
record — but writes and reads get different treatment, because the two hazards
are different.

**Writes fail closed.** `saveStore`, `addProfile`, `removeProfile`,
`renameProfile`, `updateProfile`, `redetectEmail`, `useProfile`,
`lockProfileTool`, `addCustomTool`, `removeCustomTool` and the deprecated
`ensureProfileForLogin` throw before any local I/O whenever hosted authority is
configured. A synchronous root write there would land in this machine's local
JSON file while the registry of record is elsewhere, silently diverging the two.
There is no correct local answer to give.

**Reads answer and announce.** `loadStore`, `listTools`, `getTool`,
`listProfiles`, `findProfile`, `getProfile`, `getProfileToolLock`,
`currentProfile` and `appliedProfile` return the same machine-local answer they
returned before this layer existed, and emit a `DeprecationWarning` with code
`HASNA_ACCOUNTS_LOCAL_COMPAT_READ` once per operation per process.

Making reads throw was tried and measured on the fleet, and it was worse than
the problem it addressed. `@hasna/economy`'s `resolveAccountForAgent` wraps
every accounts call in `try {} catch {}`, so the intended loud failure arrived
as a silent `null`: per-account cost attribution went to zero on every
cloud-mode machine with no error, no log and no alert — the exact
silent-wrong-answer class the gate exists to prevent. `process.emitWarning` is
used precisely because a `catch` block cannot swallow it.

Set `HASNA_ACCOUNTS_STRICT_ROOT_COMPAT=1` to opt a process into the end state,
where hosted authority makes reads throw as well. That becomes the default once
the remaining root-import consumers move to `resolveStore()` or
`@hasna/accounts/v2`; until then it is how a caller that wants fail-closed reads
gets them, and how the fleet will be flipped once `@hasna/economy` migrates.

`appliedProfileName` is exempt in every mode, including strict: it returns only
the machine-local applied pointer — never a registry record.

The deprecated `ensureProfileForLogin` root export uses that same canonical
authority resolver, including `HASNA_ACCOUNTS_MODE`, rather than maintaining a
separate mode policy. Retired `remote`, `hybrid`, and `s3` words are skipped as
absent authority and cannot mask a canonical value from a lower-precedence
compatibility key. Async v1 callers use `resolveStore()`; new callers use
`@hasna/accounts/v2`.
