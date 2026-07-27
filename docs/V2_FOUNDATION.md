# Accounts v2 foundation

`@hasna/accounts/v2` is an additive contract surface. It does not migrate the
v1 registry, create PostgreSQL tables, change CLI commands, or activate new HTTP
routes.

The domain has one immutable opaque account ID, one immutable opaque runtime
ID, and an explicit tenant/scope on every entity and registry operation.
Authentication is deliberately absent from `Account`: it belongs to a
machine-local `MachineBinding`, together with the physical root, opaque
credential reference, and local current/applied pointers.

`AccountsRegistry` is the only v2 domain port. The in-memory local adapter is a
test double, while the HTTP and PostgreSQL adapters are structural foundations
for future routes and tables. Their fixture tests check contract shape and
scope propagation only; they do not establish behavior or operational parity
with real HTTP or PostgreSQL backends. Name uniqueness and runtime-association
enforcement are intentionally deferred until the tenant-backfill and collision
gates are complete.

The process-local adapter and machine-binding overlay isolate their stored state
from callers: constructor and write inputs are parsed into frozen snapshots, and
every object or collection returned by read, write, or snapshot operations is a
fresh frozen view. Duplicate scoped IDs in local constructor seeds fail instead
of overwriting earlier entities. The HTTP adapter also treats responses as
untrusted: exact lookups must return the requested identity, and rename
responses must apply the requested new name and an advancing requested
timestamp without changing immutable identity fields.

The HTTP and PostgreSQL adapters are contract-first foundations for the later
wire/schema migration slice. Both constrain every operation by tenant and
scope. V2 DTOs omit arbitrary account metadata and reject or strip machine
paths, credential references, authentication, and current/applied state,
including those fields nested inside a metadata envelope. The existing v1 API
may retain those legacy fields only inside its isolated compatibility contract.

Synchronous profile functions exported from the package root are now explicit
local-only compatibility. They preserve local behavior, but fail before local
I/O whenever hosted/self-hosted authority is configured. Async v1 callers use
`resolveStore()`; new callers use `@hasna/accounts/v2`.
