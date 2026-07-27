# Accounts v2 foundation

`@hasna/accounts/v2` is an additive contract surface. It does not migrate the
v1 registry, create PostgreSQL tables, change CLI commands, or activate new HTTP
routes.

The domain has one immutable opaque account ID, one immutable opaque runtime
ID, and an explicit tenant/scope on every entity and registry operation.
Authentication is deliberately absent from `Account`: it belongs to a
machine-local `MachineBinding`, together with the physical root, opaque
credential reference, and local current/applied pointers.

`AccountsRegistry` is the only v2 domain port. The local, HTTP, and PostgreSQL
adapters implement the same async create/read/rename behavior. Name uniqueness
and runtime-association enforcement are intentionally deferred until the
tenant-backfill and collision gates are complete.

The HTTP and PostgreSQL adapters are contract-first foundations for the later
wire/schema migration slice. Both constrain every operation by tenant and
scope. V2 DTOs reject or strip machine paths, credentials, authentication, and
current/applied state. The existing v1 API may retain those legacy fields only
inside its isolated compatibility contract.

Synchronous profile functions exported from the package root are now explicit
local-only compatibility. They preserve local behavior, but fail before local
I/O whenever hosted/self-hosted authority is configured. Async v1 callers use
`resolveStore()`; new callers use `@hasna/accounts/v2`.
