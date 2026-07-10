# @hasna/accounts (clean V1 foundation)

Accounts is a capacity-metadata SDK and CLI for Hasna `local` and
`self_hosted` deployments. This clean implementation owns provider-account,
entitlement, capacity-pool, access-method, credential-binding, and
AuthCapsule metadata. It evaluates non-reservational slot eligibility.

It does **not** reserve capacity, issue a run/resource lease, execute a task,
resolve credential material, start a provider process, or provide SaaS tenant,
signup, billing, organization, or hosted-product features. Credential bindings
contain safe issuer metadata only; raw values and resolver locators are rejected
at DTO boundaries.

The implemented persistence adapters are:

- in-memory, as the deterministic reference model;
- SQLite through `bun:sqlite`, for local operation.

The public repository interface intentionally leaves a Postgres adapter as a
future self-hosted implementation. No Postgres conformance claim is made by
this development build.

```sh
bun install
bun test
bun run typecheck
bun run build

accounts doctor --json
accounts validate ./record.json --json
accounts list access-methods --json
accounts get access-methods <uuidv7> --json
accounts eligibility <access-method-uuidv7> \
  --operation responses.create \
  --model model.example \
  --data-classification internal \
  --json
```

Eligibility output is marked `local_diagnostic` and `non_reservational`; it is
not production Infinity authority. Current denial always wins over previously
positive evidence.
