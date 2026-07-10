# @hasna/accounts (clean V1 foundation)

Contract pin: `accounts-v1-contract.md` SHA-256
`0d2b45c286f56452312b251b7622e009c486e2fe71fe8f2a5a59c01472eb8b2a`.

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

The public development factory is read/query-only. Positive evidence ingestion,
ownership claims, recovery-frontier reconciliation, credential-handle ingestion,
terminal tombstones, and local owner ceremonies remain deliberately unavailable;
the internal catalog mutation harness exists only for reference/conformance tests.

```sh
bun install
bun test
bun run typecheck
bun run build

HASNA_ACCOUNTS_DEPLOYMENT=local accounts doctor --json
accounts validate ./record.json --json
HASNA_ACCOUNTS_DEPLOYMENT=local accounts list access-methods --json
HASNA_ACCOUNTS_DEPLOYMENT=local accounts get access-methods <uuidv7> --json
HASNA_ACCOUNTS_DEPLOYMENT=local accounts eligibility <access-method-uuidv7> \
  --operation responses.create \
  --model model.example \
  --data-classification internal \
  --json
```

Eligibility output is marked `local_diagnostic` and `non_reservational`; it is
not production Infinity authority. Current denial always wins over previously
positive evidence.

Local list/get output is intentionally owner-only metadata for the trusted OS
user. It is not a self-hosted reader projection and must not be reused without
authenticated owner scoping and redaction. Native credential mutation is also
fail-closed in this slice: drain metadata is not proof of zero live Infinity
resource leases, so reauthentication execution remains unimplemented until a
trusted Run Authority verifier is integrated.
