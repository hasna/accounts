# HTTP API and SDK

The published package includes the Bun `accounts-serve` HTTP service and a
generated TypeScript client at `@hasna/accounts/sdk`. This runtime backs
`self_hosted` and `cloud` registry modes; it is separate from the default local
JSON registry.

## Start the service

Run migrations as the schema-owning role, granting the separate DML-only runtime
role, before serving traffic:

```bash
HASNA_ACCOUNTS_STORAGE_MODE=cloud \
HASNA_ACCOUNTS_DATABASE_URL=postgres://migration-owner@db/accounts \
HASNA_ACCOUNTS_RUNTIME_ROLE=accounts_app \
accounts-migrate

HASNA_ACCOUNTS_STORAGE_MODE=cloud \
HASNA_ACCOUNTS_DATABASE_URL=postgres://accounts_app@db/accounts \
HASNA_ACCOUNTS_API_SIGNING_KEY=replace-me \
accounts-serve --host 0.0.0.0 --port 8080
```

`accounts-serve` defaults to host `0.0.0.0` and port `8080`. Port precedence is
`--port`, `PORT`, `ACCOUNTS_SERVE_PORT`, then the default. The signing secret may
also come from `HASNA_API_SIGNING_KEY`.

## Routes

Public routes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service metadata and route summary |
| `GET` | `/health` | Liveness plus database reachability |
| `GET` | `/ready` | Database reachability and migration-ledger readiness |
| `GET` | `/version` | Package version |

Authenticated routes accept `x-api-key`. Read operations require
`accounts:read`; mutations require `accounts:write`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/v1/accounts` | List/filter or create accounts |
| `GET`, `PATCH`, `DELETE` | `/v1/accounts/{tool}/{name}` | Read, update, or remove one account |
| `POST` | `/v1/accounts/{tool}/{name}/rename` | Rename an account atomically |
| `GET` | `/v1/current` | List active selections |
| `GET`, `PUT` | `/v1/current/{tool}` | Read or set one active selection |
| `GET`, `POST` | `/v1/tools` | List or register tools |
| `DELETE` | `/v1/tools/{id}` | Remove a custom tool |

Account and custom-tool directory inputs are subject to the
[profile directory policy](profile-directories.md). Built-in tools cannot be
redefined or removed.

## Generated client

```ts
import {
  AccountsClient,
  createAccountsClientFromEnv,
} from "@hasna/accounts/sdk";

const client = createAccountsClientFromEnv();
const accounts = await client.listAccounts({ tool: "claude" });
await client.setCurrent("claude", { name: "work" });

const explicit = new AccountsClient({
  baseUrl: "https://accounts.example.com",
  apiKey: process.env.ACCOUNTS_API_KEY,
});
console.log(await explicit.getReady());
```

`createAccountsClientFromEnv` reads the unprefixed client variables
`ACCOUNTS_API_URL` and `ACCOUNTS_API_KEY`. Pass `baseUrl`, `apiKey`, custom
headers, or a custom `fetch` implementation to override them. HTTP failures
throw `ApiError` with `status` and parsed response `body`.

The client exposes `getHealth`, `getReady`, `getVersion`, account CRUD and
rename methods, current-selection methods, and custom-tool list/add/remove
methods. Regenerate it from `src/server/openapi.ts` with:

```bash
bun run sdk:generate
```
