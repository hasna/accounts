# Accounts Capacity OpenAPI

`accounts.capacity.v1.json` is generated from the runtime document in
`src/http/openapi.ts`, which is also served by `GET /openapi.json`.

Regenerate deterministically with:

```sh
bun openapi/generate.ts
```

The document describes only the clean capacity origin. It deliberately omits
legacy profile/tool routes, credential-handle retrieval, provider-login or
device-code ceremonies, lease operations, tenant/signup routes, and all native
reauthentication execution methods.
