import { ACCOUNTS_CAPACITY_OPENAPI, serializeAccountsCapacityOpenApi } from "../src/http/openapi";

if (ACCOUNTS_CAPACITY_OPENAPI.openapi !== "3.1.0") {
  throw new Error("unexpected OpenAPI version");
}

await Bun.write(new URL("./accounts.capacity.v1.json", import.meta.url), serializeAccountsCapacityOpenApi());
