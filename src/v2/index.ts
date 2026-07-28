export {
  accountIdSchema,
  accountSchema,
  accountV2DtoSchema,
  accountV2ListSchema,
  assertEntityScope,
  bindingIdSchema,
  machineIdSchema,
  RegistryConflictError,
  RegistryNotFoundError,
  RegistryScopeError,
  renameAccountInputSchema,
  renameAccountRequestSchema,
  registryScopeSchema,
  runtimeIdSchema,
  runtimeSchema,
  runtimeV2DtoSchema,
  runtimeV2ListSchema,
  scopeIdSchema,
  tenantIdSchema,
  timestampSchema,
  toAccountV2Dto,
  toRuntimeV2Dto,
} from "./domain.js";
export type {
  Account,
  AccountId,
  AccountV2Dto,
  BindingId,
  MachineId,
  RegistryScope,
  Runtime,
  RuntimeId,
  RuntimeV2Dto,
  RenameAccountRequest,
  ScopeRef,
  ScopeId,
  TenantId,
} from "./domain.js";
export type { AccountsRegistry } from "./registry.js";
export { LocalAccountsRegistry } from "./local-registry.js";
export type { LocalRegistrySeed } from "./local-registry.js";
export { HttpAccountsRegistry } from "./http-registry.js";
export type { HttpAccountsRegistryOptions } from "./http-registry.js";
// PostgresAccountsRegistry is deliberately not re-exported: it queries the
// additive accounts_v2/runtimes_v2 tables, which no shipped migration creates,
// so a published consumer would fail on its first query with a missing
// relation. It rejoins this entry point in the migration slice that creates
// those tables and proves the adapter against a real PostgreSQL. Until then it
// stays reachable in-repo for contract tests only; the invariant is pinned by
// src/v2/public-surface.test.ts.
export {
  bindingAuthenticationSchema,
  machineBindingGenerationSchema,
  machineBindingSchema,
  MachineBindingOverlay,
} from "./machine-binding.js";
export type { BindingAuthentication, MachineBinding } from "./machine-binding.js";
