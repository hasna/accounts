import { AccountsError } from "../errors";
import { createLocalAccountsCapacity } from "./local";
import { createSelfHostedAccountsCapacity } from "./remote";
import type { AccountsCapacity, AccountsDeployment } from "./types";

export type {
  AccountLanesApi,
  AccountsAuthProvider,
  AccountsCapacity,
  AccountsDeployment,
  AuthCapsulesApi,
  BootstrapIntentInput,
  CallOptions,
  CapacityQueryApi,
  CreateAccountLaneInput,
  CreateEntitlementInput,
  CreateProviderAccountInput,
  EntitlementsApi,
  ListOptions,
  LocalRecoveryConfiguration,
  MutationOptions,
  Page,
  ProviderAccountsApi,
  ProviderAccountView,
  ReadonlyCapacityPoolsApi,
  ReadonlyCredentialBindingsApi,
  RevisionMutationOptions,
} from "./types";
export { createLocalAccountsCapacityFromCatalog } from "./local";

/**
 * Deployment choice is explicit and immutable. A self-hosted error is returned
 * to the caller and never falls back to SQLite.
 */
export function createAccountsCapacity(config: AccountsDeployment): AccountsCapacity {
  const record = config as AccountsDeployment & Record<string, unknown>;
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw invalidConfig("config");
  }
  if (record.mode === "local") {
    exactConfigurationKeys(record, ["mode", "actorRef"], ["sqlitePath", "recovery"]);
    if (record.recovery !== undefined) {
      if (
        record.recovery === null ||
        typeof record.recovery !== "object" ||
        Array.isArray(record.recovery)
      ) {
        throw invalidConfig("recovery");
      }
      exactConfigurationKeys(
        record.recovery as unknown as Record<string, unknown>,
        ["ledgerPath", "catalogIncarnation", "signingKey"],
      );
      if (!(record.recovery.signingKey instanceof Uint8Array)) {
        throw invalidConfig("recovery.signingKey");
      }
    }
    return createLocalAccountsCapacity(record.actorRef, record.sqlitePath, record.recovery);
  }
  if (record.mode === "self_hosted") {
    exactConfigurationKeys(record, ["mode", "baseUrl", "authProvider"]);
    if (
      record.authProvider === null ||
      typeof record.authProvider !== "object" ||
      typeof record.authProvider.authorize !== "function"
    ) {
      throw invalidConfig("authProvider");
    }
    return createSelfHostedAccountsCapacity(record.baseUrl, record.authProvider);
  }
  throw invalidConfig("mode");
}

function exactConfigurationKeys(
  config: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(config)) {
    if (!allowed.has(key)) throw invalidConfig(key);
  }
  for (const key of required) {
    if (!Object.hasOwn(config, key)) throw invalidConfig(key);
  }
}

function invalidConfig(field: string): AccountsError {
  return new AccountsError("VALIDATION_FAILED", "Accounts deployment configuration is invalid", {
    details: { field: field.replace(/[^A-Za-z0-9_.]/g, "_").slice(0, 64) },
  });
}
