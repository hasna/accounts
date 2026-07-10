import type { AccountsCatalog as AccountsCatalogType } from "./domain/catalog";
import { AccountsCatalog } from "./domain/catalog";
import { InMemoryAccountsRepository } from "./storage/memory";
import { SQLiteAccountsRepository } from "./storage/sqlite";
import { validateSlotEligibility as validateSlotEligibilityForFacade } from "./serialization/dto";

export {
  ACCOUNT_ERROR_CODES,
  AccountsError,
  asAccountsError,
  exitCodeForError,
  toErrorEnvelope,
} from "./errors";
export type {
  AccountErrorCode,
  ErrorEnvelope,
  SafeErrorDetail,
  SafeErrorDetails,
} from "./errors";
export {
  MAX_COUNTER,
  compareCounters,
  counter,
  incrementCounter,
  parseCounter,
} from "./domain/counter";
export type { Counter } from "./domain/counter";
export {
  isUuidV7,
  newAccessMethodId,
  newAccountEventId,
  newAccountId,
  newAccountLaneId,
  newAuthCapsuleId,
  newCapacityPoolId,
  newCredentialBindingId,
  newEligibilityEvidenceId,
  newEntitlementId,
  newProviderAccountId,
  parseAccessMethodId,
  parseAccountId,
  parseAccountLaneId,
  parseAuthCapsuleId,
  parseCanonicalNodeId,
  parseCapacityPoolId,
  parseCredentialBindingId,
  parseEligibilityEvidenceId,
  parseEntitlementId,
  parseProviderAccountId,
} from "./domain/ids";
export type {
  AccessMethodId,
  AccountEventId,
  AccountId,
  AccountLaneId,
  AuthCapsuleId,
  CanonicalNodeId,
  CapacityPoolId,
  CredentialBindingId,
  EligibilityEvidenceId,
  EntitlementId,
  ProviderAccountId,
} from "./domain/ids";
export {
  ACCOUNTS_CAPACITY_SCHEMA_VERSION,
  ELIGIBILITY_REASON_CODES,
} from "./domain/models";
export type {
  Account,
  AccountLane,
  AccountStatus,
  AccessMethod,
  AccessMethodStatus,
  AccessTransport,
  AnyEntity,
  AuthCapsule,
  AuthCapsuleStatus,
  CapabilitySet,
  CapacityPool,
  CapacityPoolStatus,
  CredentialBinding,
  CredentialBindingMetadata,
  CredentialBindingStatus,
  CredentialPurpose,
  CredentialResolver,
  DataPolicy,
  DenyState,
  EligibleSlotEligibility,
  EligibilityAccessTarget,
  EligibilityReasonCode,
  EligibilityRequest,
  EntityKind,
  EntityMap,
  Entitlement,
  EntitlementStatus,
  FundingKind,
  HealthObservation,
  IneligibleSlotEligibility,
  ProviderAccount,
  SlotEligibility,
  SlotEligibilityMetadata,
  TermsDecision,
} from "./domain/models";
export {
  assertTransition,
  validateNativeReauthenticationCandidate,
  validateRoutineNativeRefreshCandidate,
} from "./domain/state";
export {
  decodeRecordEnvelope,
  deserializeRecordEnvelope,
  encodeRecordEnvelope,
  serializeRecordEnvelope,
  validateEntity,
  validateEligibilityRequest,
  validateSlotEligibility,
} from "./serialization/dto";
export type { RecordEnvelope } from "./serialization/dto";
export { canonicalJson, parseClosedJson, parseClosedJsonBytes } from "./serialization/json";
export { POSTGRES_ADAPTER_STATUS } from "./storage/repository";
export { ACCOUNTS_V1_CONTRACT_SHA256, PACKAGE_VERSION } from "./version";

export interface CatalogFactoryOptions {
  readonly clock?: () => Date;
}

export interface SQLiteCatalogFactoryOptions extends CatalogFactoryOptions {
  readonly path: string;
}

export type AccountsCapacity = Pick<
  AccountsCatalogType,
  "get" | "list" | "eligibility" | "checkCurrent" | "doctor" | "close"
>;

export function createInMemoryAccounts(options: CatalogFactoryOptions = {}): AccountsCapacity {
  return readonlyFacade(new AccountsCatalog(new InMemoryAccountsRepository(), options.clock));
}

export function createSQLiteAccounts(options: SQLiteCatalogFactoryOptions): AccountsCapacity {
  return readonlyFacade(new AccountsCatalog(new SQLiteAccountsRepository(options.path), options.clock));
}

function readonlyFacade(catalog: AccountsCatalogType): AccountsCapacity {
  return Object.freeze({
    get: catalog.get.bind(catalog),
    list: catalog.list.bind(catalog),
    eligibility: async (...arguments_: Parameters<AccountsCatalogType["eligibility"]>) =>
      disablePositiveEligibility(await catalog.eligibility(...arguments_)),
    checkCurrent: async (...arguments_: Parameters<AccountsCatalogType["checkCurrent"]>) =>
      disablePositiveEligibility(await catalog.checkCurrent(...arguments_)),
    doctor: catalog.doctor.bind(catalog),
    close: catalog.close.bind(catalog),
  });
}

function disablePositiveEligibility(
  result: Awaited<ReturnType<AccountsCatalogType["eligibility"]>>,
) {
  if (!result.eligible) return result;
  return validateSlotEligibilityForFacade({
    ...result,
    eligible: false,
    reasonCodes: ["DEPENDENCY_UNAVAILABLE"],
  });
}
