import type { AccountsCatalog as AccountsCatalogType } from "./domain/catalog";
import { AccountsCatalog } from "./domain/catalog";
import { InMemoryAccountsRepository } from "./storage/memory";
import { SQLiteAccountsRepository } from "./storage/sqlite";

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
  newCanonicalNodeId,
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
export { canonicalJson, parseClosedJson } from "./serialization/json";
export { POSTGRES_ADAPTER_STATUS } from "./storage/repository";
export { PACKAGE_VERSION } from "./version";

export interface CatalogFactoryOptions {
  readonly clock?: () => Date;
}

export interface SQLiteCatalogFactoryOptions extends CatalogFactoryOptions {
  readonly path: string;
}

export type AccountsCapacity = Pick<
  AccountsCatalogType,
  "get" | "list" | "add" | "transition" | "eligibility" | "checkCurrent" | "doctor" | "close"
>;

export function createInMemoryAccounts(options: CatalogFactoryOptions = {}): AccountsCapacity {
  return new AccountsCatalog(new InMemoryAccountsRepository(), options.clock);
}

export function createSQLiteAccounts(options: SQLiteCatalogFactoryOptions): AccountsCapacity {
  return new AccountsCatalog(new SQLiteAccountsRepository(options.path), options.clock);
}
