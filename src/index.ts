import type { AccountsCatalog as AccountsCatalogType } from "./domain/catalog";
import { AccountsCatalog } from "./domain/catalog";
import { InMemoryAccountsRepository } from "./storage/memory";
import { SQLiteAccountsRepository } from "./storage/sqlite";
import { FileRecoveryLedger } from "./storage/file-recovery-ledger";
import {
  PostgresAccountsRepository,
  POSTGRES_ADAPTER_STATUS_V1,
  type ConnectPostgresAccountsOptions,
} from "./storage/postgres";
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
  newCredentialOperationId,
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
  parseCredentialOperationId,
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
  CredentialOperationId,
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
  CredentialOperation,
  CredentialOperationKind,
  CredentialOperationState,
  NonterminalCredentialBinding,
  RetiredHandleCredentialBinding,
  RevocationBarrierCredentialBinding,
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
export {
  AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  AUTHORITY_EVIDENCE_TYPES,
  AUTHORITY_ISSUER_CLASSES,
  verifyAuthorityEvidence,
} from "./domain/authority-evidence";
export type {
  AuthorityEvidenceBinding,
  AuthorityEvidenceEnvelope,
  AuthorityEvidenceExpectation,
  AuthorityEvidencePayload,
  AuthorityEvidenceTrustRoot,
  AuthorityEvidenceType,
  AuthorityIssuerClass,
  ProviderCapacityPayload,
  ProviderOwnershipPayload,
} from "./domain/authority-evidence";
export {
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION,
  ONLINE_GENERATION_RECEIPT_MAXIMUM_AGE_MS,
  ONLINE_GENERATION_RECEIPT_MAXIMUM_CLOCK_SKEW_MS,
  ONLINE_GENERATION_RECEIPT_MAXIMUM_LIFETIME_MS,
  ONLINE_GENERATION_RECEIPT_MAX_USES,
  consumeOnlineGenerationCheckReceiptUse,
  projectOnlineGenerationCheckReceipt,
  verifyAllowedOnlineGenerationCheckReceipt,
  verifyOnlineGenerationCheckReceipt,
} from "./domain/online-generation-receipt";
export type {
  ConsumedOnlineGenerationReceiptUse,
  OnlineGenerationCheckReceiptDraft,
  OnlineGenerationCheckReceiptExpectation,
  OnlineGenerationCheckReceiptTrustRoot,
  OnlineGenerationReceiptUseCasRequest,
  OnlineGenerationReceiptUseCasResult,
  OnlineGenerationReceiptUseGuard,
  OnlineGenerationReceiptUseStore,
  ProjectedOnlineGenerationCheckReceipt,
  ProviderDestinationPolicy,
  VerifiedAllowedOnlineGenerationCheckReceipt,
  VerifiedOnlineGenerationCheckReceipt,
} from "./domain/online-generation-receipt";
export { EffectDispatchJournal, effectOutcomeSigningBytes } from "./storage/effect-dispatch";
export type {
  EffectDispatchAppend,
  EffectDispatchInput,
  EffectDispatchJournalOptions,
  EffectDispatchRecord,
  EffectDispatchState,
  EffectOutcomeKind,
  EffectOutcomeRecord,
  EffectOutcomeSigningInput,
  EffectPrepareInput,
  UnsignedEffectOutcomeRecord,
} from "./storage/effect-dispatch";
export { FileRecoveryLedger, OwnerOnlySignedAppendLog } from "./storage/file-recovery-ledger";
export type {
  FileRecoveryLedgerOptions,
  OwnerOnlySignedAppendLogOptions,
  SignedLogFrontier,
  SignedLogRecord,
  SignedLogSnapshot,
} from "./storage/file-recovery-ledger";
export const POSTGRES_ADAPTER_STATUS = POSTGRES_ADAPTER_STATUS_V1;
export { runPostgresMigrations } from "./storage/postgres-migrator";
export type { PostgresMigrationReport } from "./storage/postgres-migrator";
export { ACCOUNTS_V1_CONTRACT_SHA256, PACKAGE_VERSION } from "./version";
export { createAccountsCapacity } from "./sdk/index";
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
} from "./sdk/index";
export { createAccountsHttpHandler } from "./http/handler";
export { ACCOUNTS_CAPACITY_OPENAPI, serializeAccountsCapacityOpenApi } from "./http/openapi";
export {
  MemoryBootstrapIntentStore,
  MemoryHttpIdempotencyStore,
} from "./http/stores";
export type {
  AccountsAuthenticatedPrincipal,
  AccountsHttpDeploymentConfig,
  AccountsHttpHandlerOptions,
  AccountsHttpScope,
  AccountsRequestAuthenticator,
  BootstrapIntent,
  BootstrapIntentStore,
  CatalogHttpService,
  CredentialOperationIntentService,
  HttpIdempotencyStore,
  InternalHttpService,
} from "./http/types";
export {
  ACCOUNTS_ELIGIBILITY_REQUEST_SCHEMA_VERSION_V1,
  ACCOUNTS_EVIDENCE_SIGNER_HISTORY_SCHEMA_VERSION_V2,
  ACCOUNTS_RUNTIME_CONTRACT_SHA256,
  ACCOUNTS_V10_CONTRACT_SHA256,
  ACCOUNTS_V11_CONTRACT_SHA256,
  ACCOUNTS_V10_MAX_CLOCK_SKEW_MS,
  ONLINE_GENERATION_CHECK_MAX_AGE_MS,
  ONLINE_GENERATION_CHECK_MAX_LIFETIME_MS,
  ONLINE_GENERATION_CHECK_REASON_CODES_V1,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_DIGEST_V1,
  ONLINE_GENERATION_CHECK_RECEIPT_SCHEMA_VERSION_V1,
  SLOT_ELIGIBILITY_MAX_AGE_MS,
  SLOT_ELIGIBILITY_MAX_LIFETIME_MS,
  SLOT_ELIGIBILITY_REASON_CODES_V1,
  SLOT_ELIGIBILITY_SCHEMA_DIGEST_V1,
  SLOT_ELIGIBILITY_SCHEMA_VERSION_V1,
  createAccountsSlotEligibilityAdapter,
  createDeterministicAccountsSlotEligibilitySource,
  createSQLiteAccountsSlotEligibilityPort,
  encodeSlotEligibilityV1,
  parseOnlineGenerationCheckReceiptV1,
  parseSlotEligibilityV1,
} from "./v10";
export type {
  AccountsEvidenceSignerHistoryV2,
  AccountsEvidenceSignerKeyV2,
  AccountsEvidenceTrustV1,
  AccountsOnlineGenerationCheckRequest,
  AccountsOnlineGenerationContextV1,
  AccountsOnlineGenerationSourceRequestV1,
  AccountsSlotEligibilityAdapterTrustV1,
  AccountsSlotEligibilityPort,
  AccountsSlotEligibilityRequestV1,
  AccountsSlotEligibilitySource,
  AccountsRecoveryFrontierPort,
  AccountsRecoveryFrontierV1,
  DeterministicAccountsSlotEligibilitySource,
  OnlineGenerationCheckReasonCodeV1,
  OnlineGenerationCheckReceiptV1,
  SlotEligibilityCommonV1,
  SlotEligibilityPositiveV1,
  SlotEligibilityReasonCodeV1,
  SlotEligibilityResolvedNegativeV1,
  SlotEligibilityResolvedV1,
  SlotEligibilityUnresolvedNegativeV1,
  SlotEligibilityV1,
  SQLiteAccountsSlotEligibilityPort,
  SQLiteAccountsSlotEligibilityPortOptions,
  V10Counter,
  V10PositiveCounter,
  V10Sha256Digest,
  V10Timestamp,
  V10UuidV7,
  V10WireObject,
} from "./v10";

export interface CatalogFactoryOptions {
  readonly clock?: () => Date;
}

export interface SQLiteCatalogFactoryOptions extends CatalogFactoryOptions {
  readonly path: string;
  readonly recovery?: {
    readonly ledgerPath: string;
    readonly catalogIncarnation: string;
    readonly signingKey: Uint8Array;
  };
}

export interface PostgresCatalogFactoryOptions
  extends CatalogFactoryOptions,
    ConnectPostgresAccountsOptions {}

export type AccountsCapacityReader = Pick<
  AccountsCatalogType,
  "get" | "list" | "eligibility" | "checkCurrent" | "doctor" | "close"
>;

export function createInMemoryAccounts(options: CatalogFactoryOptions = {}): AccountsCapacityReader {
  return readonlyFacade(new AccountsCatalog(new InMemoryAccountsRepository(), options.clock), false);
}

export function createSQLiteAccounts(options: SQLiteCatalogFactoryOptions): AccountsCapacityReader {
  const recoveryLedger =
    options.recovery === undefined
      ? undefined
      : new FileRecoveryLedger({
          path: options.recovery.ledgerPath,
          catalogIncarnation: options.recovery.catalogIncarnation,
          signingKey: options.recovery.signingKey,
        });
  const repository = new SQLiteAccountsRepository(options.path, {
    ...(recoveryLedger === undefined ? {} : { recoveryLedger }),
    ...(options.recovery === undefined
      ? {}
      : { catalogIncarnation: options.recovery.catalogIncarnation }),
  });
  return readonlyFacade(
    new AccountsCatalog(repository, options.clock),
    recoveryLedger !== undefined,
  );
}

export async function createPostgresAccounts(
  options: PostgresCatalogFactoryOptions,
): Promise<AccountsCapacityReader> {
  const repository = PostgresAccountsRepository.connect(options);
  try {
    await repository.initialize();
    return readonlyFacade(new AccountsCatalog(repository, options.clock), true);
  } catch (error) {
    await repository.close();
    throw error;
  }
}

function readonlyFacade(
  catalog: AccountsCatalogType,
  positiveEligibility: boolean,
): AccountsCapacityReader {
  return Object.freeze({
    get: catalog.get.bind(catalog),
    list: catalog.list.bind(catalog),
    eligibility: async (...arguments_: Parameters<AccountsCatalogType["eligibility"]>) => {
      const result = await catalog.eligibility(...arguments_);
      return positiveEligibility ? result : disablePositiveEligibility(result);
    },
    checkCurrent: async (...arguments_: Parameters<AccountsCatalogType["checkCurrent"]>) => {
      const result = await catalog.checkCurrent(...arguments_);
      return positiveEligibility ? result : disablePositiveEligibility(result);
    },
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
