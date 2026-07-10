import type {
  Account,
  AccessMethod,
  AuthCapsule,
  CapacityPool,
  CredentialBindingMetadata,
  EligibilityRequest,
  Entitlement,
  FundingKind,
  SlotEligibilityMetadata,
} from "../domain/models";
import type { Counter } from "../domain/counter";
import type {
  AccountId,
  AccessMethodId,
  AuthCapsuleId,
  CapacityPoolId,
  CredentialBindingId,
  EntitlementId,
} from "../domain/ids";
import type { BootstrapIntent } from "../http/types";

export interface AccountsAuthProvider {
  /** Adds a separately audienced capacity authorization header. */
  authorize(headers: Headers, signal?: AbortSignal): Promise<void>;
}

export interface LocalRecoveryConfiguration {
  readonly ledgerPath: string;
  readonly catalogIncarnation: string;
  readonly signingKey: Uint8Array;
}

export type AccountsDeployment =
  | {
      readonly mode: "local";
      readonly sqlitePath?: string;
      readonly actorRef: string;
      readonly recovery?: LocalRecoveryConfiguration;
    }
  | {
      readonly mode: "self_hosted";
      readonly baseUrl: string;
      readonly authProvider: AccountsAuthProvider;
    };

export interface CallOptions {
  readonly signal?: AbortSignal;
}

export interface ListOptions extends CallOptions {
  readonly cursor?: string;
  readonly limit?: number;
}

export interface MutationOptions extends CallOptions {
  readonly idempotencyKey: string;
}

export interface RevisionMutationOptions extends MutationOptions {
  readonly expectedRevision: Counter;
}

export interface Page<T> {
  readonly records: readonly T[];
  readonly nextCursor: string | null;
}

/** Normal readers never receive provider subject values or candidate fingerprints. */
export type ProviderAccountView = Omit<
  Account,
  "providerSubjectRef" | "providerSubjectCandidateRef"
> & {
  readonly providerSubjectRefRedacted?: true;
};

export interface CreateProviderAccountInput {
  readonly providerKey: string;
  readonly ownerRef: string;
  readonly displayLabel: string;
  readonly providerSubjectCandidateRef?: string;
  readonly providerDisplayHint?: string;
}

export interface CreateEntitlementInput {
  readonly providerAccountId: AccountId;
  readonly fundingKind: FundingKind;
}

export interface CreateAccountLaneInput {
  readonly entitlementId: EntitlementId;
  readonly capacityPoolId: CapacityPoolId;
  readonly adapterKey: string;
  readonly adapterVersion: string;
  readonly accessTransport: AccessMethod["accessTransport"];
}

export interface BootstrapIntentInput {
  readonly reasonCode: string;
}

export interface ProviderAccountsApi {
  list(options?: ListOptions): Promise<Page<ProviderAccountView>>;
  get(id: AccountId, options?: CallOptions): Promise<ProviderAccountView>;
  create(
    input: CreateProviderAccountInput,
    options: MutationOptions,
  ): Promise<ProviderAccountView>;
}

export interface EntitlementsApi {
  list(options?: ListOptions): Promise<Page<Entitlement>>;
  get(id: EntitlementId, options?: CallOptions): Promise<Entitlement>;
  create(input: CreateEntitlementInput, options: MutationOptions): Promise<Entitlement>;
}

export interface ReadonlyCapacityPoolsApi {
  list(options?: ListOptions): Promise<Page<CapacityPool>>;
  get(id: CapacityPoolId, options?: CallOptions): Promise<CapacityPool>;
}

export interface AccountLanesApi {
  list(options?: ListOptions): Promise<Page<AccessMethod>>;
  get(id: AccessMethodId, options?: CallOptions): Promise<AccessMethod>;
  create(input: CreateAccountLaneInput, options: MutationOptions): Promise<AccessMethod>;
}

export interface AuthCapsulesApi {
  list(options?: ListOptions): Promise<Page<AuthCapsule>>;
  get(id: AuthCapsuleId, options?: CallOptions): Promise<AuthCapsule>;
  createBootstrapIntent(
    id: AuthCapsuleId,
    input: BootstrapIntentInput,
    options: RevisionMutationOptions,
  ): Promise<BootstrapIntent>;
  getBootstrapIntent(
    id: AuthCapsuleId,
    intentId: string,
    options?: CallOptions,
  ): Promise<BootstrapIntent>;
}

export interface ReadonlyCredentialBindingsApi {
  list(options?: ListOptions): Promise<Page<CredentialBindingMetadata>>;
  get(id: CredentialBindingId, options?: CallOptions): Promise<CredentialBindingMetadata>;
}

export interface CapacityQueryApi {
  query(request: EligibilityRequest, options?: CallOptions): Promise<SlotEligibilityMetadata>;
}

export interface AccountsCapacity {
  readonly providerAccounts: ProviderAccountsApi;
  readonly entitlements: EntitlementsApi;
  readonly capacityPools: ReadonlyCapacityPoolsApi;
  readonly lanes: AccountLanesApi;
  readonly capsules: AuthCapsulesApi;
  readonly credentialBindings: ReadonlyCredentialBindingsApi;
  readonly capacity: CapacityQueryApi;
  close(options?: CallOptions): Promise<void>;
}
