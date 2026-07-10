import type { Counter } from "../domain/counter";
import type {
  AuthCapsuleId,
  CredentialOperationId,
  EntityId,
} from "../domain/ids";
import type {
  AuthCapsule,
  CredentialBinding,
  CredentialOperation,
  EligibilityRequest,
  EntityKind,
  EntityMap,
  SlotEligibilityMetadata,
} from "../domain/models";
import type {
  MutationContext,
  MutationResult,
  RepositoryDoctor,
} from "../storage/repository";

export const ACCOUNTS_HTTP_SCOPES = [
  "accounts:read",
  "accounts:write",
  "accounts:provider-ownership:verify",
  "accounts:capacity-pools:attest",
  "accounts:terms:attest",
  "accounts:execution-policy:attest",
  "accounts:health:report",
  "accounts:placement:attest",
  "accounts:deployment:attest",
  "accounts:capsules:bootstrap-intent",
  "accounts:credentials:request",
  "accounts:credentials:issue",
  "accounts:credentials:handles:read",
  "accounts:eligibility:issue",
  "accounts:generation:check",
  "accounts:admin",
] as const;

export type AccountsHttpScope = (typeof ACCOUNTS_HTTP_SCOPES)[number];

/**
 * The authenticator creates this value from verified transport credentials.
 * No request JSON member or unverified header is ever projected into it.
 */
export interface AccountsAuthenticatedPrincipal {
  readonly actorRef: string;
  readonly subjectRef: string;
  readonly issuer: string;
  readonly audience: string;
  readonly scopes: ReadonlySet<AccountsHttpScope>;
  /** Exact owners the verified actor may act for. There is deliberately no wildcard. */
  readonly authorizedOwnerRefs: ReadonlySet<string>;
}

export interface AccountsRequestAuthenticator {
  authenticate(
    request: Request,
    expectedAudience: string,
  ): Promise<AccountsAuthenticatedPrincipal | undefined>;
}

export interface CatalogHttpService {
  get<K extends EntityKind>(kind: K, id: EntityMap[K]["id"]): Promise<EntityMap[K]>;
  list<K extends EntityKind>(kind: K): Promise<readonly EntityMap[K][]>;
  eligibility(request: EligibilityRequest): Promise<SlotEligibilityMetadata>;
  doctor(): Promise<RepositoryDoctor>;
  add?<K extends EntityKind>(
    kind: K,
    record: EntityMap[K],
    context: MutationContext,
  ): Promise<MutationResult<EntityMap[K]>>;
}

export interface BootstrapIntent {
  readonly schemaVersion: "accounts.bootstrap-intent.v1";
  readonly id: string;
  readonly authCapsuleId: AuthCapsuleId;
  readonly ownerRef: string;
  readonly canonicalNodeId: string;
  readonly nodeGeneration: Counter;
  readonly placementGeneration: Counter;
  readonly authGeneration: Counter;
  readonly capsuleRevision: Counter;
  readonly status: "pending" | "expired";
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface BootstrapIntentCreateContext {
  readonly principal: AccountsAuthenticatedPrincipal;
  readonly capsule: AuthCapsule;
  readonly idempotencyKey: string;
  readonly reasonCode: string;
  readonly requestDigest: string;
  readonly now: string;
}

/**
 * A store can only create or read inert intent metadata. It intentionally has
 * no consume, provider-login, device-code, browser, or reauthentication method.
 */
export interface BootstrapIntentStore {
  create(context: BootstrapIntentCreateContext): Promise<BootstrapIntent>;
  get(authCapsuleId: AuthCapsuleId, intentId: string): Promise<BootstrapIntent | undefined>;
}

export interface CredentialOperationRequest {
  readonly kind: "rotation" | "revocation";
  readonly binding: Extract<
    CredentialBinding,
    { readonly status: "pending" | "active" | "retiring" }
  >;
  readonly expectedRevision: Counter;
  readonly principal: AccountsAuthenticatedPrincipal;
  readonly idempotencyKey: string;
  readonly reasonCode: string;
  readonly requestDigest: string;
}

/** Public operations are intent/status only; execution is deliberately absent. */
export interface CredentialOperationIntentService {
  request(request: CredentialOperationRequest): Promise<CredentialOperation>;
  get(id: CredentialOperationId): Promise<CredentialOperation | undefined>;
  list(ownerRef: string): Promise<readonly CredentialOperation[]>;
}

export interface StoredHttpResponse {
  readonly status: number;
  readonly body: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface HttpIdempotencyRequest {
  readonly actorRef: string;
  readonly audience: string;
  readonly method: string;
  readonly route: string;
  readonly key: string;
  readonly requestDigest: string;
}

/** Production deployments must back this with the same durable authority as the API. */
export interface HttpIdempotencyStore {
  execute(
    request: HttpIdempotencyRequest,
    operation: () => Promise<StoredHttpResponse>,
  ): Promise<StoredHttpResponse>;
}

export interface InternalHttpService {
  /** Returns a verified, signed snake_case wire object or fails closed. */
  issueSlotEligibility?(
    body: unknown,
    principal: AccountsAuthenticatedPrincipal,
  ): Promise<Readonly<Record<string, unknown>>>;
  /** Returns a verified, signed closed online-generation receipt or fails closed. */
  checkGeneration?(
    body: unknown,
    principal: AccountsAuthenticatedPrincipal,
  ): Promise<Readonly<Record<string, unknown>>>;
  ingestCapacityPoolEvidence?(
    body: unknown,
    principal: AccountsAuthenticatedPrincipal,
  ): Promise<Readonly<Record<string, unknown>>>;
  ingestExecutionPolicyEvidence?(
    body: unknown,
    principal: AccountsAuthenticatedPrincipal,
  ): Promise<Readonly<Record<string, unknown>>>;
  ingestCredentialBindingReceipt?(
    body: unknown,
    principal: AccountsAuthenticatedPrincipal,
  ): Promise<Readonly<Record<string, unknown>>>;
}

export interface AccountsHttpDeploymentConfig {
  readonly mode: "self_hosted";
  readonly identityRealm: string;
  readonly organizationRef: string;
  readonly publicAudience: string;
  readonly internalAudience: string;
  readonly allowedIssuers: ReadonlySet<string>;
}

export interface AccountsHttpHandlerOptions {
  readonly deployment: AccountsHttpDeploymentConfig;
  readonly authenticator: AccountsRequestAuthenticator;
  readonly catalog: CatalogHttpService;
  readonly bootstrapIntents?: BootstrapIntentStore;
  readonly credentialOperations?: CredentialOperationIntentService;
  readonly internal?: InternalHttpService;
  readonly idempotency?: HttpIdempotencyStore;
  readonly packageVersion: string;
  readonly contractSha256: string;
  readonly openApiDocument: Readonly<Record<string, unknown>>;
  readonly now?: () => Date;
}

export const HTTP_ENTITY_ROUTES = Object.freeze({
  "provider-accounts": "account",
  entitlements: "entitlement",
  "capacity-pools": "capacity_pool",
  "account-lanes": "access_method",
  "auth-capsules": "auth_capsule",
  "credential-bindings": "credential_binding",
} as const satisfies Readonly<Record<string, EntityKind>>);

export type HttpEntityRoute = keyof typeof HTTP_ENTITY_ROUTES;

export type AnyEntityIdentifier = EntityId;
