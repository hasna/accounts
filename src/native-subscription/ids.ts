import { randomBytes } from "node:crypto";

import { AccountsError } from "./errors.js";

declare const brand: unique symbol;
export type Brand<T, Name extends string> = T & { readonly [brand]: Name };

export type AccountId = Brand<string, "AccountId">;
export type ProviderAccountId = AccountId;
export type EntitlementId = Brand<string, "EntitlementId">;
export type CapacityPoolId = Brand<string, "CapacityPoolId">;
export type AccessMethodId = Brand<string, "AccessMethodId">;
export type AccountLaneId = AccessMethodId;
export type AuthCapsuleId = Brand<string, "AuthCapsuleId">;
export type CanonicalNodeId = Brand<string, "CanonicalNodeId">;
export type CredentialBindingId = Brand<string, "CredentialBindingId">;
export type CredentialOperationId = Brand<string, "CredentialOperationId">;
export type EligibilityEvidenceId = Brand<string, "EligibilityEvidenceId">;
export type AccountEventId = Brand<string, "AccountEventId">;
export type OutboxId = Brand<string, "OutboxId">;

export type EntityId =
  | AccountId
  | EntitlementId
  | CapacityPoolId
  | AccessMethodId
  | AuthCapsuleId
  | CredentialBindingId;

export type IdKind =
  | "account"
  | "entitlement"
  | "capacity_pool"
  | "access_method"
  | "auth_capsule"
  | "canonical_node"
  | "credential_binding"
  | "credential_operation"
  | "eligibility_evidence"
  | "account_event"
  | "outbox";

const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isUuidV7(value: string): boolean {
  return UUID_V7.test(value);
}

function parseId<T extends string>(kind: IdKind, value: unknown): Brand<string, T> {
  if (typeof value !== "string" || !isUuidV7(value)) {
    throw new AccountsError("VALIDATION_FAILED", `Invalid ${kind} identifier`, {
      details: { field: `${kind}Id` },
    });
  }
  return value as Brand<string, T>;
}

export function generateUuidV7(nowMs = Date.now()): string {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 0xffffffffffff) {
    throw new AccountsError("VALIDATION_FAILED", "Invalid UUIDv7 timestamp", {
      details: { field: "nowMs" },
    });
  }
  const bytes = randomBytes(16);
  let timestamp = BigInt(nowMs);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function newId<T extends string>(kind: IdKind, nowMs = Date.now()): Brand<string, T> {
  return parseId<T>(kind, generateUuidV7(nowMs));
}

export const parseAccountId = (value: unknown): AccountId =>
  parseId<"AccountId">("account", value);
export const parseProviderAccountId = parseAccountId;
export const parseEntitlementId = (value: unknown): EntitlementId =>
  parseId<"EntitlementId">("entitlement", value);
export const parseCapacityPoolId = (value: unknown): CapacityPoolId =>
  parseId<"CapacityPoolId">("capacity_pool", value);
export const parseAccessMethodId = (value: unknown): AccessMethodId =>
  parseId<"AccessMethodId">("access_method", value);
export const parseAccountLaneId = parseAccessMethodId;
export const parseAuthCapsuleId = (value: unknown): AuthCapsuleId =>
  parseId<"AuthCapsuleId">("auth_capsule", value);
export const parseCanonicalNodeId = (value: unknown): CanonicalNodeId =>
  parseId<"CanonicalNodeId">("canonical_node", value);
export const parseCredentialBindingId = (value: unknown): CredentialBindingId =>
  parseId<"CredentialBindingId">("credential_binding", value);
export const parseCredentialOperationId = (value: unknown): CredentialOperationId =>
  parseId<"CredentialOperationId">("credential_operation", value);
export const parseEligibilityEvidenceId = (value: unknown): EligibilityEvidenceId =>
  parseId<"EligibilityEvidenceId">("eligibility_evidence", value);
export const parseAccountEventId = (value: unknown): AccountEventId =>
  parseId<"AccountEventId">("account_event", value);
export const parseOutboxId = (value: unknown): OutboxId =>
  parseId<"OutboxId">("outbox", value);

export const newAccountId = (nowMs?: number): AccountId =>
  newId<"AccountId">("account", nowMs);
export const newProviderAccountId = newAccountId;
export const newEntitlementId = (nowMs?: number): EntitlementId =>
  newId<"EntitlementId">("entitlement", nowMs);
export const newCapacityPoolId = (nowMs?: number): CapacityPoolId =>
  newId<"CapacityPoolId">("capacity_pool", nowMs);
export const newAccessMethodId = (nowMs?: number): AccessMethodId =>
  newId<"AccessMethodId">("access_method", nowMs);
export const newAccountLaneId = newAccessMethodId;
export const newAuthCapsuleId = (nowMs?: number): AuthCapsuleId =>
  newId<"AuthCapsuleId">("auth_capsule", nowMs);
export const newCredentialBindingId = (nowMs?: number): CredentialBindingId =>
  newId<"CredentialBindingId">("credential_binding", nowMs);
export const newCredentialOperationId = (nowMs?: number): CredentialOperationId =>
  newId<"CredentialOperationId">("credential_operation", nowMs);
export const newEligibilityEvidenceId = (nowMs?: number): EligibilityEvidenceId =>
  newId<"EligibilityEvidenceId">("eligibility_evidence", nowMs);
export const newAccountEventId = (nowMs?: number): AccountEventId =>
  newId<"AccountEventId">("account_event", nowMs);
export const newOutboxId = (nowMs?: number): OutboxId =>
  newId<"OutboxId">("outbox", nowMs);
