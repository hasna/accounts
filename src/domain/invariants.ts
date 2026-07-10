import { AccountsError } from "../errors";
import type { AccountsRepository } from "../storage/repository";
import type { EntityKind, EntityMap } from "./models";

const INITIAL_STATUS: Readonly<Record<EntityKind, string>> = {
  account: "pending",
  entitlement: "pending",
  capacity_pool: "pending",
  access_method: "draft",
  auth_capsule: "unprovisioned",
  credential_binding: "pending",
};

export function assertInitialRecord<K extends EntityKind>(kind: K, record: EntityMap[K]): void {
  if (
    record.revision !== "0" ||
    record.status !== INITIAL_STATUS[kind] ||
    record.createdAt !== record.updatedAt
  ) {
    throw new AccountsError("VALIDATION_FAILED", "New records must begin in their initial lifecycle state", {
      details: { aggregateKind: kind },
    });
  }
}

export async function assertInsertInvariants<K extends EntityKind>(
  repository: AccountsRepository,
  kind: K,
  record: EntityMap[K],
): Promise<void> {
  assertInitialRecord(kind, record);
  switch (kind) {
    case "account": {
      const item = record as EntityMap["account"];
      if (item.status !== "pending" && item.providerSubjectRef !== undefined) {
        const accounts = await repository.list("account");
        if (
          accounts.some(
            (candidate) =>
              candidate.status !== "pending" &&
              candidate.providerKey === item.providerKey &&
              candidate.providerSubjectRef === item.providerSubjectRef,
          )
        ) {
          throw new AccountsError("CONFLICT", "Provider subject already exists");
        }
      }
      return;
    }
    case "entitlement": {
      const item = record as EntityMap["entitlement"];
      const account = await repository.get("account", item.accountId);
      if (account === undefined) throw parentMissing("account", item.accountId);
      if (item.fundingKind === "subscription" && !account.ownerRef.startsWith("principal:human:hasna:")) {
        throw new AccountsError("POLICY_DENIED", "Subscription entitlement requires a human owner");
      }
      return;
    }
    case "capacity_pool": {
      const item = record as EntityMap["capacity_pool"];
      const account = await repository.get("account", item.accountId);
      if (account === undefined) {
        throw parentMissing("account", item.accountId);
      }
      const pools = await repository.list("capacity_pool");
      for (const candidate of pools) {
        if (candidate.serializationKey === item.serializationKey) {
          throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Serialization key already exists");
        }
        if (candidate.capacityDomainRef === item.capacityDomainRef) {
          const candidateAccount = await repository.get("account", candidate.accountId);
          if (candidateAccount?.providerKey === account.providerKey) {
            throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Capacity domain already exists");
          }
        }
      }
      if (item.denyState !== "denied") {
        throw new AccountsError("CURRENT_DENY", "Pending capacity must remain denied");
      }
      return;
    }
    case "access_method": {
      const item = record as EntityMap["access_method"];
      const entitlement = await repository.get("entitlement", item.entitlementId);
      const pool = await repository.get("capacity_pool", item.capacityPoolId);
      if (entitlement === undefined) throw parentMissing("entitlement", item.entitlementId);
      if (pool === undefined) throw parentMissing("capacity_pool", item.capacityPoolId);
      if (pool.accountId !== entitlement.accountId) {
        throw new AccountsError("INVALID_ACCESS_TARGET", "Access method parents have different accounts");
      }
      if (item.accessTransport === "native_session" && pool.maxConcurrency !== "1") {
        throw new AccountsError("POLICY_DENIED", "Native session capacity must have concurrency one");
      }
      return;
    }
    case "auth_capsule": {
      const item = record as EntityMap["auth_capsule"];
      const method = await repository.get("access_method", item.accessMethodId);
      const pool = await repository.get("capacity_pool", item.capacityPoolId);
      if (method === undefined) throw parentMissing("access_method", item.accessMethodId);
      if (pool === undefined) throw parentMissing("capacity_pool", item.capacityPoolId);
      const entitlement = await repository.get("entitlement", method.entitlementId);
      if (entitlement === undefined) throw parentMissing("entitlement", method.entitlementId);
      const account = await repository.get("account", entitlement.accountId);
      if (account === undefined) throw parentMissing("account", entitlement.accountId);
      if (
        method.accessTransport !== "native_session" ||
        method.capacityPoolId !== pool.id ||
        item.ownerRef !== account.ownerRef
      ) {
        throw new AccountsError("INVALID_ACCESS_TARGET", "Authentication capsule lineage is invalid");
      }
      const capsules = await repository.list("auth_capsule");
      if (capsules.some((candidate) => candidate.capacityPoolId === pool.id && candidate.status !== "revoked")) {
        throw new AccountsError("CONFLICT", "A live native capsule already exists for this capacity pool");
      }
      return;
    }
    case "credential_binding": {
      const item = record as EntityMap["credential_binding"];
      const method = await repository.get("access_method", item.accessMethodId);
      const pool = await repository.get("capacity_pool", item.capacityPoolId);
      if (method === undefined) throw parentMissing("access_method", item.accessMethodId);
      if (pool === undefined) throw parentMissing("capacity_pool", item.capacityPoolId);
      if (method.capacityPoolId !== pool.id) {
        throw new AccountsError("INVALID_ACCESS_TARGET", "Credential binding pool does not match access method");
      }
      const expectedResolver =
        method.accessTransport === "native_session"
          ? "capsule_local_native"
          : method.accessTransport === "api_key"
            ? "brokered_secret"
            : "workload_identity";
      if (item.resolver !== expectedResolver) {
        throw new AccountsError("INVALID_ACCESS_TARGET", "Credential resolver does not match access transport");
      }
      if (item.resolver === "capsule_local_native") {
        const capsule = await repository.get("auth_capsule", item.authCapsuleId!);
        if (
          capsule === undefined ||
          capsule.accessMethodId !== method.id ||
          capsule.capacityPoolId !== pool.id ||
          capsule.authGeneration !== item.credentialGeneration ||
          capsule.authStateRevision !== item.authStateRevision
        ) {
          throw new AccountsError("INVALID_ACCESS_TARGET", "Native credential binding does not match capsule");
        }
      }
      const bindings = await repository.list("credential_binding");
      if (
        bindings.some(
          (candidate) =>
            candidate.credentialFamilyId === item.credentialFamilyId &&
            (candidate.capacityPoolId !== item.capacityPoolId ||
              candidate.purpose !== item.purpose ||
              candidate.resolver !== item.resolver),
        )
      ) {
        throw new AccountsError("CAPACITY_DOMAIN_CONFLICT", "Credential family belongs to another pool");
      }
    }
  }
}

function parentMissing(kind: EntityKind, id: string): AccountsError {
  return new AccountsError("NOT_FOUND", "Required parent record was not found", {
    details: { aggregateKind: kind, aggregateId: id },
  });
}
