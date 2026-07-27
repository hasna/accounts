import { z } from "zod";
import { profileNameSchema } from "../types.js";

const opaqueId = (label: string) =>
  z
    .string()
    .min(16, `${label} must be opaque`)
    .max(128)
    .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, `${label} must be an opaque identifier`);

export const tenantIdSchema = opaqueId("tenant id").brand<"TenantId">();
export const scopeIdSchema = opaqueId("scope id").brand<"ScopeId">();
export const accountIdSchema = opaqueId("account id").brand<"AccountId">();
export const runtimeIdSchema = opaqueId("runtime id").brand<"RuntimeId">();
export const bindingIdSchema = opaqueId("binding id").brand<"BindingId">();
export const machineIdSchema = opaqueId("machine id").brand<"MachineId">();

export type TenantId = z.infer<typeof tenantIdSchema>;
export type ScopeId = z.infer<typeof scopeIdSchema>;
export type AccountId = z.infer<typeof accountIdSchema>;
export type RuntimeId = z.infer<typeof runtimeIdSchema>;
export type BindingId = z.infer<typeof bindingIdSchema>;
export type MachineId = z.infer<typeof machineIdSchema>;

export const registryScopeSchema = z
  .object({
    tenantId: tenantIdSchema,
    scopeId: scopeIdSchema,
  })
  .strict();

export type RegistryScope = Readonly<z.infer<typeof registryScopeSchema>>;
export type ScopeRef = RegistryScope;

const timestampSchema = z.string().datetime();
export const renameAccountInputSchema = z
  .object({
    name: profileNameSchema,
    updatedAt: timestampSchema,
  })
  .strict();

/**
 * Cloud-safe account identity. Authentication, machine paths and selection
 * pointers cannot be represented by this schema.
 */
export const accountSchema = z
  .object({
    id: accountIdSchema,
    tenantId: tenantIdSchema,
    scopeId: scopeIdSchema,
    name: profileNameSchema,
    runtimeId: runtimeIdSchema,
    email: z.string().email().optional(),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export type Account = Readonly<z.infer<typeof accountSchema>>;

/** Package-known executable integration, scoped exactly like accounts. */
export const runtimeSchema = z
  .object({
    id: runtimeIdSchema,
    tenantId: tenantIdSchema,
    scopeId: scopeIdSchema,
    key: profileNameSchema,
    label: z.string().min(1).max(128),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export type Runtime = Readonly<z.infer<typeof runtimeSchema>>;

/**
 * Strict wire schemas reject local-only fields from HTTP/Postgres boundaries.
 * Serializers deliberately strip unknown local overlay fields from trusted
 * in-process composites.
 */
export const accountV2DtoSchema = accountSchema;
export const runtimeV2DtoSchema = runtimeSchema;
export const accountV2ListSchema = z.object({ accounts: z.array(accountV2DtoSchema) }).strict();
export const runtimeV2ListSchema = z.object({ runtimes: z.array(runtimeV2DtoSchema) }).strict();

export type AccountV2Dto = Account;
export type RuntimeV2Dto = Runtime;
export type RenameAccountInput = Readonly<z.infer<typeof renameAccountInputSchema>>;

export function toAccountV2Dto(value: Account & object): AccountV2Dto {
  return accountSchema.strip().parse(value);
}

export function toRuntimeV2Dto(value: Runtime & object): RuntimeV2Dto {
  return runtimeSchema.strip().parse(value);
}

export function assertEntityScope(
  expected: RegistryScope,
  value: Pick<Account | Runtime, "tenantId" | "scopeId">,
): void {
  const scope = registryScopeSchema.parse(expected);
  if (value.tenantId !== scope.tenantId || value.scopeId !== scope.scopeId) {
    throw new RegistryScopeError("registry entity does not belong to the requested tenant and scope");
  }
}

export function parseAccountRename(
  current: Account,
  nameInput: string,
  updatedAtInput: string,
): RenameAccountInput {
  const rename = parseAccountRenameInput(nameInput, updatedAtInput);
  assertAccountRenameRequest(current, rename);
  return rename;
}

export function parseAccountRenameInput(
  nameInput: string,
  updatedAtInput: string,
): RenameAccountInput {
  return renameAccountInputSchema.parse({
    name: nameInput,
    updatedAt: updatedAtInput,
  });
}

export function assertAccountRenameRequest(
  current: Account,
  rename: RenameAccountInput,
): void {
  if (rename.name === current.name) {
    throw new RegistryConflictError(
      "requested account name must be different from the current name",
    );
  }
  if (!timestampAdvances(current.updatedAt, rename.updatedAt)) {
    throw new RegistryConflictError(
      "requested updatedAt must advance the current account timestamp",
    );
  }
}

export function assertAccountRenameTransition(
  current: Account,
  requested: RenameAccountInput,
  actual: Account,
): void {
  assertSameAccountIdentity(current, actual);
  if (actual.name !== requested.name) {
    throw new RegistryConflictError(
      "v2 registry rename response did not apply the requested name",
    );
  }
  if (!timestampAdvances(current.updatedAt, actual.updatedAt)) {
    throw new RegistryConflictError(
      "v2 registry rename response did not advance updatedAt",
    );
  }
  if (!sameTimestamp(actual.updatedAt, requested.updatedAt)) {
    throw new RegistryConflictError(
      "v2 registry rename response did not apply the requested timestamp",
    );
  }
}

export function assertSameAccountIdentity(expected: Account, actual: Account): void {
  if (
    actual.id !== expected.id ||
    actual.tenantId !== expected.tenantId ||
    actual.scopeId !== expected.scopeId ||
    actual.runtimeId !== expected.runtimeId ||
    !sameTimestamp(actual.createdAt, expected.createdAt)
  ) {
    throw new RegistryConflictError(
      "v2 registry returned different immutable account identity fields",
    );
  }
}

export function assertSameRuntimeIdentity(expected: Runtime, actual: Runtime): void {
  if (
    actual.id !== expected.id ||
    actual.tenantId !== expected.tenantId ||
    actual.scopeId !== expected.scopeId ||
    !sameTimestamp(actual.createdAt, expected.createdAt)
  ) {
    throw new RegistryConflictError(
      "v2 registry returned different immutable runtime identity fields",
    );
  }
}

export function assertAccountLookupIdentity(expectedId: AccountId, actual: Account): void {
  if (actual.id !== expectedId) {
    throw new RegistryConflictError(
      "v2 registry returned a different account identity for lookup",
    );
  }
}

export function assertRuntimeLookupIdentity(expectedId: RuntimeId, actual: Runtime): void {
  if (actual.id !== expectedId) {
    throw new RegistryConflictError(
      "v2 registry returned a different runtime identity for lookup",
    );
  }
}

function timestampAdvances(current: string, next: string): boolean {
  return Date.parse(next) > Date.parse(current);
}

function sameTimestamp(first: string, second: string): boolean {
  return Date.parse(first) === Date.parse(second);
}

export class RegistryScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryScopeError";
  }
}

export class RegistryConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryConflictError";
  }
}

export class RegistryNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryNotFoundError";
  }
}
