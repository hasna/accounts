import { z } from "zod";
import { metadataSchema, profileNameSchema } from "../types.js";

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
    metadata: metadataSchema.optional(),
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
