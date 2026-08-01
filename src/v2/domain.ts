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

const CANONICAL_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Canonical v2 timestamp representation.
 *
 * PostgreSQL and JavaScript Date values preserve milliseconds, not arbitrary
 * fractional precision. Requiring the exact UTC millisecond form prevents
 * normalization from silently changing authorization and concurrency values.
 */
export const timestampSchema = z
  .string()
  .regex(
    CANONICAL_TIMESTAMP_PATTERN,
    "timestamp must use canonical RFC3339 UTC with exact millisecond precision",
  )
  .refine(
    (value) => {
      const parsed = new Date(value);
      return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
    },
    "timestamp must be a valid canonical RFC3339 UTC millisecond instant",
  );

export const renameAccountInputSchema = z
  .object({
    name: profileNameSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const renameAccountRequestSchema = renameAccountInputSchema
  .extend({
    expectedUpdatedAt: timestampSchema,
  })
  .strict();

/**
 * Cloud-safe account identity. Authentication, machine paths and selection
 * pointers cannot be represented by this schema.
 */
const accountShape = {
  id: accountIdSchema,
  tenantId: tenantIdSchema,
  scopeId: scopeIdSchema,
  name: profileNameSchema,
  runtimeId: runtimeIdSchema,
  email: z.string().email().optional(),
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
} as const;

export const accountSchema = z
  .object(accountShape)
  .strict()
  .superRefine(assertChronologicalEntity);
const accountSerializerSchema = z
  .object(accountShape)
  .strip()
  .superRefine(assertChronologicalEntity);

export type Account = Readonly<z.infer<typeof accountSchema>>;

/** Package-known executable integration, scoped exactly like accounts. */
const runtimeShape = {
  id: runtimeIdSchema,
  tenantId: tenantIdSchema,
  scopeId: scopeIdSchema,
  key: profileNameSchema,
  label: z.string().min(1).max(128),
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
} as const;

export const runtimeSchema = z
  .object(runtimeShape)
  .strict()
  .superRefine(assertChronologicalEntity);
const runtimeSerializerSchema = z
  .object(runtimeShape)
  .strip()
  .superRefine(assertChronologicalEntity);

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
export type RenameAccountRequest = Readonly<z.infer<typeof renameAccountRequestSchema>>;

export function toAccountV2Dto(value: Account & object): AccountV2Dto {
  return accountSerializerSchema.parse(value);
}

export function toRuntimeV2Dto(value: Runtime & object): RuntimeV2Dto {
  return runtimeSerializerSchema.parse(value);
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

export function toAccountRenameRequest(
  current: Account,
  rename: RenameAccountInput,
): RenameAccountRequest {
  return renameAccountRequestSchema.parse({
    ...rename,
    expectedUpdatedAt: current.updatedAt,
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
  if (actual.email !== current.email) {
    throw new RegistryConflictError(
      "v2 registry rename response changed a non-target account field",
    );
  }
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
  if (actual.updatedAt !== requested.updatedAt) {
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
    actual.createdAt !== expected.createdAt
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
    actual.createdAt !== expected.createdAt
  ) {
    throw new RegistryConflictError(
      "v2 registry returned different immutable runtime identity fields",
    );
  }
}

export function assertAccountCreationTransition(expected: Account, actual: Account): void {
  assertSameAccountIdentity(expected, actual);
  if (
    actual.name !== expected.name ||
    actual.email !== expected.email ||
    actual.updatedAt !== expected.updatedAt
  ) {
    throw new RegistryConflictError(
      "v2 registry account creation response changed requested identity or fields",
    );
  }
}

export function assertRuntimeRegistrationTransition(
  expected: Runtime,
  actual: Runtime,
): void {
  assertSameRuntimeIdentity(expected, actual);
  if (
    actual.key !== expected.key ||
    actual.label !== expected.label ||
    actual.updatedAt !== expected.updatedAt
  ) {
    throw new RegistryConflictError(
      "v2 registry runtime registration response changed requested identity or fields",
    );
  }
}

export function assertUniqueAccountIds(values: readonly Account[]): void {
  assertUniqueEntityIds("account", values);
}

export function assertUniqueRuntimeIds(values: readonly Runtime[]): void {
  assertUniqueEntityIds("runtime", values);
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
  return next > current;
}

function assertChronologicalEntity(
  value: { createdAt: string; updatedAt: string },
  context: z.RefinementCtx,
): void {
  if (value.updatedAt < value.createdAt) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["updatedAt"],
      message: "updatedAt must not precede createdAt",
    });
  }
}

function assertUniqueEntityIds(
  kind: "account" | "runtime",
  values: readonly { id: string }[],
): void {
  const ids = new Set<string>();
  for (const value of values) {
    if (ids.has(value.id)) {
      throw new RegistryConflictError(
        `v2 registry ${kind} list contains duplicate scoped id "${value.id}"`,
      );
    }
    ids.add(value.id);
  }
}

export class RegistryScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryScopeError";
  }
}

export class RegistryConflictError extends Error {
  constructor(message: string, readonly status?: number) {
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
