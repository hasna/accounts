// Request/response schemas for the accounts cloud API.
//
// Reuses the core library's validators (profileNameSchema, tool slug rules,
// metadata primitive rules) so the cloud surface enforces the SAME domain
// constraints as the local CLI/MCP — this is the "wrap the core lib" contract.

import { z } from "zod";
import { profileNameSchema } from "../types.js";

/** Tool id: same slug grammar as the core (lowercase alnum/hyphen). */
export const toolIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, "tool must be lowercase alphanumeric/hyphen");

const metadataKeyPattern = /^[A-Za-z0-9_.:-]{1,64}$/;
const reservedMetadataKeys = new Set(["__proto__", "prototype", "constructor"]);
const metadataValueSchema = z.union([
  z.string(),
  z.number().refine(Number.isFinite, "metadata numbers must be finite"),
  z.boolean(),
  z.null(),
]);

/** Same metadata rules as the core (plain object, safe keys, primitive values). */
export const metadataSchema = z
  .record(metadataValueSchema)
  .superRefine((value, ctx) => {
    for (const key of Object.keys(value)) {
      if (!metadataKeyPattern.test(key)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `invalid metadata key "${key}"` });
      }
      if (reservedMetadataKeys.has(key)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `reserved metadata key "${key}"` });
      }
    }
  });

const optionalNonBlank = (label: string) =>
  z.string().refine((v) => v.trim().length > 0, `${label} must not be empty`);
const profileDirSchema = z
  .string()
  .min(1)
  .refine((value) => !value.includes("\0") && !/[\r\n]/.test(value), "dir contains invalid characters");

export const createAccountSchema = z.object({
  name: profileNameSchema,
  tool: toolIdSchema,
  email: z.string().email().optional(),
  displayName: optionalNonBlank("display name").optional(),
  identity: optionalNonBlank("identity").optional(),
  cardLast4: z.string().regex(/^\d{4}$/, "cardLast4 must be exactly 4 digits").optional(),
  metadata: metadataSchema.optional(),
  dir: profileDirSchema.optional(),
  description: z.string().optional(),
});
export type CreateAccountInput = z.infer<typeof createAccountSchema>;

export const createLoginAccountSchema = createAccountSchema.extend({
  expectedIncarnationId: z.string().uuid(),
}).strict();
export type CreateLoginAccountInput = z.infer<typeof createLoginAccountSchema>;

export const updateAccountSchema = z
  .object({
    email: z.string().email().nullable().optional(),
    displayName: optionalNonBlank("display name").nullable().optional(),
    identity: optionalNonBlank("identity").nullable().optional(),
    cardLast4: z.string().regex(/^\d{4}$/, "cardLast4 must be exactly 4 digits").nullable().optional(),
    metadata: metadataSchema.optional(),
    dir: profileDirSchema.nullable().optional(),
    description: z.string().nullable().optional(),
    lastUsedAt: z.string().datetime().nullable().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, "update requires at least one field");
export type UpdateAccountInput = z.infer<typeof updateAccountSchema>;

export const restoreAccountSchema = z
  .object({
    expectedIncarnationId: z.string().uuid(),
    email: z.object({
      expected: z.string().email().nullable(),
      restore: z.string().email().nullable(),
    }).optional(),
    lastUsedAt: z.object({
      expected: z.string().datetime().nullable(),
      restore: z.string().datetime().nullable(),
    }).optional(),
  })
  .refine((value) => value.email !== undefined || value.lastUsedAt !== undefined, "restore requires at least one field");
export type RestoreAccountInput = z.infer<typeof restoreAccountSchema>;

export const loginUpdateAccountSchema = z.object({
  expectedIncarnationId: z.string().uuid(),
  expectedEmail: z.string().email().nullable(),
  email: z.string().email(),
}).strict();
export type LoginUpdateAccountInput = z.infer<typeof loginUpdateAccountSchema>;

const removeCreatedAccountFields = {
  expectedIncarnationId: z.string().uuid(),
  expectedCreatedAt: z.string().datetime(),
  expectedEmail: z.string().email().nullable(),
  expectedDisplayName: z.string().nullable(),
  expectedIdentity: z.string().nullable(),
  expectedCardLast4: z.string().regex(/^\d{4}$/).nullable(),
  expectedMetadata: metadataSchema,
  expectedDir: profileDirSchema.nullable(),
  expectedDescription: z.string().nullable(),
  expectedLastUsedAt: z.string().datetime().nullable(),
};

/** Response-loss-safe cleanup request used only on the new-only operation route. */
export const removeCreatedAccountSchema = z.object({
  cleanupOperationId: z.string().uuid(),
  cleanupRequestedAt: z.string().datetime(),
  ...removeCreatedAccountFields,
}).strict();
export type RemoveCreatedAccountInput = z.infer<typeof removeCreatedAccountSchema>;

export const setCurrentSchema = z.object({ name: profileNameSchema });
export const setLoginCurrentSchema = z.object({
  name: profileNameSchema,
  operationId: z.string().uuid(),
  expectedIncarnationId: z.string().uuid(),
}).strict();

const postgresRevisionSchema = z
  .string()
  .regex(/^\d+$/, "expectedRevision must be a decimal generation")
  .refine((value) => {
    const normalized = value.replace(/^0+(?=\d)/, "");
    return normalized.length < 19 || (
      normalized.length === 19 && normalized <= "9223372036854775807"
    );
  }, "expectedRevision must fit a PostgreSQL bigint");

export const restoreCurrentSchema = z.object({
  expectedName: profileNameSchema,
  name: profileNameSchema.optional(),
}).strict();

export const restoreLoginCurrentSchema = z.object({
  expectedName: profileNameSchema,
  expectedRevision: postgresRevisionSchema.optional(),
  expectedOperationId: z.string().uuid().optional(),
  name: profileNameSchema.optional(),
  restoreLastUsedAt: z.string().datetime().nullable().optional(),
}).strict();

export const renameAccountSchema = z.object({ name: profileNameSchema });
export type RenameAccountInput = z.infer<typeof renameAccountSchema>;
