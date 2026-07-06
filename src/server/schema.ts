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

export const createAccountSchema = z.object({
  name: profileNameSchema,
  tool: toolIdSchema,
  email: z.string().email().optional(),
  displayName: optionalNonBlank("display name").optional(),
  identity: optionalNonBlank("identity").optional(),
  cardLast4: z.string().regex(/^\d{4}$/, "cardLast4 must be exactly 4 digits").optional(),
  metadata: metadataSchema.optional(),
  dir: z.string().min(1).optional(),
  description: z.string().optional(),
});
export type CreateAccountInput = z.infer<typeof createAccountSchema>;

export const updateAccountSchema = z
  .object({
    email: z.string().email().nullable().optional(),
    displayName: optionalNonBlank("display name").nullable().optional(),
    identity: optionalNonBlank("identity").nullable().optional(),
    cardLast4: z.string().regex(/^\d{4}$/, "cardLast4 must be exactly 4 digits").nullable().optional(),
    metadata: metadataSchema.optional(),
    dir: z.string().min(1).nullable().optional(),
    description: z.string().nullable().optional(),
    lastUsedAt: z.string().datetime().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, "update requires at least one field");
export type UpdateAccountInput = z.infer<typeof updateAccountSchema>;

export const setCurrentSchema = z.object({ name: profileNameSchema });
