import { z } from "zod";

/** id/name shape: lowercase letters, digits, hyphen; starts alphanumeric. */
const slugSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, "must be lowercase alphanumeric/hyphen and start with a letter or digit");

/** Profile name validator. */
export const profileNameSchema = slugSchema;

/** Validator for a (custom) tool definition stored in the registry. */
export const toolDefSchema = z.object({
  id: slugSchema,
  label: z.string().min(1).max(64),
  envVar: z.string().min(1).regex(/^[A-Z_][A-Z0-9_]*$/, "envVar must look like AN_ENV_VAR"),
  defaultDir: z.string().min(1),
  bin: z.string().min(1),
  accountFile: z.string().optional(),
  emailPath: z.array(z.string()).optional(),
});

/**
 * A supported app/tool. Each tool isolates its configuration in a directory
 * pointed at by an environment variable (e.g. Claude Code reads
 * `CLAUDE_CONFIG_DIR`). A "profile" is one such directory plus metadata.
 * Tools are either built-in or registered at runtime via `accounts tools add`.
 */
export type ToolDef = z.infer<typeof toolDefSchema>;

export const profileSchema = z.object({
  name: z.string(),
  tool: z.string(),
  email: z.string().email().optional(),
  dir: z.string(),
  description: z.string().optional(),
  createdAt: z.string(),
  lastUsedAt: z.string().optional(),
});

export type Profile = z.infer<typeof profileSchema>;

export const storeSchema = z.object({
  version: z.literal(1),
  /** Map of toolId -> active profile name. */
  current: z.record(z.string(), z.string()).default({}),
  profiles: z.array(profileSchema).default([]),
  /** User-registered tools (apps) added at runtime, on top of built-ins. */
  tools: z.array(toolDefSchema).default([]),
});

export type Store = z.infer<typeof storeSchema>;

export class AccountsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountsError";
  }
}
