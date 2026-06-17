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
  extraEnv: z.record(z.string()).optional(),
  defaultDir: z.string().min(1),
  bin: z.string().min(1),
  loginArgs: z.array(z.string()).optional(),
  loginHint: z.string().optional(),
  resumeArgs: z.array(z.string()).optional(),
  /** Tool-specific permission presets exposed through `--permissions <preset>`. */
  permissionArgs: z.record(z.array(z.string())).optional(),
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
  /** Map of toolId -> active profile name (for env/launch/shell). */
  current: z.record(z.string(), z.string()).default({}),
  /**
   * Map of toolId -> profile name last applied to the tool's live default paths
   * (e.g. ~/.claude + ~/.claude.json on disk for IDE use).
   */
  applied: z.record(z.string(), z.string()).default({}),
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
