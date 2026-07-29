import { z } from "zod";

/** id/name shape: lowercase letters, digits, hyphen; starts alphanumeric. */
const slugSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9][a-z0-9-]*$/, "must be lowercase alphanumeric/hyphen and start with a letter or digit");

/** Profile name validator. */
export const profileNameSchema = slugSchema;

const reservedJsonKeys = new Set(["__proto__", "prototype", "constructor"]);

/**
 * Credential artifacts. A tool definition may arrive from the registry via
 * `store.resolveTool()`, so "we would never write that" is not a control —
 * sharing these is refused at the schema, before any filesystem work.
 */
const credentialArtifactNames = new Set([
  ".credentials.json",
  "credentials.json",
  ".credentials",
  ".accounts-auth",
  "auth.json",
  "keychain.json",
  "oauth-account.json",
  "token.json",
  "tokens.json",
]);

/** JSON keys that carry account identity or secrets and must never be copied. */
const credentialConfigKeys = new Set([
  "oauthAccount",
  "claudeAiOauth",
  "customApiKeyResponses",
  "apiKeyHelper",
  "primaryApiKey",
  "credentials",
  "userID",
  "machineID",
]);

/**
 * NUL and friends are silently swallowed by path APIs (a NUL-bearing entry just
 * fails `existsSync` and degrades to a no-op), so they are rejected outright.
 * Written as a code-point check rather than a regex literal so this source file
 * itself stays free of control characters.
 */
const noControlCharacters = (value: string): boolean =>
  ![...value].some((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });

/** A single path segment under a tool's home — never a nested or escaping path. */
const pathSegmentSchema = z
  .string()
  .min(1)
  .max(64)
  .refine(noControlCharacters, "must not contain control characters")
  .refine((v) => !/[\\/]/.test(v) && v !== "." && v !== "..", "must be a single path segment")
  .refine((v) => !reservedJsonKeys.has(v), "must not be a reserved name")
  .refine((v) => !credentialArtifactNames.has(v.toLowerCase()), "must not be a credential artifact");

/** A top-level JSON key shared between the tool's home and a profile. */
const sharedConfigKeySchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z_][A-Za-z0-9_-]*$/, "must look like a JSON config key")
  .refine((v) => !reservedJsonKeys.has(v), "must not be a reserved key")
  .refine((v) => !credentialConfigKeys.has(v), "must not be a credential key");

/** A member name inside a shared config key, e.g. one MCP server name. */
const sharedConfigMemberSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(noControlCharacters, "must not contain control characters")
  .refine((v) => !reservedJsonKeys.has(v), "must not be a reserved name");

/**
 * A shared-home-relative JSON file. At most one leading `..` is allowed, so a
 * tool may read the sibling account file (`~/.claude.json` next to `~/.claude`)
 * without being able to walk anywhere else on the machine.
 */
const sharedConfigSourceSchema = z
  .string()
  .min(1)
  .max(255)
  .refine(noControlCharacters, "must not contain control characters")
  .refine((v) => !/^([\\/]|[A-Za-z]:)/.test(v), "must be relative to the tool's shared home")
  .refine((v) => {
    const parts = v.split(/[\\/]/).filter(Boolean);
    if (parts.length === 0) return false;
    if (parts.includes(".")) return false;
    return parts.every((part, index) => part !== ".." || index === 0);
  }, "may only ascend one level above the tool's shared home");

const portableEnvNameSchema = z
  .string()
  .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "must be a portable environment variable name");

/** Validator for a (custom) tool definition stored in the registry. */
export const toolDefSchema = z.object({
  id: slugSchema,
  label: z.string().min(1).max(64),
  envVar: z.string().min(1).regex(/^[A-Z_][A-Z0-9_]*$/, "envVar must look like AN_ENV_VAR"),
  extraEnv: z.record(portableEnvNameSchema, z.string()).optional(),
  defaultDir: z.string().min(1),
  bin: z.string().min(1),
  loginArgs: z.array(z.string()).optional(),
  loginHint: z.string().optional(),
  resumeArgs: z.array(z.string()).optional(),
  /** Tool-specific permission presets exposed through `--permissions <preset>`. */
  permissionArgs: z.record(z.array(z.string())).optional(),
  /** Tool args prepended for launch/login/run; supports {profileDir}, {profileName}, {toolId}. */
  launchArgs: z.array(z.string()).optional(),
  accountFile: z.string().optional(),
  emailPath: z.array(z.string()).optional(),
  /**
   * Capability directories (skills, subagents, …) that belong to the human, not
   * to the account: linked from the tool's shared home into every profile so one
   * corpus serves all of them. Credentials are never listed here.
   */
  sharedEntries: z.array(pathSegmentSchema).max(32).optional(),
  /**
   * Capability configuration that cannot be linked because the profile's own
   * file is rewritten in place (Claude Code stores MCP servers alongside OAuth
   * state). The listed keys are merged member-by-member instead.
   */
  sharedConfig: z
    .object({
      /** Profile-relative JSON file the keys are merged into. */
      target: pathSegmentSchema,
      /**
       * Shared-home-relative JSON files read for those keys, in priority order.
       * Members are unioned across all of them and the first definition of a
       * given member name wins, so put rendered files ahead of raw ones.
       */
      sources: z.array(sharedConfigSourceSchema).min(1).max(8),
      keys: z.array(sharedConfigKeySchema).min(1).max(16),
      /** Member names never shared into a profile, whatever a source says. */
      exclude: z.array(sharedConfigMemberSchema).max(64).optional(),
    })
    .optional(),
  /**
   * Where the tool keeps conversation history, so a session started under one
   * profile can be resumed under another. These are shared entries too, but
   * they are named separately because — unlike a skills corpus — every existing
   * profile already owns a real, populated directory at the target path, which
   * `ensureSharedCapabilities` will (correctly) refuse to replace. They can only
   * be linked after `accounts sessions merge` has unioned their contents into
   * the shared home, so `sharedEntriesFor` derives the link list from here
   * rather than the list being restated in `sharedEntries`.
   *
   * Live per-process state (Claude's PID-keyed `sessions/`) is deliberately not
   * describable here: it is runtime bookkeeping for a running process, not
   * history, and two profiles sharing it would each prune the other's records.
   */
  sessions: z
    .object({
      /** Profile-relative directory holding transcripts, at any nesting depth. */
      transcripts: pathSegmentSchema,
      /** Profile-relative JSONL file of prompt history records. */
      history: pathSegmentSchema,
    })
    .optional(),
});

/**
 * A supported app/tool. Each tool isolates its configuration in a directory
 * pointed at by an environment variable (e.g. Claude Code reads
 * `CLAUDE_CONFIG_DIR`). A "profile" is one such directory plus metadata.
 * Tools are either built-in or registered at runtime via `accounts tools add`.
 */
export type ToolDef = z.infer<typeof toolDefSchema>;

const metadataKeyPattern = /^[A-Za-z0-9_.:-]{1,64}$/;
const reservedMetadataKeys = new Set(["__proto__", "prototype", "constructor"]);
const metadataValueSchema = z.union([
  z.string(),
  z.number().refine(Number.isFinite, "metadata numbers must be finite"),
  z.boolean(),
  z.null(),
]);
type MetadataValue = z.infer<typeof metadataValueSchema>;
const metadataSchema = z
  .unknown()
  .superRefine((value, ctx) => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "metadata must be an object" });
      return;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "metadata must be a plain object" });
      return;
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "metadata keys must be strings" });
        continue;
      }
      if (!metadataKeyPattern.test(key)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `invalid metadata key "${key}"` });
        continue;
      }
      if (reservedMetadataKeys.has(key)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `reserved metadata key "${key}"` });
        continue;
      }
      const parsed = metadataValueSchema.safeParse((value as Record<string, unknown>)[key]);
      if (!parsed.success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `metadata "${key}" must be a string, finite number, boolean, or null`,
        });
      }
    }
  })
  .transform((value) => {
    const out: Record<string, MetadataValue> = Object.create(null);
    const record = value as Record<string, MetadataValue>;
    for (const key of Reflect.ownKeys(value as object)) {
      if (typeof key === "string") out[key] = record[key] as MetadataValue;
    }
    return out;
  });

function nonBlankStringSchema(label: string) {
  return z.string().refine((value) => value.trim().length > 0, `${label} must not be empty`);
}

export const profileSchema = z.object({
  name: profileNameSchema,
  tool: slugSchema,
  email: z.string().email().optional(),
  displayName: nonBlankStringSchema("display name").optional(),
  identity: nonBlankStringSchema("identity").optional(),
  cardLast4: z.string().regex(/^\d{4}$/, "cardLast4 must be exactly 4 digits").optional(),
  metadata: metadataSchema.optional(),
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
  /** Map of profile/account name -> preferred tool id for bare commands. */
  toolLocks: z.record(slugSchema, slugSchema).default({}),
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
