// Runtime configuration for the accounts cloud service.
//
// Resolves the app slug, API-key signing secret, and table names from the
// environment. Never logs secret values. Follows the Hasna auth env convention:
//   HASNA_ACCOUNTS_API_SIGNING_KEY (fallback HASNA_API_SIGNING_KEY)
//   HASNA_ACCOUNTS_DATABASE_URL / HASNA_ACCOUNTS_STORAGE_MODE (kit-resolved)

export const APP_SLUG = "accounts";
export const API_KEYS_TABLE = "api_keys";
export const DEFAULT_SERVE_PORT = 8080;

/** Resolve the HMAC signing secret used to verify API keys. */
export function resolveSigningSecret(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const primary = env.HASNA_ACCOUNTS_API_SIGNING_KEY?.trim();
  if (primary) return primary;
  const shared = env.HASNA_API_SIGNING_KEY?.trim();
  if (shared) return shared;
  return undefined;
}

/** Scopes for the two access tiers this service enforces. */
export const SCOPES = {
  read: `${APP_SLUG}:read`,
  write: `${APP_SLUG}:write`,
} as const;
