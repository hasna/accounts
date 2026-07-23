/**
 * Stable public reason code for the migration 0010 deployment gate.
 *
 * Keep internal task identifiers out of runtime errors and operator docs.
 */
export const LOGIN_CLEANUP_MIGRATION_BLOCKER_REASON =
  "login-cleanup-ledger-atomicity" as const;
