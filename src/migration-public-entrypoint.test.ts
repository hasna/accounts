import { expect, test } from "bun:test";
import { LOGIN_CLEANUP_MIGRATION_BLOCKER_REASON } from "./index.js";
import { assertAccountsMigrationDeploySafe } from "./server/migrations.js";

test("root package exports the stable login cleanup migration blocker reason", () => {
  expect(LOGIN_CLEANUP_MIGRATION_BLOCKER_REASON).toBe(
    "login-cleanup-ledger-atomicity",
  );

  expect(() =>
    assertAccountsMigrationDeploySafe({
      ledgerPresent: true,
      pending: ["accounts_0010_login_cleanup_operations"],
      unknown: [],
      checksumMismatches: [],
    }),
  ).toThrow(
    "accounts migration 0010 is deployment-blocked (login-cleanup-ledger-atomicity)",
  );
});
