import { expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolveStore } from "./lib/store.js";
import { profileEnv } from "./lib/env.js";
import { getTool } from "./lib/tools.js";
import { accountsHome } from "./storage.js";
import { credentialHealth } from "./lib/auth-store.js";

/**
 * Regression for b29f5b6c — a launched Claude session reads an EMPTY (logged-out)
 * profile-root `.credentials.json` while `accounts login`/`usage` report the
 * profile as logged-in.
 *
 * ROOT CAUSE (measured, not the task's original "redacted read" guess, which does
 * not exist in the code): the empty root is the `rotated-away` fingerprint Claude
 * Code writes IN PLACE (accessToken:"", refreshToken:"", expiresAt:0, scopes/tier
 * intact) after a DUPLICATE live copy of the same account rotated the refresh
 * token out from under it. The profile's real credential still lives in the
 * snapshot and the central store, but the launch heal (`recoverParkedCredential`,
 * called by `profileEnv`) REFUSES to restore it with `account-live-elsewhere`
 * because the account is live in another dir — leaving the launched session
 * logged-out.
 *
 * FIX: when the dir legitimately holds its OWN account (identity gates passed)
 * and the only blocker is `account-live-elsewhere`, heal by CONVERGENCE
 * (`convergeDirCredential`, the sanctioned many-readers-one-writer duplicate-
 * custody path). Convergence is pure file I/O that fans the CURRENT winning
 * credential into every copy, so all dirs hold the SAME token — it never
 * introduces a second, superseded token and therefore cannot cause the
 * double-refresh revocation the refusal guards against.
 */

const OWN_UUID = "548bc422-e630-41a3-83a5-f3feb4320aec";
const DECOY_UUID = "99999999-8888-7777-6666-555555555555";

function realCred(tag = "own"): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${tag}-access-${"A".repeat(100)}`,
      refreshToken: `${tag}-refresh-${"R".repeat(100)}`,
      expiresAt: Date.now() + 3_600_000,
      scopes: ["user:inference", "user:profile"],
      subscriptionType: "max",
    },
  });
}

// The rotated-away husk Claude Code writes in place: structure intact, secrets gone.
function huskCred(): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: "",
      refreshToken: "",
      expiresAt: 0,
      scopes: ["user:inference", "user:profile"],
      subscriptionType: "max",
    },
  });
}

function accountFile(uuid: string, email: string): string {
  return JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } });
}

function centralDir(uuid: string): string {
  return join(accountsHome(), "auth", uuid);
}

function seedCentral(uuid: string, email: string, cred: string): void {
  const dir = centralDir(uuid);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "credentials.json"), cred);
  writeFileSync(join(dir, "oauth-account.json"), accountFile(uuid, email));
}

test("launch heals a rotated-away root when the account is live in a second profile (b29f5b6c)", async () => {
  const store = resolveStore();

  // Primary profile: its own account, but its LIVE root was blanked by Claude
  // (rotated-away) while the real credential survives in the snapshot + central.
  const primary = await store.addProfile({ name: "heal-primary", tool: "claude", description: "b29f5b6c" });
  const dir = primary.dir;
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(join(dir, ".credentials.json"), huskCred());
  writeFileSync(join(dir, ".claude.json"), accountFile(OWN_UUID, "own@example.test"));
  writeFileSync(join(dir, ".accounts-auth", "oauth-account.json"), accountFile(OWN_UUID, "own@example.test"));
  const parked = realCred("own");
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), parked);
  seedCentral(OWN_UUID, "own@example.test", parked);

  // The SAME account is currently live in a second registered profile — this is
  // exactly what makes `recoverParkedCredential` refuse with account-live-elsewhere.
  const sibling = await store.addProfile({ name: "heal-sibling", tool: "claude", description: "b29f5b6c" });
  mkdirSync(sibling.dir, { recursive: true });
  writeFileSync(join(sibling.dir, ".credentials.json"), parked);
  writeFileSync(join(sibling.dir, ".claude.json"), accountFile(OWN_UUID, "own@example.test"));

  // A decoy real credential filed under a DIFFERENT account — the heal must never
  // pull this into the primary's root (mis-bound uuid must not win).
  seedCentral(DECOY_UUID, "decoy@example.test", realCred("decoy"));

  const rootPath = join(dir, ".credentials.json");
  expect(credentialHealth(rootPath)).toMatchObject({ exists: true, refreshTokenLength: 0 });

  // Launch materialization (what a launched Claude session triggers).
  profileEnv(primary, getTool("claude"));

  // The root now carries a real credential again...
  const healed = credentialHealth(rootPath);
  expect(healed.exists).toBe(true);
  expect(healed.refreshTokenLength).toBeGreaterThan(0);

  // ...and it is THIS account's credential, byte-identical to its own central
  // store record — not the decoy account's.
  const rootBytes = readFileSync(rootPath);
  expect(rootBytes.equals(readFileSync(join(centralDir(OWN_UUID), "credentials.json")))).toBe(true);
  expect(rootBytes.equals(readFileSync(join(centralDir(DECOY_UUID), "credentials.json")))).toBe(false);
});

test("launch does NOT heal a MIS-BOUND dir whose live identity is a different account (discriminating)", async () => {
  const store = resolveStore();

  // The dir's live `.claude.json` says DECOY_UUID, but the profile's own parked
  // identity is OWN_UUID — an in-place switch, not this profile's own account.
  // Restoring here would change which account the dir presents, so the heal must
  // REFUSE (identity-would-change), never converge OWN_UUID's credential into a
  // dir that currently belongs to DECOY_UUID.
  const profile = await store.addProfile({ name: "heal-misbound", tool: "claude", description: "b29f5b6c" });
  const dir = profile.dir;
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  writeFileSync(join(dir, ".credentials.json"), huskCred());
  writeFileSync(join(dir, ".claude.json"), accountFile(DECOY_UUID, "decoy@example.test"));
  writeFileSync(join(dir, ".accounts-auth", "oauth-account.json"), accountFile(OWN_UUID, "own@example.test"));
  const parked = realCred("own");
  writeFileSync(join(dir, ".accounts-auth", "credentials.json"), parked);
  seedCentral(OWN_UUID, "own@example.test", parked);

  // OWN account also live elsewhere (so the only difference from the passing test
  // is the mis-bound live identity).
  const sibling = await store.addProfile({ name: "heal-misbound-sib", tool: "claude", description: "b29f5b6c" });
  mkdirSync(sibling.dir, { recursive: true });
  writeFileSync(join(sibling.dir, ".credentials.json"), parked);
  writeFileSync(join(sibling.dir, ".claude.json"), accountFile(OWN_UUID, "own@example.test"));

  const rootPath = join(dir, ".credentials.json");
  profileEnv(profile, getTool("claude"));

  // The root must stay the husk — the fix must not write OWN_UUID's credential
  // into a dir that currently presents DECOY_UUID.
  const after = credentialHealth(rootPath);
  expect(after.exists).toBe(true);
  expect(after.refreshTokenLength).toBe(0);
});
