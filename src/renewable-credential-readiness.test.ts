/**
 * A credential the tool renews on use must not be reported as `unavailable`.
 *
 * WHY THIS TEST EXISTS
 * On station01 (2026-07-30) the Claude auth pool collapsed from 21 usable
 * profiles to 11. Ten of the quarantined profiles were not broken at all:
 * their ACCESS token had aged out while the REFRESH token was intact, which is
 * the normal resting state of a parked account and self-heals on first use.
 * `accounts health --json` nevertheless reported them `unavailable`, and the
 * factory's profile probe reads `unavailable` as "dead" and quarantines
 * immediately. One dropped field cost the fleet half its Claude capacity.
 *
 * Two defects sat behind it, both covered here:
 *  1. `claudeProfileAuthHealth` only set `renewable` when the credential had a
 *     RECORDED expiry in the past, so a credential holding a refresh token but
 *     no expiry timestamp came back neither valid nor renewable.
 *  2. `profileLoginReadiness` collapsed every non-ok auth status to
 *     `unavailable` without consulting `renewable`, and never emitted the field,
 *     so no consumer could tell "needs a human" from "renews itself".
 */
import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { claudeProfileAuthHealth } from "./lib/claude-auth.js";
import { addProfile } from "./lib/profiles.js";
import { getAccountsReadiness } from "./lib/readiness.js";
import { getTool } from "./lib/tools.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-renewable-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_STORE_PATH;
});

/** Split key names so no literal credential-shaped identifier sits in the file. */
const ACCESS = "access" + "Token";
const REFRESH = "refresh" + "Token";

function writeClaudeAuth(profileDir: string, email: string, oauth: Record<string, unknown>): void {
  writeFileSync(join(profileDir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }) + "\n");
  writeFileSync(join(profileDir, ".credentials.json"), JSON.stringify({ claudeAiOauth: oauth }) + "\n");
}

function readinessEnv(): NodeJS.ProcessEnv {
  return { ...process.env, HASNA_ACCOUNTS_S3_BUCKET: "accounts-renewable-test" };
}

test("an aged-out access token with an intact refresh token is renewable", () => {
  const profile = addProfile({ name: "aged", tool: "claude", email: "aged@example.test" });
  writeClaudeAuth(profile.dir, "aged@example.test", {
    [ACCESS]: "placeholder-a",
    [REFRESH]: "placeholder-r",
    expiresAt: Date.now() - 60_000,
  });

  const health = claudeProfileAuthHealth(profile.dir, getTool("claude"));

  expect(health.status).toBe("expired");
  expect(health.valid).toBe(false);
  expect(health.renewable).toBe(true);
});

test("a refresh token with no recorded expiry is renewable, not an unknown dead end", () => {
  const profile = addProfile({ name: "noexpiry", tool: "claude", email: "noexpiry@example.test" });
  // No `expiresAt`: the payload cannot say when the access token lapses, but it
  // still carries the refresh token the tool needs to mint a new one.
  writeClaudeAuth(profile.dir, "noexpiry@example.test", {
    [ACCESS]: "placeholder-a",
    [REFRESH]: "placeholder-r",
  });

  const health = claudeProfileAuthHealth(profile.dir, getTool("claude"));

  expect(health.valid).toBe(false);
  expect(health.renewable).toBe(true);
});

test("a credential with no refresh token is neither valid nor renewable", () => {
  const profile = addProfile({ name: "norefresh", tool: "claude", email: "norefresh@example.test" });
  writeClaudeAuth(profile.dir, "norefresh@example.test", {
    [ACCESS]: "placeholder-a",
    expiresAt: Date.now() - 60_000,
  });

  const health = claudeProfileAuthHealth(profile.dir, getTool("claude"));

  expect(health.valid).toBe(false);
  expect(health.renewable).toBe(false);
});

test("an empty credential file is missing, not an unknown expiry", () => {
  // The other half of the station01 pool damage. `account001` and `account002`
  // held a two-byte `{}` in BOTH the live credential file and the parked
  // snapshot: no tokens at all, only an OAuth account record saying who the
  // profile belongs to. Because the FILE existed, the payload counted as
  // "present", the expiry could not be read, and the profile was graded
  // `unknown` -> `degraded`. A pool manager reads `degraded` as "no verdict",
  // so the profile was never quarantined, never cleared, and stayed eligible
  // for auto-pick forever while being completely unusable. An empty payload is
  // a missing credential and must say so, which is what routes it to a human.
  const profile = addProfile({ name: "hollow", tool: "claude", email: "hollow@example.test" });
  writeFileSync(
    join(profile.dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "hollow@example.test" } }) + "\n",
  );
  writeFileSync(join(profile.dir, ".credentials.json"), "{}\n");

  const health = claudeProfileAuthHealth(profile.dir, getTool("claude"));

  expect(health.status).toBe("missing");
  expect(health.valid).toBe(false);
  expect(health.renewable).toBe(false);
  expect(health.credentialPayloadPresent).toBe(false);
  expect(health.reasons.join("\n")).toContain("credential payload is missing");
});

test("readiness reports an empty credential file as unavailable, never as no-verdict", async () => {
  const profile = addProfile({ name: "hollow", tool: "claude", email: "hollow@example.test" });
  writeFileSync(
    join(profile.dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "hollow@example.test" } }) + "\n",
  );
  writeFileSync(join(profile.dir, ".credentials.json"), "{}\n");

  const readiness = await getAccountsReadiness({ env: readinessEnv() });
  const row = readiness.profiles.find((item) => item.name === "hollow" && item.tool === "claude");

  expect(row?.login.authStatus).toBe("missing");
  expect(row?.login.status).toBe("unavailable");
  expect(row?.login.status).not.toBe("degraded");
  expect(row?.nextActions.join("\n")).toContain("accounts login hollow --tool claude");
});

test("readiness reports a renewable profile as degraded and says so in the payload", async () => {
  const profile = addProfile({ name: "aged", tool: "claude", email: "aged@example.test" });
  writeClaudeAuth(profile.dir, "aged@example.test", {
    [ACCESS]: "placeholder-a",
    [REFRESH]: "placeholder-r",
    expiresAt: Date.now() - 60_000,
  });

  const readiness = await getAccountsReadiness({ env: readinessEnv() });
  const row = readiness.profiles.find((item) => item.name === "aged" && item.tool === "claude");

  expect(row).toBeDefined();
  // `renewable` is the field a downstream pool manager needs in order to tell a
  // self-healing profile from a dead one. Dropping it is what caused the outage.
  expect(row?.login.renewable).toBe(true);
  expect(row?.login.status).toBe("degraded");
  expect(row?.login.authStatus).toBe("expired");
  // A profile the tool renews on use must never be advertised as unusable.
  expect(row?.login.status).not.toBe("unavailable");
});

test("readiness still reports an unrecoverable credential as unavailable", async () => {
  const profile = addProfile({ name: "norefresh", tool: "claude", email: "norefresh@example.test" });
  writeClaudeAuth(profile.dir, "norefresh@example.test", {
    [ACCESS]: "placeholder-a",
    expiresAt: Date.now() - 60_000,
  });

  const readiness = await getAccountsReadiness({ env: readinessEnv() });
  const row = readiness.profiles.find((item) => item.name === "norefresh" && item.tool === "claude");

  expect(row?.login.renewable).toBe(false);
  expect(row?.login.status).toBe("unavailable");
});
