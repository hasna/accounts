import { afterEach, beforeEach, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { ensureProfileAuthSnapshot } from "./lib/claude-auth.js";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { convergeIdentityCredential } from "./lib/credential-broker.js";
import { switchAccount } from "./lib/switch-account.js";
import { migrateDirToLink } from "./lib/symlink-broker.js";
import { getTool } from "./lib/tools.js";
import { AccountsError } from "./types.js";

// End-to-end coverage of the single-inode broker repoint path inside
// switchAccount: uuid-keyed profiles WITH a central credential file take the
// atomic symlink swap; the outgoing account's in-place refresh is preserved.

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

const UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const UUID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-repoint-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-repoint-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
  // This file exercises the broker; opt a regular dir in to migrate-on-switch.
  process.env.HASNA_ACCOUNTS_SYMLINK_BROKER = "1";
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
  delete process.env.HASNA_ACCOUNTS_SYMLINK_BROKER;
});

function credBytes(email: string, opts: { refresh?: string | null; expiresInMs?: number } = {}): string {
  const { refresh = `${email}-refresh`, expiresInMs = 60_000 } = opts;
  return (
    JSON.stringify({
      claudeAiOauth: {
        accessToken: `${email}-access`,
        ...(refresh === null ? {} : { refreshToken: refresh }),
        expiresAt: Date.now() + expiresInMs,
      },
    }) + "\n"
  );
}

function seedCentral(uuid: string, email: string, opts: Parameters<typeof credBytes>[1] = {}): void {
  mkdirSync(join(home, "auth", uuid), { recursive: true });
  writeFileSync(centralCredentialsSnapshot(uuid), credBytes(email, opts), { mode: 0o600 });
}

/** A registered profile whose account has a uuid AND a central credential. */
function makeAccount(name: string, uuid: string, email: string, opts: Parameters<typeof credBytes>[1] = {}): string {
  const dir = mkdtempSync(join(tmpdir(), `repoint-${name}-`));
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credBytes(email, opts));
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  seedCentral(uuid, email, opts);
  return dir;
}

/** A session dir occupied by an account (uuid + email + a live regular cred file). */
function sessionOn(uuid: string, email: string, opts: Parameters<typeof credBytes>[1] = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "repoint-session-"));
  writeFileSync(
    join(dir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }),
  );
  writeFileSync(join(dir, ".credentials.json"), credBytes(email, opts));
  return dir;
}

function readClaudeJson(dir: string): { oauthAccount?: { accountUuid?: string; emailAddress?: string } } {
  return JSON.parse(readFileSync(join(dir, ".claude.json"), "utf8"));
}
function accessThroughDir(dir: string): string {
  const raw = JSON.parse(readFileSync(join(dir, ".credentials.json"), "utf8")) as {
    claudeAiOauth?: { accessToken?: string };
  };
  return raw.claudeAiOauth?.accessToken ?? "";
}

test("switchAccount takes the repoint path: the session credential becomes a symlink into central, no byte copy", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");
  // Unrelated session state must survive.
  const cj = readClaudeJson(session) as Record<string, unknown>;
  cj.projects = { "/tmp/x": { history: ["hi"] } };
  writeFileSync(join(session, ".claude.json"), JSON.stringify(cj));

  const result = await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });

  expect(result.alreadyActive).toBe(false);
  expect(result.restartRequired).toBe(false);
  expect(result.previousEmail).toBe("alpha@e.com");

  const link = join(session, ".credentials.json");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  expect(realpathSync(link)).toBe(realpathSync(centralCredentialsSnapshot(UUID_B)));
  // Same inode as the ONE central file — nothing was copied.
  expect(statSync(link).ino).toBe(statSync(centralCredentialsSnapshot(UUID_B)).ino);
  expect(accessThroughDir(session)).toBe("beta@e.com-access");
  // Identity merged; unrelated state preserved.
  expect(readClaudeJson(session).oauthAccount?.accountUuid).toBe(UUID_B);
  expect((readClaudeJson(session) as { projects?: unknown }).projects).toEqual({ "/tmp/x": { history: ["hi"] } });

  rmSync(session, { recursive: true, force: true });
});

test("the same call auto-switch makes (yes:true) takes the repoint path too", async () => {
  // performSwitch in the usage hook calls switchAccount(name, {tool, dir, yes:true}).
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");

  const result = await switchAccount("beta", { dir: session, env: {}, yes: true, allowUnregisteredDir: true });

  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(true);
  expect(accessThroughDir(session)).toBe("beta@e.com-access");
  expect(result.liveSessions).toBe(0);
  rmSync(session, { recursive: true, force: true });
});

test("NEVER DESTROYS A LOGIN: switching away preserves the outgoing account's in-place refresh onto its central", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com", { refresh: "alpha-central-old" });
  makeAccount("beta", UUID_B, "beta@e.com");
  // The live session rotated alpha's token in place (Claude's refresh fork):
  // the session dir holds a NEWER alpha credential than alpha's central.
  const session = sessionOn(UUID_A, "alpha@e.com", { refresh: "alpha-rotated-fresh" });

  await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });

  // Alpha's rotated refresh token survived onto alpha's central — the login was
  // not destroyed by switching away from it.
  const alphaCentral = JSON.parse(readFileSync(centralCredentialsSnapshot(UUID_A), "utf8")) as {
    claudeAiOauth?: { refreshToken?: string };
  };
  expect(alphaCentral.claudeAiOauth?.refreshToken).toBe("alpha-rotated-fresh");
  // Switch back to alpha: the dir reads the preserved credential through the link.
  await switchAccount("alpha", { dir: session, env: {}, allowUnregisteredDir: true });
  expect(accessThroughDir(session)).toBe("alpha@e.com-access");
  const back = JSON.parse(readFileSync(realpathSync(join(session, ".credentials.json")), "utf8")) as {
    claudeAiOauth?: { refreshToken?: string };
  };
  expect(back.claudeAiOauth?.refreshToken).toBe("alpha-rotated-fresh");
  rmSync(session, { recursive: true, force: true });
});

test("switching to the account the dir already carries is a normalising no-op that links it", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");

  const result = await switchAccount("alpha", { dir: session, env: {}, allowUnregisteredDir: true });

  expect(result.alreadyActive).toBe(true);
  // Even a no-op normalises the dir onto the link model.
  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(true);
  expect(accessThroughDir(session)).toBe("alpha@e.com-access");
  rmSync(session, { recursive: true, force: true });
});

test("repoint refuses a husked incoming account (central has no refresh token), touching nothing", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com", { refresh: null });
  const session = sessionOn(UUID_A, "alpha@e.com");
  const before = statSync(join(session, ".credentials.json")).ino;

  await expect(
    switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true }),
  ).rejects.toThrow(AccountsError);
  // The session dir is untouched: still alpha, still the same regular file.
  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(false);
  expect(statSync(join(session, ".credentials.json")).ino).toBe(before);
  expect(readClaudeJson(session).oauthAccount?.accountUuid).toBe(UUID_A);
  rmSync(session, { recursive: true, force: true });
});

test("no leftover .credentials.json.link-*.tmp files after a repoint", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");
  await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });
  const stray = (await import("node:fs")).readdirSync(session).filter((f) => f.includes(".link-"));
  expect(stray).toEqual([]);
  rmSync(session, { recursive: true, force: true });
});

test("a migrated (symlinked) dir switching to a target with no central file gets a clear login error", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  // gamma: registered with a uuid but NO central credential seeded.
  const gammaDir = mkdtempSync(join(tmpdir(), "repoint-gamma-"));
  const UUID_G = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  writeFileSync(
    join(gammaDir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_G, emailAddress: "g@e.com" } }),
  );
  writeFileSync(join(gammaDir, ".credentials.json"), credBytes("g@e.com"));
  addProfile({ name: "gamma", dir: gammaDir });
  ensureProfileAuthSnapshot(gammaDir, tool());
  // ensureProfileAuthSnapshot syncs a central file; delete it to reproduce the
  // genuine "registered account with no central credential" state.
  rmSync(centralCredentialsSnapshot(UUID_G), { force: true });

  const session = sessionOn(UUID_A, "alpha@e.com");
  // Migrate the session dir onto the model (now a symlink into central A).
  await switchAccount("alpha", { dir: session, env: {}, allowUnregisteredDir: true });
  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(true);

  await expect(
    switchAccount("gamma", { dir: session, env: {}, allowUnregisteredDir: true }),
  ).rejects.toThrow(/central credential/);
  // The dir is untouched — still linked to alpha.
  expect(accessThroughDir(session)).toBe("alpha@e.com-access");
  rmSync(session, { recursive: true, force: true });
  rmSync(gammaDir, { recursive: true, force: true });
});

test("F1: the legacy convergence writer cannot clobber a symlinked dir credential (coexistence is safe)", () => {
  // Once a dir is on the symlink model, the credential-byte writers that remain
  // for un-migrated dirs must not replace its symlink with a regular file — the
  // failure the design calls F1. writeFileAtomic refuses symlinks, so the
  // writer skips it. This proves the two models coexist without corruption.
  makeAccount("alpha", UUID_A, "alpha@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");
  migrateDirToLink(session, UUID_A);
  const link = join(session, ".credentials.json");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  const centralInodeBefore = statSync(centralCredentialsSnapshot(UUID_A)).ino;

  convergeIdentityCredential(UUID_A, { tool: tool(), extraDirs: [session] });

  // The symlink is intact — no regular file was written over it.
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  expect(realpathSync(link)).toBe(realpathSync(centralCredentialsSnapshot(UUID_A)));
  expect(statSync(centralCredentialsSnapshot(UUID_A)).ino).toBe(centralInodeBefore);
  rmSync(session, { recursive: true, force: true });
});

test("DEFECT 1 (broker no longer dormant): with the opt-in OFF, a regular dir whose target HAS a central engages the broker", async () => {
  // The shipped 0.2.35 gate was `dirIsMigrated || HASNA_ACCOUNTS_SYMLINK_BROKER===1`.
  // The env var is unset on every production box, and real seat dirs are regular
  // files, so the husk-free broker never ran for any real seat (defect 1). The
  // engagement rule is now "the incoming account has a central credential of
  // record" — which the existing snapshot machinery already creates on login and
  // on every legacy switch — so no env var is needed for the broker to activate.
  delete process.env.HASNA_ACCOUNTS_SYMLINK_BROKER;
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");

  await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });

  // beta has a central credential, so the switch takes the zero-copy repoint
  // path: the session credential is now a symlink into beta's ONE central file.
  const link = join(session, ".credentials.json");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  expect(realpathSync(link)).toBe(realpathSync(centralCredentialsSnapshot(UUID_B)));
  expect(accessThroughDir(session)).toBe("beta@e.com-access");
  rmSync(session, { recursive: true, force: true });
});

test("GRACEFUL DEGRADATION: with the opt-in OFF, a regular dir whose target has NO central stays on the legacy copy path", async () => {
  // The broker can only link a dir to a central file that exists. An account
  // that has never been migrated has no central yet, so the switch must fall
  // through to the legacy copy path rather than crash — the residual safe
  // default. (The very act of falling through creates the target's central via
  // ensureProfileAuthSnapshot, so the NEXT switch to it engages the broker.)
  delete process.env.HASNA_ACCOUNTS_SYMLINK_BROKER;
  makeAccount("alpha", UUID_A, "alpha@e.com");
  // gamma: registered, uuid-bearing, but its central is deleted to reproduce the
  // genuine "never migrated, no central" state.
  const gammaDir = mkdtempSync(join(tmpdir(), "repoint-nocentral-"));
  const UUID_G = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  writeFileSync(
    join(gammaDir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID_G, emailAddress: "g@e.com" } }),
  );
  writeFileSync(join(gammaDir, ".credentials.json"), credBytes("g@e.com"));
  addProfile({ name: "gamma", dir: gammaDir });
  ensureProfileAuthSnapshot(gammaDir, tool());
  rmSync(centralCredentialsSnapshot(UUID_G), { force: true });

  const session = sessionOn(UUID_A, "alpha@e.com");
  await switchAccount("gamma", { dir: session, env: {}, allowUnregisteredDir: true });

  // No central to link to at gate time, so the dir stays a copied regular file.
  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(false);
  expect(accessThroughDir(session)).toBe("g@e.com-access");
  rmSync(session, { recursive: true, force: true });
  rmSync(gammaDir, { recursive: true, force: true });
});

test("DEFECT 2 (E1-fork husk regression): a Claude refresh fork of a migrated dir re-adopts and stays a symlink WITHOUT the env flag", async () => {
  // Claude Code 2.1.223 refreshes its OAuth token by rename-ing a temp file over
  // `.credentials.json`, which REPLACES the migrated dir's symlink with a regular
  // file (a "fork"). Under the shipped gate, a subsequent plain switch on that
  // now-regular dir reverted to the legacy COPY path and reintroduced a husk
  // (measured: migrated -> fork -> switch -> a 508b regular copy). Because the
  // target account has a central, the switch must instead re-adopt the fork onto
  // its central and repoint — no husk, no env flag.
  makeAccount("alpha", UUID_A, "alpha@e.com", { refresh: "alpha-central-old" });
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");
  // Migrate the dir onto the model (symlink into alpha's central)...
  migrateDirToLink(session, UUID_A);
  const link = join(session, ".credentials.json");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);

  // ...simulate Claude's in-session refresh fork: the symlink becomes a regular
  // file carrying a FRESH alpha refresh token that exists nowhere else.
  rmSync(link, { force: true });
  writeFileSync(link, credBytes("alpha@e.com", { refresh: "alpha-rotated-in-session" }), { mode: 0o600 });
  expect(lstatSync(link).isSymbolicLink()).toBe(false);

  // The env flag is unset (production state), yet the switch must repoint.
  delete process.env.HASNA_ACCOUNTS_SYMLINK_BROKER;
  await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });

  // The dir is a symlink into beta's central — not a legacy copy husk.
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  expect(realpathSync(link)).toBe(realpathSync(centralCredentialsSnapshot(UUID_B)));
  expect(accessThroughDir(session)).toBe("beta@e.com-access");
  // The fork's fresh alpha refresh token was preserved onto alpha's central —
  // the login was re-adopted, not lost to a husk.
  const alphaCentral = JSON.parse(readFileSync(centralCredentialsSnapshot(UUID_A), "utf8")) as {
    claudeAiOauth?: { refreshToken?: string };
  };
  expect(alphaCentral.claudeAiOauth?.refreshToken).toBe("alpha-rotated-in-session");
  rmSync(session, { recursive: true, force: true });
});

test("a MIGRATED dir repoints even with the opt-in OFF (a symlink can only be switched by repoint)", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  makeAccount("beta", UUID_B, "beta@e.com");
  const session = sessionOn(UUID_A, "alpha@e.com");
  // Migrate the dir onto the model with the opt-in on...
  migrateDirToLink(session, UUID_A);
  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(true);
  // ...then turn the opt-in OFF: a migrated dir must still repoint.
  delete process.env.HASNA_ACCOUNTS_SYMLINK_BROKER;

  await switchAccount("beta", { dir: session, env: {}, allowUnregisteredDir: true });

  expect(lstatSync(join(session, ".credentials.json")).isSymbolicLink()).toBe(true);
  expect(accessThroughDir(session)).toBe("beta@e.com-access");
  rmSync(session, { recursive: true, force: true });
});

test("registered profile dir needs no override — repoint runs for it too", async () => {
  makeAccount("alpha", UUID_A, "alpha@e.com");
  const betaDir = makeAccount("beta", UUID_B, "beta@e.com");
  // Switch beta's OWN dir to alpha: profile-dir kind, no allowUnregisteredDir.
  const result = await switchAccount("alpha", { dir: betaDir, env: {} });
  expect(result.dirKind).toBe("profile-dir");
  expect(lstatSync(join(betaDir, ".credentials.json")).isSymbolicLink()).toBe(true);
  expect(accessThroughDir(betaDir)).toBe("alpha@e.com-access");
  expect(existsSync(centralCredentialsSnapshot(UUID_B))).toBe(true); // beta's central intact
});
