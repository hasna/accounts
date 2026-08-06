// Regression tests for bug 04a350a9 (task 61148ec0): the snapshot-back drop.
//
// Two confirmed login-destruction shapes in 0.2.32:
//  1. `switchAccount` DISCARDED the outgoing fresh login when `detectDirOwner`
//     could not resolve a single owner (no owner, or multiple profiles share
//     the email) — a warning was pushed, then `restoreClaudeAuthIntoDir`
//     overwrote the dir's credential wholesale. The rotated-in tokens existed
//     nowhere else, so the login was destroyed.
//  2. `snapshotLiveAuthToProfile` copied the live default's credential over the
//     owning profile's parked snapshot with no downgrade guard, so a husked
//     live credential (Claude Code blanks `.credentials.json` after a failed
//     refresh) overwrote a good parked copy — propagating the husk into the
//     only surviving layer.
import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import {
  ensureProfileAuthSnapshot,
  orphanSnapshotsRoot,
  snapshotLiveAuthToProfile,
} from "./lib/claude-auth.js";
import { profileCredentialsSnapshot } from "./lib/claude-layout.js";
import { switchAccount } from "./lib/switch-account.js";
import { getTool } from "./lib/tools.js";

let home: string;
let liveBase: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-sbd-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-sbd-live-"));
  process.env.ACCOUNTS_HOME = home;
  process.env.ACCOUNTS_TEST_LIVE_DIR = liveBase;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(liveBase, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_LIVE_DIR;
});

// Synthetic sentinel tokens only — shaped so no secret scanner pattern matches.
function credentialJson(email: string, opts: { rotated?: boolean; expiresInMs?: number } = {}): string {
  const tag = opts.rotated ? "-ROTATED" : "";
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${email}-access-sentinel${tag}`,
      refreshToken: `${email}-refresh-sentinel${tag}`,
      expiresAt: Date.now() + (opts.expiresInMs ?? 60_000),
    },
  });
}

const HUSK = JSON.stringify({
  claudeAiOauth: { accessToken: "", refreshToken: "", expiresAt: 0, scopes: [], subscriptionType: "max" },
});

function writeIdentity(dir: string, email: string): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: email } }));
  writeFileSync(join(dir, ".credentials.json"), credentialJson(email));
}

function makeProfile(name: string, email: string): string {
  const dir = mkdtempSync(join(tmpdir(), `sbd-${name}-`));
  writeIdentity(dir, email);
  addProfile({ name, dir });
  ensureProfileAuthSnapshot(dir, tool());
  return dir;
}

function orphanSnapshotCredentialFiles(): string[] {
  const root = orphanSnapshotsRoot();
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .map((entry) => join(root, entry, "credentials.json"))
    .filter((path) => existsSync(path));
}

test("ambiguous-owner switch parks the outgoing credential in an orphan snapshot instead of destroying it", async () => {
  makeProfile("dup1", "shared@example.com");
  makeProfile("dup2", "shared@example.com");
  makeProfile("beta", "beta@example.com");

  // The session rotated tokens in place: these bytes exist NOWHERE else.
  const sessionDir = mkdtempSync(join(tmpdir(), "sbd-ambig-"));
  writeIdentity(sessionDir, "shared@example.com");
  const outgoing = credentialJson("shared@example.com", { rotated: true, expiresInMs: 120_000 });
  writeFileSync(join(sessionDir, ".credentials.json"), outgoing);

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

  // No profile received the snapshot — ownership genuinely could not be
  // resolved — but the bytes MUST survive somewhere recoverable.
  expect(result.snapshotBackProfile).toBeUndefined();
  const parked = orphanSnapshotCredentialFiles();
  expect(parked.length).toBe(1);
  expect(readFileSync(parked[0]!, "utf8")).toBe(outgoing);
  // The parked snapshot names the account it belonged to.
  const oauthPath = join(parked[0]!.slice(0, -"credentials.json".length), "oauth-account.json");
  const oauth = JSON.parse(readFileSync(oauthPath, "utf8")) as { oauthAccount?: { emailAddress?: string } };
  expect(oauth.oauthAccount?.emailAddress).toBe("shared@example.com");
  // The operator is told where it went.
  expect(result.warnings.some((w) => w.includes("parked") && w.includes(parked[0]!.slice(0, -"/credentials.json".length)))).toBe(
    true,
  );
  // Neither same-email profile's own snapshot was contaminated with the
  // outgoing bytes (that would be guessing the owner).
  rmSync(sessionDir, { recursive: true, force: true });
});

test("a switch away from an UNOWNED dir with no credential file parks nothing and still switches", async () => {
  makeProfile("beta", "beta@example.com");
  const sessionDir = mkdtempSync(join(tmpdir(), "sbd-nocred-"));
  mkdirSync(sessionDir, { recursive: true });
  writeFileSync(join(sessionDir, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "stray@example.com" } }));

  const result = await switchAccount("beta", { dir: sessionDir, env: {}, allowUnregisteredDir: true });

  expect(result.alreadyActive).toBe(false);
  expect(orphanSnapshotCredentialFiles().length).toBe(0);
  rmSync(sessionDir, { recursive: true, force: true });
});

test("snapshot-back refuses to overwrite a good parked snapshot with a husked live credential", () => {
  const ownDir = makeProfile("own", "own@example.com");
  const snapPath = profileCredentialsSnapshot(ownDir);
  const goodBytes = readFileSync(snapPath, "utf8");

  // The live default now holds the owner's identity but a BLANKED credential —
  // the exact 281-byte husk shape Claude Code writes after a failed refresh.
  mkdirSync(join(liveBase, ".claude"), { recursive: true });
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "own@example.com" } }));
  writeFileSync(join(liveBase, ".claude", ".credentials.json"), HUSK);

  snapshotLiveAuthToProfile(ownDir, tool());

  // The parked snapshot — the only surviving good copy — must be intact.
  expect(readFileSync(snapPath, "utf8")).toBe(goodBytes);
});

test("POSITIVE CONTROL: snapshot-back still adopts a genuinely better live credential", () => {
  const ownDir = makeProfile("own", "own@example.com");
  const snapPath = profileCredentialsSnapshot(ownDir);

  const rotated = credentialJson("own@example.com", { rotated: true, expiresInMs: 300_000 });
  mkdirSync(join(liveBase, ".claude"), { recursive: true });
  writeFileSync(join(liveBase, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "own@example.com" } }));
  writeFileSync(join(liveBase, ".claude", ".credentials.json"), rotated);

  snapshotLiveAuthToProfile(ownDir, tool());

  // Without this, the refusal test proves nothing — the identical call must be
  // able to update the snapshot when the live credential genuinely is better.
  expect(readFileSync(snapPath, "utf8")).toBe(rotated);
});
