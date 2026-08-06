// Regression tests for bug 04a350a9 (task d132234c): the apply-unlink wipe.
//
// In 0.2.32, `restoreClaudeAuthFromProfile` DELETED the live
// `~/.claude/.credentials.json` whenever the target profile had no restorable
// credential snapshot, because `bestRestorableCredentialPath` considered only
// the parked snapshot and the central copy — never the profile's own dir-live
// file — while `assertRestorableProfileAuth` COUNTED the dir-live file. A
// profile could therefore pass the assert and still reach the unlink branch,
// destroying a live login that had never been snapshotted anywhere.
import { test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { applyProfile } from "./lib/apply.js";
import { writeSwitchedAccountMarker } from "./lib/claude-auth.js";
import { profileAuthDir, profileOAuthSnapshot } from "./lib/claude-layout.js";

let home: string;
let liveBase: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-wipe-"));
  liveBase = mkdtempSync(join(tmpdir(), "accounts-wipe-live-"));
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
function credential(email: string): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${email}-access-sentinel`,
      refreshToken: `${email}-refresh-sentinel`,
      expiresAt: Date.now() + 60_000,
    },
  });
}

test("apply never deletes the live credentials file when the profile has nothing restorable", async () => {
  // The live default holds a healthy login that no registered profile owns.
  const liveConfigDir = join(liveBase, ".claude");
  const liveCredFile = join(liveConfigDir, ".credentials.json");
  mkdirSync(liveConfigDir, { recursive: true });
  writeFileSync(
    join(liveBase, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "victim@example.com" } }),
  );
  writeFileSync(liveCredFile, credential("victim@example.com"));
  const liveBytesBefore = readFileSync(liveCredFile);

  // "ghost": own parked identity, NO parked/central credential snapshot; its
  // dir's live files carry ANOTHER account (agreeing in-place switch marker),
  // so the dir-live credential is not ghost's to install.
  // `assertRestorableProfileAuth` still passes because it counts the dir-live
  // payload — the exact 0.2.32 wipe shape.
  const ghostDir = mkdtempSync(join(tmpdir(), "wipe-ghost-"));
  mkdirSync(profileAuthDir(ghostDir), { recursive: true });
  writeFileSync(
    profileOAuthSnapshot(ghostDir),
    JSON.stringify({ oauthAccount: { emailAddress: "ghost@example.com" } }),
  );
  writeFileSync(
    join(ghostDir, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "occupant@example.com" } }),
  );
  writeFileSync(join(ghostDir, ".credentials.json"), credential("occupant@example.com"));
  writeSwitchedAccountMarker(ghostDir, { profile: "occ", email: "occupant@example.com" });
  addProfile({ name: "ghost", dir: ghostDir });

  // The apply must REFUSE — a profile with nothing safely restorable cannot
  // take over the live paths.
  await expect(applyProfile("ghost")).rejects.toThrow(/no restorable/i);

  // The wipe itself: 0.2.32 unlinked this file here. It must survive,
  // byte-identical.
  expect(existsSync(liveCredFile)).toBe(true);
  expect(readFileSync(liveCredFile).equals(liveBytesBefore)).toBe(true);

  // And the refusal must land BEFORE any mutation: the live identity is intact.
  const liveJson = JSON.parse(readFileSync(join(liveBase, ".claude.json"), "utf8")) as {
    oauthAccount?: { emailAddress?: string };
  };
  expect(liveJson.oauthAccount?.emailAddress).toBe("victim@example.com");
  rmSync(ghostDir, { recursive: true, force: true });
});

test("apply installs a profile's own dir-live credential when no snapshot exists yet", async () => {
  // The clean fixture from the bug report: oauth record + dir-live credential
  // + no snapshots. The dir-live copy IS this profile's own credential, so an
  // apply must install it on the live paths — never delete anything.
  const soloDir = mkdtempSync(join(tmpdir(), "wipe-solo-"));
  writeFileSync(
    join(soloDir, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "solo@example.com" } }),
  );
  const soloCred = credential("solo@example.com");
  writeFileSync(join(soloDir, ".credentials.json"), soloCred);
  addProfile({ name: "solo", dir: soloDir });

  const liveConfigDir = join(liveBase, ".claude");
  mkdirSync(liveConfigDir, { recursive: true });
  writeFileSync(
    join(liveBase, ".claude.json"),
    JSON.stringify({ oauthAccount: { emailAddress: "victim@example.com" } }),
  );
  writeFileSync(join(liveConfigDir, ".credentials.json"), credential("victim@example.com"));

  await applyProfile("solo");

  // The live file survives and is byte-identical to the profile's own dir-live
  // credential — installed, not deleted.
  const liveCred = readFileSync(join(liveConfigDir, ".credentials.json"), "utf8");
  expect(liveCred).toBe(soloCred);
  rmSync(soloDir, { recursive: true, force: true });
});
