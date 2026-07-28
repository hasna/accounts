import { test, expect, beforeEach, afterEach } from "bun:test";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { getTool } from "./lib/tools.js";
import { profilesDir } from "./storage.js";
import { ensureSharedCapabilities, sharedCapabilityHealth, sharedEntriesFor } from "./lib/shared-capabilities.js";
import { mergeClaudeSessions, type SessionMergeReport } from "./lib/session-merge.js";

let home: string;
let sharedHome: string;

const PROJECT_A = "-home-hasna-workspace-alpha";
const PROJECT_B = "-home-hasna-workspace-beta";

function uuid(n: number): string {
  const hex = n.toString(16).padStart(12, "0");
  return `00000000-0000-4000-8000-${hex}`;
}

/** A transcript line shaped like the real thing, deterministic per (uuid, index). */
function transcript(id: string, lines: number): string {
  return (
    Array.from({ length: lines }, (_, i) =>
      JSON.stringify({ sessionId: id, index: i, type: i === 0 ? "user" : "assistant", text: `line ${i}` }),
    ).join("\n") + "\n"
  );
}

/** Same shape, different bytes at every index: never a prefix of `transcript`. */
function forkedTranscript(id: string, lines: number): string {
  return (
    Array.from({ length: lines }, (_, i) =>
      JSON.stringify({ sessionId: id, index: i, type: "assistant", text: `FORK ${i}` }),
    ).join("\n") + "\n"
  );
}

function writeSession(root: string, project: string, id: string, contents: string, mtime?: number): string {
  const dir = join(root, "projects", project);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${id}.jsonl`);
  writeFileSync(path, contents);
  // Default well outside the "actively being written" window so a merge is not
  // deferred; tests that care about live files set the mtime explicitly.
  const when = mtime ?? Date.now() - 3_600_000;
  utimesSync(path, new Date(when), new Date(when));
  return path;
}

function historyLine(sessionId: string, timestamp: number, display: string): string {
  return JSON.stringify({ display, pastedContents: {}, project: "/home/hasna", sessionId, timestamp });
}

function writeHistory(root: string, lines: string[]): void {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "history.jsonl"), lines.join("\n") + "\n");
}

function readHistory(root: string): string[] {
  const path = join(root, "history.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((line) => line.length > 0);
}

/** Every regular file under `root`, as `relative-path:sha256`, sorted. */
function treeDigest(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, rel: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        out.push(`${relPath}:symlink`);
        continue;
      }
      if (entry.isDirectory()) walk(join(dir, entry.name), relPath);
      else if (entry.isFile()) {
        out.push(`${relPath}:${createHash("sha256").update(readFileSync(join(dir, entry.name))).digest("hex")}`);
      }
    }
  };
  walk(root, "");
  return out.sort();
}

function transcriptPaths(root: string): string[] {
  return treeDigest(root)
    .map((line) => line.slice(0, line.lastIndexOf(":")))
    .filter((path) => path.endsWith(".jsonl"));
}

function sourceReport(report: SessionMergeReport, profile: string) {
  const found = report.sources.find((source) => source.profile === profile);
  if (!found) throw new Error(`no source report for ${profile}: ${report.sources.map((s) => s.profile).join(",")}`);
  return found;
}

/**
 * A registered profile in the state every profile on a real machine is in: it
 * predates session sharing, so it owns a real `projects/` and `history.jsonl`.
 * `addProfile` links them straight away now, which is only true of new profiles
 * — undoing that here is what makes these tests exercise the migration.
 */
function registerProfile(name: string): string {
  const dir = addProfile({ name, tool: "claude", email: `${name}@example.com` }).dir;
  for (const entry of ["projects", "history.jsonl"]) {
    const path = join(dir, entry);
    if (lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) rmSync(path);
  }
  mkdirSync(join(dir, "projects"), { recursive: true });
  return dir;
}

/** A profile dir that exists on disk but is absent from the registry. */
function unregisteredProfile(name: string): string {
  const dir = join(profilesDir(), "claude", name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-session-merge-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
  sharedHome = join(home, "shared-claude");
  mkdirSync(join(sharedHome, "skills"), { recursive: true });
  mkdirSync(join(sharedHome, "agents"), { recursive: true });
  mkdirSync(join(sharedHome, "projects"), { recursive: true });
  process.env.ACCOUNTS_SHARED_HOME_CLAUDE = sharedHome;
});

afterEach(() => {
  delete process.env.ACCOUNTS_SHARED_HOME_CLAUDE;
  delete process.env.ACCOUNTS_HOME;
  rmSync(home, { recursive: true, force: true });
});

test("copies a transcript the shared home does not have", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(1), transcript(uuid(1), 3));

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").merged).toBe(1);
  const landed = join(sharedHome, "projects", PROJECT_A, `${uuid(1)}.jsonl`);
  expect(existsSync(landed)).toBe(true);
  expect(readFileSync(landed, "utf8")).toBe(transcript(uuid(1), 3));
});

test("leaves a byte-identical transcript alone and does not duplicate it", () => {
  const dir = registerProfile("alpha");
  const body = transcript(uuid(2), 4);
  writeSession(dir, PROJECT_A, uuid(2), body);
  writeSession(sharedHome, PROJECT_A, uuid(2), body);

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").identical).toBe(1);
  expect(sourceReport(report, "alpha").merged).toBe(0);
  expect(transcriptPaths(join(sharedHome, "projects"))).toEqual([`${PROJECT_A}/${uuid(2)}.jsonl`]);
});

test("keeps BOTH copies when the same session id holds different bytes", () => {
  // The positive control for "never destructive": a planted divergent duplicate.
  // If the merge overwrote or skipped, one of these two bodies would be gone.
  const dir = registerProfile("alpha");
  const profileBody = forkedTranscript(uuid(3), 9);
  const sharedBody = transcript(uuid(3), 4);
  writeSession(dir, PROJECT_A, uuid(3), profileBody);
  writeSession(sharedHome, PROJECT_A, uuid(3), sharedBody);

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").divergent).toBe(1);
  const canonical = join(sharedHome, "projects", PROJECT_A, `${uuid(3)}.jsonl`);
  expect(readFileSync(canonical, "utf8")).toBe(sharedBody);

  const bodies = readdirSync(join(sharedHome, "projects", PROJECT_A)).map((name) =>
    readFileSync(join(sharedHome, "projects", PROJECT_A, name), "utf8"),
  );
  expect(bodies).toContain(sharedBody);
  expect(bodies).toContain(profileBody);
  // And the source is untouched.
  expect(readFileSync(join(dir, "projects", PROJECT_A, `${uuid(3)}.jsonl`), "utf8")).toBe(profileBody);
});

test("a second run copies nothing and leaves the shared tree byte-identical", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(4), transcript(uuid(4), 3));
  writeSession(dir, PROJECT_A, uuid(5), transcript(uuid(5), 3));
  writeSession(sharedHome, PROJECT_A, uuid(5), transcript(uuid(5), 8));
  writeHistory(dir, [historyLine(uuid(4), 1000, "first")]);

  mergeClaudeSessions({ link: false });
  const afterFirst = treeDigest(sharedHome);

  const second = mergeClaudeSessions({ link: false });

  expect(sourceReport(second, "alpha").merged).toBe(0);
  expect(sourceReport(second, "alpha").alreadyMerged).toBe(1);
  // The shared copy already contains this one, so there is nothing to add and
  // nothing to write.
  expect(sourceReport(second, "alpha").contained).toBe(1);
  expect(treeDigest(sharedHome)).toEqual(afterFirst);
});

test("a re-run picks up transcripts written after the previous run", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(6), transcript(uuid(6), 3));
  mergeClaudeSessions({ link: false });

  writeSession(dir, PROJECT_B, uuid(7), transcript(uuid(7), 3));
  const second = mergeClaudeSessions({ link: false });

  expect(sourceReport(second, "alpha").merged).toBe(1);
  expect(existsSync(join(sharedHome, "projects", PROJECT_B, `${uuid(7)}.jsonl`))).toBe(true);
});

test("never removes or rewrites a source file", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(8), transcript(uuid(8), 3));
  writeSession(dir, PROJECT_A, uuid(9), transcript(uuid(9), 3));
  writeSession(sharedHome, PROJECT_A, uuid(9), transcript(uuid(9), 7));
  writeHistory(dir, [historyLine(uuid(8), 10, "a")]);
  const before = treeDigest(dir);

  mergeClaudeSessions({ link: false });

  expect(treeDigest(dir)).toEqual(before);
});

test("merges history.jsonl as a deduped union ordered by timestamp", () => {
  const dir = registerProfile("alpha");
  const other = registerProfile("beta");
  const shared = historyLine(uuid(11), 3000, "shared only");
  const both = historyLine(uuid(12), 2000, "in both");
  const alphaOnly = historyLine(uuid(13), 1000, "alpha only");
  const betaOnly = historyLine(uuid(14), 4000, "beta only");
  writeHistory(sharedHome, [shared, both]);
  writeHistory(dir, [both, alphaOnly]);
  writeHistory(other, [betaOnly]);

  const report = mergeClaudeSessions({ link: false });

  expect(readHistory(sharedHome)).toEqual([alphaOnly, both, shared, betaOnly]);
  expect(report.history.recordsAfter).toBe(4);
});

test("preserves a history line that is not parseable JSON", () => {
  const dir = registerProfile("alpha");
  writeHistory(sharedHome, [historyLine(uuid(15), 1000, "ok")]);
  writeFileSync(join(dir, "history.jsonl"), `{"display":"truncated"\n`);

  mergeClaudeSessions({ link: false });

  const lines = readHistory(sharedHome);
  expect(lines).toContain(`{"display":"truncated"`);
  expect(lines).toHaveLength(2);
});

test("merges nested non-transcript files at any depth", () => {
  const dir = registerProfile("alpha");
  const nested = join(dir, "projects", PROJECT_A, "memory", "notes");
  mkdirSync(nested, { recursive: true });
  writeFileSync(join(nested, "MEMORY.md"), "# notes\n");
  writeFileSync(join(dir, "projects", PROJECT_A, "attachment.pdf"), Buffer.from([0x25, 0x50, 0x44, 0x46, 0x00, 0xff]));

  mergeClaudeSessions({ link: false });

  expect(readFileSync(join(sharedHome, "projects", PROJECT_A, "memory", "notes", "MEMORY.md"), "utf8")).toBe("# notes\n");
  expect([...readFileSync(join(sharedHome, "projects", PROJECT_A, "attachment.pdf"))]).toEqual([
    0x25, 0x50, 0x44, 0x46, 0x00, 0xff,
  ]);
});

test("never touches live per-process session state", () => {
  const dir = registerProfile("alpha");
  mkdirSync(join(dir, "sessions"), { recursive: true });
  writeFileSync(join(dir, "sessions", "147698.json"), JSON.stringify({ pid: 147698, status: "busy" }));
  writeSession(dir, PROJECT_A, uuid(16), transcript(uuid(16), 2));

  mergeClaudeSessions({ link: true });

  expect(existsSync(join(sharedHome, "sessions"))).toBe(false);
  expect(lstatSync(join(dir, "sessions")).isDirectory()).toBe(true);
  expect(lstatSync(join(dir, "sessions")).isSymbolicLink()).toBe(false);
});

test("a dry run reports the work without writing anything", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(17), transcript(uuid(17), 3));
  writeHistory(dir, [historyLine(uuid(17), 1000, "a")]);
  const sharedBefore = treeDigest(sharedHome);
  const profileBefore = treeDigest(dir);

  const report = mergeClaudeSessions({ dryRun: true, link: true });

  expect(report.dryRun).toBe(true);
  expect(sourceReport(report, "alpha").merged).toBe(1);
  expect(sourceReport(report, "alpha").linkState).toBe("dry-run");
  expect(treeDigest(sharedHome)).toEqual(sharedBefore);
  expect(treeDigest(dir)).toEqual(profileBefore);
});

test("links a registered profile after merging and retains the original tree", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(18), transcript(uuid(18), 3));
  writeHistory(dir, [historyLine(uuid(18), 1000, "a")]);

  const report = mergeClaudeSessions({ link: true });
  const source = sourceReport(report, "alpha");

  expect(source.linkState).toBe("linked");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(true);
  expect(realpathSync(join(dir, "projects"))).toBe(realpathSync(join(sharedHome, "projects")));
  expect(lstatSync(join(dir, "history.jsonl")).isSymbolicLink()).toBe(true);
  expect(realpathSync(join(dir, "history.jsonl"))).toBe(realpathSync(join(sharedHome, "history.jsonl")));

  // The originals are moved aside, never deleted.
  expect(source.retainedAt).toBeDefined();
  expect(readFileSync(join(source.retainedAt!, "projects", PROJECT_A, `${uuid(18)}.jsonl`), "utf8")).toBe(
    transcript(uuid(18), 3),
  );
  expect(existsSync(join(source.retainedAt!, "history.jsonl"))).toBe(true);
});

test("a second link run leaves an already-linked profile alone", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(19), transcript(uuid(19), 3));
  mergeClaudeSessions({ link: true });
  const digest = treeDigest(sharedHome);

  const second = mergeClaudeSessions({ link: true });

  expect(sourceReport(second, "alpha").linkState).toBe("already-linked");
  expect(treeDigest(sharedHome)).toEqual(digest);
});

test("merges an unregistered profile dir but never links it", () => {
  const dir = unregisteredProfile("account088");
  writeSession(dir, PROJECT_B, uuid(20), transcript(uuid(20), 5));

  const report = mergeClaudeSessions({ link: true });
  const source = sourceReport(report, "account088");

  expect(source.registered).toBe(false);
  expect(source.merged).toBe(1);
  expect(source.linkState).toBe("skipped-unregistered");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);
  expect(existsSync(join(sharedHome, "projects", PROJECT_B, `${uuid(20)}.jsonl`))).toBe(true);
});

test("refuses to link a profile whose transcripts are not all accounted for", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(21), transcript(uuid(21), 3));
  // A symlink inside the tree is reported rather than followed, so something
  // under this profile is not represented in the shared home.
  symlinkSync(join(home, "elsewhere.jsonl"), join(dir, "projects", PROJECT_A, "linked.jsonl"));

  const report = mergeClaudeSessions({ link: true });

  expect(sourceReport(report, "alpha").linkState).toBe("skipped-unverified");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);
});

test("reports transcript counts before and after and asserts the total never shrinks", () => {
  const dir = registerProfile("alpha");
  writeSession(sharedHome, PROJECT_A, uuid(22), transcript(uuid(22), 3));
  writeSession(dir, PROJECT_A, uuid(23), transcript(uuid(23), 3));

  const report = mergeClaudeSessions({ link: false });

  expect(report.sharedTranscriptsBefore).toBe(1);
  expect(report.sharedTranscriptsAfter).toBe(2);
  expect(sourceReport(report, "alpha").transcriptsBefore).toBe(1);
  expect(report.totalTranscriptsAfter).toBeGreaterThanOrEqual(report.totalTranscriptsBefore);
  expect(report.verification.passed).toBe(true);
});

test("only the requested profile is merged when one is named", () => {
  const alpha = registerProfile("alpha");
  const beta = registerProfile("beta");
  writeSession(alpha, PROJECT_A, uuid(24), transcript(uuid(24), 2));
  writeSession(beta, PROJECT_B, uuid(25), transcript(uuid(25), 2));

  const report = mergeClaudeSessions({ link: false, profile: "alpha" });

  expect(report.sources.map((source) => source.profile)).toEqual(["alpha"]);
  expect(existsSync(join(sharedHome, "projects", PROJECT_B, `${uuid(25)}.jsonl`))).toBe(false);
});

test("the shared-capability guard skips a real projects dir and links a migrated one", () => {
  // This is why migration has to come first: the guard that protects real data
  // is exactly what makes a bare `sharedEntries` addition a silent no-op.
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(26), transcript(uuid(26), 3));
  writeHistory(dir, [historyLine(uuid(26), 1000, "a")]);

  const skipped = ensureSharedCapabilities(dir, getTool("claude"));
  expect(skipped.skipped.map((entry) => entry.entry)).toContain("projects");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);

  mergeClaudeSessions({ link: true });
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(true);

  const kept = ensureSharedCapabilities(dir, getTool("claude"));
  expect(kept.kept).toContain("projects");
  expect(kept.kept).toContain("history.jsonl");
});

test("claude declares sessions as shared entries", () => {
  expect(sharedEntriesFor(getTool("claude"))).toContain("projects");
  expect(sharedEntriesFor(getTool("claude"))).toContain("history.jsonl");
  expect(sharedEntriesFor(getTool("claude"))).not.toContain("sessions");
});

test("a profile dir that is already a link into the shared home is reported, not re-merged", () => {
  const dir = registerProfile("alpha");
  rmSync(join(dir, "projects"), { recursive: true, force: true });
  symlinkSync(join(sharedHome, "projects"), join(dir, "projects"));
  writeSession(sharedHome, PROJECT_A, uuid(27), transcript(uuid(27), 3));

  const report = mergeClaudeSessions({ link: true });
  const source = sourceReport(report, "alpha");

  expect(source.merged).toBe(0);
  expect(source.identical).toBe(0);
  expect(source.linkState).toBe("already-linked");
});

test("adopts the longer transcript when the shared copy is a proven byte prefix of it", () => {
  // Transcripts are append-only, so this is the ordinary case: the same session
  // continued under one profile after a copy was taken.
  const dir = registerProfile("alpha");
  writeSession(sharedHome, PROJECT_A, uuid(30), transcript(uuid(30), 4));
  writeSession(dir, PROJECT_A, uuid(30), transcript(uuid(30), 11));

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").extended).toBe(1);
  expect(readFileSync(join(sharedHome, "projects", PROJECT_A, `${uuid(30)}.jsonl`), "utf8")).toBe(
    transcript(uuid(30), 11),
  );
  // Nothing is kept beside it, because the shorter bytes are all still there.
  expect(readdirSync(join(sharedHome, "projects", PROJECT_A))).toHaveLength(1);
});

test("keeps the shared copy when the profile's transcript is a prefix of it", () => {
  const dir = registerProfile("alpha");
  writeSession(sharedHome, PROJECT_A, uuid(31), transcript(uuid(31), 11));
  writeSession(dir, PROJECT_A, uuid(31), transcript(uuid(31), 4));
  const before = treeDigest(sharedHome);

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").contained).toBe(1);
  expect(treeDigest(sharedHome)).toEqual(before);
});

test("a difference that is not a prefix relation is never adopted", () => {
  // The negative half of the pair above: same lengths, forked content. If the
  // prefix check were a length comparison, this would silently overwrite.
  const dir = registerProfile("alpha");
  const sharedBody = transcript(uuid(32), 6);
  writeSession(sharedHome, PROJECT_A, uuid(32), sharedBody);
  writeSession(dir, PROJECT_A, uuid(32), forkedTranscript(uuid(32), 6));

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").extended).toBe(0);
  expect(sourceReport(report, "alpha").divergent).toBe(1);
  expect(readFileSync(join(sharedHome, "projects", PROJECT_A, `${uuid(32)}.jsonl`), "utf8")).toBe(sharedBody);
});

test("merges subagent and workflow transcripts nested under a session directory", () => {
  // The real layout: only a small minority of transcripts sit at the top level.
  const dir = registerProfile("alpha");
  const nested = join(dir, "projects", PROJECT_A, uuid(33), "subagents", "workflows", "wf_4fda7979");
  mkdirSync(nested, { recursive: true });
  writeFileSync(join(nested, "agent-a041774103855688b.jsonl"), transcript("agent-a04", 3));
  writeFileSync(join(nested, "journal.jsonl"), transcript("journal-wf1", 2));
  mkdirSync(join(dir, "projects", PROJECT_A, uuid(33), "subagents"), { recursive: true });
  writeFileSync(join(dir, "projects", PROJECT_A, uuid(33), "subagents", "agent-b.jsonl"), transcript("agent-b", 3));

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").merged).toBe(3);
  expect(
    readFileSync(
      join(sharedHome, "projects", PROJECT_A, uuid(33), "subagents", "workflows", "wf_4fda7979", "journal.jsonl"),
      "utf8",
    ),
  ).toBe(transcript("journal-wf1", 2));
});

test("keeps same-named files at different relative paths apart", () => {
  // `journal.jsonl` occurs at hundreds of distinct paths. Keying on the file
  // name rather than the relative path would collapse them into one file.
  const dir = registerProfile("alpha");
  const base = join(dir, "projects", PROJECT_A, uuid(34), "subagents", "workflows");
  for (const [workflow, body] of [
    ["wf_one", transcript("journal-one", 2)],
    ["wf_two", transcript("journal-two", 5)],
    ["wf_three", forkedTranscript("journal-three", 3)],
  ] as const) {
    mkdirSync(join(base, workflow), { recursive: true });
    writeFileSync(join(base, workflow, "journal.jsonl"), body);
  }

  mergeClaudeSessions({ link: false });

  const target = join(sharedHome, "projects", PROJECT_A, uuid(34), "subagents", "workflows");
  expect(readFileSync(join(target, "wf_one", "journal.jsonl"), "utf8")).toBe(transcript("journal-one", 2));
  expect(readFileSync(join(target, "wf_two", "journal.jsonl"), "utf8")).toBe(transcript("journal-two", 5));
  expect(readFileSync(join(target, "wf_three", "journal.jsonl"), "utf8")).toBe(forkedTranscript("journal-three", 3));
});

test("restores a transcript that survives only in a backup", () => {
  // Measured on the real machine: transcripts present in the pre-migration
  // backup had already been deleted from the live tree by merge time.
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(35), transcript(uuid(35), 3));
  const backup = join(home, "backup");
  mkdirSync(join(backup, "profiles"), { recursive: true });
  writeSession(join(backup, "shared-home"), PROJECT_A, uuid(36), transcript(uuid(36), 4));
  writeSession(join(backup, "profiles", "account088"), PROJECT_B, uuid(37), transcript(uuid(37), 6));

  const report = mergeClaudeSessions({ link: false, from: [backup] });

  expect(existsSync(join(sharedHome, "projects", PROJECT_A, `${uuid(36)}.jsonl`))).toBe(true);
  expect(existsSync(join(sharedHome, "projects", PROJECT_B, `${uuid(37)}.jsonl`))).toBe(true);
  expect(report.sources.map((source) => source.profile)).toContain("from:shared-home");
  expect(report.sources.map((source) => source.profile)).toContain("from:profiles-account088");
});

test("a backup source is never linked and is never written to", () => {
  registerProfile("alpha");
  const backup = join(home, "backup");
  writeSession(join(backup, "shared-home"), PROJECT_A, uuid(38), transcript(uuid(38), 4));
  const before = treeDigest(backup);

  const report = mergeClaudeSessions({ link: true, from: [backup] });

  expect(sourceReport(report, "from:shared-home").linkState).toBe("skipped-unregistered");
  expect(treeDigest(backup)).toEqual(before);
  expect(lstatSync(join(backup, "shared-home", "projects")).isSymbolicLink()).toBe(false);
});

test("merges by hardlink, so the shared home holds the very same inode", () => {
  const dir = registerProfile("alpha");
  const source = writeSession(dir, PROJECT_A, uuid(41), transcript(uuid(41), 3));

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").hardlinked).toBe(1);
  expect(sourceReport(report, "alpha").copied).toBe(0);
  const target = join(sharedHome, "projects", PROJECT_A, `${uuid(41)}.jsonl`);
  expect(statSync(target).ino).toBe(statSync(source).ino);
  expect(statSync(target).nlink).toBe(2);
});

test("a transcript still being appended to arrives whole, not as a prefix of itself", () => {
  // The reason for hardlinking rather than copying: a copy of a file being
  // appended to is truncated mid-line, and the tool's next append concatenates
  // onto the partial line. The same inode cannot be torn.
  const dir = registerProfile("alpha");
  const source = writeSession(dir, PROJECT_A, uuid(42), transcript(uuid(42), 3), Date.now());

  const report = mergeClaudeSessions({ link: false });

  expect(sourceReport(report, "alpha").merged).toBe(1);
  expect(sourceReport(report, "alpha").deferredActive).toBe(0);

  appendFileSync(source, transcript(uuid(42), 6).slice(transcript(uuid(42), 3).length));
  const target = join(sharedHome, "projects", PROJECT_A, `${uuid(42)}.jsonl`);
  expect(readFileSync(target, "utf8")).toBe(transcript(uuid(42), 6));
});

test("a re-run over hardlinked files is a pure no-op", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(43), transcript(uuid(43), 3));
  mergeClaudeSessions({ link: false });
  const digest = treeDigest(sharedHome);

  const second = mergeClaudeSessions({ link: false });

  expect(sourceReport(second, "alpha").alreadyMerged).toBe(1);
  expect(sourceReport(second, "alpha").merged).toBe(0);
  expect(treeDigest(sharedHome)).toEqual(digest);
});

test("restores the original and reports rolled-back when the swap cannot complete", () => {
  // The failure this guards against: a profile left with no `projects/` at all.
  // The tool recreates it as a real directory, `shareEntry` then refuses to
  // replace it, and doctor reports that only as a warning — silently de-shared.
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(44), transcript(uuid(44), 3));
  mergeClaudeSessions({ link: false });
  chmodSync(dir, 0o500);
  try {
    const report = mergeClaudeSessions({ link: true });
    expect(sourceReport(report, "alpha").linkState).toBe("rolled-back");
  } finally {
    chmodSync(dir, 0o700);
  }
  expect(lstatSync(join(dir, "projects")).isDirectory()).toBe(true);
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);
  expect(readFileSync(join(dir, "projects", PROJECT_A, `${uuid(44)}.jsonl`), "utf8")).toBe(transcript(uuid(44), 3));
});

test("refuses a source path with a trailing separator", () => {
  registerProfile("alpha");
  const backup = join(home, "backup");
  writeSession(join(backup, "shared-home"), PROJECT_A, uuid(45), transcript(uuid(45), 2));

  // `rm -rf "$link/"` traverses the link and deletes the shared corpus, where
  // `rm -rf "$link"` only unlinks it. The trailing separator is the whole
  // difference, so it is refused rather than quietly normalised away.
  expect(() => mergeClaudeSessions({ link: false, from: [`${backup}/`] })).toThrow(/trailing|separator/i);
});

test("the corpus floor notices transcripts deleted deep inside the session tree", () => {
  // The existing floor counts top-level entries. For `projects/` that is one
  // directory per project, so every transcript inside them could be deleted
  // without the count moving. This is the planted-defect control for that.
  const dir = registerProfile("alpha");
  writeSession(dir, PROJECT_A, uuid(46), transcript(uuid(46), 3));
  writeSession(dir, PROJECT_A, uuid(47), transcript(uuid(47), 3));
  const report = mergeClaudeSessions({ link: true });
  expect(sourceReport(report, "alpha").linkState).toBe("linked");

  const healthy = sharedCapabilityHealth(dir, getTool("claude"));
  expect(healthy.problems).toEqual([]);

  // The project directory survives; only its contents are destroyed.
  rmSync(join(sharedHome, "projects", PROJECT_A, `${uuid(46)}.jsonl`));
  rmSync(join(sharedHome, "projects", PROJECT_A, `${uuid(47)}.jsonl`));

  const damaged = sharedCapabilityHealth(dir, getTool("claude"));
  expect(damaged.problems.join("\n")).toContain("projects corpus has shrunk");
});

test("repairs history that is out of ascending timestamp order", () => {
  // The tool navigates history by its ascending timestamps, so ordering is part
  // of the file being correct — not only which records it holds.
  const dir = registerProfile("alpha");
  writeHistory(sharedHome, [historyLine(uuid(48), 3000, "late"), historyLine(uuid(49), 1000, "early")]);
  writeHistory(dir, [historyLine(uuid(48), 3000, "late")]);

  const report = mergeClaudeSessions({ link: false });

  expect(report.history.recordsAfter).toBe(2);
  expect(report.history.ascending).toBe(true);
  expect(readHistory(sharedHome)).toEqual([historyLine(uuid(49), 1000, "early"), historyLine(uuid(48), 3000, "late")]);
});

test("history is not rewritten when the union already matches the file", () => {
  const dir = registerProfile("alpha");
  const lines = [historyLine(uuid(50), 1000, "a"), historyLine(uuid(51), 2000, "b")];
  writeHistory(sharedHome, lines);
  writeHistory(dir, [lines[0]!]);
  const before = treeDigest(sharedHome);

  mergeClaudeSessions({ link: false });

  expect(treeDigest(sharedHome)).toEqual(before);
});
