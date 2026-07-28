import { test, expect, beforeEach, afterEach } from "bun:test";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  renameSync,
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
import { sharedCapabilityHealth } from "./lib/shared-capabilities.js";
import { mergeClaudeSessions, type SessionMergeReport } from "./lib/session-merge.js";

let home: string;
let sharedHome: string;

const PROJECT = "-home-hasna-workspace-alpha";

function uuid(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
}

function transcript(id: string, lines: number): string {
  return (
    Array.from({ length: lines }, (_, i) => JSON.stringify({ sessionId: id, index: i, text: `line ${i}` })).join("\n") +
    "\n"
  );
}

function writeSession(root: string, id: string, contents: string, mtime?: number): string {
  const dir = join(root, "projects", PROJECT);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${id}.jsonl`);
  writeFileSync(path, contents);
  const when = mtime ?? Date.now() - 3_600_000;
  utimesSync(path, new Date(when), new Date(when));
  return path;
}

function historyLine(sessionId: string, timestamp: number, display: string): string {
  return JSON.stringify({ display, pastedContents: {}, project: "/home/hasna", sessionId, timestamp });
}

function writeHistory(root: string, lines: string[]): string {
  mkdirSync(root, { recursive: true });
  const path = join(root, "history.jsonl");
  writeFileSync(path, lines.join("\n") + "\n");
  return path;
}

function registerProfile(name: string): string {
  const dir = addProfile({ name, tool: "claude", email: `${name}@example.com` }).dir;
  for (const entry of ["projects", "history.jsonl"]) {
    const path = join(dir, entry);
    if (lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) rmSync(path);
  }
  mkdirSync(join(dir, "projects"), { recursive: true });
  return dir;
}

function sourceReport(report: SessionMergeReport, profile: string) {
  return report.sources.find((source) => source.profile === profile)!;
}

function countJsonl(root: string): number {
  let total = 0;
  const walk = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(join(dir, entry.name));
      else if (entry.name.endsWith(".jsonl")) total += 1;
    }
  };
  walk(root);
  return total;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-guards-"));
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

// --- D1 ---------------------------------------------------------------------

test("D1: a source replaced between the prefix proof and the swap never overwrites the shared copy", () => {
  // The prefix was proved on bytes read from one inode. `mv` over the source
  // puts a DIFFERENT inode at that path; linking it into place would publish
  // content that was never proved to contain the shared copy.
  const dir = registerProfile("alpha");
  const sharedBody = transcript(uuid(1), 40);
  writeSession(sharedHome, uuid(1), sharedBody);
  const sourcePath = writeSession(dir, uuid(1), transcript(uuid(1), 60));

  const impostor = join(home, "impostor.jsonl");
  writeFileSync(impostor, "x\n");
  utimesSync(impostor, new Date(Date.now() - 3_600_000), new Date(Date.now() - 3_600_000));

  const report = mergeClaudeSessions({
    link: false,
    onBeforeSwap: () => {
      renameSync(impostor, sourcePath);
    },
  });

  const shared = readFileSync(join(sharedHome, "projects", PROJECT, `${uuid(1)}.jsonl`), "utf8");
  expect(shared.length).toBeGreaterThanOrEqual(sharedBody.length);
  expect(shared).toBe(sharedBody);
  expect(sourceReport(report, "alpha").extended).toBe(0);
  expect(sourceReport(report, "alpha").deferredActive).toBe(1);
});

// --- D2 ---------------------------------------------------------------------

test("D2: an unreadable shared history is never treated as empty and never overwritten", () => {
  const dir = registerProfile("alpha");
  const sharedHistory = writeHistory(sharedHome, [
    historyLine(uuid(2), 1000, "keep me"),
    historyLine(uuid(3), 2000, "keep me too"),
  ]);
  const before = readFileSync(sharedHistory, "utf8");
  writeHistory(dir, [historyLine(uuid(4), 3000, "incoming")]);
  chmodSync(sharedHistory, 0o000);

  let report: SessionMergeReport;
  try {
    report = mergeClaudeSessions({ link: true });
  } finally {
    chmodSync(sharedHistory, 0o600);
  }

  expect(readFileSync(sharedHistory, "utf8")).toBe(before);
  expect(report.verification.passed).toBe(false);
  expect(report.errors.join("\n")).toMatch(/history/i);
});

test("D2: an unreadable source history blocks that profile from being linked", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(5), transcript(uuid(5), 3));
  const sourceHistory = writeHistory(dir, [historyLine(uuid(5), 1000, "mine")]);
  chmodSync(sourceHistory, 0o000);

  let report: SessionMergeReport;
  try {
    report = mergeClaudeSessions({ link: true });
  } finally {
    chmodSync(sourceHistory, 0o600);
  }

  expect(sourceReport(report, "alpha").linkState).toBe("skipped-unverified");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);
});

// --- D3 ---------------------------------------------------------------------

test("D3: verification fails when a merged transcript disappears from the shared home mid-run", () => {
  // Double-counting each hardlink across source and shared gave the old floor
  // ~100% slack, so a single loss could never move it.
  const dir = registerProfile("alpha");
  for (const n of [10, 11, 12, 13]) writeSession(dir, uuid(n), transcript(uuid(n), 3));

  const report = mergeClaudeSessions({
    link: true,
    onAfterMerge: () => {
      rmSync(join(sharedHome, "projects", PROJECT, `${uuid(10)}.jsonl`));
    },
  });

  expect(report.verification.passed).toBe(false);
  expect(sourceReport(report, "alpha").linkState).toBe("skipped-unverified");
});

test("D3: the shared corpus is re-counted after the link step, not only before it", () => {
  const dir = registerProfile("alpha");
  for (const n of [14, 15, 16]) writeSession(dir, uuid(n), transcript(uuid(n), 3));

  const report = mergeClaudeSessions({
    link: true,
    onAfterLink: () => {
      rmSync(join(sharedHome, "projects", PROJECT, `${uuid(14)}.jsonl`));
    },
  });

  expect(report.verification.passed).toBe(false);
  expect(report.verification.detail ?? "").toMatch(/after linking|post-link/i);
});

// --- D4 ---------------------------------------------------------------------

test("D4: a transcript created during the run is merged, not stranded behind the link", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(20), transcript(uuid(20), 3));

  const report = mergeClaudeSessions({
    link: true,
    // Written after the walk, before the swap — the whole run is the window.
    onBeforeLink: () => {
      writeSession(dir, uuid(21), transcript(uuid(21), 5));
    },
  });

  expect(sourceReport(report, "alpha").linkState).toBe("linked");
  // Reachable through the profile, which is now the shared corpus.
  expect(existsSync(join(dir, "projects", PROJECT, `${uuid(21)}.jsonl`))).toBe(true);
  expect(existsSync(join(sharedHome, "projects", PROJECT, `${uuid(21)}.jsonl`))).toBe(true);
});

// --- D5 ---------------------------------------------------------------------

test("D5: a rollback that cannot restore the original says so instead of reporting success", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(30), transcript(uuid(30), 3));
  writeHistory(dir, [historyLine(uuid(30), 1000, "a")]);

  const report = mergeClaudeSessions({
    link: true,
    // The shared corpus is emptied after verification but before the swap, so
    // the link cannot resolve to the expected corpus and must be rolled back…
    onBeforeLink: () => {
      rmSync(join(sharedHome, "projects", PROJECT, `${uuid(30)}.jsonl`));
    },
    // …and a live writer recreates `projects/` in that window, so the retained
    // original can no longer be renamed back.
    onRollback: () => {
      mkdirSync(join(dir, "projects"), { recursive: true });
    },
  });

  const source = sourceReport(report, "alpha");
  expect(source.linkState).toBe("restore-failed");
  expect(source.errors.join("\n")).toMatch(/could not restore|restore failed/i);
});

// --- D6 ---------------------------------------------------------------------

test("D6: a de-shared session entry is a problem, not a warning", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(40), transcript(uuid(40), 3));
  writeHistory(dir, [historyLine(uuid(40), 1000, "a")]);
  expect(sourceReport(mergeClaudeSessions({ link: true }), "alpha").linkState).toBe("linked");

  // The tool recreates a real directory after the link is lost.
  rmSync(join(dir, "projects"));
  mkdirSync(join(dir, "projects"), { recursive: true });

  const health = sharedCapabilityHealth(dir, getTool("claude"));
  expect(health.entries.find((entry) => entry.entry === "projects")!.status).toBe("local");
  expect(health.problems.join("\n")).toContain("projects");
});

// --- intra-tree symlinks ----------------------------------------------------

test("reproduces the symlinks Claude Code creates inside the session tree", () => {
  // Measured on the real corpus: forked/resumed subagent transcripts are
  // symlinks inside `projects/`. Reporting them as unaccounted made the largest
  // profile permanently ineligible for linking.
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(50), transcript(uuid(50), 4));
  const linkPath = join(dir, "projects", PROJECT, `${uuid(51)}.jsonl`);
  symlinkSync(join(dir, "projects", PROJECT, `${uuid(50)}.jsonl`), linkPath);

  const report = mergeClaudeSessions({ link: true });
  const source = sourceReport(report, "alpha");

  expect(source.unaccounted).toBe(0);
  expect(source.linkState).toBe("linked");
  const target = join(sharedHome, "projects", PROJECT, `${uuid(51)}.jsonl`);
  expect(lstatSync(target).isSymbolicLink()).toBe(true);
  // Rewritten relative so the corpus stays portable, and it still resolves.
  expect(readlinkSync(target).startsWith("/")).toBe(false);
  expect(readFileSync(target, "utf8")).toBe(transcript(uuid(50), 4));
});

test("a symlink pointing outside the session tree is reported, never reproduced", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(52), transcript(uuid(52), 3));
  const outside = join(home, "outside.jsonl");
  writeFileSync(outside, "not part of the corpus\n");
  symlinkSync(outside, join(dir, "projects", PROJECT, `${uuid(53)}.jsonl`));

  const report = mergeClaudeSessions({ link: true });
  const source = sourceReport(report, "alpha");

  expect(existsSync(join(sharedHome, "projects", PROJECT, `${uuid(53)}.jsonl`))).toBe(false);
  expect(source.linkState).toBe("skipped-unverified");
  expect(source.errors.join("\n")).toMatch(/outside/i);
});

// --- concurrency ------------------------------------------------------------

test("a second merge refuses to run while one holds the lock", () => {
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(60), transcript(uuid(60), 3));

  let inner: unknown;
  mergeClaudeSessions({
    link: false,
    onAfterMerge: () => {
      try {
        mergeClaudeSessions({ link: false });
      } catch (err) {
        inner = err;
      }
    },
  });

  expect(String(inner)).toMatch(/in progress|lock/i);
});

// --- dry-run honesty --------------------------------------------------------

test("a dry run says its collision counts are approximate", () => {
  const alpha = registerProfile("alpha");
  const beta = registerProfile("beta");
  writeSession(alpha, uuid(70), transcript(uuid(70), 3));
  writeSession(beta, uuid(70), transcript(uuid(70), 9));

  const report = mergeClaudeSessions({ dryRun: true, link: false });

  // Nothing is placed, so the second source is compared against a tree that
  // never received the first — merged is an upper bound, divergent a lower one.
  expect(report.approximate).toBe(true);
  expect(countJsonl(join(sharedHome, "projects"))).toBe(0);
});

test("eligibility comes from the caller's registry, not always the on-box file", () => {
  // This machine can be pointed at a self-hosted registry, in which case the
  // on-box accounts.json is empty. Reading it unconditionally would classify
  // every profile as unregistered and silently link nothing at all.
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(80), transcript(uuid(80), 3));

  const ignored = mergeClaudeSessions({ link: true, profiles: [] });
  expect(sourceReport(ignored, "alpha").registered).toBe(false);
  expect(sourceReport(ignored, "alpha").linkState).toBe("skipped-unregistered");
  expect(lstatSync(join(dir, "projects")).isSymbolicLink()).toBe(false);

  const supplied = mergeClaudeSessions({
    link: true,
    profiles: [{ name: "alpha", tool: "claude", dir, email: "alpha@example.com" }],
  });
  expect(sourceReport(supplied, "alpha").registered).toBe(true);
  expect(sourceReport(supplied, "alpha").linkState).toBe("linked");
});

test("a dry run is not held to a growth floor it cannot meet", () => {
  // Nothing is placed, so requiring the shared tree to have grown by the merge
  // count fails every dry run and reports a loss that never happened.
  const dir = registerProfile("alpha");
  writeSession(dir, uuid(81), transcript(uuid(81), 3));

  const report = mergeClaudeSessions({ dryRun: true, link: true });

  expect(sourceReport(report, "alpha").merged).toBe(1);
  expect(report.verification.passed).toBe(true);
});
