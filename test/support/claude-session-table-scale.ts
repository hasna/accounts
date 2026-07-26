// Formats a synthetic catalog of `argv[2]` rows and prints the resulting line
// count. Bundled with `--target node` and run under real node, because that is
// the engine the published `accounts` binary uses and its call arity ceiling is
// a fraction of Bun's: a table formatter that spreads one argument per row dies
// here at a catalog size `bun test` would still format happily.
import { formatClaudeSessionTable } from "../../src/lib/claude-sessions-cli.js";
import type { ClaudeSessionCatalogEntry } from "../../src/lib/claude-sessions.js";

const count = Number(process.argv[2]);
if (!Number.isSafeInteger(count) || count < 1) throw new Error(`bad row count: ${process.argv[2]}`);

// Keep the run from going quietly tautological. The row count only proves
// anything while it is above this engine's call arity ceiling, so if a future
// node can spread that many arguments, fail loudly and raise the count instead.
function spreadOverflows(size: number): boolean {
  try {
    Math.max(0, ...new Array<number>(size).fill(0));
    return false;
  } catch (error) {
    return error instanceof RangeError;
  }
}

if (!spreadOverflows(count)) {
  throw new Error(`${count} arguments no longer overflow a spread here; raise the row count`);
}

// Rows share one identity object: the table reads only the flattened columns,
// and a distinct identity per row would dominate the harness's memory.
const identity = {
  ownerProfile: "bulk",
  profileIdentity: "/profiles/bulk",
  profilePath: "/profiles/bulk",
  encodedProject: "-bulk",
  projectIdentity: "/repo-bulk",
  uuid: "00000000-0000-4000-8000-000000000000",
  sourcePath: "/profiles/bulk/projects/-bulk/session.jsonl",
};

function entry(index: number): ClaudeSessionCatalogEntry {
  const uuid = `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
  return {
    identity,
    catalogRef: `claude-session:v1:${index}`,
    ownerProfile: "bulk",
    profileIdentity: "/profiles/bulk",
    profilePath: "/profiles/bulk",
    encodedProject: "-bulk",
    projectIdentity: "/repo-bulk",
    cwd: "/repo-bulk",
    uuid,
    sourcePath: `/profiles/bulk/projects/-bulk/${uuid}.jsonl`,
    sessionIdCheck: "bounded-match",
    sizeBytes: index,
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}

const table = formatClaudeSessionTable(Array.from({ length: count }, (_, index) => entry(index)));
process.stdout.write(`${table.split("\n").length}\n`);
