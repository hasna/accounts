import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const sourceRoot = resolve(
  process.argv[2] ?? "/home/hasna/worktrees/infinity-planning-contract",
);
const repositoryRoot = resolve(import.meta.dir, "..");
const sourceCommit = "80054c36b10111765a18b89743214679c58ad7c6";
const sourcePaths = {
  contract: "workstreams/accounts-v1-contract-662842e91a4b58475b92f28eec8caeead4cd7955a485f3d20b16032ab4fa9167.md",
  redteam: "workstreams/accounts-v1-redteam-24b05c49676a9d0d8bed430619942997de2a8d6eaf6f481536d5cc5fdc33b3b4.md",
  trace: "contracts/accounts-v1-successor-v11-transition-traces.json",
  pin: "workstreams/accounts-v1-successor-v11-pin-33e19b22cb6c1687f8f85e883e73bf1ecdec88b75eccd5203d16a7f9ff2d93dc.json",
} as const;

const expected = {
  contract: "662842e91a4b58475b92f28eec8caeead4cd7955a485f3d20b16032ab4fa9167",
  redteam: "24b05c49676a9d0d8bed430619942997de2a8d6eaf6f481536d5cc5fdc33b3b4",
  trace: "763fc966acc32d1585ac96ad45051577e50b63f3cf11a78bdee5bdf8be9b1873",
  pin: "33e19b22cb6c1687f8f85e883e73bf1ecdec88b75eccd5203d16a7f9ff2d93dc",
} as const;

function readSource(path: string): Uint8Array {
  const result = Bun.spawnSync([
    "git",
    "-C",
    sourceRoot,
    "show",
    `${sourceCommit}:${path}`,
  ]);
  if (result.exitCode !== 0) {
    throw new Error(`failed to read pinned source ${path}`);
  }
  return result.stdout;
}

const sources = Object.fromEntries(
  Object.entries(sourcePaths).map(([kind, path]) => [kind, readSource(path)]),
) as Record<keyof typeof sourcePaths, Uint8Array>;
for (const [kind, bytes] of Object.entries(sources)) {
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected[kind as keyof typeof expected]) {
    throw new Error(`${kind} hash mismatch: ${actual}`);
  }
}

const document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(sources.trace)) as {
  schema_version: string;
  contract_ref: string;
  signer_history: unknown;
  wire_fixtures: Record<string, unknown>;
};
const selectedNames = Object.keys(document.wire_fixtures)
  .filter((name) => name.startsWith("slot_eligibility_") || name.startsWith("online_generation_check_"))
  .sort();
const selectedFixtures = Object.fromEntries(
  selectedNames.map((name) => [name, document.wire_fixtures[name]]),
);
const destination = resolve(repositoryRoot, "contracts/accounts-v10");
await mkdir(destination, { recursive: true, mode: 0o755 });
await Bun.write(
  resolve(destination, "acc-041-fixtures.json"),
  `${JSON.stringify({
    source_commit: sourceCommit,
    source_trace_sha256: expected.trace,
    schema_version: document.schema_version,
    contract_ref: document.contract_ref,
    signer_history: document.signer_history,
    wire_fixtures: selectedFixtures,
  }, null, 2)}\n`,
);
await Bun.write(
  resolve(destination, "pin.json"),
  `${JSON.stringify({
    schema_version: "accounts.runtime-contract-pin/v1",
    source_commit: sourceCommit,
    accounts_source_commit: "7873b8b6bae5d4a388a34add2feaea612bbaa4ee",
    contract_sha256: expected.contract,
    redteam_sha256: expected.redteam,
    transition_trace_sha256: expected.trace,
    review_pin_sha256: expected.pin,
    implementation_status: "IN_PROGRESS",
    integration_authorized: false,
    publish_authorized: false,
    deploy_authorized: false,
  }, null, 2)}\n`,
);
