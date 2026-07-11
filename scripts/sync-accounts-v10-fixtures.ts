import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const sourceRoot = resolve(
  process.argv[2] ?? "/home/hasna/worktrees/infinity-planning-contract",
);
const repositoryRoot = resolve(import.meta.dir, "..");
const contractPath = resolve(
  sourceRoot,
  "workstreams/accounts-v1-contract-eda1c92990d3562a81128a5bd455fdfc32be6b7170820f9519aae611af0a8bdc.md",
);
const tracePath = resolve(sourceRoot, "contracts/accounts-v1-successor-v10-transition-traces.json");
const pinPath = resolve(
  sourceRoot,
  "workstreams/accounts-v1-successor-v10-pin-747fe2d723f6dbaa28afbc37e40528549235168f2ebe9da45cec3e733222f0f7.json",
);

const expected = {
  contract: "eda1c92990d3562a81128a5bd455fdfc32be6b7170820f9519aae611af0a8bdc",
  trace: "d9b0d556c2e937f75a7557a2454dae19f1f39cece3d53fed976de7585e0bf0a4",
  pin: "747fe2d723f6dbaa28afbc37e40528549235168f2ebe9da45cec3e733222f0f7",
} as const;

async function sha256(path: string): Promise<string> {
  return createHash("sha256").update(await Bun.file(path).arrayBuffer()).digest("hex");
}

for (const [kind, path] of Object.entries({ contract: contractPath, trace: tracePath, pin: pinPath })) {
  const actual = await sha256(path);
  if (actual !== expected[kind as keyof typeof expected]) {
    throw new Error(`${kind} hash mismatch: ${actual}`);
  }
}

const document = await Bun.file(tracePath).json() as {
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
    source_commit: "f5f2aee8bb8a6d361c7c89a725e3c4cf4cf4553e",
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
    source_commit: "f5f2aee8bb8a6d361c7c89a725e3c4cf4cf4553e",
    accounts_source_commit: "7873b8b6bae5d4a388a34add2feaea612bbaa4ee",
    contract_sha256: expected.contract,
    redteam_sha256: "969f7e71343c7a6732530f31f64343b12afde851688ea18a3d2eeaf1a491ba15",
    transition_trace_sha256: expected.trace,
    review_pin_sha256: expected.pin,
    implementation_status: "IN_PROGRESS",
    integration_authorized: false,
    publish_authorized: false,
    deploy_authorized: false,
  }, null, 2)}\n`,
);
