#!/usr/bin/env node

// Asserts the runner resolved the pinned toolchain declared in
// scripts/release-toolchain.json — the single source of truth shared with
// scripts/release-provenance.ts and (via a test) the workflow setup-* inputs.
//
// Dependency-free on purpose: this runs before `bun install`, and it reports
// every mismatch at once with a self-describing message, so a toolchain drift
// never looks like an unrelated failure in somebody else's pull request.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const pinnedPath = new URL("./release-toolchain.json", import.meta.url);
const pinned = JSON.parse(readFileSync(pinnedPath, "utf8"));

const checks = [
  { label: "Node", expected: `v${pinned.node}`, command: "node" },
  { label: "npm", expected: pinned.npm, command: "npm" },
  { label: "Bun", expected: pinned.bun, command: "bun" },
];

const failures = [];
for (const { label, expected, command } of checks) {
  if (typeof expected !== "string" || expected.length === 0) {
    failures.push(`${label}: scripts/release-toolchain.json declares no version`);
    continue;
  }
  let actual;
  try {
    actual = execFileSync(command, ["--version"], {
      encoding: "utf8",
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    failures.push(`${label}: could not run \`${command} --version\` (${error.message})`);
    continue;
  }
  if (actual !== expected) {
    failures.push(`${label}: pinned ${expected}, runner resolved ${actual}`);
  }
}

if (failures.length > 0) {
  console.error("pinned toolchain mismatch — this is a toolchain drift, not a defect in your change");
  console.error("scripts/release-toolchain.json is the single source of truth; update it (and the");
  console.error("setup-node/setup-bun inputs it is tested against) if the pin is meant to move.");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(
  `pinned toolchain verified: Node v${pinned.node}, npm ${pinned.npm}, Bun ${pinned.bun}`,
);
