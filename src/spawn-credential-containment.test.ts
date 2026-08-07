// Containment of registry authority at the tool-binary spawn boundary (todos 03dd035d).
//
// `accounts` is the TRUSTED wrapper: it legitimately holds the accounts-registry
// credential in order to resolve a profile name to a config dir. The tool binary it
// then launches is a coding agent running against an arbitrary, potentially
// prompt-injectable repository. That binary needs the config dir and nothing else,
// so the registry credential must not cross the spawn boundary.
//
// WHAT MAKES THESE TESTS NON-VACUOUS, stated because an absence assertion is the
// easiest kind of test to write in a form that cannot fail:
//
//   1. The probe reads a POPULATION, not a filter. The fake tool binary reports every
//      environment NAME it can see matching /ACCOUNTS|HASNA|SIGNING/i and never a
//      value. So a name nobody thought to deny-list still shows up in the assertion
//      diff instead of being silently outside the query.
//   2. The canary list below is written from the CONSUMERS (lib/cloud-accounts.ts,
//      server/config.ts), NOT from the deny list the fix uses. If the two were
//      derived from one source, a name missing from the deny list would be missing
//      from the test in exactly the same way, and the suite would pass while leaking.
//      ACCOUNTS_API_KEY and HASNA_API_SIGNING_KEY are the two that a naive
//      `startsWith("HASNA_ACCOUNTS")` scan does not catch.
//   3. Every absence assertion is paired with a POSITIVE CONTROL in the same spawned
//      process: CLAUDE_CONFIG_DIR must be PRESENT. A probe that reported everything
//      absent because it was broken would fail that control.
//
// No real credential is used anywhere here. Every value is a synthetic sentinel.

import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { REGISTRY_AUTHORITY_ENV_KEYS } from "./lib/env.js";

const repo = process.cwd();
const cli = join(repo, "src", "cli.ts");

let home: string;
let binDir: string;
let launchCwd: string;
let probeLog: string;

/**
 * Names an untrusted tool binary must never receive, written independently of the
 * deny list under test. Sources, so a reviewer can re-derive rather than trust:
 *   HASNA_ACCOUNTS_API_KEY / ACCOUNTS_API_KEY  -> lib/cloud-accounts.ts (deriveEnv)
 *   HASNA_ACCOUNTS_API_URL / ACCOUNTS_API_URL  -> lib/cloud-accounts.ts (deriveEnv)
 *   HASNA_ACCOUNTS_API_SIGNING_KEY             -> server/config.ts (resolveSigningSecret)
 *   HASNA_API_SIGNING_KEY                      -> server/config.ts (resolveSigningSecret)
 *   HASNA_ACCOUNTS_DATABASE_URL                -> generated/storage-kit/mode.ts
 *   ACCOUNTS_DATABASE_URL                      -> generated/storage-kit/mode.ts
 *
 * The last two are written as LITERALS here on purpose, even though the deny list
 * now derives them from storageEnvKeys("accounts").databaseUrlKeys. If the test
 * derived them the same way, a regression in that spec would remove the name from
 * BOTH sides at once and the suite would go green while leaking. The bare
 * ACCOUNTS_DATABASE_URL alias was missed by the first version of this fix and
 * found by an independent reviewer — it is a literal here so that miss cannot
 * recur silently.
 */
const INDEPENDENT_CANARIES = [
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_KEY",
  "HASNA_ACCOUNTS_API_URL",
  "ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_SIGNING_KEY",
  "HASNA_API_SIGNING_KEY",
  "HASNA_ACCOUNTS_DATABASE_URL",
  "ACCOUNTS_DATABASE_URL",
] as const;

/** Synthetic sentinels. Never a real credential; the probe never prints a value. */
const SENTINEL_ENV: Record<string, string> = {
  HASNA_ACCOUNTS_API_KEY: "synthetic-sentinel-not-a-real-key",
  ACCOUNTS_API_KEY: "synthetic-sentinel-not-a-real-key",
  HASNA_ACCOUNTS_API_URL: "https://accounts.invalid",
  ACCOUNTS_API_URL: "https://accounts.invalid",
  HASNA_ACCOUNTS_API_SIGNING_KEY: "synthetic-sentinel-signing",
  HASNA_API_SIGNING_KEY: "synthetic-sentinel-signing",
  HASNA_ACCOUNTS_DATABASE_URL: "postgres://synthetic.invalid/db",
  ACCOUNTS_DATABASE_URL: "postgres://synthetic.invalid/db",
};

function removeTestDirectory(path: string): void {
  rmSync(path, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}

/**
 * A fake tool binary that records the NAMES of environment variables it can see.
 * It deliberately dumps a population (everything matching the pattern) rather than
 * probing a fixed list, and it never reads or writes a value.
 */
function probeSource(): string {
  return `
import { writeFileSync } from "node:fs";
const names = Object.keys(process.env)
  .filter((name) => /ACCOUNTS|HASNA|SIGNING/i.test(name))
  .sort();
writeFileSync(process.env.PROBE_LOG, JSON.stringify({
  names,
  configDirPresent: Boolean(process.env.CLAUDE_CONFIG_DIR),
}));
process.exit(0);
`;
}

function writeExecutable(name: string, source: string): string {
  const script = join(binDir, `fake-${name}.ts`);
  writeFileSync(script, source);
  const wrapper = join(binDir, name);
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" run "${script}" "$@"\n`);
  chmodSync(wrapper, 0o755);
  return wrapper;
}

beforeAll(() => {
  binDir = mkdtempSync(join(tmpdir(), "accounts-containment-bin-"));
  writeExecutable("claude", probeSource());
});

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-containment-home-"));
  launchCwd = mkdtempSync(join(tmpdir(), "accounts-containment-cwd-"));
  probeLog = join(home, "probe.json");
});

afterEach(() => {
  removeTestDirectory(home);
  removeTestDirectory(launchCwd);
});

afterAll(() => {
  removeTestDirectory(binDir);
});

function baseEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "test",
    ACCOUNTS_HOME: home,
    // PIN THE STORAGE MODE EXPLICITLY rather than relying on test/setup.ts having
    // pinned it in process.env. ACCOUNTS_HOME alone does NOT isolate: in
    // lib/cloud-accounts.ts deriveEnv(), an explicit cloud/self_hosted mode is
    // checked BEFORE the home override, so an ambient
    // HASNA_ACCOUNTS_STORAGE_MODE=cloud (which is the real setting on a fleet
    // machine) wins and the sentinel API_URL below would be dialled for real.
    // Measured: with only ACCOUNTS_HOME set, `accounts add` attempts
    // https://accounts.invalid/v1/accounts and fails ConnectionRefused. An
    // explicit local mode is step 1 of deriveEnv and cannot be overridden.
    HASNA_ACCOUNTS_STORAGE_MODE: "local",
    ACCOUNTS_STORAGE_MODE: "local",
    HASNA_ACCOUNTS_MODE: "local",
    PROBE_LOG: probeLog,
    ...SENTINEL_ENV,
    ...extra,
  };
  const inheritedPath = Object.entries(process.env).find(([k]) => k.toLowerCase() === "path")?.[1] ?? "";
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === "path") delete env[key];
  }
  env.PATH = `${binDir}${delimiter}${inheritedPath}`;
  return env;
}

function runCli(args: string[], extra: Record<string, string> = {}) {
  return spawnSync(process.execPath, ["run", cli, ...args], {
    cwd: launchCwd,
    encoding: "utf8",
    env: baseEnv(extra),
  });
}

function readProbe(): { names: string[]; configDirPresent: boolean } {
  if (!existsSync(probeLog)) {
    throw new Error("the tool binary never ran — the probe produced no output, so this test proves nothing");
  }
  return JSON.parse(readFileSync(probeLog, "utf8"));
}

function createProfile(name: string): void {
  const added = runCli(["add", name, "--tool", "claude"]);
  if (added.status !== 0) {
    throw new Error(`failed to create profile: status=${added.status}\n${added.stdout}\n${added.stderr}`);
  }
  // A launch now refuses an instruction home carrying no operating rules (todos
  // OPE15-00059), and every test here has to actually SPAWN the tool binary —
  // its own probe raises "the tool binary never ran" otherwise. This test is
  // about registry-authority containment in the spawned environment, not about
  // whether an ungoverned home may start, and a profile that gets launched in
  // real use has been rendered.
  const dir = join(home, "profiles", "claude", name);
  mkdirSync(join(dir, ".hasna"), { recursive: true });
  writeFileSync(
    join(dir, ".hasna", "session-render-manifest.json"),
    JSON.stringify({
      schema: "hasna.configs.session-render/v1",
      tool: "claude",
      profile: name,
      targetHome: dir,
      generatedAt: "2026-07-01T00:00:00.000Z",
      sources: [{ id: "hasna-agent-operating-rules" }],
      files: [],
    }) + "\n",
  );
}

/**
 * The shared assertion. Absence is only meaningful next to the positive control, so
 * they are asserted together and never separately.
 */
function expectContained(probe: { names: string[]; configDirPresent: boolean }, surface: string): void {
  // POSITIVE CONTROL: the probe can see env that is legitimately forwarded. Without
  // this, a probe that saw nothing at all would report perfect containment.
  expect(probe.configDirPresent, `${surface}: CLAUDE_CONFIG_DIR must reach the tool binary`).toBe(true);

  for (const canary of INDEPENDENT_CANARIES) {
    expect(probe.names, `${surface}: ${canary} must not reach the tool binary`).not.toContain(canary);
  }
  for (const key of REGISTRY_AUTHORITY_ENV_KEYS) {
    expect(probe.names, `${surface}: ${key} must not reach the tool binary`).not.toContain(key);
  }
}

test("launch (interactive) does not hand registry authority to the tool binary", () => {
  createProfile("acct");
  const result = runCli(["launch", "acct", "--tool", "claude", "--skip-configs"]);
  expect(result.status).toBe(0);
  expectContained(readProbe(), "launch/interactive");
});

test("launch (non-interactive) does not hand registry authority to the tool binary", () => {
  createProfile("acct");
  const result = runCli(["launch", "acct", "--tool", "claude", "--skip-configs", "--headless", "--", "prompt"]);
  expect(result.status).toBe(0);
  expectContained(readProbe(), "launch/headless");
});

test("run --headless does not hand registry authority to the tool binary", () => {
  createProfile("acct");
  const result = runCli(["run", "claude", "--profile", "acct", "--skip-configs", "--headless", "--", "prompt"]);
  expect(result.status).toBe(0);
  expectContained(readProbe(), "run/headless");
});

test("the probe itself can observe a leak — negative control for the whole file", () => {
  // Proves the probe is capable of REPORTING a canary when one is genuinely present,
  // so the ABSENT results above are observations rather than an artifact of a probe
  // that cannot see. Spawns the same binary directly with the sentinels applied and
  // no accounts boundary in between.
  const result = spawnSync(process.execPath, ["run", join(binDir, "fake-claude.ts")], {
    cwd: launchCwd,
    encoding: "utf8",
    env: { ...baseEnv(), CLAUDE_CONFIG_DIR: home },
  });
  expect(result.status).toBe(0);
  const probe = readProbe();
  expect(probe.names).toContain("HASNA_ACCOUNTS_API_KEY");
  expect(probe.names).toContain("ACCOUNTS_API_KEY");
  expect(probe.names).toContain("HASNA_API_SIGNING_KEY");
});
