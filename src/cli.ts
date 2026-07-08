#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { registerEventsCommands } from "@hasna/events/commander";
import chalk from "chalk";
import { AccountsError, type Profile } from "./types.js";
import {
  DEFAULT_TOOL,
  getTool,
  listTools,
  isBuiltinTool,
  addCustomTool,
  removeCustomTool,
  mergeToolArgs,
  normalizePermissionPreset,
} from "./lib/tools.js";
import {
  expandPath,
  type ProfileMetadata,
} from "./lib/profiles.js";
import { resolveStore } from "./lib/store.js";
import {
  accountsHome,
  getAccountsStorageStatus,
  loadStore,
  storagePull,
  storagePush,
  storageSync,
  storePath,
  type AccountsStorageStatus,
  type AccountsStorageSyncResult,
} from "./storage.js";
import { applyProfile, appliedProfile } from "./lib/apply.js";
import { listAgentsAcrossProfiles } from "./lib/agents.js";
import { importProfile } from "./lib/import-profile.js";
import { pickProfile, resolvePickMode } from "./lib/pick.js";
import { installHook, uninstallHook, shellSnippet, hookPath } from "./lib/hook.js";
import { prepareClaudeProfileKeychain, profileHasAuth } from "./lib/claude-auth.js";
import { formatEnvAssignments, formatExportLines, profileEnv } from "./lib/env.js";
import { finalizeLogin, prepareLogin } from "./lib/login.js";
import { switchProfile, type SwitchMode } from "./lib/switch.js";
import { configsSessionToolFor, runConfigsPrelaunch, type ConfigsPrelaunchMode, type ConfigsPrelaunchOptions } from "./lib/configs-prelaunch.js";
import { getConfigsPrelaunchSummary, type ConfigsPrelaunchSummary } from "./lib/configs-prelaunch-status.js";
import {
  listSupervisorStates,
  readSupervisorState,
  resolveSupervisorLaunch,
  runSupervisedTool,
  sendSupervisorRequest,
  type SupervisorState,
} from "./lib/supervisor.js";
import {
  codexAppBinaryExists,
  codexAppMenuState,
  runCodexAppMenuBar,
  switchCodexAppFromMenu,
} from "./lib/codex-app-menu.js";
import { accountsCapabilityCard, accountsNoCloudEvidencePack, toSupervisorOptionsWorkRun } from "./lib/contracts.js";
import { createAccountsEventsClient } from "./lib/events.js";
import { getAccountsReadiness, type AccountsReadiness, type AccountsReadinessStatus } from "./lib/readiness.js";

const program = new Command();

function die(message: string): never {
  console.error(chalk.red(`error: ${message}`));
  process.exit(1);
}

/** Wrap an action so AccountsError surfaces cleanly without a stack trace. */
function action<A extends unknown[]>(fn: (...args: A) => void | Promise<void>) {
  return (...args: A) => {
    try {
      Promise.resolve(fn(...args)).catch((err) => {
        if (err instanceof AccountsError) die(err.message);
        throw err;
      });
    } catch (err) {
      if (err instanceof AccountsError) die(err.message);
      throw err;
    }
  };
}

function formatPrelaunchLabel(prelaunch?: ConfigsPrelaunchSummary): string {
  if (!prelaunch || !prelaunch.supported) return "";
  const status = prelaunch.status;
  const drift = prelaunch.manifest.drift;
  const label = drift !== "ok" && drift !== "unsupported" && drift !== status ? `${status}/${drift}` : status;
  const color =
    status === "ok" ? chalk.green :
      status === "skipped" || status === "planned" ? chalk.yellow :
        status === "bypassed" || status === "missing" || status === "stale" ? chalk.yellow :
          chalk.red;
  return `  ${chalk.dim("configs:")}${color(label)}`;
}

function fmtProfile(p: Profile, active: boolean, applied = false, prelaunch?: ConfigsPrelaunchSummary): string {
  const marker =
    active && applied
      ? chalk.green("●") + chalk.magenta("◉")
      : active
        ? chalk.green("●")
        : applied
          ? chalk.magenta("◉")
          : chalk.dim("○");
  const name =
    active && applied
      ? chalk.green.bold(p.name)
      : active
        ? chalk.green.bold(p.name)
        : applied
          ? chalk.magenta.bold(p.name)
          : chalk.bold(p.name);
  const tool = chalk.cyan(p.tool);
  const email = p.email ? chalk.yellow(p.email) : chalk.dim("(no email)");
  const displayName = p.displayName ? chalk.dim(` (${p.displayName})`) : "";
  const desc = p.description ? chalk.dim(` — ${p.description}`) : "";
  return `${marker} ${name}${displayName}  ${tool}  ${email}${desc}${formatPrelaunchLabel(prelaunch)}`;
}

function prelaunchSummaryFor(p: Profile): ConfigsPrelaunchSummary {
  const tool = getTool(p.tool);
  return getConfigsPrelaunchSummary(p, tool, configsSessionToolFor(tool));
}

function profileDetails(
  p: Profile,
  active: boolean,
): Profile & { active: boolean; applied: boolean; prelaunch: ConfigsPrelaunchSummary } {
  return {
    ...p,
    active,
    applied: appliedProfile(p.tool)?.name === p.name,
    prelaunch: prelaunchSummaryFor(p),
  };
}

function printPrelaunchDetails(prelaunch: ConfigsPrelaunchSummary): void {
  if (!prelaunch.supported) {
    console.log(`  prelaunch: ${chalk.dim("unsupported")}`);
    return;
  }
  const statusColor =
    prelaunch.status === "ok" ? chalk.green :
      prelaunch.status === "failed" || prelaunch.status === "invalid" || prelaunch.status === "mismatch" ? chalk.red :
        chalk.yellow;
  console.log(`  prelaunch: ${statusColor(prelaunch.status)}`);
  if (prelaunch.reasons.length > 0) console.log(`    reason:    ${prelaunch.reasons.join("; ")}`);
  const manifest = prelaunch.manifest;
  console.log(`    manifest:  ${manifest.path}${manifest.exists ? "" : chalk.red("  [missing]")}`);
  if (manifest.hash) console.log(`    hash:      ${manifest.hash}`);
  if (manifest.generatedAt) console.log(`    generated: ${manifest.generatedAt}`);
  const ids = manifest.sourceIds.length > 0 ? ` (${manifest.sourceIds.join(", ")}${manifest.sourceIdsTruncated ? ", ..." : ""})` : "";
  console.log(`    sources:   ${manifest.sourceCount}${ids}`);
  if (prelaunch.lastRun) {
    const run = prelaunch.lastRun;
    const reason = run.reason ? `  ${run.reason}` : "";
    console.log(`    last run:  ${run.mode}/${run.result} at ${run.updatedAt}${reason}`);
  }
}

function collectMetadata(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

function collectRepeated(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

function parseMetadataValue(value: string): string | number | boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  if (value === "null") return null;
  if (/^-?(0|[1-9]\d*)(\.\d+)?$/.test(value)) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : value;
  }
  return value;
}

function parseMetadataPairs(pairs: string[] | undefined): ProfileMetadata | undefined {
  if (!pairs || pairs.length === 0) return undefined;
  const metadata = Object.create(null) as ProfileMetadata;
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx <= 0) die(`invalid metadata "${pair}" — expected key=value`);
    const key = pair.slice(0, idx);
    const value = pair.slice(idx + 1);
    metadata[key] = parseMetadataValue(value);
  }
  return metadata;
}

function printStorageStatus(status: AccountsStorageStatus, json?: boolean): void {
  if (json) {
    console.log(JSON.stringify(status, null, 2));
    return;
  }
  console.log(`${chalk.cyan("mode")}       ${status.mode}`);
  console.log(`${chalk.cyan("local")}      ${status.local.storePath}`);
  console.log(
    `${chalk.cyan("remote")}     ${
      status.remote.configured
        ? `${status.remote.bucket}/${status.remote.prefix}`
        : chalk.dim(`not configured (${status.remote.bucketEnv})`)
    }`,
  );
}

function printStorageSyncResult(result: AccountsStorageSyncResult, json?: boolean): void {
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (result.skipped) {
    console.log(chalk.yellow(`skipped: ${result.reason ?? "storage sync is not configured"}`));
    console.log(chalk.dim(`key: ${result.key}`));
    return;
  }
  console.log(chalk.green(`pushed ${result.pushed}, pulled ${result.pulled}`));
  console.log(chalk.dim(`key: ${result.key}`));
}

function readinessColor(status: AccountsReadinessStatus): (value: string) => string {
  if (status === "ok") return chalk.green;
  if (status === "degraded") return chalk.yellow;
  return chalk.red;
}

function printReadiness(readiness: AccountsReadiness): void {
  const status = readinessColor(readiness.status)(readiness.status);
  console.log(`${chalk.cyan("status")}     ${status}${readiness.ok ? "" : chalk.dim(" (ok=false)")}`);
  console.log(`${chalk.cyan("generated")}  ${readiness.generatedAt}`);
  console.log("");
  for (const item of readiness.checks) {
    const label = readinessColor(item.status)(item.status.padEnd(8));
    console.log(`${label} ${chalk.bold(item.label)} — ${item.summary}`);
    for (const reason of item.reasons.slice(0, 3)) {
      console.log(chalk.dim(`          ${reason}`));
    }
    if (item.reasons.length > 3) console.log(chalk.dim(`          +${item.reasons.length - 3} more`));
  }
  if (readiness.degradedModes.length > 0) {
    console.log("");
    console.log(chalk.cyan("modes"));
    for (const mode of readiness.degradedModes) console.log(`  ${mode}`);
  }
  if (readiness.nextActions.length > 0) {
    console.log("");
    console.log(chalk.cyan("next actions"));
    for (const action of readiness.nextActions) console.log(`  ${action}`);
  }
}

function parsePermissionArgs(entries?: string[]): Record<string, string[]> {
  const permissionArgs: Record<string, string[]> = {};
  for (const entry of entries ?? []) {
    const idx = entry.indexOf("=");
    if (idx <= 0) die(`invalid --permission-arg ${entry}; expected PRESET=ARG`);
    const preset = normalizePermissionPreset(entry.slice(0, idx));
    const arg = entry.slice(idx + 1);
    if (!arg) die(`invalid --permission-arg ${entry}; expected PRESET=ARG`);
    (permissionArgs[preset] ??= []).push(arg);
  }
  return permissionArgs;
}

interface ConfigsCliOptions {
  configs?: ConfigsPrelaunchMode;
  configsDryRun?: boolean;
  skipConfigs?: boolean;
  allowConfigsFailure?: boolean;
  configsBin?: string;
  identitiesBin?: string;
  identityExport?: string[];
}

function configsPrelaunchOptions(opts: ConfigsCliOptions): ConfigsPrelaunchOptions {
  const mode = opts.skipConfigs ? "skip" : opts.configsDryRun ? "plan" : opts.configs ?? "apply";
  if (!["plan", "apply", "skip"].includes(mode)) die(`invalid --configs "${mode}" (expected plan, apply, or skip)`);
  return {
    mode,
    allowFailure: opts.allowConfigsFailure,
    configsBin: opts.configsBin,
    identitiesBin: opts.identitiesBin,
    identityExports: opts.identityExport,
    skipReason: opts.skipConfigs ? "--skip-configs" : mode === "skip" ? "--configs skip" : undefined,
  };
}

function addConfigsOptions(command: Command): Command {
  return command
    .option("--configs <mode>", "prelaunch configs mode: apply, plan, or skip", "apply")
    .option("--configs-dry-run", "run the configs prelaunch render plan without applying")
    .option("--skip-configs", "skip configs prelaunch")
    .option("--allow-configs-failure", "continue launch/run even if configs prelaunch fails")
    .option("--configs-bin <path>", "configs CLI binary", "configs")
    .option("--identities-bin <path>", "identities CLI binary used for profile identity exports", "identities")
    .option("--identity-export <path>", "OpenIdentities configs instruction export JSON; repeatable", collectRepeated, []);
}

program
  .name("accounts")
  .description("Manage and switch between multiple Claude Code (and other AI tool) profiles/accounts.")
  .version(getVersion());

const codexApp = program.command("codex-app").description("macOS Codex.app profile helpers");

codexApp
  .command("menubar")
  .description("run a macOS menu-bar profile switcher for Codex.app")
  .option("--accounts-bin <path>", "accounts executable used by the menu helper", "accounts")
  .action(
    action((opts: { accountsBin: string }) => {
      if (!codexAppBinaryExists()) {
        console.error(chalk.yellow("warning: Codex.app binary was not found at the configured path"));
      }
      runCodexAppMenuBar({ accountsBin: opts.accountsBin });
    }),
  );

codexApp
  .command("menu-state")
  .description("print Codex.app menu-bar state")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { json?: boolean }) => {
      const state = await codexAppMenuState();
      if (opts.json) {
        console.log(JSON.stringify(state, null, 2));
        return;
      }
      if (state.profiles.length === 0) {
        console.log(chalk.dim("no codex-app profiles yet - create one with `accounts login <name> --tool codex-app`"));
        return;
      }
      for (const profile of state.profiles) {
        const marker = profile.active ? chalk.green("●") : chalk.dim("○");
        const label = profile.displayName ?? profile.email ?? chalk.dim("(no email)");
        console.log(marker + " " + chalk.bold(profile.name) + "  " + label);
      }
    }),
  );

codexApp
  .command("menu-switch")
  .argument("<name>", "codex-app profile name")
  .description("switch Codex.app to a profile, then safely quit and relaunch the desktop app")
  .option("--no-quit", "do not ask a running Codex.app to quit before launch")
  .option("--no-launch", "switch active profile without launching Codex.app")
  .option("--json", "output JSON")
  .action(
    action(async (name: string, opts: { quit?: boolean; launch?: boolean; json?: boolean }) => {
      const result = await switchCodexAppFromMenu(name, { quit: opts.quit, launch: opts.launch });
      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      console.log(chalk.green("✓ " + result.switch.profile.name + " is now the active Codex App profile"));
      if (result.launchStarted) console.log(chalk.dim("  relaunched: " + result.switch.commandLine));
      else console.log(chalk.dim("  launch command: " + result.switch.commandLine));
    }),
  );

program
  .command("add")
  .argument("<name>", "profile name (lowercase, hyphenated)")
  .description("create a new profile with an isolated config dir")
  .option("-t, --tool <tool>", "tool the profile is for", DEFAULT_TOOL)
  .option("-e, --email <email>", "account email (auto-detected when omitted)")
  .option("--display-name <name>", "human-readable account owner/name")
  .option("--identity <id>", "identity identifier or ref from the identities CLI")
  .option("--card-last4 <digits>", "payment card last four digits")
  .option("--metadata <key=value>", "arbitrary JSON-safe metadata key=value (repeatable)", collectMetadata, [])
  .option("-d, --dir <path>", "config dir to use (default: managed dir under ~/.hasna/accounts)")
  .option("--description <text>", "free-text description")
  .action(
    action(
      async (
        name: string,
        opts: {
          tool: string;
          email?: string;
          displayName?: string;
          identity?: string;
          cardLast4?: string;
          metadata?: string[];
          dir?: string;
          description?: string;
        },
      ) => {
        const p = await resolveStore().addProfile({
          name,
          tool: opts.tool,
          email: opts.email,
          displayName: opts.displayName,
          identity: opts.identity,
          cardLast4: opts.cardLast4,
          metadata: parseMetadataPairs(opts.metadata),
          dir: opts.dir,
          description: opts.description,
        });
      console.log(chalk.green(`✓ created profile ${chalk.bold(p.name)} for ${chalk.cyan(p.tool)}`));
      console.log(`  config dir: ${p.dir}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none — set with `accounts set " + p.name + " --email ...`)")}`);
      if (p.displayName) console.log(`  name:       ${p.displayName}`);
      if (p.identity) console.log(`  identity:   ${p.identity}`);
      if (p.cardLast4) console.log(`  card:       ****${p.cardLast4}`);
      const tool = getTool(p.tool);
      console.log(chalk.dim(`  launch it:  accounts launch ${p.name}    (sets ${tool.envVar} and runs ${tool.bin})`));
      },
    ),
  );

program
  .command("list")
  .alias("ls")
  .description("list all profiles")
  .option("-t, --tool <tool>", "filter by tool")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { tool?: string; json?: boolean }) => {
      const store = resolveStore();
      const profiles = await store.listProfiles(opts.tool);
      const current = await store.listCurrent();
      const activeFor = (tool: string) => current.find((c) => c.tool === tool)?.name;
      if (opts.json) {
        console.log(
          JSON.stringify(profiles.map((p) => profileDetails(p, activeFor(p.tool) === p.name)), null, 2),
        );
        return;
      }
      if (profiles.length === 0) {
        console.log(chalk.dim("no profiles yet — create one with `accounts add <name> --email you@example.com`"));
        return;
      }
      for (const p of profiles) {
        const active = activeFor(p.tool) === p.name;
        const isApplied = appliedProfile(p.tool)?.name === p.name;
        console.log(fmtProfile(p, active, isApplied, prelaunchSummaryFor(p)));
      }
    }),
  );

program
  .command("show")
  .argument("<name>", "profile name")
  .description("show full details for a profile")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--json", "output JSON")
  .action(
    action(async (name: string, opts: { tool?: string; json?: boolean }) => {
      const store = resolveStore();
      const p = await store.getProfile(name, opts.tool);
      const active = (await store.currentProfile(p.tool))?.name === p.name;
      const details = profileDetails(p, active);
      if (opts.json) {
        console.log(JSON.stringify(details, null, 2));
        return;
      }
      const isApplied = details.applied;
      console.log(fmtProfile(p, active, isApplied, details.prelaunch));
      console.log(`  tool:       ${p.tool} (${getTool(p.tool).label})`);
      console.log(`  active:     ${active ? chalk.green("yes") : chalk.dim("no")}`);
      console.log(`  applied:    ${isApplied ? chalk.magenta("yes") : chalk.dim("no")}`);
      console.log(`  config dir: ${p.dir}${existsSync(p.dir) ? "" : chalk.red("  [missing]")}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none)")}`);
      if (p.displayName) console.log(`  name:       ${p.displayName}`);
      if (p.identity) console.log(`  identity:   ${p.identity}`);
      if (p.cardLast4) console.log(`  card:       ****${p.cardLast4}`);
      if (p.metadata && Object.keys(p.metadata).length > 0) {
        console.log(`  metadata:   ${JSON.stringify(p.metadata)}`);
      }
      console.log(`  created:    ${p.createdAt}`);
      if (p.lastUsedAt) console.log(`  last used:  ${p.lastUsedAt}`);
      printPrelaunchDetails(details.prelaunch);
    }),
  );

program
  .command("use")
  .argument("<name>", "profile name")
  .description("set a profile as the active one for its tool")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      const { profile, toolId } = await resolveStore().useProfile(name, opts.tool);
      const tool = getTool(toolId);
      console.log(chalk.green(`✓ ${chalk.bold(profile.name)} is now the active ${tool.label} profile`));
      console.log(chalk.dim("  this CLI can't change your current shell's env, so either:"));
      console.log(`    accounts apply ${profile.name} --tool ${profile.tool}          ${chalk.dim("# IDE: sync auth to ~/.claude")}`);
      console.log(`    eval "$(accounts env ${profile.name} --tool ${profile.tool})"  ${chalk.dim("# terminal: isolated config dir")}`);
      console.log(`    accounts launch ${profile.name} --tool ${profile.tool}         ${chalk.dim("# launch " + tool.bin + " with it")}`);
    }),
  );

program
  .command("apply")
  .argument("<name>", "profile name")
  .description("apply profile auth to live ~/.claude paths (requires login/snapshot; Claude-only)")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      const { profile, previous } = await applyProfile(name, opts.tool);
      console.log(chalk.green(`✓ applied ${chalk.bold(profile.name)} to live ${getTool(profile.tool).label} paths`));
      if (previous) console.log(chalk.dim(`  previous applied profile "${previous}" was snapshotted`));
      if (profile.email) console.log(chalk.dim(`  email: ${profile.email}`));
    }),
  );

program
  .command("import")
  .argument("[name]", "profile name (default: main)")
  .description("import an existing config dir (default: ~/.claude) as a profile")
  .option("-t, --tool <tool>", "tool the profile is for", DEFAULT_TOOL)
  .option("-d, --dir <path>", "config dir to import (default: tool default dir)")
  .option("-e, --email <email>", "account email")
  .option("--description <text>", "description")
  .option("--copy", "copy into a managed profile dir instead of referencing the source")
  .action(
    action(async (name: string | undefined, opts: { tool: string; dir?: string; email?: string; description?: string; copy?: boolean }) => {
      const p = await importProfile({
        name: name ?? "main",
        tool: opts.tool,
        dir: opts.dir,
        email: opts.email,
        description: opts.description,
        copy: opts.copy,
      }, resolveStore());
      console.log(chalk.green(`✓ imported profile ${chalk.bold(p.name)}`));
      console.log(`  config dir: ${p.dir}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none)")}`);
      console.log(chalk.dim(`  next: accounts login ${p.name}  OR  accounts apply ${p.name}`));
    }),
  );

program
  .command("login")
  .argument("<name>", "profile name")
  .description("choose or launch a tool login flow inside an isolated profile dir")
  .option("-t, --tool <tool>", "tool to use for this profile; locks bare commands to that tool")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      const store = resolveStore();
      const prepared = await prepareLogin(name, { toolId: opts.tool, input: process.stdin, output: process.stderr, env: process.env, store });
      if (prepared.status === "stopped") {
        console.error(chalk.yellow(prepared.message));
        console.error(chalk.dim(`Selected tool kept: ${prepared.tool.id}`));
        process.exit(1);
      }
      const { profile, tool, args: loginArgs } = prepared;
      const env = profileEnv(profile, tool);
      await store.useProfile(name, tool.id);
      console.log(chalk.green(`→ launching ${tool.bin} for profile ${chalk.bold(name)}`));
      console.log(chalk.dim(`  config dir: ${profile.dir}`));
      console.log(chalk.dim(`  env: ${formatEnvAssignments(env)}`));
      console.log(chalk.yellow(`  ${tool.loginHint ?? "complete the login flow, then exit when done"}`));
      if (tool.id === "claude") {
        console.log(chalk.dim("  After Claude exits, accounts will make this the live/default Claude account."));
      }
      prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
      const res = spawnSync(tool.bin, loginArgs, {
        stdio: "inherit",
        env: { ...process.env, ...env },
      });
      if (res.error) die(`failed to launch ${tool.bin}: ${res.error.message}`);
      if ((res.status ?? 0) !== 0) process.exit(res.status ?? 1);
      const finalized = await finalizeLogin(name, tool.id, store);
      if (finalized.applied) {
        console.log(chalk.green(`✓ ${chalk.bold(name)} is now the live/default ${tool.label} account`));
      } else {
        console.log(chalk.green(`✓ ${chalk.bold(name)} login finished and profile is active`));
      }
    }),
  );

program
  .command("pick")
  .description("interactively choose a profile (default: mark active and apply to live Claude paths)")
  .option("-t, --tool <tool>", "filter by tool", DEFAULT_TOOL)
  .option("--env", "print env export after selection instead of apply")
  .option("--no-act", "only mark active (store current); do not apply or print env")
  .action(
    action(async (opts: { tool: string; env?: boolean; act?: boolean }) => {
      const store = resolveStore();
      const result = await pickProfile({ tool: opts.tool, mode: resolvePickMode(opts) }, store);
      if (!result) return;
      await store.useProfile(result.profile.name, result.profile.tool);
      console.log(chalk.green(`✓ selected ${chalk.bold(result.profile.name)}`));
      if (result.mode === "apply") {
        await applyProfile(result.profile.name, result.profile.tool, store);
        console.log(chalk.dim("  applied to live Claude paths"));
      } else if (result.mode === "env") {
        const tool = getTool(result.profile.tool);
        prepareClaudeProfileKeychain(result.profile.dir, tool, result.profile.name);
        console.log(formatExportLines(profileEnv(result.profile, tool)));
      }
    }),
  );

program
  .command("active")
  .argument("[tool]", "tool id (default: claude)")
  .description("print the active profile name (for scripting)")
  .action(
    action(async (toolId: string | undefined) => {
      const tool = toolId ?? DEFAULT_TOOL;
      const p = await resolveStore().currentProfile(tool);
      if (!p) die(`no active profile for "${tool}". Run \`accounts use <name>\` first.`);
      console.log(p.name);
    }),
  );

program
  .command("applied")
  .argument("[tool]", "tool id (default: claude)")
  .description("print the applied profile name (live auth on disk)")
  .action(
    action((toolId: string | undefined) => {
      const tool = toolId ?? DEFAULT_TOOL;
      const p = appliedProfile(tool);
      if (!p) die(`no applied profile for "${tool}". Run \`accounts apply <name>\` first.`);
      console.log(p.name);
    }),
  );

addConfigsOptions(program
  .command("switch"))
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed when printing/launching the tool")
  .description("switch to a profile and print a restart/resume command; use --launch to run it")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--mode <mode>", "switch mode: auto, apply, env, active", "auto")
  .option("--resume", "include the tool's resume/continue args in the handoff command")
  .option("--permissions <preset>", "tool-specific permission preset, e.g. dangerous")
  .option("--launch", "launch the tool after switching")
  .option("--supervisor", "ask a running accounts supervisor to restart the tool")
  .option("--json", "output JSON")
  .action(
    action(
      async (
        name: string,
        args: string[],
        opts: {
          tool?: string;
          mode: SwitchMode;
          resume?: boolean;
          permissions?: string;
          launch?: boolean;
          supervisor?: boolean;
          json?: boolean;
        } & ConfigsCliOptions,
      ) => {
        if (opts.supervisor && opts.launch) die("--supervisor and --launch cannot be used together");
        const store = resolveStore();
        if (opts.supervisor) {
          const profile = await store.getProfile(name, opts.tool);
          const response = await sendSupervisorRequest(
            profile.tool,
            {
              type: "switch_profile",
              name: profile.name,
              tool: profile.tool,
              mode: opts.mode,
              resume: opts.resume ?? true,
              args,
              permissions: opts.permissions,
              configsPrelaunch: configsPrelaunchOptions(opts),
            },
            { allowMissing: true },
          );
          if (!response) {
            die(`no running accounts supervisor for ${getTool(profile.tool).label}. Start one with \`accounts run ${profile.tool}\`.`);
          }
          if (!response.ok) die(response.error);
          if (opts.json) {
            console.log(JSON.stringify(response, null, 2));
          } else if ("queued" in response) {
            console.log(chalk.green(`✓ queued supervisor switch to ${chalk.bold(response.result.profile.name)}`));
            console.log(chalk.dim(`  ${response.state.command.join(" ")} will restart in ${response.restartDelayMs}ms`));
          } else {
            console.log(chalk.green("✓ supervisor responded"));
          }
          return;
        }

        const result = await switchProfile(name, {
          tool: opts.tool,
          mode: opts.mode,
          resume: opts.resume,
          args,
          permissions: opts.permissions,
        }, store);
        if (opts.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(chalk.green(`✓ ${result.message}`));
          if (result.applied) console.log(chalk.dim("  live/default auth updated"));
          console.log(chalk.dim(`  restart command: ${result.commandLine}`));
          if (!opts.launch) {
            console.log(chalk.yellow("  Exit the current agent session, then run the restart command above."));
          }
        }
        if (opts.launch) {
          runConfigsPrelaunch(result.profile, result.tool, configsPrelaunchOptions(opts));
          const [bin, ...launchArgs] = result.command;
          const res = spawnSync(bin!, launchArgs, {
            stdio: "inherit",
            env: { ...process.env, ...result.env },
          });
          if (res.error) die(`failed to launch ${bin}: ${res.error.message}`);
          process.exit(res.status ?? 0);
        }
      },
    ),
  );

const hook = program.command("hook").description("install a shell wrapper for claude");

hook
  .command("install")
  .description(`write ${join(accountsHome(), "claude-hook.sh")}`)
  .action(
    action(() => {
      const { path, created } = installHook();
      console.log(chalk.green(created ? `✓ installed hook at ${path}` : `✓ updated hook at ${path}`));
      console.log(chalk.dim(`  add to ~/.zshrc:  ${shellSnippet()}`));
    }),
  );

hook
  .command("uninstall")
  .description("remove the accounts claude hook script")
  .action(
    action(() => {
      if (uninstallHook()) console.log(chalk.green("✓ removed hook script"));
      else console.log(chalk.yellow("no accounts hook script to remove"));
    }),
  );

hook
  .command("path")
  .description("print the hook script path")
  .action(
    action(() => {
      console.log(hookPath());
    }),
  );

program
  .command("env")
  .argument("[name]", "profile name (defaults to the active profile for the tool)")
  .description("print the `export VAR=dir` line to activate a profile in your shell")
  .option("-t, --tool <tool>", "tool (required when a named profile is ambiguous; defaults to claude when no name is given)")
  .action(
    action(async (name: string | undefined, opts: { tool?: string }) => {
      const toolId = opts.tool ?? DEFAULT_TOOL;
      const store = resolveStore();
      const profile = name ? await store.getProfile(name, opts.tool) : await store.currentProfile(toolId);
      if (!profile) die(`no active profile for "${toolId}". Use \`accounts use <name>\` first.`);
      const tool = getTool(profile.tool);
      prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
      console.log(formatExportLines(profileEnv(profile, tool)));
    }),
  );

addConfigsOptions(program
  .command("launch"))
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed to the tool binary")
  .description("launch the tool's binary with the profile's config dir active")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--permissions <preset>", "tool-specific permission preset, e.g. dangerous")
  .action(
    action(async (name: string, args: string[], opts: { tool?: string; permissions?: string } & ConfigsCliOptions) => {
      const store = resolveStore();
      const profile = await store.getProfile(name, opts.tool);
      const tool = getTool(profile.tool);
      runConfigsPrelaunch(profile, tool, configsPrelaunchOptions(opts));
      const env = profileEnv(profile, tool);
      const launchArgs = mergeToolArgs(tool, args, { permissions: opts.permissions, profile });
      await store.useProfile(name, tool.id); // mark active + bump lastUsedAt
      console.log(chalk.dim(`→ ${formatEnvAssignments(env)} ${tool.bin} ${launchArgs.join(" ")}`));
      prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
      const res = spawnSync(tool.bin, launchArgs, {
        stdio: "inherit",
        env: { ...process.env, ...env },
      });
      if (res.error) die(`failed to launch ${tool.bin}: ${res.error.message}`);
      process.exit(res.status ?? 0);
    }),
  );

addConfigsOptions(program
  .command("run"))
  .argument("<target>", "tool id to supervise (claude, codex, opencode...) or a profile name")
  .argument("[args...]", "extra args passed to the tool binary")
  .description("run a tool under the accounts supervisor so MCP can switch/restart it")
  .option("-p, --profile <name>", "profile to run when target is a tool id")
  .option("-t, --tool <tool>", "tool when target is a profile name")
  .option("--resume", "start with the tool's resume/continue args")
  .option("--permissions <preset>", "tool-specific permission preset, e.g. dangerous")
  .action(
    action(async (target: string, args: string[], opts: { profile?: string; tool?: string; resume?: boolean; permissions?: string } & ConfigsCliOptions) => {
      const plan = await resolveSupervisorLaunch(target, { profile: opts.profile, tool: opts.tool });
      const runArgs = mergeToolArgs(plan.tool, [...(opts.resume ? (plan.tool.resumeArgs ?? []) : []), ...args], {
        permissions: opts.permissions,
        profile: plan.profile,
      });
      console.error(chalk.green(`✓ accounts supervisor running ${plan.tool.label} as ${chalk.bold(plan.profile.name)}`));
      console.error(chalk.dim(`  control: accounts supervisor status ${plan.tool.id}`));
      console.error(chalk.dim(`  switch:  accounts switch <profile> --tool ${plan.tool.id} --supervisor`));
      const code = await runSupervisedTool(plan.profile, plan.tool, runArgs, {
        configsPrelaunch: configsPrelaunchOptions(opts),
        log: (message) => console.error(chalk.dim(message)),
      });
      process.exit(code);
    }),
  );

const supervisor = program.command("supervisor").description("inspect and control accounts-run supervisors");

supervisor
  .command("status")
  .argument("[tool]", "tool id")
  .description("show running supervisor state")
  .option("--json", "output JSON")
  .action(
    action(async (toolId: string | undefined, opts: { json?: boolean }) => {
      const state = toolId ? readSupervisorState(toolId) : undefined;
      const states = toolId ? (state ? [state] : []) : listSupervisorStates();
      const live: Array<SupervisorState & { stale?: boolean }> = [];
      for (const state of states) {
        const response = await sendSupervisorRequest(state.tool, { type: "status" }, { allowMissing: true });
        live.push(response?.ok && "state" in response ? response.state : { ...state, stale: true });
      }
      if (opts.json) {
        console.log(JSON.stringify(live, null, 2));
        return;
      }
      if (live.length === 0) {
        console.log(chalk.dim("no accounts supervisors running"));
        return;
      }
      for (const state of live) {
        const stale = "stale" in state ? chalk.yellow(" stale") : "";
        const child = state.childPid ? ` child:${state.childPid}` : "";
        const configs = state.prelaunch?.supported ? formatPrelaunchLabel(state.prelaunch).trim() : "";
        console.log(`${chalk.cyan(state.tool.padEnd(10))} ${chalk.bold(state.profile)} pid:${state.pid}${child}${stale}`);
        if (configs) console.log(`  ${configs}`);
        console.log(chalk.dim(`  ${state.command.join(" ")}`));
      }
    }),
  );

addConfigsOptions(supervisor
  .command("switch")
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed after resume/continue args")
  .description("switch a running supervisor to another profile")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--mode <mode>", "switch mode: auto, apply, env, active", "auto")
  .option("--no-resume", "restart without the tool's resume/continue args")
  .option("--permissions <preset>", "tool-specific permission preset, e.g. dangerous")
  .option("--json", "output JSON"))
  .action(
    action(
      async (
        name: string,
        args: string[],
        opts: { tool?: string; mode: SwitchMode; resume?: boolean; permissions?: string; json?: boolean } & ConfigsCliOptions,
      ) => {
      const profile = await resolveStore().getProfile(name, opts.tool);
      const response = await sendSupervisorRequest(
        profile.tool,
        {
          type: "switch_profile",
          name: profile.name,
          tool: profile.tool,
          mode: opts.mode,
          resume: opts.resume !== false,
          args,
          permissions: opts.permissions,
          configsPrelaunch: configsPrelaunchOptions(opts),
        },
        { allowMissing: true },
      );
      if (!response) die(`no running accounts supervisor for ${getTool(profile.tool).label}`);
      if (!response.ok) die(response.error);
      if (opts.json) {
        console.log(JSON.stringify(response, null, 2));
        return;
      }
      if ("queued" in response) {
        console.log(chalk.green(`✓ queued supervisor switch to ${chalk.bold(response.result.profile.name)}`));
        console.log(chalk.dim(`  restart command: ${response.result.commandLine}`));
      }
      },
    ),
  );

supervisor
  .command("stop")
  .argument("<tool>", "tool id")
  .description("stop a running supervisor and its child process")
  .action(
    action(async (toolId: string) => {
      const response = await sendSupervisorRequest(toolId, { type: "stop" }, { allowMissing: true });
      if (!response) die(`no running accounts supervisor for ${toolId}`);
      if (!response.ok) die(response.error);
      console.log(chalk.green(`✓ stopping ${toolId} supervisor`));
    }),
  );

program
  .command("shell")
  .argument("<name>", "profile name")
  .description("open a subshell with the profile's config dir active")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      const store = resolveStore();
      const profile = await store.getProfile(name, opts.tool);
      const tool = getTool(profile.tool);
      const env = profileEnv(profile, tool);
      await store.useProfile(name, tool.id);
      const shell = process.env.SHELL || "/bin/sh";
      console.log(chalk.dim(`→ subshell with ${formatEnvAssignments(env)} (exit to leave)`));
      prepareClaudeProfileKeychain(profile.dir, tool, profile.name);
      const res = spawnSync(shell, ["-i"], {
        stdio: "inherit",
        env: { ...process.env, ...env, ACCOUNTS_ACTIVE: profile.name },
      });
      process.exit(res.status ?? 0);
    }),
  );

program
  .command("current")
  .description("show the active profile for each tool")
  .option("-t, --tool <tool>", "show only this tool")
  .action(
    action(async (opts: { tool?: string }) => {
      const store = resolveStore();
      const tools = opts.tool ? [getTool(opts.tool)] : listTools();
      for (const tool of tools) {
        const p = await store.currentProfile(tool.id);
        const a = appliedProfile(tool.id);
        const val = p ? `${chalk.green.bold(p.name)}${p.email ? chalk.dim(" (" + p.email + ")") : ""}` : chalk.dim("(none)");
        const appliedVal = a && a.name !== p?.name ? chalk.magenta(` → applied: ${a.name}`) : a ? chalk.magenta(" (applied)") : "";
        console.log(`${chalk.cyan(tool.label.padEnd(14))} ${val}${appliedVal}`);
      }
    }),
  );

program
  .command("agents")
  .description("list Claude Code agent sessions (interactive + background) across all profiles")
  .option("-t, --tool <tool>", "tool id", "claude")
  .option("-p, --profile <name>", "only show agents for this profile")
  .option("-b, --background", "only show background agents")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { tool: string; profile?: string; background?: boolean; json?: boolean }) => {
      const results = listAgentsAcrossProfiles({
        profiles: await resolveStore().listProfiles(opts.tool),
        tool: opts.tool,
        profile: opts.profile,
        backgroundOnly: opts.background,
      });
      if (opts.json) {
        console.log(JSON.stringify(results, null, 2));
        return;
      }
      if (results.length === 0) {
        console.log(chalk.dim(`no ${opts.tool} profiles registered`));
        return;
      }
      for (const r of results) {
        const email = r.email ? chalk.yellow(r.email) : chalk.dim("(no email)");
        console.log(`${chalk.bold(r.profile)}  ${chalk.cyan(r.tool)}  ${email}`);
        if (r.error) {
          console.log(`  ${chalk.red("error:")} ${r.error}`);
          continue;
        }
        if (r.agents.length === 0) {
          console.log(chalk.dim("  (no agents)"));
          continue;
        }
        for (const a of r.agents) {
          if (a.kind === "process") {
            const cfg = typeof a.configDir === "string" ? chalk.dim(`  cfg=${a.configDir}`) : "";
            const cmd = typeof a.command === "string" ? chalk.dim(`  ${a.command.slice(0, 100)}`) : "";
            console.log(`  ${chalk.yellow("process    ")} pid ${a.pid}${cfg}${cmd}`);
            continue;
          }
          const kind = a.kind === "background" ? chalk.magenta("background ") : chalk.dim("interactive");
          const state = String(a.state ?? a.status ?? "");
          const stateFmt = state === "working" || state === "busy" ? chalk.green(state) : chalk.dim(state);
          const name = typeof a.name === "string" ? ` ${a.name}` : "";
          const session = typeof a.sessionId === "string" ? chalk.dim(`  ${a.sessionId.slice(0, 8)}`) : "";
          const cwd = typeof a.cwd === "string" ? chalk.dim(`  ${a.cwd}`) : "";
          console.log(`  ${kind} ${stateFmt.padEnd(8)}${session}${chalk.bold(name)}${cwd}`);
        }
      }
    }),
  );

const storage = program.command("storage").description("inspect and sync the accounts storage snapshot");

storage
  .command("status", { isDefault: true })
  .description("show local and optional S3 snapshot storage status")
  .option("--json", "output JSON")
  .action(
    action((opts: { json?: boolean }) => {
      printStorageStatus(getAccountsStorageStatus(), opts.json);
    }),
  );

storage
  .command("push")
  .description("push the local accounts snapshot to S3 when configured")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { json?: boolean }) => {
      printStorageSyncResult(await storagePush(), opts.json);
    }),
  );

storage
  .command("pull")
  .description("pull the accounts snapshot from S3 when configured")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { json?: boolean }) => {
      printStorageSyncResult(await storagePull(), opts.json);
    }),
  );

storage
  .command("sync")
  .description("pull then push the accounts snapshot when S3 is configured")
  .option("--json", "output JSON")
  .action(
    action(async (opts: { json?: boolean }) => {
      printStorageSyncResult(await storageSync(), opts.json);
    }),
  );

program
  .command("health")
  .alias("readiness")
  .description("show sanitized account, provider, supervisor, and storage readiness")
  .option("--json", "output JSON")
  .action(
    action((opts: { json?: boolean }) => {
      const readiness = getAccountsReadiness();
      if (opts.json) {
        console.log(JSON.stringify(readiness, null, 2));
      } else {
        printReadiness(readiness);
      }
      if (readiness.status === "unavailable") process.exitCode = 1;
    }),
  );

program
  .command("set")
  .argument("<name>", "profile name")
  .description("update a profile's email, metadata, description, or config dir")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("-e, --email <email>", "set the account email")
  .option("--display-name <name>", "set the human-readable account owner/name")
  .option("--identity <id>", "set the identity identifier or ref from the identities CLI")
  .option("--card-last4 <digits>", "set the payment card last four digits")
  .option("--metadata <key=value>", "merge arbitrary JSON-safe metadata key=value (repeatable)", collectMetadata, [])
  .option("--description <text>", "set the description")
  .option("-d, --dir <path>", "set the config dir")
  .action(
    action(
      async (
        name: string,
        opts: {
          tool?: string;
          email?: string;
          displayName?: string;
          identity?: string;
          cardLast4?: string;
          metadata?: string[];
          description?: string;
          dir?: string;
        },
      ) => {
        if (
          opts.email === undefined &&
          opts.displayName === undefined &&
          opts.identity === undefined &&
          opts.cardLast4 === undefined &&
          (!opts.metadata || opts.metadata.length === 0) &&
          opts.description === undefined &&
          opts.dir === undefined
        ) {
          die("nothing to set — pass --email, --display-name, --identity, --card-last4, --metadata, --description, or --dir");
        }
        const p = await resolveStore().updateProfile(name, {
          tool: opts.tool,
          email: opts.email,
          displayName: opts.displayName,
          identity: opts.identity,
          cardLast4: opts.cardLast4,
          metadata: parseMetadataPairs(opts.metadata),
          description: opts.description,
          dir: opts.dir,
        });
        console.log(chalk.green(`✓ updated ${chalk.bold(p.name)}`));
      }
    ),
  );

program
  .command("detect")
  .argument("<name>", "profile name")
  .description("re-detect the account email from the profile's config dir")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      const p = await resolveStore().redetectEmail(name, opts.tool);
      console.log(p.email ? chalk.green(`✓ ${p.name}: ${p.email}`) : chalk.yellow(`no email found in ${p.dir}`));
    }),
  );

program
  .command("rename")
  .argument("<old>", "current name")
  .argument("<new>", "new name")
  .description("rename a profile")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (oldName: string, newName: string, opts: { tool?: string }) => {
      const p = await resolveStore().renameProfile(oldName, newName, opts.tool);
      console.log(chalk.green(`✓ renamed to ${chalk.bold(p.name)}`));
    }),
  );

program
  .command("remove")
  .alias("rm")
  .argument("<name>", "profile name")
  .description("remove a profile from the registry")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--purge", "also delete the managed config dir on disk")
  .action(
    action(async (name: string, opts: { tool?: string; purge?: boolean }) => {
      const { profile, purged, purgeNote } = await resolveStore().removeProfile(name, {
        tool: opts.tool,
        purge: opts.purge,
      });
      console.log(chalk.green(`✓ removed ${chalk.bold(profile.name)}`));
      if (purged) console.log(chalk.dim(`  deleted ${profile.dir}`));
      if (purgeNote) console.log(chalk.yellow(`  ${purgeNote}`));
    }),
  );

program
  .command("path")
  .argument("<name>", "profile name")
  .description("print just the config dir path (useful for scripting)")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action(async (name: string, opts: { tool?: string }) => {
      console.log((await resolveStore().getProfile(name, opts.tool)).dir);
    }),
  );

const tools = program.command("tools").description("manage the apps/tools profiles can target");

tools
  .command("list", { isDefault: true })
  .description("list supported tools (built-in + custom)")
  .option("--json", "output JSON")
  .action(
    action((opts: { json?: boolean }) => {
      const all = listTools();
      if (opts.json) {
        console.log(JSON.stringify(all, null, 2));
        return;
      }
      for (const t of all) {
        const tag = isBuiltinTool(t.id) ? chalk.dim("built-in") : chalk.magenta("custom");
        const envNames = [t.envVar, ...Object.keys(t.extraEnv ?? {})].join(", ");
        const permissions = Object.keys(t.permissionArgs ?? {});
        const permissionsHint = permissions.length > 0 ? chalk.dim(` permissions: ${permissions.sort().join(",")}`) : "";
        console.log(
          `${chalk.cyan(t.id.padEnd(10))} ${t.label.padEnd(16)} ${chalk.dim(envNames)} → ${chalk.dim(t.defaultDir)}  ${tag}${permissionsHint}`,
        );
      }
    }),
  );

tools
  .command("add")
  .argument("<id>", "tool id, e.g. cursor")
  .description("register a custom tool/app so profiles can target it")
  .requiredOption("--label <label>", 'display name, e.g. "Cursor"')
  .requiredOption("--env-var <VAR>", "env var that points the tool at its config dir")
  .requiredOption("--bin <bin>", "binary to launch")
  .option("--default-dir <path>", "default config dir (default: ~/.<id>)")
  .option("--extra-env <VAR=VALUE...>", "additional env var templates; supports {profileDir}, {profileName}, {toolId}")
  .option("--login-arg <arg...>", "arguments for `accounts login <profile> --tool <id>`")
  .option("--launch-arg <arg...>", "arguments prepended when launching; supports {profileDir}, {profileName}, {toolId}")
  .option("--resume-arg <arg...>", "arguments for supervised resume/restart, e.g. --continue")
  .option("--permission-arg <preset=arg...>", "tool permission preset args, e.g. dangerous=--yolo")
  .option("--account-file <file>", "file inside the config dir holding the email")
  .option("--email-path <path>", "dot-path to the email inside that file (e.g. account.email)")
  .action(
    action(
      (
        id: string,
        opts: {
          label: string;
          envVar: string;
          bin: string;
          defaultDir?: string;
          extraEnv?: string[];
          loginArg?: string[];
          launchArg?: string[];
          resumeArg?: string[];
          permissionArg?: string[];
          accountFile?: string;
          emailPath?: string;
        },
      ) => {
        const extraEnv: Record<string, string> = {};
        for (const entry of opts.extraEnv ?? []) {
          const idx = entry.indexOf("=");
          if (idx <= 0) die(`invalid --extra-env ${entry}; expected VAR=VALUE`);
          extraEnv[entry.slice(0, idx)] = entry.slice(idx + 1);
        }
        const permissionArgs = parsePermissionArgs(opts.permissionArg);
        const def = {
          id,
          label: opts.label,
          envVar: opts.envVar,
          bin: opts.bin,
          defaultDir: opts.defaultDir ? expandPath(opts.defaultDir) : join(homedir(), `.${id}`),
          ...(Object.keys(extraEnv).length > 0 ? { extraEnv } : {}),
          ...(opts.loginArg ? { loginArgs: opts.loginArg } : {}),
          ...(opts.launchArg ? { launchArgs: opts.launchArg } : {}),
          ...(opts.resumeArg ? { resumeArgs: opts.resumeArg } : {}),
          ...(Object.keys(permissionArgs).length > 0 ? { permissionArgs } : {}),
          ...(opts.accountFile ? { accountFile: opts.accountFile } : {}),
          ...(opts.emailPath ? { emailPath: opts.emailPath.split(".") } : {}),
        };
        const t = addCustomTool(def);
        console.log(chalk.green(`✓ registered tool ${chalk.bold(t.id)} (${t.label})`));
        console.log(chalk.dim(`  add a profile: accounts add <name> --tool ${t.id} --email you@example.com`));
      },
    ),
  );

tools
  .command("remove")
  .alias("rm")
  .argument("<id>", "custom tool id")
  .description("remove a custom tool")
  .action(
    action((id: string) => {
      removeCustomTool(id);
      console.log(chalk.green(`✓ removed custom tool ${chalk.bold(id)}`));
    }),
  );

program
  .command("doctor")
  .description("check the store and profile dirs for problems (exits 1 if any)")
  .action(
    action(async () => {
      console.log(chalk.bold(`store: ${storePath()}`));
      const localState = loadStore();
      const profiles = await resolveStore().listProfiles();
      let problems = 0;
      for (const p of profiles) {
        const missing = !existsSync(p.dir);
        const noEmail = !p.email;
        if (missing) {
          console.log(chalk.red(`  ✗ ${p.name}: config dir missing (${p.dir})`));
          problems++;
        } else if (p.tool === "claude" && !profileHasAuth(p.dir, getTool("claude"))) {
          console.log(chalk.yellow(`  ! ${p.name}: no auth snapshot (run login + detect before apply)`));
        } else if (!noEmail) {
          console.log(chalk.green(`  ✓ ${p.name}`));
        } else {
          console.log(chalk.yellow(`  ! ${p.name}: no email recorded`));
        }
      }
      for (const [toolId, appliedName] of Object.entries(localState.applied)) {
        if (!profiles.some((p) => p.name === appliedName && p.tool === toolId)) {
          console.log(chalk.red(`  ✗ stale applied.${toolId}: "${appliedName}" (profile missing)`));
          problems++;
        }
      }
      for (const [toolId, currentName] of Object.entries(localState.current)) {
        if (!profiles.some((p) => p.name === currentName && p.tool === toolId)) {
          console.log(chalk.red(`  ✗ stale current.${toolId}: "${currentName}" (profile missing)`));
          problems++;
        }
      }
      const driftWarned = new Set<string>();
      for (const p of profiles) {
        const active = localState.current[p.tool];
        const applied = localState.applied[p.tool];
        if (active && applied && active !== applied && !driftWarned.has(p.tool)) {
          driftWarned.add(p.tool);
          console.log(
            chalk.yellow(
              `  ! ${p.tool}: active (${active}) ≠ applied (${applied}) — Cursor/IDE use applied; run \`accounts apply ${active}\``,
            ),
          );
        }
      }
      if (profiles.length === 0) console.log(chalk.dim("  no profiles."));
      if (problems > 0) {
        console.log(chalk.red(`\n${problems} problem(s) found.`));
        process.exit(1);
      }
      console.log(chalk.green("\nhealthy."));
    }),
  );

const contracts = program.command("contracts").description("Emit @hasna/contracts-compatible Accounts JSON");

contracts
  .command("capability-card")
  .description("Print the Accounts CLI capability card contract")
  .option("-j, --json", "Print JSON output", false)
  .action(
    action((options: { json?: boolean }) => {
      const card = accountsCapabilityCard();
      if (options.json) {
        console.log(JSON.stringify(card, null, 2));
        return;
      }
      console.log(`${card.name}\t${card.schema}\t${card.status}`);
    }),
  );

contracts
  .command("work-run")
  .description("Print a sample supervisor work_run contract for Accounts")
  .option("--tool <tool>", "Tool identifier", "claude")
  .option("--profile <profile>", "Profile name", "current")
  .option("-j, --json", "Print JSON output", false)
  .action(
    action((options: { tool: string; profile: string; json?: boolean }) => {
      const run = toSupervisorOptionsWorkRun({}, { tool: options.tool, profile: options.profile });
      if (options.json) {
        console.log(JSON.stringify(run, null, 2));
        return;
      }
      console.log(`${run.id}\t${run.schema}\t${run.status}`);
    }),
  );

contracts
  .command("no-cloud-scan")
  .description("Run the contracts no-cloud scan and print the evidence pack")
  .argument("[target]", "Target path to scan", ".")
  .option("-j, --json", "Print JSON output", false)
  .action(
    action((target: string, options: { json?: boolean }) => {
      const pack = accountsNoCloudEvidencePack(target);
      if (options.json) {
        console.log(JSON.stringify(pack, null, 2));
        return;
      }
      console.log(`${pack.id}\t${pack.schema}\t${pack.verdict}`);
    }),
  );

registerEventsCommands(program, { source: "accounts", createClient: () => createAccountsEventsClient() });

program.parseAsync(process.argv);

function getVersion(): string {
  // Read the version from the package.json that ships alongside the build.
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const candidate of [join(here, "..", "package.json"), join(here, "package.json")]) {
      if (existsSync(candidate)) {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { version?: string };
        if (pkg.version) return pkg.version;
      }
    }
  } catch {
    /* fall through */
  }
  return "0.0.0";
}
