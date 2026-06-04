#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import chalk from "chalk";
import { AccountsError, type Profile } from "./types.js";
import { DEFAULT_TOOL, getTool, listTools, isBuiltinTool, addCustomTool, removeCustomTool } from "./lib/tools.js";
import {
  addProfile,
  currentProfile,
  expandPath,
  getProfile,
  listProfiles,
  redetectEmail,
  removeProfile,
  renameProfile,
  updateProfile,
  useProfile,
} from "./lib/profiles.js";
import { accountsHome, storePath } from "./storage.js";
import { applyProfile, appliedProfile } from "./lib/apply.js";
import { importProfile, ensureProfileForLogin } from "./lib/import-profile.js";
import { pickProfile, resolvePickMode } from "./lib/pick.js";
import { installHook, uninstallHook, shellSnippet, hookPath } from "./lib/hook.js";
import { profileHasAuth } from "./lib/claude-auth.js";
import { loadStore } from "./storage.js";
import { formatEnvAssignments, formatExportLines, profileEnv } from "./lib/env.js";
import { finalizeLogin } from "./lib/login.js";
import { switchProfile, type SwitchMode } from "./lib/switch.js";

const program = new Command();

function die(message: string): never {
  console.error(chalk.red(`error: ${message}`));
  process.exit(1);
}

/** Wrap an action so AccountsError surfaces cleanly without a stack trace. */
function action<A extends unknown[]>(fn: (...args: A) => void) {
  return (...args: A) => {
    try {
      fn(...args);
    } catch (err) {
      if (err instanceof AccountsError) die(err.message);
      throw err;
    }
  };
}

function fmtProfile(p: Profile, active: boolean, applied = false): string {
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
  const desc = p.description ? chalk.dim(` — ${p.description}`) : "";
  return `${marker} ${name}  ${tool}  ${email}${desc}`;
}

program
  .name("accounts")
  .description("Manage and switch between multiple Claude Code (and other AI tool) profiles/accounts.")
  .version(getVersion());

program
  .command("add")
  .argument("<name>", "profile name (lowercase, hyphenated)")
  .description("create a new profile with an isolated config dir")
  .option("-t, --tool <tool>", "tool the profile is for", DEFAULT_TOOL)
  .option("-e, --email <email>", "account email (auto-detected when omitted)")
  .option("-d, --dir <path>", "config dir to use (default: managed dir under ~/.hasna/accounts)")
  .option("--description <text>", "free-text description")
  .action(
    action((name: string, opts: { tool: string; email?: string; dir?: string; description?: string }) => {
      const p = addProfile({ name, tool: opts.tool, email: opts.email, dir: opts.dir, description: opts.description });
      console.log(chalk.green(`✓ created profile ${chalk.bold(p.name)} for ${chalk.cyan(p.tool)}`));
      console.log(`  config dir: ${p.dir}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none — set with `accounts set " + p.name + " --email ...`)")}`);
      const tool = getTool(p.tool);
      console.log(chalk.dim(`  launch it:  accounts launch ${p.name} --tool ${p.tool}    (sets ${tool.envVar} and runs ${tool.bin})`));
    }),
  );

program
  .command("list")
  .alias("ls")
  .description("list all profiles")
  .option("-t, --tool <tool>", "filter by tool")
  .option("--json", "output JSON")
  .action(
    action((opts: { tool?: string; json?: boolean }) => {
      const profiles = listProfiles(opts.tool);
      if (opts.json) {
        console.log(JSON.stringify(profiles, null, 2));
        return;
      }
      if (profiles.length === 0) {
        console.log(chalk.dim("no profiles yet — create one with `accounts add <name> --email you@example.com`"));
        return;
      }
      for (const p of profiles) {
        const active = currentProfile(p.tool)?.name === p.name;
        const isApplied = appliedProfile(p.tool)?.name === p.name;
        console.log(fmtProfile(p, active, isApplied));
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
    action((name: string, opts: { tool?: string; json?: boolean }) => {
      const p = getProfile(name, opts.tool);
      if (opts.json) {
        console.log(JSON.stringify(p, null, 2));
        return;
      }
      const active = currentProfile(p.tool)?.name === p.name;
      const isApplied = appliedProfile(p.tool)?.name === p.name;
      console.log(fmtProfile(p, active, isApplied));
      console.log(`  tool:       ${p.tool} (${getTool(p.tool).label})`);
      console.log(`  active:     ${active ? chalk.green("yes") : chalk.dim("no")}`);
      console.log(`  applied:    ${isApplied ? chalk.magenta("yes") : chalk.dim("no")}`);
      console.log(`  config dir: ${p.dir}${existsSync(p.dir) ? "" : chalk.red("  [missing]")}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none)")}`);
      console.log(`  created:    ${p.createdAt}`);
      if (p.lastUsedAt) console.log(`  last used:  ${p.lastUsedAt}`);
    }),
  );

program
  .command("use")
  .argument("<name>", "profile name")
  .description("set a profile as the active one for its tool")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action((name: string, opts: { tool?: string }) => {
      const { profile, toolId } = useProfile(name, opts.tool);
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
    action((name: string, opts: { tool?: string }) => {
      const { profile, previous } = applyProfile(name, opts.tool);
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
    action((name: string | undefined, opts: { tool: string; dir?: string; email?: string; description?: string; copy?: boolean }) => {
      const p = importProfile({
        name: name ?? "main",
        tool: opts.tool,
        dir: opts.dir,
        email: opts.email,
        description: opts.description,
        copy: opts.copy,
      });
      console.log(chalk.green(`✓ imported profile ${chalk.bold(p.name)}`));
      console.log(`  config dir: ${p.dir}`);
      console.log(`  email:      ${p.email ?? chalk.dim("(none)")}`);
      console.log(chalk.dim(`  next: accounts login ${p.name} --tool ${p.tool}  OR  accounts apply ${p.name} --tool ${p.tool}`));
    }),
  );

program
  .command("login")
  .argument("<name>", "profile name")
  .description("launch the tool's login flow inside an isolated profile dir")
  .option("-t, --tool <tool>", "tool", DEFAULT_TOOL)
  .action(
    action((name: string, opts: { tool: string }) => {
      const profile = ensureProfileForLogin(name, opts.tool);
      const tool = getTool(profile.tool);
      const env = profileEnv(profile, tool);
      const loginArgs = tool.loginArgs ?? [];
      useProfile(name, tool.id);
      console.log(chalk.green(`→ launching ${tool.bin} for profile ${chalk.bold(name)}`));
      console.log(chalk.dim(`  config dir: ${profile.dir}`));
      console.log(chalk.dim(`  env: ${formatEnvAssignments(env)}`));
      console.log(chalk.yellow(`  ${tool.loginHint ?? "complete the login flow, then exit when done"}`));
      if (tool.id === "claude") {
        console.log(chalk.dim("  After Claude exits, accounts will make this the live/default Claude account."));
      }
      const res = spawnSync(tool.bin, loginArgs, {
        stdio: "inherit",
        env: { ...process.env, ...env },
      });
      if (res.error) die(`failed to launch ${tool.bin}: ${res.error.message}`);
      if ((res.status ?? 0) !== 0) process.exit(res.status ?? 1);
      const finalized = finalizeLogin(name, tool.id);
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
      const result = await pickProfile({ tool: opts.tool, mode: resolvePickMode(opts) });
      if (!result) return;
      useProfile(result.profile.name, result.profile.tool);
      console.log(chalk.green(`✓ selected ${chalk.bold(result.profile.name)}`));
      if (result.mode === "apply") {
        applyProfile(result.profile.name, result.profile.tool);
        console.log(chalk.dim("  applied to live Claude paths"));
      } else if (result.mode === "env") {
        const tool = getTool(result.profile.tool);
        console.log(formatExportLines(profileEnv(result.profile, tool)));
      }
    }),
  );

program
  .command("active")
  .argument("[tool]", "tool id (default: claude)")
  .description("print the active profile name (for scripting)")
  .action(
    action((toolId: string | undefined) => {
      const tool = toolId ?? DEFAULT_TOOL;
      const p = currentProfile(tool);
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

program
  .command("switch")
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed when printing/launching the tool")
  .description("switch to a profile and print a restart/resume command; use --launch to run it")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("--mode <mode>", "switch mode: auto, apply, env, active", "auto")
  .option("--resume", "include the tool's resume/continue args in the handoff command")
  .option("--launch", "launch the tool after switching")
  .option("--json", "output JSON")
  .action(
    action((name: string, args: string[], opts: { tool?: string; mode: SwitchMode; resume?: boolean; launch?: boolean; json?: boolean }) => {
      const result = switchProfile(name, { tool: opts.tool, mode: opts.mode, resume: opts.resume, args });
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
        const [bin, ...launchArgs] = result.command;
        const res = spawnSync(bin!, launchArgs, {
          stdio: "inherit",
          env: { ...process.env, ...result.env },
        });
        if (res.error) die(`failed to launch ${bin}: ${res.error.message}`);
        process.exit(res.status ?? 0);
      }
    }),
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
    action((name: string | undefined, opts: { tool?: string }) => {
      const toolId = opts.tool ?? DEFAULT_TOOL;
      const profile = name ? getProfile(name, opts.tool) : currentProfile(toolId);
      if (!profile) die(`no active profile for "${toolId}". Use \`accounts use <name>\` first.`);
      const tool = getTool(profile.tool);
      console.log(formatExportLines(profileEnv(profile, tool)));
    }),
  );

program
  .command("launch")
  .alias("run")
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed to the tool binary")
  .description("launch the tool's binary with the profile's config dir active")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action((name: string, args: string[], opts: { tool?: string }) => {
      const profile = getProfile(name, opts.tool);
      const tool = getTool(profile.tool);
      const env = profileEnv(profile, tool);
      useProfile(name, tool.id); // mark active + bump lastUsedAt
      console.log(chalk.dim(`→ ${formatEnvAssignments(env)} ${tool.bin} ${args.join(" ")}`));
      const res = spawnSync(tool.bin, args, {
        stdio: "inherit",
        env: { ...process.env, ...env },
      });
      if (res.error) die(`failed to launch ${tool.bin}: ${res.error.message}`);
      process.exit(res.status ?? 0);
    }),
  );

program
  .command("shell")
  .argument("<name>", "profile name")
  .description("open a subshell with the profile's config dir active")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action((name: string, opts: { tool?: string }) => {
      const profile = getProfile(name, opts.tool);
      const tool = getTool(profile.tool);
      const env = profileEnv(profile, tool);
      useProfile(name, tool.id);
      const shell = process.env.SHELL || "/bin/sh";
      console.log(chalk.dim(`→ subshell with ${formatEnvAssignments(env)} (exit to leave)`));
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
    action((opts: { tool?: string }) => {
      const tools = opts.tool ? [getTool(opts.tool)] : listTools();
      for (const tool of tools) {
        const p = currentProfile(tool.id);
        const a = appliedProfile(tool.id);
        const val = p ? `${chalk.green.bold(p.name)}${p.email ? chalk.dim(" (" + p.email + ")") : ""}` : chalk.dim("(none)");
        const appliedVal = a && a.name !== p?.name ? chalk.magenta(` → applied: ${a.name}`) : a ? chalk.magenta(" (applied)") : "";
        console.log(`${chalk.cyan(tool.label.padEnd(14))} ${val}${appliedVal}`);
      }
    }),
  );

program
  .command("set")
  .argument("<name>", "profile name")
  .description("update a profile's email, description, or config dir")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .option("-e, --email <email>", "set the account email")
  .option("--description <text>", "set the description")
  .option("-d, --dir <path>", "set the config dir")
  .action(
    action((name: string, opts: { tool?: string; email?: string; description?: string; dir?: string }) => {
      if (opts.email === undefined && opts.description === undefined && opts.dir === undefined) {
        die("nothing to set — pass --email, --description, or --dir");
      }
      const p = updateProfile(name, opts);
      console.log(chalk.green(`✓ updated ${chalk.bold(p.name)}`));
    }),
  );

program
  .command("detect")
  .argument("<name>", "profile name")
  .description("re-detect the account email from the profile's config dir")
  .option("-t, --tool <tool>", "tool when the profile name exists for multiple tools")
  .action(
    action((name: string, opts: { tool?: string }) => {
      const p = redetectEmail(name, opts.tool);
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
    action((oldName: string, newName: string, opts: { tool?: string }) => {
      const p = renameProfile(oldName, newName, opts.tool);
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
    action((name: string, opts: { tool?: string; purge?: boolean }) => {
      const { profile, purged, purgeNote } = removeProfile(name, { tool: opts.tool, purge: opts.purge });
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
    action((name: string, opts: { tool?: string }) => {
      console.log(getProfile(name, opts.tool).dir);
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
        console.log(`${chalk.cyan(t.id.padEnd(10))} ${t.label.padEnd(16)} ${chalk.dim(envNames)} → ${chalk.dim(t.defaultDir)}  ${tag}`);
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
        const def = {
          id,
          label: opts.label,
          envVar: opts.envVar,
          bin: opts.bin,
          defaultDir: opts.defaultDir ? expandPath(opts.defaultDir) : join(homedir(), `.${id}`),
          ...(Object.keys(extraEnv).length > 0 ? { extraEnv } : {}),
          ...(opts.loginArg ? { loginArgs: opts.loginArg } : {}),
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
    action(() => {
      console.log(chalk.bold(`store: ${storePath()}`));
      const store = loadStore();
      const profiles = listProfiles();
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
      for (const [toolId, appliedName] of Object.entries(store.applied)) {
        if (!profiles.some((p) => p.name === appliedName && p.tool === toolId)) {
          console.log(chalk.red(`  ✗ stale applied.${toolId}: "${appliedName}" (profile missing)`));
          problems++;
        }
      }
      for (const [toolId, currentName] of Object.entries(store.current)) {
        if (!profiles.some((p) => p.name === currentName && p.tool === toolId)) {
          console.log(chalk.red(`  ✗ stale current.${toolId}: "${currentName}" (profile missing)`));
          problems++;
        }
      }
      const driftWarned = new Set<string>();
      for (const p of profiles) {
        const active = store.current[p.tool];
        const applied = store.applied[p.tool];
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
