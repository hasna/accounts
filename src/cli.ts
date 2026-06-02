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
import { storePath } from "./storage.js";

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

function fmtProfile(p: Profile, active: boolean): string {
  const marker = active ? chalk.green("●") : chalk.dim("○");
  const name = active ? chalk.green.bold(p.name) : chalk.bold(p.name);
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
      console.log(chalk.dim(`  launch it:  accounts launch ${p.name}    (sets ${tool.envVar} and runs ${tool.bin})`));
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
        console.log(fmtProfile(p, active));
      }
    }),
  );

program
  .command("show")
  .argument("<name>", "profile name")
  .description("show full details for a profile")
  .option("--json", "output JSON")
  .action(
    action((name: string, opts: { json?: boolean }) => {
      const p = getProfile(name);
      if (opts.json) {
        console.log(JSON.stringify(p, null, 2));
        return;
      }
      const active = currentProfile(p.tool)?.name === p.name;
      console.log(fmtProfile(p, active));
      console.log(`  tool:       ${p.tool} (${getTool(p.tool).label})`);
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
  .action(
    action((name: string) => {
      const { profile, toolId } = useProfile(name);
      const tool = getTool(toolId);
      console.log(chalk.green(`✓ ${chalk.bold(profile.name)} is now the active ${tool.label} profile`));
      console.log(chalk.dim("  this CLI can't change your current shell's env, so either:"));
      console.log(`    eval "$(accounts env ${profile.name})"        ${chalk.dim("# export into this shell")}`);
      console.log(`    accounts launch ${profile.name}                ${chalk.dim("# launch " + tool.bin + " with it")}`);
    }),
  );

program
  .command("env")
  .argument("[name]", "profile name (defaults to the active profile for the tool)")
  .description("print the `export VAR=dir` line to activate a profile in your shell")
  .option("-t, --tool <tool>", "tool (used when no name is given)", DEFAULT_TOOL)
  .action(
    action((name: string | undefined, opts: { tool: string }) => {
      const profile = name ? getProfile(name) : currentProfile(opts.tool);
      if (!profile) die(`no active profile for "${opts.tool}". Use \`accounts use <name>\` first.`);
      const tool = getTool(profile.tool);
      console.log(`export ${tool.envVar}=${JSON.stringify(profile.dir)}`);
    }),
  );

program
  .command("launch")
  .alias("run")
  .argument("<name>", "profile name")
  .argument("[args...]", "extra args passed to the tool binary")
  .description("launch the tool's binary with the profile's config dir active")
  .action(
    action((name: string, args: string[]) => {
      const profile = getProfile(name);
      const tool = getTool(profile.tool);
      useProfile(name); // mark active + bump lastUsedAt
      console.log(chalk.dim(`→ ${tool.envVar}=${profile.dir} ${tool.bin} ${args.join(" ")}`));
      const res = spawnSync(tool.bin, args, {
        stdio: "inherit",
        env: { ...process.env, [tool.envVar]: profile.dir },
      });
      if (res.error) die(`failed to launch ${tool.bin}: ${res.error.message}`);
      process.exit(res.status ?? 0);
    }),
  );

program
  .command("shell")
  .argument("<name>", "profile name")
  .description("open a subshell with the profile's config dir active")
  .action(
    action((name: string) => {
      const profile = getProfile(name);
      const tool = getTool(profile.tool);
      useProfile(name);
      const shell = process.env.SHELL || "/bin/sh";
      console.log(chalk.dim(`→ subshell with ${tool.envVar}=${profile.dir} (exit to leave)`));
      const res = spawnSync(shell, ["-i"], {
        stdio: "inherit",
        env: { ...process.env, [tool.envVar]: profile.dir, ACCOUNTS_ACTIVE: profile.name },
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
        const val = p ? `${chalk.green.bold(p.name)}${p.email ? chalk.dim(" (" + p.email + ")") : ""}` : chalk.dim("(none)");
        console.log(`${chalk.cyan(tool.label.padEnd(14))} ${val}`);
      }
    }),
  );

program
  .command("set")
  .argument("<name>", "profile name")
  .description("update a profile's email, description, or config dir")
  .option("-e, --email <email>", "set the account email")
  .option("--description <text>", "set the description")
  .option("-d, --dir <path>", "set the config dir")
  .action(
    action((name: string, opts: { email?: string; description?: string; dir?: string }) => {
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
  .action(
    action((name: string) => {
      const p = redetectEmail(name);
      console.log(p.email ? chalk.green(`✓ ${p.name}: ${p.email}`) : chalk.yellow(`no email found in ${p.dir}`));
    }),
  );

program
  .command("rename")
  .argument("<old>", "current name")
  .argument("<new>", "new name")
  .description("rename a profile")
  .action(
    action((oldName: string, newName: string) => {
      const p = renameProfile(oldName, newName);
      console.log(chalk.green(`✓ renamed to ${chalk.bold(p.name)}`));
    }),
  );

program
  .command("remove")
  .alias("rm")
  .argument("<name>", "profile name")
  .description("remove a profile from the registry")
  .option("--purge", "also delete the managed config dir on disk")
  .action(
    action((name: string, opts: { purge?: boolean }) => {
      const { profile, purged, purgeNote } = removeProfile(name, opts.purge);
      console.log(chalk.green(`✓ removed ${chalk.bold(profile.name)}`));
      if (purged) console.log(chalk.dim(`  deleted ${profile.dir}`));
      if (purgeNote) console.log(chalk.yellow(`  ${purgeNote}`));
    }),
  );

program
  .command("path")
  .argument("<name>", "profile name")
  .description("print just the config dir path (useful for scripting)")
  .action(
    action((name: string) => {
      console.log(getProfile(name).dir);
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
        console.log(`${chalk.cyan(t.id.padEnd(10))} ${t.label.padEnd(16)} ${chalk.dim(t.envVar)} → ${chalk.dim(t.defaultDir)}  ${tag}`);
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
  .option("--account-file <file>", "file inside the config dir holding the email")
  .option("--email-path <path>", "dot-path to the email inside that file (e.g. account.email)")
  .action(
    action(
      (
        id: string,
        opts: { label: string; envVar: string; bin: string; defaultDir?: string; accountFile?: string; emailPath?: string },
      ) => {
        const def = {
          id,
          label: opts.label,
          envVar: opts.envVar,
          bin: opts.bin,
          defaultDir: opts.defaultDir ? expandPath(opts.defaultDir) : join(homedir(), `.${id}`),
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
  .description("check the store and profile dirs for problems")
  .action(
    action(() => {
      console.log(chalk.bold(`store: ${storePath()}`));
      const profiles = listProfiles();
      let problems = 0;
      for (const p of profiles) {
        const missing = !existsSync(p.dir);
        const noEmail = !p.email;
        if (missing) {
          console.log(chalk.red(`  ✗ ${p.name}: config dir missing (${p.dir})`));
          problems++;
        }
        if (noEmail) {
          console.log(chalk.yellow(`  ! ${p.name}: no email recorded`));
        }
        if (!missing && !noEmail) console.log(chalk.green(`  ✓ ${p.name}`));
      }
      if (profiles.length === 0) console.log(chalk.dim("  no profiles."));
      console.log(problems === 0 ? chalk.green("\nhealthy.") : chalk.red(`\n${problems} problem(s) found.`));
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
