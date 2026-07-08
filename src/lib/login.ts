import { accessSync, constants, existsSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { createInterface, type Interface } from "node:readline";
import type { Profile } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile } from "./apply.js";
import { ensureProfileAuthSnapshot } from "./claude-auth.js";
import { getProfileToolLock, lockProfileTool } from "./profiles.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { getTool, listTools, mergeToolArgs } from "./tools.js";
import type { ToolDef } from "../types.js";
import { profilesDir } from "../storage.js";

export interface FinalizeLoginResult {
  profile: Profile;
  applied: boolean;
}

export interface ToolAvailability {
  available: boolean;
  bin: string;
  path?: string;
  reason?: string;
}

export interface LoginToolChoice {
  tool: ToolDef;
  availability: ToolAvailability;
  hasProfile: boolean;
}

interface PromptSession {
  input: NodeJS.ReadStream;
  output: NodeJS.WriteStream;
  rl?: Interface;
  lines?: string[];
  waiters?: Array<(line: string | undefined) => void>;
  closed?: boolean;
}

export interface PrepareLoginOptions {
  toolId?: string;
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
  env?: NodeJS.ProcessEnv;
  forceInteractive?: boolean;
  /** Registry store to route reads/writes through (defaults to `resolveStore()`). */
  store?: AccountsStore;
}

export interface LoginPreparationReady {
  status: "ready";
  profile: Profile;
  tool: ToolDef;
  args: string[];
}

export interface LoginPreparationStopped {
  status: "stopped";
  profile: Profile;
  tool: ToolDef;
  message: string;
}

export type LoginPreparation = LoginPreparationReady | LoginPreparationStopped;

function isExecutable(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function pathCandidates(bin: string, env: NodeJS.ProcessEnv): string[] {
  if (isAbsolute(bin) || bin.includes("/") || bin.includes("\\")) return [bin];
  const extensions =
    process.platform === "win32" ? (env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";").filter(Boolean) : [""];
  return (env.PATH ?? "")
    .split(delimiter)
    .filter(Boolean)
    .flatMap((dir) => extensions.map((ext) => join(dir, `${bin}${ext}`)));
}

function findExecutable(bin: string, env: NodeJS.ProcessEnv): string | undefined {
  for (const candidate of pathCandidates(bin, env)) {
    if (isExecutable(candidate)) return candidate;
  }
  return undefined;
}

function cursorIdeInstalled(env: NodeJS.ProcessEnv): boolean {
  if (findExecutable("cursor", env)) return true;
  const candidates =
    process.platform === "darwin"
      ? ["/Applications/Cursor.app", join(homedir(), "Applications", "Cursor.app")]
      : process.platform === "win32"
        ? [
            env.LOCALAPPDATA ? join(env.LOCALAPPDATA, "Programs", "Cursor", "Cursor.exe") : "",
            env.ProgramFiles ? join(env.ProgramFiles, "Cursor", "Cursor.exe") : "",
          ]
        : ["/usr/share/cursor", "/opt/Cursor", "/opt/cursor"];
  return candidates.filter(Boolean).some((candidate) => existsSync(candidate));
}

export function detectToolAvailability(tool: ToolDef, env: NodeJS.ProcessEnv = process.env): ToolAvailability {
  const path = findExecutable(tool.bin, env);
  if (!path) {
    return {
      available: false,
      bin: tool.bin,
      reason: isAbsolute(tool.bin) || tool.bin.includes("/") || tool.bin.includes("\\") ? "binary was not found" : "binary is not on PATH",
    };
  }
  if (tool.id === "cursor" && !cursorIdeInstalled(env)) {
    return {
      available: false,
      bin: tool.bin,
      path,
      reason: "Cursor IDE installation was not found",
    };
  }
  return { available: true, bin: tool.bin, path };
}

export function installInstructions(tool: ToolDef): string {
  if (tool.id === "cursor") {
    return "Install Cursor from https://cursor.com/download, then run `accounts login <name> --tool cursor` again.";
  }
  if (isAbsolute(tool.bin) || tool.bin.includes("/") || tool.bin.includes("\\")) {
    return `Install ${tool.label} so the binary exists at ${tool.bin}.`;
  }
  return `Install ${tool.label} so \`${tool.bin}\` is available on PATH.`;
}

export async function loginToolChoices(
  name: string,
  env: NodeJS.ProcessEnv = process.env,
  store: AccountsStore = resolveStore(),
): Promise<LoginToolChoice[]> {
  const existing = new Set(
    (await store.listProfiles()).filter((profile) => profile.name === name).map((profile) => profile.tool),
  );
  return listTools()
    .map((tool) => ({
      tool,
      availability: detectToolAvailability(tool, env),
      hasProfile: existing.has(tool.id),
    }))
    .sort((a, b) => {
      if (a.availability.available !== b.availability.available) return a.availability.available ? -1 : 1;
      if (a.hasProfile !== b.hasProfile) return a.hasProfile ? -1 : 1;
      return a.tool.label.localeCompare(b.tool.label) || a.tool.id.localeCompare(b.tool.id);
    });
}

function managedProfileDir(name: string, toolId: string): string {
  return join(profilesDir(), toolId, name);
}

async function profileDirForLogin(name: string, toolId: string, store: AccountsStore): Promise<string> {
  return (await store.listProfiles(toolId)).find((profile) => profile.name === name)?.dir ?? managedProfileDir(name, toolId);
}

function canPrompt(opts: PrepareLoginOptions): boolean {
  if (opts.forceInteractive) return true;
  if (opts.env?.ACCOUNTS_FORCE_INTERACTIVE === "1") return true;
  return Boolean(opts.input?.isTTY && opts.output?.isTTY);
}

function statusText(choice: LoginToolChoice): string {
  const parts: string[] = [];
  parts.push(choice.availability.available ? "available" : `requires install: ${choice.availability.reason ?? "unavailable"}`);
  if (choice.hasProfile) parts.push("existing profile");
  return parts.join(", ");
}

export function nonInteractiveToolSelectionMessage(name: string, choices: LoginToolChoice[]): string {
  const installed = choices.filter((choice) => choice.availability.available).map((choice) => choice.tool.id);
  const commands = choices
    .map((choice) => `  accounts login ${name} --tool ${choice.tool.id}${choice.availability.available ? "" : "  # requires install"}`);
  return [
    `profile "${name}" is not locked to a tool.`,
    "Run one of these commands to choose the tool explicitly:",
    ...commands,
    installed.length > 0 ? `Installed tools: ${installed.join(", ")}` : "No supported tool binaries were found on PATH.",
  ].join("\n");
}

export async function unavailableToolMessage(
  name: string,
  tool: ToolDef,
  availability: ToolAvailability,
  store: AccountsStore = resolveStore(),
): Promise<string> {
  return [
    `${tool.label} is selected for profile "${name}", but it is unavailable: ${availability.reason ?? "not installed"}.`,
    installInstructions(tool).replace("<name>", name),
    `Profile dir if kept selected: ${JSON.stringify(await profileDirForLogin(name, tool.id, store))}`,
    `To choose another tool, run: accounts login ${name} --tool <tool-id>`,
  ].join("\n");
}

function ensurePromptReader(session: PromptSession): void {
  if (session.rl) return;
  session.lines = [];
  session.waiters = [];
  session.closed = false;
  const rl = createInterface({
    input: session.input,
    output: session.output,
    terminal: Boolean(session.input.isTTY && session.output.isTTY),
  });
  rl.on("line", (line) => {
    const waiter = session.waiters?.shift();
    if (waiter) waiter(line);
    else session.lines?.push(line);
  });
  rl.once("close", () => {
    session.closed = true;
    const waiters = session.waiters?.splice(0) ?? [];
    for (const waiter of waiters) waiter(undefined);
  });
  session.rl = rl;
}

function readLine(session: PromptSession, prompt: string): Promise<string | undefined> {
  ensurePromptReader(session);
  session.output.write(prompt);
  const buffered = session.lines?.shift();
  if (buffered !== undefined) return Promise.resolve(buffered);
  if (session.closed) return Promise.resolve(undefined);
  return new Promise((resolve) => session.waiters?.push(resolve));
}

function closePrompt(session: PromptSession): void {
  session.rl?.close();
  session.rl = undefined;
}

async function promptForTool(
  name: string,
  opts: PrepareLoginOptions,
  session: PromptSession,
  store: AccountsStore,
  reason?: string,
): Promise<ToolDef> {
  const choices = await loginToolChoices(name, opts.env, store);
  if (!canPrompt({ ...opts, input: session.input, output: session.output })) {
    throw new AccountsError(nonInteractiveToolSelectionMessage(name, choices));
  }

  if (reason) session.output.write(`${reason}\n`);
  session.output.write(`Choose a tool for profile "${name}":\n`);
  choices.forEach((choice, index) => {
    session.output.write(`  ${index + 1}. ${choice.tool.label} (${choice.tool.id}) - ${statusText(choice)}\n`);
  });
  session.output.write("  q. Cancel\n");

  while (true) {
    const answer = (await readLine(session, "Tool: "))?.trim();
    if (!answer || answer.toLowerCase() === "q" || answer.toLowerCase() === "cancel") {
      throw new AccountsError("cancelled; no profile tool was changed");
    }
    const numeric = Number(answer);
    const choice = Number.isInteger(numeric) ? choices[numeric - 1] : choices.find((item) => item.tool.id === answer);
    if (choice) return choice.tool;
    session.output.write(`Enter a number from 1-${choices.length}, a tool id, or q to cancel.\n`);
  }
}

async function promptForUnavailableTool(
  name: string,
  tool: ToolDef,
  availability: ToolAvailability,
  opts: PrepareLoginOptions,
  session: PromptSession,
  store: AccountsStore,
) {
  if (!canPrompt({ ...opts, input: session.input, output: session.output })) {
    throw new AccountsError(await unavailableToolMessage(name, tool, availability, store));
  }

  session.output.write(`${await unavailableToolMessage(name, tool, availability, store)}\n`);
  session.output.write("  1. Choose another tool\n");
  session.output.write(`  2. Keep ${tool.label} selected and stop\n`);
  session.output.write("  3. Cancel without changes\n");

  while (true) {
    const answer = (await readLine(session, "Choice: "))?.trim().toLowerCase();
    if (answer === "1" || answer === "choose" || answer === "other") return "choose-other" as const;
    if (answer === "2" || answer === "keep") return "keep" as const;
    if (!answer || answer === "3" || answer === "cancel" || answer === "q") return "cancel" as const;
    session.output.write("Enter 1, 2, or 3.\n");
  }
}

async function existingOrCreateProfile(name: string, tool: ToolDef, store: AccountsStore): Promise<Profile> {
  const existing = await store.findProfile(name, tool.id);
  const profile = existing ?? (await store.addProfile({ name, tool: tool.id, description: "created for login" }));
  // The tool lock is a machine-local disambiguation for bare commands; only the
  // LocalStore keeps it. In api mode the shared registry (+ explicit --tool)
  // resolves the profile, so there is no local lock to write.
  if (store.transport === "local") lockProfileTool(profile.name, profile.tool);
  return profile;
}

async function selectLoginTool(
  name: string,
  opts: PrepareLoginOptions,
  session: PromptSession,
  store: AccountsStore,
): Promise<ToolDef> {
  if (opts.toolId) return getTool(opts.toolId);

  if (store.transport === "local") {
    const lockedTool = getProfileToolLock(name);
    if (lockedTool) return getTool(lockedTool);
  }

  const matches = (await store.listProfiles()).filter((profile) => profile.name === name);
  if (matches.length === 1) {
    return getTool(matches[0]!.tool);
  }

  const reason =
    matches.length > 1
      ? `profile "${name}" exists for multiple tools (${matches.map((profile) => profile.tool).join(", ")}).`
      : undefined;
  return promptForTool(name, opts, session, store, reason);
}

export async function prepareLogin(name: string, opts: PrepareLoginOptions = {}): Promise<LoginPreparation> {
  const store = opts.store ?? resolveStore();
  const session: PromptSession = {
    input: opts.input ?? process.stdin,
    output: opts.output ?? process.stderr,
  };
  try {
    let tool = await selectLoginTool(name, opts, session, store);

    while (true) {
      const availability = detectToolAvailability(tool, opts.env);
      if (availability.available) {
        const profile = await existingOrCreateProfile(name, tool, store);
        return {
          status: "ready",
          profile,
          tool,
          args: mergeToolArgs(tool, tool.loginArgs ?? [], { profile }),
        };
      }

      const action = await promptForUnavailableTool(name, tool, availability, opts, session, store);
      if (action === "choose-other") {
        tool = await promptForTool(name, opts, session, store, `${tool.label} is unavailable; choose another tool.`);
        continue;
      }
      if (action === "keep") {
        const profile = await existingOrCreateProfile(name, tool, store);
        return {
          status: "stopped",
          profile,
          tool,
          message: await unavailableToolMessage(name, tool, availability, store),
        };
      }
      throw new AccountsError("cancelled; no profile tool was changed");
    }
  } finally {
    closePrompt(session);
  }
}

/**
 * Finish an isolated login after the tool process exits successfully.
 * Claude login becomes the live/default account; other tools are marked active
 * and have metadata re-detected where possible.
 */
export async function finalizeLogin(
  name: string,
  toolId?: string,
  store: AccountsStore = resolveStore(),
): Promise<FinalizeLoginResult> {
  const profile = await store.getProfile(name, toolId);
  const tool = getTool(profile.tool);

  if (tool.id === "claude") {
    ensureProfileAuthSnapshot(profile.dir, tool, { overwrite: true });
    await store.redetectEmail(name, tool.id);
    return { profile: (await applyProfile(name, tool.id, store)).profile, applied: true };
  }

  const updated = await store.redetectEmail(name, tool.id);
  await store.useProfile(name, tool.id);
  return { profile: updated, applied: false };
}
