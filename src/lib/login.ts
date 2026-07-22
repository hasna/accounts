import { accessSync, constants, existsSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { createInterface, type Interface } from "node:readline";
import type { Profile } from "../types.js";
import { AccountsError } from "../types.js";
import { applyProfile, ownsApplyAuthWrites, type ApplyTransactionTracker } from "./apply.js";
import {
  assertClaudeProfileCommittedAuthSnapshot,
  captureClaudeLiveAuthSnapshot,
  captureClaudeProfileAuthSnapshot,
  ensureProfileAuthSnapshot,
  restoreClaudeProfileCommittedAuthSnapshot,
  restoreClaudeLiveAuthSnapshot,
  restoreClaudeProfileAuthSnapshot,
  writeClaudeProfileCommittedAuthSnapshot,
  pruneClaudeProfileCommittedAuthSnapshotSets,
  type ClaudeLiveAuthSnapshot,
  type ClaudeProfileAuthSnapshot,
} from "./claude-auth.js";
import {
  claimProfileToolLock,
  getProfileToolLock,
  planProfileToolLockClaim,
  restoreProfileToolLock,
} from "./profiles.js";
import { withApplyLockWait } from "./apply-lock.js";
import { detectEmail } from "./detect.js";
import {
  resolveStore,
  beginLoginCleanupIntent,
  abandonLoginCleanupIntentInProcess,
  clearLoginCleanupIntentByOperation,
  evolveLoginCleanupIntent,
  injectLoginCleanupFaultForTests,
  isInjectedLoginCleanupFault,
  LoginCleanupInProgressError,
  type AccountsStore,
  type CurrentEntry,
  type LoginCleanupIntent,
  type ProfileRollbackFields,
} from "./store.js";
import { mergeToolArgs } from "./tools.js";
import type { ToolDef } from "../types.js";
import {
  accountsHome,
  loadMachineStore,
  findProfileAuthRevisionKey,
  parkedProfileAuthRevisionKey,
  profileAuthIncarnation,
  profileAuthRevisionKey,
  profilesDir,
  saveStore,
  withStoreLock,
} from "../storage.js";
import { assertSafeWritePath } from "./safe-path.js";

export interface FinalizeLoginResult {
  profile: Profile;
  applied: boolean;
}

export interface LoginFinalizationState {
  tool: ToolDef;
  profile: Profile;
  current?: CurrentEntry;
  applied?: { name: string; revision?: string };
  liveClaude?: ClaudeLiveAuthSnapshot;
  profileClaude?: ClaudeProfileAuthSnapshot;
  profileClaudeIdentityRevision?: string;
  profileClaudeCommitRevision?: string;
  writes: ApplyTransactionTracker & {
    profile: ProfileRollbackFields;
  };
}

function ownedProfileIdentityKey(
  machine: ReturnType<typeof loadMachineStore>,
  state: LoginFinalizationState,
  currentProfile: Profile,
): string | undefined {
  const identity = state.profileClaudeIdentityRevision;
  if (!identity) return undefined;
  const currentKey = findProfileAuthRevisionKey(machine, currentProfile);
  return currentKey && machine.profileAuthRevisions[currentKey] === identity
    ? currentKey
    : undefined;
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
  /** Validate the final selected tool before creating a profile or tool lock. */
  validateTool?: (tool: ToolDef) => void | Promise<void>;
  /** Optionally serialize preparation through a tool-specific profile lease. */
  acquireProfileLease?: (
    profileDir: string,
    tool: ToolDef,
  ) => Promise<(() => void) | undefined>;
  /** Registry store to route reads/writes through (defaults to `resolveStore()`). */
  store?: AccountsStore;
}

export interface LoginPreparationReady {
  status: "ready";
  profile: Profile;
  tool: ToolDef;
  args: string[];
  created: boolean;
  createdProfileDir: boolean;
  previousToolLock?: string;
  previousToolLockRevision?: string;
  previousToolLockProfileIncarnation?: string;
  toolLockRevision?: string;
  cleanupOperationId?: string;
  cleanupRequestedAt?: string;
  releaseProfileLease?: () => void;
}

export interface LoginPreparationStopped {
  status: "stopped";
  profile: Profile;
  tool: ToolDef;
  message: string;
  created: boolean;
  createdProfileDir: boolean;
  previousToolLock?: string;
  previousToolLockRevision?: string;
  previousToolLockProfileIncarnation?: string;
  toolLockRevision?: string;
  cleanupOperationId?: string;
  cleanupRequestedAt?: string;
  releaseProfileLease?: () => void;
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
  return (await store.listTools())
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

interface PreparedProfile {
  profile: Profile;
  created: boolean;
  createdProfileDir: boolean;
  previousToolLock?: string;
  previousToolLockRevision?: string;
  previousToolLockProfileIncarnation?: string;
  toolLockRevision?: string;
  cleanupOperationId?: string;
  cleanupRequestedAt?: string;
  releaseProfileLease?: () => void;
}

async function existingOrCreateProfile(
  name: string,
  tool: ToolDef,
  store: AccountsStore,
  reconciledExisting?: { profile: Profile | undefined },
): Promise<PreparedProfile> {
  if (!reconciledExisting) {
    await store.reconcileInterruptedLoginCleanup?.(name, tool.id);
  }
  let existing = reconciledExisting
    ? reconciledExisting.profile
    : await store.findProfile(name, tool.id);
  if (!existing) {
    await store.assertCreatedProfileCleanup?.();
  }
  const managedDir = managedProfileDir(name, tool.id);
  let intent: LoginCleanupIntent = beginLoginCleanupIntent(
    name,
    tool.id,
    store.transport,
    existing?.dir ?? managedDir,
    Boolean(existing),
    existing?.incarnationId ?? randomUUID(),
  );
  const plannedAuthIdentity = store.transport === "api" && tool.id === "claude"
    ? randomUUID()
    : undefined;
  if (plannedAuthIdentity) {
    intent = evolveLoginCleanupIntent(intent, {
      ownership: {
        cleanupOperationId: intent.cleanupOperationId,
        cleanupRequestedAt: intent.cleanupRequestedAt,
        authIdentity: plannedAuthIdentity,
      },
    });
  }
  try {
    // This durable registry record is now the first login preparation write.
    injectLoginCleanupFaultForTests("pre-create", intent.cleanupOperationId);
    if (existing && store.upgradeProfileIncarnationForLogin) {
      existing = await store.upgradeProfileIncarnationForLogin(
        existing,
        intent.plannedIncarnationId,
      );
    }
    const fallbackCreatedProfileDir = !existing && intent.createdProfileDir;
    const createdProfile = existing
      ? undefined
      : store.addProfileForLogin
        ? await store.addProfileForLogin(
            { name, tool: tool.id, description: "created for login" },
            {
              cleanupOperationId: intent.cleanupOperationId,
              cleanupRequestedAt: intent.cleanupRequestedAt,
              plannedIncarnationId: intent.plannedIncarnationId,
              ...(plannedAuthIdentity ? { plannedAuthIdentity } : {}),
            },
          )
        : {
            profile: await store.addProfile({ name, tool: tool.id, description: "created for login" }),
            createdProfileDir: fallbackCreatedProfileDir,
          };
    const profile = existing ?? createdProfile!.profile;
    const builtInFenceWasPlanned = Boolean(
      (existing && store.upgradeProfileIncarnationForLogin) ||
      (!existing && store.addProfileForLogin),
    );
    if (builtInFenceWasPlanned && profile.incarnationId !== intent.plannedIncarnationId) {
      throw new AccountsError("login profile did not retain its planned rollback fence");
    }
    if (
      !builtInFenceWasPlanned &&
      profile.incarnationId &&
      profile.incarnationId !== intent.plannedIncarnationId
    ) {
      intent = evolveLoginCleanupIntent(intent, {
        plannedIncarnationId: profile.incarnationId,
      });
    }
    const createdProfileDir = createdProfile?.createdProfileDir ?? false;
    intent = evolveLoginCleanupIntent(intent, {
      phase: "profile-created",
      createdProfileDir,
      ownership: {
        cleanupOperationId: intent.cleanupOperationId,
        cleanupRequestedAt: intent.cleanupRequestedAt,
        ...(plannedAuthIdentity ? { authIdentity: plannedAuthIdentity } : {}),
      },
    });

    // The tool lock is machine-local. Plan its generation and persist exact
    // displaced fields before claiming it, so a crash immediately after the
    // registry write remains conditionally reversible.
    const toolLockPlan = store.transport === "local"
      ? planProfileToolLockClaim(profile.name, profile.tool)
      : undefined;
    if (toolLockPlan) {
      intent = evolveLoginCleanupIntent(intent, {
        phase: "lock-planned",
        ownership: {
          cleanupOperationId: intent.cleanupOperationId,
          cleanupRequestedAt: intent.cleanupRequestedAt,
          ...(plannedAuthIdentity ? { authIdentity: plannedAuthIdentity } : {}),
          toolLockRevision: toolLockPlan.revision,
          ...(toolLockPlan.previousTool
            ? { previousToolLock: toolLockPlan.previousTool }
            : {}),
          ...(toolLockPlan.previousRevision
            ? { previousToolLockRevision: toolLockPlan.previousRevision }
            : {}),
          ...(toolLockPlan.previousProfileIncarnation
            ? { previousToolLockProfileIncarnation: toolLockPlan.previousProfileIncarnation }
            : {}),
        },
      });
    }
    const toolLockClaim = toolLockPlan
      ? claimProfileToolLock(profile.name, profile.tool, toolLockPlan)
      : undefined;
    if (toolLockClaim) {
      injectLoginCleanupFaultForTests("post-lock", intent.cleanupOperationId);
    }
    return {
      profile,
      created: !existing,
      createdProfileDir,
      cleanupOperationId: intent.cleanupOperationId,
      cleanupRequestedAt: intent.cleanupRequestedAt,
      ...(toolLockClaim?.previousTool ? { previousToolLock: toolLockClaim.previousTool } : {}),
      ...(toolLockClaim?.previousRevision
        ? { previousToolLockRevision: toolLockClaim.previousRevision }
        : {}),
      ...(toolLockClaim?.previousProfileIncarnation
        ? { previousToolLockProfileIncarnation: toolLockClaim.previousProfileIncarnation }
        : {}),
      ...(toolLockClaim ? { toolLockRevision: toolLockClaim.revision } : {}),
    };
  } catch (error) {
    if (isInjectedLoginCleanupFault(error)) throw error;
    abandonLoginCleanupIntentInProcess(intent.cleanupOperationId);
    try {
      await store.reconcileInterruptedLoginCleanup?.(name, tool.id);
    } catch (rollbackError) {
      throw new AccountsError(
        `login preparation failed and cleanup could not be reconciled: ${
          rollbackError instanceof Error ? rollbackError.message : String(rollbackError)
        }`,
      );
    }
    throw error;
  }
}

function samePreparationProfile(
  expected: Profile,
  current: Profile | undefined,
): boolean {
  if (!current || expected.tool !== current.tool || expected.name !== current.name) return false;
  if (expected.incarnationId) return current.incarnationId === expected.incarnationId;
  return profileAuthIncarnation(current) === profileAuthIncarnation(expected);
}

async function prepareSelectedProfile(
  name: string,
  tool: ToolDef,
  opts: PrepareLoginOptions,
  store: AccountsStore,
): Promise<PreparedProfile> {
  await opts.validateTool?.(tool);
  if (!opts.acquireProfileLease) return existingOrCreateProfile(name, tool, store);

  // Recover stale work before acquiring the live-login lease. A live owner is
  // expected here: wait on the established profile lease instead of treating
  // its durable intent as interrupted.
  try {
    await store.reconcileInterruptedLoginCleanup?.(name, tool.id);
  } catch (error) {
    if (!(error instanceof LoginCleanupInProgressError)) throw error;
  }
  const expected = await store.findProfile(name, tool.id);
  const profileDir = expected?.dir ?? managedProfileDir(name, tool.id);
  const release = await opts.acquireProfileLease(profileDir, tool);
  try {
    await store.reconcileInterruptedLoginCleanup?.(name, tool.id);
    const current = await store.findProfile(name, tool.id);
    if (expected && !samePreparationProfile(expected, current)) {
      throw new AccountsError("profile changed before Claude auth capture");
    }
    const prepared = await existingOrCreateProfile(
      name,
      tool,
      store,
      { profile: current },
    );
    return {
      ...prepared,
      ...(release ? { releaseProfileLease: release } : {}),
    };
  } catch (error) {
    release?.();
    throw error;
  }
}

async function selectLoginTool(
  name: string,
  opts: PrepareLoginOptions,
  session: PromptSession,
  store: AccountsStore,
): Promise<ToolDef> {
  if (opts.toolId) return store.resolveTool(opts.toolId);

  if (store.transport === "local") {
    const lockedTool = getProfileToolLock(name);
    if (lockedTool) return store.resolveTool(lockedTool);
  }

  const matches = (await store.listProfiles()).filter((profile) => profile.name === name);
  if (matches.length === 1) {
    return store.resolveTool(matches[0]!.tool);
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
        const prepared = await prepareSelectedProfile(name, tool, opts, store);
        return {
          status: "ready",
          ...prepared,
          tool,
          args: mergeToolArgs(tool, tool.loginArgs ?? [], { profile: prepared.profile }),
        };
      }

      const action = await promptForUnavailableTool(name, tool, availability, opts, session, store);
      if (action === "choose-other") {
        tool = await promptForTool(name, opts, session, store, `${tool.label} is unavailable; choose another tool.`);
        continue;
      }
      if (action === "keep") {
        const prepared = await prepareSelectedProfile(name, tool, opts, store);
        const stopped: LoginPreparationStopped = {
          status: "stopped",
          ...prepared,
          tool,
          message: await unavailableToolMessage(name, tool, availability, store),
        };
        commitLoginPreparation(stopped, store);
        stopped.releaseProfileLease?.();
        delete stopped.releaseProfileLease;
        return stopped;
      }
      throw new AccountsError("cancelled; no profile tool was changed");
    }
  } finally {
    closePrompt(session);
  }
}

/** Roll back only state created or changed while preparing a failed login. */
export async function rollbackLoginPreparation(
  preparation: LoginPreparationReady,
  store: AccountsStore = resolveStore(),
  expectedProfileAuthIdentity?: string,
  expectedProfileAuthCommitRevision?: string,
): Promise<void> {
  let removed = false;
  let rollbackReachedTerminalState = false;
  try {
    if (
      preparation.created &&
      store.removeProfileIncarnation
    ) {
      removed = Boolean(await store.removeProfileIncarnation(
        preparation.profile,
        {
          ...(preparation.cleanupOperationId
            ? { cleanupOperationId: preparation.cleanupOperationId }
            : {}),
          ...(preparation.cleanupRequestedAt
            ? { cleanupRequestedAt: preparation.cleanupRequestedAt }
            : {}),
          ...(preparation.toolLockRevision
            ? { toolLockRevision: preparation.toolLockRevision }
            : {}),
          ...(preparation.previousToolLock
            ? { previousToolLock: preparation.previousToolLock }
            : {}),
          ...(preparation.previousToolLockRevision
            ? { previousToolLockRevision: preparation.previousToolLockRevision }
            : {}),
          ...(preparation.previousToolLockProfileIncarnation
            ? { previousToolLockProfileIncarnation: preparation.previousToolLockProfileIncarnation }
            : {}),
          ...(expectedProfileAuthIdentity
            ? { authIdentity: expectedProfileAuthIdentity }
            : {}),
          ...(expectedProfileAuthCommitRevision
            ? { authCommitRevision: expectedProfileAuthCommitRevision }
            : {}),
        },
        { tool: preparation.tool.id, purge: preparation.createdProfileDir },
      ));
    }
    rollbackReachedTerminalState = true;
  } catch (error) {
    if (preparation.cleanupOperationId) {
      abandonLoginCleanupIntentInProcess(preparation.cleanupOperationId);
    }
    throw error;
  } finally {
    if (store.transport === "local" && !removed) {
      const currentIncarnation = (await store.listProfiles(preparation.tool.id)).find(
        (profile) =>
          profile.name === preparation.profile.name &&
          profile.incarnationId === preparation.profile.incarnationId,
      );
      if (currentIncarnation) {
        if (preparation.toolLockRevision) {
          restoreProfileToolLock(
            currentIncarnation.name,
            preparation.toolLockRevision,
            preparation.previousToolLock,
            preparation.previousToolLockRevision ?? null,
            preparation.previousToolLockProfileIncarnation,
          );
        }
      }
    }
    if (rollbackReachedTerminalState) {
      clearLoginCleanupIntentByOperation(
        preparation.profile.name,
        preparation.tool.id,
        store.transport,
        preparation.cleanupOperationId,
      );
    }
  }
}

/** Mark preparation ownership terminal after a successful or intentional login. */
export function commitLoginPreparation(
  preparation: LoginPreparationReady | LoginPreparationStopped,
  store: AccountsStore = resolveStore(),
): void {
  clearLoginCleanupIntentByOperation(
    preparation.profile.name,
    preparation.tool.id,
    store.transport,
    preparation.cleanupOperationId,
  );
}

async function resolveUnchangedLoginTool(
  captured: ToolDef,
  store: AccountsStore,
  required: boolean,
): Promise<ToolDef | undefined> {
  try {
    const current = await store.resolveTool(captured.id);
    if (isDeepStrictEqual(current, captured)) return current;
  } catch {
    // Removal and API tombstones are handled identically to redefinition.
  }
  if (required) {
    throw new AccountsError(
      `tool definition changed or was removed during login for "${captured.id}"; refusing stale finalization`,
    );
  }
  return undefined;
}

/** Capture state that Claude finalization may mutate after the login child exits. */
export async function captureLoginFinalizationState(
  name: string,
  tool: ToolDef,
  store: AccountsStore = resolveStore(),
  expectedProfile?: Profile,
): Promise<LoginFinalizationState> {
  if (
    !store.restoreCurrentGeneration ||
    !store.restoreCurrentOperation ||
    !store.restoreProfileState ||
    !store.useProfileForLogin
  ) {
    throw new AccountsError(
      "the configured Accounts store does not support transactional login activation and rollback; " +
      "upgrade the custom store before running accounts login",
    );
  }
  const currentSnapshot = store.listCurrentForLoginRollback
    ? store.listCurrentForLoginRollback()
    : store.transport === "local"
      ? store.listCurrent()
      : Promise.reject(
          new AccountsError(
            "the configured Accounts API store does not support transactional login rollback; " +
            "upgrade the custom store before running accounts login",
          ),
        );
  const [profile, currentSelections] = await Promise.all([
    store.getProfile(name, tool.id),
    currentSnapshot,
  ]);
  if (
    expectedProfile &&
    (profile.tool !== expectedProfile.tool ||
      profile.name !== expectedProfile.name ||
      (expectedProfile.incarnationId
        ? profile.incarnationId !== expectedProfile.incarnationId
        : profileAuthIncarnation(profile) !== profileAuthIncarnation(expectedProfile)))
  ) {
    throw new AccountsError("profile changed before Claude auth capture");
  }
  if (store.requiresProfileIncarnationRollback && !profile.incarnationId) {
    throw new AccountsError(
      "accounts-serve did not return an account incarnation for transactional profile rollback; " +
      "redeploy accounts-serve 0.2.9 or newer before running accounts login",
    );
  }
  if (process.env.NODE_ENV === "test" && process.env.ACCOUNTS_TEST_LOGIN_CAPTURE_READY) {
    const marker = process.env.ACCOUNTS_TEST_LOGIN_CAPTURE_READY;
    assertSafeWritePath(marker, { mustStayUnder: accountsHome() });
    writeFileSync(marker, "ready\n", { mode: 0o600 });
    const delayMs = Number(process.env.ACCOUNTS_TEST_LOGIN_CAPTURE_DELAY_MS ?? 0);
    if (Number.isFinite(delayMs) && delayMs > 0) {
      await new Promise<void>((resolveDelay) => setTimeout(resolveDelay, delayMs));
    }
  }
  const current = currentSelections.find((selection) => selection.tool === tool.id);
  const machineState = tool.id === "claude"
    ? await withApplyLockWait(() => withStoreLock(() => {
        const machine = loadMachineStore();
        const appliedName = machine.applied[tool.id];
        const requestedAuthRevisionKey = profileAuthRevisionKey(tool.id, profile.name);
        const sourceAuthRevisionKey = findProfileAuthRevisionKey(machine, profile);
        const authRevisionKey = sourceAuthRevisionKey ?? requestedAuthRevisionKey;
        let authStateChanged = false;
        const authIncarnation = profileAuthIncarnation(profile);
        if (
          !sourceAuthRevisionKey &&
          machine.profileAuthIncarnations[requestedAuthRevisionKey] &&
          machine.profileAuthIncarnations[requestedAuthRevisionKey] !== authIncarnation
        ) {
          const displacedIncarnation = machine.profileAuthIncarnations[requestedAuthRevisionKey]!;
          const parkedKey = parkedProfileAuthRevisionKey(displacedIncarnation);
          if (
            machine.profileAuthRevisions[parkedKey] ||
            machine.profileAuthCommitRevisions[parkedKey] ||
            machine.profileAuthIncarnations[parkedKey]
          ) {
            throw new AccountsError("duplicate parked profile auth ownership");
          }
          const displacedIdentity = machine.profileAuthRevisions[requestedAuthRevisionKey];
          const displacedCommit = machine.profileAuthCommitRevisions[requestedAuthRevisionKey];
          delete machine.profileAuthRevisions[requestedAuthRevisionKey];
          delete machine.profileAuthCommitRevisions[requestedAuthRevisionKey];
          delete machine.profileAuthIncarnations[requestedAuthRevisionKey];
          if (displacedIdentity) machine.profileAuthRevisions[parkedKey] = displacedIdentity;
          if (displacedCommit) machine.profileAuthCommitRevisions[parkedKey] = displacedCommit;
          machine.profileAuthIncarnations[parkedKey] = displacedIncarnation;
          authStateChanged = true;
        }
        let authIdentityRevision = machine.profileAuthRevisions[authRevisionKey];
        const existingCommittedAuthRevision = machine.profileAuthCommitRevisions[authRevisionKey];
        if (!authIdentityRevision && existingCommittedAuthRevision) {
          throw new AccountsError("committed Claude profile auth is missing its profile identity");
        }
        const profileClaude = captureClaudeProfileAuthSnapshot(profile.dir);
        authIdentityRevision ??= randomUUID();
        let committedAuthRevision = existingCommittedAuthRevision;
        if (committedAuthRevision) {
          assertClaudeProfileCommittedAuthSnapshot(authIdentityRevision, committedAuthRevision);
        } else {
          committedAuthRevision = randomUUID();
          writeClaudeProfileCommittedAuthSnapshot(profile.dir, authIdentityRevision, committedAuthRevision);
        }
        if (machine.profileAuthIncarnations[authRevisionKey] !== authIncarnation) {
          machine.profileAuthIncarnations[authRevisionKey] = authIncarnation;
          authStateChanged = true;
        }
        if (!machine.profileAuthRevisions[authRevisionKey] || !existingCommittedAuthRevision) {
          machine.profileAuthRevisions[authRevisionKey] = authIdentityRevision;
          machine.profileAuthCommitRevisions[authRevisionKey] = committedAuthRevision;
          authStateChanged = true;
        }
        if (authStateChanged) saveStore(machine);
        return {
          ...(appliedName
            ? { applied: { name: appliedName, ...(machine.appliedRevisions[tool.id] ? { revision: machine.appliedRevisions[tool.id] } : {}) } }
            : {}),
          liveClaude: captureClaudeLiveAuthSnapshot(),
          profileClaude,
          profileClaudeIdentityRevision: authIdentityRevision,
          profileClaudeCommitRevision: committedAuthRevision,
        };
      }))
    : {};
  return {
    tool,
    profile,
    ...(current ? { current } : {}),
    ...machineState,
    writes: { profile: {} },
  };
}

function recordEmailFinalizationWrite(state: LoginFinalizationState | undefined, profile: Profile): void {
  if (!state) return;
  const beforeEmail = state.profile.email ?? null;
  const afterEmail = profile.email ?? null;
  const anticipated = state.writes.profile.email;
  if (anticipated) {
    if (afterEmail !== anticipated.expected) delete state.writes.profile.email;
    return;
  }
  if (beforeEmail !== afterEmail) {
    state.writes.profile.email = { expected: afterEmail, restore: beforeEmail };
  }
}

function expectEmailFinalizationWrite(
  state: LoginFinalizationState | undefined,
  profile: Profile,
  tool: ToolDef,
): void {
  if (!state || !profile.dir || !existsSync(profile.dir)) return;
  const detected = detectEmail(profile.dir, tool);
  const beforeEmail = state.profile.email ?? null;
  if (detected && detected !== beforeEmail) {
    // Record ownership before the awaited registry write so a committed write
    // with a lost response can still be conditionally rolled back.
    state.writes.profile.email = { expected: detected, restore: beforeEmail };
  }
}

function recordLastUsedFinalizationWrite(state: LoginFinalizationState | undefined, profile: Profile): void {
  if (!state) return;
  const beforeLastUsedAt = state.profile.lastUsedAt ?? null;
  const afterLastUsedAt = profile.lastUsedAt ?? null;
  if (beforeLastUsedAt !== afterLastUsedAt) {
    state.writes.profile.lastUsedAt = { expected: afterLastUsedAt, restore: beforeLastUsedAt };
  }
}

function requireLoginCurrentRevision(revision: string | undefined): string {
  if (!revision) {
    throw new AccountsError(
      "accounts-serve returned a current selection missing a current-selection revision; " +
      "Redeploy accounts-serve 0.2.9 or newer before running accounts login.",
    );
  }
  return revision;
}

/** Restore live auth and active/applied pointers after failed or interrupted finalization. */
export async function rollbackLoginFinalization(
  state: LoginFinalizationState,
  store: AccountsStore = resolveStore(),
): Promise<void> {
  const currentTool = await resolveUnchangedLoginTool(state.tool, store, false);
  const toolSpecificRollbackAllowed = Boolean(currentTool);
  let firstError: unknown;
  const attempt = async (operation: () => void | Promise<void>) => {
    try {
      await operation();
    } catch (error) {
      firstError ??= error;
    }
  };

  if (state.writes.currentOperationId) {
    try {
      if (!store.restoreCurrentOperation) {
        throw new AccountsError("the Accounts store lost operation-owned current rollback support");
      }
      await store.restoreCurrentOperation(
        state.tool.id,
        state.profile.name,
        state.writes.currentOperationId,
        state.writes.currentPreviousName,
        state.writes.currentPreviousProfileLastUsedAt ?? null,
      );
    } catch (error) {
      firstError ??= error;
    }
  } else if (state.writes.currentRevision) {
    try {
      if (!store.restoreCurrentGeneration) {
        throw new AccountsError("the Accounts store lost generation-aware current rollback support");
      }
      await store.restoreCurrentGeneration(
        state.tool.id,
        state.profile.name,
        state.writes.currentRevision,
        state.current?.name,
      );
    } catch (error) {
      firstError ??= error;
    }
  }

  const applyRollback = state.writes.applyRollback;
  const displacedDifferentAppliedState = Boolean(
    applyRollback &&
    (applyRollback.applied?.name !== state.applied?.name ||
      applyRollback.applied?.revision !== state.applied?.revision),
  );
  const liveBeforeApply = displacedDifferentAppliedState
    ? applyRollback?.liveClaude
    : state.liveClaude ?? applyRollback?.liveClaude;
  const appliedBeforeApply = applyRollback?.applied ?? state.applied;
  const profileAuthSnapshots = [
    ...(state.writes.profileAuthSnapshots ?? []),
    ...(state.profileClaude ? [state.profileClaude] : []),
  ];
  let currentAuthProfile: Profile | undefined;
  if (toolSpecificRollbackAllowed && state.tool.id === "claude") {
    try {
      currentAuthProfile = (await store.listProfiles(state.tool.id)).find(
        (profile) =>
          profile.createdAt === state.profile.createdAt &&
          resolve(profile.dir) === resolve(state.profile.dir),
      );
    } catch (error) {
      firstError ??= error;
    }
  }
  if (toolSpecificRollbackAllowed && state.writes.applyStarted) {
    await attempt(() => withApplyLockWait(() => withStoreLock(() => {
      const machine = loadMachineStore();
      const appliedNow = machine.applied[state.tool.id];
      const appliedRevisionNow = machine.appliedRevisions[state.tool.id];
      const expectedName = state.writes.appliedRevision ? state.profile.name : appliedBeforeApply?.name;
      const expectedRevision = state.writes.appliedRevision ?? appliedBeforeApply?.revision;
      const ownsAppliedState = appliedNow === expectedName && appliedRevisionNow === expectedRevision;
      const ownsAuthState = !applyRollback || ownsApplyAuthWrites(machine, applyRollback);
      if (!ownsAppliedState || !ownsAuthState) return;
      for (const snapshot of profileAuthSnapshots) restoreClaudeProfileAuthSnapshot(snapshot);
      if (applyRollback) {
        for (const ref of applyRollback.profileAuthRefs) {
          if (ref.identity) machine.profileAuthRevisions[ref.key] = ref.identity;
          else delete machine.profileAuthRevisions[ref.key];
          if (ref.commitRevision) machine.profileAuthCommitRevisions[ref.key] = ref.commitRevision;
          else delete machine.profileAuthCommitRevisions[ref.key];
          if (ref.incarnation) machine.profileAuthIncarnations[ref.key] = ref.incarnation;
          else delete machine.profileAuthIncarnations[ref.key];
        }
      }
      if (liveBeforeApply) restoreClaudeLiveAuthSnapshot(liveBeforeApply);
      if (appliedBeforeApply) {
        machine.applied[state.tool.id] = appliedBeforeApply.name;
        machine.appliedRevisions[state.tool.id] = randomUUID();
      } else {
        delete machine.applied[state.tool.id];
        delete machine.appliedRevisions[state.tool.id];
      }
      saveStore(machine);
    })));
  } else if (toolSpecificRollbackAllowed && profileAuthSnapshots.length > 0) {
    await attempt(() => withApplyLockWait(() => withStoreLock(() => {
      const machine = loadMachineStore();
      // A removed/recreated or relocated profile is a different incarnation;
      // never write the old child's rollback into it. If the same incarnation
      // still exists, missing ownership metadata is malformed state and must
      // fail closed instead of silently leaving partial child auth behind.
      if (!currentAuthProfile) return;
      const identityKey = ownedProfileIdentityKey(machine, state, currentAuthProfile);
      if (!identityKey) {
        throw new AccountsError("missing Claude profile auth identity while rolling back a failed login");
      }
      const currentCommittedRevision = machine.profileAuthCommitRevisions[identityKey];
      if (!currentCommittedRevision) {
        throw new AccountsError("missing committed Claude profile auth while rolling back a failed login");
      }
      // The published immutable commit is authoritative even when unchanged:
      // another overlapping failed login may have captured uncommitted child
      // output in memory. Never delete this shared baseline on login failure.
      restoreClaudeProfileCommittedAuthSnapshot(
        state.profile.dir,
        state.profileClaudeIdentityRevision!,
        currentCommittedRevision,
      );
    })));
  }
  const profileFields: ProfileRollbackFields = { ...state.writes.profile };
  if (state.writes.currentOperationId) {
    // Operation rollback restores lastUsedAt atomically only while it still
    // owns the current-selection generation. A value-only profile fallback
    // can collide with a later same-profile activation in the same millisecond.
    delete profileFields.lastUsedAt;
  }
  if (Object.keys(profileFields).length > 0) {
    await attempt(() => store.restoreProfileState!(state.profile, profileFields, {
      ...(state.profileClaudeIdentityRevision
        ? { authIdentity: state.profileClaudeIdentityRevision }
        : {}),
      ...(state.profileClaudeCommitRevision
        ? { authCommitRevision: state.profileClaudeCommitRevision }
        : {}),
    }).then(() => undefined));
  }

  if (firstError) throw firstError;
}

/** Finalize retention only after the parent has passed its last signal check. */
export async function commitLoginFinalization(
  state: LoginFinalizationState,
  canCommit: () => boolean = () => true,
): Promise<boolean> {
  return withApplyLockWait(() => withStoreLock(() => {
    if (!canCommit()) return false;
    const rollback = state.writes.applyRollback;
    if (!rollback) return true;
    const machine = loadMachineStore();
    // A later apply owns its immutable generations. Never prune revisions
    // against stale login-finalization state after waiting for the apply lock.
    if (!ownsApplyAuthWrites(machine, rollback)) return true;
    pruneClaudeProfileCommittedAuthSnapshotSets(
      rollback.profileAuthWrites.flatMap((write) =>
        write.identity && write.commitRevision
          ? [{ identity: write.identity, keepRevision: write.commitRevision }]
          : []
      ),
    );
    return true;
  }));
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
  state?: LoginFinalizationState,
): Promise<FinalizeLoginResult> {
  const profile = await store.getProfile(name, toolId);
  if (
    state &&
    (profile.tool !== state.profile.tool ||
      profile.name !== state.profile.name ||
      (state.profile.incarnationId
        ? profile.incarnationId !== state.profile.incarnationId
        : profileAuthIncarnation(profile) !== profileAuthIncarnation(state.profile)))
  ) {
    throw new AccountsError("profile changed while login finalization was in progress");
  }
  const tool = state
    ? await resolveUnchangedLoginTool(state.tool, store, true) as ToolDef
    : await store.resolveTool(profile.tool);

  if (tool.id === "claude") {
    ensureProfileAuthSnapshot(profile.dir, tool, { overwrite: true });
    expectEmailFinalizationWrite(state, profile, tool);
    const redetected = await store.redetectEmail(name, tool.id, state?.profile);
    recordEmailFinalizationWrite(state, redetected);
    const applied = await applyProfile(name, tool.id, store, state?.writes, state?.profile);
    if (state) state.writes.currentRevision = requireLoginCurrentRevision(applied.currentRevision);
    recordLastUsedFinalizationWrite(state, applied.profile);
    return { profile: applied.profile, applied: true };
  }

  expectEmailFinalizationWrite(state, profile, tool);
  const updated = await store.redetectEmail(name, tool.id, state?.profile);
  recordEmailFinalizationWrite(state, updated);
  const operationId = state ? randomUUID() : undefined;
  if (state) state.writes.currentOperationId = operationId;
  const active = state
    ? await store.useProfileForLogin!(name, tool.id, operationId!, state.profile)
    : await store.useProfile(name, tool.id);
  if (state) state.writes.currentRevision = requireLoginCurrentRevision(active.currentRevision);
  if (state) state.writes.currentPreviousName = active.previousCurrentName;
  if (state) state.writes.currentPreviousProfileLastUsedAt = active.previousProfileLastUsedAt;
  recordLastUsedFinalizationWrite(state, active.profile);
  return { profile: active.profile, applied: false };
}
