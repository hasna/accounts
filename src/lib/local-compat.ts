/**
 * Synchronous root exports are frozen v1 compatibility only.
 *
 * They can never select the async hosted registry, so under hosted/self-hosted
 * authority they cannot answer for the authoritative store. New integrations
 * must use resolveStore() (v1) or AccountsRegistry (v2).
 *
 * Two different hazards live behind that one sentence, and they get two
 * different answers:
 *
 *   WRITES fail closed. A synchronous root write under hosted authority lands
 *   in the machine's local JSON file while the registry of record is elsewhere,
 *   so it silently diverges the two. There is no correct local answer to give,
 *   and no measured consumer performs one, so these throw.
 *
 *   READS warn and answer. Making them throw was tried and measured on the
 *   fleet, and it was worse: @hasna/economy's resolveAccountForAgent wraps every
 *   accounts call in `try {} catch {}`, so the intended loud failure arrived as
 *   a silent `null` and zeroed per-account cost attribution on every cloud-mode
 *   machine — no error, no log, no alert. Reads therefore return the same
 *   machine-local answer they returned before this compatibility layer existed,
 *   and announce themselves once per operation through `process.emitWarning`,
 *   which a `catch` block cannot swallow. This is the deprecation phase; the
 *   fail-closed behaviour is available today via
 *   HASNA_ACCOUNTS_STRICT_ROOT_COMPAT and becomes the default once the
 *   remaining consumers move to the async paths.
 *
 * appliedProfileName() is exempt in every mode: it returns only the
 * machine-local applied pointer (which profile's auth is restored to this
 * machine's live default paths), never a registry record, so it is exported
 * straight from lib/apply.js. appliedProfile() resolves that same pointer
 * against the local profile registry, so it is a gated read here.
 */
import { AccountsError, type Profile, type Store, type ToolDef } from "../types.js";
import {
  loadStore as localLoadStore,
  saveStore as localSaveStore,
} from "../storage.js";
import { appliedProfile as localAppliedProfile } from "./apply.js";
import { resolveAccountsCloud } from "./cloud-accounts.js";
import {
  addCustomTool as localAddCustomTool,
  DEFAULT_TOOL,
  getTool as localGetTool,
  listTools as localListTools,
  removeCustomTool as localRemoveCustomTool,
} from "./tools.js";
import {
  addProfile as localAddProfile,
  currentProfile as localCurrentProfile,
  findProfile as localFindProfile,
  getProfile as localGetProfile,
  getProfileToolLock as localGetProfileToolLock,
  listProfiles as localListProfiles,
  lockProfileTool as localLockProfileTool,
  redetectEmail as localRedetectEmail,
  removeProfile as localRemoveProfile,
  renameProfile as localRenameProfile,
  updateProfile as localUpdateProfile,
  useProfile as localUseProfile,
  type AddOptions,
  type RemoveOptions,
  type UpdateOptions,
} from "./profiles.js";

/** Opt into the end-state behaviour: hosted authority makes reads throw too. */
const STRICT_ENV_KEY = "HASNA_ACCOUNTS_STRICT_ROOT_COMPAT";

/** Warning code so consumers and log pipelines can match on it structurally. */
export const ROOT_COMPAT_READ_WARNING_CODE = "HASNA_ACCOUNTS_LOCAL_COMPAT_READ";

const UNAVAILABLE_MESSAGE =
  "synchronous @hasna/accounts registry exports are local-only compatibility and are unavailable when hosted authority is configured; use resolveStore() or @hasna/accounts/v2";

const warnedOperations = new Set<string>();

/** Test-only: forget which operations have already warned in this process. */
export function resetRootCompatWarnings(): void {
  warnedOperations.clear();
}

function strictModeEnabled(env: NodeJS.ProcessEnv): boolean {
  const raw = (env[STRICT_ENV_KEY] ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

/**
 * Fail closed for a synchronous root WRITE whenever hosted authority is
 * configured. Resolving the authority also surfaces a misconfigured hosted
 * setup (missing URL/key, invalid mode word) before any local I/O.
 */
export function assertRootCompatibilityIsLocal(env: NodeJS.ProcessEnv = process.env): void {
  const authority = resolveAccountsCloud(env);
  if (authority.transport === "cloud-http") throw new AccountsError(UNAVAILABLE_MESSAGE);
}

/**
 * Announce (or, in strict mode, refuse) a synchronous root READ whenever hosted
 * authority is configured. The warning is emitted once per operation per
 * process so a polling caller cannot flood stderr, and `process.emitWarning`
 * is deliberately used instead of a thrown error because the measured consumers
 * swallow throws.
 */
export function noteRootCompatibilityRead(
  operation: string,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const authority = resolveAccountsCloud(env);
  if (authority.transport !== "cloud-http") return;
  if (strictModeEnabled(env)) throw new AccountsError(UNAVAILABLE_MESSAGE);
  if (warnedOperations.has(operation)) return;
  warnedOperations.add(operation);
  process.emitWarning(
    `${operation}() from the @hasna/accounts package root answered from this machine's local registry while hosted authority is configured; the authoritative registry is reachable only through resolveStore() or @hasna/accounts/v2. Set ${STRICT_ENV_KEY}=1 to make this throw instead.`,
    "DeprecationWarning",
    ROOT_COMPAT_READ_WARNING_CODE,
  );
}

// ---------------------------------------------------------------------------
// Reads: warn once, then answer from the machine-local registry.
// ---------------------------------------------------------------------------

export function loadStore(): Store {
  noteRootCompatibilityRead("loadStore");
  return localLoadStore();
}

export function getTool(toolId: string): ToolDef {
  noteRootCompatibilityRead("getTool");
  return localGetTool(toolId);
}

export function listTools(): ToolDef[] {
  noteRootCompatibilityRead("listTools");
  return localListTools();
}

export function listProfiles(toolId?: string): Profile[] {
  noteRootCompatibilityRead("listProfiles");
  return localListProfiles(toolId);
}

export function findProfile(name: string, toolId?: string): Profile | undefined {
  noteRootCompatibilityRead("findProfile");
  return localFindProfile(name, toolId);
}

export function getProfile(name: string, toolId?: string): Profile {
  noteRootCompatibilityRead("getProfile");
  return localGetProfile(name, toolId);
}

export function getProfileToolLock(name: string): string | undefined {
  noteRootCompatibilityRead("getProfileToolLock");
  return localGetProfileToolLock(name);
}

export function currentProfile(toolId: string): Profile | undefined {
  noteRootCompatibilityRead("currentProfile");
  return localCurrentProfile(toolId);
}

export function appliedProfile(toolId: string): Profile | undefined {
  noteRootCompatibilityRead("appliedProfile");
  return localAppliedProfile(toolId);
}

// ---------------------------------------------------------------------------
// Writes: fail closed, before any local I/O.
// ---------------------------------------------------------------------------

export function saveStore(store: Store): void {
  assertRootCompatibilityIsLocal();
  localSaveStore(store);
}

export function addCustomTool(def: ToolDef): ToolDef {
  assertRootCompatibilityIsLocal();
  return localAddCustomTool(def);
}

export function removeCustomTool(id: string): void {
  assertRootCompatibilityIsLocal();
  localRemoveCustomTool(id);
}

/**
 * @deprecated Local-only synchronous compatibility shim. New callers should
 * use prepareLogin(), whose async Store path also supports cloud custom tools.
 */
export function ensureProfileForLogin(name: string, toolId = DEFAULT_TOOL): Profile {
  assertRootCompatibilityIsLocal();
  const existing = localFindProfile(name, toolId);
  if (existing) {
    localLockProfileTool(existing.name, existing.tool);
    return existing;
  }
  const profile = localAddProfile({
    name,
    tool: toolId,
    description: "created for login",
  });
  localLockProfileTool(profile.name, profile.tool);
  return profile;
}

export function lockProfileTool(name: string, toolId: string): void {
  assertRootCompatibilityIsLocal();
  localLockProfileTool(name, toolId);
}

export function addProfile(opts: AddOptions): Profile {
  assertRootCompatibilityIsLocal();
  return localAddProfile(opts);
}

export function removeProfile(
  name: string,
  opts: RemoveOptions | boolean = {},
): { profile: Profile; purged: boolean; purgeNote?: string } {
  assertRootCompatibilityIsLocal();
  return localRemoveProfile(name, opts);
}

export function renameProfile(oldName: string, newName: string, toolId?: string): Profile {
  assertRootCompatibilityIsLocal();
  return localRenameProfile(oldName, newName, toolId);
}

export function updateProfile(name: string, opts: UpdateOptions): Profile {
  assertRootCompatibilityIsLocal();
  return localUpdateProfile(name, opts);
}

export function redetectEmail(name: string, toolId?: string): Profile {
  assertRootCompatibilityIsLocal();
  return localRedetectEmail(name, toolId);
}

export function useProfile(name: string, toolId?: string): { profile: Profile; toolId: string } {
  assertRootCompatibilityIsLocal();
  return localUseProfile(name, toolId);
}
