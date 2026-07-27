/**
 * Synchronous root exports are frozen v1 compatibility only.
 *
 * They can never select the async hosted registry, so fail before touching the
 * local store whenever any hosted/self-hosted authority is configured. New
 * integrations must use resolveStore() (v1) or AccountsRegistry (v2).
 */
import { AccountsError, type Profile, type Store, type ToolDef } from "../types.js";
import {
  loadStore as localLoadStore,
  saveStore as localSaveStore,
} from "../storage.js";
import { resolveAccountsCloud } from "./cloud-accounts.js";
import {
  addCustomTool as localAddCustomTool,
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

export function assertRootCompatibilityIsLocal(env: NodeJS.ProcessEnv = process.env): void {
  const authority = resolveAccountsCloud(env);
  if (authority.transport === "cloud-http") {
    throw new AccountsError(
      "synchronous @hasna/accounts registry exports are local-only compatibility and are unavailable when hosted authority is configured; use resolveStore() or @hasna/accounts/v2",
    );
  }
}

export function loadStore(): Store {
  assertRootCompatibilityIsLocal();
  return localLoadStore();
}

export function saveStore(store: Store): void {
  assertRootCompatibilityIsLocal();
  localSaveStore(store);
}

export function getTool(toolId: string): ToolDef {
  assertRootCompatibilityIsLocal();
  return localGetTool(toolId);
}

export function listTools(): ToolDef[] {
  assertRootCompatibilityIsLocal();
  return localListTools();
}

export function addCustomTool(def: ToolDef): ToolDef {
  assertRootCompatibilityIsLocal();
  return localAddCustomTool(def);
}

export function removeCustomTool(id: string): void {
  assertRootCompatibilityIsLocal();
  localRemoveCustomTool(id);
}

export function listProfiles(toolId?: string): Profile[] {
  assertRootCompatibilityIsLocal();
  return localListProfiles(toolId);
}

export function findProfile(name: string, toolId?: string): Profile | undefined {
  assertRootCompatibilityIsLocal();
  return localFindProfile(name, toolId);
}

export function getProfile(name: string, toolId?: string): Profile {
  assertRootCompatibilityIsLocal();
  return localGetProfile(name, toolId);
}

export function getProfileToolLock(name: string): string | undefined {
  assertRootCompatibilityIsLocal();
  return localGetProfileToolLock(name);
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

export function currentProfile(toolId: string): Profile | undefined {
  assertRootCompatibilityIsLocal();
  return localCurrentProfile(toolId);
}
