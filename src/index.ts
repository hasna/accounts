// Public library surface for @hasna/accounts.
export * from "./types.js";
export { loadStore, saveStore, storePath, accountsHome, profilesDir } from "./storage.js";
export {
  BUILTIN_TOOLS,
  DEFAULT_TOOL,
  getTool,
  listTools,
  isBuiltinTool,
  addCustomTool,
  removeCustomTool,
} from "./lib/tools.js";
export { profileEnv, formatEnvAssignments, formatExportLines } from "./lib/env.js";
export { detectEmail } from "./lib/detect.js";
export {
  expandPath,
  listProfiles,
  findProfile,
  getProfile,
  addProfile,
  removeProfile,
  renameProfile,
  updateProfile,
  redetectEmail,
  useProfile,
  currentProfile,
} from "./lib/profiles.js";
export type { AddOptions, RemoveOptions, UpdateOptions } from "./lib/profiles.js";
export { applyProfile, appliedProfile } from "./lib/apply.js";
export { importProfile, ensureProfileForLogin } from "./lib/import-profile.js";
export type { ImportOptions } from "./lib/import-profile.js";
export { finalizeLogin } from "./lib/login.js";
export type { FinalizeLoginResult } from "./lib/login.js";
export { switchProfile } from "./lib/switch.js";
export type { SwitchMode, SwitchOptions, SwitchResult } from "./lib/switch.js";
export { pickProfile } from "./lib/pick.js";
export type { PickOptions, PickResult } from "./lib/pick.js";
export { installHook, uninstallHook, hookPath, hookScript, shellSnippet } from "./lib/hook.js";
export {
  snapshotClaudeAuthToProfile,
  snapshotLiveAuthToProfile,
  restoreClaudeAuthFromProfile,
  ensureProfileAuthSnapshot,
  hasAuthSnapshot,
  profileHasAuth,
} from "./lib/claude-auth.js";
export { withApplyLock } from "./lib/apply-lock.js";
export { isSafeProfileName } from "./lib/hook.js";
export { readClaudeKeychain, keychainSupported } from "./lib/keychain.js";
