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
  mergeToolArgs,
  launchArgsFor,
  normalizePermissionPreset,
  permissionArgsFor,
} from "./lib/tools.js";
export { profileEnv, formatEnvAssignments, formatExportLines } from "./lib/env.js";
export { detectEmail } from "./lib/detect.js";
export {
  expandPath,
  listProfiles,
  findProfile,
  getProfile,
  getProfileToolLock,
  lockProfileTool,
  addProfile,
  removeProfile,
  renameProfile,
  updateProfile,
  redetectEmail,
  useProfile,
  currentProfile,
} from "./lib/profiles.js";
export type { AddOptions, RemoveOptions, UpdateOptions, ProfileMetadata, ProfileMetadataValue } from "./lib/profiles.js";
export { resolveStore } from "./lib/store.js";
export type { AccountsStore, CurrentEntry, RemoveResult } from "./lib/store.js";
export { applyProfile, appliedProfile } from "./lib/apply.js";
export { importProfile, ensureProfileForLogin } from "./lib/import-profile.js";
export type { ImportOptions } from "./lib/import-profile.js";
export {
  detectToolAvailability,
  finalizeLogin,
  installInstructions,
  loginToolChoices,
  nonInteractiveToolSelectionMessage,
  prepareLogin,
  unavailableToolMessage,
} from "./lib/login.js";
export type {
  FinalizeLoginResult,
  LoginPreparation,
  LoginPreparationReady,
  LoginPreparationStopped,
  LoginToolChoice,
  PrepareLoginOptions,
  ToolAvailability,
} from "./lib/login.js";
export { switchProfile } from "./lib/switch.js";
export type { SwitchMode, SwitchOptions, SwitchResult } from "./lib/switch.js";
export {
  codexAppBinaryExists,
  codexAppMenuState,
  codexAppMenuSwiftSource,
  runCodexAppMenuBar,
  switchCodexAppFromMenu,
} from "./lib/codex-app-menu.js";
export type {
  CodexAppMenuProfile,
  CodexAppMenuState,
  CodexAppMenuSwitchResult,
  CodexAppProcessRunner,
  CodexAppRelaunchOptions,
  RunCodexAppMenuBarOptions,
} from "./lib/codex-app-menu.js";
export {
  listSupervisorStates,
  readSupervisorState,
  resolveSupervisorLaunch,
  runSupervisedTool,
  sendSupervisorRequest,
  supervisorDir,
  supervisorSocketPath,
  supervisorStatePath,
} from "./lib/supervisor.js";
export type {
  RunSupervisorOptions,
  SupervisorClientOptions,
  SupervisorLaunchPlan,
  SupervisorRequest,
  SupervisorResponse,
  SupervisorState,
} from "./lib/supervisor.js";
export {
  configsSessionToolFor,
  configsPrelaunchCommand,
  runConfigsPrelaunch,
} from "./lib/configs-prelaunch.js";
export type {
  ConfigsPrelaunchMode,
  ConfigsPrelaunchOptions,
  ConfigsPrelaunchResult,
  ConfigsRunner,
} from "./lib/configs-prelaunch.js";
export {
  assessConfigsManifest,
  configsManifestPath,
  configsPrelaunchAuditPath,
  getConfigsPrelaunchSummary,
  readConfigsPrelaunchAudit,
  recordConfigsPrelaunchAudit,
} from "./lib/configs-prelaunch-status.js";
export type {
  ConfigsManifestDrift,
  ConfigsPrelaunchAudit,
  ConfigsPrelaunchAuditResult,
  ConfigsPrelaunchManifestStatus,
  ConfigsPrelaunchStatus,
  ConfigsPrelaunchSummary,
} from "./lib/configs-prelaunch-status.js";
export { getAccountsReadiness } from "./lib/readiness.js";
export type {
  AccountsProviderReadiness,
  AccountsProfileLoginReadiness,
  AccountsProfileReadiness,
  AccountsReadiness,
  AccountsReadinessCheck,
  AccountsReadinessStatus,
  AccountsStorageReadiness,
  AccountsSupervisorReadiness,
} from "./lib/readiness.js";
export { pickProfile } from "./lib/pick.js";
export type { PickOptions, PickResult } from "./lib/pick.js";
export { installHook, uninstallHook, hookPath, hookScript, shellSnippet } from "./lib/hook.js";
export {
  snapshotClaudeAuthToProfile,
  snapshotLiveAuthToProfile,
  restoreClaudeAuthFromProfile,
  ensureProfileAuthSnapshot,
  claudeKeychainCredentialFromProfile,
  prepareClaudeProfileKeychain,
  liveCredentialShouldUpdateProfile,
  hasAuthSnapshot,
  profileHasAuth,
  claudeProfileAuthHealth,
  sanitizeClaudeProfileApiSettings,
  sanitizeClaudeOAuthProfileSettings,
  sanitizeLiveClaudeOAuthSettings,
  CLAUDE_API_AUTH_ENV_KEYS,
} from "./lib/claude-auth.js";
export type { ClaudeProfileAuthHealth, ClaudeProfileAuthStatus } from "./lib/claude-auth.js";
export { withApplyLock } from "./lib/apply-lock.js";
export { isSafeProfileName } from "./lib/hook.js";
export { readClaudeKeychain, keychainSupported } from "./lib/keychain.js";
export {
  accountsCapabilityCard,
  accountsNoCloudEvidencePack,
  toAccountsActorRef,
  toAgentsRunnerWorkRun,
  toSupervisorOptionsWorkRun,
  validateEventActorRefs,
} from "./lib/contracts.js";
export { AccountsEventsClient, createAccountsEventsClient } from "./lib/events.js";
