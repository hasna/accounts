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
export type { AddOptions, UpdateOptions } from "./lib/profiles.js";
