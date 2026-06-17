import { cpSync, existsSync } from "node:fs";
import { join } from "node:path";
import { profilesDir } from "../storage.js";
import { AccountsError } from "../types.js";
import { addProfile, expandPath, getProfile, type AddOptions } from "./profiles.js";
import { getTool, DEFAULT_TOOL } from "./tools.js";
import { ensureProfileAuthSnapshot } from "./claude-auth.js";
import { detectEmail } from "./detect.js";

export interface ImportOptions {
  name?: string;
  tool?: string;
  dir?: string;
  email?: string;
  description?: string;
  copy?: boolean;
}

/**
 * Register an existing Claude (or tool) config directory as a profile.
 * Default source is the tool's default dir (e.g. ~/.claude).
 */
export function importProfile(opts: ImportOptions) {
  const toolId = opts.tool ?? DEFAULT_TOOL;
  const tool = getTool(toolId);
  const name = opts.name ?? "main";
  const sourceDir = opts.dir ? expandPath(opts.dir) : tool.defaultDir;

  if (!existsSync(sourceDir)) {
    throw new AccountsError(`config dir does not exist: ${sourceDir}`);
  }

  if (opts.copy) {
    const targetDir = join(profilesDir(), toolId, name);
    if (existsSync(targetDir)) {
      throw new AccountsError(`managed copy target already exists: ${targetDir}`);
    }
    cpSync(sourceDir, targetDir, { recursive: true });
    if (tool.id === "claude") ensureProfileAuthSnapshot(targetDir, tool);
    const addOpts: AddOptions = {
      name,
      tool: toolId,
      dir: targetDir,
      email: opts.email ?? detectEmail(targetDir, tool),
      description: opts.description ?? "imported copy",
    };
    return addProfile(addOpts);
  }

  const addOpts: AddOptions = {
    name,
    tool: toolId,
    dir: sourceDir,
    email: opts.email ?? detectEmail(sourceDir, tool),
    description: opts.description ?? "imported",
  };
  const profile = addProfile(addOpts);
  if (tool.id === "claude") ensureProfileAuthSnapshot(profile.dir, tool);
  return profile;
}

export function ensureProfileForLogin(name: string, toolId?: string) {
  const existing = findProfileByName(name, toolId);
  if (existing) return existing;
  return addProfile({ name, tool: toolId ?? DEFAULT_TOOL, description: "created for login" });
}

function findProfileByName(name: string, toolId?: string) {
  try {
    return getProfile(name, toolId);
  } catch (err) {
    if (err instanceof AccountsError) return undefined;
    throw err;
  }
}
