import { cpSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Profile } from "../types.js";
import { profilesDir } from "../storage.js";
import { AccountsError } from "../types.js";
import { expandPath, type AddOptions } from "./profiles.js";
import { getTool, DEFAULT_TOOL } from "./tools.js";
import { ensureProfileAuthSnapshot } from "./claude-auth.js";
import { detectEmail } from "./detect.js";
import { resolveStore, type AccountsStore } from "./store.js";

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
 *
 * The registry write goes through the resolved Store, so in self_hosted/cloud
 * mode the imported profile lands in the cloud registry (visible to
 * `accounts list`/other machines). The on-disk copy/snapshot work is
 * machine-local and stays local.
 */
export async function importProfile(opts: ImportOptions, store: AccountsStore = resolveStore()): Promise<Profile> {
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
    return store.addProfile(addOpts);
  }

  const addOpts: AddOptions = {
    name,
    tool: toolId,
    dir: sourceDir,
    email: opts.email ?? detectEmail(sourceDir, tool),
    description: opts.description ?? "imported",
  };
  const profile = await store.addProfile(addOpts);
  if (tool.id === "claude") ensureProfileAuthSnapshot(profile.dir, tool);
  return profile;
}
