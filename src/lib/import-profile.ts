import { cpSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { Profile } from "../types.js";
import { profilesDir } from "../storage.js";
import { AccountsError, profileNameSchema } from "../types.js";
import {
  addProfile,
  expandPath,
  findProfile,
  lockProfileTool,
  type AddOptions,
} from "./profiles.js";
import { DEFAULT_TOOL } from "./tools.js";
import { ensureProfileAuthSnapshot } from "./claude-auth.js";
import { detectEmail } from "./detect.js";
import { resolveStore, type AccountsStore } from "./store.js";
import { assertSafeWritePath } from "./safe-path.js";

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
export function importProfile(opts: ImportOptions, store?: AccountsStore): Promise<Profile>;
export async function importProfile(
  opts: ImportOptions,
  store: AccountsStore = resolveStore(),
  copyDirectory: (source: string, target: string) => void = (source, target) => {
    cpSync(source, target, { recursive: true });
  },
): Promise<Profile> {
  const toolId = opts.tool ?? DEFAULT_TOOL;
  const name = opts.name ?? "main";
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");
  const tool = await store.resolveTool(toolId);
  const sourceDir = opts.dir ? expandPath(opts.dir) : tool.defaultDir;

  if (!existsSync(sourceDir)) {
    throw new AccountsError(`config dir does not exist: ${sourceDir}`);
  }

  if (opts.copy) {
    const targetDir = join(profilesDir(), toolId, name);
    if (existsSync(targetDir)) {
      throw new AccountsError(`managed copy target already exists: ${targetDir}`);
    }
    try {
      assertSafeWritePath(join(targetDir, ".accounts-import-check"), { mustStayUnder: profilesDir() });
      copyDirectory(sourceDir, targetDir);
      if (tool.id === "claude") ensureProfileAuthSnapshot(targetDir, tool);
      const addOpts: AddOptions = {
        name,
        tool: toolId,
        dir: targetDir,
        email: opts.email ?? detectEmail(targetDir, tool),
        description: opts.description ?? "imported copy",
      };
      return await store.addProfile(addOpts);
    } catch (error) {
      rmSync(targetDir, { recursive: true, force: true });
      throw error;
    }
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

/**
 * @deprecated Local-only synchronous compatibility shim. New callers should
 * use prepareLogin(), whose async Store path also supports cloud custom tools.
 */
export function ensureProfileForLogin(name: string, toolId = DEFAULT_TOOL): Profile {
  const mode = (
    process.env.HASNA_ACCOUNTS_STORAGE_MODE ||
    process.env.ACCOUNTS_STORAGE_MODE ||
    ""
  ).trim().toLowerCase();
  const apiConfigured = Boolean(
    (process.env.HASNA_ACCOUNTS_API_URL || process.env.ACCOUNTS_API_URL) &&
    (process.env.HASNA_ACCOUNTS_API_KEY || process.env.ACCOUNTS_API_KEY),
  );
  if (mode === "cloud" || mode === "self_hosted" || (mode !== "local" && apiConfigured)) {
    throw new AccountsError(
      "ensureProfileForLogin is a local-only compatibility shim; use async prepareLogin in API mode",
    );
  }
  const existing = findProfile(name, toolId);
  if (existing) {
    lockProfileTool(existing.name, existing.tool);
    return existing;
  }
  const profile = addProfile({ name, tool: toolId, description: "created for login" });
  lockProfileTool(profile.name, profile.tool);
  return profile;
}
