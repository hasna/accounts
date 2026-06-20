import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { type Profile, AccountsError, profileNameSchema } from "../types.js";
import { loadStore, saveStore, profilesDir } from "../storage.js";
import { DEFAULT_TOOL, getTool } from "./tools.js";
import { detectEmail } from "./detect.js";

function nowIso(): string {
  return new Date().toISOString();
}

/** Expand a leading `~` and resolve to an absolute path. */
export function expandPath(p: string): string {
  let out = p;
  if (out === "~") out = homedir();
  else if (out.startsWith("~/")) out = join(homedir(), out.slice(2));
  return isAbsolute(out) ? out : resolve(process.cwd(), out);
}

export function listProfiles(toolId?: string): Profile[] {
  const profiles = loadStore().profiles;
  const filtered = toolId ? profiles.filter((p) => p.tool === toolId) : profiles;
  return filtered.slice().sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name));
}

function profileMatches(name: string, toolId?: string): Profile[] {
  return loadStore().profiles.filter((p) => p.name === name && (!toolId || p.tool === toolId));
}

export function findProfile(name: string, toolId?: string): Profile | undefined {
  const matches = profileMatches(name, toolId);
  return matches.length === 1 ? matches[0] : undefined;
}

export function getProfile(name: string, toolId?: string): Profile {
  const matches = profileMatches(name, toolId);
  if (matches.length === 0) {
    const suffix = toolId ? ` for tool "${toolId}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}. Run \`accounts list\` to see profiles.`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  const profile = matches[0]!;
  return profile;
}

export interface AddOptions {
  name: string;
  tool?: string;
  email?: string;
  dir?: string;
  description?: string;
}

export function addProfile(opts: AddOptions): Profile {
  const name = opts.name;
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");

  const toolId = opts.tool ?? DEFAULT_TOOL;
  const tool = getTool(toolId);

  const store = loadStore();
  if (store.profiles.some((p) => p.name === name && p.tool === toolId)) {
    throw new AccountsError(`a ${toolId} profile named "${name}" already exists`);
  }

  const dir = opts.dir ? expandPath(opts.dir) : join(profilesDir(), toolId, name);
  if (store.profiles.some((p) => p.dir === dir)) {
    throw new AccountsError(`a profile already uses config dir ${dir}`);
  }
  mkdirSync(dir, { recursive: true });

  const email = opts.email ?? detectEmail(dir, tool);
  const profile: Profile = {
    name,
    tool: toolId,
    ...(email ? { email } : {}),
    dir,
    ...(opts.description ? { description: opts.description } : {}),
    createdAt: nowIso(),
  };

  store.profiles.push(profile);
  saveStore(store);
  return profile;
}

export interface RemoveOptions {
  tool?: string;
  purge?: boolean;
}

export function removeProfile(
  name: string,
  opts: RemoveOptions | boolean = {},
): { profile: Profile; purged: boolean; purgeNote?: string } {
  const options = typeof opts === "boolean" ? { purge: opts } : opts;
  const store = loadStore();
  const matches = store.profiles
    .map((profile, idx) => ({ profile, idx }))
    .filter(({ profile }) => profile.name === name && (!options.tool || profile.tool === options.tool));
  if (matches.length === 0) {
    const suffix = options.tool ? ` for tool "${options.tool}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map(({ profile }) => profile.tool).join(", ")}); pass --tool`,
    );
  }
  const idx = matches[0]!.idx;
  const profile = store.profiles[idx]!;

  store.profiles.splice(idx, 1);
  if (store.current[profile.tool] === name) delete store.current[profile.tool];
  if (store.applied[profile.tool] === name) delete store.applied[profile.tool];
  saveStore(store);

  let purged = false;
  let purgeNote: string | undefined;
  if (options.purge) {
    const managed = profile.dir.startsWith(profilesDir());
    const isDefault = profile.dir === getTool(profile.tool).defaultDir;
    if (managed && !isDefault && existsSync(profile.dir)) {
      rmSync(profile.dir, { recursive: true, force: true });
      purged = true;
    } else {
      purgeNote = `refused to delete ${profile.dir} (not a managed profile dir); remove it manually if intended`;
    }
  }
  return { profile, purged, purgeNote };
}

export function renameProfile(oldName: string, newName: string, toolId?: string): Profile {
  const nameCheck = profileNameSchema.safeParse(newName);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");

  const store = loadStore();
  const matches = store.profiles.filter((p) => p.name === oldName && (!toolId || p.tool === toolId));
  if (matches.length === 0) {
    const suffix = toolId ? ` for tool "${toolId}"` : "";
    throw new AccountsError(`no profile named "${oldName}"${suffix}`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${oldName}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  const profile = matches[0]!;
  if (store.profiles.some((p) => p.name === newName && p.tool === profile.tool)) {
    throw new AccountsError(`a ${profile.tool} profile named "${newName}" already exists`);
  }

  if (store.current[profile.tool] === oldName) store.current[profile.tool] = newName;
  if (store.applied[profile.tool] === oldName) store.applied[profile.tool] = newName;
  profile.name = newName;
  saveStore(store);
  return profile;
}

export interface UpdateOptions {
  tool?: string;
  email?: string;
  description?: string;
  dir?: string;
}

export function updateProfile(name: string, opts: UpdateOptions): Profile {
  const store = loadStore();
  const matches = store.profiles.filter((p) => p.name === name && (!opts.tool || p.tool === opts.tool));
  if (matches.length === 0) {
    const suffix = opts.tool ? ` for tool "${opts.tool}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  const profile = matches[0]!;
  if (opts.email !== undefined) profile.email = opts.email;
  if (opts.description !== undefined) profile.description = opts.description;
  if (opts.dir !== undefined) {
    const dir = expandPath(opts.dir);
    mkdirSync(dir, { recursive: true });
    profile.dir = dir;
  }
  saveStore(store);
  return profile;
}

/** Re-detect the account email from the profile's config dir. */
export function redetectEmail(name: string, toolId?: string): Profile {
  const store = loadStore();
  const matches = store.profiles.filter((p) => p.name === name && (!toolId || p.tool === toolId));
  if (matches.length === 0) {
    const suffix = toolId ? ` for tool "${toolId}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  const profile = matches[0]!;
  const email = detectEmail(profile.dir, getTool(profile.tool));
  if (email) profile.email = email;
  saveStore(store);
  return profile;
}

/** Mark a profile as the active one for its tool. */
export function useProfile(name: string, toolId?: string): { profile: Profile; toolId: string } {
  const store = loadStore();
  const matches = store.profiles.filter((p) => p.name === name && (!toolId || p.tool === toolId));
  if (matches.length === 0) {
    const suffix = toolId ? ` for tool "${toolId}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}`);
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  const profile = matches[0]!;
  store.current[profile.tool] = name;
  profile.lastUsedAt = nowIso();
  saveStore(store);
  return { profile, toolId: profile.tool };
}

export function currentProfile(toolId: string): Profile | undefined {
  const store = loadStore();
  const name = store.current[toolId];
  if (!name) return undefined;
  return store.profiles.find((p) => p.name === name && p.tool === toolId);
}
