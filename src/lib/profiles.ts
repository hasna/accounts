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

export function findProfile(name: string): Profile | undefined {
  return loadStore().profiles.find((p) => p.name === name);
}

export function getProfile(name: string): Profile {
  const profile = findProfile(name);
  if (!profile) throw new AccountsError(`no profile named "${name}". Run \`accounts list\` to see profiles.`);
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
  if (store.profiles.some((p) => p.name === name)) {
    throw new AccountsError(`a profile named "${name}" already exists`);
  }

  const dir = opts.dir ? expandPath(opts.dir) : join(profilesDir(), toolId, name);
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

export function removeProfile(name: string, purge = false): { profile: Profile; purged: boolean; purgeNote?: string } {
  const store = loadStore();
  const idx = store.profiles.findIndex((p) => p.name === name);
  if (idx === -1) throw new AccountsError(`no profile named "${name}"`);
  const profile = store.profiles[idx]!;

  store.profiles.splice(idx, 1);
  if (store.current[profile.tool] === name) delete store.current[profile.tool];
  saveStore(store);

  let purged = false;
  let purgeNote: string | undefined;
  if (purge) {
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

export function renameProfile(oldName: string, newName: string): Profile {
  const nameCheck = profileNameSchema.safeParse(newName);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");

  const store = loadStore();
  const profile = store.profiles.find((p) => p.name === oldName);
  if (!profile) throw new AccountsError(`no profile named "${oldName}"`);
  if (store.profiles.some((p) => p.name === newName)) throw new AccountsError(`a profile named "${newName}" already exists`);

  if (store.current[profile.tool] === oldName) store.current[profile.tool] = newName;
  profile.name = newName;
  saveStore(store);
  return profile;
}

export interface UpdateOptions {
  email?: string;
  description?: string;
  dir?: string;
}

export function updateProfile(name: string, opts: UpdateOptions): Profile {
  const store = loadStore();
  const profile = store.profiles.find((p) => p.name === name);
  if (!profile) throw new AccountsError(`no profile named "${name}"`);
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
export function redetectEmail(name: string): Profile {
  const store = loadStore();
  const profile = store.profiles.find((p) => p.name === name);
  if (!profile) throw new AccountsError(`no profile named "${name}"`);
  const email = detectEmail(profile.dir, getTool(profile.tool));
  if (email) profile.email = email;
  saveStore(store);
  return profile;
}

/** Mark a profile as the active one for its tool. */
export function useProfile(name: string): { profile: Profile; toolId: string } {
  const store = loadStore();
  const profile = store.profiles.find((p) => p.name === name);
  if (!profile) throw new AccountsError(`no profile named "${name}"`);
  store.current[profile.tool] = name;
  profile.lastUsedAt = nowIso();
  saveStore(store);
  return { profile, toolId: profile.tool };
}

export function currentProfile(toolId: string): Profile | undefined {
  const store = loadStore();
  const name = store.current[toolId];
  if (!name) return undefined;
  return store.profiles.find((p) => p.name === name);
}
