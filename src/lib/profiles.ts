import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { existsSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import { type NormalizedStore, type Profile, AccountsError, profileNameSchema } from "../types.js";
import { loadStore, profileAuthIncarnation, profileAuthRevisionKey, saveStore, profilesDir, withStoreLock } from "../storage.js";
import { DEFAULT_TOOL, getTool } from "./tools.js";
import { detectEmail } from "./detect.js";
import { removeClaudeProfileCommittedAuthSnapshots } from "./claude-auth.js";

export type ProfileMetadataValue = string | number | boolean | null;
export type ProfileMetadata = Record<string, ProfileMetadataValue>;
const RESERVED_METADATA_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function nowIso(): string {
  return new Date().toISOString();
}

function assertCardLast4(value: string): void {
  if (!/^\d{4}$/.test(value)) throw new AccountsError("card last4 must be exactly 4 digits");
}

function normalizeNonEmptyText(value: string | undefined, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (value.trim().length === 0) throw new AccountsError(`${label} must not be empty`);
  return value;
}

function normalizeMetadata(metadata: ProfileMetadata | undefined): ProfileMetadata | undefined {
  if (metadata === undefined) return undefined;
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new AccountsError("metadata must be a plain object");
  }
  const prototype = Object.getPrototypeOf(metadata);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new AccountsError("metadata must be a plain object");
  }
  const out: ProfileMetadata = Object.create(null) as ProfileMetadata;
  for (const [key, value] of Object.entries(metadata)) {
    if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) {
      throw new AccountsError(`invalid metadata key "${key}"`);
    }
    if (RESERVED_METADATA_KEYS.has(key)) {
      throw new AccountsError(`reserved metadata key "${key}"`);
    }
    if (value !== null && !["string", "number", "boolean"].includes(typeof value)) {
      throw new AccountsError(`metadata "${key}" must be a string, number, boolean, or null`);
    }
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new AccountsError(`metadata "${key}" must be a finite number`);
    }
    out[key] = value;
  }
  return out;
}

/** Expand a leading `~` and resolve to an absolute path. */
export function expandPath(p: string): string {
  let out = p;
  if (out === "~") out = homedir();
  else if (out.startsWith("~/")) out = join(homedir(), out.slice(2));
  return resolve(out);
}

export function listProfiles(toolId?: string): Profile[] {
  const profiles = loadStore().profiles;
  const filtered = toolId ? profiles.filter((p) => p.tool === toolId) : profiles;
  return filtered.slice().sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name));
}

function profileMatches(name: string, toolId?: string): Profile[] {
  return loadStore().profiles.filter((p) => p.name === name && (!toolId || p.tool === toolId));
}

function resolveProfileFromStore(store: NormalizedStore, name: string, toolId?: string): Profile {
  const matches = store.profiles.filter((p) => p.name === name && (!toolId || p.tool === toolId));
  if (matches.length === 0) {
    const suffix = toolId ? ` for tool "${toolId}"` : "";
    throw new AccountsError(`no profile named "${name}"${suffix}. Run \`accounts list\` to see profiles.`);
  }
  if (!toolId) {
    const lockedTool = store.toolLocks[name];
    if (lockedTool) {
      const locked = matches.find((p) => p.tool === lockedTool);
      if (locked) return locked;
    }
  }
  if (matches.length > 1) {
    throw new AccountsError(
      `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
    );
  }
  return matches[0]!;
}

function isManagedProfileDir(dir: string): boolean {
  const rel = relative(resolve(profilesDir()), resolve(dir));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

function canonicalConfigDir(dir: string): string {
  const resolved = resolve(dir);
  const missing: string[] = [];
  let cursor = resolved;

  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) return resolved;
    missing.unshift(basename(cursor));
    cursor = parent;
  }

  try {
    return join(realpathSync(cursor), ...missing);
  } catch {
    return resolved;
  }
}

function sameConfigDir(a: string, b: string): boolean {
  return canonicalConfigDir(a) === canonicalConfigDir(b);
}

export function findProfile(name: string, toolId?: string): Profile | undefined {
  const matches = profileMatches(name, toolId);
  return matches.length === 1 ? matches[0] : undefined;
}

export function getProfile(name: string, toolId?: string): Profile {
  return resolveProfileFromStore(loadStore(), name, toolId);
}

export function getProfileToolLock(name: string): string | undefined {
  return loadStore().toolLocks[name];
}

export function getProfileToolLockRevision(name: string): string | undefined {
  return loadStore().toolLockRevisions[name];
}

export interface ProfileToolLockClaim {
  revision: string;
  previousTool?: string;
  previousRevision?: string;
  previousProfileIncarnation?: string;
}

/** Capture the exact lock state and choose its replacement generation without writing. */
export function planProfileToolLockClaim(name: string, toolId: string): ProfileToolLockClaim {
  getTool(toolId);
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");
  return withStoreLock(() => {
    const store = loadStore();
    if (!store.profiles.some((profile) => profile.name === name && profile.tool === toolId)) {
      throw new AccountsError(`no profile named "${name}" for tool "${toolId}"`);
    }
    const previousTool = store.toolLocks[name];
    const previousRevision = store.toolLockRevisions[name];
    const previousProfile = previousTool
      ? store.profiles.find((profile) => profile.name === name && profile.tool === previousTool)
      : undefined;
    return {
      revision: randomUUID(),
      ...(previousTool ? { previousTool } : {}),
      ...(previousRevision ? { previousRevision } : {}),
      ...(previousProfile
        ? { previousProfileIncarnation: profileAuthIncarnation(previousProfile) }
        : {}),
    };
  });
}

/** Claim a profile-name tool lock and capture the displaced lock atomically. */
export function claimProfileToolLock(
  name: string,
  toolId: string,
  planned?: ProfileToolLockClaim,
): ProfileToolLockClaim {
  getTool(toolId);
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");
  const claim = planned ?? planProfileToolLockClaim(name, toolId);
  return withStoreLock(() => {
    const store = loadStore();
    if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) {
      throw new AccountsError(`no profile named "${name}" for tool "${toolId}"`);
    }
    const previousTool = store.toolLocks[name];
    const previousRevision = store.toolLockRevisions[name];
    const previousProfile = previousTool
      ? store.profiles.find((profile) => profile.name === name && profile.tool === previousTool)
      : undefined;
    if (
      previousTool !== claim.previousTool ||
      previousRevision !== claim.previousRevision ||
      (previousProfile ? profileAuthIncarnation(previousProfile) : undefined) !==
        claim.previousProfileIncarnation
    ) {
      throw new AccountsError("profile tool lock changed concurrently; retry the operation");
    }
    const revision = claim.revision;
    store.toolLocks[name] = toolId;
    store.toolLockRevisions[name] = revision;
    saveStore(store);
    return {
      revision,
      ...(previousTool ? { previousTool } : {}),
      ...(previousRevision ? { previousRevision } : {}),
      ...(previousProfile
        ? { previousProfileIncarnation: profileAuthIncarnation(previousProfile) }
        : {}),
    };
  });
}

export function lockProfileTool(name: string, toolId: string): string {
  return claimProfileToolLock(name, toolId).revision;
}

/** Restore a profile-name tool lock only while the failed preparation owns it. */
export function restoreProfileToolLock(
  name: string,
  expectedRevision: string,
  toolId?: string,
  restoreRevision?: string | null,
  expectedProfileIncarnation?: string,
): boolean {
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");
  return withStoreLock(() => {
    const store = loadStore();
    if (store.toolLockRevisions[name] !== expectedRevision) return false;
    if (toolId) {
      getTool(toolId);
      const profile = store.profiles.find((candidate) => candidate.name === name && candidate.tool === toolId);
      if (!profile) {
        throw new AccountsError(`no profile named "${name}" for tool "${toolId}"`);
      }
      if (
        expectedProfileIncarnation &&
        profileAuthIncarnation(profile) !== expectedProfileIncarnation
      ) {
        return false;
      }
      store.toolLocks[name] = toolId;
      if (restoreRevision === undefined) store.toolLockRevisions[name] = randomUUID();
      else if (restoreRevision === null) delete store.toolLockRevisions[name];
      else store.toolLockRevisions[name] = restoreRevision;
    } else {
      delete store.toolLocks[name];
      delete store.toolLockRevisions[name];
    }
    saveStore(store);
    return true;
  });
}

export interface AddOptions {
  name: string;
  tool?: string;
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata?: ProfileMetadata;
  dir?: string;
  description?: string;
  /** Internal rollback fence fixed before login profile/directory mutation. */
  incarnationId?: string;
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
  if (store.profiles.some((p) => sameConfigDir(p.dir, dir))) {
    throw new AccountsError(`a profile already uses config dir ${dir}`);
  }
  mkdirSync(dir, { recursive: true });

  const email = opts.email ?? detectEmail(dir, tool);
  if (opts.cardLast4) assertCardLast4(opts.cardLast4);
  const displayName = normalizeNonEmptyText(opts.displayName, "display name");
  const identity = normalizeNonEmptyText(opts.identity, "identity");
  const metadata = normalizeMetadata(opts.metadata);
  const profile: Profile = {
    name,
    tool: toolId,
    ...(email ? { email } : {}),
    ...(displayName !== undefined ? { displayName } : {}),
    ...(identity !== undefined ? { identity } : {}),
    ...(opts.cardLast4 ? { cardLast4: opts.cardLast4 } : {}),
    ...(metadata && Object.keys(metadata).length > 0 ? { metadata } : {}),
    dir,
    ...(opts.description ? { description: opts.description } : {}),
    createdAt: nowIso(),
    incarnationId: opts.incarnationId ?? randomUUID(),
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
  if (store.current[profile.tool] === name) {
    delete store.current[profile.tool];
    delete store.currentRevisions[profile.tool];
  }
  if (store.applied[profile.tool] === name) {
    delete store.applied[profile.tool];
    delete store.appliedRevisions[profile.tool];
  }
  const authIncarnation = profileAuthIncarnation(profile);
  const authKeys = new Set([
    profileAuthRevisionKey(profile.tool, profile.name),
    ...Object.entries(store.profileAuthIncarnations)
      .filter(([, candidate]) => candidate === authIncarnation)
      .map(([key]) => key),
  ]);
  const removedAuthIdentities = new Set<string>();
  for (const authKey of authKeys) {
    const identity = store.profileAuthRevisions[authKey];
    if (identity) removedAuthIdentities.add(identity);
    delete store.profileAuthRevisions[authKey];
    delete store.profileAuthCommitRevisions[authKey];
    delete store.profileAuthIncarnations[authKey];
  }
  if (store.toolLocks[profile.name] === profile.tool) {
    delete store.toolLocks[profile.name];
    delete store.toolLockRevisions[profile.name];
  }
  saveStore(store);
  for (const identity of removedAuthIdentities) {
    // Legacy stores allowed arbitrary opaque identity strings. They cannot be
    // converted into a safe commit-directory path, so leave only those legacy
    // artifacts fail closed; all generated UUID identities are purged.
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(identity)) {
      removeClaudeProfileCommittedAuthSnapshots(identity);
    }
  }

  let purged = false;
  let purgeNote: string | undefined;
  if (options.purge) {
    const managed = isManagedProfileDir(profile.dir);
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

  if (store.current[profile.tool] === oldName) {
    store.current[profile.tool] = newName;
    store.currentRevisions[profile.tool] = randomUUID();
  }
  if (store.applied[profile.tool] === oldName) {
    store.applied[profile.tool] = newName;
    store.appliedRevisions[profile.tool] = randomUUID();
  }
  const oldAuthKey = profileAuthRevisionKey(profile.tool, oldName);
  const newAuthKey = profileAuthRevisionKey(profile.tool, newName);
  const authIdentity = store.profileAuthRevisions[oldAuthKey];
  if (authIdentity) {
    delete store.profileAuthRevisions[oldAuthKey];
    store.profileAuthRevisions[newAuthKey] = authIdentity;
  }
  const authCommitRevision = store.profileAuthCommitRevisions[oldAuthKey];
  if (authCommitRevision) {
    delete store.profileAuthCommitRevisions[oldAuthKey];
    store.profileAuthCommitRevisions[newAuthKey] = authCommitRevision;
  }
  const authIncarnation = store.profileAuthIncarnations[oldAuthKey];
  if (authIncarnation) {
    delete store.profileAuthIncarnations[oldAuthKey];
    store.profileAuthIncarnations[newAuthKey] = authIncarnation;
  }
  if (store.toolLocks[oldName] === profile.tool) {
    delete store.toolLocks[oldName];
    delete store.toolLockRevisions[oldName];
    if (!store.toolLocks[newName]) {
      store.toolLocks[newName] = profile.tool;
      store.toolLockRevisions[newName] = randomUUID();
    }
  }
  profile.name = newName;
  saveStore(store);
  return profile;
}

export interface UpdateOptions {
  tool?: string;
  email?: string;
  displayName?: string;
  identity?: string;
  cardLast4?: string;
  metadata?: ProfileMetadata;
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
  if (opts.displayName !== undefined) profile.displayName = normalizeNonEmptyText(opts.displayName, "display name");
  if (opts.identity !== undefined) profile.identity = normalizeNonEmptyText(opts.identity, "identity");
  if (opts.cardLast4 !== undefined) {
    assertCardLast4(opts.cardLast4);
    profile.cardLast4 = opts.cardLast4;
  }
  if (opts.metadata !== undefined) {
    const metadata = normalizeMetadata(opts.metadata);
    profile.metadata = { ...(profile.metadata ?? {}), ...(metadata ?? {}) };
  }
  if (opts.description !== undefined) profile.description = opts.description;
  if (opts.dir !== undefined) {
    const dir = expandPath(opts.dir);
    if (store.profiles.some((p) => p !== profile && sameConfigDir(p.dir, dir))) {
      throw new AccountsError(`a profile already uses config dir ${dir}`);
    }
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
export function useProfile(
  name: string,
  toolId?: string,
  currentRevision: string = randomUUID(),
): { profile: Profile; toolId: string; currentRevision: string } {
  const store = loadStore();
  const profile = resolveProfileFromStore(store, name, toolId);
  store.current[profile.tool] = name;
  store.currentRevisions[profile.tool] = currentRevision;
  store.toolLocks[profile.name] = profile.tool;
  store.toolLockRevisions[profile.name] = randomUUID();
  profile.lastUsedAt = nowIso();
  saveStore(store);
  return { profile, toolId: profile.tool, currentRevision };
}

export function currentProfile(toolId: string): Profile | undefined {
  const store = loadStore();
  const name = store.current[toolId];
  if (!name) return undefined;
  return store.profiles.find((p) => p.name === name && p.tool === toolId);
}
