import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { existsSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import { type Profile, type Store, AccountsError, profileNameSchema } from "../types.js";
import { loadStore, saveStore, profilesDir } from "../storage.js";
import { DEFAULT_TOOL, getTool } from "./tools.js";
import { detectEmail } from "./detect.js";
import { sameConfigDir } from "./safe-path.js";
import { ensureSharedCapabilities } from "./shared-capabilities.js";
import { isAccountUuid } from "./auth-store.js";

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

function resolveProfileFromStore(store: Store, name: string, toolId?: string): Profile {
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

/**
 * Containment decided on REAL paths, for the one caller that deletes.
 *
 * This replaces a purely lexical predicate that resolved neither side. The
 * lexical form was the only containment check the purge had, and it is the one
 * a reviewer walked past with a symlink.
 *
 * `isManagedProfileDir` is purely lexical, so a symlink sitting under the
 * profiles root satisfies it while pointing anywhere on the machine. That is
 * harmless for the read-only callers, and not harmless for `rmSync`: a reviewer
 * walked past the lexical guard with a symlink and deleted a different live
 * profile's dir, `.credentials.json` and all. Resolving both sides first closes
 * it, and refusing when the path does not resolve keeps the failure a refusal
 * rather than a delete of whatever the parent happens to be.
 */
function isRealManagedProfileDir(dir: string): boolean {
  let realRoot: string;
  let realDir: string;
  try {
    realRoot = realpathSync(profilesDir());
    realDir = realpathSync(dir);
  } catch {
    return false;
  }
  const rel = relative(realRoot, realDir);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
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

export function lockProfileTool(name: string, toolId: string): void {
  getTool(toolId);
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");
  const store = loadStore();
  if (!store.profiles.some((p) => p.name === name && p.tool === toolId)) {
    throw new AccountsError(`no profile named "${name}" for tool "${toolId}"`);
  }
  store.toolLocks[name] = toolId;
  saveStore(store);
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
}

/**
 * One-account-one-tool: an account name identifies exactly one tool, because
 * resolution is name-first — `resolveProfileFromStore` throws `exists for
 * multiple tools` the moment two rows share a name, breaking every bare
 * `accounts <cmd> <name>`. Same rule and error wording as the api transport
 * (AccountsRepo.nameConflict, src/server/repo.ts) so both transports refuse a
 * duplicate identically. Grandfathered collisions already in the store stay
 * resolvable (via --tool or a tool lock); only NEW collisions are refused.
 */
function nameConflict(name: string, holderTool: string, tool: string): AccountsError {
  return holderTool === tool
    ? new AccountsError(`a ${tool} profile named "${name}" already exists`)
    : new AccountsError(
        `a profile named "${name}" already exists for tool "${holderTool}"; ` +
          "account names must be unique across tools",
      );
}

export function addProfile(opts: AddOptions): Profile {
  const name = opts.name;
  const nameCheck = profileNameSchema.safeParse(name);
  if (!nameCheck.success) throw new AccountsError(nameCheck.error.issues[0]?.message ?? "invalid profile name");

  const toolId = opts.tool ?? DEFAULT_TOOL;
  const tool = getTool(toolId);

  const store = loadStore();
  const holder = store.profiles.find((p) => p.name === name);
  if (holder) {
    throw nameConflict(name, holder.tool, toolId);
  }

  const dir = opts.dir ? expandPath(opts.dir) : join(profilesDir(), toolId, name);
  if (store.profiles.some((p) => sameConfigDir(p.dir, dir))) {
    throw new AccountsError(`a profile already uses config dir ${dir}`);
  }
  mkdirSync(dir, { recursive: true });
  // A new profile starts with the machine's shared skills/subagents/MCP servers;
  // only credentials stay per-profile.
  ensureSharedCapabilities(dir, tool);

  const email = opts.email ?? detectEmail(dir, tool);
  if (opts.cardLast4) assertCardLast4(opts.cardLast4);
  const displayName = normalizeNonEmptyText(opts.displayName, "display name");
  const identity = normalizeNonEmptyText(opts.identity, "identity");
  const metadata = normalizeMetadata(opts.metadata);
  const profile: Profile = {
    name,
    tool: toolId,
    // Written alongside `tool`, not instead of it: every existing reader keeps
    // working off `tool` for one release while new records already carry the
    // canonical field, so the later flip has no backfill to do for anything
    // created from here on.
    provider: toolId,
    ...(email ? { email } : {}),
    ...(displayName !== undefined ? { displayName } : {}),
    ...(identity !== undefined ? { identity } : {}),
    ...(opts.cardLast4 ? { cardLast4: opts.cardLast4 } : {}),
    ...(metadata && Object.keys(metadata).length > 0 ? { metadata } : {}),
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
  if (store.toolLocks[profile.name] === profile.tool) delete store.toolLocks[profile.name];
  saveStore(store);

  const { purged, purgeNote } = options.purge ? purgeProfileDir(profile) : { purged: false, purgeNote: undefined };
  return { profile, purged, purgeNote };
}

/**
 * Delete a profile's managed config dir. Shared by the local and hosted stores
 * because a PROFILE DIR IS ALWAYS MACHINE-LOCAL — which store holds the row says
 * nothing about where the bytes are. The hosted path used to skip this and
 * report it as "a local-only operation", which left the directory behind after
 * the row that named it was gone: an orphan no `accounts` command can list,
 * still holding whatever the profile accumulated, including `.credentials.json`.
 * A dir invisible to the tool that made it is exactly the population an audit
 * cannot see.
 *
 * The guards are unchanged: never a dir outside the managed profile root, never
 * the tool's own default dir, and a refusal is reported rather than performed.
 */
export function purgeProfileDir(profile: Profile): { purged: boolean; purgeNote?: string } {
  if (!profile.dir || !existsSync(profile.dir)) return { purged: false };

  // The identity the path is derived FROM is remote-supplied too, so validate it
  // before deriving. `HostedStore.removeProfile` returns the server's body, and
  // `toProfile` in cloud-accounts.ts is a plain field copy that never applies
  // `profileSchema` — so a response naming `../claude/victim` normalises back
  // inside the managed root, both checks below agree, and the delete lands on a
  // different profile. Deriving from unvalidated input just moves the trust from
  // `dir` to `name` rather than removing it. Slugs cannot contain a separator or
  // a dot segment, which is exactly the property the derivation needs.
  if (!profileNameSchema.safeParse(profile.name).success || !profileNameSchema.safeParse(profile.tool).success) {
    return {
      purged: false,
      purgeNote: `refused to delete ${profile.dir}: "${profile.tool}/${profile.name}" is not a valid profile identity`,
    };
  }

  // DERIVE the path to delete; never delete the one we were handed. On the
  // hosted path `profile.dir` arrives in an API response, so trusting it makes
  // the delete target remote-controlled. The canonical managed location is a
  // pure function of (profiles root, tool, name), so the supplied dir only has
  // to AGREE with it — and a supplied path that disagrees is refused and
  // reported rather than deleted.
  const expected = join(profilesDir(), profile.tool, profile.name);
  if (!isRealManagedProfileDir(profile.dir) || !samePathOnDisk(profile.dir, expected)) {
    return {
      purged: false,
      purgeNote:
        `refused to delete ${profile.dir}: it is not the managed dir for ${profile.tool}/${profile.name} ` +
        `(expected ${expected}). Remove it manually if that is genuinely intended.`,
    };
  }

  rmSync(expected, { recursive: true, force: true });
  return { purged: true };
}

/** Both paths resolved, so a symlink cannot make two different dirs compare equal. */
function samePathOnDisk(a: string, b: string): boolean {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
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
  // Name-scoped, and skipped for a rename onto itself — the same semantics as
  // AccountsRepo.rename (src/server/repo.ts), so both transports behave alike.
  if (oldName !== newName) {
    const holder = store.profiles.find((p) => p.name === newName);
    if (holder) throw nameConflict(newName, holder.tool, profile.tool);
  }

  if (store.current[profile.tool] === oldName) store.current[profile.tool] = newName;
  if (store.applied[profile.tool] === oldName) store.applied[profile.tool] = newName;
  if (store.toolLocks[oldName] === profile.tool) {
    delete store.toolLocks[oldName];
    if (!store.toolLocks[newName]) store.toolLocks[newName] = profile.tool;
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
  /**
   * The account uuid this profile belongs to, as backfilled from the dir's
   * parked identity. Set only by the reconcile backfill, which refuses to
   * overwrite a disagreeing value — see src/lib/uuid-backfill.ts.
   */
  accountUuid?: string;
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
  if (opts.accountUuid !== undefined) {
    if (!isAccountUuid(opts.accountUuid)) {
      throw new AccountsError(`accountUuid must be a uuid; got ${JSON.stringify(opts.accountUuid)}`);
    }
    profile.accountUuid = opts.accountUuid.toLowerCase();
  }
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
export function useProfile(name: string, toolId?: string): { profile: Profile; toolId: string } {
  const store = loadStore();
  const profile = resolveProfileFromStore(store, name, toolId);
  store.current[profile.tool] = name;
  store.toolLocks[profile.name] = profile.tool;
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
