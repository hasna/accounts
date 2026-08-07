// The single storage abstraction for the accounts *registry*.
//
// One `AccountsStore` interface, two transports behind it:
//   - LocalStore: on-box JSON registry (`~/.hasna/accounts/accounts.json`).
//   - ApiStore:   the self-hosted/cloud HTTP API at `<API_URL>/v1` + bearer key.
//
// `resolveStore()` is the mode resolver: when `HASNA_ACCOUNTS_API_URL` +
// `HASNA_ACCOUNTS_API_KEY` are set (and mode is not explicitly `local`, and
// `ACCOUNTS_HOME` is not overridden), every registry read/write routes to the
// cloud ApiStore. Explicit API modes fail closed when either value is missing;
// an unset mode defaults to local. Both `self_hosted` and `cloud` deployments
// use the SAME ApiStore code — only the URL/key differ (server-side tenancy,
// not client logic).
//
// SCOPE: the Store owns the shared registry — profiles, their metadata, and the
// per-tool "current" selection. Genuinely machine-local state (a profile's
// on-disk config `dir`, the `applied` auth map, tool locks, launching a tool)
// is not part of the shared registry and is handled by the local orchestration
// modules (apply.ts, switch.ts, launch). Those read the profile record through
// this Store, then act on the local machine.
//
// No CLI command, MCP tool, or SDK method touches sqlite or issues raw fetch —
// the only two backends are LocalStore (fs) and ApiStore (@hasna/contracts HTTP
// transport). The bearer key never appears in output or logs.

import { existsSync, mkdirSync, rmSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  profilesDir,
  reconcileMachineProfileRemove,
  reconcileMachineProfileRename,
} from "../storage.js";
import {
  DEFAULT_TOOL,
  getTool,
  isBuiltinTool,
  listTools as localListTools,
  addCustomTool as localAddCustomTool,
  removeCustomTool as localRemoveCustomTool,
  setCustomToolsCache,
  clearCustomToolsCache,
  BUILTIN_TOOLS,
} from "./tools.js";
import { profileNameSchema, toolDefSchema } from "../types.js";
import { detectEmail } from "./detect.js";
import {
  addProfile as localAdd,
  currentProfile as localCurrent,
  expandPath,
  findProfile as localFind,
  getProfile as localGet,
  listProfiles as localList,
  purgeProfileDir,
  redetectEmail as localRedetect,
  removeProfile as localRemove,
  renameProfile as localRename,
  updateProfile as localUpdate,
  useProfile as localUse,
  type AddOptions,
  type RemoveOptions,
  type UpdateOptions,
} from "./profiles.js";
import { loadStore } from "../storage.js";
import { resolveAccountsCloud, type AccountsCloudApi } from "./cloud-accounts.js";
import { assertSafeWritePath } from "./safe-path.js";
import { assertNameFree, type NameInvariantVerdict } from "./name-invariant.js";
import { grandfatheredPairs } from "./grandfather-manifest.js";
import { ensureSharedCapabilities } from "./shared-capabilities.js";
import {
  enumerateProfileDirs,
  mergedNameUniverse,
  type DiscoveredProfileDir,
} from "./profile-namespaces.js";

export interface CurrentEntry {
  tool: string;
  name: string;
}

export interface RemoveResult {
  profile: Profile;
  purged: boolean;
  purgeNote?: string;
}

/** The single registry surface. LocalStore and ApiStore both implement it. */
export interface AccountsStore {
  readonly transport: "local" | "api";
  listProfiles(tool?: string): Promise<Profile[]>;
  getProfile(name: string, tool?: string): Promise<Profile>;
  findProfile(name: string, tool?: string): Promise<Profile | undefined>;
  addProfile(opts: AddOptions): Promise<Profile>;
  updateProfile(name: string, opts: UpdateOptions): Promise<Profile>;
  renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile>;
  removeProfile(name: string, opts?: RemoveOptions): Promise<RemoveResult>;
  redetectEmail(name: string, tool?: string): Promise<Profile>;
  useProfile(name: string, tool?: string): Promise<{ profile: Profile; toolId: string }>;
  currentProfile(tool: string): Promise<Profile | undefined>;
  listCurrent(): Promise<CurrentEntry[]>;
  /** All tools (built-in + custom) known to the active registry. */
  listTools(): Promise<ToolDef[]>;
  /** Resolve a tool after hydrating the active registry's custom definitions. */
  resolveTool(toolId: string): Promise<ToolDef>;
  /** Register (or update) a custom tool in the active registry. */
  addTool(def: ToolDef): Promise<ToolDef>;
  /** Remove a custom tool from the active registry. */
  removeTool(id: string): Promise<void>;
  /**
   * Evaluate one-name-one-provider for a prospective binding, against the
   * MERGED universe this transport can see.
   *
   * Part of the contract rather than a helper each caller assembles, because
   * the enforcement point is the thing the design's first review cycle got
   * wrong: a check built from `loadStore()` sees 14 of 23 colliding records and
   * cannot see two of the named fixtures at all. Putting it here means both
   * transports answer from their own authoritative view.
   *
   * PR-1 semantics are WARN: this RETURNS a verdict and does not throw. The
   * existing per-store hard rejections (`nameConflict` in profiles.ts and in
   * AccountsRepo) are untouched and still refuse a duplicate — this adds
   * coverage over the merged universe, it does not relax anything.
   */
  assertNameFree(name: string, provider: string): Promise<NameInvariantVerdict>;
}

/**
 * The universe + grandfather set a store evaluates the invariant against.
 *
 * Shared by both transports so "what counts as the universe" is written once;
 * only the record source differs.
 */
async function evaluateAgainstUniverse(
  records: readonly Profile[],
  discovered: readonly DiscoveredProfileDir[],
  name: string,
  provider: string,
): Promise<NameInvariantVerdict> {
  return assertNameFree(name, provider, mergedNameUniverse(records, discovered), {
    grandfathered: grandfatheredPairs(),
  });
}

/** On-box JSON registry. Delegates to the core profile library. */
class LocalStore implements AccountsStore {
  readonly transport = "local" as const;

  async listProfiles(tool?: string): Promise<Profile[]> {
    return localList(tool);
  }
  async getProfile(name: string, tool?: string): Promise<Profile> {
    return localGet(name, tool);
  }
  async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    return localFind(name, tool);
  }
  async addProfile(opts: AddOptions): Promise<Profile> {
    return localAdd(opts);
  }
  async updateProfile(name: string, opts: UpdateOptions): Promise<Profile> {
    return localUpdate(name, opts);
  }
  async renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile> {
    return localRename(oldName, newName, tool);
  }
  async removeProfile(name: string, opts: RemoveOptions = {}): Promise<RemoveResult> {
    return localRemove(name, opts);
  }
  async redetectEmail(name: string, tool?: string): Promise<Profile> {
    return localRedetect(name, tool);
  }
  async useProfile(name: string, tool?: string): Promise<{ profile: Profile; toolId: string }> {
    return localUse(name, tool);
  }
  async currentProfile(tool: string): Promise<Profile | undefined> {
    return localCurrent(tool);
  }
  async listCurrent(): Promise<CurrentEntry[]> {
    const current = loadStore().current;
    return Object.entries(current).map(([tool, name]) => ({ tool, name }));
  }
  async listTools(): Promise<ToolDef[]> {
    return localListTools();
  }
  async resolveTool(toolId: string): Promise<ToolDef> {
    return getTool(toolId);
  }
  async addTool(def: ToolDef): Promise<ToolDef> {
    return localAddCustomTool(def);
  }
  async removeTool(id: string): Promise<void> {
    localRemoveCustomTool(id);
  }
  async assertNameFree(name: string, provider: string): Promise<NameInvariantVerdict> {
    // Registry rows PLUS on-disk dirs: in local mode the registry file is known
    // to describe a fraction of the machine (8 of 28 claude dirs measured), so
    // the file alone would under-report.
    return evaluateAgainstUniverse(await this.listProfiles(), enumerateProfileDirs(await this.listTools()), name, provider);
  }
}

/**
 * Self-hosted/cloud registry over `<API_URL>/v1`. The account `dir` is
 * machine-local, so create/update materialize a managed local config dir on
 * this machine and record its path in the cloud record (so the creating machine
 * can immediately launch the profile).
 */
class ApiStore implements AccountsStore {
  readonly transport = "api" as const;

  constructor(private readonly api: AccountsCloudApi) {}

  async listProfiles(tool?: string): Promise<Profile[]> {
    const profiles = await this.api.list(tool);
    await this.hydrateProfileTools(profiles);
    return profiles;
  }

  async getProfile(name: string, tool?: string): Promise<Profile> {
    const profile = await this.resolve(name, tool);
    return profile;
  }

  async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    const profile = await this.api.get(name, tool);
    if (profile) await this.hydrateProfileTools([profile]);
    return profile;
  }

  async addProfile(opts: AddOptions): Promise<Profile> {
    assertProfileName(opts.name);
    const toolId = opts.tool ?? DEFAULT_TOOL;
    const tool = await this.resolveTool(toolId);
    const managed = opts.dir === undefined;
    const dir = managed ? join(profilesDir(), toolId, opts.name) : validatedDirectoryPath(opts.dir!);
    const created = prepareProfileDirectory(dir, managed);
    // Keep the hosted transport's machine-local provisioning contract aligned
    // with LocalStore: a profile must be born with the shared Claude settings
    // that the selected machine declares, not repaired by a later sweep.
    ensureSharedCapabilities(dir, tool);
    const email = opts.email ?? detectEmail(dir, tool) ?? undefined;
    try {
      return await this.api.create({
        name: opts.name,
        tool: toolId,
        email,
        displayName: opts.displayName,
        identity: opts.identity,
        cardLast4: opts.cardLast4,
        metadata: opts.metadata,
        dir,
        description: opts.description,
      });
    } catch (error) {
      if (created) rmSync(dir, { recursive: true, force: true });
      throw error;
    }
  }

  async updateProfile(name: string, opts: UpdateOptions): Promise<Profile> {
    const existing = await this.resolve(name, opts.tool);
    const dir = opts.dir !== undefined ? validatedDirectoryPath(opts.dir) : undefined;
    const created = dir !== undefined ? prepareProfileDirectory(dir, false) : false;
    try {
      return await this.api.update(name, existing.tool, {
        email: opts.email,
        displayName: opts.displayName,
        identity: opts.identity,
        cardLast4: opts.cardLast4,
        metadata: opts.metadata,
        dir,
        description: opts.description,
        nativeName: opts.nativeName,
        aliases: opts.aliases,
      });
    } catch (error) {
      if (dir && created) rmSync(dir, { recursive: true, force: true });
      throw error;
    }
  }

  async renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile> {
    assertProfileName(newName);
    const existing = await this.resolve(oldName, tool);
    const renamed = await this.api.rename(oldName, newName, existing.tool);
    reconcileMachineProfileRename(existing.tool, oldName, newName);
    return renamed;
  }

  async removeProfile(name: string, opts: RemoveOptions = {}): Promise<RemoveResult> {
    const profile = await this.api.remove(name, opts.tool);
    reconcileMachineProfileRemove(profile.tool, profile.name);
    // The row lives in the API; the DIRECTORY has always lived on this machine.
    // Skipping it here is what turned `--purge` into a silent orphan generator.
    const { purged, purgeNote } = opts.purge ? purgeProfileDir(profile) : { purged: false, purgeNote: undefined };
    return { profile, purged, ...(purgeNote ? { purgeNote } : {}) };
  }

  async redetectEmail(name: string, tool?: string): Promise<Profile> {
    const profile = await this.resolve(name, tool);
    if (!profile.dir || !existsSync(profile.dir)) return profile;
    const email = detectEmail(profile.dir, getTool(profile.tool));
    if (!email || email === profile.email) return profile;
    return this.api.update(name, profile.tool, { email });
  }

  async useProfile(name: string, tool?: string): Promise<{ profile: Profile; toolId: string }> {
    const profile = await this.resolve(name, tool);
    await this.api.setCurrent(profile.tool, profile.name);
    return { profile, toolId: profile.tool };
  }

  async currentProfile(tool: string): Promise<Profile | undefined> {
    const current = await this.api.getCurrent(tool);
    if (!current) return undefined;
    const profile = await this.api.get(current.name, tool);
    if (profile) await this.hydrateProfileTools([profile]);
    return profile;
  }

  async listCurrent(): Promise<CurrentEntry[]> {
    const current = await this.api.listCurrent();
    return current.map((c) => ({ tool: c.tool, name: c.name }));
  }

  async listTools(): Promise<ToolDef[]> {
    const cloud = await this.api.listTools();
    const custom = this.customToolsFrom(cloud);
    setCustomToolsCache(custom);
    const byId = new Map<string, ToolDef>();
    for (const t of BUILTIN_TOOLS) byId.set(t.id, t);
    for (const t of custom) byId.set(t.id, t);
    return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  async resolveTool(toolId: string): Promise<ToolDef> {
    if (!isBuiltinTool(toolId)) await this.refreshToolCache();
    return getTool(toolId);
  }

  async addTool(def: ToolDef): Promise<ToolDef> {
    if (isBuiltinTool(def.id)) throw new AccountsError(`"${def.id}" is a built-in tool and cannot be redefined`);
    const created = await this.api.createTool(def);
    // Write through to the process cache so this process can launch it now.
    await this.refreshToolCache();
    return created;
  }

  async removeTool(id: string): Promise<void> {
    if (isBuiltinTool(id)) throw new AccountsError(`"${id}" is a built-in tool and cannot be removed`);
    await this.api.removeTool(id);
    await this.refreshToolCache();
  }

  /**
   * Client-side PRE-FLIGHT only. The server's own write path is authoritative:
   * `AccountsRepo.create`/`rename` refuse a duplicate whatever this returns, so
   * a client that skipped this check still cannot create one. This exists to
   * give the operator the provider and email of the holder before they spend a
   * login on a name that will be refused.
   */
  async assertNameFree(name: string, provider: string): Promise<NameInvariantVerdict> {
    // Server rows are the primary universe (they ARE what `accounts list`
    // returns); local dirs are supplementary and catch unregistered drift.
    return evaluateAgainstUniverse(await this.listProfiles(), enumerateProfileDirs(await this.listTools()), name, provider);
  }

  /** Pull the cloud custom-tool set into the process-local resolution cache. */
  private async refreshToolCache(): Promise<void> {
    const cloud = await this.api.listTools();
    setCustomToolsCache(this.customToolsFrom(cloud));
  }

  private customToolsFrom(cloud: Awaited<ReturnType<AccountsCloudApi["listTools"]>>): ToolDef[] {
    const custom: ToolDef[] = [];
    for (const item of cloud) {
      if (item.builtin !== false) continue;
      const { builtin: _builtin, ...definition } = item;
      const parsed = toolDefSchema.safeParse(definition);
      if (!parsed.success) {
        throw new AccountsError(
          `invalid custom tool "${item.id}" returned by accounts-serve: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`,
        );
      }
      custom.push(parsed.data);
    }
    return custom;
  }

  private async hydrateProfileTools(profiles: readonly Profile[]): Promise<void> {
    if (profiles.some((profile) => !isBuiltinTool(profile.tool))) await this.refreshToolCache();
  }

  /** Resolve a profile by name (+optional tool), mirroring local error text. */
  private async resolve(name: string, tool?: string): Promise<Profile> {
    if (tool) {
      const profile = await this.api.get(name, tool);
      if (!profile) throw new AccountsError(`no profile named "${name}" for tool "${tool}". Run \`accounts list\` to see profiles.`);
      await this.hydrateProfileTools([profile]);
      return profile;
    }
    const matches = (await this.api.list()).filter((p) => p.name === name);
    if (matches.length === 0) {
      throw new AccountsError(`no profile named "${name}". Run \`accounts list\` to see profiles.`);
    }
    if (matches.length > 1) {
      throw new AccountsError(
        `profile "${name}" exists for multiple tools (${matches.map((p) => p.tool).join(", ")}); pass --tool`,
      );
    }
    const profile = matches[0]!;
    await this.hydrateProfileTools([profile]);
    return profile;
  }
}

function assertProfileName(name: string): void {
  const parsed = profileNameSchema.safeParse(name);
  if (!parsed.success) throw new AccountsError(parsed.error.issues[0]?.message ?? "invalid profile name");
}

function validatedDirectoryPath(input: string): string {
  if (!input.trim() || input.includes("\0") || /[\r\n]/.test(input)) {
    throw new AccountsError("invalid profile directory");
  }
  return expandPath(input);
}

function assertManagedDirectory(dir: string): void {
  const base = resolve(profilesDir());
  const rel = relative(base, resolve(dir));
  if (!rel || rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) {
    throw new AccountsError(`refusing to create managed profile outside ${base}`);
  }
}

function prepareProfileDirectory(dir: string, managed: boolean): boolean {
  if (managed) assertManagedDirectory(dir);
  const existed = existsSync(dir);
  assertSafeWritePath(
    join(dir, ".accounts-directory-check"),
    managed ? { mustStayUnder: profilesDir() } : { mustStayUnder: dir },
  );
  mkdirSync(dir, { recursive: true });
  return !existed;
}

/**
 * Resolve the active registry store for this process. ApiStore when the
 * self-hosted API is configured (URL + key present, mode not forced local,
 * and no local `ACCOUNTS_HOME` override), else LocalStore.
 */
export function resolveStore(
  env: NodeJS.ProcessEnv = process.env,
  overrides?: Parameters<typeof resolveAccountsCloud>[1],
): AccountsStore {
  const cloud = resolveAccountsCloud(env, overrides);
  if (cloud.transport === "cloud-http") return new ApiStore(cloud.api);
  clearCustomToolsCache();
  return new LocalStore();
}

/**
 * The usage-hook's local profile view: the on-disk profile DIRECTORIES union
 * the local registry rows. Read-only for the registry; grants ZERO cloud
 * authority.
 *
 * Why the registry alone is not enough. In cloud mode the on-box
 * `accounts.json` is a fraction of the machine — measured 2026-08-07 on
 * station01: 7 claude rows against 41 managed profile dirs and 26 central-auth
 * accounts. Every one of those 34 unregistered dirs has an on-box credential
 * the hook can switch to, and — the case that actually breaks auto-switch — a
 * session LAUNCHED on one of them has a config dir the registry does not list,
 * so `switchAccount`'s allowlist would refuse the session's OWN dir as
 * "external" and no auto-switch could ever happen there. The hook's whole job
 * is "switch to any healthy account present on this box", so its profile set
 * must be what is present on this box, not the sparse registry subset.
 *
 * Security: this list is BOTH the switch-candidate set AND the
 * anti-exfiltration allowlist inside `switchAccount`. That allowlist must come
 * from somewhere the calling (potentially prompt-injected) agent does not
 * control. It still does: the added dirs live under `profilesDir()`
 * (`<accountsHome>/profiles/...`) and each tool's native profile root — the
 * credential store's own directories. An agent that could plant a profile dir
 * there could already read the credential store directly, so enumerating those
 * dirs is exactly as trustworthy as reading `accounts.json`, which lives in the
 * same place. A caller-supplied `--dir <arbitrary path>` is still refused
 * because it matches no enumerated dir.
 */
class HookLocalStore extends LocalStore {
  private diskProfiles(toolId?: string): Profile[] {
    const tools = toolId ? [getTool(toolId)] : BUILTIN_TOOLS;
    // A synthetic createdAt keeps the shape a Profile; the hook and
    // switchAccount read name/tool/dir/email only.
    const created = new Date(0).toISOString();
    return enumerateProfileDirs(tools).map(
      (discovered): Profile => ({
        name: discovered.name,
        tool: discovered.provider,
        dir: discovered.dir,
        createdAt: created,
      }),
    );
  }

  /** Registry rows (email/uuid-bearing) unioned with on-disk dirs, by dir. */
  private localView(toolId?: string): Profile[] {
    const byDir = new Map<string, Profile>();
    for (const profile of localList(toolId)) byDir.set(resolve(profile.dir), profile);
    for (const profile of this.diskProfiles(toolId)) {
      const key = resolve(profile.dir);
      if (!byDir.has(key)) byDir.set(key, profile);
    }
    return [...byDir.values()].sort(
      (a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name),
    );
  }

  override async listProfiles(tool?: string): Promise<Profile[]> {
    return this.localView(tool);
  }

  override async getProfile(name: string, tool?: string): Promise<Profile> {
    const found = this.localView(tool).find((p) => p.name === name && (!tool || p.tool === tool));
    if (!found) {
      throw new AccountsError(
        `no profile named "${name}"${tool ? ` for tool "${tool}"` : ""}. Run \`accounts list\` to see profiles.`,
      );
    }
    return found;
  }

  override async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    return this.localView(tool).find((p) => p.name === name && (!tool || p.tool === tool));
  }

  override async useProfile(name: string, tool?: string): Promise<{ profile: Profile; toolId: string }> {
    const profile = await this.getProfile(name, tool);
    // Recording "current" in the on-box registry is best-effort here: the hook
    // runs in a launched session whose profile may exist only on disk, and the
    // session adopting the account on its next request does NOT depend on the
    // registry pointer. A disk-only profile has no `accounts.json` row for
    // `localUse` to update, so its throw must not fail the switch (switchAccount
    // already tolerates it; applyProfile on the live-default path does not).
    try {
      await super.useProfile(name, tool);
    } catch {
      // best-effort
    }
    return { profile, toolId: profile.tool };
  }
}

/**
 * The on-box profile view for the usage-hook, ALWAYS local, never the cloud
 * API — and never a throw over storage-mode configuration. `resolveStore()`
 * consults the cloud resolver, which is correct for operator commands but wrong
 * for a caller that only ever touches local-machine state and must not fail
 * when the cloud variables are absent.
 *
 * The measured case: `accounts launch` strips `HASNA_ACCOUNTS_API_URL` /
 * `HASNA_ACCOUNTS_API_KEY` from the launched session (registry-authority
 * denial, #126) while leaving a `cloud` storage mode set, so `resolveStore()`
 * inside that session throws and the usage-hook fails open into "auto-switching
 * is NOT running". `HookLocalStore` grants ZERO registry authority, so using it
 * here does not reopen #126; it just stops the hook from depending on cloud
 * variables it was deliberately denied, and sources its profiles from what is
 * actually on the box (see the class doc for the disk-union rationale).
 */
export function resolveLocalStore(): AccountsStore {
  clearCustomToolsCache();
  return new HookLocalStore();
}
