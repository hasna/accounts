// The single storage abstraction for the accounts *registry*.
//
// One `AccountsStore` interface, two transports behind it:
//   - LocalStore: on-box JSON registry (`~/.hasna/accounts/accounts.json`).
//   - ApiStore:   the self-hosted/cloud HTTP API at `<API_URL>/v1` + bearer key.
//
// `resolveStore()` is the mode resolver: when `HASNA_ACCOUNTS_API_URL` +
// `HASNA_ACCOUNTS_API_KEY` are set (and mode is not explicitly `local`), every
// registry read/write routes to the cloud ApiStore. Explicit API modes fail
// closed when either value is missing; an unset mode defaults to local. Both
// `self_hosted` and `cloud` deployments use the SAME ApiStore code — only the
// URL/key differ (server-side tenancy, not client logic).
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
    const purgeNote = opts.purge
      ? "--purge is a local-only operation; the config dir (if any) was not touched in self_hosted mode"
      : undefined;
    return { profile, purged: false, ...(purgeNote ? { purgeNote } : {}) };
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
 * self-hosted API is configured (URL + key present, mode not forced local),
 * else LocalStore.
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
