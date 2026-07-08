// The single storage abstraction for the accounts *registry*.
//
// One `AccountsStore` interface, two transports behind it:
//   - LocalStore: on-box JSON registry (`~/.hasna/accounts/accounts.json`).
//   - ApiStore:   the self-hosted/cloud HTTP API at `<API_URL>/v1` + bearer key.
//
// `resolveStore()` is the mode resolver: when `HASNA_ACCOUNTS_API_URL` +
// `HASNA_ACCOUNTS_API_KEY` are set (and mode is not explicitly `local`), every
// registry read/write routes to the cloud ApiStore; otherwise LocalStore. Both
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

import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Profile } from "../types.js";
import { AccountsError } from "../types.js";
import { profilesDir } from "../storage.js";
import { DEFAULT_TOOL, getTool } from "./tools.js";
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
    return this.api.list(tool);
  }

  async getProfile(name: string, tool?: string): Promise<Profile> {
    const profile = await this.resolve(name, tool);
    return profile;
  }

  async findProfile(name: string, tool?: string): Promise<Profile | undefined> {
    return this.api.get(name, tool);
  }

  async addProfile(opts: AddOptions): Promise<Profile> {
    const toolId = opts.tool ?? DEFAULT_TOOL;
    getTool(toolId); // validate tool exists
    const dir = opts.dir ? expandPath(opts.dir) : join(profilesDir(), toolId, opts.name);
    mkdirSync(dir, { recursive: true });
    const email = opts.email ?? detectEmail(dir, getTool(toolId)) ?? undefined;
    return this.api.create({
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
  }

  async updateProfile(name: string, opts: UpdateOptions): Promise<Profile> {
    const existing = await this.resolve(name, opts.tool);
    const dir = opts.dir !== undefined ? expandPath(opts.dir) : undefined;
    if (dir !== undefined) mkdirSync(dir, { recursive: true });
    return this.api.update(name, existing.tool, {
      email: opts.email,
      displayName: opts.displayName,
      identity: opts.identity,
      cardLast4: opts.cardLast4,
      metadata: opts.metadata,
      dir,
      description: opts.description,
    });
  }

  async renameProfile(oldName: string, newName: string, tool?: string): Promise<Profile> {
    const existing = await this.resolve(oldName, tool);
    return this.api.rename(oldName, newName, existing.tool);
  }

  async removeProfile(name: string, opts: RemoveOptions = {}): Promise<RemoveResult> {
    const profile = await this.api.remove(name, opts.tool);
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
    return this.api.get(current.name, tool);
  }

  async listCurrent(): Promise<CurrentEntry[]> {
    const current = await this.api.listCurrent();
    return current.map((c) => ({ tool: c.tool, name: c.name }));
  }

  /** Resolve a profile by name (+optional tool), mirroring local error text. */
  private async resolve(name: string, tool?: string): Promise<Profile> {
    if (tool) {
      const profile = await this.api.get(name, tool);
      if (!profile) throw new AccountsError(`no profile named "${name}" for tool "${tool}". Run \`accounts list\` to see profiles.`);
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
    return matches[0]!;
  }
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
  return new LocalStore();
}
