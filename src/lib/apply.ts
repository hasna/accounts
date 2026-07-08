import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import { loadStore, saveStore } from "../storage.js";
import { getTool } from "./tools.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  assertRestorableProfileAuth,
  ensureProfileAuthSnapshot,
  liveCredentialShouldUpdateProfile,
  liveOAuthEmail,
  restoreClaudeAuthFromProfile,
  snapshotLiveAuthToProfile,
} from "./claude-auth.js";
import { withApplyLock } from "./apply-lock.js";

function singleMatch(profiles: Profile[]): Profile | undefined {
  return profiles.length === 1 ? profiles[0] : undefined;
}

/**
 * The `applied` pointer (which profile's Claude auth is currently restored to
 * the live default paths) is genuinely machine-local: it tracks on-disk auth on
 * THIS machine, so it lives in the local JSON store — never in the shared
 * registry. In api mode the profile record itself lives in the cloud, so this
 * best-effort lookup only resolves a full record when the profile is also known
 * locally; callers that just need the name read `loadStore().applied` directly.
 */
export function appliedProfile(toolId: string): Profile | undefined {
  const store = loadStore();
  const name = store.applied[toolId];
  if (!name) return undefined;
  return store.profiles.find((p) => p.name === name && p.tool === toolId);
}

/**
 * Apply a profile's auth to the tool's live default paths (IDE-friendly).
 * Snapshots the previously applied profile's auth before switching.
 *
 * The profile record and the shared "current" selection are read/written
 * through the Store (cloud in api mode, local JSON otherwise). Only the on-disk
 * Claude auth work and the machine-local `applied` pointer touch local files,
 * guarded by the cross-process apply lock.
 */
export async function applyProfile(
  name: string,
  toolId?: string,
  store: AccountsStore = resolveStore(),
): Promise<{ profile: Profile; previous?: string }> {
  const profile = await store.getProfile(name, toolId);
  const tool = getTool(profile.tool);

  if (tool.id !== "claude") {
    throw new AccountsError(
      `apply is only supported for Claude Code today (tool "${tool.id}"). Use \`accounts launch ${name}\` for isolated switching.`,
    );
  }

  // The owner-detection heuristic needs the registry's view of this tool's
  // profiles; fetch it via the Store before taking the (synchronous) lock so no
  // async work happens while the lock file is held.
  const toolProfiles = await store.listProfiles(tool.id);
  const result = withApplyLock(() => applyProfileAuth(profile, tool, toolProfiles));
  await store.useProfile(profile.name, tool.id);
  return result;
}

/** Synchronous, machine-local disk work for apply (runs under the apply lock). */
function applyProfileAuth(
  profile: Profile,
  tool: ToolDef,
  toolProfiles: Profile[],
): { profile: Profile; previous?: string } {
  assertRestorableProfileAuth(profile.dir, tool, profile.name);

  const local = loadStore();
  const previous = local.applied[tool.id];

  // Preserve whatever auth is currently live by snapshotting it into the
  // profile that actually owns it. The live OAuth email is the source of
  // truth — the applied pointer goes stale when the user logs in directly
  // on the live paths (e.g. `claude /login`), and trusting it would clobber
  // another profile's snapshot with the wrong account's tokens.
  const liveEmail = liveOAuthEmail();
  const owner =
    (liveEmail && singleMatch(toolProfiles.filter((p) => p.email === liveEmail))) ||
    (previous ? toolProfiles.find((p) => p.name === previous) : undefined);
  if (
    owner &&
    (!(owner.name === profile.name && owner.tool === profile.tool) ||
      liveCredentialShouldUpdateProfile(profile.dir))
  ) {
    snapshotLiveAuthToProfile(owner.dir, tool);
  }

  ensureProfileAuthSnapshot(profile.dir, tool);
  restoreClaudeAuthFromProfile(profile.dir, tool, profile.name);

  local.applied[tool.id] = profile.name;
  saveStore(local);

  return { profile, ...(previous && previous !== profile.name ? { previous } : {}) };
}
