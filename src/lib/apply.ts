import type { Profile } from "../types.js";
import { AccountsError } from "../types.js";
import { loadStore, saveStore } from "../storage.js";
import { getTool } from "./tools.js";
import { getProfile, useProfile } from "./profiles.js";
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

export function appliedProfile(toolId: string): Profile | undefined {
  const store = loadStore();
  const name = store.applied[toolId];
  if (!name) return undefined;
  return store.profiles.find((p) => p.name === name && p.tool === toolId);
}

/**
 * Apply a profile's auth to the tool's live default paths (IDE-friendly).
 * Snapshots the previously applied profile's auth before switching.
 */
export function applyProfile(name: string, toolId?: string): { profile: Profile; previous?: string } {
  return withApplyLock(() => applyProfileUnlocked(name, toolId));
}

function applyProfileUnlocked(name: string, toolId?: string): { profile: Profile; previous?: string } {
  const profile = getProfile(name, toolId);
  const tool = getTool(profile.tool);

  if (tool.id !== "claude") {
    throw new AccountsError(
      `apply is only supported for Claude Code today (tool "${tool.id}"). Use \`accounts launch ${name}\` for isolated switching.`,
    );
  }

  assertRestorableProfileAuth(profile.dir, tool, name);

  const store = loadStore();
  const previous = store.applied[tool.id];

  // Preserve whatever auth is currently live by snapshotting it into the
  // profile that actually owns it. The live OAuth email is the source of
  // truth — the applied pointer goes stale when the user logs in directly
  // on the live paths (e.g. `claude /login`), and trusting it would clobber
  // another profile's snapshot with the wrong account's tokens.
  const liveEmail = liveOAuthEmail();
  const owner =
    (liveEmail &&
      singleMatch(store.profiles.filter((p) => p.tool === tool.id && p.email === liveEmail))) ||
    (previous ? store.profiles.find((p) => p.name === previous && p.tool === tool.id) : undefined);
  if (
    owner &&
    (!(owner.name === profile.name && owner.tool === profile.tool) ||
      liveCredentialShouldUpdateProfile(profile.dir))
  ) {
    snapshotLiveAuthToProfile(owner.dir, tool);
  }

  ensureProfileAuthSnapshot(profile.dir, tool);
  restoreClaudeAuthFromProfile(profile.dir, tool, name);

  store.applied[tool.id] = name;
  saveStore(store);
  useProfile(name, tool.id);

  return { profile, ...(previous && previous !== name ? { previous } : {}) };
}
