import type { Profile, ToolDef } from "../types.js";
import { randomUUID } from "node:crypto";
import { AccountsError } from "../types.js";
import { loadAppliedMap, loadMachineStore, loadStore, saveStore, withStoreLock } from "../storage.js";
import { getTool } from "./tools.js";
import { resolveStore, type AccountsStore } from "./store.js";
import {
  assertRestorableProfileAuth,
  captureClaudeLiveAuthSnapshot,
  captureClaudeProfileAuthSnapshot,
  ensureProfileAuthSnapshot,
  liveCredentialShouldUpdateProfile,
  liveOAuthEmail,
  restoreClaudeAuthFromProfile,
  restoreClaudeLiveAuthSnapshot,
  restoreClaudeProfileAuthSnapshot,
  snapshotLiveAuthToProfile,
  type ClaudeLiveAuthSnapshot,
  type ClaudeProfileAuthSnapshot,
} from "./claude-auth.js";
import { withApplyLock, withApplyLockWait } from "./apply-lock.js";
import { acquireClaudeKeychainLock } from "./claude-launch.js";
import {
  captureClaudeKeychain,
  keychainSupported,
  restoreClaudeKeychain,
  type KeychainCredential,
} from "./keychain.js";

interface ApplyRollbackState {
  liveClaude: ClaudeLiveAuthSnapshot;
  applied?: { name: string; revision?: string };
  profileAuthSnapshots: ClaudeProfileAuthSnapshot[];
}

export interface ApplyTransactionTracker {
  applyStarted?: boolean;
  appliedRevision?: string;
  currentRevision?: string;
  currentOperationId?: string;
  currentPreviousName?: string;
  currentPreviousProfileLastUsedAt?: string;
  profileAuthSnapshots?: ClaudeProfileAuthSnapshot[];
  applyRollback?: ApplyRollbackState;
  keychainLeaseHeld?: boolean;
}

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

export function appliedProfileName(toolId: string): string | undefined {
  return loadAppliedMap()[toolId];
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
  tracker?: ApplyTransactionTracker,
): Promise<{ profile: Profile; previous?: string; appliedRevision: string; currentRevision?: string }> {
  if (!store.useProfileForLogin || !store.restoreCurrentOperation) {
    throw new AccountsError(
      "the configured Accounts store does not support transactional apply activation and rollback; " +
      "upgrade the custom store before running accounts apply",
    );
  }
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
  let releaseKeychainLease: (() => void) | undefined;
  if (keychainSupported() && !tracker?.keychainLeaseHeld) {
    releaseKeychainLease = await acquireClaudeKeychainLock();
  }
  let keychainBefore: KeychainCredential | undefined;
  let result: ReturnType<typeof applyProfileAuth> | undefined;
  try {
    keychainBefore = keychainSupported() ? captureClaudeKeychain() : undefined;
    try {
      result = withApplyLock(() => {
        if (tracker) tracker.applyStarted = true;
        return applyProfileAuth(profile, tool, toolProfiles, tracker);
      });
    } catch (error) {
      restoreKeychainAfterFailure(keychainBefore, error);
    }
    if (tracker) tracker.appliedRevision = result.appliedRevision;
    const operationId = randomUUID();
    if (tracker) tracker.currentOperationId = operationId;
    let active;
    try {
      active = await store.useProfileForLogin(profile.name, tool.id, operationId);
    } catch (error) {
      if (tracker) throw error;
      await rollbackAppliedState(
        result.rollback,
        profile.name,
        result.appliedRevision,
        keychainBefore,
        () => store.restoreCurrentOperation!(tool.id, profile.name, operationId),
        error,
      );
    }
    if (!active) throw new AccountsError("apply activation ended without a committed result");
    if (tracker) tracker.currentRevision = active.currentRevision;
    if (tracker) tracker.currentPreviousName = active.previousCurrentName;
    if (tracker) tracker.currentPreviousProfileLastUsedAt = active.previousProfileLastUsedAt;
    return { ...result, profile: active.profile, currentRevision: active.currentRevision };
  } finally {
    releaseKeychainLease?.();
  }
}

function restoreKeychainAfterFailure(previous: KeychainCredential | undefined, original: unknown): never {
  if (!keychainSupported()) throw original;
  try {
    restoreClaudeKeychain(previous);
  } catch {
    const message = original instanceof Error ? original.message : String(original);
    throw new AccountsError(`${message}; failed to restore the prior Claude keychain state`);
  }
  throw original;
}

async function rollbackAppliedState(
  rollback: ApplyRollbackState,
  expectedName: string,
  expectedRevision: string,
  keychainBefore: KeychainCredential | undefined,
  restoreCurrent: () => Promise<boolean>,
  original: unknown,
): Promise<never> {
  let rollbackFailed = false;
  try {
    await restoreCurrent();
  } catch {
    rollbackFailed = true;
  }
  try {
    await withApplyLockWait(() => withStoreLock(() => {
      const local = loadMachineStore();
      if (local.applied.claude !== expectedName || local.appliedRevisions.claude !== expectedRevision) return;
      for (const snapshot of [...rollback.profileAuthSnapshots].reverse()) {
        restoreClaudeProfileAuthSnapshot(snapshot);
      }
      restoreClaudeLiveAuthSnapshot(rollback.liveClaude);
      if (rollback.applied) {
        local.applied.claude = rollback.applied.name;
        local.appliedRevisions.claude = randomUUID();
      } else {
        delete local.applied.claude;
        delete local.appliedRevisions.claude;
      }
      saveStore(local);
    }));
  } catch {
    rollbackFailed = true;
  }
  try {
    if (keychainSupported()) restoreClaudeKeychain(keychainBefore);
  } catch {
    rollbackFailed = true;
  }
  if (rollbackFailed) {
    const message = original instanceof Error ? original.message : String(original);
    throw new AccountsError(`${message}; failed to roll back the interrupted apply transaction`);
  }
  throw original;
}

/** Synchronous, machine-local disk work for apply (runs under the apply lock). */
function applyProfileAuth(
  profile: Profile,
  tool: ToolDef,
  toolProfiles: Profile[],
  tracker?: ApplyTransactionTracker,
): { profile: Profile; previous?: string; appliedRevision: string; rollback: ApplyRollbackState } {
  assertRestorableProfileAuth(profile.dir, tool, profile.name);
  return withStoreLock(() => {
    const local = loadMachineStore();
    const previous = local.applied[tool.id];
    const rollback: ApplyRollbackState = {
      liveClaude: captureClaudeLiveAuthSnapshot(),
      ...(previous
        ? { applied: { name: previous, ...(local.appliedRevisions[tool.id] ? { revision: local.appliedRevisions[tool.id] } : {}) } }
        : {}),
      profileAuthSnapshots: [captureClaudeProfileAuthSnapshot(profile.dir)],
    };
    if (tracker) tracker.applyRollback = rollback;

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
      if (tracker && !tracker.profileAuthSnapshots?.some((snapshot) => snapshot.base === owner.dir)) {
        (tracker.profileAuthSnapshots ??= []).push(captureClaudeProfileAuthSnapshot(owner.dir));
      }
      if (!rollback.profileAuthSnapshots.some((snapshot) => snapshot.base === owner.dir)) {
        rollback.profileAuthSnapshots.push(captureClaudeProfileAuthSnapshot(owner.dir));
      }
      try {
        snapshotLiveAuthToProfile(owner.dir, tool);
      } catch (error) {
        for (const snapshot of [...rollback.profileAuthSnapshots].reverse()) restoreClaudeProfileAuthSnapshot(snapshot);
        restoreClaudeLiveAuthSnapshot(rollback.liveClaude);
        throw error;
      }
    }
    try {
      ensureProfileAuthSnapshot(profile.dir, tool);
      restoreClaudeAuthFromProfile(profile.dir, tool, profile.name);

      local.applied[tool.id] = profile.name;
      const appliedRevision = randomUUID();
      local.appliedRevisions[tool.id] = appliedRevision;
      saveStore(local);

      return { profile, appliedRevision, rollback, ...(previous && previous !== profile.name ? { previous } : {}) };
    } catch (error) {
      for (const snapshot of [...rollback.profileAuthSnapshots].reverse()) restoreClaudeProfileAuthSnapshot(snapshot);
      restoreClaudeLiveAuthSnapshot(rollback.liveClaude);
      throw error;
    }
  });
}
