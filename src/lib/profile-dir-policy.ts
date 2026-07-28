// Where a profile config dir is allowed to live.
//
// WHY THIS EXISTS: the cloud registry accepted any string as `dir`. Test
// harnesses and investigating agents that call `accounts add` with the ambient
// fleet API key therefore wrote throwaway `/tmp` paths straight into the
// production registry — 16 such rows accumulated, 6 of them in a single day,
// one pointing at an agent's own scratchpad. Harness isolation only binds
// `bun test`; it cannot bind a CLI call, so the boundary has to be in the
// registry write path itself.
//
// THE RULE: a registrable dir is an absolute, traversal-free path under a home
// root, whose first home-relative segment is a dot-directory. That is not an
// arbitrary allowlist — it is the convention every built-in tool already
// follows (`src/lib/tools.ts` defines every defaultDir as `homedir()/.<name>`)
// plus the managed profiles root `~/.hasna/accounts/profiles`. Ephemeral roots
// are refused first and unconditionally, so widening the home roots can never
// re-admit a temp path.

import { posix } from "node:path";
import { AccountsError } from "../types.js";

export type ProfileDirRejectionCode =
  | "not-absolute"
  | "invalid-characters"
  | "ephemeral-root"
  | "not-home-anchored"
  | "outside-profile-roots";

export interface ProfileDirRejection {
  code: ProfileDirRejectionCode;
  message: string;
}

export type ProfileDirVerdict = { ok: true } | { ok: false; reason: ProfileDirRejection };

export interface ProfileDirPolicy {
  /** Path prefixes that contain per-user home directories. */
  homeRoots: string[];
  /** Roots whose contents do not survive a reboot; never registrable. */
  ephemeralRoots: string[];
}

/** Env var operators set to widen `homeRoots` on machines with other layouts. */
export const PROFILE_DIR_ROOTS_ENV = "HASNA_ACCOUNTS_PROFILE_DIR_ROOTS";

export const defaultProfileDirPolicy: ProfileDirPolicy = Object.freeze({
  // Linux and macOS home roots. Everything the registry has ever legitimately
  // held sits under one of these two.
  homeRoots: Object.freeze(["/home", "/Users"]) as unknown as string[],
  // Temp and runtime roots on Linux and macOS, including the macOS private/
  // aliases that `/tmp` and `/var/folders` resolve through.
  ephemeralRoots: Object.freeze([
    "/tmp",
    "/var/tmp",
    "/var/folders",
    "/private/tmp",
    "/private/var/tmp",
    "/private/var/folders",
    "/dev/shm",
    "/run",
  ]) as unknown as string[],
});

function hasControlCharacters(value: string): boolean {
  return [...value].some((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });
}

function isUnder(path: string, root: string): boolean {
  return path === root || path.startsWith(root.endsWith("/") ? root : `${root}/`);
}

/** Read the policy from the environment, falling back to the defaults. */
export function resolveProfileDirPolicy(
  env: NodeJS.ProcessEnv = process.env,
): ProfileDirPolicy {
  const raw = env[PROFILE_DIR_ROOTS_ENV];
  if (raw === undefined || raw.trim() === "") return defaultProfileDirPolicy;

  const homeRoots: string[] = [];
  for (const entry of raw.split(":")) {
    const trimmed = entry.trim();
    if (trimmed === "") continue;
    if (!posix.isAbsolute(trimmed)) {
      throw new AccountsError(
        `${PROFILE_DIR_ROOTS_ENV} entries must be absolute paths; got "${trimmed}"`,
      );
    }
    const normalized = posix.normalize(trimmed).replace(/\/+$/, "") || "/";
    if (!homeRoots.includes(normalized)) homeRoots.push(normalized);
  }
  if (homeRoots.length === 0) return defaultProfileDirPolicy;
  return { homeRoots, ephemeralRoots: defaultProfileDirPolicy.ephemeralRoots };
}

/**
 * Decide whether `dir` may be recorded as a profile config dir.
 *
 * Pure and filesystem-free on purpose: the cloud service validates dirs that
 * belong to other machines, so it must never stat or resolve them locally.
 */
export function classifyProfileDir(
  dir: string,
  policy: ProfileDirPolicy = resolveProfileDirPolicy(),
): ProfileDirVerdict {
  const reject = (code: ProfileDirRejectionCode, message: string): ProfileDirVerdict => ({
    ok: false,
    reason: { code, message },
  });

  if (hasControlCharacters(dir)) {
    return reject("invalid-characters", "dir contains control characters");
  }
  if (!posix.isAbsolute(dir)) {
    return reject("not-absolute", `profile dir must be an absolute path: ${dir}`);
  }

  // Normalise before every path decision so `..` cannot smuggle a path out of
  // an allowed root — `/home/u/.claude/../../../tmp/x` collapses to `/tmp/x`
  // and is then caught by the ephemeral check below.
  const normalized = posix.normalize(dir).replace(/(?!^)\/+$/, "");

  for (const root of policy.ephemeralRoots) {
    if (isUnder(normalized, root)) {
      return reject(
        "ephemeral-root",
        `refusing to register a profile dir under the ephemeral root ${root}: ${dir}`,
      );
    }
  }

  const home = policy.homeRoots.find((root) => isUnder(normalized, root));
  const rest = home ? normalized.slice(home.length).split("/").filter(Boolean) : [];
  // rest[0] is the user directory; rest[1] is the tool home under it.
  if (!home || rest.length < 2) {
    return reject(
      "not-home-anchored",
      `profile dir must live under a home root (${policy.homeRoots.join(", ")}): ${dir}. ` +
        `Set ${PROFILE_DIR_ROOTS_ENV} if this machine uses a different home layout.`,
    );
  }

  if (!rest[1]!.startsWith(".")) {
    return reject(
      "outside-profile-roots",
      `profile dir must sit in a tool home directory such as ~/.hasna/accounts/profiles ` +
        `or ~/.claude, not ${dir}. ` +
        `Set ${PROFILE_DIR_ROOTS_ENV} if this machine uses a different home layout.`,
    );
  }

  return { ok: true };
}

/** Throwing form of {@link classifyProfileDir}, for use at registry write sites. */
export function assertRegistrableProfileDir(
  dir: string,
  policy: ProfileDirPolicy = resolveProfileDirPolicy(),
): void {
  const verdict = classifyProfileDir(dir, policy);
  if (!verdict.ok) throw new AccountsError(verdict.reason.message);
}
