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
// THE RULE: a registrable profile dir is an absolute, traversal-free path under
// a home root that sits inside a known profile root. The profile roots are the
// managed profiles root plus every built-in tool home, DERIVED from the tool
// table rather than enumerated, so the two cannot desync.
//
// It is an ALLOWLIST — the default answer is refuse. An earlier version asked
// only whether the first home-relative segment was a dot-directory, which
// admitted `~/.hasna/repos/worktrees/...`, `~/.hasna/projects/workspaces/.../
// scratchpad/...` and `~/.cache/...`. Those are not incidental: the global
// rules REQUIRE agents to work in `$HOME/.hasna/repos/worktrees/<repo>/<name>`,
// so the shape heuristic left the hole open on exactly the class of path every
// agent uses, one level in from the one it closed. The real leak lever was
// never an explicit `--dir` — it was an `ACCOUNTS_HOME` override feeding
// `profilesDir()`, which is why the allowlist is pinned to the DEFAULT accounts
// home and not the live one.
//
// Ephemeral roots are refused first and unconditionally, so widening the home
// roots can never re-admit a temp path.

import { homedir } from "node:os";
import { posix, relative, sep } from "node:path";
import { AccountsError } from "../types.js";
import { BUILTIN_TOOLS } from "./builtin-tools.js";

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
  /** Home-relative directories a profile may live in. Allowlist: default is refuse. */
  profileRoots: string[];
}

/**
 * The managed profiles root, home-relative.
 *
 * Deliberately the DEFAULT location (`accountsHome()` with no override) rather
 * than the live `profilesDir()`. `ACCOUNTS_HOME` is exactly the lever that
 * produced the leaked rows: point it at a scratch directory and every profile
 * created under it inherits that path. Deriving the allowlist from the live
 * value would therefore let the thing being validated choose its own validator.
 */
export const DEFAULT_MANAGED_PROFILES_ROOT = ".hasna/accounts/profiles";

/**
 * Home-relative tool home directories, derived from the built-in tool table
 * (`src/lib/builtin-tools.ts`) rather than enumerated here — same provenance as
 * the rest of the policy, so adding a tool cannot silently desync the two.
 *
 * Note these are genuine PREFIXES: `.codewith` admits `.codewith/auth_profiles`,
 * which holds 23 of the registry's live rows. Depth varies (`.config/opencode`
 * is two segments), which is why the rule cannot be "first segment is a dot-dir"
 * — that older shape admitted `.hasna/repos/worktrees/...`, i.e. precisely the
 * directories the global rules require agents to work in.
 */
export function builtinToolHomeRoots(home: string = homedir()): string[] {
  const roots = new Set<string>();
  for (const tool of BUILTIN_TOOLS) {
    if (!tool.defaultDir) continue;
    const rel = relative(home, tool.defaultDir);
    if (!rel || rel.startsWith("..") || posix.isAbsolute(rel)) continue;
    roots.add(rel.split(sep).join("/"));
  }
  return [...roots].sort();
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
  profileRoots: Object.freeze([
    DEFAULT_MANAGED_PROFILES_ROOT,
    ...builtinToolHomeRoots(),
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
  return {
    homeRoots,
    ephemeralRoots: defaultProfileDirPolicy.ephemeralRoots,
    profileRoots: defaultProfileDirPolicy.profileRoots,
  };
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
  return classify(dir, policy, { requireProfileRoot: true, label: "profile dir" });
}

/**
 * Decide whether `dir` may be recorded as a custom tool's `defaultDir`.
 *
 * Same primitives as {@link classifyProfileDir} — absolute, traversal-free, not
 * ephemeral, home-anchored — but deliberately WITHOUT the profile-root
 * allowlist. A custom tool exists precisely to introduce a config directory the
 * built-in table does not know (see the header of src/lib/builtin-tools.ts), so
 * constraining tool homes to the known roots would defeat the feature. What it
 * must not be is `/tmp/evil`, `/dev/shm/x`, or a bare relative string — and
 * those this refuses. The value matters because it is consumed AS a profile dir
 * (src/lib/agents.ts, src/lib/switch-account.ts).
 */
export function classifyToolHomeDir(
  dir: string,
  policy: ProfileDirPolicy = resolveProfileDirPolicy(),
): ProfileDirVerdict {
  return classify(dir, policy, { requireProfileRoot: false, label: "tool defaultDir" });
}

function classify(
  dir: string,
  policy: ProfileDirPolicy,
  opts: { requireProfileRoot: boolean; label: string },
): ProfileDirVerdict {
  const reject = (code: ProfileDirRejectionCode, message: string): ProfileDirVerdict => ({
    ok: false,
    reason: { code, message },
  });

  // Guard non-string input explicitly: a bare `.includes` on a number throws a
  // raw TypeError out of a validator, which surfaces as a 500 rather than a 400.
  if (typeof dir !== "string") {
    return reject("invalid-characters", `${opts.label} must be a string`);
  }
  if (hasControlCharacters(dir)) {
    return reject("invalid-characters", `${opts.label} contains control characters`);
  }
  if (!posix.isAbsolute(dir)) {
    return reject("not-absolute", `${opts.label} must be an absolute path: ${dir}`);
  }

  // Normalise before every path decision so `..` cannot smuggle a path out of
  // an allowed root — `/home/u/.claude/../../../tmp/x` collapses to `/tmp/x`
  // and is then caught by the ephemeral check below.
  const normalized = posix.normalize(dir).replace(/(?!^)\/+$/, "");

  for (const root of policy.ephemeralRoots) {
    if (isUnder(normalized, root)) {
      return reject(
        "ephemeral-root",
        `refusing to register a ${opts.label} under the ephemeral root ${root}: ${dir}`,
      );
    }
  }

  const home = policy.homeRoots.find((root) => isUnder(normalized, root));
  const rest = home ? normalized.slice(home.length).split("/").filter(Boolean) : [];
  // rest[0] is the user directory; rest[1] is the tool home under it.
  if (!home || rest.length < 2) {
    return reject(
      "not-home-anchored",
      `${opts.label} must live under a home root (${policy.homeRoots.join(", ")}): ${dir}. ` +
        `Set ${PROFILE_DIR_ROOTS_ENV} if this machine uses a different home layout.`,
    );
  }

  // Allowlist, not a shape heuristic: anything not under a known profile root is
  // refused by default. This is what keeps agent worktrees
  // (~/.hasna/repos/worktrees/...), agent scratchpads
  // (~/.hasna/projects/workspaces/.../scratchpad/...) and caches (~/.cache/...)
  // out — they sit beside the managed profiles root, not inside it.
  if (!opts.requireProfileRoot) return { ok: true };

  const afterUser = rest.slice(1).join("/");
  const inProfileRoot = policy.profileRoots.some(
    (root) => afterUser === root || afterUser.startsWith(`${root}/`),
  );
  if (!inProfileRoot) {
    return reject(
      "outside-profile-roots",
      `profile dir must sit in a known profile root (${policy.profileRoots.join(", ")}), ` +
        `not ${dir}. Agent worktrees, scratchpads and caches are not profile roots.`,
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
