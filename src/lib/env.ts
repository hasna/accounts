import type { Profile, ToolDef } from "../types.js";
import { AccountsError } from "../types.js";
import {
  CLAUDE_API_AUTH_ENV_KEYS,
  healSwitchedProfileDir,
  recoverParkedCredential,
  sanitizeClaudeProfileApiSettings,
} from "./claude-auth.js";
import { convergeDirCredential } from "./credential-broker.js";
import { ensureCodexAppProfileConfig } from "./codex-app.js";
import { storageEnvKeys } from "../generated/storage-kit/mode.js";
import { redactText } from "./redaction.js";
import { assertProfileGuarded, ensureSharedCapabilities } from "./shared-capabilities.js";
import { ensureSharedClaudeSessions } from "./claude-session-registry.js";

/**
 * Runtime request diagnostics that can print provider request headers or
 * credential-bearing payloads. These are intentionally narrow: provider
 * launches keep the caller's PATH, proxy, TLS, Bedrock, Vertex, and cloud SDK
 * environment because they remain inside the caller's existing trust binding.
 */
export const UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS = [
  "BUN_CONFIG_VERBOSE_FETCH",
  "NODE_DEBUG",
  "NODE_DEBUG_NATIVE",
] as const;

const UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEY_SET = new Set(
  UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS.map((name) => name.toLowerCase()),
);

/**
 * Authority over the accounts REGISTRY itself. `accounts` is the trusted wrapper and
 * legitimately holds these in order to resolve a profile name to a config dir; the
 * tool binary it launches is a coding agent running against an arbitrary,
 * potentially prompt-injectable repository, and it needs the config dir and nothing
 * else. So these stop at the spawn boundary.
 *
 * ENUMERATED, NOT PREFIX-MATCHED, and that is the whole point. A
 * `startsWith("HASNA_ACCOUNTS")` scan reads as equivalent and is not: this package
 * accepts unprefixed and differently-prefixed aliases for the same authority, and a
 * prefix scan leaks every one of them. Each entry below cites the consumer that
 * reads it, so the list can be re-derived rather than trusted:
 *
 *   HASNA_ACCOUNTS_API_KEY, ACCOUNTS_API_KEY
 *     -> lib/cloud-accounts.ts deriveEnv(). Bearer credential for the registry /v1
 *        API, and it is NOT read-only: list/create/update/rename/delete any profile
 *        fleet-wide. ACCOUNTS_API_KEY is a full alias and has no HASNA_ prefix.
 *   HASNA_ACCOUNTS_API_URL, ACCOUNTS_API_URL
 *     -> lib/cloud-accounts.ts deriveEnv(). Not itself secret; denied so the child
 *        cannot address the registry at all.
 *   HASNA_ACCOUNTS_API_SIGNING_KEY, HASNA_API_SIGNING_KEY
 *     -> server/config.ts resolveSigningSecret(). The HMAC secret that MINTS api
 *        keys — strictly more powerful than the bearer token above. Note the
 *        fallback's prefix is HASNA_, not HASNA_ACCOUNTS_.
 *   HASNA_ACCOUNTS_DATABASE_URL, ACCOUNTS_DATABASE_URL
 *     -> NOT hand-listed. Taken from storageEnvKeys("accounts").databaseUrlKeys in
 *        src/generated/storage-kit/mode.ts, which is the same spec
 *        resolveDatabaseUrl()/createCloudPoolFromEnv() consult for server/app.ts
 *        and server/migrate.ts. A direct DSN carries its own password and is
 *        unscoped SQL access to the whole registry — strictly worse than the
 *        bearer token, which is at least bound to the /v1 API's own authz.
 *
 *        DERIVED RATHER THAN COPIED because copying it is what went wrong: the
 *        first version of this list hand-wrote only the HASNA_-prefixed form and
 *        silently leaked the bare `ACCOUNTS_DATABASE_URL` alias, which the kit
 *        generates as `${token}_DATABASE_URL` and reads with equal authority.
 *        That is the very failure this comment warns about, committed inside the
 *        fix for it. Deriving from the resolver's own spec means the deny list
 *        cannot drift from what the resolver accepts.
 *
 * DELIBERATELY NOT DENIED: the storage-MODE keys — including the bare
 * `ACCOUNTS_STORAGE_MODE` alias from that same spec. When a mode is explicitly
 * `cloud`/`self_hosted`, deriveEnv() THROWS on the now-absent key rather than
 * silently reading a different store — a loud failure is the one we want, and
 * stripping the mode would convert it into a silent fallback to a local registry.
 * Also not denied: PATH, proxy, TLS, Bedrock/Vertex and cloud-SDK environment,
 * which this module's existing policy keeps inside the caller's trust binding.
 */
export const REGISTRY_AUTHORITY_ENV_KEYS: readonly string[] = [
  "HASNA_ACCOUNTS_API_KEY",
  "ACCOUNTS_API_KEY",
  "HASNA_ACCOUNTS_API_URL",
  "ACCOUNTS_API_URL",
  "HASNA_ACCOUNTS_API_SIGNING_KEY",
  "HASNA_API_SIGNING_KEY",
  ...storageEnvKeys("accounts").databaseUrlKeys,
];

const REGISTRY_AUTHORITY_ENV_KEY_SET = new Set(
  REGISTRY_AUTHORITY_ENV_KEYS.map((name) => name.toLowerCase()),
);
const PORTABLE_ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isUnsafeProviderRequestDebugEnvKey(name: string): boolean {
  return UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEY_SET.has(name.toLowerCase());
}

function removeUnsafeProviderRequestDebugEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  for (const name of Object.keys(env)) {
    if (isUnsafeProviderRequestDebugEnvKey(name)) delete env[name];
  }
  return env;
}

function requestDebugUnsetKeys(parentEnv: NodeJS.ProcessEnv = process.env): string[] {
  const keys: string[] = [...UNSAFE_PROVIDER_REQUEST_DEBUG_ENV_KEYS];
  for (const name of Object.keys(parentEnv)) {
    if (isUnsafeProviderRequestDebugEnvKey(name) && !keys.includes(name)) keys.push(name);
  }
  return keys;
}

function assertPortableEnvName(name: string): void {
  if (!PORTABLE_ENV_NAME_PATTERN.test(name)) {
    throw new AccountsError(`invalid environment variable name "${name}" for POSIX shell handoff`);
  }
}

/**
 * Serialize one POSIX shell word without expansion. Single quotes preserve
 * spaces, newlines, backslashes, dollars, backticks, and leading hyphens; the
 * close/quoted-quote/reopen sequence handles embedded single quotes.
 */
export function quotePosixShellWord(value: string): string {
  if (value.includes("\0")) {
    throw new AccountsError("POSIX shell handoffs cannot represent NUL bytes");
  }
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function shellEnvEntries(env: Record<string, string>): Array<[string, string]> {
  return Object.entries(env).map(([name, value]) => {
    assertPortableEnvName(name);
    return [name, value];
  });
}

function renderTemplate(value: string, profile: Profile): string {
  return value.replaceAll("{profileDir}", profile.dir).replaceAll("{profileName}", profile.name).replaceAll("{toolId}", profile.tool);
}

function removeRegistryAuthorityEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  for (const name of Object.keys(env)) {
    if (REGISTRY_AUTHORITY_ENV_KEY_SET.has(name.toLowerCase())) delete env[name];
  }
  return env;
}

/**
 * Assemble the final environment at the credential-bearing provider boundary.
 * Scrubbing after every overlay prevents a custom tool setting from re-enabling
 * a dangerous inherited diagnostic, including on case-insensitive platforms.
 *
 * DENIES ACCOUNTS-REGISTRY AUTHORITY BY DEFAULT (todos 03dd035d). Every caller of
 * this function spawns either the tool binary itself or a bounded helper, and none
 * of them needs authority over the registry that decides which identity the tool
 * runs as. Default-deny here rather than at the call sites, so a spawn site added
 * later is contained without anyone remembering to contain it; the single context
 * that legitimately keeps this authority opts out explicitly and by name below.
 */
export function providerLaunchEnv(
  parentEnv: NodeJS.ProcessEnv,
  ...overlays: Array<NodeJS.ProcessEnv | Record<string, string>>
): NodeJS.ProcessEnv {
  return removeRegistryAuthorityEnv(
    removeUnsafeProviderRequestDebugEnv(Object.assign({}, parentEnv, ...overlays)),
  );
}

/**
 * The one sanctioned exception to the registry-authority denial: `accounts shell`,
 * which spawns the OPERATOR'S OWN interactive shell rather than an untrusted tool
 * binary.
 *
 * Why this is an exception and not a hole. The operator already holds these
 * credentials in the shell they typed the command into, and still holds them after
 * they type `exit`; accounts removing them in between prevents nothing that the
 * operator could not trivially do anyway, while breaking the ordinary case of
 * running an `accounts` command inside the subshell — which, with the API key
 * absent but a storage mode set, fails loudly, and with no mode set silently reads
 * a DIFFERENT local registry. A control the constrained party can bypass in one
 * command, whose cost is a silent wrong-store read, is not containment.
 *
 * The real boundary is the one `accounts launch` / `accounts run` cross: there
 * accounts execs an untrusted binary directly, and that binary has no route to the
 * credential except the one accounts hands it. That route is closed.
 */
export function operatorShellEnv(
  parentEnv: NodeJS.ProcessEnv,
  ...overlays: Array<NodeJS.ProcessEnv | Record<string, string>>
): NodeJS.ProcessEnv {
  return removeUnsafeProviderRequestDebugEnv(Object.assign({}, parentEnv, ...overlays));
}

/** A separately named policy for bounded helper processes that capture output. */
export function controlledProbeEnv(
  parentEnv: NodeJS.ProcessEnv = process.env,
  ...overlays: Array<NodeJS.ProcessEnv | Record<string, string>>
): NodeJS.ProcessEnv {
  return providerLaunchEnv(parentEnv, ...overlays);
}

export async function profileEnv(profile: Profile, tool: ToolDef): Promise<Record<string, string>> {
  const env: Record<string, string> = {
    [tool.envVar]: profile.dir,
  };
  for (const [name, value] of Object.entries(tool.extraEnv ?? {})) {
    env[name] = renderTemplate(value, profile);
  }
  // Every launch surface goes through here, so profiles created before shared
  // capabilities existed are repaired the next time they are used.
  ensureSharedCapabilities(profile.dir, tool);
  // Same self-heal for the machine-shared session registry: a Claude update
  // that recreates `sessions/` as a real dir is re-linked on the next launch
  // (entries written in between are migrated, not lost).
  if (tool.id === "claude") ensureSharedClaudeSessions(profile.dir);
  // ...and then verified, because "the repair ran" is not "the profile is
  // correct". Seeding is best-effort by design (it must not stop a tool from
  // starting), so without this the failure mode of a failed seed is a profile
  // that launches happily with its guards missing.
  assertProfileGuarded(profile.dir, tool);
  if (tool.id === "claude") {
    // A dir whose own credential was rotated away by another copy of the same
    // account has parked material nothing else reaches — put it back before the
    // launch, so the session starts with a working credential instead of a
    // blank one. Runs BEFORE the switched-away heal because it refuses the
    // identity-changing case outright, leaving that to the function below.
    const recovery = recoverParkedCredential(profile.dir, tool, profile.name);
    // b29f5b6c: the launched session reads an EMPTY (logged-out) root while
    // `login`/`usage` report logged-in. The empty root is Claude Code's own
    // `rotated-away` blank, written in place after a DUPLICATE live copy of this
    // same account rotated the refresh token out. `recoverParkedCredential`
    // above then REFUSES to restore the intact parked copy with
    // `account-live-elsewhere` — because a blind restore of a possibly-superseded
    // PREDECESSOR credential, while the account is live in another dir, would put
    // two DIFFERENT tokens on disk and the next refresh would revoke one
    // (defect bb267228). That refusal is correct for a restore, but it leaves the
    // dir logged-out.
    //
    // The safe heal for a dir that legitimately holds its OWN account is
    // CONVERGENCE, not restore. `convergeDirCredential` is pure file I/O (no
    // token exchange) that fans the CURRENT WINNING credential — the freshest
    // copy across the central store, the profile snapshots, and every live dir,
    // which includes the still-valid copy that is live elsewhere — into every
    // copy, so all dirs end holding the SAME token. It never introduces a second,
    // superseded token, so it cannot cause the double-refresh revocation the
    // restore refusal guards against, and it re-checks each dir's occupant
    // identity (and, since #99, its content binding) at write time.
    //
    // NARROWED TO LEGITIMATE DUPLICATE DOORS ONLY, and this condition is
    // load-bearing rather than defensive. `account-live-elsewhere` covers two
    // shapes that "the account is running somewhere else" does not distinguish:
    // another dir that OWNS this account and is running it, and a dir owned by a
    // DIFFERENT account that is merely carrying this one after an in-place
    // switch. Converging through the second one sources and fans a credential
    // across a custody boundary the squatted dir's real owner never consented
    // to — the class of write the bb267228 gate exists to prevent, which
    // `src/repair-auth-gates.test.ts` ("a blanket launch cannot create the
    // second copy") asserts a launch must not perform.
    //
    // THE GATE MUST RANGE OVER THE SAME DOORS THE WRITE DOES. An earlier form of
    // this check asked whether every door in `accountLiveDoorsElsewhere` owned
    // the account — but that set is filtered to RESTORABLE credentials, while
    // the broker's fan-out targets every `current-occupant` door regardless of
    // state. A guest dir holding a husk therefore sat outside the gate and
    // inside the write set, and was written through while the gate reported no
    // guests present. `noGuestOccupantDoorsElsewhere` is computed over the
    // unfiltered occupant set for exactly that reason, and is consulted with an
    // explicit `=== true` so an absent field can never be read as permission.
    //
    // Best-effort: a launch must never fail on a heal.
    if (recovery.outcome === "account-live-elsewhere" && recovery.noGuestOccupantDoorsElsewhere === true) {
      try {
        await convergeDirCredential(profile.dir, { tool });
      } catch (error) {
        // Best-effort stands: a launch must never fail on a heal. But a
        // refused or failed convergence means this session starts on whatever
        // credential the dir already holds — through 0.2.32 this catch was
        // EMPTY, so the launch path degraded with no trace anywhere (the
        // silent half of bug 2865f9f5). Say so where the operator can see it;
        // stderr is safe for every consumer of this env (launch, `accounts
        // env` command substitution, the supervisor).
        // Redacted on the way out: nicanor's probe found no reachable error
        // message on this path carrying a credential value (synthetic-key
        // check 0 hits against a positive control returning 1), so this is
        // defence-in-depth rather than a known leak — but this is a NEW
        // output surface on the credential-bearing launch path, and the
        // cheapest moment to make it unable to print one is now.
        console.error(
          redactText(
            `accounts: credential convergence for ${profile.dir} failed before launch — ` +
              `${error instanceof Error ? error.message : String(error)}. ` +
              `The session launches on the dir's current credential.`,
          ),
        );
      }
    }
    // A dir left switched to another account by `switch-account` must not
    // launch as that other account: restore the profile's own auth (or refuse
    // loudly while live sessions still use the dir).
    healSwitchedProfileDir(profile.dir, tool, profile.name);
    sanitizeClaudeProfileApiSettings(profile.dir, tool);
    for (const key of CLAUDE_API_AUTH_ENV_KEYS) env[key] = "";
  }
  if (tool.id === "codex-app") ensureCodexAppProfileConfig(profile.dir);
  return removeUnsafeProviderRequestDebugEnv(env) as Record<string, string>;
}

export function claudeApiAuthClearingEnv(): Record<string, string> {
  return Object.fromEntries(CLAUDE_API_AUTH_ENV_KEYS.map((key) => [key, ""]));
}

export function formatEnvAssignments(
  env: Record<string, string>,
  parentEnv: NodeJS.ProcessEnv = process.env,
  additionalUnsetKeys: readonly string[] = [],
): string {
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env }) as Record<string, string>;
  const unsetKeys = requestDebugUnsetKeys(parentEnv);
  for (const name of additionalUnsetKeys) {
    if (!unsetKeys.includes(name)) unsetKeys.push(name);
  }
  const unset = unsetKeys.flatMap((name) => {
    assertPortableEnvName(name);
    return ["-u", name];
  });
  return [
    "env",
    ...unset,
    "--",
    ...shellEnvEntries(sanitized).map(([name, value]) => `${name}=${quotePosixShellWord(value)}`),
  ].join(" ");
}

export function formatExportLines(
  env: Record<string, string>,
  parentEnv: NodeJS.ProcessEnv = process.env,
): string {
  const sanitized = removeUnsafeProviderRequestDebugEnv({ ...env }) as Record<string, string>;
  const unsetKeys = requestDebugUnsetKeys(parentEnv);
  for (const name of unsetKeys) assertPortableEnvName(name);
  return [
    `unset ${unsetKeys.join(" ")}`,
    ...shellEnvEntries(sanitized).map(([name, value]) => `export ${name}=${quotePosixShellWord(value)}`),
  ].join("\n");
}
