import { existsSync } from "node:fs";
import type { Profile, Store, ToolDef } from "../types.js";
import { accountsHome, loadStore, profilesDir, storePath } from "../storage.js";
import { resolveAccountsCloud } from "./cloud-accounts.js";
import { claudeProfileAuthHealth, type ClaudeProfileAuthStatus } from "./claude-auth.js";
import { configsSessionToolFor } from "./configs-prelaunch.js";
import {
  getConfigsPrelaunchSummary,
  type ConfigsPrelaunchStatus,
  type ConfigsPrelaunchSummary,
} from "./configs-prelaunch-status.js";
import { detectToolAvailability } from "./login.js";
import { listSupervisorStates, readSupervisorState, type SupervisorState } from "./supervisor.js";
import { BUILTIN_TOOLS } from "./tools.js";

export type AccountsReadinessStatus = "ok" | "degraded" | "unavailable";

export interface AccountsReadinessCheck {
  id: string;
  label: string;
  status: AccountsReadinessStatus;
  summary: string;
  reasons: string[];
  nextActions: string[];
}

export interface AccountsProfileLoginReadiness {
  status: AccountsReadinessStatus;
  validator: "claude-auth-snapshot" | "local-presence-only" | "unavailable";
  valid: boolean | null;
  authStatus?: ClaudeProfileAuthStatus;
  oauthAccountPresent?: boolean;
  credentialPayloadPresent?: boolean;
  credentialPayloadValid?: boolean;
  credentialPayloadExpired?: boolean;
  credentialExpiresAt?: string;
  keychainSnapshotPresent?: boolean;
  snapshotPresent?: boolean;
  reasons: string[];
  nextActions: string[];
}

export interface AccountsProfileReadiness {
  name: string;
  tool: string;
  status: AccountsReadinessStatus;
  active: boolean;
  applied: boolean;
  emailRecorded: boolean;
  dir: {
    exists: boolean;
  };
  login: AccountsProfileLoginReadiness;
  configs?: {
    supported: boolean;
    required: boolean;
    status: ConfigsPrelaunchStatus;
    reasons: string[];
  };
  reasons: string[];
  nextActions: string[];
}

export interface AccountsProviderReadiness {
  id: string;
  label: string;
  status: AccountsReadinessStatus;
  required: boolean;
  available: boolean;
  bin: string;
  path?: string;
  profileCount: number;
  activeProfile?: string;
  appliedProfile?: string;
  reasons: string[];
  nextActions: string[];
}

export interface AccountsSupervisorReadiness {
  tool: string;
  status: "running" | "stale" | "missing";
  readiness: AccountsReadinessStatus;
  running: boolean;
  profile?: string;
  pid?: number;
  childPid?: number;
  startedAt?: string;
  updatedAt?: string;
  reasons: string[];
  nextActions: string[];
}

export interface AccountsStorageReadiness {
  status: AccountsReadinessStatus;
  /** `local` (on-box JSON registry) or `self_hosted` (cloud HTTP `/v1` API). */
  mode: "local" | "self_hosted";
  /** Store transport in effect: `local` (fs) or `api` (contracts HTTP client). */
  transport: "local" | "api";
  configured: boolean;
  local: {
    home: string;
    storePath: string;
    profilesDir: string;
    storeExists: boolean;
  };
  /** Present only in api mode: the `<url>/v1` base the client reads/writes. */
  api?: {
    baseUrl: string;
  };
  reasons: string[];
  nextActions: string[];
}

export interface AccountsReadiness {
  schema: "hasna.accounts.readiness/v1";
  ok: boolean;
  status: AccountsReadinessStatus;
  generatedAt: string;
  checks: AccountsReadinessCheck[];
  profiles: AccountsProfileReadiness[];
  providers: AccountsProviderReadiness[];
  supervisors: AccountsSupervisorReadiness[];
  storage: AccountsStorageReadiness;
  degradedModes: string[];
  nextActions: string[];
}

export interface AccountsReadinessOptions {
  env?: NodeJS.ProcessEnv;
  now?: Date;
}

function rank(status: AccountsReadinessStatus): number {
  if (status === "unavailable") return 2;
  if (status === "degraded") return 1;
  return 0;
}

function worst(statuses: AccountsReadinessStatus[]): AccountsReadinessStatus {
  return statuses.reduce((current, status) => (rank(status) > rank(current) ? status : current), "ok" as AccountsReadinessStatus);
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function check(
  id: string,
  label: string,
  status: AccountsReadinessStatus,
  summary: string,
  reasons: string[] = [],
  nextActions: string[] = [],
): AccountsReadinessCheck {
  return { id, label, status, summary, reasons: unique(reasons), nextActions: unique(nextActions) };
}

function toolsFromStore(store: Store): ToolDef[] {
  const byId = new Map<string, ToolDef>();
  for (const tool of BUILTIN_TOOLS) byId.set(tool.id, tool);
  for (const tool of store.tools) byId.set(tool.id, tool);
  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function configsStatus(summary: ConfigsPrelaunchSummary | undefined): AccountsReadinessStatus {
  if (!summary || !summary.supported || summary.status === "ok") return "ok";
  if (summary.status === "failed" || summary.status === "invalid" || summary.status === "mismatch") return "unavailable";
  return "degraded";
}

function configsStatusValue(status: ConfigsPrelaunchStatus | undefined, supported: boolean | undefined): AccountsReadinessStatus {
  if (!supported || !status || status === "ok") return "ok";
  if (status === "failed" || status === "invalid" || status === "mismatch") return "unavailable";
  return "degraded";
}

function profileLoginReadiness(profile: Profile, tool: ToolDef | undefined): AccountsProfileLoginReadiness {
  if (!tool) {
    return {
      status: "unavailable",
      validator: "unavailable",
      valid: false,
      reasons: [`unknown tool ${profile.tool}`],
      nextActions: [`Register tool ${profile.tool} again or update profile ${profile.name} to a supported tool.`],
    };
  }

  if (tool.id !== "claude") {
    return {
      status: "degraded",
      validator: "local-presence-only",
      valid: null,
      reasons: [`local auth validation is not available for ${tool.id}`],
      nextActions: [`Run accounts login ${profile.name} --tool ${tool.id} if the provider reports auth errors.`],
    };
  }

  const health = claudeProfileAuthHealth(profile.dir, tool);
  const status: AccountsReadinessStatus =
    health.status === "ok" ? "ok" : health.status === "unknown" ? "degraded" : "unavailable";
  const nextActions =
    status === "ok"
      ? []
      : [`Run accounts login ${profile.name} --tool ${tool.id} to refresh the Claude auth snapshot.`];
  return {
    status,
    validator: "claude-auth-snapshot",
    valid: health.valid,
    authStatus: health.status,
    oauthAccountPresent: health.oauthAccountPresent,
    credentialPayloadPresent: health.credentialPayloadPresent,
    credentialPayloadValid: health.credentialPayloadValid,
    credentialPayloadExpired: health.credentialPayloadExpired,
    ...(health.credentialExpiresAt ? { credentialExpiresAt: health.credentialExpiresAt } : {}),
    keychainSnapshotPresent: health.keychainSnapshotPresent,
    snapshotPresent: health.snapshotPresent,
    reasons: health.reasons,
    nextActions,
  };
}

function profileReadiness(
  profile: Profile,
  tool: ToolDef | undefined,
  store: Store,
  providerStatus: AccountsReadinessStatus,
): AccountsProfileReadiness {
  const dirExists = existsSync(profile.dir);
  const login = profileLoginReadiness(profile, tool);
  const configs = tool ? getConfigsPrelaunchSummary(profile, tool, configsSessionToolFor(tool)) : undefined;
  const reasons: string[] = [];
  const nextActions: string[] = [];
  const statuses: AccountsReadinessStatus[] = [login.status, providerStatus, configsStatus(configs)];

  if (!dirExists) {
    statuses.push("unavailable");
    reasons.push("profile config directory is missing");
    nextActions.push(`Run accounts set ${profile.name} --tool ${profile.tool} --dir <path> or recreate the profile.`);
  }
  if (!profile.email) {
    statuses.push("degraded");
    reasons.push("profile email is not recorded");
    nextActions.push(`Run accounts detect ${profile.name} --tool ${profile.tool} or accounts set ${profile.name} --tool ${profile.tool} --email <email>.`);
  }
  if (configs && configsStatus(configs) !== "ok") {
    reasons.push(...configs.reasons);
    nextActions.push(`Run accounts launch ${profile.name} --tool ${profile.tool} to refresh prelaunch configs before starting the tool.`);
  }
  reasons.push(...login.reasons);
  nextActions.push(...login.nextActions);

  return {
    name: profile.name,
    tool: profile.tool,
    status: worst(statuses),
    active: store.current[profile.tool] === profile.name,
    applied: store.applied[profile.tool] === profile.name,
    emailRecorded: Boolean(profile.email),
    dir: { exists: dirExists },
    login,
    ...(configs
      ? {
          configs: {
            supported: configs.supported,
            required: configs.required,
            status: configs.status,
            reasons: configs.reasons,
          },
        }
      : {}),
    reasons: unique(reasons),
    nextActions: unique(nextActions),
  };
}

function providerReadiness(
  tool: ToolDef,
  profiles: Profile[],
  store: Store,
  env: NodeJS.ProcessEnv,
): AccountsProviderReadiness {
  const availability = detectToolAvailability(tool, env);
  const activeProfile = store.current[tool.id];
  const applied = store.applied[tool.id];
  const required = profiles.length > 0 || Boolean(activeProfile) || Boolean(applied);
  const status: AccountsReadinessStatus = availability.available || !required ? "ok" : "unavailable";
  const reasons = availability.available
    ? []
    : required
      ? [availability.reason ?? "provider binary is unavailable"]
      : [availability.reason ? `${availability.reason}; no registered profile requires it` : "provider binary is unavailable but unused"];
  const nextActions =
    availability.available || !required
      ? []
      : [`Install ${tool.label} so ${tool.bin} is available before launching its profiles.`];
  return {
    id: tool.id,
    label: tool.label,
    status,
    required,
    available: availability.available,
    bin: availability.bin,
    ...(availability.path ? { path: availability.path } : {}),
    profileCount: profiles.length,
    ...(activeProfile ? { activeProfile } : {}),
    ...(applied ? { appliedProfile: applied } : {}),
    reasons,
    nextActions,
  };
}

function supervisorReadiness(toolId: string, state: SupervisorState | undefined, expected: boolean): AccountsSupervisorReadiness {
  if (!state) {
    return {
      tool: toolId,
      status: "missing",
      readiness: expected ? "degraded" : "ok",
      running: false,
      reasons: expected ? ["no supervisor state is present for the active/applied tool"] : [],
      nextActions: expected ? [`Start managed restarts with accounts run ${toolId} when supervisor switching is needed.`] : [],
    };
  }

  const running = processAlive(state.pid);
  if (!running) {
    return {
      tool: toolId,
      status: "stale",
      readiness: "degraded",
      running: false,
      profile: state.profile,
      pid: state.pid,
      ...(state.childPid ? { childPid: state.childPid } : {}),
      startedAt: state.startedAt,
      updatedAt: state.updatedAt,
      reasons: ["supervisor state exists but its process is not running"],
      nextActions: [`Remove stale supervisor state by starting or stopping accounts run ${toolId}.`],
    };
  }

  return {
    tool: toolId,
    status: "running",
    readiness: "ok",
    running: true,
    profile: state.profile,
    pid: state.pid,
    ...(state.childPid ? { childPid: state.childPid } : {}),
    startedAt: state.startedAt,
    updatedAt: state.updatedAt,
    reasons: [],
    nextActions: [],
  };
}

function storageReadiness(env: NodeJS.ProcessEnv): AccountsStorageReadiness {
  const local = {
    home: accountsHome(),
    storePath: storePath(),
    profilesDir: profilesDir(),
    storeExists: existsSync(storePath()),
  };

  let cloud: ReturnType<typeof resolveAccountsCloud> | undefined;
  try {
    cloud = resolveAccountsCloud(env);
  } catch (err) {
    // Cloud was requested but is misconfigured (e.g. URL without a key). Surface
    // it without leaking the key or a raw stack trace.
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: "unavailable",
      mode: "self_hosted",
      transport: "api",
      configured: false,
      local,
      reasons: [`self_hosted storage is misconfigured: ${message}`],
      nextActions: [
        "Set both HASNA_ACCOUNTS_API_URL and HASNA_ACCOUNTS_API_KEY, or unset them to use local storage.",
      ],
    };
  }

  if (cloud.transport === "cloud-http") {
    return {
      status: "ok",
      mode: "self_hosted",
      transport: "api",
      configured: true,
      local,
      api: { baseUrl: cloud.api.baseUrl },
      reasons: [],
      nextActions: [],
    };
  }

  return {
    status: "ok",
    mode: "local",
    transport: "local",
    configured: true,
    local,
    reasons: [],
    nextActions: [],
  };
}

function degradedModesFrom(readiness: {
  profiles: AccountsProfileReadiness[];
  providers: AccountsProviderReadiness[];
  supervisors: AccountsSupervisorReadiness[];
  storage: AccountsStorageReadiness;
}): string[] {
  const modes: string[] = [];
  if (readiness.storage.status !== "ok") {
    modes.push("storage.misconfigured");
  }
  for (const provider of readiness.providers) {
    if (provider.status !== "ok") modes.push(`provider.${provider.id}.unavailable`);
  }
  for (const profile of readiness.profiles) {
    if (!profile.dir.exists) modes.push(`profile.${profile.tool}.${profile.name}.missing_dir`);
    if (!profile.emailRecorded) modes.push(`profile.${profile.tool}.${profile.name}.missing_email`);
    if (profile.login.status !== "ok") modes.push(`login.${profile.tool}.${profile.name}.${profile.login.authStatus ?? "unvalidated"}`);
    if (profile.configs && configsStatusValue(profile.configs.status, profile.configs.supported) !== "ok") {
      modes.push(`configs.${profile.tool}.${profile.name}.${profile.configs.status}`);
    }
  }
  for (const supervisor of readiness.supervisors) {
    if (supervisor.readiness !== "ok") modes.push(`supervisor.${supervisor.tool}.${supervisor.status}`);
  }
  return unique(modes);
}

function unavailableReadiness(generatedAt: string, env: NodeJS.ProcessEnv, err: unknown): AccountsReadiness {
  const message = err instanceof Error ? err.message : String(err);
  const storage = storageReadiness(env);
  const checks = [
    check("store", "Profile registry", "unavailable", "accounts store could not be loaded", [message], ["Fix the accounts store JSON before checking readiness again."]),
    check("storage", "Registry storage", storage.status, storage.status === "ok" ? `registry storage is ${storage.mode}` : "registry storage is misconfigured", storage.reasons, storage.nextActions),
  ];
  const status = worst(checks.map((item) => item.status));
  return {
    schema: "hasna.accounts.readiness/v1",
    ok: status === "ok",
    status,
    generatedAt,
    checks,
    profiles: [],
    providers: [],
    supervisors: [],
    storage,
    degradedModes: unique(["store.unreadable", ...(storage.status !== "ok" ? ["storage.misconfigured"] : [])]),
    nextActions: unique(checks.flatMap((item) => item.nextActions)),
  };
}

export function getAccountsReadiness(opts: AccountsReadinessOptions = {}): AccountsReadiness {
  const env = opts.env ?? process.env;
  const generatedAt = (opts.now ?? new Date()).toISOString();

  let store: Store;
  try {
    store = loadStore();
  } catch (err) {
    return unavailableReadiness(generatedAt, env, err);
  }

  const tools = toolsFromStore(store);
  const toolById = new Map(tools.map((tool) => [tool.id, tool]));
  const profilesByTool = new Map<string, Profile[]>();
  for (const profile of store.profiles) {
    const profiles = profilesByTool.get(profile.tool) ?? [];
    profiles.push(profile);
    profilesByTool.set(profile.tool, profiles);
  }

  const providers = tools.map((tool) => providerReadiness(tool, profilesByTool.get(tool.id) ?? [], store, env));
  const providerStatusById = new Map(providers.map((provider) => [provider.id, provider.status]));
  const profiles = store.profiles
    .slice()
    .sort((a, b) => a.tool.localeCompare(b.tool) || a.name.localeCompare(b.name))
    .map((profile) => profileReadiness(profile, toolById.get(profile.tool), store, providerStatusById.get(profile.tool) ?? "unavailable"));

  const activeOrAppliedTools = unique([...Object.keys(store.current), ...Object.keys(store.applied)]);
  const supervisorToolIds = unique([
    ...activeOrAppliedTools,
    ...listSupervisorStates().map((state) => state.tool),
  ]).sort();
  const supervisors = supervisorToolIds.map((toolId) =>
    supervisorReadiness(toolId, readSupervisorState(toolId), activeOrAppliedTools.includes(toolId)),
  );
  const storage = storageReadiness(env);

  const checks = [
    check(
      "profiles",
      "Profile availability",
      profiles.length === 0 ? "unavailable" : worst(profiles.map((profile) => profile.status)),
      profiles.length === 0 ? "no profiles are registered" : `${profiles.length} profile(s) inspected`,
      profiles.length === 0 ? ["profile registry is empty"] : profiles.flatMap((profile) => profile.reasons),
      profiles.length === 0 ? ["Run accounts add <name> --tool <tool> to create a profile."] : profiles.flatMap((profile) => profile.nextActions),
    ),
    check(
      "providers",
      "Provider availability",
      worst(providers.filter((provider) => provider.required).map((provider) => provider.status)),
      `${providers.filter((provider) => provider.available).length}/${providers.length} provider binary checks passed`,
      providers.filter((provider) => provider.required).flatMap((provider) => provider.reasons),
      providers.filter((provider) => provider.required).flatMap((provider) => provider.nextActions),
    ),
    check(
      "supervisors",
      "Supervisor status",
      supervisors.length === 0 ? "ok" : worst(supervisors.map((supervisor) => supervisor.readiness)),
      supervisors.length === 0 ? "no active/applied supervisor targets" : `${supervisors.length} supervisor target(s) inspected`,
      supervisors.flatMap((supervisor) => supervisor.reasons),
      supervisors.flatMap((supervisor) => supervisor.nextActions),
    ),
    check(
      "storage",
      "Registry storage",
      storage.status,
      storage.status === "ok" ? `registry storage is ${storage.mode}` : "registry storage is misconfigured",
      storage.reasons,
      storage.nextActions,
    ),
  ];
  const status = worst(checks.map((item) => item.status));

  return {
    schema: "hasna.accounts.readiness/v1",
    ok: status === "ok",
    status,
    generatedAt,
    checks,
    profiles,
    providers,
    supervisors,
    storage,
    degradedModes: degradedModesFrom({ profiles, providers, supervisors, storage }),
    nextActions: unique(checks.flatMap((item) => item.nextActions)),
  };
}
