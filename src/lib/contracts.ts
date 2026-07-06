import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanNoCloudTarget, SCHEMA_IDS, parseContract, type ActorRef, type CapabilityCard, type NoCloudEvidencePack, type WorkRun } from "@hasna/contracts";
import type { EventInput } from "@hasna/events";
import type { AgentsRunnerResult, ProfileLike } from "./agents.js";
import type { RunSupervisorOptions } from "./supervisor.js";

const PACKAGE_NAME = "@hasna/accounts";
const PACKAGE_VERSION = "0.1.31";
type ActorObject = Record<string, unknown>;

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "unknown";
}

function createdAt(now?: string): string {
  return now ?? new Date().toISOString();
}

function packageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const candidate of [join(here, "..", "..", "package.json"), join(here, "..", "package.json")]) {
      if (!existsSync(candidate)) continue;
      const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { version?: string };
      if (pkg.version) return pkg.version;
    }
  } catch {
    /* fall through */
  }
  return PACKAGE_VERSION;
}

export function toAccountsActorRef(input: {
  id?: string;
  kind?: ActorRef["kind"];
  name?: string;
  provider?: string;
  accountId?: string;
  machineId?: string;
  capabilities?: string[];
  createdAt?: string;
}): ActorRef {
  const id = input.id ?? `actor_${slug(input.provider ?? input.name ?? PACKAGE_NAME)}`;
  return parseContract(SCHEMA_IDS.actorRef, {
    schema: SCHEMA_IDS.actorRef,
    id,
    createdAt: createdAt(input.createdAt),
    kind: input.kind ?? "service",
    ...(input.name ? { name: input.name } : {}),
    ...(input.provider ? { provider: input.provider } : {}),
    ...(input.accountId ? { accountId: input.accountId } : {}),
    ...(input.machineId ? { machineId: input.machineId } : {}),
    capabilities: input.capabilities ?? ["profile-management", "agent-supervision", "event-emission"],
  });
}

function actorRefFromObject(value: ActorObject, now?: string): ActorRef {
  const draft = value.schema === SCHEMA_IDS.actorRef
    ? value
    : {
        schema: SCHEMA_IDS.actorRef,
        id: typeof value.id === "string" ? value.id : `actor_${slug(String(value.name ?? value.provider ?? "event"))}`,
        createdAt: typeof value.createdAt === "string" ? value.createdAt : createdAt(now),
        kind: value.kind,
        ...(typeof value.name === "string" ? { name: value.name } : {}),
        ...(typeof value.provider === "string" ? { provider: value.provider } : {}),
        ...(typeof value.accountId === "string" ? { accountId: value.accountId } : {}),
        ...(typeof value.machineId === "string" ? { machineId: value.machineId } : {}),
        ...(Array.isArray(value.capabilities) ? { capabilities: value.capabilities } : {}),
      };
  return parseContract(SCHEMA_IDS.actorRef, draft);
}

function validateActorField(value: unknown, path: string, options: { allowScalar?: boolean; now?: string } = {}): void {
  if (value === undefined || value === null) return;
  if (typeof value !== "object" || Array.isArray(value)) {
    if (options.allowScalar) return;
    throw new Error(`${path} must be an actor_ref-compatible object`);
  }
  actorRefFromObject(value as ActorObject, options.now);
}

export function validateEventActorRefs<TData extends Record<string, unknown>>(input: EventInput<TData>, now?: string): EventInput<TData> {
  const data = input.data as Record<string, unknown> | undefined;
  const metadata = input.metadata;
  validateActorField(data?.actor, "data.actor", { allowScalar: true, now });
  validateActorField(data?.actorRef, "data.actorRef", { now });
  validateActorField(data?.actor_ref, "data.actor_ref", { now });
  validateActorField(metadata?.actor, "metadata.actor", { allowScalar: true, now });
  validateActorField(metadata?.actorRef, "metadata.actorRef", { now });
  validateActorField(metadata?.actor_ref, "metadata.actor_ref", { now });
  return input;
}

export function toAgentsRunnerWorkRun(
  result: AgentsRunnerResult,
  profile: ProfileLike,
  options: { id?: string; createdAt?: string; startedAt?: string; finishedAt?: string } = {},
): WorkRun {
  const timestamp = createdAt(options.createdAt);
  return parseContract(SCHEMA_IDS.workRun, {
    schema: SCHEMA_IDS.workRun,
    id: options.id ?? `work_run_agents_${slug(profile.tool)}_${slug(profile.name)}`,
    createdAt: timestamp,
    objective: `List ${profile.tool} agents for ${profile.name}`,
    status: result.ok ? "succeeded" : "failed",
    actor: {
      kind: "service",
      id: "actor_hasna_accounts",
      name: PACKAGE_NAME,
      provider: "hasna",
    },
    startedAt: options.startedAt ?? timestamp,
    finishedAt: options.finishedAt ?? timestamp,
    resourceRefs: [
      {
        kind: "tool",
        id: slug(profile.tool),
        name: profile.tool,
        externalId: profile.tool,
        sourcePackage: PACKAGE_NAME,
      },
    ],
    evidenceRefs: [
      {
        id: result.ok ? "agents_stdout" : "agents_error",
        kind: result.ok ? "command_output" : "log",
        summary: result.ok ? result.raw.slice(0, 200) : result.error ?? "agents command failed",
      },
    ],
    metadata: {
      profile: profile.name,
      tool: profile.tool,
      dir: profile.dir,
      rawLength: result.raw.length,
    },
  });
}

export function toSupervisorOptionsWorkRun(
  options: RunSupervisorOptions = {},
  details: { id?: string; createdAt?: string; tool?: string; profile?: string; command?: string[] } = {},
): WorkRun {
  const timestamp = createdAt(details.createdAt);
  return parseContract(SCHEMA_IDS.workRun, {
    schema: SCHEMA_IDS.workRun,
    id: details.id ?? `work_run_supervisor_${slug(details.tool ?? "tool")}_${slug(details.profile ?? "profile")}`,
    createdAt: timestamp,
    objective: `Run supervised ${details.tool ?? "tool"} session`,
    status: "running",
    actor: {
      kind: "service",
      id: "actor_hasna_accounts_supervisor",
      name: "accounts supervisor",
      provider: "hasna",
    },
    startedAt: timestamp,
    constraints: [
      `restartDelayMs=${options.restartDelayMs ?? "default"}`,
      `stdio=${Array.isArray(options.stdio) ? "custom" : options.stdio ?? "default"}`,
    ],
    resourceRefs: [
      {
        kind: "tool",
        id: slug(details.tool ?? "unknown"),
        name: details.tool ?? "unknown",
        externalId: details.tool ?? "unknown",
        sourcePackage: PACKAGE_NAME,
      },
    ],
    metadata: {
      profile: details.profile,
      command: details.command,
      configsPrelaunch: options.configsPrelaunch ?? null,
    },
  });
}

export function accountsCapabilityCard(options: { createdAt?: string } = {}): CapabilityCard {
  return parseContract(SCHEMA_IDS.capabilityCard, {
    schema: SCHEMA_IDS.capabilityCard,
    id: "capability_hasna_accounts_cli",
    createdAt: createdAt(options.createdAt),
    kind: "tool",
    name: "accounts",
    version: packageVersion(),
    status: "available",
    capabilities: [
      "profile-management",
      "profile-switching",
      "agent-session-inspection",
      "supervisor-control",
      "local-storage-sync",
      "event-emission",
    ],
    limitations: [
      "local-machine state only",
      "cloud posture for no-cloud-scan remains pending upstream ratification",
    ],
    riskLevel: "medium",
    evidenceRefs: [
      {
        id: "package_manifest",
        kind: "file",
        uri: "file://package.json",
        summary: "Package manifest describes accounts CLI entrypoints and dependencies.",
      },
    ],
  });
}

export function accountsNoCloudEvidencePack(target = ".", options: { id?: string; createdAt?: string } = {}): NoCloudEvidencePack {
  const pack = scanNoCloudTarget(target, {
    id: options.id ?? "no_cloud_hasna_accounts",
    now: createdAt(options.createdAt),
    generatedBy: {
      kind: "service",
      id: "actor_hasna_accounts",
      name: PACKAGE_NAME,
      provider: "hasna",
    },
  });
  return parseContract(SCHEMA_IDS.noCloudEvidencePack, pack);
}
