import { createHash } from "node:crypto";
import { join } from "node:path";
import type { Profile, Store, ToolDef } from "../types.js";
import { AccountsError, profileSchema, toolDefSchema } from "../types.js";
import { accountsHome, loadMachineStore, saveStore, storePath } from "../storage.js";
import { writeFileAtomic } from "./safe-path.js";

export const PROFILE_INVENTORY_SCHEMA_VERSION = 1 as const;
export const REGISTRY_DIAGNOSTIC_SCHEMA = "hasna.accounts.registry-diagnostic/v1" as const;
export const EXPECTED_STORAGE_TARGET_ENV = "HASNA_ACCOUNTS_EXPECTED_STORAGE_TARGET";
export const EXPECTED_SERVER_HEAD_ENV = "HASNA_ACCOUNTS_EXPECTED_SERVER_HEAD";

export interface ProfileInventory {
  schemaVersion: typeof PROFILE_INVENTORY_SCHEMA_VERSION;
  count: number;
  digest: string;
}

export interface RegistryAuthoritySnapshot {
  schema: typeof REGISTRY_DIAGNOSTIC_SCHEMA;
  authority: "api";
  storageTarget: string;
  runtime: {
    schema: "hasna.accounts.runtime-provenance/v1";
    package: { name: "@hasna/accounts"; version: string };
    source: { head: string; kind: "build-manifest" | "git-worktree" };
    verifiable: true;
  };
  inventory: ProfileInventory;
  profiles: Profile[];
}

const FULL_GIT_HEAD = /^[0-9a-f]{40}$/;

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const item = (value as Record<string, unknown>)[key];
    if (item !== undefined) out[key] = canonical(item);
  }
  return out;
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex")}`;
}

export function profileInventory(profiles: readonly Profile[]): ProfileInventory {
  const ordered = profiles
    .map((profile) => canonical(profile))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return {
    schemaVersion: PROFILE_INVENTORY_SCHEMA_VERSION,
    count: profiles.length,
    digest: digest(ordered),
  };
}

export function toolInventory(tools: readonly ToolDef[]): { count: number; digest: string } {
  const ordered = tools
    .map((tool) => canonical(tool))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return { count: tools.length, digest: digest(ordered) };
}

export function assertRegistryAuthoritySnapshot(
  value: unknown,
  expectedStorageTarget?: string,
  expectedServerHead?: string,
): RegistryAuthoritySnapshot {
  if (!value || typeof value !== "object") throw new AccountsError("accounts-serve returned no registry diagnostic");
  const snapshot = value as Partial<RegistryAuthoritySnapshot>;
  if (snapshot.schema !== REGISTRY_DIAGNOSTIC_SCHEMA || snapshot.authority !== "api") {
    throw new AccountsError("accounts-serve returned an incompatible registry diagnostic schema");
  }
  if (typeof snapshot.storageTarget !== "string" || snapshot.storageTarget.length === 0) {
    throw new AccountsError("accounts-serve did not identify its authoritative storage target");
  }
  if (expectedStorageTarget && snapshot.storageTarget !== expectedStorageTarget) {
    throw new AccountsError(
      `storage target mismatch: expected ${expectedStorageTarget}, accounts-serve reports ${snapshot.storageTarget}`,
    );
  }
  const runtime = snapshot.runtime;
  if (
    runtime?.schema !== "hasna.accounts.runtime-provenance/v1" ||
    runtime.package?.name !== "@hasna/accounts" ||
    runtime.verifiable !== true ||
    !FULL_GIT_HEAD.test(runtime.source?.head ?? "")
  ) {
    throw new AccountsError("accounts-serve command provenance is not verifiable");
  }
  if (expectedServerHead && runtime.source.head !== expectedServerHead) {
    throw new AccountsError(
      `server provenance mismatch: expected HEAD ${expectedServerHead}, accounts-serve reports ${runtime.source.head}`,
    );
  }
  if (!snapshot.inventory || snapshot.inventory.schemaVersion !== PROFILE_INVENTORY_SCHEMA_VERSION) {
    throw new AccountsError(
      `profile schema mismatch: client requires ${PROFILE_INVENTORY_SCHEMA_VERSION}, accounts-serve reports ${snapshot.inventory?.schemaVersion ?? "unknown"}`,
    );
  }
  if (!Array.isArray(snapshot.profiles)) throw new AccountsError("accounts-serve omitted its authoritative profile inventory");
  const profiles = snapshot.profiles.map((profile, index) => {
    const parsed = profileSchema.safeParse(profile);
    if (!parsed.success) {
      throw new AccountsError(`accounts-serve profile inventory row ${index} is invalid: ${parsed.error.issues[0]?.message}`);
    }
    return parsed.data;
  });
  const actual = profileInventory(profiles);
  if (actual.count !== snapshot.inventory.count || actual.digest !== snapshot.inventory.digest) {
    throw new AccountsError("accounts-serve profile inventory digest does not match the returned rows");
  }
  return { ...(snapshot as RegistryAuthoritySnapshot), profiles };
}

export function assertNoShadowProfileStore(machine: Store, remote: ProfileInventory): void {
  if (machine.profiles.length === 0 && machine.tools.length === 0) return;
  const local = profileInventory(machine.profiles);
  const relationship = local.digest === remote.digest && local.count === remote.count ? "duplicates" : "diverges from";
  throw new AccountsError(
    `profile inventory is split-brain: local ${storePath()} (${local.count} profile(s)) ${relationship} ` +
      `the configured API inventory (${remote.count} profile(s)). No stores were merged. ` +
      "Run `accounts provenance --json` to inspect both inventories, then `accounts storage reconcile --use api` " +
      "to archive the local store and select the API inventory.",
  );
}

export interface ReconciliationEvidence {
  schema: "hasna.accounts.registry-reconciliation/v1";
  createdAt: string;
  selectedAuthority: "api";
  storageTarget: string;
  local: { path: string; inventory: ProfileInventory; tools: { count: number; digest: string }; store: Store };
  remote: { inventory: ProfileInventory; runtimeHead: string };
}

export function archiveAndSelectApi(snapshot: RegistryAuthoritySnapshot): { evidencePath: string; evidence: ReconciliationEvidence } {
  const machine = loadMachineStore();
  const createdAt = new Date().toISOString();
  const evidence: ReconciliationEvidence = {
    schema: "hasna.accounts.registry-reconciliation/v1",
    createdAt,
    selectedAuthority: "api",
    storageTarget: snapshot.storageTarget,
    local: {
      path: storePath(),
      inventory: profileInventory(machine.profiles),
      tools: toolInventory(machine.tools),
      store: machine,
    },
    remote: { inventory: snapshot.inventory, runtimeHead: snapshot.runtime.source.head },
  };
  const stamp = createdAt.replace(/[:.]/g, "-");
  const evidencePath = join(accountsHome(), "reconciliation", `${stamp}-select-api.json`);
  writeFileAtomic(evidencePath, JSON.stringify(evidence, null, 2) + "\n", {
    mode: 0o600,
    mustStayUnder: accountsHome(),
  });
  saveStore({ ...machine, current: {}, profiles: [], tools: [] });
  return { evidencePath, evidence };
}

export function validateToolInventory(tools: readonly unknown[]): ToolDef[] {
  return tools.map((tool, index) => {
    const parsed = toolDefSchema.safeParse(tool);
    if (!parsed.success) throw new AccountsError(`invalid local tool inventory row ${index}`);
    return parsed.data;
  });
}
