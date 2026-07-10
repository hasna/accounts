#!/usr/bin/env bun

import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

import {
  AccountsError,
  asAccountsError,
  canonicalJson,
  createSQLiteAccounts,
  decodeRecordEnvelope,
  exitCodeForError,
  parseAccessMethodId,
  parseAccountId,
  parseAuthCapsuleId,
  parseCapacityPoolId,
  parseClosedJsonBytes,
  parseCredentialBindingId,
  parseEntitlementId,
  PACKAGE_VERSION,
  toErrorEnvelope,
  validateSlotEligibility,
  type EntityKind,
} from "./index";

const CLI_SCHEMA_VERSION = "accounts.cli.v1" as const;

const NOUNS: Readonly<Record<string, EntityKind>> = {
  accounts: "account",
  entitlements: "entitlement",
  "capacity-pools": "capacity_pool",
  "access-methods": "access_method",
  "auth-capsules": "auth_capsule",
  "credential-bindings": "credential_binding",
};

interface ParsedArguments {
  readonly positionals: readonly string[];
  readonly flags: Readonly<Record<string, string | true>>;
}

export async function runAccountsCli(argv: readonly string[]): Promise<number> {
  const jsonRequested = argv.includes("--json");
  try {
    const parsed = parseArguments(argv);
    const [command, ...positionals] = parsed.positionals;
    if (command === undefined || command === "help" || parsed.flags.help === true) {
      output(jsonRequested, "help", { usage: usageText() });
      return 0;
    }
    if (command === "version" || parsed.flags.version === true) {
      output(jsonRequested, "version", { package: "@hasna/accounts", version: PACKAGE_VERSION });
      return 0;
    }
    if (command === "validate") return await validateCommand(positionals, parsed.flags, jsonRequested);

    const catalog = createLocalCatalog();
    try {
      if (command === "doctor") {
        requireNoPositionals(positionals, "doctor");
        output(jsonRequested, "doctor", await catalog.doctor());
        return 0;
      }
      if (command === "list") {
        const kind = parseNoun(positionals[0]);
        requirePositionals(positionals, 1, "list");
        const records = await catalog.list(kind);
        output(jsonRequested, "list", {
          kind,
          records: records.map((data) => ({
            schemaVersion: "accounts.capacity.v1",
            kind,
            data,
          })),
        });
        return 0;
      }
      if (command === "get") {
        const kind = parseNoun(positionals[0]);
        requirePositionals(positionals, 2, "get");
        const id = parseEntityId(kind, positionals[1]);
        const record = await catalog.get(kind, id as never);
        output(jsonRequested, "get", {
          schemaVersion: "accounts.capacity.v1",
          kind,
          data: record,
        });
        return 0;
      }
      if (command === "eligibility") {
        requirePositionals(positionals, 1, "eligibility");
        const accessMethodId = parseAccessMethodId(positionals[0]);
        const operation = requiredFlag(parsed.flags, "operation");
        const model = requiredFlag(parsed.flags, "model");
        const dataClassification = requiredFlag(parsed.flags, "data-classification");
        const destinationPolicyClass =
          typeof parsed.flags["destination-policy-class"] === "string"
            ? parsed.flags["destination-policy-class"]
            : "default";
        const result = await catalog.eligibility({
          accessMethodId,
          operation,
          model,
          dataClassification,
          destinationPolicyClass,
        });
        output(jsonRequested, "eligibility", result);
        return result.eligible ? 0 : 7;
      }
      throw usageError("Unknown command");
    } finally {
      await catalog.close();
    }
  } catch (error) {
    const safe = asAccountsError(error);
    const envelope = toErrorEnvelope(safe, randomUUID());
    if (jsonRequested) Bun.stderr.write(`${canonicalJson(envelope)}\n`);
    else Bun.stderr.write(`${envelope.error.code}: ${envelope.error.message}\n`);
    return exitCodeForError(safe);
  }
}

function createLocalCatalog() {
  const deployment = Bun.env.HASNA_ACCOUNTS_DEPLOYMENT;
  const localPath = Bun.env.HASNA_ACCOUNTS_DATABASE_PATH;
  const serviceConfigPresent =
    Bun.env.HASNA_ACCOUNTS_CAPACITY_API_URL !== undefined ||
    Bun.env.HASNA_ACCOUNTS_CAPACITY_AUTH_REF !== undefined;
  if (deployment === "self_hosted" && localPath !== undefined) {
    throw usageError("Self-hosted deployment cannot use a local database path");
  }
  if (deployment !== "local") {
    if (deployment === "self_hosted") {
      throw new AccountsError("NOT_IMPLEMENTED", "The self-hosted CLI client is not configured", {
        details: { adapter: "http" },
      });
    }
    throw usageError("HASNA_ACCOUNTS_DEPLOYMENT must be local or self_hosted");
  }
  if (serviceConfigPresent) {
    throw usageError("Local deployment cannot use self-hosted capacity configuration");
  }
  if (localPath !== undefined && !isAbsolute(localPath)) {
    throw usageError("HASNA_ACCOUNTS_DATABASE_PATH must be absolute");
  }
  const path = localPath === undefined ? join(homedir(), ".hasna", "accounts", "accounts.db") : localPath;
  return createSQLiteAccounts({ path });
}

async function validateCommand(
  positionals: readonly string[],
  flags: Readonly<Record<string, string | true>>,
  jsonRequested: boolean,
): Promise<number> {
  requirePositionals(positionals, 1, "validate");
  const bytes =
    positionals[0] === "-"
      ? new Uint8Array(await Bun.stdin.arrayBuffer())
      : new Uint8Array(await Bun.file(resolve(positionals[0]!)).arrayBuffer());
  const parsed = parseClosedJsonBytes(bytes);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw usageError("Expected a DTO object");
  const schemaVersion = (parsed as Record<string, unknown>).schemaVersion;
  let documentKind: string;
  if (schemaVersion === "accounts.capacity.v1") {
    documentKind = decodeRecordEnvelope(parsed).kind;
  } else if (schemaVersion === "accounts.slot-eligibility.v1") {
    validateSlotEligibility(parsed);
    documentKind = "slot_eligibility";
  } else {
    throw new AccountsError("SCHEMA_VERSION_UNSUPPORTED", "Unsupported DTO schema version");
  }
  if (flags.json !== undefined && flags.json !== true) throw usageError("--json takes no value");
  output(jsonRequested, "validate", { valid: true, documentKind });
  return 0;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  const positionals: string[] = [];
  const flags: Record<string, string | true> = Object.create(null) as Record<string, string | true>;
  const valueFlags = new Set(["operation", "model", "data-classification", "destination-policy-class"]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (!argument.startsWith("--")) {
      positionals.push(argument);
      continue;
    }
    const name = argument.slice(2);
    if (name.length === 0 || Object.hasOwn(flags, name)) throw usageError("Invalid or duplicate option");
    if (valueFlags.has(name)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw usageError("Option value is required");
      flags[name] = value;
      index += 1;
    } else if (name === "json" || name === "help" || name === "version") {
      flags[name] = true;
    } else {
      throw usageError("Unknown option");
    }
  }
  return { positionals, flags };
}

function parseNoun(value: string | undefined): EntityKind {
  if (value === undefined || NOUNS[value] === undefined) throw usageError("Unknown record noun");
  return NOUNS[value];
}

function parseEntityId(kind: EntityKind, value: string | undefined) {
  switch (kind) {
    case "account":
      return parseAccountId(value);
    case "entitlement":
      return parseEntitlementId(value);
    case "capacity_pool":
      return parseCapacityPoolId(value);
    case "access_method":
      return parseAccessMethodId(value);
    case "auth_capsule":
      return parseAuthCapsuleId(value);
    case "credential_binding":
      return parseCredentialBindingId(value);
  }
}

function requiredFlag(flags: Readonly<Record<string, string | true>>, name: string): string {
  const value = flags[name];
  if (typeof value !== "string" || value.length === 0 || value.length > 255) {
    throw usageError(`--${name} is required`);
  }
  return value;
}

function requirePositionals(positionals: readonly string[], count: number, command: string): void {
  if (positionals.length !== count) throw usageError(`Invalid ${command} arguments`);
}

function requireNoPositionals(positionals: readonly string[], command: string): void {
  requirePositionals(positionals, 0, command);
}

function usageError(message: string): AccountsError {
  return new AccountsError("VALIDATION_FAILED", message);
}

function output(json: boolean, command: string, data: unknown): void {
  const envelope = { schemaVersion: CLI_SCHEMA_VERSION, command, data };
  if (json) Bun.stdout.write(`${canonicalJson(envelope)}\n`);
  else if (command === "help") Bun.stdout.write(`${(data as { usage: string }).usage}\n`);
  else Bun.stdout.write(`${canonicalJson(data)}\n`);
}

function usageText(): string {
  return [
    "accounts validate <file|-> [--json]",
    "accounts doctor [--json]",
    "accounts list <accounts|entitlements|capacity-pools|access-methods|auth-capsules|credential-bindings> [--json]",
    "accounts get <noun> <uuidv7> [--json]",
    "accounts eligibility <access-method-uuidv7> --operation <id> --model <id> --data-classification <id> [--json]",
  ].join("\n");
}

if (import.meta.main) {
  const code = await runAccountsCli(Bun.argv.slice(2));
  process.exitCode = code;
}
