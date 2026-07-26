import { Argument, type Command } from "commander";
import { resolveStore } from "./store.js";
import {
  listClaudeSessions,
  type ClaudeSessionCatalogEntry,
  type ClaudeSessionCatalogOptions,
} from "./claude-sessions.js";

interface SessionsCliOptions {
  profile?: string;
  project?: string;
  uuid?: string;
  json?: boolean;
}

type ActionWrapper = <Args extends unknown[]>(
  fn: (...args: Args) => void | Promise<void>,
) => (...args: Args) => void;

function truncate(value: string, width: number): string {
  if (value.length <= width) return value;
  if (width <= 1) return value.slice(0, width);
  return `${value.slice(0, width - 1)}…`;
}

function printable(value: string): string {
  return value.replace(
    /[\u0000-\u001f\u007f-\u009f]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function pad(value: string, width: number): string {
  return value.padEnd(width, " ");
}

/** Concise human output; exact paths and the full identity remain in JSON. */
export function formatClaudeSessionTable(entries: readonly ClaudeSessionCatalogEntry[]): string {
  if (entries.length === 0) return "no Claude sessions found.";
  const rows = entries.map((entry) => ({
    OWNER: truncate(printable(entry.ownerProfile), 20),
    PROJECT: truncate(printable(entry.cwd ?? entry.encodedProject), 40),
    UUID: entry.uuid,
    UPDATED: entry.updatedAt.slice(0, 19).replace("T", " "),
    SIZE: formatBytes(entry.sizeBytes),
  }));
  const headers = ["OWNER", "PROJECT", "UUID", "UPDATED", "SIZE"] as const;
  const widths = Object.fromEntries(
    headers.map((header) => [
      header,
      Math.max(header.length, ...rows.map((row) => row[header].length)),
    ]),
  ) as Record<(typeof headers)[number], number>;

  return [
    headers.map((header) => pad(header, widths[header])).join("  ").trimEnd(),
    headers.map((header) => "-".repeat(widths[header])).join("  "),
    ...rows.map((row) => headers.map((header) => pad(row[header], widths[header])).join("  ").trimEnd()),
  ].join("\n");
}

function addOptions(command: Command): Command {
  return command
    .option("--profile <name>", "filter by Accounts owner profile")
    .option("--project <identity>", "filter by canonical cwd/project identity or encoded project key")
    .option("--uuid <uuid>", "filter by session UUID (owner and project remain part of identity)")
    .option("--json", "output structured JSON");
}

async function printSessions(options: SessionsCliOptions): Promise<void> {
  const profiles = await resolveStore().listProfiles("claude");
  const catalogOptions: ClaudeSessionCatalogOptions = {
    ...(options.profile ? { profile: options.profile } : {}),
    ...(options.project ? { project: options.project } : {}),
    ...(options.uuid ? { uuid: options.uuid } : {}),
  };
  const sessions = listClaudeSessions(profiles, catalogOptions);
  if (options.json) {
    console.log(JSON.stringify(sessions, null, 2));
    return;
  }
  console.log(formatClaudeSessionTable(sessions));
}

/** Register both `accounts sessions` and the explicit `accounts sessions list`. */
export function registerClaudeSessionCommands(program: Command, wrapAction: ActionWrapper): void {
  addOptions(
    program
      .command("sessions")
      .description("list Accounts-owned local Claude sessions without transcript content")
      .addArgument(
        new Argument("[operation]", "session operation")
          .choices(["list"])
          .default("list"),
      ),
  ).action(wrapAction((_operation: string, options: SessionsCliOptions) => printSessions(options)));
}
