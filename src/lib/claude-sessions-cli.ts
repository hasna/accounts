import { Argument, type Command } from "commander";
import { once } from "node:events";
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
) => (...args: Args) => Promise<void>;

function codePointWidth(character: string): number {
  const codePoint = character.codePointAt(0)!;
  if (/\p{Mark}/u.test(character)) return 0;
  if (
    codePoint >= 0x1100 &&
    (codePoint <= 0x115f ||
      codePoint === 0x2329 ||
      codePoint === 0x232a ||
      (codePoint >= 0x2e80 && codePoint <= 0xa4cf && codePoint !== 0x303f) ||
      (codePoint >= 0xac00 && codePoint <= 0xd7a3) ||
      (codePoint >= 0xf900 && codePoint <= 0xfaff) ||
      (codePoint >= 0xfe10 && codePoint <= 0xfe19) ||
      (codePoint >= 0xfe30 && codePoint <= 0xfe6f) ||
      (codePoint >= 0xff00 && codePoint <= 0xff60) ||
      (codePoint >= 0xffe0 && codePoint <= 0xffe6) ||
      (codePoint >= 0x1f300 && codePoint <= 0x1faff) ||
      (codePoint >= 0x20000 && codePoint <= 0x3fffd))
  ) {
    return 2;
  }
  return 1;
}

function displayWidth(value: string): number {
  let width = 0;
  for (const character of value) width += codePointWidth(character);
  return width;
}

function truncate(value: string, width: number): string {
  if (displayWidth(value) <= width) return value;
  if (width <= 0) return "";
  if (width === 1) return "…";
  let result = "";
  let used = 0;
  for (const character of value) {
    const characterWidth = codePointWidth(character);
    if (used + characterWidth + 1 > width) break;
    result += character;
    used += characterWidth;
  }
  return `${result}…`;
}

function printable(value: string): string {
  return value.replace(
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (character) => {
      const codePoint = character.codePointAt(0)!;
      return codePoint <= 0xffff
        ? `\\u${codePoint.toString(16).padStart(4, "0")}`
        : `\\u{${codePoint.toString(16)}}`;
    },
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function pad(value: string, width: number): string {
  return `${value}${" ".repeat(Math.max(0, width - displayWidth(value)))}`;
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
      Math.max(displayWidth(header), ...rows.map((row) => displayWidth(row[header]))),
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

async function writeStdout(value: string): Promise<void> {
  if (!process.stdout.write(`${value}\n`)) await once(process.stdout, "drain");
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
    await writeStdout(JSON.stringify(sessions, null, 2));
    return;
  }
  await writeStdout(formatClaudeSessionTable(sessions));
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
