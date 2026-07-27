import chalk from "chalk";
import { Argument, type Command } from "commander";
import { AccountsError } from "../types.js";
import { resolveStore } from "./store.js";
import {
  runClaudeSessionResume,
  type ClaudeSessionResumeResult,
} from "./claude-session-resume.js";
import {
  isClaudeSessionUuid,
  listClaudeSessions,
  type ClaudeSessionCatalogEntry,
  type ClaudeSessionCatalogOptions,
  type ClaudeSessionScanSkip,
} from "./claude-sessions.js";

interface SessionsCliOptions {
  profile?: string;
  project?: string;
  uuid?: string;
  json?: boolean;
  account?: string;
  cwd?: string;
  dryRun?: boolean;
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
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\uD800-\uDFFF]/gu,
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
    OWNER: truncate(
      printable(
        [...new Set(entry.representations.map((representation) => representation.ownerProfile))]
          .sort()
          .join(","),
      ),
      20,
    ),
    PROJECT: truncate(printable(entry.cwd ?? entry.encodedProject), 40),
    UUID: entry.uuid,
    UPDATED: entry.updatedAt.slice(0, 19).replace("T", " "),
    SIZE: formatBytes(entry.sizeBytes),
    "ID CHECK":
      entry.sessionIdCheck === "bounded-match"
        ? "bounded-match"
        : entry.sessionIdCheck === "bounded-mismatch"
          ? "BOUNDED-MISMATCH"
          : "NOT-OBSERVED",
  }));
  const headers = ["OWNER", "PROJECT", "UUID", "UPDATED", "SIZE", "ID CHECK"] as const;
  // Folded, never spread: one call argument per row overflows the engine's call
  // arity ceiling, so a large catalog would exit with a RangeError and an empty
  // stdout instead of a table.
  const widths = Object.fromEntries(
    headers.map((header) => [
      header,
      rows.reduce((width, row) => Math.max(width, displayWidth(row[header])), displayWidth(header)),
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
    .option("--uuid <uuid>", "filter by canonical session UUID (owner and project remain part of identity)")
    .option("--json", "output structured JSON");
}

/** A reader that quits early (`| head`, `| less`) is a normal end of output. */
function isClosedPipe(error: unknown): boolean {
  const code =
    error && typeof error === "object" && "code" in error
      ? String((error as { code?: unknown }).code)
      : "";
  return code === "EPIPE" || code === "ERR_STREAM_DESTROYED";
}

let stdoutPipeGuarded = false;

/** Keep a closed reader from surfacing as an unhandled stdout `error` event. */
function guardStdoutPipe(): void {
  if (stdoutPipeGuarded) return;
  stdoutPipeGuarded = true;
  process.stdout.on("error", (error: unknown) => {
    if (!isClosedPipe(error)) {
      process.nextTick(() => {
        throw error;
      });
    }
  });
}

/** Resolves once stdout drains, or once the reader goes away. */
function waitForDrain(): Promise<void> {
  return new Promise((resolve, reject) => {
    const settle = (error?: unknown) => {
      process.stdout.off("drain", onDrain);
      process.stdout.off("close", onClose);
      process.stdout.off("error", onError);
      if (error !== undefined && !isClosedPipe(error)) reject(error);
      else resolve();
    };
    const onDrain = () => settle();
    const onClose = () => settle();
    const onError = (error: unknown) => settle(error);
    process.stdout.on("drain", onDrain);
    process.stdout.on("close", onClose);
    process.stdout.on("error", onError);
  });
}

async function writeStdout(value: string): Promise<void> {
  guardStdoutPipe();
  if (process.stdout.destroyed || process.stdout.writableEnded) return;
  try {
    if (!process.stdout.write(`${value}\n`)) await waitForDrain();
  } catch (error) {
    if (!isClosedPipe(error)) throw error;
  }
}

const MAX_REPORTED_SKIPS = 10;

/** Skips go to stderr so a catalog consumer can tell absent from not observed. */
function warnSkipped(skipped: readonly ClaudeSessionScanSkip[]): void {
  if (skipped.length === 0) return;
  console.error(
    chalk.yellow(
      `warning: ${skipped.length} source root/path(s) could not be represented and are missing from this catalog`,
    ),
  );
  for (const skip of skipped.slice(0, MAX_REPORTED_SKIPS)) {
    console.error(chalk.dim(`  ${skip.reason}: ${printable(skip.path)}`));
  }
  if (skipped.length > MAX_REPORTED_SKIPS) {
    console.error(chalk.dim(`  … and ${skipped.length - MAX_REPORTED_SKIPS} more`));
  }
}

async function printSessions(options: SessionsCliOptions): Promise<void> {
  if (options.uuid && !isClaudeSessionUuid(options.uuid)) {
    throw new AccountsError(
      "--uuid must be a valid UUID in canonical 8-4-4-4-12 hexadecimal form",
    );
  }
  const profiles = await resolveStore().listProfiles("claude");
  const skipped: ClaudeSessionScanSkip[] = [];
  const catalogOptions: ClaudeSessionCatalogOptions = {
    ...(options.profile ? { profile: options.profile } : {}),
    ...(options.project ? { project: options.project } : {}),
    ...(options.uuid ? { uuid: options.uuid } : {}),
    onSkip: (skip) => {
      skipped.push(skip);
    },
  };
  const sessions = listClaudeSessions(profiles, catalogOptions);
  warnSkipped(skipped);
  if (options.json) {
    await writeStdout(JSON.stringify(sessions, null, 2));
    return;
  }
  await writeStdout(formatClaudeSessionTable(sessions));
}

function formatResumeResult(result: ClaudeSessionResumeResult): string {
  return [
    `mode: ${result.mode}`,
    `source: ${result.source}`,
    `destination: ${result.destination}`,
    `target: ${result.target}`,
    `cwd: ${result.cwd}`,
    `transaction: ${result.transaction ?? "none"}`,
    ...(result.fork ? [`fork: ${result.fork}`] : []),
    `recovery: ${result.recovery}`,
  ].join("\n");
}

async function resumeSession(
  referenceOrUuid: string | undefined,
  options: SessionsCliOptions,
): Promise<void> {
  if (!referenceOrUuid) {
    throw new AccountsError(
      "sessions resume requires an opaque catalog reference or a unique UUID",
    );
  }
  if (!options.account) {
    throw new AccountsError("sessions resume requires --account <target>");
  }
  const store = resolveStore();
  if (store.transport !== "local") {
    throw new AccountsError(
      "sessions resume is restricted to the local Accounts registry and uid trust domain",
    );
  }
  const profiles = await store.listProfiles("claude");
  const targetProfile = await store.getProfile(options.account, "claude");
  const run = await runClaudeSessionResume({
    profiles,
    targetProfile,
    referenceOrUuid,
    ...(options.cwd ? { cwd: options.cwd } : {}),
    dryRun: options.dryRun === true,
  });
  if (options.json) await writeStdout(JSON.stringify(run.result, null, 2));
  else await writeStdout(formatResumeResult(run.result));
  if (run.exitCode !== 0) process.exitCode = run.exitCode;
}

/** Register catalog listing plus guarded native resume/fork. */
export function registerClaudeSessionCommands(program: Command, wrapAction: ActionWrapper): void {
  addOptions(
    program
      .command("sessions")
      .description("list or safely resume Accounts-owned local Claude sessions")
      .addArgument(
        new Argument("[operation]", "session operation")
          .choices(["list", "resume"])
          .default("list"),
      )
      .addArgument(
        new Argument(
          "[catalog-ref-or-uuid]",
          "opaque catalogRef or unique Claude session UUID",
        ),
      ),
  )
    .option("--account <name>", "target local Accounts Claude profile")
    .option("--cwd <path>", "explicit absolute launch cwd; never inferred from the caller")
    .option("--dry-run", "validate all applicable gates without mutation or launch")
    .action(
      wrapAction(
        (
          operation: "list" | "resume",
          referenceOrUuid: string | undefined,
          options: SessionsCliOptions,
        ) =>
          operation === "resume"
            ? resumeSession(referenceOrUuid, options)
            : printSessions(options),
      ),
    );
}
