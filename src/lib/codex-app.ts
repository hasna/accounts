import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const FILE_CREDENTIALS_LINE = 'cli_auth_credentials_store = "file"';
const CREDENTIALS_STORE_RE = /^\s*cli_auth_credentials_store\s*=/;
const TABLE_HEADER_RE = /^\s*(?:\[[^\]\r\n]+\]|\[\[[^\]\r\n]+\]\])\s*(?:#.*)?$/;

function insertRootConfigLine(config: string): string {
  if (config.trim() === "") return `${FILE_CREDENTIALS_LINE}\n`;
  const lines = config.split(/\r?\n/);
  const tableIndex = lines.findIndex((entry) => TABLE_HEADER_RE.test(entry));
  if (tableIndex === -1) return `${config.trimEnd()}\n\n${FILE_CREDENTIALS_LINE}\n`;

  const before = lines.slice(0, tableIndex).join("\n").trimEnd();
  const after = lines.slice(tableIndex).join("\n").trimStart();
  return `${before}${before ? "\n\n" : ""}${FILE_CREDENTIALS_LINE}\n\n${after}${after.endsWith("\n") ? "" : "\n"}`;
}

function ensureTrailingNewline(config: string): string {
  return config.endsWith("\n") ? config : `${config}\n`;
}

function upsertRootCredentialsStore(config: string): string {
  const lines = config.split(/\r?\n/);
  const tableIndex = lines.findIndex((entry) => TABLE_HEADER_RE.test(entry));
  const rootEnd = tableIndex === -1 ? lines.length : tableIndex;
  let found = false;
  const next: string[] = [];

  for (const [index, line] of lines.entries()) {
    if (index < rootEnd && CREDENTIALS_STORE_RE.test(line)) {
      if (!found) next.push(FILE_CREDENTIALS_LINE);
      found = true;
    } else {
      next.push(line);
    }
  }

  return found ? ensureTrailingNewline(next.join("\n")) : insertRootConfigLine(config);
}

export function ensureCodexAppProfileConfig(profileDir: string): void {
  mkdirSync(profileDir, { recursive: true });
  const configPath = join(profileDir, "config.toml");
  const current = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const next = upsertRootCredentialsStore(current);
  if (next === current) return;
  writeFileSync(configPath, next, { mode: 0o600 });
}
