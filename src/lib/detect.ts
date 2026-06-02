import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ToolDef } from "../types.js";

/**
 * Best-effort: read the account email a tool stored inside its config dir.
 * For Claude Code this is `<dir>/.claude.json` -> oauthAccount.emailAddress.
 * Returns undefined when the file/field is missing or unreadable.
 */
export function detectEmail(dir: string, tool: ToolDef): string | undefined {
  if (!tool.accountFile || !tool.emailPath) return undefined;
  const file = join(dir, tool.accountFile);
  if (!existsSync(file)) return undefined;
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
  let cursor: unknown = data;
  for (const key of tool.emailPath) {
    if (cursor && typeof cursor === "object" && key in (cursor as Record<string, unknown>)) {
      cursor = (cursor as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return typeof cursor === "string" && cursor.includes("@") ? cursor : undefined;
}
