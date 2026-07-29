import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { accountsHome } from "../storage.js";
import { profileNameSchema } from "../types.js";

const HOOK_FILE = "claude-hook.sh";
const MARKER = "# accounts-claude-hook";
const NAME_PATTERN = "^[a-z0-9][a-z0-9-]*$";

/** Single-quote a path for safe shell interpolation. */
export function shellQuotePath(path: string): string {
  return `'${path.replace(/'/g, `'\\''`)}'`;
}

export function hookPath(): string {
  return join(accountsHome(), HOOK_FILE);
}

export function hookScript(): string {
  const quotedHook = shellQuotePath(hookPath());
  return `#!/usr/bin/env bash
${MARKER}
# Source from ~/.zshrc:  source ${quotedHook}
claude() {
  local _bin
  _bin="$(command -v claude 2>/dev/null | head -1)"
  if [[ -z "$_bin" ]]; then
    echo "accounts hook: claude binary not found" >&2
    return 127
  fi
  if command -v accounts >/dev/null 2>&1; then
    local _profile _applied
    _profile="$(accounts active claude 2>/dev/null || true)"
    _applied="$(accounts applied claude 2>/dev/null || true)"
    if [[ -n "$_profile" && "$_profile" =~ ${NAME_PATTERN} && "$_profile" != "$_applied" ]]; then
      if ! accounts apply "$_profile" >&2; then
        echo "accounts hook: warning — could not apply profile $_profile" >&2
      fi
    fi
  fi
  command env -u BUN_CONFIG_VERBOSE_FETCH -u NODE_DEBUG -u NODE_DEBUG_NATIVE "$_bin" "$@"
}
`;
}

export function installHook(): { path: string; created: boolean } {
  const path = hookPath();
  mkdirSync(accountsHome(), { recursive: true });
  const created = !existsSync(path);
  writeFileSync(path, hookScript(), { mode: 0o755 });
  return { path, created };
}

export function uninstallHook(): boolean {
  const path = hookPath();
  if (!existsSync(path)) return false;
  const content = readFileSync(path, "utf8");
  if (!content.includes(MARKER)) return false;
  unlinkSync(path);
  return true;
}

export function shellSnippet(): string {
  return `source ${shellQuotePath(hookPath())}`;
}

/** Validate a profile name is safe for shell interpolation. */
export function isSafeProfileName(name: string): boolean {
  return profileNameSchema.safeParse(name).success;
}
