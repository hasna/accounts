import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Test support: a REAL live process attributable to a Claude config dir.
 *
 * Since the machine-shared session registry (lib/claude-session-registry.ts),
 * a profile dir's `sessions/` is a symlink to one machine-level directory, so
 * a bare `<pid>.json` no longer says WHICH config dir the session runs under.
 * `listDirLiveSessions` attributes a live entry by reading the process's
 * `CLAUDE_CONFIG_DIR` from `/proc/<pid>/environ`. A test that wrote its own
 * `process.pid` — whose environ points nowhere near the profile dir — would
 * therefore see the entry (correctly) attributed away and the guard not fire.
 *
 * This spawns a short-lived real child holding `CLAUDE_CONFIG_DIR=<configDir>`
 * and writes its pid into the dir's registry, so a guard reading the real
 * `/proc` attributes it to that dir exactly as it would a real `accounts
 * launch <profile>` Claude process. The caller MUST `stop()` it (e.g. in
 * `afterEach`).
 */
export interface LiveClaudeSession {
  pid: number;
  stop: () => void;
}

export function attachLiveClaudeSession(
  configDir: string,
  record: Record<string, unknown> = {},
): LiveClaudeSession {
  const child = Bun.spawn(["sleep", "120"], {
    env: { ...process.env, CLAUDE_CONFIG_DIR: configDir },
    stdout: "ignore",
    stderr: "ignore",
  });
  const pid = child.pid;
  const sessionsDir = join(configDir, "sessions");
  // Resolves through the shared-registry symlink when the dir is linked; a
  // plain mkdir when a test deliberately keeps a real per-profile dir.
  mkdirSync(sessionsDir, { recursive: true });
  writeFileSync(join(sessionsDir, `${pid}.json`), JSON.stringify({ pid, ...record }));
  // Give the child a beat to exec so its /proc/<pid>/environ is populated
  // before the code under test reads it.
  Bun.spawnSync(["sh", "-c", `for i in 1 2 3 4 5 6 7 8 9 10; do [ -r /proc/${pid}/environ ] && grep -qa CLAUDE_CONFIG_DIR= /proc/${pid}/environ && exit 0; sleep 0.02; done`]);
  return {
    pid,
    stop: () => {
      try {
        child.kill();
      } catch {
        // already gone
      }
    },
  };
}
