import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function runHelp() {
  const root = mkdtempSync(join(tmpdir(), "accounts-events-"));
  try {
    return Bun.spawnSync({
      cmd: ["bun", "run", "src/cli.ts", "--help"],
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        HASNA_ACCOUNTS_HOME: join(root, "accounts"),
        HASNA_EVENTS_DIR: join(root, "events"),
      },
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function text(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf-8");
}

describe("accounts events CLI", () => {
  test("help exposes shared events and webhooks commands", () => {
    const result = runHelp();
    const stdout = text(result.stdout);

    expect(result.exitCode).toBe(0);
    expect(stdout).toContain("events");
    expect(stdout).toContain("webhooks");
  });
});
