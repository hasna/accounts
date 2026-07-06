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

function runEventsEmit(data: string) {
  const root = mkdtempSync(join(tmpdir(), "accounts-events-"));
  try {
    return Bun.spawnSync({
      cmd: ["bun", "run", "src/cli.ts", "events", "emit", "accounts.test", "--data", data, "--json"],
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

  test("events emit rejects invalid actor_ref-shaped fields", () => {
    const result = runEventsEmit(JSON.stringify({ actor: { id: "actor_bad", kind: "robot" } }));
    const stderr = text(result.stderr);

    expect(result.exitCode).not.toBe(0);
    expect(stderr).toContain("Contract validation failed for hasna.actor_ref.v1");
  });

  test("events emit accepts ordinary scalar actor fields", () => {
    const result = runEventsEmit(JSON.stringify({ actor: "alice" }));

    expect(result.exitCode).toBe(0);
  });
});
