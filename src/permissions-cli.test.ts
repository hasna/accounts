import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-permissions-cli-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function runCli(...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      HASNA_ACCOUNTS_STORAGE_MODE: "local",
      HASNA_ACCOUNTS_API_URL: "",
      HASNA_ACCOUNTS_API_KEY: "",
    },
  });
}

function writeManifest(dir: string, tool: string, profile: string) {
  mkdirSync(join(dir, ".hasna"), { recursive: true });
  writeFileSync(
    join(dir, ".hasna", "session-render-manifest.json"),
    JSON.stringify(
      {
        schema: "hasna.configs.session-render/v1",
        tool,
        profile,
        targetHome: dir,
        generatedAt: "2026-07-01T00:00:00.000Z",
        sources: [{ id: "global-codewith" }, { id: "agent-marcus" }],
        files: [],
      },
      null,
      2,
    ) + "\n",
  );
}

test("switch CLI accepts --permissions and returns tool-specific command args", () => {
  const add = runCli("add", "codexer", "--tool", "codex");
  expect(add.status).toBe(0);

  const result = runCli("switch", "codexer", "--tool", "codex", "--resume", "--permissions", "dangerous", "--json");
  expect(result.status).toBe(0);

  const parsed = JSON.parse(result.stdout) as { command: string[]; permissions?: string };
  expect(parsed.permissions).toBe("dangerous");
  expect(parsed.command).toEqual(["codex", "--dangerously-bypass-approvals-and-sandbox", "resume", "--last"]);
});

test("profile metadata can be added, shown, and updated through the CLI", () => {
  const add = runCli(
    "add",
    "account001",
    "--email",
    "owner@example.com",
    "--display-name",
    "Owner One",
    "--identity",
    "agent:owner-one",
    "--card-last4",
    "4242",
    "--metadata",
    "machine=spark02",
    "--metadata",
    "slot=1",
  );
  expect(add.status).toBe(0);

  const set = runCli("set", "account001", "--metadata", "source=manual", "--display-name", "Owner 1");
  expect(set.status).toBe(0);

  const show = runCli("show", "account001", "--json");
  expect(show.status).toBe(0);
  const profile = JSON.parse(show.stdout) as {
    email?: string;
    displayName?: string;
    identity?: string;
    cardLast4?: string;
    metadata?: Record<string, unknown>;
  };
  expect(profile.email).toBe("owner@example.com");
  expect(profile.displayName).toBe("Owner 1");
  expect(profile.identity).toBe("agent:owner-one");
  expect(profile.cardLast4).toBe("4242");
  expect(profile.metadata).toEqual({ machine: "spark02", slot: 1, source: "manual" });
});

test("CLI rejects invalid metadata updates without poisoning the store", () => {
  expect(runCli("add", "account001").status).toBe(0);

  const emptyName = runCli("set", "account001", "--display-name", "");
  expect(emptyName.status).not.toBe(0);
  expect(runCli("list").status).toBe(0);

  const reservedKey = runCli("set", "account001", "--metadata", "__proto__=null");
  expect(reservedKey.status).not.toBe(0);
  expect(runCli("list").status).toBe(0);
});

test("CLI does not coerce huge numeric-looking metadata values to null", () => {
  const huge = "9".repeat(400);
  const add = runCli("add", "account001", "--metadata", `huge=${huge}`);
  expect(add.status).toBe(0);

  const show = runCli("show", "account001", "--json");
  expect(show.status).toBe(0);
  const profile = JSON.parse(show.stdout) as { metadata?: Record<string, unknown> };
  expect(profile.metadata?.huge).toBe(huge);
});

test("list and show JSON expose bounded prelaunch manifest diagnostics", () => {
  const add = runCli("add", "account001", "--tool", "codewith", "--identity", "agent:marcus");
  expect(add.status).toBe(0);

  const missingShow = runCli("show", "account001", "--tool", "codewith", "--json");
  expect(missingShow.status).toBe(0);
  const missing = JSON.parse(missingShow.stdout) as { dir: string; active: boolean; applied: boolean; prelaunch: { status: string; manifest: { path: string; drift: string } } };
  expect(missing.active).toBe(false);
  expect(missing.applied).toBe(false);
  expect(missing.prelaunch.status).toBe("missing");
  expect(missing.prelaunch.manifest.drift).toBe("missing");
  expect(missing.prelaunch.manifest.path).toBe(join(missing.dir, ".hasna", "session-render-manifest.json"));

  writeManifest(missing.dir, "codewith", "account001");

  const show = runCli("show", "account001", "--tool", "codewith", "--json");
  expect(show.status).toBe(0);
  const profile = JSON.parse(show.stdout) as {
    prelaunch: {
      status: string;
      manifest: { hash?: string; generatedAt?: string; sourceCount: number; sourceIds: string[] };
    };
  };
  expect(profile.prelaunch.status).toBe("ok");
  expect(typeof profile.prelaunch.manifest.hash).toBe("string");
  expect(profile.prelaunch.manifest.generatedAt).toBe("2026-07-01T00:00:00.000Z");
  expect(profile.prelaunch.manifest.sourceCount).toBe(2);
  expect(profile.prelaunch.manifest.sourceIds).toEqual(["global-codewith", "agent-marcus"]);

  const list = runCli("list", "--tool", "codewith", "--json");
  expect(list.status).toBe(0);
  const profiles = JSON.parse(list.stdout) as Array<{ name: string; prelaunch?: { status: string; manifest: { sourceCount: number } } }>;
  expect(profiles.find((entry) => entry.name === "account001")?.prelaunch).toMatchObject({
    status: "ok",
    manifest: { sourceCount: 2 },
  });
});
