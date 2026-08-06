import { afterEach, beforeEach, expect, test } from "bun:test";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

let root: string;
let accountsHome: string;
let configDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "accounts-migcli-"));
  accountsHome = join(root, "accounts");
  configDir = join(root, "cfg");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(
    join(configDir, ".claude.json"),
    JSON.stringify({ oauthAccount: { accountUuid: UUID, emailAddress: "c@e.com" } }),
  );
  writeFileSync(
    join(configDir, ".credentials.json"),
    JSON.stringify({ claudeAiOauth: { accessToken: "c-access", refreshToken: "c-refresh", expiresAt: Date.now() + 60_000 } }) + "\n",
  );
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

test("migrate-links --dir converts a real credential file into a central symlink (no byte copy)", () => {
  const proc = Bun.spawnSync({
    cmd: ["bun", "run", "src/cli.ts", "migrate-links", "--dir", configDir, "--json"],
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ACCOUNTS_HOME: accountsHome },
  });
  const stdout = proc.stdout.toString();
  expect(proc.exitCode).toBe(0);
  const parsed = JSON.parse(stdout) as { schema: string; results: Array<{ outcome: string; uuid?: string }> };
  expect(parsed.schema).toBe("hasna.accounts.migrate-links/v1");
  expect(parsed.results[0]?.outcome).toBe("migrated");
  expect(parsed.results[0]?.uuid).toBe(UUID);

  // The dir credential is now a symlink into the central store.
  const link = join(configDir, ".credentials.json");
  expect(lstatSync(link).isSymbolicLink()).toBe(true);
  const central = join(accountsHome, "auth", UUID, "credentials.json");
  expect(realpathSync(link)).toBe(realpathSync(central));
  const payload = JSON.parse(readFileSync(central, "utf8")) as { claudeAiOauth?: { refreshToken?: string } };
  expect(payload.claudeAiOauth?.refreshToken).toBe("c-refresh");
});

test("migrate-links --dir is idempotent on an already-linked dir", () => {
  const env = { ...process.env, ACCOUNTS_HOME: accountsHome };
  Bun.spawnSync({ cmd: ["bun", "run", "src/cli.ts", "migrate-links", "--dir", configDir, "--json"], stdout: "pipe", stderr: "pipe", env });
  const second = Bun.spawnSync({
    cmd: ["bun", "run", "src/cli.ts", "migrate-links", "--dir", configDir, "--json"],
    stdout: "pipe",
    stderr: "pipe",
    env,
  });
  expect(second.exitCode).toBe(0);
  const parsed = JSON.parse(second.stdout.toString()) as { results: Array<{ outcome: string }> };
  expect(parsed.results[0]?.outcome).toBe("already-linked");
});
