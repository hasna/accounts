import { afterEach, beforeEach, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { addProfile } from "./lib/profiles.js";
import {
  accountsHome,
  loadAppliedMap,
  loadCurrentMap,
  loadMachineStore,
  loadStore,
  profilesDir,
  reconcileMachineProfileRemove,
  reconcileMachineProfileRename,
  saveStore,
  storePath,
  withStoreLock,
} from "./storage.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-storage-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
  delete process.env.ACCOUNTS_TEST_PROCESS_START_ID;
});

test("local path helpers resolve under ACCOUNTS_HOME", () => {
  expect(accountsHome()).toBe(home);
  expect(storePath()).toBe(join(home, "accounts.json"));
  expect(profilesDir()).toBe(join(home, "profiles"));
});

test("loadStore returns an empty store before anything is written", () => {
  const store = loadStore();
  expect(store.profiles).toEqual([]);
  expect(existsSync(storePath())).toBe(false);
});

test("saveStore/loadStore round-trips the registry", () => {
  addProfile({ name: "work", tool: "claude", email: "work@example.test" });
  const store = loadStore();
  expect(store.profiles[0]?.name).toBe("work");
  expect(store.profiles[0]?.email).toBe("work@example.test");

  store.profiles.push({ name: "home", tool: "claude", dir: join(home, "profiles/claude/home"), createdAt: new Date().toISOString() });
  saveStore(store);
  expect(loadStore().profiles.map((p) => p.name).sort()).toEqual(["home", "work"]);
});

test("a stale local writer cannot erase a newer registry generation", () => {
  addProfile({ name: "work", tool: "claude", email: "before@example.test" });
  const stale = loadMachineStore();
  const newer = loadMachineStore();
  newer.current.claude = "work";
  newer.currentRevisions.claude = "newer-generation";
  saveStore(newer);
  stale.profiles[0]!.email = "stale@example.test";

  expect(() => saveStore(stale)).toThrow(/changed concurrently/);
  expect(loadMachineStore().currentRevisions.claude).toBe("newer-generation");
  expect(loadMachineStore().profiles[0]!.email).toBe("before@example.test");
});

test("saveStore reclaims a registry lock whose owning process is gone", () => {
  const lock = join(accountsHome(), ".store.lock");
  writeFileSync(lock, "999999999\n", { mode: 0o600 });

  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });

  expect(existsSync(lock)).toBe(false);
  expect(loadMachineStore().version).toBe(1);
});

test("an unverifiable same-PID lock fails closed instead of stealing across module isolates", () => {
  const lock = join(accountsHome(), ".store.lock");
  writeFileSync(lock, `${process.pid}:old-process-token\n`, { mode: 0o600 });

  expect(() => withStoreLock(() => "unsafe", 50)).toThrow(/timed out waiting/);

  expect(existsSync(lock)).toBe(true);
});

test("registry lock timeout is checked before every acquisition attempt", () => {
  expect(() => withStoreLock(() => "unsafe", 0)).toThrow(/timed out waiting/);
  expect(existsSync(join(accountsHome(), ".store.lock"))).toBe(false);
});

test("registry acquisition never enters through an inode removed during initialization", async () => {
  const trace = join(home, "initialization-trace.txt");
  const marker = join(home, "initialization-paused.txt");
  const storageUrl = pathToFileURL(join(process.cwd(), "src/storage.ts")).href;
  const source = `
    import { appendFileSync } from "node:fs";
    import { withStoreLock } from ${JSON.stringify(storageUrl)};
    withStoreLock(() => {
      appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "enter:" + process.pid + "\\n");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.ACCOUNTS_LOCK_HOLD_MS));
      appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "exit:" + process.pid + "\\n");
    });
  `;
  const first = spawn(process.execPath, ["-e", source], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      ACCOUNTS_LOCK_TRACE: trace,
      ACCOUNTS_LOCK_HOLD_MS: "400",
      ACCOUNTS_TEST_STORE_LOCK_INIT_DELAY_MS: "1300",
      ACCOUNTS_TEST_STORE_LOCK_INIT_MARKER: marker,
    },
    stdio: "pipe",
  });
  for (let attempt = 0; attempt < 200 && !existsSync(marker); attempt += 1) await Bun.sleep(5);
  expect(existsSync(marker)).toBe(true);
  const second = spawn(process.execPath, ["-e", source], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ACCOUNTS_HOME: home,
      ACCOUNTS_LOCK_TRACE: trace,
      ACCOUNTS_LOCK_HOLD_MS: "400",
    },
    stdio: "pipe",
  });
  const exits = await Promise.all([first, second].map((worker) => new Promise<number | null>((resolve) => {
    worker.once("exit", resolve);
  })));
  expect(exits).toEqual([0, 0]);
  let active = 0;
  let maximumActive = 0;
  for (const line of readFileSync(trace, "utf8").trim().split("\n")) {
    active += line.startsWith("enter:") ? 1 : -1;
    maximumActive = Math.max(maximumActive, active);
  }
  expect(active).toBe(0);
  expect(maximumActive).toBe(1);
  expect(readdirSync(home).filter((name) => name.startsWith(".store.lock"))).toEqual([]);
});

test("registry acquisition reclaims a live reused PID with a different portable incarnation", () => {
  const child = spawn(process.execPath, ["-e", "await Bun.sleep(10_000)"], { stdio: "ignore" });
  if (!child.pid) throw new Error("test child did not expose a pid");
  const lock = join(accountsHome(), ".store.lock");
  writeFileSync(lock, `v2:${child.pid}:darwin-old-process-start:old-token\n`, { mode: 0o600 });
  process.env.ACCOUNTS_TEST_PROCESS_START_ID = `${child.pid}:darwin-new-process-start`;
  try {
    expect(withStoreLock(() => "acquired", 100)).toBe("acquired");
  } finally {
    child.kill("SIGKILL");
  }
  expect(existsSync(lock)).toBe(false);
});

test.skipIf(process.platform !== "darwin")(
  "macOS observers in different timezones never reclaim one live registry lock",
  async () => {
    const marker = join(home, "timezone-owner-ready.txt");
    const trace = join(home, "timezone-lock-trace.txt");
    const storageUrl = pathToFileURL(join(process.cwd(), "src/storage.ts")).href;
    const ownerSource = `
      import { appendFileSync, writeFileSync } from "node:fs";
      import { withStoreLock } from ${JSON.stringify(storageUrl)};
      withStoreLock(() => {
        appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "owner-enter\\n");
        writeFileSync(process.env.ACCOUNTS_LOCK_MARKER, "ready\\n");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
        appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "owner-exit\\n");
      });
    `;
    const observerSource = `
      import { appendFileSync } from "node:fs";
      import { withStoreLock } from ${JSON.stringify(storageUrl)};
      try {
        withStoreLock(() => appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "observer-enter\\n"), 100);
        process.exit(42);
      } catch (error) {
        if (!String(error).includes("timed out waiting")) throw error;
      }
    `;
    const owner = spawn(process.execPath, ["-e", ownerSource], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        TZ: "America/Los_Angeles",
        ACCOUNTS_HOME: home,
        ACCOUNTS_LOCK_MARKER: marker,
        ACCOUNTS_LOCK_TRACE: trace,
      },
      stdio: "pipe",
    });
    for (let attempt = 0; attempt < 200 && !existsSync(marker); attempt += 1) await Bun.sleep(5);
    expect(existsSync(marker)).toBe(true);
    const observer = spawnSync(process.execPath, ["-e", observerSource], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        TZ: "Asia/Tokyo",
        ACCOUNTS_HOME: home,
        ACCOUNTS_LOCK_TRACE: trace,
      },
      encoding: "utf8",
    });
    const ownerExit = await new Promise<number | null>((resolve) => owner.once("exit", resolve));
    expect(observer.status).toBe(0);
    expect(ownerExit).toBe(0);
    expect(readFileSync(trace, "utf8").trim().split("\n")).toEqual(["owner-enter", "owner-exit"]);
  },
);

test("saveStore reclaims an abandoned stale-lock claim", async () => {
  const lock = join(accountsHome(), ".store.lock");
  const text = "999999999\n";
  writeFileSync(lock, text, { mode: 0o600 });
  const stat = statSync(lock);
  const claimHash = createHash("sha256")
    .update(`${stat.dev}:${stat.ino}:`)
    .update(text)
    .digest("hex")
    .slice(0, 24);
  const claim = `${lock}.reclaim-${claimHash}`;
  linkSync(lock, claim);
  await Bun.sleep(1_100);

  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });

  expect(existsSync(lock)).toBe(false);
  expect(existsSync(claim)).toBe(false);
});

test("concurrent stale-lock reclaimers never overlap their critical sections", async () => {
  const lock = join(accountsHome(), ".store.lock");
  const trace = join(accountsHome(), "lock-trace.txt");
  writeFileSync(lock, "999999999\n", { mode: 0o600 });
  const storageUrl = pathToFileURL(join(process.cwd(), "src/storage.ts")).href;
  const source = `
    import { appendFileSync } from "node:fs";
    import { withStoreLock } from ${JSON.stringify(storageUrl)};
    withStoreLock(() => {
      appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "enter:" + process.pid + "\\n");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      appendFileSync(process.env.ACCOUNTS_LOCK_TRACE, "exit:" + process.pid + "\\n");
    });
  `;
  const workers = Array.from({ length: 8 }, () => spawn(process.execPath, ["-e", source], {
    cwd: process.cwd(),
    env: { ...process.env, ACCOUNTS_HOME: home, ACCOUNTS_LOCK_TRACE: trace },
    stdio: "pipe",
  }));
  const results = await Promise.all(workers.map((worker) => new Promise<number | null>((resolve) => {
    worker.once("exit", (code) => resolve(code));
  })));
  expect(results).toEqual(Array(8).fill(0));
  let active = 0;
  for (const line of readFileSync(trace, "utf8").trim().split("\n")) {
    active += line.startsWith("enter:") ? 1 : -1;
    expect(active).toBeGreaterThanOrEqual(0);
    expect(active).toBeLessThanOrEqual(1);
  }
  expect(active).toBe(0);
  expect(existsSync(lock)).toBe(false);
});

test("raw machine pointers survive cloud-only profiles and reconcile rename/remove", () => {
  saveStore({
    version: 1,
    current: { acme: "old" },
    applied: { acme: "old" },
    toolLocks: { old: "acme" },
    profiles: [],
    tools: [],
  });
  expect(loadCurrentMap()).toEqual({ acme: "old" });
  expect(loadAppliedMap()).toEqual({ acme: "old" });
  expect(loadStore().current).toEqual({});

  reconcileMachineProfileRename("acme", "old", "new");
  expect(loadMachineStore().current).toEqual({ acme: "new" });
  expect(loadMachineStore().applied).toEqual({ acme: "new" });
  expect(loadMachineStore().toolLocks).toEqual({ new: "acme" });

  reconcileMachineProfileRemove("acme", "new");
  expect(loadMachineStore().current).toEqual({});
  expect(loadMachineStore().applied).toEqual({});
  expect(loadMachineStore().toolLocks).toEqual({});
});

test("machine pointer reconciliation reads after acquiring the registry lock", async () => {
  saveStore({
    version: 1,
    current: { claude: "old" },
    applied: { claude: "old" },
    toolLocks: { old: "claude" },
    profiles: [{
      name: "old",
      tool: "claude",
      dir: join(home, "profiles/claude/old"),
      createdAt: new Date(0).toISOString(),
    }],
    tools: [],
  });
  const marker = join(home, "reconcile-lock-held");
  const storageUrl = pathToFileURL(join(process.cwd(), "src/storage.ts")).href;
  const source = `
    import { writeFileSync } from "node:fs";
    import { withStoreLock, loadMachineStore, saveStore } from ${JSON.stringify(storageUrl)};
    withStoreLock(() => {
      const store = loadMachineStore();
      writeFileSync(process.env.ACCOUNTS_LOCK_MARKER, "held");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
      store.profiles[0].description = "concurrent edit";
      saveStore(store);
    });
  `;
  const worker = spawn(process.execPath, ["-e", source], {
    cwd: process.cwd(),
    env: { ...process.env, ACCOUNTS_HOME: home, ACCOUNTS_LOCK_MARKER: marker },
    stdio: "pipe",
  });
  const workerExit = new Promise<number | null>((resolve) => worker.once("exit", resolve));
  for (let attempt = 0; attempt < 100 && !existsSync(marker); attempt += 1) await Bun.sleep(5);
  expect(existsSync(marker)).toBe(true);

  reconcileMachineProfileRename("claude", "old", "new");
  expect(await workerExit).toBe(0);
  expect(loadMachineStore()).toMatchObject({
    current: { claude: "new" },
    applied: { claude: "new" },
    toolLocks: { new: "claude" },
    profiles: [{ description: "concurrent edit" }],
  });

  reconcileMachineProfileRemove("claude", "new");
  expect(loadMachineStore()).toMatchObject({
    current: {},
    applied: {},
    toolLocks: {},
    profiles: [{ description: "concurrent edit" }],
  });
});

test("saveStore atomically replaces the registry without leaving temp files", () => {
  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });
  saveStore({ version: 1, current: {}, applied: {}, toolLocks: {}, profiles: [], tools: [] });
  expect(JSON.parse(readFileSync(storePath(), "utf8")).version).toBe(1);
  expect(readdirSync(accountsHome()).filter((name) => name.endsWith(".tmp"))).toEqual([]);
});

function runCli(env: Record<string, string>, ...args: string[]) {
  return spawnSync(process.execPath, ["run", "src/cli.ts", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ACCOUNTS_HOME: home, ...env },
  });
}

test("the legacy storage command group is a fail-explicit compatibility shim", () => {
  const result = runCli({}, "storage", "status");
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("legacy provider-backed sync is retired");
  for (const operation of ["push", "pull", "sync"]) {
    for (const args of [[operation], [operation, "--json"]]) {
      const retired = runCli({}, "storage", ...args);
      expect(retired.status).not.toBe(0);
      expect(retired.stderr).toContain("legacy storage sync was retired");
      expect(retired.stderr).not.toContain("unknown option");
    }
  }
});

// Regression: a machine still carrying a stale S3-era storage-mode word must not
// crash — the legacy value is ignored and the client stays local.
for (const legacy of ["remote", "hybrid", "s3"]) {
  test(`stale HASNA_ACCOUNTS_STORAGE_MODE=${legacy} does not crash registry commands`, () => {
    const result = runCli(
      { HASNA_ACCOUNTS_STORAGE_MODE: legacy, ACCOUNTS_STORAGE_MODE: legacy },
      "list",
      "--json",
    );
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain("Unknown storage mode");
    expect(result.stderr).not.toContain("misconfigured");
  });
}

for (const mode of ["cloud", "self_hosted"]) {
  test(`explicit ${mode} CLI mode fails closed without API configuration`, () => {
    const result = runCli(
      {
        HASNA_ACCOUNTS_STORAGE_MODE: mode,
        HASNA_ACCOUNTS_API_URL: "",
        HASNA_ACCOUNTS_API_KEY: "",
      },
      "list",
      "--json",
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`${mode} storage mode requires HASNA_ACCOUNTS_API_URL and HASNA_ACCOUNTS_API_KEY`);
    expect(existsSync(storePath())).toBe(false);
  });
}

test("unknown CLI storage modes fail validation instead of falling back", () => {
  const result = runCli({ HASNA_ACCOUNTS_STORAGE_MODE: "typo" }, "list", "--json");
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("invalid accounts storage mode");
  expect(existsSync(storePath())).toBe(false);
});
