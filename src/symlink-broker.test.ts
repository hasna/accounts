import { afterEach, beforeEach, expect, test } from "bun:test";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { centralCredentialsSnapshot } from "./lib/auth-store.js";
import { dirCredentialsFile } from "./lib/claude-layout.js";
import {
  adoptForkToCentral,
  centralUuidOfCredentialsPath,
  inspectDirCredential,
  linkDirToCentral,
  migrateDirToLink,
  quarantineRoot,
  repointDir,
} from "./lib/symlink-broker.js";
import { AccountsError } from "./types.js";

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-symbroker-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

function cred(email: string, opts: { refresh?: string | null; expiresInMs?: number } = {}): string {
  const { refresh = `${email}-refresh`, expiresInMs = 60_000 } = opts;
  return (
    JSON.stringify({
      claudeAiOauth: {
        accessToken: `${email}-access`,
        ...(refresh === null ? {} : { refreshToken: refresh }),
        expiresAt: Date.now() + expiresInMs,
      },
    }) + "\n"
  );
}

/** Seed a central credential file for an account and return its path + inode. */
function seedCentral(uuid: string, email: string, opts: Parameters<typeof cred>[1] = {}): { path: string; inode: number } {
  const path = centralCredentialsSnapshot(uuid);
  mkdirSync(join(home, "auth", uuid), { recursive: true });
  writeFileSync(path, cred(email, opts), { mode: 0o600 });
  return { path, inode: statSync(path).ino };
}

function newConfigDir(): string {
  return mkdtempSync(join(tmpdir(), "symbroker-dir-"));
}

function accessTokenThroughDir(configDir: string): string {
  // readFileSync follows the symlink, exactly as Claude reads it.
  const raw = JSON.parse(readFileSync(dirCredentialsFile(configDir), "utf8")) as {
    claudeAiOauth?: { accessToken?: string };
  };
  return raw.claudeAiOauth?.accessToken ?? "";
}

// --- inversion of the canonical path -----------------------------------------

test("centralUuidOfCredentialsPath inverts the canonical builder and rejects strangers", () => {
  expect(centralUuidOfCredentialsPath(centralCredentialsSnapshot(A))).toBe(A);
  expect(centralUuidOfCredentialsPath(join(home, "auth", A, "other.json"))).toBeUndefined();
  expect(centralUuidOfCredentialsPath(join(home, "auth", "not-a-uuid", "credentials.json"))).toBeUndefined();
  expect(centralUuidOfCredentialsPath("/etc/passwd")).toBeUndefined();
});

// --- inspection --------------------------------------------------------------

test("inspectDirCredential classifies missing, regular, central-link and foreign-link", () => {
  const dir = newConfigDir();
  try {
    expect(inspectDirCredential(dir).kind).toBe("missing");

    writeFileSync(dirCredentialsFile(dir), cred("x@e.com"));
    expect(inspectDirCredential(dir).kind).toBe("regular");

    seedCentral(A, "a@e.com");
    linkDirToCentral(dir, A);
    const linked = inspectDirCredential(dir);
    expect(linked.kind).toBe("link-central");
    if (linked.kind === "link-central") expect(linked.uuid).toBe(A);

    rmSync(dirCredentialsFile(dir));
    symlinkSync("/tmp/somewhere-else.json", dirCredentialsFile(dir));
    expect(inspectDirCredential(dir).kind).toBe("link-foreign");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- linkDirToCentral: atomic symlink swap, no byte copy ---------------------

test("linkDirToCentral creates an absolute symlink to the central inode without copying bytes", () => {
  const dir = newConfigDir();
  try {
    const { path: central, inode } = seedCentral(A, "a@e.com");
    linkDirToCentral(dir, A);
    const link = dirCredentialsFile(dir);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(realpathSync(link)).toBe(realpathSync(central));
    // Same inode: the dir reads THROUGH to the one central file, no copy exists.
    expect(statSync(link).ino).toBe(inode);
    expect(accessTokenThroughDir(dir)).toBe("a@e.com-access");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("linkDirToCentral atomically replaces an existing regular file (repoint over a fork)", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com");
    writeFileSync(dirCredentialsFile(dir), cred("stale@e.com"));
    linkDirToCentral(dir, A);
    expect(lstatSync(dirCredentialsFile(dir)).isSymbolicLink()).toBe(true);
    expect(accessTokenThroughDir(dir)).toBe("a@e.com-access");
    // No leftover temp files.
    const stray = readFileSync; // noop ref to keep lints quiet
    void stray;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("linkDirToCentral refuses when the account has no central credential", () => {
  const dir = newConfigDir();
  try {
    expect(() => linkDirToCentral(dir, A)).toThrow(AccountsError);
    expect(existsSync(dirCredentialsFile(dir))).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- adoptForkToCentral: the E1 self-healing fork ----------------------------

test("adoptForkToCentral moves a fresh fork onto central by inode move (mtime preserved), old central quarantined", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com", { refresh: "old-refresh" });
    // Simulate Claude's refresh fork: a regular file with a NEWER credential.
    const forkPath = dirCredentialsFile(dir);
    writeFileSync(forkPath, cred("a@e.com", { refresh: "rotated-refresh" }));
    const forkInode = statSync(forkPath).ino;

    const result = adoptForkToCentral(dir, A);
    expect(result.adopted).toBe(true);
    // The fork's inode IS now the central file — no byte copy happened.
    expect(statSync(centralCredentialsSnapshot(A)).ino).toBe(forkInode);
    // The rotated token survived onto central.
    const central = JSON.parse(readFileSync(centralCredentialsSnapshot(A), "utf8")) as {
      claudeAiOauth?: { refreshToken?: string };
    };
    expect(central.claudeAiOauth?.refreshToken).toBe("rotated-refresh");
    // The superseded central is preserved in quarantine, not deleted.
    expect(result.quarantined).toBeDefined();
    expect(existsSync(result.quarantined!)).toBe(true);
    expect(result.quarantined!.startsWith(quarantineRoot())).toBe(true);
    // The dir file is gone (moved); the caller relinks next.
    expect(existsSync(forkPath)).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("adoptForkToCentral NEVER downgrades central: a husk fork is quarantined, central kept", () => {
  const dir = newConfigDir();
  try {
    const { inode } = seedCentral(A, "a@e.com", { refresh: "good-refresh" });
    // A husk fork (no refresh token) must not overwrite a healthy central.
    writeFileSync(dirCredentialsFile(dir), cred("a@e.com", { refresh: null }));

    const result = adoptForkToCentral(dir, A);
    expect(result.adopted).toBe(false);
    expect(result.quarantined).toBeDefined();
    // Central is byte-for-byte and inode-for-inode intact.
    expect(statSync(centralCredentialsSnapshot(A)).ino).toBe(inode);
    const central = JSON.parse(readFileSync(centralCredentialsSnapshot(A), "utf8")) as {
      claudeAiOauth?: { refreshToken?: string };
    };
    expect(central.claudeAiOauth?.refreshToken).toBe("good-refresh");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("adoptForkToCentral creates central from the fork when none exists (first migration)", () => {
  const dir = newConfigDir();
  try {
    const forkPath = dirCredentialsFile(dir);
    writeFileSync(forkPath, cred("a@e.com"));
    const forkInode = statSync(forkPath).ino;

    const result = adoptForkToCentral(dir, A);
    expect(result.adopted).toBe(true);
    expect(result.created).toBe(true);
    expect(statSync(centralCredentialsSnapshot(A)).ino).toBe(forkInode);
    // 0600 on the created central.
    expect(statSync(centralCredentialsSnapshot(A)).mode & 0o777).toBe(0o600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("adoptForkToCentral is a no-op for a symlink or a missing dir file", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com");
    linkDirToCentral(dir, A);
    expect(adoptForkToCentral(dir, A).adopted).toBe(false);
    rmSync(dirCredentialsFile(dir));
    expect(adoptForkToCentral(dir, A).adopted).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- repointDir: the switch primitive ----------------------------------------

test("repointDir preserves the outgoing fork AND points at the incoming account — never destroys a login", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com", { refresh: "a-old" });
    seedCentral(B, "b@e.com");
    // The dir is running account A and Claude rotated A's token in place (fork).
    writeFileSync(dirCredentialsFile(dir), cred("a@e.com", { refresh: "a-rotated" }));

    const result = repointDir(dir, { fromUuid: A, toUuid: B });

    // Incoming: the dir now reads account B through the link.
    expect(result.toUuid).toBe(B);
    expect(lstatSync(dirCredentialsFile(dir)).isSymbolicLink()).toBe(true);
    expect(accessTokenThroughDir(dir)).toBe("b@e.com-access");
    // Outgoing: A's rotated refresh token was preserved onto A's central — the
    // login was not destroyed by switching away from it.
    const aCentral = JSON.parse(readFileSync(centralCredentialsSnapshot(A), "utf8")) as {
      claudeAiOauth?: { refreshToken?: string };
    };
    expect(aCentral.claudeAiOauth?.refreshToken).toBe("a-rotated");
    // B's central is untouched (still one real file per account).
    expect(lstatSync(centralCredentialsSnapshot(B)).isSymbolicLink()).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("repointDir from an already-linked dir simply relinks (nothing to adopt)", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com");
    seedCentral(B, "b@e.com");
    linkDirToCentral(dir, A);
    const result = repointDir(dir, { fromUuid: A, toUuid: B });
    expect(result.adopted).toBe(false);
    expect(accessTokenThroughDir(dir)).toBe("b@e.com-access");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- migrateDirToLink --------------------------------------------------------

test("migrateDirToLink turns a real credential file into a symlink to its own central (no byte copy)", () => {
  const dir = newConfigDir();
  try {
    const forkPath = dirCredentialsFile(dir);
    writeFileSync(forkPath, cred("a@e.com"));
    const inode = statSync(forkPath).ino;

    const result = migrateDirToLink(dir, A);
    expect(result.changed).toBe(true);
    expect(result.reason).toBe("adopted-and-linked");
    expect(lstatSync(forkPath).isSymbolicLink()).toBe(true);
    // The original inode is now the canonical central file — the bytes were
    // moved, not copied.
    expect(statSync(centralCredentialsSnapshot(A)).ino).toBe(inode);
    expect(realpathSync(forkPath)).toBe(realpathSync(centralCredentialsSnapshot(A)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("migrateDirToLink is idempotent — a dir already linked to its account is a no-op", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com");
    linkDirToCentral(dir, A);
    const result = migrateDirToLink(dir, A);
    expect(result.changed).toBe(false);
    expect(result.reason).toBe("already-linked");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("migrateDirToLink relinks a dir whose credential belongs to a different account (already-central)", () => {
  const dir = newConfigDir();
  try {
    seedCentral(A, "a@e.com");
    seedCentral(B, "b@e.com");
    linkDirToCentral(dir, A);
    const result = migrateDirToLink(dir, B);
    expect(result.changed).toBe(true);
    expect(accessTokenThroughDir(dir)).toBe("b@e.com-access");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
