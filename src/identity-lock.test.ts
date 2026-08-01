import { test, expect } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AccountsError } from "./types.js";
import { withIdentityLock, withIdentityLockSync } from "./lib/identity-lock.js";

const UUID = "11111111-2222-4333-8444-555555555555";

function tempRoot(): string {
  return mkdtempSync(join(tmpdir(), "accounts-idlock-"));
}

test("the lock serializes two concurrent async sections", async () => {
  const root = tempRoot();
  try {
    const order: string[] = [];
    const first = withIdentityLock(
      UUID,
      async () => {
        order.push("first-start");
        await new Promise((r) => setTimeout(r, 150));
        order.push("first-end");
      },
      { root },
    );
    // Give the first acquire a head start so the contention is real.
    await new Promise((r) => setTimeout(r, 30));
    const second = withIdentityLock(
      UUID,
      async () => {
        order.push("second-start");
      },
      { root },
    );
    await Promise.all([first, second]);
    expect(order).toEqual(["first-start", "first-end", "second-start"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a lock whose owner pid is dead is broken and acquired", () => {
  const root = tempRoot();
  try {
    const lockDir = join(root, `identity-${UUID}.lock`);
    mkdirSync(lockDir, { recursive: true });
    writeFileSync(
      join(lockDir, "owner.json"),
      JSON.stringify({ pid: 2 ** 30, host: hostname(), acquiredAt: new Date().toISOString(), token: "t" }),
    );
    let ran = false;
    withIdentityLockSync(UUID, () => {
      ran = true;
    }, { root, timeoutMs: 2_000 });
    expect(ran).toBe(true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a lock held by a LIVE process is respected until timeout", () => {
  const root = tempRoot();
  try {
    const lockDir = join(root, `identity-${UUID}.lock`);
    mkdirSync(lockDir, { recursive: true });
    writeFileSync(
      join(lockDir, "owner.json"),
      JSON.stringify({ pid: process.pid, host: hostname(), acquiredAt: new Date().toISOString(), token: "t" }),
    );
    expect(() =>
      withIdentityLockSync(UUID, () => undefined, { root, timeoutMs: 250, staleMs: 60_000 }),
    ).toThrow(AccountsError);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a stale lock (age past staleMs) is broken even when the pid cannot be judged dead", () => {
  const root = tempRoot();
  try {
    const lockDir = join(root, `identity-${UUID}.lock`);
    mkdirSync(lockDir, { recursive: true });
    // A live pid on ANOTHER host: unprobeable, so only age can break it.
    writeFileSync(
      join(lockDir, "owner.json"),
      JSON.stringify({
        pid: process.pid,
        host: "some-other-host",
        acquiredAt: new Date(Date.now() - 10 * 60_000).toISOString(),
        token: "t",
      }),
    );
    let ran = false;
    withIdentityLockSync(UUID, () => {
      ran = true;
    }, { root, timeoutMs: 2_000, staleMs: 120_000 });
    expect(ran).toBe(true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a malformed uuid is refused before touching the filesystem", () => {
  expect(() => withIdentityLockSync("../../evil", () => undefined, { root: "/nonexistent-root" })).toThrow(
    AccountsError,
  );
});
