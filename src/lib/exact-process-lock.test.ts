import { afterEach, beforeEach, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  exactProcessLockHasLiveReclaimClaims,
  observeExactProcessLock,
  removeObservedExactProcessLock,
  setAfterExactProcessLockClaimForTest,
} from "./exact-process-lock.js";

let directory: string;

function claimPath(
  lockPath: string,
  pid: number,
  incarnation: string,
): string {
  return `${lockPath}.reclaim-v2-${pid}-${incarnation}-${randomUUID()}`;
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "accounts-exact-process-lock-test-"));
  delete process.env.ACCOUNTS_TEST_PROCESS_START_ID;
});

afterEach(() => {
  setAfterExactProcessLockClaimForTest(undefined);
  delete process.env.ACCOUNTS_TEST_PROCESS_START_ID;
  rmSync(directory, { recursive: true, force: true });
});

test("a reused PID with a different verifiable incarnation does not keep its reclaim alias live", () => {
  const lockPath = join(directory, "shared.lock");
  const token = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, token, { mode: 0o600 });
  const staleClaim = claimPath(lockPath, process.pid, "linux-old-incarnation");
  linkSync(lockPath, staleClaim);
  process.env.ACCOUNTS_TEST_PROCESS_START_ID =
    `${process.pid}:linux-reused-incarnation`;

  expect(exactProcessLockHasLiveReclaimClaims(lockPath)).toBe(false);
  expect(existsSync(staleClaim)).toBe(false);
});

test("the same live verifiable process incarnation fences its exact acquisition", () => {
  const lockPath = join(directory, "shared.lock");
  const token = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, token, { mode: 0o600 });
  const incarnation = "linux-current-incarnation";
  const liveClaim = claimPath(lockPath, process.pid, incarnation);
  linkSync(lockPath, liveClaim);
  process.env.ACCOUNTS_TEST_PROCESS_START_ID = `${process.pid}:${incarnation}`;

  expect(exactProcessLockHasLiveReclaimClaims(lockPath)).toBe(true);
  expect(existsSync(liveClaim)).toBe(true);
});

test("a live claim for an old acquisition does not fence removal of a replacement inode", () => {
  const lockPath = join(directory, "shared.lock");
  const oldToken = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, oldToken, { mode: 0o600 });
  const incarnation = "linux-current-incarnation";
  const oldClaim = claimPath(lockPath, process.pid, incarnation);
  linkSync(lockPath, oldClaim);
  unlinkSync(lockPath);

  const replacementToken = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, replacementToken, { mode: 0o600 });
  const replacement = observeExactProcessLock(lockPath, replacementToken);
  if (!replacement) throw new Error("replacement lock was not observable");
  process.env.ACCOUNTS_TEST_PROCESS_START_ID = `${process.pid}:${incarnation}`;

  expect(removeObservedExactProcessLock(replacement)).toBe(true);
  expect(existsSync(lockPath)).toBe(false);
  expect(readFileSync(oldClaim, "utf8")).toBe(oldToken);
});

test("cleanup leaves a dead unmatched acquisition claim untouched", () => {
  const lockPath = join(directory, "shared.lock");
  const oldToken = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, oldToken, { mode: 0o600 });
  const oldClaim = claimPath(
    lockPath,
    2_147_483_647,
    "linux-dead-incarnation",
  );
  linkSync(lockPath, oldClaim);
  unlinkSync(lockPath);

  const replacementToken = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, replacementToken, { mode: 0o600 });
  const replacement = observeExactProcessLock(lockPath, replacementToken);
  if (!replacement) throw new Error("replacement lock was not observable");

  expect(removeObservedExactProcessLock(replacement)).toBe(true);
  expect(existsSync(lockPath)).toBe(false);
  expect(lstatSync(oldClaim).isFile()).toBe(true);
  expect(readFileSync(oldClaim, "utf8")).toBe(oldToken);
});

test("a dead exact claim is cleaned without touching an unmatched live acquisition", () => {
  const lockPath = join(directory, "shared.lock");
  const deadToken = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, deadToken, { mode: 0o600 });
  const deadClaim = claimPath(
    lockPath,
    2_147_483_647,
    "linux-dead-incarnation",
  );
  linkSync(lockPath, deadClaim);
  unlinkSync(lockPath);

  const liveToken = `${process.pid}:${randomUUID()}`;
  const liveSource = join(directory, "live-source.lock");
  writeFileSync(liveSource, liveToken, { mode: 0o600 });
  const incarnation = "linux-current-incarnation";
  const liveClaim = claimPath(lockPath, process.pid, incarnation);
  linkSync(liveSource, liveClaim);
  unlinkSync(liveSource);
  process.env.ACCOUNTS_TEST_PROCESS_START_ID = `${process.pid}:${incarnation}`;

  expect(exactProcessLockHasLiveReclaimClaims(lockPath, deadToken)).toBe(false);
  expect(existsSync(deadClaim)).toBe(false);
  expect(readFileSync(liveClaim, "utf8")).toBe(liveToken);
});

test("a peer claim published concurrently prevents both deleters from reaching unlink", () => {
  const lockPath = join(directory, "shared.lock");
  const token = `${process.pid}:${randomUUID()}`;
  writeFileSync(lockPath, token, { mode: 0o600 });
  const observation = observeExactProcessLock(lockPath, token);
  if (!observation) throw new Error("lock was not observable");
  const incarnation = "linux-current-incarnation";
  const peerClaim = claimPath(lockPath, process.pid, incarnation);
  process.env.ACCOUNTS_TEST_PROCESS_START_ID = `${process.pid}:${incarnation}`;
  setAfterExactProcessLockClaimForTest(() => {
    setAfterExactProcessLockClaimForTest(undefined);
    linkSync(lockPath, peerClaim);
  });

  expect(removeObservedExactProcessLock(observation)).toBe(false);
  expect(readFileSync(lockPath, "utf8")).toBe(token);
  expect(readFileSync(peerClaim, "utf8")).toBe(token);
});
