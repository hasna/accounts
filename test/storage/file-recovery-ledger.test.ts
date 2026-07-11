import { afterAll, describe, expect, test } from "bun:test";
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalJson } from "../../src/serialization/json";
import {
  FileRecoveryLedger,
  OwnerOnlySignedAppendLog,
  type OwnerOnlySignedAppendLogOptions,
} from "../../src/storage/file-recovery-ledger";

const cleanup: string[] = [];
const KEY = new Uint8Array(32).fill(0x37);
const CATALOG = "catalog:file-recovery-test";
const ID = "018f0f00-0001-7000-8000-000000000001";

afterAll(() => {
  for (const path of cleanup) rmSync(path, { recursive: true, force: true });
});

function directory(): string {
  const path = mkdtempSync(join(tmpdir(), "accounts-file-recovery-"));
  chmodSync(path, 0o700);
  cleanup.push(path);
  return path;
}

function ledgerAt(path: string, key: Uint8Array = KEY): FileRecoveryLedger {
  return new FileRecoveryLedger({
    path,
    catalogIncarnation: CATALOG,
    signingKey: key,
  });
}

function entry(character: string, minute = 0) {
  return {
    kind: "catalog_mutation" as const,
    aggregateKind: "account" as const,
    aggregateId: ID,
    mutationDigest: `sha256:${character.repeat(64)}`,
    occurredAt: `2026-07-10T12:${minute.toString().padStart(2, "0")}:00.000Z`,
  };
}

function bootId(): string {
  return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
}

function processStart(pid: number): string {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8").trim();
  const closingParenthesis = stat.lastIndexOf(")");
  if (closingParenthesis < 0) throw new Error("invalid proc stat fixture");
  const fieldsFromState = stat.slice(closingParenthesis + 2).split(" ");
  const start = fieldsFromState[19];
  if (start === undefined || !/^\d+$/.test(start)) {
    throw new Error("invalid proc start fixture");
  }
  return start;
}

function writeLock(path: string, value: unknown): void {
  writeFileSync(`${path}.lock`, `${canonicalJson(value)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
}

describe("owner-only file recovery ledger", () => {
  test("fsync-appends a signed frontier and verifies it after reopen", () => {
    const root = directory();
    const path = join(root, "recovery.log");
    const ledger = ledgerAt(path);
    const genesis = ledger.readFreshFrontier();
    const first = ledger.append(genesis, entry("a"));
    const second = ledger.append(first, entry("b", 1));

    expect(String(second.sequence)).toBe("2");
    expect(second.previousHash).toBe(first.hash);
    expect(ledger.verifyFrontier(second)).toBe(true);
    expect(lstatSync(path).mode & 0o777).toBe(0o600);
    expect(lstatSync(`${path}.frontier`).mode & 0o777).toBe(0o600);

    const reopened = ledgerAt(path);
    expect(reopened.readFreshFrontier()).toEqual({
      catalogIncarnation: second.catalogIncarnation,
      sequence: second.sequence,
      hash: second.hash,
      signatureDigest: second.signatureDigest,
    });
    expect(reopened.verifyFrontier(first)).toBe(true);
  });

  test("conditionally appends and rejects a stale or forged frontier", () => {
    const path = join(directory(), "recovery.log");
    const ledger = ledgerAt(path);
    const stale = ledger.readFreshFrontier();
    const current = ledger.append(stale, entry("a"));

    expect(() => ledger.append(stale, entry("b", 1))).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
    expect(() =>
      ledger.append(
        { ...current, signatureDigest: `sha256:${"0".repeat(64)}` },
        entry("c", 2),
      ),
    ).toThrow(expect.objectContaining({ code: "RECOVERY_HOLD" }));
    expect(String(ledger.readFreshFrontier().sequence)).toBe("1");
  });

  test("detects truncation to a formerly valid prefix using the high-water anchor", () => {
    const path = join(directory(), "recovery.log");
    const ledger = ledgerAt(path);
    const first = ledger.append(ledger.readFreshFrontier(), entry("a"));
    ledger.append(first, entry("b", 1));

    const lines = readFileSync(path, "utf8").split("\n");
    writeFileSync(path, `${lines.slice(0, 2).join("\n")}\n`, { mode: 0o600 });

    expect(() => ledgerAt(path)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("forward-heals a lagging anchor across multiple complete authenticated tail records", () => {
    const path = join(directory(), "recovery.log");
    const ledger = ledgerAt(path);
    const genesisAnchor = readFileSync(`${path}.frontier`);
    const first = ledger.append(ledger.readFreshFrontier(), entry("a"));
    const second = ledger.append(first, entry("b", 1));
    const finalAnchor = readFileSync(`${path}.frontier`);

    // Crash state: every signed log line reached stable storage but the atomic
    // frontier replacement did not happen.
    writeFileSync(`${path}.frontier`, genesisAnchor, { mode: 0o600 });

    const reopened = ledgerAt(path);
    expect(reopened.readFreshFrontier()).toEqual({
      catalogIncarnation: second.catalogIncarnation,
      sequence: second.sequence,
      hash: second.hash,
      signatureDigest: second.signatureDigest,
    });
    expect(readFileSync(`${path}.frontier`)).toEqual(finalAnchor);
  });

  test("never heals a lagging anchor over an invalid or partial tail", () => {
    for (const mutation of ["invalid", "partial"] as const) {
      const path = join(directory(), `recovery-${mutation}.log`);
      const ledger = ledgerAt(path);
      const first = ledger.append(ledger.readFreshFrontier(), entry("a"));
      const firstAnchor = readFileSync(`${path}.frontier`);
      ledger.append(first, entry("b", 1));
      writeFileSync(`${path}.frontier`, firstAnchor, { mode: 0o600 });

      const source = readFileSync(path, "utf8");
      writeFileSync(
        path,
        mutation === "invalid"
          ? source.replace(`sha256:${"b".repeat(64)}`, `sha256:${"c".repeat(64)}`)
          : source.slice(0, -1),
        { mode: 0o600 },
      );

      expect(() => ledgerAt(path)).toThrow(
        expect.objectContaining({ code: "RECOVERY_HOLD" }),
      );
      expect(readFileSync(`${path}.frontier`)).toEqual(firstAnchor);
    }
  });

  test("rejects a substituted valid frontier from a same-sequence fork", () => {
    const originalPath = join(directory(), "original.log");
    const forkPath = join(directory(), "fork.log");
    const original = ledgerAt(originalPath);
    const fork = ledgerAt(forkPath);
    original.append(original.readFreshFrontier(), entry("a"));
    fork.append(fork.readFreshFrontier(), entry("b", 1));

    writeFileSync(
      `${originalPath}.frontier`,
      readFileSync(`${forkPath}.frontier`),
      { mode: 0o600 },
    );

    expect(() => ledgerAt(originalPath)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("detects a fork, byte corruption, partial tail, and the wrong HMAC key", () => {
    for (const mutation of ["fork", "corrupt", "partial", "wrong-key"] as const) {
      const path = join(directory(), "recovery.log");
      const ledger = ledgerAt(path);
      ledger.append(ledger.readFreshFrontier(), entry("a"));

      if (mutation === "fork") {
        const source = readFileSync(path, "utf8");
        const lines = source.trimEnd().split("\n");
        writeFileSync(path, `${source}${lines.at(-1)}\n`, { mode: 0o600 });
      } else if (mutation === "corrupt") {
        const source = readFileSync(path, "utf8");
        writeFileSync(path, source.replace(`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`), {
          mode: 0o600,
        });
      } else if (mutation === "partial") {
        const source = readFileSync(path, "utf8");
        writeFileSync(path, source.slice(0, -1), { mode: 0o600 });
      }

      expect(() =>
        ledgerAt(path, mutation === "wrong-key" ? new Uint8Array(32).fill(0x91) : KEY),
      ).toThrow(expect.objectContaining({ code: "RECOVERY_HOLD" }));
    }
  });

  test("fails closed on unsafe permissions and symlinks", () => {
    const unsafeRoot = directory();
    chmodSync(unsafeRoot, 0o755);
    expect(() => ledgerAt(join(unsafeRoot, "unsafe.log"))).toThrow(
      expect.objectContaining({ code: "DATABASE_PATH_UNSAFE" }),
    );

    const root = directory();
    const target = join(root, "target.log");
    const targetLedger = ledgerAt(target);
    targetLedger.append(targetLedger.readFreshFrontier(), entry("a"));
    const link = join(root, "linked.log");
    symlinkSync(target, link);
    expect(() => ledgerAt(link)).toThrow(
      expect.objectContaining({ code: "DATABASE_PATH_UNSAFE" }),
    );

  });

  test("recovers a stale dead-process lock with strong process identity", () => {
    const path = join(directory(), "stale-lock.log");
    const first = ledgerAt(path);
    writeLock(path, {
      schema_version: "accounts.signed-log-lock.v2",
      identity_mode: "linux-proc-v1",
      pid: 999_999_999,
      process_start: "1",
      boot_id: bootId(),
    });

    expect(ledgerAt(path).readFreshFrontier()).toEqual(first.readFreshFrontier());
    expect(() => lstatSync(`${path}.lock`)).toThrow();
  });

  test("keeps live and malformed legacy locks fail closed", () => {
    const livePath = join(directory(), "live-lock.log");
    ledgerAt(livePath);
    writeLock(livePath, {
      schema_version: "accounts.signed-log-lock.v2",
      identity_mode: "linux-proc-v1",
      pid: process.pid,
      process_start: processStart(process.pid),
      boot_id: bootId(),
    });
    expect(() => ledgerAt(livePath)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );

    const malformedPath = join(directory(), "malformed-lock.log");
    ledgerAt(malformedPath);
    writeFileSync(`${malformedPath}.lock`, "interrupted\n", {
      mode: 0o600,
      flag: "wx",
    });
    expect(() => ledgerAt(malformedPath)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("rejects a forged structural coordinator and retains the mandatory file lock", () => {
    const path = join(directory(), "forged-coordinator.log");
    writeFileSync(`${path}.lock`, "", { mode: 0o600, flag: "wx" });
    const forged = {
      path,
      catalogIncarnation: CATALOG,
      signingKey: KEY,
      logKind: "forged-coordinator",
      validatePayload: (value: unknown): unknown => value,
      coordination: {
        runExclusive: <R>(operation: () => R): R => operation(),
      },
    } as unknown as OwnerOnlySignedAppendLogOptions<unknown>;

    expect(() => new OwnerOnlySignedAppendLog(forged)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("uses conservative PID liveness when strong platform identity is unavailable", () => {
    const deadPath = join(directory(), "fallback-dead-lock.log");
    ledgerAt(deadPath);
    writeLock(deadPath, {
      schema_version: "accounts.signed-log-lock.v2",
      identity_mode: "pid-liveness-v1",
      pid: 999_999_999,
    });
    expect(String(ledgerAt(deadPath).readFreshFrontier().sequence)).toBe("0");

    const livePath = join(directory(), "fallback-live-lock.log");
    ledgerAt(livePath);
    writeLock(livePath, {
      schema_version: "accounts.signed-log-lock.v2",
      identity_mode: "pid-liveness-v1",
      pid: process.pid,
    });
    expect(() => ledgerAt(livePath)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
  });

  test("rejects non-canonical entries without persisting them", () => {
    const path = join(directory(), "recovery.log");
    const ledger = ledgerAt(path);
    const frontier = ledger.readFreshFrontier();
    expect(() =>
      ledger.append(frontier, {
        ...entry("a"),
        mutationDigest: "not-a-digest",
      }),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(ledger.readFreshFrontier()).toEqual(frontier);
  });

  test("rejects accessor-backed entry fields without invoking them", () => {
    const path = join(directory(), "recovery.log");
    const ledger = ledgerAt(path);
    let invoked = false;
    const malicious = { ...entry("a") } as Record<string, unknown>;
    Object.defineProperty(malicious, "kind", {
      enumerable: true,
      get() {
        invoked = true;
        return "catalog_mutation";
      },
    });
    expect(() =>
      ledger.append(
        ledger.readFreshFrontier(),
        malicious as unknown as ReturnType<typeof entry>,
      ),
    ).toThrow(expect.objectContaining({ code: "VALIDATION_FAILED" }));
    expect(invoked).toBe(false);
  });
});
