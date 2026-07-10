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

import { FileRecoveryLedger } from "../../src/storage/file-recovery-ledger";

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

  test("fails closed on unsafe permissions, symlinks, and an interrupted lock", () => {
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

    const locked = join(directory(), "locked.log");
    const first = ledgerAt(locked);
    writeFileSync(`${locked}.lock`, "interrupted\n", { mode: 0o600, flag: "wx" });
    expect(() => ledgerAt(locked)).toThrow(
      expect.objectContaining({ code: "RECOVERY_HOLD" }),
    );
    rmSync(`${locked}.lock`);
    expect(ledgerAt(locked).readFreshFrontier()).toEqual(first.readFreshFrontier());
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
