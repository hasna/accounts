import { createHmac, randomBytes } from "node:crypto";

import { AccountsError } from "../errors";
import { incrementCounter, parseCounter } from "../domain/counter";
import { canonicalJson, canonicalSha256 } from "../serialization/json";
import type {
  RecoveryFrontier,
  RecoveryLedger,
  RecoveryLedgerEntry,
  RecoveryLedgerReceipt,
} from "./repository";

export class InMemoryRecoveryLedger implements RecoveryLedger {
  private frontier: RecoveryFrontier;
  private readonly signingKey: Buffer;

  constructor(
    catalogIncarnation: string,
    signingKey: Uint8Array = randomBytes(32),
  ) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/.test(catalogIncarnation)) {
      throw new AccountsError("VALIDATION_FAILED", "Recovery catalog incarnation is invalid");
    }
    if (signingKey.byteLength < 32) {
      throw new AccountsError("VALIDATION_FAILED", "Recovery signing key is too short");
    }
    this.signingKey = Buffer.from(signingKey);
    const unsigned = {
      catalogIncarnation,
      sequence: parseCounter("0"),
      hash: canonicalSha256({ kind: "accounts-recovery-genesis", catalogIncarnation }),
    };
    this.frontier = Object.freeze({
      ...unsigned,
      signatureDigest: this.signFrontier(unsigned),
    });
  }

  readFreshFrontier(): RecoveryFrontier {
    return { ...this.frontier };
  }

  append(expected: RecoveryFrontier, entry: RecoveryLedgerEntry): RecoveryLedgerReceipt {
    if (
      !this.verifyFrontier(expected) ||
      expected.catalogIncarnation !== this.frontier.catalogIncarnation ||
      expected.sequence !== this.frontier.sequence ||
      expected.hash !== this.frontier.hash ||
      expected.signatureDigest !== this.frontier.signatureDigest
    ) {
      throw new AccountsError("RECOVERY_HOLD", "Recovery frontier compare-and-append failed");
    }
    const sequence = incrementCounter(expected.sequence);
    const entryDigest = canonicalSha256(entry);
    const hash = canonicalSha256({
      catalogIncarnation: expected.catalogIncarnation,
      sequence,
      previousHash: expected.hash,
      entryDigest,
    });
    const unsigned = {
      catalogIncarnation: expected.catalogIncarnation,
      sequence,
      hash,
    };
    const signatureDigest = this.signFrontier(unsigned);
    const receiptDigest = `sha256:${createHmac("sha256", this.signingKey)
      .update(
        canonicalJson({
          ...unsigned,
          signatureDigest,
          previousHash: expected.hash,
          entryDigest,
        }),
        "utf8",
      )
      .digest("hex")}`;
    this.frontier = Object.freeze({ ...unsigned, signatureDigest });
    return {
      ...this.frontier,
      previousHash: expected.hash,
      entryDigest,
      receiptDigest,
    };
  }

  verifyFrontier(frontier: RecoveryFrontier): boolean {
    return (
      /^sha256:[0-9a-f]{64}$/.test(frontier.hash) &&
      /^sha256:[0-9a-f]{64}$/.test(frontier.signatureDigest) &&
      frontier.signatureDigest ===
        this.signFrontier({
          catalogIncarnation: frontier.catalogIncarnation,
          sequence: frontier.sequence,
          hash: frontier.hash,
        })
    );
  }

  private signFrontier(frontier: Omit<RecoveryFrontier, "signatureDigest">): string {
    return `sha256:${createHmac("sha256", this.signingKey)
      .update(canonicalJson(frontier), "utf8")
      .digest("hex")}`;
  }
}

export const UNAVAILABLE_RECOVERY_LEDGER: RecoveryLedger = Object.freeze({
  readFreshFrontier(): never {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Recovery ledger is unavailable");
  },
  append(): never {
    throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Recovery ledger is unavailable");
  },
  verifyFrontier(): boolean {
    return false;
  },
});
