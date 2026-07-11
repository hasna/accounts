import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalJson } from "../../../src/serialization/json";
import {
  NonRewindableCapabilityUseLedger,
  verifyCapabilityUseEvidence,
  type CapabilityUseVerifiedClaims,
} from "../../../src/v10/capability-use-ledger";

const KEY = new Uint8Array(32).fill(0x53);
const encoder = new TextEncoder();

function digest(character: string): `sha256:${string}` {
  return `sha256:${character.repeat(64)}`;
}

function signal(path: string, name: string): void {
  writeFileSync(join(path, name), "ready\n", { mode: 0o600, flag: "wx" });
}

function wait(path: string, name: string): void {
  const target = join(path, name);
  const deadline = Date.now() + 10_000;
  const state = new Int32Array(new SharedArrayBuffer(4));
  while (!existsSync(target)) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${name}`);
    Atomics.wait(state, 0, 0, 10);
  }
}

function ledgerAt(path: string): NonRewindableCapabilityUseLedger {
  return new NonRewindableCapabilityUseLedger({
    ledgerPath: join(path, "capability-use.log"),
    mirrorPath: join(path, "capability-use.sqlite"),
    catalogIncarnation: "accounts-v10-ledger-test",
    signingKey: KEY,
  });
}

function secondClaims(): CapabilityUseVerifiedClaims {
  return {
    consumeRequestId: "0198a0a0-0000-7000-8000-000000000902",
    idempotencyKeyDigest: digest("7"),
    effectNamespaceId: "effect-namespace-1",
    serializationKeyDigest: digest("2"),
    capabilityId: "capability-2",
    capabilityDigest: digest("3"),
    nonce: "nonce-2",
    onlineReceiptDigest: digest("4"),
    modelCallAnchorDigest: digest("5"),
    useId: digest("8"),
    committedAt: "2026-07-11T10:00:15.000Z",
    consumeReceiptExpiresAt: "2026-07-11T10:01:15.000Z",
    catalogIncarnation: "accounts-v10-ledger-test",
    recoveryFrontierSequence:
      "1" as CapabilityUseVerifiedClaims["recoveryFrontierSequence"],
    recoveryFrontierHash: digest("0"),
  };
}

async function appendWait(directory: string, signals: string): Promise<void> {
  const ledger = ledgerAt(directory);
  signal(signals, "append-ready");
  wait(signals, "append-go");
  signal(signals, "append-started");
  const request = encoder.encode(canonicalJson({ fixture: "worker-request-2" }));
  const receipt = encoder.encode(canonicalJson({ fixture: "worker-receipt-2" }));
  const evidence = await verifyCapabilityUseEvidence(
    { consumeRequestBytes: request, consumeReceiptBytes: receipt },
    { verify: async () => secondClaims() },
  );
  ledger.append(evidence);
  signal(signals, "append-done");
  ledger.close();
}

function reconcilePause(directory: string, signals: string): void {
  const prototype = NonRewindableCapabilityUseLedger.prototype as unknown as Record<
    string,
    unknown
  >;
  const original = prototype.mirrorMatches;
  if (typeof original !== "function") throw new Error("mirrorMatches hook unavailable");
  let paused = false;
  prototype.mirrorMatches = function (this: NonRewindableCapabilityUseLedger, ...args: unknown[]) {
    const matches = Reflect.apply(original, this, args) as boolean;
    if (!matches && !paused) {
      paused = true;
      signal(signals, "reconcile-snapshot");
      wait(signals, "reconcile-release");
    }
    return matches;
  };
  const ledger = ledgerAt(directory);
  ledger.close();
}

const [mode, directory, signals] = process.argv.slice(2);
if (mode === undefined || directory === undefined || signals === undefined) {
  throw new Error("worker requires mode, directory, and signals");
}
chmodSync(signals, 0o700);

if (mode === "append-wait") {
  await appendWait(directory, signals);
} else if (mode === "reconcile-pause") {
  reconcilePause(directory, signals);
} else {
  throw new Error(`unknown worker mode: ${mode}`);
}
