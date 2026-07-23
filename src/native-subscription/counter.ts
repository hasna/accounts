import { AccountsError } from "./errors";
import type { Brand } from "./ids";

export type Counter = Brand<string, "Counter">;

export const MAX_COUNTER = 9_223_372_036_854_775_807n;
const COUNTER_PATTERN = /^(0|[1-9][0-9]{0,18})$/;

export function parseCounter(value: unknown, field = "counter"): Counter {
  if (typeof value !== "string" || !COUNTER_PATTERN.test(value)) {
    throw new AccountsError("VALIDATION_FAILED", `Invalid ${field}`, {
      details: { field },
    });
  }
  const parsed = BigInt(value);
  if (parsed > MAX_COUNTER) {
    throw new AccountsError("VALIDATION_FAILED", `${field} exceeds signed 64-bit range`, {
      details: { field },
    });
  }
  return value as Counter;
}

export function counter(value: bigint): Counter {
  if (typeof value !== "bigint" || value < 0n || value > MAX_COUNTER) {
    throw new AccountsError("VALIDATION_FAILED", "Counter is outside signed 64-bit range", {
      details: { field: "counter" },
    });
  }
  return value.toString(10) as Counter;
}

export function incrementCounter(value: Counter): Counter {
  const next = BigInt(parseCounter(value)) + 1n;
  if (next > MAX_COUNTER) {
    throw new AccountsError("COUNTER_EXHAUSTED", "Counter cannot advance safely");
  }
  return counter(next);
}

export function compareCounters(left: Counter, right: Counter): -1 | 0 | 1 {
  const leftValue = BigInt(parseCounter(left));
  const rightValue = BigInt(parseCounter(right));
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}
