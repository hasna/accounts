import { describe, expect, test } from "bun:test";

import {
  AccountsError,
  MAX_COUNTER,
  compareCounters,
  counter,
  incrementCounter,
  isUuidV7,
  newAccessMethodId,
  newAccountId,
  parseAccessMethodId,
  parseAccountId,
  parseCounter,
} from "../../src/index";

describe("strict identifiers", () => {
  test("generates lowercase UUIDv7 identifiers", () => {
    const first = newAccountId(1_750_000_000_000);
    const second = newAccessMethodId(1_750_000_000_001);
    expect(isUuidV7(first)).toBe(true);
    expect(isUuidV7(second)).toBe(true);
    expect(first[14]).toBe("7");
  });

  test("rejects non-v7, uppercase, and malformed identifiers", () => {
    expect(() => parseAccountId("00000000-0000-4000-8000-000000000000")).toThrow(AccountsError);
    const valid = newAccessMethodId();
    expect(() => parseAccessMethodId(valid.toUpperCase())).toThrow(AccountsError);
    expect(() => parseAccessMethodId("method-1")).toThrow(AccountsError);
  });
});

describe("signed-64-bit decimal counters", () => {
  test("round-trips values around Number precision without using Number", () => {
    const below = parseCounter("9007199254740991");
    const above = parseCounter("9007199254740993");
    expect(String(incrementCounter(below))).toBe("9007199254740992");
    expect(compareCounters(above, below)).toBe(1);
  });

  test("accepts the signed-64-bit maximum and refuses wraparound", () => {
    const maximum = parseCounter(MAX_COUNTER.toString(10));
    expect(String(maximum)).toBe("9223372036854775807");
    expect(() => incrementCounter(maximum)).toThrow(
      expect.objectContaining({ code: "COUNTER_EXHAUSTED" }),
    );
  });

  test.each([0, 1, -1, "+1", "-1", "01", "00", "1.0", "9223372036854775808", ""])(
    "rejects non-canonical counter %p",
    (value) => {
      expect(() => parseCounter(value)).toThrow(AccountsError);
    },
  );

  test("constructs counters from bigint only within range", () => {
    expect(String(counter(42n))).toBe("42");
    expect(() => counter(-1n)).toThrow(AccountsError);
    expect(() => (counter as unknown as (value: unknown) => unknown)(1)).toThrow(AccountsError);
    expect(() =>
      (incrementCounter as unknown as (value: unknown) => unknown)(9007199254740992),
    ).toThrow(AccountsError);
    expect(() =>
      (compareCounters as unknown as (left: unknown, right: unknown) => unknown)("01", "1"),
    ).toThrow(AccountsError);
  });
});
