import { describe, expect, test } from "bun:test";
import { createAccountSchema, updateAccountSchema } from "./schema.js";

describe("accounts API path validation", () => {
  test("create rejects NUL and newline directory paths", () => {
    expect(
      createAccountSchema.safeParse({ name: "bad-dir", tool: "claude", dir: "/tmp/bad\0path" }).success,
    ).toBe(false);
    expect(
      createAccountSchema.safeParse({ name: "bad-dir", tool: "claude", dir: "/tmp/bad\npath" }).success,
    ).toBe(false);
  });

  test("update rejects invalid directory paths", () => {
    expect(updateAccountSchema.safeParse({ dir: "/tmp/bad\0path" }).success).toBe(false);
    expect(updateAccountSchema.safeParse({ dir: "/tmp/bad\rpath" }).success).toBe(false);
  });
});
