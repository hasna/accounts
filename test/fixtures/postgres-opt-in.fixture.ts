import { expect, test } from "bun:test";

test("explicit PostgreSQL integration opt-in preserves only its isolated test URL", () => {
  expect(process.env.ACCOUNTS_TEST_POSTGRES_PROBE).toBe("1");
  expect(process.env.ACCOUNTS_REQUIRE_POSTGRES).toBe("1");
  expect(process.env.HASNA_ACCOUNTS_TEST_DATABASE_URL).toBe(
    process.env.ACCOUNTS_TEST_EXPECTED_POSTGRES_URL,
  );
  expect(process.env.HASNA_ACCOUNTS_DATABASE_URL).toBeUndefined();
  expect(process.env.ACCOUNTS_DATABASE_URL).toBeUndefined();
  expect(process.env.HASNA_ACCOUNTS_STORAGE_MODE).toBe("local");
});
