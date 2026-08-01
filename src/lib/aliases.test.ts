// R-P1-4 (2026-07-31-accounts-debloat-design.md): "each renamed record gains
// aliases: [<old-name>] and nativeName: <tool-native/on-disk name>" and
// "accounts show <name> and list read aliases". These are the pure functions
// the CLI read path (src/cli.ts `show`) is built on: given the full profile
// set and a queried name, which OTHER profiles record that name as a former
// name of themselves.
import { describe, expect, test } from "bun:test";
import { findAliasHolders, formatAliasNote } from "./aliases.js";
import type { Profile } from "../types.js";

function profile(overrides: Partial<Profile> & Pick<Profile, "name" | "tool">): Profile {
  return {
    dir: "/tmp/x",
    createdAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  } as Profile;
}

describe("findAliasHolders", () => {
  test("finds the profile whose aliases array records the queried name", () => {
    const claude = profile({ name: "account005", tool: "claude" });
    const codewith = profile({
      name: "account005-codewith",
      tool: "codewith",
      nativeName: "account005",
      aliases: ["account005"],
    });
    const holders = findAliasHolders([claude, codewith], "account005");
    expect(holders).toEqual([codewith]);
  });

  test("returns empty when no profile carries that alias", () => {
    const claude = profile({ name: "account005", tool: "claude" });
    expect(findAliasHolders([claude], "account005")).toEqual([]);
  });

  test("a profile with no aliases field at all is not a match (undefined, not []) ", () => {
    const bare = profile({ name: "solo", tool: "claude" });
    expect(findAliasHolders([bare], "solo")).toEqual([]);
  });

  test("matches across multiple recorded aliases (more than one historical rename)", () => {
    const twice = profile({
      name: "account009-codewith",
      tool: "codewith",
      nativeName: "account009",
      aliases: ["account009", "account009-old"],
    });
    expect(findAliasHolders([twice], "account009-old")).toEqual([twice]);
    expect(findAliasHolders([twice], "account009")).toEqual([twice]);
  });
});

describe("formatAliasNote", () => {
  test("matches the exact wording from the design doc's worked example", () => {
    const holder = profile({
      name: "account005-codewith",
      tool: "codewith",
      nativeName: "account005",
      aliases: ["account005"],
    });
    expect(formatAliasNote("account005", holder)).toBe(
      "alias note: 'account005' is also the former/native name of account005-codewith (codewith)",
    );
  });
});
