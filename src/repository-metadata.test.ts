import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

interface PackageMetadata {
  repository?: { type?: string; url?: string };
  homepage?: string;
  bugs?: { url?: string };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  overrides?: Record<string, string>;
  scripts?: Record<string, string>;
}

describe("repository metadata", () => {
  test("points package consumers to the canonical repository", () => {
    const packageMetadata = JSON.parse(
      readFileSync(join(import.meta.dir, "../package.json"), "utf8"),
    ) as PackageMetadata;

    expect(packageMetadata.repository).toEqual({
      type: "git",
      url: "git+https://github.com/hasna/accounts.git",
    });
    expect(packageMetadata.homepage).toBe("https://github.com/hasna/accounts");
    expect(packageMetadata.bugs?.url).toBe(
      "https://github.com/hasna/accounts/issues",
    );
  });

  test("keeps the bundled MCP validation graph out of consumer installs", () => {
    const packageMetadata = JSON.parse(
      readFileSync(join(import.meta.dir, "../package.json"), "utf8"),
    ) as PackageMetadata;
    const mcpBuild = packageMetadata.scripts?.build
      ?.split("&&")
      .map((command) => command.trim())
      .find((command) => command.startsWith("bun build src/mcp.ts "));

    expect(
      packageMetadata.dependencies?.["@modelcontextprotocol/sdk"],
    ).toBeUndefined();
    expect(packageMetadata.dependencies?.["fast-uri"]).toBeUndefined();
    expect(packageMetadata.devDependencies?.["@modelcontextprotocol/sdk"]).toBe(
      "^1.27.1",
    );
    expect(packageMetadata.devDependencies?.["fast-uri"]).toBe("3.1.4");
    expect(packageMetadata.overrides?.["fast-uri"]).toBe("3.1.4");
    expect(mcpBuild).toBe(
      "bun build src/mcp.ts --outdir dist --target node --external @hasna/contracts",
    );
  });
});
