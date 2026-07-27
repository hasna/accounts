import { afterEach, beforeEach, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addProfile } from "./lib/profiles.js";
import { addCustomTool } from "./lib/tools.js";

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-mcp-test-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

test("MCP switch_profile redacts chained sensitive argv in command and commandLine", async () => {
  addCustomTool({
    id: "mcp-argv",
    label: "MCP argv",
    envVar: "MCP_ARGV_HOME",
    defaultDir: join(home, "mcp-argv-default"),
    bin: "mcp-argv-tool",
  });
  addProfile({ name: "acct", tool: "mcp-argv" });

  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["run", "src/mcp.ts"],
    cwd: process.cwd(),
    env: environment,
    stderr: "pipe",
  });
  const client = new Client({ name: "accounts-test", version: "1.0.0" });

  try {
    await client.connect(transport);
    const response = await client.callTool({
      name: "switch_profile",
      arguments: {
        name: "acct",
        tool: "mcp-argv",
        mode: "active",
        resume: false,
        args: [
          "--api-key",
          "--client-key",
          "mcp-chained-client-secret",
          "-k",
          "-vk",
          "mcp-chained-short-secret",
          "--api-key",
          "-x=client-key=mcp-opaque-bound-secret",
          "keep-after-opaque-bound-value",
          "--api-key",
          "--label=opaque/--label=mcp-complete-token-secret",
          "keep-after-complete-token-value",
          "--api-key",
          "--",
          "--client-key",
          "keep-mcp-positional-client-value",
          "--api-key=keep-mcp-positional-attached-value",
          "-k",
          "keep-mcp-positional-short-value",
        ],
      },
    });
    const text = response.content.find((entry) => entry.type === "text")?.text;
    expect(text).toBeDefined();
    expect(text).not.toContain("mcp-chained-client-secret");
    expect(text).not.toContain("mcp-chained-short-secret");
    expect(text).not.toContain("mcp-opaque-bound-secret");
    expect(text).not.toContain("mcp-complete-token-secret");
    const output = JSON.parse(text ?? "{}") as {
      command: string[];
      commandLine: string;
    };
    expect(output.command).toEqual([
      "mcp-argv-tool",
      "--api-key",
      "--client-key",
      "[REDACTED]",
      "-k",
      "-vk",
      "[REDACTED]",
      "--api-key",
      "[REDACTED]",
      "keep-after-opaque-bound-value",
      "--api-key",
      "[REDACTED]",
      "keep-after-complete-token-value",
      "--api-key",
      "--",
      "--client-key",
      "keep-mcp-positional-client-value",
      "--api-key=keep-mcp-positional-attached-value",
      "-k",
      "keep-mcp-positional-short-value",
    ]);
    expect(output.commandLine).toContain(
      "'--api-key' '--client-key' '[REDACTED]'",
    );
    expect(output.commandLine).toContain("'-k' '-vk' '[REDACTED]'");
    expect(output.commandLine).toContain(
      "'--api-key' '[REDACTED]' 'keep-after-opaque-bound-value'",
    );
    expect(output.commandLine).toContain(
      "'--api-key' '[REDACTED]' 'keep-after-complete-token-value'",
    );
    expect(output.commandLine).toContain(
      "'--api-key' '--' '--client-key' 'keep-mcp-positional-client-value'",
    );
    expect(output.commandLine).toContain(
      "'--api-key=keep-mcp-positional-attached-value' '-k' 'keep-mcp-positional-short-value'",
    );
  } finally {
    await client.close();
  }
});
