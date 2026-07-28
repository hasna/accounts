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
    const mcpProjectKey = ["sk", "proj", "mcp-positional-secret"].join("-");
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
          "---api-key=mcp-malformed-three-dash-secret",
          "keep-mcp-malformed-three-dash",
          "--api-key",
          "--.client-key:mcp-malformed-dot-secret",
          "keep-mcp-malformed-dot",
          "--api-key",
          "--_master-key=mcp-malformed-underscore-secret",
          "keep-mcp-malformed-underscore",
          "--api-key",
          "－－－api-key=mcp-malformed-fullwidth-secret",
          "keep-mcp-malformed-fullwidth",
          "--api-key",
          "−−−client-key:mcp-malformed-minus-secret",
          "keep-mcp-malformed-minus",
          "--api-key",
          "--",
          "--client-key",
          "keep-mcp-positional-plain-value",
          "--api-key=mcp-positional-attached-secret",
          "env=--client-key",
          "",
          "mcp-positional-wrapper-split-secret",
          "keep-mcp-positional-wrapper-split",
          "url=urn:authorization:public",
          "keep-mcp-positional-urn",
          "Authorization: Bearer mcp-positional-bearer-secret",
          mcpProjectKey,
          "keep-mcp-positional-control",
        ],
      },
    });
    const text = response.content.find((entry) => entry.type === "text")?.text;
    expect(text).toBeDefined();
    expect(text).not.toContain("mcp-chained-client-secret");
    expect(text).not.toContain("mcp-chained-short-secret");
    expect(text).not.toContain("mcp-opaque-bound-secret");
    expect(text).not.toContain("mcp-complete-token-secret");
    for (const secret of [
      "mcp-malformed-three-dash-secret",
      "mcp-malformed-dot-secret",
      "mcp-malformed-underscore-secret",
      "mcp-malformed-fullwidth-secret",
      "mcp-malformed-minus-secret",
      "mcp-positional-attached-secret",
      "mcp-positional-wrapper-split-secret",
      "mcp-positional-bearer-secret",
      mcpProjectKey,
    ]) {
      expect(text).not.toContain(secret);
    }
    for (const syntax of [
      "---api-key=",
      "--.client-key:",
      "--_master-key=",
      "－－－api-key=",
      "−−−client-key:",
    ]) {
      expect(text).not.toContain(syntax);
    }
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
      "[REDACTED]",
      "keep-mcp-malformed-three-dash",
      "--api-key",
      "[REDACTED]",
      "keep-mcp-malformed-dot",
      "--api-key",
      "[REDACTED]",
      "keep-mcp-malformed-underscore",
      "--api-key",
      "[REDACTED]",
      "keep-mcp-malformed-fullwidth",
      "--api-key",
      "[REDACTED]",
      "keep-mcp-malformed-minus",
      "--api-key",
      "--",
      "--client-key",
      "keep-mcp-positional-plain-value",
      "--api-key=[REDACTED]",
      "env=--client-key",
      "",
      "[REDACTED]",
      "keep-mcp-positional-wrapper-split",
      "url=urn:authorization:public",
      "keep-mcp-positional-urn",
      "Authorization: [REDACTED]",
      "[REDACTED]",
      "[REDACTED]",
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
    for (const retained of [
      "keep-mcp-malformed-three-dash",
      "keep-mcp-malformed-dot",
      "keep-mcp-malformed-underscore",
      "keep-mcp-malformed-fullwidth",
      "keep-mcp-malformed-minus",
    ]) {
      expect(output.commandLine).toContain(
        `'--api-key' '[REDACTED]' '${retained}'`,
      );
    }
    expect(output.commandLine).toContain(
      "'--api-key' '--' '--client-key' 'keep-mcp-positional-plain-value'",
    );
    expect(output.commandLine).toContain(
      "'env=--client-key' '' '[REDACTED]' 'keep-mcp-positional-wrapper-split'",
    );
    expect(output.commandLine).toContain(
      "'url=urn:authorization:public' 'keep-mcp-positional-urn'",
    );
    expect(output.commandLine).toContain(
      "'Authorization: [REDACTED]' '[REDACTED]' '[REDACTED]'",
    );
    expect(output.commandLine).not.toContain("keep-mcp-positional-control");
  } finally {
    await client.close();
  }
});
