#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { currentProfile, listProfiles } from "./lib/profiles.js";
import { appliedProfile } from "./lib/apply.js";
import { switchProfile, type SwitchMode } from "./lib/switch.js";
import { listTools } from "./lib/tools.js";
import { AccountsError } from "./types.js";

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(message: string) {
  return { content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }], isError: true };
}

const server = new Server(
  { name: "accounts", version: "0.1.4" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list_tools",
      description: "List account-switchable coding tools known to accounts.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "list_profiles",
      description: "List account profiles. Optional: tool.",
      inputSchema: { type: "object", properties: { tool: { type: "string" } } },
    },
    {
      name: "current_profile",
      description: "Show active and live/applied profile for a tool.",
      inputSchema: { type: "object", properties: { tool: { type: "string" } }, required: ["tool"] },
    },
    {
      name: "switch_profile",
      description:
        "Switch to a profile. For Claude this applies live/default auth. Returns restart/resume handoff command; MCP does not kill the parent agent process.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string" },
          tool: { type: "string" },
          mode: { type: "string", enum: ["auto", "apply", "env", "active"] },
          resume: { type: "boolean" },
          args: { type: "array", items: { type: "string" } },
        },
        required: ["name"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  try {
    switch (req.params.name) {
      case "list_tools":
        return ok(listTools());
      case "list_profiles":
        return ok(listProfiles(typeof args["tool"] === "string" ? args["tool"] : undefined));
      case "current_profile": {
        const tool = args["tool"];
        if (typeof tool !== "string") return fail("tool is required");
        return ok({ tool, active: currentProfile(tool) ?? null, applied: appliedProfile(tool) ?? null });
      }
      case "switch_profile": {
        const name = args["name"];
        if (typeof name !== "string") return fail("name is required");
        const result = switchProfile(name, {
          tool: typeof args["tool"] === "string" ? args["tool"] : undefined,
          mode: typeof args["mode"] === "string" ? (args["mode"] as SwitchMode) : "auto",
          resume: args["resume"] === true,
          args: Array.isArray(args["args"]) ? args["args"].filter((value): value is string => typeof value === "string") : undefined,
        });
        return ok({
          ...result,
          instruction: result.restartRequired
            ? "Exit the current agent session and run commandLine to resume under the selected profile."
            : "Profile switched.",
        });
      }
      default:
        return fail(`unknown tool ${req.params.name}`);
    }
  } catch (err) {
    if (err instanceof AccountsError) return fail(err.message);
    throw err;
  }
});

await server.connect(new StdioServerTransport());
