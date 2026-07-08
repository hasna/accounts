#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { resolveStore } from "./lib/store.js";
import { appliedProfile } from "./lib/apply.js";
import { switchProfile, type SwitchMode } from "./lib/switch.js";
import { listTools } from "./lib/tools.js";
import { AccountsError } from "./types.js";
import { listSupervisorStates, sendSupervisorRequest } from "./lib/supervisor.js";

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(message: string) {
  return { content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }], isError: true };
}

const server = new Server(
  { name: "accounts", version: "0.1.21" },
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
      name: "supervisor_status",
      description: "Show accounts-run supervisors that can restart an agent process after profile switches.",
      inputSchema: { type: "object", properties: { tool: { type: "string" } } },
    },
    {
      name: "switch_profile",
      description:
        "Switch to a profile. If the current agent was started with accounts run, the supervisor restarts it under the new profile; otherwise this returns a restart/resume handoff command.",
      inputSchema: {
        type: "object",
        properties: {
          name: { type: "string" },
          tool: { type: "string" },
          mode: { type: "string", enum: ["auto", "apply", "env", "active"] },
          resume: { type: "boolean" },
          permissions: { type: "string" },
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
        return ok(await resolveStore().listProfiles(typeof args["tool"] === "string" ? args["tool"] : undefined));
      case "current_profile": {
        const tool = args["tool"];
        if (typeof tool !== "string") return fail("tool is required");
        const active = (await resolveStore().currentProfile(tool)) ?? null;
        return ok({ tool, active, applied: appliedProfile(tool) ?? null });
      }
      case "supervisor_status": {
        const tool = args["tool"];
        const states =
          typeof tool === "string" ? listSupervisorStates().filter((state) => state.tool === tool) : listSupervisorStates();
        return ok({ supervisors: states });
      }
      case "switch_profile": {
        const name = args["name"];
        if (typeof name !== "string") return fail("name is required");
        const profile = await resolveStore().getProfile(name, typeof args["tool"] === "string" ? args["tool"] : undefined);
        const resume = args["resume"] !== false;
        const switchArgs = Array.isArray(args["args"])
          ? args["args"].filter((value): value is string => typeof value === "string")
          : undefined;
        const permissions = typeof args["permissions"] === "string" ? args["permissions"] : undefined;
        const supervisor = await sendSupervisorRequest(
          profile.tool,
          {
            type: "switch_profile",
            name: profile.name,
            tool: profile.tool,
            mode: typeof args["mode"] === "string" ? (args["mode"] as SwitchMode) : "auto",
            resume,
            args: switchArgs,
            permissions,
          },
          { allowMissing: true },
        );
        if (supervisor) {
          if (!supervisor.ok) return fail(supervisor.error);
          return ok({
            supervised: true,
            ...supervisor,
            instruction:
              "Profile switch queued. The accounts supervisor will close this agent process and restart it under the selected profile.",
          });
        }
        const result = switchProfile(name, {
          tool: profile.tool,
          mode: typeof args["mode"] === "string" ? (args["mode"] as SwitchMode) : "auto",
          resume,
          args: switchArgs,
          permissions,
        });
        return ok({
          supervised: false,
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
