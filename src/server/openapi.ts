// OpenAPI 3 document for the accounts cloud API.
//
// This is the single source of truth for the HTTP contract AND the generated
// SDK (`@hasna/contracts/sdk` turns this document into the typed client in
// src/sdk/). Keep operationIds stable — they become SDK method names.

export interface OpenApiDoc {
  openapi: string;
  info: { title: string; version: string; description?: string };
  paths: Record<string, Record<string, unknown>>;
  components: { schemas: Record<string, unknown>; securitySchemes?: Record<string, unknown> };
}

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

const jsonBody = (schema: unknown, required = true) => ({
  required,
  content: { "application/json": { schema } },
});

const jsonResponse = (description: string, schema: unknown) => ({
  description,
  content: { "application/json": { schema } },
});

export function buildOpenApiDoc(version: string): OpenApiDoc {
  const errorResponses = {
    "400": jsonResponse("Validation error", ref("ErrorResponse")),
    "401": jsonResponse("Missing or invalid API key", ref("ErrorResponse")),
    "403": jsonResponse("Insufficient scope", ref("ErrorResponse")),
  };

  return {
    openapi: "3.0.3",
    info: {
      title: "Accounts",
      version,
      description:
        "Cloud API for @hasna/accounts: manage AI coding tool profiles/accounts. API-key auth (x-api-key or Authorization: Bearer). PURE REMOTE per Amendment A1.",
    },
    components: {
      securitySchemes: {
        apiKey: { type: "apiKey", in: "header", name: "x-api-key" },
      },
      schemas: {
        HealthResponse: {
          type: "object",
          required: ["status", "version", "mode"],
          properties: {
            status: { type: "string", enum: ["ok", "degraded", "unavailable"] },
            version: { type: "string" },
            mode: { type: "string", enum: ["local", "cloud"] },
          },
        },
        ReadyResponse: {
          type: "object",
          required: ["ready"],
          properties: {
            ready: { type: "boolean" },
            reason: { type: "string" },
          },
        },
        VersionResponse: {
          type: "object",
          required: ["version"],
          properties: { version: { type: "string" } },
        },
        ErrorResponse: {
          type: "object",
          required: ["error"],
          properties: {
            error: { type: "string" },
            reason: { type: "string" },
          },
        },
        Account: {
          type: "object",
          required: ["tool", "name", "metadata", "createdAt"],
          properties: {
            tool: { type: "string" },
            name: { type: "string" },
            email: { type: "string" },
            displayName: { type: "string" },
            identity: { type: "string" },
            cardLast4: { type: "string" },
            metadata: { type: "object", additionalProperties: true },
            dir: { type: "string" },
            description: { type: "string" },
            createdAt: { type: "string" },
            lastUsedAt: { type: "string" },
          },
        },
        AccountList: {
          type: "object",
          required: ["accounts"],
          properties: {
            accounts: { type: "array", items: ref("Account") },
          },
        },
        CreateAccountInput: {
          type: "object",
          required: ["name", "tool"],
          properties: {
            name: { type: "string" },
            tool: { type: "string" },
            email: { type: "string" },
            displayName: { type: "string" },
            identity: { type: "string" },
            cardLast4: { type: "string" },
            metadata: { type: "object", additionalProperties: true },
            dir: { type: "string" },
            description: { type: "string" },
          },
        },
        UpdateAccountInput: {
          type: "object",
          properties: {
            email: { type: "string" },
            displayName: { type: "string" },
            identity: { type: "string" },
            cardLast4: { type: "string" },
            metadata: { type: "object", additionalProperties: true },
            dir: { type: "string" },
            description: { type: "string" },
            lastUsedAt: { type: "string" },
          },
        },
        CurrentSelection: {
          type: "object",
          required: ["tool", "name", "updatedAt"],
          properties: {
            tool: { type: "string" },
            name: { type: "string" },
            updatedAt: { type: "string" },
          },
        },
        CurrentSelectionList: {
          type: "object",
          required: ["current"],
          properties: {
            current: { type: "array", items: ref("CurrentSelection") },
          },
        },
        SetCurrentInput: {
          type: "object",
          required: ["name"],
          properties: { name: { type: "string" } },
        },
        Tool: {
          type: "object",
          required: ["id", "label"],
          properties: {
            id: { type: "string" },
            label: { type: "string" },
            envVar: { type: "string" },
            bin: { type: "string" },
            builtin: { type: "boolean" },
          },
        },
        ToolList: {
          type: "object",
          required: ["tools"],
          properties: { tools: { type: "array", items: ref("Tool") } },
        },
      },
    },
    paths: {
      "/health": {
        get: {
          operationId: "getHealth",
          summary: "Liveness + DB reachability probe",
          responses: { "200": jsonResponse("Service health", ref("HealthResponse")) },
        },
      },
      "/ready": {
        get: {
          operationId: "getReady",
          summary: "Readiness probe (reachable AND migrated)",
          responses: {
            "200": jsonResponse("Ready", ref("ReadyResponse")),
            "503": jsonResponse("Not ready", ref("ReadyResponse")),
          },
        },
      },
      "/version": {
        get: {
          operationId: "getVersion",
          summary: "Service version",
          responses: { "200": jsonResponse("Version", ref("VersionResponse")) },
        },
      },
      "/v1/accounts": {
        get: {
          operationId: "listAccounts",
          summary: "List accounts (optionally filtered by tool)",
          security: [{ apiKey: [] }],
          parameters: [{ name: "tool", in: "query", required: false, schema: { type: "string" } }],
          responses: {
            "200": jsonResponse("Accounts", ref("AccountList")),
            ...errorResponses,
          },
        },
        post: {
          operationId: "createAccount",
          summary: "Create an account",
          security: [{ apiKey: [] }],
          requestBody: jsonBody(ref("CreateAccountInput")),
          responses: {
            "201": jsonResponse("Created", ref("Account")),
            "409": jsonResponse("Already exists", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
      },
      "/v1/accounts/{tool}/{name}": {
        get: {
          operationId: "getAccount",
          summary: "Get one account",
          security: [{ apiKey: [] }],
          parameters: [
            { name: "tool", in: "path", required: true, schema: { type: "string" } },
            { name: "name", in: "path", required: true, schema: { type: "string" } },
          ],
          responses: {
            "200": jsonResponse("Account", ref("Account")),
            "404": jsonResponse("Not found", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
        patch: {
          operationId: "updateAccount",
          summary: "Update an account",
          security: [{ apiKey: [] }],
          parameters: [
            { name: "tool", in: "path", required: true, schema: { type: "string" } },
            { name: "name", in: "path", required: true, schema: { type: "string" } },
          ],
          requestBody: jsonBody(ref("UpdateAccountInput")),
          responses: {
            "200": jsonResponse("Updated", ref("Account")),
            "404": jsonResponse("Not found", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
        delete: {
          operationId: "deleteAccount",
          summary: "Delete an account",
          security: [{ apiKey: [] }],
          parameters: [
            { name: "tool", in: "path", required: true, schema: { type: "string" } },
            { name: "name", in: "path", required: true, schema: { type: "string" } },
          ],
          responses: {
            "204": { description: "Deleted" },
            "404": jsonResponse("Not found", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
      },
      "/v1/current": {
        get: {
          operationId: "listCurrent",
          summary: "List current active selections per tool",
          security: [{ apiKey: [] }],
          responses: {
            "200": jsonResponse("Current selections", ref("CurrentSelectionList")),
            ...errorResponses,
          },
        },
      },
      "/v1/current/{tool}": {
        get: {
          operationId: "getCurrent",
          summary: "Get the current active account for a tool",
          security: [{ apiKey: [] }],
          parameters: [{ name: "tool", in: "path", required: true, schema: { type: "string" } }],
          responses: {
            "200": jsonResponse("Current selection", ref("CurrentSelection")),
            "404": jsonResponse("No current selection", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
        put: {
          operationId: "setCurrent",
          summary: "Set the current active account for a tool",
          security: [{ apiKey: [] }],
          parameters: [{ name: "tool", in: "path", required: true, schema: { type: "string" } }],
          requestBody: jsonBody(ref("SetCurrentInput")),
          responses: {
            "200": jsonResponse("Current selection", ref("CurrentSelection")),
            "404": jsonResponse("Account not found", ref("ErrorResponse")),
            ...errorResponses,
          },
        },
      },
      "/v1/tools": {
        get: {
          operationId: "listTools",
          summary: "List known tools (builtin + custom)",
          security: [{ apiKey: [] }],
          responses: {
            "200": jsonResponse("Tools", ref("ToolList")),
            ...errorResponses,
          },
        },
      },
    },
  };
}
