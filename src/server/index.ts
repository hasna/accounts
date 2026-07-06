#!/usr/bin/env bun
// accounts-serve — HTTP API for @hasna/accounts (PURE REMOTE, cloud Postgres).
//
// GET /health, /ready, /version + authenticated /v1 CRUD. Binds 0.0.0.0:PORT
// (PORT env or --port, default 8080). Runs on Bun.

import { buildServiceContext, createHandler } from "./app.js";
import { DEFAULT_SERVE_PORT } from "./config.js";
import { packageVersion } from "./version.js";

function argValue(name: string): string | undefined {
  const idx = process.argv.findIndex((a) => a === name || a.startsWith(`${name}=`));
  if (idx === -1) return undefined;
  const arg = process.argv[idx]!;
  if (arg.includes("=")) return arg.split("=")[1];
  return process.argv[idx + 1];
}

function resolvePort(): number {
  const raw = argValue("--port") ?? process.env.PORT ?? process.env.ACCOUNTS_SERVE_PORT;
  const parsed = raw ? Number.parseInt(raw, 10) : DEFAULT_SERVE_PORT;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_SERVE_PORT;
}

async function main(): Promise<void> {
  if (process.argv.includes("--version") || process.argv.includes("-V")) {
    console.log(packageVersion());
    return;
  }
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(`accounts-serve — @hasna/accounts cloud API

Usage: accounts-serve [--port <port>] [--host <host>]

Environment:
  PORT / ACCOUNTS_SERVE_PORT           HTTP port (default ${DEFAULT_SERVE_PORT})
  HASNA_ACCOUNTS_STORAGE_MODE=cloud    required (PURE REMOTE)
  HASNA_ACCOUNTS_DATABASE_URL          cloud Postgres DSN
  HASNA_ACCOUNTS_API_SIGNING_KEY       API-key HMAC signing secret`);
    return;
  }

  const port = resolvePort();
  const host = argValue("--host") ?? process.env.HOST ?? "0.0.0.0";
  const ctx = buildServiceContext();
  const handler = createHandler(ctx);

  const server = Bun.serve({
    port,
    hostname: host,
    fetch: handler,
    error(err) {
      console.error(JSON.stringify({ evt: "serve_error", message: err instanceof Error ? err.message : String(err) }));
      return new Response(JSON.stringify({ error: "internal error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    },
  });

  console.log(JSON.stringify({ evt: "listening", host: server.hostname, port: server.port, version: ctx.version, mode: ctx.mode }));

  const shutdown = async (signal: string) => {
    console.log(JSON.stringify({ evt: "shutdown", signal }));
    server.stop(true);
    await ctx.close().catch(() => {});
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
