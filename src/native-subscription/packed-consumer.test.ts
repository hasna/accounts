import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

const created: string[] = [];

afterEach(() => {
  for (const path of created.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("packed native-subscription declarations", () => {
  test("typecheck under NodeNext without package dev dependencies or Bun SQL types", () => {
    const root = process.cwd();
    execFileSync("bun", ["run", "build"], { cwd: root, stdio: "pipe" });
    const temporary = mkdtempSync(join(root, ".packed-consumer-"));
    created.push(temporary);
    const packDirectory = join(temporary, "pack");
    const consumer = join(temporary, "consumer");
    const installedPackage = join(
      consumer,
      "node_modules",
      "@hasna",
      "accounts",
    );
    mkdirSync(packDirectory, { recursive: true });
    mkdirSync(installedPackage, { recursive: true });

    execFileSync(
      "npm",
      ["pack", "--ignore-scripts", "--pack-destination", packDirectory],
      { cwd: root, stdio: "pipe" },
    );
    const archive = readdirSync(packDirectory).find((name) => name.endsWith(".tgz"));
    expect(archive).toBeDefined();
    const unpacked = join(temporary, "unpacked");
    mkdirSync(unpacked);
    execFileSync(
      "tar",
      ["-xzf", join(packDirectory, archive!), "--strip-components=1", "-C", unpacked],
      { stdio: "pipe" },
    );
    cpSync(unpacked, installedPackage, { recursive: true });

    expect(existsSync(join(installedPackage, "node_modules"))).toBe(false);
    const declarationDirectory = join(installedPackage, "dist", "native-subscription");
    const declarations = readdirSync(declarationDirectory)
      .filter((name) => name.endsWith(".d.ts"))
      .map((name) => readFileSync(join(declarationDirectory, name), "utf8"))
      .join("\n");
    expect(declarations).not.toMatch(/from\s+["']bun["']/);
    expect(declarations).not.toMatch(/(?:from|export\s+\*)\s+["']\.{1,2}\/[^"']+(?<!\.js)["']/);

    writeFileSync(
      join(consumer, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    writeFileSync(
      join(consumer, "consumer.ts"),
      [
        "import type {",
        "  PostgresRuntimeRoleBoundary,",
        "  PostgresSqlClient,",
        "  PostgresTransaction,",
        '} from "@hasna/accounts/native-subscription";',
        "",
        "declare const client: PostgresSqlClient;",
        "declare const transaction: PostgresTransaction;",
        'const boundary: PostgresRuntimeRoleBoundary = { mode: "direct", roleName: "accounts_app" };',
        "void client;",
        "void transaction;",
        "void boundary;",
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(consumer, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noEmit: true,
          skipLibCheck: false,
          types: ["node"],
        },
        files: ["consumer.ts"],
      }),
    );

    execFileSync(
      "bun",
      [resolve(root, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"],
      { cwd: consumer, stdio: "pipe" },
    );
  }, 15_000);
});
