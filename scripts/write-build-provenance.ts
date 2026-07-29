import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name?: string; version?: string };
const fromEnv = process.env.HASNA_ACCOUNTS_BUILD_HEAD?.trim().toLowerCase();
const git = spawnSync("git", ["-C", root, "rev-parse", "--verify", "HEAD"], { encoding: "utf8" });
const head = fromEnv || (git.status === 0 ? git.stdout.trim().toLowerCase() : "");
if (!/^[0-9a-f]{40}$/.test(head)) throw new Error("build requires an exact 40-character Git HEAD");
if (pkg.name !== "@hasna/accounts" || !pkg.version) throw new Error("build package identity is not @hasna/accounts");

mkdirSync(join(root, "dist"), { recursive: true });
writeFileSync(
  join(root, "dist", "runtime-provenance.json"),
  JSON.stringify(
    {
      schema: "hasna.accounts.runtime-provenance/v1",
      package: { name: pkg.name, version: pkg.version },
      source: { head },
    },
    null,
    2,
  ) + "\n",
  { mode: 0o644 },
);
