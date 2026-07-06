// Resolve the package version at runtime (dev, bundled dist, and Docker).

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | undefined;

export function packageVersion(): string {
  if (cached) return cached;
  const candidates: string[] = [];
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    candidates.push(join(here, "..", "..", "package.json"));
    candidates.push(join(here, "..", "package.json"));
    candidates.push(join(here, "package.json"));
  } catch {
    // ignore
  }
  candidates.push(join(process.cwd(), "package.json"));
  candidates.push("/app/package.json");
  for (const candidate of candidates) {
    try {
      if (existsSync(candidate)) {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { name?: string; version?: string };
        if (pkg.version && (pkg.name === "@hasna/accounts" || candidate.includes("open-accounts") || candidate === "/app/package.json")) {
          cached = pkg.version;
          return cached;
        }
      }
    } catch {
      // keep looking
    }
  }
  cached = "0.0.0";
  return cached;
}
