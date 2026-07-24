import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Profile } from "./types.js";
import { addProfile } from "./lib/profiles.js";
import { addCustomTool, getTool } from "./lib/tools.js";
import {
  configsPrelaunchCommand,
  configsSessionToolFor,
  runConfigsPrelaunch,
} from "./lib/configs-prelaunch.js";
import { getConfigsPrelaunchSummary } from "./lib/configs-prelaunch-status.js";

let home = "";

function resetHome() {
  if (home) rmSync(home, { recursive: true, force: true });
  home = mkdtempSync(join(tmpdir(), "accounts-configs-prelaunch-"));
  process.env.ACCOUNTS_HOME = home;
  delete process.env.ACCOUNTS_STORE_PATH;
}

function cleanup() {
  if (home) rmSync(home, { recursive: true, force: true });
  home = "";
  delete process.env.ACCOUNTS_HOME;
}

function profile(tool: string): Profile {
  return {
    name: `${tool}-profile`,
    tool,
    dir: `/tmp/accounts/${tool}-profile`,
    createdAt: "2026-07-01T00:00:00.000Z",
  };
}

function profileInHome(tool: string, opts: Partial<Profile> = {}): Profile {
  return {
    ...profile(tool),
    dir: join(home, `${tool}-profile`),
    ...opts,
  };
}

function hash(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function writeManifest(p: Profile, toolId = p.tool, sources: Array<{ id: string }> = [{ id: "global-codewith" }]) {
  const hasnaDir = join(p.dir, ".hasna");
  mkdirSync(hasnaDir, { recursive: true });
  writeFileSync(
    join(hasnaDir, "session-render-manifest.json"),
    JSON.stringify(
      {
        schema: "hasna.configs.session-render/v1",
        tool: toolId,
        profile: p.name,
        targetHome: p.dir,
        generatedAt: "2026-07-01T00:00:00.000Z",
        sources,
        files: [],
      },
      null,
      2,
    ) + "\n",
  );
}

function writeManifestWithManagedFile(p: Profile, relativePath = "AGENTS.md", content = "Managed instructions\n") {
  mkdirSync(p.dir, { recursive: true });
  writeFileSync(join(p.dir, relativePath), content);
  const hasnaDir = join(p.dir, ".hasna");
  mkdirSync(hasnaDir, { recursive: true });
  writeFileSync(
    join(hasnaDir, "session-render-manifest.json"),
    JSON.stringify(
      {
        schema: "hasna.configs.session-render/v1",
        tool: p.tool,
        profile: p.name,
        targetHome: p.dir,
        generatedAt: "2026-07-01T00:00:00.000Z",
        sources: [{ id: "agent-marcus" }],
        files: [{ path: join(p.dir, relativePath), relativePath, role: "config", sha256: hash(content), sourceIds: ["agent-marcus"] }],
      },
      null,
      2,
    ) + "\n",
  );
}

describe("configs prelaunch", () => {
  test("maps Claude, Codex, and Codewith tools to configs session tools", () => {
    expect(configsSessionToolFor(getTool("claude"))).toBe("claude");
    expect(configsSessionToolFor(getTool("codex"))).toBe("codex");
    expect(configsSessionToolFor(getTool("codewith"))).toBe("codewith");
    expect(getTool("codewith").envVar).toBe("CODEWITH_HOME");
  });

  test("builds profile-scoped configs plan command for Codex", () => {
    const p = profile("codex");
    const command = configsPrelaunchCommand(p, getTool("codex"), { mode: "plan", configsBin: "configs-dev" });

    expect(command).toEqual([
      "configs-dev",
      "session",
      "plan",
      "--tool",
      "codex",
      "--profile",
      "codex-profile",
      "--target-home",
      "/tmp/accounts/codex-profile",
      "--session-id",
      "accounts:codex:codex-profile",
      "--allow-empty-sources",
    ]);
  });

  test("builds apply command for Claude using the profile dir as target home", () => {
    const p = profile("claude");
    const command = configsPrelaunchCommand(p, getTool("claude"));

    expect(command[0]).toBe("configs");
    expect(command.slice(1, 5)).toEqual(["session", "apply", "--tool", "claude"]);
    expect(command).toContain("--target-home");
    expect(command).toContain("/tmp/accounts/claude-profile");
    expect(command).toContain("--allow-empty-sources");
  });

  test("passes OpenIdentities configs exports to the configs session command", () => {
    const p = profile("codewith");
    const command = configsPrelaunchCommand(p, getTool("codewith"), {
      mode: "apply",
      identityExports: ["/tmp/global-identities.json", "/tmp/account-agent.json"],
    });

    expect(command).toContain("--identity-export");
    expect(command).not.toContain("--allow-empty-sources");
    expect(command.slice(-4)).toEqual([
      "--identity-export",
      "/tmp/global-identities.json",
      "--identity-export",
      "/tmp/account-agent.json",
    ]);
  });

  test("adds --allow-empty-sources only when there are no instruction sources", () => {
    const p = profile("claude");

    const emptyImplicit = configsPrelaunchCommand(p, getTool("claude"));
    expect(emptyImplicit).toContain("--allow-empty-sources");
    expect(emptyImplicit).not.toContain("--identity-export");

    const emptyExplicit = configsPrelaunchCommand(p, getTool("claude"), { identityExports: [] });
    expect(emptyExplicit).toContain("--allow-empty-sources");

    const withSources = configsPrelaunchCommand(p, getTool("claude"), {
      identityExports: ["/tmp/one.json"],
    });
    expect(withSources).toContain("--identity-export");
    expect(withSources).not.toContain("--allow-empty-sources");
  });

  test("runs configs prelaunch and fails closed unless bypassed", () => {
    const p = profile("codex");
    const tool = getTool("codex");
    const ok = runConfigsPrelaunch(p, tool, {
      runner: () => {
        writeManifest(p);
        return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
      },
    });
    expect(ok.skipped).toBe(false);
    expect(ok.result).toBe("applied");
    expect(ok.prelaunch.status).toBe("ok");

    expect(() =>
      runConfigsPrelaunch(p, tool, {
        runner: () => ({ status: 2, stdout: Buffer.from(""), stderr: Buffer.from("bad config") }),
      }),
    ).toThrow("configs prelaunch apply failed");

    const bypassed = runConfigsPrelaunch(p, tool, {
      allowFailure: true,
      runner: () => ({ status: 2, stdout: Buffer.from(""), stderr: Buffer.from("bad config") }),
    });
    expect(bypassed.status).toBe(2);
    expect(bypassed.result).toBe("bypassed");
    expect(bypassed.prelaunch.status).toBe("bypassed");
  });

  test("fails closed when apply succeeds without a fresh manifest unless bypassed", () => {
    resetHome();
    try {
      const p = profileInHome("claude");
      expect(() =>
        runConfigsPrelaunch(p, getTool("claude"), {
          runner: () => ({ status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") }),
        }),
      ).toThrow("session render manifest missing");

      const bypassed = runConfigsPrelaunch(p, getTool("claude"), {
        allowFailure: true,
        runner: () => ({ status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") }),
      });
      expect(bypassed.result).toBe("bypassed");
      expect(bypassed.prelaunch.status).toBe("bypassed");
      expect(bypassed.prelaunch.manifest.drift).toBe("missing");
    } finally {
      cleanup();
    }
  });

  test("reports stale managed files from the OpenConfigs manifest", () => {
    resetHome();
    try {
      const p = profileInHome("codex");
      writeManifestWithManagedFile(p, "AGENTS.md", "Original\n");
      expect(getConfigsPrelaunchSummary(p, getTool("codex"), "codex").status).toBe("ok");

      writeFileSync(join(p.dir, "AGENTS.md"), "Drifted\n");
      const summary = getConfigsPrelaunchSummary(p, getTool("codex"), "codex");
      expect(summary.status).toBe("stale");
      expect(summary.manifest.reasons.join("\n")).toContain("managed file drifted: AGENTS.md");
    } finally {
      cleanup();
    }
  });

  test("records explicit skip audit without requiring a manifest", () => {
    resetHome();
    try {
      const p = profileInHome("codewith");
      const result = runConfigsPrelaunch(p, getTool("codewith"), { mode: "skip", skipReason: "--skip-configs" });
      expect(result.skipped).toBe(true);
      expect(result.prelaunch.status).toBe("skipped");
      expect(result.prelaunch.lastRun?.reason).toBe("--skip-configs");
      expect(result.prelaunch.manifest.drift).toBe("missing");
    } finally {
      cleanup();
    }
  });

  test("exports profile identity refs before running configs apply", () => {
    resetHome();
    try {
      const p = profileInHome("claude", { identity: "agent:marcus" });
      const calls: string[][] = [];
      const result = runConfigsPrelaunch(p, getTool("claude"), {
        mode: "apply",
        configsBin: "configs-dev",
        identitiesBin: "identities-dev",
        runner: (bin, args) => {
          calls.push([bin, ...args]);
          if (bin === "configs-dev") writeManifest(p, "claude");
          return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
        },
      });

      expect(calls[0]?.slice(0, 4)).toEqual(["identities-dev", "instructions", "export", result.identityExports?.[0]]);
      expect(calls[0]).toContain("agent:marcus");
      expect(calls[1]).toContain("--identity-export");
      expect(calls[1]).toContain(result.identityExports?.[0] ?? "");
      expect(result.identityExports?.[0]).toEndWith("agent-marcus.configs.json");
      expect(existsSync(join(p.dir, ".hasna", "accounts", "identity-exports"))).toBe(true);
    } finally {
      cleanup();
    }
  });

  test("uses profile identity paths as existing OpenIdentities configs exports", () => {
    resetHome();
    try {
      const exportPath = join(home, "identity-export.json");
      writeFileSync(exportPath, "{}\n");
      const p = profileInHome("claude", { identity: exportPath });
      const calls: string[][] = [];
      const result = runConfigsPrelaunch(p, getTool("claude"), {
        runner: (bin, args) => {
          calls.push([bin, ...args]);
          if (bin === "configs") writeManifest(p, "claude");
          return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
        },
      });

      expect(calls).toHaveLength(1);
      expect(calls[0]).toContain("--identity-export");
      expect(calls[0]).toContain(exportPath);
      expect(result.identityExports).toEqual([exportPath]);
    } finally {
      cleanup();
    }
  });

  test("does not reuse a stale generated identity export when export failure is bypassed", () => {
    resetHome();
    try {
      const p = profileInHome("claude", { identity: "agent:marcus" });
      const calls: string[][] = [];
      const result = runConfigsPrelaunch(p, getTool("claude"), {
        allowFailure: true,
        runner: (bin, args) => {
          calls.push([bin, ...args]);
          if (bin === "identities") return { status: 1, stdout: Buffer.from(""), stderr: Buffer.from("identity offline") };
          writeManifest(p, "claude");
          return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
        },
      });

      expect(calls[0]?.slice(0, 3)).toEqual(["identities", "instructions", "export"]);
      expect(calls[1]?.slice(0, 4)).toEqual(["configs", "session", "apply", "--tool"]);
      expect(calls[1]).not.toContain("--identity-export");
      expect(result.identityExports).toEqual([]);
      expect(result.result).toBe("bypassed");
      expect(result.prelaunch.status).toBe("bypassed");
    } finally {
      cleanup();
    }
  });

  test("fails safely for missing profile identity export paths unless explicitly bypassed", () => {
    resetHome();
    try {
      const p = profileInHome("claude", { identity: join(home, "missing-identity.json") });
      expect(() =>
        runConfigsPrelaunch(p, getTool("claude"), {
          runner: () => ({ status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") }),
        }),
      ).toThrow("profile identity export file not found");

      const bypassed = runConfigsPrelaunch(p, getTool("claude"), {
        allowFailure: true,
        runner: (bin) => {
          if (bin === "configs") writeManifest(p, "claude");
          return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
        },
      });
      expect(bypassed.result).toBe("bypassed");
      expect(bypassed.reason).toContain("profile identity export file not found");
      expect(bypassed.identityExports).toEqual([]);
      expect(bypassed.prelaunch.status).toBe("bypassed");
    } finally {
      cleanup();
    }
  });

  test("skips unsupported tools without failing", () => {
    resetHome();
    try {
      addCustomTool({
        id: "fakeagent",
        label: "Fake Agent",
        envVar: "FAKE_HOME",
        defaultDir: join(home, "fake-default"),
        bin: "fake",
      });
      const p = addProfile({ name: "fake", tool: "fakeagent" });
      const result = runConfigsPrelaunch(p, getTool("fakeagent"));
      expect(result.skipped).toBe(true);
      expect(result.reason).toBe("unsupported tool fakeagent");
    } finally {
      cleanup();
    }
  });
});
