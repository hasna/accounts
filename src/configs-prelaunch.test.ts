import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

  test("identity-less profiles get --allow-empty-sources on the actual configs apply invocation", () => {
    // Regression: `accounts launch`/`run`/supervisor prelaunch for a profile with
    // zero identity exports (e.g. accountNNN) must request an explicit empty
    // render, not fail closed with "Session render has no instruction sources".
    resetHome();
    try {
      const p = profileInHome("codewith");
      const calls: string[][] = [];
      const result = runConfigsPrelaunch(p, getTool("codewith"), {
        runner: (bin, args) => {
          calls.push([bin, ...args]);
          writeManifest(p, "codewith", []);
          return { status: 0, stdout: Buffer.from("ok"), stderr: Buffer.from("") };
        },
      });

      expect(result.result).toBe("applied");
      expect(result.identityExports).toEqual([]);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.slice(0, 3)).toEqual(["configs", "session", "apply"]);
      expect(calls[0]).toContain("--allow-empty-sources");
      expect(calls[0]).not.toContain("--identity-export");
      expect(result.prelaunch.status).toBe("ok");
    } finally {
      cleanup();
    }
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

  test("controlled prelaunch probes suppress inherited request-debug output", () => {
    resetHome();
    const p = profileInHome("codex");
    const probe = join(home, "configs-probe");
    const dummyCredential = "dummy-controlled-probe-credential";
    const previous = {
      BUN_CONFIG_VERBOSE_FETCH: process.env.BUN_CONFIG_VERBOSE_FETCH,
      NODE_DEBUG: process.env.NODE_DEBUG,
      NODE_DEBUG_NATIVE: process.env.NODE_DEBUG_NATIVE,
    };
    writeFileSync(
      probe,
      [
        "#!/bin/sh",
        'if [ -n "${BUN_CONFIG_VERBOSE_FETCH:-}${NODE_DEBUG:-}${NODE_DEBUG_NATIVE:-}" ]; then',
        `  printf 'Authorization: Bearer %s\\n' ${JSON.stringify(dummyCredential)}`,
        `  printf 'x-api-key=%s\\n' ${JSON.stringify(dummyCredential)} >&2`,
        "fi",
        "exit 2",
      ].join("\n"),
    );
    chmodSync(probe, 0o755);

    try {
      process.env.BUN_CONFIG_VERBOSE_FETCH = "1";
      process.env.NODE_DEBUG = "http,http2";
      process.env.NODE_DEBUG_NATIVE = "http";
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), { configsBin: probe });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("configs prelaunch apply failed");
      expect(message).not.toContain(dummyCredential);
    } finally {
      for (const [name, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      cleanup();
    }
  });

  test("prelaunch errors redact normalized and escaped credential keys end to end", () => {
    const p = profile("codex");
    const samples: Array<[string, (secret: string) => string]> = [
      ["prelaunch-oauth-secret", (secret) => `oauth_token=${secret}`],
      ["prelaunch-bearer-secret", (secret) => `bearer-token=${secret}`],
      ["prelaunch-signing-secret", (secret) => `signing_secret=${secret}`],
      ["prelaunch-consumer-secret", (secret) => `consumerSecret=${secret}`],
      ["prelaunch-database-secret", (secret) => `database_password=${secret}`],
      ["prelaunch-webhook-secret", (secret) => `webhookCredential=${secret}`],
      [
        "prelaunch-escaped-auth-secret",
        (secret) => String.raw`{"Authoriz\u0061tion":"${secret}","status":401}`,
      ],
      [
        "prelaunch-escaped-api-secret",
        (secret) => String.raw`{"x-\u0061pi-key":"${secret}","message"="malformed"}`,
      ],
    ];

    for (const [secret, render] of samples) {
      const output = render(secret);
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stdout: Buffer.from(""),
            stderr: Buffer.from(output),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }

      expect(message).toContain("configs prelaunch apply failed");
      expect(message).toContain("[REDACTED]");
      expect(message).not.toContain(secret);
    }
  });

  test("prelaunch captured command text redacts credential options without erasing diagnostics", () => {
    const p = profile("codex");
    const cases = [
      {
        output: "provider --api-key prelaunch-api-secret --verbose keep-api-diagnostic",
        secret: "prelaunch-api-secret",
        retained: "--verbose keep-api-diagnostic",
      },
      {
        output: 'provider "--secret-key=prelaunch-secret-key-secret" status=keep-secret-key-status',
        secret: "prelaunch-secret-key-secret",
        retained: "status=keep-secret-key-status",
      },
      {
        output: "provider --service-auth 'prelaunch service auth secret' --mode keep-service-mode",
        secret: "prelaunch service auth secret",
        retained: "--mode keep-service-mode",
      },
      {
        output: "provider --credentials prelaunch-credentials\\ escaped --trace keep-credentials-trace",
        secret: "prelaunch-credentials escaped",
        retained: "--trace keep-credentials-trace",
      },
      {
        output: "provider -k prelaunch-short-secret --color keep-short-color",
        secret: "prelaunch-short-secret",
        retained: "--color keep-short-color",
      },
    ];

    for (const sample of cases) {
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stdout: Buffer.from(""),
            stderr: Buffer.from(sample.output),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("[REDACTED]");
      expect(message).not.toContain(sample.secret);
      expect(message).toContain(sample.retained);
    }
  });

  test("prelaunch command redaction carries bound values across every physical line ending", () => {
    const p = profile("codex");

    for (const lineEnding of ["\n", "\r\n", "\r"]) {
      const secrets = [
        "prelaunch-multiline-plain-secret",
        "--prelaunch-multiline-quoted-secret",
        "--prelaunch-multiline-wrapper-secret",
      ];
      const cases = [
        {
          output: `provider --api-key${lineEnding}${secrets[0]}${lineEnding}status=keep-prelaunch-plain`,
          secret: secrets[0]!,
          retained: "status=keep-prelaunch-plain",
        },
        {
          output: `provider --client-key${lineEnding}"${secrets[1]}"${lineEnding}message=keep-prelaunch-quoted`,
          secret: secrets[1]!,
          retained: "message=keep-prelaunch-quoted",
        },
        {
          output: `provider --master-key${lineEnding}(\\"${secrets[2]}\\")${lineEnding}detail=keep-prelaunch-wrapper`,
          secret: secrets[2]!,
          retained: "detail=keep-prelaunch-wrapper",
        },
      ];

      for (const sample of cases) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stdout: Buffer.from(""),
              stderr: Buffer.from(sample.output),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).toContain("[REDACTED]");
        expect(message).not.toContain(sample.secret);
        expect(message).toContain(sample.retained);
      }
    }
  });

  test("prelaunch command redaction keeps opaque and attached option-looking values private", () => {
    const p = profile("codex");
    const cases: Array<{
      output: string;
      secret: string;
      retained: string;
    }> = [];

    for (const [lineIndex, lineEnding] of [" ", "\n", "\r\n", "\r"].entries()) {
      for (const [variantIndex, value] of [
        `--label/client-key/prelaunch-hidden-${lineIndex}-0`,
        `"--label/client-key/prelaunch-hidden-${lineIndex}-1"`,
        `\\--label/client-key/prelaunch-hidden-${lineIndex}-2`,
        `－label/client-key/prelaunch-hidden-${lineIndex}-3`,
        `(--label/client-key/prelaunch-hidden-${lineIndex}-4)`,
        `|--label/client-key/prelaunch-hidden-${lineIndex}-5`,
        `--label=opaque/--label=prelaunch-hidden-${lineIndex}-6`,
        `--label=opaque|--label=prelaunch-hidden-${lineIndex}-7`,
        `--label=opaque<--label=prelaunch-hidden-${lineIndex}-8`,
        `(--label=opaque/--label=prelaunch-hidden-${lineIndex}-9)`,
        `－label=opaque/－label=prelaunch-hidden-${lineIndex}-10`,
        `"--label=opaque/--label=prelaunch-hidden-${lineIndex}-11"`,
        `\\--label=opaque/--label=prelaunch-hidden-${lineIndex}-12`,
      ].entries()) {
        cases.push({
          output:
            `provider --api-key${lineEnding}${value} ` +
            `status=keep-prelaunch-opaque-${lineIndex}-${variantIndex}`,
          secret: `prelaunch-hidden-${lineIndex}-${variantIndex}`,
          retained: `status=keep-prelaunch-opaque-${lineIndex}-${variantIndex}`,
        });
      }
    }
    cases.push(
      {
        output:
          "provider --api-key=--client-key status=keep-prelaunch-attached-equals",
        secret: "--client-key",
        retained: "status=keep-prelaunch-attached-equals",
      },
      {
        output:
          "provider --api-key:--client-key status=keep-prelaunch-attached-colon",
        secret: "--client-key",
        retained: "status=keep-prelaunch-attached-colon",
      },
    );

    for (const sample of cases) {
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stdout: Buffer.from(""),
            stderr: Buffer.from(sample.output),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message, sample.output).toContain("[REDACTED]");
      expect(message, sample.output).not.toContain(sample.secret);
      expect(message, sample.output).toContain(sample.retained);
    }
  });

  test("prelaunch command redaction covers logical values continued across lines", () => {
    const p = profile("codex");

    for (const lineEnding of ["\n", "\r\n", "\r"]) {
      const cases = [
        {
          output: `provider --api-key \\${lineEnding}prelaunch-bare-continuation-secret${lineEnding}status=keep-prelaunch-bare-continuation`,
          secret: "prelaunch-bare-continuation-secret",
          retained: "status=keep-prelaunch-bare-continuation",
        },
        {
          output: `provider --client-key first-fragment\\${lineEnding}prelaunch-fragment-continuation-secret${lineEnding}message=keep-prelaunch-fragment-continuation`,
          secret: "prelaunch-fragment-continuation-secret",
          retained: "message=keep-prelaunch-fragment-continuation",
        },
        {
          output: `provider --master-key "quoted-first-fragment${lineEnding}prelaunch-quoted-continuation-secret"${lineEnding}detail=keep-prelaunch-quoted-continuation`,
          secret: "prelaunch-quoted-continuation-secret",
          retained: "detail=keep-prelaunch-quoted-continuation",
        },
      ];

      for (const sample of cases) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stdout: Buffer.from(""),
              stderr: Buffer.from(sample.output),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).toContain("[REDACTED]");
        expect(message).not.toContain(sample.secret);
        expect(message).toContain(sample.retained);
      }
    }
  });

  test("prelaunch active logical values do not expose continuation suffixes", () => {
    const p = profile("codex");

    for (const [lineEndingIndex, lineEnding] of ["\n", "\r\n", "\r"].entries()) {
      const cases = [
        {
          output:
            `provider --api-key seed\\${lineEnding}` +
            `tail/--label=prelaunch-active-${lineEndingIndex}-suffix-secret ` +
            "--trace keep-prelaunch-active-escaped",
          secrets: [`prelaunch-active-${lineEndingIndex}-suffix-secret`],
          retained: "--trace keep-prelaunch-active-escaped",
        },
        {
          output:
            `provider --client-key="seed${lineEnding}tail"/-- ` +
            `--master-key=prelaunch-active-${lineEndingIndex}-following-secret ` +
            "--mode keep-prelaunch-active-quoted",
          secrets: [`prelaunch-active-${lineEndingIndex}-following-secret`],
          retained: "--mode keep-prelaunch-active-quoted",
        },
        {
          output:
            `provider -kseed\\${lineEnding}` +
            `tail((/|<－－label:prelaunch-active-${lineEndingIndex}-layered-secret>)) ` +
            "--color keep-prelaunch-active-short",
          secrets: [`prelaunch-active-${lineEndingIndex}-layered-secret`],
          retained: "--color keep-prelaunch-active-short",
        },
      ];

      for (const sample of cases) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stdout: Buffer.from(""),
              stderr: Buffer.from(sample.output),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message, sample.output).toContain("[REDACTED]");
        for (const secret of sample.secrets) {
          expect(message, sample.output).not.toContain(secret);
        }
        expect(message, sample.output).toContain(sample.retained);
      }
    }
  });

  test("prelaunch redacts attached multiline values without swallowing later options", () => {
    const p = profile("codex");

    for (const lineEnding of ["\n", "\r\n", "\r"]) {
      const cases = [
        {
          output: `provider --api-key="first${lineEnding}prelaunch-attached-quoted-secret" --verbose keep-prelaunch-attached-quoted`,
          secret: "prelaunch-attached-quoted-secret",
          retained: "--verbose keep-prelaunch-attached-quoted",
        },
        {
          output: `provider --client-key:first\\${lineEnding}prelaunch-attached-escaped-secret --mode keep-prelaunch-attached-escaped`,
          secret: "prelaunch-attached-escaped-secret",
          retained: "--mode keep-prelaunch-attached-escaped",
        },
        {
          output: "provider x|--master-key=prelaunch-punctuation-secret|--trace keep-prelaunch-punctuation-suffix",
          secret: "prelaunch-punctuation-secret",
          retained: "|--trace keep-prelaunch-punctuation-suffix",
        },
        {
          output: 'provider --api-key "prelaunch-separate-punctuation-secret"|--color keep-prelaunch-separate-punctuation',
          secret: "prelaunch-separate-punctuation-secret",
          retained: "keep-prelaunch-separate-punctuation",
        },
      ];

      for (const sample of cases) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stdout: Buffer.from(""),
              stderr: Buffer.from(sample.output),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).not.toContain(sample.secret);
        expect(message).toContain(sample.retained);
      }
    }
  });

  test("prelaunch command redaction recognizes safe punctuation boundaries", () => {
    const p = profile("codex");
    const safePrefixes = ["|", "/", "<", ">", "(", ")", "[", "]", "{", "}", ",", ";"];

    for (const [index, prefix] of safePrefixes.entries()) {
      const secret = `prelaunch-punctuation-secret-${index}`;
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stdout: Buffer.from(""),
            stderr: Buffer.from(
              `diagnostic${prefix}--api-key ${secret} --verbose keep-prelaunch-punctuation-${index}`,
            ),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("[REDACTED]");
      expect(message).not.toContain(secret);
      expect(message).toContain(`--verbose keep-prelaunch-punctuation-${index}`);
    }

    for (const nearMiss of [
      "word--api-key keep-prelaunch-word-near-miss",
      "https://example.invalid/--api-key keep-prelaunch-url-near-miss",
      "https://example.invalid/?arg=--api-key keep-prelaunch-url-query-near-miss",
      "https://example.invalid/path;--api-key keep-prelaunch-url-param-near-miss",
      "mailto:person@example.invalid?subject=--api-key keep-prelaunch-mailto-near-miss",
      "mailto:?subject=--api-key keep-prelaunch-empty-mailto-near-miss",
      "person@--api-key keep-prelaunch-email-near-miss",
      "1--api-key keep-prelaunch-arithmetic-near-miss",
    ]) {
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stdout: Buffer.from(""),
            stderr: Buffer.from(nearMiss),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain(nearMiss);
    }
  });

  test("controlled prelaunch errors redact credential-shaped headers", () => {
    resetHome();
    const p = profileInHome("codex");
    const probe = join(home, "configs-redaction-probe");
    const credentialFragments = [
      "controlled-cookie-alpha",
      "controlled-cookie-beta",
    ];
    writeFileSync(
      probe,
      [
        "#!/bin/sh",
        "printf '%s\\n' 'Cookie: sid=controlled-cookie-alpha;' ' arbitrary=controlled-cookie-beta' 'stack=Error keep-stack' >&2",
        "exit 2",
      ].join("\n"),
    );
    chmodSync(probe, 0o755);

    try {
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), { configsBin: probe });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("[REDACTED]");
      for (const fragment of credentialFragments) expect(message).not.toContain(fragment);
      expect(message).toContain("stack=Error keep-stack");
    } finally {
      cleanup();
    }
  });

  test("prelaunch error summaries keep stderr and stdout as separate records before redaction", () => {
    resetHome();
    const p = profileInHome("codex");
    const fusedCredential = "controlled-fused-stream-credential";

    try {
      for (const stderrEnding of ["", "\n", "\r\n", "\r"]) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stderr: Buffer.from(`diagnostic-prefix${stderrEnding}`),
              stdout: Buffer.from(`Authorization: Bearer ${fusedCredential}`),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).toContain("diagnostic-prefix");
        expect(message).toContain("[REDACTED]");
        expect(message).not.toContain(fusedCredential);
      }
    } finally {
      cleanup();
    }
  });

  test("a missing stderr command value never consumes the independent stdout record", () => {
    const p = profile("codex");

    for (const stderrEnding of ["", "\n", "\r\n", "\r"]) {
      let message = "";
      try {
        runConfigsPrelaunch(p, getTool("codex"), {
          runner: () => ({
            status: 2,
            stderr: Buffer.from(`provider --api-key${stderrEnding}`),
            stdout: Buffer.from("keep-independent-stdout-record"),
          }),
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).toContain("provider --api-key");
      expect(message).toContain("keep-independent-stdout-record");
      expect(message).not.toContain("[REDACTED]");
    }
  });

  test("controlled prelaunch errors fail closed on hostile folded credential records", () => {
    resetHome();
    const p = profileInHome("codex");
    const cases: Array<{ output: string; secret: string }> = [];

    for (const lineEnding of ["\n", "\r\n", "\r"]) {
      for (const header of [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
      ]) {
        const label = header.toLowerCase().replaceAll("-", "_");
        cases.push(
          {
            output: [
              `${header}: seed=${label}_seed`,
              " \t",
              ` ${label}_blank_fold_fragment`,
            ].join(lineEnding),
            secret: `${label}_blank_fold_fragment`,
          },
          {
            output: `${header}: "${label}_quoted", extension=${label}_quoted_tail`,
            secret: `${label}_quoted_tail`,
          },
        );
      }
    }
    cases.push({
      output: 'x-api-key: "generic_quoted_\\"fragment", suffix=generic_quoted_tail',
      secret: "generic_quoted_tail",
    });

    try {
      expect(cases).toHaveLength(25);
      for (const hostile of cases) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), {
            runner: () => ({
              status: 2,
              stderr: Buffer.from(hostile.output),
              stdout: Buffer.from(""),
            }),
          });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).toContain("[REDACTED]");
        expect(message).not.toContain(hostile.secret);
      }
    } finally {
      cleanup();
    }
  });

  test("prelaunch bounding preserves stream order without exposing truncated folds", () => {
    resetHome();
    const p = profileInHome("codex");
    const truncatedSecret = "controlled-truncated-fold-fragment";
    const orderedSecret = "controlled-ordered-header-fragment";

    try {
      for (const runner of [
        () => ({
          status: 2,
          stderr: Buffer.from(`Authorization: Bearer ${orderedSecret}`),
          stdout: Buffer.from("status=418 keep-stdout-record"),
        }),
        () => ({
          status: 2,
          stderr: Buffer.from("diagnostic-one\ndiagnostic-two"),
          stdout: Buffer.from(
            `Authorization: seed=bounded-seed,\n \t\n ${truncatedSecret}`,
          ),
        }),
      ]) {
        let message = "";
        try {
          runConfigsPrelaunch(p, getTool("codex"), { runner });
        } catch (error) {
          message = error instanceof Error ? error.message : String(error);
        }
        expect(message).toContain("[REDACTED]");
        expect(message).not.toContain(orderedSecret);
        expect(message).not.toContain(truncatedSecret);
      }
    } finally {
      cleanup();
    }
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
