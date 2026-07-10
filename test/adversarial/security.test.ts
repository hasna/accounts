import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import * as publicApi from "../../src/index";
import {
  POSTGRES_ADAPTER_STATUS,
  decodeRecordEnvelope,
  encodeRecordEnvelope,
  serializeRecordEnvelope,
} from "../../src/index";
import { makeFixtureGraph } from "../fixtures";

describe("adversarial public-boundary checks", () => {
  test("exports no run, lease, grant, reservation, scheduling, or SaaS authority", () => {
    const exported = Object.keys(publicApi).join("\n").toLowerCase();
    for (const forbidden of [
      "acquire",
      "billing",
      "grant",
      "holder",
      "invite",
      "lease",
      "organization",
      "reserve",
      "scheduler",
      "signup",
      "tenant",
    ]) {
      expect(exported).not.toContain(forbidden);
    }
  });

  test("marks Postgres as reserved with no implementation or conformance claim", () => {
    expect(POSTGRES_ADAPTER_STATUS).toEqual({
      adapter: "postgres",
      implemented: false,
      conformanceClaim: false,
      target: "self_hosted",
    });
    expect(publicApi).not.toHaveProperty("createPostgresAccounts");
  });

  test("normal binding serialization contains metadata only", () => {
    const graph = makeFixtureGraph();
    const source = serializeRecordEnvelope("credential_binding", graph.binding);
    expect(source).not.toContain("credentialHandle");
    expect(source).not.toContain("vaultPath");
    expect(source).not.toContain("roleArn");
    expect(source).not.toContain("localPath");
  });

  test.each(["tenantId", "organizationId", "billingPlan", "signup", "credentialHandle"])(
    "closed DTO rejects prohibited field %s",
    (field) => {
      const graph = makeFixtureGraph();
      const envelope = structuredClone(encodeRecordEnvelope("account", graph.account)) as unknown as {
        data: Record<string, unknown>;
      };
      envelope.data[field] = true;
      expect(() => decodeRecordEnvelope(envelope)).toThrow();
    },
  );

  test("capacity bundle source imports no process execution or credential-store runtime", async () => {
    const root = join(import.meta.dir, "..", "..", "src");
    const files: string[] = [];
    for await (const relative of new Bun.Glob("**/*.ts").scan({ cwd: root })) files.push(relative);
    const source = files.map((file) => readFileSync(join(root, file), "utf8")).join("\n");
    expect(source).not.toMatch(/from\s+["'](?:node:)?child_process["']/);
    expect(source).not.toMatch(/\b(?:execFile|fork|spawnSync)\s*\(/);
    expect(source).not.toMatch(/\bKeychain\b/);
    expect(source).not.toMatch(/credentials\.json/);
  });
});
