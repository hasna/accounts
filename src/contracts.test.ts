import { describe, expect, test } from "bun:test";
import { SCHEMA_IDS } from "@hasna/contracts";
import {
  accountsCapabilityCard,
  accountsNoCloudEvidencePack,
  toAccountsActorRef,
  toAgentsRunnerWorkRun,
  toSupervisorOptionsWorkRun,
  validateEventActorRefs,
} from "./lib/contracts.js";
import { AccountsEventsClient } from "./lib/events.js";

describe("accounts contract adapters", () => {
  test("builds parseContract-validated actor_ref", () => {
    const actor = toAccountsActorRef({
      id: "actor_account004",
      kind: "agent",
      name: "Codewith account004",
      provider: "codewith",
      accountId: "account004",
      machineId: "spark01",
      createdAt: "2026-07-06T00:00:00.000Z",
    });

    expect(actor.schema).toBe(SCHEMA_IDS.actorRef);
    expect(actor.kind).toBe("agent");
    expect(actor.capabilities).toContain("profile-management");
  });

  test("rejects invalid actor fields in event payloads", () => {
    expect(() =>
      validateEventActorRefs({
        source: "accounts",
        type: "accounts.test",
        data: {
          actor: {
            id: "actor_bad",
            kind: "daemon",
          },
        },
      }),
    ).toThrow();
  });

  test("validates actor fields without changing event wire shape", () => {
    const input = {
      source: "accounts",
      type: "accounts.test",
      data: {
        actor: {
          id: "actor_accounts",
          kind: "service",
          name: "@hasna/accounts",
        },
        value: 1,
      },
    };

    expect(validateEventActorRefs(input)).toBe(input);
  });

  test("leaves ordinary scalar actor payload fields untouched", () => {
    const input = {
      source: "accounts",
      type: "accounts.test",
      data: {
        actor: "alice",
        actorRef: null,
      },
    };

    expect(validateEventActorRefs(input)).toBe(input);
  });

  test("rejects scalar actor_ref aliases", () => {
    expect(() =>
      validateEventActorRefs({
        source: "accounts",
        type: "accounts.test",
        data: {
          actorRef: "alice",
        },
      }),
    ).toThrow("data.actorRef must be an actor_ref-compatible object");
  });

  test("events client wrapper rejects invalid actor refs before publish", async () => {
    const client = new AccountsEventsClient();

    await expect(
      client.emit({
        source: "accounts",
        type: "accounts.test",
        data: {
          actorRef: {
            id: "actor_bad",
            kind: "robot",
          },
        },
      }),
    ).rejects.toThrow();
  });

  test("builds work_run adapters for agent and supervisor surfaces", () => {
    const agentRun = toAgentsRunnerWorkRun(
      { ok: false, raw: "", error: "exit 1" },
      { name: "account004", tool: "claude", dir: "/tmp/claude" },
      { createdAt: "2026-07-06T00:00:00.000Z" },
    );
    const supervisorRun = toSupervisorOptionsWorkRun(
      { restartDelayMs: 250 },
      { tool: "claude", profile: "account004", createdAt: "2026-07-06T00:00:00.000Z" },
    );

    expect(agentRun.schema).toBe(SCHEMA_IDS.workRun);
    expect(agentRun.status).toBe("failed");
    expect(supervisorRun.schema).toBe(SCHEMA_IDS.workRun);
    expect(supervisorRun.status).toBe("running");
  });

  test("builds capability_card and no_cloud_evidence_pack contracts", () => {
    const card = accountsCapabilityCard({ createdAt: "2026-07-06T00:00:00.000Z" });
    const pack = accountsNoCloudEvidencePack(".", { createdAt: "2026-07-06T00:00:00.000Z" });

    expect(card.schema).toBe(SCHEMA_IDS.capabilityCard);
    expect(card.capabilities).toContain("event-emission");
    expect(pack.schema).toBe(SCHEMA_IDS.noCloudEvidencePack);
    expect(pack.packageName).toBe("@hasna/accounts");
  });

  test("uses live timestamps by default for generated contracts", () => {
    const before = Date.now();
    const actor = toAccountsActorRef({ name: "@hasna/accounts" });
    const after = Date.now();

    const created = Date.parse(actor.createdAt);
    expect(created).toBeGreaterThanOrEqual(before);
    expect(created).toBeLessThanOrEqual(after);
  });
});
