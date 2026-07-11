import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { chmodSync, existsSync, lstatSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { AccountsError } from "../../src/errors";
import { canonicalJson } from "../../src/serialization/json";
import {
  createAccountsSlotEligibilityAdapter,
  createDeterministicAccountsSlotEligibilitySource,
  type AccountsEvidenceSignerHistoryV2,
} from "../../src/v10";
import {
  SQLiteAccountsSlotEligibilitySource,
  type AccountsRecoveryFrontierPort,
  type AccountsRecoveryFrontierV1,
} from "../../src/v10/sqlite-slot-source";

interface Fixture {
  readonly wire: Record<string, unknown>;
}

const fixtureDocument = await Bun.file(
  new URL("../../contracts/accounts-v10/acc-041-fixtures.json", import.meta.url),
).json() as {
  readonly signer_history: AccountsEvidenceSignerHistoryV2;
  readonly wire_fixtures: Readonly<Record<string, Fixture>>;
};
const NOW = new Date("2026-07-11T10:00:15.000Z");
const LANE_ID = "0198a0a0-0000-7000-8000-000000000002";
const FRONTIER: AccountsRecoveryFrontierV1 = {
  catalog_incarnation: "catalog-incarnation-1",
  sequence: "42",
  hash: `sha256:${"1".repeat(64)}`,
};
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

class MutableRecoveryFrontier implements AccountsRecoveryFrontierPort {
  state: "current" | "stale" | "forked" | "unavailable" = "current";

  async readFreshFrontier(): Promise<AccountsRecoveryFrontierV1> {
    if (this.state === "unavailable") {
      throw new AccountsError("DEPENDENCY_UNAVAILABLE", "Recovery frontier unavailable");
    }
    if (this.state === "stale") return { ...FRONTIER, sequence: "41" };
    if (this.state === "forked") return { ...FRONTIER, hash: `sha256:${"2".repeat(64)}` };
    return FRONTIER;
  }
}

function bytes(name: string): Uint8Array {
  return new TextEncoder().encode(canonicalJson(fixtureDocument.wire_fixtures[name]!.wire));
}

function installSignedEvidence(path: string): void {
  const database = new Database(path);
  try {
    const insert = database.query(`
      INSERT INTO accounts_v10_signed_evidence(
        account_lane_id, phase, decision, wire_jcs,
        catalog_incarnation, recovery_frontier_sequence, recovery_frontier_hash
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    for (const [phase, decision, name] of [
      ["SLOT", "ALLOW", "slot_eligibility_brokered_positive"],
      ["SLOT", "DENY", "slot_eligibility_brokered_resolved_negative"],
      ["ONLINE", "ALLOW", "online_generation_check_positive"],
      ["ONLINE", "DENY", "online_generation_check_resolved_negative"],
    ] as const) {
      insert.run(
        LANE_ID,
        phase,
        decision,
        bytes(name),
        FRONTIER.catalog_incarnation,
        FRONTIER.sequence,
        FRONTIER.hash,
      );
    }
    database.query(
      "INSERT INTO accounts_v10_runtime_state(account_lane_id, current_deny) VALUES (?, 0)",
    ).run(LANE_ID);
  } finally {
    database.close();
  }
}

describe("ACC-041 SQLite Slot/online adapter", () => {
  test("uses the same exact codecs for deterministic and production SQLite sources", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-slot-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const frontier = new MutableRecoveryFrontier();
    const source = new SQLiteAccountsSlotEligibilitySource({ path, recoveryFrontier: frontier });
    installSignedEvidence(path);
    const trust = {
      signerHistory: fixtureDocument.signer_history,
      clock: () => new Date(NOW),
    };
    const production = createAccountsSlotEligibilityAdapter(source, trust);
    const deterministic = createAccountsSlotEligibilityAdapter(
      createDeterministicAccountsSlotEligibilitySource({
        slot: bytes("slot_eligibility_brokered_positive"),
        online: bytes("online_generation_check_positive"),
      }),
      trust,
    );

    const query = { account_lane_id: LANE_ID };
    expect(await production.getSlotEligibility(query)).toEqual(
      await deterministic.getSlotEligibility(query),
    );
    expect(await production.checkOnlineGeneration(query)).toEqual(
      await deterministic.checkOnlineGeneration(query),
    );
    for (const candidate of [path, `${path}-wal`, `${path}-shm`]) {
      if (existsSync(candidate)) expect(lstatSync(candidate).mode & 0o777).toBe(0o600);
    }
    source.close();
  });

  test("current deny changes signed generation/revision consequences and no allow survives", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-deny-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const source = new SQLiteAccountsSlotEligibilitySource({
      path,
      recoveryFrontier: new MutableRecoveryFrontier(),
    });
    installSignedEvidence(path);
    const port = createAccountsSlotEligibilityAdapter(source, {
      signerHistory: fixtureDocument.signer_history,
      clock: () => new Date(NOW),
    });
    const query = { account_lane_id: LANE_ID };
    const allowed = await port.checkOnlineGeneration(query);
    expect(allowed.allowed).toBe(true);

    const database = new Database(path);
    database.query(
      "UPDATE accounts_v10_runtime_state SET current_deny=1 WHERE account_lane_id=?",
    ).run(LANE_ID);
    database.close();
    const deniedSlot = await port.getSlotEligibility(query);
    const denied = await port.checkOnlineGeneration(query);
    expect(deniedSlot.eligible).toBe(false);
    expect(denied.allowed).toBe(false);
    expect(denied.current_deny).toBe(true);
    expect(BigInt(denied.deny_generation)).toBeGreaterThan(BigInt(allowed.deny_generation));
    expect(denied.accounts_revision_set_digest).not.toBe(allowed.accounts_revision_set_digest);
    source.close();
  });

  test("stale, forked, or unavailable external frontier fails before returning signed evidence", async () => {
    const root = mkdtempSync(join(tmpdir(), "accounts-v10-frontier-"));
    chmodSync(root, 0o700);
    roots.push(root);
    const path = join(root, "accounts.sqlite");
    const frontier = new MutableRecoveryFrontier();
    const source = new SQLiteAccountsSlotEligibilitySource({ path, recoveryFrontier: frontier });
    installSignedEvidence(path);

    for (const state of ["stale", "forked", "unavailable"] as const) {
      frontier.state = state;
      await expect(source.getSlotEligibility({ account_lane_id: LANE_ID }))
        .rejects.toBeInstanceOf(AccountsError);
      await expect(source.checkOnlineGeneration({ account_lane_id: LANE_ID }))
        .rejects.toBeInstanceOf(AccountsError);
    }
    source.close();
  });
});
