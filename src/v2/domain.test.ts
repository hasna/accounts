import { describe, expect, test } from "bun:test";
import {
  accountSchema,
  accountV2DtoSchema,
  registryScopeSchema,
  runtimeSchema,
  toAccountV2Dto,
  type Account,
} from "./domain.js";
import { MachineBindingOverlay, machineBindingSchema } from "./machine-binding.js";

const NOW = "2026-07-27T10:00:00.000Z";
const tenantId = "tenant_000000000001";
const scopeId = "scope_000000000001";
const accountId = "account_00000000001";
const runtimeId = "runtime_00000000001";

function account(): Account {
  return accountSchema.parse({
    id: accountId,
    tenantId,
    scopeId,
    name: "work",
    runtimeId,
    email: "work@example.test",
    metadata: { identity_hint: "sanitized" },
    createdAt: NOW,
    updatedAt: NOW,
  });
}

describe("v2 domain boundary", () => {
  test("uses opaque identity fields and excludes machine authentication from Account/Runtime", () => {
    expect(accountSchema.safeParse({ ...account(), id: "work" }).success).toBe(false);
    expect(
      accountSchema.safeParse({
        ...account(),
        authentication: "authenticated",
      }).success,
    ).toBe(false);
    expect(
      runtimeSchema.safeParse({
        id: runtimeId,
        tenantId,
        scopeId,
        key: "claude",
        label: "Claude Code",
        authentication: "authenticated",
        createdAt: NOW,
        updatedAt: NOW,
      }).success,
    ).toBe(false);
  });

  test("strict wire DTOs reject local fields while serialization omits them", () => {
    const composite = {
      ...account(),
      dir: "/machine/private/root",
      rootPath: "/machine/private/root",
      credentialRef: "vault:item",
      credentials: { access: "never-wire" },
      authentication: "authenticated",
      current: true,
      applied: true,
    };
    expect(accountV2DtoSchema.safeParse(composite).success).toBe(false);
    const dto = toAccountV2Dto(composite);
    expect(dto).toEqual(account());
    for (const forbidden of [
      "dir",
      "rootPath",
      "credentialRef",
      "credentials",
      "authentication",
      "current",
      "applied",
    ]) {
      expect(forbidden in dto).toBe(false);
    }
  });

  test("two machines bind one account with independent roots, auth, current and applied state", () => {
    const scope = registryScopeSchema.parse({ tenantId, scopeId });
    const first = machineBindingSchema.parse({
      id: "binding_00000000001",
      tenantId,
      scopeId,
      accountId,
      runtimeId,
      machineId: "machine_00000000001",
      rootPath: "/machines/one/accounts/work",
      credentialRef: "vault:machine-one",
      authentication: "authenticated",
      generation: 2,
    });
    const second = machineBindingSchema.parse({
      id: "binding_00000000002",
      tenantId,
      scopeId,
      accountId,
      runtimeId,
      machineId: "machine_00000000002",
      rootPath: "/machines/two/accounts/work",
      credentialRef: "vault:machine-two",
      authentication: "needs_login",
      generation: 7,
    });
    const machineOne = new MachineBindingOverlay(first.machineId, [first]);
    const machineTwo = new MachineBindingOverlay(second.machineId, [second]);
    machineOne.setCurrent(first.runtimeId, first.id);
    machineOne.setApplied(first.runtimeId, first.id);

    expect(machineOne.forAccount(scope, first.accountId)[0]?.rootPath).toBe(
      "/machines/one/accounts/work",
    );
    expect(machineTwo.forAccount(scope, second.accountId)[0]?.rootPath).toBe(
      "/machines/two/accounts/work",
    );
    expect(machineOne.current(first.runtimeId)?.id).toBe(first.id);
    expect(machineTwo.current(second.runtimeId)).toBeNull();
    expect(machineOne.applied(first.runtimeId)?.id).toBe(first.id);
    expect(machineTwo.applied(second.runtimeId)).toBeNull();
    expect(machineOne.get(first.id)?.authentication).toBe("authenticated");
    expect(machineTwo.get(second.id)?.authentication).toBe("needs_login");
    expect(toAccountV2Dto(account())).toEqual(account());
  });
});
