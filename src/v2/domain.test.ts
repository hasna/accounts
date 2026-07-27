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
      metadata: {
        rootPath: "/machine/private/nested-root",
        credentialRef: "vault:nested-item",
        authentication: "authenticated",
        current: true,
        applied: true,
      },
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
      "metadata",
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
    const machineOne = new MachineBindingOverlay(first.machineId);
    const machineTwo = new MachineBindingOverlay(second.machineId);
    machineOne.put(scope, first);
    machineTwo.put(scope, second);
    machineOne.setCurrent(scope, first.runtimeId, first.id);
    machineOne.setApplied(scope, first.runtimeId, first.id);

    expect(machineOne.forAccount(scope, first.accountId)[0]?.rootPath).toBe(
      "/machines/one/accounts/work",
    );
    expect(machineTwo.forAccount(scope, second.accountId)[0]?.rootPath).toBe(
      "/machines/two/accounts/work",
    );
    expect(machineOne.current(scope, first.runtimeId)?.id).toBe(first.id);
    expect(machineTwo.current(scope, second.runtimeId)).toBeNull();
    expect(machineOne.applied(scope, first.runtimeId)?.id).toBe(first.id);
    expect(machineTwo.applied(scope, second.runtimeId)).toBeNull();
    expect(machineOne.get(scope, first.id)?.authentication).toBe("authenticated");
    expect(machineTwo.get(scope, second.id)?.authentication).toBe("needs_login");
    expect(toAccountV2Dto(account())).toEqual(account());
  });

  test("identical binding, account and runtime ids remain isolated across scopes", () => {
    const firstScope = registryScopeSchema.parse({ tenantId, scopeId });
    const secondScope = registryScopeSchema.parse({
      tenantId: "tenant_000000000002",
      scopeId: "scope_000000000002",
    });
    const shared = {
      id: "binding_00000000001",
      accountId,
      runtimeId,
      machineId: "machine_00000000001",
      credentialRef: "vault:shared-reference",
    } as const;
    const first = machineBindingSchema.parse({
      ...shared,
      ...firstScope,
      rootPath: "/machines/shared/tenant-one",
      authentication: "authenticated",
      generation: 1,
    });
    const second = machineBindingSchema.parse({
      ...shared,
      ...secondScope,
      rootPath: "/machines/shared/tenant-two",
      authentication: "needs_login",
      generation: 2,
    });
    const overlay = new MachineBindingOverlay(first.machineId);
    overlay.put(firstScope, first);
    overlay.put(secondScope, second);

    overlay.setCurrent(firstScope, first.runtimeId, first.id);
    overlay.setCurrent(secondScope, second.runtimeId, second.id);
    overlay.setApplied(firstScope, first.runtimeId, first.id);

    expect(overlay.get(firstScope, first.id)?.rootPath).toBe("/machines/shared/tenant-one");
    expect(overlay.get(secondScope, second.id)?.rootPath).toBe("/machines/shared/tenant-two");
    expect(overlay.current(firstScope, first.runtimeId)?.rootPath).toBe(
      "/machines/shared/tenant-one",
    );
    expect(overlay.current(secondScope, second.runtimeId)?.rootPath).toBe(
      "/machines/shared/tenant-two",
    );
    expect(overlay.applied(firstScope, first.runtimeId)?.id).toBe(first.id);
    expect(overlay.applied(secondScope, second.runtimeId)).toBeNull();
    expect(() => overlay.put(firstScope, second)).toThrow(/does not belong/);

    overlay.put(firstScope, { ...first, generation: 3 });
    expect(overlay.get(firstScope, first.id)?.generation).toBe(3);
    expect(overlay.get(secondScope, second.id)?.generation).toBe(2);
  });
});
