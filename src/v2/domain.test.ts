import { describe, expect, test } from "bun:test";
import {
  accountSchema,
  accountV2DtoSchema,
  renameAccountInputSchema,
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
  test.each([
    ["missing milliseconds", "2026-07-27T10:00:00Z"],
    ["sub-millisecond precision", "2026-07-27T10:00:00.0001Z"],
    ["excess fractional precision", "2026-07-27T10:00:00.000000Z"],
    ["offset alias", "2026-07-27T12:00:00.000+02:00"],
    ["invalid calendar date", "2026-02-30T10:00:00.000Z"],
  ])("rejects noncanonical %s timestamps at every entity ingress", (_label, timestamp) => {
    expect(accountSchema.safeParse({ ...account(), createdAt: timestamp }).success).toBe(false);
    expect(
      runtimeSchema.safeParse({
        id: runtimeId,
        tenantId,
        scopeId,
        key: "claude",
        label: "Claude Code",
        createdAt: NOW,
        updatedAt: timestamp,
      }).success,
    ).toBe(false);
    expect(
      renameAccountInputSchema.safeParse({
        name: "renamed",
        updatedAt: timestamp,
      }).success,
    ).toBe(false);
  });

  test("preserves the exact canonical millisecond timestamp representation", () => {
    const value = account();
    expect(value.createdAt).toBe(NOW);
    expect(value.updatedAt).toBe(NOW);
  });

  test.each([
    ["account", accountSchema, { ...account(), createdAt: "2026-07-27T11:00:00.000Z" }],
    [
      "runtime",
      runtimeSchema,
      {
        id: runtimeId,
        tenantId,
        scopeId,
        key: "claude",
        label: "Claude Code",
        createdAt: "2026-07-27T11:00:00.000Z",
        updatedAt: NOW,
      },
    ],
  ])("rejects %s entities whose updatedAt precedes createdAt", (_label, schema, value) => {
    expect(schema.safeParse(value).success).toBe(false);
  });

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

  test("machine binding ingress and every egress view cannot mutate overlay state", () => {
    const scope = registryScopeSchema.parse({ tenantId, scopeId });
    const input = machineBindingSchema.parse({
      id: "binding_00000000001",
      ...scope,
      accountId,
      runtimeId,
      machineId: "machine_00000000001",
      rootPath: "/machines/original/accounts/work",
      credentialRef: "vault:original",
      authentication: "authenticated",
      generation: 1,
    });
    const overlay = new MachineBindingOverlay(input.machineId);
    const inserted = overlay.put(scope, input);
    overlay.setCurrent(scope, input.runtimeId, input.id);
    overlay.setApplied(scope, input.runtimeId, input.id);

    const fetched = overlay.get(scope, input.id);
    const accountBindings = overlay.forAccount(scope, input.accountId);
    expect(Object.isFrozen(accountBindings)).toBe(true);
    expect(inserted).not.toBe(fetched);
    expect(fetched).not.toBe(overlay.get(scope, input.id));
    const views = [
      inserted,
      fetched,
      accountBindings[0],
      overlay.current(scope, input.runtimeId),
      overlay.applied(scope, input.runtimeId),
    ];
    for (const view of views) {
      if (!view) throw new Error("expected binding view");
      expect(Object.isFrozen(view)).toBe(true);
      expect(() =>
        Object.assign(view as Record<string, unknown>, {
          tenantId: "tenant_000000000099",
          scopeId: "scope_000000000099",
          accountId: "account_00000000099",
          rootPath: "/foreign/root",
          credentialRef: "vault:foreign",
        }),
      ).toThrow();
    }

    Object.assign(input as unknown as Record<string, unknown>, {
      id: "binding_00000000099",
      tenantId: "tenant_000000000099",
      rootPath: "/foreign/input-root",
      credentialRef: "vault:foreign-input",
    });
    expect(overlay.get(scope, "binding_00000000001")).toMatchObject({
      tenantId,
      scopeId,
      accountId,
      rootPath: "/machines/original/accounts/work",
      credentialRef: "vault:original",
    });
    expect(overlay.get(scope, input.id)).toBeNull();
  });

  test.each([
    ["negative", -1],
    ["fractional", 1.5],
    ["NaN", Number.NaN],
    ["positive infinity", Number.POSITIVE_INFINITY],
    ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
    ["overflow exponent", 1e309],
  ])("rejects %s machine-binding generations", (_label, generation) => {
    expect(
      machineBindingSchema.safeParse({
        id: "binding_00000000001",
        tenantId,
        scopeId,
        accountId,
        runtimeId,
        machineId: "machine_00000000001",
        rootPath: "/machines/original/accounts/work",
        authentication: "authenticated",
        generation,
      }).success,
    ).toBe(false);
  });

  test("allows the final safe generation once, permits exact replay, and rejects exhaustion", () => {
    const scope = registryScopeSchema.parse({ tenantId, scopeId });
    const initial = machineBindingSchema.parse({
      id: "binding_00000000001",
      ...scope,
      accountId,
      runtimeId,
      machineId: "machine_00000000001",
      rootPath: "/machines/original/accounts/work",
      authentication: "authenticated",
      generation: Number.MAX_SAFE_INTEGER - 1,
    });
    const final = machineBindingSchema.parse({
      ...initial,
      rootPath: "/machines/final/accounts/work",
      generation: Number.MAX_SAFE_INTEGER,
    });
    const overlay = new MachineBindingOverlay(initial.machineId);

    expect(overlay.put(scope, initial)).toEqual(initial);
    expect(overlay.put(scope, final)).toEqual(final);
    expect(overlay.put(scope, { ...final })).toEqual(final);
    expect(() =>
      overlay.put(scope, {
        ...final,
        rootPath: "/machines/unrepresentable/accounts/work",
      }),
    ).toThrow(/exhausted/i);
    expect(() =>
      overlay.put(scope, {
        ...final,
        generation: Number.MAX_SAFE_INTEGER + 1,
      }),
    ).toThrow(/safe integer|generation/i);
    expect(overlay.get(scope, final.id)).toEqual(final);
  });
});
