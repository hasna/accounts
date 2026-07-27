import { isAbsolute } from "node:path";
import { z } from "zod";
import {
  accountIdSchema,
  assertEntityScope,
  bindingIdSchema,
  machineIdSchema,
  registryScopeSchema,
  runtimeIdSchema,
  type AccountId,
  type BindingId,
  type MachineId,
  type RuntimeId,
  type ScopeRef,
} from "./domain.js";

export const bindingAuthenticationSchema = z.enum([
  "authenticated",
  "needs_login",
  "unknown",
]);

export const machineBindingSchema = z
  .object({
    id: bindingIdSchema,
    tenantId: registryScopeSchema.shape.tenantId,
    scopeId: registryScopeSchema.shape.scopeId,
    accountId: accountIdSchema,
    runtimeId: runtimeIdSchema,
    machineId: machineIdSchema,
    rootPath: z.string().min(1).refine(isAbsolute, "binding rootPath must be absolute"),
    credentialRef: z.string().min(1).max(512).optional(),
    authentication: bindingAuthenticationSchema,
    generation: z.number().int().nonnegative(),
  })
  .strict();

export type MachineBinding = Readonly<z.infer<typeof machineBindingSchema>>;
export type BindingAuthentication = z.infer<typeof bindingAuthenticationSchema>;

/**
 * Process-local view of machine bindings and legacy current/applied pointers.
 * It has no serialization or registry methods, so these fields cannot enter
 * cloud authority through AccountsRegistry.
 */
export class MachineBindingOverlay {
  readonly machineId: MachineId;
  private readonly bindings = new Map<string, MachineBinding>();
  private readonly currentByRuntime = new Map<string, BindingId>();
  private readonly appliedByRuntime = new Map<string, BindingId>();

  constructor(machineIdInput: MachineBinding["machineId"]) {
    this.machineId = machineIdSchema.parse(machineIdInput);
  }

  put(scopeInput: ScopeRef, input: MachineBinding): MachineBinding {
    const scope = registryScopeSchema.parse(scopeInput);
    const binding = immutableBinding(input);
    assertEntityScope(scope, binding);
    if (binding.machineId !== this.machineId) {
      throw new Error("machine binding belongs to a different machine");
    }
    const bindingKey = scopedKey(scope, binding.id);
    const existing = this.bindings.get(bindingKey);
    if (existing) assertBindingTransition(existing, binding);
    this.bindings.set(bindingKey, binding);
    return immutableBinding(binding);
  }

  get(scopeInput: ScopeRef, bindingIdInput: BindingId): MachineBinding | null {
    const scope = registryScopeSchema.parse(scopeInput);
    const bindingId = bindingIdSchema.parse(bindingIdInput);
    const binding = this.bindings.get(scopedKey(scope, bindingId));
    return binding ? immutableBinding(binding) : null;
  }

  forAccount(scopeInput: ScopeRef, accountIdInput: AccountId): readonly MachineBinding[] {
    const scope = registryScopeSchema.parse(scopeInput);
    const accountId = accountIdSchema.parse(accountIdInput);
    return Object.freeze(
      [...this.bindings.values()]
        .filter(
          (binding) =>
            binding.tenantId === scope.tenantId &&
            binding.scopeId === scope.scopeId &&
            binding.accountId === accountId,
        )
        .map(immutableBinding),
    );
  }

  setCurrent(scopeInput: ScopeRef, runtimeIdInput: RuntimeId, bindingIdInput: BindingId): void {
    const scope = registryScopeSchema.parse(scopeInput);
    const binding = this.requireRuntimeBinding(scope, runtimeIdInput, bindingIdInput);
    this.currentByRuntime.set(scopedKey(scope, binding.runtimeId), binding.id);
  }

  setApplied(scopeInput: ScopeRef, runtimeIdInput: RuntimeId, bindingIdInput: BindingId): void {
    const scope = registryScopeSchema.parse(scopeInput);
    const binding = this.requireRuntimeBinding(scope, runtimeIdInput, bindingIdInput);
    this.appliedByRuntime.set(scopedKey(scope, binding.runtimeId), binding.id);
  }

  current(scopeInput: ScopeRef, runtimeIdInput: RuntimeId): MachineBinding | null {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const bindingId = this.currentByRuntime.get(scopedKey(scope, runtimeId));
    return bindingId ? this.get(scope, bindingId) : null;
  }

  applied(scopeInput: ScopeRef, runtimeIdInput: RuntimeId): MachineBinding | null {
    const scope = registryScopeSchema.parse(scopeInput);
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const bindingId = this.appliedByRuntime.get(scopedKey(scope, runtimeId));
    return bindingId ? this.get(scope, bindingId) : null;
  }

  private requireRuntimeBinding(
    scope: ScopeRef,
    runtimeIdInput: RuntimeId,
    bindingIdInput: BindingId,
  ): MachineBinding {
    const runtimeId = runtimeIdSchema.parse(runtimeIdInput);
    const bindingId = bindingIdSchema.parse(bindingIdInput);
    const binding = this.bindings.get(scopedKey(scope, bindingId));
    if (!binding || binding.runtimeId !== runtimeId) {
      throw new Error("binding is not registered for this runtime and scope on this machine");
    }
    return binding;
  }
}

function scopedKey(scope: ScopeRef, id: string): string {
  return `${scope.tenantId}\0${scope.scopeId}\0${id}`;
}

function immutableBinding(input: MachineBinding): MachineBinding {
  return Object.freeze(machineBindingSchema.parse(input));
}

function assertBindingTransition(current: MachineBinding, next: MachineBinding): void {
  if (
    current.id !== next.id ||
    current.accountId !== next.accountId ||
    current.runtimeId !== next.runtimeId ||
    current.machineId !== next.machineId ||
    current.tenantId !== next.tenantId ||
    current.scopeId !== next.scopeId
  ) {
    throw new Error("binding identity fields are immutable");
  }
  if (next.generation < current.generation) {
    throw new Error("machine binding generation cannot move backwards");
  }
  if (next.generation === current.generation && !sameBinding(current, next)) {
    throw new Error("same-generation machine binding update must be an exact idempotent replay");
  }
}

function sameBinding(first: MachineBinding, second: MachineBinding): boolean {
  return (
    first.id === second.id &&
    first.tenantId === second.tenantId &&
    first.scopeId === second.scopeId &&
    first.accountId === second.accountId &&
    first.runtimeId === second.runtimeId &&
    first.machineId === second.machineId &&
    first.rootPath === second.rootPath &&
    first.credentialRef === second.credentialRef &&
    first.authentication === second.authentication &&
    first.generation === second.generation
  );
}
