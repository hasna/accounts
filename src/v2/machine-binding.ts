import { isAbsolute } from "node:path";
import { z } from "zod";
import {
  accountIdSchema,
  bindingIdSchema,
  machineIdSchema,
  registryScopeSchema,
  runtimeIdSchema,
  type AccountId,
  type BindingId,
  type RegistryScope,
  type RuntimeId,
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
  private readonly bindings = new Map<BindingId, MachineBinding>();
  private readonly currentByRuntime = new Map<RuntimeId, BindingId>();
  private readonly appliedByRuntime = new Map<RuntimeId, BindingId>();

  constructor(readonly machineId: MachineBinding["machineId"], seed: readonly MachineBinding[] = []) {
    for (const binding of seed) this.put(binding);
  }

  put(input: MachineBinding): MachineBinding {
    const binding = machineBindingSchema.parse(input);
    if (binding.machineId !== this.machineId) {
      throw new Error("machine binding belongs to a different machine");
    }
    const existing = this.bindings.get(binding.id);
    if (
      existing &&
      (existing.accountId !== binding.accountId ||
        existing.runtimeId !== binding.runtimeId ||
        existing.tenantId !== binding.tenantId ||
        existing.scopeId !== binding.scopeId)
    ) {
      throw new Error("binding identity fields are immutable");
    }
    this.bindings.set(binding.id, binding);
    return binding;
  }

  get(bindingId: BindingId): MachineBinding | null {
    return this.bindings.get(bindingId) ?? null;
  }

  forAccount(scopeInput: RegistryScope, accountId: AccountId): readonly MachineBinding[] {
    const scope = registryScopeSchema.parse(scopeInput);
    return [...this.bindings.values()].filter(
      (binding) =>
        binding.tenantId === scope.tenantId &&
        binding.scopeId === scope.scopeId &&
        binding.accountId === accountId,
    );
  }

  setCurrent(runtimeId: RuntimeId, bindingId: BindingId): void {
    const binding = this.requireRuntimeBinding(runtimeId, bindingId);
    this.currentByRuntime.set(runtimeId, binding.id);
  }

  setApplied(runtimeId: RuntimeId, bindingId: BindingId): void {
    const binding = this.requireRuntimeBinding(runtimeId, bindingId);
    this.appliedByRuntime.set(runtimeId, binding.id);
  }

  current(runtimeId: RuntimeId): MachineBinding | null {
    const bindingId = this.currentByRuntime.get(runtimeId);
    return bindingId ? this.get(bindingId) : null;
  }

  applied(runtimeId: RuntimeId): MachineBinding | null {
    const bindingId = this.appliedByRuntime.get(runtimeId);
    return bindingId ? this.get(bindingId) : null;
  }

  private requireRuntimeBinding(runtimeId: RuntimeId, bindingId: BindingId): MachineBinding {
    const binding = this.bindings.get(bindingId);
    if (!binding || binding.runtimeId !== runtimeId) {
      throw new Error("binding is not registered for this runtime on this machine");
    }
    return binding;
  }
}
