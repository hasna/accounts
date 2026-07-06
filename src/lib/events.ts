import { EventsClient, type EmitOptions, type EmitResult, type EventInput } from "@hasna/events";
import { validateEventActorRefs } from "./contracts.js";

export class AccountsEventsClient extends EventsClient {
  override async emit<TData extends Record<string, unknown>>(input: EventInput<TData>, options?: EmitOptions): Promise<EmitResult<TData>> {
    return super.emit(validateEventActorRefs(input), options);
  }
}

export function createAccountsEventsClient(options: { dataDir?: string } = {}): EventsClient {
  return new AccountsEventsClient({ dataDir: options.dataDir });
}
