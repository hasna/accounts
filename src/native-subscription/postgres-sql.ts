/**
 * Package-owned structural SQL contract used by the native-subscription
 * Postgres adapters. Bun.SQL satisfies this interface, but the public
 * declarations do not require consumers to install Bun's ambient types.
 */
export interface PostgresSimpleQuery<T = unknown> extends PromiseLike<T> {}

export interface PostgresTransaction {
  <T = readonly Record<string, unknown>[]>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): PostgresSimpleQuery<T>;
  readonly unsafe: <T = unknown>(sql: string) => {
    readonly simple: () => PostgresSimpleQuery<T>;
  };
}

export interface PostgresSqlClient {
  readonly begin: <T>(
    options: string,
    callback: (transaction: PostgresTransaction) => Promise<T>,
  ) => Promise<T>;
}
