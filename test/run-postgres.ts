const child = Bun.spawn({
  cmd: [process.execPath, "test", "./src/server/postgres.integration.ts", ...process.argv.slice(2)],
  cwd: process.cwd(),
  env: {
    ...process.env,
    ACCOUNTS_REQUIRE_POSTGRES: "1",
    ACCOUNTS_POSTGRES_TEST_TARGET: "1",
  },
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});

process.exit(await child.exited);
