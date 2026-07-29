// End-to-end proof that the production registry refuses an ephemeral profile
// dir. The unit tests in src/lib/profile-dir-policy.test.ts prove the decision
// function; these prove the decision is actually WIRED into the HTTP surface
// that `accounts add` talks to. A policy nothing calls is not a control.

import { describe, expect, test } from "bun:test";
import { mintApiKey, verifyApiKey } from "@hasna/contracts/auth";
import { createHandler, type ServiceContext } from "./app.js";
import type { Account, AccountsStore, CurrentSelection } from "./repo.js";
import { SCOPES } from "./config.js";
import { AccountsError } from "../types.js";

const SIGNING_SECRET = "test-signing-secret-accounts-dir-guard";

/** Records whether the store was reached, so we can prove rejection is pre-write. */
class SpyStore implements AccountsStore {
  writes: string[] = [];
  private accounts = new Map<string, Account>();
  private k(tool: string, name: string) {
    return `${tool} ${name}`;
  }
  async list(): Promise<Account[]> {
    return [...this.accounts.values()];
  }
  async get(tool: string, name: string): Promise<Account | null> {
    return this.accounts.get(this.k(tool, name)) ?? null;
  }
  async create(input: any): Promise<Account> {
    this.writes.push(`create ${input.tool}/${input.name} dir=${input.dir ?? ""}`);
    const account: Account = {
      tool: input.tool,
      name: input.name,
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString(),
      ...(input.dir ? { dir: input.dir } : {}),
    };
    this.accounts.set(this.k(input.tool, input.name), account);
    return account;
  }
  async update(tool: string, name: string, input: any): Promise<Account> {
    this.writes.push(`update ${tool}/${name} dir=${input.dir ?? ""}`);
    const existing = this.accounts.get(this.k(tool, name));
    if (!existing) throw new AccountsError(`no profile named "${name}" for tool "${tool}"`);
    const updated = { ...existing, ...(input.dir !== undefined ? { dir: input.dir } : {}) };
    this.accounts.set(this.k(tool, name), updated);
    return updated;
  }
  async rename(tool: string, oldName: string, newName: string): Promise<Account> {
    const existing = this.accounts.get(this.k(tool, oldName));
    if (!existing) throw new AccountsError(`no profile named "${oldName}"`);
    this.accounts.delete(this.k(tool, oldName));
    const renamed = { ...existing, name: newName };
    this.accounts.set(this.k(tool, newName), renamed);
    return renamed;
  }
  async remove(tool: string, name: string): Promise<boolean> {
    return this.accounts.delete(this.k(tool, name));
  }
  async listCurrent(): Promise<CurrentSelection[]> {
    return [];
  }
  async getCurrent(): Promise<CurrentSelection | null> {
    return null;
  }
  async setCurrent(tool: string, name: string): Promise<CurrentSelection> {
    return { tool, name, updatedAt: new Date().toISOString() };
  }
  async listCustomTools(): Promise<any[]> {
    return [];
  }
  async addCustomTool(def: any): Promise<any> {
    return def;
  }
  async removeCustomTool(): Promise<boolean> {
    return true;
  }
}

function harness() {
  const repo = new SpyStore();
  const ctx: ServiceContext = {
    repo,
    verifier: verifyApiKey({ app: "accounts", signingSecret: SIGNING_SECRET }),
    health: async () => ({ ok: true }),
    ready: async () => ({ ready: true }),
    mode: "cloud",
    version: "test",
    close: async () => {},
  };
  const token = mintApiKey({
    app: "accounts",
    scopes: [SCOPES.read, SCOPES.write],
    signingSecret: SIGNING_SECRET,
  }).token;
  const handle = createHandler(ctx);
  const post = (body: unknown) =>
    handle(
      new Request("http://localhost/v1/accounts", {
        method: "POST",
        headers: { "x-api-key": token, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    );
  const patch = (tool: string, name: string, body: unknown) =>
    handle(
      new Request(`http://localhost/v1/accounts/${tool}/${name}`, {
        method: "PATCH",
        headers: { "x-api-key": token, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    );
  return { repo, post, patch };
}

describe("POST /v1/accounts rejects ephemeral profile dirs", () => {
  test("the exact shape that polluted production is refused with 400", async () => {
    const { repo, post } = harness();
    const res = await post({
      name: "acct",
      tool: "claude",
      dir: "/tmp/accounts-login-cli-1ITud2/profiles/claude/acct",
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/ephemeral root/);
    // The write never reached the store — refusal is before persistence.
    expect(repo.writes).toEqual([]);
  });

  test("an agent scratchpad path is refused", async () => {
    const { repo, post } = harness();
    const res = await post({
      name: "profclaude",
      tool: "claude",
      dir: "/tmp/claude-1000/-home-hasna/abc/scratchpad/h2/prof-claude",
    });
    expect(res.status).toBe(400);
    expect(repo.writes).toEqual([]);
  });

  test("a non-tool-home path under a real home is refused", async () => {
    const { repo, post } = harness();
    const res = await post({ name: "x", tool: "claude", dir: "/home/hasna/scratch/x" });
    expect(res.status).toBe(400);
    expect(repo.writes).toEqual([]);
  });

  // POSITIVE CONTROL: the same request path must still admit a real dir,
  // otherwise the 400s above would prove only that the endpoint is broken.
  test("a legitimate managed dir is still accepted with 201", async () => {
    const { repo, post } = harness();
    const res = await post({
      name: "account003",
      tool: "claude",
      dir: "/home/hasna/.hasna/accounts/profiles/claude/account003",
    });
    expect(res.status).toBe(201);
    expect(repo.writes).toEqual([
      "create claude/account003 dir=/home/hasna/.hasna/accounts/profiles/claude/account003",
    ]);
  });

  test("omitting dir entirely is still accepted", async () => {
    const { post } = harness();
    const res = await post({ name: "nodir", tool: "claude" });
    expect(res.status).toBe(201);
  });
});

describe("POST /v1/tools rejects ephemeral tool homes (F2)", () => {
  // Same registry, same write scope: before this, accounts.dir=/tmp/evil was
  // refused while tools.defaultDir=/tmp/evil sailed through — and the tool's
  // defaultDir is consumed as a profile dir downstream.
  const postTool = (defaultDir: string) => {
    const { repo } = harness();
    const ctx: ServiceContext = {
      repo,
      verifier: verifyApiKey({ app: "accounts", signingSecret: SIGNING_SECRET }),
      health: async () => ({ ok: true }),
      ready: async () => ({ ready: true }),
      mode: "cloud",
      version: "test",
      close: async () => {},
    };
    const token = mintApiKey({
      app: "accounts",
      scopes: [SCOPES.read, SCOPES.write],
      signingSecret: SIGNING_SECRET,
    }).token;
    return createHandler(ctx)(
      new Request("http://localhost/v1/tools", {
        method: "POST",
        headers: { "x-api-key": token, "Content-Type": "application/json" },
        body: JSON.stringify({
          id: "eviltool",
          label: "Evil",
          envVar: "EVIL_HOME",
          defaultDir,
          bin: "evil",
        }),
      }),
    );
  };

  test("a /tmp tool home is refused with 400", async () => {
    const res = await postTool("/tmp/evil");
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/ephemeral root/);
  });

  test("/dev/shm is refused", async () => {
    expect((await postTool("/dev/shm/x")).status).toBe(400);
  });

  test("a bare relative string is refused", async () => {
    expect((await postTool("relative")).status).toBe(400);
  });

  // POSITIVE CONTROL: a genuinely new tool home must still register, otherwise
  // the 400s above would only prove the endpoint is broken.
  test("a new tool home outside the built-in table is still accepted", async () => {
    const res = await postTool("/home/hasna/.some-new-agent");
    expect(res.status).toBe(201);
  });
});

describe("PATCH /v1/accounts/:tool/:name rejects ephemeral profile dirs", () => {
  test("a stored account cannot be repointed at /tmp", async () => {
    const { repo, post, patch } = harness();
    await post({
      name: "account003",
      tool: "claude",
      dir: "/home/hasna/.hasna/accounts/profiles/claude/account003",
    });
    repo.writes.length = 0;

    const res = await patch("claude", "account003", { dir: "/tmp/somewhere-else" });
    expect(res.status).toBe(400);
    expect(repo.writes).toEqual([]);

    // And the stored value is untouched.
    const stored = await repo.get("claude", "account003");
    expect(stored?.dir).toBe("/home/hasna/.hasna/accounts/profiles/claude/account003");
  });

  test("repointing at another legitimate dir still works", async () => {
    const { repo, post, patch } = harness();
    await post({ name: "account003", tool: "claude", dir: "/home/hasna/.claude" });
    const res = await patch("claude", "account003", {
      dir: "/home/hasna/.hasna/accounts/profiles/claude/account003",
    });
    expect(res.status).toBe(200);
    const stored = await repo.get("claude", "account003");
    expect(stored?.dir).toBe("/home/hasna/.hasna/accounts/profiles/claude/account003");
  });
});
