import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EMPTY_CREDENTIAL_MAX_BYTES,
  buildProfileRegistry,
  classifyCredentialPresence,
  credentialKeyForEntry,
  profilesByCredential,
} from "./lib/profile-registry.js";
import { getTool } from "./lib/tools.js";

let home: string;
let root: string;
const tool = () => getTool("claude");

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "accounts-reg-home-"));
  root = mkdtempSync(join(tmpdir(), "accounts-reg-"));
  process.env.ACCOUNTS_HOME = home;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
  delete process.env.ACCOUNTS_HOME;
});

/**
 * Credential payloads are built from a `secret` label so two fixtures either
 * share bytes exactly or differ — the same distinction the registry groups on.
 *
 * `expiresAt` is a FIXED constant, never `Date.now()`. Two writes of the "same"
 * credential a millisecond apart would otherwise differ by one byte and stop
 * grouping, which made this suite pass 5/8, 7/8 or 6/8 on identical code.
 */
const FIXED_EXPIRY = 4_102_444_800_000; // 2100-01-01T00:00:00Z

function credential(secret: string, expiresAt: number = FIXED_EXPIRY): string {
  return JSON.stringify({
    claudeAiOauth: {
      accessToken: `${secret}-access`,
      refreshToken: `${secret}-refresh`,
      expiresAt,
    },
  });
}

function profileDir(name: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, ".accounts-auth"), { recursive: true });
  return dir;
}

function writeLive(dir: string, uuid: string, email: string, secret?: string): void {
  writeFileSync(join(dir, ".claude.json"), JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }));
  if (secret !== undefined) writeFileSync(join(dir, ".credentials.json"), credential(secret));
}

function writeParked(dir: string, uuid: string, email: string, secret?: string): void {
  writeFileSync(
    join(dir, ".accounts-auth", "oauth-account.json"),
    JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }),
  );
  if (secret !== undefined) writeFileSync(join(dir, ".accounts-auth", "credentials.json"), credential(secret));
}

function writeMarker(dir: string, profile: string, email: string): void {
  writeFileSync(
    join(dir, ".accounts-auth", "switched-account.json"),
    JSON.stringify({ profile, email, switchedAt: new Date().toISOString() }),
  );
}

const UUID_A = "11111111-1111-4111-8111-111111111111";
const UUID_B = "22222222-2222-4222-8222-222222222222";
const UUID_C = "33333333-3333-4333-8333-333333333333";

test("absent, empty and present are three distinct states, not two", () => {
  const dir = profileDir("p");
  expect(classifyCredentialPresence(join(dir, "missing.json")).presence).toBe("absent");

  const empty = join(dir, "empty.json");
  writeFileSync(empty, "{}");
  const emptyFacts = classifyCredentialPresence(empty);
  expect(emptyFacts.presence).toBe("empty");
  expect(emptyFacts.bytes).toBeLessThanOrEqual(EMPTY_CREDENTIAL_MAX_BYTES);
  // The whole point: an empty placeholder must not carry a fingerprint, or
  // every `{}` on the machine groups together as a fake duplicate set.
  expect(emptyFacts.fingerprint).toBeUndefined();

  const real = join(dir, "real.json");
  writeFileSync(real, credential("a"));
  const realFacts = classifyCredentialPresence(real);
  expect(realFacts.presence).toBe("present");
  expect(realFacts.fingerprint).toBeTruthy();
});

test("two empty placeholders never form a group", () => {
  const a = profileDir("a");
  const b = profileDir("b");
  writeFileSync(join(a, ".credentials.json"), "{}");
  writeFileSync(join(b, ".credentials.json"), "{}");
  writeLive(a, UUID_A, "a@example.com");
  writeLive(b, UUID_B, "b@example.com");

  const registry = buildProfileRegistry([{ name: "a", dir: a }, { name: "b", dir: b }], tool());
  expect(registry.groups).toHaveLength(0);
  expect(registry.contradictions).toHaveLength(0);
});

test("a switched dir reads as displaced, and its own account is not treated as a copy", () => {
  // The measured shape of account035 on station01: own identity parked, another
  // account's credential switched into the live files, marker recording it.
  const host = profileDir("account035");
  writeParked(host, UUID_A, "fox@survivalvitamins.com", "fox-secret");
  writeLive(host, UUID_B, "jeannie@hasna.studio", "jeannie-secret");
  writeMarker(host, "account039", "jeannie@hasna.studio");

  const guestHome = profileDir("account039");
  writeParked(guestHome, UUID_B, "jeannie@hasna.studio", "jeannie-secret");
  writeLive(guestHome, UUID_B, "jeannie@hasna.studio", "jeannie-secret");

  const registry = buildProfileRegistry(
    [{ name: "account035", dir: host }, { name: "account039", dir: guestHome }],
    tool(),
  );

  const entry = registry.entries.find((e) => e.profileName === "account035")!;
  expect(entry.binding).toBe("displaced");
  expect(entry.own.email).toBe("fox@survivalvitamins.com");
  expect(entry.occupant.email).toBe("jeannie@hasna.studio");
  expect(entry.marker?.profile).toBe("account039");

  // The shared jeannie credential must read as displacement, NOT as two
  // accounts contending for one credential — account035 is a distinct account.
  const shared = registry.groups.find((g) => g.members.length >= 3)!;
  expect(shared.inference.cause).toBe("displacement");
  expect(registry.contradictions).toHaveLength(0);
});

test("one credential under two identities with no switch to explain it is a contradiction", () => {
  // The measured shape of the central store: distinct accounts, distinct
  // emails, byte-identical credential, nothing recording a switch.
  const a = profileDir("account003");
  writeParked(a, UUID_A, "andrew@hasna.studio", "shared-secret");
  writeLive(a, UUID_A, "andrew@hasna.studio", "shared-secret");

  const b = profileDir("account006");
  writeParked(b, UUID_C, "anya@ideawin.com", "shared-secret");
  writeLive(b, UUID_C, "anya@ideawin.com", "shared-secret");

  const registry = buildProfileRegistry([{ name: "account003", dir: a }, { name: "account006", dir: b }], tool());

  expect(registry.contradictions).toHaveLength(1);
  const contradiction = registry.contradictions[0]!;
  expect(contradiction.inference.cause).toBe("contamination");
  expect(contradiction.inference.confidence).toBe("high");
  expect(contradiction.distinctEmails).toEqual(["andrew@hasna.studio", "anya@ideawin.com"]);
  // Never asserted as fact: a later probe can overturn it.
  expect(contradiction.inference.verified).toBeNull();
  expect(contradiction.inference.verificationPath).toContain("probe a sibling");
});

test("a half-finished switch is not reported as contamination", () => {
  // switch-account writes the marker BEFORE it mutates, so a failure midway
  // leaves the guest's credential in the live files while .claude.json still
  // names the host. Counting that host as a claimant on the guest's credential
  // would invent a contradiction out of an ordinary, reversible switch.
  const host = profileDir("host");
  writeParked(host, UUID_A, "host@example.com", "host-secret");
  writeLive(host, UUID_A, "host@example.com", "guest-secret"); // identity not yet rewritten
  writeMarker(host, "guest", "guest@example.com");

  const guest = profileDir("guest");
  writeParked(guest, UUID_B, "guest@example.com", "guest-secret");
  writeLive(guest, UUID_B, "guest@example.com", "guest-secret");

  const registry = buildProfileRegistry([{ name: "host", dir: host }, { name: "guest", dir: guest }], tool());

  const shared = registry.groups.find((g) => g.fingerprint === registry.entries[1]!.liveCredential.fingerprint)!;
  expect(shared.inference.cause).toBe("displacement");
  expect(registry.contradictions).toHaveLength(0);
});

test("the same account behind two names collapses to one credential key", () => {
  const a = profileDir("aliasA");
  writeParked(a, UUID_A, "one@example.com", "same");
  writeLive(a, UUID_A, "one@example.com", "same");
  const b = profileDir("aliasB");
  writeParked(b, UUID_A, "one@example.com", "same");
  writeLive(b, UUID_A, "one@example.com", "same");

  const registry = buildProfileRegistry([{ name: "aliasA", dir: a }, { name: "aliasB", dir: b }], tool());
  expect(registry.groups[0]!.inference.cause).toBe("aliasing");

  // A name-based walk would offer these as two switch targets; the credential
  // key is what stops a selector retrying the account it just died on.
  const byCredential = profilesByCredential(registry);
  expect(byCredential.size).toBe(1);
  expect([...byCredential.values()][0]!.sort()).toEqual(["aliasA", "aliasB"]);
});

test("a profile with no credential at all yields no credential key", () => {
  const dir = profileDir("bare");
  writeLive(dir, UUID_A, "bare@example.com");
  const registry = buildProfileRegistry([{ name: "bare", dir }], tool());
  expect(credentialKeyForEntry(registry.entries[0]!)).toBeUndefined();
  expect(registry.entries[0]!.binding).toBe("unbound");
});

test("the grouping method is reported so two registries can be compared", () => {
  const registry = buildProfileRegistry([], tool());
  expect(registry.method).toContain("md5");
  expect(registry.method).toContain(String(EMPTY_CREDENTIAL_MAX_BYTES));
});

test("no credential value ever appears in the registry output", () => {
  const dir = profileDir("leaky");
  writeParked(dir, UUID_A, "leak@example.com", "topsecret");
  writeLive(dir, UUID_A, "leak@example.com", "topsecret");
  const registry = buildProfileRegistry([{ name: "leaky", dir }], tool());
  const serialized = JSON.stringify(registry);
  expect(serialized).not.toContain("topsecret-access");
  expect(serialized).not.toContain("topsecret-refresh");
});
