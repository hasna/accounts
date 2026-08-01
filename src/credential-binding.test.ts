import { test, expect } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { convergeIdentityCredential, ensureFreshIdentityCredential } from "./lib/credential-broker.js";
import {
  centralCredentialsSnapshot,
  centralOAuthSnapshot,
  syncProfileSnapshotToCentral,
} from "./lib/auth-store.js";
import { profileCredentialsSnapshot, profileOAuthSnapshot } from "./lib/claude-layout.js";
import {
  bindingClaimsForAccount,
  classifyCredentialWrite,
  credentialBindingConflicts,
  credentialBindingPath,
  credentialClaimants,
  credentialFingerprintFromBytes,
  listCredentialBindings,
  readCredentialBinding,
  recordCredentialBinding,
} from "./lib/credential-binding.js";
import { getTool } from "./lib/tools.js";

/**
 * CREDENTIAL → ACCOUNT IDENTITY BINDING (todos bc32e38c).
 *
 * The P0 this file pins: on station01 the central store held 18 accounts with
 * 18 distinct emails but only 8 distinct credentials — ONE credential filed
 * under EIGHT different account uuids. Eight identities cannot share one OAuth
 * credential, so at most one of those bindings was true and the other seven
 * accounts had silently lost their credential while every health surface stayed
 * green.
 *
 * Why nothing caught it: through 0.2.26 the only binding a credential had was
 * CONTAINMENT — "whose credential is this?" was answered by whatever directory
 * the file sat in. PR #97 made containment symmetric (sources gated as well as
 * targets) and said so in its own comment: the central copy's check is
 * `carriesThisAccount: () => true`, which "proves the SLOT is the right one,
 * never that the BYTES in it were legitimately filed."
 *
 * A container's claim is exactly as trustworthy as the last thing that wrote
 * the container, and the two files that make that claim — `oauth-account.json`
 * and `credentials.json` — are written by SEPARATE code paths. When they
 * disagree, every containment gate passes and the wrong credential is filed
 * under the right-looking uuid.
 *
 * The tests below are ordered defect-first: `credential-binding-*` reproduce
 * the cross-write through the public API, then the positive controls prove the
 * gate did not simply refuse everything.
 */

const UUID_A = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const UUID_B = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
const UUID_C = "cccccccc-3333-4333-8333-cccccccccccc";
const tool = getTool("claude");

interface Cred {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function cred(label: string, expiresInMs = 60 * 60 * 1000): Cred {
  return {
    accessToken: `${label}-access`,
    refreshToken: `${label}-refresh`,
    expiresAt: Date.now() + expiresInMs,
  };
}

function credBytes(c: Cred): string {
  return JSON.stringify({ claudeAiOauth: { ...c, scopes: ["user:inference"] } });
}

function readCred(path: string): Cred {
  return (JSON.parse(readFileSync(path, "utf8")) as { claudeAiOauth: Cred }).claudeAiOauth;
}

function writeCred(path: string, c: Cred, mtime?: Date): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, credBytes(c));
  if (mtime) utimesSync(path, mtime, mtime);
}

function writeOAuth(path: string, uuid: string, email: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify({ oauthAccount: { accountUuid: uuid, emailAddress: email } }, null, 2));
}

/** A central store entry: identity file plus credential file. */
function seedCentral(uuid: string, email: string, c: Cred, mtime?: Date): void {
  writeOAuth(centralOAuthSnapshot(uuid), uuid, email);
  writeCred(centralCredentialsSnapshot(uuid), c, mtime);
}

function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(join(tmpdir(), "accounts-binding-"));
  const previous = process.env.ACCOUNTS_HOME;
  process.env.ACCOUNTS_HOME = home;
  try {
    fn(home);
  } finally {
    if (previous === undefined) delete process.env.ACCOUNTS_HOME;
    else process.env.ACCOUNTS_HOME = previous;
    rmSync(home, { recursive: true, force: true });
  }
}

const OLD = new Date(Date.now() - 60 * 60 * 1000);
const NEW = new Date(Date.now() - 60 * 1000);

// --- the defect ---------------------------------------------------------------

test("credential-binding: a snapshot holding ANOTHER account's credential cannot be filed under this account", () => {
  withHome((home) => {
    const credA = cred("A");
    const credB = cred("B");

    // B is a legitimate, fully-established account: its credential of record
    // sits in ITS OWN central slot. That slot is what makes `B-refresh`
    // attributable to B without reading a token value.
    seedCentral(UUID_B, "b@example.com", credB, OLD);
    seedCentral(UUID_A, "a@example.com", credA, OLD);

    // A's profile dir. Its identity files all say A — the switch marker is
    // absent and the live identity agrees with the parked one, so every
    // containment gate in the broker passes. Only the CREDENTIAL bytes in the
    // parked snapshot are B's, and they are the freshest file on disk, which is
    // exactly what `betterCredential` ranks first.
    const dirA = join(home, "profiles", "accountA");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(
      join(dirA, ".claude.json"),
      JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
    );
    writeCred(join(dirA, ".credentials.json"), credA, OLD);
    writeOAuth(profileOAuthSnapshot(dirA), UUID_A, "a@example.com");
    writeCred(profileCredentialsSnapshot(dirA), credB, NEW);

    const report = convergeIdentityCredential(UUID_A, {
      tool,
      profiles: [{ name: "accountA", dir: dirA }],
    });

    // The assertion that fails before the fix: A's credential of record is
    // replaced by B's, silently, with `report.writes` reporting success.
    expect(readCred(centralCredentialsSnapshot(UUID_A)).refreshToken).toBe("A-refresh");
    // And B's own slot is left alone either way — stated so a fix that
    // "resolves" the conflict by mutating B would not pass.
    expect(readCred(centralCredentialsSnapshot(UUID_B)).refreshToken).toBe("B-refresh");
    // The refusal is REPORTED. Silence is how this survived from the broker's
    // introduction through 0.2.27.
    expect(
      report.skipped.some(
        (s) => s.path === profileCredentialsSnapshot(dirA) && s.reason.includes("bound to another account"),
      ),
    ).toBe(true);
  });
});

test("credential-binding: the same cross-write through syncProfileSnapshotToCentral is refused", () => {
  withHome((home) => {
    const credA = cred("A");
    const credB = cred("B");
    seedCentral(UUID_B, "b@example.com", credB, OLD);
    seedCentral(UUID_A, "a@example.com", credA, OLD);

    const dirA = join(home, "profiles", "accountA");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(
      join(dirA, ".claude.json"),
      JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
    );
    writeOAuth(profileOAuthSnapshot(dirA), UUID_A, "a@example.com");
    writeCred(profileCredentialsSnapshot(dirA), credB, NEW);

    const result = syncProfileSnapshotToCentral(dirA, tool);

    expect(readCred(centralCredentialsSnapshot(UUID_A)).refreshToken).toBe("A-refresh");
    expect(result.credentials).toBe("refused");
    expect(result.credentialsReason).toContain("bound to another account");
  });
});

test("credential-binding: a contaminated central slot cannot DONATE to the account it was misfiled under", () => {
  withHome((home) => {
    // The state the fleet is already in: one credential sitting in two central
    // slots. A's slot holds B's credential. Nothing may propagate out of it —
    // fanning it into A's live dirs would put two live copies of ONE refresh
    // token on disk, and the next exchange revokes whichever copy loses.
    const credB = cred("B");
    seedCentral(UUID_B, "b@example.com", credB, OLD);
    seedCentral(UUID_A, "a@example.com", credB, NEW);

    const dirA = join(home, "profiles", "accountA");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(
      join(dirA, ".claude.json"),
      JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
    );
    writeCred(join(dirA, ".credentials.json"), cred("A-stale", -60 * 60 * 1000), OLD);
    writeOAuth(profileOAuthSnapshot(dirA), UUID_A, "a@example.com");

    const report = convergeIdentityCredential(UUID_A, {
      tool,
      profiles: [{ name: "accountA", dir: dirA }],
    });

    expect(readCred(join(dirA, ".credentials.json")).refreshToken).toBe("A-stale-refresh");
    expect(report.writes).toEqual([]);
    // Named explicitly rather than resting on `writes === []`: `betterCredential`
    // would also have refused this write, so an assertion on the outcome alone
    // passes whether or not the binding gate fired at all.
    expect(
      report.skipped.some(
        (s) => s.kind === "central" && s.reason.includes("bound to another account"),
      ),
    ).toBe(true);
  });
});

test("credential-binding: a contested credential is never sent to the token endpoint", async () => {
  const home = mkdtempSync(join(tmpdir(), "accounts-binding-"));
  const previous = process.env.ACCOUNTS_HOME;
  process.env.ACCOUNTS_HOME = home;
  try {
    // Both accounts' central slots hold the same credential, and it is close
    // enough to expiry that `ensureFresh` would normally exchange it.
    const shared = cred("shared", 60 * 1000);
    seedCentral(UUID_A, "a@example.com", shared, NEW);
    seedCentral(UUID_B, "b@example.com", shared, NEW);

    let exchanges = 0;
    const fetchImpl = (async () => {
      exchanges += 1;
      return new Response(JSON.stringify({ access_token: "x", expires_in: 3600 }), { status: 200 });
    }) as unknown as typeof fetch;

    const report = await ensureFreshIdentityCredential(UUID_A, { tool, profiles: [], fetchImpl });

    // Exchanging here would rotate the TRUE owner's refresh token and revoke
    // them server-side, irreversibly — the exact harm the broker exists to
    // prevent, delivered by the broker.
    expect(exchanges).toBe(0);
    expect(report.refreshed).toBe(false);
    expect(readCred(centralCredentialsSnapshot(UUID_B)).refreshToken).toBe("shared-refresh");
  } finally {
    if (previous === undefined) delete process.env.ACCOUNTS_HOME;
    else process.env.ACCOUNTS_HOME = previous;
    rmSync(home, { recursive: true, force: true });
  }
});

test("credential-binding: an UNcontested credential IS still exchanged", async () => {
  const home = mkdtempSync(join(tmpdir(), "accounts-binding-"));
  const previous = process.env.ACCOUNTS_HOME;
  process.env.ACCOUNTS_HOME = home;
  try {
    // The control for the test above: same shape, same expiry, one claimant.
    // Without it, "0 exchanges" proves only that the harness never exchanges.
    seedCentral(UUID_A, "a@example.com", cred("A", 60 * 1000), NEW);

    let exchanges = 0;
    const fetchImpl = (async () => {
      exchanges += 1;
      return new Response(
        JSON.stringify({ access_token: "rotated-access", refresh_token: "rotated-refresh", expires_in: 3600 }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const report = await ensureFreshIdentityCredential(UUID_A, { tool, profiles: [], fetchImpl });

    expect(exchanges).toBe(1);
    expect(report.refreshed).toBe(true);
    expect(readCred(centralCredentialsSnapshot(UUID_A)).refreshToken).toBe("rotated-refresh");
    // The rotation is this account's by construction, so it is rebound, and the
    // predecessor it replaced is remembered.
    const binding = readCredentialBinding(UUID_A);
    expect(binding?.evidence).toBe("rotation");
    expect(binding?.fingerprint).toBe(
      credentialFingerprintFromBytes(
        Buffer.from(JSON.stringify({ claudeAiOauth: { refreshToken: "rotated-refresh" } })),
      )!,
    );
  } finally {
    if (previous === undefined) delete process.env.ACCOUNTS_HOME;
    else process.env.ACCOUNTS_HOME = previous;
    rmSync(home, { recursive: true, force: true });
  }
});

// --- positive controls: the gate must not refuse everything -------------------

test("credential-binding: an account's own fresher credential still converges", () => {
  withHome((home) => {
    const stale = cred("A", -60 * 60 * 1000);
    const fresh = { ...cred("A"), accessToken: "A-access-rotated" };

    seedCentral(UUID_A, "a@example.com", stale, OLD);

    const dirA = join(home, "profiles", "accountA");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(
      join(dirA, ".claude.json"),
      JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
    );
    writeCred(join(dirA, ".credentials.json"), fresh, NEW);
    writeOAuth(profileOAuthSnapshot(dirA), UUID_A, "a@example.com");

    const report = convergeIdentityCredential(UUID_A, {
      tool,
      profiles: [{ name: "accountA", dir: dirA }],
    });

    expect(readCred(centralCredentialsSnapshot(UUID_A)).accessToken).toBe("A-access-rotated");
    expect(report.writes.some((w) => w.kind === "central")).toBe(true);
  });
});

test("credential-binding: a first-capture profile with no central entry still binds", () => {
  withHome((home) => {
    const credA = cred("A");
    const dirA = join(home, "profiles", "accountA");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(
      join(dirA, ".claude.json"),
      JSON.stringify({ oauthAccount: { accountUuid: UUID_A, emailAddress: "a@example.com" } }),
    );
    writeCred(join(dirA, ".credentials.json"), credA, NEW);
    writeOAuth(profileOAuthSnapshot(dirA), UUID_A, "a@example.com");
    writeCred(profileCredentialsSnapshot(dirA), credA, NEW);

    const result = syncProfileSnapshotToCentral(dirA, tool);

    expect(result.credentials).toBe("created");
    expect(readCred(centralCredentialsSnapshot(UUID_A)).refreshToken).toBe("A-refresh");
    const binding = readCredentialBinding(UUID_A);
    expect(binding?.accountUuid).toBe(UUID_A);
    expect(binding?.fingerprint).toBe(credentialFingerprintFromBytes(Buffer.from(credBytes(credA)))!);
  });
});

test("credential-binding: rotation rebinds and remembers exactly one predecessor", () => {
  withHome(() => {
    const first = credentialFingerprintFromBytes(Buffer.from(credBytes(cred("first"))))!;
    const second = credentialFingerprintFromBytes(Buffer.from(credBytes(cred("second"))))!;
    const third = credentialFingerprintFromBytes(Buffer.from(credBytes(cred("third"))))!;

    recordCredentialBinding(UUID_A, first, { evidence: "central-write", sourceKind: "profile-snapshot" });
    expect(readCredentialBinding(UUID_A)?.supersedes).toBeUndefined();

    recordCredentialBinding(UUID_A, second, { evidence: "rotation", sourceKind: "exchange" });
    expect(readCredentialBinding(UUID_A)?.fingerprint).toBe(second);
    expect(readCredentialBinding(UUID_A)?.supersedes).toBe(first);

    // The predecessor window is ONE deep on purpose: it covers the interval
    // between an owner's rotation and the next converge, without turning the
    // record into an unbounded history of every token the account ever held.
    recordCredentialBinding(UUID_A, third, { evidence: "rotation", sourceKind: "exchange" });
    expect(readCredentialBinding(UUID_A)?.supersedes).toBe(second);
    expect(bindingClaimsForAccount(UUID_A).has(first)).toBe(false);
    expect(bindingClaimsForAccount(UUID_A).has(second)).toBe(true);
    expect(bindingClaimsForAccount(UUID_A).has(third)).toBe(true);
  });
});

// --- the decision function, in isolation --------------------------------------

test("credential-binding: classifyCredentialWrite is exhaustive over the four cases", () => {
  const fp = "sha256:" + "a".repeat(64);
  expect(classifyCredentialWrite({ accountUuid: UUID_A, fingerprint: fp, claimants: [] })).toBe("bind");
  expect(classifyCredentialWrite({ accountUuid: UUID_A, fingerprint: fp, claimants: [UUID_A] })).toBe("bound");
  expect(classifyCredentialWrite({ accountUuid: UUID_A, fingerprint: fp, claimants: [UUID_B] })).toBe(
    "cross-write",
  );
  // Claimed by this account AND another: still a cross-write. One of the two
  // bindings is false and this code cannot tell which, so it must not add a
  // third copy of the ambiguity.
  expect(
    classifyCredentialWrite({ accountUuid: UUID_A, fingerprint: fp, claimants: [UUID_A, UUID_B] }),
  ).toBe("cross-write");
  expect(classifyCredentialWrite({ accountUuid: UUID_A, fingerprint: undefined, claimants: [] })).toBe(
    "unbindable",
  );
});

test("credential-binding: uuid comparison is case-insensitive", () => {
  const fp = "sha256:" + "b".repeat(64);
  expect(
    classifyCredentialWrite({
      accountUuid: UUID_A.toUpperCase(),
      fingerprint: fp,
      claimants: [UUID_A],
    }),
  ).toBe("bound");
});

test("credential-binding: a husk with no refresh token has no fingerprint", () => {
  expect(
    credentialFingerprintFromBytes(
      Buffer.from(JSON.stringify({ claudeAiOauth: { accessToken: "a", refreshToken: "", expiresAt: 0 } })),
    ),
  ).toBeUndefined();
  expect(credentialFingerprintFromBytes(Buffer.from("not json"))).toBeUndefined();
  expect(credentialFingerprintFromBytes(Buffer.from(JSON.stringify({})))).toBeUndefined();
});

test("credential-binding: the fingerprint never contains token material", () => {
  const fp = credentialFingerprintFromBytes(Buffer.from(credBytes(cred("secretive"))))!;
  expect(fp).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(fp).not.toContain("secretive");
});

// --- detection surface --------------------------------------------------------

test("credential-binding: claimants and conflicts read the central store, never a token", () => {
  withHome(() => {
    const shared = cred("shared");
    seedCentral(UUID_A, "a@example.com", shared, OLD);
    seedCentral(UUID_B, "b@example.com", shared, OLD);
    seedCentral(UUID_C, "c@example.com", cred("own"), OLD);

    const fp = credentialFingerprintFromBytes(Buffer.from(credBytes(shared)))!;
    expect(credentialClaimants(fp).sort()).toEqual([UUID_A, UUID_B].sort());

    const conflicts = credentialBindingConflicts();
    expect(conflicts.length).toBe(1);
    expect(conflicts[0]!.accountUuids.sort()).toEqual([UUID_A, UUID_B].sort());
    expect(JSON.stringify(conflicts)).not.toContain("shared-refresh");

    const listed = listCredentialBindings();
    expect(listed.length).toBe(3);
    expect(JSON.stringify(listed)).not.toContain("own-refresh");
  });
});

test("credential-binding: a malformed uuid directory never reaches a path helper", () => {
  withHome((home) => {
    mkdirSync(join(home, "auth", "not-a-uuid"), { recursive: true });
    writeFileSync(join(home, "auth", "not-a-uuid", "credentials.json"), credBytes(cred("planted")));
    seedCentral(UUID_A, "a@example.com", cred("A"), OLD);

    expect(() => listCredentialBindings()).not.toThrow();
    expect(listCredentialBindings().map((b) => b.accountUuid)).toEqual([UUID_A]);
    expect(credentialClaimants(credentialFingerprintFromBytes(Buffer.from(credBytes(cred("planted"))))!)).toEqual(
      [],
    );
  });
});

test("credential-binding: the binding record is written 0600 and carries its method", () => {
  withHome(() => {
    const fp = credentialFingerprintFromBytes(Buffer.from(credBytes(cred("A"))))!;
    recordCredentialBinding(UUID_A, fp, { evidence: "central-write", sourceKind: "dir-live" });
    const raw = JSON.parse(readFileSync(credentialBindingPath(UUID_A), "utf8")) as Record<string, unknown>;
    expect(raw.schema).toBe("accounts.credential-binding.v1");
    expect(raw.method).toBe("sha256-refresh-token/v1");
    expect(raw.accountUuid).toBe(UUID_A);
    expect(typeof raw.boundAt).toBe("string");
    expect(JSON.stringify(raw)).not.toContain("A-refresh");
  });
});
