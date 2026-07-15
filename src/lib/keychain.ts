import { execFileSync } from "node:child_process";
import { platform } from "node:os";
import { AccountsError } from "../types.js";
import { CLAUDE_KEYCHAIN_SERVICE } from "./claude-layout.js";

export function keychainSupported(): boolean {
  return process.env.ACCOUNTS_TEST_KEYCHAIN === "1" || platform() === "darwin";
}

export function securityExecutable(): string {
  if (process.env["NODE_ENV"] === "test" && process.env.ACCOUNTS_TEST_SECURITY_BIN) {
    return process.env.ACCOUNTS_TEST_SECURITY_BIN;
  }
  return keychainSupported() ? "/usr/bin/security" : "security";
}

export interface KeychainCredential {
  service: string;
  account: string;
  secret: string;
}

const KEYCHAIN_ACCOUNT_RE = /^[a-zA-Z0-9._@+-]{1,256}$/;

/** Allowlist service/account before any keychain write (blocks store-name injection). */
export function assertAllowedKeychainCredential(cred: KeychainCredential): void {
  if (cred.service !== CLAUDE_KEYCHAIN_SERVICE) {
    throw new AccountsError(`refusing keychain operation for unexpected service "${cred.service}"`);
  }
  if (!KEYCHAIN_ACCOUNT_RE.test(cred.account)) {
    throw new AccountsError("refusing keychain operation for invalid account name");
  }
  if (!cred.secret || cred.secret.length > 65_536) {
    throw new AccountsError("refusing keychain operation for invalid secret");
  }
}

/** Read Claude Code OAuth payload from macOS login keychain. */
export function readClaudeKeychain(): KeychainCredential | undefined {
  if (!keychainSupported()) return undefined;
  try {
    const secret = execFileSync(
      securityExecutable(),
      ["find-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE, "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
    if (!secret) return undefined;
    const account = readKeychainAccount();
    const cred = { service: CLAUDE_KEYCHAIN_SERVICE, account: account ?? "claude", secret };
    if (!KEYCHAIN_ACCOUNT_RE.test(cred.account)) return undefined;
    return cred;
  } catch {
    return undefined;
  }
}

function commandStatus(err: unknown): number | undefined {
  return err && typeof err === "object" && typeof (err as { status?: unknown }).status === "number"
    ? (err as { status: number }).status
    : undefined;
}

/**
 * Capture the current Claude credential without collapsing a read failure into
 * "not found". Launch leases use this so they never overwrite state they could
 * not first preserve in memory.
 */
export function captureClaudeKeychain(): KeychainCredential | undefined {
  if (!keychainSupported()) return undefined;
  let secret: string;
  try {
    secret = execFileSync(
      securityExecutable(),
      ["find-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE, "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();
  } catch (err) {
    if (commandStatus(err) === 44) return undefined;
    throw new AccountsError("keychain read failed before Claude launch");
  }
  if (!secret) return undefined;

  let account: string;
  try {
    const metadata = execFileSync(
      securityExecutable(),
      ["find-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const match = metadata.match(/"acct"<blob>="([^"]+)"/);
    if (!match) throw new AccountsError("keychain account metadata is unavailable");
    account = match[1]!;
  } catch (err) {
    if (err instanceof AccountsError) throw err;
    throw new AccountsError("keychain account read failed before Claude launch");
  }
  const credential = { service: CLAUDE_KEYCHAIN_SERVICE, account, secret };
  assertAllowedKeychainCredential(credential);
  return credential;
}

function readKeychainAccount(): string | undefined {
  try {
    const out = execFileSync(
      securityExecutable(),
      ["find-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const match = out.match(/"acct"<blob>="([^"]+)"/);
    return match?.[1];
  } catch {
    return undefined;
  }
}

function bufferText(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  return undefined;
}

export function keychainWriteFailureMessage(err: unknown): string {
  const record = err && typeof err === "object" ? (err as Record<string, unknown>) : {};
  const stderr = bufferText(record.stderr);
  const stdout = bufferText(record.stdout);
  const detail = (stderr || stdout || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .at(-1);
  if (detail) return detail;
  return typeof record.status === "number" ? `security exited with status ${record.status}` : "security command failed";
}

/** Write Claude Code credentials into the login keychain (replaces existing entry). */
export function writeClaudeKeychain(cred: KeychainCredential): void {
  if (!keychainSupported()) {
    throw new AccountsError("macOS keychain is only available on darwin");
  }
  assertAllowedKeychainCredential(cred);
  try {
    execFileSync(
      securityExecutable(),
      ["delete-generic-password", "-s", cred.service, "-a", cred.account],
      { stdio: "ignore" },
    );
  } catch {
    /* not found */
  }
  for (let i = 0; i < 5; i += 1) {
    try {
      execFileSync(securityExecutable(), ["delete-generic-password", "-s", cred.service], { stdio: "ignore" });
    } catch {
      break;
    }
  }
  try {
    execFileSync(
      securityExecutable(),
      ["add-generic-password", "-U", "-s", cred.service, "-a", cred.account, "-w", cred.secret],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
  } catch (err) {
    throw new AccountsError(`keychain write failed: ${keychainWriteFailureMessage(err)}`);
  }
}
