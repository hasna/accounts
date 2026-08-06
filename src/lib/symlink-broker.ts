import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { accountsHome } from "../storage.js";
import { AccountsError } from "../types.js";
import {
  centralAuthDir,
  centralCredentialsSnapshot,
  credentialHealth,
  isAccountUuid,
} from "./auth-store.js";
import { dirCredentialsFile } from "./claude-layout.js";

/**
 * The single-inode credential broker.
 *
 * The owner-confirmed model (2026-08-06): accounts are a fungible pool, seats
 * are not bound to accounts, and each OAuth account owns exactly ONE real
 * `credentials.json` on the machine — the central file at
 * `~/.hasna/accounts/auth/<uuid>/credentials.json`. A session's config dir
 * points at its current account by a SYMLINK (`<dir>/.credentials.json` ->
 * that central file), and switching an account is one atomic `rename(2)` of a
 * symlink. Nothing here copies credential bytes and nothing unlinks a central
 * file, so a switch can never destroy a login and there is no sibling copy for
 * a rotation to strand.
 *
 * The one load-bearing measurement (experiment E1, 2026-08-06): Claude Code
 * 2.1.223 refreshes its OAuth token by writing a temp file into the config dir
 * and `rename`-ing it over `.credentials.json` — which REPLACES the symlink
 * with a regular file (a "fork") and leaves the central target stale. Under the
 * shipped account<->dir bijection that is a benign, self-healing fork: this
 * module adopts the fork back onto the canonical path by `rename` (an inode
 * move, zero bytes copied, mtime preserved) before repointing, so the fresh
 * token is preserved and the central file stays canonical.
 *
 * This module is deliberately tool-agnostic and free of registry/store
 * concerns: it operates on a config dir and an account uuid, nothing else, so
 * it is exhaustively testable against temp dirs with no live credentials.
 */

/** Root for displaced credential artifacts — outside every config dir, 0700. */
export function quarantineRoot(): string {
  return join(accountsHome(), "quarantine");
}

export type DirCredentialInfo =
  | { kind: "missing" }
  /** A real file: a fresh login, or a Claude refresh fork of the occupant. */
  | { kind: "regular"; path: string }
  /** A symlink INTO the central auth store — the migrated, at-rest state. */
  | { kind: "link-central"; path: string; uuid: string; target: string }
  /** A symlink pointing somewhere other than the central store. */
  | { kind: "link-foreign"; path: string; target: string };

/**
 * The uuid a central-store credentials path belongs to, or undefined when the
 * path is not `<centralAuthRoot>/<uuid>/credentials.json`. Inverts the
 * canonical builder rather than parsing by hand so the two can never drift.
 */
export function centralUuidOfCredentialsPath(absPath: string): string | undefined {
  const seg = basename(dirname(absPath));
  if (!isAccountUuid(seg)) return undefined;
  try {
    if (resolve(centralCredentialsSnapshot(seg)) === resolve(absPath)) return seg.toLowerCase();
  } catch {
    return undefined;
  }
  return undefined;
}

/** Classify a config dir's `.credentials.json` without following the link. */
export function inspectDirCredential(configDir: string): DirCredentialInfo {
  const path = dirCredentialsFile(configDir);
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return { kind: "missing" };
  }
  if (st.isSymbolicLink()) {
    const target = resolve(dirname(path), readlinkSync(path));
    const uuid = centralUuidOfCredentialsPath(target);
    if (uuid) return { kind: "link-central", path, uuid, target };
    return { kind: "link-foreign", path, target };
  }
  return { kind: "regular", path };
}

function assertUuid(uuid: string): string {
  if (!isAccountUuid(uuid)) {
    throw new AccountsError(`invalid account uuid: ${JSON.stringify(uuid)}`);
  }
  return uuid.toLowerCase();
}

function bytesEqual(a: string, b: string): boolean {
  try {
    return readFileSync(a).equals(readFileSync(b));
  } catch {
    return false;
  }
}

function renameNoCrossDevice(from: string, to: string): void {
  try {
    renameSync(from, to);
  } catch (error) {
    if (error instanceof Error && "code" in error && (error as { code?: string }).code === "EXDEV") {
      throw new AccountsError(
        `refusing to move a credential across filesystems (${from} -> ${to}); the central store and config dir must share one device`,
      );
    }
    throw error;
  }
}

/**
 * Move a displaced credential artifact into quarantine by rename — never a
 * copy, never a delete. Bytes and mtime are preserved; the caller gets the new
 * path for the disposal record (graft G2 of the design).
 */
export function quarantineCredential(uuid: string, path: string, label: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dir = join(quarantineRoot(), `${stamp}-${assertUuid(uuid)}-${randomUUID().slice(0, 8)}`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const dest = join(dir, `${label}-${basename(path)}`);
  renameNoCrossDevice(path, dest);
  return dest;
}

export interface AdoptResult {
  /** The fork was moved onto the canonical central path. */
  adopted: boolean;
  /** A central file was created where none existed (first migration). */
  created?: boolean;
  /** Path a displaced artifact was preserved at (old central, or the fork). */
  quarantined?: string;
}

/**
 * Adopt a config dir's regular-file credential (a Claude refresh fork, or the
 * pre-migration real file) onto the account's canonical central path.
 *
 * The central store is NEVER downgraded: a fork that is strictly worse than an
 * existing central (by {@link betterCredential} — refresh-token presence, then
 * usability, then mtime) is preserved in quarantine and the central is left
 * intact. Otherwise the old central is quarantined and the fork is moved into
 * its place by `rename` (inode move; zero bytes copied). A symlink or a missing
 * dir file is a no-op — there is nothing forked to adopt.
 */
export function adoptForkToCentral(configDir: string, uuid: string): AdoptResult {
  const id = assertUuid(uuid);
  const info = inspectDirCredential(configDir);
  if (info.kind !== "regular") return { adopted: false };

  const forkPath = info.path;
  const central = centralCredentialsSnapshot(id);
  mkdirSync(centralAuthDir(id), { recursive: true });

  const centralIsRegular = existsSync(central) && !lstatSync(central).isSymbolicLink();
  if (centralIsRegular) {
    if (bytesEqual(forkPath, central)) {
      // Identical custody: preserve the redundant fork rather than delete it,
      // and keep the existing central inode.
      const quarantined = quarantineCredential(id, forkPath, "identical-fork");
      return { adopted: false, quarantined };
    }
    // The fork is the account's LIVE credential — Claude wrote it in place, so
    // it is by construction the newest rotation and adopting it is not a
    // downgrade. The one case that WOULD destroy a login is a husk fork (a
    // login-empty / no-refresh-token file) overwriting a central that still
    // holds a usable refresh token: refuse that, preserving the fork for
    // forensics and keeping the good central intact. Every other fork wins,
    // including a fork that merely aged out its access token (its refresh
    // survives). Ranking on mtime/expiry is deliberately NOT used here: a
    // same-millisecond tie must not strand the session's live token behind a
    // stale central.
    const forkHealth = credentialHealth(forkPath);
    const centralHealth = credentialHealth(central);
    const forkUsable = forkHealth.exists && forkHealth.refreshTokenLength > 0;
    const centralUsable = centralHealth.exists && centralHealth.refreshTokenLength > 0;
    if (centralUsable && !forkUsable) {
      const quarantined = quarantineCredential(id, forkPath, "husk-fork");
      return { adopted: false, quarantined };
    }
    const quarantined = quarantineCredential(id, central, "superseded-central");
    renameNoCrossDevice(forkPath, central);
    chmodSync(central, 0o600);
    return { adopted: true, quarantined };
  }

  // No central yet (or central is itself a stray symlink): the fork becomes the
  // canonical file. This is the migration inode move — zero bytes copied.
  if (existsSync(central)) {
    // central is a symlink/dir stray — quarantine it out of the way first.
    quarantineCredential(id, central, "stray-central");
  }
  renameNoCrossDevice(forkPath, central);
  chmodSync(central, 0o600);
  return { adopted: true, created: true };
}

/**
 * Point a config dir's `.credentials.json` at an account's canonical central
 * file by an ATOMIC symlink swap: create the link at a temp path, then
 * `rename` it over the destination. A crash leaves either the old entry or the
 * new link — both valid. Zero credential bytes are written; the central file is
 * never touched.
 */
export function linkDirToCentral(configDir: string, uuid: string): void {
  const id = assertUuid(uuid);
  const central = centralCredentialsSnapshot(id);
  if (!existsSync(central)) {
    throw new AccountsError(
      `no central credential for account ${id} — run \`accounts login\` for it before linking a session to it`,
    );
  }
  if (lstatSync(central).isSymbolicLink()) {
    throw new AccountsError(`central credential for ${id} is a symlink; expected a regular file`);
  }
  const dest = dirCredentialsFile(configDir);
  mkdirSync(configDir, { recursive: true });
  const tmp = `${dest}.link-${process.pid}-${randomUUID().slice(0, 12)}.tmp`;
  rmSync(tmp, { force: true });
  symlinkSync(central, tmp);
  try {
    renameSync(tmp, dest);
  } catch (error) {
    rmSync(tmp, { force: true });
    throw error;
  }
}

export interface RepointResult {
  fromUuid?: string;
  toUuid: string;
  adopted: boolean;
  quarantined?: string;
}

/**
 * The switch primitive. Preserve the outgoing account's in-place refresh (if
 * Claude forked one into the dir) back to its central file, then point the dir
 * at the incoming account's central file. No credential bytes are copied and no
 * central file is unlinked, so the outgoing account's login survives untouched
 * and the incoming account is adopted, not duplicated.
 */
export function repointDir(
  configDir: string,
  opts: { fromUuid?: string; toUuid: string },
): RepointResult {
  const toUuid = assertUuid(opts.toUuid);
  let adopt: AdoptResult = { adopted: false };
  if (opts.fromUuid && isAccountUuid(opts.fromUuid)) {
    adopt = adoptForkToCentral(configDir, opts.fromUuid);
  }
  linkDirToCentral(configDir, toUuid);
  return {
    ...(opts.fromUuid ? { fromUuid: opts.fromUuid.toLowerCase() } : {}),
    toUuid,
    adopted: adopt.adopted,
    ...(adopt.quarantined ? { quarantined: adopt.quarantined } : {}),
  };
}

export interface MigrateResult {
  changed: boolean;
  reason: "already-linked" | "adopted-and-linked" | "linked";
  quarantined?: string;
}

/**
 * Convert a config dir to the symlink model for the account it already carries:
 * a real credential file is adopted onto the central path (its inode becomes
 * the canonical file — no byte copy), then the dir is relinked. An
 * already-correct link is a no-op. This is the per-dir migration step; it
 * preserves the canonical credential and touches no other dir.
 */
export function migrateDirToLink(configDir: string, uuid: string): MigrateResult {
  const id = assertUuid(uuid);
  const info = inspectDirCredential(configDir);
  if (info.kind === "link-central" && info.uuid === id) {
    return { changed: false, reason: "already-linked" };
  }
  if (info.kind === "regular") {
    const adopt = adoptForkToCentral(configDir, id);
    linkDirToCentral(configDir, id);
    return {
      changed: true,
      reason: "adopted-and-linked",
      ...(adopt.quarantined ? { quarantined: adopt.quarantined } : {}),
    };
  }
  // missing, link-foreign, or link-central(other): repoint at this account's
  // central, which must already exist.
  linkDirToCentral(configDir, id);
  return { changed: true, reason: "linked" };
}

/** Central credential path for an account uuid (canonical builder re-export). */
export function centralCredentialsPath(uuid: string): string {
  return centralCredentialsSnapshot(assertUuid(uuid));
}
