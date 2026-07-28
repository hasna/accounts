# Central auth snapshot store

`~/.hasna/accounts/auth/<accountUuid>/{credentials.json,oauth-account.json}`
is the canonical, identity-keyed home for an account's auth snapshot
(introduced in 0.2.16).

## Why

The legacy store `.accounts-auth/` inside each profile config dir was
**directory-keyed** while the account is the real identity:

- one account snapshotted by several profile dirs had no canonical copy and no
  rule for which wins when they diverge;
- the files sat inside `$CLAUDE_CONFIG_DIR`, a namespace Claude Code owns and
  whose schema we do not control;
- credentials did not survive profile dir deletion, rename or rebinding even
  though the account does.

## Layout

```
~/.hasna/accounts/auth/<accountUuid>/credentials.json    # .credentials.json payload
~/.hasna/accounts/auth/<accountUuid>/oauth-account.json  # { oauthAccount: {...} }
~/.hasna/accounts/auth-trash/<timestamp>/<uuid>/         # entries removed by `auth sweep --delete`
```

`accountUuid` must be a strict UUID — it becomes a path segment, and a hostile
`oauth-account.json` must not be able to steer writes elsewhere. All files are
written atomically with mode 0600.

The profile→account **binding** resolves from the per-profile snapshot first
(owner-true even when the dir's live files were switched to another account by
`switch-account`), then the dir's account file. A switched-away dir with no
snapshot has no resolvable binding on purpose — never bind a foreign identity.

## Compatibility window (0.2.15 ⇄ 0.2.16)

Binaries `<= 0.2.15` read and rotate only the per-profile `.accounts-auth/`.
Therefore 0.2.16:

- **writes both** — every per-profile snapshot write is mirrored centrally
  (`syncProfileSnapshotToCentral`, called from every snapshot writer);
- **reads best-of-both** — credential reads rank the central and per-profile
  copies with `betterCredential` (refresh-token presence → unexpired → newer
  mtime → later expiry) and use the winner. Deliberately **not** "central
  first": an old binary may have rotated a fresher token into the per-profile
  copy, and restoring a stale central token logs the account out (rotated-out
  refresh tokens are revoked server-side);
- **never deletes** a per-profile `.accounts-auth/` directory.

The same `betterCredential` rule is the **merge rule** for duplicate custody:
when several profiles snapshot one account, central converges on the newest
valid refresh token and is never downgraded. Losing copies stay untouched in
their profile dirs.

**Mirror removal criteria** (a later release, not this one): every fleet
machine runs `>= 0.2.16` AND central hashes have been observed advancing
through a full token-rotation cycle. Then per-profile mirrors become read-only
legacy, and are removed only by an explicit sweep verb — never automatically.

## Purge and orphans

`accounts remove --purge` deletes the profile dir (including its legacy
mirror) and **never** touches the central store — credential survival across
dir deletion is the store's whole point. Central entries no longer referenced
by any profile are handled by the explicit verb:

```
accounts auth sweep            # dry-run: list orphaned central entries
accounts auth sweep --delete   # MOVE them to ~/.hasna/accounts/auth-trash/<ts>/ (no rm)
```

## Import

Both `accounts import` paths call `ensureProfileAuthSnapshot`, which now ends
with a central sync — importing a profile registers its account centrally, and
importing an account unknown to this machine creates its central entry. The
`betterCredential` guard means an import can never downgrade central.

## CLI

```
accounts auth status [--json]    # every account known to this machine (central + bindings)
accounts auth migrate [--json]   # mirror every claude profile's snapshot centrally
accounts auth sweep [--delete]   # orphan handling, see above
```

## Library accessor

`listKnownAccounts()` (exported from the package root) is THE identity
enumeration surface: central store first, per-profile bindings as fallback,
deduped by uuid. Features that reason over accounts (e.g. usage-aware
auto-switching) should consume it instead of walking profile dirs.

Out of scope here: `keychain.json` (macOS live-auth cache) and
`switched-account.json` (live dir state, not account state) stay per-profile.
