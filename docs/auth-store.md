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
~/.hasna/accounts/auth/<accountUuid>/credentials.json         # .credentials.json payload
~/.hasna/accounts/auth/<accountUuid>/oauth-account.json       # { oauthAccount: {...} }
~/.hasna/accounts/auth/<accountUuid>/credential-binding.json  # which credential this account claims
~/.hasna/accounts/auth-trash/<timestamp>/<uuid>/              # entries removed by `auth sweep --delete`
```

`accountUuid` must be a strict UUID — it becomes a path segment, and a hostile
`oauth-account.json` must not be able to steer writes elsewhere. All files are
written atomically with mode 0600.

The profile→account **binding** resolves from the per-profile snapshot first
(owner-true even when the dir's live files were switched to another account by
`switch-account`), then the dir's account file. A switched-away dir with no
snapshot has no resolvable binding on purpose — never bind a foreign identity.

## Credential → account binding

The binding above answers *which account a **directory** belongs to*. It cannot
answer *which account the **bytes** belong to*, and that is a different
question with its own failure.

**Measured on station01:** the central store held 18 accounts with 18 distinct
emails but only **8 distinct credentials** — one credential filed under **eight**
different account uuids. Eight identities cannot share one OAuth credential, so
at most one of those bindings was true and the other seven accounts had silently
lost their credential while every health surface stayed green.

Until 0.2.27 a credential's only binding was **containment** — whose credential
this is was answered by the directory the file sat in. That is only as
trustworthy as the last thing that wrote the directory, and the two files making
the claim (`oauth-account.json` and `credentials.json`) are written by
**separate code paths**. When they disagree, every containment gate passes,
ranking is identity-blind by construction (`betterCredential` compares health
structs, which carry no identity), and the freshest file wins.

So each credential also carries a **content** binding:

- **The fingerprint is `sha256` of the REFRESH TOKEN**, not of the file. Two
  copies of one credential are routinely spelled differently on disk — raw-byte
  copy vs compact `JSON.stringify`, and Claude Code rewrites the access token in
  place every eight hours — so a whole-file digest reports two spellings of one
  credential as two credentials and misses exactly the duplication that matters.
  The refresh token is also the *harm*: two files holding the same one is the
  mutual-revocation hazard the broker exists to prevent.
- **No token value is emitted.** The token is hashed and discarded; only
  `sha256:<hex>` leaves the module, the record is 0600, and the CLI prints 12
  hex characters.
- **A claim is the central slot's current contents, plus the record's
  fingerprint and one predecessor.** Current contents count as a claim so an
  estate that predates this feature is protected from the first write onward
  rather than needing a migration. The one predecessor covers the interval
  between the true owner rotating and the next converge seeing it.
- **Refusal happens only on positive proof**, and this is a *different posture*
  from containment on purpose. Containment default-**denies** (an unattributable
  dir may neither donate nor receive) because a dir either claims an account or
  does not. Content binding cannot: a credential never filed anywhere has no
  claimant, and refusing that would stop any account acquiring its first
  binding. The two layers are complementary; neither weakens the other.

Enforced in both directions, for the reason PR #97 made containment symmetric —
a credential that may not be **written** under an account may equally not be
**adopted** as that account's source of truth:

| site | effect |
|---|---|
| `syncCredentialsFile` | `credentials: "refused"` + `credentialsReason`; nothing written |
| broker `rankedCopies` | the copy is not eligible as a **source**; reported in `skipped` |
| broker `fanOut` | the payload reaches **no** target, central included |

**What this does not buy.** A claim rests on the central store's current
contents plus one predecessor, so once the true owner has rotated twice, an
older credential of theirs is no longer claimed and could be filed elsewhere.
That is a stale credential rather than a live one, and `betterCredential`
already ranks it last — stated rather than glossed, because a guard trusted past
its reach is how the next one gets through.

Inspect with `accounts auth bindings [--json] [--conflicts]`. It exits **1**
when any credential is claimed by more than one account: every such case is
provably wrong, the losing side has no credential of its own left, and
`accounts login <profile>` is the only repair. The command reports; it never
chooses.

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

Sweep safety posture: it **refuses in api/cloud storage mode** (profile
records live in the cloud registry there, so the local registry cannot prove
non-reference), and a registered profile whose dir is missing — or whose dir
carries auth material without a resolvable uuid — is reported as `unresolved`
and **blocks `--delete`** entirely: unknown is not unreferenced.

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

`buildIdentityIndex()` (identity-index.ts, exported from the package root) is
THE identity enumeration surface: uuid-keyed, central store first, per-profile
stores as compat fallback, with per-layer identity/credential pairing and
door/role attribution. The usage-aware auto-switcher and `accounts auth
status` both consume it; features that reason over accounts must too, instead
of walking profile dirs. This module (auth-store.ts) deliberately owns only
the central store's layout, write path and lifecycle.

Two credential rankings exist ON PURPOSE — they answer different questions:

- `betterCredential` (auth-store.ts): which BYTES survive a sync/restore —
  refresh-token presence and write recency first, because restoring a
  rotated-out refresh token logs the account out.
- `betterCredentialRef` (identity-index.ts): which credential a caller can
  USE right now — validity and expiry first, for selection.

Scope and semantics notes:

- **Claude accounts only today.** The central layout has no tool dimension;
  other tools have no account-uuid concept here yet. Extending to another
  tool is a deliberate layout decision, not a drop-in.
- **Profile bindings come from the machine-local registry.** In api/cloud
  storage mode, cloud-registered profiles are not reflected in `profiles`.
- **Switch markers fail closed.** Any existing `switched-account.json` file —
  even one that no longer parses — excludes the dir's live files as identity
  and credential sources; only the owner-true snapshot syncs.
- **mtime ranks sync/copy recency, not token-rotation time.** The mtime tier
  of `betterCredential` assumes the most recently written copy carries the
  most recently rotated token. With two custodies both holding unexpired
  tokens, a later sync of an older rotation can transiently win; the next
  rotation self-corrects, and losing copies are never destroyed.
- `claudeProfileAuthHealth().snapshotPresent` keeps its legacy meaning —
  "a PER-PROFILE snapshot exists" — while `credentialPayloadPresent`/`status`
  now also see the central store. A central-only profile reports
  `status: "ok", snapshotPresent: false`.

Out of scope here: `keychain.json` (macOS live-auth cache) and
`switched-account.json` (live dir state, not account state) stay per-profile.
