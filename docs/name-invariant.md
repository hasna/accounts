# One name, one provider

A profile name identifies exactly one provider. This page says what enforces
that, what does not yet, and what a warning here means.

## Why it matters

Profile resolution is name-first: `accounts <verb> <name>` looks a profile up by
name and refuses with `exists for multiple tools` the moment two records share
one. So a name claimed by two providers breaks every bare command for that name.

It is also not a naming preference. Measured on 2026-07-31, ten names are held
by more than one provider across twenty-three records, and in most measured
cases **the two records are different human identities** — `account005` is
`andrei.hasna@gmail.com` under claude and `theflashbadger@gmail.com` under
codewith. That is why the repair is a rename keyed to a verified account uuid
and never a merge by name.

## What enforces it today

| Layer | Scope | Behaviour |
| --- | --- | --- |
| `nameConflict` (`src/lib/profiles.ts`) | the local `accounts.json` registry | **refuses** a new cross-provider duplicate |
| `AccountsRepo` (`src/server/repo.ts`) | the server `accounts` table | **refuses** a new cross-provider duplicate |
| `assertNameFree` (`src/lib/name-invariant.ts`) | the **merged universe** | **warns** |

The first two are per-store and predate this work; they are unchanged. The third
is new, and it is the only one that sees the whole picture.

## The merged universe, and why the scope matters

The universe the invariant is evaluated against is assembled by
`mergedNameUniverse` (`src/lib/profile-namespaces.ts`):

- **Primary — store records.** In api mode that is the server `accounts` table,
  which is what `accounts list` returns. Two of the regression fixtures,
  `account01` and `account024`, have no local directory and no `accounts.json`
  row on station01; they exist only as server rows.
- **Supplementary — on-disk directories**, in both layouts: managed
  (`<accountsHome>/profiles/<provider>/<name>`) and tool-native
  (`<tool.defaultDir>/<tool.nativeProfilesDir>/<name>`, e.g. codewith's
  `~/.codewith/auth_profiles`). These catch directories no store row describes.

A check built from `loadStore()` alone would see fourteen of the twenty-three
colliding records and neither of the two fixtures. **Silence from the load-time
warning is therefore not evidence that the merged view is clean** — run
`accounts registry --invariant`, which reads the universe above.

## Why it warns instead of refusing

Twenty-three records violate the invariant right now. A hard check over the
merged universe would refuse the very records the backfill and the rename
migration exist to repair — including the re-logins the credential
materialization fix is currently forcing, six of which are codewith accounts the
loops runtime routes to.

So the failing state is deliberately made reachable only **after** the data is
clean. `NAME_INVARIANT_MODE` in `src/lib/name-invariant.ts` is the single
constant that flips it, and there is a test on each side of the flip: warn mode
must not throw, and the same input in hard mode must.

A hard-mode violation exits **3** (`NAME_INVARIANT_EXIT_CODE`), which is
distinct from exit 2, reserved for a removed or absorbed verb stub.

## The grandfather manifest

`accounts registry --write-manifest --apply` records every `(name, provider)`
pair that exists at that moment, built from the same enumerator the invariant
reads — so a pair that exists only on another machine is included and its
re-login is not blocked. Pairs in the manifest are never violations; only new
bindings are checked.

The manifest is a snapshot, not a rule. The rename migration deletes it, after
which there is no grandfathering. A manifest that outlives that migration is
itself a defect.

A malformed manifest reads as **absent**. It can only ever widen what is
allowed, so losing it fails toward warning more rather than allowing more.

## accountUuid backfill

`accounts registry --backfill-uuid` binds each profile to the account that owns
it. The only admissible evidence is the directory's **parked** identity at
`.accounts-auth/oauth-account.json`, confirmed present in the central store at
`<accountsHome>/auth/<uuid>/`.

Three joins are forbidden outright, each because it produces a confident wrong
answer rather than an error:

- **By name** — names collide across providers; that ambiguity is what this
  series exists to remove, and joining on it would launder the ambiguity into a
  binding that then looks authoritative.
- **By credential hash** — nine distinct credentials were measured across
  eighteen accounts. Identical bytes in two places is the signature of
  contamination: at most one of the two claims is true and nothing here can say
  which. A hash join binds both to one account and destroys the evidence that
  they disagreed.
- **By occupant** — `.claude.json` names whoever is in the directory right now.
  `switch-account` copies a credential into whatever directory the session is
  using, so a directory routinely holds a foreign identity while still answering
  to its own name. Reading it binds the profile to the visitor.

Outcomes: `backfilled` (confirmed, safe to write), `already-set`, `conflict`
(the record and the directory disagree — never overwritten), `unverified` (a
parked uuid the central store does not know — reported, not applied), and
`unresolved` (no parked identity — stays absent and earns a finding rather than
a guess).

`--apply` is local-transport only in this release: the hosted `accounts` table
has no `accountUuid` column until the server migration lands. It refuses loudly
rather than writing nowhere and reporting success.

## `provider` and `tool`

`provider` is the canonical name for the field `tool` has always held. It is
introduced as a **mirror**, not a replacement: `tool` stays the persisted key
for one release, new records carry both, and new code reads through
`profileProvider()` so the eventual flip is a change to one function rather than
to every call site. A record whose `provider` and `tool` disagree is refused —
it has no correct interpretation.
