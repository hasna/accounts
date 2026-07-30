# Credential broker — sharing one account across sessions

`accounts credential-sync` and the machinery behind it (`src/lib/credential-broker.ts`,
`src/lib/identity-lock.ts`) let any number of sessions run the SAME account at the
same time: many readers, one writer, no session refused.

## The defect this dissolves

`switch-account` copies a credential into the session's config dir. Two dirs then
hold independent copies of one account, each Claude Code process refreshes on its
own, and OAuth refresh tokens rotate on exchange — the first copy to refresh
invalidates every other, whose next refresh fails and blanks its file in place
(measured 2026-07-29: six of twenty-three profile dirs on one machine). The old
mitigation refused to create the second copy at all, which withheld every healthy
account exactly when a session was about to hit its usage wall.

## The model

Ported from the codewith lineage. codewith runs many concurrent sessions against
one `auth.json` per profile and survives rotation by re-reading the shared file
and adopting a sibling's rotation instead of refreshing over it. iapp-infinity's
subscription broker (`src/lanes/subscription-broker.ts`,
`subscription-token-refresh.ts`, `file-lock.ts`) hardens that across processes:
a per-credential `mkdir` mutex held over re-read → exchange → atomic persist.
Claude Code itself already survives many sessions in ONE config dir the same way —
it re-reads `.credentials.json` at request time (measured on 2.1.220).

What Claude Code cannot do is converge copies across dirs. The broker does:

- **Converge** (`accounts credential-sync`): under the account's cross-process
  lock, find every file holding the account's credential — central store
  (`~/.hasna/accounts/auth/<uuid>/credentials.json`), profile snapshots
  (`.accounts-auth/credentials.json`), live config dirs (`.credentials.json`) —
  rank them with the same survival rule the sync path uses (`betterCredential`),
  and fan the newest rotation out so every copy holds the same bytes. File I/O
  only; runs before every prompt via the usage hook.
- **Ensure-fresh** (`accounts credential-sync --ensure-fresh`): converge, then,
  when the winning access token has less than `--min-ttl` (default 15 min) left,
  perform the `grant_type=refresh_token` exchange ONCE against the endpoint
  Claude Code itself uses (`https://platform.claude.com/v1/oauth/token`, client id
  extracted from the 2.1.220 binary; both overridable via
  `ACCOUNTS_CLAUDE_OAUTH_TOKEN_URL` / `ACCOUNTS_CLAUDE_OAUTH_CLIENT_ID`), persist
  the rotation atomically to the central store first, and fan out. A concurrent
  caller blocks on the lock, re-reads, finds a fresh token, and spends nothing.

The hook (`accounts usage-hook`) wires both: a synchronous converge before every
prompt (so the dir holds the account's newest rotation before Claude Code
re-reads it), and a detached `credential-sync --ensure-fresh --quiet` when less
than 30 minutes of access-token life remain (so sessions essentially never
trigger the tool's own uncoordinated refresh).

## Write rules (the safety story)

- A copy that ranks better than the payload is never overwritten.
- Live and snapshot files are update-only; the broker never creates credential
  material in a dir that had none (keychain-backed dirs stay untouched — it
  never writes the macOS keychain at all).
- A dir whose occupant is no longer this account is skipped — identity is
  re-checked at write time, the same discipline as `syncProfileSnapshotToCentral`
  and `planParkedRecovery`, which both remain in force.
- A husk (no refresh token) never propagates; with no restorable copy anywhere,
  nothing is written.
- Symlinked paths are refused; every write is atomic (temp + rename, mode 0600).
- A failed exchange writes nothing.

## Ops

```sh
accounts credential-sync                 # converge this session's account
accounts credential-sync --all           # converge every account on the machine
accounts credential-sync --all --ensure-fresh   # broker sweep (loop/cron)
accounts credential-sync --uuid <uuid> --json
```

A periodic `--all --ensure-fresh` sweep (5–10 min loop) keeps shared accounts
fresh even for sessions that idle mid-turn; the per-prompt hook pass covers
everything else. The residual uncovered window — every sharing session mid-turn
across an expiry with no sweep configured — degrades to the pre-broker behaviour,
and the next converge repairs the loser from the surviving copy.
