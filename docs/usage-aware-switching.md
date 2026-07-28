# Usage-aware automatic account switching

When a Claude account hits its session or weekly limit mid-task, the failure
arrives as a mid-turn API error — there is no on-error hook, and by then the
work is already stuck. This feature is **proactive** instead: a
`UserPromptSubmit` hook checks the account's remaining headroom *before* each
message is processed and switches the session (in place, no restart, via
`accounts switch-account`) to the healthiest account when the current one is
nearly exhausted. The message then runs on the fresh account and the user never
sees the wall.

## The usage contract

Measured live on 2026-07-28 against Claude Code 2.1.220 (the binary's
`fetchUtilization`):

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <claudeAiOauth.accessToken>     # from .credentials.json
anthropic-beta: oauth-2025-04-20
```

The response carries named windows (`five_hour`, `seven_day`, plus nullable
model-scoped siblings such as `seven_day_opus`) and a structured `limits[]`
array — `{kind, group, percent, severity, resets_at, scope, is_active}` with
kinds like `session`, `weekly_all`, `weekly_scoped`. There are at least **two
independent caps** (session ≈ 5-hourly, weekly), and either can be the one that
bites; `limits[]` is preferred because it labels them explicitly. Model-scoped
windows never set overall headroom — a saturated Opus cap does not gate other
models. Headroom = 100 − the worst *unscoped* window. Override the endpoint
with `ACCOUNTS_CLAUDE_USAGE_URL` (tests, staging).

## Accounts, not directories

Profile **directories are doors; accounts are the thing.** Several dirs
routinely hold the same OAuth account (imports, in-place switches), so all of
this is keyed on `oauthAccount.accountUuid`:

- the identity index (`src/lib/identity-index.ts`) enumerates distinct
  accounts across every store, deduplicated by uuid;
- usage is queried **once per account**, not per dir, and cached per uuid;
- the selector returns an *account*, then resolves which profile door can
  serve it;
- after a switch the hook re-reads the dir's active uuid and **asserts it
  changed to the target** — "switched" onto the same account (two doors, one
  account) is reported as a loud failure, not a success.

Identity/credential pairs are read per *layer* — central
`~/.hasna/accounts/auth/<accountUuid>/` first (the post-migration home, task
`7840d1da`), then per-profile `.accounts-auth/` snapshots, then the dir's live
files — each layer pairing an identity file with the credential written beside
it, so a switched dir can never attribute the guest's token to the owner's
uuid. All reads go through `buildIdentityIndex()`; the auth-store migration
changes one implementation, not call sites.

## Commands

```bash
accounts usage                 # per-account usage: headroom, windows, resets, doors
accounts usage --json          # machine-readable; includes the session's currentUuid
accounts usage --refresh       # bypass cache (also the hook's background cache warmer)
accounts pick --healthiest     # non-interactive: most-headroom account, never the current one
accounts pick --healthiest --no-act --json   # selection only, no apply
accounts usage-hook            # the UserPromptSubmit handler (fail-open, cached-only)
accounts usage-hook --print-install          # the settings.json snippet — NOT auto-installed
```

Expired-OAuth profiles are reported as `expired` (never crash the report);
profiles with no credentials as `no-credentials`; dirs that don't exist are
skipped.

## The hook

`accounts usage-hook` is designed for the `UserPromptSubmit` event:

- **Fast**: decisions use the per-uuid cache only. A missing/stale cache
  triggers a *detached* background refresh (`accounts usage --refresh
  --quiet`) and lets the prompt through — it never blocks on the network.
- **Fail-open**: any error (no account readable, registry down, anything
  thrown) lets the prompt through untouched, exit 0 always.
- **Loud**: every switch — and every *failed* switch — emits a
  `systemMessage` the user sees, plus `additionalContext` so the model knows
  the identity changed. A silent identity change is the half-switch nightmare
  in a different costume.
- **Anti-flap**: one switch attempt per cooldown window (default 10 min),
  shared across successes and failures; when *every* account is limited it
  says so honestly and stays put rather than ping-ponging between exhausted
  accounts.

### Sibling sessions — decision

`switch-account` flips **every** live session sharing the config dir. The hook
proceeds anyway (the `--yes` path) and announces the count in its message
("N live sessions share this config dir and ALL of them switched together").
Rationale: the siblings share the *same exhausted account* — refusing to switch
would strand all of them at the wall, which is exactly the incident that
motivated this feature. The hazard worth engineering against is silence, not
the shared switch; the announcement plus the switched-account marker make the
change visible. Sessions on other dirs are untouched.

### Client identities — decision

There is **no identity exclusion list**: every authenticated account is
eligible for auto-selection, including client-owned identities. Ratified by
the owner on 2026-07-28 ("it's fine to switch across all clients") — do not
re-add an exclusion thinking it was an oversight.

## Install (operator opt-in — never automatic)

The hook is **not** installed by this package. To enable it, merge into
`~/.claude/settings.json` (add to any existing `UserPromptSubmit` hooks — do
not replace them):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "accounts usage-hook", "timeout": 15 }
        ]
      }
    ]
  }
}
```

Keep the cache warm so the hook always has data (optional but recommended):

```bash
# cron / loop, every few minutes
accounts usage --refresh --quiet
```

### Tuning

| Knob | Flag | Env | Default |
| --- | --- | --- | --- |
| Switch trigger (percent used) | `--threshold` | `ACCOUNTS_USAGE_SWITCH_THRESHOLD` | 90 |
| Minimum target headroom | `--min-headroom` | `ACCOUNTS_USAGE_SWITCH_MIN_HEADROOM` | 25 |
| Cooldown (seconds) | `--cooldown` | `ACCOUNTS_USAGE_SWITCH_COOLDOWN_S` | 600 |
| Cache tolerance (seconds) | `--max-age` | `ACCOUNTS_USAGE_CACHE_MAX_AGE_S` | 300 |

State lives under `~/.hasna/accounts/`: `cache/usage/<uuid>.json` (per-account
usage), `cache/auto-switch-state.json` (cooldown), `logs/usage-hook.log`
(size-capped decision log; never contains tokens).
