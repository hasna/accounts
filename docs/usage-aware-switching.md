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
models. `usage.headroom` = 100 − the worst *unscoped* window, kept for
reporting; **selection never ranks on it** (see below). Override the endpoint
with `ACCOUNTS_CLAUDE_USAGE_URL` (tests, staging).

## Two windows, two failure modes

The two caps are independent and they fail differently. Collapsing them into a
single "usage %" produces one of two wrong behaviours, and which one you get is
luck:

| | 5-hour session window | 7-day weekly window |
| --- | --- | --- |
| Exhausted means | unusable for **minutes to hours** | unusable for **days** |
| Right response | switch away, take it back after the roll | switch away, do not return until reset |
| Collapse failure | account abandoned though it would recover in minutes | session returns to an account that is dead until next week |

So the model is two-axis throughout (`src/lib/usage-windows.ts`):

- **Classification is data, not inference.** Every `limits[]` entry measured on
  2026-07-28 across 8 live accounts carried a `group` discriminator —
  `kind=session group=session`, `kind=weekly_all group=weekly`,
  `kind=weekly_scoped group=weekly scoped`. `group` is read first, then `kind`.
- **The reset-horizon fallback is asymmetric, deliberately.** A horizon longer
  than the session window's 5-hour maximum life cannot be a session window, so
  `> 5h ⇒ weekly`. The converse does **not** hold: a live `weekly_all` window
  was measured **0.86h** from its reset, indistinguishable by horizon from a
  session window. A short horizon therefore yields `unknown`, never `session` —
  guessing "session" would let a weekly-dead account back into the pool hours
  early. Horizon-derived classes are flagged `inferred: true`.
- **A rolled window is re-read as recovered.** When a window's `resets_at` has
  passed since the reading was taken, the cached utilization no longer describes
  it and effective headroom becomes 100. This is INFERRED (`headroomInferred`) —
  a window returns to zero consumption at its reset boundary by definition, and
  the next refresh corrects it. It is what makes an account come *back*: without
  it a stale 100%-weekly reading excludes an account forever. A `resets_at` that
  was already past when the reading was taken is a malformed payload, not a
  roll, and is not credited.
- **Unclassifiable unscoped windows gate on the slow (weekly) axis.** The
  optimistic error — assuming an unknown cap is short-lived — is the one that
  strands a session on a dead account.

### Selection

`selectHealthiestAccount` excludes, then ranks. Exclusions carry a reason and,
where known, an `eligibleAt`:

| Reason | Recovers |
| --- | --- |
| `weekly-exhausted` | at the weekly reset — days |
| `session-exhausted` | at the 5-hour roll — minutes to hours |
| `window-exhausted` | unclassified cap, bounded backoff |
| `cooldown` | at the ledger's `releaseAt` |
| `insufficient-headroom` | when a refresh says otherwise |
| `current-account`, `credential`, `no-usage-data` | n/a |

Survivors rank by the **binding window** first — `min(session, weekly)`,
whichever will bite soonest — then **weekly headroom** (the scarce resource that
does not self-heal within a session), then **session headroom** (which is what
makes an already-rolled 5-hour window win a tie), then uuid for determinism.
Leading with the binding window is what stops the selector handing back an
account with a great week and no runway for the next hour.

A target must also clear both floors: `--min-headroom` on the weekly axis and
`--min-session-headroom` on the session axis. The session floor exists because a
target with almost no 5-hour runway re-breaches immediately, and the cooldown
then blocks the follow-up switch — stranding the session on an account that
cannot serve it.

The trigger side is roll-aware too: a window whose reset has already passed is
never a breach however high its cached number reads, so the hook cannot switch
the session away from an account that has quietly recovered.

### Cooldown ledger

`cache/exhaustion-ledger.json` is the memory that survives process restarts. The
usage cache expires and a refresh can fail; neither is a durable record of "this
account told us it was out", and without one a restarted hook re-reads an empty
cache and walks straight back onto the account it just fled.

Each record carries the window class that died, its reset, a consecutive counter
and a computed `releaseAt` = **later of** the reported reset and an exponential
backoff (15 min base, doubling). Both caps are bounded — 5h for session/unknown,
24h for weekly — so a misclassified window or a malformed payload can never
retire an account permanently. It is a cooldown, not a blocklist: records go
inert on their own and need no cleanup.

**A record is written only at 100% utilization, but switches fire from 90%.**
That gap is deliberate — writing a days-long weekly cooldown for an account at
91% would exclude one that still has real headroom — but it has a consequence
worth stating plainly: in the **90–99% band, where most switches actually fire,
no ledger record is written at all.** The ledger therefore does **not** backstop
the global anti-flap cooldown in the common case. The two guards are
complementary but not redundant:

| Guard | Stored at | Covers |
| --- | --- | --- |
| Global anti-flap (`cache/auto-switch-state.json`) | `cache/` | switch *rate*, every switch |
| Per-account ledger (`state/exhaustion-ledger.json`) | `state/` | switch *destination*, only at 100% |

So if `cache/` is cleared, the anti-flap guard is lost and back-to-back switches
remain possible, with no ledger substitute in the band where switching normally
happens. Bounded residual risk, tracked separately.

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

### Keep the cache warm — this is REQUIRED, not optional

The hook decides from cache only, and cached usage older than `--max-age`
(default 300s) is treated as absent. With no warmer running, the first prompt
after any idle gap longer than the TTL logs `refresh-triggered` and decides
NOTHING; the switch can only land on the **second** prompt. Measured in
production on this fleet 2026-07-28 — `logs/usage-hook.log` shows exactly that
`refresh-triggered` / decide-nothing pattern after idle gaps.

For an unattended session that is the difference between switching before the
wall and hitting it, so install a warmer alongside the hook:

```bash
# cron / loop, every few minutes
accounts usage --refresh --quiet
```

Verify one is actually scheduled — a warmer that was recommended but never
installed looks identical to one that is running, right up until the session
stalls.

### Tuning

| Knob | Flag | Env | Default |
| --- | --- | --- | --- |
| Switch trigger (percent used) | `--threshold` | `ACCOUNTS_USAGE_SWITCH_THRESHOLD` | 90 |
| Minimum target **weekly** headroom | `--min-headroom` | `ACCOUNTS_USAGE_SWITCH_MIN_HEADROOM` | 25 |
| Minimum target **session** headroom | `--min-session-headroom` | `ACCOUNTS_USAGE_SWITCH_MIN_SESSION_HEADROOM` | 10 |
| Cooldown (seconds) | `--cooldown` | `ACCOUNTS_USAGE_SWITCH_COOLDOWN_S` | 600 |
| Cache tolerance (seconds) | `--max-age` | `ACCOUNTS_USAGE_CACHE_MAX_AGE_S` | 300 |

State lives under `~/.hasna/accounts/`: `cache/usage/<uuid>.json` (per-account
usage), `cache/auto-switch-state.json` (global anti-flap cooldown),
`cache/exhaustion-ledger.json` (per-account cooldowns, restart-durable),
`logs/usage-hook.log` (size-capped decision log; never contains tokens).

The two cooldowns are different guards and both are needed: the global one
bounds *switch rate* (one switch per window, no ping-pong), the per-account
ledger bounds *where* a switch may land (never back onto an account that just
reported exhaustion, even after a restart).

## Limitations (read before relying on this unattended)

**The hook only fires on `UserPromptSubmit`.** Claude Code exposes no
pre-request hook, and `StopFailure` fires after the turn has already failed
with no ability to recover it (it is monitoring-only). Consequences:

- **A long autonomous run is not protected.** An agent that burns through the
  5-hour window across many tool calls inside a single turn generates no
  prompt events, so nothing is evaluated and nothing switches. Protection
  applies between messages, not within one.
- The limit can still arrive mid-turn. The hook makes that rarer by switching
  before a message is processed; it cannot make it impossible.

Covering long autonomous runs needs an out-of-band watcher (a loop that polls
`accounts usage` and calls `accounts switch-account` on its own schedule)
rather than a `UserPromptSubmit` hook. That watcher does not exist yet.
