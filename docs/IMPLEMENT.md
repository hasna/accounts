# Implementation guide — `@hasna/accounts`

For contributors and coding agents working in this repo.

## Three-pointer model

Profiles are keyed by **tool + name**, and an account name is unique to exactly
one tool: creating or renaming into a name already held under a different tool
is refused on both transports (`nameConflict` in `src/lib/profiles.ts` and
`src/server/repo.ts`). Registries written before that rule may still hold the
same name under several tools; those rows stay resolvable — bare name lookup is
allowed only when it resolves to one profile; otherwise commands must pass
`--tool`.

Each tool (e.g. `claude`) tracks **two registry pointers** plus an optional **isolated runtime** mode:

| Pointer / mode | Store field | CLI surface | What it controls |
|----------------|-------------|-------------|------------------|
| **Active** (intent) | `store.current[toolId]` | `accounts use`, `accounts active`, `accounts pick` (always), `launch`/`shell` | Which profile you mean for terminal workflows and the shell hook |
| **Applied** (live auth) | `store.applied[toolId]` | `accounts apply`, `accounts applied`, `accounts pick` (default) | OAuth/credentials on live `~/.claude` paths (what Cursor/VS Code read) |
| **Isolated** (no pointer) | — | `accounts env`, `accounts launch`, `accounts shell` | Tool env vars rendered from `src/lib/env.ts` for one process/shell only |

**Rules:**

- `accounts use` updates **active** only — it does **not** change IDE auth.
- `accounts apply` updates **applied** and also sets **active** to the same profile.
- `accounts pick` defaults to **active + apply**; use `--env` or `--no-act` for other modes.
- The shell hook compares **active** vs **applied** and runs `accounts apply` when they differ ([hook docs](./hook.md)).
- `apply` is Claude-only until another tool has a verified live-path adapter.

Registry file: `~/.hasna/accounts/accounts.json` (fields `current` and `applied`, not `active`).

## Key modules

| Path | Role |
|------|------|
| `src/storage.ts` | `ACCOUNTS_HOME`, atomic temp+rename saves, pruned local reads, raw machine-pointer reads |
| `src/lib/store.ts` | Local/API registry routing, cloud custom-tool hydration, API path cleanup |
| `src/lib/profiles.ts` | CRUD, profile metadata/identity/card-last4 validation, `useProfile` → `current`, rename/remove pointer hygiene |
| `src/lib/profile-dir-policy.ts` | Cloud registry path allowlist and custom-tool home validation |
| `src/lib/tools.ts` | Built-in and custom tool registry |
| `src/lib/env.ts` | Per-tool env rendering (`{profileDir}`, `{profileName}`, `{toolId}` templates), including Claude channel state |
| `src/lib/codex-app.ts` | Codex App profile preparation, including file-based credential cache defaults |
| `src/lib/codex-app-menu.ts` | macOS Codex App menu-bar state, switch, safe quit/relaunch, and Swift status-item launcher |
| `src/lib/apply.ts` | `applyProfile`, `applied` pointer, live path sync |
| `src/lib/auth-store.ts`, `identity-index.ts` | UUID-keyed auth custody and account enumeration |
| `src/lib/claude-auth.ts` | Auth snapshots under `<profile>/.accounts-auth/` |
| `src/lib/import-profile.ts` | `import` / `login` |
| `src/lib/pick.ts`, `usage*.ts`, `auto-switch.ts` | Interactive and usage-aware account selection |
| `src/lib/hook.ts` | `claude-hook.sh` generator |
| `src/lib/claude-sessions*.ts`, `session-merge.ts` | Read-only catalog and verified transcript union/linking |
| `src/server/*`, `src/sdk/*` | Postgres HTTP runtime, migrations, OpenAPI document, and generated client |
| `src/cli.ts` | Commander CLI |

For user-facing command details, see [CLI reference](./cli-reference.md). For the
service boundary, see [HTTP API and SDK](./http-api.md) and
[profile directory policy](./profile-directories.md).

## Request-debug boundary

`src/lib/env.ts` owns a deliberately narrow three-key policy:
`BUN_CONFIG_VERBOSE_FETCH`, `NODE_DEBUG`, and `NODE_DEBUG_NATIVE` are removed
case-insensitively after all provider env overlays. Generated export handoffs
explicitly `unset` them, and generated command handoffs use `env -u`, so an
inherited value cannot survive merely because the caller executes printed
output instead of using an Accounts-owned spawn. The optional bash/zsh
`claude()` hook uses the same child-only `env -u` boundary: it preserves the
parent shell and every other inherited environment variable.

Generated handoffs target POSIX sh/bash/zsh syntax. `src/lib/env.ts` rejects
non-portable variable names, quotes every value as a non-expanding POSIX word,
and inserts `env --` before assignments so a leading-hyphen provider binary
cannot be parsed as an `env` option. Embedded quotes, newlines, backslashes,
dollars, and backticks remain literal. Tool schemas validate `extraEnv` keys
at registration/load time, while the renderer validates again at the execution
boundary for defense in depth. fish, nushell, and PowerShell output is not
claimed; use an Accounts-owned launch there (or `accounts shell` for
fish/nushell when `SHELL` identifies that shell).

Do not broaden that list without evidence that another control dumps provider
requests. `PATH`, proxy/TLS configuration, Bedrock/Vertex selection, and
AWS/Google SDK settings are intentionally preserved as part of the caller's
existing trust binding. Provider flags/config, edited handoff commands, and
other caller-selected diagnostics remain residual caller-trusted controls.

`src/lib/redaction.ts` applies a separate output boundary to controlled launch
and prelaunch diagnostics. Its sensitive-header scanner tracks quote, escape,
separator, blank-fold, and record state with linear forward scanning. The same
record scanner handles generic credential keys such as `x-api-key`,
`client-secret`, and token fields, rather than redacting only a first token. It
does not use an authorization-parameter allowlist: arbitrary extension
parameters and cookie names remain inside a folded credential record. Open
quotes and ambiguous indented continuations fail closed. A new header, an
unambiguous structured diagnostic record, or an explicit `status`, `message`,
`stack`, or `detail` record after a syntactically complete non-separated value
ends the record. Unknown assignment names, whitespace-only folds,
diagnostic-looking names after an empty value or dangling credential separator,
separator-only folds, raw quoted tails, and serialized-looking malformed tails
remain sensitive. A quoted value terminates at its closing quote only when its
quoted key and following sibling form a structural serialized-field boundary;
raw comma or semicolon tails are not trusted. Controlled prelaunch stderr and
stdout are separated by a record boundary before line bounding and redaction.
This keeps provably independent records visible without repeated suffix scans,
fusing process streams, or exposing malformed folds.
Credential-key classification is centralized and normalizes separators and
camel case, including dot and space boundaries, before applying stemmed
terminal semantic tokens. This includes `credentials`, `secret-key`,
`service-account-key`, `auth-header`, `service-auth`, and `bearer` without
turning benign suffixes such as `credential-provider` into credentials. Any
distinct normalized `key` token is sensitive regardless of qualifier or
position, covering `encryption-key`, `master-key`, `client-key`, and
`access-key-id` without matching unsplit words such as `keyboard`, `keynote`,
`monkey`, `hockey`, or `turkey`. Valid
JSON documents are walked recursively after JSON key escape decoding; escaped
and single-quoted keys in malformed serialized fragments use the same
fail-closed record boundary. Argument redaction handles credential-bearing long
options separated by `=`, `:`, or the next argv item, the supported `-k value`
and `-kvalue` forms, combined clusters ending in `k`, and Unicode compatibility
forms of the short option. A syntactically bare credential option encountered
while a prior option is awaiting a separate value is classified as new syntax:
an attached value is redacted immediately, while a separate-value option takes
over the pending state. Credential-shaped fragments inside opaque or
non-option dash-leading argv items remain the prior option's value. An exact
`--` ends argv option interpretation even while a credential option is
pending. Every later positional item is still passed through independent
generic text redaction before it crosses a public boundary. Attached
credential fields are redacted in place. Empty-value credential fields keep
one pending value across empty argv padding and redact the next non-empty item.
Because authorization schemes can span multiple argv items,
`Authorization` and `Proxy-Authorization` fail closed by redacting every later
non-empty positional item while preserving empty items. Other benign
positional values retain command and command-line fidelity. A separate
credential option discovered behind a recognized wrapper boundary (for
example `env=--api-key`, `wrapper:--client-key`, or a nested balanced wrapper)
preserves that syntax and binds exactly one later non-empty positional value.
URI schemes with `//`, URNs, mail addresses, and drive-like paths remain
structured data in both the command scanner and the later generic field pass;
an interior `authorization:` segment cannot create sensitive tail state or
consume the next safe token. Captured command text uses that same policy through
a quote-aware, forward-only token scanner that emits physical-newline and
quoted/escaped-origin metadata. A separate option's single pending value
survives LF, CRLF, or bare CR and consumes the next syntactic value; quoted or
escaped dash-leading text remains the value. Opaque dash-leading text remains
bound too: only a complete bare option or a complete sensitive attached form
can replace pending state. The shared bare-option grammar requires exactly one
or two compatibility-normalized leading dashes followed by an alphanumeric
body start; later body characters may be alphanumeric, dot, underscore, or
dash. Exact `--` is handled only as the end-of-options sentinel. Longer dash
normalization is not used for that control decision: the scanner requires the
complete physical token to be raw, unquoted, unescaped, standalone ASCII `--`.
Unicode dash pairs, quoted or escaped markers, wrappers, and
punctuation-adjacent fragments remain value or text data. Longer dash runs and
dot- or underscore-leading bodies, including credential-looking attached
forms, stay opaque bound values. Attached credential values that
themselves resemble options are redacted in place before punctuation splitting,
so the next safe token remains visible. A pending separate value is classified
as one complete physical token before embedded punctuation is considered.
Unless that whole
token is proven bare option syntax or a supported sensitive attached form, the
whole token is redacted and the next whitespace-separated token remains
visible. Open quotes and odd trailing backslashes enter one carried
logical-value scanner across later physical fragments. The active scanner
redacts through quote closure and every adjacent non-whitespace suffix; it does
not split embedded punctuation or reinterpret complete bare options, supported
sensitive option spellings, or exact `--` text inside that logical token.
Option classification resumes only at following whitespace. Blank physical
lines and explicit `status`, `message`, `stack`, or
`detail` records take precedence over incomplete shell syntax and terminate
both missing-value and active continuation state, preventing unbounded carry
into independent output. Physical lines, tokens, embedded punctuation, and
quoted segments are each scanned forward-only. When no separate value is
pending or active, safe punctuation boundaries include `:`, `=`, `|`, `/`, `<`,
`>`, brackets, parentheses, commas, and semicolons. Embedded word, URL, email,
and arithmetic near-misses remain ordinary text. Balanced punctuation opened
inside a structured URL/email value does not end that context, while a closing
outer wrapper or quote resumes option parsing. Explicit unquoted `--` still
ends options for that physical command record only when it is the complete raw
standalone ASCII token and is not part of a pending or active sensitive value.
If a captured physical line ends with unmatched nested syntactic quotes, a
bounded sequence of literal-syntax recovery passes inspects each remainder
after an opener so later standalone credential options cannot be hidden inside
malformed output. Exhausting that bound fails closed for the remaining suffix.
Quoted or escaped option-looking data remains data during recovery, and an
exact raw ASCII `--` retains its ordinary end-of-options meaning.
Prelaunch stderr and stdout are line-bounded and passed through the scanner as
separate records; pending option state cannot cross a process-stream boundary.

`src/lib/switch.ts` separates the internal `SwitchResult`, which may contain
raw launch material, from the explicit public
`hasna.accounts.switch-output/v1` projection. CLI, MCP, and supervisor switch
surfaces emit only that DTO: bounded profile/tool identity, status, redacted
command/handoff data, and message. Environment maps, export scripts, complete
profiles, and complete tool definitions remain internal. The supervisor client
also projects socket responses rather than trusting unknown fields, and legacy
state parsing constructs the current schema field by field instead of spreading
persisted data. Nested prelaunch state has its own explicit allowlist, recursive
redaction allocates null-prototype objects from own enumerable data descriptors
only, and caller-defined tool labels are
represented by an opaque `Custom tool` label rather than reflected into public
switch or supervisor messages. Accessors, inherited fields, pollution keys,
proxies, and non-plain objects are rejected or omitted without evaluating their
payloads.

`accounts agents` applies the same getter-free, cycle-safe recursive public
projection to parsed provider agent records and scanned process records before
either JSON serialization or human rendering. Nested strings and untracked
process command lines are redacted; accessors, proxies, cycles, non-record
entries, and unsafe object shapes cannot cross that output boundary. Provider
records are limited to known agent kinds, malformed PIDs are discarded before
process accounting, process scans are bound to the requested tool, and human
rendering reads only validated scalar fields without coercing provider values.
Configured absolute executables must match observed paths exactly. A configured
bare executable accepts its literal bare invocation, the exact executable
resolved from `PATH` (including its real path), or a native versioned build;
neither direct nor Node/Bun-wrapped processes can borrow the identity of a
different or unresolved same-named executable. Versioned native builds
must live under the current user's exact
`~/.local/share/<tool>/versions/<semver>` root and use strict SemVer 2.0.0
syntax. Exact helper options, terminal
help/version flags, and known Claude non-session subcommands are excluded
without substring matching. The Claude 2.1.220 pre-parser grammar is modeled
before the root command grammar: bridge commands and background-control
commands are recognized only in their fast-path positions, with first-token
background-control dispatch taking precedence over later flags. Otherwise,
exact `--bg` and `--background` select the native background path anywhere in
argv; their transient launcher processes are excluded from session results.
`daemon` is a control command only at token zero after any leading exact
dangerous-permission flags. Root argument scanning then honors required,
optional, and mandatory-first variadic option arities, including hidden
options, helper modes, terminal modes, and `--handle-uri`, before treating a
positional token as a subcommand. That grammar is selected from the registered
tool identity, not the executable basename; arbitrary custom tools named
`claude`, `node`, or `bun` do not inherit Claude or wrapper semantics. Codex App
keeps its direct executable behavior. Interpreter wrappers use explicit Node
22.22.3 and Bun 1.3.14 option schemas, including their attached-versus-separate
value rules and Bun's exact `run` passthrough after validated global
non-execution options. Required-value schema entries reject an empty attached
`--name=` value before child attribution even where Bun currently tolerates
that spelling; this classifier is a fail-closed trust boundary, not a
byte-for-byte runtime parser. Optional attached-value entries remain distinct
and may accept an empty suffix. The syntax-only classifier requires an
interpreter token to resolve to the current `PATH` executable (or that exact
resolved path) and a wrapped child to use its explicit resolved path. Live
process attribution is stricter: a direct process must have a kernel-reported
PID executable matching the configured executable, its exact current `PATH`
target/real path, or the accepted native version path. Node/Bun wrapper rows
fail closed even when the kernel executable matches the trusted interpreter.
Both runtimes allow a same-user process to rewrite argv/process-title text
after startup, and the kernel executable proves only the interpreter after the
child script is closed. Missing or inaccessible PID identity also fails closed.
Unknown or execution-mode options fail closed before accepting a later
executable-shaped argument.
Provider projection is iterative and bounded by explicit depth, object, and
entry limits; truncated branches use a deterministic `[TRUNCATED]` marker.
Pseudo-TTY JSON extraction removes CSI/OSC terminal controls before a bounded
single-pass candidate scan. It preserves the earliest possible root while
rolling a fixed number of fallback candidates, recovers a later agent-record
array after malformed or unterminated wrapper noise, counts both object and
array containers toward the nesting bound, enforces the candidate limit in
UTF-8 bytes, and never retries from every opening bracket. Non-empty payloads
must contain a known background or interactive agent kind. When a containing
candidate exceeds its byte or nesting bound, its full mixed-container region
is quarantined through the matching close so a nested fallback cannot replace
the bounded-out payload's identity. Scanning resumes for later independent
output after a normally bounded quarantine closes. If quarantine nesting itself
exceeds twice the parser nesting limit, its container stack is discarded and
the remainder of that output is quarantined through EOF to keep memory bounded.

Supervisor arguments remain raw only in memory long enough to spawn the
provider child. State files, legacy-state reads, switch responses, and
live/stale status output all use argument-aware redaction before data leaves
that boundary. On Unix, the supervisor directory is forced to `0700` and its
state file and control socket to `0600`, including when `ACCOUNTS_HOME` points
at a pre-existing permissive directory. Every existing directory component is
checked with `lstat`; symlinked Accounts or supervisor roots and non-socket
control leaves are refused before chmod, unlink, write, connect, or listen.
The supervisor snapshots real paths and directory identities, revalidates them
after prelaunch and before provider spawn/persistence, and uses a no-follow
temporary state file plus fsync and rename so a changed boundary fails closed.

## Apply safety

- Refuse apply when the profile has no auth snapshot and no oauth in the profile dir.
- Never delete live oauth unless replacing with target profile auth.
- Exclusive lock: `src/lib/apply-lock.ts`.
- Live paths in tests: set `ACCOUNTS_TEST_LIVE_DIR` (never touch real `~/.claude`).

## Doctor

`accounts doctor` exits **1** when:

- A profile config dir is missing
- `applied.<tool>` or `current.<tool>` points at a removed profile
- A configured shared capability link/merge is broken or its recorded corpus floor shrank

Warnings (exit 0): no email, no usable Claude auth, active ≠ applied drift,
and non-fatal shared capability conditions. Intentional corpus shrinkage can be
accepted with `--accept-capability-baseline`.

## Profile metadata

The store keeps account ownership metadata directly on each profile:

- `email` — account email, auto-detected for tools with an account file.
- `displayName` — human-readable account owner/name.
- `identity` — identity identifier/ref from `identities`.
- `cardLast4` — optional payment card last four digits only, validated as `^\d{4}$`.
- `metadata` — JSON-safe string/finite-number/boolean/null map for operational tags;
  reserved object prototype keys are rejected.

Never store secrets, access tokens, full card numbers, billing addresses, or
private identity documents in `metadata`.

## Tests

```bash
bun test
bun run typecheck
bun run build
bun run contracts:no-cloud-scan
bun run conformance
ACCOUNTS_REQUIRE_POSTGRES=1 HASNA_ACCOUNTS_TEST_DATABASE_URL=<isolated-test-db> bun run test:postgres
```

Use isolated `ACCOUNTS_HOME` and `ACCOUNTS_TEST_LIVE_DIR` in every test (`accounts.test.ts`, `switcher.test.ts`).
PostgreSQL tests create and drop random owner/runtime roles plus a random
schema. Migrations run as the non-superuser schema owner; server and raw legacy
SQL operations reconnect through the documented DML-only runtime grants. CI
provides a disposable PostgreSQL service and treats role separation,
migration/concurrency coverage, and the checksum-pinned full-PR-range gitleaks
scan as required.
