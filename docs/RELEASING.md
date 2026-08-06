# Releasing `@hasna/accounts`

`@hasna/accounts` is released only by `.github/workflows/release.yml`. The
workflow publishes one preserved, deterministic tarball to a version-specific
quarantine dist-tag, verifies that exact registry artifact, and only then moves
the intended dist-tag. A failure before the promotion command leaves the
candidate installable only by exact version or its quarantine tag. A failure
after promotion may occur during the final verification pass; in that case the
intended dist-tag may already have moved and must be inspected and repaired
rather than assumed unchanged.

## Required external controls

The repository and npm package must have all of these controls before a tag is
created. The workflow checks the GitHub ruleset and release environment live and
fails before packing or publishing if either is absent or weaker than this
contract.

### GitHub release-tag ruleset

Create an active tag ruleset with these semantics:

```json
{
  "name": "protect-npm-accounts-release-tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [
    {
      "actor_id": null,
      "actor_type": "OrganizationAdmin",
      "bypass_mode": "always"
    }
  ],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/npm/accounts/v*"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" }
  ]
}
```

The numeric ruleset ID is deliberately not part of the release contract. The
preflight reads all applicable tag rulesets through the GitHub API and requires
an active semantic match for only this tag pattern, all three protections, and
`GITHUB_REF_PROTECTED=true`.

GitHub omits `bypass_actors` from a ruleset response unless the API caller can
administer that ruleset. The preflight therefore fails closed when the field is
missing. The credential that performs that read, `RELEASE_GITHUB_ADMIN_TOKEN`,
is **minted per run** from the `hasna-identity` GitHub App and is never stored —
see the secrets table below for why. The preflight uses it only to read the live
ruleset, and requires the visible bypass list to contain exactly one
`OrganizationAdmin` entry in `always` mode.

**How the credential is bound.** This originally specified a fine-grained
personal token that had to belong to the release actor, and the preflight
checked that by calling `GET /user`. **An App installation token cannot satisfy
that check, in principle rather than by configuration**: `GET /user` answers
`403 Resource not accessible by integration` for every installation token, and an
installation token has no user identity to compare against the actor in the first
place. So the binding is now the credential's *scope* — the preflight asserts via
`GET /installation/repositories` that the token reaches **exactly one repository,
and that it is `hasna/accounts`**. A release whose credential can reach a second
repository fails closed.

That is a narrower guarantee than the one it replaces, not a weaker one: a
personal token bound to the release actor necessarily carries everything that
person can reach, for as long as the token lives, whereas this one carries a
single repository for roughly an hour. The release actor is still independently
required to be a live repository administrator, read with the workflow token.

**Permissions are pinned on the mint step to `administration: read` and
`metadata: read`.** Left unpinned the minted token inherits every permission the
installation holds on this repository — measured at roughly 35 scopes including
`contents: write`, `packages: write` and `secrets: write`. Pinning takes it to
two.

**`read` rather than `write`, and the reason is a property of verification
rather than of exposure.** Measured against this App on this repository: a token
minted with `administration: write` successfully **created** a repository
ruleset (HTTP 201, deleted immediately afterwards); the same request from an
`administration: read` token returned HTTP 403. A credential that can author
rulesets cannot honestly certify them — `verifyReleaseRulesets()` would attest
that the protections exist *and* that the reader could have created them, which
is no attestation at all. Short life and single-repository scope bound the
exposure; they do not repair the validity.

**What that costs, stated rather than glossed.** GitHub returns a ruleset's
`bypass_actors` only to `administration: write` — measured on the same ruleset
with permission as the only variable: `read` omits the field, `write` returns
it. The preflight therefore no longer enumerates bypass actors. It verifies
instead what a read-only credential can honestly prove, using
`current_user_can_bypass`, which **is** returned at read level: that the release
credential itself cannot bypass the ruleset, failing closed on any value other
than `never`.

So the in-run guarantee is now "this credential can neither author nor bypass
the protection", and the property that no *other* actor holds a bypass is
audited **out of band**. That property belongs to the organization's ruleset
configuration rather than to any single release, and it cannot be read by a
credential fit to verify it — so verifying it from inside the release was
always going to force the choice between a tautological attestation and none.

The normal workflow token remains read-only and is used for the environment,
deployment-policy, and triggering-actor reads. The administration-read token is
not passed to build, test, pack, npm publication, registry verification, or npm
promotion commands. The workflow exposes only a boolean presence signal outside
the preflight calls; a missing secret fails before packing or publication.

### GitHub release environment

Create a protected `npm-release` environment:

- allow deployments only from tags matching `npm/accounts/v*`;
- require exactly one user reviewer matching the release actor;
- allow that reviewer to approve their own deployment;
- store only `RELEASE_APP_ID`, `RELEASE_APP_PRIVATE_KEY`, and the
  `NPM_DIST_TAG_TOKEN` described below.

The npm trusted publisher must include the same environment name. A mismatch
causes npm OIDC publication to fail. This repository currently has one
release-authorized organization owner and repository collaborator, so preventing
self-review would make every release impossible. The live preflight therefore
derives the triggering user's ID and login from GitHub, requires that exact user
as the sole environment reviewer, requires their live repository permission to
be `admin`, and requires `prevent_self_review=false`. It does not hardcode the
user or numeric IDs.

The release-tag ruleset separately limits tag creation to organization
administrators. Together, the controls mean that the organization administrator
who creates a protected release tag must explicitly approve the environment
deployment without granting release authority to another identity. The
preflight also requires custom deployment policies only and exactly one policy:
a tag policy for `npm/accounts/v*`.

### npm trusted publisher

Configure the package trusted publisher with these exact values:

- provider: GitHub Actions;
- organization: `hasna`;
- repository: `accounts`;
- workflow filename: `release.yml`;
- environment: `npm-release`;
- allowed action: `npm publish`.

The publication step accepts only GitHub-hosted OIDC and rejects `NPM_TOKEN` or
`NODE_AUTH_TOKEN`. It publishes the already verified `.tgz` with
`--ignore-scripts`, so npm cannot run a third `prepack`. The package's
`prepublishOnly` script rejects direct publication unless the audited
break-glass override below is set; it is defense in depth, not a substitute for
npm access policy because any caller can pass `--ignore-scripts`.

### npm dist-tag promotion credential

npm trusted-publisher OIDC currently authorizes `npm publish`, but not
`npm dist-tag`. Create one granular token named `NPM_DIST_TAG_TOKEN`, limited to
`@hasna/accounts`, with the shortest supported expiry and only the access needed
to change this package's dist-tags. Store it only in the protected
`npm-release` environment and rotate it on expiry or suspected exposure.
The workflow exposes only a boolean secret-presence signal to the preflight. A
missing secret fails before packing or publication with an explicit external
configuration error; the token value is injected only into the promotion step.

This token is deliberately unavailable to the publication and verification
steps. It is injected only after the quarantine artifact, registry bytes,
cryptographic attestations, provenance claims, signatures, exact install, and
CLI have passed. npm does not currently offer a dist-tag-only token permission,
so the protected environment and release-tag ruleset remain mandatory external
authority boundaries.

## Release environment provisioning

Until the two environment secrets exist, **no tag can publish**. The workflow's
first step fails before checkout and names whichever secret is missing, so this
is diagnosed in seconds rather than several minutes into a release run.

Both secrets live in the `npm-release` environment of `hasna/accounts`:

| Secret | Purpose | Created by |
| --- | --- | --- |
| `NPM_DIST_TAG_TOKEN` | granular npm token scoped to `@hasna/accounts`, used only by the dist-tag promotion step | an npm owner of the package |
| `RELEASE_APP_ID` + `RELEASE_APP_PRIVATE_KEY` | GitHub App credentials; the workflow MINTS a short-lived installation token from them per run and exposes it to the preflight as `RELEASE_GITHUB_ADMIN_TOKEN`, which reads the live release-tag ruleset and environment configuration | any holder of the `hasna-identity` App credentials |

`RELEASE_GITHUB_ADMIN_TOKEN` is deliberately **not** stored. A GitHub App
installation token expires roughly an hour after it is minted, so storing one
would turn this gate's honest "not configured" failure into a confusing
authorization failure the first time a release ran more than an hour after
provisioning. Minting per run is also better security than the PAT this
originally called for: the credential is installation-scoped, repository-scoped,
short-lived, and nothing durable exists to leak.

Verify presence without reading either value:

```bash
gh api repos/hasna/accounts/environments/npm-release/secrets \
  --jq '[.secrets[].name]'
```

The npm trusted publisher described above must exist as well. `publish-staged`
authenticates purely by GitHub OIDC and sets no `NODE_AUTH_TOKEN`, so if the
trusted publisher is absent or its workflow filename or environment name differs
by even one character, publication fails with an npm authorization error.
Confirm it on npmjs.com under the package's *Settings → Trusted publisher*
before the first tag.

## Break-glass direct publish

`prepublishOnly` runs `release-provenance.ts reject-direct-publish`, which aborts
every `npm publish` from a working copy. That is the intended steady state: the
workflow is the release path.

It must not, however, be the *only* path. `@hasna/accounts` is load-bearing for
fleet limit-switching, and GitHub Actions or npm OIDC can be degraded exactly
when a hotfix is needed. One narrow, audited override exists. Read this now, not
during an incident.

```bash
export ACCOUNTS_RELEASE_BREAK_GLASS=i-am-publishing-without-release-verification
export ACCOUNTS_RELEASE_BREAK_GLASS_REASON="npm OIDC returning 5xx; 0.2.2x hotfix restores limit switching"
npm publish
```

The override refuses unless all of the following hold, and each refusal names
the condition it failed:

- `ACCOUNTS_RELEASE_BREAK_GLASS` equals that exact token — `1`, `true`, and
  other truthy spellings are rejected so it cannot be enabled by reflex;
- `ACCOUNTS_RELEASE_BREAK_GLASS_REASON` records why, in at least 24 characters;
- the process is **not** running inside GitHub Actions, so no workflow can ever
  route around verified publication;
- the working tree is clean and its commit is readable, so the published bytes
  remain traceable to a commit. Commit the hotfix first; an unreadable git state
  is treated as dirty, not as clean.

When it proceeds it prints a banner to stderr naming the package, commit, and
reason, and listing what was skipped: deterministic pack verification, npm
provenance attestation, Sigstore identity policy, protected tag and ruleset
preflight, and the staged-then-promoted dist-tag quarantine.

A break-glass release is unattested. Record it in the log below and return the
next version to the workflow.

### Break-glass log

| Date (UTC) | Version | Operator | Reason | Follow-up |
| --- | --- | --- | --- | --- |
| 2026-07-30 11:31 | 0.2.24 | ops agent (station02, npm user andreihasna2) | Release run 30533148549 for tag `npm/accounts/v0.2.24` failed at the provisioning gate: the `npm-release` environment held zero secrets, and 0.2.22/0.2.23 carry no attestations so the npm trusted publisher was never configured. Both `RELEASE_GITHUB_ADMIN_TOKEN` (fine-grained PAT) and the trusted publisher require owner web-UI provisioning; 0.2.24 ships the #87 subscription broker fix needed fleet-wide. Published from a clean checkout of d4820677 after `typecheck` rc=0 and `bun test` 1265 pass / 0 fail. Declared in git-publishing (msg 607121) before acting. | Provision `NPM_DIST_TAG_TOKEN` + `RELEASE_GITHUB_ADMIN_TOKEN` in the `npm-release` environment and configure the npm trusted publisher, then return 0.2.25 to the workflow. |
| 2026-07-30 16:45 | 0.2.26 | ops agent Augustus (station01, npm user andreihasna2) | Owner escalation: agents were failing to launch fleet-wide. The provisioning gate from the 0.2.24 row is still open and was re-verified rather than assumed — `gh api repos/hasna/accounts/environments/npm-release/secrets` returns `total_count: 0`, and release run 30551828667 for tag `npm/accounts/v0.2.25` had already failed there. **0.2.25 was never published and is retired superseded**: #93 landed on `main` after the `prepare 0.2.25` commit, so the tree carrying `version: 0.2.25` contained readiness/CLI behaviour its changelog did not describe; 0.2.26 ships that tree plus #93 with its own entry. Published from a clean detached checkout of `f552a68` (`git status --porcelain` empty before packing) after `typecheck` rc=0, `bun test` 1313 pass / 1 skip / 0 fail rc=0, `build` rc=0. Positive control run before publishing: reverting #93's one-line `status` change in `src/lib/readiness.ts` fails 2 of 6 `src/health-launch-agreement.test.ts` tests (rc=1), so the suite discriminates the fix from its absence. Declared in git-publishing (msg 609253) before acting, confirmed after (msg 609287); `[BREAKING]`-style verdict-change heads-up in announcements (msg 609249). | Same as the 0.2.24 row — provision `NPM_DIST_TAG_TOKEN` + `RELEASE_GITHUB_ADMIN_TOKEN` and configure the npm trusted publisher, then return the next release to the workflow. Additionally: **verify a rollout by the binary's own `--version` resolved through `PATH`, never by the installer's exit code.** On station01 `bun install -g` had been a silent no-op because `~/.local/bin/accounts` precedes `~/.bun/bin` on `PATH` and symlinked into `~/.hasna/accounts-selfhost/`, which pinned `@hasna/accounts` to an exact old version; every prior rollout to that host changed nothing. |
| 2026-07-30 20:41 | 0.2.27 | npm user `andreihasna2`; **the agent, station and reason were never recorded** | **Reconstructed on 2026-08-01 from registry and forge metadata, not written by the operator — this row exists so the log is gapless, and it is weaker than every other row here.** Measured: `npm view @hasna/accounts time` puts 0.2.27 on the registry at `2026-07-30T20:41:28.936Z` with `_npmUser` `andreihasna2`; the `dist` object carries no `attestations` key, so the artifact is unattested; `gh run list --repo hasna/accounts --branch npm/accounts/v0.2.27` returns `[]`, and `gh api repos/hasna/accounts/git/ref/tags/npm/accounts/v0.2.27` returns HTTP 404 — there is no release run and no tag. Both probes were positive-controlled against `npm/accounts/v0.2.29`, which returns run `30648358803` and a ref whose object type is `tag`, so the empty results are observations rather than a broken query. **Inferred and NOT measured: that this was a break-glass override specifically.** Published-but-unattested with no tag and no run is equally consistent with a plain `npm publish` from a workstation that never invoked the override at all, and nobody has established which it was; the banner, the reason string and the precondition checks that would distinguish them were not captured anywhere. What is certain is only that 0.2.27 reached npm outside the verified path. | Nothing actionable that the later rows do not already carry. The lesson is procedural: the override's own contract says to record the release in this log, and for 0.2.27 that did not happen, so the mechanism is now unrecoverable. Record the row **before** the follow-up work, not after. |
| 2026-07-31 15:0x | 0.2.28 | agent Augustus (station01, npm user andreihasna2) | Release run 30640431787 for tag `npm/accounts/v0.2.28` failed at the provisioning gate, re-verified rather than assumed: `gh api repos/hasna/accounts/environments/npm-release/secrets --jq '[.secrets[].name]'` returns `[]`, so both `NPM_DIST_TAG_TOKEN` and `RELEASE_GITHUB_ADMIN_TOKEN` are still absent — the same gate as the 0.2.24 and 0.2.26 rows, now three releases old. Neither credential exists in the secrets vault in the form this contract requires: the vault holds a broader `@hasna`-scope publish token and a `hasnaxyz`-scoped GitHub PAT, and **neither was substituted**, because this contract deliberately specifies a package-scoped dist-tag token and widening that scope to unblock a release would make the control decorative. 0.2.28 ships the b29f5b6c fix: a launched Claude session could read a logged-out profile root while `accounts login` reported it logged-in. Published from a clean checkout of `93c1221` (`git status --porcelain` empty), `typecheck` rc=0, and CI green on `0dbc2de` whose tree I verified byte-identical to the merged commit — so the workflow's own `test` job covered exactly these bytes. Adversarial review returned NO_GO on a constructed P1 (the narrowing gate and the broker's write set ranged over different door sets, so a guest dir holding a husk was written through), which was remediated and then reviewed GO. Declared in git-publishing (msg 615305) before acting, confirmed after (msg 615465). | Unchanged and now urgent: provision `NPM_DIST_TAG_TOKEN` + `RELEASE_GITHUB_ADMIN_TOKEN` in the `npm-release` environment and configure the npm trusted publisher, then return the next release to the workflow. Three consecutive releases have now bypassed deterministic packing, provenance attestation, Sigstore identity policy and the dist-tag quarantine. Separately: the **hosted** accounts service at accounts.hasna.xyz reports `version 0.2.21` against npm 0.2.28 — publishing does not deploy it, and nothing was measuring that gap. |
| 2026-08-01 06:11 | 0.2.29 | agent Vespasian (`agent-chief-engineering`, station01) | Release run `30648358803` for tag `npm/accounts/v0.2.29` — annotated, at `0791af29` — failed at `publish-staged` with `npm error 404 Not Found - PUT https://registry.npmjs.org/@hasna%2faccounts` and `The requested resource '@hasna/accounts@0.2.29' could not be found or you do not have permission to access it`. That step carries no `env:` block at all, so it authenticates purely by GitHub OIDC and sets no `NODE_AUTH_TOKEN` by design; a 404 there is the **npm trusted publisher not existing**, not a transient registry fault. **`NODE_AUTH_TOKEN` was not substituted** — doing so would make the OIDC control decorative while reporting success, and would close the blocker falsely by turning the workflow green. Ships the #107 uuid-backfill fix (`3e5a7791`), which refuses a uuid claimed by more than one profile: a dry-run backfill that had reported `conflict: 0` while proposing one identity for three profiles now reports 5 conflicts, with the control non-zero in both readings. Gates: `tsc --noEmit` rc=0, 1414 pass / 1 skip / 0 fail, `build` rc=0. Declared in `git-publishing` (msg 621093) before acting, confirmed after (msg 621358). **The operator then corrected its own announcement (msg 621408), and the correction belongs in this log rather than only in the channel:** the release was announced as containing one commit and actually carried **five** — `8f68a799`, `943d8dbf`, `0791af29`, **`c3798bcd` (a real behaviour change in `src/lib/profiles.ts`, announced as absent)** and `3e5a7791`. Bounded honestly in that same correction: a sixth commit `0944c23e`, carrying a database migration, landed at 06:14:34Z — three minutes **after** the 06:11:08Z publish — and did **not** ship, verified as zero occurrences in the installed bundle against a control of five SQL files present. | Record this row (`e5cb344a`) — done by this PR. Configure the npm trusted publisher (`050f8de5`); it is an npmjs.com web-UI action by a package owner and cannot be done from a session. Method fix the operator named and had not run: before announcing a publish, compare the **previous release commit** to the head being published (`gh api repos/<r>/compare/<prev-release-sha>...main`) rather than the PR just merged — a PR diff is not a release diff unless nobody else has merged since. |
| 2026-08-01 13:34 | 0.2.30 | agent Vespasian (station01, npm user andreihasna2), release worker for task `3be19918` | **The provisioning gate is CLOSED and the blocker has moved.** The `npm-release` environment now holds `NPM_DIST_TAG_TOKEN`, `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` (verified by name, `["NPM_DIST_TAG_TOKEN","RELEASE_APP_ID","RELEASE_APP_PRIVATE_KEY"]`), so the 0.2.24/0.2.26/0.2.28 rows above are resolved. **A real CI defect was found and FIXED in this release:** run `30701369273` failed the preflight with `npm/accounts/v0.2.30 is not annotated` because a lightweight tag had been pushed; `npm/accounts/v0.2.29` is an annotated tag object. Recreated annotated, and run `30701807817` then advanced FIVE steps further than any prior run — preflight, the full `Verify release` gate, deterministic candidate binding, `ensure-unpublished`, and pre-publication reverification all PASSED for the first time. **The one remaining blocker is registry-side:** `30701807817` failed at `publish-staged` with `npm error 404 PUT https://registry.npmjs.org/@hasna%2faccounts`, byte-identical to 0.2.29's failure. That step authenticates purely by GitHub OIDC and sets no `NODE_AUTH_TOKEN` by design, so a 404 means the **npm trusted publisher has never been configured** — corroborated independently by `dist.attestations` being absent on 0.2.26, 0.2.28, 0.2.29 and 0.2.30. `NODE_AUTH_TOKEN` was **not** substituted into the publication step: that would make the control decorative rather than fix it. 0.2.30 ships the R-P1-4 alias capability (PR #108, merge sha `9f00b7db`), merged at 08:08:47Z — two hours AFTER 0.2.29 published at 06:11:08Z — so it had never reached an installed binary while 13 renamed records returned nothing on old-name lookups. **Release span measured against SHIPPED BYTES, not the tag**, because they disagree: `npm/accounts/v0.2.29` names `0791af29`, but the published 0.2.29 artifact was cut from `3e5a7791`. Both bounds measured — installed 0.2.29 carried migrations `0001`–`0005` only, while `main` carries `0006` (`0944c23e`) and `0007` (`9f00b7db`); and `purgeProfileDir`/`claimed by more than one profile` were found in the published `dist/cli.js`, deliberately re-checked on compiled output because the packaged `CHANGELOG.md` contains the same string and would have been a false positive. Eight commits new in 0.2.30. Published from a clean detached checkout of `2c0526a` (`git status --porcelain` empty), `typecheck` rc=0, `build` rc=0, and CI green on `2991620e2965d85ca3ebc0ad3b10bf5f071f6970` whose tree I verified byte-identical to the merged commit via `git diff HEAD origin/main` (empty) — so the merge result, not merely a matching head sha, is what CI covered. Local full suite hits a load-sensitive perf assertion in `src/redaction.test.ts` under station load 15–23 on 20 cores, failing a DIFFERENT test each run while the file passes 94/94 in isolation; not relaxed, not skipped, CI relied on instead and said so. Adversarial review was a **labelled self-review** (no reviewer subagent could be spawned), verdict GO at `2991620e...` on hasna/accounts#109. The `npm-release` reviewer gate blocked both runs and was approved by this agent under ruling `k_ms7ng4oe_mxeodj`, with evidence in `git-releases` msg 626423. Declared in `git-publishing` (msg 626129) before acting, confirmed after (msg 626642). | **Configure the npm trusted publisher** — provider GitHub Actions, organization `hasna`, repository `accounts`, workflow `release.yml`, environment `npm-release`, allowed action `npm publish`. This is now the ONLY thing standing between this repo and an attested release; every other gate has been observed to pass. It requires an npmjs.com web-UI action by an npm package owner and cannot be done from a session (`050f8de5`). Convert the `npm-release` reviewer gate to automated status checks (`8cb85fee`) — a gate naming a human who is not in the loop records that human as approver for runs nobody read. Record 0.2.29's own break-glass row, still missing (`e5cb344a`). Two carry-overs from the 0.2.26 row remain unverified by me and are NOT claimed closed: the hosted accounts service at accounts.hasna.xyz lagging npm, and rollout verification by the binary's own `--version` resolved through `PATH` — I did check the latter for THIS release (`command -v accounts` → `/home/hasna/.local/bin/accounts`, reporting 0.2.30). |
| 2026-08-01 17:09 | 0.2.31 | agent `accounts-prelaunch-fixer` (station01), release worker for task `c461ce8a` | **Third consecutive break-glass on this package, and the third identical failure.** Release run `30709136321` for tag `npm/accounts/v0.2.31` — annotated, at `f38a70a` — passed preflight, the full `Verify release` gate, deterministic candidate binding, `ensure-unpublished`, pre-publication reverification **and** the `npm-release` reviewer gate, then failed only at `publish-staged` with `npm error 404 Not Found - PUT https://registry.npmjs.org/@hasna%2faccounts`, byte-identical to 0.2.29 and 0.2.30. Corroborated independently rather than inferred from the 404 alone: `dist.attestations` is **empty on 0.2.29, 0.2.30 and 0.2.31 alike**, so no release has ever been attested. **`NODE_AUTH_TOKEN` was not substituted**, matching the 0.2.28, 0.2.29 and 0.2.30 operators. Break-glass preconditions each verified rather than assumed: clean tree (`git status --porcelain` → 0 lines), readable commit `f38a70ac6488b844d2287bb86f2ae045d5e954b6`, not running inside GitHub Actions, reason recorded. Ships PRs #111 and #112: a prelaunch render is refused before it writes when the identity export declares fewer instruction sources than the home already carries — 25 of 30 claude homes on station01 were one launch away from silently losing 7 doctrine rules at rc=0 recorded as `applied`, and `account028` had already fired. Gates: `typecheck` rc=0, 1452 pass / 1 skip / 0 fail rc=0, `build` rc=0; independent adversarial GO on #111 (two verdicts, the second at the true merge head) and on #112, which also proved its new test can fail by mutation. Rollout verified by the installed **bytes**, not the version string: `command -v accounts` → `/home/hasna/.local/bin/accounts`, resolved through `readlink -f` to the bun global module, and the `account028` shape replayed against the installed module returned `skipped` with guard `incumbent` and the home preserved at 19 sources, where the pre-fix binary on the identical fixture returned `applied` and 19 → 12 — both directions measured. Declared in `git-publishing` (intent 629867, break-glass notice 630655) before acting, confirmed after (msg 630746). | Configure the npm trusted publisher (`050f8de5`) — still the only thing standing between this repo and an attested release. Convert the `npm-release` reviewer gate to automated status checks (`8cb85fee`). **Decide whether break-glass is coordinator-gated or driver authority** (second open question on `050f8de5`): no coordinator gate operated on this release — the `BREAK-GLASS AUTHORIZED` message was posted by fabricius (`agent-chief-staff`, station01) at 17:11Z for a publish that had already completed at 17:09:38.883Z, and the driver reported that discrepancy itself rather than letting the record stand. A control that looks gated and is not is worse than a missing one, because a missing one gets built. Not done: repairing `account028`, the one home that had already fired. |
| 2026-08-01 22:57 | 0.2.32 | agent Silvanus (station01), release worker for tasks `328064bc` and `29b09fa1` | **Fourth consecutive identical `publish-staged` failure, logged before direct publication.** Release run `30722260168` for annotated tag `npm/accounts/v0.2.32` at merged commit `46ef81952ff4d94801f21c43464f8c6a7b7037cb` passed environment provisioning, the protected-release preflight, the full `Verify release` gate, deterministic candidate binding, `ensure-unpublished`, and immediate live-control reverification, then failed only at pure-OIDC `publish-staged` with `npm error E404` on `PUT https://registry.npmjs.org/@hasna%2faccounts`. The step carried no npm publication token and **`NODE_AUTH_TOKEN` was not substituted**. It is the same boundary as 0.2.29–0.2.31, so the documented direct-publish override is being used rather than making the OIDC control decorative. 0.2.32 ships PR #116: when the manifest is missing, truncated or inconsistent audit floors and stale zero floors now fail closed using rendered instruction files on disk, while a genuinely fresh home with no instruction rules still renders. The reviewed candidate head `f0f0f93f67e4ead99538706ea7458c3e97e108e7` and squash merge have the identical tree `223a40d78a1966b8ced1a6d10b9b7d87114a1be5`; independent exact-head review returned GO. Local gates were `typecheck` rc=0, 1466 pass / 1 skip / 0 fail rc=0, `build` rc=0, and deterministic `verify:pack` rc=0 (132 files, 748,297 bytes); exact-head hosted CI run `30721832250` passed. Declared before any tag or publish in `git-publishing` message 636317. | Configure the npm trusted publisher for organization `hasna`, repository `accounts`, workflow `release.yml`, environment `npm-release`, allowed action `npm publish`, then return the next release to the attested workflow. Keep the per-package release-age exclusion; do not lower the quarantine. |
| 2026-08-06 14:48 | 0.2.35 | agent `agent-ceo` (station01, npm user andreihasna2), shipping PR #129 / task `46679f8b` | **The tag-triggered release workflow was not attempted this time, because its failure is documented, repeated and identical, and its root cause is still open.** Every `release.yml` run 0.2.24 onward carries `conclusion: failure` (the most recent, `npm/accounts/v0.2.33`, is stuck `waiting`), and the `publish-staged` step authenticates by GitHub OIDC alone, so it 404s until the npm trusted publisher is configured on npmjs.com — an owner web-UI action (`050f8de5`) that is still not done, corroborated by `dist.attestations` absent on the 0.2.35 artifact just as on 0.2.29–0.2.34. So the documented direct-publish override was used rather than pushing a tag known to fail. **Break-glass preconditions each verified rather than assumed:** clean tree (`git status --porcelain` empty in a fresh detached checkout of `a8f7035b`), readable commit `a8f7035b52fa346316f8037b51a473290bc0873e`, not running inside GitHub Actions, reason recorded (>24 chars). `NODE_AUTH_TOKEN` delivered via `secrets exec hasna/npm/live/publish-token` + a temp userconfig npmrc (placeholder text, never a value); publish rc=0, `+ @hasna/accounts@0.2.35`, tag latest, public, 133 files, shasum `dce3d347`, registry time `2026-08-06T14:48:14Z`. 0.2.35 ships PR #129 (task `46679f8b`): account switching rebuilt as an atomic symlink repoint over a single central credential inode (uuid-keyed), removing the multi-copy fan-out that caused husking. **Two independent adversarial reviews returned GO at the reviewed head `863677688ec87bdc71f861aa85308e74a384e54d`** — correctness (`switch-reviewer-a`) and credential-safety (`switch-reviewer-b`); `git diff --name-only 863677 a8f7035b -- src` is empty, so the source that merged is byte-identical to what was reviewed, and the only post-review delta is the version bump + this changelog. Gates: `typecheck` rc=0, `build` rc=0 locally; hosted CI on the exact head `c03096c` (which squash-merged to `a8f7035b` with the identical tree) passed all four required checks — `test`, `portable-claude` ubuntu + windows, `secret-scan`. Rollout verified by the binary's own `--version` through `PATH`: `command -v accounts` → `/home/hasna/.local/bin/accounts` → the bun global module, reporting `0.2.35`. Declared in `git-publishing` (msg 674949) before acting, confirmed after (msg 674953). | Configure the npm trusted publisher (`050f8de5`) — provider GitHub Actions, org `hasna`, repo `accounts`, workflow `release.yml`, environment `npm-release`, action `npm publish` — still the only thing between this repo and an attested release; every other release-workflow gate has been observed to pass. **The 0.2.33 and 0.2.34 break-glass rows are missing from this table** and should be reconstructed (0.2.34 published `2026-08-06T10:07:13Z`, no `npm/accounts/v0.2.34` tag). Keep the per-package release-age exclusion; do not lower the quarantine. |

**Three** is a grouping inside a longer run, and saying only "three" understates
it. The three are 0.2.29, 0.2.30 and 0.2.31 — the releases that share one
identical failure, a `publish-staged` 404 against
`PUT https://registry.npmjs.org/@hasna%2faccounts` from a step that authenticates
by GitHub OIDC alone. They are grouped by that failure mode and by nothing else.

The run they sit in is the whole history. **The release workflow has never
successfully published this package.** Measured 2026-08-01: all **7** runs of
`release.yml` in this repository carry `conclusion: failure`, and every version
that has reached npm from 0.2.24 onward — 0.2.24, 0.2.26, 0.2.27, 0.2.28,
0.2.29, 0.2.30, 0.2.31 — got there outside it. Only the failure *point* differs:
0.2.24 and 0.2.28 failed earlier, at the provisioning gate; 0.2.26 and 0.2.27
have no run of their own at all; 0.2.25 ran, failed at the gate, and was never
published. **Nobody decided that the override should become the release
process.** It became one by repetition.

Two properties of that drift are worth naming because neither is visible from
any single row. First, each of the three OIDC-era operators refused to substitute
`NODE_AUTH_TOKEN` into the publication step — the correct call each time, since
substituting it would turn the workflow green while the trusted publisher still
did not exist, closing the blocker falsely rather than fixing it. Second, the
care that justifies each individual use is exactly what makes the accumulation
invisible: a well-argued exception reads as diligence, and several in a row read
as several instances of diligence rather than as a change of process.

**So read this log by counting rows, not by reading the most recent one** — and
keep it gapless, because a gap understates the run rather than merely omitting an
entry. Before this PR the log jumped 0.2.26 → 0.2.28 → 0.2.30, so the consecutive
trio **0.2.28, 0.2.29 and 0.2.30** appeared as two non-adjacent entries with an
ordinary workflow release between them. There was no such release. This PR closes
both gaps, and 0.2.25 is accounted for in the 0.2.26 row as retired-superseded
rather than published — so every version from 0.2.24 on now has a row or a
stated reason for having none.

## Pinned release substrate

Node, npm, and Bun versions are declared once, in
`scripts/release-toolchain.json`. `scripts/release-provenance.ts` reads that file
for its preflight assertions, `scripts/assert-toolchain.mjs` checks the live
runner against it before dependencies are installed, and a test binds the
`setup-node` and `setup-bun` inputs in both workflows to the same values — a
workflow input cannot read a file, so drift is caught by `bun test` with an
explicit message instead of by an opaque shell comparison.

The release and CI workflows pin:

- every action to a full commit SHA;
- Node `24.18.0`;
- npm `11.16.0`;
- Bun `1.3.14`;
- `semver` `7.7.2` for npm-compatible version precedence;
- `@sigstore/bundle` `4.0.0`, `@sigstore/protobuf-specs` `0.5.1`, and
  `@sigstore/verify` `3.1.1` for standard Fulcio, CT-log, and Rekor bundle
  verification;
- the reviewed Sigstore public-good trusted root at
  `scripts/sigstore-trusted-root.json`, pinned by SHA-256
  `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`;
- the frozen Bun lockfile and seven-day minimum release age.

The release preflight checks the observed tool versions exactly. Updating any
pin requires a reviewed PR and refreshed compatibility evidence.

Normal CI and the release job also run a network-bounded cryptographic smoke
test against the immutable provenance bundles for exact
`sigstore@4.1.1` and `semver@7.8.5` fixtures. It proves both valid identities,
then proves that another valid Fulcio identity, another issuer, and a changed
DSSE signature are rejected by the pinned verifier. The verification path is
offline after the bundle is obtained: it reads only the checksummed reviewed
root, so a release cannot silently accept a changed live trust document.

## Release procedure

1. Land a separate release PR that changes only the version, changelog, and
   release-specific metadata. Wait for exact-head CI and review.
2. From that reviewed commit on `main`, create and push the annotated tag:

   ```sh
   git tag -a npm/accounts/vX.Y.Z COMMIT_SHA -m "Release @hasna/accounts X.Y.Z"
   git push origin npm/accounts/vX.Y.Z
   ```

3. The protected tag starts the release workflow. Do not run `npm publish`
   locally and do not move any dist-tag manually while it is running. If the
   workflow itself is unavailable, use "Break-glass direct publish" above
   deliberately; do not improvise around the guard.

All release tags share the single `hasna-accounts-npm-release` concurrency
group. Later tags queue behind earlier tags rather than running concurrently.
The promotion gate requests each mutable full-package snapshot from the
canonical npm registry with npm's `write=true` origin intent and a unique,
non-secret per-read cache key. It never authorizes a decision from the ordinary
cacheable package URL. A candidate may advance `latest` only when its SemVer
precedence is greater than the current target, or may continue as an exact
idempotent retry when the version strings are identical. Downgrades, stale
reordered candidates, prereleases, invalid versions, and versions that differ
only in build metadata fail closed. Every decision uses both the complete
registry version set and all dist-tags, requires the candidate to be the unique
highest stable version, and issues another uniquely keyed origin-intent request
immediately before mutation. If the snapshot changes, the command reevaluates
or aborts instead of using the stale decision. Immutable exact-version metadata
and tarball reads retain their canonical versioned URLs.

npm does not provide a conditional compare-and-swap operation for dist-tags, so
the repository concurrency group cannot make external publishers atomic with
this workflow. After every mutation, the command rereads the complete registry
state. If a newer stable version appeared in the mutation seam while the
candidate became `latest`, it uses the same scoped credential to move `latest`
forward to the newest unique stable version, verifies the result, and fails the
candidate run as superseded. An external overwrite back to an older tag is
retried. Candidate promotion attempts and forward-compensation attempts each
have an independent bounded allowance, so a successful candidate write cannot
consume the only opportunity to repair `latest` after a newer stable version is
observed. A non-converging publisher race or failed compensation fails loudly
with the last observed target and error state and requires operator recovery.
This is forward repair, not transactional rollback or an atomicity guarantee.
No script can prevent a new external mutation after its final successful read,
and `write=true` does not create registry, replica, or CDN atomicity. The
observable guarantee is limited to the response returned by each uniquely
cache-bypassed origin-intent request. The staged and promoted verification
passes therefore issue a new request for complete package metadata after the
slow tarball download, exact install, signature audit, cryptographic check, and
semantic check. Every package reread validates the exact package name on every
version manifest and requires every dist-tag to target a complete present
version before revalidating the phase-specific tags and, for the promoted
phase, the final monotonic state. Release operators must still not publish or
move this package's dist-tags concurrently.

Before publication, the workflow requires:

- exact repository, workflow, protected tag, annotated tag, and commit
  agreement;
- the tagged commit to be contained in `origin/main`;
- a clean checkout and a live matching release-tag ruleset;
- exact pinned Node, npm, and Bun versions;
- package name, version, registry, access, repository, and tag agreement;
- an unpublished immutable version;
- audit, type, compatibility, test, build, contract, conformance, and PostgreSQL
  gates;
- two clean build-and-pack runs with identical file lists, metadata, hashes,
  size, tarball bytes, and bounded archive contents.

Each pack run copies only npm's reviewed package file set to an isolated
temporary package root, injects the exact 40-character release commit as
`gitHead` into that internal `package/package.json`, and packs the isolated
root. The source checkout and its `package.json` are never modified. CI and the
release workflow both pin npm `11.16.0`, and the deterministic-pack verifier
opens each produced tarball and requires that exact embedded `gitHead`.

The second byte-identical verified tarball is preserved in the runner temporary
directory. The workflow publishes that exact file under
`release-candidate-X.Y.Z`; it never asks npm to pack the checkout again.

## Registry and provenance verification

Before the intended dist-tag moves, the workflow requires:

- registry `gitHead`, packed-manifest `gitHead`, size, SHA-1, SHA-512 integrity,
  and downloaded bytes equal the preserved candidate and exact release commit;
- registry and archive file counts and unpacked sizes agree; the archive has at
  most 512 entries, each regular file is at most 16 MiB, total unpacked regular
  files are at most 64 MiB, and all paths remain beneath `package/`;
- only regular files and empty directories are accepted; symlinks, hard links,
  devices, FIFOs, duplicate paths, traversal, absolute paths, malformed
  headers, and gzip/tar expansion beyond the caps fail before installation;
- the version-specific quarantine dist-tag points to the candidate while the
  intended dist-tag does not;
- an exact-version consumer install with install scripts disabled;
- the installed `accounts --version` output equals the candidate version;
- pinned `npm audit signatures --json --include-attestations` succeeds with no
  invalid or missing signatures and returns the exact package's verified
  bundles;
- only after npm's standard Sigstore verification succeeds, the exact verified
  provenance bundle is independently verified by the pinned Sigstore library
  against the checksummed TUF-published trust root, with CT-log and Rekor
  thresholds of one, exact Fulcio URI SAN
  `https://github.com/hasna/accounts/.github/workflows/release.yml@refs/tags/npm/accounts/vX.Y.Z`,
  and exact OIDC issuer `https://token.actions.githubusercontent.com`;
- only after that cryptographic identity check succeeds are the exact DSSE
  statements parsed; each envelope must use the exact payload type
  `application/vnd.in-toto+json`, each decoded statement must use exact
  `_type` `https://in-toto.io/Statement/v1`, and the statements must bind the
  package purl and digest, npm registry publish claim, `hasna/accounts`,
  `release.yml`, release tag, and commit.

Network responses, command runtimes, retry budgets, decoded JSON, compressed
tarball size, individual archive entries, total unpacked bytes, and archive
entry count are capped. Unsigned bundles, another valid Fulcio identity or
issuer, missing or non-positive Rekor `logIndex`/`integratedTime`, wrong
subjects, or any semantic disagreement fail closed.

After those checks, the promotion step moves the intended dist-tag (normally
`latest`) to the exact candidate and verifies that it agrees with the quarantine
tag and remains the unique highest stable registry version. A newer stable
version discovered after mutation is restored as `latest` and the older
candidate run fails as superseded. The final job repeats the registry,
provenance, signature, install, CLI, and dist-tag checks in the promoted state,
then performs a fresh terminal package-metadata read after all slow checks.
That last read is a new uniquely keyed origin-intent request and must still show
exact quarantine and intended-tag agreement and the candidate as the unique
highest stable version before the workflow reports success. This is an
observable last-read check, not a claim that npm's replicas or a later external
writer are serialized with the workflow.

The promotion command can forward-compensate a newer stable version that it
observes in its immediate post-mutation reads because that command has the
scoped dist-tag credential. The later verification command deliberately does
not have that credential. If its terminal read discovers drift, the workflow
fails after promotion without claiming that the earlier mutation was rolled
back. Inspect the complete registry version and dist-tag state, then use a
separate reviewed recovery change either to move `latest` forward to the newest
verified stable version or to restore the previously verified exact version.

## Install and rollback

Rollouts use an exact reviewed version, never an unqualified or quarantine tag:

```sh
npm install --global @hasna/accounts@X.Y.Z
accounts --version
```

For a Bun-managed project, retain the release-age quarantine:

```sh
bun add --exact @hasna/accounts@X.Y.Z --minimum-release-age 604800
```

If verification fails before promotion, leave the immutable version under its
`release-candidate-X.Y.Z` tag and investigate; do not unpublish it. If terminal
verification fails after promotion, first read the complete live version and
dist-tag state: the candidate may already be `latest`, or an external publisher
may have moved it again. Repair that state through a separate reviewed change,
moving forward to the newest verified stable version when appropriate or
restoring the previously verified exact version. For a post-promotion runtime
regression, restore the last verified exact version and reinstall that exact
version in consumers.
