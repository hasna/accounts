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
missing. Store a fine-grained token named `RELEASE_GITHUB_ADMIN_TOKEN` in the
protected environment with only repository Metadata read and Administration
read access for `hasna/accounts`. Do not grant Contents write, Actions write, or
any organization-wide mutation permission. The token must belong to the same
user who triggered the release. The preflight uses it only to read the live
ruleset, requires the visible bypass list to contain exactly one
`OrganizationAdmin` entry in `always` mode, and verifies that its owner and the
release actor are the same live repository administrator.

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
- store only `RELEASE_GITHUB_ADMIN_TOKEN` and the `NPM_DIST_TAG_TOKEN` described
  below.

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
`prepublishOnly` script rejects direct publication; it is defense in depth, not
a substitute for npm access policy because any caller can pass
`--ignore-scripts`.

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

## Pinned release substrate

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
   locally and do not move any dist-tag manually while it is running.

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
