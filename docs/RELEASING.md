# Releasing `@hasna/accounts`

`@hasna/accounts` is released only by `.github/workflows/release.yml`. The
workflow publishes one preserved, deterministic tarball to a version-specific
quarantine dist-tag, verifies that exact registry artifact, and only then moves
the intended dist-tag. A failed candidate remains installable only by exact
version or its quarantine tag; it is never promoted by the failed run.

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
administer that ruleset. The normal workflow token is intentionally read-only,
so the preflight validates the organization-administrator bypass whenever
GitHub exposes it but does not require that privileged field to be present. The
creation restriction proves that a successfully created protected tag used a
configured bypass authority; the release environment then independently
requires the exact live triggering user as its sole reviewer and confirms,
through GitHub's metadata read API, that the user has repository administrator
permission.

### GitHub release environment

Create a protected `npm-release` environment:

- allow deployments only from tags matching `npm/accounts/v*`;
- require exactly one user reviewer matching the release actor;
- allow that reviewer to approve their own deployment;
- store only the `NPM_DIST_TAG_TOKEN` secret described below.

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
- the frozen Bun lockfile and seven-day minimum release age.

The release preflight checks the observed tool versions exactly. Updating any
pin requires a reviewed PR and refreshed compatibility evidence.

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
  size, and tarball bytes.

The second verified tarball is preserved in the runner temporary directory.
The workflow publishes that exact file under
`release-candidate-X.Y.Z`; it never asks npm to pack the checkout again.

## Registry and provenance verification

Before the intended dist-tag moves, the workflow requires:

- registry `gitHead`, size, SHA-1, SHA-512 integrity, and downloaded bytes equal
  the preserved candidate;
- the version-specific quarantine dist-tag points to the candidate while the
  intended dist-tag does not;
- an exact-version consumer install with install scripts disabled;
- the installed `accounts --version` output equals the candidate version;
- pinned `npm audit signatures --json --include-attestations` succeeds with no
  invalid or missing signatures and returns the exact package's verified
  bundles;
- only after npm's standard Sigstore verification succeeds, the exact verified
  DSSE statements are parsed and required to bind the package purl and digest,
  npm registry publish claim, `hasna/accounts`, `release.yml`, release tag, and
  commit.

Network responses, command runtimes, retry budgets, decoded JSON, and tarball
sizes are capped. Unsigned bundles, missing transparency-log evidence, wrong
subjects, or any semantic disagreement fail closed.

After those checks, the promotion step moves the intended dist-tag (normally
`latest`) to the exact candidate and verifies that it agrees with the quarantine
tag. The final job repeats the registry, provenance, signature, install, CLI,
and dist-tag checks in the promoted state.

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
`release-candidate-X.Y.Z` tag and investigate; do not unpublish it. If a
post-promotion runtime regression is discovered, move the intended dist-tag
back to the last verified exact version through a separate reviewed recovery
change, then reinstall that exact version in consumers.
