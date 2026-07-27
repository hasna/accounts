# Releasing `@hasna/accounts`

`@hasna/accounts` is published only by the GitHub-hosted workflow in
`.github/workflows/release.yml`. Local/manual publishing and long-lived npm
write tokens are fail-closed.

## One-time npm configuration

Configure the npm package trusted publisher with these exact values:

- provider: GitHub Actions
- organization: `hasna`
- repository: `accounts`
- workflow filename: `release.yml`
- allowed action: `npm publish`

The workflow deliberately has no token fallback. A missing or mismatched npm
trusted-publisher configuration causes publication to fail.

After the trusted publisher is verified, restrict traditional token publishing
for this package and remove unused write tokens. Repository lifecycle gates
cannot stop a token holder from deliberately publishing with
`--ignore-scripts`.

Protect release tags so only reviewed release owners can create them.

## Release procedure

1. Land a separate release PR that changes only the version, changelog, and
   release-specific metadata. Wait for exact-head CI and review.
2. From the reviewed commit on `main`, create an annotated tag whose name is
   derived from the package version:

   ```sh
   git tag -a npm/accounts/vX.Y.Z COMMIT_SHA -m "Release @hasna/accounts X.Y.Z"
   git push origin npm/accounts/vX.Y.Z
   ```

3. The tag push runs the release workflow. Do not run `npm publish` locally.

Before publishing, the workflow requires all of the following:

- a GitHub-hosted runner with OIDC and no npm write token;
- npm 11.5.1 or newer;
- the exact `npm/accounts/vX.Y.Z` annotated tag at `GITHUB_SHA`;
- the tag commit present on `origin/main` and a clean checkout;
- package name, version, public registry/access, and repository agreement;
- a version that does not already exist in the registry;
- the frozen Bun lockfile with the seven-day release-age quarantine;
- audit, type, compatibility, test, build, contract, conformance, and PostgreSQL
  gates;
- two independent clean build-and-pack runs with identical file lists,
  shasum, integrity, and tarball bytes.

Publication invokes `npm publish --provenance --access public` from the tagged
repository checkout. The `prepublishOnly` gate rejects every other context.
Real provenance is created only by the trusted publish; a pull request or local
pack is not an attestation.

After publication, the same workflow fails unless the registry record has:

- `gitHead` equal to the tagged commit;
- shasum, integrity, and downloaded tarball bytes equal to the reviewed pack;
- both npm publish and SLSA v1 provenance attestations bound to the exact
  package digest;
- provenance bound to `hasna/accounts`, `release.yml`, the exact release tag,
  and the exact commit;
- a successful exact-version consumer install and `npm audit signatures`
  verification of both attestations.

## Install and rollback

Install a reviewed version exactly; never use an unqualified or `latest`
install during rollout:

```sh
npm install --global @hasna/accounts@X.Y.Z
accounts --version
```

For a Bun-managed project, preserve the quarantine and exact pin:

```sh
bun add --exact @hasna/accounts@X.Y.Z --minimum-release-age 604800
```

Roll back by reinstalling the last verified exact version, for example:

```sh
npm install --global @hasna/accounts@0.2.12
accounts --version
```

Stop rollout on any provenance, integrity, exact-install, signature, auth,
profile, or session regression. Do not unpublish or delete uncertain registry
artifacts; quarantine the version and move the dist-tag only through a separate
reviewed recovery action.
