# Releasing HaltSQL

This page is for maintainers. It describes how a release is cut, how to
rehearse one without publishing anything, and what has to be configured in
GitHub, PyPI and npm before the first real tag. Users who want to check a
release should read
[supply-chain.md](../security/supply-chain.md#verifying-a-release).

## Workflows

| Workflow | Builds | Publishes (real mode) |
|---|---|---|
| `.github/workflows/release.yml` | Static Linux tarballs (amd64, arm64), macOS arm64 tarball, `haltsql` and `haltsql-mcp` images (amd64, arm64), Helm chart, CycloneDX SBOM, `SHA256SUMS`, cosign bundles, build-provenance attestations | `ghcr.io/haltsql/haltsql:<version>`, `ghcr.io/haltsql/haltsql-mcp:<version>`, `oci://ghcr.io/haltsql/charts/haltsql`, GitHub release |
| `.github/workflows/native-packages.yml` | Platform wheels, sdists (`haltsql`, `haltsql-mcp`), npm platform packages, `@haltsql/client` | PyPI (`haltsql`, `haltsql-mcp`), npm (`@haltsql/client`, `@haltsql/native-*`) |

Both start on a `v*` tag push. `release.yml` ends with a `verify` job that runs
`scripts/verify-release.sh` against the files it just published, so the
verification commands in the docs are exercised on every run.

## Real and dry-run mode

| Trigger | Mode |
|---|---|
| Push `vX.Y.Z` | Real |
| Push `vX.Y.Z-rc.N` | Dry run |
| Run `release.yml` by hand, `dry_run` ticked (the default) | Dry run; the `tag` input is only a label and needs no git tag |
| Run `release.yml` by hand, `dry_run` unticked | Real rebuild of an existing tag |
| Run `native-packages.yml` by hand, `dry_run` ticked (the default) | Builds and tests, then the publish dry run |

A dry run does everything a real release does except the final publication:

| Step | Real | Dry run |
|---|---|---|
| Images | `ghcr.io/haltsql/<name>:<version>` and `:<major>.<minor>` | `ghcr.io/haltsql/dryrun/<name>:dryrun-<run id>` |
| Helm chart | `oci://ghcr.io/haltsql/charts/haltsql`, version `X.Y.Z` | `oci://ghcr.io/haltsql/dryrun/charts/haltsql`, version `X.Y.Z-rc.N` |
| Cosign signatures, SBOMs, provenance | Yes | Yes, the same steps (entries in the public Sigstore transparency log are made either way) |
| GitHub release | Published (pre-release for `v0.*`) | Draft, titled `DRY RUN` |
| PyPI | `haltsql`, `haltsql-mcp` | `twine check --strict`; TestPyPI upload only if `TESTPYPI_PUBLISH` is set (below) |
| npm | `npm publish --provenance` | `npm publish --dry-run` |

After a dry run, delete the draft release and the rc tag (if you pushed one).
The `dryrun/` packages can be deleted from the organisation's package settings.

## Rehearse a release

```sh
# Version strings agree, and match the tag you are about to push
scripts/check-versions.sh --tag v0.0.1

# Dry run from a branch, no tag needed
gh workflow run release.yml --ref my-branch -f tag=v0.0.1-rc.1 -f dry_run=true
gh workflow run native-packages.yml --ref my-branch -f dry_run=true

# Or as a release candidate, which also signs with the tag identity users verify
git tag -s v0.0.1-rc.1 && git push origin v0.0.1-rc.1

# Verify the draft locally (needs write access to see a draft; private dryrun/
# packages need `docker login ghcr.io` with read:packages)
scripts/verify-release.sh v0.0.1-rc.1
```

A manual run signs with the branch's workflow identity, so verify it with
`--identity https://github.com/HaltSQL/HaltSQL/.github/workflows/release.yml@refs/heads/<branch>`.

## Version numbers

Everything versions in lockstep. `scripts/check-versions.sh` (run by `ci.yml`
on every change and by both release workflows) fails when any of these
differ: `dune-project`, the three `*.opam` files, `lib/haltsql/haltsql.ml`,
`clients/python` (`pyproject.toml`, `_version.py`), `clients/mcp`
(`pyproject.toml`, `__init__.py`), `clients/typescript` (`package.json`, its
lock file, the `@haltsql/native-*` pins, `src/client.ts`),
`clients/go/haltsql/client.go`, `clients/java` (`pom.xml`,
`HaltSQLClient.java`) and `deploy/helm/haltsql/Chart.yaml` (`version`,
`appVersion` and the Artifact Hub image). A release candidate `vX.Y.Z-rc.N` is
checked against `X.Y.Z`.

The Go SDK is a module in a subdirectory, so Go needs its own tag,
`clients/go/haltsql/vX.Y.Z`, on the same commit for `go get ...@vX.Y.Z` to
resolve.

## Before the first real tag

These are not configured yet. Each is a setting only a maintainer can create.

| What | Where | Settings |
|---|---|---|
| PyPI trusted publisher for `haltsql` | pypi.org, "Publishing" (pending publisher, the project does not exist yet) | Owner `HaltSQL`, repository `HaltSQL`, workflow `native-packages.yml`, environment `pypi` |
| PyPI trusted publisher for `haltsql-mcp` | pypi.org, same | Same, but environment `pypi-mcp`. PyPI refuses two pending publishers with the same repository, workflow and environment, so each project has its own environment and publish job |
| `NPM_TOKEN` secret | Repository or `npm` environment secret | An npm automation (or granular) token with publish rights to the `@haltsql` scope; the scope must exist on npm |
| `pypi`, `pypi-mcp` and `npm` environments | Repository settings, Environments | Add required reviewers so a tag alone cannot publish |
| GHCR package visibility | Organisation packages, after the first real run | Make `haltsql`, `haltsql-mcp` and `charts/haltsql` public; new packages are created private |
| Optional: TestPyPI | test.pypi.org trusted publishers for `haltsql` (workflow `native-packages.yml`, environment `testpypi`) and `haltsql-mcp` (environment `testpypi-mcp`), then repository variable `TESTPYPI_PUBLISH=true` | TestPyPI accepts each version once; rc runs re-uploading `X.Y.Z` are skipped |

Not published by any workflow: the Java SDK (Maven Central needs a Sonatype
account, a verified `com.haltsql` namespace and a GPG signing key) and the
Kubernetes operator image.

## Cutting the release

1. Move the `[Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - <date>`;
   the release notes are taken from that section.
2. Run a dry run on the release commit and check `verify` is green.
3. Push the signed tags `vX.Y.Z` and `clients/go/haltsql/vX.Y.Z`.
4. Approve the `pypi`, `pypi-mcp` and `npm` environment deployments.
5. Make new GHCR packages public, then run
   `scripts/verify-release.sh vX.Y.Z` from a clean machine.
