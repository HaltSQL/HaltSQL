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
| Run `release.yml` by hand, `dry_run` ticked (the default) | Dry run; the `tag` input is only a label and needs no git tag. Without a matching tag there is no draft release (the workflow token cannot create a tag on a commit that changes workflows); the assets are in the run's `release-assets` artifact |
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
scripts/check-versions.sh --tag v0.0.3

# Dry run from a branch, no tag needed
gh workflow run release.yml --ref my-branch -f tag=v0.0.3-rc.1 -f dry_run=true
gh workflow run native-packages.yml --ref my-branch -f dry_run=true

# Or as a release candidate, which also signs with the tag identity users verify
git tag -s v0.0.3-rc.1 && git push origin v0.0.3-rc.1

# Verify the draft locally (needs write access to see a draft; private dryrun/
# packages need `docker login ghcr.io` with read:packages)
scripts/verify-release.sh v0.0.3-rc.1
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

## Publishing setup

Settings only a maintainer can create, and their state. Each environment named
here also has required reviewers, so a pushed tag waits for an approval before
anything reaches PyPI or npm; GitHub lists every waiting environment in one
"Review deployments" dialog.

| What | Where | Settings | State |
|---|---|---|---|
| PyPI trusted publisher for `haltsql` | pypi.org, project `haltsql`, Publishing | Owner `HaltSQL`, repository `HaltSQL`, workflow `native-packages.yml`, environment `pypi` | Done (0.0.1). The environment must be set: a publisher without one matches every environment and catches the uploads of the other projects |
| PyPI trusted publisher for `haltsql-mcp` | pypi.org | Same, environment `pypi-mcp` | Done (0.0.1) |
| PyPI trusted publishers for the eight integrations | pypi.org, Publishing, pending publishers | Same owner, repository and workflow; project `haltsql-<slug>`, environment `pypi-<slug>`, for the slugs `crewai`, `google-adk`, `langchain`, `langgraph`, `llamaindex`, `openai-agents`, `semantic-kernel`, `vanna`. PyPI refuses two pending publishers with the same repository, workflow and environment, so each project has its own environment | Needed before the first release that publishes them (0.0.3) |
| npm org `haltsql` | npmjs.com | Free plan; owns the `@haltsql` scope | Done |
| `NPM_TOKEN` | `npm` environment secret | Granular token, **Read and write** (not stage-only) on `@haltsql`, read and write on the `haltsql` organization, 2FA bypass, shortest expiry. A stage-only token makes npm hold the upload instead of publishing it | In use until trusted publishing is set up |
| npm trusted publishers | npmjs.com, each package's Settings, for `@haltsql/client` and the three `@haltsql/native-*` | Owner `HaltSQL`, repository `HaltSQL`, workflow `native-packages.yml`, environment `npm`; then delete `NPM_TOKEN` and revoke the token. Only possible once a package exists | To do |
| Environments with required reviewers | Repository settings, Environments | `pypi`, `pypi-mcp`, `npm`, and `pypi-<slug>` for each integration | `pypi`, `pypi-mcp`, `npm` done |
| GHCR package visibility | Organisation packages | `haltsql`, `haltsql-mcp` and `charts/haltsql` public; new packages are created private | Done |
| Optional: TestPyPI | test.pypi.org trusted publishers for `haltsql` (environment `testpypi`) and `haltsql-mcp` (environment `testpypi-mcp`), then repository variable `TESTPYPI_PUBLISH=true` | TestPyPI accepts each version once; rc runs re-uploading `X.Y.Z` are skipped | Publishers registered; variable not set |

Not published by any workflow: the Java SDK (Maven Central needs a Sonatype
account, a verified `com.haltsql` namespace and a GPG signing key) and the
Kubernetes operator image.

## Cutting the release

1. Move the `[Unreleased]` notes in `CHANGELOG.md` under `## [X.Y.Z] - <date>`;
   the release notes are taken from that section.
2. Run a dry run on the release commit and check `verify` is green.
3. Push the signed tags `vX.Y.Z` and `clients/go/haltsql/vX.Y.Z`.
4. Approve the `pypi`, `pypi-mcp`, `pypi-<slug>` and `npm` deployments
   (one "Review deployments" dialog per wait).
5. Run `scripts/verify-release.sh vX.Y.Z` from a clean machine.
