# Supply chain and release verification

This page describes how HaltSQL releases are built and published, and how to
verify an artifact before you run it. It is for security reviewers and
platform teams who need to check signatures, provenance and SBOMs, or answer
supply-chain questions about HaltSQL. Everything here is taken from the
workflows in `.github/workflows/`, the `Dockerfile` and
`.github/dependabot.yml`.

## What a release contains

A release is triggered by pushing a `vX.Y.Z` tag (or by running the release
workflow by hand for an existing tag). Release-candidate tags (`vX.Y.Z-rc.N`)
and manual runs with `dry_run` are rehearsals: they run every build, signing
and provenance step but publish only a draft release and packages under
`ghcr.io/haltsql/dryrun/`; see
[releasing.md](../operations/releasing.md#real-and-dry-run-mode).
`.github/workflows/release.yml` produces:

| Artifact | Where | Built by |
|---|---|---|
| `haltsql-<tag>-linux-amd64.tar.gz`, `haltsql-<tag>-linux-arm64.tar.gz` | GitHub release | The `dist` stage of the `Dockerfile`: static musl binaries `haltsql`, `haltsql-server`, `haltsql-proxy`, plus licences |
| `haltsql-<tag>-darwin-arm64.tar.gz` | GitHub release | A `macos-15` runner with `ocaml/setup-ocaml`; links only system libraries |
| `haltsql-<tag>.cdx.json` | GitHub release | CycloneDX SBOM (see [SBOMs](#sboms)) |
| `haltsql-<version>.tgz` | GitHub release | The Helm chart archive (`helm package deploy/helm/haltsql`) |
| `haltsql-<tag>.oci.txt` | GitHub release | The digests of the three images and the chart as pushed to GHCR |
| `SHA256SUMS` | GitHub release | SHA-256 of every tarball, the chart archive, the SBOM and `haltsql-<tag>.oci.txt` |
| `*.sigstore.json` | GitHub release | Keyless cosign signature bundle for every file above and `SHA256SUMS` |
| `ghcr.io/haltsql/haltsql:<version>` | GHCR | The `runtime` stage of the `Dockerfile`, `linux/amd64` and `linux/arm64` |
| `ghcr.io/haltsql/haltsql-mcp:<version>` | GHCR | `clients/mcp/Dockerfile`, on top of the `haltsql` image by digest |
| `ghcr.io/haltsql/haltsql-console:<version>` | GHCR | The `console` stage of the `Dockerfile`, `linux/amd64` and `linux/arm64` |
| `oci://ghcr.io/haltsql/charts/haltsql`, version `<version>` | GHCR | The same chart archive, pushed with `helm push` |

`.github/workflows/native-packages.yml` publishes, on `v*` tags:

| Artifact | Where | Notes |
|---|---|---|
| `haltsql` wheels and sdist, `haltsql-mcp` and the eight `haltsql-<framework>` integrations (wheel and sdist each) | PyPI | Trusted publishing (OIDC, no long-lived PyPI token), through the `pypi` and `pypi-mcp` environments and one `pypi-<framework>` environment per integration |
| `@haltsql/client` and `@haltsql/native-<platform>` | npm | Published with `npm publish --provenance`, through the `npm` environment, by npm trusted publishing (OIDC); the first publish only uses a short-lived `NPM_TOKEN` |

Not published by these workflows: the Kubernetes operator image (you build it from
`deploy/operator`, see [kubernetes-operator.md](../kubernetes-operator.md)),
the Java SDK and the Go SDK (Go modules are fetched from the repository).

## Build integrity

| Control | What exists | Source |
|---|---|---|
| Pinned GitHub Actions | Every third-party action in every workflow is pinned to a full commit SHA, with the version in a comment | `.github/workflows/*.yml` |
| Pinned base images | Builder (`ocaml/opam:alpine-3.22-ocaml-5.3`) and runtime (`gcr.io/distroless/static-debian12:nonroot`) pinned by digest; the Dockerfile syntax image too | `Dockerfile` |
| Pinned OCaml dependencies | The Linux release build resolves opam packages against a fixed opam-repository commit (`OPAM_REPOSITORY_COMMIT`), so tarballs and image ship the same dependency versions. The resolved list is written to `/usr/share/doc/haltsql/opam-packages.txt` in the image. | `Dockerfile` |
| Vendored parser | `libpg_query` is vendored in `vendor/libpg_query` and compiled from source | `Dockerfile`, `vendor/` |
| Static linking check | The build fails unless every binary is statically linked, runs, and runs on an empty (`scratch`) filesystem | `Dockerfile`, `release.yml` |
| Smoke test before push | Each architecture's image is built on a native runner (amd64 and arm64, no emulation), run against PostgreSQL 17 by `scripts/docker-smoke.sh` (including the proxy), and only then pushed by digest and merged into the multi-arch index | `release.yml` |
| Least-privilege workflow tokens | Workflows default to `permissions: contents: read`; jobs that publish add only `packages: write`, `id-token: write`, `attestations: write` or `contents: write` as needed | `.github/workflows/*.yml` |
| No persisted checkout credentials | `actions/checkout` runs with `persist-credentials: false` | `.github/workflows/*.yml` |
| Workflow linting | `actionlint`, from a digest-pinned image, on every PR | `security.yml` |

Known gaps:

- The **macOS release tarball**, the **macOS wheel and npm package**, and the
  **Linux `libhaltsql.so`** in the wheels and npm packages are built with
  `opam install --deps-only` against the current opam-repository, not the
  pinned commit. Their OCaml dependency versions can differ from the Linux
  tarballs and the image.
- The `manylinux_2_28` build container used for `libhaltsql.so` is referenced
  by tag, not digest.
- Builds are not documented or tested as bit-for-bit reproducible.
- The macOS binaries are not signed with an Apple Developer ID or notarized.
  (The `libhaltsql` dylib in the macOS wheel has an ad-hoc signature only.)

## Signatures and provenance

| Artifact | Signature | Provenance |
|---|---|---|
| Release tarballs | Keyless cosign (`cosign sign-blob --bundle`) | GitHub build-provenance attestation (`actions/attest-build-provenance`) |
| Helm chart archive | Keyless cosign (`cosign sign-blob --bundle`) | GitHub build-provenance attestation |
| `SHA256SUMS`, SBOM, `haltsql-<tag>.oci.txt` | Keyless cosign | None |
| Helm chart in GHCR | Keyless cosign on the chart's OCI digest, verified in the same job | GitHub build-provenance attestation pushed to the registry |
| `haltsql`, `haltsql-mcp` and `haltsql-console` images | Keyless cosign on the image digest, verified in the same job | BuildKit SLSA provenance (`provenance: mode=max`) attached to the image index, plus a GitHub build-provenance attestation pushed to the registry |
| PyPI files | Trusted publishing through `pypa/gh-action-pypi-publish` | See the PyPI file page |
| npm packages | npm registry signatures | npm provenance (`--provenance`) |

Keyless signatures are issued by Sigstore to the identity of the GitHub
Actions workflow that ran, so there is no long-lived signing key to protect or
leak. The certificate identity is the workflow file and ref, for example
`https://github.com/HaltSQL/HaltSQL/.github/workflows/release.yml@refs/tags/v0.0.3`,
and the OIDC issuer is `https://token.actions.githubusercontent.com`.

> **Note:** a release rebuilt by hand (`workflow_dispatch`) runs from the
> branch the workflow was dispatched on, so its certificate identity ends in
> `@refs/heads/<branch>` instead of `@refs/tags/<tag>`. The commands below
> accept only tag identities. If one fails for this reason, check with the
> maintainers before relaxing the identity.

## SBOMs

| SBOM | Format | Produced by | Covers |
|---|---|---|---|
| `haltsql-<tag>.cdx.json` (release asset) | CycloneDX JSON | `anchore/sbom-action` (Syft), run on the **source tree** (`path: .`) | The dependency manifests Syft finds in the repository |
| Image SBOM attestation | SPDX (BuildKit default) | `docker/build-push-action` with `sbom: true` | The contents of the built image |

> **Warning:** the release binaries are static OCaml executables. Neither
> SBOM is guaranteed to list every OCaml library linked into them, and the
> source-tree SBOM also includes manifests from parts of the repository that
> are not in the binaries (SDKs, the docs site, the lab). For the exact OCaml
> packages in the image and Linux tarballs, use
> `/usr/share/doc/haltsql/opam-packages.txt` from the image. That file is not
> included in the tarballs.

There are no VEX documents.

## Scanning and dependency updates

| Control | What runs | When |
|---|---|---|
| Container image scan | Trivy (digest-pinned) on the built image, `HIGH` and `CRITICAL`, unfixed ignored; fails the job on findings; SARIF uploaded to GitHub code scanning | Weekly (Mondays) and on demand; not on pull requests |
| Configuration and secret scan | Trivy `fs --scanners misconfig,secret` on the repository, `MEDIUM` and above, SARIF uploaded | Weekly and on demand |
| Dependency review | `actions/dependency-review-action`, fails on `high` severity; denies AGPL and SSPL licences | Every pull request (public repository only) |
| Static analysis of OCaml code | None. CodeQL does not support OCaml. | |
| Dependabot | Weekly, with a 7-day cooldown on new releases: GitHub Actions, the root `Dockerfile` base images, npm (`clients/typescript`, `website`), pip (`clients/python`, `clients/mcp`, `lab`), Go modules (`clients/go/...`), Maven (`clients/java`) | `.github/dependabot.yml` |

Dependabot does not support opam. OCaml dependencies move only when the
`OPAM_REPOSITORY_COMMIT` in the `Dockerfile` is bumped by hand. Dependabot is
not configured for `deploy/operator` (Go) or for `clients/mcp/Dockerfile` and
`deploy/operator/Dockerfile` base images.

Vulnerability reports go through GitHub Security Advisories
([SECURITY.md](../../SECURITY.md)). Only the latest release receives security
fixes while HaltSQL is pre-1.0.

## Verifying a release

You need [cosign](https://github.com/sigstore/cosign) v2.4 or later (v3 works
too), the [GitHub CLI](https://cli.github.com/) 2.49 or later, and `jq`.
Replace `v0.0.3` with the release you are checking.

`scripts/verify-release.sh v0.0.3` runs every command below (and checks that
every asset is present, listed in `SHA256SUMS` and signed) against a
downloaded release; the release workflow runs it on every release before
anyone else can. The steps by hand:

### Release tarballs

```sh
TAG=v0.0.3
gh release download "$TAG" --repo HaltSQL/HaltSQL --dir "haltsql-$TAG"
cd "haltsql-$TAG"

ID='^https://github.com/HaltSQL/HaltSQL/\.github/workflows/release\.yml@refs/tags/v'
ISSUER=https://token.actions.githubusercontent.com

# 1. The checksum file was signed by the release workflow
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" \
  SHA256SUMS

# 2. Every downloaded file matches it
sha256sum -c SHA256SUMS --ignore-missing      # macOS: shasum -a 256 -c SHA256SUMS

# 3. A tarball's own signature
cosign verify-blob --bundle "haltsql-$TAG-linux-amd64.tar.gz.sigstore.json" \
  --certificate-identity-regexp "$ID" --certificate-oidc-issuer "$ISSUER" \
  "haltsql-$TAG-linux-amd64.tar.gz"

# 4. Build provenance: built by this repository's workflow from this commit
gh attestation verify "haltsql-$TAG-linux-amd64.tar.gz" --repo HaltSQL/HaltSQL
```

### Container images

```sh
IMAGE=ghcr.io/haltsql/haltsql:0.0.3
ID='^https://github.com/HaltSQL/HaltSQL/\.github/workflows/release\.yml@refs/tags/v'

# Signature
cosign verify "$IMAGE" \
  --certificate-identity-regexp "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# GitHub build-provenance attestation
gh attestation verify "oci://$IMAGE" --repo HaltSQL/HaltSQL

# BuildKit SBOM and SLSA provenance attached to the image index
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}'
docker buildx imagetools inspect "$IMAGE" --format '{{ json .Provenance }}'
```

Deploy by digest (`ghcr.io/haltsql/haltsql@sha256:...`), not by tag; the
release notes print the digest, and `haltsql-<tag>.oci.txt` (covered by the
signed `SHA256SUMS`) lists the digest of each image and the chart. The same commands work for
`ghcr.io/haltsql/haltsql-mcp`. To enforce signatures at admission time, use
Sigstore policy-controller or Kyverno with the identity and issuer above.

### Helm chart

```sh
CHART=ghcr.io/haltsql/charts/haltsql
DIGEST=$(awk '$1 == "helm-chart" {sub(/.*@/, "", $2); print $2}' haltsql-$TAG.oci.txt)

cosign verify "$CHART@$DIGEST" \
  --certificate-identity-regexp "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$CHART@$DIGEST" --repo HaltSQL/HaltSQL

helm install haltsql "oci://$CHART" --version "${TAG#v}"   # or pull the verified release asset
```

The chart's content layer in the registry is byte-for-byte the
`haltsql-<version>.tgz` release asset, so the asset's signature and
attestation cover the registry copy too.

### npm packages

```sh
npm install @haltsql/client
npm audit signatures      # checks registry signatures and provenance attestations
```

### Python packages

`haltsql`, `haltsql-mcp` and the `haltsql-<framework>` integration packages
are uploaded by trusted publishing from `.github/workflows/native-packages.yml`,
with PyPI attestations. Check the file's provenance on its
PyPI page, and pin hashes in production (`pip install --require-hashes -r
requirements.txt`).

## Policy bundles are a separate chain

The signatures above cover HaltSQL itself. Your policies have their own
supply chain: signed with your Ed25519 key in your CI, and verified by every
server before any policy is read. See
[policy-bundles.md](../policy-bundles.md) and [policy-ci.md](../policy-ci.md).

## Related

- [deployment.md](../deployment.md#verifying-release-artifacts)
- [overview.md](overview.md)
- [hardening.md](hardening.md)
- [security-questionnaire.md](security-questionnaire.md)
- [SECURITY.md](../../SECURITY.md)
- [policy-bundles.md](../policy-bundles.md)
