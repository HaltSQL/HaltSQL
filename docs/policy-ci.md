# Policy CI

Treat HaltSQL policies like code. Every change is validated, linted and tested
against policy test suites before it merges. The main branch then produces a
[signed bundle](policy-bundles.md) that servers load.

HaltSQL ships three integrations:

| Integration | File | For |
|---|---|---|
| GitHub Action | [`action.yml`](../action.yml) | GitHub Actions workflows |
| GitLab CI templates | [`ci/gitlab/haltsql.gitlab-ci.yml`](../ci/gitlab/haltsql.gitlab-ci.yml) | GitLab pipelines (`include:` + `extends:`) |
| pre-commit hooks | [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) | Local checks before each commit |

All three run the same CLI commands: `haltsql validate`, `haltsql lint-policy`,
`haltsql test --json` and, optionally, `haltsql bundle build/sign`. A
pipeline always agrees with what you see locally.

Ready-made examples are in [`examples/ci/`](../examples/ci/).

## GitHub Action

```yaml
# .github/workflows/policy-ci.yml
on: [pull_request]
permissions:
  contents: read
  pull-requests: write          # only for comment-summary
jobs:
  policies:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: ardada2468/HaltSQL@v0.2.0
        with:
          version: v0.2.0
          policies: policies/**/*.yaml
          suites: tests
          fail-on-warnings: "true"
          comment-summary: "true"
```

### What it does

1. **Installs haltsql.** It downloads the release archive for the runner
   (`linux-amd64`, `linux-arm64` or `darwin-arm64`) and **verifies it against
   the release's `SHA256SUMS`**. The archive must be listed exactly once and
   its checksum must match. A mismatch fails the job and never falls back to
   another source. With `verify-signature: true` (and cosign on `PATH`), it
   also verifies `SHA256SUMS` with cosign keyless signatures. On other
   platforms, or if the download itself fails, it falls back to the container
   image `ghcr.io/ardada2468/haltsql:<version>`, which needs Docker. The tag is
   resolved to a digest once, and the image is always run by that digest.
   With `verify-signature: true`, a failed download is fatal (there is no
   container fallback), and a container image (`install-method: docker` or an
   unsupported platform) is used only after `cosign verify` of its digest
   passes with the same identity constraints as the release.
2. **Validates** every policy and suite file (`haltsql validate --json`).
3. **Lints** every policy (`haltsql lint-policy --json`).
4. **Tests** the suites (`haltsql test --json`).
5. **Writes a job summary** (`$GITHUB_STEP_SUMMARY`) with these sections:
   - a check overview;
   - per-suite pass/fail counts;
   - failed cases with their reason codes;
   - a collapsible table of **denied cases** per suite, showing whether the
     denial was expected, the reason codes and the first reason message;
   - validation errors and lint warnings.

   With `comment-summary: true` on pull requests, the same Markdown is posted
   as one PR comment that is updated in place. With a read-only token (for
   example on fork PRs) this only produces a warning.
6. **Optionally builds a bundle** (`bundle: true`). It runs only after all the
   checks pass. The bundle is signed when `signing-key` is set, verified
   against `public-keys` when given, and uploaded as the
   `haltsql-policy-bundle` artifact.

All case names and messages are HTML-escaped in the summary, so a crafted test
name in a pull request cannot inject Markdown or HTML. Inputs reach the scripts
only as environment variables, never interpolated into shell code.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `version` | `latest` | Release to install (`latest`, `v0.2.0` or `0.2.0`). Pin it. |
| `policies` | `policies` | Policy files, directories or globs, whitespace or newline separated. `**` matches any depth, including none. Directories are searched for `*.yaml`, `*.yml` and `*.json`. |
| `suites` | (none) | Test-suite files, directories or globs. Directories are searched for `*.suite.yaml`, `*.suite.yml` and `*.suite.json`. |
| `fail-on-warnings` | `false` | Fail when `lint-policy` reports warnings. |
| `comment-summary` | `false` | Post or update a PR comment with the summary. |
| `max-denied` | `50` | Denied cases listed per suite in the summary. |
| `working-directory` | `.` | Base directory for the globs. |
| `install-method` | `auto` | `auto`, `release` (never use the container) or `docker`. |
| `verify-signature` | `false` | Also verify the release (or the container image) with cosign. Disables the container fallback after a download failure. |
| `haltsql-path` | (none) | Use an existing binary and skip the install. |
| `bundle` | `false` | Build a bundle from `policies` after the checks pass. |
| `bundle-name` | repository name | Bundle `metadata.name`. |
| `bundle-version` | first 12 characters of the commit SHA | Bundle `metadata.version`. |
| `catalogs` | (none) | Catalog snapshots to ship (`[NAME=]FILE`, whitespace separated). |
| `signing-key` | (none) | PEM Ed25519 private key; pass `${{ secrets.HALTSQL_SIGNING_KEY }}`. |
| `public-keys` | (none) | Public keys the signed bundle must verify against. |
| `upload-bundle` | `true` | Upload the bundle and signature as a workflow artifact. |
| `github-token` | `${{ github.token }}` | Used for the PR comment and for resolving `latest`. |

### Outputs

`result` (`pass` or `fail`), `passed`, `failed`, `warnings`, `summary-file`,
`haltsql-path`, `bundle-path`, `signature-path`.

### Signing in CI safely

Put `HALTSQL_SIGNING_KEY` in a protected **environment** that requires
reviewers, and run the bundle job only on the default branch (see
`examples/ci/github-policy-ci.yml`). The key reaches haltsql through an
environment variable (`--key-env`), is never written to disk, and is never
printed.

## GitLab CI

```yaml
# .gitlab-ci.yml
include:
  - remote: https://raw.githubusercontent.com/ardada2468/HaltSQL/v0.2.0/ci/gitlab/haltsql.gitlab-ci.yml

variables:
  HALTSQL_VERSION: v0.2.0
  HALTSQL_POLICIES: policies
  HALTSQL_SUITES: tests

policy-check:
  extends: .haltsql-check

policy-bundle:
  extends: .haltsql-bundle
  needs: [policy-check]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

The template only defines hidden jobs, so including it adds no jobs until you
extend them.

- `.haltsql-base`: an `alpine` image that installs the static Linux release
  binary after checking it against `SHA256SUMS`, with the same fail-closed
  rules as the action. `HALTSQL_RELEASE_BASE_URL` points it at an https
  mirror.
- `.haltsql-check`: runs validate, lint (with `HALTSQL_FAIL_ON_WARNINGS`) and
  test. It writes `haltsql-ci/test.json` and a **JUnit report**
  (`haltsql-ci/junit.xml`), so merge requests show per-case results. Denied
  cases list their reason codes in the JUnit system-out.
- `.haltsql-bundle`: builds the bundle with the project URL and commit as its
  source. It signs the bundle when the masked, protected variable
  `HALTSQL_SIGNING_KEY` is set and verifies it against `HALTSQL_PUBLIC_KEYS`.
  The bundle is kept as a job artifact.

Pin the `include:` to a release tag, never a branch.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ardada2468/HaltSQL
    rev: v0.2.0
    hooks:
      - id: haltsql-validate
      - id: haltsql-lint-policy
      - id: haltsql-test
        args: [tests]
```

The hooks use the `haltsql` binary on `PATH` (`language: system`):

| Hook | Runs | Files |
|---|---|---|
| `haltsql-validate` | `haltsql validate FILE...` | YAML/JSON under `policies/`, `policy/`, `haltsql/`, `tests/`, `suites/`, `catalog(s)/` |
| `haltsql-lint-policy` | `haltsql lint-policy` per changed policy | YAML/JSON under `policies/` or `policy/`, excluding suites |
| `haltsql-test` | `haltsql test tests` (once, not per file) | runs when any of those files change |

If your layout differs, override `files:` or `args:`.

## Testing the integrations

The action's shell steps and the GitLab job scripts are tested locally against
a locally built binary. The tests make no network calls.

```sh
dune build ./bin/haltsql/main.exe
test/bundle/action/test_action.sh _build/default/bin/haltsql/main.exe
PYTHON=python3 test/bundle/action/test_gitlab.sh _build/default/bin/haltsql/main.exe   # needs PyYAML
shellcheck -x .github/actions/policy-ci/*.sh test/bundle/action/*.sh
```

These tests cover glob expansion (including `**`), checksum verification
(match, mismatch, unlisted, duplicated), install argument validation, the
summary Markdown (exact rows, escaping, denied-case details, truncation), exit
codes, fail-on-warnings, the GitHub outputs, bundle build/sign/verify with
provenance, that no key is ever logged, and JUnit well-formedness and
escaping.
