#!/usr/bin/env bash
# Decides which CI areas a change touches, so ci.yml and integration.yml run only
# the jobs that can be affected. Writes one `<area>=true|false` line per area to
# $GITHUB_OUTPUT (or stdout when run locally).
#
# Usage: changes.sh [BASE [HEAD]]
#   With no BASE (push to main, schedule, workflow_dispatch) every area is true.
#   On a pull_request, the workflow checks out the merge commit with
#   fetch-depth: 2 and passes HEAD^1 (the base tip) as BASE.
#   With NIGHTLY=1 (scheduled runs): if the checked-out commit is older than
#   26 hours, every area is false and `idle=true` is written as well.
#
# When in doubt, an area is true: a path that matches no rule below marks
# nothing, but anything under the OCaml tree, the build files or the CI
# definitions themselves marks every area that depends on it.
#
# Areas inside the OCaml tree (each also marks `ocaml`). They exist so that a
# pull request pays for the expensive jobs only when it can affect them; pushes
# to main and the nightly run everything.
#   native    C stubs, the vendored parser, the C API and the build files:
#             the only changes that can behave differently on macOS.
#   services  the server, the proxy and the libraries that talk to outside
#             services (IdP, Kafka, Elasticsearch, object stores, registries,
#             OPA, OTLP): what the Docker-based suites of integration.yml test.
#   e2e       `services`, plus the end-to-end suite itself and the Python
#             clients it drives.

set -euo pipefail

areas=(ocaml native services e2e python typescript go java action helm operator terraform)
# Plain variables (hit_<area>) rather than an associative array, so the script
# also runs under macOS's bash 3.2.
mark() { for a in "$@"; do printf -v "hit_$a" true; done; }
for a in "${areas[@]}"; do printf -v "hit_$a" false; done
all() { mark "${areas[@]}"; }

# A nightly run on a branch that has not changed since the previous night would
# repeat that night's results: mark nothing and report idle=true instead.
idle=false
if [ "${NIGHTLY:-}" = "1" ]; then
  age=$(( $(date +%s) - $(git log -1 --format=%ct) ))
  if [ "$age" -gt $(( 26 * 3600 )) ]; then idle=true; fi
fi

if [ "$idle" = true ]; then
  :
elif [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
  all
else
  base="$1"
  head="${2:-HEAD}"
  while IFS= read -r f; do
    case "$f" in
      # Tooling that no CI job runs or reads.
      test/mutation/*) continue ;;
    esac
    case "$f" in
      # The CI definitions themselves: run everything.
      .github/workflows/ci.yml | .github/workflows/integration.yml | .github/scripts/changes.sh \
      | .github/actions/haltsql-binaries/*)
        all ;;

      # The OCaml tree and everything its tests read (test/*/dune files point
      # into examples/ and lab/). Every job that builds a haltsql binary
      # depends on this area; see the `needs.changes.outputs.*` conditions.
      test/e2e/*) ;; # the Docker Compose suite: area `e2e` below, no OCaml job
      lib/* | bin/* | vendor/* | test/* | examples/* | schemas/* | lab/* \
      | dune-project | dune | */dune | *.opam | .ocamlformat | Makefile)
        mark ocaml ;;
      # Console deployment files that test/console/test_deploy.ml checks.
      deploy/console/* | deploy/helm/* | deploy/cloud/* \
      | deploy/terraform/examples/console-kubernetes/* | docs/console/deploy.md \
      | .github/workflows/release.yml | scripts/console-docker-smoke.sh)
        mark ocaml ;;
    esac
    case "$f" in
      lib/pgquery/* | vendor/* | native/* | dune-project | dune | */dune | *.opam)
        mark native ;;
    esac
    case "$f" in
      bin/server/* | bin/proxy/* | lib/pgwire/* | lib/scram/* | lib/auth/* | lib/siem/* \
      | lib/opa/* | lib/cloud/* | lib/bundle/* | lib/bundle_source/* | lib/telemetry/* \
      | lib/report/* | lib/load/* | test/siem/* | test/opa/* | test/wiring/* | test/auth/* \
      | test/bundle_source/* | test/bundle/* | test/audit/* | test/proxy/* | test/report/* \
      | dune-project | *.opam)
        mark services e2e ;;
      test/e2e/* | clients/python/* | clients/mcp/* | Makefile)
        mark e2e ;;
    esac
    case "$f" in
      clients/python/* | clients/mcp/* | integrations/*) mark python ;;
      clients/typescript/*) mark typescript ;;
      clients/go/*) mark go ;;
      clients/java/*) mark java ;;
      clients/testvectors/*) mark python typescript go java ;;
      action.yml | .github/actions/* | ci/* | examples/*) mark action ;;
      deploy/helm/* | deploy/cloud/* | deploy/k8s/*) mark helm ;;
      deploy/operator/*) mark operator ;;
      deploy/terraform/*) mark terraform ;;
    esac
  done < <(git diff --name-only "$base" "$head")
fi

out="${GITHUB_OUTPUT:-/dev/stdout}"
for a in "${areas[@]}"; do v="hit_$a"; echo "$a=${!v}" >> "$out"; done
echo "idle=$idle" >> "$out"
