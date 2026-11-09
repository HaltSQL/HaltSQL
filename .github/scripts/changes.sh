#!/usr/bin/env bash
# Decides which CI areas a change touches, so ci.yml and integration.yml run only
# the jobs that can be affected. Writes one `<area>=true|false` line per area to
# $GITHUB_OUTPUT (or stdout when run locally).
#
# Usage: changes.sh [BASE [HEAD]]
#   With no BASE (push to main, schedule, workflow_dispatch) every area is true.
#   On a pull_request, the workflow checks out the merge commit with
#   fetch-depth: 2 and passes HEAD^1 (the base tip) as BASE.
#
# When in doubt, an area is true: a path that matches no rule below marks
# nothing, but anything under the OCaml tree, the build files or the CI
# definitions themselves marks every area that depends on it.

set -euo pipefail

areas=(ocaml python typescript go java action helm operator terraform)
# Plain variables (hit_<area>) rather than an associative array, so the script
# also runs under macOS's bash 3.2.
mark() { for a in "$@"; do printf -v "hit_$a" true; done; }
for a in "${areas[@]}"; do printf -v "hit_$a" false; done
all() { mark "${areas[@]}"; }

if [ "$#" -eq 0 ] || [ -z "${1:-}" ]; then
  all
else
  base="$1"
  head="${2:-HEAD}"
  while IFS= read -r f; do
    case "$f" in
      # The CI definitions themselves: run everything.
      .github/workflows/ci.yml | .github/workflows/integration.yml | .github/scripts/changes.sh)
        all ;;

      # The OCaml tree and everything its tests read (test/*/dune files point
      # into examples/ and lab/). Every job that builds a haltsql binary
      # depends on this area; see the `needs.changes.outputs.*` conditions.
      lib/* | bin/* | vendor/* | test/* | examples/* | schemas/* | lab/* \
      | dune-project | dune | */dune | *.opam | .ocamlformat | Makefile)
        mark ocaml ;;
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
