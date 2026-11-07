#!/usr/bin/env bash
# Wrapper used by the repository Makefile: lab/run.sh up|run|down|smoke [SCENARIO]
set -euo pipefail
cd "$(dirname "$0")"
cmd="${1:-smoke}"; shift || true
case "$cmd" in
  up|down|smoke|selftest|matrix|validate|test) make "$cmd" ;;
  run) make run SCENARIO="${1:-scenarios/pr-smoke.yaml}" ;;
  *) echo "usage: $0 up|run [SCENARIO]|down|smoke|selftest|matrix|validate|test" >&2; exit 2 ;;
esac
