#!/usr/bin/env bash
# HALTSQL_SERVER_BIN wrapper for the console e2e: runs the real haltsql-server exactly
# as the integration test fixtures ask, but writes a hash-chained audit file per suite
# (E2E_AUDIT_DIR/E2E_SUITE.jsonl) with raw SQL, so the console can ingest the traffic.
set -euo pipefail
args=()
skip=0
for a in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  if [ "$a" = "--audit" ]; then skip=1; continue; fi
  args+=("$a")
done
exec "${E2E_REAL_SERVER_BIN:?}" "${args[@]}" --audit "file:${E2E_AUDIT_DIR:?}/${E2E_SUITE:?}.jsonl" --log-raw-sql
