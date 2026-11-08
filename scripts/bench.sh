#!/usr/bin/env bash
# Builds HaltSQL in release mode and runs the benchmark harness (bench/bench.ml).
#
#   scripts/bench.sh                         # all suites (proxy needs the lab Postgres)
#   scripts/bench.sh --small --suite library,cli,http \
#       --baseline bench/baseline/ci-small.json   # the CI regression check
#
# Extra arguments are passed to bench.exe (see `bench.exe --help`).
#
# Environment:
#   BUILD_DIR           dune build directory          (default _build)
#   OUT_DIR             where bench.json / bench.md go (default $BUILD_DIR/bench-results)
#   HALTSQL_PGPASSWORD  lab Postgres password for the proxy suite (default haltlab)

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
BUILD_DIR=${BUILD_DIR:-_build}
OUT_DIR=${OUT_DIR:-$BUILD_DIR/bench-results}

dune build --build-dir "$BUILD_DIR" --profile release lib/pgquery/libpg_query.a
dune build --build-dir "$BUILD_DIR" --profile release \
  bench/bench.exe bin/haltsql/main.exe bin/server/main.exe bin/proxy/main.exe

B=$BUILD_DIR/default
mkdir -p "$OUT_DIR"
exec "$B/bench/bench.exe" --root "$ROOT" \
  --haltsql "$B/bin/haltsql/main.exe" \
  --server "$B/bin/server/main.exe" \
  --proxy "$B/bin/proxy/main.exe" \
  --json "$OUT_DIR/bench.json" --markdown "$OUT_DIR/bench.md" \
  "$@"
