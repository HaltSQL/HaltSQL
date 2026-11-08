#!/usr/bin/env bash
# Run every Python test suite owned by the python track (SDK, MCP server,
# LangChain / LlamaIndex / Vanna integrations, shared test-vector drift check).
#
#   clients/python/run-all-tests.sh            # core deps only; framework-specific tests skip
#   FULL=1 clients/python/run-all-tests.sh     # also install langchain, llama-index, vanna, sqlalchemy
#
# Integration tests use (when present) the binaries in _build/default/bin
# (or HALTSQL_BIN / HALTSQL_SERVER_BIN) and the lab Postgres on 127.0.0.1:5417
# (make -C lab up); without them they skip with a message.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VENV="${VENV:-$ROOT/clients/python/.venv}"
PY="${PYTHON:-python3}"

if [ ! -x "$VENV/bin/python" ]; then
  "$PY" -m venv "$VENV"
fi
PIP="$VENV/bin/python -m pip"
$PIP install -q --upgrade pip
$PIP install -q -e "$ROOT/clients/python[psycopg,asyncpg,test]" \
  -e "$ROOT/clients/mcp[test,yaml]" \
  -e "$ROOT/integrations/langchain" -e "$ROOT/integrations/llamaindex" -e "$ROOT/integrations/vanna"
if [ "${FULL:-0}" = "1" ]; then
  $PIP install -q sqlalchemy langchain-core langchain-community llama-index-core vanna pandas
fi

status=0
for dir in clients/python clients/mcp integrations/langchain integrations/llamaindex integrations/vanna; do
  echo "== $dir"
  (cd "$ROOT/$dir" && "$VENV/bin/python" -m pytest -q -rs -W ignore::DeprecationWarning) || status=1
done

if [ -x "${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}" ]; then
  echo "== test vectors"
  "$VENV/bin/python" "$ROOT/clients/testvectors/generate.py" --check \
    --haltsql "${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}" || status=1
fi
exit $status
