#!/usr/bin/env bash
# Run every Python test suite owned by the python track (SDK, MCP server,
# LangChain / LlamaIndex / Vanna integrations, shared test-vector drift check)
# and, with FULL=1, the agent-framework packages (OpenAI Agents SDK, LangGraph,
# Semantic Kernel, CrewAI, Google ADK).
#
#   clients/python/run-all-tests.sh            # core deps only; framework-specific tests skip
#   FULL=1 clients/python/run-all-tests.sh     # also install langchain, llama-index, vanna, sqlalchemy,
#                                              # and test the agent-framework packages
#   ONLY=agents clients/python/run-all-tests.sh   # just the agent-framework packages
#
# Integration tests use (when present) the binaries in _build/default/bin
# (or HALTSQL_BIN / HALTSQL_SERVER_BIN) and the lab Postgres on 127.0.0.1:5417
# (make -C lab up); without them they skip with a message.
#
# The agent frameworks have conflicting dependency pins, so each package gets
# its own virtualenv (integrations/<pkg>/.venv, Python 3.11-3.13: set
# PYTHON_AGENTS to choose the interpreter). Installs use the package's
# constraints.txt and only consider releases uploaded before AGENTS_CUTOFF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VENV="${VENV:-$ROOT/clients/python/.venv}"
PY="${PYTHON:-python3}"
AGENT_PKGS="openai_agents langgraph semantic_kernel crewai google_adk"
AGENTS_CUTOFF="${AGENTS_CUTOFF:-2026-10-01T00:00:00Z}"

status=0

run_core() {
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

  for dir in clients/python clients/mcp integrations/langchain integrations/llamaindex integrations/vanna; do
    echo "== $dir"
    (cd "$ROOT/$dir" && "$VENV/bin/python" -m pytest -q -rs -W ignore::DeprecationWarning) || status=1
  done

  if [ -x "${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}" ]; then
    echo "== test vectors"
    "$VENV/bin/python" "$ROOT/clients/testvectors/generate.py" --check \
      --haltsql "${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}" || status=1
  fi
}

agents_python() {
  if [ -n "${PYTHON_AGENTS:-}" ]; then echo "$PYTHON_AGENTS"; return; fi
  for c in python3.12 python3.13 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if (3, 11) <= sys.version_info[:2] <= (3, 13) else 1)' 2>/dev/null; then
      echo "$c"; return
    fi
  done
  return 1
}

run_agents() {
  # The shared core and test fixtures are copied into each package: keep them identical.
  local first="${AGENT_PKGS%% *}"
  echo "== agent packages: shared files"
  for pkg in $AGENT_PKGS; do
    for f in "src/haltsql_$pkg/_core.py:src/haltsql_$first/_core.py" "tests/conftest.py:tests/conftest.py" \
             "tests/test_core.py:tests/test_core.py"; do
      if ! cmp -s "$ROOT/integrations/$pkg/${f%%:*}" "$ROOT/integrations/$first/${f#*:}"; then
        echo "integrations/$pkg/${f%%:*} differs from integrations/$first/${f#*:}"; status=1
      fi
    done
  done

  local apy
  if ! apy="$(agents_python)"; then
    echo "== agent packages: SKIPPED (need Python 3.11-3.13; set PYTHON_AGENTS)"; return
  fi
  for pkg in $AGENT_PKGS; do
    local dir="$ROOT/integrations/$pkg" venv="$ROOT/integrations/$pkg/.venv"
    echo "== integrations/$pkg"
    if [ ! -x "$venv/bin/python" ]; then
      "$apy" -m venv "$venv"
    fi
    if ! "$venv/bin/python" -m pip install -q --upgrade pip ||
       ! "$venv/bin/python" -m pip install -q --uploaded-prior-to "$AGENTS_CUTOFF" \
           -c "$dir/constraints.txt" -e "$ROOT/clients/python[psycopg]" -e "$dir[test]"; then
      echo "install failed for integrations/$pkg"; status=1; continue
    fi
    (cd "$dir" && "$venv/bin/python" -m pytest -q -rs -W ignore::DeprecationWarning) || status=1
  done
}

if [ "${ONLY:-}" != "agents" ]; then
  run_core
fi
if [ "${FULL:-0}" = "1" ] || [ "${ONLY:-}" = "agents" ]; then
  run_agents
fi
exit $status
