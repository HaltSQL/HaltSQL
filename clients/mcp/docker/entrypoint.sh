#!/bin/sh
# haltsql-mcp container entrypoint.
#
# Mount a folder at /config and the server picks it up with no flags:
#   /config/haltsql-mcp.yaml (or .json)  -> HALTSQL_MCP_CONFIG
#   /config/policy.yaml (or .json)       -> verify locally with the bundled haltsql
#                                           CLI (no central server needed), unless a
#                                           config file, HALTSQL_URL or a flag says
#                                           otherwise.
# Anything set explicitly (environment variable or flag) wins.
set -eu

explicit=""
for arg in "$@"; do
  case "$arg" in
    --config|--config=*|--local-policy|--local-policy=*|--haltsql-url|--haltsql-url=*) explicit=1 ;;
  esac
done

if [ -z "$explicit" ] && [ -z "${HALTSQL_MCP_CONFIG:-}" ]; then
  for f in /config/haltsql-mcp.yaml /config/haltsql-mcp.yml /config/haltsql-mcp.json; do
    if [ -f "$f" ]; then export HALTSQL_MCP_CONFIG="$f"; break; fi
  done
fi

if [ -z "$explicit" ] && [ -z "${HALTSQL_MCP_CONFIG:-}" ] && [ -z "${HALTSQL_URL:-}" ] \
   && [ -z "${HALTSQL_MCP_LOCAL_POLICY:-}" ]; then
  for f in /config/policy.yaml /config/policy.yml /config/policy.json; do
    if [ -f "$f" ]; then export HALTSQL_MCP_LOCAL_POLICY="$f"; break; fi
  done
fi

exec /opt/haltsql-mcp/bin/haltsql-mcp "$@"
