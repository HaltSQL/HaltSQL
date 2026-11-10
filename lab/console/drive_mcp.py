"""Send MCP-tool traffic through haltsql-mcp's tools to a real haltsql-server.

    python drive_mcp.py SERVER_URL TOKEN DSN

Uses the same HaltSQLTools object the MCP server exposes to clients (query tool), with
a real HaltSQLClient and the lab Postgres. Prints one JSON line with counts.
"""

import asyncio
import json
import sys

import psycopg
from haltsql import HaltSQLClient
from haltsql_mcp.core import HaltSQLTools, ToolFailure

url, token, dsn = sys.argv[1:4]
counts = {"allowed": 0, "denied": 0, "unexpected": []}
with HaltSQLClient(url, token=token) as client:
    tools = HaltSQLTools(client, lambda: {"tenant_id": "acme"}, connect=lambda: psycopg.AsyncConnection.connect(dsn))  # awaited by the tools
    cases = [
        ("SELECT o.id, o.status FROM app.orders o WHERE o.tenant_id = $1 LIMIT 10", "allowed"),
        ("SELECT o.id, o.currency FROM app.orders o WHERE o.tenant_id = $1 LIMIT 10", "allowed"),
        ("SELECT c.email FROM app.customers c WHERE c.tenant_id = $1 LIMIT 5", "denied"),
        ("SELECT o.id FROM app.orders o WHERE o.tenant_id = 'globex' LIMIT 5", "denied"),
    ]
    for sql, expect in cases * 2:
        try:
            out = asyncio.run(tools.query(sql))
            got = "denied" if (isinstance(out, dict) and (out.get("status") == "denied" or out.get("denied") or out.get("allowed") is False)) else "allowed"
        except ToolFailure as e:
            got = "denied" if "denied" in str(e).lower() or "E_" in str(e) else "error"
            counts.setdefault("errors", []).append(str(e)[:200])
        counts[got] = counts.get(got, 0) + 1
        if got != expect:
            counts["unexpected"].append(sql)
print(json.dumps({"adapter": "mcp", **counts}))
sys.exit(1 if counts["unexpected"] else 0)
