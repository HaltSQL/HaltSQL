"""Send MCP-tool traffic through haltsql-mcp's tools to a real haltsql-server.

    python drive_mcp.py SERVER_URL TOKEN DSN

Uses the same HaltSQLTools object the MCP server exposes to clients (query tool), with
a real HaltSQLClient and the lab Postgres. Prints one JSON line with counts.

Only the query tool's structured result decides the outcome: "allowed" true is an
allow, "allowed" false a denial. A ToolFailure (refused request, bad token, verifier or
database down) is an "error", which is always unexpected.
"""

import asyncio
import json
import sys

CASES = [
    ("SELECT o.id, o.status FROM app.orders o WHERE o.tenant_id = $1 LIMIT 10", "allowed"),
    ("SELECT o.id, o.currency FROM app.orders o WHERE o.tenant_id = $1 LIMIT 10", "allowed"),
    ("SELECT c.email FROM app.customers c WHERE c.tenant_id = $1 LIMIT 5", "denied"),
    ("SELECT o.id FROM app.orders o WHERE o.tenant_id = 'globex' LIMIT 5", "denied"),
]


def classify(out):
    """'allowed' | 'denied' | 'error' for one query tool result."""
    if isinstance(out, dict):
        if out.get("allowed") is True:
            return "allowed"
        if out.get("allowed") is False:
            return "denied"
    return "error"


def drive(query, failure_type, cases=CASES):
    """Runs [cases] (twice) through [query]; returns the counts per outcome."""
    counts = {"allowed": 0, "denied": 0, "error": 0, "unexpected": [], "errors": []}
    for sql, expect in cases * 2:
        try:
            out = query(sql)
            got = classify(out)
            if got == "error":
                counts["errors"].append(f"unexpected result: {out!r}"[:200])
        except failure_type as e:
            got = "error"
            counts["errors"].append(str(e)[:200])
        counts[got] += 1
        if got != expect:
            counts["unexpected"].append(sql)
    return counts


def main():
    import psycopg
    from haltsql import HaltSQLClient
    from haltsql_mcp.core import HaltSQLTools, ToolFailure

    url, token, dsn = sys.argv[1:4]
    with HaltSQLClient(url, token=token) as client:
        tools = HaltSQLTools(client, lambda: {"tenant_id": "acme"},
                             connect=lambda: psycopg.AsyncConnection.connect(dsn))  # awaited by the tools
        counts = drive(lambda sql: asyncio.run(tools.query(sql)), ToolFailure)
    print(json.dumps({"adapter": "mcp", **counts}))
    sys.exit(1 if counts["unexpected"] else 0)


if __name__ == "__main__":
    main()
