"""MCP client for scripts/mcp-docker-smoke.sh. Runs inside the haltsql-mcp image.

Starts the image's entrypoint as a stdio MCP server (so the /config
auto-detection is exercised), calls the tools, and checks the results.

Usage: python mcp_smoke_client.py MODE [entrypoint args...]
  MODE: local | central | closed   (expected verification backend / outcome)
Environment: EXPECT_ROWS (JSON list of the allowed query's rows).
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ALLOWED = "SELECT id, name FROM customers WHERE tenant_id = $1 ORDER BY id LIMIT 10"
DENIED = {
    "SELECT name, email FROM customers LIMIT 10": "E_COLUMN_DENIED",
    "SELECT 1; COMMIT; DROP SCHEMA app CASCADE": "E_MULTI_STATEMENT",
    "SELECT pg_sleep(30) LIMIT 1": "E_FUNCTION_DENIED",
}


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


async def main() -> None:
    mode, args = sys.argv[1], sys.argv[2:]
    params = StdioServerParameters(
        command="/usr/local/bin/haltsql-mcp-entrypoint", args=args, env=dict(os.environ))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            if tools != ["describe_policy", "explain_denial", "list_tables", "query"]:
                fail(f"unexpected tools {tools}")
            res = await s.call_tool("query", {"sql": ALLOWED})
            text = res.content[0].text
            if mode == "closed":
                if not res.is_error or "not executed" not in text:
                    fail(f"expected fail-closed tool error, got {text[:200]}")
                print("ok   closed: verification refused, nothing executed")
                return
            if res.is_error:
                fail(f"allowed query failed: {text[:300]}")
            out = json.loads(text)
            want = json.loads(os.environ["EXPECT_ROWS"])
            if out["rows"] != want:
                fail(f"rows {out['rows']} != {want}")
            for sql, code in DENIED.items():
                d = json.loads((await s.call_tool("query", {"sql": sql})).content[0].text)
                codes = [x["code"] for x in d.get("reasons", [])]
                if d.get("allowed") or d.get("executed") or code not in codes:
                    fail(f"{sql!r}: expected {code}, got {d}")
            desc = json.loads((await s.call_tool("describe_policy", {})).content[0].text)
            central = "policies" in desc
            if central != (mode == "central"):
                fail(f"expected {mode} verification, describe_policy says {sorted(desc)}")
            print(f"ok   {mode}: rows {out['rows']}, {len(DENIED)} denials")


asyncio.run(main())
