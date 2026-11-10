"""Send one agent's traffic through a real HaltSQL framework adapter.

    python drive_adapter.py ADAPTER SERVER_URL TOKEN DSN [--cross-tenant N]

Runs in the virtualenv of that adapter. Each query goes through the adapter's own
guard (so the adapter, the Python SDK and haltsql-server are all exercised) and, when
allowed, runs on the lab Postgres. Prints one JSON line with counts per outcome.

Traffic per run: allowed tenant-scoped reads, a PII column (denied), a query without
LIMIT (denied), a table outside the policy (denied), and optional cross-tenant probes
(tenant_id compared to other tenants' literals: denied at the tenancy check).
"""

import json
import sys

import psycopg
from haltsql import HaltSQLClient, QueryDenied

ALLOWED = [
    "SELECT o.id, o.status, o.total_cents FROM app.orders o WHERE o.tenant_id = $1 ORDER BY o.id LIMIT 20",
    "SELECT o.id, o.currency FROM app.orders o WHERE o.tenant_id = $1 AND o.total_cents > 0 LIMIT 50",
    "SELECT o.status, count(*) FROM app.orders o WHERE o.tenant_id = $1 GROUP BY o.status LIMIT 10",
]
DENIED = [
    "SELECT c.email FROM app.customers c WHERE c.tenant_id = $1 LIMIT 5",  # PII column
    "SELECT o.id FROM app.orders o WHERE o.tenant_id = $1",  # no LIMIT
    "SELECT k.id FROM app.api_keys k LIMIT 5",  # table outside the policy
]
OTHER_TENANTS = ["globex", "initech", "umbrella", "hooli", "stark", "wayne", "wonka", "acme-eu", "tyrell"]
CTX = {"tenant_id": "acme"}


def make_runner(adapter, client, dsn):
    """Returns run(sql) -> 'allowed' | 'denied', going through the adapter."""
    connect = lambda: psycopg.connect(dsn)  # noqa: E731

    if adapter in ("crewai", "langgraph", "openai_agents", "google_adk", "semantic_kernel"):
        mod = __import__(f"haltsql_{adapter}", fromlist=["HaltSQLToolRunner"])
        runner = mod.HaltSQLToolRunner(client, connect)

        def run(sql):
            out = runner.run(sql, CTX)
            if out.get("status") == "error":
                raise RuntimeError(out.get("message"))
            return "denied" if out.get("status") == "denied" else "allowed"

        return run

    if adapter == "langchain":
        from haltsql_langchain import HaltSQLQueryRunner

        runner = HaltSQLQueryRunner(client, context=lambda: CTX, connect=connect, max_rows=200)

        def run(sql):
            try:
                out = runner.run(sql)
            except QueryDenied:
                return "denied"
            return "denied" if "denied" in str(out).lower()[:200] else "allowed"

        return run

    if adapter == "llamaindex":
        from haltsql_llamaindex import guard_sql_database
        from llama_index.core import SQLDatabase
        from sqlalchemy import create_engine

        url = "postgresql+psycopg://" + dsn_to_url(dsn)
        db = SQLDatabase(create_engine(url), schema="app")
        guarded = guard_sql_database(db, client, lambda: CTX)

        def run(sql):
            try:
                guarded.run_sql(sql)
            except QueryDenied:
                return "denied"
            except Exception as e:  # denials_as_sql_errors and friends
                if "denied" in str(e).lower() or "E_" in str(e):
                    return "denied"
                raise
            return "allowed"

        return run

    if adapter == "vanna":
        from haltsql_vanna import install_legacy_run_sql

        class Vn:  # the Vanna 0.x VannaBase surface install_legacy_run_sql replaces
            run_sql = None

        vn = Vn()
        install_legacy_run_sql(vn, client, lambda: CTX, connect=connect)

        def run(sql):
            try:
                vn.run_sql(sql)
            except QueryDenied:
                return "denied"
            return "allowed"

        return run

    if adapter == "sdk":

        def run(sql):
            return "allowed" if client.verify(sql, CTX).allowed else "denied"

        return run

    raise SystemExit(f"unknown adapter {adapter}")


def dsn_to_url(dsn):
    parts = dict(p.split("=", 1) for p in dsn.split() if "=" in p and not p.startswith("options"))
    auth = parts.get("user", "postgres") + (":" + parts["password"] if parts.get("password") else "")
    return f"{auth}@{parts.get('host', '127.0.0.1')}:{parts.get('port', '5432')}/{parts.get('dbname', 'postgres')}"


def main():
    adapter, url, token, dsn = sys.argv[1:5]
    cross = int(sys.argv[sys.argv.index("--cross-tenant") + 1]) if "--cross-tenant" in sys.argv else 0
    counts = {"allowed": 0, "denied": 0, "unexpected": []}
    with HaltSQLClient(url, token=token) as client:
        run = make_runner(adapter, client, dsn)
        for sql in ALLOWED * 3:
            r = run(sql)
            counts[r] += 1
            if r != "allowed":
                counts["unexpected"].append(sql)
        for sql in DENIED:
            r = run(sql)
            counts[r] += 1
            if r != "denied":
                counts["unexpected"].append(sql)
        for i in range(cross):
            t = OTHER_TENANTS[i % len(OTHER_TENANTS)]
            sql = f"SELECT t.id, t.status FROM app.orders t WHERE t.tenant_id = '{t}' LIMIT 50"
            r = run(sql)
            counts[r] += 1
            if r != "denied":
                counts["unexpected"].append(sql)
    print(json.dumps({"adapter": adapter, **counts}))
    sys.exit(1 if counts["unexpected"] else 0)


if __name__ == "__main__":
    main()
