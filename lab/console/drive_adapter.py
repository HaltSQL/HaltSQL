"""Send one agent's traffic through a real HaltSQL framework adapter.

    python drive_adapter.py ADAPTER SERVER_URL TOKEN DSN [--cross-tenant N]

Runs in the virtualenv of that adapter. Each query goes through the adapter's own
guard (so the adapter, the Python SDK and haltsql-server are all exercised) and, when
allowed, runs on the lab Postgres. Prints one JSON line with counts per outcome.

Only a structured denial counts as "denied": a QueryDenied (or an adapter error whose
cause is one), a verdict with allowed false, or a tool result with status "denied".
Any other failure (bad token, verifier down, database error) is an "error", which is
always unexpected.

Traffic per run: allowed tenant-scoped reads, a PII column (denied), a query without
LIMIT (denied), a table outside the policy (denied), and optional cross-tenant probes
(tenant_id compared to other tenants' literals: denied at the tenancy check).
"""

import json
import sys
from urllib.parse import quote

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


def outcome_of_exception(e, denied_types):
    """'denied' when [e] is (or was raised from) a policy denial, else 'error'."""
    seen = set()
    while e is not None and id(e) not in seen:
        if isinstance(e, denied_types):
            return "denied"
        seen.add(id(e))
        e = e.__cause__
    return "error"


def make_runner(adapter, client, dsn):
    """Returns run(sql) -> 'allowed' | 'denied', going through the adapter. Failures
    that are not a structured allow or deny raise; the caller classifies them."""
    import psycopg

    connect = lambda: psycopg.connect(dsn)  # noqa: E731

    if adapter in ("crewai", "langgraph", "openai_agents", "google_adk", "semantic_kernel"):
        mod = __import__(f"haltsql_{adapter}", fromlist=["HaltSQLToolRunner"])
        runner = mod.HaltSQLToolRunner(client, connect)

        def run(sql):
            out = runner.run(sql, CTX)
            status = out.get("status") if isinstance(out, dict) else None
            if status == "denied":
                return "denied"
            if status == "error" or not isinstance(out, dict):
                raise RuntimeError(f"tool error: {out}")
            return "allowed"

        return run

    if adapter == "langchain":
        from haltsql_langchain import HaltSQLQueryRunner

        runner = HaltSQLQueryRunner(client, context=lambda: CTX, connect=connect, max_rows=200)

        def run(sql):
            # execute() is what run() wraps; it raises QueryDenied on a denial instead of
            # turning every failure into model feedback text.
            runner.execute(sql)
            return "allowed"

        return run

    if adapter == "llamaindex":
        from haltsql_llamaindex import guard_sql_database
        from llama_index.core import SQLDatabase
        from sqlalchemy import create_engine

        url = dsn_to_url(dsn)
        db = SQLDatabase(create_engine(url), schema="app")
        guarded = guard_sql_database(db, client, lambda: CTX)

        def run(sql):
            guarded.run_sql(sql)  # a denial raises QueryDenied (or an error caused by one)
            return "allowed"

        return run

    if adapter == "vanna":
        from haltsql_vanna import install_legacy_run_sql

        class Vn:  # the Vanna 0.x VannaBase surface install_legacy_run_sql replaces
            run_sql = None

        vn = Vn()
        install_legacy_run_sql(vn, client, lambda: CTX, connect=connect)

        def run(sql):
            vn.run_sql(sql)
            return "allowed"

        return run

    if adapter == "sdk":

        def run(sql):
            return "allowed" if client.verify(sql, CTX).allowed else "denied"

        return run

    raise SystemExit(f"unknown adapter {adapter}")


def parse_dsn(dsn):
    """The keywords of a libpq DSN (libpq's own parser when psycopg is installed)."""
    try:
        from psycopg.conninfo import conninfo_to_dict
    except ImportError:
        return dict(p.split("=", 1) for p in dsn.split() if "=" in p)
    return conninfo_to_dict(dsn)


def dsn_to_url(dsn, parse=parse_dsn):
    """A SQLAlchemy URL for a libpq DSN, with the user and password percent-encoded."""
    parts = parse(dsn)
    auth = quote(parts.get("user") or "postgres", safe="")
    if parts.get("password"):
        auth += ":" + quote(parts["password"], safe="")
    host = parts.get("host") or "127.0.0.1"
    db = quote(parts.get("dbname") or "postgres", safe="")
    return f"postgresql+psycopg://{auth}@{host}:{parts.get('port') or '5432'}/{db}"


def drive(run, cross, denied_types):
    """Runs the traffic through [run]; returns the counts per outcome."""
    counts = {"allowed": 0, "denied": 0, "error": 0, "unexpected": [], "errors": []}

    def one(sql, expect):
        try:
            r = run(sql)
        except Exception as e:  # noqa: BLE001 - classified: denial or error
            r = outcome_of_exception(e, denied_types)
            if r == "error":
                counts["errors"].append(f"{type(e).__name__}: {e}"[:200])
        counts[r] += 1
        if r != expect:
            counts["unexpected"].append(sql)

    for sql in ALLOWED * 3:
        one(sql, "allowed")
    for sql in DENIED:
        one(sql, "denied")
    for i in range(cross):
        t = OTHER_TENANTS[i % len(OTHER_TENANTS)]
        one(f"SELECT t.id, t.status FROM app.orders t WHERE t.tenant_id = '{t}' LIMIT 50", "denied")
    return counts


def main():
    from haltsql import HaltSQLClient, QueryDenied

    adapter, url, token, dsn = sys.argv[1:5]
    cross = int(sys.argv[sys.argv.index("--cross-tenant") + 1]) if "--cross-tenant" in sys.argv else 0
    with HaltSQLClient(url, token=token) as client:
        counts = drive(make_runner(adapter, client, dsn), cross, (QueryDenied,))
    print(json.dumps({"adapter": adapter, **counts}))
    sys.exit(1 if counts["unexpected"] else 0)


if __name__ == "__main__":
    main()
