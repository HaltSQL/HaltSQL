"""Real-driver (psycopg 3 / libpq) client for the haltsql-proxy integration tests.

Usage (driven by test_proxy_integration.ml):
  pgclient.py setup DB            create DB on the lab Postgres, load saas_shared.sql + rows
  pgclient.py teardown DB         drop DB
  pgclient.py scenarios           run every scenario through the proxy, print one JSON object

Environment for `scenarios`: PROXY_PORT (scram proxy), CERT_PROXY_PORT (cert proxy),
PROXY_DB, CERT_DIR, AGENT_PASSWORD, AGENT2_PASSWORD.
Each scenario records exact observations (rows, SQLSTATE, detail) or {"error": ...}.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import psycopg
from psycopg import pq

ADMIN = dict(host="127.0.0.1", port=5417, user="postgres", password=os.environ.get("HALTSQL_PGPASSWORD", "haltlab"))
REPO = Path(__file__).resolve().parents[2]


def setup(db: str) -> None:
    with psycopg.connect(dbname="postgres", autocommit=True, **ADMIN) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        c.execute(f'CREATE DATABASE "{db}"')
    schema = (REPO / "lab/schemas/saas_shared.sql").read_text()
    with psycopg.connect(dbname=db, autocommit=True, **ADMIN) as c:
        c.execute(schema)
        c.execute("""
          INSERT INTO app.currencies VALUES ('USD','US dollar','$',2), ('EUR','Euro','E',2);
          INSERT INTO app.customers (id, tenant_id, name, country, created_at, email) VALUES
            (1,'acme','Acme Buyer','US',now(),'buyer@acme.test'),
            (2,'globex','Globex Buyer','DE',now(),'buyer@globex.test');
          INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency, created_at) VALUES
            (1,'acme',1,'paid',100,'USD',now()), (2,'acme',1,'open',200,'USD',now()),
            (3,'acme',1,'paid',300,'EUR',now()), (4,'globex',2,'paid',400,'EUR',now()),
            (5,'globex',2,'open',500,'EUR',now()), (6,'globex',2,'paid',600,'USD',now());
          INSERT INTO app.users (id, tenant_id, email, full_name, role, password_hash, created_at) VALUES
            (1,'acme','a@acme.test','A','admin','HTSECRET',now());
        """)


def teardown(db: str) -> None:
    with psycopg.connect(dbname="postgres", autocommit=True, **ADMIN) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


def err(e: BaseException) -> dict:
    d = {"error": type(e).__name__, "message": str(e).strip()}
    diag = getattr(e, "diag", None)
    if diag is not None:
        d.update(sqlstate=diag.sqlstate, primary=diag.message_primary,
                 detail=diag.message_detail, hint=diag.message_hint)
    return d


def scenarios() -> dict:
    port = int(os.environ["PROXY_PORT"])
    cport = int(os.environ["CERT_PROXY_PORT"])
    db = os.environ["PROXY_DB"]
    certs = Path(os.environ["CERT_DIR"])
    pw = os.environ["AGENT_PASSWORD"]
    pw2 = os.environ["AGENT2_PASSWORD"]
    out: dict = {}

    def conn(user="agent", password=pw, sslmode="disable", **kw):
        return psycopg.connect(host="127.0.0.1", port=port, dbname=db, user=user,
                               password=password, sslmode=sslmode, connect_timeout=10, **kw)

    def run(name, fn):
        try:
            out[name] = fn()
        except BaseException as e:  # record, never crash the run
            out[name] = err(e)

    def simple(pg: pq.PGconn, sql: str) -> dict:
        r = pg.exec_(sql.encode())
        if r.status == pq.ExecStatus.TUPLES_OK:
            return {"rows": [[None if r.get_value(i, j) is None else r.get_value(i, j).decode()
                              for j in range(r.nfields)] for i in range(r.ntuples)]}
        def f(code):
            v = r.error_field(code)
            return v.decode() if v is not None else None
        return {"status": pq.ExecStatus(r.status).name, "sqlstate": f(pq.DiagnosticField.SQLSTATE),
                "severity": f(pq.DiagnosticField.SEVERITY_NONLOCALIZED),
                "primary": f(pq.DiagnosticField.MESSAGE_PRIMARY),
                "detail": f(pq.DiagnosticField.MESSAGE_DETAIL),
                "hint": f(pq.DiagnosticField.MESSAGE_HINT)}

    # --- simple query protocol --------------------------------------------
    def simple_flow():
        with conn(autocommit=True) as c:
            pg = c.pgconn
            return {
                "allowed": simple(pg, "SELECT code FROM app.currencies ORDER BY code LIMIT 10"),
                "denied": simple(pg, "SELECT email FROM app.users WHERE tenant_id = $1 LIMIT 5"),
                "after_deny": simple(pg, "SELECT code FROM app.currencies ORDER BY code LIMIT 1"),
                "bound_in_simple": simple(
                    pg, "SELECT id FROM app.orders WHERE tenant_id = $1 ORDER BY id LIMIT 100"),
                "multi": simple(pg, "SELECT 1 LIMIT 1; SELECT 2 LIMIT 1"),
                "connection_ok": pg.status == pq.ConnStatus.OK,
            }
    run("simple", simple_flow)

    # --- extended protocol: tenancy overwrite -------------------------------
    q_orders = "SELECT id, tenant_id FROM app.orders WHERE tenant_id = %s ORDER BY id LIMIT 100"

    def extended():
        with conn(autocommit=True) as c:
            r1 = c.execute(q_orders, ["globex"]).fetchall()
            r2 = c.execute(q_orders, ["acme"], prepare=True).fetchall()
            r3 = c.execute(q_orders, ["globex' OR '1'='1"], prepare=True).fetchall()
            r4 = c.execute(q_orders, [None], prepare=True).fetchall()
            return {"unnamed_other_tenant": r1, "named": r2, "named_injection": r3,
                    "named_null": r4}
    run("extended", extended)

    def extended_tenant2():
        with conn(user="agent2", password=pw2, autocommit=True) as c:
            return {"rows": c.execute(q_orders, ["acme"]).fetchall()}
    run("extended_tenant2", extended_tenant2)

    def extended_denied():
        with conn(autocommit=True) as c:
            try:
                c.execute("SELECT email FROM app.users WHERE tenant_id = %s LIMIT 5", ["acme"])
                denied = {"unexpected": "allowed"}
            except psycopg.Error as e:
                denied = err(e)
            after = c.execute(q_orders, ["globex"]).fetchall()
            return {"denied": denied, "after": after}
    run("extended_denied", extended_denied)

    def transaction():
        with conn() as c:  # not autocommit: implicit BEGIN
            first = c.execute(q_orders, ["x"]).fetchall()
            try:
                c.execute("SELECT ssn FROM app.customers WHERE tenant_id = %s LIMIT 1", ["acme"])
                denied = {"unexpected": "allowed"}
            except psycopg.Error as e:
                denied = err(e)
            status_after_deny = c.info.transaction_status.name
            c.rollback()
            again = c.execute(q_orders, ["x"]).fetchall()
            c.commit()
            return {"first": first, "denied": denied, "status_after_deny": status_after_deny,
                    "again": again}
    run("transaction", transaction)

    def pipeline():
        with conn(autocommit=True) as c:
            with c.pipeline():
                curs = [c.execute(q_orders, [t]) for t in ("globex", "acme", "nobody")]
                c.execute("SELECT code FROM app.currencies ORDER BY code LIMIT 10")
            return {"rows": [cur.fetchall() for cur in curs]}
    run("pipeline", pipeline)

    def pipeline_denied():
        with conn(autocommit=True) as c:
            res = {}
            try:
                with c.pipeline():
                    a = c.execute(q_orders, ["globex"])
                    c.execute("SELECT email FROM app.users WHERE tenant_id = %s LIMIT 5", ["acme"])
                    c.execute(q_orders, ["globex"])
                res["outcome"] = "no error"
            except psycopg.Error as e:
                res["outcome"] = err(e)
            res["after"] = c.execute(q_orders, ["globex"]).fetchall()
            return res
    run("pipeline_denied", pipeline_denied)

    def copy_denied():
        with conn(autocommit=True) as c:
            try:
                with c.cursor().copy("COPY app.orders TO STDOUT") as cp:
                    data = b"".join(bytes(b) for b in cp)
                res = {"unexpected": data.decode()[:200]}
            except psycopg.Error as e:
                res = err(e)
            return {"copy": res, "after": c.execute(q_orders, ["globex"]).fetchall()}
    run("copy", copy_denied)

    def cancel():
        with conn(autocommit=True) as c:
            result = {}

            def canceller():
                time.sleep(0.7)
                c.cancel_safe()

            t = threading.Thread(target=canceller)
            t.start()
            t0 = time.monotonic()
            try:
                c.execute("SELECT pg_sleep(6) LIMIT 1")
                result["outcome"] = "completed"
            except psycopg.Error as e:
                result["outcome"] = err(e)
            result["elapsed_lt_4s"] = (time.monotonic() - t0) < 4.0
            t.join()
            result["after"] = c.execute(q_orders, ["globex"]).fetchall()
            return result
    run("cancel", cancel)

    def tls():
        with conn(sslmode="require", autocommit=True) as c:
            return {"ssl_in_use": c.pgconn.ssl_in_use,
                    "rows": c.execute(q_orders, ["globex"]).fetchall()}
    run("tls", tls)

    def tls_cancel():
        with conn(sslmode="require", autocommit=True) as c:
            threading.Timer(0.7, c.cancel_safe).start()
            try:
                c.execute("SELECT pg_sleep(6) LIMIT 1")
                return {"outcome": "completed"}
            except psycopg.Error as e:
                return {"outcome": err(e)}
    run("tls_cancel", tls_cancel)

    def bad_login(**kw):
        def f():
            try:
                with conn(**kw):
                    return {"unexpected": "connected"}
            except psycopg.Error as e:
                return err(e)
        return f
    run("bad_password", bad_login(password="wrong-password"))
    run("unknown_user", bad_login(user="mallory", password="x"))
    run("wrong_database", lambda: _wrong_db(port, pw))
    run("replication", lambda: _replication(port, db, pw))

    # --- cert-auth proxy -----------------------------------------------------
    def cconn(**kw):
        return psycopg.connect(host="127.0.0.1", port=cport, dbname=db, user="anyone",
                               connect_timeout=10, autocommit=True, **kw)

    def cert_ok():
        with cconn(sslmode="require", sslcert=str(certs / "client.pem"),
                   sslkey=str(certs / "client.key")) as c:
            return {"rows": c.execute(q_orders, ["acme"]).fetchall(),
                    "ssl_in_use": c.pgconn.ssl_in_use}
    run("cert_ok", cert_ok)

    def cert_fail(**kw):
        def f():
            try:
                with cconn(**kw):
                    return {"unexpected": "connected"}
            except psycopg.Error as e:
                return err(e)
        return f
    run("cert_plaintext", cert_fail(sslmode="disable"))
    run("cert_missing", cert_fail(sslmode="require"))
    run("cert_rogue", cert_fail(sslmode="require", sslcert=str(certs / "rogue.pem"),
                                sslkey=str(certs / "rogue.key")))
    return out


def _wrong_db(port, pw):
    try:
        with psycopg.connect(host="127.0.0.1", port=port, dbname="postgres", user="agent",
                             password=pw, sslmode="disable", connect_timeout=10):
            return {"unexpected": "connected"}
    except psycopg.Error as e:
        return err(e)


def _replication(port, db, pw):
    try:
        with psycopg.connect(host="127.0.0.1", port=port, dbname=db, user="agent", password=pw,
                             sslmode="disable", replication="database", connect_timeout=10):
            return {"unexpected": "connected"}
    except psycopg.Error as e:
        return err(e)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "setup":
        setup(sys.argv[2])
    elif cmd == "teardown":
        teardown(sys.argv[2])
    elif cmd == "scenarios":
        print(json.dumps(scenarios(), default=str))
    else:
        sys.exit(f"unknown command {cmd}")
