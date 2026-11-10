"""The shared core (identical copy in each package): real haltsql CLI, real
haltsql-server, real lab Postgres."""

from __future__ import annotations

import re
import json
import os

import pytest

from conftest import (
    CROSS_TENANT_SQL,
    OK_SQL,
    POLICY,
    ROOT,
    acme_rows,
    assert_denied_cross_tenant,
)

_PKG = "haltsql_" + os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
core = pytest.importorskip(f"{_PKG}._core")

LITERAL_POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas_literal.yaml")
ACME = {"tenant_id": "acme"}


def test_context_from_app_sources():
    class App:
        haltsql_context = {"tenant_id": "acme"}

    assert core.context_from_app(App()) == ACME
    assert core.context_from_app({"haltsql_context": lambda: ACME}) == ACME
    assert core.context_from_app({"tenant": {"tenant_id": "x"}}, "tenant") == {"tenant_id": "x"}
    with pytest.raises(core.ContextUnavailable):
        core.context_from_app(None)
    with pytest.raises(core.ContextUnavailable):
        core.context_from_app({"other": 1})
    with pytest.raises(ValueError):
        core.context_from_app({"haltsql_context": "acme"})
    with pytest.raises(ValueError):
        core.context_from_app({"haltsql_context": {"tenant_id": 1.5}})


def test_runner_rejects_bad_configuration(local_verifier, connections):
    with pytest.raises(ValueError):
        core.HaltSQLToolRunner(object(), connections)
    with pytest.raises(ValueError):
        core.HaltSQLToolRunner(local_verifier, None)
    for bad in (0, -1, True, 100001):
        with pytest.raises(ValueError):
            core.HaltSQLToolRunner(local_verifier, connections, max_rows=bad)
    with pytest.raises(ValueError):
        core.HaltSQLToolRunner(local_verifier, connections, statement_timeout_ms=0)
    with pytest.raises(ValueError):
        core.HaltSQLToolRunner(local_verifier, connections, settings="x")


@pytest.mark.integration
def test_allowed_query_returns_rows(local_verifier, connections):
    r = core.HaltSQLToolRunner(local_verifier, connections).run(OK_SQL, ACME)
    assert r == {"status": "ok", "executed": True, "columns": ["id", "status"], "rows": acme_rows(),
                 "row_count": 2, "truncated": False}
    assert connections.opened == 1


@pytest.mark.integration
def test_cross_tenant_denied_and_never_executed(local_verifier, connections):
    r = core.HaltSQLToolRunner(local_verifier, connections).run(CROSS_TENANT_SQL, ACME)
    assert_denied_cross_tenant(r)
    assert connections.opened == 0
    text = core.result_to_text(r)
    assert json.loads(text) == r


@pytest.mark.integration
def test_no_context_refuses_without_verifying_or_connecting(local_verifier, connections):
    runner = core.HaltSQLToolRunner(local_verifier, connections)
    for ctx in (None, lambda: (_ for _ in ()).throw(core.ContextUnavailable("x")), lambda: {}["k"]):
        r = runner.run(OK_SQL, ctx)
        assert r["status"] == "error" and r["executed"] is False
        assert "No trusted HaltSQL context" in r["message"]
    r = runner.run(OK_SQL, {"tenant_id": 2.5})
    assert r["status"] == "error" and "not executed" in r["message"]
    for q in ("", "   ", None, 5, "x" * 70000):
        assert runner.run(q, ACME)["status"] == "error"
    assert connections.opened == 0


@pytest.mark.integration
def test_unavailable_haltsql_never_executes(connections):
    from haltsql import HaltSQLClient, RetryPolicy

    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with HaltSQLClient(f"http://127.0.0.1:{port}", timeout=1.0, retry=RetryPolicy(max_attempts=1)) as dead:
        r = core.HaltSQLToolRunner(dead, connections).run(OK_SQL, ACME)
    assert r == {"status": "error", "executed": False,
                 "message": "SQL verification is unavailable; the query was not executed."}
    assert connections.opened == 0


@pytest.mark.integration
def test_row_cap_timeout_and_settings(local_verifier, connections):
    seen = []

    def settings(ctx):
        seen.append(ctx)
        return {"app.tenant_id": ctx["tenant_id"]}

    runner = core.HaltSQLToolRunner(local_verifier, connections, max_rows=1, statement_timeout_ms=2000,
                                    settings=settings)
    r = runner.run(OK_SQL, lambda: ACME)
    assert r["rows"] == [[1, "open"]] and r["truncated"] is True and r["row_count"] == 1
    assert seen == [ACME]


@pytest.mark.integration
def test_database_error_is_reported_after_verification(local_verifier, pg_dsn):
    import psycopg

    def database_without_the_tables():
        # The lab's own "postgres" database has no app schema.
        return psycopg.connect(re.sub(r"dbname=\S+", "dbname=postgres", pg_dsn))

    r = core.HaltSQLToolRunner(local_verifier, database_without_the_tables).run(OK_SQL, ACME)
    assert r["status"] == "error" and r["executed"] is True
    assert r["message"].startswith("Database error: UndefinedTable")


@pytest.mark.integration
def test_session_search_path_cannot_redirect_the_query(local_verifier, pg_dsn):
    """The guard pins the policy's search_path, whatever the session default is."""
    import psycopg

    def other_search_path():
        return psycopg.connect(pg_dsn.replace("options=-csearch_path=app", "options=-csearch_path=public"))

    r = core.HaltSQLToolRunner(local_verifier, other_search_path).run(OK_SQL, ACME)
    assert r["status"] == "ok" and r["executed"] is True


@pytest.mark.integration
def test_unreachable_database_after_allow(local_verifier):
    def refuse():
        raise OSError("connection refused")

    r = core.HaltSQLToolRunner(local_verifier, refuse).run(OK_SQL, ACME)
    assert r == {"status": "error", "executed": False,
                 "message": "The database is unavailable; the query was not executed."}


@pytest.mark.integration
def test_check_only(local_verifier, haltsql_cli):
    from haltsql import LocalVerifier

    # Bound tenancy: allowed only with $1 bound, which another tool cannot pass.
    r = core.check_only(local_verifier, OK_SQL, ACME)
    assert r["status"] == "error" and "bound parameters" in r["message"]
    assert_denied_cross_tenant(core.check_only(local_verifier, CROSS_TENANT_SQL, ACME))
    assert "No trusted" in core.check_only(local_verifier, OK_SQL, None)["message"]
    literal = LocalVerifier(LITERAL_POLICY, binary=haltsql_cli)
    assert core.check_only(literal, "SELECT id FROM orders WHERE tenant_id = 'acme' LIMIT 5", ACME) is None
    d = core.check_only(literal, "SELECT id FROM orders WHERE tenant_id = 'globex' LIMIT 5", ACME)
    assert d["status"] == "denied" and d["reasons"][0]["code"] == "E_TENANT_MISMATCH"


@pytest.mark.integration
def test_real_server_verifier(server_verifier, connections):
    runner = core.HaltSQLToolRunner(server_verifier, connections)
    assert runner.run(OK_SQL, ACME)["rows"] == acme_rows()
    assert_denied_cross_tenant(runner.run(CROSS_TENANT_SQL, ACME))
    assert connections.opened == 1


def test_policy_fixture_exists():
    assert os.path.isfile(POLICY)


# ---- stub verifiers: what the runner does whatever the verifier answers -------

UNAVAILABLE = {"status": "error", "executed": False,
               "message": "SQL verification is unavailable; the query was not executed."}
PROBE_SQL = ("SELECT current_setting('transaction_read_only'), current_setting('statement_timeout'), "
             "current_setting('app.tenant_id') FROM orders WHERE tenant_id = $1 LIMIT 1")
WRITE_SQL = "UPDATE orders SET status = 'x' WHERE tenant_id = $1"
SLOW_SQL = "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"


def _allows(kind="select"):
    """A verifier that allows everything and reports ``kind`` as the statement kind."""
    from haltsql.testing import FakeVerifier, make_verdict_dict

    return FakeVerifier(lambda sql, ctx, _p: make_verdict_dict(
        sql, allowed=True, bind=[ctx["tenant_id"]] if "$1" in sql else [], statement_kind=kind))


class _Raises:
    def __init__(self, exc):
        self.exc = exc

    def verify(self, sql, context=None):
        raise self.exc


def _never_connect():
    raise AssertionError("must not connect")


class _Tracked:
    """Wraps a connection factory and keeps every connection it handed out."""

    def __init__(self, connect):
        self.connect = connect
        self.made = []

    def __call__(self):
        c = self.connect()
        self.made.append(c)
        return c


def test_only_select_verdicts_are_run():
    for kind in ("update", "delete", "insert", None):
        r = core.HaltSQLToolRunner(_allows(kind), _never_connect).run(WRITE_SQL, ACME)
        assert r == {"status": "error", "executed": False,
                     "message": "The query was not executed: this tool only runs read-only SELECT statements."}
        r = core.check_only(_allows(kind), "DELETE FROM orders", ACME)
        assert r == {"status": "error", "executed": False,
                     "message": "The query was not executed: only read-only SELECT statements are allowed."}
    assert core.check_only(_allows("select"), "SELECT 1", ACME) is None


def test_verifier_failures_fail_closed_without_details():
    from haltsql import HaltSQLError, HaltSQLRequestError, HaltSQLUnavailable

    secret = "postgresql://agent:s3cret@db.internal/app Bearer tok-123"
    cases = [
        (RuntimeError(secret), UNAVAILABLE),
        (OSError(secret), UNAVAILABLE),
        (HaltSQLUnavailable(secret), UNAVAILABLE),
        (HaltSQLRequestError(secret, status=401, code="UNAUTHORIZED"), UNAVAILABLE),
        (HaltSQLError(secret), {"status": "error", "executed": False, "message": "The query was not executed."}),
    ]
    for exc, expected in cases:
        assert core.HaltSQLToolRunner(_Raises(exc), _never_connect).run(OK_SQL, ACME) == expected, exc
        # A guard hook must refuse too: None would let the other tool run the SQL.
        assert core.check_only(_Raises(exc), "SELECT 1", ACME) == expected, exc


def test_check_only_refuses_unusable_queries_and_contexts():
    fv = _allows()
    for q in (None, "", "   ", 5, ["SELECT 1"], "x" * 70000):
        r = core.check_only(fv, q, ACME)
        assert r is not None and r["status"] == "error" and r["executed"] is False, q
    for bad in ({"tenant_id": 2.5}, {"tenant_id": {"nested": 1}}, {"": "acme"}, "acme"):
        r = core.check_only(fv, "SELECT 1", bad)
        assert r is not None and r["status"] == "error" and "not executed" in r["message"], bad
        r = core.HaltSQLToolRunner(fv, _never_connect).run("SELECT 1", bad)
        assert r["status"] == "error" and r["executed"] is False, bad
    assert fv.calls == []  # nothing above was even sent to the verifier
    with pytest.raises(ValueError):
        core.HaltSQLToolRunner(fv, _never_connect, statement_timeout_ms=3_600_001)


def test_check_only_with_unreachable_sidecar_refuses():
    import socket

    from haltsql import HaltSQLClient, RetryPolicy

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with HaltSQLClient(f"http://127.0.0.1:{port}", timeout=1.0, retry=RetryPolicy(max_attempts=1)) as dead:
        assert core.check_only(dead, "SELECT 1", ACME) == UNAVAILABLE


@pytest.mark.integration
def test_transaction_is_read_only_with_timeout_and_settings(connections, pg_dsn):
    """The limits hold even when the verifier is wrong: a write it labelled SELECT
    still meets a READ ONLY transaction, and every connection is closed."""
    import psycopg

    made = _Tracked(connections)
    runner = core.HaltSQLToolRunner(_allows(), made, statement_timeout_ms=150,
                                    settings=lambda ctx: {"app.tenant_id": ctx["tenant_id"]})
    assert runner.run(PROBE_SQL, ACME)["rows"] == [["on", "150ms", "acme"]]
    r = runner.run(WRITE_SQL, ACME)
    assert r["status"] == "error" and r["executed"] is True
    assert r["message"].startswith("Database error: ReadOnlySqlTransaction")
    r = runner.run(SLOW_SQL, ACME)
    assert r == {"status": "error", "executed": True,
                 "message": "Database error: QueryCanceled: canceling statement due to statement timeout"}
    fixed = core.HaltSQLToolRunner(_allows(), made, settings={"app.tenant_id": "fixed"})
    assert fixed.run(PROBE_SQL, ACME)["rows"] == [["on", "5s", "fixed"]]
    assert len(made.made) == 4 and all(c.closed for c in made.made)
    with psycopg.connect(pg_dsn) as c:
        assert c.execute("SELECT count(*) FROM orders WHERE status = 'x'").fetchone() == (0,)


def test_driver_errors_without_sqlstate_are_not_quoted():
    """Only what the database server reported is quoted to the model."""

    class Conn:
        closed = False

        def close(self):
            self.closed = True

    conn = Conn()
    r = core.HaltSQLToolRunner(_allows(), lambda: conn).run(OK_SQL, ACME)
    # Not a psycopg connection: the guard refuses with its own (safe) message.
    assert r["status"] == "error" and r["executed"] is False and conn.closed is True
    from haltsql.integration import feedback_for_model

    leaky = RuntimeError("connection to postgresql://agent:s3cret@db.internal:5432/app failed")
    assert feedback_for_model(leaky) == "Database error: RuntimeError"
