"""The shared core (identical copy in each package): real haltsql CLI, real
haltsql-server, real lab Postgres."""

from __future__ import annotations

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

    def broken_search_path():
        return psycopg.connect(pg_dsn.replace("options=-csearch_path=app", "options=-csearch_path=public"))

    r = core.HaltSQLToolRunner(local_verifier, broken_search_path).run(OK_SQL, ACME)
    assert r["status"] == "error" and r["executed"] is True
    assert r["message"].startswith("Database error: UndefinedTable")


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
