"""Unit tests for the console e2e harness (no Postgres, no binaries, stdlib only)."""

import os
import re
import socket
import subprocess
from urllib.parse import unquote, urlsplit

import pytest

import drive_adapter
import drive_mcp
import run_e2e

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))


# ---- E2E-1: run_e2e ignores the suites' HALTSQL_SERVER_BIN ----


def test_server_bin_ignores_the_suite_wrapper():
    wrapper = os.path.join(HERE, "server-wrapper.sh")
    default = os.path.join(run_e2e.BUILD, "server", "main.exe")
    assert run_e2e.server_bin({"HALTSQL_SERVER_BIN": wrapper, "E2E_SUITE": "crewai"}) == default
    assert run_e2e.server_bin({}) == default
    assert run_e2e.server_bin({"HALTSQL_SERVER_BIN": wrapper, "E2E_SERVER_BIN": "/x/server"}) == "/x/server"


def test_readme_does_not_export_the_wrapper():
    readme = open(os.path.join(HERE, "README.md")).read()
    assert not re.search(r"^\s*export\s+[^\n]*HALTSQL_SERVER_BIN", readme, re.M)


# ---- E2E-2: only structured denials count as denied ----


class Denied(Exception):
    """Stands in for haltsql.QueryDenied."""


def runner_failing_with(exc_for_denied_sql):
    deny = set(drive_adapter.DENIED)

    def run(sql):
        if sql in deny or "tenant_id = '" in sql:
            raise exc_for_denied_sql
        return "allowed"

    return run


def test_adapter_error_text_with_E_code_is_not_a_denial():
    counts = drive_adapter.drive(runner_failing_with(RuntimeError("verification refused (E_UNAUTHORIZED)")), 2, (Denied,))
    assert counts["denied"] == 0
    assert counts["error"] == len(drive_adapter.DENIED) + 2
    assert len(counts["unexpected"]) == len(drive_adapter.DENIED) + 2
    assert "E_UNAUTHORIZED" in counts["errors"][0]


def test_adapter_error_text_saying_denied_is_not_a_denial():
    counts = drive_adapter.drive(runner_failing_with(RuntimeError("permission denied for table orders")), 0, (Denied,))
    assert counts["denied"] == 0 and counts["unexpected"]


def test_adapter_structured_denials_count():
    counts = drive_adapter.drive(runner_failing_with(Denied("E_TENANT_MISMATCH")), 3, (Denied,))
    assert counts["denied"] == len(drive_adapter.DENIED) + 3
    assert counts["error"] == 0 and counts["unexpected"] == []


def test_adapter_error_caused_by_a_denial_counts():
    try:
        try:
            raise Denied("E_PII")
        except Denied as d:
            raise NotImplementedError("feedback for the model") from d
    except NotImplementedError as e:
        wrapped = e
    assert drive_adapter.outcome_of_exception(wrapped, (Denied,)) == "denied"
    assert drive_adapter.outcome_of_exception(RuntimeError("E_X denied"), (Denied,)) == "error"


class ToolFailure(Exception):
    """Stands in for haltsql_mcp.core.ToolFailure."""


def test_mcp_tool_failure_is_an_error_not_a_denial():
    def query(sql):
        if "$1" in sql and "email" not in sql:
            return {"allowed": True, "executed": True, "rows": []}
        raise ToolFailure("verification refused (E_UNAUTHORIZED); the query was not executed")

    counts = drive_mcp.drive(query, ToolFailure)
    assert counts["denied"] == 0
    assert counts["error"] == 4 and len(counts["unexpected"]) == 4


def test_mcp_structured_results():
    assert drive_mcp.classify({"allowed": False, "executed": False, "reasons": []}) == "denied"
    assert drive_mcp.classify({"allowed": True, "executed": True}) == "allowed"
    assert drive_mcp.classify({"status": "denied"}) == "error"
    assert drive_mcp.classify("denied E_X") == "error"

    def query(sql):
        return {"allowed": "$1" in sql and "email" not in sql}

    counts = drive_mcp.drive(query, ToolFailure)
    assert counts["unexpected"] == [] and counts["denied"] == 4 and counts["allowed"] == 4


# ---- E2E-5: the raw-SQL check needs a 200 and the tenant literal ----


def test_raw_sql_check():
    sql = "SELECT t.id FROM app.orders t WHERE t.tenant_id = 'initech' LIMIT 50"
    assert run_e2e.raw_sql_ok(200, {"sql": sql})
    assert not run_e2e.raw_sql_ok(403, {"sql": sql})  # a quote alone used to pass
    assert not run_e2e.raw_sql_ok(200, {"sql": "SELECT 'x'"})
    assert not run_e2e.raw_sql_ok(200, b"not json")
    assert not run_e2e.raw_sql_ok(200, {})


# ---- E2E-9: harness errors become failed checks; readiness is polled ----


def test_guarded_records_harness_errors(monkeypatch):
    monkeypatch.setattr(run_e2e, "FAILURES", [])

    def hang():
        raise subprocess.TimeoutExpired(["adapter"], 300)

    assert run_e2e.guarded("langchain", hang) is None
    assert run_e2e.guarded("pack", lambda: next(iter([]))) is None
    assert len(run_e2e.FAILURES) == 2
    assert "TimeoutExpired" in run_e2e.FAILURES[0] and "StopIteration" in run_e2e.FAILURES[1]
    assert run_e2e.guarded("ok", lambda x: x + 1, 1) == 2


def test_wait_tcp():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        run_e2e.wait_tcp(s.getsockname()[1], timeout=2)
    port = run_e2e.free_port()
    with pytest.raises(run_e2e.HarnessError):
        run_e2e.wait_tcp(port, timeout=0.3)


def test_wait_until():
    seen = []
    assert run_e2e.wait_until(lambda: seen.append(1) or len(seen) >= 3, timeout=5, interval=0.01)
    assert not run_e2e.wait_until(lambda: 1 / 0, timeout=0.05, interval=0.01)


def test_no_fixed_sleeps_or_dead_tls():
    src = open(os.path.join(HERE, "run_e2e.py")).read()
    assert "time.sleep(1.0)" not in src and "time.sleep(5)" not in src
    assert '"tls"' not in src


# ---- E2E-10: DSN credentials are percent-encoded in the SQLAlchemy URL ----


def simple_parse(dsn):
    return dict(p.split("=", 1) for p in dsn.split() if "=" in p)


def test_dsn_to_url_encodes_credentials():
    url = drive_adapter.dsn_to_url("host=127.0.0.1 port=5417 user=lab@ops password=p@s/w:d#1 dbname=db_1", parse=simple_parse)
    parts = urlsplit(url)
    assert parts.scheme == "postgresql+psycopg"
    assert parts.hostname == "127.0.0.1" and parts.port == 5417
    assert unquote(parts.username) == "lab@ops" and unquote(parts.password) == "p@s/w:d#1"
    assert parts.path == "/db_1"


def test_dsn_to_url_defaults():
    url = drive_adapter.dsn_to_url("dbname=x", parse=simple_parse)
    assert url == "postgresql+psycopg://postgres@127.0.0.1:5432/x"


# ---- E2E-11: the schema is a fixture, not a framework test's conftest ----


def test_schema_fixture():
    src = open(os.path.join(HERE, "run_e2e.py")).read()
    assert "conftest" not in src
    assert "CREATE TABLE app.orders" in run_e2e.load_schema()


def _sql(text):
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("--")]
    return " ".join(" ".join(lines).split())


def test_schema_fixture_matches_the_integration_fixtures():
    conftest = os.path.join(ROOT, "integrations", "crewai", "tests", "conftest.py")
    if not os.path.exists(conftest):
        pytest.skip("integration packages not present")
    m = re.search(r'^SETUP = """(.*?)"""', open(conftest).read(), re.S | re.M)
    assert m, "SETUP not found in the crewai conftest"
    assert _sql(run_e2e.load_schema()) == _sql(m.group(1))
