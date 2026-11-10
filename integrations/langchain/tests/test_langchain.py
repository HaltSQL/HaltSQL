"""haltsql-langchain: core tests use fakes; framework tests skip when
langchain is not installed; execution tests skip without the lab Postgres."""

import os
import json

import pytest

from haltsql import GuardError, HaltSQLUnavailable, QueryDenied
from haltsql.integration import ContextUnavailable
from haltsql.testing import FakeVerifier, make_verdict_dict, temporary_database
from haltsql_langchain import HaltSQLQueryRunner, HaltSQLQueryTool, guard_sql_database

OK = "SELECT id, status FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"
BAD = "SELECT id FROM orders LIMIT 10"

SETUP = """
CREATE TABLE orders (id int8 PRIMARY KEY, tenant_id text NOT NULL, status text);
INSERT INTO orders VALUES (1, 'acme', 'open'), (2, 'globex', 'open'), (3, 'acme', 'paid');
"""


def decide(sql, ctx, _p):
    if "tenant_id = $1" in sql:
        return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]])
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])


class NoEngine:
    def raw_connection(self):
        raise AssertionError("engine used after a refusal")


class FakeSQLDatabase:
    """Stands in for langchain's SQLDatabase (same attribute names)."""

    def __init__(self):
        self._engine = NoEngine()
        self.dialect = "postgresql"

    def run(self, command, fetch="all", include_columns=False, **kw):
        raise AssertionError("unguarded run called")

    def get_usable_table_names(self):
        return ["orders"]


def test_runner_denial_is_feedback_and_never_connects():
    def connect():
        raise AssertionError("must not connect")

    fv = FakeVerifier(decide)
    r = HaltSQLQueryRunner(fv, lambda: {"tenant_id": "acme"}, connect=connect)
    out = r.run(BAD)
    assert out == ("HaltSQL denied the query; it was not executed. Fix the SQL and retry:\n"
                   "- E_TENANT_MISSING: fix E_TENANT_MISSING")
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]
    with pytest.raises(QueryDenied):
        r.execute(BAD)


def test_runner_requires_one_backend():
    with pytest.raises(ValueError):
        HaltSQLQueryRunner(FakeVerifier(decide), {})
    with pytest.raises(ValueError):
        HaltSQLQueryRunner(FakeVerifier(decide), {}, engine=object(), connect=lambda: None)


def test_runner_context_callable_evaluated_per_query():
    seen = []
    tenants = iter(["a", "b"])
    fv = FakeVerifier(lambda s, c, p: (seen.append(c["tenant_id"]), make_verdict_dict(s, allowed=False))[1])
    r = HaltSQLQueryRunner(fv, lambda: {"tenant_id": next(tenants)}, engine=NoEngine())
    r.run(BAD)
    r.run(BAD)
    assert seen == ["a", "b"]


def test_guarded_database_keeps_type_and_delegates():
    db = FakeSQLDatabase()
    g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "acme"})
    assert isinstance(g, FakeSQLDatabase) and g is not db
    assert g.get_usable_table_names() == ["orders"]
    with pytest.raises(QueryDenied):
        g.run(BAD)
    assert g.run_no_throw(BAD).startswith("Error: HaltSQL denied the query")
    with pytest.raises(GuardError, match="parameters"):
        g.run(OK, parameters={"x": 1})
    with pytest.raises(GuardError, match="cursor"):
        g.run(OK, fetch="cursor")
    # the original object is untouched
    with pytest.raises(AssertionError, match="unguarded"):
        db.run(OK)


WRITE = "DELETE FROM orders WHERE tenant_id = $1 AND id = 1"


def decide_kinds(sql, ctx, _p):
    kind = sql.split()[0].lower()
    return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]], statement_kind=kind)


class Reached(Exception):
    pass


class ReachEngine:
    """Records that guarded execution got as far as taking a connection."""

    def raw_connection(self):
        raise Reached()


def test_context_callable_returning_none_refuses_without_verifying():
    fv = FakeVerifier(decide)
    r = HaltSQLQueryRunner(fv, lambda: None, engine=NoEngine())
    with pytest.raises(ContextUnavailable):
        r.execute(OK)
    assert r.run(OK).startswith("No trusted HaltSQL context")
    assert fv.calls == []


def test_context_callable_exception_is_verification_unavailable():
    def broken():
        raise RuntimeError("session store down: secret detail")

    fv = FakeVerifier(decide)
    r = HaltSQLQueryRunner(fv, broken, engine=NoEngine())
    with pytest.raises(HaltSQLUnavailable):
        r.execute(OK)
    out = r.run(OK)
    assert out == "SQL verification is unavailable; the query was not executed."
    assert "secret" not in out
    assert fv.calls == []


def test_read_only_refuses_non_select_before_connecting():
    r = HaltSQLQueryRunner(FakeVerifier(decide_kinds), {"tenant_id": "acme"}, engine=NoEngine())
    with pytest.raises(GuardError, match="only SELECT"):
        r.execute(WRITE)
    assert r.run(WRITE).startswith("The query was not executed: only SELECT")


def test_read_write_runs_what_the_policy_allowed():
    r = HaltSQLQueryRunner(FakeVerifier(decide_kinds), {"tenant_id": "acme"}, engine=ReachEngine(),
                           read_only=False)
    assert r.guard_kwargs["read_only"] is None  # SELECTs still run READ ONLY
    with pytest.raises(Reached):
        r.execute(WRITE)
    # a verdict without a statement kind never runs, even read-write
    r2 = HaltSQLQueryRunner(
        FakeVerifier(lambda s, c, p: make_verdict_dict(s, allowed=True, statement_kind=None)),
        {"tenant_id": "acme"}, engine=NoEngine(), read_only=False)
    with pytest.raises(GuardError, match="statement kind"):
        r2.execute("SELECT 1")


def test_guarded_database_never_reads_sample_rows_or_executes_unverified():
    db = FakeSQLDatabase()
    db._sample_rows_in_table_info = 3
    g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "acme"})
    assert g._sample_rows_in_table_info == 0
    assert db._sample_rows_in_table_info == 3  # the original is untouched
    assert g._get_sample_rows(object()) == ""
    with pytest.raises(GuardError, match="unverified"):
        g._execute("SELECT * FROM orders")


def test_real_sqldatabase_table_info_runs_no_unguarded_select():
    """get_table_info on the guarded copy must not SELECT rows from the engine."""
    pytest.importorskip("langchain_community")
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from langchain_community.utilities import SQLDatabase

    engine = sqlalchemy.create_engine("sqlite://")
    with engine.begin() as c:
        c.exec_driver_sql("CREATE TABLE orders (id INTEGER PRIMARY KEY, tenant_id TEXT, status TEXT)")
        c.exec_driver_sql("INSERT INTO orders VALUES (1, 'acme', 'open'), (2, 'globex', 'secret')")
    executed = []
    sqlalchemy.event.listen(engine, "before_cursor_execute",
                            lambda conn, cur, stmt, *a: executed.append(stmt))
    try:
        db = SQLDatabase(engine)  # sample_rows_in_table_info defaults to 3
        assert "globex" in db.get_table_info()  # the unguarded original leaks rows
        executed.clear()
        g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "acme"})
        for info in (g.get_table_info(), g.get_table_info_no_throw(["orders"]), g.table_info,
                     g.get_context()["table_info"]):
            assert "CREATE TABLE orders" in info
            assert "globex" not in info and "rows from orders" not in info
        assert not [x for x in executed if x.lstrip().upper().startswith("SELECT")], executed
        with pytest.raises(GuardError):
            g._execute("SELECT * FROM orders")
        assert not [x for x in executed if "orders" in x and "PRAGMA" not in x.upper()], executed
    finally:
        engine.dispose()


@pytest.fixture(scope="module")
def pg():
    with temporary_database("haltsql_python_lc", SETUP) as dsn:
        if dsn is None:
            pytest.skip("psycopg or the lab Postgres is not available (make -C lab up)")
        yield dsn


def _url(dsn):
    name = dsn.split("dbname=")[1]
    return f"postgresql+psycopg://postgres:{os.environ.get('HALTSQL_PGPASSWORD', 'haltlab')}@127.0.0.1:5417/{name}"


@pytest.mark.integration
def test_runner_with_psycopg_connect(pg):
    import psycopg

    r = HaltSQLQueryRunner(FakeVerifier(decide), {"tenant_id": "acme"}, connect=lambda: psycopg.connect(pg))
    assert json.loads(r.run(OK)) == {"columns": ["id", "status"], "rows": [[1, "open"], [3, "paid"]],
                                     "truncated": False}


@pytest.mark.integration
def test_real_sqldatabase_guarded(pg):
    pytest.importorskip("langchain_community")
    from langchain_community.utilities import SQLDatabase

    db = SQLDatabase.from_uri(_url(pg))
    g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "globex"})
    assert isinstance(g, SQLDatabase)
    assert g.run(OK) == "[(2, 'open')]"
    assert g.run(OK, include_columns=True) == "[{'id': 2, 'status': 'open'}]"
    assert g.run_no_throw(BAD).startswith("Error: HaltSQL denied")
    assert "orders" in g.get_usable_table_names()
    db._engine.dispose()


@pytest.mark.integration
def test_langchain_tool(pg):
    pytest.importorskip("langchain_core")
    import psycopg

    tool = HaltSQLQueryTool(runner=HaltSQLQueryRunner(
        FakeVerifier(decide), {"tenant_id": "acme"}, connect=lambda: psycopg.connect(pg), max_rows=1))
    assert tool.name == "haltsql_query"
    assert list(tool.args) == ["query"]
    out = json.loads(tool.invoke({"query": OK}))
    assert out == {"columns": ["id", "status"], "rows": [[1, "open"]], "truncated": True}
    assert tool.invoke({"query": BAD}).startswith("HaltSQL denied the query")


def test_guarded_database_refuses_non_string_commands():
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide), {"tenant_id": "acme"})
    with pytest.raises(GuardError, match="only SQL strings"):
        g.run(object())
    assert g.run_no_throw(object()) == "Error: The query was not executed: only SQL strings can be guarded"


def test_feedback_never_quotes_connection_failures():
    """Only what the database server reported is quoted to the model; a failed
    connect() (which can name the host, the role or the whole DSN) is not."""

    def connect():
        raise RuntimeError("could not connect to postgresql://agent:s3cret@db.internal:5432/app")

    r = HaltSQLQueryRunner(FakeVerifier(decide), {"tenant_id": "acme"}, connect=connect)
    out = r.run(OK)
    assert out == "Database error: RuntimeError"
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide), {"tenant_id": "acme"})
    g._haltsql_runner.execute = lambda sql: connect()
    assert g.run_no_throw(OK) == "Error: Database error: RuntimeError"


@pytest.mark.integration
def test_unreachable_database_message_has_no_host_or_role(pg):
    import psycopg

    bad = pg.replace("user=postgres", "user=no_such_role_s3cret")
    r = HaltSQLQueryRunner(FakeVerifier(decide), {"tenant_id": "acme"},
                           connect=lambda: psycopg.connect(bad, connect_timeout=5))
    out = r.run(OK)
    assert out == "Database error: OperationalError"
    assert "127.0.0.1" not in out and "no_such_role" not in out


@pytest.mark.integration
def test_statement_timeout_settings_and_read_only_reach_the_transaction(pg):
    import psycopg

    def connect():
        return psycopg.connect(pg)

    r = HaltSQLQueryRunner(FakeVerifier(decide), {"tenant_id": "acme"}, connect=connect,
                           statement_timeout_ms=150, settings={"app.tenant_id": "acme-setting"})
    slow = "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"
    assert r.run(slow) == "Database error: QueryCanceled: canceling statement due to statement timeout"
    probe = ("SELECT current_setting('app.tenant_id'), current_setting('statement_timeout'), "
             "current_setting('transaction_read_only') FROM orders WHERE tenant_id = $1 LIMIT 1")
    assert json.loads(r.run(probe))["rows"] == [["acme-setting", "150ms", "on"]]
    # A statement the verifier allowed but that writes is stopped by the READ ONLY transaction.
    write = "UPDATE orders SET status = 'x' WHERE tenant_id = $1"
    allow_all = FakeVerifier(lambda s, c, p: make_verdict_dict(s, allowed=True, bind=[c["tenant_id"]]))
    r2 = HaltSQLQueryRunner(allow_all, {"tenant_id": "acme"}, connect=connect)
    assert r2.run(write).startswith("Database error: ReadOnlySqlTransaction")
    with psycopg.connect(pg) as c:
        assert c.execute("SELECT count(*) FROM orders WHERE status = 'x'").fetchone() == (0,)


@pytest.mark.integration
def test_guard_sql_database_passes_runner_options(pg):
    pytest.importorskip("langchain_community")
    from langchain_community.utilities import SQLDatabase

    db = SQLDatabase.from_uri(_url(pg))
    try:
        g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "acme"}, max_rows=1,
                               statement_timeout_ms=150)
        assert g.run(OK) == "[(1, 'open')]"
        slow = "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"
        assert g.run_no_throw(slow) == "Error: Database error: QueryCanceled: canceling statement due to statement timeout"
    finally:
        db._engine.dispose()


@pytest.mark.integration
def test_langchain_tool_ignores_model_supplied_context(pg):
    pytest.importorskip("langchain_core")
    import psycopg

    fv = FakeVerifier(decide)
    tool = HaltSQLQueryTool(runner=HaltSQLQueryRunner(
        fv, {"tenant_id": "acme"}, connect=lambda: psycopg.connect(pg)))
    out = json.loads(tool.invoke({"query": OK, "tenant_id": "globex", "context": {"tenant_id": "globex"},
                                  "haltsql_context": {"tenant_id": "globex"}}))
    assert out["rows"] == [[1, "open"], [3, "paid"]]
    assert fv.calls == [(OK, {"tenant_id": "acme"})]
