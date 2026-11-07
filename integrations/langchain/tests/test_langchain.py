"""haltsql-langchain: core tests use fakes; framework tests skip when
langchain is not installed; execution tests skip without the lab Postgres."""

import json

import pytest

from haltsql import GuardError, QueryDenied
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


@pytest.fixture(scope="module")
def pg():
    with temporary_database("haltsql_python_lc", SETUP) as dsn:
        if dsn is None:
            pytest.skip("psycopg or the lab Postgres is not available (make -C lab up)")
        yield dsn


def _url(dsn):
    name = dsn.split("dbname=")[1]
    return f"postgresql+psycopg://postgres:haltlab@127.0.0.1:5417/{name}"


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
