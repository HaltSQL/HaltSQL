"""haltsql-llamaindex: fakes first; real LlamaIndex objects when installed and
the lab Postgres is up."""

import os
import pytest

from haltsql import QueryDenied
from haltsql.testing import FakeVerifier, make_verdict_dict, temporary_database
from haltsql_llamaindex import HaltSQLSQLError, guard_sql_database

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
    def __init__(self):
        self._engine = NoEngine()

    def run_sql(self, command):
        raise AssertionError("unguarded run_sql")


def test_denial_raises_and_never_touches_engine():
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide), {"tenant_id": "acme"})
    assert isinstance(g, FakeSQLDatabase)
    with pytest.raises(QueryDenied) as ei:
        g.run_sql(BAD)
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]


def test_denials_as_sql_errors():
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide), {"tenant_id": "acme"},
                           denials_as_sql_errors=True)
    with pytest.raises(HaltSQLSQLError) as ei:
        g.run_sql(BAD)
    assert isinstance(ei.value, NotImplementedError)
    assert "E_TENANT_MISSING: fix E_TENANT_MISSING" in str(ei.value)
    assert isinstance(ei.value.__cause__, QueryDenied)


@pytest.fixture(scope="module")
def pg():
    with temporary_database("haltsql_python_li", SETUP) as dsn:
        if dsn is None:
            pytest.skip("psycopg or the lab Postgres is not available (make -C lab up)")
        yield f"postgresql+psycopg://postgres:{os.environ.get('HALTSQL_PGPASSWORD', 'haltlab')}@127.0.0.1:5417/{dsn.split('dbname=')[1]}"


@pytest.mark.integration
def test_real_llamaindex_sqldatabase_and_retriever(pg):
    pytest.importorskip("llama_index.core")
    from llama_index.core import SQLDatabase
    from sqlalchemy import create_engine

    from haltsql_llamaindex import guarded_sql_retriever

    engine = create_engine(pg)
    try:
        db = SQLDatabase(engine, include_tables=["orders"])
        g = guard_sql_database(db, FakeVerifier(decide), lambda: {"tenant_id": "acme"}, max_rows=5)
        assert isinstance(g, SQLDatabase)
        text, meta = g.run_sql(OK)
        assert text == "[(1, 'open'), (3, 'paid')]"
        assert meta == {"result": [(1, "open"), (3, "paid")], "col_keys": ["id", "status"], "truncated": False}
        with pytest.raises(QueryDenied):
            g.run_sql(BAD)
        assert "orders" in g.get_usable_table_names()

        retriever = guarded_sql_retriever(db, FakeVerifier(decide), {"tenant_id": "globex"})
        nodes = retriever.retrieve(OK)
        assert len(nodes) == 1
        assert nodes[0].node.metadata["result"] == [(2, "open")]
        with pytest.raises(QueryDenied):
            retriever.retrieve(BAD)
    finally:
        engine.dispose()
