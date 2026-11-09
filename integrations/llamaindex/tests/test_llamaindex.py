"""haltsql-llamaindex: fakes first; real LlamaIndex objects when installed and
the lab Postgres is up."""

import os
import pytest

from haltsql import GuardError, QueryDenied
from haltsql.integration import ContextUnavailable
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


WRITE = "UPDATE orders SET status = 'x' WHERE tenant_id = $1"


def decide_kinds(sql, ctx, _p):
    kind = sql.split()[0].lower()
    return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]], statement_kind=kind)


class Reached(Exception):
    pass


class ReachEngine:
    def raw_connection(self):
        raise Reached()


class EngineDB:
    def __init__(self, engine):
        self._engine = engine


def test_context_callable_returning_none_refuses_without_verifying():
    fv = FakeVerifier(decide)
    g = guard_sql_database(FakeSQLDatabase(), fv, lambda: None)
    with pytest.raises(ContextUnavailable):
        g.run_sql(OK)
    g2 = guard_sql_database(FakeSQLDatabase(), fv, lambda: None, denials_as_sql_errors=True)
    with pytest.raises(HaltSQLSQLError, match="No trusted HaltSQL context"):
        g2.run_sql(OK)
    assert fv.calls == []


def test_read_only_refuses_non_select_and_read_write_follows_policy():
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide_kinds), {"tenant_id": "acme"})
    with pytest.raises(GuardError, match="only SELECT"):
        g.run_sql(WRITE)
    rw = guard_sql_database(EngineDB(ReachEngine()), FakeVerifier(decide_kinds), {"tenant_id": "acme"},
                            read_only=False)
    assert rw._haltsql["guard_kwargs"]["read_only"] is None
    with pytest.raises(Reached):
        rw.run_sql(WRITE)


def test_insert_into_table_refuses():
    g = guard_sql_database(FakeSQLDatabase(), FakeVerifier(decide), {"tenant_id": "acme"})
    with pytest.raises(GuardError, match="insert_into_table"):
        g.insert_into_table("orders", {"id": 9, "tenant_id": "acme"})


def _sqlite_db():
    sqlalchemy = pytest.importorskip("sqlalchemy")
    pytest.importorskip("llama_index.core")
    from llama_index.core import SQLDatabase

    engine = sqlalchemy.create_engine("sqlite://")
    with engine.begin() as c:
        c.exec_driver_sql("CREATE TABLE orders (id INTEGER PRIMARY KEY, tenant_id TEXT, status TEXT)")
        c.exec_driver_sql("INSERT INTO orders VALUES (1, 'acme', 'open'), (2, 'globex', 'secret')")
    executed = []
    sqlalchemy.event.listen(engine, "before_cursor_execute",
                            lambda conn, cur, stmt, *a: executed.append(stmt))
    return engine, SQLDatabase(engine), executed


def test_real_sqldatabase_descriptions_and_inserts_never_touch_rows():
    engine, db, executed = _sqlite_db()
    try:
        g = guard_sql_database(db, FakeVerifier(decide), {"tenant_id": "acme"})
        executed.clear()
        info = g.get_single_table_info("orders")
        assert "tenant_id" in info and "globex" not in info
        with pytest.raises(GuardError):
            g.insert_into_table("orders", {"id": 3, "tenant_id": "globex", "status": "x"})
        touched = [x for x in executed if "PRAGMA" not in x.upper() and "sqlite_" not in x]
        assert touched == [], touched
        with engine.connect() as c:
            assert c.exec_driver_sql("SELECT count(*) FROM orders").scalar() == 2
    finally:
        engine.dispose()


def test_nl_sql_query_engine_accepts_guard_options_as_keywords(monkeypatch):
    engine, db, _ = _sqlite_db()
    from llama_index.core import MockEmbedding, Settings
    from llama_index.core.llms import MockLLM

    monkeypatch.setattr(Settings, "_embed_model", MockEmbedding(embed_dim=8), raising=False)

    from haltsql_llamaindex import guarded_nl_sql_query_engine

    try:
        qe = guarded_nl_sql_query_engine(db, FakeVerifier(decide), {"tenant_id": "acme"},
                                         tables=["orders"], llm=MockLLM(), max_rows=50,
                                         read_only=False, statement_timeout_ms=1234)
        cfg = qe.sql_retriever._sql_database._haltsql
        assert cfg["guard_kwargs"]["max_rows"] == 50
        assert cfg["guard_kwargs"]["statement_timeout_ms"] == 1234
        assert cfg["read_only"] is False
        assert cfg["denials_as_sql_errors"] is True
        qe2 = guarded_nl_sql_query_engine(db, FakeVerifier(decide), {"tenant_id": "acme"},
                                          guard_kwargs={"max_rows": 7}, tables=["orders"], llm=MockLLM())
        assert qe2.sql_retriever._sql_database._haltsql["guard_kwargs"]["max_rows"] == 7
        with pytest.raises(TypeError, match="both"):
            guarded_nl_sql_query_engine(db, FakeVerifier(decide), {}, guard_kwargs={"max_rows": 1},
                                        max_rows=2, llm=MockLLM())
        with pytest.raises(TypeError, match="unknown guard option"):
            guarded_nl_sql_query_engine(db, FakeVerifier(decide), {}, guard_kwargs={"max_row": 1},
                                        llm=MockLLM())
    finally:
        engine.dispose()


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
