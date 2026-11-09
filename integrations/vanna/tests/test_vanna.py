"""haltsql-vanna: fakes always; real Vanna classes when installed; execution
with the lab Postgres."""

from types import SimpleNamespace

import pytest

from haltsql import QueryDenied
from haltsql.integration import ContextUnavailable
from haltsql.testing import FakeVerifier, make_verdict_dict, temporary_database
from haltsql_vanna import HaltSQLSqlRunner, context_from_user_metadata, install_legacy_run_sql

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


def user(ctx):
    return SimpleNamespace(metadata={"haltsql_context": ctx} if ctx is not None else {})


async def never_connect():
    raise AssertionError("must not connect")


def test_context_from_user_metadata():
    assert context_from_user_metadata(user({"tenant_id": "a"})) == {"tenant_id": "a"}
    with pytest.raises(PermissionError):
        context_from_user_metadata(user(None))
    with pytest.raises(PermissionError):
        context_from_user_metadata(None)


async def test_denied_never_connects():
    fv = FakeVerifier(decide)
    r = HaltSQLSqlRunner(fv, connect=never_connect)
    with pytest.raises(QueryDenied) as ei:
        await r.run_sql(SimpleNamespace(sql=BAD), SimpleNamespace(user=user({"tenant_id": "acme"})))
    assert "E_TENANT_MISSING" in str(ei.value)
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]


async def test_unauthenticated_user_never_verifies():
    fv = FakeVerifier(decide)
    r = HaltSQLSqlRunner(fv, connect=never_connect)
    with pytest.raises(PermissionError):
        await r.run_sql(SimpleNamespace(sql=OK), SimpleNamespace(user=user(None)))
    assert fv.calls == []


def test_legacy_denied_never_connects():
    vn = SimpleNamespace()

    def connect():
        raise AssertionError("must not connect")

    install_legacy_run_sql(vn, FakeVerifier(decide), {"tenant_id": "acme"}, connect=connect)
    assert vn.run_sql_is_set is True
    with pytest.raises(QueryDenied):
        vn.run_sql(BAD)


def test_legacy_context_returning_none_refuses_without_verifying():
    vn = SimpleNamespace()

    def connect():
        raise AssertionError("must not connect")

    fv = FakeVerifier(decide)
    install_legacy_run_sql(vn, fv, lambda: None, connect=connect)
    with pytest.raises(ContextUnavailable):
        vn.run_sql(OK)
    assert fv.calls == []


async def test_context_from_user_returning_none_refuses():
    fv = FakeVerifier(decide)
    r = HaltSQLSqlRunner(fv, connect=never_connect, context_from_user=lambda u: None)
    with pytest.raises(ContextUnavailable):
        await r.run_sql(SimpleNamespace(sql=OK), SimpleNamespace(user=user({"tenant_id": "a"})))
    assert fv.calls == []


def test_constructor_validation():
    with pytest.raises(ValueError):
        HaltSQLSqlRunner(FakeVerifier(decide))
    with pytest.raises(ValueError):
        install_legacy_run_sql(SimpleNamespace(), FakeVerifier(decide), {})


def test_is_a_vanna_sql_runner_when_installed():
    sr = pytest.importorskip("vanna.capabilities.sql_runner")
    assert issubclass(HaltSQLSqlRunner, sr.SqlRunner)


@pytest.fixture(scope="module")
def pg():
    with temporary_database("haltsql_python_vn", SETUP) as dsn:
        if dsn is None:
            pytest.skip("psycopg or the lab Postgres is not available (make -C lab up)")
        yield dsn


@pytest.mark.integration
async def test_runner_returns_dataframe(pg):
    pytest.importorskip("pandas")
    r = HaltSQLSqlRunner(FakeVerifier(decide), dsn=pg, max_rows=10)
    df = await r.run_sql(SimpleNamespace(sql=OK), SimpleNamespace(user=user({"tenant_id": "acme"})))
    assert list(df.columns) == ["id", "status"]
    assert df.values.tolist() == [[1, "open"], [3, "paid"]]


@pytest.mark.integration
async def test_with_real_vanna_models(pg):
    pytest.importorskip("vanna")
    from vanna.capabilities.sql_runner import RunSqlToolArgs
    from vanna.core.user import User

    r = HaltSQLSqlRunner(FakeVerifier(decide), dsn=pg)
    ctx = SimpleNamespace(user=User(id="u1", metadata={"haltsql_context": {"tenant_id": "globex"}}))
    df = await r.run_sql(RunSqlToolArgs(sql=OK), ctx)
    assert df.values.tolist() == [[2, "open"]]


@pytest.mark.integration
def test_legacy_returns_dataframe(pg):
    pytest.importorskip("pandas")
    vn = SimpleNamespace()
    install_legacy_run_sql(vn, FakeVerifier(decide), lambda: {"tenant_id": "globex"}, dsn=pg)
    assert vn.run_sql(OK).values.tolist() == [[2, "open"]]
