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


async def test_context_never_comes_from_tool_arguments():
    """RunSqlToolArgs are model-written: nothing in them can choose the tenant."""
    fv = FakeVerifier(decide)
    r = HaltSQLSqlRunner(fv, connect=never_connect)
    forged = {"tenant_id": "globex"}
    args = SimpleNamespace(sql=BAD, context=forged, haltsql_context=forged, tenant_id="globex",
                           metadata={"haltsql_context": forged})
    with pytest.raises(QueryDenied):
        await r.run_sql(args, SimpleNamespace(user=user({"tenant_id": "acme"}), haltsql_context=forged,
                                              metadata={"haltsql_context": forged}))
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]


async def test_non_string_sql_is_refused_before_verifying():
    fv = FakeVerifier(decide)
    r = HaltSQLSqlRunner(fv, connect=never_connect)
    for sql in (None, 5, b"SELECT 1", ["SELECT 1"]):
        with pytest.raises(ValueError, match="must be a string"):
            await r.run_sql(SimpleNamespace(sql=sql), SimpleNamespace(user=user({"tenant_id": "acme"})))
    assert fv.calls == []


def test_legacy_ignores_keyword_arguments_for_context():
    vn = SimpleNamespace()

    def connect():
        raise AssertionError("must not connect")

    fv = FakeVerifier(decide)
    install_legacy_run_sql(vn, fv, {"tenant_id": "acme"}, connect=connect)
    with pytest.raises(QueryDenied):
        vn.run_sql(BAD, haltsql_context={"tenant_id": "globex"}, context={"tenant_id": "globex"},
                   tenant_id="globex")
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]


PROBE = ("SELECT current_setting('app.tenant_id') AS s, current_setting('statement_timeout') AS t, "
         "current_setting('transaction_read_only') AS ro FROM orders WHERE tenant_id = $1 LIMIT 1")
SLOW = "SELECT pg_sleep(3) FROM orders WHERE tenant_id = $1 LIMIT 1"
WRITE = "UPDATE orders SET status = 'x' WHERE tenant_id = $1"


def decide_kinds(sql, ctx, _p):
    """Like a policy that allows writes: the verdict carries the real statement kind."""
    return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]], statement_kind=sql.split()[0].lower())


def _unchanged(pg):
    import psycopg

    with psycopg.connect(pg) as c:
        return c.execute("SELECT count(*) FROM orders WHERE status = 'x'").fetchone() == (0,)


@pytest.mark.integration
async def test_runner_limits_settings_and_read_only(pg):
    pytest.importorskip("pandas")
    import psycopg

    r = HaltSQLSqlRunner(FakeVerifier(decide), dsn=pg, max_rows=1, statement_timeout_ms=150,
                         settings={"app.tenant_id": "acme-setting"})
    ctx = SimpleNamespace(user=user({"tenant_id": "acme"}))
    df = await r.run_sql(SimpleNamespace(sql=OK), ctx)
    assert df.values.tolist() == [[1, "open"]]  # row cap
    df = await r.run_sql(SimpleNamespace(sql=PROBE), ctx)
    assert df.values.tolist() == [["acme-setting", "150ms", "on"]]
    with pytest.raises(psycopg.errors.QueryCanceled):
        await r.run_sql(SimpleNamespace(sql=SLOW), ctx)
    # Even a write the policy allowed cannot run: the transaction is always READ ONLY.
    rw = HaltSQLSqlRunner(FakeVerifier(decide_kinds), dsn=pg)
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        await rw.run_sql(SimpleNamespace(sql=WRITE), ctx)
    assert _unchanged(pg)


@pytest.mark.integration
def test_legacy_limits_settings_and_read_only(pg):
    pytest.importorskip("pandas")
    import psycopg

    vn = SimpleNamespace()
    install_legacy_run_sql(vn, FakeVerifier(decide), {"tenant_id": "acme"}, dsn=pg, max_rows=1,
                           statement_timeout_ms=150, settings={"app.tenant_id": "acme-setting"})
    assert vn.run_sql(OK).values.tolist() == [[1, "open"]]
    assert vn.run_sql(PROBE).values.tolist() == [["acme-setting", "150ms", "on"]]
    with pytest.raises(psycopg.errors.QueryCanceled):
        vn.run_sql(SLOW)
    install_legacy_run_sql(vn, FakeVerifier(decide_kinds), {"tenant_id": "acme"}, dsn=pg)
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        vn.run_sql(WRITE)
    assert _unchanged(pg)
