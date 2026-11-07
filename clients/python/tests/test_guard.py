"""guard.execute / execute_async: refuse before touching the DB; with the lab
Postgres, run exactly the verified string with the bound params."""

import os

import pytest

from haltsql import Guard, GuardError, HaltSQLUnavailable, LocalVerifier, QueryDenied, guard
from haltsql.testing import FakeVerifier, make_verdict, make_verdict_dict

from conftest import POLICIES_DIR

SQL_OK = "SELECT id, status FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 100"
SQL_BAD = "SELECT id FROM orders LIMIT 10"


def decide(sql, ctx, _policy):
    if "tenant_id = $1" in sql:
        return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]])
    if "ANY($1)" in sql:
        return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_ids"]])
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])


class Untouchable:
    """A connection that fails the test if the guard uses it."""

    __haltsql_driver__ = "psycopg"

    def __getattr__(self, name):
        raise AssertionError(f"connection used after a refusal: {name}")


class UntouchableAsync(Untouchable):
    __haltsql_driver__ = "asyncpg"


def test_denied_never_touches_connection():
    fv = FakeVerifier(decide)
    with pytest.raises(QueryDenied) as ei:
        guard.execute(Untouchable(), SQL_BAD, {"tenant_id": "acme"}, verifier=fv)
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]
    assert fv.calls == [(SQL_BAD, {"tenant_id": "acme"})]


def test_verifier_error_never_touches_connection():
    class Down:
        def verify(self, sql, context=None):
            raise HaltSQLUnavailable("down")

    with pytest.raises(HaltSQLUnavailable):
        guard.execute(Untouchable(), SQL_OK, {"tenant_id": "acme"}, verifier=Down())


def test_verdict_for_other_sql_is_refused():
    fv = FakeVerifier(lambda sql, ctx, p: make_verdict("SELECT 1", allowed=True))
    with pytest.raises(HaltSQLUnavailable, match="sql_sha256"):
        guard.execute(Untouchable(), SQL_OK, {"tenant_id": "acme"}, verifier=fv)


def test_non_verdict_is_refused():
    class Liar:
        def verify(self, sql, context=None):
            return {"allowed": True}

    with pytest.raises(HaltSQLUnavailable, match="did not return a Verdict"):
        guard.execute(Untouchable(), SQL_OK, {}, verifier=Liar())


def test_unsupported_connections():
    fv = FakeVerifier(decide)
    with pytest.raises(GuardError, match="unsupported"):
        guard.execute(object(), SQL_OK, {"tenant_id": "a"}, verifier=fv)
    with pytest.raises(GuardError, match="execute_async"):
        guard.execute(UntouchableAsync(), SQL_OK, {"tenant_id": "a"}, verifier=fv)
    assert fv.calls == []


def test_async_verifier_in_sync_execute_is_refused():
    class AsyncV:
        async def verify(self, sql, context=None):
            return make_verdict(sql, allowed=True, bind=["a"])

    with pytest.raises(GuardError, match="async verifier"):
        guard.execute(Untouchable(), SQL_OK, {"tenant_id": "a"}, verifier=AsyncV())


def test_argument_validation():
    fv = FakeVerifier(decide)
    for kw in ({"max_rows": -1}, {"statement_timeout_ms": 0}, {"settings": {"bad name;": "x"}},
               {"settings": {"app.tenant": 5}}):
        with pytest.raises(ValueError):
            guard.execute(Untouchable(), SQL_OK, {"tenant_id": "a"}, verifier=fv, **kw)
    with pytest.raises(TypeError):
        guard.execute(Untouchable(), b"SELECT 1", {}, verifier=fv)  # type: ignore[arg-type]


async def test_async_denied_never_touches_connection():
    fv = FakeVerifier(decide)
    with pytest.raises(QueryDenied):
        await guard.execute_async(UntouchableAsync(), SQL_BAD, {"tenant_id": "a"}, verifier=fv)


# ---- lab Postgres ----------------------------------------------------------


@pytest.mark.integration
def test_psycopg_runs_verified_sql_with_binds(pg_dsn):
    import psycopg

    fv = FakeVerifier(decide)
    with psycopg.connect(pg_dsn) as conn:
        r = guard.execute(conn, SQL_OK, {"tenant_id": "acme"}, verifier=fv,
                          statement_timeout_ms=2000, settings={"app.tenant_id": "acme"})
        assert r.columns == ["id", "status"]
        assert [row[0] for row in r.rows] == [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
        assert r.rowcount == 10 and r.truncated is False
        assert r.verdict.allowed
        # transaction-local settings did not leak
        assert conn.execute("SHOW statement_timeout").fetchone()[0] == "0"
        conn.rollback()  # SHOW opened a transaction (autocommit is off)

        capped = guard.execute(conn, SQL_OK, {"tenant_id": "acme"}, verifier=fv, max_rows=3)
        assert [row[0] for row in capped.rows] == [2, 4, 6] and capped.truncated is True


@pytest.mark.integration
def test_psycopg_read_only_blocks_writes(pg_dsn):
    import psycopg

    sql = "UPDATE orders SET status = status WHERE tenant_id = $1"
    fv = FakeVerifier(lambda s, c, p: make_verdict(s, allowed=True, bind=[c["tenant_id"]],
                                                   statement_kind="select"))
    with psycopg.connect(pg_dsn) as conn:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            guard.execute(conn, sql, {"tenant_id": "acme"}, verifier=fv)
        conn.rollback()
        # explicitly read-write, as for a policy that allows updates
        r = guard.execute(conn, sql, {"tenant_id": "acme"}, verifier=fv, read_only=False)
        assert r.columns == [] and r.rowcount == 10


@pytest.mark.integration
def test_psycopg_refuses_inside_open_transaction(pg_dsn):
    import psycopg

    with psycopg.connect(pg_dsn) as conn:
        conn.execute("SELECT 1")  # opens a transaction (autocommit off)
        with pytest.raises(GuardError, match="already in a transaction"):
            guard.execute(conn, SQL_OK, {"tenant_id": "acme"}, verifier=FakeVerifier(decide))


@pytest.mark.integration
def test_psycopg_statement_timeout_applies(pg_dsn):
    import psycopg

    sql = "SELECT pg_sleep(2), tenant_id FROM orders WHERE tenant_id = $1 LIMIT 1"
    with psycopg.connect(pg_dsn) as conn:
        with pytest.raises(psycopg.errors.QueryCanceled):
            guard.execute(conn, sql, {"tenant_id": "acme"}, verifier=FakeVerifier(decide),
                          statement_timeout_ms=100)


@pytest.mark.integration
def test_psycopg_with_real_cli_verifier(pg_dsn, haltsql_cli):
    import psycopg

    lv = LocalVerifier(os.path.join(POLICIES_DIR, "hierarchical.yaml"), binary=haltsql_cli)
    sql = "SELECT a.id, a.name FROM accounts a WHERE a.tenant_id = ANY($1) ORDER BY a.id LIMIT 100"
    g = Guard(lv, statement_timeout_ms=2000)
    with psycopg.connect(pg_dsn) as conn:
        r = g.execute(conn, sql, {"tenant_ids": ["acme", "acme-eu"]})
        assert r.rows == [(1, "a"), (2, "b")]
        with pytest.raises(QueryDenied) as ei:
            g.execute(conn, "SELECT a.id FROM accounts a LIMIT 1", {"tenant_ids": ["acme"]})
        assert "E_TENANT_MISSING" in ei.value.verdict.codes


@pytest.mark.integration
async def test_asyncpg_runs_verified_sql(pg_dsn):
    asyncpg = pytest.importorskip("asyncpg")
    dsn = "postgresql://postgres:haltlab@127.0.0.1:5417/" + pg_dsn.split("dbname=")[1]
    conn = await asyncpg.connect(dsn)
    try:
        fv = FakeVerifier(decide)
        r = await guard.execute_async(conn, SQL_OK, {"tenant_id": "globex"}, verifier=fv,
                                      statement_timeout_ms=2000, max_rows=4)
        assert r.columns == ["id", "status"]
        assert r.rows == [(1, "open"), (3, "open"), (5, "open"), (7, "open")]
        assert r.truncated is True
        sql = "SELECT id FROM accounts WHERE tenant_id = ANY($1) ORDER BY id LIMIT 10"
        r2 = await guard.execute_async(conn, sql, {"tenant_ids": ["acme", "globex"]}, verifier=fv)
        assert r2.rows == [(1,), (3,)] and r2.truncated is False
        upd = "UPDATE orders SET status = 'y' WHERE tenant_id = $1"
        with pytest.raises(asyncpg.exceptions.ReadOnlySQLTransactionError):
            await guard.execute_async(conn, upd, {"tenant_id": "acme"}, verifier=fv)
    finally:
        await conn.close()


@pytest.mark.integration
async def test_psycopg_async(pg_dsn):
    import psycopg

    async with await psycopg.AsyncConnection.connect(pg_dsn) as conn:
        r = await guard.execute_async(conn, SQL_OK, {"tenant_id": "acme"},
                                      verifier=FakeVerifier(decide), max_rows=2)
        assert [row[0] for row in r.rows] == [2, 4] and r.truncated


@pytest.mark.integration
def test_sqlalchemy_engine(pg_dsn):
    sqlalchemy = pytest.importorskip("sqlalchemy")
    url = "postgresql+psycopg://postgres:haltlab@127.0.0.1:5417/" + pg_dsn.split("dbname=")[1]
    engine = sqlalchemy.create_engine(url)
    try:
        r = guard.execute_on_engine(engine, SQL_OK, {"tenant_id": "acme"},
                                    verifier=FakeVerifier(decide), max_rows=1)
        assert r.rows == [(2, "open")]
    finally:
        engine.dispose()


def test_authorize_then_execute_with_verdict():
    fv = FakeVerifier(decide)
    v = guard.authorize(SQL_OK, {"tenant_id": "acme"}, verifier=fv)
    assert v.allowed and v.bind_args() == ["acme"]
    with pytest.raises(QueryDenied):
        guard.authorize(SQL_BAD, {"tenant_id": "acme"}, verifier=fv)
    # a verdict for another string is refused before the connection is used
    with pytest.raises(HaltSQLUnavailable, match="sql_sha256"):
        guard.execute(Untouchable(), SQL_OK + " ", {"tenant_id": "acme"}, verdict=v)
    denied = make_verdict(SQL_OK, allowed=False, codes=["E_X"])
    with pytest.raises(QueryDenied):
        guard.execute(Untouchable(), SQL_OK, {"tenant_id": "acme"}, verdict=denied)


def test_execute_on_engine_verifies_before_taking_a_connection():
    class NoPool:
        def raw_connection(self):
            raise AssertionError("pool used before verification")

    with pytest.raises(QueryDenied):
        guard.execute_on_engine(NoPool(), SQL_BAD, {"tenant_id": "a"}, verifier=FakeVerifier(decide))


async def test_authorize_async_with_async_verifier():
    class AsyncV:
        async def verify(self, sql, context=None):
            return make_verdict(sql, allowed=True, bind=[context["tenant_id"]])

    v = await guard.authorize_async(SQL_OK, {"tenant_id": "z"}, verifier=AsyncV())
    assert v.bind_args() == ["z"]
