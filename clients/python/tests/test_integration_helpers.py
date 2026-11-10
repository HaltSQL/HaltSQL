"""haltsql.integration: context resolution and verify-before-run checks."""

import pytest

from haltsql import GuardError, HaltSQLUnavailable, QueryDenied, agent_core
from haltsql.integration import (
    ContextUnavailable,
    authorize_guarded,
    feedback_for_model,
    guard_read_only,
    resolve_context,
)
from haltsql.testing import FakeVerifier, make_verdict_dict


def kinds(sql, ctx, _p):
    if "deny" in sql:
        return make_verdict_dict(sql, allowed=False, codes=["E_X"])
    kind = None if sql.startswith("VALUES") else sql.split()[0].lower()
    return make_verdict_dict(sql, allowed=True, statement_kind=kind)


def test_resolve_context_refuses_none():
    assert resolve_context({"tenant_id": "a"}) == {"tenant_id": "a"}
    assert resolve_context(lambda: {}) == {}
    with pytest.raises(ContextUnavailable):
        resolve_context(None)
    with pytest.raises(ContextUnavailable):
        resolve_context(lambda: None)
    assert agent_core.ContextUnavailable is ContextUnavailable


def test_authorize_guarded():
    fv = FakeVerifier(kinds)
    ctx, v = authorize_guarded("SELECT 1", lambda: {"t": "a"}, verifier=fv)
    assert ctx == {"t": "a"} and v.statement_kind == "select"
    with pytest.raises(GuardError, match="only SELECT"):
        authorize_guarded("DELETE FROM t", {}, verifier=fv)
    assert authorize_guarded("DELETE FROM t", {}, verifier=fv, read_only=False)[1].statement_kind == "delete"
    with pytest.raises(GuardError, match="statement kind"):
        authorize_guarded("VALUES (1)", {}, verifier=fv, read_only=False)
    with pytest.raises(QueryDenied):
        authorize_guarded("SELECT deny", {}, verifier=fv)
    calls = len(fv.calls)
    with pytest.raises(ContextUnavailable):
        authorize_guarded("SELECT 1", lambda: None, verifier=fv)

    def boom():
        raise KeyError("tenant")

    with pytest.raises(HaltSQLUnavailable):
        authorize_guarded("SELECT 1", boom, verifier=fv)
    with pytest.raises(HaltSQLUnavailable):
        authorize_guarded("SELECT 1", lambda: "not a mapping", verifier=fv)
    assert len(fv.calls) == calls


def test_guard_read_only_and_feedback():
    assert guard_read_only(True) is True and guard_read_only(False) is None
    assert feedback_for_model(ContextUnavailable("x")).startswith("No trusted HaltSQL context")
    assert feedback_for_model(HaltSQLUnavailable("x")).startswith("SQL verification is unavailable")


def test_resolve_context_validates():
    for bad in ({"tenant_id": 1.5}, {"tenant_id": None}, {"": "a"}, ["tenant_id"], "acme"):
        with pytest.raises(ValueError):
            resolve_context(bad)
        with pytest.raises(ValueError):
            resolve_context(lambda: bad)
    src = {"tenant_id": "a", "roles": ("x", "y")}
    out = resolve_context(src)
    assert out == {"tenant_id": "a", "roles": ["x", "y"]} and out is not src


def test_authorize_guarded_failure_names_only_the_exception_type():
    def boom():
        raise RuntimeError("session store postgresql://app:s3cret@db/app is down")

    fv = FakeVerifier(kinds)
    with pytest.raises(HaltSQLUnavailable) as ei:
        authorize_guarded("SELECT 1", boom, verifier=fv)
    assert str(ei.value) == "could not verify the query (RuntimeError)"
    assert fv.calls == []


def test_feedback_for_model_texts():
    from haltsql import HaltSQLError, HaltSQLRequestError
    from haltsql.models import Verdict

    secret = "postgresql://app:s3cret@db.internal/app Bearer tok-123"
    unavailable = "SQL verification is unavailable; the query was not executed."
    assert feedback_for_model(HaltSQLUnavailable(secret)) == unavailable
    assert feedback_for_model(HaltSQLRequestError(secret, status=401, code="UNAUTHORIZED")) == unavailable
    assert feedback_for_model(HaltSQLError(secret)) == "The query was not executed."
    assert feedback_for_model(ContextUnavailable(secret)) == (
        "No trusted HaltSQL context is configured for this request; the query was not executed.")
    denied = QueryDenied(Verdict.from_dict(make_verdict_dict("SELECT 1", allowed=False, codes=["E_A", "E_B"])))
    assert feedback_for_model(denied) == (
        "HaltSQL denied the query; it was not executed. Fix the SQL and retry:\n"
        "- E_A: fix E_A\n- E_B: fix E_B")

    class ServerError(Exception):
        """Shaped like a psycopg / asyncpg server error: it has an SQLSTATE."""

        sqlstate = "42703"

    multi = ServerError('column "emial" does not exist\nLINE 1: SELECT emial FROM customers\n               ^')
    assert feedback_for_model(multi) == 'Database error: ServerError: column "emial" does not exist'
    assert feedback_for_model(ServerError()) == "Database error: ServerError"

    class ConnectError(Exception):
        """Shaped like a failed psycopg connect: no SQLSTATE."""

        sqlstate = None

    # No SQLSTATE: the text can name hosts, roles or a whole DSN, so only the type is given.
    for exc in (ConnectError(f'connection to server at "db.internal" failed for user "app": {secret}'),
                RuntimeError(secret), OSError(111, secret)):
        out = feedback_for_model(exc)
        assert out == f"Database error: {type(exc).__name__}"
