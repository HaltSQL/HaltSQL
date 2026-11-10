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
