"""HaltSQLTools without the MCP layer."""

import datetime as dt
import decimal
import uuid

import pytest

from haltsql import AsyncHaltSQLClient, HaltSQLUnavailable, RetryPolicy
from haltsql.testing import FakeVerifier, make_verdict
from haltsql_mcp import HaltSQLTools, ToolFailure, jsonable, summarize_policy
from haltsql_mcp.core import load_policy_document

from conftest import SAAS_POLICY, decide

OK = "SELECT id, total_cents, created_at FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50"
BAD = "SELECT id FROM orders LIMIT 5"


async def never_connect():
    raise AssertionError("must not connect to the database")


def tools(**kw):
    kw.setdefault("connect", never_connect)
    return HaltSQLTools(FakeVerifier(decide), lambda: {"tenant_id": "acme"}, **kw)


async def test_denied_query_returns_reasons_without_connecting():
    t = tools()
    out = await t.query(BAD)
    assert out["allowed"] is False and out["executed"] is False
    assert [r["code"] for r in out["reasons"]] == ["E_TENANT_MISSING"]
    assert out["reasons"][0]["hint"] == "fix E_TENANT_MISSING"


async def test_context_comes_only_from_provider():
    fv = FakeVerifier(decide)
    t = HaltSQLTools(fv, lambda: {"tenant_id": "acme"}, connect=never_connect)
    await t.explain_denial(BAD)
    assert fv.calls == [(BAD, {"tenant_id": "acme"})]


async def test_unauthenticated_session_is_refused():
    def provider():
        raise PermissionError("not authenticated")

    fv = FakeVerifier(decide)
    t = HaltSQLTools(fv, provider, connect=never_connect, policy_file=SAAS_POLICY)
    for coro in (t.query(OK), t.explain_denial(OK), t.list_tables(), t.describe_policy()):
        with pytest.raises(ToolFailure, match="not authenticated"):
            await coro
    assert fv.calls == []


async def test_sidecar_down_fails_closed():
    class Down:
        async def verify(self, sql, ctx=None):
            raise HaltSQLUnavailable("connection refused to 10.0.0.1")

    t = HaltSQLTools(Down(), lambda: {"tenant_id": "a"}, connect=never_connect)
    with pytest.raises(ToolFailure, match="verification is unavailable; the query was not executed"):
        await t.query(OK)


async def test_unexpected_verifier_exception_fails_closed_without_details():
    class Broken:
        async def verify(self, sql, ctx=None):
            raise RuntimeError("secret internal detail")

    t = HaltSQLTools(Broken(), lambda: {"tenant_id": "a"}, connect=never_connect)
    with pytest.raises(ToolFailure, match="verification failed; the query was not executed") as ei:
        await t.query(OK)
    assert "secret" not in str(ei.value)


async def test_real_http_client_against_dead_port_fails_closed():
    client = AsyncHaltSQLClient("http://127.0.0.1:9", retry=RetryPolicy(max_attempts=1))
    t = HaltSQLTools(client, lambda: {"tenant_id": "a"}, connect=never_connect)
    with pytest.raises(ToolFailure, match="unavailable"):
        await t.query(OK)
    await client.aclose()


async def test_forged_verdict_for_other_sql_is_refused():
    fv = FakeVerifier(lambda s, c, p: make_verdict("SELECT 1", allowed=True))
    t = HaltSQLTools(fv, lambda: {}, connect=never_connect)
    with pytest.raises(ToolFailure, match="invalid verdict"):
        await t.query(OK)


@pytest.mark.parametrize("sql", ["", "   ", None, 5, "x" * 100_001])
async def test_sql_validation(sql):
    with pytest.raises(ToolFailure):
        await tools().query(sql)


async def test_no_database_configured():
    t = HaltSQLTools(FakeVerifier(decide), lambda: {"tenant_id": "a"})
    with pytest.raises(ToolFailure, match="no database"):
        await t.query(OK)


async def test_set_config_requires_context_key():
    t = tools(set_config={"app.tenant_id": "missing_key"})
    with pytest.raises(ToolFailure, match="misconfigured"):
        await t.query(OK)


async def test_explain_denial_allowed_and_denied():
    t = tools()
    d = await t.explain_denial(BAD)
    assert d["allowed"] is False and d["policy"]["name"] == "saas"
    a = await t.explain_denial(OK)
    assert a["allowed"] is True and a["reasons"] == [] and "allowed" in a["message"]


async def test_list_tables_and_describe_policy_from_file(fake_sidecar):
    client = AsyncHaltSQLClient(fake_sidecar.url, "sidecar-token")
    t = HaltSQLTools(client, lambda: {"tenant_id": "acme"}, policy_file=SAAS_POLICY,
                     policies_lister=client.policies)
    lt = await t.list_tables()
    names = [x["table"] for x in lt["tables"]]
    assert "app.orders" in names and "app.api_keys" not in names
    customers = next(x for x in lt["tables"] if x["table"] == "app.customers")
    assert "email" not in customers["columns"] and customers["tenant_scoped"] is True
    assert customers["tenant_columns"] == {"tenant_id": "tenant"}
    currencies = next(x for x in lt["tables"] if x["table"] == "app.currencies")
    assert currencies["tenant_scoped"] is False and currencies["columns"] == "*"
    assert "$1" in lt["guidance"]
    dp = await t.describe_policy()
    assert dp["policies"] == [{"name": "saas", "version": "sha256:" + "a" * 64, "mode": "enforce"}]
    assert dp["policy"]["name"] == "saas"
    assert dp["policy"]["tenancy"] == {"mode": "bound", "keys": ["tenant"]}
    assert dp["policy"]["require_limit"] == {"max": 1000}
    assert dp["policy"]["statements"] == ["select"]
    await client.aclose()


async def test_describe_policy_sidecar_down_still_reports_file():
    client = AsyncHaltSQLClient("http://127.0.0.1:9", retry=RetryPolicy(max_attempts=1))
    t = HaltSQLTools(client, lambda: {}, policy_file=SAAS_POLICY, policies_lister=client.policies)
    dp = await t.describe_policy()
    assert "policies_error" in dp and dp["policy"]["name"] == "saas"
    await client.aclose()


def test_summarize_policy_never_includes_context_values():
    doc = load_policy_document(SAAS_POLICY)
    s = summarize_policy(doc)
    assert "${ctx" not in repr(s)


def test_jsonable():
    assert jsonable(decimal.Decimal("1.50")) == "1.50"
    assert jsonable(dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)) == "2026-01-02T03:04:05+00:00"
    assert jsonable(dt.date(2026, 1, 2)) == "2026-01-02"
    assert jsonable(dt.timedelta(seconds=90)) == 90.0
    u = uuid.UUID(int=1)
    assert jsonable(u) == str(u)
    assert jsonable(b"\x00\x01") == {"base64": "AAE="}
    assert jsonable({"a": [1, decimal.Decimal("2")]}) == {"a": [1, "2"]}
    assert jsonable(float("nan")) == "nan"
    assert jsonable("x" * 10_001).endswith("...[truncated]")


async def test_shadow_would_deny_is_not_executed_without_opt_in(monkeypatch):
    from haltsql import guard

    monkeypatch.delenv("HALTSQL_ALLOW_SHADOW", raising=False)
    guard.set_allow_shadow(None)
    fv = FakeVerifier(lambda sql, ctx, p: make_verdict(sql, allowed=True, shadow_codes=["E_TENANT_MISSING"]))
    t = HaltSQLTools(fv, lambda: {"tenant_id": "acme"}, connect=never_connect)
    out = await t.query(BAD)
    assert out["allowed"] is False and out["executed"] is False
    assert [r["code"] for r in out["reasons"]] == ["E_TENANT_MISSING"]
