"""HaltSQLClient / AsyncHaltSQLClient against the in-process fake sidecar."""

import socket
import time

import httpx
import pytest

from haltsql import (
    AsyncHaltSQLClient,
    HaltSQLClient,
    HaltSQLRequestError,
    HaltSQLUnavailable,
    QueryDenied,
    RetryPolicy,
)
from haltsql.testing import FakeSidecar, make_verdict_dict

SQL_OK = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
SQL_BAD = "SELECT id FROM orders LIMIT 10"
TOKEN = "s3cret-token"
FAST = RetryPolicy(max_attempts=3, backoff_base=0.001, backoff_max=0.01)


def decide(sql, ctx, policy):
    if "tenant_id = $1" in sql:
        return make_verdict_dict(sql, allowed=True, bind=[ctx["tenant_id"]])
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])


@pytest.fixture
def fake():
    with FakeSidecar(decide, token=TOKEN) as f:
        yield f


@pytest.fixture
def client(fake):
    with HaltSQLClient(fake.url, token=TOKEN, retry=FAST, timeout=1.0) as c:
        yield c


def test_verify_allowed_sends_exact_request(fake, client):
    v = client.verify(SQL_OK, {"tenant_id": "acme"}, request_id="rid-1")
    assert v.allowed is True
    assert v.bind_args() == ["acme"]
    assert v.request_id == "rid-1"
    req = fake.requests[-1]
    assert req.method == "POST" and req.path == "/v1/verify"
    assert req.body == {"sql": SQL_OK, "context": {"tenant_id": "acme"}}
    assert req.headers["authorization"] == f"Bearer {TOKEN}"
    assert req.headers["x-request-id"] == "rid-1"
    assert req.headers["user-agent"].startswith("haltsql-python/")


def test_verify_denied_is_a_result_and_check_raises(client):
    v = client.verify(SQL_BAD, {"tenant_id": "acme"})
    assert v.allowed is False and v.codes == ["E_TENANT_MISSING"]
    with pytest.raises(QueryDenied) as ei:
        client.check(SQL_BAD, {"tenant_id": "acme"})
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]


def test_policy_is_sent_when_configured(fake):
    with HaltSQLClient(fake.url, token=TOKEN, policy="saas") as c:
        c.verify(SQL_OK, {"tenant_id": "a"})
        assert fake.requests[-1].body["policy"] == "saas"
        c.verify(SQL_OK, {"tenant_id": "a"}, policy="other")
        assert fake.requests[-1].body["policy"] == "other"


def test_bad_token_raises_request_error_without_retry(fake):
    with HaltSQLClient(fake.url, token="wrong", retry=FAST) as c:
        with pytest.raises(HaltSQLRequestError) as ei:
            c.verify(SQL_OK, {"tenant_id": "a"})
    assert ei.value.status == 401 and ei.value.code == "UNAUTHORIZED"
    assert len(fake.requests) == 1
    assert "wrong" not in str(ei.value)


def test_503_is_retried_then_succeeds(fake, client):
    fake.push(503, {"error": {"code": "NOT_READY", "message": "no policy"}})
    fake.push(503, {"error": {"code": "AUDIT_UNAVAILABLE", "message": "audit"}})
    v = client.verify(SQL_OK, {"tenant_id": "acme"})
    assert v.allowed is True
    assert len(fake.requests) == 3


def test_503_exhausted_raises_unavailable(fake, client):
    for _ in range(3):
        fake.push(503, {"error": {"code": "AUDIT_UNAVAILABLE", "message": "audit"}})
    with pytest.raises(HaltSQLUnavailable) as ei:
        client.verify(SQL_OK, {"tenant_id": "acme"})
    assert ei.value.status == 503 and ei.value.code == "AUDIT_UNAVAILABLE"
    assert len(fake.requests) == 3


def test_500_not_retried_and_unavailable(fake, client):
    fake.push(500, {"error": {"code": "INTERNAL", "message": "boom"}})
    with pytest.raises(HaltSQLUnavailable) as ei:
        client.verify(SQL_OK, {"tenant_id": "acme"})
    assert ei.value.status == 500 and len(fake.requests) == 1


def test_retry_after_is_honoured_but_capped(fake):
    fake.push(503, {"error": {"code": "NOT_READY", "message": ""}}, headers={"Retry-After": "100"})
    with HaltSQLClient(fake.url, token=TOKEN,
                       retry=RetryPolicy(max_attempts=2, backoff_base=0.001, backoff_max=0.05)) as c:
        t = time.monotonic()
        assert c.verify(SQL_OK, {"tenant_id": "a"}).allowed
        assert time.monotonic() - t < 2


def test_timeout_raises_unavailable(fake):
    fake.push(200, make_verdict_dict(SQL_OK, allowed=True, bind=["a"]), delay=0.6)
    fake.push(200, make_verdict_dict(SQL_OK, allowed=True, bind=["a"]), delay=0.6)
    with HaltSQLClient(fake.url, token=TOKEN, timeout=0.2,
                       retry=RetryPolicy(max_attempts=2, backoff_base=0.001)) as c:
        with pytest.raises(HaltSQLUnavailable, match="after 2 attempt"):
            c.verify(SQL_OK, {"tenant_id": "a"})


def test_connection_refused_raises_unavailable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with HaltSQLClient(f"http://127.0.0.1:{port}", retry=FAST) as c:
        with pytest.raises(HaltSQLUnavailable):
            c.verify(SQL_OK, {"tenant_id": "a"})


def test_hash_mismatch_fails_closed(fake, client):
    fake.push(200, make_verdict_dict("SELECT 1", allowed=True))
    with pytest.raises(HaltSQLUnavailable, match="sql_sha256"):
        client.verify(SQL_OK, {"tenant_id": "a"})


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[]", b'{"allowed": "yes"}', b'{"allowed": true}'],
)
def test_malformed_200_fails_closed(fake, client, raw):
    fake.push(200, raw=raw)
    with pytest.raises(HaltSQLUnavailable):
        client.verify(SQL_OK, {"tenant_id": "a"})


def test_invalid_context_rejected_before_sending(fake, client):
    with pytest.raises(ValueError):
        client.verify(SQL_OK, {"tenant_id": True})
    assert fake.requests == []


def test_policies_health_ready(fake, client):
    pols = client.policies()
    assert [(p.name, p.mode) for p in pols] == [("test", "enforce")]
    assert client.healthz() == {"status": "ok"}
    assert client.readyz()["status"] == "ready"
    fake.ready = False
    assert client.is_ready() is False
    with pytest.raises(HaltSQLUnavailable):
        client.readyz()


def test_repr_hides_token(client):
    assert TOKEN not in repr(client) and "<redacted>" in repr(client)


@pytest.mark.parametrize("url", ["ftp://x", "127.0.0.1:8080", "http://h/?q=1"])
def test_bad_base_url(url):
    with pytest.raises(ValueError):
        HaltSQLClient(url)


def test_bad_token_rejected():
    with pytest.raises(ValueError):
        HaltSQLClient("http://127.0.0.1:1", token="a\r\nX-Evil: 1")


def test_from_env(monkeypatch, fake):
    monkeypatch.setenv("HALTSQL_URL", fake.url)
    monkeypatch.setenv("HALTSQL_TOKEN", TOKEN)
    monkeypatch.setenv("HALTSQL_TIMEOUT", "1.5")
    monkeypatch.setenv("HALTSQL_POLICY", "saas")
    with HaltSQLClient.from_env() as c:
        assert c.timeout.read == 1.5
        assert c.verify(SQL_OK, {"tenant_id": "a"}).allowed
        assert fake.requests[-1].body["policy"] == "saas"


def test_mock_transport_never_allows_on_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    with HaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler), retry=FAST) as c:
        with pytest.raises(HaltSQLUnavailable, match="ConnectError"):
            c.verify(SQL_OK, {})


# ---- async ----------------------------------------------------------------


async def test_async_allowed_and_denied(fake):
    async with AsyncHaltSQLClient(fake.url, token=TOKEN, retry=FAST) as c:
        v = await c.verify(SQL_OK, {"tenant_id": "acme"})
        assert v.allowed and v.bind_args() == ["acme"]
        with pytest.raises(QueryDenied):
            await c.check(SQL_BAD, {"tenant_id": "acme"})
        assert [p.name for p in await c.policies()] == ["test"]
        assert await c.is_ready() is True


async def test_async_retries_and_fails_closed(fake):
    fake.push(503, {"error": {"code": "NOT_READY", "message": ""}})
    async with AsyncHaltSQLClient(fake.url, token=TOKEN, retry=FAST) as c:
        assert (await c.verify(SQL_OK, {"tenant_id": "a"})).allowed
        for _ in range(3):
            fake.push(503, {"error": {"code": "NOT_READY", "message": ""}})
        with pytest.raises(HaltSQLUnavailable):
            await c.verify(SQL_OK, {"tenant_id": "a"})
        fake.push(403, {"error": {"code": "FORBIDDEN", "message": "pinned"}})
        with pytest.raises(HaltSQLRequestError) as ei:
            await c.verify(SQL_OK, {"tenant_id": "a"}, policy="x")
        assert ei.value.code == "FORBIDDEN"
