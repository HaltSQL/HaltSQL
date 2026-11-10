"""Transport hardening: TLS options, response size cap, error wrapping, secrets."""

import gzip
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from haltsql import AsyncHaltSQLClient, HaltSQLClient, HaltSQLRequestError, HaltSQLUnavailable, RetryPolicy
from haltsql.client import _ssl_context
from haltsql.testing import make_verdict_dict

SQL = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"
TOKEN = "s3cret-token-do-not-leak"
FAST = RetryPolicy(max_attempts=2, backoff_base=0.001, backoff_max=0.01)


# ---- response size cap ------------------------------------------------------


def test_oversized_response_fails_closed():
    def handler(request):
        return httpx.Response(200, content=b"{" + b" " * 5000 + b"}")

    with HaltSQLClient(
        "http://sidecar", transport=httpx.MockTransport(handler), max_response_bytes=1024
    ) as c:
        with pytest.raises(HaltSQLUnavailable, match="larger than 1024 bytes"):
            c.verify(SQL, {"tenant_id": "a"})


def test_declared_oversized_response_fails_closed():
    def handler(request):
        return httpx.Response(200, headers={"content-length": "99999999"}, content=b"{}")

    with HaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(HaltSQLUnavailable, match="larger than"):
            c.verify(SQL, {"tenant_id": "a"})


async def test_async_oversized_response_fails_closed():
    def handler(request):
        return httpx.Response(200, content=b"x" * 4096)

    async with AsyncHaltSQLClient(
        "http://sidecar", transport=httpx.MockTransport(handler), max_response_bytes=100
    ) as c:
        with pytest.raises(HaltSQLUnavailable, match="larger than 100 bytes"):
            await c.verify(SQL, {"tenant_id": "a"})


def test_gzip_response_is_decoded_once():
    def handler(request):
        body = json.loads(request.content)
        raw = json.dumps(make_verdict_dict(body["sql"], allowed=True, bind=["a"])).encode()
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=gzip.compress(raw))

    with HaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler)) as c:
        assert c.verify(SQL, {"tenant_id": "a"}).allowed


@pytest.mark.parametrize("n", [0, -1, 1.5])
def test_bad_max_response_bytes(n):
    with pytest.raises(ValueError):
        HaltSQLClient("http://sidecar", max_response_bytes=n)


# ---- error wrapping and secrets --------------------------------------------


def test_non_transport_httpx_error_is_wrapped_and_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        # Claims gzip but is not: httpx raises DecodingError (not a TransportError).
        return httpx.Response(200, headers={"content-encoding": "gzip"}, content=b"not gzip")

    with HaltSQLClient(
        "http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler), retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable, match="DecodingError") as ei:
            c.verify(SQL, {"tenant_id": "a"})
    assert len(calls) == 1
    assert ei.value.__cause__ is None
    assert TOKEN not in str(ei.value)


def test_transport_error_never_carries_the_token():
    def handler(request):
        raise httpx.ConnectError(f"boom {request.headers['authorization']}", request=request)

    with HaltSQLClient(
        "http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler), retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable) as ei:
            c.verify(SQL, {"tenant_id": "a"})
    err = ei.value
    assert TOKEN not in str(err) and TOKEN not in repr(err)
    assert err.__cause__ is None
    assert TOKEN not in repr(c)


def test_redirects_are_not_followed():
    def handler(request):
        return httpx.Response(307, headers={"location": "http://evil.example/v1/verify"})

    with HaltSQLClient(
        "http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler), retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable):
            c.verify(SQL, {"tenant_id": "a"})


def test_default_timeout_is_set():
    c = HaltSQLClient("http://sidecar")
    try:
        assert c.timeout.connect == 2.0 and c.timeout.read == 2.0
    finally:
        c.close()


# ---- TLS options ------------------------------------------------------------


def test_ssl_context_helper():
    assert _ssl_context(True, None) is True
    assert _ssl_context(False, None) is False
    ctx = ssl.create_default_context()
    assert _ssl_context(ctx, None) is ctx
    import certifi

    built = _ssl_context(certifi.where(), None)
    assert isinstance(built, ssl.SSLContext)
    assert built.verify_mode == ssl.CERT_REQUIRED and built.check_hostname
    assert built.cert_store_stats()["x509_ca"] > 0
    with pytest.raises(ValueError):
        _ssl_context(False, "client.pem")
    with pytest.raises(ValueError):
        _ssl_context(ctx, "client.pem")
    with pytest.raises(TypeError):
        _ssl_context(123, None)
    with pytest.raises(FileNotFoundError):
        _ssl_context("/nonexistent/ca.pem", None)


def test_tls_options_conflict_with_http_client():
    hc = httpx.Client()
    try:
        with pytest.raises(ValueError):
            HaltSQLClient("https://sidecar", http_client=hc, verify="/tmp/ca.pem")
        with pytest.raises(ValueError):
            HaltSQLClient("https://sidecar", http_client=hc, cert="/tmp/c.pem")
    finally:
        hc.close()


def test_from_env_tls(monkeypatch):
    import certifi

    monkeypatch.setenv("HALTSQL_URL", "https://sidecar")
    monkeypatch.setenv("HALTSQL_CA_FILE", certifi.where())
    with HaltSQLClient.from_env() as c:
        assert c.base_url == "https://sidecar"
    monkeypatch.setenv("HALTSQL_CLIENT_KEY", "/tmp/key.pem")
    with pytest.raises(ValueError, match="HALTSQL_CLIENT_CERT"):
        HaltSQLClient.from_env()


@pytest.fixture(scope="module")
def tls_sidecar(tmp_path_factory):
    """A tiny HTTPS sidecar with a self-signed certificate for 127.0.0.1."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True,
    )
    if r.returncode != 0:
        pytest.skip("openssl could not create a test certificate")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(n))
            out = json.dumps(make_verdict_dict(body["sql"], allowed=True, bind=["a"])).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):  # silence
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(cert), str(key))
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", str(cert)
    srv.shutdown()
    srv.server_close()


def test_untrusted_certificate_fails_closed(tls_sidecar):
    url, _ = tls_sidecar
    with HaltSQLClient(url, retry=RetryPolicy(max_attempts=1)) as c:
        with pytest.raises(HaltSQLUnavailable):
            c.verify(SQL, {"tenant_id": "a"})


def test_custom_ca_bundle_is_trusted(tls_sidecar):
    url, ca = tls_sidecar
    with HaltSQLClient(url, verify=ca, retry=RetryPolicy(max_attempts=1)) as c:
        assert c.verify(SQL, {"tenant_id": "a"}).allowed


async def test_async_custom_ca_bundle_is_trusted(tls_sidecar):
    url, ca = tls_sidecar
    async with AsyncHaltSQLClient(url, verify=ca, retry=RetryPolicy(max_attempts=1)) as c:
        assert (await c.verify(SQL, {"tenant_id": "a"})).allowed


# ---- only a direct 200 answer is a verdict ------------------------------------


def _allow(request):
    body = json.loads(request.content)
    return make_verdict_dict(body["sql"], allowed=True, bind=["a"])


@pytest.mark.parametrize("status", [201, 202, 203, 206, 226, 300, 301, 302, 303, 304, 307, 308])
async def test_non_200_with_an_allow_body_is_not_a_verdict(status):
    """A well-formed "allowed" body under any status but 200 (a cache, a proxy,
    a redirect page) never becomes a verdict."""

    def handler(request):
        return httpx.Response(status, json=_allow(request))

    with HaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler), retry=FAST) as c:
        with pytest.raises(HaltSQLUnavailable) as ei:
            c.verify(SQL, {"tenant_id": "a"})
        assert ei.value.status == status
        with pytest.raises(HaltSQLUnavailable):
            c.check(SQL, {"tenant_id": "a"})
    async with AsyncHaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler), retry=FAST) as c:
        with pytest.raises(HaltSQLUnavailable) as ei:
            await c.verify(SQL, {"tenant_id": "a"})
        assert ei.value.status == status


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_redirect_target_is_never_contacted(status):
    """Following a redirect would send the SQL, the context and the bearer token
    to whoever the Location header names, and take that host's answer as the verdict."""
    elsewhere = []

    def handler(request):
        if request.url.host != "sidecar":
            elsewhere.append((str(request.url), request.headers.get("authorization")))
            return httpx.Response(200, json=_allow(request))
        return httpx.Response(status, headers={"location": "http://evil.example/v1/verify"})

    with HaltSQLClient(
        "http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler), retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable):
            c.verify(SQL, {"tenant_id": "a"})
        with pytest.raises(HaltSQLUnavailable):
            c.policies()
    async with AsyncHaltSQLClient(
        "http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler), retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable):
            await c.verify(SQL, {"tenant_id": "a"})
        with pytest.raises(HaltSQLUnavailable):
            await c.policies()
    assert elsewhere == []


async def test_undeclared_oversized_body_is_cut_off_while_streaming():
    """No Content-Length (chunked) or one that understates the body: the cap is
    enforced on the bytes actually received."""
    produced = []

    def chunks():
        for _ in range(64):
            produced.append(1)
            yield b" " * 1024

    async def achunks():
        for c in chunks():
            yield c

    def chunked(request):
        return httpx.Response(200, content=chunks())

    def understated(request):
        return httpx.Response(200, headers={"content-length": "10"}, stream=httpx.ByteStream(b" " * 5000))

    for handler in (chunked, understated):
        with HaltSQLClient(
            "http://sidecar", transport=httpx.MockTransport(handler), max_response_bytes=2048, retry=FAST
        ) as c:
            with pytest.raises(HaltSQLUnavailable, match="larger than 2048 bytes"):
                c.verify(SQL, {"tenant_id": "a"})
    assert len(produced) <= 8  # reading stopped at the cap, not after 64 KiB
    produced.clear()

    def achunked(request):
        return httpx.Response(200, content=achunks())

    async with AsyncHaltSQLClient(
        "http://sidecar", transport=httpx.MockTransport(achunked), max_response_bytes=2048, retry=FAST
    ) as c:
        with pytest.raises(HaltSQLUnavailable, match="larger than 2048 bytes"):
            await c.verify(SQL, {"tenant_id": "a"})
    assert len(produced) <= 8


@pytest.mark.parametrize("status,exc", [(401, HaltSQLRequestError), (403, HaltSQLRequestError),
                                        (500, HaltSQLUnavailable), (203, HaltSQLUnavailable)])
async def test_policies_and_health_require_200(status, exc):
    listing = {"policies": [{"name": "saas", "version": "sha256:" + "0" * 64, "mode": "enforce"}],
               "status": "ready"}

    def handler(request):
        return httpx.Response(status, json=listing)

    one = RetryPolicy(max_attempts=1)
    with HaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler), retry=one) as c:
        for call in (c.policies, c.healthz, c.readyz):
            with pytest.raises(exc):
                call()
        assert c.is_ready() is False
    async with AsyncHaltSQLClient("http://sidecar", transport=httpx.MockTransport(handler), retry=one) as c:
        for call in (c.policies, c.healthz, c.readyz):
            with pytest.raises(exc):
                await call()
        assert await c.is_ready() is False


def test_request_id_is_validated_before_sending():
    """A request id goes into a header: line breaks or control characters are refused."""
    sent = []

    def handler(request):
        sent.append(request.headers.get("x-request-id"))
        return httpx.Response(200, json=_allow(request))

    with HaltSQLClient("http://sidecar", token=TOKEN, transport=httpx.MockTransport(handler)) as c:
        for bad in ("a\r\nX-Injected: 1", "a\nb", "tab\there", "nul\x00", "x" * 201, 5, b"abc"):
            with pytest.raises(ValueError, match="request_id"):
                c.verify(SQL, {"tenant_id": "a"}, request_id=bad)
        assert sent == []
        assert c.verify(SQL, {"tenant_id": "a"}, request_id="req-1").allowed
    assert sent == ["req-1"]
