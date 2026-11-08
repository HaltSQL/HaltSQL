"""HTTP clients for the ``haltsql-server`` sidecar (``docs/http-api.md``).

Both clients fail closed: a verdict is returned only when the sidecar answered
``200`` with a well-formed verdict for exactly the SQL that was sent. Everything
else raises (:class:`HaltSQLUnavailable` or :class:`HaltSQLRequestError`).
Denials are *not* exceptions in :meth:`HaltSQLClient.verify`; use
:meth:`HaltSQLClient.check` to raise :class:`QueryDenied` instead.
"""

from __future__ import annotations

import asyncio
import os
import random
import ssl
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Union
from urllib.parse import urlsplit

import httpx

from ._version import __version__
from .errors import HaltSQLRequestError, HaltSQLUnavailable
from .models import Context, PolicyInfo, Verdict, validate_context

__all__ = ["RetryPolicy", "HaltSQLClient", "AsyncHaltSQLClient", "TLSVerify", "TLSCert"]

_RETRY_STATUSES = frozenset({502, 503, 504})
_USER_AGENT = f"haltsql-python/{__version__}"
_DEFAULT_MAX_RESPONSE_BYTES = 8 << 20

#: What ``verify=`` accepts: ``True`` (system CAs, the default), a CA bundle
#: path, or a ready :class:`ssl.SSLContext`. ``False`` disables certificate
#: verification and is only for local testing.
TLSVerify = Union[bool, str, "os.PathLike[str]", ssl.SSLContext]
#: What ``cert=`` accepts for mutual TLS: a PEM file holding certificate and
#: key, or ``(cert_file, key_file)``.
TLSCert = Union[str, "os.PathLike[str]", "tuple[str, str]"]


@dataclass(frozen=True)
class RetryPolicy:
    """How transient failures are retried.

    Only connection errors, timeouts, and HTTP 502/503/504 are retried; a
    request that still fails after ``max_attempts`` raises
    :class:`HaltSQLUnavailable`. Verification is idempotent, so retrying a
    ``POST /v1/verify`` is safe.
    """

    max_attempts: int = 3
    """Total attempts including the first (1 disables retries)."""
    backoff_base: float = 0.05
    """Delay before the first retry, in seconds; doubles each retry."""
    backoff_max: float = 1.0
    """Upper bound for one delay (also caps a server ``Retry-After``)."""
    jitter: bool = True
    """Randomize each delay to 50-100% of its value."""

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.backoff_base < 0 or self.backoff_max < 0:
            raise ValueError("backoff values must be >= 0")

    def delay(self, retry_number: int, retry_after: Optional[float] = None) -> float:
        """Seconds to wait before retry number ``retry_number`` (1-based)."""
        if retry_after is not None:
            return max(0.0, min(float(retry_after), self.backoff_max))
        d = min(self.backoff_max, self.backoff_base * (2.0 ** (retry_number - 1)))
        if self.jitter:
            d *= 0.5 + random.random() / 2
        return d


def _check_base_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("base_url must be an absolute http:// or https:// URL")
    if parts.query or parts.fragment:
        raise ValueError("base_url must not contain a query or fragment")
    return url.rstrip("/")


def _check_token(token: Optional[str]) -> Optional[str]:
    if token is None or token == "":
        return None
    if not isinstance(token, str) or any(c in token for c in "\r\n\x00 \t"):
        raise ValueError("token must be a single printable word")
    return token


def _ssl_context(verify: Any, cert: Any) -> Union[bool, ssl.SSLContext]:
    """Build the ``verify=`` value for httpx.

    An :class:`ssl.SSLContext` is built here (instead of passing paths through)
    so that custom CA bundles and client certificates behave the same on every
    supported httpx version.
    """
    if isinstance(verify, ssl.SSLContext):
        if cert is not None:
            raise ValueError("pass the client certificate inside the SSLContext, not via cert=")
        return verify
    if verify is False:
        if cert is not None:
            raise ValueError("cert= requires certificate verification (verify must not be False)")
        return False
    if verify is True and cert is None:
        return True
    if verify is True:
        ctx = ssl.create_default_context()
    elif isinstance(verify, (str, os.PathLike)):
        ctx = ssl.create_default_context(cafile=os.fspath(verify))
    else:
        raise TypeError("verify must be a bool, a CA bundle path, or an ssl.SSLContext")
    if cert is not None:
        if isinstance(cert, tuple):
            if len(cert) != 2:
                raise ValueError("cert must be a path or a (cert_file, key_file) tuple")
            ctx.load_cert_chain(os.fspath(cert[0]), os.fspath(cert[1]))
        else:
            ctx.load_cert_chain(os.fspath(cert))
    return ctx


def _http_client_kwargs(
    http_client: Any, transport: Any, verify: Any, cert: Any
) -> Dict[str, Any]:
    if http_client is not None and (verify is not True or cert is not None):
        raise ValueError("configure TLS on the http_client you pass, not via verify=/cert=")
    if http_client is not None and transport is not None:
        raise ValueError("pass either transport= or http_client=, not both")
    return {"verify": _ssl_context(verify, cert)} if http_client is None else {}


def _retry_after(resp: httpx.Response) -> Optional[float]:
    value = resp.headers.get("retry-after")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _error_fields(resp: httpx.Response) -> "tuple[str, str]":
    """``(code, message)`` from an error body; never echoes request data."""
    try:
        body = resp.json()
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            code = err.get("code")
            msg = err.get("message")
            return (
                code if isinstance(code, str) else f"HTTP_{resp.status_code}",
                msg if isinstance(msg, str) else "",
            )
    except Exception:  # noqa: BLE001 - malformed error bodies are expected
        pass
    return (f"HTTP_{resp.status_code}", "")


class _Base:
    """Request building and response validation shared by both clients."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str],
        timeout: Union[float, httpx.Timeout],
        retry: Optional[RetryPolicy],
        policy: Optional[str],
        verify_sql_hash: bool,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")
        self.max_response_bytes = max_response_bytes
        self.base_url = _check_base_url(base_url)
        self._token = _check_token(token)
        self.timeout = timeout if isinstance(timeout, httpx.Timeout) else httpx.Timeout(timeout)
        self.retry = retry or RetryPolicy()
        self.policy = policy
        self.verify_sql_hash = verify_sql_hash

    def __repr__(self) -> str:  # never show the token
        auth = "token=<redacted>" if self._token else "token=None"
        return f"{type(self).__name__}(base_url={self.base_url!r}, {auth})"

    def _headers(self, request_id: Optional[str]) -> Dict[str, str]:
        h = {"Accept": "application/json", "User-Agent": _USER_AGENT}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if request_id is not None:
            if not isinstance(request_id, str) or not request_id.isprintable() or len(request_id) > 200:
                raise ValueError("request_id must be a printable string of at most 200 characters")
            h["X-Request-Id"] = request_id
        return h

    def _verify_body(
        self, sql: str, context: Optional[Context], policy: Optional[str]
    ) -> Dict[str, Any]:
        if not isinstance(sql, str):
            raise TypeError("sql must be a str")
        body: Dict[str, Any] = {"sql": sql, "context": validate_context(context)}
        pol = policy if policy is not None else self.policy
        if pol is not None:
            if not isinstance(pol, str) or not pol:
                raise ValueError("policy must be a non-empty string")
            body["policy"] = pol
        return body

    def _too_large(self, resp: httpx.Response) -> HaltSQLUnavailable:
        return HaltSQLUnavailable(
            f"haltsql response larger than {self.max_response_bytes} bytes",
            status=resp.status_code,
            request_id=resp.headers.get("x-request-id"),
        )

    def _declared_too_large(self, resp: httpx.Response) -> bool:
        cl = resp.headers.get("content-length")
        return cl is not None and cl.isdigit() and int(cl) > self.max_response_bytes

    @staticmethod
    def _buffered(resp: httpx.Response, chunks: List[bytes]) -> httpx.Response:
        # ``chunks`` are already decoded; drop the encoding headers so httpx
        # does not try to decode them a second time.
        headers = [
            (k, v)
            for k, v in resp.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")
        ]
        return httpx.Response(
            resp.status_code, headers=headers, content=b"".join(chunks), request=resp.request
        )

    @staticmethod
    def _unavailable(attempts: int, last: Optional[BaseException]) -> HaltSQLUnavailable:
        # Only the exception *type* is reported: httpx exceptions carry the
        # request (and so the Authorization header) and are never chained.
        return HaltSQLUnavailable(
            f"haltsql unavailable after {attempts} attempt(s): {type(last).__name__}"
        )

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        rid = resp.headers.get("x-request-id")
        code, msg = _error_fields(resp)
        if 400 <= resp.status_code < 500:
            raise HaltSQLRequestError(
                f"haltsql rejected the request: HTTP {resp.status_code} {code}"
                + (f": {msg}" if msg else ""),
                status=resp.status_code,
                code=code,
                request_id=rid,
            )
        raise HaltSQLUnavailable(
            f"haltsql unavailable: HTTP {resp.status_code} {code}" + (f": {msg}" if msg else ""),
            status=resp.status_code,
            code=code,
            request_id=rid,
        )

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except Exception as e:  # noqa: BLE001
            raise HaltSQLUnavailable(
                f"haltsql returned a non-JSON response: {type(e).__name__}",
                status=resp.status_code,
                request_id=resp.headers.get("x-request-id"),
            ) from None

    def _parse_verdict(self, resp: httpx.Response, sql: str) -> Verdict:
        if resp.status_code != 200:
            self._raise_for_status(resp)
        rid = resp.headers.get("x-request-id")
        data = self._json(resp)
        try:
            verdict = Verdict.from_dict(data, request_id=rid)
        except ValueError as e:
            raise HaltSQLUnavailable(
                f"haltsql returned a malformed verdict: {e}", status=200, request_id=rid
            ) from None
        if self.verify_sql_hash and not verdict.matches_sql(sql):
            raise HaltSQLUnavailable(
                "haltsql verdict is for a different SQL string (sql_sha256 mismatch)",
                status=200,
                request_id=rid,
            )
        return verdict

    @staticmethod
    def _parse_policies(data: Any) -> List[PolicyInfo]:
        if not isinstance(data, dict) or not isinstance(data.get("policies"), list):
            raise HaltSQLUnavailable("haltsql returned a malformed policy list")
        try:
            return [PolicyInfo.from_dict(p) for p in data["policies"]]
        except ValueError as e:
            raise HaltSQLUnavailable(f"haltsql returned a malformed policy list: {e}") from None


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        v = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number") from None
    if v <= 0:
        raise ValueError(f"{name} must be > 0")
    return v


def _env_kwargs() -> Dict[str, Any]:
    kw: Dict[str, Any] = {
        "base_url": os.environ.get("HALTSQL_URL") or "http://127.0.0.1:8080",
        "token": os.environ.get("HALTSQL_TOKEN") or None,
        "timeout": _env_float("HALTSQL_TIMEOUT", 2.0),
        "policy": os.environ.get("HALTSQL_POLICY") or None,
    }
    ca = os.environ.get("HALTSQL_CA_FILE")
    if ca:
        kw["verify"] = ca
    cert = os.environ.get("HALTSQL_CLIENT_CERT")
    key = os.environ.get("HALTSQL_CLIENT_KEY")
    if key and not cert:
        raise ValueError("HALTSQL_CLIENT_KEY is set without HALTSQL_CLIENT_CERT")
    if cert:
        kw["cert"] = (cert, key) if key else cert
    return kw


class HaltSQLClient(_Base):
    """Synchronous client for ``haltsql-server``.

    Example::

        with HaltSQLClient("http://127.0.0.1:8080", token=os.environ["HALTSQL_TOKEN"]) as hs:
            verdict = hs.check(sql, {"tenant_id": session.tenant_id})
            rows = conn.execute(sql, verdict.bind_args())  # via a RawCursor

    Args:
        base_url: Sidecar URL, e.g. ``http://127.0.0.1:8080``.
        token: Bearer token (pinned to one policy on the server).
        timeout: Per-attempt timeout in seconds (or an ``httpx.Timeout``).
        retry: Retry policy for transient failures.
        policy: Default policy name to send (optional with a token).
        verify_sql_hash: Check that each verdict's ``sql_sha256`` matches the
            SQL sent (default on; leave it on).
        verify: TLS server verification: ``True`` (system CAs, default), a CA
            bundle path for a private CA, or an :class:`ssl.SSLContext`.
        cert: Client certificate for mutual TLS: a PEM path (cert + key) or
            ``(cert_file, key_file)``.
        max_response_bytes: Largest response body accepted (default 8 MiB);
            a larger one raises :class:`HaltSQLUnavailable`.
        transport: Custom ``httpx`` transport (tests, proxies).
        http_client: A preconfigured ``httpx.Client``; it is not closed by
            :meth:`close`. Configure TLS and proxies on it directly.

    One client keeps a pool of keep-alive connections and is safe to share
    between threads; create it once and reuse it.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        token: Optional[str] = None,
        *,
        timeout: Union[float, httpx.Timeout] = 2.0,
        retry: Optional[RetryPolicy] = None,
        policy: Optional[str] = None,
        verify_sql_hash: bool = True,
        transport: Optional[httpx.BaseTransport] = None,
        http_client: Optional[httpx.Client] = None,
        verify: TLSVerify = True,
        cert: Optional[TLSCert] = None,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        super().__init__(
            base_url, token, timeout, retry, policy, verify_sql_hash, max_response_bytes
        )
        tls = _http_client_kwargs(http_client, transport, verify, cert)
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(
            timeout=self.timeout, transport=transport, follow_redirects=False, **tls
        )

    @classmethod
    def from_env(cls, **overrides: Any) -> "HaltSQLClient":
        """Build a client from ``HALTSQL_URL``, ``HALTSQL_TOKEN``,
        ``HALTSQL_TIMEOUT`` (seconds), ``HALTSQL_POLICY``, and for TLS
        ``HALTSQL_CA_FILE``, ``HALTSQL_CLIENT_CERT`` and ``HALTSQL_CLIENT_KEY``."""
        kw = _env_kwargs()
        kw.update(overrides)
        return cls(**kw)

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> "HaltSQLClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _send(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        request_id: Optional[str] = None,
        retry_statuses: "frozenset[int]" = _RETRY_STATUSES,
    ) -> httpx.Response:
        url = self.base_url + path
        headers = self._headers(request_id)
        last: Optional[BaseException] = None
        resp: Optional[httpx.Response] = None
        for attempt in range(1, self.retry.max_attempts + 1):
            if attempt > 1:
                time.sleep(
                    self.retry.delay(attempt - 1, _retry_after(resp) if resp is not None else None)
                )
            resp = None
            try:
                resp = self._once(method, url, json, headers)
            except httpx.TransportError as e:  # connect/read errors and timeouts
                last = e
                continue
            except httpx.HTTPError as e:  # anything else from httpx: not retried
                raise self._unavailable(attempt, e) from None
            if resp.status_code in retry_statuses and attempt < self.retry.max_attempts:
                continue
            return resp
        if resp is not None:
            return resp
        raise self._unavailable(self.retry.max_attempts, last)

    def _once(
        self, method: str, url: str, json: Optional[Mapping[str, Any]], headers: Dict[str, str]
    ) -> httpx.Response:
        req = self._http.build_request(method, url, json=json, headers=headers, timeout=self.timeout)
        resp = self._http.send(req, stream=True)
        try:
            if self._declared_too_large(resp):
                raise self._too_large(resp)
            chunks: List[bytes] = []
            size = 0
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > self.max_response_bytes:
                    raise self._too_large(resp)
                chunks.append(chunk)
        finally:
            resp.close()
        return self._buffered(resp, chunks)

    def verify(
        self,
        sql: str,
        context: Optional[Context] = None,
        *,
        policy: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Verdict:
        """Verify ``sql``; returns the verdict (allowed **or** denied).

        Raises :class:`HaltSQLUnavailable` / :class:`HaltSQLRequestError` when
        no verdict could be obtained.
        """
        body = self._verify_body(sql, context, policy)
        resp = self._send("POST", "/v1/verify", json=body, request_id=request_id)
        return self._parse_verdict(resp, sql)

    def check(
        self,
        sql: str,
        context: Optional[Context] = None,
        *,
        policy: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Verdict:
        """Like :meth:`verify`, but raises :class:`QueryDenied` on a denial."""
        return self.verify(sql, context, policy=policy, request_id=request_id).raise_for_denied()

    def policies(self) -> List[PolicyInfo]:
        """``GET /v1/policies``: the policies this caller may use."""
        resp = self._send("GET", "/v1/policies")
        if resp.status_code != 200:
            self._raise_for_status(resp)
        return self._parse_policies(self._json(resp))

    def healthz(self) -> Dict[str, Any]:
        """``GET /healthz``; raises :class:`HaltSQLUnavailable` unless 200."""
        resp = self._send("GET", "/healthz", retry_statuses=frozenset())
        if resp.status_code != 200:
            self._raise_for_status(resp)
        data = self._json(resp)
        return data if isinstance(data, dict) else {}

    def readyz(self) -> Dict[str, Any]:
        """``GET /readyz``; raises :class:`HaltSQLUnavailable` when not ready."""
        resp = self._send("GET", "/readyz", retry_statuses=frozenset())
        if resp.status_code != 200:
            self._raise_for_status(resp)
        data = self._json(resp)
        return data if isinstance(data, dict) else {}

    def is_ready(self) -> bool:
        """True if ``/readyz`` answers 200; never raises."""
        try:
            self.readyz()
            return True
        except Exception:  # noqa: BLE001
            return False


class AsyncHaltSQLClient(_Base):
    """``asyncio`` twin of :class:`HaltSQLClient` with the same semantics.

    Example::

        async with AsyncHaltSQLClient.from_env() as hs:
            verdict = await hs.check(sql, {"tenant_id": tenant})
            rows = await conn.fetch(sql, *verdict.bind_args())
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        token: Optional[str] = None,
        *,
        timeout: Union[float, httpx.Timeout] = 2.0,
        retry: Optional[RetryPolicy] = None,
        policy: Optional[str] = None,
        verify_sql_hash: bool = True,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        verify: TLSVerify = True,
        cert: Optional[TLSCert] = None,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        super().__init__(
            base_url, token, timeout, retry, policy, verify_sql_hash, max_response_bytes
        )
        tls = _http_client_kwargs(http_client, transport, verify, cert)
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=self.timeout, transport=transport, follow_redirects=False, **tls
        )

    @classmethod
    def from_env(cls, **overrides: Any) -> "AsyncHaltSQLClient":
        """Same environment variables as :meth:`HaltSQLClient.from_env`."""
        kw = _env_kwargs()
        kw.update(overrides)
        return cls(**kw)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncHaltSQLClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def _send(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        request_id: Optional[str] = None,
        retry_statuses: "frozenset[int]" = _RETRY_STATUSES,
    ) -> httpx.Response:
        url = self.base_url + path
        headers = self._headers(request_id)
        last: Optional[BaseException] = None
        resp: Optional[httpx.Response] = None
        for attempt in range(1, self.retry.max_attempts + 1):
            if attempt > 1:
                await asyncio.sleep(
                    self.retry.delay(attempt - 1, _retry_after(resp) if resp is not None else None)
                )
            resp = None
            try:
                resp = await self._once(method, url, json, headers)
            except httpx.TransportError as e:
                last = e
                continue
            except httpx.HTTPError as e:
                raise self._unavailable(attempt, e) from None
            if resp.status_code in retry_statuses and attempt < self.retry.max_attempts:
                continue
            return resp
        if resp is not None:
            return resp
        raise self._unavailable(self.retry.max_attempts, last)

    async def _once(
        self, method: str, url: str, json: Optional[Mapping[str, Any]], headers: Dict[str, str]
    ) -> httpx.Response:
        req = self._http.build_request(method, url, json=json, headers=headers, timeout=self.timeout)
        resp = await self._http.send(req, stream=True)
        try:
            if self._declared_too_large(resp):
                raise self._too_large(resp)
            chunks: List[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > self.max_response_bytes:
                    raise self._too_large(resp)
                chunks.append(chunk)
        finally:
            await resp.aclose()
        return self._buffered(resp, chunks)

    async def verify(
        self,
        sql: str,
        context: Optional[Context] = None,
        *,
        policy: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Verdict:
        """See :meth:`HaltSQLClient.verify`."""
        body = self._verify_body(sql, context, policy)
        resp = await self._send("POST", "/v1/verify", json=body, request_id=request_id)
        return self._parse_verdict(resp, sql)

    async def check(
        self,
        sql: str,
        context: Optional[Context] = None,
        *,
        policy: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Verdict:
        """See :meth:`HaltSQLClient.check`."""
        v = await self.verify(sql, context, policy=policy, request_id=request_id)
        return v.raise_for_denied()

    async def policies(self) -> List[PolicyInfo]:
        resp = await self._send("GET", "/v1/policies")
        if resp.status_code != 200:
            self._raise_for_status(resp)
        return self._parse_policies(self._json(resp))

    async def healthz(self) -> Dict[str, Any]:
        resp = await self._send("GET", "/healthz", retry_statuses=frozenset())
        if resp.status_code != 200:
            self._raise_for_status(resp)
        data = self._json(resp)
        return data if isinstance(data, dict) else {}

    async def readyz(self) -> Dict[str, Any]:
        resp = await self._send("GET", "/readyz", retry_statuses=frozenset())
        if resp.status_code != 200:
            self._raise_for_status(resp)
        data = self._json(resp)
        return data if isinstance(data, dict) else {}

    async def is_ready(self) -> bool:
        try:
            await self.readyz()
            return True
        except Exception:  # noqa: BLE001
            return False

