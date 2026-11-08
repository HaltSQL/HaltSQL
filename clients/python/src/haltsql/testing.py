"""Test helpers: build verdicts and run an in-process fake sidecar.

These are for *your* tests (and this package's). Never use them in production:
the fake decides verdicts with whatever function you give it.

Example::

    from haltsql.testing import FakeSidecar, make_verdict

    def decide(sql, context, policy):
        if "tenant_id = $1" in sql:
            return make_verdict(sql, allowed=True, bind=[context["tenant_id"]])
        return make_verdict(sql, allowed=False, codes=["E_TENANT_MISSING"])

    with FakeSidecar(decide, token="t0k") as fake:
        client = HaltSQLClient(fake.url, token="t0k")
"""

from __future__ import annotations

import os
import contextlib
import hmac
import json
import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Union

from .models import Context, Verdict, sql_sha256

__all__ = [
    "make_verdict",
    "make_verdict_dict",
    "FakeVerifier",
    "FakeSidecar",
    "RecordedRequest",
    "temporary_database",
    "LAB_ADMIN_DSN",
]

#: The haltlab Postgres 17 (``make -C lab up``); lab-only credentials.
LAB_ADMIN_DSN = (
    "host=127.0.0.1 port=5417 user=postgres password="
    + os.environ.get("HALTSQL_PGPASSWORD", "haltlab") + " dbname=postgres"
)


def make_verdict_dict(
    sql: str,
    *,
    allowed: bool,
    codes: Sequence[str] = (),
    bind: Sequence[Union[str, List[str]]] = (),
    shadow_codes: Sequence[str] = (),
    policy: str = "test",
    statement_kind: Optional[str] = "select",
    tables: Sequence[str] = (),
    columns: Sequence[str] = (),
) -> Dict[str, Any]:
    """A verdict JSON object for ``sql`` (``bind`` gives values for $1..$n)."""
    if not allowed and not codes:
        codes = ["E_TEST_DENIED"]

    def reason(code: str) -> Dict[str, Any]:
        return {"code": code, "message": f"{code} (fake)", "rule": "fake", "hint": f"fix {code}"}

    return {
        "allowed": allowed,
        "reasons": [] if allowed else [reason(c) for c in codes],
        "shadow_reasons": [reason(c) for c in shadow_codes],
        "policy": {"name": policy, "version": "sha256:" + "0" * 64},
        "statement_kind": statement_kind,
        "tables": sorted(tables),
        "columns": sorted(columns),
        "bind_params": [] if not allowed else [
            {"param": i, "value": list(v) if isinstance(v, (list, tuple)) else v}
            for i, v in enumerate(bind, start=1)
        ],
        "fingerprint": "0" * 16,
        "sql_sha256": sql_sha256(sql),
        "elapsed_us": 1,
    }


def make_verdict(sql: str, **kwargs: Any) -> Verdict:
    """Like :func:`make_verdict_dict`, parsed into a :class:`Verdict`."""
    return Verdict.from_dict(make_verdict_dict(sql, **kwargs))


Decide = Callable[[str, Mapping[str, Any], Optional[str]], Union[Verdict, Dict[str, Any]]]


class FakeVerifier:
    """In-memory verifier: ``decide(sql, context, None)`` returns the verdict.

    Records every call in :attr:`calls` as ``(sql, context)``.
    """

    def __init__(self, decide: Decide) -> None:
        self._decide = decide
        self.calls: List["tuple[str, Dict[str, Any]]"] = []

    def verify(self, sql: str, context: Optional[Context] = None) -> Verdict:
        ctx = dict(context or {})
        self.calls.append((sql, ctx))
        v = self._decide(sql, ctx, None)
        return v if isinstance(v, Verdict) else Verdict.from_dict(v)


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: Any = None


@dataclass
class _Scripted:
    status: int
    body: Any = None
    headers: Dict[str, str] = field(default_factory=dict)
    delay: float = 0.0
    raw: Optional[bytes] = None


class FakeSidecar:
    """A minimal ``haltsql-server`` lookalike on ``127.0.0.1`` (random port).

    Args:
        decide: ``decide(sql, context, policy) -> Verdict | dict`` for ``POST /v1/verify``.
        token: If set, ``/v1/*`` requires ``Authorization: Bearer <token>``.
        policies: Body of ``GET /v1/policies``.

    Use :meth:`push` to script the next responses (status codes, delays, raw
    bodies) before the normal behaviour resumes.
    """

    def __init__(
        self,
        decide: Optional[Decide] = None,
        *,
        token: Optional[str] = None,
        policies: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.decide = decide or (lambda sql, ctx, pol: make_verdict_dict(sql, allowed=False))
        self.token = token
        self.policies = policies if policies is not None else [
            {"name": "test", "version": "sha256:" + "0" * 64, "mode": "enforce"}
        ]
        self.requests: List[RecordedRequest] = []
        self.ready = True
        self._script: List[_Scripted] = []
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- scripting ---------------------------------------------------------
    def push(
        self,
        status: int,
        body: Any = None,
        *,
        headers: Optional[Dict[str, str]] = None,
        delay: float = 0.0,
        raw: Optional[bytes] = None,
    ) -> None:
        """Queue one scripted response (served before normal handling)."""
        with self._lock:
            self._script.append(_Scripted(status, body, headers or {}, delay, raw))

    def _pop(self) -> Optional[_Scripted]:
        with self._lock:
            return self._script.pop(0) if self._script else None

    # -- lifecycle ---------------------------------------------------------
    @property
    def url(self) -> str:
        assert self._server is not None, "FakeSidecar not started"
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}" if isinstance(host, str) else f"http://127.0.0.1:{port}"

    def start(self) -> "FakeSidecar":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _send(self, status: int, body: Any, headers: Optional[Dict[str, str]] = None,
                      raw: Optional[bytes] = None) -> None:
                data = raw if raw is not None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Request-Id", self.headers.get("X-Request-Id") or "fake-req")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw_body) if raw_body else None
                except ValueError:
                    body = None
                fake.requests.append(
                    RecordedRequest(method, self.path, {k.lower(): v for k, v in self.headers.items()}, body)
                )
                scripted = fake._pop()
                if scripted is not None:
                    if scripted.delay:
                        threading.Event().wait(scripted.delay)
                    self._send(scripted.status, scripted.body, scripted.headers, scripted.raw)
                    return
                if self.path == "/healthz":
                    self._send(200, {"status": "ok"})
                    return
                if self.path == "/readyz":
                    if fake.ready:
                        self._send(200, {"status": "ready", "policies": len(fake.policies)})
                    else:
                        self._send(503, {"status": "not_ready", "policies": 0})
                    return
                if self.path.startswith("/v1/") and fake.token is not None:
                    auth = self.headers.get("Authorization") or ""
                    expected = f"Bearer {fake.token}"
                    if not hmac.compare_digest(auth.encode(), expected.encode()):
                        self._send(401, {"error": {"code": "UNAUTHORIZED", "message": "invalid bearer token"}},
                                   {"WWW-Authenticate": "Bearer"})
                        return
                if self.path == "/v1/policies" and method == "GET":
                    self._send(200, {"policies": fake.policies})
                    return
                if self.path == "/v1/verify" and method == "POST":
                    if not isinstance(body, dict) or not isinstance(body.get("sql"), str):
                        self._send(400, {"error": {"code": "BAD_REQUEST", "message": "sql is required"}})
                        return
                    v = fake.decide(body["sql"], body.get("context") or {}, body.get("policy"))
                    self._send(200, v.to_dict() if isinstance(v, Verdict) else v)
                    return
                self._send(404, {"error": {"code": "NOT_FOUND", "message": "unknown path"}})

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "FakeSidecar":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


@contextlib.contextmanager
def temporary_database(
    prefix: str,
    setup_sql: str = "",
    *,
    admin_dsn: str = LAB_ADMIN_DSN,
) -> Iterator[Optional[str]]:
    """Create a throwaway database, yield its libpq DSN, drop it afterwards.

    Yields ``None`` when psycopg is missing or the server is unreachable, so
    tests can skip cleanly. ``prefix`` must be a lower-case identifier; a
    random suffix is appended. ``setup_sql`` runs in the new database.
    """
    if not prefix.replace("_", "").isalnum() or not prefix.islower():
        raise ValueError("prefix must be a lower-case identifier")
    try:
        import psycopg
    except ImportError:
        yield None
        return
    try:
        admin = psycopg.connect(admin_dsn, autocommit=True, connect_timeout=2)
    except Exception:  # noqa: BLE001
        yield None
        return
    name = f"{prefix}_{uuid.uuid4().hex[:10]}"
    try:
        admin.execute(f'CREATE DATABASE "{name}"')
        dsn = admin_dsn.replace("dbname=postgres", f"dbname={name}")
        if setup_sql:
            with psycopg.connect(dsn, autocommit=True) as c:
                c.execute(setup_sql)
        yield dsn
    finally:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        admin.close()
