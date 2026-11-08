"""Shared fixtures for the HaltSQL agent-framework packages (identical copy in
each package's tests/): the real haltsql CLI, a real haltsql-server process and
a throwaway database on the lab Postgres. Nothing here fakes HaltSQL or the
database; each fixture skips with a message when its component is missing."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from typing import Any, Dict, Iterator, List, Optional

import pytest

# Keep framework telemetry and tracing exporters off: tests make no outbound calls.
os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_DISABLE_TRACKING", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
os.environ.setdefault("SEMANTICKERNEL_TELEMETRY_ENABLED", "false")
os.environ.setdefault("ADK_DISABLE_TELEMETRY", "1")

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
POLICY = os.path.join(ROOT, "test", "fixtures", "policies", "saas.yaml")

OK_SQL = "SELECT id, status FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 10"
CROSS_TENANT_SQL = "SELECT id, status FROM orders WHERE tenant_id = 'globex' ORDER BY id LIMIT 10"
TENANT_HINT = "Use a $n placeholder"

SETUP = """
CREATE SCHEMA app;
CREATE TABLE app.orders (id int8 PRIMARY KEY, tenant_id text NOT NULL, customer_id int8,
  status text, total_cents int8, currency text, created_at timestamptz DEFAULT now(),
  updated_at timestamptz);
INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, currency) VALUES
  (1, 'acme', 10, 'open', 1250, 'USD'), (2, 'globex', 11, 'open', 990, 'EUR'),
  (3, 'acme', 12, 'paid', 4200, 'USD'), (4, 'globex', 13, 'paid', 100, 'EUR');
"""


def _bin(env: str, *rel: str) -> Optional[str]:
    for path in ([os.environ[env]] if os.environ.get(env) else []) + [os.path.join(ROOT, *rel)]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


@pytest.fixture(scope="session")
def haltsql_cli() -> str:
    b = _bin("HALTSQL_BIN", "_build", "default", "bin", "haltsql", "main.exe")
    if b is None:
        pytest.skip("haltsql CLI not built (dune build ./bin/haltsql/main.exe) and HALTSQL_BIN not set")
    return b


@pytest.fixture(scope="session")
def local_verifier(haltsql_cli: str) -> Any:
    from haltsql import LocalVerifier

    return LocalVerifier(POLICY, binary=haltsql_cli)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def server_url() -> Iterator[str]:
    """A real haltsql-server serving saas.yaml on a random loopback port."""
    import httpx

    b = _bin("HALTSQL_SERVER_BIN", "_build", "default", "bin", "server", "main.exe")
    if b is None:
        pytest.skip("haltsql-server not built (dune build ./bin/server/main.exe) and HALTSQL_SERVER_BIN not set")
    port = _free_port()
    argv = [b, "--listen", f"127.0.0.1:{port}", "--allow-unauthenticated", "--audit", "none",
            "--no-watch", "--log-level", "error", "--policy", POLICY]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 15
        while True:
            if proc.poll() is not None:
                err = proc.stderr.read().decode() if proc.stderr else ""
                pytest.fail(f"haltsql-server exited early ({proc.returncode}): {err[:500]}")
            try:
                if httpx.get(url + "/readyz", timeout=0.5).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.time() > deadline:
                pytest.fail("haltsql-server did not become ready")
            time.sleep(0.05)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def server_verifier(server_url: str) -> Iterator[Any]:
    from haltsql import HaltSQLClient

    with HaltSQLClient(server_url) as c:
        yield c


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    from haltsql.testing import temporary_database

    with temporary_database("haltsql_agents", SETUP) as dsn:
        if dsn is None:
            pytest.skip("psycopg or the lab Postgres on 127.0.0.1:5417 is not available (make -C lab up)")
        yield dsn + " options=-csearch_path=app"


class Connections:
    """Real psycopg connections to the test database, counted: a denied query
    must never open one."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self.opened = 0

    def __call__(self) -> Any:
        import psycopg

        self.opened += 1
        return psycopg.connect(self.dsn, connect_timeout=5)


@pytest.fixture
def connections(pg_dsn: str) -> Connections:
    return Connections(pg_dsn)


def acme_rows() -> List[List[Any]]:
    return [[1, "open"], [3, "paid"]]


def assert_denied_cross_tenant(result: Dict[str, Any]) -> None:
    assert result["status"] == "denied", result
    assert result["executed"] is False
    assert [r["code"] for r in result["reasons"]] == ["E_TENANT_MISMATCH"]
    assert TENANT_HINT in result["reasons"][0]["hint"]
    assert TENANT_HINT in result["message"]
    assert result["message"].startswith("HaltSQL denied the query; it was not executed.")

